//! Blobs on any storage [`OpenDAL`](https://opendal.apache.org) can reach.
//!
//! One adapter, and with it a filesystem, S3, GCS, Azure, and the rest — which
//! is the whole reason to take the dependency here and not for the journal. A
//! content-addressed write needs `put` and `get` and nothing else: no ordered
//! scan, no multi-key transaction, no unique constraint. Those are exactly what
//! the journal needs and exactly what an object store cannot give, which is why
//! the two sit on different foundations rather than one compromise.

use async_trait::async_trait;
use opendal::Operator;

use super::{BlobError, BlobStore, verify};
use crate::core::{Digest, Timestamp};

/// Content-addressed blobs on an `OpenDAL` operator.
#[derive(Debug, Clone)]
pub struct OpenDalBlobs {
    op: Operator,
    prefix: String,
    tenant: crate::core::TenantId,
}

impl OpenDalBlobs {
    /// Store blobs under `prefix` on this operator.
    #[must_use]
    pub fn new(op: Operator, prefix: impl Into<String>) -> Self {
        Self {
            op,
            prefix: prefix.into(),
            tenant: crate::core::TenantId::default(),
        }
    }

    /// Serve one tenant.
    ///
    /// Blobs are content-addressed, so without this two tenants writing the same
    /// bytes share one object — and erasing it for one destroys it for the
    /// other while reporting both requests discharged. The tenant leads the
    /// path, so the sharing cannot happen.
    #[must_use]
    pub fn for_tenant(mut self, tenant: crate::core::TenantId) -> Self {
        self.tenant = tenant;
        self
    }

    /// Where a blob's tombstone lives.
    ///
    /// Beside the blob rather than inside it, because the whole point is that
    /// it outlives the bytes: a reader arriving after erasure finds the
    /// tombstone at a derivable location and can say *deliberately expired*
    /// instead of *missing*.
    fn tomb(&self, digest: Digest) -> String {
        format!("{}.tomb", self.path(digest))
    }

    /// Where a digest lives.
    ///
    /// Fanned out over two leading bytes, because object stores and filesystems
    /// alike degrade when a single directory holds millions of siblings — and
    /// the hex of a hash is uniformly distributed, so the fan-out is even
    /// without anything having to balance it.
    ///
    /// The tenant leads the fan-out rather than following it, so one tenant's
    /// bytes are a subtree: listable, countable, and removable as a unit.
    fn path(&self, digest: Digest) -> String {
        let hex = digest.to_hex();
        format!(
            "{}/{}/{}/{}/{hex}",
            self.prefix,
            self.tenant,
            &hex[0..2],
            &hex[2..4]
        )
    }
}

impl OpenDalBlobs {
    /// Why nothing is at this address: erased, never written, or a tombstone
    /// that does not read.
    ///
    /// One reader, called from both read paths and from the write refusal, so
    /// none of the three can come to a different answer about what a tombstone
    /// means. Returns the error rather than a value, because every caller wants
    /// one.
    async fn absent(&self, digest: Digest) -> BlobError {
        let raw = match self.op.read(&self.tomb(digest)).await {
            Ok(raw) => raw.to_vec(),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                return BlobError::NotFound(digest.to_hex());
            }
            Err(e) => return backend(&e),
        };
        let unreadable = |detail: String| BlobError::UnreadableTombstone {
            digest: digest.to_hex(),
            detail,
        };
        // The version is read before any field is trusted, so a tombstone a
        // later build wrote is refused by name rather than half-parsed.
        let stone: Tombstone = match serde_json::from_slice(&raw) {
            Ok(stone) => stone,
            Err(e) => return unreadable(e.to_string()),
        };
        if stone.v != TOMBSTONE_FORMAT_VERSION {
            return unreadable(format!(
                "written under tombstone format {}, and this build reads {TOMBSTONE_FORMAT_VERSION}",
                stone.v
            ));
        }
        BlobError::Expired {
            digest: digest.to_hex(),
            at: stone.at,
            reason: stone.reason,
        }
    }
}

fn backend(e: &opendal::Error) -> BlobError {
    BlobError::Backend(e.to_string())
}

/// The tombstone layout this build writes and reads.
///
/// One number naming the whole thing, on the same terms as every other durable
/// format here: a reader that cannot interpret a tombstone must refuse rather
/// than guess, and "which shape is this" has to be answerable from the bytes.
/// A tombstone outlives the object it describes by design, so it is the one
/// artifact in this store that a future build is certain to meet.
pub const TOMBSTONE_FORMAT_VERSION: u8 = 1;

/// What a tombstone records.
///
/// Serialised through [`canon`](crate::core::canon) rather than as a delimited
/// line, so the bytes do not depend on field order and a reason containing a
/// space, a newline or a quote survives a round trip. A delimited form has to
/// decide what an absent half means, and the only safe answer — refuse — is
/// what a parser gives for free.
/// Strict in both directions, as every durable format here is: a tombstone is
/// evidence, and a reader that drops a member it does not recognise reaches a
/// verdict over evidence it did not see. An added member is a format bump.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Tombstone {
    /// The format this was written under. Read before anything else is trusted.
    v: u8,
    /// When the bytes were expired, as a Unix second.
    at: i64,
    /// Why, in the words of whoever asked.
    reason: String,
}

#[async_trait]
impl BlobStore for OpenDalBlobs {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        let digest = Digest::of(bytes);
        self.put_at(digest, bytes).await?;
        Ok(digest)
    }

    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        // One read before the write, and it is the tombstone rather than the
        // object. Re-writing the bytes themselves cannot do harm — the address
        // is the content — but writing them over an *erased* address puts the
        // data back, silently, under a tombstone that still says when it went.
        // So the round trip buys the one thing a content-addressed store cannot
        // get for free.
        match self.absent(digest).await {
            // Nothing has been erased here, which is what "no tombstone" means
            // on the read path and the only answer that licenses a write.
            BlobError::NotFound(_) => {}
            refusal => return Err(refusal),
        }
        self.op
            .write(&self.path(digest), bytes.to_vec())
            .await
            .map_err(|e| backend(&e))?;
        Ok(())
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        match self.op.read(&self.path(digest)).await {
            Ok(buf) => Ok(buf.to_vec()),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Err(self.absent(digest).await),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        match self.op.read(&self.path(digest)).await {
            Ok(buf) => verify(digest, buf.to_vec()),
            // Only now look for a tombstone: while the bytes are live it would
            // be a contradiction, and answering from it would hide data that is
            // still there.
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Err(self.absent(digest).await),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        // The tombstone is written *before* the bytes are dropped. Crash in
        // between and the result is a tombstone beside live bytes — which `get`
        // ignores, so the blob still reads correctly and the expiry can be
        // retried. The other order would lose the bytes and the explanation
        // together, leaving an erasure indistinguishable from data loss.
        let existing = self
            .op
            .exists(&self.tomb(digest))
            .await
            .map_err(|e| backend(&e))?;
        if !existing {
            let stone = Tombstone {
                v: TOMBSTONE_FORMAT_VERSION,
                at: at.unix_timestamp(),
                reason: reason.to_owned(),
            };
            let bytes = crate::core::canon::to_bytes(&stone)
                .map_err(|e| BlobError::Backend(format!("a tombstone did not serialize: {e}")))?;
            self.op
                .write(&self.tomb(digest), bytes)
                .await
                .map_err(|e| backend(&e))?;
        }
        match self.op.delete(&self.path(digest)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(backend(&e)),
        }
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        self.op
            .exists(&self.path(digest))
            .await
            .map_err(|e| backend(&e))
    }
}
