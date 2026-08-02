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
}

impl OpenDalBlobs {
    /// Store blobs under `prefix` on this operator.
    #[must_use]
    pub fn new(op: Operator, prefix: impl Into<String>) -> Self {
        Self {
            op,
            prefix: prefix.into(),
        }
    }

    /// Where a digest lives.
    ///
    /// Fanned out over two leading bytes, because object stores and filesystems
    /// alike degrade when a single directory holds millions of siblings — and
    /// the hex of a hash is uniformly distributed, so the fan-out is even
    /// without anything having to balance it.
    /// Where a blob's tombstone lives.
    ///
    /// Beside the blob rather than inside it, because the whole point is that
    /// it outlives the bytes: a reader arriving after erasure finds the
    /// tombstone at a derivable location and can say *deliberately expired*
    /// instead of *missing*.
    fn tomb(&self, digest: Digest) -> String {
        format!("{}.tomb", self.path(digest))
    }

    fn path(&self, digest: Digest) -> String {
        let hex = digest.to_hex();
        format!("{}/{}/{}/{hex}", self.prefix, &hex[0..2], &hex[2..4])
    }
}

fn backend(e: &opendal::Error) -> BlobError {
    BlobError::Backend(e.to_string())
}

#[async_trait]
impl BlobStore for OpenDalBlobs {
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        let digest = Digest::of(bytes);
        // No read-before-write: the address is the content, so re-writing is
        // writing the same bytes to the same place. Checking first would buy a
        // round trip to avoid an operation that cannot do harm.
        self.op
            .write(&self.path(digest), bytes.to_vec())
            .await
            .map_err(|e| backend(&e))?;
        Ok(digest)
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        match self.op.read(&self.path(digest)).await {
            Ok(buf) => verify(digest, buf.to_vec()),
            Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                // Only now look for a tombstone: while the bytes are live it
                // would be a contradiction, and answering from it would hide
                // data that is still there.
                match self.op.read(&self.tomb(digest)).await {
                    Ok(raw) => {
                        let text = String::from_utf8_lossy(&raw.to_vec()).into_owned();
                        let (at, reason) = text.split_once(' ').unwrap_or(("0", "expired"));
                        Err(BlobError::Expired {
                            digest: digest.to_hex(),
                            at: at.parse().unwrap_or(0),
                            reason: reason.to_owned(),
                        })
                    }
                    Err(e) if e.kind() == opendal::ErrorKind::NotFound => {
                        Err(BlobError::NotFound(digest.to_hex()))
                    }
                    Err(e) => Err(backend(&e)),
                }
            }
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
            let line = format!("{} {}", at.unix_timestamp(), reason.replace('\n', " "));
            self.op
                .write(&self.tomb(digest), line.into_bytes())
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
