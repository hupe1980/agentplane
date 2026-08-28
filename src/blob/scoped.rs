//! A blob store whose addresses belong to one erasure unit.
//!
//! Content addressing stores identical bytes once — a feature inside one
//! erasure unit and a defect across two. The severe half is not reading, it is
//! **erasure**: with the bare content digest as the storage key, two cases of
//! one tenant holding the same bytes share one object, so expiring one case's
//! blobs tombstones the other's data while discharging the first's request —
//! and the drill then reads the survivor's loss as *erased by design*, which
//! is precisely the answer that does not page anyone. Sealed deployments fare
//! no better: the second case's write re-seals the shared object under its own
//! scope, so whichever case erases its key first strands the other.
//!
//! The rule is the tenant rule — tenant leads the blob path, so two tenants'
//! identical bytes are two objects — applied at the unit that actually owns
//! erasure: **the erasure unit leads the storage address**. Two cases'
//! identical bytes are two objects, one case's tombstone cannot reach the
//! other's, and a scope's key destruction and its tombstones cover exactly
//! the same set.
//!
//! The journal is untouched by this: records commit to the **content**
//! digest, which still identifies the bytes and still verifies them. Only the
//! storage key underneath is unit-qualified, derived here and nowhere else.

use async_trait::async_trait;

use super::{BlobError, BlobStore, verify};
use crate::core::{Digest, Timestamp};

/// Where one unit's copy of `digest` lives in the backing store.
///
/// Domain-separated and unambiguous: a tag no content digest can collide with
/// short of a preimage, a length-prefixed scope so `("a", "b/c")` and
/// `("a/b", "c")` cannot meet, and the raw content digest. Derived in exactly
/// one place, because the write path, the read path, the erasure path and the
/// drill must all reach the same object or the guarantee quietly halves.
#[must_use]
pub fn unit_address(scope: &str, digest: Digest) -> Digest {
    let mut bytes = Vec::with_capacity(23 + 8 + scope.len() + 32);
    bytes.extend_from_slice(b"agentplane/blob-unit/1\n");
    bytes.extend_from_slice(&(scope.len() as u64).to_be_bytes());
    bytes.extend_from_slice(scope.as_bytes());
    bytes.extend_from_slice(digest.as_bytes());
    Digest::of(&bytes)
}

/// A [`BlobStore`] that keeps one erasure unit's blobs under addresses of its
/// own.
///
/// Callers keep speaking content digests — `put` still returns
/// [`Digest::of`] of the bytes, `get` still verifies against it — while the
/// backing store is keyed by [`unit_address`]. Errors are reported in the
/// caller's vocabulary too: a missing or expired blob names the content
/// digest, never the derived address, which identifies nothing a reader can
/// look up.
///
/// The sealing decorator composes on top: `EncryptedBlobs` writes envelopes
/// through [`put_at`](BlobStore::put_at)/[`get_raw`](BlobStore::get_raw),
/// which this store translates, so a sealed deployment gets both properties
/// from one wiring.
#[derive(Debug)]
pub struct ScopedBlobs {
    inner: std::sync::Arc<dyn BlobStore>,
    scope: String,
}

impl ScopedBlobs {
    /// Address everything written through this handle under `scope`.
    #[must_use]
    pub fn new(inner: std::sync::Arc<dyn BlobStore>, scope: impl Into<String>) -> Self {
        Self {
            inner,
            scope: scope.into(),
        }
    }

    fn address(&self, digest: Digest) -> Digest {
        unit_address(&self.scope, digest)
    }

    /// Re-state an inner error in terms of the content digest the caller asked
    /// about. The derived address in a `NotFound` or an `Expired` identifies
    /// nothing anybody can look up, and leaking it would send an operator
    /// searching for a digest that is not in any journal.
    fn named(digest: Digest, e: BlobError) -> BlobError {
        match e {
            BlobError::NotFound(_) => BlobError::NotFound(digest.to_hex()),
            BlobError::Expired { at, reason, .. } => BlobError::Expired {
                digest: digest.to_hex(),
                at,
                reason,
            },
            other => other,
        }
    }
}

#[async_trait]
impl BlobStore for ScopedBlobs {
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        let digest = Digest::of(bytes);
        self.inner
            .put_at(self.address(digest), bytes)
            .await
            .map_err(|e| Self::named(digest, e))?;
        Ok(digest)
    }

    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        self.inner
            .put_at(self.address(digest), bytes)
            .await
            .map_err(|e| Self::named(digest, e))
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        self.inner
            .get_raw(self.address(digest))
            .await
            .map_err(|e| Self::named(digest, e))
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        // Fetched raw and verified here against the *content* digest: the
        // inner store's own `get` would verify against the derived address,
        // which nothing hashes to on purpose.
        let bytes = self
            .inner
            .get_raw(self.address(digest))
            .await
            .map_err(|e| Self::named(digest, e))?;
        verify(digest, bytes)
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        self.inner
            .expire(self.address(digest), at, reason)
            .await
            .map_err(|e| Self::named(digest, e))
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        self.inner
            .has(self.address(digest))
            .await
            .map_err(|e| Self::named(digest, e))
    }
}
