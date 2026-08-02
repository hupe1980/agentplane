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
use crate::core::Digest;

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
                Err(BlobError::NotFound(digest.to_hex()))
            }
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
