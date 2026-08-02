//! An in-process blob store, for tests and the simulator.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use super::{BlobError, BlobStore, verify};
use crate::core::Digest;

/// Blobs held in memory for the life of the process.
#[derive(Debug, Default)]
pub struct MemoryBlobs {
    blobs: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
}

impl MemoryBlobs {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct blobs are held.
    ///
    /// Exists so a test can assert that writing the same bytes twice stored them
    /// once — the idempotence a content-addressed store is supposed to give.
    ///
    /// # Panics
    ///
    /// If a previous caller panicked while holding the lock.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blobs.lock().expect("blob mutex").len()
    }

    /// Whether nothing is stored.
    ///
    /// # Panics
    ///
    /// If a previous caller panicked while holding the lock.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Replace a blob's bytes without changing its address.
    ///
    /// Exists so the suite can prove corruption is *detected* rather than
    /// assumed impossible — the same reason the journal has a tamper hook. Not
    /// part of the supported surface.
    ///
    /// # Panics
    ///
    /// If a previous caller panicked while holding the lock.
    #[doc(hidden)]
    pub fn tamper_for_test(&self, digest: Digest, bytes: Vec<u8>) {
        self.blobs
            .lock()
            .expect("blob mutex")
            .insert(digest.as_bytes().to_owned(), bytes);
    }
}

#[async_trait]
impl BlobStore for MemoryBlobs {
    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        // The store hashes; the caller does not get to say where its bytes live.
        let digest = Digest::of(bytes);
        self.blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .insert(digest.as_bytes().to_owned(), bytes.to_vec());
        Ok(digest)
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        let found = self
            .blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .get(digest.as_bytes())
            .cloned();
        match found {
            Some(bytes) => verify(digest, bytes),
            None => Err(BlobError::NotFound(digest.to_hex())),
        }
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .contains_key(digest.as_bytes()))
    }
}
