//! An in-process blob store, for tests and the simulator.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use super::{BlobError, BlobStore, verify};
use crate::core::{Digest, Timestamp};

/// Blobs held in memory for the life of the process.
#[derive(Debug, Default)]
pub struct MemoryBlobs {
    blobs: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
    /// `digest -> (when, why)`. Kept after the bytes go, because "deliberately
    /// expired" and "missing" are different answers to an operator.
    tombstones: Mutex<BTreeMap<[u8; 32], (i64, String)>>,
    tenant: crate::core::TenantId,
}

impl MemoryBlobs {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve one tenant.
    ///
    /// In-process and per-handle, so two tenants' handles are two maps rather
    /// than one map with a shared keyspace — the same separation the object
    /// store gets from its path prefix.
    #[must_use]
    pub fn for_tenant(mut self, tenant: crate::core::TenantId) -> Self {
        self.tenant = tenant;
        self
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

impl MemoryBlobs {
    /// Why nothing is here: deliberately expired, or simply absent.
    ///
    /// Consulted only once the bytes are gone — a tombstone beside live bytes
    /// would be a contradiction, and answering from it would hide them.
    fn absent<T>(&self, digest: Digest) -> Result<T, BlobError> {
        self.tombstone(digest)?;
        Err(BlobError::NotFound(digest.to_hex()))
    }

    /// `Err(Expired)` if this address has been erased, `Ok(())` if it has not.
    ///
    /// Shaped as a refusal rather than as a lookup because both callers want it
    /// that way: the read path turns an absent blob into the reason it is
    /// absent, and the write path refuses to undo an erasure. One function, so
    /// the two cannot come to disagree about what a tombstone means.
    fn tombstone(&self, digest: Digest) -> Result<(), BlobError> {
        let stone = self
            .tombstones
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .get(digest.as_bytes())
            .cloned();
        match stone {
            Some((at, reason)) => Err(BlobError::Expired {
                digest: digest.to_hex(),
                at,
                reason,
            }),
            None => Ok(()),
        }
    }
}

#[async_trait]
impl BlobStore for MemoryBlobs {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    async fn put(&self, bytes: &[u8]) -> Result<Digest, BlobError> {
        // The store hashes; the caller does not get to say where its bytes live.
        let digest = Digest::of(bytes);
        self.put_at(digest, bytes).await?;
        Ok(digest)
    }

    async fn put_at(&self, digest: Digest, bytes: &[u8]) -> Result<(), BlobError> {
        // An expired address stays expired: the address is the content, so
        // writing the same bytes again lands on the erased object and puts the
        // data back under a tombstone that still says when it went.
        self.tombstone(digest)?;
        self.blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .insert(digest.as_bytes().to_owned(), bytes.to_vec());
        Ok(())
    }

    async fn get_raw(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        let found = self
            .blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .get(digest.as_bytes())
            .cloned();
        if let Some(bytes) = found {
            return Ok(bytes);
        }
        self.absent(digest)
    }

    async fn get(&self, digest: Digest) -> Result<Vec<u8>, BlobError> {
        let found = self
            .blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .get(digest.as_bytes())
            .cloned();
        if let Some(bytes) = found {
            return verify(digest, bytes);
        }
        // Checked only once the bytes are absent: a tombstone beside live bytes
        // would be a contradiction, and answering from it would hide them.
        self.absent(digest)
    }

    async fn expire(&self, digest: Digest, at: Timestamp, reason: &str) -> Result<(), BlobError> {
        let mut stones = self
            .tombstones
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?;
        // First expiry wins: a retry must not rewrite when the data went, for
        // the same reason a repeated stop request does not reassign who asked.
        stones
            .entry(digest.as_bytes().to_owned())
            .or_insert_with(|| (at.unix_timestamp(), reason.to_owned()));
        drop(stones);
        self.blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .remove(digest.as_bytes());
        Ok(())
    }

    async fn has(&self, digest: Digest) -> Result<bool, BlobError> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| BlobError::Backend("blob mutex poisoned".into()))?
            .contains_key(digest.as_bytes()))
    }
}
