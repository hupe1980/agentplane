//! Cryptographically erasable governed memory for single-node deployments.
//!
//! Content is sealed before it reaches `MemoryStore`; metadata remains clear so
//! subject/purpose indexes and policy remain usable. Every item gets a fresh
//! data key wrapped under the subject's tenant-qualified key scope. Destroying
//! that wrapping scope makes live rows, replicas and backups unreadable.
//!
//! Subject erasure is serialized with writes and legal-hold changes by this
//! wrapper. That mutex is process-local, so this concrete adapter is for redb or
//! another single-writer deployment. Active-active deployments need a
//! distributed erasure coordinator spanning their database lock and KMS call;
//! pretending a local mutex supplies that contract would create a hold race.

use std::sync::Arc;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{Digest, StoreError, TenantId, Timestamp};
use crate::memory::{MemoryItem, MemoryStore, Recall, Selected};

use super::{DataKey, KeyError, KeyRing, WrappedKey};

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    wrapped: WrappedKey,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    digest: Digest,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlainMemory {
    content: Value,
    derived_from: Vec<Selected>,
}

/// A memory store whose content is unreadable after subject-key destruction.
pub struct EncryptedMemoryStore {
    inner: Arc<dyn MemoryStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
    lifecycle: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for EncryptedMemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMemoryStore")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl EncryptedMemoryStore {
    #[must_use]
    pub fn new_single_node(
        inner: Arc<dyn MemoryStore>,
        keys: Arc<dyn KeyRing>,
        tenant: TenantId,
    ) -> Self {
        Self {
            inner,
            keys,
            tenant,
            lifecycle: tokio::sync::Mutex::new(()),
        }
    }

    fn scope(&self, subject: &str) -> String {
        super::scope(&self.tenant, &format!("memory/{subject}"))
    }

    fn cipher(key: &DataKey) -> chacha20poly1305::XChaCha20Poly1305 {
        use chacha20poly1305::KeyInit as _;
        chacha20poly1305::XChaCha20Poly1305::new(key.expose().into())
    }

    async fn seal(&self, item: &MemoryItem) -> Result<Value, StoreError> {
        let plain = crate::core::canon::to_bytes(&PlainMemory {
            content: item.content.clone(),
            derived_from: item.derived_from.clone(),
        })
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        let digest = Digest::of(&plain);
        let (key, wrapped) = self
            .keys
            .data_key(&self.scope(&item.subject))
            .await
            .map_err(key_error)?;
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = Self::cipher(&key)
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plain,
                    aad: digest.as_bytes(),
                },
            )
            .map_err(|error| StoreError::Backend(format!("sealing memory failed: {error}")))?;
        serde_json::to_value(Envelope {
            wrapped,
            nonce: nonce.to_vec(),
            ciphertext,
            digest,
        })
        .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn open_item(&self, mut item: MemoryItem) -> Result<MemoryItem, StoreError> {
        let envelope: Envelope = serde_json::from_value(item.content).map_err(|_| {
            StoreError::Backend("encrypted memory row does not contain a valid envelope".to_owned())
        })?;
        if envelope.nonce.len() != 24 {
            return Err(StoreError::Backend(
                "encrypted memory nonce has the wrong length".to_owned(),
            ));
        }
        let key = self.keys.open(&envelope.wrapped).await.map_err(key_error)?;
        let plain = Self::cipher(&key)
            .decrypt(
                envelope.nonce.as_slice().into(),
                chacha20poly1305::aead::Payload {
                    msg: &envelope.ciphertext,
                    aad: envelope.digest.as_bytes(),
                },
            )
            .map_err(|_| StoreError::Backend("encrypted memory did not authenticate".to_owned()))?;
        if Digest::of(&plain) != envelope.digest {
            return Err(StoreError::Backend(
                "encrypted memory plaintext digest changed".to_owned(),
            ));
        }
        let plain: PlainMemory = serde_json::from_slice(&plain)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        item.content = plain.content;
        item.derived_from = plain.derived_from;
        Ok(item)
    }

    async fn backing_selection(&self, source: &Selected) -> Result<Selected, StoreError> {
        let stored = self
            .inner
            .version(&source.id, source.version)
            .await?
            .ok_or_else(|| {
                StoreError::Backend(format!(
                    "derived memory source '{}' version {} is absent",
                    source.id, source.version
                ))
            })?;
        let opened = self.open_item(stored.clone()).await?;
        if opened.selection_digest() != source.digest {
            return Err(StoreError::Backend(format!(
                "derived memory source '{}' version {} changed",
                source.id, source.version
            )));
        }
        Ok(Selected {
            id: source.id.clone(),
            version: source.version,
            digest: stored.selection_digest(),
        })
    }

    /// Destroy a subject's wrapping scope, then clean unreadable ciphertext.
    ///
    /// `at` and `reason` come from the caller's audited lifecycle operation;
    /// this adapter never reads an ambient clock.
    pub async fn erase_subject(
        &self,
        subject: &str,
        at: Timestamp,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let _guard = self.lifecycle.lock().await;
        let current = self
            .inner
            .recall(&Recall::about(subject).limit(usize::MAX))
            .await?;
        for item in &current {
            if self.inner.legal_hold(&item.id).await? {
                return Err(StoreError::Backend(format!(
                    "memory '{}' is under legal hold",
                    item.id
                )));
            }
        }
        self.keys
            .destroy(&self.scope(subject), at, reason)
            .await
            .map_err(key_error)?;
        match self.inner.forget_subject(subject).await {
            Ok(count) => Ok(count),
            Err(error) => {
                tracing::warn!(%subject, %error, "memory key was destroyed but ciphertext cleanup failed");
                Ok(current.len())
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn key_error(error: KeyError) -> StoreError {
    StoreError::Backend(error.to_string())
}

#[async_trait]
impl MemoryStore for EncryptedMemoryStore {
    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        let _guard = self.lifecycle.lock().await;
        let mut sealed = item.clone();
        sealed.content = self.seal(item).await?;
        sealed.derived_from.clear();
        for source in &item.derived_from {
            sealed
                .derived_from
                .push(self.backing_selection(source).await?);
        }
        self.inner.remember(&sealed).await
    }

    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError> {
        let items = self.inner.recall(query).await?;
        let mut opened = Vec::with_capacity(items.len());
        for item in items {
            opened.push(self.open_item(item).await?);
        }
        Ok(opened)
    }

    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError> {
        match self.inner.version(id, version).await? {
            Some(item) => self.open_item(item).await.map(Some),
            None => Ok(None),
        }
    }

    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        let _guard = self.lifecycle.lock().await;
        self.inner.forget(id).await
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let _guard = self.lifecycle.lock().await;
        self.inner.forget_subject(subject).await
    }

    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError> {
        let items = self.inner.derivatives(id).await?;
        let mut opened = Vec::with_capacity(items.len());
        for item in items {
            opened.push(self.open_item(item).await?);
        }
        Ok(opened)
    }

    async fn forget_cascading(&self, id: &str) -> Result<usize, StoreError> {
        let _guard = self.lifecycle.lock().await;
        self.inner.forget_cascading(id).await
    }

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        let _guard = self.lifecycle.lock().await;
        self.inner.set_legal_hold(id, held).await
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        self.inner.legal_hold(id).await
    }

    async fn sweep_expired(&self, at: Timestamp) -> Result<usize, StoreError> {
        let _guard = self.lifecycle.lock().await;
        self.inner.sweep_expired(at).await
    }

    async fn touch(&self, ids: &[String], at: Timestamp) -> Result<(), StoreError> {
        self.inner.touch(ids, at).await
    }
}
