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
    lifecycle: Arc<dyn super::ErasureCoordinator>,
}

impl std::fmt::Debug for EncryptedMemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMemoryStore")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl EncryptedMemoryStore {
    /// Seal this store's content, serialised by a **process-local** lifecycle
    /// lock.
    ///
    /// It was called `new_single_node`, and that name stopped being true when
    /// the lock became a seam: this is single-node *by default* now, not by
    /// construction. An active-active plane calls
    /// [`coordinated_by`](Self::coordinated_by) with a coordinator that spans
    /// instances — and [`is_distributed`](Self::is_distributed) is how a caller
    /// checks which it got, rather than inferring it from a constructor name.
    #[must_use]
    pub fn new(inner: Arc<dyn MemoryStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Self {
        Self {
            inner,
            keys,
            tenant,
            lifecycle: Arc::new(super::LocalCoordinator::new()),
        }
    }

    /// Serialise this store's lifecycle operations with somebody else's lock.
    ///
    /// The default is [`LocalCoordinator`](super::LocalCoordinator), which is a
    /// process-local mutex and therefore correct for a single-writer deployment
    /// and **nothing else**. An active-active plane supplies a coordinator that
    /// spans instances — otherwise a write on the second instance lands under a
    /// scope the first is destroying, and the erasure reports success over a row
    /// sealed to a key that no longer exists.
    #[must_use]
    pub fn coordinated_by(mut self, coordinator: Arc<dyn super::ErasureCoordinator>) -> Self {
        self.lifecycle = coordinator;
        self
    }

    /// Whether this store's lifecycle lock spans instances.
    ///
    /// Read at `build`, so a plane wiring a shared store can refuse a
    /// single-node coordinator rather than discovering it during an erasure
    /// that already reported success.
    #[must_use]
    pub fn is_distributed(&self) -> bool {
        self.lifecycle.is_distributed()
    }

    /// The lifecycle lock's scope: one per **tenant**, not per subject.
    ///
    /// Per-subject would be finer and is not available: `forget`,
    /// `forget_cascading` and `set_legal_hold` are addressed by item id, and
    /// `sweep_expired` spans every subject at once. Looking a subject up to
    /// decide which lock to take is a read that races the very thing the lock
    /// protects — so the scope is the widest operation's scope, which is what
    /// the process-local mutex this replaced was already doing.
    fn lifecycle_scope(&self) -> String {
        super::scope(&self.tenant, "memory-lifecycle")
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
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
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
        })
        .await
    }
}

#[allow(clippy::needless_pass_by_value)]
fn key_error(error: KeyError) -> StoreError {
    StoreError::Backend(error.to_string())
}

#[async_trait]
impl MemoryStore for EncryptedMemoryStore {
    /// This store *does* have a lifecycle lock, so the answer is never `None` —
    /// and whether it spans instances is the coordinator's to say.
    fn erasure_is_distributed(&self) -> Option<bool> {
        Some(self.lifecycle.is_distributed())
    }

    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            let mut sealed = item.clone();
            sealed.content = self.seal(item).await?;
            sealed.derived_from.clear();
            for source in &item.derived_from {
                sealed
                    .derived_from
                    .push(self.backing_selection(source).await?);
            }
            self.inner.remember(&sealed).await
        })
        .await
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
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.forget(id).await
        })
        .await
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.forget_subject(subject).await
        })
        .await
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
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.forget_cascading(id).await
        })
        .await
    }

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.set_legal_hold(id, held).await
        })
        .await
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        self.inner.legal_hold(id).await
    }

    async fn sweep_expired(&self, at: Timestamp) -> Result<usize, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.sweep_expired(at).await
        })
        .await
    }

    async fn touch(&self, ids: &[String], at: Timestamp) -> Result<(), StoreError> {
        self.inner.touch(ids, at).await
    }
}
