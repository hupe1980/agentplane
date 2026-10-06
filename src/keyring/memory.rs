//! Cryptographically erasable governed memory for single-node deployments.
//!
//! Content is sealed before it reaches `MemoryStore`; metadata remains clear so
//! subject/purpose indexes and policy remain usable. Every **version** of every
//! item is sealed in the crate's one envelope under its own tenant-qualified
//! key scope, `memory-item/<id>@<version>`, so each erasure verb destroys
//! exactly the keys of what it erased: `forget` every version of one id,
//! `forget_cascading` and `sweep_expired` every version of each id they erased
//! whole, `erase_subject` every version of every id the subject holds — and a
//! cascade that trims an id's superseded versions destroys exactly those
//! versions' keys, leaving its current one readable. Destroying a scope makes
//! the live rows, replicas and backups of that version unreadable at once. A
//! subject is not a key scope, so erasing one does not stop it being written
//! to again under new ids.
//!
//! Subject erasure is serialized with writes and legal-hold changes by this
//! wrapper. That mutex is process-local, so this concrete adapter is for redb or
//! another single-writer deployment. Active-active deployments need a
//! distributed erasure coordinator spanning their database lock and KMS call;
//! pretending a local mutex supplies that contract would create a hold race.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{StoreError, TenantId, Timestamp};
use crate::journal::payload;
use crate::memory::{Cascade, MemoryItem, MemoryStore, Recall, Selected};

use super::{Erasure, KeyError, KeyRing};

/// What the envelope seals: the content and the lineage it was derived from.
///
/// Integrity is the AEAD's: the envelope authenticates these bytes under the
/// item's identity, so no digest of the plaintext is stored beside them.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainMemory {
    content: serde_json::Value,
    derived_from: Vec<Selected>,
}

/// A memory store whose content is unreadable once its items' keys are destroyed.
pub struct EncryptedMemoryStore {
    inner: Arc<dyn MemoryStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
    lifecycle: Arc<dyn super::ErasureCoordinator>,
    /// Key destructions an erasure owes: rows already gone whose keys the ring
    /// refused to destroy.
    owed: Arc<tokio::sync::Mutex<Vec<OwedKey>>>,
}

/// One version's key an erasure still has to destroy.
#[derive(Debug)]
struct OwedKey {
    id: String,
    version: u64,
    at: Timestamp,
    reason: String,
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
    /// Single-node *by default*, not by construction: the lock is a seam. An
    /// active-active plane calls
    /// [`coordinated_by`](Self::coordinated_by) with a coordinator that spans
    /// instances — and [`is_distributed`](Self::is_distributed) is how a caller
    /// checks which it got, rather than inferring it from a constructor name.
    ///
    /// # Panics
    ///
    /// If `tenant` is not the tenant `inner` serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for why that pair is
    /// checked rather than trusted.
    #[must_use]
    pub fn new(inner: Arc<dyn MemoryStore>, keys: Arc<dyn KeyRing>, tenant: TenantId) -> Self {
        super::assert_serves(inner.tenant(), &tenant, "memory");
        Self {
            inner,
            keys,
            tenant,
            lifecycle: Arc::new(super::LocalCoordinator::new()),
            owed: Arc::default(),
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
    ///
    /// The cost is stated rather than implied: `remember` takes this lock on
    /// **every write**, so all of a tenant's memory writes serialise through
    /// it, and the coordinator's per-scope granularity buys this wrapper
    /// nothing — one tenant is one scope. That is a throughput ceiling, not a
    /// safety gap. What the single scope does *not* protect: nothing — it is
    /// strictly coarser than any finer scheme; what it forgoes is concurrency
    /// between one tenant's unrelated subjects. A deployment for which that
    /// ceiling matters needs id-addressed operations to learn their subject
    /// transactionally before a finer scope is sound; until then, wider and
    /// correct beats finer and racy.
    fn lifecycle_scope(&self) -> String {
        super::scope(&self.tenant, "memory-lifecycle")
    }

    /// The erasure scope of one version of one memory id.
    ///
    /// Per version rather than per id or per subject: `forget` and the expiry
    /// sweep erase ids, and a cascade erases ids *and* trims superseded
    /// versions of ids that stay current. Only a key that seals exactly one
    /// version can be destroyed by the trim without taking the current version
    /// along — a per-id key would survive the trim, and a backup would keep
    /// opening the version it removed. An id belongs to one subject and is never
    /// reused once erased, and versions only grow, so erasing an id destroys
    /// the scopes of versions `1..=` its highest.
    fn scope(&self, id: &str, version: u64) -> String {
        super::scope(&self.tenant, &format!("memory-item/{id}@{version}"))
    }

    /// The identity one stored version is sealed to.
    ///
    /// A canonical JSON array, so no field's content can spell another's: an
    /// envelope moved to another id, version, subject, purpose or tenant fails
    /// to authenticate there rather than opening as that row's content.
    fn aad(&self, item: &MemoryItem, version: u64) -> Result<Vec<u8>, StoreError> {
        crate::core::canon::to_bytes(&(
            "memory",
            self.tenant.as_str(),
            item.id.as_str(),
            version,
            item.subject.as_str(),
            item.purpose.as_str(),
        ))
        .map_err(|error| StoreError::Backend(error.to_string()))
    }

    async fn seal(&self, item: &MemoryItem, version: u64) -> Result<serde_json::Value, StoreError> {
        let plain = crate::core::canon::to_bytes(&PlainMemory {
            content: item.content.clone(),
            derived_from: item.derived_from.clone(),
        })
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        let envelope = super::envelope::seal(
            self.keys.as_ref(),
            &self.scope(&item.id, version),
            &self.aad(item, version)?,
            &plain,
        )
        .await
        .map_err(|error| match error {
            KeyError::Destroyed { .. } => StoreError::Backend(format!(
                "memory id '{}' was erased and cannot be reused",
                item.id
            )),
            other => key_error(other),
        })?;
        Ok(payload::wrap(&envelope))
    }

    /// `Ok(None)` when the row's key was destroyed — a completed erasure
    /// reporting itself, not a fault. Every other failure stays loud: a row
    /// that is not an envelope, an envelope that does not authenticate under
    /// this row's identity, a retired key version and an unreachable ring are
    /// all things someone must be told about, and folding them into the skip
    /// would make tampering read as erasure.
    async fn open_item(&self, mut item: MemoryItem) -> Result<Option<MemoryItem>, StoreError> {
        let envelope = payload::unwrap(&item.content).ok_or_else(|| {
            StoreError::Backend(
                "encrypted memory row does not contain a sealed envelope".to_owned(),
            )
        })?;
        let aad = self.aad(&item, item.version)?;
        let Some(plain) = super::envelope::open_or_erased(self.keys.as_ref(), &aad, &envelope)
            .await
            .map_err(key_error)?
        else {
            return Ok(None);
        };
        let plain: PlainMemory = serde_json::from_slice(&plain)
            .map_err(|error| StoreError::Backend(format!("encrypted memory: {error}")))?;
        item.content = plain.content;
        item.derived_from = plain.derived_from;
        Ok(Some(item))
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
        // An erased source cannot anchor new lineage: deriving from a version
        // whose key is destroyed would commit to content nobody can verify.
        let opened = self.open_item(stored.clone()).await?.ok_or_else(|| {
            StoreError::Backend(format!(
                "derived memory source '{}' version {} was erased",
                source.id, source.version
            ))
        })?;
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

    /// Destroy the keys of versions the inner store already erased — each
    /// entry an id and the versions of it that went — after whatever earlier
    /// erasures still owe.
    ///
    /// The rows are gone from the live store, so repeating the verb that
    /// erased them would find nothing: a key the ring refuses stays owed, and
    /// every later erasure verb destroys it first, failing while it cannot.
    /// The debt lives in this process; a restart before it is paid loses it,
    /// and the error names the scope to destroy by hand.
    async fn destroy_erased(
        &self,
        erased: &[(String, Vec<u64>)],
        at: Timestamp,
        reason: &str,
    ) -> Result<(), StoreError> {
        let mut owed = self.owed.lock().await;
        for (id, versions) in erased {
            owed.extend(versions.iter().map(|version| OwedKey {
                id: id.clone(),
                version: *version,
                at,
                reason: reason.to_owned(),
            }));
        }
        while let Some(key) = owed.first() {
            let scope = self.scope(&key.id, key.version);
            self.keys
                .destroy(&scope, key.at, &key.reason)
                .await
                .map_err(|error| {
                    StoreError::Backend(format!(
                        "memory '{}' version {} was erased from the store, and destroying its \
                         key failed ({error}) — its backups still open until scope '{scope}' is \
                         destroyed, which the next erasure retries",
                        key.id, key.version
                    ))
                })?;
            owed.remove(0);
        }
        Ok(())
    }

    /// Every version of each id, up to the highest it held.
    fn every_version(ids: impl IntoIterator<Item = (String, u64)>) -> Vec<(String, Vec<u64>)> {
        ids.into_iter()
            .map(|(id, highest)| (id, (1..=highest).collect()))
            .collect()
    }

    /// Each of `ids` with the highest version the store holds for it, read
    /// before an erasure removes the rows that say.
    async fn highest_versions(&self, ids: &[String]) -> Result<Vec<(String, u64)>, StoreError> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(current) = self.inner.current(id, None).await? {
                out.push((id.clone(), current.version));
            }
        }
        Ok(out)
    }

    /// Refuse when any of `ids` is under legal hold.
    async fn refuse_held(&self, ids: &[String]) -> Result<(), StoreError> {
        for id in ids {
            if self.inner.legal_hold(id).await? {
                return Err(StoreError::UnderLegalHold { id: id.clone() });
            }
        }
        Ok(())
    }

    /// Destroy every item key of a subject, then clean unreadable ciphertext.
    ///
    /// Holds are checked first, and a held item refuses the whole erasure with
    /// [`StoreError::UnderLegalHold`] before any key is touched. Then each of
    /// the subject's ids has its key destroyed — the erasure, reaching every
    /// copy — and only then are the live rows removed. A cleanup failure after
    /// the keys are gone is reported in [`Erasure::cleanup_failed`], not as
    /// success. The subject stays writable under new ids.
    ///
    /// `at` and `reason` come from the caller's audited lifecycle operation;
    /// this adapter never reads an ambient clock.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnderLegalHold`] naming a held item, or a failure to read
    /// the subject or destroy a key.
    pub async fn erase_subject(
        &self,
        subject: &str,
        at: Timestamp,
        reason: &str,
    ) -> Result<Erasure, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            // The subject's ids, enumerated by the dedicated erasure-path
            // operation rather than by a recall with an enormous limit. A
            // recall is a bounded content query, and a backend may cap or
            // refuse extreme limits — the PostgreSQL store refuses anything
            // past BIGINT — so an erasure riding one either failed outright or
            // silently checked holds for a truncated page of the subject.
            let ids = self.inner.subject_ids(subject).await?;
            self.refuse_held(&ids).await?;
            self.destroy_erased(&[], at, reason).await?;
            for (id, versions) in Self::every_version(self.highest_versions(&ids).await?) {
                for version in versions {
                    self.keys
                        .destroy(&self.scope(&id, version), at, reason)
                        .await
                        .map_err(key_error)?;
                }
            }
            Ok(match self.inner.forget_subject(subject).await {
                Ok(count) => Erasure {
                    reached: count,
                    cleanup_failed: None,
                },
                Err(error) => {
                    tracing::warn!(%subject, %error, "memory keys were destroyed but ciphertext cleanup failed");
                    Erasure {
                        reached: ids.len(),
                        cleanup_failed: Some(error.to_string()),
                    }
                }
            })
        })
        .await
    }
}

#[allow(clippy::needless_pass_by_value)]
fn key_error(error: KeyError) -> StoreError {
    StoreError::Backend(error.to_string())
}

/// The instant and reason a key destruction records for a verb that carries
/// neither: the trait's erasure verbs are addressed by id alone.
///
/// A wall-clock read, because the instant is the key ring's own record of when
/// the key went — descriptive metadata no run reads back and nothing replays.
/// Erasures that carry their caller's instant (`erase_subject`, the sweep)
/// record that instead.
#[allow(clippy::disallowed_methods)]
fn verb_erasure(verb: &str) -> (Timestamp, String) {
    (Timestamp::now_utc(), format!("memory {verb}"))
}

#[async_trait]
impl MemoryStore for EncryptedMemoryStore {
    fn tenant(&self) -> &str {
        self.tenant.as_str()
    }

    /// This store *does* have a lifecycle lock, so the answer is never `None` —
    /// and whether it spans instances is the coordinator's to say.
    fn erasure_is_distributed(&self) -> Option<bool> {
        Some(self.lifecycle.is_distributed())
    }

    fn seals(&self) -> bool {
        true
    }

    fn erasure_index(&self) -> Option<Arc<dyn crate::memory::SemanticRetriever>> {
        self.inner.erasure_index()
    }

    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            // The version is part of what the envelope is sealed to, and the
            // store assigns it: the next after the current one. Predicted here
            // under the lifecycle lock every write takes, and checked against
            // the store's answer, so a disagreement fails this write rather
            // than leaving a row that will never authenticate.
            let version = self
                .inner
                .current(&item.id, None)
                .await?
                .map_or(1, |current| current.version + 1);
            let mut sealed = item.clone();
            sealed.content = self.seal(item, version).await?;
            sealed.derived_from.clear();
            for source in &item.derived_from {
                sealed
                    .derived_from
                    .push(self.backing_selection(source).await?);
            }
            let written = self.inner.remember(&sealed).await?;
            if written != version {
                return Err(StoreError::Backend(format!(
                    "memory '{}' was sealed as version {version} and stored as {written}; \
                     the row will not open, so the write is refused",
                    item.id
                )));
            }
            Ok(written)
        })
        .await
    }

    // The read paths follow the skip-sealed convention SealedJournal and
    // SealedCases set: a row whose key was **destroyed** is a completed
    // erasure, and a completed erasure must not turn every later query about
    // the subject into a persistent error — which is exactly what happens when
    // an erasure destroys the keys and the ciphertext cleanup then fails.
    // Destroyed rows are silently absent from `recall` and `derivatives`, and
    // `version` answers `None` as it does for any erased version. What the
    // skip does **not** cover: rows that are not envelopes, envelopes that do
    // not authenticate under their row's identity, and an unreachable key ring
    // all stay loud, because those are faults to page about rather than
    // erasures reporting themselves.
    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError> {
        // A destroyed row is one the inner store's cleanup has not removed
        // yet, so a page can come back shorter than `limit` while more
        // readable rows exist past it — an erasure mid-cleanup, not a complete
        // answer, and it ends when the cleanup is retried.
        let items = self.inner.recall(query).await?;
        let mut opened = Vec::with_capacity(items.len());
        for item in items {
            if let Some(item) = self.open_item(item).await? {
                opened.push(item);
            }
        }
        Ok(opened)
    }

    async fn subject_ids(&self, subject: &str) -> Result<Vec<String>, StoreError> {
        // Ids are metadata and never sealed, so there is nothing to open —
        // and erasure needs this to work *after* the keys are gone.
        self.inner.subject_ids(subject).await
    }

    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError> {
        match self.inner.version(id, version).await? {
            Some(item) => self.open_item(item).await,
            None => Ok(None),
        }
    }

    async fn current(
        &self,
        id: &str,
        as_of: Option<Timestamp>,
    ) -> Result<Option<MemoryItem>, StoreError> {
        match self.inner.current(id, as_of).await? {
            Some(item) => self.open_item(item).await,
            None => Ok(None),
        }
    }

    /// Destroys the id's key, then removes its rows.
    ///
    /// The hold is checked first, so a held id loses nothing. A failure to
    /// remove the rows after the key is gone is an error naming it; retrying
    /// `forget` completes it.
    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.refuse_held(&[id.to_owned()]).await?;
            let (at, reason) = verb_erasure("forget");
            self.destroy_erased(&[], at, &reason).await?;
            for (id, versions) in
                Self::every_version(self.highest_versions(&[id.to_owned()]).await?)
            {
                for version in versions {
                    self.keys
                        .destroy(&self.scope(&id, version), at, &reason)
                        .await
                        .map_err(key_error)?;
                }
            }
            self.inner.forget(id).await.map_err(|error| {
                StoreError::Backend(format!(
                    "memory '{id}': its key is destroyed, so no copy opens, and removing its \
                     rows failed ({error}) — retry forget to remove them"
                ))
            })
        })
        .await
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            let ids = self.inner.subject_ids(subject).await?;
            let highest = self.highest_versions(&ids).await?;
            let count = self.inner.forget_subject(subject).await?;
            let (at, reason) = verb_erasure("forget_subject");
            self.destroy_erased(&Self::every_version(highest), at, &reason)
                .await?;
            Ok(count)
        })
        .await
    }

    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError> {
        let items = self.inner.derivatives(id).await?;
        let mut opened = Vec::with_capacity(items.len());
        for item in items {
            if let Some(item) = self.open_item(item).await? {
                opened.push(item);
            }
        }
        Ok(opened)
    }

    /// Destroys the key of every version of every id the cascade erased
    /// whole, and of exactly the versions it trimmed from ids that stay
    /// current — whose current version keeps its own key and stays readable,
    /// while a backup taken before the cascade no longer opens what it
    /// removed.
    async fn forget_cascading(&self, id: &str) -> Result<Cascade, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            let cascade = self.inner.forget_cascading(id).await?;
            let (at, reason) = verb_erasure("forget_cascading");
            self.destroy_erased(&Self::every_version(cascade.erased.clone()), at, &reason)
                .await?;
            self.destroy_erased(&cascade.trimmed, at, &reason).await?;
            Ok(cascade)
        })
        .await
    }

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            self.inner.set_legal_hold(id, held).await
        })
        .await
    }

    async fn legal_holds(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, StoreError> {
        // Ids are not sealed — only content is — so the listing passes straight
        // through. Sealing an id would make the hold register unreadable
        // without the very key an erasure destroys.
        self.inner.legal_holds(after, limit).await
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        self.inner.legal_hold(id).await
    }

    /// Destroys the key of every version of every id the sweep erased.
    async fn sweep_expired(&self, at: Timestamp) -> Result<Vec<(String, u64)>, StoreError> {
        super::under_lock(self.lifecycle.as_ref(), &self.lifecycle_scope(), || async {
            let swept = self.inner.sweep_expired(at).await?;
            self.destroy_erased(
                &Self::every_version(swept.clone()),
                at,
                "memory retention expired",
            )
            .await?;
            Ok(swept)
        })
        .await
    }

    async fn touch(&self, ids: &[String], at: Timestamp) -> Result<(), StoreError> {
        self.inner.touch(ids, at).await
    }
}
