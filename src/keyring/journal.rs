//! A journal whose payloads are sealed at rest.
//!
//! Wraps any [`JournalStore`], so both backends get this from one
//! implementation rather than two that agree everywhere except the boundary
//! nobody probed. Sealing happens on the way in, opening on the way out, and
//! nothing between the two knows.
//!
//! What is sealed and what is not is [`journal::payload`](crate::journal::payload)'s
//! decision, and the short version is: the caller's data is sealed, the
//! runtime's routing is not. Reading a sealed journal therefore needs a key;
//! *verifying* one does not.

use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{Digest, Epoch, RunId, StoreError, TenantId};
use crate::journal::{
    Append, Cancellation, Checkpoint, Head, Inclusion, JournalStore, Lease, Record, payload,
};

use super::KeyRing;

/// A [`JournalStore`] that seals payloads under a key ring.
#[derive(Debug)]
pub struct SealedJournal {
    inner: Arc<dyn JournalStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
}

impl SealedJournal {
    /// Seal this store's payloads under `keys`.
    ///
    /// `tenant` must be the tenant the wrapped store serves, and it is taken as
    /// an argument for the same reason [`SealedCases::wrap`](super::SealedCases::wrap)
    /// takes one: the *write* scope and the scope `erase_case` destroys have to
    /// agree byte for byte, so both are derived from one value supplied by one
    /// caller.
    ///
    /// Taking it as an argument is deliberately *not* the same as reading it
    /// back out of `inner.tenant()`, which looks like the safer shape — one
    /// fact, one source — and is not. [`JournalStore`] is a public seam, so an
    /// embedder's backend may return a name [`TenantId`] refuses, and any
    /// fallback for that case seals payloads under a scope `erase_case` never
    /// destroys: an erasure reporting success over readable bytes, which is the
    /// one failure in this module that is silent by construction. Supplied by
    /// the caller and asserted against the store, both scopes come from one
    /// value that cannot quietly become a default.
    ///
    /// # Panics
    ///
    /// If `tenant` is not the tenant `inner` serves — see
    /// [`SealedCases::wrap`](super::SealedCases::wrap) for why that pair is
    /// checked rather than trusted.
    #[must_use]
    pub fn wrap(
        inner: Arc<dyn JournalStore>,
        keys: Arc<dyn KeyRing>,
        tenant: TenantId,
    ) -> Arc<Self> {
        super::assert_serves(inner.tenant(), &tenant, "journal");
        Arc::new(Self {
            inner,
            keys,
            tenant,
        })
    }

    /// The erasure unit a record's payloads are sealed under.
    ///
    /// The **case** when the record has one, so `erase_case` — which already
    /// destroys that scope's wrapping key for blobs — reaches the journal's
    /// payloads by the same act, rather than through a second mechanism that
    /// could disagree with the first about what an erasure covered. A record
    /// bound to no case falls back to its run, which is still an erasure unit
    /// somebody can name.
    fn scope_for(&self, run: RunId, case: Option<crate::core::CaseId>) -> String {
        case.map_or_else(
            || super::scope(&self.tenant, &run.to_string()),
            |c| super::scope(&self.tenant, &c.to_string()),
        )
    }

    /// The associated data a record's payloads authenticate under.
    ///
    /// The ciphertext binds **tenant, record identity and purpose** as
    /// authenticated associated data, and each component here closes one move:
    ///
    /// * the purpose label separates this from every other envelope the same
    ///   ring seals, so a case-state envelope cannot be replayed as a journal
    ///   payload;
    /// * the tenant stops an envelope crossing tenants that happen to share a
    ///   ring (scopes already differ, but the AAD must not be the only thing
    ///   left agreeing);
    /// * the run stops an envelope lifted into another run's history from
    ///   opening as somebody else's data;
    /// * the record kind stops a payload moving between fields *within* a run
    ///   — an `EffectDone` output replayed as a `RunAdmitted` input;
    /// * the effect key (`-` when the record has none) pins an effect payload
    ///   to its effect, so one attempt's output cannot be presented as
    ///   another's.
    ///
    /// Position within a run needs no binding: the chain already covers it.
    /// The kind string is the serde tag, stable across upcasts, so a record
    /// written today still opens after a schema bump.
    fn aad(
        &self,
        run: RunId,
        kind: &crate::journal::RecordKind,
        effect: Option<crate::core::EffectKey>,
    ) -> String {
        format!(
            "journal:{}:{run}:{}:{}",
            self.tenant,
            kind.kind_str(),
            effect.map_or_else(|| "-".to_owned(), crate::core::EffectKey::to_hex),
        )
    }
}

fn sealing(e: &super::KeyError) -> StoreError {
    StoreError::Backend(format!("sealing a journal payload failed: {e}"))
}

#[async_trait]
impl JournalStore for SealedJournal {
    /// The durable state's answer, not this decorator's: sealing payloads
    /// changes what is readable, never how many writers there are.
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }

    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        let mut sealed = Vec::with_capacity(batch.len());
        for mut entry in batch {
            let scope = self.scope_for(entry.run, entry.case);
            let aad = self.aad(entry.run, &entry.kind, entry.effect_key);
            for field in payload::payloads(&mut entry.kind) {
                match field {
                    payload::SealedField::Value(field) => {
                        // Canonical bytes: the same reason every other digest
                        // input in this crate is canonical, and here it also
                        // means a payload seals identically however the map
                        // was built.
                        let plain = crate::core::canon::to_bytes(&*field).map_err(|e| {
                            StoreError::Backend(format!("a payload would not serialise: {e}"))
                        })?;
                        let envelope = super::envelope::seal(
                            self.keys.as_ref(),
                            &scope,
                            aad.as_bytes(),
                            &plain,
                        )
                        .await
                        .map_err(|e| sealing(&e))?;
                        *field = payload::wrap(&envelope);
                    }
                    // A text field seals over its UTF-8 bytes and is replaced
                    // by a marked string rather than an object, because the
                    // field's wire type is a string and the record must
                    // serialise with the same shape sealed or clear.
                    payload::SealedField::Text(field) => {
                        let envelope = super::envelope::seal(
                            self.keys.as_ref(),
                            &scope,
                            aad.as_bytes(),
                            field.as_bytes(),
                        )
                        .await
                        .map_err(|e| sealing(&e))?;
                        *field = payload::wrap_text(&envelope);
                    }
                }
            }
            sealed.push(entry);
        }
        // The inner store hashes what it is given, so the chain commits to the
        // ciphertext — which is what lets an auditor with no keys verify the
        // history of a run whose payloads have been erased.
        let written = self.inner.append(epoch, sealed).await?;
        // Handed back opened, so a caller cannot tell it wrote through a
        // sealed store — the runtime reads its own `EffectDone` output back on
        // the same values it just wrote.
        self.open_all(written).await
    }

    async fn read(&self, run: RunId, from: crate::core::Seq) -> Result<Vec<Record>, StoreError> {
        let records = self.inner.read(run, from).await?;
        self.open_all(records).await
    }

    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        let records = self.inner.case_history(case, limit).await?;
        self.open_all(records).await
    }

    async fn acquire(
        &self,
        run: RunId,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<Lease, StoreError> {
        self.inner.acquire(run, owner, ttl).await
    }

    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: std::time::Duration,
    ) -> Result<Lease, StoreError> {
        self.inner.renew(run, owner, epoch, ttl).await
    }

    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        self.inner.release_lease(run, epoch).await
    }

    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.abandoned_runs(limit).await
    }

    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    /// Delegated: an outcome is index metadata, never a sealed payload, so the
    /// count is answerable with no key at all — the same property that lets an
    /// auditor holding no keys still list a quarantine backlog.
    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, StoreError> {
        self.inner.count_by_outcome(outcome).await
    }

    /// Delegated, and the key is **not** sealed on the way through: it is the
    /// counterparty's message identity rather than content, and the index has to
    /// be searchable by a value the caller holds in the clear.
    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: crate::core::Timestamp,
    ) -> Result<usize, StoreError> {
        self.inner.forget_admissions(older_than).await
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }

    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        self.inner.head(run).await
    }

    async fn seal(&self, run: RunId, epoch: Epoch, outcome: &str) -> Result<Digest, StoreError> {
        self.inner.seal(run, epoch, outcome).await
    }

    async fn checkpoint(&self) -> Result<Checkpoint, StoreError> {
        self.inner.checkpoint().await
    }

    async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof(old_size).await
    }

    async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }

    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

impl SealedJournal {
    /// Open every sealed payload, leaving the record's bytes and hashes alone.
    ///
    /// A **read-time view**, exactly as upcasting is: `raw`, `hash` and
    /// `prev_hash` are untouched, so the chain still verifies over what was
    /// written and no proof changes meaning. A payload whose key has been
    /// destroyed stays sealed rather than failing the read — erasure is a
    /// completed operation, not an outage, and a run whose data is gone must
    /// still be listable, verifiable and auditable.
    async fn open_all(&self, records: Vec<Record>) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let run = record.body.run;
            let aad = self.aad(run, record.kind(), record.effect_key());
            let mut kind = record.kind().clone();
            let mut changed = false;
            for field in payload::payloads(&mut kind) {
                // A payload that will not open is left sealed on purpose: the
                // alternative — failing the read — would make a
                // cryptographically erased run unreadable *and* unauditable,
                // turning a discharged obligation into an outage.
                match field {
                    payload::SealedField::Value(field) => {
                        let Some(envelope) = payload::unwrap(field) else {
                            continue;
                        };
                        if let Ok(plain) =
                            super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope)
                                .await
                        {
                            *field = serde_json::from_slice(&plain)?;
                            changed = true;
                        }
                    }
                    payload::SealedField::Text(field) => {
                        let Some(envelope) = payload::unwrap_text(field) else {
                            continue;
                        };
                        if let Ok(plain) =
                            super::envelope::open(self.keys.as_ref(), aad.as_bytes(), &envelope)
                                .await
                            && let Ok(text) = String::from_utf8(plain)
                        {
                            *field = text;
                            changed = true;
                        }
                    }
                }
            }
            out.push(if changed {
                record.with_opened_kind(kind)
            } else {
                record
            });
        }
        Ok(out)
    }
}
