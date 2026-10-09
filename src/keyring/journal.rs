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
    Append, AtomicJournal, AtomicTx, AtomicWork, Cancellation, Checkpoint, Head, Inclusion,
    JournalStore, Lease, Record, payload,
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
        journal_aad(self.tenant.as_str(), run, kind, effect)
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
    fn seals(&self) -> bool {
        true
    }

    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        let (sealed, plain) = self.seal_batch(batch).await?;
        // The inner store hashes what it is given, so the chain commits to the
        // ciphertext — which is what lets an auditor with no keys verify the
        // history of a run whose payloads have been erased.
        let written = self.inner.append(epoch, sealed).await?;
        self.reopened(written, plain).await
    }

    fn atomic(&self) -> Option<&dyn AtomicJournal> {
        self.inner.atomic().map(|_| self as &dyn AtomicJournal)
    }

    async fn read(&self, run: RunId, from: crate::core::Seq) -> Result<Vec<Record>, StoreError> {
        let records = self.inner.read(run, from).await?;
        self.open_all(records).await
    }

    async fn read_page(
        &self,
        run: RunId,
        from: crate::core::Seq,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        let records = self.inner.read_page(run, from, limit).await?;
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

    async fn waiting_runs(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::journal::WaitingRun>, StoreError> {
        self.inner.waiting_runs(limit).await
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

    async fn runs_by_id(
        &self,
        after: Option<RunId>,
        limit: usize,
    ) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_id(after, limit).await
    }
    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }
    async fn recent_runs_from(
        &self,
        source: &str,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs_from(source, after, limit).await
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

    async fn consistency_proof_at(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof_at(old_size, new_size).await
    }

    async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }

    async fn inclusion_proof_at(
        &self,
        run: RunId,
        size: u64,
    ) -> Result<Option<Inclusion>, StoreError> {
        self.inner.inclusion_proof_at(run, size).await
    }

    async fn log_positions(
        &self,
        runs: &[RunId],
    ) -> Result<Vec<Option<(u64, crate::core::Digest)>>, StoreError> {
        self.inner.log_positions(runs).await
    }

    async fn request_cancel(
        &self,
        run: RunId,
        actor: &crate::core::Operator,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }

    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

/// The group's work, with every record it hands the store sealed first, so
/// plaintext never crosses into the inner transaction.
struct SealingWork<'a> {
    journal: &'a SealedJournal,
    work: &'a dyn AtomicWork,
    plain: std::sync::Mutex<Vec<crate::journal::RecordKind>>,
}

#[async_trait]
impl AtomicWork for SealingWork<'_> {
    async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, crate::core::EffectError> {
        let batch = self.work.run(tx).await?;
        let (sealed, plain) = self.journal.seal_batch(batch).await.map_err(|e| {
            crate::core::EffectError::Unavailable {
                driver: "keyring".to_owned(),
                detail: e.to_string(),
            }
        })?;
        *self
            .plain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = plain;
        Ok(sealed)
    }
}

#[async_trait]
impl AtomicJournal for SealedJournal {
    async fn append_atomic(
        &self,
        run: RunId,
        epoch: Epoch,
        work: &dyn AtomicWork,
    ) -> Result<Vec<Record>, StoreError> {
        let Some(inner) = self.inner.atomic() else {
            return Err(StoreError::Backend(
                "the sealed store has no transaction a resource can join".to_owned(),
            ));
        };
        let sealing = SealingWork {
            journal: self,
            work,
            plain: std::sync::Mutex::new(Vec::new()),
        };
        let written = inner.append_atomic(run, epoch, &sealing).await?;
        let plain = sealing
            .plain
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.reopened(written, plain).await
    }
}

impl SealedJournal {
    /// Seal every payload in `batch`, handing back the plaintext kinds beside
    /// the sealed appends.
    async fn seal_batch(
        &self,
        batch: Vec<Append>,
    ) -> Result<(Vec<Append>, Vec<crate::journal::RecordKind>), StoreError> {
        let mut sealed = Vec::with_capacity(batch.len());
        let mut plain = Vec::with_capacity(batch.len());
        for mut entry in batch {
            // Written bytes are stored as they stand, so a payload in them
            // would land in this store as whatever the bytes carry — plaintext,
            // in a store whose every other record is sealed — and sealing it
            // would change the bytes their hash covers. Neither is a write
            // this journal can make.
            if entry.written().is_some() {
                return Err(StoreError::Backend(
                    "a sealed journal cannot store written bytes: stored as they stand, \
                     their payloads would sit unsealed in a store that seals every payload, \
                     and sealed they would no longer hash as written — restore into the \
                     unwrapped store"
                        .to_owned(),
                ));
            }
            plain.push(entry.kind.clone());
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
        Ok((sealed, plain))
    }

    /// What was just written, handed back with the plaintext it was given.
    ///
    /// A caller cannot tell it wrote through a sealed store, and the write is
    /// never re-opened: once committed, a key service failing is not a reason
    /// to report the write as failed.
    async fn reopened(
        &self,
        written: Vec<Record>,
        plain: Vec<crate::journal::RecordKind>,
    ) -> Result<Vec<Record>, StoreError> {
        if written.len() != plain.len() {
            return self.open_all(written).await;
        }
        Ok(written
            .into_iter()
            .zip(plain)
            .map(|(record, kind)| record.with_opened_kind(kind))
            .collect())
    }

    /// Open every sealed payload, leaving the record's bytes and hashes alone.
    ///
    /// A **read-time view**, exactly as upcasting is: `raw`, `hash` and
    /// `prev_hash` are untouched, so the chain still verifies over what was
    /// written and no proof changes meaning. A payload whose key has been
    /// **destroyed** stays sealed rather than failing the read — erasure is a
    /// completed operation, not an outage, and a run whose data is gone must
    /// still be listable, verifiable and auditable.
    ///
    /// Every other key failure fails the read. A key service that cannot be
    /// reached is a transient fault whose remedy is waiting; reported as a
    /// sealed payload it is indistinguishable from a discharged erasure, and
    /// the two call for opposite actions — one is *come back later*, the other
    /// is *this is gone for good*. `open_or_erased` is where that line is
    /// drawn.
    ///
    /// # Errors
    ///
    /// Whatever the ring said, for every cause but a destroyed key.
    async fn open_all(&self, records: Vec<Record>) -> Result<Vec<Record>, StoreError> {
        let mut out = Vec::with_capacity(records.len());
        for record in records {
            let mut kind = record.kind().clone();
            let opened = open_payloads(
                self.keys.as_ref(),
                self.tenant.as_str(),
                record.body.run,
                record.effect_key(),
                &mut kind,
            )
            .await?;
            out.push(if opened.opened > 0 {
                record.with_opened_kind(kind)
            } else {
                record
            });
        }
        Ok(out)
    }
}

/// The associated data a journal payload authenticates under.
///
/// The ciphertext binds **tenant, record identity and purpose** — see
/// [`SealedJournal`]'s own `aad` for what each component closes. A free
/// function because an offline reader of an export opens the same payloads
/// under the same binding without a store.
pub(crate) fn journal_aad(
    tenant: &str,
    run: RunId,
    kind: &crate::journal::RecordKind,
    effect: Option<crate::core::EffectKey>,
) -> String {
    format!(
        "journal:{tenant}:{run}:{}:{}",
        kind.kind_str(),
        effect.map_or_else(|| "-".to_owned(), crate::core::EffectKey::to_hex),
    )
}

/// What opening one record's sealed payloads found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Opened {
    /// Payloads this call turned back into their plaintext.
    pub(crate) opened: usize,
    /// Payloads whose key has been **destroyed**: erased, for good.
    pub(crate) erased: usize,
}

/// Open every sealed payload `kind` carries, in place.
///
/// The one opener: [`SealedJournal`] reads through it, and so does
/// `policy check` over an export, so the two cannot disagree about which
/// payload is erased and which merely sealed. A payload whose key was
/// destroyed stays sealed and is counted in [`Opened::erased`] — erasure is a
/// completed operation, not an outage. Every other key failure is an error: a
/// ring that cannot be reached reported as an erasure is indistinguishable
/// from one, and the two call for opposite actions.
///
/// # Errors
///
/// Whatever the ring said, for every cause but a destroyed key; or opened
/// bytes that do not parse as the field they replace.
pub(crate) async fn open_payloads(
    keys: &dyn KeyRing,
    tenant: &str,
    run: RunId,
    effect: Option<crate::core::EffectKey>,
    kind: &mut crate::journal::RecordKind,
) -> Result<Opened, StoreError> {
    let aad = journal_aad(tenant, run, kind, effect);
    let mut found = Opened::default();
    for field in payload::payloads(kind) {
        match field {
            payload::SealedField::Value(field) => {
                let Some(envelope) = payload::unwrap(field) else {
                    continue;
                };
                match super::envelope::open_or_erased(keys, aad.as_bytes(), &envelope)
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                {
                    Some(plain) => {
                        *field = serde_json::from_slice(&plain)?;
                        found.opened += 1;
                    }
                    None => found.erased += 1,
                }
            }
            payload::SealedField::Text(field) => {
                let Some(envelope) = payload::unwrap_text(field) else {
                    continue;
                };
                match super::envelope::open_or_erased(keys, aad.as_bytes(), &envelope)
                    .await
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                {
                    Some(plain) => {
                        *field = String::from_utf8(plain).map_err(|e| {
                            StoreError::Backend(format!(
                                "a sealed text payload opened to bytes that are not UTF-8: {e}"
                            ))
                        })?;
                        found.opened += 1;
                    }
                    None => found.erased += 1,
                }
            }
        }
    }
    Ok(found)
}

#[cfg(all(test, feature = "testkit"))]
mod tests {
    use super::{journal_aad, open_payloads, payload};
    use crate::core::RunId;
    use crate::journal::RecordKind;

    /// A text field whose plaintext is not UTF-8 is an error, not a payload
    /// left sealed and counted as neither opened nor erased.
    #[tokio::test]
    async fn a_text_payload_that_opens_to_non_utf8_is_an_error() {
        let keys = crate::testkit::MemoryKeyRing::default();
        let run = RunId::generate();
        let probe = RecordKind::Note {
            text: String::new(),
        };
        let aad = journal_aad("t", run, &probe, None);
        let envelope = super::super::envelope::seal(&keys, "t/run", aad.as_bytes(), &[0xff, 0xfe])
            .await
            .expect("seal");
        let mut kind = RecordKind::Note {
            text: payload::wrap_text(&envelope),
        };
        let opened = open_payloads(&keys, "t", run, None, &mut kind).await;
        assert!(
            opened.is_err(),
            "non-UTF-8 plaintext was left sealed and reported as {opened:?}"
        );
    }

    /// **A historical consistency proof reaches the store beneath the seal.**
    ///
    /// A witness submission proves an older checkpoint against the one it
    /// carries, while runs keep sealing. Answered by the trait's default
    /// rather than the store's own, the proof exists only while the live log
    /// is exactly the size asked for, so a sealed plane's submission failed
    /// whenever a run sealed mid-submission.
    #[cfg(feature = "redb")]
    #[tokio::test]
    async fn a_historical_consistency_proof_reaches_the_store_beneath() {
        use std::sync::Arc;

        use crate::journal::{Append, JournalStore};

        let tenant = crate::core::TenantId::default();
        let raw = Arc::new(crate::store::RedbStore::open_in_memory().expect("store"))
            as Arc<dyn JournalStore>;
        let sealed = super::SealedJournal::wrap(
            Arc::clone(&raw),
            Arc::new(crate::testkit::MemoryKeyRing::new()),
            tenant,
        );
        let mut sizes = Vec::new();
        for _ in 0..3 {
            let run = RunId::generate();
            let lease = sealed
                .acquire(run, "proof", std::time::Duration::from_mins(1))
                .await
                .expect("lease");
            sealed
                .append(
                    lease.epoch,
                    vec![Append::new(
                        run,
                        RecordKind::Note {
                            text: "probe".into(),
                        },
                    )],
                )
                .await
                .expect("append");
            let head = sealed.head(run).await.expect("head");
            sealed
                .append(
                    lease.epoch,
                    vec![Append::new(
                        run,
                        RecordKind::RunConcluded {
                            outcome: "succeeded".to_owned(),
                            chain_head: head.hash,
                            reason: None,
                            exhaustion: None,
                            live_spend: crate::core::Spend::default(),
                        },
                    )],
                )
                .await
                .expect("conclude");
            sealed
                .seal(run, lease.epoch, "succeeded")
                .await
                .expect("seal");
            sizes.push(sealed.checkpoint().await.expect("checkpoint").size);
        }
        let (old, new) = (sizes[0], sizes[1]);
        assert_eq!(
            sealed
                .consistency_proof_at(old, new)
                .await
                .expect("a proof between two past sizes"),
            raw.consistency_proof_at(old, new)
                .await
                .expect("the store's proof"),
        );
    }
}
