//! The journal a resume pass writes through.
//!
//! A resume that owes the quota ledger a settlement marks its pass in the
//! journal, so recovery can settle what the pass spent if its process dies.
//! The marker rides the pass's **first append** to its run, in the same batch:
//! a pass that writes nothing — a resume reaching the conclusion the record
//! already holds — leaves no marker. Every reader that takes a run's status
//! from its last record depends on that.
//!
//! A conclusion names the head it is drawn over, so when it is the pass's first
//! write the marker is appended alone just before it and the conclusion is
//! drawn over the marker. A crash between the two leaves an unconcluded run
//! ending in a marker, which recovery resumes like any other.

use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{EffectError, Epoch, RunId, StoreError};
use crate::journal::{
    Append, AtomicJournal, AtomicTx, AtomicWork, JournalStore, Record, RecordKind,
};

/// A journal that prepends one pass marker to the first batch written to `run`.
#[derive(Debug)]
pub(crate) struct PassJournal {
    inner: Arc<dyn JournalStore>,
    run: RunId,
    marker: tokio::sync::Mutex<Option<RecordKind>>,
}

impl PassJournal {
    pub(crate) fn new(inner: Arc<dyn JournalStore>, run: RunId, marker: RecordKind) -> Self {
        Self {
            inner,
            run,
            marker: tokio::sync::Mutex::new(Some(marker)),
        }
    }

    /// The marker as an append beside `batch`'s first record for this run,
    /// carrying that record's case.
    fn marker_for(&self, kind: &RecordKind, batch: &[Append]) -> Option<Append> {
        let first = batch.iter().find(|a| a.run == self.run)?;
        let mut marker = Append::new(self.run, kind.clone());
        marker.case = first.case;
        Some(marker)
    }

    /// The index of `batch`'s first record for this run when that record is a
    /// conclusion.
    fn leading_conclusion(&self, batch: &[Append]) -> Option<usize> {
        let first = batch.iter().position(|a| a.run == self.run)?;
        matches!(batch[first].kind, RecordKind::RunConcluded { .. }).then_some(first)
    }
}

/// Strip the marker's record from what the store hands back, so a caller sees
/// exactly the records it asked for.
fn without_marker(mut written: Vec<Record>) -> Vec<Record> {
    if !written.is_empty() {
        written.remove(0);
    }
    written
}

#[async_trait]
impl JournalStore for PassJournal {
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }
    fn seals(&self) -> bool {
        self.inner.seals()
    }

    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    fn atomic(&self) -> Option<&dyn AtomicJournal> {
        self.inner.atomic().map(|_| self as &dyn AtomicJournal)
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        let mut pending = self.marker.lock().await;
        let Some(marker) = pending
            .as_ref()
            .and_then(|kind| self.marker_for(kind, &batch))
        else {
            drop(pending);
            return self.inner.append(epoch, batch).await;
        };
        if let Some(conclusion) = self.leading_conclusion(&batch) {
            let written = self.inner.append(epoch, vec![marker]).await?;
            *pending = None;
            let mut batch = batch;
            if let Some(marker) = written.last()
                && let RecordKind::RunConcluded { chain_head, .. } = &mut batch[conclusion].kind
                && *chain_head == marker.prev_hash
            {
                *chain_head = marker.hash;
            }
            drop(pending);
            return self.inner.append(epoch, batch).await;
        }
        let mut with_marker = Vec::with_capacity(batch.len() + 1);
        with_marker.push(marker);
        with_marker.extend(batch);
        let written = self.inner.append(epoch, with_marker).await?;
        *pending = None;
        Ok(without_marker(written))
    }

    async fn read(&self, run: RunId, from: crate::core::Seq) -> Result<Vec<Record>, StoreError> {
        self.inner.read(run, from).await
    }

    async fn read_page(
        &self,
        run: RunId,
        from: crate::core::Seq,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        self.inner.read_page(run, from, limit).await
    }

    async fn acquire(
        &self,
        run: RunId,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<crate::journal::Lease, StoreError> {
        self.inner.acquire(run, owner, ttl).await
    }

    async fn renew(
        &self,
        run: RunId,
        owner: &str,
        epoch: Epoch,
        ttl: std::time::Duration,
    ) -> Result<crate::journal::Lease, StoreError> {
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

    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: crate::core::Timestamp,
    ) -> Result<usize, StoreError> {
        self.inner.forget_admissions(older_than).await
    }

    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    async fn count_by_outcome(&self, outcome: &str) -> Result<u64, StoreError> {
        self.inner.count_by_outcome(outcome).await
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

    async fn case_history(
        &self,
        case: crate::core::CaseId,
        limit: usize,
    ) -> Result<Vec<Record>, StoreError> {
        self.inner.case_history(case, limit).await
    }

    async fn head(&self, run: RunId) -> Result<crate::journal::Head, StoreError> {
        self.inner.head(run).await
    }

    async fn seal(
        &self,
        run: RunId,
        epoch: Epoch,
        outcome: &str,
    ) -> Result<crate::core::Digest, StoreError> {
        self.inner.seal(run, epoch, outcome).await
    }

    async fn checkpoint(&self) -> Result<crate::journal::Checkpoint, StoreError> {
        self.inner.checkpoint().await
    }

    async fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<Vec<crate::core::Digest>, StoreError> {
        self.inner.consistency_proof(old_size).await
    }

    async fn consistency_proof_at(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<Vec<crate::core::Digest>, StoreError> {
        self.inner.consistency_proof_at(old_size, new_size).await
    }

    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }

    async fn inclusion_proof_at(
        &self,
        run: RunId,
        size: u64,
    ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
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

    async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }

    async fn verify(&self, run: RunId) -> Result<crate::core::Digest, StoreError> {
        self.inner.verify(run).await
    }
}

/// The pass's work, with the marker ahead of whatever records it returns
/// for the pass's run.
struct MarkedWork<'a> {
    work: &'a dyn AtomicWork,
    journal: &'a PassJournal,
    kind: &'a RecordKind,
    marked: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl AtomicWork for MarkedWork<'_> {
    async fn run(&self, tx: &dyn AtomicTx) -> Result<Vec<Append>, EffectError> {
        let batch = self.work.run(tx).await?;
        let Some(marker) = self.journal.marker_for(self.kind, &batch) else {
            return Ok(batch);
        };
        self.marked
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut with_marker = Vec::with_capacity(batch.len() + 1);
        with_marker.push(marker);
        with_marker.extend(batch);
        Ok(with_marker)
    }
}

#[async_trait]
impl AtomicJournal for PassJournal {
    async fn append_atomic(
        &self,
        run: RunId,
        epoch: Epoch,
        work: &dyn AtomicWork,
    ) -> Result<Vec<Record>, StoreError> {
        let Some(inner) = self.inner.atomic() else {
            return Err(StoreError::Backend(
                "the pass journal's store has no transaction a resource can join".to_owned(),
            ));
        };
        let mut pending = self.marker.lock().await;
        let Some(kind) = pending.clone().filter(|_| run == self.run) else {
            drop(pending);
            return inner.append_atomic(run, epoch, work).await;
        };
        let marked = MarkedWork {
            work,
            journal: self,
            kind: &kind,
            marked: std::sync::atomic::AtomicBool::new(false),
        };
        let written = inner.append_atomic(run, epoch, &marked).await?;
        if !marked.marked.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(written);
        }
        *pending = None;
        Ok(without_marker(written))
    }
}
