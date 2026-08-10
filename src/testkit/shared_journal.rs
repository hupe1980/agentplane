//! A journal double that answers `is_shared()` differently from what it wraps.
//!
//! `is_shared()` is the answer the runtime refuses configurations on, and
//! exercising that refusal should not need a database — the check is about two
//! answers meeting, not about `PostgreSQL`.

use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{Epoch, RunId, StoreError};
use crate::journal::{Append, AtomicJournal, JournalStore, Record};

/// A journal that claims to be shared, over one that is not.
///
/// Everything but the claim delegates, so a run through this behaves exactly
/// like a run through what it wraps.
#[derive(Debug)]
pub struct SharedJournal {
    inner: Arc<dyn JournalStore>,
}

impl SharedJournal {
    #[must_use]
    pub fn new(inner: Arc<dyn JournalStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl JournalStore for SharedJournal {
    /// The whole point of this double.
    fn is_shared(&self) -> bool {
        true
    }

    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    fn atomic(&self) -> Option<&dyn AtomicJournal> {
        self.inner.atomic()
    }

    async fn append(&self, epoch: Epoch, batch: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        self.inner.append(epoch, batch).await
    }

    async fn read(&self, run: RunId, from: crate::core::Seq) -> Result<Vec<Record>, StoreError> {
        self.inner.read(run, from).await
    }

    async fn acquire(
        &self,
        run: RunId,
        owner: &str,
        ttl: std::time::Duration,
    ) -> Result<crate::journal::Lease, StoreError> {
        self.inner.acquire(run, owner, ttl).await
    }

    async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
        self.inner.release_lease(run, epoch).await
    }

    async fn runs_by_outcome(
        &self,
        outcome: &str,
        limit: usize,
    ) -> Result<Vec<crate::core::RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }

    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
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

    async fn inclusion_proof(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Inclusion>, StoreError> {
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

    async fn cancellation(
        &self,
        run: RunId,
    ) -> Result<Option<crate::journal::Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}
