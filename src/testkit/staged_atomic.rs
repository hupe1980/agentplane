//! A journal that lends a transaction, for tests that have no database.
//!
//! # What this proves, and what it cannot
//!
//! It proves the **runtime's** half of the contract: that atomic members run at
//! the frontier and not before, that a member which refuses takes the whole
//! group's statements with it, that a replayed run does not apply them a second
//! time, and that the group settles inside the same unit as the work.
//!
//! It cannot prove **atomicity**. Nothing here is a transaction: statements are
//! staged in memory and applied together at the end, which models the contract
//! rather than implementing it. A fixture that could demonstrate atomicity would
//! be a database. The real property is checked against Postgres, in the
//! conformance battery, where a `ROLLBACK` is a rollback.
//!
//! Saying so matters more than usual here, because a green test named
//! "the transaction rolled back" against this fixture would be evidence about
//! the fixture.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{Epoch, RunId, StoreError};
use crate::journal::{Append, AtomicJournal, AtomicTx, AtomicWork, JournalStore, Record, SqlValue};

/// One statement a resource ran.
pub type Statement = (String, Vec<SqlValue>);

/// A journal store that lends a (simulated) transaction.
///
/// Wraps any store and adds the capability. Every other method delegates, so a
/// test gets a real journal with one extra thing it can do.
#[derive(Debug)]
pub struct StagedAtomic {
    inner: Arc<dyn JournalStore>,
    applied: Mutex<Vec<Statement>>,
}

impl StagedAtomic {
    #[must_use]
    pub fn wrap(inner: Arc<dyn JournalStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            applied: Mutex::new(Vec::new()),
        })
    }

    /// Statements that were actually applied, in order.
    ///
    /// Empty for a unit of work that refused: its statements were staged and
    /// discarded, which is what a rollback would have done to them.
    #[must_use]
    pub fn applied(&self) -> Vec<Statement> {
        self.applied.lock().expect("staged").clone()
    }
}

/// Collects statements until the whole unit of work succeeds.
#[derive(Debug, Default)]
struct Staging(Mutex<Vec<Statement>>);

#[async_trait]
impl AtomicTx for Staging {
    async fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, StoreError> {
        self.0
            .lock()
            .expect("staging")
            .push((sql.to_owned(), params.to_vec()));
        Ok(1)
    }

    async fn query(&self, _sql: &str, _params: &[SqlValue]) -> Result<Vec<Value>, StoreError> {
        // Reads are not modelled: a fixture that answered them would be
        // answering from a database it does not have, and a resource written
        // against invented rows is a resource nothing checked.
        Err(StoreError::Backend(
            "this fixture stages writes and does not answer queries — read from a \
             real database, or do not read"
                .to_owned(),
        ))
    }
}

#[async_trait]
impl AtomicJournal for StagedAtomic {
    async fn append_atomic(
        &self,
        _run: RunId,
        epoch: Epoch,
        work: &dyn AtomicWork,
    ) -> Result<Vec<Record>, StoreError> {
        let staging = Staging::default();
        // A refusal discards the staged statements, exactly as a rollback
        // discards uncommitted ones — and, crucially, the records are never
        // appended either. The two failing together is the contract.
        let batch = work
            .run(&staging)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let sealed = self.inner.append(epoch, batch).await?;
        self.applied
            .lock()
            .expect("staged")
            .extend(staging.0.lock().expect("staging").drain(..));
        Ok(sealed)
    }
}

#[async_trait]
impl JournalStore for StagedAtomic {
    fn tenant(&self) -> &str {
        self.inner.tenant()
    }

    fn atomic(&self) -> Option<&dyn AtomicJournal> {
        Some(self)
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
