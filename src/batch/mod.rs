//! Batch runs — one plan, many items, per-item durability.
//!
//! # Why a batch is not a run, and not N unrelated runs
//!
//! A Jahresabrechnung over 10⁵ `Marktlokationen`, or a `MaBiS` `Clearingliste` across
//! a Bilanzierungsgebiet, is a single business act made of many independent
//! ones. Modelling it as *one run* means one journal, one budget, and one
//! failure: item 60,000 fails and the run fails, so the 59,999 settlements that
//! worked are trapped inside a failed audit record. Modelling it as *N unrelated
//! runs* loses the act — nobody can answer "did the Jahresabrechnung finish", or
//! "what did it cost", because there is no it.
//!
//! So a batch is a first-class object that owns N runs sharing one frozen plan.
//! Each item gets its own journal, its own budget, and its own outcome. The
//! batch gets a cursor, a census of what happened, and a terminal state.
//!
//! # Partial failure is a terminal state, not a degraded success
//!
//! [`BatchStatus`] has no `Succeeded`. A finished batch is
//! [`BatchStatus::Completed`] carrying counts, so a caller cannot write
//! `if status.is_ok()` and skip the 43 items that did not settle. "Mostly
//! worked" is the single most dangerous thing a batch can report, because it is
//! reported as success everywhere it is not explicitly handled — and the items
//! that failed are precisely the ones a human needed to hear about.
//!
//! Reading the outcome forces a decision:
//!
//! ```text
//! match report.status {
//!     BatchStatus::Completed { failed: 0, quarantined: 0, succeeded } => ok(succeeded),
//!     BatchStatus::Completed { failed, quarantined, .. } => escalate(failed, quarantined),
//!     BatchStatus::Running => still_going(),
//! }
//! ```
//!
//! # Resume is the effect protocol, one level up
//!
//! An item is processed exactly the way an effect is performed: **announce, act,
//! record.** Before an item runs, its run id is written to the batch store
//! ([`BatchStore::reserve`]); then the run happens; then the outcome is recorded.
//!
//! That ordering is what makes item-granular resume work, and it is worth being
//! precise about why. A crash between reserve and record leaves an item marked
//! started with a known run id. Resume finds it, and **replays that run** rather
//! than starting a new one — so the item's effects are read back from its
//! journal instead of performed again. Exactly-once for a batch item is not new
//! machinery; it is the run-level guarantee, addressed by a stored id.
//!
//! The cursor is therefore an *optimisation*, not a correctness mechanism. If it
//! were lost entirely, re-processing every item would be safe — slow, but not
//! wrong. That is the property to preserve when changing anything here.
//!
//! # Input is streamed, never materialised
//!
//! [`ItemSource`] is a cursor, not a `Vec`. A batch over 10⁵ meters must not
//! require 10⁵ items in memory, and — more subtly — must not require the caller
//! to have *produced* them all before the first one runs. A source that reads
//! from a database, a file, or a paged API is the normal case.

use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{BatchId, RunId, Spend, StoreError};

/// One unit of work in a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchItem {
    /// Stable, unique within the batch, and **ordered**.
    ///
    /// Ordering is what lets the cursor be a single value rather than a set of
    /// seen keys, which for 10⁵ items is the difference between a resume that
    /// reads one row and one that reads the whole batch. A meter number, a
    /// document id, or a zero-padded sequence all work; a random uuid does not,
    /// because "everything after this key" then means nothing.
    pub key: String,
    /// What the plan receives as run input for this item.
    pub input: Value,
}

impl BatchItem {
    pub fn new(key: impl Into<String>, input: Value) -> Self {
        Self {
            key: key.into(),
            input,
        }
    }
}

/// A source could not produce items.
///
/// Distinct from `StoreError` because an [`ItemSource`] is the embedder's code
/// reading the embedder's system — a meter register, a paged API, a file. Making
/// it a store error would say the *plane's* storage failed, sending an operator
/// to look at the wrong thing.
#[derive(Debug, Clone, thiserror::Error)]
#[error("batch source: {0}")]
pub struct SourceError(String);

impl SourceError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

/// Where a batch's work comes from.
///
/// A cursor rather than a collection — see the module docs on why input is never
/// materialised.
#[async_trait]
pub trait ItemSource: Send + Sync + Debug {
    /// The next page of items strictly after `after`, in key order.
    ///
    /// Returning fewer than `limit` items does **not** mean the source is
    /// exhausted; returning zero does. The distinction matters for sources that
    /// page unevenly, and conflating them truncates a batch silently — which is
    /// the failure mode this whole crate exists to make loud.
    async fn next(&self, after: Option<&str>, limit: usize) -> Result<Vec<BatchItem>, SourceError>;
}

/// How one item ended.
///
/// Mirrors `RunStatus` but deliberately coarser: a batch's census is about what
/// a human must do next, and "failed" and "exhausted" both mean *this item did
/// not settle*. The item's own run journal holds the detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemOutcome {
    Succeeded,
    /// Ran and did not settle — a failure, or a limit.
    Failed(String),
    /// Set aside for a human. Distinct from failed because the *response* is
    /// different: a failed item may be re-run, a quarantined one must not be
    /// touched until someone has looked at it.
    Quarantined(String),
    /// Waiting on something — an event, a person, a timer.
    ///
    /// Not terminal. A batch that suspends items is not finished, and counting a
    /// suspension as a failure would send someone to investigate a run that is
    /// working exactly as designed.
    Suspended(String),
    /// Paused at a ceiling. Not terminal, and deliberately not `Failed`: the
    /// item's run is intact and stays open — an operator's two honest moves
    /// are raise the ceiling and resume, or cancel — and a pause reported as
    /// a fault teaches the reader to re-run work that is standing. The string
    /// names the ceiling that was hit.
    Exhausted(String),
}

impl ItemOutcome {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed(_) => "failed",
            Self::Quarantined(_) => "quarantined",
            Self::Suspended(_) => "suspended",
            Self::Exhausted(_) => "exhausted",
        }
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !matches!(self, Self::Suspended(_) | Self::Exhausted(_))
    }
}

/// What a batch has done, and whether it is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    /// Items remain, or some are still suspended.
    Running,
    /// Every item reached a terminal outcome.
    ///
    /// Note the absence of a `Succeeded` variant: see the module docs. A caller
    /// must read the counts to know what happened, because there is no way to
    /// spell "it worked" that skips them.
    Completed {
        succeeded: u64,
        failed: u64,
        quarantined: u64,
    },
}

impl BatchStatus {
    /// Whether every item settled.
    ///
    /// Named for what it asserts rather than `is_ok`: the question a caller
    /// usually means is "is there anything to do", and a batch with 43 failures
    /// answers yes.
    #[must_use]
    pub const fn everything_settled(&self) -> bool {
        matches!(
            self,
            Self::Completed {
                failed: 0,
                quarantined: 0,
                ..
            }
        )
    }
}

/// One item's record within a batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRecord {
    pub key: String,
    /// The run that processed it. Stable across resume — replaying this id is
    /// what makes re-processing safe.
    pub run: RunId,
    /// `None` while the item is reserved but not yet finished.
    pub outcome: Option<ItemOutcome>,
    /// What this item consumed, so "what did the settlement run cost" is a sum
    /// rather than an estimate.
    pub spend: Spend,
}

/// What a batch cost and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchReport {
    pub id: BatchId,
    pub status: BatchStatus,
    /// Items reserved but not yet terminal — suspended, or interrupted.
    pub in_flight: u64,
    /// The whole batch's consumption, summed from its items.
    pub spend: Spend,
    /// The key processing stopped after, for a resume.
    pub cursor: Option<String>,
}

/// Durable batch state.
///
/// Separate from the journal because a batch is not a run: it has no hash chain
/// of its own, and its integrity comes from the per-item runs it points at. What
/// it needs is a cursor, a reservation, and a census — three queries, not a log.
#[async_trait]
pub trait BatchStore: Send + Sync + Debug {
    /// Register a batch. Idempotent on `id`, so a retried submission does not
    /// fork one act into two.
    async fn open(&self, id: BatchId, plan_digest: &str) -> Result<(), StoreError>;

    /// Record that the source produced its last item.
    ///
    /// Without this a batch cannot tell "every item I have stored is terminal"
    /// from "I am finished" — and those differ every time processing stops
    /// early. A batch halted after 10,000 of 100,000 items has no unfinished
    /// item anywhere in its store, so a census alone would report it complete
    /// with 90,000 meters unsettled.
    ///
    /// Durable rather than in-memory because the distinction has to survive the
    /// process: a resumed batch must know whether it ever reached the end.
    async fn mark_exhausted(&self, id: BatchId) -> Result<(), StoreError>;

    /// Whether the source has been read to the end.
    async fn is_exhausted(&self, id: BatchId) -> Result<bool, StoreError>;

    /// Claim an item and bind it to a run id, **before** the run starts.
    ///
    /// Returns the existing record if the item was already reserved — which is
    /// what makes a crashed batch resumable: the second attempt gets the first
    /// attempt's run id back and replays it rather than starting fresh.
    async fn reserve(
        &self,
        batch: BatchId,
        key: &str,
        run: RunId,
    ) -> Result<ItemRecord, StoreError>;

    /// Record how an item ended, and what it consumed.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] when the item was never reserved. Both shipped
    /// backends once returned `Ok` while writing nothing there — a caller told
    /// *recorded* over an outcome that vanished, which is the same lie a
    /// release that freed nothing tells, and it is caught by the row count the
    /// write already produces.
    async fn record(
        &self,
        batch: BatchId,
        key: &str,
        outcome: &ItemOutcome,
        spend: Spend,
    ) -> Result<(), StoreError>;

    /// The highest key whose item reached a terminal outcome, with no
    /// unfinished item before it.
    ///
    /// The contiguous prefix, not the maximum: an item suspended at key 400 must
    /// hold the cursor at 399 even if 401 through 500 have finished, or a resume
    /// would step over it and the batch would report complete with an item still
    /// waiting.
    async fn cursor(&self, batch: BatchId) -> Result<Option<String>, StoreError>;

    /// Counts by outcome, plus reserved-but-unfinished.
    async fn census(&self, batch: BatchId) -> Result<BatchCensus, StoreError>;

    /// Every item record, oldest key first. For operators and for tests; the
    /// driver uses `cursor` and `census`.
    async fn items(&self, batch: BatchId, limit: usize) -> Result<Vec<ItemRecord>, StoreError>;
}

/// A batch's tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchCensus {
    pub succeeded: u64,
    pub failed: u64,
    pub quarantined: u64,
    pub suspended: u64,
    /// Paused at a ceiling — resumable once somebody raises it.
    pub exhausted: u64,
    /// Reserved with no outcome recorded — an item interrupted mid-flight.
    pub in_flight: u64,
    pub spend: Spend,
}

impl BatchCensus {
    /// Items that will not change without intervention.
    #[must_use]
    pub const fn terminal(&self) -> u64 {
        self.succeeded + self.failed + self.quarantined
    }
}
