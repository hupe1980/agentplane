//! Case storage: correlation, state, obligations, and inbound events.

mod events;
mod tasks;
mod timers;

pub use events::{BufferedEvent, EventStore};
pub use tasks::{ClaimError, TaskStore};
pub use timers::TimerStore;

use std::fmt::Debug;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineState, Digest, RunId,
    StoreError, Timestamp,
};

/// What admission did with an inbound trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correlation {
    /// No open case matched; a new one was created.
    Opened(CaseId),
    /// An open case matched and this run joined it.
    Attached(CaseId),
}

impl Correlation {
    #[must_use]
    pub fn case_id(self) -> CaseId {
        match self {
            Self::Opened(id) | Self::Attached(id) => id,
        }
    }

    #[must_use]
    pub fn is_new(self) -> bool {
        matches!(self, Self::Opened(_))
    }
}

/// Long-lived case state, correlated by business key.
///
/// Correlation is a deterministic lookup — never a model call. It runs at
/// admission, before planning, because which case a message belongs to is a
/// question of fact, not of judgement.
#[async_trait]
pub trait CaseStore: Send + Sync + Debug {
    /// Find an **open** case matching any of these keys.
    ///
    /// Closed cases are not matched: a new message about a settled matter opens
    /// a new case rather than reanimating one that was concluded and audited.
    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError>;

    /// Correlate, or open a new case if nothing matched.
    ///
    /// Implementations must make this atomic. Two messages for the same new case
    /// arriving concurrently must produce one case, not two — otherwise a
    /// process fragments across cases and its obligations are tracked in neither.
    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, StoreError>;

    /// Fetch one case.
    ///
    /// Named for what it returns rather than `get`: a single store commonly
    /// implements several of these traits, and same-named methods make every
    /// call site ambiguous.
    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError>;

    /// Record that a run touched this case.
    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError>;

    /// Record that a case produced a blob.
    ///
    /// The case is what an erasure request actually names — nobody asks to
    /// forget a digest — so something has to know which bytes belong to which
    /// matter. That association cannot live in the blob store, which is
    /// content-addressed on purpose and has no idea what a case is, and it
    /// cannot be recomputed later: a digest is deliberately not reversible.
    ///
    /// Recording the same blob twice is the same record. Two runs on one case
    /// storing identical bytes land on one digest by construction, and that is
    /// one artifact, not two.
    ///
    /// # Errors
    ///
    /// If the store rejects the write.
    async fn link_blob(
        &self,
        case: CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), StoreError>;

    /// Every blob this case produced, oldest first.
    ///
    /// # Errors
    ///
    /// If the store cannot be read.
    async fn blobs_of(&self, case: CaseId) -> Result<Vec<Digest>, StoreError>;

    /// Replace the case's opaque state.
    /// Replace a case's state, if it is still at `expected`.
    ///
    /// # Why this takes a version
    ///
    /// A case is shared by every run correlated to it, and the window between
    /// reading its state and writing it back contains a model call — which is
    /// unbounded. Two runs on one case *will* overlap, and a blind write in that
    /// window silently discards whichever one lost. See [`CaseVersion`].
    ///
    /// Implementations must make the check part of the write itself — a single
    /// `UPDATE ... WHERE version = ?` — and not a read followed by a write. A
    /// check performed in application code is a check the next caller can race.
    ///
    /// # Errors
    ///
    /// * [`StoreError::CaseConflict`] if the case has moved past `expected`. The
    ///   caller re-reads and decides again; retrying the same write is the lost
    ///   update this exists to prevent.
    /// * [`StoreError::NotFound`] if there is no such case. Implementations must
    ///   tell these apart — reporting a missing case as a conflict sends the
    ///   caller into a re-read loop against something that will never exist.
    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StoreError>;

    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError>;

    /// Close a case.
    ///
    /// **Fails while an obligation is open.** A case with an unmet deadline
    /// cannot be closed silently: that is precisely how a missed regulatory
    /// window becomes invisible.
    async fn close(&self, case: CaseId) -> Result<(), StoreError>;

    /// Register an obligation. The resolved instant is stored as given and never
    /// recomputed.
    async fn register_deadline(&self, deadline: &Deadline) -> Result<(), StoreError>;

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError>;

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError>;

    /// Obligations that are due or approaching, oldest first.
    ///
    /// The sweep that turns a passing instant into an escalation. Without it a
    /// deadline is a stored number that nobody reads.
    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError>;

    /// Cases matching a status, newest first.
    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError>;

    /// How much is open right now, for the gauges in `runtime::metrics`.
    ///
    /// Deliberately not expressible as `by_status(...).len()`: that is bounded
    /// by a `limit`, and a gauge computed from a truncated list is a number that
    /// stops rising exactly when the backlog becomes worth knowing about. It is
    /// also the only consumer of a case's `opened_at` — a count alone cannot
    /// distinguish ten cases open for an hour from ten open for a month.
    ///
    /// `now` is passed in so the reading is testable against arbitrary ageing
    /// and needs no escape from the determinism gate.
    async fn census(&self, now: Timestamp) -> Result<CaseCensus, StoreError>;
}

/// What the case store is currently holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaseCensus {
    /// Cases in any status other than `Closed`.
    pub open: u64,
    /// The longest-open case's age in seconds, or `None` if none are open.
    pub oldest_age_secs: Option<u64>,
    /// Obligations at or past their instant, still `Pending` or `Warned`.
    pub due: u64,
}
