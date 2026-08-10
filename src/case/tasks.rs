//! The worklist contract.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{CaseId, StoreError, Task, TaskId, TaskState, Timestamp};

/// Why a claim was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("task {0} does not exist")]
    NotFound(TaskId),

    #[error("task {task} is already {state:?}")]
    NotPending { task: TaskId, state: TaskState },

    #[error("task {task} is held by '{holder}'")]
    AlreadyClaimed { task: TaskId, holder: String },

    /// The four-eyes control: whoever proposed an action does not approve it.
    #[error("'{actor}' proposed this action and may not also decide it")]
    Excluded { actor: String },

    #[error("'{actor}' holds none of the roles this task requires")]
    WrongRole { actor: String },

    /// A release from somebody who is not the holder.
    ///
    /// Distinct from [`NotFound`](ClaimError::NotFound) because the two call for
    /// opposite responses: a task that does not exist means the id is wrong, and
    /// a task held by someone else means the release did nothing — which is the
    /// answer a caller must not receive as success.
    #[error("task {task} is not held by '{actor}'")]
    NotHeld { task: TaskId, actor: String },

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Pending human work.
#[async_trait]
pub trait TaskStore: Send + Sync + Debug {
    /// Create a task, or return the existing one with this id.
    ///
    /// Idempotent because task ids are derived from the awaiting effect rather
    /// than minted: a resumed run addresses the same task instead of opening a
    /// second one for the same decision.
    async fn open(&self, task: &Task) -> Result<Task, StoreError>;

    /// Fetch one task. Named for what it returns — see `CaseStore::case`.
    async fn task(&self, id: TaskId) -> Result<Option<Task>, StoreError>;

    /// Reserve a task for one actor.
    ///
    /// Enforces the four-eyes exclusion and role eligibility, atomically, so two
    /// reviewers cannot both believe they hold it.
    ///
    /// **Eligibility is checked before availability**, and the order is part of
    /// the contract rather than an artefact of how it was written:
    ///
    /// `NotFound` → `Excluded` → `WrongRole` → `NotPending` → `AlreadyClaimed`
    ///
    /// Told "held by Bob", a barred reviewer waits for Bob to release it and
    /// tries again — and is refused, for a reason nobody has yet mentioned. The
    /// permanent answer has to win over the transient one, or the transient one
    /// hides it. It also keeps queue state — who is reviewing what — from
    /// anybody not eligible for that queue.
    ///
    /// # Errors
    ///
    /// [`ClaimError`], per the order above.
    async fn claim(&self, id: TaskId, actor: &str, roles: &[String]) -> Result<Task, ClaimError>;

    /// Release a claim without deciding.
    ///
    /// Only the holder may. A release by anybody else must report
    /// [`ClaimError::NotHeld`] rather than succeed silently: a caller who is
    /// told "released" and then sees the task still assigned has no way to tell
    /// which of the two is lying.
    ///
    /// # Errors
    ///
    /// [`ClaimError::NotHeld`] if `actor` does not hold it, or it is not
    /// claimed.
    async fn release(&self, id: TaskId, actor: &str) -> Result<(), ClaimError>;

    /// Take a claim over from a holder who is not coming back.
    ///
    /// The absent-holder case [`release`](Self::release) cannot reach: only
    /// the holder may release, so a task claimed by a reviewer who has left is
    /// parked until its deadline breaches — a routine handover turned into an
    /// escalation, or "an operator edits the database", which is the
    /// anti-pattern the release endpoint exists to prevent.
    ///
    /// `from` names the holder being displaced and is a compare-and-swap
    /// guard, not documentation: a take-over decided from a stale view must
    /// fail rather than displace whoever holds it *now* — the same rule a
    /// case write follows by naming the version it read. Eligibility is
    /// re-checked in full for the new actor; a take-over is a claim, and
    /// four-eyes exclusion does not thin because the previous reviewer left.
    ///
    /// A reservation, not a decision: like claim and release it lives in the
    /// store, and the decision eventually taken still records its decider.
    /// The API gates it under its own action, so policy can hand it to a
    /// queue lead without handing it to every reviewer.
    ///
    /// # Errors
    ///
    /// [`ClaimError`], in claim's eligibility-first order, with
    /// [`ClaimError::NotHeld`] naming `from` when the task is not currently
    /// held by them — including when it is not held at all, where the right
    /// verb is [`claim`](Self::claim).
    async fn take_over(
        &self,
        id: TaskId,
        from: &str,
        actor: &str,
        roles: &[String],
    ) -> Result<Task, ClaimError>;

    async fn set_state(&self, id: TaskId, state: TaskState) -> Result<(), StoreError>;

    /// Open work, highest priority and oldest first.
    async fn queue(&self, roles: &[String], limit: usize) -> Result<Vec<Task>, StoreError>;

    /// Everything pending on one matter.
    async fn for_case(&self, case: CaseId) -> Result<Vec<Task>, StoreError>;

    /// How many decisions are waiting on a person, across every role.
    ///
    /// Separate from `queue` for the same reason `pending_count` is separate
    /// from `pending`: a gauge must not be read from a `limit`-bounded list.
    async fn open_count(&self) -> Result<u64, StoreError>;

    /// Tasks whose window has closed and which nobody answered.
    async fn overdue(&self, now: Timestamp, limit: usize) -> Result<Vec<Task>, StoreError>;
}
