//! Durable timers — a wait whose event is the clock.
//!
//! # Why this is not `tokio::time::sleep`
//!
//! An in-process sleep holds a worker for its duration and forgets everything if
//! the process dies. A business process that waits five Werktage cannot be a
//! held task, and a retry that backs off for ten minutes should not occupy a
//! frame for ten minutes.
//!
//! A durable timer is a row. The run suspends, the frame is persisted, and a
//! sweep wakes it when the instant arrives — so a plane can hold as many
//! sleeping runs as it has disk, and a restart loses none of them.
//!
//! # Why the instant is journaled
//!
//! The wake instant is resolved once and recorded, exactly as an obligation's
//! deadline is (§ the `Calendar` seam). Recomputing `now + duration` on replay
//! would move the instant every time the run was replayed, and a run that slept
//! until Tuesday would sleep until a different Tuesday on every audit.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{EffectKey, RunId, StoreError, Timer, Timestamp};

/// Durable wake-ups.
#[async_trait]
pub trait TimerStore: Send + Sync + Debug {
    /// Register a run's wake-up.
    ///
    /// Idempotent on `(run, effect)`: a resumed run that re-registers the same
    /// timer must not create a second one, or the run would be woken twice.
    async fn arm(&self, timer: &Timer) -> Result<(), StoreError>;

    /// Atomically claim timers due at or before `now`.
    ///
    /// Claiming is what makes a wake-up single-delivery. Two sweepers running
    /// against one store must not both resume the same run — that is the same
    /// requirement `claim_for` has for events, for the same reason.
    async fn claim_due(&self, now: Timestamp, limit: usize) -> Result<Vec<Timer>, StoreError>;

    /// Retire a fired timer.
    async fn disarm(&self, run: RunId, effect: EffectKey) -> Result<(), StoreError>;

    /// How many runs are sleeping.
    ///
    /// Separate from `pending` because that is `limit`-bounded, and a gauge read
    /// from a truncated list silently flattens exactly when the number matters.
    async fn pending_count(&self) -> Result<u64, StoreError>;

    /// Timers not yet due, soonest first.
    ///
    /// For operators: "what is this plane waiting for, and until when" should be
    /// one query, not an inference from suspended runs.
    async fn pending(&self, limit: usize) -> Result<Vec<Timer>, StoreError>;
}
