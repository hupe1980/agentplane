//! The assertion that a defence-in-depth property is actually being tested.
//!
//! # The problem it solves
//!
//! Exactly-once is enforced twice here, on purpose. Replay reads a completed
//! effect back out of the journal instead of performing it, and beneath that the
//! store holds a unique index rejecting a second `EffectStarted` for one effect
//! key. Two layers, so that a bug in either one is not a duplicated payment.
//!
//! That redundancy is good engineering and it is *poison for tests*. Delete the
//! entire replay read-back and the world still contains no duplicate — the
//! re-announcement is rejected one layer down. Every outcome-shaped assertion
//! still passes:
//!
//! - the world has one entry, because the second attempt never reached it;
//! - the chain still verifies, because nothing was written;
//! - the run still "failed", which a test that permits failure will accept.
//!
//! The general rule, which is not specific to this crate: **a property enforced
//! at more than one layer cannot be tested by observing the outcome**, because
//! the outer layer masks every inner failure. The test has to assert *which
//! layer held*.
//!
//! # What this checks
//!
//! That the run was not stopped by the backstop. A run may fail, refuse, or
//! quarantine for reasons the design names — but if it stopped because the store
//! rejected a duplicate announcement, then replay tried to re-perform something
//! the journal already had, and the constraint caught what replay should have.
//! The run looks handled and the runtime is broken.
//!
//! This lives in the testkit rather than in one test file because it was written
//! twice, in two harnesses, and missed the second time. An embedder testing its
//! own store wants it for the same reason.

use crate::core::{RuntimeError, StoreError};
use crate::runtime::{RunOutcome, RunStatus};

/// Whether a failure message is the store's exactly-once constraint talking.
fn is_backstop(detail: &str) -> bool {
    detail.contains("already started in this run")
}

/// Panic if a run was stopped by a lower layer's exactly-once constraint.
///
/// `what` labels the situation — a crash point, a fault schedule, a seed — so a
/// failure names the case that produced it rather than only the assertion.
///
/// # Panics
///
/// If the outcome is a failure caused by the store rejecting a duplicate
/// `EffectStarted`.
pub fn assert_replay_was_not_backstopped(what: &str, outcome: &Result<RunOutcome, RuntimeError>) {
    let detail = match outcome {
        Err(RuntimeError::Store(StoreError::DuplicateEffect(k))) => {
            panic!(
                "{what}: replay re-announced effect {k}, and only the store's \
                 unique index stopped it. Exactly-once did not hold here — it \
                 was rescued. Replay must read a completed effect back from the \
                 journal and never reach the constraint at all."
            )
        }
        Err(e) => e.to_string(),
        Ok(RunOutcome {
            status: RunStatus::Failed(detail) | RunStatus::Quarantined(detail),
            ..
        }) => detail.clone(),
        Ok(_) => return,
    };

    assert!(
        !is_backstop(&detail),
        "{what}: the run was stopped by the store's exactly-once constraint, \
         which means replay tried to re-announce an effect the journal already \
         holds: {detail}\n\n\
         This is not exactly-once working. It is the backstop catching what \
         replay should have caught, and every outcome-shaped assertion in the \
         test still passes while it happens."
    );
}
