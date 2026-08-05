//! One contract, run against every quota store.
//!
//! A ceiling is arithmetic at a boundary, and boundaries are where two
//! implementations of one rule diverge. This battery exists because they already
//! did: one backend compared "am I at the limit?" *inside* its counting loop,
//! which is correct for every ceiling except zero — the loop body never runs, so
//! nothing is compared, and a tenant stopped dead is admitted instead. The other
//! backend had it right. Only a shared contract catches that shape.
//!
//! The properties are the ones a ceiling stands or falls on:
//!
//! * a limit of **zero** admits nothing, because that is how an operator stops a
//!   tenant;
//! * a run at the ceiling is **refused**, and refused with the count, so an
//!   operator can tell throttling from a fault;
//! * releasing makes room, because a ceiling is back-pressure and not a
//!   permanent verdict;
//! * reserving one run **twice takes one slot**, or a retried admission costs
//!   the tenant capacity forever;
//! * accruals **sum**, because reading, adding and writing back loses one of two
//!   concurrent updates — and what it loses is spend already incurred;
//! * periods are **independent**, since the window is a billing period.

use crate::core::{RunId, Spend, Timestamp};
use crate::quota::{QuotaError, QuotaStore};

use super::conformance::Report;

/// Run the battery against one quota store.
///
/// The store must be scoped to a tenant with no runs and no recorded spend: this
/// reserves, releases and accrues under it.
pub async fn check(store: &dyn QuotaStore, report: &mut Report) {
    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");
    zero_admits_nothing(store, at, report).await;
    ceiling_refuses_and_frees(store, at, report).await;
    reserving_twice_takes_one_slot(store, at, report).await;
    spend_accrues_per_period(store, report).await;
    halt(store, report).await;
}

/// A ceiling of zero admits nothing.
async fn zero_admits_nothing(store: &dyn QuotaStore, at: Timestamp, report: &mut Report) {
    report.checked += 1;
    let run = RunId::generate();
    match store.reserve(run, Some(0), at).await {
        Err(QuotaError::TooManyRuns { .. }) => {}
        Err(e) => report.record(
            "a ceiling of zero admits nothing",
            format!("reserving under a zero ceiling failed with `{e}` rather than a refusal"),
        ),
        Ok(()) => {
            report.record(
                "a ceiling of zero admits nothing",
                "a run was admitted under a ceiling of zero — the value an \
                 operator sets to stop a tenant dead, and the one a limit \
                 compared inside its counting loop never sees",
            );
            let _ = store.release(run).await;
        }
    }
}

/// A tenant at its ceiling is refused, and a release makes room.
async fn ceiling_refuses_and_frees(store: &dyn QuotaStore, at: Timestamp, report: &mut Report) {
    let first = RunId::generate();
    let second = RunId::generate();

    report.checked += 1;
    if let Err(e) = store.reserve(first, Some(1), at).await {
        report.record(
            "a run fits under a ceiling of one",
            format!("the first reservation failed: {e}"),
        );
        return;
    }

    report.checked += 1;
    match store.reserve(second, Some(1), at).await {
        Err(QuotaError::TooManyRuns { running, .. }) => {
            report.checked += 1;
            if running == 0 {
                report.record(
                    "a refusal reports how many runs are executing",
                    "the refusal said zero runs are executing, which tells an \
                     operator asking why they are throttled precisely nothing",
                );
            }
        }
        Err(e) => report.record(
            "a tenant at its ceiling is refused",
            format!("failed with `{e}` rather than reporting the ceiling"),
        ),
        Ok(()) => report.record(
            "a tenant at its ceiling is refused",
            "a second run was admitted past a ceiling of one, so the ceiling \
             bounds nothing",
        ),
    }

    report.checked += 1;
    if let Err(e) = store.release(first).await {
        report.record("releasing a slot", format!("{e}"));
        return;
    }
    report.checked += 1;
    match store.reserve(second, Some(1), at).await {
        Ok(()) => {
            let _ = store.release(second).await;
        }
        Err(e) => report.record(
            "releasing makes room",
            format!(
                "the slot freed by a finished run could not be reused: {e}. A \
                 ceiling is back-pressure, and one that never frees is a tenant \
                 permanently stopped by its first burst"
            ),
        ),
    }
}

/// Reserving one run twice takes one slot.
async fn reserving_twice_takes_one_slot(
    store: &dyn QuotaStore,
    at: Timestamp,
    report: &mut Report,
) {
    let run = RunId::generate();
    report.checked += 1;
    if let Err(e) = store.reserve(run, Some(1), at).await {
        report.record("reserving a run", format!("{e}"));
        return;
    }

    report.checked += 1;
    match store.reserve(run, Some(1), at).await {
        Ok(()) => {}
        Err(e) => report.record(
            "reserving one run twice is idempotent",
            format!(
                "a retried admission was refused against its own slot ({e}), so \
                 a transient error during admission costs the tenant capacity \
                 until something releases a run it never really started"
            ),
        ),
    }

    report.checked += 1;
    match store.running().await {
        Ok(1) => {}
        Ok(n) => report.record(
            "reserving one run twice takes one slot",
            format!(
                "{n} slots are held for one run, so every retry permanently shrinks the ceiling"
            ),
        ),
        Err(e) => report.record("counting running runs", format!("{e}")),
    }
    let _ = store.release(run).await;
}

/// Spend sums within a period and does not cross between them.
async fn spend_accrues_per_period(store: &dyn QuotaStore, report: &mut Report) {
    let (this, next) = ("2999-01", "2999-02");

    report.checked += 1;
    for n in [400u64, 600] {
        if let Err(e) = store.accrue(this, Spend::tokens(n)).await {
            report.record("accruing spend", format!("{e}"));
            return;
        }
    }

    report.checked += 1;
    match store.spent(this).await {
        Ok(s) if s.tokens == 1_000 => {}
        Ok(s) => report.record(
            "accruals sum",
            format!(
                "two accruals of 400 and 600 totalled {} rather than 1000. \
                 Reading a total, adding to it and writing it back loses one of \
                 two concurrent updates — and what it loses is spend a tenant \
                 has already incurred, so the ceiling drifts upward under load",
                s.tokens
            ),
        ),
        Err(e) => report.record("reading spend", format!("{e}")),
    }

    report.checked += 1;
    match store.spent(next).await {
        Ok(s) if s.tokens == 0 => {}
        Ok(s) => report.record(
            "periods are independent",
            format!(
                "an untouched period already reports {} tokens, so a ceiling \
                 would never reset and a tenant is billed forever for one month",
                s.tokens
            ),
        ),
        Err(e) => report.record("reading an untouched period", format!("{e}")),
    }
}

/// The emergency stop, held to the same contract on every backend.
///
/// Three properties, and the third is the one an in-process flag fails.
async fn halt(store: &dyn QuotaStore, report: &mut Report) {
    report.checked += 1;
    match store.halted().await {
        Ok(None) => {}
        Ok(Some(reason)) => report.record(
            "a fresh tenant is not halted",
            format!("an untouched tenant reports itself halted for '{reason}', so a plane would refuse every run it was never told to refuse"),
        ),
        Err(e) => report.record("reading the halt", format!("{e}")),
    }

    report.checked += 1;
    if let Err(e) = store.set_halt(Some("incident 42")).await {
        report.record("setting the halt", format!("{e}"));
    }
    match store.halted().await {
        Ok(Some(reason)) if reason == "incident 42" => {}
        Ok(other) => report.record(
            "the halt survives being written",
            format!(
                "after halting, the store reports {other:?} — a switch that does \
                 not read back is one an operator believes they threw"
            ),
        ),
        Err(e) => report.record("reading the halt back", format!("{e}")),
    }

    // The reason is replaced rather than appended to, so the current one is
    // always the current one.
    report.checked += 1;
    if let Err(e) = store.set_halt(Some("incident 43")).await {
        report.record("re-halting", format!("{e}"));
    }
    match store.halted().await {
        Ok(Some(reason)) if reason == "incident 43" => {}
        Ok(other) => report.record(
            "re-halting replaces the reason",
            format!("expected the newer reason, got {other:?}"),
        ),
        Err(e) => report.record("re-reading the halt", format!("{e}")),
    }

    report.checked += 1;
    if let Err(e) = store.set_halt(None).await {
        report.record("lifting the halt", format!("{e}"));
    }
    match store.halted().await {
        Ok(None) => {}
        Ok(Some(reason)) => report.record(
            "a lifted halt stays lifted",
            format!(
                "the tenant is still halted for '{reason}' after the stop was \
                 lifted, so an incident that is over never ends"
            ),
        ),
        Err(e) => report.record("reading a lifted halt", format!("{e}")),
    }

    // Lifting a halt nobody set is a no-op, not an error: an operator clearing
    // a switch they are not sure about must not be punished for it.
    report.checked += 1;
    if let Err(e) = store.set_halt(None).await {
        report.record("lifting an unset halt", format!("{e}"));
    }
}
