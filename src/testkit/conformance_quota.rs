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
use crate::quota::{QuotaError, QuotaSettlement, QuotaStore};

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
    if let Err(e) = store
        .settle(&QuotaSettlement {
            run: first,
            epoch: 1,
            period: None,
            spend: Spend::default(),
            release_slot: true,
        })
        .await
    {
        report.record("settling and releasing a slot", format!("{e}"));
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
    let run = RunId::generate();
    let first = QuotaSettlement {
        run,
        epoch: 1,
        period: Some(this.to_owned()),
        spend: Spend::tokens(400),
        release_slot: false,
    };
    let second = QuotaSettlement {
        run,
        epoch: 2,
        period: Some(this.to_owned()),
        spend: Spend::tokens(600),
        release_slot: false,
    };

    report.checked += 1;
    for settlement in [&first, &second] {
        if let Err(e) = store.settle(settlement).await {
            report.record("settling spend", format!("{e}"));
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

    // A lost acknowledgement retries the exact same receipt. It must not bill
    // the pass twice, and the positive total above means this cannot pass by
    // ignoring every settlement.
    report.checked += 1;
    if let Err(e) = store.settle(&first).await {
        report.record("retrying an identical settlement", format!("{e}"));
    }
    match store.spent(this).await {
        Ok(s) if s.tokens == 1_000 => {}
        Ok(s) => report.record(
            "an identical settlement accrues once",
            format!("retrying one pass changed the total to {} tokens", s.tokens),
        ),
        Err(e) => report.record("reading spend after a settlement retry", format!("{e}")),
    }

    // A key may not be reused to rewrite accounting. The store must compare
    // the receipt, not treat every conflict as idempotent success.
    report.checked += 1;
    let changed = QuotaSettlement {
        spend: Spend::tokens(401),
        ..first.clone()
    };
    if store.settle(&changed).await.is_ok() {
        report.record(
            "one pass key names one exact settlement",
            "the same run/epoch accepted a different spend, so a retry can rewrite the bill",
        );
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
/// Four properties, and the last two are the ones an in-process flag and a
/// single overwritable row respectively fail.
#[allow(clippy::too_many_lines)]
async fn halt(store: &dyn QuotaStore, report: &mut Report) {
    use crate::quota::HaltScope;

    let tenant = HaltScope::Tenant;
    let agent = HaltScope::agent("payments-clerk");
    let revision = HaltScope::revision(crate::core::Digest::of(b"a manifest revision"));

    let standing = |halts: &[crate::quota::Halt], scope: &HaltScope| -> Option<String> {
        halts
            .iter()
            .find(|h| &h.scope == scope)
            .map(|h| h.reason.clone())
    };

    report.checked += 1;
    match store.halts().await {
        Ok(halts) if halts.is_empty() => {}
        Ok(halts) => report.record(
            "a fresh tenant is not halted",
            format!(
                "an untouched tenant reports {halts:?}, so a plane would refuse \
                 every run it was never told to refuse"
            ),
        ),
        Err(e) => report.record("reading the halts", format!("{e}")),
    }

    report.checked += 1;
    if let Err(e) = store.set_halt(&tenant, Some("incident 42")).await {
        report.record("setting the halt", format!("{e}"));
    }
    match store.halts().await {
        Ok(halts) if standing(&halts, &tenant).as_deref() == Some("incident 42") => {}
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
    if let Err(e) = store.set_halt(&tenant, Some("incident 43")).await {
        report.record("re-halting", format!("{e}"));
    }
    match store.halts().await {
        Ok(halts) if standing(&halts, &tenant).as_deref() == Some("incident 43") => {}
        Ok(other) => report.record(
            "re-halting replaces the reason",
            format!("expected the newer reason, got {other:?}"),
        ),
        Err(e) => report.record("re-reading the halt", format!("{e}")),
    }

    // **Scopes are independent rows.** A narrow halt beside a broad one, and
    // lifting the narrow one, must leave the broad one standing: an incident
    // that widens and then partly resolves is the ordinary shape, and a single
    // overwritable flag gets it wrong in the direction that lets work through.
    report.checked += 1;
    if let Err(e) = store.set_halt(&agent, Some("agent 12 is looping")).await {
        report.record("halting one agent", format!("{e}"));
    }
    if let Err(e) = store.set_halt(&revision, Some("bad deploy")).await {
        report.record("halting one revision", format!("{e}"));
    }
    match store.halts().await {
        Ok(halts)
            if standing(&halts, &tenant).as_deref() == Some("incident 43")
                && standing(&halts, &agent).as_deref() == Some("agent 12 is looping")
                && standing(&halts, &revision).as_deref() == Some("bad deploy") => {}
        Ok(other) => report.record(
            "scopes are independent",
            format!(
                "a narrow halt overwrote a broader one, or was not kept: {other:?} — \
                 an incident that widens must not un-stop what was already stopped"
            ),
        ),
        Err(e) => report.record("reading several standing halts", format!("{e}")),
    }

    report.checked += 1;
    if let Err(e) = store.set_halt(&agent, None).await {
        report.record("lifting one scope", format!("{e}"));
    }
    match store.halts().await {
        Ok(halts)
            if standing(&halts, &agent).is_none()
                && standing(&halts, &tenant).as_deref() == Some("incident 43") => {}
        Ok(other) => report.record(
            "lifting one scope leaves the others",
            format!(
                "after lifting the agent halt the store reports {other:?} — lifting \
                 a narrow stop must not lift the broad one it sits under"
            ),
        ),
        Err(e) => report.record("reading a partly lifted halt", format!("{e}")),
    }

    report.checked += 1;
    for scope in [&tenant, &revision] {
        if let Err(e) = store.set_halt(scope, None).await {
            report.record("lifting the halt", format!("{e}"));
        }
    }
    match store.halts().await {
        Ok(halts) if halts.is_empty() => {}
        Ok(other) => report.record(
            "a lifted halt stays lifted",
            format!(
                "the tenant is still halted by {other:?} after the stop was \
                 lifted, so an incident that is over never ends"
            ),
        ),
        Err(e) => report.record("reading a lifted halt", format!("{e}")),
    }

    // Lifting a halt nobody set is a no-op, not an error: an operator clearing
    // a switch they are not sure about must not be punished for it.
    report.checked += 1;
    if let Err(e) = store.set_halt(&tenant, None).await {
        report.record("lifting an unset halt", format!("{e}"));
    }
}
