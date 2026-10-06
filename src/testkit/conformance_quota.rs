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
//! * periods are **independent**, since the window is a billing period;
//! * a **spend hold** counts against the period ceiling beside settled spend,
//!   and is decided in the transaction that inserts it;
//! * a pass settlement moves its spend **out of the hold**, so the period is
//!   charged once, and the concluding one releases the rest;
//! * a pre-journal release drops the hold with the slot, and a resume's carry
//!   moves the hold between periods without growing it;
//! * a **rate ceiling** admits its count and refuses past it, re-reserving a
//!   present dispatch spends nothing, two runs making the same call each
//!   spend, the window **slides** rather than restarting at a boundary, an
//!   undo is counted and never refused, and one tenant's count is its own.

use crate::core::{EffectKey, Phase, RunId, Spend, StepId, Timestamp};
use crate::quota::{
    QuotaError, QuotaSettlement, QuotaStore, RateCeiling, RateReservation, SpendHold, TenantQuota,
};

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
    spend_holds(store, at, report).await;
    halt(store, report).await;
    lift_only_the_halt_read(store, report).await;
    rate(store, report).await;
    rate_windows_share_a_grant(store, report).await;
    an_uncountable_rate_window_is_refused(store, report).await;
}

/// A quota with only a concurrency ceiling.
fn slots(n: u32) -> TenantQuota {
    TenantQuota {
        max_concurrent_runs: Some(n),
        ..TenantQuota::default()
    }
}

/// A quota with only a token ceiling per period.
fn tokens_per_period(limit: u64) -> TenantQuota {
    TenantQuota {
        max_tokens_per_period: Some(limit),
        ..TenantQuota::default()
    }
}

fn hold(period: &str, tokens: u64) -> SpendHold {
    SpendHold {
        period: period.to_owned(),
        amount: Spend::tokens(tokens),
    }
}

/// Spend holds: counted, moved, released, carried.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn spend_holds(store: &dyn QuotaStore, at: Timestamp, report: &mut Report) {
    let period = "2998-01";
    let quota = tokens_per_period(1_000);
    let (a, b, c, d) = (
        RunId::generate(),
        RunId::generate(),
        RunId::generate(),
        RunId::generate(),
    );

    report.checked += 1;
    for (run, amount) in [(a, 600), (c, 400)] {
        if let Err(e) = store
            .reserve(run, &quota, Some(&hold(period, amount)), at)
            .await
        {
            report.record(
                "holds that fit the ceiling are admitted",
                format!(
                    "holding {amount} of a 1000-token period failed with `{e}` — a period \
                     filled exactly is one its admitted work can reach and not pass"
                ),
            );
            return;
        }
    }

    // Retried: the run already holds, so nothing more is taken and nothing
    // refused, even though the period is now full.
    report.checked += 1;
    if let Err(e) = store.reserve(a, &quota, Some(&hold(period, 600)), at).await {
        report.record(
            "holding one run twice is idempotent",
            format!("a retried admission was refused against its own hold: {e}"),
        );
    }
    match store.reserved(period).await {
        Ok(s) if s.tokens == 1_000 => {}
        Ok(s) => report.record(
            "a hold is what the period counts",
            format!(
                "two holds of 600 and 400 read back as {} reserved",
                s.tokens
            ),
        ),
        Err(e) => report.record("reading what is reserved", format!("{e}")),
    }

    report.checked += 1;
    match store.reserve(b, &quota, Some(&hold(period, 1)), at).await {
        Err(QuotaError::SpentOut {
            settled: 0,
            reserved: 1_000,
            requested: 1,
            limit: 1_000,
            ..
        }) => {}
        Err(e) => report.record(
            "a full period refuses and names what is reserved",
            format!("refused with `{e}` rather than naming settled and reserved apart"),
        ),
        Ok(()) => {
            report.record(
                "outstanding holds count against the ceiling",
                "a period whose holds already reach its ceiling admitted one more, so \
                 the ceiling counts settled spend only and every run admitted before any \
                 settles may spend its whole budget",
            );
            let _ = store.release(b).await;
        }
    }
    // A refused hold took no slot either: the decision was one.
    report.checked += 1;
    if let Ok(held) = store.running_runs(100).await
        && held.contains(&b)
    {
        report.record(
            "a refused hold takes no slot",
            "the slot was inserted although the spend hold was refused",
        );
    }

    // A suspended pass settles 200: it leaves the hold as it enters the
    // settled total, so the period still counts 1000, not 1200.
    report.checked += 1;
    let pass = |epoch, tokens, concludes| QuotaSettlement {
        run: a,
        epoch,
        period: Some(period.to_owned()),
        spend: Spend::tokens(tokens),
        release_slot: epoch == 1,
        concludes,
    };
    if let Err(e) = store.settle(&pass(1, 200, false)).await {
        report.record("settling a pass under a hold", format!("{e}"));
        return;
    }
    match (store.spent(period).await, store.reserved(period).await) {
        (Ok(spent), Ok(held)) if spent.tokens == 200 && held.tokens == 800 => {}
        (Ok(spent), Ok(held)) => report.record(
            "a pass settlement moves its spend out of the hold",
            format!(
                "after a 200-token pass the period reads {} settled and {} reserved — a \
                 suspended run is charged twice unless its settled spend leaves its hold",
                spent.tokens, held.tokens
            ),
        ),
        (Err(e), _) | (_, Err(e)) => report.record("reading the period", format!("{e}")),
    }

    // The concluding pass spends 100 more and gives back the other 300.
    report.checked += 1;
    if let Err(e) = store.settle(&pass(2, 100, true)).await {
        report.record("settling the concluding pass", format!("{e}"));
        return;
    }
    match (store.spent(period).await, store.reserved(period).await) {
        (Ok(spent), Ok(held)) if spent.tokens == 300 && held.tokens == 400 => {}
        (Ok(spent), Ok(held)) => report.record(
            "the concluding settlement releases what the run did not spend",
            format!(
                "after the run concluded having spent 300 of its 600 the period reads \
                 {} settled and {} reserved",
                spent.tokens, held.tokens
            ),
        ),
        (Err(e), _) | (_, Err(e)) => report.record("reading the period", format!("{e}")),
    }
    // The receipt covers the conclusion: a retry that disagrees is damage.
    report.checked += 1;
    if store.settle(&pass(2, 100, false)).await.is_ok() {
        report.record(
            "one pass key names one conclusion",
            "the same run/epoch was accepted as concluding and as not",
        );
    }

    // What the conclusion freed is admissible again, to the unit.
    report.checked += 1;
    if let Err(e) = store.reserve(d, &quota, Some(&hold(period, 300)), at).await {
        report.record(
            "a released hold makes room",
            format!("300 tokens freed by a conclusion could not be held again: {e}"),
        );
    }

    // A resume in a later period carries the remainder; the old period is
    // released and nothing grows.
    report.checked += 1;
    let later = "2998-02";
    if let Err(e) = store.carry(c, later).await {
        report.record("carrying a hold", format!("{e}"));
    }
    match (store.reserved(period).await, store.reserved(later).await) {
        (Ok(old), Ok(new)) if old.tokens == 300 && new.tokens == 400 => {}
        (Ok(old), Ok(new)) => report.record(
            "a carried hold moves whole",
            format!(
                "after carrying a 400-token hold the old period holds {} and the new {}",
                old.tokens, new.tokens
            ),
        ),
        (Err(e), _) | (_, Err(e)) => report.record("reading carried holds", format!("{e}")),
    }

    // The holders are named, so a period filled by runs nobody will conclude
    // has somebody to act on.
    report.checked += 1;
    match store.reservations(100).await {
        Ok(held) => {
            let mut runs: Vec<RunId> = held.iter().map(|h| h.run).collect();
            runs.sort();
            let mut want = vec![c, d];
            want.sort();
            if runs != want {
                report.record(
                    "the runs holding spend are listed",
                    format!("expected {want:?} to hold spend, the listing says {held:?}"),
                );
            }
        }
        Err(e) => report.record("listing holds", format!("{e}")),
    }

    // A pre-journal cleanup drops the hold with the slot.
    report.checked += 1;
    for run in [c, d] {
        if let Err(e) = store.release(run).await {
            report.record("releasing a hold", format!("{e}"));
        }
    }
    match (store.reserved(period).await, store.reserved(later).await) {
        (Ok(old), Ok(new)) if old.is_free() && new.is_free() => {}
        (Ok(old), Ok(new)) => report.record(
            "a release drops the hold with the slot",
            format!(
                "after releasing every holder, {old} and {new} are still held — a crash \
                 before the admission record strands a reservation over no run"
            ),
        ),
        (Err(e), _) | (_, Err(e)) => report.record("reading released holds", format!("{e}")),
    }
}

/// Admissions from two handles at a period's edge admit exactly what fits.
///
/// Sequential calls prove the arithmetic and not the transaction: the decision
/// and the insert must be one, or two instances each read a period with room
/// and both land. Twenty holds of 100 race for a 1000-token period through
/// two handles onto the same tenant; exactly ten may land.
///
/// # Panics
///
/// Never on a conforming store; the report carries any violation.
pub async fn check_race(first: &dyn QuotaStore, second: &dyn QuotaStore, report: &mut Report) {
    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid test instant");
    let quota = tokens_per_period(1_000);
    let period = "2997-01";
    let runs: Vec<RunId> = (0..20).map(|_| RunId::generate()).collect();
    let spend = hold(period, 100);
    let attempts = runs.iter().enumerate().map(|(i, run)| {
        let store = if i % 2 == 0 { first } else { second };
        let (quota, spend) = (&quota, &spend);
        async move { store.reserve(*run, quota, Some(spend), at).await }
    });
    let outcomes = futures_util::future::join_all(attempts).await;

    report.checked += 1;
    let admitted = outcomes.iter().filter(|o| o.is_ok()).count();
    let refused = outcomes
        .iter()
        .filter(|o| matches!(o, Err(QuotaError::SpentOut { .. })))
        .count();
    if admitted != 10 || refused != 10 {
        report.record(
            "concurrent admissions at the spend ceiling admit only what fits",
            format!(
                "{admitted} holds of 100 landed in a 1000-token period ({refused} refused, \
                 {} failed otherwise) — the check and the insert are not one decision",
                20 - admitted - refused
            ),
        );
    }
    match first.reserved(period).await {
        Ok(s) if s.tokens == 1_000 => {}
        Ok(s) => report.record(
            "concurrent admissions at the spend ceiling admit only what fits",
            format!("the period holds {} tokens after the race", s.tokens),
        ),
        Err(e) => report.record("reading the raced period", format!("{e}")),
    }
    for run in runs {
        let _ = first.release(run).await;
    }
}

/// A ceiling of zero admits nothing.
async fn zero_admits_nothing(store: &dyn QuotaStore, at: Timestamp, report: &mut Report) {
    report.checked += 1;
    let run = RunId::generate();
    match store.reserve(run, &slots(0), None, at).await {
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
    if let Err(e) = store.reserve(first, &slots(1), None, at).await {
        report.record(
            "a run fits under a ceiling of one",
            format!("the first reservation failed: {e}"),
        );
        return;
    }

    report.checked += 1;
    match store.reserve(second, &slots(1), None, at).await {
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
            concludes: true,
        })
        .await
    {
        report.record("settling and releasing a slot", format!("{e}"));
        return;
    }
    report.checked += 1;
    match store.reserve(second, &slots(1), None, at).await {
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
    if let Err(e) = store.reserve(run, &slots(1), None, at).await {
        report.record("reserving a run", format!("{e}"));
        return;
    }

    report.checked += 1;
    match store.reserve(run, &slots(1), None, at).await {
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

    // A count says *one of one* and a throttled tenant needs the id, because
    // the slot may belong to a run that stopped existing — see
    // `QuotaStore::running_runs`.
    report.checked += 1;
    match store.running_runs(100).await {
        Ok(held) if held == vec![run] => {}
        Ok(held) => report.record(
            "naming the runs that hold slots",
            format!(
                "one run holds a slot and the listing says {held:?} — an operator \
                 told only how many cannot tell a live run from a slot a dead \
                 instance stranded, which is the case the accounting exists for"
            ),
        ),
        Err(e) => report.record("naming the runs that hold slots", format!("{e}")),
    }

    let _ = store.release(run).await;

    // And it empties, which is what makes the listing a queue rather than a
    // record of everything that ever ran.
    report.checked += 1;
    match store.running_runs(100).await {
        Ok(held) if held.is_empty() => {}
        Ok(held) => report.record(
            "releasing a slot takes the run off the listing",
            format!("the released run is still listed as holding a slot: {held:?}"),
        ),
        Err(e) => report.record(
            "releasing a slot takes the run off the listing",
            format!("{e}"),
        ),
    }
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
        concludes: false,
    };
    let second = QuotaSettlement {
        run,
        epoch: 2,
        period: Some(this.to_owned()),
        spend: Spend::tokens(600),
        release_slot: false,
        concludes: false,
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
    // Every throw in this battery names somebody: a halt with no operator on
    // it is the state this contract exists to make unreachable.
    let thrower =
        |actor: &str| crate::core::Operator::asserted(actor).expect("a battery names its operator");
    let at = crate::core::Timestamp::from_unix_timestamp(1_700_000_000).expect("a fixed instant");
    if let Err(e) = store
        .set_halt(&tenant, &thrower("ops-alice"), at, "incident 42")
        .await
    {
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
    if let Err(e) = store
        .set_halt(&tenant, &thrower("ops-alice"), at, "incident 43")
        .await
    {
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
    if let Err(e) = store
        .set_halt(&agent, &thrower("ops-bob"), at, "agent 12 is looping")
        .await
    {
        report.record("halting one agent", format!("{e}"));
    }
    if let Err(e) = store
        .set_halt(&revision, &thrower("ops-bob"), at, "bad deploy")
        .await
    {
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
    if let Err(e) = store.lift_halt(&agent).await {
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
        if let Err(e) = store.lift_halt(scope).await {
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
    // a switch they are not sure about must not be punished for it — and the
    // answer still has to say that nothing was standing, because during an
    // incident *I cleared it* and *I cleared the wrong scope* are different
    // facts and only one of them is good news.
    report.checked += 1;
    match store.lift_halt(&tenant).await {
        Ok(false) => {}
        Ok(true) => report.record(
            "lifting an unset halt",
            "the store reported that a halt was standing when none was".to_owned(),
        ),
        Err(e) => report.record("lifting an unset halt", format!("{e}")),
    }

    // **Who threw it survives the round trip, and so does what established the
    // name.** The runtime cannot check an emergency stop, so the operator on
    // the row is the whole of its evidence — a store that keeps the reason and
    // drops the name leaves a switch nobody can be asked about.
    report.checked += 1;
    let by = crate::core::Operator::authenticated("ops-carol").expect("a name");
    if let Err(e) = store.set_halt(&tenant, &by, at, "incident 44").await {
        report.record("halting with an authenticated operator", format!("{e}"));
    }
    match store.halts().await {
        Ok(halts) => match halts.iter().find(|h| h.scope == tenant) {
            Some(h) if h.by == by && h.at == at => {}
            Some(h) => report.record(
                "a halt keeps who threw it",
                format!(
                    "the store read back {:?} at {:?} rather than {by:?} at {at:?} — an \
                     emergency stop nobody is named on cannot be asked about afterwards",
                    h.by, h.at
                ),
            ),
            None => report.record(
                "a halt keeps who threw it",
                "the halt did not read back at all".to_owned(),
            ),
        },
        Err(e) => report.record("reading an attributed halt", format!("{e}")),
    }
    if let Err(e) = store.lift_halt(&tenant).await {
        report.record("clearing the attributed halt", format!("{e}"));
    }
}

/// A conditional lift removes only the row it names.
///
/// [`set_halt`](QuotaStore::set_halt) overwrites, so a halt re-thrown after a
/// lifter read the old one stands in the same row. A removal keyed on the
/// scope alone deletes the new halt under a record naming the old one, and the
/// work it stopped starts again with nobody having lifted it.
async fn lift_only_the_halt_read(store: &dyn QuotaStore, report: &mut Report) {
    use crate::quota::HaltScope;

    let scope = HaltScope::agent("conditional-lift");
    let first_by = crate::core::Operator::authenticated("ops-erin").expect("a name");
    let second_by = crate::core::Operator::authenticated("ops-frank").expect("a name");
    let first_at = instant(1_700_000_100);
    let second_at = instant(1_700_000_160);
    let read = |halts: Vec<crate::quota::Halt>| halts.into_iter().find(|h| h.scope == scope);

    report.checked += 1;
    if let Err(e) = store
        .set_halt(&scope, &first_by, first_at, "incident 46")
        .await
    {
        report.record("throwing the halt a lifter reads", format!("{e}"));
        return;
    }
    let first = match store.halts().await.map(read) {
        Ok(Some(h)) => h,
        Ok(None) => {
            report.record(
                "reading the halt a lifter reads",
                "it did not read back".to_owned(),
            );
            return;
        }
        Err(e) => {
            report.record("reading the halt a lifter reads", format!("{e}"));
            return;
        }
    };
    if let Err(e) = store
        .set_halt(&scope, &second_by, second_at, "incident 46")
        .await
    {
        report.record("re-throwing the halt", format!("{e}"));
        return;
    }
    match store.lift_halt_if(&first).await {
        Ok(false) => {}
        Ok(true) => report.record(
            "a conditional lift leaves a re-thrown halt",
            "lifting the halt as first read removed the one re-thrown over it".to_owned(),
        ),
        Err(e) => report.record("lifting a re-thrown halt conditionally", format!("{e}")),
    }
    let second = match store.halts().await.map(read) {
        Ok(Some(h)) if h.by == second_by => h,
        Ok(other) => {
            report.record(
                "a conditional lift leaves a re-thrown halt",
                format!("after a refused conditional lift the scope reads {other:?}"),
            );
            return;
        }
        Err(e) => {
            report.record("reading a re-thrown halt", format!("{e}"));
            return;
        }
    };

    report.checked += 1;
    match store.lift_halt_if(&second).await {
        Ok(true) => {}
        Ok(false) => report.record(
            "a conditional lift removes the halt it names",
            "the row as read back was not removed".to_owned(),
        ),
        Err(e) => report.record("lifting a halt conditionally", format!("{e}")),
    }
    match store.halts().await.map(read) {
        Ok(None) => {}
        Ok(Some(h)) => report.record(
            "a conditional lift removes the halt it names",
            format!("the scope still reads {h:?} after its lift answered removed"),
        ),
        Err(e) => report.record("reading a conditionally lifted halt", format!("{e}")),
    }

    report.checked += 1;
    match store.lift_halt_if(&second).await {
        Ok(false) => {}
        Ok(true) => report.record(
            "a second conditional lift removes nothing",
            "the store answered removed for a row that was already gone".to_owned(),
        ),
        Err(e) => report.record("lifting a lifted halt conditionally", format!("{e}")),
    }
}

/// A distinct dispatch key per `n`, as a run's successive effects have.
fn dispatch(n: u32) -> EffectKey {
    EffectKey::derive(StepId(n), Phase::Forward, 0, 1, "tool.call", b"{}")
}

/// One dispatch of `grant` under `ceiling`.
fn rated(
    grant: &str,
    run: RunId,
    key: EffectKey,
    ceiling: RateCeiling,
    at: Timestamp,
) -> RateReservation {
    RateReservation {
        grant: grant.to_owned(),
        run,
        dispatch: key,
        ceilings: vec![ceiling],
        at,
        exempt: false,
    }
}

fn instant(seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(seconds).expect("a valid test instant")
}

/// Rate ceilings: the count, the key, the sliding window, the undo.
#[allow(clippy::too_many_lines)]
async fn rate(store: &dyn QuotaStore, report: &mut Report) {
    let three = RateCeiling {
        count: 3,
        window_seconds: 60,
    };
    let at = instant(1_760_000_000);
    let grant = "tool://conformance/refund";
    let run = RunId::generate();

    report.checked += 1;
    for n in 0..3 {
        if let Err(e) = store
            .reserve_rate(&rated(grant, run, dispatch(n), three, at))
            .await
        {
            report.record(
                "a rate ceiling admits its count",
                format!("dispatch {} of 3 was refused: {e}", n + 1),
            );
            return;
        }
    }
    report.checked += 1;
    match store
        .reserve_rate(&rated(grant, run, dispatch(3), three, at))
        .await
    {
        Err(QuotaError::RateLimited { reached: 3, .. }) => {}
        Err(e) => report.record(
            "a full window refuses and says what it counted",
            format!("the fourth dispatch failed with `{e}`"),
        ),
        Ok(()) => report.record(
            "a full window refuses",
            "a fourth dispatch was admitted under a ceiling of three",
        ),
    }

    // A retry, or a recovered re-dispatch, carries a key already present.
    report.checked += 1;
    if let Err(e) = store
        .reserve_rate(&rated(grant, run, dispatch(0), three, at))
        .await
    {
        report.record(
            "re-reserving a present dispatch spends nothing and is not judged",
            format!(
                "a dispatch already counted was refused against its own row: {e} —                  every retry of a call the window admitted would be refused"
            ),
        );
    }
    report.checked += 1;
    match store.rate_room(grant, &[three], at).await {
        Err(QuotaError::RateLimited { reached: 3, .. }) => {}
        Err(QuotaError::RateLimited { reached, .. }) => report.record(
            "re-reserving a present dispatch spends nothing",
            format!("three dispatches and a retry read back as {reached}"),
        ),
        other => report.record(
            "asking for room takes none and answers a full window",
            format!("a full window answered {other:?}"),
        ),
    }

    // Two runs making the same call derive the same effect key; each spends.
    let same = "tool://conformance/same-call";
    let two = RateCeiling {
        count: 2,
        window_seconds: 60,
    };
    report.checked += 1;
    for _ in 0..2 {
        if let Err(e) = store
            .reserve_rate(&rated(same, RunId::generate(), dispatch(0), two, at))
            .await
        {
            report.record(
                "two runs making the same call each count",
                format!("the second run's identical call was refused: {e}"),
            );
            return;
        }
    }
    report.checked += 1;
    if store
        .reserve_rate(&rated(same, RunId::generate(), dispatch(0), two, at))
        .await
        .is_ok()
    {
        report.record(
            "two runs making the same call each count",
            "a third run's identical call was admitted under a ceiling of two, so \
             identical calls from different runs share one row and the ceiling \
             admits every run making the same call",
        );
    }

    // Twenty an hour, around an hour boundary: forty in two minutes is the
    // burst a fixed bucket admits and a sliding window refuses.
    let edge = "tool://conformance/boundary";
    let hourly = RateCeiling {
        count: 20,
        window_seconds: 3_600,
    };
    // An hour boundary: a multiple of 3600 seconds.
    let boundary: i64 = 1_760_004_000;
    let edge_run = RunId::generate();
    report.checked += 1;
    for n in 0..20 {
        if let Err(e) = store
            .reserve_rate(&rated(
                edge,
                edge_run,
                dispatch(n),
                hourly,
                instant(boundary - 60),
            ))
            .await
        {
            report.record(
                "a rate ceiling admits its count",
                format!(
                    "dispatch {} of 20 before the boundary was refused: {e}",
                    n + 1
                ),
            );
            return;
        }
    }
    let past = (20..40)
        .map(|n| rated(edge, edge_run, dispatch(n), hourly, instant(boundary + 60)))
        .collect::<Vec<_>>();
    let mut admitted = 0;
    for r in &past {
        if store.reserve_rate(r).await.is_ok() {
            admitted += 1;
        }
    }
    report.checked += 1;
    if admitted > 0 {
        report.record(
            "a window boundary does not double the ceiling",
            format!(
                "twenty dispatches a minute before an hour boundary and {admitted} more a \
                 minute after it were admitted under twenty an hour — the window is a \
                 fixed bucket, not a sliding one"
            ),
        );
    }
    report.checked += 1;
    if let Err(e) = store
        .reserve_rate(&rated(
            edge,
            edge_run,
            dispatch(99),
            hourly,
            instant(boundary - 60 + 3_600 + 1),
        ))
        .await
    {
        report.record(
            "a window that has passed makes room",
            format!("a dispatch an hour after the burst was refused: {e}"),
        );
    }

    // An undo is counted and never refused.
    let undo = "tool://conformance/undo";
    let one = RateCeiling {
        count: 1,
        window_seconds: 60,
    };
    let undo_run = RunId::generate();
    report.checked += 1;
    let _ = store
        .reserve_rate(&rated(undo, undo_run, dispatch(0), one, at))
        .await;
    let mut exempt = rated(undo, undo_run, dispatch(1), one, at);
    exempt.exempt = true;
    if let Err(e) = store.reserve_rate(&exempt).await {
        report.record(
            "an undo is counted and never refused",
            format!("an exempt reservation was refused: {e}"),
        );
    }
    report.checked += 1;
    match store
        .rate_room(
            undo,
            &[RateCeiling {
                count: 2,
                window_seconds: 60,
            }],
            at,
        )
        .await
    {
        Err(QuotaError::RateLimited { reached: 2, .. }) => {}
        other => report.record(
            "an undo is counted",
            format!("a dispatch and an undo under a ceiling of two left room: {other:?}"),
        ),
    }
}

/// Two declarations over one grant with different windows: the narrower one's
/// reservation must not prune rows the wider one still counts — the state of a
/// rolling deploy that changed a tool's ceiling.
async fn rate_windows_share_a_grant(store: &dyn QuotaStore, report: &mut Report) {
    let grant = "tool://conformance/two-windows";
    let hourly = RateCeiling {
        count: 3,
        window_seconds: 3_600,
    };
    let minutely = RateCeiling {
        count: 20,
        window_seconds: 60,
    };
    let start: i64 = 1_760_010_000;
    let run = RunId::generate();
    for n in 0..3 {
        if let Err(e) = store
            .reserve_rate(&rated(grant, run, dispatch(n), hourly, instant(start)))
            .await
        {
            report.record("a rate ceiling admits its count", format!("{e}"));
            return;
        }
    }
    let _ = store
        .reserve_rate(&rated(
            grant,
            run,
            dispatch(3),
            minutely,
            instant(start + 120),
        ))
        .await;
    report.checked += 1;
    if store
        .reserve_rate(&rated(
            grant,
            run,
            dispatch(4),
            hourly,
            instant(start + 180),
        ))
        .await
        .is_ok()
    {
        report.record(
            "a narrower window does not prune a wider one's count",
            "a reservation under 20 a minute pruned the rows three an hour counts, so \
             a fourth dispatch within the hour was admitted — co-deployed declarations \
             with different windows turn the wider ceiling into the narrower one",
        );
    }
}

/// A ceiling built in code with a window wider than a store keeps its rows,
/// or of no time at all, is refused rather than counted: either would admit
/// more than it states.
async fn an_uncountable_rate_window_is_refused(store: &dyn QuotaStore, report: &mut Report) {
    let grant = "tool://conformance/uncountable";
    let at = instant(1_760_020_000);
    for window_seconds in [crate::quota::MAX_RATE_WINDOW_SECONDS + 1, 0] {
        report.checked += 1;
        let ceiling = RateCeiling {
            count: 1,
            window_seconds,
        };
        match store
            .reserve_rate(&rated(grant, RunId::generate(), dispatch(0), ceiling, at))
            .await
        {
            Err(QuotaError::UncountableRate { .. }) => {}
            other => report.record(
                "a rate window no store can count is refused",
                format!("a ceiling of {ceiling} was reserved under: {other:?}"),
            ),
        }
    }
    report.checked += 1;
    let widest = RateCeiling {
        count: 1,
        window_seconds: crate::quota::MAX_RATE_WINDOW_SECONDS,
    };
    if let Err(e) = store
        .reserve_rate(&rated(grant, RunId::generate(), dispatch(1), widest, at))
        .await
    {
        report.record(
            "the widest countable window is counted",
            format!("a ceiling of {widest} was refused: {e}"),
        );
    }
}

/// One tenant's rate count does not throttle another's.
///
/// Two handles on one backend, scoped to different tenants, and one grant.
///
/// # Panics
///
/// Never on a conforming store; the report carries any violation.
pub async fn check_rate_tenants(
    first: &dyn QuotaStore,
    other: &dyn QuotaStore,
    report: &mut Report,
) {
    let at = instant(1_760_000_000);
    let grant = "tool://conformance/tenants";
    let one = RateCeiling {
        count: 1,
        window_seconds: 60,
    };
    report.checked += 1;
    if let Err(e) = first
        .reserve_rate(&rated(grant, RunId::generate(), dispatch(0), one, at))
        .await
    {
        report.record("a rate ceiling admits its count", format!("{e}"));
        return;
    }
    if let Err(e) = other
        .reserve_rate(&rated(grant, RunId::generate(), dispatch(0), one, at))
        .await
    {
        report.record(
            "one tenant's rate count does not throttle another",
            format!(
                "tenant '{}' was refused by tenant '{}''s count: {e}",
                other.tenant(),
                first.tenant()
            ),
        );
    }
}

/// **A rate ceiling holds while two instances dispatch at its edge.**
///
/// Forty dispatches race for a ceiling of ten through two handles onto one
/// tenant; exactly ten may land.
///
/// # Panics
///
/// Never on a conforming store; the report carries any violation.
pub async fn check_rate_race(first: &dyn QuotaStore, second: &dyn QuotaStore, report: &mut Report) {
    let at = instant(1_760_000_000);
    let grant = "tool://conformance/race";
    let ten = RateCeiling {
        count: 10,
        window_seconds: 3_600,
    };
    let attempts = (0..40u32).map(|n| {
        let store = if n % 2 == 0 { first } else { second };
        let reservation = rated(grant, RunId::generate(), dispatch(n), ten, at);
        async move { store.reserve_rate(&reservation).await }
    });
    let outcomes = futures_util::future::join_all(attempts).await;
    report.checked += 1;
    let admitted = outcomes.iter().filter(|o| o.is_ok()).count();
    let refused = outcomes
        .iter()
        .filter(|o| matches!(o, Err(QuotaError::RateLimited { .. })))
        .count();
    if admitted != 10 || refused != 30 {
        report.record(
            "concurrent dispatches at a rate ceiling admit exactly the ceiling",
            format!(
                "{admitted} of 40 dispatches landed under a ceiling of ten ({refused} \
                 refused, {} failed otherwise) — the count and the insert are not one \
                 decision",
                40 - admitted - refused
            ),
        );
    }
}
