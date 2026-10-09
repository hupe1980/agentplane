//! What the case-layer stores must do, checked against any implementation.
//!
//! The journal battery next door covers fencing, exactly-once and chaining.
//! These cover the invariants that live in the *case* stores, and they share one
//! shape: **something must happen at most once, decided by the database rather
//! than by the callers agreeing.**
//!
//! | Store | The thing that must be atomic |
//! |---|---|
//! | [`CaseStore`] | two messages for one new matter produce one case |
//! | [`EventStore`] | one message is delivered to one waiter |
//! | [`TimerStore`] | one wake-up fires once |
//! | [`TaskStore`] | one decision is held by one reviewer |
//! | [`BatchStore`] | one item keeps the run id it was first given |
//!
//! Every one of those is a race, and a race is exactly what a second backend
//! reimplements *nearly* correctly — a `SELECT` then an `INSERT` looks like the
//! atomic version and passes every single-threaded test written for it.

use std::sync::Arc;

use crate::batch::{BatchStore, ItemOutcome};
use crate::case::{CaseStore, ClaimError, EventStore, TargetedDelivery, TaskStore, TimerStore};
use crate::core::{
    BatchId, CaseId, CaseVersion, CorrelationKey, Digest, EffectKey, InboundEvent, Justification,
    OnExpiry, Phase, Priority, RunId, Spend, StepId, StoreError, Subscription, Task, TaskId,
    TaskState, Timestamp,
};

pub use super::conformance::Report;

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

fn keys(n: &str) -> Vec<CorrelationKey> {
    vec![CorrelationKey::new("doc", n)]
}

fn effect(n: u8) -> EffectKey {
    EffectKey::derive(StepId(0), Phase::Forward, u32::from(n), 1, "probe", &[n])
}

// ── Cases ───────────────────────────────────────────────────────────────────

/// Check a [`CaseStore`].
pub async fn check_cases(store: &Arc<dyn CaseStore>, r: &mut Report) {
    correlating_twice_yields_one_case(store, r).await;
    a_closed_case_does_not_match(store, r).await;
    closing_via_set_status_also_releases_the_keys(store, r).await;
    an_unmet_obligation_blocks_closure(store, r).await;
    the_census_counts_every_open_case(store, r).await;
    two_concurrent_messages_open_one_case(store, r).await;
    a_stale_state_write_is_refused(store, r).await;
    a_state_write_to_a_missing_case_is_not_found(store, r).await;
    a_write_to_a_missing_matter_is_not_found(store, r).await;
    only_one_of_several_racing_writers_wins(store, r).await;
    enumeration_pages_without_gap_or_overlap(store, r).await;
    an_imported_case_is_reachable_by_every_read_path(store, r).await;
    concurrent_attaches_all_land_and_land_once(store, r).await;
    a_breached_obligation_is_listable_and_survives_closure(store, r).await;
    an_acknowledged_breach_leaves_the_listing(store, r).await;
    a_breach_cannot_be_transitioned_away(store, r).await;
    a_breach_applies_only_to_what_is_still_owed(store, r).await;
    an_applied_breach_is_owed_its_account_until_noted(store, r).await;
    an_obligation_cannot_be_registered_on_a_closed_case(store, r).await;
    a_reopened_case_correlates_again(store, r).await;
    a_cases_blob_list_holds_only_its_own(store, r).await;
    a_hold_is_placed_once_listed_and_lifted(store, r).await;
    a_hold_on_a_missing_matter_is_not_found(store, r).await;
    a_conditional_release_spares_a_hold_placed_since(store, r).await;
    the_last_drill_is_absent_then_replaced(store, r).await;
    an_erasure_record_is_decided_against_the_hold(store, r).await;
    an_erased_case_takes_no_write_and_no_hold(store, r).await;
    a_named_obligation_is_registered_once(store, r).await;
}

/// **The erasure record is decided against the hold, and the first stands.**
///
/// `begin_erasure` is the decision every destruction rests on, so it has to
/// refuse a held or unclosed matter *without writing* — a record left behind
/// by a refusal would lock a case nobody erased — and a retry has to get the
/// first attempt's instant and reason back, or its tombstones say something
/// the first attempt's did not.
async fn an_erasure_record_is_decided_against_the_hold(store: &Arc<dyn CaseStore>, r: &mut Report) {
    use crate::case::ErasureStart;

    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("ERASE-1"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    match store.begin_erasure(case, ts(5_000), "too early").await {
        Ok(ErasureStart::NotClosed(_)) => {}
        other => {
            return r.record(
                "erasure",
                format!("an open case must refuse its erasure as NotClosed, got {other:?}"),
            );
        }
    }
    let hold = crate::core::LegalHold {
        placed_at: ts(2_000),
        reason: "preservation order".to_owned(),
        by: crate::core::Operator::asserted("compliance").expect("a name"),
    };
    if store.place_hold(case, &hold).await.is_err() || store.close(case).await.is_err() {
        return r.record("erasure", "a case could not be held and closed");
    }
    match store.begin_erasure(case, ts(5_000), "held").await {
        Ok(ErasureStart::Held(back)) if back == hold => {}
        other => {
            return r.record(
                "erasure",
                format!("a held case must refuse its erasure with the hold, got {other:?}"),
            );
        }
    }
    match store.erasure(case).await {
        Ok(None) => {}
        other => {
            return r.record(
                "erasure",
                format!("a refused erasure left a record behind: {other:?}"),
            );
        }
    }
    if store.release_hold(case).await.is_err() {
        return r.record("erasure", "a hold could not be released");
    }
    let first = crate::case::Erasure {
        at: ts(6_000),
        reason: "art-17 request".to_owned(),
        complete: false,
    };
    match store.begin_erasure(case, first.at, &first.reason).await {
        Ok(ErasureStart::Marked(got)) if got == first => {}
        other => {
            return r.record(
                "erasure",
                format!("a closed, unheld case must be marked, got {other:?}"),
            );
        }
    }
    match store.begin_erasure(case, ts(7_000), "a retry").await {
        Ok(ErasureStart::Marked(got)) if got == first => {}
        other => r.record(
            "erasure",
            format!(
                "a retried erasure must get the first record back, so its tombstones say \
                 what the first attempt's did — got {other:?}"
            ),
        ),
    }
    if let Err(e) = store.complete_erasure(case).await {
        return r.record("erasure", format!("completing an erasure failed: {e}"));
    }
    match store.erasure(case).await {
        Ok(Some(got)) if got.complete && got.at == first.at && got.reason == first.reason => {}
        other => r.record(
            "erasure",
            format!("a completed erasure must read back complete and unchanged, got {other:?}"),
        ),
    }
    let missing = CaseId::generate();
    if !matches!(
        store.begin_erasure(missing, ts(1), "nothing").await,
        Err(StoreError::NotFound(_))
    ) {
        r.record("erasure", "an erasure of a missing case must be NotFound");
    }
}

/// **An erased case takes no write and no hold.**
///
/// Reopening one re-claims its correlation keys and routes the next message
/// about the matter into a case whose key is gone; a state write lands under
/// that scope; and a hold accepted after the erasure began preserves nothing
/// while reading as effective. Each is refused, and the case stays closed.
async fn an_erased_case_takes_no_write_and_no_hold(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("ERASE-2"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    if store.close(case).await.is_err()
        || store
            .begin_erasure(case, ts(5_000), "art-17 request")
            .await
            .is_err()
    {
        return r.record("erasure", "a closed case could not be marked erased");
    }
    if !matches!(
        store.set_status(case, crate::core::CaseStatus::Open).await,
        Err(StoreError::CaseErased { .. })
    ) {
        r.record(
            "erasure",
            "an erased case was reopened, or refused as something else",
        );
    }
    let version = match store.case(case).await {
        Ok(Some(c)) => c.version,
        other => return r.record("erasure", format!("reading the case failed: {other:?}")),
    };
    if !matches!(
        store
            .put_state(case, version, serde_json::json!({"again": true}))
            .await,
        Err(StoreError::CaseErased { .. })
    ) {
        r.record(
            "erasure",
            "state was written into an erased case, or refused as something else",
        );
    }
    let hold = crate::core::LegalHold {
        placed_at: ts(6_000),
        reason: "too late".to_owned(),
        by: crate::core::Operator::asserted("compliance").expect("a name"),
    };
    if !matches!(
        store.place_hold(case, &hold).await,
        Err(StoreError::CaseErased { .. })
    ) {
        r.record(
            "erasure",
            "a hold on a case whose erasure had begun was accepted, or refused as \
             something other than an erased case",
        );
    }
    match store.case(case).await {
        Ok(Some(c)) if c.status == crate::core::CaseStatus::Closed => {}
        other => r.record(
            "erasure",
            format!("an erased case must stay closed, got {other:?}"),
        ),
    }
    if !matches!(store.correlate(&keys("ERASE-2")).await, Ok(None)) {
        r.record("erasure", "an erased case's keys were claimed again");
    }
}

/// **A named obligation is registered once.**
///
/// The same terms again are the same registration. Different terms are
/// refused rather than dropped: the journal records the second registration,
/// and a store that kept the first silently would enforce a deadline the
/// journal does not show as current.
async fn a_named_obligation_is_registered_once(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("OBLIGATION-ONCE"), ts(1_000))
        .await
    else {
        return;
    };
    let first = crate::core::Deadline {
        case: opened.case_id(),
        name: "respond".into(),
        resolved_at: ts(9_000),
        calendar_digest: Digest::of(b"cal"),
        warn_at: Some(ts(8_000)),
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if let Err(e) = store.register_deadline(&first).await {
        return r.record("obligation", format!("registering failed: {e}"));
    }
    if let Err(e) = store.register_deadline(&first).await {
        r.record(
            "obligation",
            format!("re-registering the same terms must be the same registration, got {e}"),
        );
    }
    let moved = [
        crate::core::Deadline {
            resolved_at: ts(9_500),
            ..first.clone()
        },
        crate::core::Deadline {
            calendar_digest: Digest::of(b"another calendar"),
            ..first.clone()
        },
        crate::core::Deadline {
            warn_at: None,
            ..first.clone()
        },
    ];
    for later in moved {
        if !matches!(
            store.register_deadline(&later).await,
            Err(StoreError::DeadlineExists { .. })
        ) {
            r.record(
                "obligation",
                "a second registration with different terms was accepted, so the store \
                 enforces terms the journal does not show as current",
            );
        }
    }
    match store.deadlines(first.case).await {
        Ok(held) if held == [first.clone()] => {}
        other => r.record(
            "obligation",
            format!("the first registration must stand unchanged, got {other:?}"),
        ),
    }
}

/// **A rehearsal's verdict: absent before the first, replaced by the latest.**
///
/// Two halves, and the first is the one a store is most likely to get subtly
/// wrong. *Nobody has rehearsed this plane* must read as `None` and not as a
/// zeroed record — an auditor asking *when did you last drill* has to be able
/// to tell "never" from "cleanly, at the epoch", and a store that invented a
/// default would answer the wrong one silently.
///
/// The second is that the row is **replaced**, not appended: this answers
/// *when did you last rehearse*, and a store accumulating history would make
/// the newest verdict a query rather than a read — and eventually a table
/// nobody prunes.
async fn the_last_drill_is_absent_then_replaced(store: &Arc<dyn CaseStore>, r: &mut Report) {
    use crate::case::DrillRecord;

    r.checked += 1;
    // Not asserted as `None` up front: a battery runs against a store that may
    // already hold one, and a case that demanded a virgin store would fail for
    // a reason unrelated to the contract. What is asserted is what each write
    // does to the answer.
    let first = DrillRecord {
        at: ts(7_000),
        sound: false,
        cases: 12,
        findings: 3,
        not_checked: 1,
        origin: "conformance-plane".into(),
        size: 41,
    };
    if let Err(e) = store.record_drill(&first).await {
        r.record("drill record", format!("record_drill failed: {e}"));
        return;
    }
    match store.last_drill().await {
        Ok(Some(got)) if got == first => {}
        Ok(other) => r.record(
            "drill record",
            format!("a rehearsal was written and read back as {other:?}"),
        ),
        Err(e) => r.record("drill record", format!("last_drill failed: {e}")),
    }

    // The later rehearsal is the answer. A store that kept both would leave
    // an operator reading a stale verdict as current.
    let second = DrillRecord {
        at: ts(9_000),
        sound: true,
        cases: 14,
        findings: 0,
        not_checked: 0,
        origin: "conformance-plane".into(),
        size: 57,
    };
    if let Err(e) = store.record_drill(&second).await {
        r.record("drill record", format!("a second record_drill failed: {e}"));
        return;
    }
    match store.last_drill().await {
        Ok(Some(got)) if got == second => {}
        Ok(other) => r.record(
            "drill record",
            format!(
                "a second rehearsal did not replace the first — read back {other:?}, \
                 so an operator sees a stale verdict as current"
            ),
        ),
        Err(e) => r.record("drill record", format!("last_drill failed: {e}")),
    }
}

/// **The one control that can refuse an erasure, held to all four of its
/// halves.**
///
/// A store that satisfies only the first two is a store where a legal hold
/// cannot be found by anybody who does not already know which case they are
/// asking about — which is detection without delivery, and is worth less than
/// no control at all because it also manufactures the belief that somebody was
/// told.
///
/// So: it must be readable back with the *reason and instant it was placed
/// with*; it must appear in a listing keyed by nothing; a second placement must
/// not rewrite the first (a retry that moved the instant would destroy the one
/// fact a hold exists to record); and releasing must empty the listing, because
/// a preservation register that only ever grows is one nobody reviews.
async fn a_hold_is_placed_once_listed_and_lifted(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("HOLD-1"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let hold = crate::core::LegalHold {
        placed_at: ts(2_000),
        reason: "preservation order 2026-114".to_owned(),
        by: crate::core::Operator::authenticated("compliance-dana").expect("a name"),
    };

    match store.place_hold(case, &hold).await {
        Ok(true) => {}
        Ok(false) => {
            return r.record("hold", "a first placement reported that it placed nothing");
        }
        Err(e) => return r.record("hold", format!("placing a hold failed: {e}")),
    }

    match store.hold(case).await {
        Ok(Some(back)) if back == hold => {}
        Ok(other) => r.record(
            "hold",
            format!("a hold must read back as it was placed, got {other:?}"),
        ),
        Err(e) => r.record("hold", format!("reading a hold failed: {e}")),
    }

    // Second placement: the first stands, instant and reason untouched.
    // A different operator on a different basis, so first-placement-wins is
    // checked over *who* as well as over the instant and the reason. A store
    // that let the second write through would attribute a preservation order to
    // whoever retried it last.
    let later = crate::core::LegalHold {
        placed_at: ts(9_000),
        reason: "a retry that must not win".to_owned(),
        by: crate::core::Operator::asserted("a-retry").expect("a name"),
    };
    match store.place_hold(case, &later).await {
        Ok(false) => match store.hold(case).await {
            Ok(Some(back)) if back == hold => {}
            Ok(other) => r.record(
                "hold",
                format!("a second placement rewrote the hold: {other:?}"),
            ),
            Err(e) => r.record("hold", format!("reading a hold failed: {e}")),
        },
        Ok(true) => r.record(
            "hold",
            "a second placement reported itself as the first — a retry must not \
             move when a hold began or why",
        ),
        Err(e) => r.record("hold", format!("a repeated placement failed: {e}")),
    }

    // Listable by somebody who does not know the case id.
    match store.holds(None, 50).await {
        Ok(listed) => {
            if !listed.iter().any(|(c, h)| *c == case && *h == hold) {
                r.record(
                    "hold",
                    "a held matter is not in the hold listing, so it can only be \
                     found by somebody who already knows the answer",
                );
            }
        }
        Err(e) => r.record("hold", format!("listing holds failed: {e}")),
    }

    match store.release_hold(case).await {
        Ok(true) => {}
        Ok(false) => r.record("hold", "releasing a placed hold reported nothing to lift"),
        Err(e) => r.record("hold", format!("releasing a hold failed: {e}")),
    }

    match store.hold(case).await {
        Ok(None) => {}
        Ok(Some(_)) => r.record("hold", "a released hold is still in force"),
        Err(e) => r.record("hold", format!("reading a hold failed: {e}")),
    }
    match store.holds(None, 50).await {
        Ok(listed) if listed.iter().any(|(c, _)| *c == case) => r.record(
            "hold",
            "a released hold is still listed — the listing has no verb that \
             empties it, so it is a level that only rises",
        ),
        Ok(_) => {}
        Err(e) => r.record("hold", format!("listing holds failed: {e}")),
    }

    match store.release_hold(case).await {
        Ok(false) => {}
        Ok(true) => r.record("hold", "releasing twice reported a second lift"),
        Err(e) => r.record("hold", format!("a repeated release failed: {e}")),
    }
}

/// **A conditional release removes only the hold it names.**
///
/// A release followed by a re-place puts a new hold where the read one was;
/// a releaser still holding the old read must not delete the new one under a
/// record that names the old.
async fn a_conditional_release_spares_a_hold_placed_since(
    store: &Arc<dyn CaseStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("HOLD-IF-1"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let first = crate::core::LegalHold {
        placed_at: ts(2_000),
        reason: "preservation order 2026-201".to_owned(),
        by: crate::core::Operator::authenticated("compliance-dana").expect("a name"),
    };
    let second = crate::core::LegalHold {
        placed_at: ts(3_000),
        reason: "preservation order 2026-202".to_owned(),
        by: crate::core::Operator::authenticated("compliance-eli").expect("a name"),
    };
    if store.place_hold(case, &first).await.is_err()
        || store.release_hold(case).await.is_err()
        || store.place_hold(case, &second).await.is_err()
    {
        return r.record("hold-if", "placing, releasing and placing again failed");
    }
    match store.release_hold_if(case, &first).await {
        Ok(false) => {}
        Ok(true) => r.record(
            "hold-if",
            "a release naming the old hold reported removing the new one",
        ),
        Err(e) => r.record("hold-if", format!("a conditional release failed: {e}")),
    }
    match store.hold(case).await {
        Ok(Some(back)) if back == second => {}
        Ok(other) => r.record(
            "hold-if",
            format!("a release naming the old hold removed the new one: {other:?}"),
        ),
        Err(e) => r.record("hold-if", format!("reading a hold failed: {e}")),
    }
    match store.release_hold_if(case, &second).await {
        Ok(true) => {}
        Ok(false) => r.record(
            "hold-if",
            "a release naming the standing hold removed nothing",
        ),
        Err(e) => r.record("hold-if", format!("a conditional release failed: {e}")),
    }
    match store.hold(case).await {
        Ok(None) => {}
        Ok(Some(_)) => r.record("hold-if", "a conditionally released hold is still in force"),
        Err(e) => r.record("hold-if", format!("reading a hold failed: {e}")),
    }
    match store.holds(None, 50).await {
        Ok(listed) if listed.iter().any(|(c, _)| *c == case) => {
            r.record("hold-if", "a conditionally released hold is still listed");
        }
        Ok(_) => {}
        Err(e) => r.record("hold-if", format!("listing holds failed: {e}")),
    }
    match store.release_hold_if(case, &second).await {
        Ok(false) => {}
        Ok(true) => r.record(
            "hold-if",
            "a repeated conditional release reported a second lift",
        ),
        Err(e) => r.record(
            "hold-if",
            format!("a repeated conditional release failed: {e}"),
        ),
    }
    match store.release_hold_if(CaseId::generate(), &second).await {
        Err(StoreError::NotFound(_)) => {}
        other => r.record(
            "hold-if",
            format!("a conditional release on a missing matter must be NotFound, got {other:?}"),
        ),
    }
}

/// A hold on a matter that is not there would read as effective in the listing
/// while preserving nothing.
async fn a_hold_on_a_missing_matter_is_not_found(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let absent = CaseId::generate();
    let hold = crate::core::LegalHold {
        placed_at: ts(2_000),
        reason: "on nothing".to_owned(),
        by: crate::core::Operator::authenticated("compliance-dana").expect("a name"),
    };
    match store.place_hold(absent, &hold).await {
        Err(StoreError::NotFound(_)) => {}
        other => r.record(
            "hold",
            format!("a hold on a missing matter must be NotFound, got {other:?}"),
        ),
    }
    match store.release_hold(absent).await {
        Err(StoreError::NotFound(_)) => {}
        other => r.record(
            "hold",
            format!("releasing on a missing matter must be NotFound, got {other:?}"),
        ),
    }
}

/// The obligation listing drains, and only by somebody answering it.
///
/// Four halves, because the first two alone are satisfied by a store that
/// simply forgets: the breach must leave the listing when acknowledged, the
/// **account must still be readable** on the obligation, the first account must
/// stand against a second, and an obligation that has not been breached must
/// refuse one.
///
/// The reason this is contract rather than convenience: the listing is ordered
/// longest-overdue first and bounded by a page. A store that never removes an
/// entry shows the same head forever, so every breach after the page boundary
/// is unreachable — and the entries an operator could still act on are exactly
/// the ones they never see. The gauge beside it has the same defect in the
/// other direction: a level that cannot fall says only that this deployment has
/// ever missed something.
async fn an_acknowledged_breach_leaves_the_listing(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("BRE-ACK"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let deadline = |name: &str| crate::core::Deadline {
        case,
        name: name.to_owned(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if store
        .register_deadline(&deadline("answered"))
        .await
        .is_err()
        || store.register_deadline(&deadline("pending")).await.is_err()
    {
        r.record("breach account", "register_deadline failed");
        return;
    }
    let _ = store
        .set_deadline_state(case, "answered", crate::core::DeadlineState::Breached)
        .await;

    // An account before the breach would take an obligation off the listing
    // while it was still going to be missed.
    let note = crate::core::BreachNote {
        // Asserted, so the battery proves the basis survives the store rather
        // than defaulting to the one a reader might assume.
        by: crate::core::Operator::asserted("compliance@example.test")
            .expect("a well-formed actor"),
        note: "filed under Q3 exceptions".to_owned(),
        at: ts(9_500),
    };
    match store.acknowledge_breach(case, "pending", &note).await {
        Err(StoreError::NotBreached { .. }) => {}
        Ok(_) => r.record(
            "breach account",
            "an obligation that has not been breached accepted an account, which takes it off the \
             listing before it was ever due",
        ),
        Err(other) => r.record(
            "breach account",
            format!("an account before the breach must refuse as `NotBreached`, not `{other}`"),
        ),
    }

    let before = store.census(ts(9_600)).await.map_or(0, |c| c.breached);
    match store.acknowledge_breach(case, "answered", &note).await {
        Ok(true) => {}
        Ok(false) => {
            r.record(
                "breach account",
                "the first account reported that somebody had already answered",
            );
            return;
        }
        Err(e) => {
            r.record("breach account", format!("acknowledge_breach failed: {e}"));
            return;
        }
    }

    match store.breached(1_000).await {
        Ok(list) => {
            if list.iter().any(|d| d.case == case && d.name == "answered") {
                r.record(
                    "breach account",
                    "an acknowledged breach stayed on the listing. Ordered longest-overdue first, \
                     an entry nothing removes occupies the page forever and every later breach is \
                     unreachable",
                );
            }
        }
        Err(e) => r.record("breach account", format!("breached() failed with {e}")),
    }

    the_fact_survives_the_answer(store, case, &note, r).await;

    match store.census(ts(9_600)).await {
        Ok(c) if c.breached + 1 == before => {}
        Ok(c) => r.record(
            "breach account",
            format!(
                "the unaccounted-breach gauge went {before} -> {} across one \
                 acknowledgement. A gauge that does not fall when somebody acts \
                 cannot say whether there is work outstanding",
                c.breached
            ),
        ),
        Err(e) => r.record("breach account", format!("census() failed with {e}")),
    }

    the_first_account_stands(store, case, &note, r).await;
}

/// The breach outlives the account of it, and so does the account.
///
/// Checked separately from the listing, because a store that dropped the state
/// on acknowledgement would satisfy *left the listing* exactly — by forgetting
/// what happened. What ends is the question, not the fact.
async fn the_fact_survives_the_answer(
    store: &Arc<dyn CaseStore>,
    case: CaseId,
    note: &crate::core::BreachNote,
    r: &mut Report,
) {
    match store.deadlines(case).await {
        Ok(list) => match list.iter().find(|d| d.name == "answered") {
            Some(d) if d.state != crate::core::DeadlineState::Breached => r.record(
                "breach account",
                "acknowledging a breach changed its state. What ends is the question, not the \
                 fact — an obligation that was missed stays missed",
            ),
            Some(d) => match &d.acknowledged {
                None => r.record(
                    "breach account",
                    "the account was not readable back, so who answered for a missed obligation \
                     is a fact the store took and did not keep",
                ),
                Some(a) if a.by != note.by || a.note != note.note || a.at != note.at => r.record(
                    "breach account",
                    "the account read back different from the one recorded",
                ),
                Some(_) => {}
            },
            None => r.record("breach account", "the obligation disappeared"),
        },
        Err(e) => r.record("breach account", format!("deadlines() failed with {e}")),
    }
}

/// The second account is refused the *rewrite*, not the call.
///
/// Acknowledging twice is a retry — a delivery that timed out after the write
/// landed looks exactly like one that never landed — so it must succeed and say
/// which happened. What it must not do is change who looked or when: the record
/// of who answered is the answer.
async fn the_first_account_stands(
    store: &Arc<dyn CaseStore>,
    case: CaseId,
    first: &crate::core::BreachNote,
    r: &mut Report,
) {
    let later = crate::core::BreachNote {
        by: crate::core::Operator::authenticated("someone-else@example.test")
            .expect("a well-formed actor"),
        note: "second".to_owned(),
        at: ts(9_900),
    };
    match store.acknowledge_breach(case, "answered", &later).await {
        Ok(false) => {}
        Ok(true) => r.record(
            "breach account",
            "a second account reported itself as the one recorded",
        ),
        Err(e) => r.record(
            "breach account",
            format!("acknowledging twice must be idempotent, not `{e}`"),
        ),
    }
    if let Ok(list) = store.deadlines(case).await
        && let Some(d) = list.iter().find(|d| d.name == "answered")
        && d.acknowledged.as_ref().is_some_and(|a| a.by != first.by)
    {
        r.record(
            "breach account",
            "a second account overwrote the first. The record of who answered is \
             the answer, so a retry must not rewrite it",
        );
    }
}

/// How an obligation ended is not editable.
///
/// The state column is the only record that a window closed unmet, and
/// `set_deadline_state` is reachable from a skill — `cx.meet_deadline` is the
/// same write. A run that answered late would otherwise take the miss off the
/// operator's listing and out of the row in one call, leaving no account of it
/// anywhere: not a stale row, an erased one. Answering late is a fact to record
/// beside the breach.
///
/// The positive half is checked with it, because a store that refused *every*
/// transition would satisfy the negative one exactly: re-applying the state
/// already held must still succeed, since every writer here is a sweep or a
/// resumed run and both repeat their own last write by design.
async fn a_breach_cannot_be_transitioned_away(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("BRE-FINAL"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let deadline = crate::core::Deadline {
        case,
        name: "final".into(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if store.register_deadline(&deadline).await.is_err() {
        r.record("obligation lifecycle", "register_deadline failed");
        return;
    }
    if store
        .set_deadline_state(case, "final", crate::core::DeadlineState::Breached)
        .await
        .is_err()
    {
        r.record(
            "obligation lifecycle",
            "a pending obligation must be breachable",
        );
        return;
    }
    // Idempotent re-application, which a sweep repeating its own last write
    // relies on.
    if let Err(e) = store
        .set_deadline_state(case, "final", crate::core::DeadlineState::Breached)
        .await
    {
        r.record(
            "obligation lifecycle",
            format!(
                "re-applying the state already held was refused as `{e}` — a sweep repeating its \
                 own write is a retry, not an edit"
            ),
        );
    }
    for to in [
        crate::core::DeadlineState::Met,
        crate::core::DeadlineState::Cancelled,
        crate::core::DeadlineState::Pending,
    ] {
        match store.set_deadline_state(case, "final", to).await {
            Err(StoreError::DeadlineFinal { .. }) => {}
            Ok(()) => {
                r.record(
                    "obligation lifecycle",
                    format!(
                        "a breached obligation became `{}`. The state column is the only record \
                         that the window closed unmet, so this does not leave a stale row — it \
                         erases one",
                        to.as_str()
                    ),
                );
                return;
            }
            Err(other) => r.record(
                "obligation lifecycle",
                format!(
                    "moving a breached obligation must refuse as `DeadlineFinal`, not as \
                     `{other}`"
                ),
            ),
        }
    }
}

/// **An applied breach is owed its account until the sweep notes it.**
///
/// The sweep breaches first and writes its notes after, so the mark that a
/// breach still owes its account is what a crash between the two leaves for
/// the next tick: written by the breach in its own transaction, cleared by
/// `mark_breach_noted`, and never set by a breach that did not apply.
async fn an_applied_breach_is_owed_its_account_until_noted(
    store: &Arc<dyn CaseStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let Ok(case) = store
        .correlate_or_open("matter", &keys("BREACH-OWED"), ts(1_000))
        .await
        .map(crate::case::Correlation::case_id)
    else {
        r.record("owed breach", "the fixture could not open its case");
        return;
    };
    for (name, resolved) in [("owed", 2_000), ("not-yet", 9_000)] {
        if store
            .register_deadline(&crate::core::Deadline {
                case,
                name: name.into(),
                resolved_at: ts(resolved),
                calendar_digest: crate::core::Digest::of(b"cal"),
                warn_at: None,
                state: crate::core::DeadlineState::Pending,
                acknowledged: None,
            })
            .await
            .is_err()
        {
            r.record(
                "owed breach",
                "the fixture could not register its obligations",
            );
            return;
        }
    }
    let owed = |store: Arc<dyn CaseStore>| async move {
        store.breaches_to_note(1_000).await.map(|list| {
            list.into_iter()
                .filter(|d| d.case == case)
                .map(|d| d.name)
                .collect::<Vec<_>>()
        })
    };
    let _ = store.breach_deadline(case, "owed", ts(3_000)).await;
    let _ = store.breach_deadline(case, "not-yet", ts(3_000)).await;
    match owed(Arc::clone(store)).await {
        Ok(names) if names == ["owed"] => {}
        other => {
            r.record(
                "owed breach",
                format!(
                    "an applied breach must be owed its account and a refused one must not: {other:?}"
                ),
            );
            return;
        }
    }
    if store.mark_breach_noted(case, "owed").await.is_err() {
        r.record("owed breach", "marking a breach noted failed");
        return;
    }
    if !matches!(owed(Arc::clone(store)).await, Ok(names) if names.is_empty()) {
        r.record("owed breach", "a noted breach is still owed its account");
    }
}

/// **A breach applies only to what is still owed and due, and escalates only
/// an open matter.**
///
/// The sweep decides from a `due` read that is stale by the time it acts. A
/// run that met the obligation and closed the case in between has settled it;
/// a breach written anyway reopens a closed matter and misreports a met duty
/// as missed. `breach_deadline` makes the check and both writes one decision.
async fn a_breach_applies_only_to_what_is_still_owed(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let register = |label: &'static str, resolved: i64| {
        let store = Arc::clone(store);
        async move {
            let case = store
                .correlate_or_open("matter", &keys(label), ts(1_000))
                .await
                .ok()?
                .case_id();
            store
                .register_deadline(&crate::core::Deadline {
                    case,
                    name: "owed".into(),
                    resolved_at: ts(resolved),
                    calendar_digest: crate::core::Digest::of(b"cal"),
                    warn_at: None,
                    state: crate::core::DeadlineState::Pending,
                    acknowledged: None,
                })
                .await
                .ok()?;
            Some(case)
        }
    };
    let (Some(due), Some(early), Some(met)) = (
        register("BREACH-DUE", 2_000).await,
        register("BREACH-EARLY", 9_000).await,
        register("BREACH-MET", 2_000).await,
    ) else {
        r.record("breach", "the fixture could not register its obligations");
        return;
    };

    match store.breach_deadline(due, "owed", ts(3_000)).await {
        Ok(true) => {}
        other => r.record(
            "breach",
            format!("a due, outstanding obligation was not breached: {other:?}"),
        ),
    }
    let status = |case| {
        let store = Arc::clone(store);
        async move { store.case(case).await.ok().flatten().map(|c| c.status) }
    };
    if status(due).await != Some(crate::core::CaseStatus::Escalated) {
        r.record("breach", "a breach did not escalate its open case");
    }

    if !matches!(
        store.breach_deadline(early, "owed", ts(3_000)).await,
        Ok(false)
    ) {
        r.record("breach", "an obligation not yet due was breached");
    }

    // The race the verb exists for: met and closed after the sweep read it.
    let settled = store
        .set_deadline_state(met, "owed", crate::core::DeadlineState::Met)
        .await
        .is_ok()
        && store.close(met).await.is_ok();
    if !settled {
        r.record("breach", "the fixture could not meet and close its case");
        return;
    }
    match store.breach_deadline(met, "owed", ts(3_000)).await {
        Ok(false) => {}
        other => r.record(
            "breach",
            format!(
                "an obligation met since the sweep read it answered {other:?} — a met duty \
                 is reported as missed"
            ),
        ),
    }
    if status(met).await != Some(crate::core::CaseStatus::Closed) {
        r.record(
            "breach",
            "a closed matter was reopened by a breach of an obligation it had met",
        );
    }
}

/// A closed case may not acquire a new obligation.
///
/// Closure refuses an outstanding obligation, and on its own that is a check at
/// one instant rather than a property of the store. This is the write that
/// walks past it: register an obligation afterwards and the sweep breaches it
/// and escalates, so a matter audited as settled acquires a duty and misses it
/// with no run and no operator involved.
///
/// Both backends must refuse, and the refusal must be typed — a closed case
/// reported as a backend fault is indistinguishable from a store that was
/// briefly down, which is the reading that turns enforcement into an outage.
async fn an_obligation_cannot_be_registered_on_a_closed_case(
    store: &Arc<dyn CaseStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("INV-CLOSED"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    if store.close(case).await.is_err() {
        r.record("closure", "a case with no obligations must be closable");
        return;
    }
    let late = crate::core::Deadline {
        case,
        name: "late".into(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    match store.register_deadline(&late).await {
        Err(StoreError::CaseClosed { .. }) => {}
        Ok(()) => r.record(
            "closure",
            "an obligation was registered on a closed case. Closure refusing an outstanding \
             obligation is a precondition, not an invariant, unless this write refuses too — the \
             sweep will breach this one and escalate a matter nobody is watching",
        ),
        Err(other) => r.record(
            "closure",
            format!(
                "registering on a closed case must refuse as `CaseClosed`, not as `{other}` — a \
                 business refusal wearing a fault's type makes an outage read as enforcement"
            ),
        ),
    }
}

/// A case that leaves `Closed` can correlate again.
///
/// Closure releases the correlation keys so a genuinely new matter about the
/// same entity opens a fresh case. Read backwards, that is a rule with a second
/// half: a case reopened by any route — a run's `set_case_status`, the sweep
/// escalating over an expired task — must take the free ones back, or it comes
/// back as a matter no inbound message can ever reach. Live-looking and
/// unreachable is the drift `close` exists to prevent, in the other direction.
///
/// The negative half is the load-bearing one: a key another case has since
/// claimed stays with that case. A reopening that took one back would silently
/// redirect a live matter's traffic.
async fn a_reopened_case_correlates_again(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let free = keys("REOPEN-FREE");
    let taken = vec![
        CorrelationKey::new("doc", "REOPEN-FREE"),
        CorrelationKey::new("doc", "REOPEN-TAKEN"),
    ];
    let Ok(opened) = store.correlate_or_open("matter", &taken, ts(1_000)).await else {
        return;
    };
    let case = opened.case_id();
    if store.close(case).await.is_err() {
        r.record("reopening", "a case with no obligations must be closable");
        return;
    }
    // A new matter claims one of the two keys while the first is closed.
    let Ok(successor) = store
        .correlate_or_open(
            "matter",
            &[CorrelationKey::new("doc", "REOPEN-TAKEN")],
            ts(2_000),
        )
        .await
    else {
        r.record("reopening", "a released key must be claimable");
        return;
    };
    if successor.case_id() == case {
        r.record("reopening", "closing did not release the keys");
        return;
    }

    if store
        .set_status(case, crate::core::CaseStatus::Escalated)
        .await
        .is_err()
    {
        r.record("reopening", "set_status off Closed failed");
        return;
    }
    match store.correlate(&free).await {
        Ok(Some(found)) if found == case => {}
        Ok(other) => r.record(
            "reopening",
            format!(
                "a reopened case did not take back its free correlation key (correlate answered \
                 {other:?}). It is open, it looks live, and no inbound message can ever reach it"
            ),
        ),
        Err(e) => r.record("reopening", format!("correlate failed with {e}")),
    }
    match store
        .correlate(&[CorrelationKey::new("doc", "REOPEN-TAKEN")])
        .await
    {
        Ok(Some(found)) if found == successor.case_id() => {}
        Ok(other) => r.record(
            "reopening",
            format!(
                "reopening took back a key another open case holds (correlate answered \
                 {other:?}). The identifier belongs to whichever matter is open for it now, and \
                 stealing it redirects that matter's traffic"
            ),
        ),
        Err(e) => r.record("reopening", format!("correlate failed with {e}")),
    }
}

/// A case's blob list is its own, and the negative half is the load-bearing one.
///
/// `blobs_of` is the list an erasure request walks, so a list that answers with
/// another matter's artifacts erases data nobody asked about — tombstones
/// written across matters, and a count that reports more discharged than the
/// case ever held. Asserting only that the case's own digest is *present* is
/// one-sided: a `blobs_of` that returned every case's blobs satisfies it
/// exactly, which is how a de-scoped read passed a battery that had checked it.
async fn a_cases_blob_list_holds_only_its_own(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let (Ok(mine), Ok(theirs)) = (
        store
            .correlate_or_open("blob-scope", &keys("C-BLOBS-MINE"), ts(1_000))
            .await,
        store
            .correlate_or_open("blob-scope", &keys("C-BLOBS-THEIRS"), ts(1_000))
            .await,
    ) else {
        r.record("blobs", "the fixture cases did not open");
        return;
    };
    let (mine, theirs) = (mine.case_id(), theirs.case_id());

    let ours = Digest::of(b"conformance: this matter's artifact");
    let other = Digest::of(b"conformance: another matter's artifact");
    if let Err(e) = store.link_blob(mine, ours, ts(1_001)).await {
        r.record("blobs", format!("linking this case's artifact failed: {e}"));
        return;
    }
    if let Err(e) = store.link_blob(theirs, other, ts(1_001)).await {
        r.record(
            "blobs",
            format!("linking the other case's artifact failed: {e}"),
        );
        return;
    }

    match store.blobs_of(mine).await {
        Ok(list) => {
            if !list.contains(&ours) {
                r.record(
                    "blobs",
                    "a case's own artifact is missing from its blob list — erasure \
                     cannot find the bytes from the matter that names them",
                );
            }
            if list.contains(&other) {
                r.record(
                    "blobs",
                    "a case's blob list carries another case's artifact — an erasure \
                     request for one matter reaches a matter nobody named, and reports \
                     more artifacts discharged than the case ever held",
                );
            }
        }
        Err(e) => r.record(
            "blobs",
            format!("a case's blob list could not be read: {e}"),
        ),
    }
}

/// A missed obligation is findable without knowing which case to open, and
/// stays findable after that case is closed.
///
/// Delivering a breach through the case it escalated is the trap: that is a
/// status, `close` admits a case once nothing is still *outstanding*, and a
/// breach is not outstanding — so the last handle on a missed regulatory window
/// goes exactly when the case stops being watched.
///
/// Three halves, because a listing that answered "everything" would satisfy the
/// first two: the breach must appear, it must still appear after closure, and
/// an obligation that was *met* must not appear at all.
async fn a_breached_obligation_is_listable_and_survives_closure(
    store: &Arc<dyn CaseStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("BRE-1"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let deadline = |name: &str| crate::core::Deadline {
        case,
        name: name.to_owned(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if store.register_deadline(&deadline("missed")).await.is_err()
        || store.register_deadline(&deadline("kept")).await.is_err()
    {
        r.record("breach listing", "register_deadline failed");
        return;
    }
    let _ = store
        .set_deadline_state(case, "missed", crate::core::DeadlineState::Breached)
        .await;
    let _ = store
        .set_deadline_state(case, "kept", crate::core::DeadlineState::Met)
        .await;

    let mine = |list: Vec<crate::core::Deadline>| -> Vec<String> {
        list.into_iter()
            .filter(|d| d.case == case)
            .map(|d| d.name)
            .collect()
    };

    match store.breached(1_000).await {
        Ok(list) => {
            let names = mine(list);
            if !names.iter().any(|n| n == "missed") {
                r.record(
                    "breach listing",
                    "a breached obligation was not listed, so the only party who \
                     could find it is one who already knows which case to open",
                );
            }
            if names.iter().any(|n| n == "kept") {
                r.record(
                    "breach listing",
                    "an obligation that was met was listed as breached — the \
                     listing does not read state, so every finding in it is noise",
                );
            }
        }
        Err(e) => {
            r.record("breach listing", format!("breached() failed with {e}"));
            return;
        }
    }

    if store.close(case).await.is_err() {
        r.record(
            "breach listing",
            "a case whose obligations are resolved-or-breached must be closable",
        );
        return;
    }
    match store.breached(1_000).await {
        Ok(list) => {
            if !mine(list).iter().any(|n| n == "missed") {
                r.record(
                    "breach listing",
                    "closing the case took the breach off the list. Closure is \
                     when people stop looking, which is precisely when the \
                     record has to outlive the status that produced it",
                );
            }
        }
        Err(e) => r.record(
            "breach listing",
            format!("breached() failed after closure with {e}"),
        ),
    }
}

/// Every mutation of a matter that does not exist says so.
///
/// `put_state` already has this pinned; `close` and `set_deadline_state` are
/// the other verbs a sweep or an operator drives blind, and a backend that
/// discards their row counts reports success for a decision that landed
/// nowhere — a closed case nobody closed, a breached obligation nobody
/// registered.
async fn a_write_to_a_missing_matter_is_not_found(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let ghost = CaseId::generate();
    match store.close(ghost).await {
        Err(StoreError::NotFound(_)) => {}
        Ok(()) => r.record(
            "missing rows",
            "closing a case that does not exist reported success — the caller \
             now believes an audited matter was settled",
        ),
        Err(e) => r.record(
            "missing rows",
            format!("closing a missing case was answered with {e}"),
        ),
    }
    match store
        .set_deadline_state(ghost, "response-due", crate::core::DeadlineState::Breached)
        .await
    {
        Err(StoreError::NotFound(_)) => {}
        Ok(()) => r.record(
            "missing rows",
            "a deadline transition on an obligation nobody registered reported \
             success — the sweep's decision was written into nothing",
        ),
        Err(e) => r.record(
            "missing rows",
            format!("a missing deadline transition was answered with {e}"),
        ),
    }
}

/// **Concurrent attaches all land, and each run lands once.**
///
/// `attach_run` allocates the next position in the case's run order, and two
/// instances attaching different runs at the same moment must not both take
/// one position — nor may the collision surface as an error, because the
/// runs already executed and their attachment is a fact being recorded, not
/// requested. The store retries or serialises; the caller sees every run
/// attached exactly once.
async fn concurrent_attaches_all_land_and_land_once(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let opened = store
        .correlate_or_open("attach-race", &keys("C-ATTACH-RACE"), ts(1_000))
        .await;
    let Ok(crate::case::Correlation::Opened(case)) = opened else {
        r.record(
            "attach",
            format!("the fixture case did not open: {opened:?}"),
        );
        return;
    };

    let runs: Vec<RunId> = (0..4).map(|_| RunId::generate()).collect();
    let mut handles = Vec::new();
    for run in &runs {
        let store = Arc::clone(store);
        let run = *run;
        handles.push(tokio::spawn(
            async move { store.attach_run(case, run).await },
        ));
    }
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            other => {
                r.record(
                    "attach",
                    format!(
                        "a concurrent attach failed instead of serialising: {other:?} — \
                         the run executed, and the record of it joining its matter is \
                         a fact the store refused to hold"
                    ),
                );
                return;
            }
        }
    }
    // Idempotence under the same contention rules.
    let _ = store.attach_run(case, runs[0]).await;

    match store.case(case).await {
        Ok(Some(read)) => {
            let mut attached: Vec<String> = read.runs.iter().map(ToString::to_string).collect();
            attached.sort_unstable();
            let mut expected: Vec<String> = runs.iter().map(ToString::to_string).collect();
            expected.sort_unstable();
            if attached != expected {
                r.record(
                    "attach",
                    format!(
                        "after four concurrent attaches the case holds {:?} — every \
                         run must appear exactly once, in a stable order",
                        read.runs
                    ),
                );
            }
        }
        other => r.record(
            "attach",
            format!("the case could not be read back: {other:?}"),
        ),
    }
}

/// `cases` pages exhaustively: every case exactly once, whatever the limit.
///
/// A bounded list with no cursor enumerates a prefix and calls it everything —
/// and this method's one caller is the export, whose whole job is
/// completeness. The check drives the cursor with a page size smaller than the
/// population, which is the shape a big store forces and a small test forgets.
async fn enumeration_pages_without_gap_or_overlap(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let mut opened = std::collections::BTreeSet::new();
    for n in 0..5 {
        let Ok(c) = store
            .correlate_or_open("page", &keys(&format!("PAGE-{n}")), ts(2_000 + n))
            .await
        else {
            r.record("enumeration", "correlate_or_open failed while seeding");
            return;
        };
        opened.insert(c.case_id());
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut after = None;
    loop {
        let Ok(page) = store.cases(after, 2).await else {
            r.record("enumeration", "cases() failed mid-page");
            return;
        };
        let full = page.len() >= 2;
        for case in page {
            if !seen.insert(case.id) {
                r.record(
                    "enumeration",
                    "cases() served one case on two pages — an export would carry \
                     the matter twice and the verifier would read a duplicate",
                );
                return;
            }
            after = Some(case.id);
        }
        if !full {
            break;
        }
    }
    // Superset, not equality: earlier checks leave their own cases behind, and
    // holding this check to an exact count would couple it to their fixtures.
    if !opened.is_subset(&seen) {
        r.record(
            "enumeration",
            "cases() finished without serving every case — an export taken from \
             this store silently drops matters",
        );
    }
}

/// An imported case is indistinguishable from one the store built itself.
///
/// `import_case` maintains every index by hand, which is the shape that drifts:
/// an import that rebuilds five indexes out of six reads perfectly until
/// somebody queries the sixth. So the read paths are the check — `case`,
/// `correlate`, `by_status`, `due`, `blobs_of` — and a second import of the
/// same id must refuse, because a restore rebuilds a case layer rather than
/// merging one.
async fn an_imported_case_is_reachable_by_every_read_path(
    store: &Arc<dyn CaseStore>,
    r: &mut Report,
) {
    use crate::core::{Case, CaseStatus, CaseVersion, Deadline, DeadlineState};
    r.checked += 1;

    let id = crate::core::CaseId::generate();
    let case = Case {
        id,
        kind: "imported".to_owned(),
        status: CaseStatus::Escalated,
        correlation: vec![CorrelationKey::new("doc", "IMPORT-1")],
        state: serde_json::json!({"carried": true}),
        version: CaseVersion(41),
        opened_at: ts(3_000),
        runs: vec![crate::core::RunId::generate()],
    };
    let deadline = Deadline {
        case: id,
        name: "respond-by".to_owned(),
        resolved_at: ts(9_000),
        calendar_digest: Digest::of(b"cal"),
        warn_at: Some(ts(8_000)),
        state: DeadlineState::Pending,
        acknowledged: None,
    };
    let blob = Digest::of(b"artifact");
    if store
        .import_case(&case, &[deadline], &[blob])
        .await
        .is_err()
    {
        r.record("import", "import_case refused a fresh case");
        return;
    }

    let Ok(Some(read)) = store.case(id).await else {
        r.record("import", "an imported case is not readable by `case`");
        return;
    };
    // Version and status are the fields a restore exists to carry —
    // `put_state` cannot say "version 41" and `correlate_or_open` cannot say
    // "escalated".
    if read.version != CaseVersion(41)
        || read.status != CaseStatus::Escalated
        || read.runs != case.runs
        || read.correlation != case.correlation
    {
        r.record(
            "import",
            "an imported case read back with different fields than it was \
             given — the restore is lossy where it claims fidelity",
        );
    }
    if !matches!(
        store.correlate(&case.correlation).await,
        Ok(Some(found)) if found == id
    ) {
        r.record(
            "import",
            "an imported open case is invisible to correlation — the next inbound \
             message about this matter opens a duplicate",
        );
    }
    if !matches!(
        store.by_status(CaseStatus::Escalated, 100).await,
        Ok(cases) if cases.iter().any(|c| c.id == id)
    ) {
        r.record(
            "import",
            "an imported escalated case is missing from the status worklist — \
             whoever clears escalations cannot find it",
        );
    }
    if !matches!(
        store.due(ts(10_000), 500).await,
        Ok(due) if due.iter().any(|d| d.case == id)
    ) {
        r.record(
            "import",
            "an imported pending obligation is invisible to the sweep — the \
             deadline breaches and nothing notices",
        );
    }
    if !matches!(
        store.blobs_of(id).await,
        Ok(blobs) if blobs.contains(&blob)
    ) {
        r.record(
            "import",
            "an imported blob link is unreachable — erasure cannot find the \
             artifact from the case that names it",
        );
    }
    if store.import_case(&case, &[], &[]).await.is_ok() {
        r.record(
            "import",
            "importing an existing case succeeded — a second restore can silently \
             rewrite a matter",
        );
    }
}

/// The lost update, refused.
///
/// A run is owned — one writer per journal, arbitrated by the fencing lease. A
/// case is the opposite by construction: it is what several runs share, and the
/// window between reading its state and writing it back contains a model call,
/// which is unbounded. Two runs on one case overlap as a matter of course.
///
/// A backend that ignores the expected version loses whichever write arrives
/// second, silently, with nothing in the record to show it happened.
async fn a_stale_state_write_is_refused(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(c) = store
        .correlate_or_open("matter", &keys("INV-CAS"), ts(2_000))
        .await
    else {
        r.record("case state", "correlate_or_open failed");
        return;
    };
    let case = c.case_id();
    let Ok(Some(before)) = store.case(case).await else {
        r.record(
            "case state",
            "a case that was just opened cannot be read back",
        );
        return;
    };

    // One writer gets there first.
    let Ok(after) = store
        .put_state(case, before.version, serde_json::json!({ "by": "first" }))
        .await
    else {
        r.record("case state", "a write at the current version was refused");
        return;
    };
    if after <= before.version {
        r.record(
            "case state",
            "a write did not advance the version, so no later write can tell \
             whether the case moved",
        );
    }

    // The second writer read at the same version and is now stale.
    match store
        .put_state(case, before.version, serde_json::json!({ "by": "second" }))
        .await
    {
        Err(StoreError::CaseConflict { .. }) => {}
        Ok(_) => r.record(
            "case state",
            "a write made against a version the case has moved past was accepted. \
             That is a lost update: the first writer's work is gone and nothing \
             in the record shows it. The version check must be a predicate on the \
             UPDATE, not a read followed by a write",
        ),
        Err(e) => r.record(
            "case state",
            format!("a stale write must report CaseConflict, reported: {e}"),
        ),
    }

    // And the first writer's value is what survived.
    if let Ok(Some(now)) = store.case(case).await
        && now.state != serde_json::json!({ "by": "first" })
    {
        r.record(
            "case state",
            "the refused write changed the state anyway — the check must happen \
             before the row is touched",
        );
    }
}

/// A missing case is `NotFound`, not a conflict.
///
/// Reporting it as a conflict sends the caller into a re-read loop against
/// something that will never exist. Both are "the UPDATE matched no rows", which
/// is exactly why a backend that only reads the row count gets this wrong.
async fn a_state_write_to_a_missing_case_is_not_found(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    // Well-formed but absent: an id this store has never seen.
    let absent = CaseId::generate();
    match store
        .put_state(absent, CaseVersion::INITIAL, serde_json::json!({}))
        .await
    {
        Err(StoreError::NotFound(_)) => {}
        Ok(_) => r.record(
            "case state",
            "writing to a case that does not exist reported success. A guard whose \
             result nobody reads is not a guard",
        ),
        Err(e) => r.record(
            "case state",
            format!("a write to a missing case must report NotFound, reported: {e}"),
        ),
    }
}

/// The race, run as a race.
///
/// Sequential checks prove the *result* is right; only an actual race
/// distinguishes a store whose version check is atomic from one that reads the
/// version and then writes, which returns the right answer every time it is
/// called one at a time.
///
/// Corroboration, not proof — the same caveat as the correlation race above. A
/// store that serialises internally passes trivially and correctly, having no
/// race to lose.
async fn only_one_of_several_racing_writers_wins(store: &Arc<dyn CaseStore>, r: &mut Report) {
    const RACERS: usize = 8;
    r.checked += 1;

    let Ok(c) = store
        .correlate_or_open("matter", &keys("INV-RACE-CAS"), ts(3_000))
        .await
    else {
        r.record("case state", "correlate_or_open failed");
        return;
    };
    let case = c.case_id();
    let Ok(Some(start)) = store.case(case).await else {
        r.record("case state", "cannot read back a fresh case");
        return;
    };

    // Every racer read the same version, as concurrent runs on one case do.
    let winners = futures_util::future::join_all((0..RACERS).map(|i| {
        let store = Arc::clone(store);
        async move {
            store
                .put_state(case, start.version, serde_json::json!({ "by": i }))
                .await
                .is_ok()
        }
    }))
    .await
    .into_iter()
    .filter(|ok| *ok)
    .count();

    if winners != 1 {
        r.record(
            "case state",
            format!(
                "{winners} of {RACERS} writers holding the same version succeeded; \
                 exactly one may. More than one means the version check is not part \
                 of the write, and the losers' work vanished silently"
            ),
        );
    }
}

/// The invariant the whole correlation model rests on.
///
/// Two messages about the same new matter must produce one case, not two —
/// otherwise the process fragments and its obligations are tracked in neither
/// half. Sequential, so it proves the *result* is right; the racing check below
/// is what tests whether it is right for the right reason.
async fn correlating_twice_yields_one_case(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let k = keys("INV-1");
    let Ok(first) = store.correlate_or_open("matter", &k, ts(1_000)).await else {
        r.record("correlation", "correlate_or_open failed on a fresh key");
        return;
    };
    let Ok(second) = store.correlate_or_open("matter", &k, ts(1_001)).await else {
        r.record("correlation", "correlate_or_open failed on a known key");
        return;
    };
    if first.case_id() != second.case_id() {
        r.record(
            "correlation",
            "two messages carrying the same key opened two cases. The process then \
             fragments across them and its obligations are tracked in neither",
        );
    }
    if !matches!(second, crate::case::Correlation::Attached(_)) {
        r.record(
            "correlation",
            "the second message must report Attached, not Opened — a caller uses \
             that to decide whether this is a new matter",
        );
    }
}

/// The race, run as a race.
///
/// Every other check here is sequential, and a sequential test cannot detect a
/// missing atomicity: a `SELECT` then `INSERT` returns the right answer every
/// time it is called one at a time. Only an actual race distinguishes an
/// implementation that *is* atomic from one that looks it.
///
/// Two racers are not enough — they serialise often enough that dropping the
/// arbitrating unique index goes unnoticed. So this runs a **fan-out over
/// several keys**, which is both more likely to interleave and cheap.
///
/// Being explicit about what this can and cannot do: a race test corroborates,
/// it never proves. Passing means no interleaving *found* one; the constraint in
/// the schema is what makes the absence real. A store that serialises internally
/// — the embedded store behind one connection — passes trivially and correctly, having no
/// race to lose.
async fn two_concurrent_messages_open_one_case(store: &Arc<dyn CaseStore>, r: &mut Report) {
    const RACERS: usize = 8;
    const KEYS: usize = 4;

    for round in 0..KEYS {
        r.checked += 1;
        let k = keys(&format!("RACE-{round}"));
        let mut tasks = Vec::with_capacity(RACERS);
        for _ in 0..RACERS {
            let store = Arc::clone(store);
            let k = k.clone();
            tasks.push(tokio::spawn(async move {
                store.correlate_or_open("matter", &k, ts(3_000)).await
            }));
        }

        let mut ids = std::collections::BTreeSet::new();
        for t in tasks {
            if let Ok(Ok(c)) = t.await {
                ids.insert(c.case_id());
            } else {
                r.record(
                    "correlation",
                    "a concurrent correlate_or_open call failed outright",
                );
                return;
            }
        }
        if ids.len() > 1 {
            r.record(
                "correlation",
                format!(
                    "{RACERS} messages racing for one new matter opened {} cases. Reading \
                     and then inserting looks atomic when called one at a time; only the \
                     database can settle this, and here it did not",
                    ids.len()
                ),
            );
            return;
        }
    }
}

/// Closing releases the keys, so a later message opens a *new* matter.
async fn a_closed_case_does_not_match(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let k = keys("INV-2");
    let Ok(opened) = store.correlate_or_open("matter", &k, ts(1_000)).await else {
        return;
    };
    if store.close(opened.case_id()).await.is_err() {
        r.record("closure", "a case with no obligations must be closable");
        return;
    }
    let Ok(again) = store.correlate_or_open("matter", &k, ts(2_000)).await else {
        r.record("closure", "a key must be reusable once its case is closed");
        return;
    };
    if again.case_id() == opened.case_id() {
        r.record(
            "closure",
            "a message about a settled matter reanimated the closed case. Closing \
             must release the keys, or a new dispute joins an audited one",
        );
    }
}

/// The only agent-reachable way to close a case is `set_status(Closed)` — the
/// `SetCaseStatus` effect. It must do everything `close` does, or a case reached
/// closed by the path agents actually use stays correlatable (a new matter
/// attaches to a closed case) and can hide an unmet obligation behind a tidy
/// status. `close` itself has no agent surface, so a battery that only exercised
/// it proved a path nobody takes.
async fn closing_via_set_status_also_releases_the_keys(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let k = keys("INV-SS");
    let Ok(opened) = store.correlate_or_open("matter", &k, ts(1_000)).await else {
        return;
    };
    let case = opened.case_id();

    // An unmet obligation must block this path exactly as it blocks `close`.
    let deadline = crate::core::Deadline {
        case,
        name: "ack".into(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if store.register_deadline(&deadline).await.is_err() {
        r.record("closure", "register_deadline failed");
        return;
    }
    match store
        .set_status(case, crate::core::CaseStatus::Closed)
        .await
    {
        Ok(()) => r.record(
            "closure",
            "set_status(Closed) closed a case with a pending obligation. The agent \
             path must refuse it exactly as close does",
        ),
        Err(crate::core::StoreError::ObligationsOutstanding { .. }) => {}
        Err(other) => r.record(
            "closure",
            format!(
                "set_status(Closed) over an open obligation must refuse as \
                 `ObligationsOutstanding`, not as `{other}` — same rule, same \
                 spelling, on the path agents actually take"
            ),
        ),
    }
    let _ = store
        .set_deadline_state(case, "ack", crate::core::DeadlineState::Met)
        .await;
    if store
        .set_status(case, crate::core::CaseStatus::Closed)
        .await
        .is_err()
    {
        r.record(
            "closure",
            "a case with all obligations met must be closable",
        );
        return;
    }

    // Closed by the agent path — the keys must be released too.
    let Ok(again) = store.correlate_or_open("matter", &k, ts(2_000)).await else {
        r.record("closure", "a key must be reusable once its case is closed");
        return;
    };
    if again.case_id() == case {
        r.record(
            "closure",
            "set_status(Closed) left the case correlatable. The status column and \
             correlation-open membership are two spellings of closed and the agent \
             path wrote only one",
        );
    }
}

/// A case with an unmet obligation cannot be closed.
///
/// That is how a missed regulatory window stays visible: closure is the moment
/// someone would otherwise stop looking.
async fn an_unmet_obligation_blocks_closure(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let Ok(opened) = store
        .correlate_or_open("matter", &keys("INV-3"), ts(1_000))
        .await
    else {
        return;
    };
    let case = opened.case_id();
    let deadline = crate::core::Deadline {
        case,
        name: "ack".into(),
        resolved_at: ts(9_000),
        calendar_digest: crate::core::Digest::of(b"cal"),
        warn_at: None,
        state: crate::core::DeadlineState::Pending,
        acknowledged: None,
    };
    if store.register_deadline(&deadline).await.is_err() {
        r.record("closure", "register_deadline failed");
        return;
    }
    match store.close(case).await {
        Ok(()) => r.record(
            "closure",
            "a case with a pending obligation was closed. Closure is when people \
             stop looking, so an unmet deadline must survive it",
        ),
        // The shape of the refusal is part of the contract: a business rule
        // reported as a backend fault is indistinguishable from an outage, so
        // a store that is merely down would read as enforcing the rule.
        Err(crate::core::StoreError::ObligationsOutstanding { outstanding, .. }) => {
            if outstanding == 0 {
                r.record(
                    "closure",
                    "the refusal counted zero outstanding obligations while refusing \
                     over one",
                );
            }
        }
        Err(other) => r.record(
            "closure",
            format!(
                "an open obligation must refuse closure as \
                 `ObligationsOutstanding`, not as `{other}` — a business refusal \
                 wearing a fault's type makes an outage read as enforcement"
            ),
        ),
    }
    let _ = store
        .set_deadline_state(case, "ack", crate::core::DeadlineState::Met)
        .await;
    if store.close(case).await.is_err() {
        r.record(
            "closure",
            "a case whose obligations are all met must be closable",
        );
    }
}

async fn the_census_counts_every_open_case(store: &Arc<dyn CaseStore>, r: &mut Report) {
    r.checked += 1;
    let before = store.census(ts(5_000)).await.map_or(0, |c| c.open);
    for i in 0..3 {
        let _ = store
            .correlate_or_open("bulk", &keys(&format!("C-{i}")), ts(1_000))
            .await;
    }
    match store.census(ts(5_000)).await {
        Ok(c) if c.open == before + 3 => {
            if c.oldest_age_secs.is_none() {
                r.record(
                    "census",
                    "an open case must report an age — a count alone cannot tell a \
                     healthy queue from a stuck one",
                );
            }
        }
        Ok(c) => r.record(
            "census",
            format!(
                "census must count every open case, expected {} got {}",
                before + 3,
                c.open
            ),
        ),
        Err(e) => r.record("census", format!("census failed: {e}")),
    }
}

// ── Events ──────────────────────────────────────────────────────────────────

/// Check an [`EventStore`].
pub async fn check_events(store: &Arc<dyn EventStore>, r: &mut Report) {
    a_repeated_event_id_is_not_buffered_twice(store, r).await;
    an_event_is_claimed_by_one_waiter_only(store, r).await;
    a_waiter_is_matched_by_one_event_only(store, r).await;
    a_waiter_is_consumed_by_one_of_two_distinct_events(store, r).await;
    a_targeted_event_resumes_only_its_named_run(store, r).await;
    a_wait_naming_its_sender_takes_no_other_producers_event(store, r).await;
    a_claimed_event_is_never_retired(store, r).await;
    a_claimed_event_is_recoverable_by_its_own_run(store, r).await;
    a_satisfied_waiter_does_not_claim_a_second_event(store, r).await;
    a_parked_wait_is_not_matched_again(store, r).await;
    an_erased_claim_is_dead_lettered_and_its_wait_reopened(store, r).await;
    a_zero_grace_sweep_retires_an_event_received_this_second(store, r).await;
    a_dead_letter_carries_the_keys_it_was_routed_on(store, r).await;
    a_minted_event_keeps_the_operator_who_minted_it(store, r).await;
    a_parked_wait_is_listed_ahead_of_idle_ones(store, r).await;
    a_closed_runs_waits_are_retired_together(store, r).await;
    a_consumed_event_is_not_claimed_again_by_its_own_run(store, r).await;
    unsubscribing_one_wait_sheds_only_its_own_claim(store, r).await;
    a_retried_targeted_message_is_not_a_second_turn(store, r).await;
    a_wait_claimed_in_step_takes_no_second_event(store, r).await;
    a_closed_runs_unconsumed_message_goes_to_the_next_waiter(store, r).await;
    a_parked_wait_recovers_only_its_own_claim(store, r).await;
    a_message_addressed_to_a_closed_run_reaches_no_other(store, r).await;
}

/// **A wait already holding a claim takes no second message.**
///
/// A targeted delivery reached the wait between its registration and the
/// step's own claim. The step must recover that message — not claim an older
/// buffered one beside it, which retiring the wait would then shed unread.
async fn a_parked_wait_recovers_only_its_own_claim(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let run = RunId::generate();
    let wait = turn(run, 54, "E-RACE-STEP");
    let _ = store.subscribe(&wait, ts(1_000)).await;
    let _ = store
        .buffer(&message("race-old", "E-RACE-STEP", 1), ts(1_001))
        .await;
    if !matches!(
        store
            .deliver_to(run, &message("race-new", "E-RACE-STEP", 2), ts(1_002))
            .await,
        Ok(TargetedDelivery::Matched(_))
    ) {
        r.record("parked claim", "the targeted message was not matched");
        return;
    }
    match store.claim_for(&wait, ts(1_003)).await {
        Ok(Some(own)) if own.event.payload == serde_json::json!({ "n": 2 }) => {}
        other => {
            r.record(
                "parked claim",
                format!("a wait holding a targeted message claimed another beside it: {other:?}"),
            );
            return;
        }
    }
    let other = turn(RunId::generate(), 55, "E-RACE-STEP");
    let _ = store.subscribe(&other, ts(1_004)).await;
    match store.claim_for(&other, ts(1_005)).await {
        Ok(Some(left)) if left.event.payload == serde_json::json!({ "n": 1 }) => {}
        other => r.record(
            "parked claim",
            format!("the buffered message was not left for the next waiter: {other:?}"),
        ),
    }
}

/// **A message sent to one run by name is that run's alone.**
///
/// Its run concluded without consuming it. Retiring the run's waits must not
/// offer it to another run waiting on the same key — it was a continuation of
/// one task, not of another — but dead-letter it, saying why.
async fn a_message_addressed_to_a_closed_run_reaches_no_other(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let closed = RunId::generate();
    let wait = turn(closed, 56, "E-ADDRESSED");
    let _ = store.subscribe(&wait, ts(1_000)).await;
    let addressed = message("addressed-1", "E-ADDRESSED", 1);
    if !matches!(
        store.deliver_to(closed, &addressed, ts(1_001)).await,
        Ok(TargetedDelivery::Matched(_))
    ) {
        r.record("addressed", "the targeted message was not matched");
        return;
    }
    let other = turn(RunId::generate(), 57, "E-ADDRESSED");
    let _ = store.subscribe(&other, ts(1_002)).await;
    match store.unsubscribe_run(closed, &[wait.effect]).await {
        Ok(retired) if retired.released.is_empty() => {}
        other => {
            r.record(
                "addressed",
                format!("retiring the run released its addressed message: {other:?}"),
            );
            return;
        }
    }
    if let Ok(Some(taken)) = store.claim_for(&other, ts(1_003)).await {
        r.record(
            "addressed",
            format!(
                "another run took a message addressed to a closed run: {:?}",
                taken.event
            ),
        );
    }
    match store.dead_letters(100).await {
        Ok(dead)
            if dead.iter().any(|d| {
                d.event.id == addressed.id && d.reason == crate::case::ADDRESSEE_CONCLUDED_REASON
            }) => {}
        other => r.record(
            "addressed",
            format!("the unconsumed addressed message was not dead-lettered: {other:?}"),
        ),
    }
}

/// **A message a run claimed and never consumed outlives the run.**
///
/// The run concluded between the claim and its delivery. Retiring its waits
/// hands that message back, whole, for the next waiter — and keeps what the
/// run did consume, which a second run must never be handed.
async fn a_closed_runs_unconsumed_message_goes_to_the_next_waiter(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let closed = RunId::generate();
    let answered = turn(closed, 50, "E-HANDOVER-A");
    let pending = turn(closed, 51, "E-HANDOVER");
    let _ = store.subscribe(&answered, ts(1_000)).await;
    let _ = store.subscribe(&pending, ts(1_000)).await;
    let _ = store
        .buffer(&message("handover-a", "E-HANDOVER-A", 1), ts(1_001))
        .await;
    let _ = store
        .buffer(&message("handover-1", "E-HANDOVER", 2), ts(1_001))
        .await;
    let a = store.claim_for(&answered, ts(1_002)).await;
    let p = store.claim_for(&pending, ts(1_002)).await;
    if !matches!((a, p), (Ok(Some(_)), Ok(Some(_)))) {
        r.record("handover", "the closed run's two messages were not claimed");
        return;
    }
    let next = turn(RunId::generate(), 52, "E-HANDOVER");
    let _ = store.subscribe(&next, ts(1_003)).await;

    match store.unsubscribe_run(closed, &[pending.effect]).await {
        Ok(retired) => match retired.released.as_slice() {
            [released] if released.payload == serde_json::json!({ "n": 2 }) => {}
            other => {
                r.record(
                    "handover",
                    format!(
                        "retiring the run handed back {other:?} rather than the one \
                         message its unanswered wait held"
                    ),
                );
                return;
            }
        },
        Err(e) => {
            r.record("handover", format!("unsubscribe_run failed: {e}"));
            return;
        }
    }
    match store.claim_for(&next, ts(1_004)).await {
        Ok(Some(taken)) if taken.event.payload == serde_json::json!({ "n": 2 }) => {}
        other => r.record(
            "handover",
            format!("the next waiter was not offered the released message: {other:?}"),
        ),
    }
    let late = turn(RunId::generate(), 53, "E-HANDOVER-A");
    let _ = store.subscribe(&late, ts(1_005)).await;
    if let Ok(Some(again)) = store.claim_for(&late, ts(1_006)).await {
        r.record(
            "handover",
            format!(
                "a message the closed run consumed was handed to another run: {:?}",
                again.event
            ),
        );
    }
}

fn turn(run: RunId, n: u8, key: &str) -> Subscription {
    Subscription {
        run,
        case: None,
        effect: effect(n),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "turn".into(),
        correlation: keys(key),
        from: None,
    }
}

fn message(id: &str, key: &str, n: i64) -> InboundEvent {
    InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "turn".into(),
        correlation: keys(key),
        payload: serde_json::json!({ "n": n }),
        by: None,
    }
}

/// **A message a run consumed is not consumed again by its next wait.**
///
/// A conversation waits on one kind and key turn after turn. The first turn's
/// message was journaled and its wait retired; the second wait must find
/// nothing until a second message arrives — not the first one again, and not
/// its stripped husk.
async fn a_consumed_event_is_not_claimed_again_by_its_own_run(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let first = turn(run, 40, "E-TURNS");
    let _ = store.subscribe(&first, ts(1_000)).await;
    let _ = store
        .buffer(&message("turn-1", "E-TURNS", 1), ts(1_001))
        .await;
    if !matches!(store.claim_for(&first, ts(1_002)).await, Ok(Some(_))) {
        r.record("turns", "the first turn's message was not claimed");
        return;
    }
    let _ = store.unsubscribe(run, first.effect).await;

    let second = turn(run, 41, "E-TURNS");
    let _ = store.subscribe(&second, ts(1_003)).await;
    match store.claim_for(&second, ts(1_004)).await {
        Ok(None) => {}
        Ok(Some(again)) => {
            r.record(
                "turns",
                format!(
                    "the second turn was handed the first turn's message again \
                     (payload {}) — a consumed message counted twice",
                    again.event.payload
                ),
            );
            return;
        }
        Err(e) => {
            r.record("turns", format!("claim_for failed: {e}"));
            return;
        }
    }
    let _ = store
        .buffer(&message("turn-2", "E-TURNS", 2), ts(1_005))
        .await;
    match store.claim_for(&second, ts(1_006)).await {
        Ok(Some(next)) if next.event.payload == serde_json::json!({ "n": 2 }) => {}
        other => r.record(
            "turns",
            format!("the second turn did not receive the second message: {other:?}"),
        ),
    }
}

/// **Retiring one wait sheds only what that wait consumed.**
///
/// Two waits of one run each hold a claimed message not yet journaled; the
/// first is journaled and retired. The second's message must still be there
/// whole for its own delivery.
async fn unsubscribing_one_wait_sheds_only_its_own_claim(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let a = turn(run, 42, "E-SHED-A");
    let b = turn(run, 43, "E-SHED-B");
    let _ = store.subscribe(&a, ts(1_000)).await;
    let _ = store.subscribe(&b, ts(1_000)).await;
    let _ = store
        .buffer(&message("shed-a", "E-SHED-A", 1), ts(1_001))
        .await;
    let _ = store
        .buffer(&message("shed-b", "E-SHED-B", 2), ts(1_001))
        .await;
    let claimed_a = store.claim_for(&a, ts(1_002)).await;
    let claimed_b = store.claim_for(&b, ts(1_002)).await;
    if !matches!((claimed_a, claimed_b), (Ok(Some(_)), Ok(Some(_)))) {
        r.record("shedding", "both waits' messages were not claimed");
        return;
    }
    let _ = store.unsubscribe(run, a.effect).await;
    match store.claim_for(&b, ts(1_003)).await {
        Ok(Some(kept)) if kept.event.payload == serde_json::json!({ "n": 2 }) => {}
        other => r.record(
            "shedding",
            format!("retiring one wait stripped another wait's undelivered message: {other:?}"),
        ),
    }
}

/// **A peer's retry of a message already consumed is not the next turn.**
///
/// Targeted delivery recovers its own claim after a crash; it must not hand a
/// message the run already journaled to the run's next wait on the same key.
async fn a_retried_targeted_message_is_not_a_second_turn(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let first = turn(run, 44, "E-RETRY");
    let _ = store.subscribe(&first, ts(1_000)).await;
    let reply = message("retry-1", "E-RETRY", 1);
    if !matches!(
        store.deliver_to(run, &reply, ts(1_001)).await,
        Ok(TargetedDelivery::Matched(_))
    ) {
        r.record("targeted retry", "the first delivery was not matched");
        return;
    }
    let _ = store.unsubscribe(run, first.effect).await;
    let _ = store.subscribe(&turn(run, 45, "E-RETRY"), ts(1_002)).await;
    match store.deliver_to(run, &reply, ts(1_003)).await {
        Ok(TargetedDelivery::Duplicate) => {}
        other => r.record(
            "targeted retry",
            format!("a retried, already consumed message was delivered again: {other:?}"),
        ),
    }
}

/// **A wait that claimed its message in step takes no second one.**
///
/// The waiting step claims a buffered message and journals it; until the wait
/// is retired, a delivery arriving for the same key must find no waiter there
/// and stay buffered for the next.
async fn a_wait_claimed_in_step_takes_no_second_event(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let run = RunId::generate();
    let wait = turn(run, 46, "E-INSTEP");
    let _ = store.subscribe(&wait, ts(1_000)).await;
    let _ = store
        .buffer(&message("instep-1", "E-INSTEP", 1), ts(1_001))
        .await;
    if !matches!(store.claim_for(&wait, ts(1_002)).await, Ok(Some(_))) {
        r.record("in-step claim", "the buffered message was not claimed");
        return;
    }
    let second = message("instep-2", "E-INSTEP", 2);
    let _ = store.buffer(&second, ts(1_003)).await;
    match store.match_waiter(&second, ts(1_004)).await {
        Ok(None) => {}
        other => r.record(
            "in-step claim",
            format!(
                "a wait that already claimed its message was matched a second one, \
                 which its delivery then discards: {other:?}"
            ),
        ),
    }
}

/// **A parked wait is listed for redelivery ahead of every idle one.**
///
/// A plane holds many long, legitimate waits; a redelivery page drawn from
/// those in registration order never reaches a pair parked after them. The
/// parked listing holds only parked waits, and the mark goes with the wait.
async fn a_parked_wait_is_listed_ahead_of_idle_ones(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let at = ts(1_000);
    let wait = |n: u8| Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(n),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "parked.probe".into(),
        correlation: keys(&format!("PARKED-{n}")),
        from: None,
    };
    for n in 0..4u8 {
        if store.subscribe(&wait(n), at).await.is_err() {
            r.record("redelivery", "subscribe failed");
            return;
        }
    }
    let parked = wait(9);
    if store.park_wait(&parked, ts(2_000)).await.is_err() {
        r.record("redelivery", "park failed");
        return;
    }
    match store.parked_waits(64).await {
        Ok(listed) if listed.iter().any(|s| s.run == parked.run) => {
            if listed
                .iter()
                .any(|s| s.kind == "parked.probe" && s.run != parked.run)
            {
                r.record("redelivery", "an idle wait was listed as parked");
            }
        }
        other => {
            r.record(
                "redelivery",
                format!("a parked wait was not listed for redelivery: {other:?}"),
            );
            return;
        }
    }
    if store.unsubscribe(parked.run, parked.effect).await.is_err() {
        r.record("redelivery", "unsubscribe failed");
        return;
    }
    if store
        .parked_waits(64)
        .await
        .is_ok_and(|listed| listed.iter().any(|s| s.run == parked.run))
    {
        r.record(
            "redelivery",
            "a wait that was unsubscribed is still listed as parked",
        );
    }
}

/// **A closed run's waits are retired in one verb.**
///
/// Left registered, a closed run's wait is the oldest waiter on its key: the
/// next matching event is claimed for a run that will never consume it, and a
/// live run waiting on the same key starves.
async fn a_closed_runs_waits_are_retired_together(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let closed = RunId::generate();
    for n in [30u8, 31] {
        let sub = Subscription {
            run: closed,
            case: None,
            effect: effect(n),
            step: StepId(0),
            phase: Phase::Forward,
            kind: "retire.probe".into(),
            correlation: keys("RETIRE-1"),
            from: None,
        };
        if store.subscribe(&sub, ts(1_000)).await.is_err() {
            r.record("retirement", "subscribe failed");
            return;
        }
    }
    let live = Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(32),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "retire.probe".into(),
        correlation: keys("RETIRE-1"),
        from: None,
    };
    if store.subscribe(&live, ts(1_001)).await.is_err() {
        r.record("retirement", "subscribe failed");
        return;
    }
    match store.unsubscribe_run(closed, &[]).await {
        Ok(retired) if retired.waits == 2 && retired.released.is_empty() => {}
        other => r.record(
            "retirement",
            format!("retiring a run with two waits answered {other:?}"),
        ),
    }
    let event = InboundEvent::new(
        "urn:probe",
        "retire-1",
        "retire.probe",
        serde_json::json!({}),
    )
    .correlate(CorrelationKey::new("doc", "RETIRE-1"));
    if store.buffer(&event, ts(1_002)).await.is_err() {
        r.record("retirement", "buffer failed");
        return;
    }
    match store.match_waiter(&event, ts(1_002)).await {
        Ok(Some(sub)) if sub.run == live.run => {}
        other => r.record(
            "retirement",
            format!(
                "the event for a key a retired run had waited on went to {other:?}, not the \
                 live waiter"
            ),
        ),
    }
}

/// **An event this plane minted comes back naming who minted it.**
///
/// [`InboundEvent::by`] is how an operator act reaches the journal's *clear*
/// side. A worklist decision travels as an awaited effect's output, and that
/// output is a sealed payload — so the approver's name reaches
/// `EffectDone.by` through this field or it reaches the record only inside
/// something a lawful erasure destroys.
///
/// A store that drops it is not obviously broken: every existing case still
/// passes, delivery still works, and the loss shows up years later as an
/// approval nobody can attribute. So the contract asks for it directly, and
/// asks for **both halves** — an actor with no basis is an attribution this
/// runtime cannot state, and a store that flattened the pair would return a
/// name whose strength it invented.
async fn a_minted_event_keeps_the_operator_who_minted_it(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let by = crate::core::Operator::authenticated("rita").expect("a fixture names its operator");
    let event = InboundEvent {
        source: "agentplane://worklist".to_owned(),
        id: "evt-minted".into(),
        kind: "ack".into(),
        correlation: keys("E-MINTED"),
        payload: serde_json::json!({}),
        by: Some(by.clone()),
    };
    let sub = Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(24),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-MINTED"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;
    let _ = store.buffer(&event, ts(1_000)).await;

    match store.match_waiter(&event, ts(1_100)).await {
        Ok(Some(_)) => match store.claim_for(&sub, ts(1_100)).await {
            Ok(Some(buffered)) => {
                if buffered.event.by.as_ref() != Some(&by) {
                    r.record(
                        "minted events",
                        format!(
                            "an event minted by {by:?} came back as {:?} — the operator \
                             who authorised it is how an approval reaches the journal's \
                             readable side, and a store that drops it leaves the name \
                             only inside a payload an erasure destroys",
                            buffered.event.by
                        ),
                    );
                }
            }
            Ok(None) => r.record("minted events", "the claimed event came back empty"),
            Err(e) => r.record("minted events", format!("claim_for failed: {e}")),
        },
        Ok(None) => r.record("minted events", "the waiter did not match its own event"),
        Err(e) => r.record("minted events", format!("match_waiter failed: {e}")),
    }
}

/// **Two distinct events racing one wait: exactly one is consumed, and the
/// other stays live.**
///
/// `a_waiter_is_matched_by_one_event_only` replays the *same* event twice, so
/// the event-row claim alone passes it. This is the race that claim cannot
/// settle: two *different* messages both carry the wait's correlation key, and
/// both `match_waiter` calls select the same subscription. Each then claims
/// its own — unclaimed — event row, and the loser's message ends up claimed
/// for a run whose wait the winner already satisfied: parked under a claim
/// nobody will consume, and a claimed event never dead-letters, so it vanishes
/// from every listing an operator reads. The subscription row itself has to be
/// the thing the two matches serialise on.
///
/// The pin is the aftermath rather than the interleaving: exactly one match
/// reports a resume, and a zero-grace sweep must still be able to retire the
/// other event — a message nobody consumed must age out with a reason, not
/// disappear.
async fn a_waiter_is_consumed_by_one_of_two_distinct_events(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(23),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-TWO-EVENTS"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "ack".into(),
        correlation: keys("E-TWO-EVENTS"),
        payload: serde_json::json!({}),
        by: None,
    };
    let first = event("evt-two-1");
    let second = event("evt-two-2");
    let _ = store.buffer(&first, ts(1_001)).await;
    let _ = store.buffer(&second, ts(1_001)).await;

    // Concurrently, because the defect is a missing lock: two transactions
    // that both read the subscription before either retires it.
    let (a, b) = {
        let (s1, s2) = (Arc::clone(store), Arc::clone(store));
        let (e1, e2) = (first.clone(), second.clone());
        let one = tokio::spawn(async move { s1.match_waiter(&e1, ts(1_002)).await });
        let two = tokio::spawn(async move { s2.match_waiter(&e2, ts(1_002)).await });
        (one.await, two.await)
    };
    let (Ok(Ok(a)), Ok(Ok(b))) = (a, b) else {
        r.record("single-consumption", "match_waiter failed under contention");
        return;
    };
    match (&a, &b) {
        (Some(_), None) | (None, Some(_)) => {}
        (Some(_), Some(_)) => r.record(
            "single-consumption",
            "two distinct events both matched one wait — one run is resumed \
             twice, and the second message is consumed by a wait it never \
             satisfied",
        ),
        (None, None) => {
            r.record(
                "single-consumption",
                "neither of two matching events found the waiting run",
            );
            return;
        }
    }

    // The unconsumed event must still be sweepable. With the race unlocked it
    // sits claimed for the resumed run and the sweep — which only retires
    // unclaimed rows — never touches it.
    if let Err(e) = store.sweep_unclaimed(ts(9_999), "expired").await {
        r.record("single-consumption", format!("sweep_unclaimed failed: {e}"));
        return;
    }
    let consumed = if a.is_some() { &first } else { &second };
    let loser = if a.is_some() { &second } else { &first };
    match store.dead_letters(100).await {
        Ok(dead) => {
            if !dead.iter().any(|d| d.event.id == loser.id) {
                r.record(
                    "single-consumption",
                    format!(
                        "event {} was neither consumed nor dead-lettered — it is \
                         parked under a claim nobody will ever consume, invisible \
                         to every listing",
                        loser.id
                    ),
                );
            }
            if dead.iter().any(|d| d.event.id == consumed.id) {
                r.record(
                    "single-consumption",
                    "the consumed event was retired as unclaimed",
                );
            }
        }
        Err(e) => r.record("single-consumption", format!("dead_letters failed: {e}")),
    }
}

/// **A zero grace window retires an event received this second.**
///
/// The sweep's cutoff is *the oldest instant still worth keeping*, and both
/// backends stamp at second granularity — so `received_at < cutoff` silently
/// spares everything received in the cutoff's own second. An operator who
/// configures "retire immediately" then watches unclaimed messages survive
/// exactly one sweep, which on a quiet store is forever.
async fn a_zero_grace_sweep_retires_an_event_received_this_second(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-boundary".into(),
        kind: "ack".into(),
        correlation: keys("E-BOUNDARY"),
        payload: serde_json::json!({}),
        by: None,
    };
    let _ = store.buffer(&event, ts(5_000)).await;
    match store.sweep_unclaimed(ts(5_000), "zero grace").await {
        Ok(_) => {}
        Err(e) => {
            r.record("sweep boundary", format!("sweep_unclaimed failed: {e}"));
            return;
        }
    }
    match store.dead_letters(100).await {
        Ok(dead) => {
            if !dead.iter().any(|d| d.event.id == "evt-boundary") {
                r.record(
                    "sweep boundary",
                    "an event received at the cutoff instant survived a zero-grace \
                     sweep — `<` where the contract is `<=`, and on a quiet store \
                     the message it spares is never retired",
                );
            }
        }
        Err(e) => r.record("sweep boundary", format!("dead_letters failed: {e}")),
    }
}

/// **A dead letter still carries the correlation keys it was routed on.**
///
/// The dead-letter view exists for an operator deciding what went wrong, and
/// the first question about an unclaimed message is *what was it correlated
/// by* — a wrong key is the most common reason nobody was waiting. A backend
/// that reconstructs the event without re-reading its keys hands back a
/// valid-looking message silently stripped of the one field that explains it.
async fn a_dead_letter_carries_the_keys_it_was_routed_on(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-keyed-letter".into(),
        kind: "ack".into(),
        correlation: keys("E-DEAD-KEYS"),
        payload: serde_json::json!({}),
        by: None,
    };
    let _ = store.buffer(&event, ts(6_000)).await;
    let _ = store.sweep_unclaimed(ts(9_999), "nobody was waiting").await;
    match store.dead_letters(100).await {
        Ok(dead) => match dead.iter().find(|d| d.event.id == "evt-keyed-letter") {
            Some(letter) => {
                if letter.event.correlation != keys("E-DEAD-KEYS") {
                    r.record(
                        "dead letters",
                        format!(
                            "a dead letter came back with correlation {:?} instead of \
                             the keys it was buffered with — the operator reading it \
                             cannot see what it failed to match on",
                            letter.event.correlation
                        ),
                    );
                }
            }
            None => r.record("dead letters", "the unclaimed event was not retired"),
        },
        Err(e) => r.record("dead letters", format!("dead_letters failed: {e}")),
    }
}

/// **One subscription consumes one event — the match retires the waiter.**
///
/// `match_waiter` claims the event and hands back the subscription, and the
/// run's resume unsubscribes *later*, in its own store call. Leaving the
/// subscription registered in between let a second event match the same
/// waiter and be claimed for the same run — sequentially, on any backend, no
/// race required. The first event satisfies the wait; the second is parked
/// under a claim nobody will consume, and a claimed event never dead-letters,
/// so the parking is invisible: a message that should have aged out with a
/// reason instead vanishes from every listing an operator reads.
///
/// So the claim must retire the subscription in the same transaction. The
/// resumed wait re-subscribes idempotently and recovers its own claimed
/// event through the crash-recovery arm, so nothing legitimate needs the
/// stale registration — and the second event stays live, to be claimed by a
/// future waiter or dead-lettered honestly.
async fn a_satisfied_waiter_does_not_claim_a_second_event(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(22),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-ONESHOT"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "ack".into(),
        correlation: keys("E-ONESHOT"),
        payload: serde_json::json!({}),
        by: None,
    };
    let first = event("evt-oneshot-1");
    let second = event("evt-oneshot-2");
    let _ = store.buffer(&first, ts(1_001)).await;
    match store.match_waiter(&first, ts(1_002)).await {
        Ok(Some(matched)) if matched.run == run => {}
        other => {
            r.record(
                "one-shot subscription",
                format!("the first event did not match the waiter: {other:?}"),
            );
            return;
        }
    }

    // The waiter is satisfied and merely not yet unsubscribed — the store
    // state every delivery leaves between the claim and the resume.
    let _ = store.buffer(&second, ts(1_003)).await;
    if let Ok(Some(matched)) = store.match_waiter(&second, ts(1_004)).await {
        r.record(
            "one-shot subscription",
            format!(
                "a second event was claimed for {} through a subscription its first event already satisfied — the second is parked under a claim nobody will consume, and a claimed event never dead-letters, so it vanishes from every listing",
                matched.run
            ),
        );
    }
}

/// **A parked wait already holds its event, so no second event matches it.**
///
/// A delivery that claimed an event and could not resume the run parks the
/// pair for redelivery. The parked wait is listed for that pass and recovers
/// its claimed event through `claim_for`, but it is not a waiter: a second
/// matching event elected for it is claimed for a run whose wait the first
/// already satisfied, and stays claimed forever — a claimed event never
/// dead-letters. The second event must stay live for the next real waiter.
async fn a_parked_wait_is_not_matched_again(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(23),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "parked.ack".into(),
        correlation: keys("E-PARKED"),
        from: None,
    };
    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "parked.ack".into(),
        correlation: keys("E-PARKED"),
        payload: serde_json::json!({ "id": id }),
        by: None,
    };
    let (first, second) = (event("evt-parked-1"), event("evt-parked-2"));
    if store.subscribe(&sub, ts(1_000)).await.is_err()
        || store.buffer(&first, ts(1_001)).await.is_err()
    {
        r.record("parked wait", "setup failed");
        return;
    }
    if !matches!(store.match_waiter(&first, ts(1_002)).await, Ok(Some(m)) if m.run == run) {
        r.record("parked wait", "the first event did not match the waiter");
        return;
    }
    if store.park_wait(&sub, ts(1_003)).await.is_err()
        || store.buffer(&second, ts(1_004)).await.is_err()
    {
        r.record("parked wait", "park or buffer failed");
        return;
    }
    if let Ok(Some(m)) = store.match_waiter(&second, ts(1_005)).await {
        r.record(
            "parked wait",
            format!(
                "a second event was claimed for {} through a wait parked with its first — it stays claimed forever",
                m.run
            ),
        );
        return;
    }
    if !store
        .parked_waits(64)
        .await
        .is_ok_and(|listed| listed.iter().any(|s| s.run == run))
    {
        r.record("parked wait", "the parked wait left the redelivery listing");
    }
    // The second event is still live: the next real waiter claims it.
    let other = Subscription {
        run: RunId::generate(),
        effect: effect(24),
        ..sub.clone()
    };
    let _ = store.subscribe(&other, ts(1_006)).await;
    match store.claim_for(&other, ts(1_007)).await {
        Ok(Some(b)) if b.event.id == second.id => {}
        got => r.record(
            "parked wait",
            format!("the second event was not left live for the next waiter: {got:?}"),
        ),
    }
    let _ = store.unsubscribe(run, sub.effect).await;
    let _ = store.unsubscribe(other.run, other.effect).await;
}

/// **A message erased between its claim and its delivery is not delivered.**
///
/// The claim is durable and the resume a separate step, so the recovery of a
/// crashed delivery re-reads the claimed row — and once erased that row holds
/// no payload, which handed over as a value is a `null` the counterparty never
/// sent. The erased message is dead-lettered as erased, its claim released,
/// and the wait it was parked with is a wait again: the next matching event
/// is claimed for it.
async fn an_erased_claim_is_dead_lettered_and_its_wait_reopened(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(25),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "erased.ack".into(),
        correlation: keys("E-ERASED-CLAIM"),
        from: None,
    };
    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "erased.ack".into(),
        correlation: keys("E-ERASED-CLAIM"),
        payload: serde_json::json!({ "secret": id }),
        by: None,
    };
    let (first, second) = (event("evt-erased-1"), event("evt-erased-2"));
    if store.subscribe(&sub, ts(1_000)).await.is_err()
        || store.buffer(&first, ts(1_001)).await.is_err()
        || !matches!(store.match_waiter(&first, ts(1_002)).await, Ok(Some(_)))
        || store.park_wait(&sub, ts(1_003)).await.is_err()
    {
        r.record("erased claim", "setup failed");
        return;
    }
    if !matches!(
        store.erase_payload("urn:conformance", "evt-erased-1").await,
        Ok(true)
    ) {
        r.record("erased claim", "the erasure did not find the claimed row");
        return;
    }
    match store.claim_for(&sub, ts(1_004)).await {
        Ok(None) => {}
        got => r.record(
            "erased claim",
            format!("the claiming run's recovery was handed the erased row: {got:?}"),
        ),
    }
    if !store.dead_letters(64).await.is_ok_and(|letters| {
        letters
            .iter()
            .any(|d| d.event.id == first.id && d.reason == crate::case::ERASED_REASON)
    }) {
        r.record(
            "erased claim",
            "a claimed message erased before delivery is not on the dead-letter list",
        );
    }
    if store.buffer(&second, ts(1_005)).await.is_err() {
        r.record("erased claim", "buffer failed");
        return;
    }
    match store.match_waiter(&second, ts(1_006)).await {
        Ok(Some(m)) if m.run == run => {}
        got => r.record(
            "erased claim",
            format!(
                "the wait parked with the erased message was not reopened — the next \
                 event was matched to {got:?}"
            ),
        ),
    }
    let _ = store.unsubscribe(run, sub.effect).await;
}

/// **The crash between the claim and the resume must not lose the message.**
///
/// `match_waiter` claims the event durably; resuming the run is a separate
/// step. A process that dies between the two leaves an event claimed for a run
/// that never saw it — the counterparty's retry is answered `Duplicate`, and a
/// `claim_for` that filters on "unclaimed" hides the run's *own* event from
/// it. The resumed wait then re-subscribes, finds nothing, and sleeps until
/// its deadline breaches: a message that arrived in time, lost anyway, in the
/// failure mode that presents as a process silently never completing.
///
/// So the contract is: an event already claimed **by this subscription's run**
/// is claimable again — the same idempotence `deliver_to` grants a retried
/// targeted delivery — while any *other* run still finds nothing, which is the
/// half that keeps single delivery intact.
async fn a_claimed_event_is_recoverable_by_its_own_run(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(20),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-RECLAIM"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-reclaim".into(),
        kind: "ack".into(),
        correlation: keys("E-RECLAIM"),
        payload: serde_json::json!({"n": 1}),
        by: None,
    };
    let _ = store.buffer(&event, ts(1_001)).await;

    // The durable claim — and, immediately after it, the crash.
    match store.match_waiter(&event, ts(1_002)).await {
        Ok(Some(matched)) if matched.run == run => {}
        other => {
            r.record(
                "claim recovery",
                format!("the waiter was not matched at all: {other:?}"),
            );
            return;
        }
    }

    // The resumed wait asks again. Its own claim must not hide its own event.
    match store.claim_for(&sub, ts(1_003)).await {
        Ok(Some(recovered)) => {
            if recovered.event.dedup_key() != event.dedup_key() {
                r.record(
                    "claim recovery",
                    "the resumed wait recovered a different event than the one \
                     claimed for it",
                );
            }
        }
        Ok(None) => r.record(
            "claim recovery",
            "an event claimed for this very run was hidden from its resumed wait — \
             the run sleeps until its deadline breaches, and a message that arrived \
             in time is lost to a crash between the claim and the resume",
        ),
        Err(e) => r.record("claim recovery", format!("claim_for failed: {e}")),
    }

    // The other half: re-claimability is scoped to the claiming run alone.
    let stranger = Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(21),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-RECLAIM"),
        from: None,
    };
    let _ = store.subscribe(&stranger, ts(1_004)).await;
    if let Ok(Some(_)) = store.claim_for(&stranger, ts(1_005)).await {
        r.record(
            "claim recovery",
            "another run claimed an event already claimed for its rightful waiter — \
             recovery re-opened single delivery",
        );
    }
}

/// A protocol carrying a task id must not fall back to ordinary correlation.
async fn a_targeted_event_resumes_only_its_named_run(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let first = RunId::generate();
    let target = RunId::generate();
    let waiting = |run, n| Subscription {
        run,
        case: None,
        effect: effect(n),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "continue".into(),
        correlation: keys("E-TARGET"),
        from: None,
    };
    let a = waiting(first, 13);
    let b = waiting(target, 14);
    let _ = store.subscribe(&a, ts(1_000)).await;
    let _ = store.subscribe(&b, ts(1_001)).await;

    let event = InboundEvent {
        source: "urn:a2a:peer-a".to_owned(),
        id: "message-1".into(),
        kind: "continue".into(),
        correlation: keys("E-TARGET"),
        payload: serde_json::json!({"answer": 42}),
        by: None,
    };
    match store.deliver_to(target, &event, ts(1_002)).await {
        Ok(TargetedDelivery::Matched(sub)) if sub.run == target => {}
        Ok(other) => {
            r.record(
                "targeted delivery",
                format!("an event for {target} was not claimed by that run: {other:?}"),
            );
            return;
        }
        Err(error) => {
            r.record("targeted delivery", format!("delivery failed: {error}"));
            return;
        }
    }
    if !matches!(
        store.deliver_to(target, &event, ts(1_003)).await,
        Ok(TargetedDelivery::Matched(_))
    ) {
        r.record(
            "targeted delivery",
            "retrying a claimed event with a live subscription did not recover the prior claim",
        );
    }

    let absent = InboundEvent {
        id: "message-no-waiter".into(),
        ..event
    };
    if !matches!(
        store
            .deliver_to(RunId::generate(), &absent, ts(1_004))
            .await,
        Ok(TargetedDelivery::NotWaiting)
    ) {
        r.record(
            "targeted delivery",
            "a task with no subscription did not report NotWaiting",
        );
    }
    // NotWaiting must not buffer the message. If it did, this ordinary buffer
    // would see a duplicate and another correlated run could consume it.
    if !matches!(store.buffer(&absent, ts(1_005)).await, Ok(true)) {
        r.record(
            "targeted delivery",
            "a failed targeted delivery left an orphan event in the shared buffer",
        );
    }
}

/// **A wait naming its sender is satisfied by that sender only** — on every
/// delivery path. Correlation keys are business values any authenticated
/// producer may know; `from` is what stops one of them consuming another
/// producer's wait.
#[allow(clippy::too_many_lines)]
async fn a_wait_naming_its_sender_takes_no_other_producers_event(
    store: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    const RULE: &str = "a wait naming its sender";
    r.checked += 1;
    let wait = |key: &str, n: u8| Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(n),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "reply".into(),
        correlation: keys(key),
        from: Some("urn:peer:expected".to_owned()),
    };
    let event = |source: &str, id: &str, key: &str| InboundEvent {
        source: source.to_owned(),
        id: id.to_owned(),
        kind: "reply".into(),
        correlation: keys(key),
        payload: serde_json::json!({}),
        by: None,
    };

    // Broadcast: an arriving event looks for its waiter.
    let broadcast = wait("E-FROM-BROADCAST", 40);
    let _ = store.subscribe(&broadcast, ts(1_000)).await;
    let stranger = event("urn:peer:other", "from-1", "E-FROM-BROADCAST");
    let _ = store.buffer(&stranger, ts(1_001)).await;
    if let Ok(Some(sub)) = store.match_waiter(&stranger, ts(1_001)).await {
        r.record(
            RULE,
            format!(
                "an event from urn:peer:other was matched to run {}, whose wait accepts \
                 only urn:peer:expected",
                sub.run
            ),
        );
    }
    let expected = event("urn:peer:expected", "from-2", "E-FROM-BROADCAST");
    let _ = store.buffer(&expected, ts(1_002)).await;
    match store.match_waiter(&expected, ts(1_002)).await {
        Ok(Some(sub))
            if sub.run == broadcast.run && sub.from.as_deref() == Some("urn:peer:expected") => {}
        other => r.record(
            RULE,
            format!("the named sender's event did not match its wait intact: {other:?}"),
        ),
    }

    // Buffered: a wait registering finds an event already waiting for it.
    let early = event("urn:peer:other", "from-3", "E-FROM-BUFFERED");
    let _ = store.buffer(&early, ts(1_003)).await;
    let buffered = wait("E-FROM-BUFFERED", 41);
    let _ = store.subscribe(&buffered, ts(1_004)).await;
    if let Ok(Some(found)) = store.claim_for(&buffered, ts(1_004)).await {
        r.record(
            RULE,
            format!(
                "a wait accepting only urn:peer:expected claimed a buffered event from {}",
                found.event.source
            ),
        );
    }
    let _ = store
        .buffer(
            &event("urn:peer:expected", "from-5", "E-FROM-BUFFERED"),
            ts(1_004),
        )
        .await;
    match store.claim_for(&buffered, ts(1_004)).await {
        Ok(Some(found)) if found.event.source == "urn:peer:expected" => {}
        other => r.record(
            RULE,
            format!("the named sender's buffered event was not claimed for its wait: {other:?}"),
        ),
    }

    // Targeted: delivery names the run.
    let targeted = wait("E-FROM-TARGETED", 42);
    let _ = store.subscribe(&targeted, ts(1_005)).await;
    let aimed = event("urn:peer:other", "from-4", "E-FROM-TARGETED");
    if let Ok(TargetedDelivery::Matched(_)) =
        store.deliver_to(targeted.run, &aimed, ts(1_006)).await
    {
        r.record(
            RULE,
            "a targeted event from urn:peer:other resumed a wait accepting only \
             urn:peer:expected",
        );
    }
    let answer = event("urn:peer:expected", "from-6", "E-FROM-TARGETED");
    match store.deliver_to(targeted.run, &answer, ts(1_007)).await {
        Ok(TargetedDelivery::Matched(sub)) if sub.run == targeted.run => {}
        other => r.record(
            RULE,
            format!("the named sender's targeted event did not resume its wait: {other:?}"),
        ),
    }
}

/// A delivered message is not garbage.
///
/// The sweep exists to retire messages nobody ever wanted. A backend that finds
/// its sweep candidates through a derived index — rather than by reading every
/// event — has to keep that index in step with the rows, and the failure is
/// silent in the worst way: the message *was* delivered, the run *did* resume,
/// and the operator's dead-letter queue reports it as never claimed.
///
/// So the grace window here is deliberately absurd. Everything buffered is old
/// enough to retire, and the claim is the only thing standing between this
/// event and the dead-letter list.
async fn a_claimed_event_is_never_retired(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-swept".into(),
        kind: "ack".into(),
        correlation: keys("E-9"),
        payload: serde_json::json!({}),
        by: None,
    };
    let _ = store.buffer(&event, ts(1_000)).await;

    let sub = Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(90),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-9"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;
    if !matches!(store.claim_for(&sub, ts(1_001)).await, Ok(Some(_))) {
        r.record("sweep", "a waiting subscription did not claim its event");
        return;
    }

    if let Err(e) = store.sweep_unclaimed(ts(9_000), "expired").await {
        // Reported rather than ignored: a sweep that errors retires nothing, so
        // discarding this would let a broken sweep read as a clean one.
        r.record("sweep", format!("sweep_unclaimed failed: {e}"));
        return;
    }

    match store.dead_letters(100).await {
        Ok(dead) => {
            if dead.iter().any(|d| d.event.id == "evt-swept") {
                r.record(
                    "sweep",
                    "an event that was claimed and delivered was retired as unclaimed. The run already resumed on it, so the dead-letter queue is now reporting a message that was in fact acted on",
                );
            }
        }
        Err(e) => r.record("sweep", format!("dead_letters failed: {e}")),
    }
}

async fn a_repeated_event_id_is_not_buffered_twice(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-dup".into(),
        kind: "ack".into(),
        correlation: keys("E-1"),
        payload: serde_json::json!({}),
        by: None,
    };
    let first = store.buffer(&event, ts(1_000)).await;
    let second = store.buffer(&event, ts(1_001)).await;
    match (first, second) {
        (Ok(true), Ok(false)) => {}
        (Ok(a), Ok(b)) => r.record(
            "deduplication",
            format!(
                "buffering one event id twice reported ({a}, {b}); it must be (true, false). \
                 Every counterparty retries, and a duplicate delivered twice is the message \
                 acted on twice"
            ),
        ),
        _ => r.record("deduplication", "buffer failed"),
    }
}

/// One message, one waiter.
async fn an_event_is_claimed_by_one_waiter_only(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-claim".into(),
        kind: "ack".into(),
        correlation: keys("E-2"),
        payload: serde_json::json!({}),
        by: None,
    };
    let _ = store.buffer(&event, ts(1_000)).await;

    let sub = |n: u8| Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(n),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-2"),
        from: None,
    };
    let (a, b) = (sub(10), sub(11));
    let _ = store.subscribe(&a, ts(1_000)).await;
    let _ = store.subscribe(&b, ts(1_000)).await;

    let first = store.claim_for(&a, ts(1_002)).await;
    let second = store.claim_for(&b, ts(1_003)).await;
    match (first, second) {
        (Ok(Some(_)), Ok(None)) => {}
        (Ok(Some(_)), Ok(Some(_))) => r.record(
            "single-delivery",
            "one buffered event was claimed by two waiters. Claiming is what makes \
             delivery exactly-once; two runs both consuming one message is the same \
             message acted on twice",
        ),
        (Ok(None), _) => r.record(
            "single-delivery",
            "a waiting subscription did not claim a matching buffered event",
        ),
        _ => r.record("single-delivery", "claim_for failed"),
    }
}

async fn a_waiter_is_matched_by_one_event_only(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let sub = Subscription {
        run: RunId::generate(),
        case: None,
        effect: effect(12),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-3"),
        from: None,
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-match".into(),
        kind: "ack".into(),
        correlation: keys("E-3"),
        payload: serde_json::json!({}),
        by: None,
    };
    // Buffered first, which is the delivery order the runtime uses and the
    // reason it uses it: the message is durable before anyone looks for a
    // waiter, so a crash between the two loses nothing. `match_waiter` claims
    // the buffered row, so an unbuffered event has nothing to claim.
    let _ = store.buffer(&event, ts(1_000)).await;
    let first = store.match_waiter(&event, ts(1_001)).await;
    let second = store.match_waiter(&event, ts(1_002)).await;
    match (first, second) {
        (Ok(Some(_)), Ok(None)) => {}
        (Ok(Some(_)), Ok(Some(_))) => r.record(
            "single-delivery",
            "one subscription was matched twice. The arrive-before-wait direction \
             must claim just as the wait-before-arrive one does",
        ),
        (Ok(None), _) => r.record(
            "single-delivery",
            "an arriving event did not find the run already waiting for it",
        ),
        _ => r.record("single-delivery", "match_waiter failed"),
    }
}

/// **Two tenants' waiting lists are two lists, even under colliding names.**
///
/// `mine` and `other` must be handles onto **one** shared backend, scoped to
/// two different tenants — that is the whole point, and a caller passing two
/// separate databases proves nothing.
///
/// The adversarial half hands the attacker every identifier the row is keyed
/// by: the *same* run id, effect key, kind and correlation key registered in
/// the other tenant — all attacker-suppliable strings, since a run id is not a
/// secret and a correlation key is a business value. `waiting` must count the
/// row once for its owner and zero times for anyone else; a listing that
/// leaned on a tenant-keyed row lookup while walking every tenant's index
/// found its own row *through the other tenant's index entry too*, listing one
/// wait twice — phantom backlog whose size another tenant controls. The
/// positive halves pin that each owner still sees exactly its own row, so a
/// scoping that broke the listing for everybody cannot pass.
pub async fn check_waiting_tenancy(
    mine: &Arc<dyn EventStore>,
    other: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let run = RunId::generate();
    let sub = Subscription {
        run,
        case: None,
        effect: effect(77),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack".into(),
        correlation: keys("E-TENANCY-WAIT"),
        from: None,
    };
    let _ = mine.subscribe(&sub, ts(1_000)).await;
    // The attacker registers an identical wait — same run id, same effect,
    // same key — in *their* tenant.
    let _ = other.subscribe(&sub, ts(1_000)).await;

    match mine.waiting(100).await {
        Ok(waits) => {
            let matching = waits
                .iter()
                .filter(|w| w.run == run && w.effect == sub.effect)
                .count();
            if matching != 1 {
                r.record(
                    "tenancy",
                    format!(
                        "one registered wait was listed {matching} time(s) after another \
                         tenant registered a colliding row — the listing walked past its \
                         own tenant's range"
                    ),
                );
            }
        }
        Err(e) => r.record("tenancy", format!("waiting failed: {e}")),
    }
    match other.waiting(100).await {
        Ok(waits) => {
            let matching = waits
                .iter()
                .filter(|w| w.run == run && w.effect == sub.effect)
                .count();
            if matching != 1 {
                r.record(
                    "tenancy",
                    format!(
                        "the other tenant's own wait was listed {matching} time(s) — \
                         the scoping removed the feature rather than isolating it"
                    ),
                );
            }
        }
        Err(e) => r.record("tenancy", format!("waiting failed: {e}")),
    }
}

// ── Timers ──────────────────────────────────────────────────────────────────

/// Check a [`TimerStore`].
pub async fn check_timers(store: &Arc<dyn TimerStore>, r: &mut Report) {
    a_timer_fires_once(store, r).await;
    a_held_timer_does_not_hide_a_due_one(store, r).await;
    a_closed_runs_timers_are_retired_together(store, r).await;
}

async fn a_timer_fires_once(store: &Arc<dyn TimerStore>, r: &mut Report) {
    r.checked += 1;
    let timer = crate::core::Timer {
        run: RunId::generate(),
        case: None,
        effect: effect(20),
        step: StepId(0),
        phase: Phase::Forward,
        fire_at: ts(1_000),
    };
    if store.arm(&timer).await.is_err() {
        r.record("timers", "arm failed");
        return;
    }
    // Arming the same (run, effect) again must not create a second wake-up: a
    // resumed run re-registers its timer, and being woken twice is a run that
    // performs its next step twice.
    let _ = store.arm(&timer).await;

    let first = store.claim_due(ts(2_000), 10).await;
    let second = store.claim_due(ts(2_000), 10).await;
    match (first, second) {
        (Ok(a), Ok(b)) => {
            if a.len() != 1 {
                r.record(
                    "timers",
                    format!(
                        "arming twice produced {} due timers; it must produce one, or a \
                         resumed run is woken twice",
                        a.len()
                    ),
                );
            }
            if !b.is_empty() {
                r.record(
                    "single-delivery",
                    "a claimed timer was handed to a second sweep. Two sweepers against \
                     one store must not both resume the same run",
                );
            }
        }
        _ => r.record("timers", "claim_due failed"),
    }
}

/// **A timer held under another sweeper's claim does not hide the due ones
/// behind it.**
///
/// `claim_due`'s limit bounds what it returns. A backend that takes `limit`
/// candidates and *then* skips the held ones answers a page of nothing while
/// due timers wait behind the held head — silently, because a short page looks
/// like a quiet plane. Runs after [`a_timer_fires_once`], whose timer is held
/// at the head of the due order.
async fn a_held_timer_does_not_hide_a_due_one(store: &Arc<dyn TimerStore>, r: &mut Report) {
    r.checked += 1;
    for (n, at) in [(21u8, 1_100), (22, 1_200)] {
        let timer = crate::core::Timer {
            run: RunId::generate(),
            case: None,
            effect: effect(n),
            step: StepId(0),
            phase: Phase::Forward,
            fire_at: ts(at),
        };
        if store.arm(&timer).await.is_err() {
            r.record("timers", "arm failed");
            return;
        }
    }
    for round in 0..2 {
        match store.claim_due(ts(2_000), 1).await {
            Ok(page) if page.len() == 1 => {}
            Ok(page) => {
                r.record(
                    "timers",
                    format!(
                        "claim {round} with a limit of one returned {} timers while due ones \
                         were armed — a timer held by another sweeper filled the page and \
                         hid the due timers behind it",
                        page.len()
                    ),
                );
                return;
            }
            Err(e) => {
                r.record("timers", format!("claim_due failed: {e}"));
                return;
            }
        }
    }
}

/// **A closed run's timers are retired in one verb.**
///
/// A sealed run can record no wake, so a timer it leaves armed is claimed and
/// fails once per lease period for as long as the store exists. Another run's
/// timer is untouched.
async fn a_closed_runs_timers_are_retired_together(store: &Arc<dyn TimerStore>, r: &mut Report) {
    r.checked += 1;
    let (closed, other) = (RunId::generate(), RunId::generate());
    for (run, n) in [(closed, 23u8), (closed, 24), (other, 25)] {
        let timer = crate::core::Timer {
            run,
            case: None,
            effect: effect(n),
            step: StepId(0),
            phase: Phase::Forward,
            fire_at: ts(5_000_000),
        };
        if store.arm(&timer).await.is_err() {
            r.record("timers", "arm failed");
            return;
        }
    }
    match store.disarm_run(closed).await {
        Ok(2) => {}
        Ok(n) => r.record(
            "timers",
            format!("disarm_run retired {n} timers of a run that had two armed"),
        ),
        Err(e) => {
            r.record("timers", format!("disarm_run failed: {e}"));
            return;
        }
    }
    let Ok(due) = store.claim_due(ts(6_000_000), 64).await else {
        r.record("timers", "claim_due failed");
        return;
    };
    if due.iter().any(|t| t.run == closed) {
        r.record(
            "timers",
            "a retired run's timer was still claimable — it would be claimed and fail \
             once per lease period for ever",
        );
    }
    if !due.iter().any(|t| t.run == other) {
        r.record(
            "timers",
            "retiring one run's timers retired another run's too",
        );
    }
}

// ── Sealed runs ─────────────────────────────────────────────────────────────

/// A parked wait is the redelivery pass's work; a sealed run can record no
/// delivery, so its parked pair is retired rather than listed — or the pass
/// tries it, fails and finds it again every tick. `false` when the fixture
/// could not be set up.
async fn a_sealed_runs_parked_wait_is_retired(
    events: &Arc<dyn EventStore>,
    sealed: RunId,
    r: &mut Report,
) -> bool {
    let parked = Subscription {
        run: sealed,
        case: None,
        effect: effect(42),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "sealed.parked".into(),
        correlation: keys("SEALED-PARKED"),
        from: None,
    };
    if events.park_wait(&parked, ts(1_000)).await.is_err() {
        r.record("sealed waits", "park failed");
        return false;
    }
    for pass in ["first", "second"] {
        match events.parked_waits(64).await {
            Ok(listed) if listed.iter().any(|s| s.run == sealed) => r.record(
                "sealed waits",
                format!(
                    "the {pass} redelivery page listed a sealed run's parked wait — it can \
                     record no delivery and is tried again every tick"
                ),
            ),
            Ok(_) => {}
            Err(e) => r.record("sealed waits", format!("parked_waits failed: {e}")),
        }
    }
    true
}

/// A run admitted, concluded and sealed, or `None` with the reason recorded.
async fn a_sealed_run(
    journal: &Arc<dyn crate::journal::JournalStore>,
    r: &mut Report,
) -> Option<RunId> {
    let sealed = RunId::generate();
    let Ok(lease) = journal
        .acquire(sealed, "conformance", std::time::Duration::from_secs(60))
        .await
    else {
        r.record("sealed waits", "acquire failed");
        return None;
    };
    let admitted = crate::journal::Append::new(
        sealed,
        crate::journal::RecordKind::RunAdmitted {
            capability: "conformance".into(),
            governed_by: None,
            input_label: crate::core::Label::trusted(),
            input: serde_json::Value::Null,
            policy_bundle: None,
            canon: crate::core::canon::VERSION,
            idempotency_key: None,
            admitted_by: None,
            served_unchained: false,
            plane_chain: false,
        },
    );
    let concluded = crate::journal::Append::new(
        sealed,
        crate::journal::RecordKind::RunConcluded {
            outcome: "cancelled".into(),
            reason: None,
            exhaustion: None,
            live_spend: crate::core::Spend::default(),
            chain_head: crate::core::Digest::ZERO,
        },
    );
    if journal
        .append(lease.epoch, vec![admitted, concluded])
        .await
        .is_err()
        || journal
            .seal(sealed, lease.epoch, "cancelled")
            .await
            .is_err()
    {
        r.record("sealed waits", "the fixture could not seal its run");
        return None;
    }
    Some(sealed)
}

/// Check that the wait tables pass over a sealed run.
///
/// The three handles are one backend: the liveness check is the wait tables
/// consulting the journal's seal in the same database. The runtime retires a
/// closed run's timers and waits as it seals it; this covers what outlives
/// that — a crash between the seal and the retirement.
pub async fn check_sealed_runs_waits(
    journal: &Arc<dyn crate::journal::JournalStore>,
    timers: &Arc<dyn TimerStore>,
    events: &Arc<dyn EventStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let Some(sealed) = a_sealed_run(journal, r).await else {
        return;
    };

    let timer = crate::core::Timer {
        run: sealed,
        case: None,
        effect: effect(40),
        step: StepId(0),
        phase: Phase::Forward,
        fire_at: ts(7_000_000),
    };
    if timers.arm(&timer).await.is_err() {
        r.record("sealed waits", "arm failed");
        return;
    }
    match timers.claim_due(ts(7_000_001), 64).await {
        Ok(due) if due.iter().any(|t| t.run == sealed) => r.record(
            "sealed waits",
            "a sealed run's timer was claimed — it fails to record a wake and is \
             claimed again every lease period",
        ),
        Ok(_) => {}
        Err(e) => r.record("sealed waits", format!("claim_due failed: {e}")),
    }

    if !a_sealed_runs_parked_wait_is_retired(events, sealed, r).await {
        return;
    }

    let wait = |run| Subscription {
        run,
        case: None,
        effect: effect(41),
        step: StepId(0),
        phase: Phase::Forward,
        kind: "sealed.probe".into(),
        correlation: keys("SEALED-1"),
        from: None,
    };
    let live = RunId::generate();
    if events.subscribe(&wait(sealed), ts(1_000)).await.is_err()
        || events.subscribe(&wait(live), ts(1_001)).await.is_err()
    {
        r.record("sealed waits", "subscribe failed");
        return;
    }
    let event = InboundEvent::new(
        "urn:probe",
        "sealed-1",
        "sealed.probe",
        serde_json::json!({}),
    )
    .correlate(CorrelationKey::new("doc", "SEALED-1"));
    if events.buffer(&event, ts(1_002)).await.is_err() {
        r.record("sealed waits", "buffer failed");
        return;
    }
    match events.match_waiter(&event, ts(1_002)).await {
        Ok(Some(sub)) if sub.run == live => {}
        other => r.record(
            "sealed waits",
            format!(
                "an event went to {other:?} while the oldest waiter on its key was a \
                 sealed run and a live run waited behind it"
            ),
        ),
    }
}

// ── Tasks ───────────────────────────────────────────────────────────────────

/// Check a [`TaskStore`].
pub async fn check_tasks(store: &Arc<dyn TaskStore>, r: &mut Report) {
    a_task_is_claimed_by_one_actor_only(store, r).await;
    an_excluded_actor_cannot_claim(store, r).await;
    ineligibility_outranks_contention(store, r).await;
    only_the_holder_releases(store, r).await;
    the_backlog_counts_work_somebody_is_holding(store, r).await;
    a_claimed_task_is_offered_to_nobody_else(store, r).await;
    a_take_over_names_its_holder_and_keeps_the_exclusions(store, r).await;
    an_expired_task_is_not_resurrected_by_a_claim(store, r).await;
    a_state_write_to_a_missing_task_is_not_found(store, r).await;
    escalation_widens_the_audience_and_frees_the_reservation(store, r).await;
    an_escalated_task_leaves_the_overdue_scan(store, r).await;
    a_decided_task_is_not_resurrected_by_escalation(store, r).await;
    a_role_name_is_stored_verbatim(store, r).await;
    a_settled_task_is_not_settled_again(store, r).await;
    a_closed_runs_pending_tasks_are_withdrawn(store, r).await;
}

/// **A claim racing an expiry cannot resurrect the task.**
///
/// The sweep expires a task; a reviewer's claim is in flight at the same
/// moment. A claim whose reservation is keyed on the assignee alone passes its
/// eligibility read while the task is still open, loses the race, and then
/// writes `claimed` over `expired` — un-deciding an expiry policy that
/// already fired, on the on-expiry disposition an operator relied on.
///
/// The sequential half pins the visible contract; the concurrent rounds are
/// what reach the reservation statement itself, because the eligibility
/// read refuses a *settled* expiry before the write is ever attempted.
/// Whatever the interleaving, the invariant is the same: once both calls have
/// returned, the task is `expired` — either the claim lost and erred, or it
/// won first and the expiry overwrote it.
async fn an_expired_task_is_not_resurrected_by_a_claim(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let roles = vec!["ops".to_owned()];

    // Sequential: a settled expiry refuses the claim outright.
    let settled = task(36, None);
    if store.open(&settled).await.is_err() {
        r.record("expiry", "open failed");
        return;
    }
    if store
        .set_state(settled.id, TaskState::Expired)
        .await
        .is_err()
    {
        r.record("expiry", "the fixture could not expire its task");
        return;
    }
    if store.claim(settled.id, "alice", &roles).await.is_ok() {
        r.record(
            "expiry",
            "a claim on an expired task succeeded — the expiry the sweep \
             already acted on is silently un-decided",
        );
    }

    // Concurrent: the race the reservation predicate exists for.
    for round in 0u8..8 {
        let t = task(40 + round, None);
        if store.open(&t).await.is_err() {
            r.record("expiry", "open failed");
            return;
        }
        let (s1, s2) = (Arc::clone(store), Arc::clone(store));
        let claim = tokio::spawn(async move { s1.claim(t.id, "alice", &["ops".to_owned()]).await });
        let expire = tokio::spawn(async move { s2.set_state(t.id, TaskState::Expired).await });
        let _ = claim.await;
        let _ = expire.await;
        let Ok(Some(after)) = store.task(t.id).await else {
            r.record("expiry", "the raced task could not be read back");
            return;
        };
        if after.state != TaskState::Expired {
            r.record(
                "expiry",
                format!(
                    "after a claim raced an expiry the task ended {:?} — an \
                     expired task was resurrected into a reviewer's hands",
                    after.state
                ),
            );
            return;
        }
    }
}

/// A state write to a task that does not exist is `NotFound`, not silence.
///
/// The sweep and the decision path both drive tasks through `set_state`, and a
/// backend that discards the row count reports success for a write that landed
/// nowhere — the same lie a release that freed nothing tells, on the verb the
/// expiry sweep trusts.
async fn a_state_write_to_a_missing_task_is_not_found(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let ghost = task(63, None);
    match store.set_state(ghost.id, TaskState::Completed).await {
        Err(StoreError::NotFound(_)) => {}
        Ok(_) => r.record(
            "missing rows",
            "set_state on a task that does not exist reported success — the \
             caller now believes a decision was recorded that no store holds",
        ),
        Err(e) => r.record(
            "missing rows",
            format!("set_state on a missing task was answered with {e}"),
        ),
    }
}

/// **The absent-holder case: a take-over displaces exactly the holder it
/// names, and eligibility does not thin because the previous reviewer left.**
///
/// Only the holder may release, so a task claimed by a reviewer who is not
/// coming back would stay parked until its deadline breached. `take_over` is the
/// answer, and its two guards are what this pins. The `from` argument is a
/// compare-and-swap: a take-over decided from a stale queue view must fail
/// rather than displace whoever holds the task *now*. And a take-over is a
/// claim — the four-eyes exclusion refuses the proposer however the task
/// came to be held.
async fn a_take_over_names_its_holder_and_keeps_the_exclusions(
    store: &Arc<dyn TaskStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let t = task(34, Some("mallory"));
    if store.open(&t).await.is_err() {
        r.record("tasks", "open failed");
        return;
    }
    let roles = vec!["ops".to_owned()];
    if store.claim(t.id, "alice", &roles).await.is_err() {
        r.record("tasks", "the fixture's first claim failed");
        return;
    }

    // A stale view: carol believes bob holds it. Nobody is displaced.
    if store.take_over(t.id, "bob", "carol", &roles).await.is_ok() {
        r.record(
            "take-over",
            "a take-over naming the wrong holder displaced whoever held the task \
             — the compare-and-swap guard is not one",
        );
    }
    // The excluded proposer cannot acquire the task by displacement either.
    if store
        .take_over(t.id, "alice", "mallory", &roles)
        .await
        .is_ok()
    {
        r.record(
            "take-over",
            "the four-eyes exclusion thinned on take-over — the proposer acquired \
             the decision by displacing its reviewer",
        );
    }
    // The legitimate handover: alice is gone, carol names her and takes over.
    match store.take_over(t.id, "alice", "carol", &roles).await {
        Ok(taken) if taken.assignee.as_deref() == Some("carol") => {}
        Ok(taken) => r.record(
            "take-over",
            format!("the take-over succeeded but assigned {:?}", taken.assignee),
        ),
        Err(e) => r.record(
            "take-over",
            format!("an eligible take-over naming the true holder failed: {e}"),
        ),
    }
    // And an unheld task takes the ordinary claim verb, not this one.
    let open = task(35, None);
    let _ = store.open(&open).await;
    if store
        .take_over(open.id, "alice", "carol", &roles)
        .await
        .is_ok()
    {
        r.record(
            "take-over",
            "a take-over of an unheld task succeeded — the verb for that is claim, \
             and accepting it here hides a stale view",
        );
    }
}

/// Claiming a task does not answer it.
///
/// `open_count` is what an operator watches to know whether the plane is keeping
/// up. A backend that counts only *unclaimed* work — or that keeps a derived
/// count and forgets to move it when a task is claimed — makes the backlog fall
/// the moment somebody opens an item, which reads as progress and is not.
///
/// Completing it is what should decrement the count, and this checks both edges
/// rather than only the first, because a count that never moves would pass a
/// check that only claimed.
async fn the_backlog_counts_work_somebody_is_holding(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(70, None);
    let Ok(opened) = store.open(&t).await else {
        r.record("backlog", "open failed");
        return;
    };
    let before = store.open_count().await.unwrap_or(0);

    let roles = vec!["ops".to_owned()];
    if store.claim(opened.id, "reviewer", &roles).await.is_err() {
        r.record("backlog", "the task could not be claimed");
        return;
    }
    let claimed = store.open_count().await.unwrap_or(0);
    if claimed != before {
        r.record(
            "backlog",
            format!(
                "the backlog moved from {before} to {claimed} when a task was merely claimed. A task somebody is holding is still a decision the plane is waiting on, so this reports progress that has not happened"
            ),
        );
    }

    if store
        .set_state(opened.id, TaskState::Completed)
        .await
        .is_err()
    {
        r.record("backlog", "the task could not be completed");
        return;
    }
    let done = store.open_count().await.unwrap_or(0);
    if done + 1 != claimed {
        r.record(
            "backlog",
            format!(
                "the backlog went from {claimed} to {done} when a task was completed; it must fall by exactly one. A count that never moves is a dashboard that cannot show the queue draining"
            ),
        );
    }
}

/// The queue offers a task nobody holds.
///
/// The exact complement of [`the_backlog_counts_work_somebody_is_holding`], and
/// the two are only meaningful together: a claimed task stays in the *backlog*
/// because it is still a decision the plane is waiting on, and leaves the
/// *queue* because it is nobody else's to take. A backend where those two are
/// one predicate shows a held task to a second reviewer, who opens it, reads
/// the case, decides — and is refused at the claim, having done the work.
async fn a_claimed_task_is_offered_to_nobody_else(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let roles = vec!["ops".to_owned()];
    let t = task(74, None);
    let Ok(opened) = store.open(&t).await else {
        r.record("queue", "open failed");
        return;
    };
    let offered = |page: &[Task]| page.iter().any(|q| q.id == opened.id);

    match store.queue(&roles, 64).await {
        Ok(page) if offered(&page) => {}
        Ok(_) => {
            r.record(
                "queue",
                "an open task is not in the queue, so the check below would pass \
                 on a queue that is simply empty",
            );
            return;
        }
        Err(error) => {
            r.record("queue", format!("the queue could not be read: {error}"));
            return;
        }
    }

    if store.claim(opened.id, "reviewer", &roles).await.is_err() {
        r.record("queue", "the task could not be claimed");
        return;
    }
    match store.queue(&roles, 64).await {
        Ok(page) if offered(&page) => r.record(
            "queue",
            "a claimed task is still offered by the queue, so a second reviewer \
             is shown a decision somebody already holds and finds out at the claim",
        ),
        Ok(_) => {}
        Err(error) => r.record("queue", format!("the queue could not be read: {error}")),
    }
}

/// **A settled task is not settled again.**
///
/// The expiry sweep and a reviewer's decision race to settle one task, and the
/// run consumes whichever answer reached it first. `set_state` is the
/// compare-and-set that keeps the worklist agreeing with that answer: the
/// loser's write reports `false` and leaves the winner's state standing.
async fn a_settled_task_is_not_settled_again(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(70, None);
    if store.open(&t).await.is_err() {
        r.record("settlement", "open failed");
        return;
    }
    match store.set_state(t.id, TaskState::Completed).await {
        Ok(true) => {}
        other => {
            r.record(
                "settlement",
                format!("settling an open task answered {other:?}, not that it settled"),
            );
            return;
        }
    }
    match store.set_state(t.id, TaskState::Expired).await {
        Ok(false) => {}
        other => r.record(
            "settlement",
            format!("a second settlement of a decided task answered {other:?}, not `false`"),
        ),
    }
    match store.task(t.id).await {
        Ok(Some(after)) if after.state == TaskState::Completed => {}
        other => r.record(
            "settlement",
            format!(
                "the expiry that lost the race overwrote the decision that won it: {other:?} — \
                 the worklist now contradicts the answer the run consumed"
            ),
        ),
    }
}

/// **A closed run's awaited tasks are withdrawn; nothing else is.**
///
/// Nobody can answer a task whose run is sealed. Left pending it stays in the
/// queue and the backlog, and its expiry is applied to a run that cannot
/// consume it. A task the run did not name — opened beside an answer, already
/// decided, or another run's — stands.
async fn a_closed_runs_pending_tasks_are_withdrawn(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let awaited = task(71, None);
    let mut decided = task(72, None);
    decided.run = awaited.run;
    decided.id = TaskId::derive(awaited.run, effect(72));
    let mut beside = task(74, None);
    beside.run = awaited.run;
    beside.id = TaskId::derive(awaited.run, effect(74));
    let unrelated = task(73, None);
    for t in [&awaited, &decided, &beside, &unrelated] {
        if store.open(t).await.is_err() {
            r.record("withdrawal", "open failed");
            return;
        }
    }
    if store
        .set_state(decided.id, TaskState::Completed)
        .await
        .is_err()
    {
        r.record("withdrawal", "the fixture could not decide its task");
        return;
    }
    let named = [awaited.id, decided.id, unrelated.id];
    match store.withdraw_run(awaited.run, &named).await {
        Ok(1) => {}
        other => r.record(
            "withdrawal",
            format!("withdrawing a run with one pending awaited task answered {other:?}"),
        ),
    }
    let state = |id| {
        let store = Arc::clone(store);
        async move { store.task(id).await.ok().flatten().map(|t| t.state) }
    };
    if state(awaited.id).await != Some(TaskState::Withdrawn) {
        r.record(
            "withdrawal",
            "a closed run's awaited task is still pending — offered for a decision no \
             answer can reach",
        );
    }
    if state(decided.id).await != Some(TaskState::Completed) {
        r.record(
            "withdrawal",
            "withdrawal rewrote a task that was already decided",
        );
    }
    if state(beside.id).await != Some(TaskState::Open) {
        r.record("withdrawal", "withdrawal took a task the run did not name");
    }
    if state(unrelated.id).await != Some(TaskState::Open) {
        r.record(
            "withdrawal",
            "withdrawing one run's tasks withdrew another run's",
        );
    }
}

fn task(id: u8, excluded: Option<&str>) -> Task {
    let run = RunId::generate();
    Task {
        id: TaskId::derive(run, effect(id)),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new(
            crate::core::Tainted::trusted("needs a person".to_owned()),
            serde_json::json!({}),
        ),
        candidate_roles: vec!["ops".into()],
        escalate_to: Vec::new(),
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        excluded_actors: excluded.map(|a| vec![a.to_owned()]).unwrap_or_default(),
        created_at: ts(1_000),
        due_at: None,
        withheld: None,
    }
}

/// **Escalation is a widening, not a flag.**
///
/// `TaskStore::escalate` must move three facts in one verb: the state says
/// what happened, the stale reservation is cleared — the claim belonged to
/// the window that closed, and an escalation that leaves the task assigned
/// to whoever sat on it has widened the audience to people who cannot claim
/// the row — and the declared `escalate_to` roles join the audience as a
/// union, because the original reviewers remain eligible. The four-eyes
/// exclusion must survive it: the proposer is barred from the wider audience
/// exactly as from the narrow one.
async fn escalation_widens_the_audience_and_frees_the_reservation(
    store: &Arc<dyn TaskStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let mut t = task(60, Some("mallory"));
    t.on_expiry = OnExpiry::Escalate;
    t.escalate_to = vec!["ops-lead".into()];
    if store.open(&t).await.is_err() {
        r.record("escalation", "open failed");
        return;
    }
    // Claimed and sat on: the shape the sweep escalates past.
    if store
        .claim(t.id, "alice", &["ops".to_owned()])
        .await
        .is_err()
    {
        r.record("escalation", "an eligible actor could not claim");
        return;
    }
    let escalated = match store.escalate(t.id).await {
        Ok(task) => task,
        Err(e) => {
            r.record("escalation", format!("escalate failed: {e}"));
            return;
        }
    };
    if escalated.state != TaskState::Escalated {
        r.record("escalation", "the state does not say what happened");
    }
    if escalated.assignee.is_some() {
        r.record(
            "escalation",
            "the stale reservation survived — the widened audience is being \
             shown a task only the absent holder can act on",
        );
    }
    if !escalated.candidate_roles.iter().any(|x| x == "ops-lead") {
        r.record(
            "escalation",
            "the declared escalation audience was not added — the widening \
             the manifest promised did not happen",
        );
    }
    if !escalated.candidate_roles.iter().any(|x| x == "ops") {
        r.record(
            "escalation",
            "the original audience was dropped — that is a reassignment, not \
             a widening",
        );
    }
    // The wider audience can act on it now.
    if store
        .claim(t.id, "lena", &["ops-lead".to_owned()])
        .await
        .is_err()
    {
        r.record(
            "escalation",
            "a reviewer from the escalation audience could not claim the \
             escalated task, so the widening exists only as data",
        );
    }
    if store.release(t.id, "lena").await.is_err() {
        r.record("escalation", "the new holder could not release");
    }
    // Four-eyes does not thin because nobody answered.
    if store
        .claim(t.id, "mallory", &["ops-lead".to_owned()])
        .await
        .is_ok()
    {
        r.record(
            "four-eyes",
            "the proposer claimed the task after escalation — the exclusion \
             must survive the audience widening, or escalating a proposal is \
             how its proposer gets to approve it",
        );
    }
}

/// **An escalated task leaves the overdue scan.**
///
/// `overdue` drives the sweep that applies each task's declared expiry
/// policy, and escalation is that policy having fired. An escalated task is
/// pending and past due forever — deciding it is exactly what did not happen
/// — so a scan that keeps returning it fills its bounded, oldest-first batch
/// with rows the sweep will no-op, and the `deny`/`proceed` tasks queued
/// behind them silently stop expiring. The positive half is load-bearing: a
/// scan broken for everybody would also return nothing.
async fn an_escalated_task_leaves_the_overdue_scan(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let mut escalating = task(61, None);
    escalating.on_expiry = OnExpiry::Escalate;
    escalating.escalate_to = vec!["ops-lead".into()];
    escalating.due_at = Some(ts(2_000));
    let mut denying = task(62, None);
    denying.due_at = Some(ts(2_500));
    if store.open(&escalating).await.is_err() || store.open(&denying).await.is_err() {
        r.record("escalation", "open failed");
        return;
    }
    let now = ts(3_000);
    let before = store.overdue(now, 50).await.unwrap_or_default();
    if !before.iter().any(|x| x.id == escalating.id) {
        r.record(
            "escalation",
            "an open task past its window is missing from the overdue scan",
        );
        return;
    }
    if store.escalate(escalating.id).await.is_err() {
        r.record("escalation", "escalate failed");
        return;
    }
    let after = store.overdue(now, 50).await.unwrap_or_default();
    if after.iter().any(|x| x.id == escalating.id) {
        r.record(
            "escalation",
            "an escalated task is still in the overdue scan. Its expiry \
             policy has already fired, so every later sweep re-selects and \
             no-ops it; enough of them fill the bounded batch and the expiry \
             policies of the tasks behind them never fire at all",
        );
    }
    if !after.iter().any(|x| x.id == denying.id) {
        r.record(
            "escalation",
            "a task still awaiting its expiry policy vanished from the scan",
        );
    }
}

/// **A racing decision beats an escalation.**
///
/// The sweep reads `overdue`, then escalates; a reviewer decides in between.
/// `escalate` keyed on nothing would write `escalated` over `completed`,
/// un-deciding the answer — the same race `an_expired_task_is_not_resurrected`
/// pins for the expiry write.
async fn a_decided_task_is_not_resurrected_by_escalation(
    store: &Arc<dyn TaskStore>,
    r: &mut Report,
) {
    r.checked += 1;
    let mut t = task(63, None);
    t.on_expiry = OnExpiry::Escalate;
    t.escalate_to = vec!["ops-lead".into()];
    if store.open(&t).await.is_err() {
        r.record("escalation", "open failed");
        return;
    }
    if store.set_state(t.id, TaskState::Completed).await.is_err() {
        r.record("escalation", "the fixture could not complete its task");
        return;
    }
    match store.escalate(t.id).await {
        Ok(after) => {
            if after.state != TaskState::Completed {
                r.record(
                    "escalation",
                    "escalating a decided task changed its state — the \
                     decision that won the race was un-decided by the sweep",
                );
            }
        }
        Err(e) => r.record(
            "escalation",
            format!("escalate errored on a decided task: {e}"),
        ),
    }
}

/// **A role or actor name is data, not syntax.**
///
/// The store does not get to constrain the alphabet of the four-eyes
/// control's operands: an exclusion list that round-trips 'a,b' as two
/// actors named neither has un-barred the person it exists to bar. Both
/// halves matter — the names come back verbatim, and the exclusion still
/// fires for the actor as named.
async fn a_role_name_is_stored_verbatim(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let mut t = task(64, Some("spiffe://acme/ns,prod/agent"));
    t.candidate_roles = vec!["ops,eu".into()];
    if store.open(&t).await.is_err() {
        r.record("tasks", "open failed");
        return;
    }
    let Ok(Some(read)) = store.task(t.id).await else {
        r.record("tasks", "the task could not be read back");
        return;
    };
    if read.candidate_roles != vec!["ops,eu".to_owned()]
        || read.excluded_actors != vec!["spiffe://acme/ns,prod/agent".to_owned()]
    {
        r.record(
            "four-eyes",
            format!(
                "a name did not round-trip verbatim: roles {:?}, excluded {:?}. \
                 A delimiter the store chose has split somebody's identifier",
                read.candidate_roles, read.excluded_actors
            ),
        );
    }
    if store
        .claim(t.id, "spiffe://acme/ns,prod/agent", &["ops,eu".to_owned()])
        .await
        .is_ok()
    {
        r.record(
            "four-eyes",
            "the excluded actor claimed the task — the exclusion did not \
             survive storage of the actor's own name",
        );
    }
    if store
        .claim(t.id, "someone-else", &["ops,eu".to_owned()])
        .await
        .is_err()
    {
        r.record("four-eyes", "an eligible actor was refused");
    }
}

async fn a_task_is_claimed_by_one_actor_only(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(30, None);
    if store.open(&t).await.is_err() {
        r.record("tasks", "open failed");
        return;
    }
    let roles = vec!["ops".to_owned()];
    let first = store.claim(t.id, "alice", &roles).await;
    let second = store.claim(t.id, "bob", &roles).await;
    if first.is_err() {
        r.record("tasks", "an eligible actor could not claim an open task");
    }
    if second.is_ok() {
        r.record(
            "four-eyes",
            "two reviewers both hold one decision. Reservation must be atomic, or \
             both believe they own it and one of them acts on a stale view",
        );
    }
}

/// Four-eyes: whoever proposed cannot approve.
async fn an_excluded_actor_cannot_claim(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(31, Some("alice"));
    if store.open(&t).await.is_err() {
        return;
    }
    let roles = vec!["ops".to_owned()];
    if store.claim(t.id, "alice", &roles).await.is_ok() {
        r.record(
            "four-eyes",
            "an excluded actor claimed the task. The exclusion is the whole control: \
             whoever proposed an action must not be the one who approves it",
        );
    }
    if store.claim(t.id, "bob", &roles).await.is_err() {
        r.record("four-eyes", "an eligible actor was refused");
    }
}

/// A permanent refusal must win over a transient one.
///
/// The obvious implementation checks availability first, because that is the
/// state the row is in. Then a barred reviewer asking for a held task is told
/// "held by Bob" — so they wait for Bob to release it, ask again, and are
/// refused for a reason nobody has yet mentioned. It also hands queue state to
/// somebody with no standing in that queue. `403` and `409` ask different
/// things of the person reading them.
async fn ineligibility_outranks_contention(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(32, Some("alice"));
    if store.open(&t).await.is_err() {
        r.record("tasks", "open failed");
        return;
    }
    let roles = vec!["ops".to_owned()];
    if store.claim(t.id, "bob", &roles).await.is_err() {
        r.record("tasks", "an eligible actor could not claim an open task");
        return;
    }

    // Alice is excluded *and* the task is held. She must hear the permanent one.
    match store.claim(t.id, "alice", &roles).await {
        Err(ClaimError::Excluded { .. }) => {}
        Err(ClaimError::AlreadyClaimed { .. }) => r.record(
            "four-eyes",
            "a barred reviewer was told the task is held rather than that it is \
             not theirs — they will wait for the holder to release it and be \
             refused again, and meanwhile they have learnt who is reviewing what",
        ),
        other => r.record(
            "four-eyes",
            format!("an excluded actor's claim was answered with {other:?}"),
        ),
    }

    // Same for the wrong role, which is the other permanent refusal.
    let wrong = vec!["clerk".to_owned()];
    match store.claim(t.id, "carol", &wrong).await {
        Err(ClaimError::WrongRole { .. }) => {}
        other => r.record(
            "tasks",
            format!("an ineligible actor's claim was answered with {other:?}"),
        ),
    }
}

/// A claim is given back by its holder, and by nobody else.
///
/// Without release, a reviewer who claims something they then cannot decide has
/// parked it until somebody edits the database — so the queue learns not to
/// claim, and the reservation stops meaning anything.
async fn only_the_holder_releases(store: &Arc<dyn TaskStore>, r: &mut Report) {
    r.checked += 1;
    let t = task(33, None);
    if store.open(&t).await.is_err() {
        r.record("tasks", "open failed");
        return;
    }
    let roles = vec!["ops".to_owned()];
    if store.claim(t.id, "bob", &roles).await.is_err() {
        r.record("tasks", "an eligible actor could not claim an open task");
        return;
    }

    match store.release(t.id, "carol").await {
        Err(ClaimError::NotHeld { .. }) => {}
        Ok(()) => r.record(
            "tasks",
            "a stranger's release reported success. Whether or not it freed the \
             task, the caller now believes it did — and the holder believes they \
             still have it",
        ),
        other => r.record(
            "tasks",
            format!("a stranger's release was answered with {other:?}"),
        ),
    }
    match store.task(t.id).await {
        Ok(Some(held)) if held.assignee.as_deref() == Some("bob") => {}
        _ => r.record("tasks", "a refused release still freed the task"),
    }

    if store.release(t.id, "bob").await.is_err() {
        r.record("tasks", "the holder could not release their own claim");
    }
    match store.task(t.id).await {
        Ok(Some(freed)) if freed.assignee.is_none() && freed.state == TaskState::Open => {}
        Ok(Some(freed)) => r.record(
            "tasks",
            format!(
                "a released task is {:?} assigned to {:?} — it is invisible to \
                 the queue that must now pick it up",
                freed.state, freed.assignee
            ),
        ),
        _ => r.record("tasks", "a released task could not be read back"),
    }
}

// ── Batches ─────────────────────────────────────────────────────────────────

/// Check a [`BatchStore`].
pub async fn check_batches(store: &Arc<dyn BatchStore>, r: &mut Report) {
    r.checked += 1;
    let id = BatchId::generate();
    if store.open(id, "digest").await.is_err() {
        r.record("batches", "open failed");
        return;
    }

    // A record for an item nobody reserved is a refusal, not a silent no-op:
    // both backends once returned `Ok` while writing nothing, telling the
    // caller *recorded* over an outcome that vanished.
    if store
        .record(
            id,
            "item-unreserved",
            &ItemOutcome::Succeeded,
            Spend::default(),
        )
        .await
        .is_ok()
    {
        r.record(
            "batches",
            "recording an unreserved item reported success while writing nothing",
        );
    }
    let (first, second) = (RunId::generate(), RunId::generate());
    let Ok(a) = store.reserve(id, "item-001", first).await else {
        r.record("batches", "reserve failed");
        return;
    };
    let Ok(b) = store.reserve(id, "item-001", second).await else {
        r.record("batches", "the second reserve failed");
        return;
    };
    if a.run != first || b.run != first {
        r.record(
            "reservation",
            "reserving an item twice did not return the original run id. Overwriting \
             it orphans the journal that already holds this item's effects, and they \
             are performed again",
        );
    }

    r.checked += 1;
    let _ = store
        .record(id, "item-001", &ItemOutcome::Succeeded, Spend::default())
        .await;
    let _ = store.reserve(id, "item-002", RunId::generate()).await;
    match store.cursor(id).await {
        Ok(c) if c.as_deref() == Some("item-001") => {}
        Ok(c) => r.record(
            "cursor",
            format!(
                "the cursor must stop before the first unfinished item, got {c:?} — a \
                 resume that steps over one reports the batch complete with work \
                 outstanding"
            ),
        ),
        Err(e) => r.record("cursor", format!("cursor failed: {e}")),
    }

    // The half a store gets wrong by asking *which outcomes are open* rather
    // than which are terminal. A suspended item has an outcome, so a predicate
    // written as a list of the non-terminal spellings passes the check above
    // and steps over this one — the batch then reports complete while an item
    // is still waiting on an event, a person or a raised ceiling.
    r.checked += 1;
    let _ = store
        .record(
            id,
            "item-002",
            &ItemOutcome::Suspended("waiting".to_owned()),
            Spend::default(),
        )
        .await;
    match store.cursor(id).await {
        Ok(c) if c.as_deref() == Some("item-001") => {}
        Ok(c) => r.record(
            "cursor",
            format!(
                "a suspended item was treated as settled and the cursor moved to \
                 {c:?} — a resume steps over work that never finished"
            ),
        ),
        Err(e) => r.record("cursor", format!("cursor failed: {e}")),
    }

    check_batch_backlog(store, id, r).await;
    check_batch_identity(store, id, r).await;
}

/// The listing that turns *43 failed* into the 43 keys.
///
/// The state left by [`check_batches`] is exactly the interesting one: one
/// settled item, one suspended, and one reserved with no outcome at all. A
/// store that filters on `outcome <> 'succeeded'` passes on the suspended item
/// and silently drops the reserved one — and the reserved items are the ones a
/// crash left mid-flight, which is the class an operator most needs named.
async fn check_batch_backlog(store: &Arc<dyn BatchStore>, id: BatchId, r: &mut Report) {
    r.checked += 1;
    let _ = store.reserve(id, "item-003", RunId::generate()).await;

    let keys = match store.items_needing_attention(id, 100).await {
        Ok(items) => items.iter().map(|i| i.key.clone()).collect::<Vec<_>>(),
        Err(e) => {
            r.record("backlog", format!("items_needing_attention failed: {e}"));
            return;
        }
    };

    if keys.contains(&"item-001".to_owned()) {
        r.record(
            "backlog",
            "a succeeded item is in the backlog, so the listing an operator reads to \
             find the failures is mostly successes — which is the paging problem it \
             exists to remove",
        );
    }
    for (key, why) in [
        (
            "item-002",
            "a suspended item is missing from the backlog. It is not terminal and not \
             settled: something is waiting on a person, an event or a raised ceiling, \
             and nothing else names it",
        ),
        (
            "item-003",
            "an item reserved with no outcome is missing from the backlog. That is what \
             a crash mid-item leaves, and a store filtering on `outcome <> settled` \
             drops it because NULL compares to nothing",
        ),
    ] {
        if !keys.contains(&key.to_owned()) {
            r.record("backlog", why);
        }
    }

    // Ordering, because the listing is a work queue: a page that is not the
    // oldest unsettled items is a page whose head moves for reasons that have
    // nothing to do with what was resolved.
    r.checked += 1;
    let mut sorted = keys.clone();
    sorted.sort();
    if keys != sorted {
        r.record(
            "backlog",
            format!("the backlog is not ordered oldest key first: {keys:?}"),
        );
    }

    // And it has to empty, which is what makes an ascending page legitimate at
    // all — see I13 on a backlog with no verb.
    r.checked += 1;
    let _ = store
        .record(id, "item-003", &ItemOutcome::Succeeded, Spend::default())
        .await;
    match store.items_needing_attention(id, 100).await {
        Ok(items) if items.iter().any(|i| i.key == "item-003") => r.record(
            "backlog",
            "settling an item did not take it off the backlog, so the listing only \
             grows — a queue that floods retires the control without anyone deciding to",
        ),
        Ok(_) => {}
        Err(e) => r.record("backlog", format!("items_needing_attention failed: {e}")),
    }
}

/// One batch runs one frozen plan, and the store's row is the only witness to
/// which; the same row answers existence, and the exhausted mark must land or
/// refuse. Split from [`check_batches`] only for length — it continues on the
/// batch that function opened.
async fn check_batch_identity(store: &Arc<dyn BatchStore>, id: BatchId, r: &mut Report) {
    // Reopening under the same digest is an idempotent retry; reopening under
    // another one must be refused, or items settle under a plan the batch's
    // record does not name.
    r.checked += 1;
    if store.open(id, "digest").await.is_err() {
        r.record(
            "batches",
            "reopening under the same plan digest was refused",
        );
    }
    match store.open(id, "another-digest").await {
        Err(StoreError::BatchPlanChanged { .. }) => {}
        Err(e) => r.record(
            "batches",
            format!("a plan swap was refused with the wrong error: {e}"),
        ),
        Ok(()) => r.record(
            "batches",
            "reopening a batch under a different plan digest was accepted — items \
             from here on would settle under a plan the batch's record does not name",
        ),
    }
    match store.plan_digest(id).await {
        Ok(Some(d)) if d == "digest" => {}
        Ok(d) => r.record(
            "batches",
            format!("plan_digest answered {d:?} for a batch opened with 'digest'"),
        ),
        Err(e) => r.record("batches", format!("plan_digest failed: {e}")),
    }
    match store.plan_digest(BatchId::generate()).await {
        Ok(None) => {}
        Ok(Some(d)) => r.record(
            "batches",
            format!("plan_digest invented '{d}' for a batch that does not exist"),
        ),
        Err(e) => r.record(
            "batches",
            format!("plan_digest failed on a missing batch: {e}"),
        ),
    }

    // The exhausted mark is the one bit that lets a census read as finished;
    // written to nowhere it is lost with no symptom, so a mark on an unknown
    // batch must refuse. The positive half: on a real batch it lands.
    r.checked += 1;
    if store.mark_exhausted(BatchId::generate()).await.is_ok() {
        r.record(
            "batches",
            "marking an unknown batch exhausted reported success while writing nothing",
        );
    }
    if store.mark_exhausted(id).await.is_err() {
        r.record("batches", "marking a real batch exhausted failed");
    }
    if !store.is_exhausted(id).await.unwrap_or(false) {
        r.record("batches", "the exhausted mark did not land");
    }
}
