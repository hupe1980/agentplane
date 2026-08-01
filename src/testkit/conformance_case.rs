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
use crate::case::{CaseStore, ClaimError, EventStore, TaskStore, TimerStore};
use crate::core::{
    BatchId, CaseId, CaseVersion, CorrelationKey, EffectKey, InboundEvent, Justification, OnExpiry,
    Phase, Priority, RunId, Spend, StepId, StoreError, Subscription, Task, TaskId, TaskState,
    Timestamp,
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
    an_unmet_obligation_blocks_closure(store, r).await;
    the_census_counts_every_open_case(store, r).await;
    two_concurrent_messages_open_one_case(store, r).await;
    a_stale_state_write_is_refused(store, r).await;
    a_state_write_to_a_missing_case_is_not_found(store, r).await;
    only_one_of_several_racing_writers_wins(store, r).await;
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
/// Two racers were not enough — they serialised often enough that dropping the
/// arbitrating unique index went unnoticed. So this runs a **fan-out over
/// several keys**, which is both more likely to interleave and cheap.
///
/// Being explicit about what this can and cannot do: a race test corroborates,
/// it never proves. Passing means no interleaving *found* one; the constraint in
/// the schema is what makes the absence real. A store that serialises internally
/// — `SQLite` behind one connection — passes trivially and correctly, having no
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
    };
    if store.register_deadline(&deadline).await.is_err() {
        r.record("closure", "register_deadline failed");
        return;
    }
    if store.close(case).await.is_ok() {
        r.record(
            "closure",
            "a case with a pending obligation was closed. Closure is when people \
             stop looking, so an unmet deadline must survive it",
        );
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
}

async fn a_repeated_event_id_is_not_buffered_twice(store: &Arc<dyn EventStore>, r: &mut Report) {
    r.checked += 1;
    let event = InboundEvent {
        id: "evt-dup".into(),
        kind: "ack".into(),
        correlation: keys("E-1"),
        payload: serde_json::json!({}),
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
        id: "evt-claim".into(),
        kind: "ack".into(),
        correlation: keys("E-2"),
        payload: serde_json::json!({}),
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
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = InboundEvent {
        id: "evt-match".into(),
        kind: "ack".into(),
        correlation: keys("E-3"),
        payload: serde_json::json!({}),
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

// ── Timers ──────────────────────────────────────────────────────────────────

/// Check a [`TimerStore`].
pub async fn check_timers(store: &Arc<dyn TimerStore>, r: &mut Report) {
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

// ── Tasks ───────────────────────────────────────────────────────────────────

/// Check a [`TaskStore`].
pub async fn check_tasks(store: &Arc<dyn TaskStore>, r: &mut Report) {
    a_task_is_claimed_by_one_actor_only(store, r).await;
    an_excluded_actor_cannot_claim(store, r).await;
    ineligibility_outranks_contention(store, r).await;
    only_the_holder_releases(store, r).await;
}

fn task(id: u8, excluded: Option<&str>) -> Task {
    let run = RunId::generate();
    Task {
        id: TaskId::derive(run, effect(id)),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new("needs a person", serde_json::json!({})),
        candidate_roles: vec!["ops".into()],
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        excluded_actors: excluded.map(|a| vec![a.to_owned()]).unwrap_or_default(),
        created_at: ts(1_000),
        due_at: None,
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
/// somebody with no standing in that queue.
///
/// Both backends got this wrong, and it was found by writing an HTTP handler
/// that had to choose a status code: `403` and `409` ask different things of
/// the person reading them.
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
}
