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
    a_cases_blob_list_holds_only_its_own(store, r).await;
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
/// Two racers were not enough — they serialised often enough that dropping the
/// arbitrating unique index went unnoticed. So this runs a **fan-out over
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
    a_claimed_event_is_never_retired(store, r).await;
    a_claimed_event_is_recoverable_by_its_own_run(store, r).await;
    a_satisfied_waiter_does_not_claim_a_second_event(store, r).await;
    a_zero_grace_sweep_retires_an_event_received_this_second(store, r).await;
    a_dead_letter_carries_the_keys_it_was_routed_on(store, r).await;
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
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "ack".into(),
        correlation: keys("E-TWO-EVENTS"),
        payload: serde_json::json!({}),
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
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = |id: &str| InboundEvent {
        source: "urn:conformance".to_owned(),
        id: id.into(),
        kind: "ack".into(),
        correlation: keys("E-ONESHOT"),
        payload: serde_json::json!({}),
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
    };
    let _ = store.subscribe(&sub, ts(1_000)).await;

    let event = InboundEvent {
        source: "urn:conformance".to_owned(),
        id: "evt-reclaim".into(),
        kind: "ack".into(),
        correlation: keys("E-RECLAIM"),
        payload: serde_json::json!({"n": 1}),
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
        source: "urn:conformance".to_owned(),
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
    the_backlog_counts_work_somebody_is_holding(store, r).await;
    a_take_over_names_its_holder_and_keeps_the_exclusions(store, r).await;
    an_expired_task_is_not_resurrected_by_a_claim(store, r).await;
    a_state_write_to_a_missing_task_is_not_found(store, r).await;
    escalation_widens_the_audience_and_frees_the_reservation(store, r).await;
    an_escalated_task_leaves_the_overdue_scan(store, r).await;
    a_decided_task_is_not_resurrected_by_escalation(store, r).await;
    a_role_name_is_stored_verbatim(store, r).await;
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
        Ok(()) => r.record(
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
/// coming back was parked until its deadline breached. `take_over` is the
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

fn task(id: u8, excluded: Option<&str>) -> Task {
    let run = RunId::generate();
    Task {
        id: TaskId::derive(run, effect(id)),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new("needs a person", serde_json::json!({})),
        candidate_roles: vec!["ops".into()],
        escalate_to: Vec::new(),
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        excluded_actors: excluded.map(|a| vec![a.to_owned()]).unwrap_or_default(),
        created_at: ts(1_000),
        due_at: None,
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

    check_batch_identity(store, id, r).await;
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
