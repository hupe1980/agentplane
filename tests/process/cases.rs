//! Cases, correlation, and deadlines.
//!
//! A run is one goal, one lifetime. A business process is not: it spans days,
//! many inbound messages, and several runs — and something has to know they all
//! belong together, and what is owed by when.

// Tests sit outside the deterministic zone: they drive the runtime rather than
// run inside it, so reading a clock here is the harness establishing "now",
// not a step smuggling non-determinism past the journal.
#![allow(clippy::disallowed_methods)]
// These exercise the runtime end to end, which needs a store. Gated so
// `--no-default-features` still builds and tests cleanly: an embedder who
// brings their own backend must not be forced to compile SQLite.
#![cfg(feature = "sqlite")]

use std::sync::Arc;

use agentplane::case::{CaseStore, Correlation};
use agentplane::core::{
    Calendar, CalendarError, CaseStatus, CorrelationKey, DeadlineSpec, DeadlineState, Digest,
    Outcome, Skill, SkillDescriptor, Tainted, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

// ── Fixtures ────────────────────────────────────────────────────────────────

fn key(ns: &str, v: &str) -> CorrelationKey {
    CorrelationKey::new(ns, v)
}

/// Registers an obligation and optionally satisfies it.
#[derive(Debug)]
struct Obliges {
    name: &'static str,
    spec: DeadlineSpec,
    meet: bool,
}

#[async_trait::async_trait]
impl Skill for Obliges {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("obliges").provides("demo.obliges")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let d = cx
            .deadline(self.name, &self.spec, Some(time::Duration::hours(1)))
            .await?;
        cx.note(format!("obligation due {}", d.resolved_at)).await?;
        if self.meet {
            cx.meet_deadline(self.name).await?;
        }
        Ok(Outcome::done(input))
    }
}

/// Writes to case state so a later run can read it.
#[derive(Debug)]
struct Accumulates;

#[async_trait::async_trait]
impl Skill for Accumulates {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("accumulates").provides("demo.accumulate")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        let (existing, at) = cx.case_state().await?;
        let mut seen: Vec<Value> = existing.peek().as_array().cloned().unwrap_or_default();
        seen.push(input.peek().clone());
        cx.put_case_state(at, Value::Array(seen.clone())).await?;
        Ok(Outcome::done(Tainted::trusted(
            json!({ "seen": seen.len() }),
        )))
    }
}

/// A calendar that only knows one rule, to prove the seam works and that
/// unknown rules are refused rather than approximated.
#[derive(Debug)]
struct WorkingDays;

impl Calendar for WorkingDays {
    fn resolve(&self, from: Timestamp, spec: &DeadlineSpec) -> Result<Timestamp, CalendarError> {
        if spec.kind != "working-days" {
            return Err(CalendarError::UnknownKind(spec.kind.clone()));
        }
        let n = spec
            .params
            .get("n")
            .and_then(Value::as_i64)
            .ok_or_else(|| CalendarError::BadParams {
                kind: spec.kind.clone(),
                detail: "expected `n`".into(),
            })?;
        // Deliberately simplistic: the point is that the *adapter* owns this.
        let mut at = from;
        let mut left = n;
        while left > 0 {
            at += time::Duration::days(1);
            if !matches!(
                at.weekday(),
                time::Weekday::Saturday | time::Weekday::Sunday
            ) {
                left -= 1;
            }
        }
        Ok(at)
    }

    fn digest(&self) -> Digest {
        Digest::of(b"test.calendar.working-days.v1")
    }
}

/// A "corrected" calendar that resolves the same rule to a wildly different
/// instant, standing in for a rule change between the original run and a replay.
#[derive(Debug)]
struct Corrected;

impl Calendar for Corrected {
    fn resolve(&self, from: Timestamp, _s: &DeadlineSpec) -> Result<Timestamp, CalendarError> {
        Ok(from + time::Duration::days(999))
    }
    fn digest(&self) -> Digest {
        Digest::of(b"test.calendar.corrected")
    }
}

fn runtime_with_cases(store: &Arc<SqliteStore>) -> Runtime {
    Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Accumulates)
        .build()
}

// ── Correlation ─────────────────────────────────────────────────────────────

/// Two messages carrying the same business key land in **one** case.
///
/// This is the property that makes a multi-day process trackable: an
/// acknowledgement arriving nineteen hours later must join the matter it
/// belongs to, not start a parallel one.
#[tokio::test]
async fn messages_sharing_a_key_join_one_case() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "DOC-4711")];

    let first = rt
        .run_in_case("accumulates", json!("request"), "supplier-switch", &keys)
        .await
        .unwrap();
    let second = rt
        .run_in_case(
            "accumulates",
            json!("acknowledgement"),
            "supplier-switch",
            &keys,
        )
        .await
        .unwrap();

    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(
        second.output,
        Some(json!({ "seen": 2 })),
        "state carried across runs"
    );

    let case_id = store.correlate(&keys).await.unwrap().expect("case exists");
    let case = store.case(case_id).await.unwrap().unwrap();
    assert_eq!(case.runs.len(), 2, "both runs attached to one case");
    assert_eq!(case.kind, "supplier-switch");
}

/// Correlation is recorded in the journal, so which case a run belongs to is
/// part of the tamper-evident history rather than a mutable side table.
#[tokio::test]
async fn the_case_binding_is_journaled() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);

    let out = rt
        .run_in_case("accumulates", json!(1), "matter", &[key("meter", "M-1")])
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let bound = records.iter().find_map(|r| match r.kind() {
        RecordKind::CaseBound { case_kind, opened } => {
            Some((r.body.case, case_kind.clone(), *opened))
        }
        _ => None,
    });
    let (case, kind, opened) = bound.expect("CaseBound must be journaled");
    assert_eq!(kind, "matter");
    assert!(opened, "the first message opens the case");
    assert!(case.is_some(), "the case id rides on the record body");

    // Every record of a case-bound run carries the case, so the matter's whole
    // history is one indexed range scan rather than a join.
    // The length check is not decoration: `all` passes on an empty slice, and
    // an assertion that holds for want of anything to check is not an assertion.
    assert!(records.len() > 3, "there is a history to check");
    assert!(
        records.iter().all(|r| r.body.case == case),
        "all records in a case-bound run must carry the case id"
    );
}

/// Different keys are different matters.
#[tokio::test]
async fn unrelated_keys_do_not_collide() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);

    rt.run_in_case("accumulates", json!(1), "m", &[key("document", "A")])
        .await
        .unwrap();
    rt.run_in_case("accumulates", json!(1), "m", &[key("document", "B")])
        .await
        .unwrap();

    let a = store
        .correlate(&[key("document", "A")])
        .await
        .unwrap()
        .unwrap();
    let b = store
        .correlate(&[key("document", "B")])
        .await
        .unwrap()
        .unwrap();
    assert_ne!(a, b);
}

/// A closed case releases its keys, so a genuinely new matter about the same
/// entity opens a fresh case rather than reanimating a concluded one.
#[tokio::test]
async fn closing_a_case_releases_its_correlation_keys() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let keys = [key("meter", "M-9")];

    let first = store
        .correlate_or_open("m", &keys, Timestamp::now_utc())
        .await
        .unwrap();
    store.close(first.case_id()).await.unwrap();

    let second = store
        .correlate_or_open("m", &keys, Timestamp::now_utc())
        .await
        .unwrap();

    assert!(matches!(second, Correlation::Opened(_)));
    assert_ne!(second.case_id(), first.case_id());
}

/// Correlating against no keys never invents a case.
#[tokio::test]
async fn empty_keys_correlate_to_nothing() {
    let store = SqliteStore::open_in_memory().unwrap();
    assert_eq!(store.correlate(&[]).await.unwrap(), None);
}

// ── Deadlines ───────────────────────────────────────────────────────────────

/// The resolved instant is journaled — not the rule that produced it.
///
/// Calendars change. Recomputing on replay would silently move a legally
/// binding instant under an audit, so the instant is a recorded fact and the
/// calendar digest beside it says which ruleset produced it.
#[tokio::test]
async fn the_resolved_instant_is_journaled_with_its_calendar() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .calendar(Arc::new(WorkingDays))
        .skill(Obliges {
            name: "acknowledgement",
            spec: DeadlineSpec::new("working-days", json!({ "n": 5 })),
            meet: false,
        })
        .build();

    let out = rt
        .run_in_case("obliges", json!({}), "matter", &[key("document", "D-1")])
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);

    let records = store.read(out.run_id, 1).await.unwrap();
    let registered = records.iter().find_map(|r| match r.kind() {
        RecordKind::DeadlineRegistered {
            name,
            resolved_at,
            calendar_digest,
        } => Some((name.clone(), *resolved_at, *calendar_digest)),
        _ => None,
    });
    let (name, at, digest) = registered.expect("the obligation must be journaled");
    assert_eq!(name, "acknowledgement");
    assert_eq!(
        digest,
        WorkingDays.digest(),
        "the ruleset is identified on the record"
    );

    let case_id = store
        .correlate(&[key("document", "D-1")])
        .await
        .unwrap()
        .unwrap();
    let stored = store.deadlines(case_id).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].resolved_at, at, "store and journal agree");
}

/// Replay reads the recorded instant back rather than asking the calendar again.
///
/// The test swaps in a calendar that would answer differently; replay must not
/// notice, because it never asks.
#[tokio::test]
async fn replay_does_not_recompute_a_deadline() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let spec = DeadlineSpec::new("working-days", json!({ "n": 5 }));

    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .calendar(Arc::new(WorkingDays))
        .skill(Obliges {
            name: "ack",
            spec: spec.clone(),
            meet: false,
        })
        .build();

    let out = rt
        .run_in_case("obliges", json!({}), "matter", &[key("document", "D-2")])
        .await
        .unwrap();

    let case_id = store
        .correlate(&[key("document", "D-2")])
        .await
        .unwrap()
        .unwrap();
    let original = store.deadlines(case_id).await.unwrap()[0].resolved_at;

    let with_new_calendar = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .calendar(Arc::new(Corrected))
        .skill(Obliges {
            name: "ack",
            spec,
            meet: false,
        })
        .build();

    let replayed = with_new_calendar
        .replay(out.run_id, Mode::Strict)
        .await
        .unwrap();
    assert_eq!(replayed.status, RunStatus::Succeeded);

    let after = store.deadlines(case_id).await.unwrap()[0].resolved_at;
    assert_eq!(
        after, original,
        "a corrected calendar must not retroactively move a registered obligation"
    );
}

/// A case with an unmet obligation cannot be closed.
///
/// This is the check that stops a missed regulatory window from disappearing
/// behind a tidy "closed" status.
#[tokio::test]
async fn a_case_with_an_open_obligation_refuses_to_close() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Obliges {
            name: "ack",
            spec: DeadlineSpec::hours(24),
            meet: false,
        })
        .build();

    rt.run_in_case("obliges", json!({}), "matter", &[key("document", "D-3")])
        .await
        .unwrap();

    let case_id = store
        .correlate(&[key("document", "D-3")])
        .await
        .unwrap()
        .unwrap();
    let err = store.close(case_id).await.unwrap_err();
    assert!(
        err.to_string().contains("open deadline"),
        "closing must name the obligation that blocks it, got: {err}"
    );
}

/// Satisfying the obligation unblocks closing, and the transition is journaled.
#[tokio::test]
async fn meeting_an_obligation_permits_closing_and_is_journaled() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Obliges {
            name: "ack",
            spec: DeadlineSpec::hours(24),
            meet: true,
        })
        .build();

    let out = rt
        .run_in_case("obliges", json!({}), "matter", &[key("document", "D-4")])
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let transitioned = records.iter().any(|r| {
        matches!(
            r.kind(),
            RecordKind::DeadlineTransition {
                to: DeadlineState::Met,
                ..
            }
        )
    });
    assert!(transitioned, "the transition must be part of the history");

    let case_id = store
        .correlate(&[key("document", "D-4")])
        .await
        .unwrap()
        .unwrap();
    store
        .close(case_id)
        .await
        .expect("closing is now permitted");
    assert_eq!(
        store.case(case_id).await.unwrap().unwrap().status,
        CaseStatus::Closed
    );
}

/// The sweep finds obligations that are due or approaching.
///
/// Without it a deadline is a stored number nobody reads.
#[tokio::test]
async fn the_sweep_surfaces_due_and_approaching_obligations() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let now = Timestamp::now_utc();

    let case = store
        .correlate_or_open("m", &[key("document", "D-5")], now)
        .await
        .unwrap()
        .case_id();

    let overdue = agentplane::core::Deadline {
        case,
        name: "overdue".into(),
        resolved_at: now - time::Duration::hours(1),
        calendar_digest: Digest::of(b"c"),
        warn_at: None,
        state: DeadlineState::Pending,
    };
    let future = agentplane::core::Deadline {
        case,
        name: "distant".into(),
        resolved_at: now + time::Duration::days(30),
        calendar_digest: Digest::of(b"c"),
        warn_at: None,
        state: DeadlineState::Pending,
    };
    store.register_deadline(&overdue).await.unwrap();
    store.register_deadline(&future).await.unwrap();

    let due = store.due(now, 100).await.unwrap();
    assert_eq!(due.len(), 1, "only the overdue obligation is due");
    assert_eq!(due[0].name, "overdue");
    assert!(due[0].is_due(now));

    // A satisfied obligation drops out of the sweep.
    store
        .set_deadline_state(case, "overdue", DeadlineState::Met)
        .await
        .unwrap();
    assert!(store.due(now, 100).await.unwrap().is_empty());
}

/// A run admitted with correlation keys against a runtime with no case store is
/// refused at admission rather than running half-configured.
#[tokio::test]
async fn correlation_without_a_case_store_is_refused() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Accumulates)
        .build();

    let err = rt
        .run_in_case("accumulates", json!(1), "m", &[key("document", "X")])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("case store"), "got: {err}");
}

/// Case state survives a resumed run, and the resume does not double-append it.
#[tokio::test]
async fn case_state_survives_resume() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-6")];

    let out = rt
        .run_in_case("accumulates", json!("first"), "m", &keys)
        .await
        .unwrap();
    let resumed = rt.replay(out.run_id, Mode::Resume).await.unwrap();
    assert_eq!(resumed.status, RunStatus::Succeeded);

    let case_id = store.correlate(&keys).await.unwrap().unwrap();
    let case = store.case(case_id).await.unwrap().unwrap();
    assert_eq!(
        case.state,
        json!(["first"]),
        "resume must not append the same work twice"
    );
}

// ── Case state across replay ────────────────────────────────────────────────

/// Does a strict replay re-execute a case-state read against *live* storage?
///
/// The determinism claim is that every non-deterministic input is journaled and
/// read back. Case state is mutable storage shared by every run on the case, so
/// a read of it is a non-deterministic input by that definition.
#[tokio::test]
async fn a_strict_replay_reads_case_state_from_the_journal_not_the_store() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-REPLAY")];

    let out = rt
        .run_in_case("accumulates", json!("first"), "m", &keys)
        .await
        .unwrap();
    assert_eq!(out.output.as_ref().unwrap()["seen"], json!(1));

    // Somebody else moves the case on: another run, an operator, a repair.
    let case_id = store.correlate(&keys).await.unwrap().unwrap();
    let at = store.case(case_id).await.unwrap().unwrap().version;
    store
        .put_state(case_id, at, json!(["first", "second", "third"]))
        .await
        .unwrap();

    let replayed = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(
        replayed.output.as_ref().unwrap()["seen"],
        json!(1),
        "the replayed run saw a different case state than the live run did, so \
         the run's own logic reached a different answer from the same journal"
    );
}

/// A strict replay must not write to the world, and the case store is world.
#[tokio::test]
async fn a_strict_replay_does_not_rewrite_case_state() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-NOWRITE")];

    let out = rt
        .run_in_case("accumulates", json!("first"), "m", &keys)
        .await
        .unwrap();

    let case_id = store.correlate(&keys).await.unwrap().unwrap();
    let at = store.case(case_id).await.unwrap().unwrap().version;
    store
        .put_state(case_id, at, json!(["untouched"]))
        .await
        .unwrap();

    rt.replay(out.run_id, Mode::Strict).await.unwrap();

    let case = store.case(case_id).await.unwrap().unwrap();
    assert_eq!(
        case.state,
        json!(["untouched"]),
        "a strict replay wrote to the case store — replay must perform nothing"
    );
}

// ── Concurrent writers on one case ──────────────────────────────────────────
//
// A run is owned — the fencing lease means one writer appends to its journal.
// A case is the opposite by construction: it is what several runs share, and the
// window between reading its state and writing it back contains a model call,
// which is unbounded. Two runs on one case overlap as a matter of course.

/// The lost update, refused.
///
/// Without the version this is silent: the second write wins, the first run's
/// work vanishes, and nothing in the record shows it happened.
#[tokio::test]
async fn a_write_against_a_stale_read_is_refused() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let case = store
        .correlate_or_open("m", &[key("document", "D-CAS")], Timestamp::now_utc())
        .await
        .unwrap()
        .case_id();

    let at = store.case(case).await.unwrap().unwrap().version;

    // Run A reads at `at`, then goes off to call a model.
    // Run B reads at `at` too, and gets there first.
    let after_b = store.put_state(case, at, json!({"by": "B"})).await.unwrap();
    assert_eq!(after_b, at.next());

    // Run A comes back and writes against the version it read.
    let err = store
        .put_state(case, at, json!({"by": "A"}))
        .await
        .expect_err("A's read is stale");

    match err {
        agentplane::core::StoreError::CaseConflict {
            expected, current, ..
        } => {
            assert_eq!(expected, at.0);
            assert_eq!(current, after_b.0);
        }
        other => panic!("a lost update must be refused, not absorbed: {other}"),
    }

    let case = store.case(case).await.unwrap().unwrap();
    assert_eq!(case.state, json!({"by": "B"}), "B's write must survive");
}

/// A missing case is `NotFound`, not a conflict.
///
/// Reporting it as a conflict sends the caller into a re-read loop against
/// something that will never exist.
#[tokio::test]
async fn a_write_to_a_missing_case_is_not_found() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    // A real id from another store, so it is well-formed but absent here.
    let elsewhere = Arc::new(SqliteStore::open_in_memory().unwrap());
    let missing = elsewhere
        .correlate_or_open("m", &[key("document", "D-ELSEWHERE")], Timestamp::now_utc())
        .await
        .unwrap()
        .case_id();

    let err = store
        .put_state(missing, agentplane::core::CaseVersion::INITIAL, json!({}))
        .await
        .expect_err("no such case");
    assert!(
        matches!(err, agentplane::core::StoreError::NotFound(_)),
        "got: {err}"
    );
}

/// Versions advance by one per write, so a reader can tell them apart.
#[tokio::test]
async fn each_write_advances_the_version() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let case = store
        .correlate_or_open("m", &[key("document", "D-SEQ")], Timestamp::now_utc())
        .await
        .unwrap()
        .case_id();

    let mut at = store.case(case).await.unwrap().unwrap().version;
    for i in 0..3 {
        at = store.put_state(case, at, json!(i)).await.unwrap();
    }
    assert_eq!(at, agentplane::core::CaseVersion(3));
    assert_eq!(store.case(case).await.unwrap().unwrap().version, at);
}

/// A run whose case moved under it is told, rather than overwriting.
#[tokio::test]
async fn a_step_whose_case_moved_under_it_is_refused() {
    #[derive(Debug)]
    struct WritesStale;

    #[async_trait::async_trait]
    impl Skill for WritesStale {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("stale").provides("demo.stale")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            let (_, at) = cx.case_state().await?;
            // Somebody else writes while this step is "thinking".
            cx.put_case_state(at, json!("mine")).await?;
            // Writing again against the *same* version is the mistake the
            // signature is shaped to prevent, and it must not succeed.
            cx.put_case_state(at, json!("mine again")).await?;
            Ok(Outcome::done(Tainted::trusted(json!("unreachable"))))
        }
    }

    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .skill(WritesStale)
        .build();

    let out = rt
        .run_in_case("stale", json!({}), "m", &[key("document", "D-STALE")])
        .await
        .unwrap();
    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "the second write reused a spent version and must be refused: {:?}",
        out.status
    );
}
