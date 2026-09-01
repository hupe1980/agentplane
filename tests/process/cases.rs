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
#![cfg(feature = "redb")]

use std::sync::Arc;

use agentplane::case::{CaseStore, Correlation};
use agentplane::core::{
    Calendar, CalendarError, CaseStatus, CorrelationKey, DeadlineSpec, DeadlineState, Digest,
    Outcome, Skill, SkillDescriptor, Tainted, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
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
            .deadline(
                self.name,
                &self.spec,
                Some(std::time::Duration::from_secs(3600)),
            )
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
            at += std::time::Duration::from_secs(86_400);
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
        Ok(from + std::time::Duration::from_secs(86_313_600))
    }
    fn digest(&self) -> Digest {
        Digest::of(b"test.calendar.corrected")
    }
}

fn runtime_with_cases(store: &Arc<RedbStore>) -> Arc<Runtime> {
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "DOC-4711")];

    let first = rt
        .run_correlated(
            "accumulates",
            Tainted::trusted(json!("request")),
            "supplier-switch",
            &keys,
        )
        .await
        .unwrap();
    let second = rt
        .run_correlated(
            "accumulates",
            Tainted::trusted(json!("acknowledgement")),
            "supplier-switch",
            &keys,
        )
        .await
        .unwrap();

    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(
        second.output.map(|o| o.peek().clone()),
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);

    let out = rt
        .run_correlated(
            "accumulates",
            Tainted::trusted(json!(1)),
            "matter",
            &[key("meter", "M-1")],
        )
        .await
        .unwrap();

    let records = store.read(out.run_id, 1).await.unwrap();
    let bound = records.iter().find_map(|r| match r.kind() {
        RecordKind::CaseBound {
            case_kind,
            opened,
            correlation,
        } => Some((r.body.case, case_kind.clone(), *opened, correlation.clone())),
        _ => None,
    });
    let (case, kind, opened, correlation) = bound.expect("CaseBound must be journaled");
    assert_eq!(kind, "matter");
    assert!(opened, "the first message opens the case");
    assert!(case.is_some(), "the case id rides on the record body");
    // The business keys are on the record too, because a resumed run resolves
    // manifest bindings from history rather than from a case that has since
    // accumulated more keys.
    assert_eq!(
        correlation,
        vec![key("meter", "M-1")],
        "the binding records the keys this run's case was identified by"
    );

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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);

    rt.run_correlated(
        "accumulates",
        Tainted::trusted(json!(1)),
        "m",
        &[key("document", "A")],
    )
    .await
    .unwrap();
    rt.run_correlated(
        "accumulates",
        Tainted::trusted(json!(1)),
        "m",
        &[key("document", "B")],
    )
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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
    let store = RedbStore::open_in_memory().unwrap();
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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
        .run_correlated(
            "obliges",
            Tainted::trusted(json!({})),
            "matter",
            &[key("document", "D-1")],
        )
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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
        .run_correlated(
            "obliges",
            Tainted::trusted(json!({})),
            "matter",
            &[key("document", "D-2")],
        )
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Obliges {
            name: "ack",
            spec: DeadlineSpec::hours(24),
            meet: false,
        })
        .build();

    rt.run_correlated(
        "obliges",
        Tainted::trusted(json!({})),
        "matter",
        &[key("document", "D-3")],
    )
    .await
    .unwrap();

    let case_id = store
        .correlate(&[key("document", "D-3")])
        .await
        .unwrap()
        .unwrap();
    let err = store.close(case_id).await.unwrap_err();
    // The variant, not a substring: the refusal is a business rule, and a
    // `Backend` string here would make a store outage indistinguishable from
    // the rule firing.
    assert!(
        matches!(
            err,
            agentplane::core::StoreError::ObligationsOutstanding { outstanding: 1, .. }
        ),
        "closing must refuse as ObligationsOutstanding naming the count, got: {err}"
    );
}

/// Satisfying the obligation unblocks closing, and the transition is journaled.
#[tokio::test]
async fn meeting_an_obligation_permits_closing_and_is_journaled() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(Obliges {
            name: "ack",
            spec: DeadlineSpec::hours(24),
            meet: true,
        })
        .build();

    let out = rt
        .run_correlated(
            "obliges",
            Tainted::trusted(json!({})),
            "matter",
            &[key("document", "D-4")],
        )
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let now = Timestamp::now_utc();

    let case = store
        .correlate_or_open("m", &[key("document", "D-5")], now)
        .await
        .unwrap()
        .case_id();

    let overdue = agentplane::core::Deadline {
        case,
        name: "overdue".into(),
        resolved_at: now - std::time::Duration::from_secs(3600),
        calendar_digest: Digest::of(b"c"),
        warn_at: None,
        state: DeadlineState::Pending,
    };
    let future = agentplane::core::Deadline {
        case,
        name: "distant".into(),
        resolved_at: now + std::time::Duration::from_secs(2_592_000),
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Accumulates)
        .build();

    let err = rt
        .run_correlated(
            "accumulates",
            Tainted::trusted(json!(1)),
            "m",
            &[key("document", "X")],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("case store"), "got: {err}");
}

/// Case state survives a resumed run, and the resume does not double-append it.
#[tokio::test]
async fn case_state_survives_resume() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-6")];

    let out = rt
        .run_correlated("accumulates", Tainted::trusted(json!("first")), "m", &keys)
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-REPLAY")];

    let out = rt
        .run_correlated("accumulates", Tainted::trusted(json!("first")), "m", &keys)
        .await
        .unwrap();
    assert_eq!(out.output.as_ref().unwrap().peek()["seen"], json!(1));

    // Somebody else moves the case on: another run, an operator, a repair.
    let case_id = store.correlate(&keys).await.unwrap().unwrap();
    let at = store.case(case_id).await.unwrap().unwrap().version;
    store
        .put_state(case_id, at, json!(["first", "second", "third"]))
        .await
        .unwrap();

    let replayed = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(
        replayed.output.as_ref().unwrap().peek()["seen"],
        json!(1),
        "the replayed run saw a different case state than the live run did, so \
         the run's own logic reached a different answer from the same journal"
    );
}

/// A strict replay must not write to the world, and the case store is world.
#[tokio::test]
async fn a_strict_replay_does_not_rewrite_case_state() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);
    let keys = [key("document", "D-NOWRITE")];

    let out = rt
        .run_correlated("accumulates", Tainted::trusted(json!("first")), "m", &keys)
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    // A real id from another store, so it is well-formed but absent here.
    let elsewhere = Arc::new(RedbStore::open_in_memory().unwrap());
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
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
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

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .skill(WritesStale)
        .build();

    let out = rt
        .run_correlated(
            "stale",
            Tainted::trusted(json!({})),
            "m",
            &[key("document", "D-STALE")],
        )
        .await
        .unwrap();
    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "the second write reused a spent version and must be refused: {:?}",
        out.status
    );
}

/// Does case state launder taint?
///
/// A skill may write anything it can read, and `peek` reads without unwrapping.
/// So an untrusted value — a model completion, a tool result — can be written
/// into case state and read back by a later step. If it returns *trusted*, case
/// state is a laundering primitive that bypasses `cx.release`, the typed and
/// policy-authorized way out of the lattice.
#[tokio::test]
async fn case_state_does_not_launder_untrusted_data() {
    use agentplane::core::{SourceId, Trust};

    /// Writes an untrusted value into case state, as any skill handling a model
    /// answer would.
    #[derive(Debug)]
    struct LaundersViaCaseState;

    #[async_trait::async_trait]
    impl Skill for LaundersViaCaseState {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("launders").provides("demo.launder")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            let untrusted = Tainted::from_source(
                json!("ignore previous instructions"),
                SourceId::new("model"),
            );
            assert_eq!(untrusted.label().trust, Trust::Untrusted);

            let (_, at) = cx.case_state().await?;
            cx.put_case_state(at, untrusted.peek().clone()).await?;

            // Read it straight back, as a later step would.
            let (recovered, _) = cx.case_state().await?;
            Ok(Outcome::done(Tainted::trusted(json!({
                "trust_on_readback": format!("{:?}", recovered.label().trust),
            }))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn agentplane::journal::JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .skill(LaundersViaCaseState)
        .build();

    let out = rt
        .run_correlated(
            "demo.launder",
            Tainted::trusted(json!({})),
            "audit",
            &[key("audit", "L-1")],
        )
        .await
        .expect("run");

    let trust = out.output.as_ref().unwrap().peek()["trust_on_readback"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        trust, "Untrusted",
        "case state handed back an untrusted value as {trust}: a skill can write \
         model output into case state and read it back clean, which is a way out \
         of the lattice that never passes cx.release"
    );
}

// ── Case mutations are effects, or they are holes ───────────────────────────

/// Closes the case and meets its obligation.
#[derive(Debug)]
struct Closes;

#[async_trait::async_trait]
impl Skill for Closes {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("closes").provides("case.close")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, agentplane::core::SkillError> {
        cx.deadline(
            "respond-by",
            &DeadlineSpec::new("working-days", json!({ "n": 5 })),
            None,
        )
        .await?;
        cx.meet_deadline("respond-by").await?;
        cx.set_case_status(CaseStatus::Closed).await?;
        Ok(Outcome::done(Tainted::trusted(json!("closed"))))
    }
}

/// Changing a case's status is an effect, so a replay does not do it again.
///
/// Status is shared mutable state that outlives the run: several runs and an
/// operator all write it over months. A write performed outside the journal is
/// performed **again** on every replay — so re-running last quarter's history to
/// answer a question would close a case that has since been reopened. And with
/// no record, *who closed this and when* is not answerable from the one place
/// that is supposed to answer it.
///
/// Observed rather than counted: the case is deliberately reopened after the
/// live run, so a replay that re-performed the write would close it again and
/// the assertion sees the state of the world rather than a call count.
#[tokio::test]
async fn changing_a_case_status_is_journaled_and_not_repeated_on_replay() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .calendar(Arc::new(WorkingDays) as Arc<dyn Calendar>)
        .skill(Closes)
        .build();

    let out = rt
        .run_correlated(
            "case.close",
            Tainted::trusted(json!({})),
            "matter",
            &[key("matter", "M-9")],
        )
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded, "got {:?}", out.status);

    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    // The case id comes from the journal, not from `correlate`: closing the case
    // released its correlation keys (that is the whole point — a new matter must
    // open a fresh case rather than reanimating a closed one), so a closed case
    // is deliberately no longer correlatable.
    let records = store.read(out.run_id, 1).await.unwrap();
    let case = records
        .iter()
        .find_map(|r| r.body.case)
        .expect("the run was correlated to a case");
    assert!(
        cases
            .correlate(&[key("matter", "M-9")])
            .await
            .unwrap()
            .is_none(),
        "a closed case must not stay correlatable, or a new matter joins it"
    );
    assert_eq!(
        cases.case(case).await.unwrap().expect("case").status,
        CaseStatus::Closed
    );

    // Both mutations must be on the record: an unjournaled change to shared
    // state is a change nobody can attribute.
    let kinds: Vec<String> = records
        .iter()
        .map(|r| r.kind().kind_str().to_owned())
        .collect();
    assert!(
        kinds.iter().any(|k| k == "DeadlineTransition"),
        "the deadline transition was not journaled: {kinds:?}"
    );

    // The world moves on: an operator reopens the case.
    cases.set_status(case, CaseStatus::Open).await.unwrap();
    let deadline_before = cases
        .deadlines(case)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.name == "respond-by")
        .expect("the deadline exists")
        .state;
    cases
        .set_deadline_state(case, "respond-by", DeadlineState::Pending)
        .await
        .unwrap();
    assert_eq!(deadline_before, DeadlineState::Met);

    let replayed = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(replayed.status, RunStatus::Succeeded);

    assert_eq!(
        cases.case(case).await.unwrap().expect("case").status,
        CaseStatus::Open,
        "strict replay set the case status again — replaying history to answer a \
         question closed a case that had since been reopened"
    );
    assert_eq!(
        cases
            .deadlines(case)
            .await
            .unwrap()
            .into_iter()
            .find(|d| d.name == "respond-by")
            .expect("the deadline exists")
            .state,
        DeadlineState::Pending,
        "strict replay transitioned the deadline again"
    );
}

/// A capped sweep says it was capped.
///
/// A bounded query returns a list shaped exactly like a complete one. Without a
/// signal, the tick that handled its cap and the tick that handled everything
/// produce identical-looking reports — and they are the two states an operator
/// most needs to tell apart, because the first means the backlog is growing
/// while the numbers look ordinary.
#[tokio::test]
async fn a_sweep_that_hits_its_cap_says_so() {
    use agentplane::core::{Deadline, DeadlineState};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    // One more than the sweep will take in a tick.
    for i in 0..=512 {
        let case = cases
            .correlate_or_open("matter", &[key("matter", &format!("M-{i}"))], now)
            .await
            .unwrap()
            .case_id();
        cases
            .register_deadline(&Deadline {
                case,
                name: "respond-by".to_owned(),
                resolved_at: now - std::time::Duration::from_secs(3600),
                calendar_digest: Digest::of(b"test-calendar"),
                warn_at: None,
                state: DeadlineState::Pending,
            })
            .await
            .unwrap();
    }

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();

    let report = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert!(
        report.saturated.deadlines,
        "the sweep took its full batch and reported an ordinary tick — the \
         backlog grows while the numbers look normal: {report:?}"
    );
    assert!(
        report.needs_attention(),
        "a saturated sweep is exactly when a human should look"
    );
    assert!(!report.is_quiet(), "a capped sweep is not a quiet one");

    // And an ordinary tick is not falsely flagged, so the signal means something.
    let after = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert!(
        !after.saturated.deadlines,
        "the remaining handful still reported saturation: {after:?}"
    );
}

/// What the sweeper did is on the record, not only in a log.
///
/// The sweeper makes the plane's most consequential *automated* decisions —
/// it breaches an obligation and escalates a case, and nothing asked it to.
/// There is no run whose history explains the change, so without a record of
/// its own, *why is this case escalated* is answerable only from the resulting
/// state. State cannot distinguish "the sweep breached this at 02:00" from
/// "somebody set it", and no human was present to remember which.
#[tokio::test]
async fn a_sweep_records_what_it_did_in_a_sealed_run() {
    use agentplane::core::{Deadline, DeadlineState, SweptAction};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let case = cases
        .correlate_or_open("matter", &[key("matter", "M-77")], now)
        .await
        .unwrap()
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
        })
        .await
        .unwrap();

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();

    let report = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert_eq!(report.breached, 1);

    let run = report
        .record
        .expect("a sweep that breached an obligation left no record of doing so");

    let records = store.read(run, 1).await.unwrap();
    let swept: Vec<(String, SweptAction)> = records
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::Swept {
                subject, action, ..
            } => Some((subject.clone(), *action)),
            _ => None,
        })
        .collect();

    assert!(
        swept.contains(&(case.to_string(), SweptAction::DeadlineBreached)),
        "the breach was not recorded against the case: {swept:?}"
    );
    assert!(
        swept.contains(&(case.to_string(), SweptAction::CaseEscalated)),
        "the escalation was not recorded: {swept:?}"
    );

    // Sealed, so it enters the Merkle log and the external audit tool checks it
    // without being taught what a sweep is.
    store
        .verify(run)
        .await
        .expect("the sweep's own chain does not verify");
    assert!(
        records
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::RunConcluded { .. })),
        "the sweep's record was left open, so it never enters the Merkle log"
    );

    // A quiet tick writes nothing: a log of nothings is where the somethings
    // hide, and the Merkle log should not fill with evidence of inactivity.
    let quiet = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert!(
        quiet.record.is_none(),
        "a tick that decided nothing still opened a run"
    );
    assert!(
        !quiet.evidence_lost && !quiet.needs_attention(),
        "a quiet tick is not an incident"
    );
}

/// A sweep whose own evidence cannot be written says so.
///
/// The tick breaches an obligation — the state changes — and then its sealed
/// record fails to write. That must not read as a quiet tick: a decision with no
/// durable account of who made it is the exact I13 failure the sweep's own run
/// exists to prevent, so `evidence_lost` is set and `needs_attention` is true.
/// The bug this rules out is `seal` returning the same empty `record` for both
/// "nothing happened" and "something happened and its record did not".
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_sweep_whose_evidence_fails_to_write_is_flagged_not_silent() {
    use agentplane::core::{Deadline, DeadlineState};
    use agentplane::testkit::{Fault, Faulty, Schedule};

    let inner = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&inner) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let case = cases
        .correlate_or_open("matter", &[key("matter", "M-88")], now)
        .await
        .unwrap()
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
        })
        .await
        .unwrap();

    // The notes land and the breach is applied — but the sweep's own record
    // cannot be *closed*: the `RunConcluded` append fails, so the decisions sit
    // in an open run no checkpoint will ever commit to.
    let journal: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        Arc::clone(&inner) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("RunConcluded", Fault::FailedClean),
    ));
    let rt = Runtime::builder(journal).cases(Arc::clone(&cases)).build();

    let report = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert_eq!(report.breached, 1, "the breach must still have happened");
    assert!(
        report.record.is_none(),
        "no sealed run exists when its closure failed"
    );
    assert!(
        report.evidence_lost,
        "a sweep whose evidence write failed reported as a quiet tick"
    );
    assert!(
        report.needs_attention(),
        "a lost sweep record must demand attention"
    );
}

/// **A decision that cannot be recorded is not applied.**
///
/// I2, aimed at the sweeper itself: the note announcing a breach is durable
/// *before* the deadline state moves. The old order — apply, then buffer the
/// note for the tick's end — orphaned the decision permanently on a crash in
/// between, because the transition is idempotent and the next tick found it
/// already applied and re-decided nothing. Written first, the failure mode
/// inverts: the obligation stays `Pending`, and the next tick breaches it
/// *with* its record.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_sweep_decision_that_cannot_be_recorded_is_not_applied() {
    use agentplane::core::{Deadline, DeadlineState};
    use agentplane::testkit::{Fault, Faulty, Schedule};

    let inner = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&inner) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let case = cases
        .correlate_or_open("matter", &[key("matter", "M-89")], now)
        .await
        .unwrap()
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
        })
        .await
        .unwrap();

    // The sweep's `Swept` note cannot be written, so the breach must not be.
    let journal: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        Arc::clone(&inner) as Arc<dyn JournalStore>,
        Schedule::healthy().on_kind("Swept", Fault::FailedClean),
    ));
    let rt = Runtime::builder(journal).cases(Arc::clone(&cases)).build();

    rt.sweep(now, std::time::Duration::from_mins(5))
        .await
        .expect_err("a decision whose record cannot be written fails the tick loudly");

    let standing = cases
        .deadlines(case)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.name == "respond-by")
        .expect("the obligation still exists");
    assert_eq!(
        standing.state,
        DeadlineState::Pending,
        "the breach was applied without its record — announce-before-act \
         inverted, and a crash here orphans the decision forever"
    );

    // The store heals — modelled as a plane over the un-faulted backend — and
    // the next tick breaches the obligation *with* its record.
    let healed = Runtime::builder(Arc::clone(&inner) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();
    let report = healed
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert_eq!(report.breached, 1);
    assert!(report.record.is_some(), "the breach carries its evidence");
}

/// Evidence already earned survives a later phase's error.
///
/// The deadline pass breaches an obligation *into state*, then the timer phase
/// fails. The sweep returns the error — but the breach's sealed record must
/// exist anyway, because the state already changed and a `?` past an unsealed
/// ledger would be the sweep silently dropping the account of decisions it
/// already applied. That is the exact failure the ledger exists to prevent,
/// reintroduced by control flow — and it is invisible to every test that only
/// exercises phases which succeed.
#[tokio::test]
async fn sweep_evidence_survives_a_later_phase_failure() {
    use agentplane::core::{Deadline, DeadlineState, RunId, StoreError, SweptAction, Timer};

    /// A timer store whose claim always fails, the way a partitioned backend's
    /// would.
    #[derive(Debug)]
    struct ClaimFails;

    #[async_trait::async_trait]
    impl agentplane::case::TimerStore for ClaimFails {
        fn tenant(&self) -> &str {
            agentplane::core::TenantId::DEFAULT
        }

        async fn arm(&self, _: &Timer) -> Result<(), StoreError> {
            Ok(())
        }
        async fn claim_due(&self, _: Timestamp, _: usize) -> Result<Vec<Timer>, StoreError> {
            Err(StoreError::Backend(
                "the timer backend is unreachable".into(),
            ))
        }
        async fn disarm(&self, _: RunId, _: agentplane::core::EffectKey) -> Result<(), StoreError> {
            Ok(())
        }
        async fn pending_count(&self) -> Result<u64, StoreError> {
            Ok(0)
        }
        async fn pending(&self, _: usize) -> Result<Vec<Timer>, StoreError> {
            Ok(Vec::new())
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let case = cases
        .correlate_or_open("matter", &[key("matter", "M-99")], now)
        .await
        .unwrap()
        .case_id();
    cases
        .register_deadline(&Deadline {
            case,
            name: "respond-by".to_owned(),
            resolved_at: now - std::time::Duration::from_secs(3600),
            calendar_digest: Digest::of(b"test-calendar"),
            warn_at: None,
            state: DeadlineState::Pending,
        })
        .await
        .unwrap();

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .timers(Arc::new(ClaimFails))
        .build();

    let err = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .expect_err("the timer phase's failure must reach the caller");
    assert!(
        err.to_string().contains("unreachable"),
        "the error is the phase's own: {err}"
    );

    // The state changed — the breach applied before the failing phase ran —
    // and its evidence is sealed in the journal despite the error.
    let swept = store.runs_by_outcome("swept", 10).await.unwrap();
    let run = *swept
        .first()
        .expect("the breach's evidence left with the error");
    let records = store.read(run, 1).await.unwrap();
    assert!(
        records.iter().any(|r| matches!(
            r.kind(),
            RecordKind::Swept {
                action: SweptAction::DeadlineBreached,
                ..
            }
        )),
        "the sealed sweep run does not carry the breach"
    );
    store
        .verify(run)
        .await
        .expect("the sweep's own chain does not verify");
}

/// A case's history includes what happened *to* it, not only what its runs did.
///
/// "Show me everything about this matter" is answered by a range scan over the
/// journal, not by listing the case's runs and reading each. The difference is
/// not only cost: a per-run walk **misses** every record written by a run the
/// case does not own — and a sweep is exactly that, since one tick may escalate
/// several cases and belongs to none of them.
///
/// So the record explaining *why this case is escalated* is reachable from the
/// case, which is the entire reason for writing it down.
#[tokio::test]
async fn a_case_s_history_includes_a_sweep_that_escalated_it() {
    use agentplane::core::{Deadline, DeadlineState, SweptAction};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let case = cases
        .correlate_or_open("matter", &[key("matter", "M-88")], now)
        .await
        .unwrap()
        .case_id();
    // A second matter, so the scan is shown to select rather than to return
    // everything it can find.
    let other = cases
        .correlate_or_open("matter", &[key("matter", "M-89")], now)
        .await
        .unwrap()
        .case_id();
    for c in [case, other] {
        cases
            .register_deadline(&Deadline {
                case: c,
                name: "respond-by".to_owned(),
                resolved_at: now - std::time::Duration::from_secs(3600),
                calendar_digest: Digest::of(b"test-calendar"),
                warn_at: None,
                state: DeadlineState::Pending,
            })
            .await
            .unwrap();
    }

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&cases))
        .build();
    let report = rt
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert_eq!(report.breached, 2);

    let history = store.case_history(case, 100).await.unwrap();
    assert!(
        !history.is_empty(),
        "the case has no history at all, so the scan is reading the wrong thing"
    );

    let escalations: Vec<SweptAction> = history
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::Swept { action, .. } => Some(*action),
            _ => None,
        })
        .collect();
    assert!(
        escalations.contains(&SweptAction::CaseEscalated),
        "the case's own history does not say why it was escalated: {escalations:?}"
    );

    // Every record belongs to *this* matter. A scan that returned the other
    // case's escalation would be a scan that answers the wrong question, and it
    // would pass the assertion above.
    for record in &history {
        assert_eq!(
            record.body.case,
            Some(case),
            "a record from another matter appeared in this case's history"
        );
    }
    assert_eq!(
        store.case_history(other, 100).await.unwrap().len(),
        history.len(),
        "the two matters should have symmetrical histories"
    );

    // The bound is visible rather than silent.
    assert_eq!(
        store.case_history(case, 1).await.unwrap().len(),
        1,
        "the limit was not applied"
    );
}

/// A quarantined run is findable by whoever has to deal with it.
///
/// The most serious conclusion this runtime reaches used to produce a run
/// status, an `error!` event and a counter — none of which can be queried, and
/// a run started with `spawn` returns before the status exists at all. Every
/// other backlog here is findable by whoever must clear it; this one was not,
/// and a finding nobody can find is one that never reached a human in a form
/// they could act on.
#[tokio::test]
async fn a_quarantined_run_can_be_found_afterwards() {
    /// Fails in a way that cannot be resolved: the outcome is unknown and the
    /// declared recovery forbids guessing.
    #[derive(Debug)]
    struct Undecidable;

    #[async_trait::async_trait]
    impl agentplane::core::Effect for Undecidable {
        type Output = Value;
        fn descriptor(&self) -> agentplane::core::EffectDescriptor {
            agentplane::core::EffectDescriptor::nullary("ledger.transfer")
        }
        fn retry(&self) -> agentplane::core::RetryPolicy {
            agentplane::core::RetryPolicy::never()
        }
        async fn perform(&self) -> Result<Value, agentplane::core::EffectError> {
            Err(agentplane::core::EffectError::Timeout {
                driver: "ledger".to_owned(),
                waited_ms: 30_000,
            })
        }
    }

    #[derive(Debug)]
    struct Transfers;

    #[async_trait::async_trait]
    impl Skill for Transfers {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("transfers").provides("ledger.transfer")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            cx.effect(Undecidable).await?;
            Ok(Outcome::done(Tainted::trusted(json!("done"))))
        }
    }

    #[derive(Debug)]
    struct Settles;

    #[async_trait::async_trait]
    impl Skill for Settles {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("settles").provides("ledger.settle")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            Ok(Outcome::done(Tainted::trusted(json!("settled"))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Transfers)
        .skill(Settles)
        .build();

    let out = rt
        .run("ledger.transfer", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(out.status, RunStatus::Quarantined(_)),
        "expected a quarantine, got {:?}",
        out.status
    );

    // A genuinely-succeeding run, so the selectivity check below has a real
    // succeeded run to place — not the same skill again, which also quarantines.
    let ok = rt
        .run("ledger.settle", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(ok.status, RunStatus::Succeeded),
        "expected a success, got {:?}",
        ok.status
    );

    // The outcome index is *selective*, and both directions are asserted against
    // queries taken after both runs exist — an earlier snapshot could not have
    // contained the later run's id, so the property looked pinned while nothing
    // was checked.
    let quarantined = store.runs_by_outcome("quarantined", 50).await.unwrap();
    let succeeded = store.runs_by_outcome("succeeded", 50).await.unwrap();
    assert!(
        quarantined.contains(&out.run_id),
        "the quarantined run is not findable, so the only trace of the most \
         serious thing this runtime concluded is a log line: {quarantined:?}"
    );
    assert!(
        !quarantined.contains(&ok.run_id),
        "a succeeded run appeared under `quarantined`: {quarantined:?}"
    );
    assert!(
        succeeded.contains(&ok.run_id),
        "the succeeded run is not findable under its own outcome: {succeeded:?}"
    );
    assert!(
        !succeeded.contains(&out.run_id),
        "a quarantined run appeared under `succeeded`: {succeeded:?}"
    );
}

/// `case_of` answers from the journal, which is where the binding lives.
///
/// The first question an operator surface asks. It reads the run's own records
/// rather than a column beside them, so it cannot disagree with the history it
/// describes — and a run in no case is `None` rather than an error, because
/// that is an honest answer and not a fault.
#[tokio::test]
async fn case_of_reads_the_binding_off_the_run() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = runtime_with_cases(&store);

    let correlated = rt
        .run_correlated(
            "accumulates",
            Tainted::trusted(json!("request")),
            "supplier-switch",
            &[key("document", "DOC-9")],
        )
        .await
        .unwrap();
    let case = rt
        .case_of(correlated.run_id)
        .await
        .expect("readable")
        .expect("a correlated run belongs to a case");

    // The same answer the journal's own stamp gives, which is the point: this
    // is an accessor over the plan of record, not a second copy of it.
    let stamped = rt.journal().read(correlated.run_id, 1).await.unwrap()[0]
        .body
        .case
        .expect("the admission record carries the case");
    assert_eq!(case, stamped);

    // A run in no case is `None` rather than an error.
    let lone = rt
        .run("accumulates", Tainted::trusted(json!("alone")))
        .await
        .unwrap();
    assert_eq!(rt.case_of(lone.run_id).await.expect("readable"), None);
}

// ── Strict verification writes nothing to the case layer ────────────────────

/// A case store that counts obligation registrations, can be made to fail an
/// escalation, and delegates the rest.
#[derive(Debug)]
struct InstrumentedCases {
    inner: Arc<dyn CaseStore>,
    registered: Arc<std::sync::atomic::AtomicUsize>,
    /// Makes `set_status` fail, standing in for the process dying at that exact
    /// point in the sweep.
    escalation_fails: bool,
}

#[async_trait::async_trait]
impl CaseStore for InstrumentedCases {
    async fn correlate(
        &self,
        keys: &[CorrelationKey],
    ) -> Result<Option<agentplane::core::CaseId>, agentplane::core::StoreError> {
        self.inner.correlate(keys).await
    }
    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, agentplane::core::StoreError> {
        self.inner.correlate_or_open(kind, keys, at).await
    }
    async fn detach_run(
        &self,
        case: agentplane::core::CaseId,
        run: agentplane::RunId,
    ) -> Result<bool, agentplane::core::StoreError> {
        self.inner.detach_run(case, run).await
    }
    async fn case(
        &self,
        id: agentplane::core::CaseId,
    ) -> Result<Option<agentplane::core::Case>, agentplane::core::StoreError> {
        self.inner.case(id).await
    }
    async fn cases(
        &self,
        after: Option<agentplane::core::CaseId>,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Case>, agentplane::core::StoreError> {
        self.inner.cases(after, limit).await
    }
    async fn import_case(
        &self,
        case: &agentplane::core::Case,
        deadlines: &[agentplane::core::Deadline],
        blobs: &[Digest],
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.import_case(case, deadlines, blobs).await
    }
    async fn attach_run(
        &self,
        case: agentplane::core::CaseId,
        run: agentplane::core::RunId,
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.attach_run(case, run).await
    }
    async fn link_blob(
        &self,
        case: agentplane::core::CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.link_blob(case, digest, at).await
    }
    async fn blobs_of(
        &self,
        case: agentplane::core::CaseId,
    ) -> Result<Vec<Digest>, agentplane::core::StoreError> {
        self.inner.blobs_of(case).await
    }
    async fn put_state(
        &self,
        case: agentplane::core::CaseId,
        expected: agentplane::core::CaseVersion,
        state: Value,
    ) -> Result<agentplane::core::CaseVersion, agentplane::core::StoreError> {
        self.inner.put_state(case, expected, state).await
    }
    async fn set_status(
        &self,
        case: agentplane::core::CaseId,
        status: agentplane::core::CaseStatus,
    ) -> Result<(), agentplane::core::StoreError> {
        if self.escalation_fails {
            return Err(agentplane::core::StoreError::Backend(
                "instrumented failure".to_owned(),
            ));
        }
        self.inner.set_status(case, status).await
    }
    async fn close(
        &self,
        case: agentplane::core::CaseId,
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.close(case).await
    }
    async fn register_deadline(
        &self,
        deadline: &agentplane::core::Deadline,
    ) -> Result<(), agentplane::core::StoreError> {
        self.registered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.register_deadline(deadline).await
    }
    async fn deadlines(
        &self,
        case: agentplane::core::CaseId,
    ) -> Result<Vec<agentplane::core::Deadline>, agentplane::core::StoreError> {
        self.inner.deadlines(case).await
    }
    async fn set_deadline_state(
        &self,
        case: agentplane::core::CaseId,
        name: &str,
        state: agentplane::core::DeadlineState,
    ) -> Result<(), agentplane::core::StoreError> {
        self.inner.set_deadline_state(case, name, state).await
    }
    async fn breached(
        &self,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Deadline>, agentplane::core::StoreError> {
        self.inner.breached(limit).await
    }
    async fn due(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Deadline>, agentplane::core::StoreError> {
        self.inner.due(now, limit).await
    }
    async fn by_status(
        &self,
        status: agentplane::core::CaseStatus,
        limit: usize,
    ) -> Result<Vec<agentplane::core::Case>, agentplane::core::StoreError> {
        self.inner.by_status(status, limit).await
    }
    async fn census(
        &self,
        now: Timestamp,
    ) -> Result<agentplane::case::CaseCensus, agentplane::core::StoreError> {
        self.inner.census(now).await
    }
}

/// Strict replay does not re-register a run's obligations.
///
/// Verification is a pure read — `store_blob` and the memory paths already
/// honour that — but `deadline` re-registered unconditionally, so every
/// regression check of a recorded run wrote to the case layer it was supposed
/// to be observing. Idempotence hid most of it; what it could not hide is the
/// principle, and the day the registration is *not* idempotent against the
/// case's current state (a cancelled obligation, a migrated row), a
/// verification pass becomes the thing that re-arms it.
#[tokio::test]
async fn strict_replay_does_not_re_register_an_obligation() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let registered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cases: Arc<dyn CaseStore> = Arc::new(InstrumentedCases {
        inner: store.clone() as Arc<dyn CaseStore>,
        registered: Arc::clone(&registered),
        escalation_fails: false,
    });
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(cases)
        .skill(Obliges {
            name: "respond-by",
            spec: DeadlineSpec::days(5),
            meet: true,
        })
        .build();

    let out = rt
        .run_correlated(
            "obliges",
            Tainted::trusted(json!({})),
            "matter",
            &[key("document", "D-strict")],
        )
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(registered.load(std::sync::atomic::Ordering::SeqCst), 1);

    let replayed = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        registered.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "strict verification wrote to the case layer it was observing"
    );
}

// ── A breach survives the crash that interrupts it ──────────────────────────

/// A sweep interrupted between escalating and breaching leaves the obligation
/// outstanding, so the next tick makes the decision again.
///
/// `due` selects obligations that are still `pending` or `warned`, which makes
/// writing `Breached` the write that removes one from the only pass that looks
/// at it. Ordered the other way, a crash in the window between the two writes
/// is unrecoverable in the strict sense: the obligation is breached, the case
/// still says nothing happened, and no later tick will ever select it again —
/// the sweep would have spent its one chance to notice. Escalating twice is a
/// no-op, so the order that repeats work is the order that is safe.
///
/// The failure is injected at `set_status` rather than by killing a process
/// because that is the write the fix moved. Both halves are asserted: the
/// interrupted tick must leave the obligation outstanding, and a healthy tick
/// over the same fixture must actually breach it — a store that refused
/// everything would satisfy the first half alone.
#[tokio::test]
async fn a_sweep_interrupted_before_the_breach_leaves_the_obligation_outstanding() {
    use agentplane::core::{Deadline, DeadlineState};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let now = Timestamp::from_unix_timestamp(1_800_000_000).unwrap();

    let open = |cases: &Arc<dyn CaseStore>| {
        let cases = Arc::clone(cases);
        async move {
            let case = cases
                .correlate_or_open("matter", &[key("matter", "M-91")], now)
                .await
                .unwrap()
                .case_id();
            cases
                .register_deadline(&Deadline {
                    case,
                    name: "respond-by".to_owned(),
                    resolved_at: now - std::time::Duration::from_secs(3600),
                    calendar_digest: Digest::of(b"test-calendar"),
                    warn_at: None,
                    state: DeadlineState::Pending,
                })
                .await
                .unwrap();
            case
        }
    };

    let plain = Arc::clone(&store) as Arc<dyn CaseStore>;
    let case = open(&plain).await;

    let crashing: Arc<dyn CaseStore> = Arc::new(InstrumentedCases {
        inner: Arc::clone(&store) as Arc<dyn CaseStore>,
        registered: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        escalation_fails: true,
    });
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&crashing))
        .build();
    let interrupted = rt.sweep(now, std::time::Duration::from_mins(5)).await;
    assert!(
        interrupted.is_err(),
        "the escalation failed, so the tick must not report success"
    );

    let state = plain.deadlines(case).await.unwrap()[0].state;
    assert_eq!(
        state,
        DeadlineState::Pending,
        "the obligation was written off before the escalation it pays for landed, \
         so it has left `due` and no tick will look at it again — the breach is \
         now findable only by somebody who already knows to open this case"
    );
    assert!(
        plain
            .due(now, 16)
            .await
            .unwrap()
            .iter()
            .any(|d| d.case == case),
        "the interrupted obligation is no longer outstanding, so the sweep has \
         spent its one chance to notice it"
    );
    assert!(
        plain.breached(16).await.unwrap().is_empty(),
        "nothing was breached: the tick failed before it earned the right to say so"
    );

    // The positive half. The same fixture, a store that answers, and the
    // decision lands — so the assertions above are about the interruption and
    // not about a plane that cannot breach anything at all.
    let healthy = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&plain))
        .build();
    let report = healthy
        .sweep(now, std::time::Duration::from_mins(5))
        .await
        .unwrap();
    assert_eq!(report.breached, 1);
    assert_eq!(
        plain.deadlines(case).await.unwrap()[0].state,
        DeadlineState::Breached
    );
    let listed = plain.breached(16).await.unwrap();
    assert!(
        listed
            .iter()
            .any(|d| d.case == case && d.name == "respond-by"),
        "the breach is not listable, so it reaches whoever must answer for it \
         only if they already suspected it: {listed:?}"
    );
}
