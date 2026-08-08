//! Feature *interactions* — the pairs that share machinery.
//!
//! Every test here covers a combination the coverage matrix in
//! `tests/layering.rs` flagged as unexercised. That matrix exists because a
//! feature can break an invariant an older feature already proved: replanning
//! shipped with its own gates tested and made the saga compensate work that
//! never ran, because no test combined a replan with an unwind.
//!
//! A guard that an invariant is checked *somewhere* is not a guard that it is
//! checked *everywhere it now applies*, and adding a feature silently widens
//! where it applies.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]
use agentplane::case::TimerStore;
use agentplane::core::{
    ArgSource, Budget, Capability, Compensation, Outcome, PlanIR, PlanNode, Skill, SkillDescriptor,
    SkillError, StepId, Tainted, Timestamp,
};
use agentplane::journal::JournalStore;
use agentplane::plan::{ReplanError, Replanner};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Log = Arc<Mutex<Vec<String>>>;
fn log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}
fn entries(l: &Log) -> Vec<String> {
    l.lock().unwrap().clone()
}
fn later(s: i64) -> Timestamp {
    Timestamp::now_utc()
        .checked_add(time::Duration::seconds(s))
        .unwrap()
}

// ── saga x timers: a compensation that sleeps ──────────────────────────────

#[derive(Debug)]
struct SleepsToUndo(Log);

#[async_trait::async_trait]
impl Skill for SleepsToUndo {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("a").provides("a")
    }
    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }
    async fn invoke(
        &self,
        _c: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.lock().unwrap().push("do:a".into());
        Ok(Outcome::done(Tainted::trusted(json!({"s":"a"}))))
    }
    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _o: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        // A settlement window before the reversal is allowed to go out.
        self.0.lock().unwrap().push("undo:a:waiting".into());
        cx.sleep(Duration::from_mins(1)).await?;
        self.0.lock().unwrap().push("undo:a".into());
        Ok(())
    }
}

#[derive(Debug)]
struct Boom(Log);
#[async_trait::async_trait]
impl Skill for Boom {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("b").provides("b")
    }
    async fn invoke(
        &self,
        _c: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.lock().unwrap().push("do:b".into());
        Ok(Outcome::fail("b refuses"))
    }
}

#[tokio::test]
async fn a_compensation_may_sleep_before_it_reverses() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("t")
        .timers(store.clone() as Arc<dyn TimerStore>)
        .skill(SleepsToUndo(Arc::clone(&l)))
        .skill(Boom(Arc::clone(&l)))
        .build();

    let p = PlanIR::new(vec![
        PlanNode::new(0, "a").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "b")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ]);

    let out = rt.run_plan(p, Tainted::trusted(json!({}))).await.unwrap();

    assert!(
        out.status.is_suspended(),
        "a compensation that sleeps suspends the run"
    );
    assert_eq!(
        rt.fire_timers(later(120)).await.unwrap(),
        1,
        "the compensation's own timer fires"
    );
    assert!(
        entries(&l).contains(&"undo:a".to_string()),
        "the unwind finishes after the sleep"
    );
}

// ── concurrency x replan ───────────────────────────────────────────────────

#[derive(Debug)]
struct Ok1(Log, &'static str);
#[async_trait::async_trait]
impl Skill for Ok1 {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.1).provides(self.1)
    }
    fn compensation(&self) -> Compensation {
        Compensation::Unnecessary
    }
    async fn invoke(
        &self,
        _c: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.lock().unwrap().push(format!("do:{}", self.1));
        Ok(Outcome::done(Tainted::trusted(json!({"s": self.1}))))
    }
}

#[derive(Debug)]
struct AsksR(Log);
#[async_trait::async_trait]
impl Skill for AsksR {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("r").provides("r")
    }
    async fn invoke(
        &self,
        _c: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.0.lock().unwrap().push("do:r".into());
        Ok(Outcome::Replan {
            reason: "reroute".into(),
        })
    }
}

#[derive(Debug)]
struct KeepsDone;
#[async_trait::async_trait]
impl Replanner for KeepsDone {
    async fn replan(
        &self,
        cur: &PlanIR,
        why: &str,
        done: &[(StepId, Capability)],
    ) -> Result<PlanIR, ReplanError> {
        // Keep every completed step exactly as it ran, and add a finisher.
        let mut nodes: Vec<PlanNode> = done
            .iter()
            .map(|(id, cap)| PlanNode::new(id.0, cap.clone()).arg("input", ArgSource::run_input()))
            .collect();
        let mut z = PlanNode::new(9, "z")
            .arg("input", ArgSource::run_input())
            .terminal();
        for (id, _) in done {
            z = z.arg(format!("d{}", id.0), ArgSource::node(*id));
        }
        nodes.push(z);
        Ok(cur.succeed_with(nodes, why))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replan_requested_beside_a_succeeding_sibling_keeps_its_work() {
    let l = log();
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .owner("t")
        .budget(Budget::default().replans(2))
        .replanner(Arc::new(KeepsDone))
        .skill(Ok1(Arc::clone(&l), "s"))
        .skill(AsksR(Arc::clone(&l)))
        .skill(Ok1(Arc::clone(&l), "z"))
        .build();

    // `s` and `r` are siblings: one succeeds, the other asks to replan.
    let p = PlanIR::new(vec![
        PlanNode::new(0, "s")
            .arg("input", ArgSource::run_input())
            .terminal(),
        PlanNode::new(1, "r")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ]);

    let out = rt.run_plan(p, Tainted::trusted(json!({}))).await.unwrap();
    assert_eq!(
        out.status,
        RunStatus::Succeeded,
        "the successor finishes the run"
    );
}

// ── retry x timers, and timers x waits: shared ordinal + suspension machinery ──

#[derive(Debug)]
struct Interleaves {
    log: Log,
    calls: Arc<Mutex<usize>>,
}

#[async_trait::async_trait]
impl Skill for Interleaves {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("i").provides("i")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        use agentplane::core::{Effect, EffectDescriptor, EffectError, Recovery, RetryPolicy};

        #[derive(Debug, Clone)]
        struct Flaky(Arc<Mutex<usize>>, Log);
        #[async_trait::async_trait]
        impl Effect for Flaky {
            type Output = Value;
            fn descriptor(&self) -> EffectDescriptor {
                EffectDescriptor::nullary("t.flaky")
            }
            fn mutates(&self) -> bool {
                false
            }
            fn recovery(&self) -> Recovery {
                Recovery::Retry
            }
            fn retry(&self) -> RetryPolicy {
                RetryPolicy::attempts(3)
                    .with_backoff(Duration::from_millis(1), Duration::from_millis(2))
            }
            async fn perform(&self) -> Result<Value, EffectError> {
                let mut n = self.0.lock().unwrap();
                *n += 1;
                self.1.lock().unwrap().push(format!("call#{n}"));
                if *n < 2 {
                    return Err(EffectError::Rejected("flaky".into()));
                }
                Ok(json!({"n": *n}))
            }
        }

        // sleep, then a retrying effect, then sleep again — three suspensions
        // and a retry sharing one step's ordinal space.
        cx.sleep(Duration::from_mins(1)).await?;
        self.log.lock().unwrap().push("after-sleep-1".into());
        cx.effect(Flaky(Arc::clone(&self.calls), Arc::clone(&self.log)))
            .await?;
        self.log.lock().unwrap().push("after-retry".into());
        cx.sleep(Duration::from_mins(1)).await?;
        self.log.lock().unwrap().push("after-sleep-2".into());
        Ok(Outcome::done(Tainted::trusted(json!({"done": true}))))
    }
}

#[tokio::test]
async fn one_step_may_sleep_retry_and_sleep_again() {
    let l = log();
    let calls = Arc::new(Mutex::new(0usize));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("t")
        .timers(store.clone() as Arc<dyn TimerStore>)
        .skill(Interleaves {
            log: Arc::clone(&l),
            calls: Arc::clone(&calls),
        })
        .build();

    let mut out = rt.run("i", Tainted::trusted(json!({}))).await.unwrap();
    let mut rounds = 0;
    while out.status.is_suspended() && rounds < 5 {
        rt.fire_timers(later(120 * (rounds + 1))).await.unwrap();
        out = rt
            .replay(out.run_id, agentplane::runtime::Mode::Resume)
            .await
            .unwrap();
        rounds += 1;
    }
    store.verify(out.run_id).await.expect("chain verifies");

    assert_eq!(
        out.status,
        RunStatus::Succeeded,
        "the step finishes across both sleeps"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        2,
        "the flaky effect is attempted twice in total and never re-performed on resume"
    );
}
