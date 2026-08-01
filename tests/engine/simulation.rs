//! Crash-schedule exploration: the same invariants the specs check, against the
//! code, at *every* point a process could die.
//!
//! # What this is, and what it is not
//!
//! This is not full deterministic simulation. It does not reorder writes, skew
//! clocks, partition a network, or stall a disk — that needs the runtime on a
//! simulated executor (`madsim`), and a store that can be simulated with it.
//!
//! What it does do is the part that finds the most bugs for the least
//! machinery: a crash truncates an append-only journal, so **every prefix of a
//! real journal is a crash that could have happened**. The sweep rebuilds each
//! prefix into a fresh store, resumes it, and checks the invariants. For a run
//! of *n* records that is *n* distinct crash schedules, exhaustively, with no
//! seed to get lucky with.
//!
//! # The invariants are deliberately the specs' invariants
//!
//! | Checked here | Spec |
//! |---|---|
//! | No effect reaches the world twice | `EffectProtocol::ExactlyOnce` |
//! | Nothing acts without a durable announcement first | `EffectProtocol::DurableIntentPrecedesAction` |
//! | The chain verifies after every resume | — (store invariant) |
//! | Success means every terminal step ran | `EffectProtocol::SuccessMeansComplete` |
//! | Nothing is undone that was not done | `Saga::CompensationFollowsCompletion` |
//!
//! Where TLA+ checks the design, this checks the code, and a divergence between
//! them shows up as a failure here rather than as a production incident.
//!
//! # Why "no duplicate in the world" is not the assertion that bites
//!
//! Counting performances is the obvious check and, on its own, it is nearly
//! vacuous here — because it is not the last line of defence. The store holds a
//! partial unique index on `EffectStarted` per `(run, effect_key)`, so a replay
//! that wrongly falls through to live execution is stopped when it *announces*,
//! one layer beneath the counter. The world stays clean and the sweep goes
//! green while replay is comprehensively broken.
//!
//! This sweep was written that way first, and a mutation that deleted the whole
//! read-back path passed it.
//!
//! So the assertion that carries the weight is the one about *failures*:
//! **replay must never reach the constraint.** A resume may refuse, but only for
//! a reason the design names — a crash before the plan was frozen, or an
//! undecidable outcome. Being stopped by the store's exactly-once index is not
//! exactly-once working; it is the backstop catching what replay should have.
//!
//! Both mutations are checked by hand against this file before it is trusted:
//! deleting the read-back in `StepCtx`, and returning an empty replay cursor.
//! Each is caught, by the named assertion, at the first crash point where
//! replay carries any information.

#![cfg(all(feature = "turso", feature = "testkit"))]
#![allow(clippy::disallowed_methods)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use agentplane::core::{
    ArgSource, Compensation, Effect, EffectDescriptor, EffectError, Outcome, PlanIR, PlanNode,
    Recovery, RetryPolicy, RunId, Skill, SkillDescriptor, SkillError, StepId, Tainted,
};
use agentplane::journal::{Append, JournalStore, Record, RecordKind};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::TursoStore;
use agentplane::testkit::assert_replay_was_not_backstopped;
use serde_json::{Value, json};

/// Every performance of an externally visible effect, by name.
type World = Arc<Mutex<Vec<String>>>;

/// A mutating effect that records that it really happened.
#[derive(Debug, Clone)]
struct Touches {
    what: String,
    world: World,
}

#[async_trait::async_trait]
impl Effect for Touches {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("sim.touch", json!({ "what": self.what }))
    }
    fn mutates(&self) -> bool {
        true
    }
    /// Declared safe to repeat, so a crash-orphan is *retried* rather than
    /// quarantined. That is the harder case: the runtime has to get
    /// exactly-once right rather than refusing to decide.
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().unwrap().push(self.what.clone());
        Ok(json!({ "did": self.what }))
    }
}

#[derive(Debug)]
struct Touch {
    name: &'static str,
    world: World,
    fails: bool,
}

#[async_trait::async_trait]
impl Skill for Touch {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }
    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Touches {
            what: format!("do:{}", self.name),
            world: Arc::clone(&self.world),
        })
        .await?;
        if self.fails {
            return Ok(Outcome::fail(format!("{} refuses", self.name)));
        }
        Ok(Outcome::done(Tainted::trusted(json!({ "s": self.name }))))
    }
    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _o: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Touches {
            what: format!("undo:{}", self.name),
            world: Arc::clone(&self.world),
        })
        .await?;
        Ok(())
    }
}

fn runtime(store: &Arc<TursoStore>, world: &World, failing: Option<&'static str>) -> Runtime {
    let mut b = Runtime::builder(store.clone() as Arc<dyn JournalStore>).owner("sim");
    for name in ["a", "b", "c"] {
        b = b.skill(Touch {
            name,
            world: Arc::clone(world),
            fails: failing == Some(name),
        });
    }
    b.build()
}

fn chain() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "a").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "b").arg("x", ArgSource::node(StepId(0))),
        PlanNode::new(2, "c")
            .arg("x", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

/// Rebuild a journal prefix into a fresh store.
///
/// A crash truncates an append-only log, so a prefix *is* a crash. Replaying the
/// records through `append` re-forms the chain exactly as the original run did,
/// which is also a check on the chain being a pure function of its contents.
async fn crash_at(records: &[Record], n: usize, run: RunId) -> Arc<TursoStore> {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let lease = store
        .acquire(run, "sim", std::time::Duration::from_mins(5))
        .await
        .unwrap();

    for r in &records[..n] {
        let mut a = Append::new(run, r.kind().clone()).phase(r.body.phase);
        if let Some(s) = r.body.step {
            a = a.step(s);
        }
        if let Some(c) = r.body.case {
            a = a.case(c);
        }
        if let Some(k) = r.effect_key() {
            a = a.effect(k);
        }
        store.append(lease.epoch, vec![a]).await.unwrap();
    }
    store
}

/// Effects the prefix already records as having reached the world.
fn already_done(prefix: &[Record]) -> BTreeSet<String> {
    let mut started: BTreeMap<agentplane::core::EffectKey, String> = BTreeMap::new();
    let mut done = BTreeSet::new();
    for r in prefix {
        let Some(key) = r.effect_key() else { continue };
        match r.kind() {
            RecordKind::EffectStarted { descriptor, .. } => {
                if let Some(w) = descriptor.args.get("what").and_then(Value::as_str) {
                    started.insert(key, w.to_owned());
                }
            }
            RecordKind::EffectDone { .. } => {
                if let Some(w) = started.get(&key) {
                    done.insert(w.clone());
                }
            }
            _ => {}
        }
    }
    done
}

/// The sweep. `failing` names a step that refuses after mutating, which drives
/// the run into an unwind so compensation is explored too.
async fn sweep(failing: Option<&'static str>) {
    let origin = Arc::new(TursoStore::open_in_memory().await.unwrap());
    let world = Arc::new(Mutex::new(Vec::new()));
    let rt = runtime(&origin, &world, failing);

    let out = rt.run_plan(chain(), json!({})).await.unwrap();
    let records = origin.read(out.run_id, 1).await.unwrap();
    assert!(records.len() > 6, "a journal worth truncating");

    for n in 1..records.len() {
        let prefix = &records[..n];
        let survived = already_done(prefix);

        let store = crash_at(&records, n, out.run_id).await;
        store
            .verify(out.run_id)
            .await
            .unwrap_or_else(|e| panic!("crash@{n}: the truncated chain must verify: {e}"));

        let after = Arc::new(Mutex::new(Vec::new()));
        let resumed = runtime(&store, &after, failing);
        let outcome = resumed.replay(out.run_id, Mode::Resume).await;

        // A resume may refuse, but only for a reason the design names. Anything
        // else — a store constraint, a broken chain — means replay is not doing
        // its job, and the *absence* of a duplicated effect then proves nothing:
        // it was the database's unique index that stopped it, not replay.
        //
        // Tolerating every failure here is how this sweep first passed while a
        // deliberately broken replay path went undetected.
        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                let why = e.to_string();
                // The named legitimate refusals, and only these:
                //
                //   * the crash landed before the plan was frozen, so there is
                //     no run to resume — it never really started;
                //   * an effect's outcome is undecidable and its recovery mode
                //     forbids guessing.
                let legitimate = why.contains("no PlanFrozen")
                    || why.contains("no RunAdmitted")
                    || why.contains("undecidable")
                    || why.contains("quarantin");
                assert!(
                    legitimate,
                    "crash@{n}: resume failed for a reason the design does not \
                     name: {why}"
                );
                store.verify(out.run_id).await.unwrap_or_else(|e| {
                    panic!("crash@{n}: chain broken after a refused resume: {e}")
                });
                continue;
            }
        };

        // Likewise for a run that *reports* failure: an unwind is a legitimate
        // ending, a store rejecting a duplicate announcement is not. The check
        // lives in the testkit because it was written here first, then missed
        // in `tests/faults.rs` — see `testkit::backstop` for why the outcome
        // never shows it.
        assert_replay_was_not_backstopped(&format!("crash@{n}"), &Ok(outcome.clone()));

        // ── ExactlyOnce ────────────────────────────────────────────────────
        for did in after.lock().unwrap().iter() {
            assert!(
                !survived.contains(did),
                "crash@{n}: '{did}' had already reached the world before the \
                 crash and was performed again on resume — exactly-once is the \
                 one property this runtime exists to provide"
            );
        }

        // ── The chain survives every resume ────────────────────────────────
        store
            .verify(out.run_id)
            .await
            .unwrap_or_else(|e| panic!("crash@{n}: chain broken after resume: {e}"));

        // ── SuccessMeansComplete ───────────────────────────────────────────
        if outcome.status == RunStatus::Succeeded {
            let full: Vec<String> = survived
                .iter()
                .cloned()
                .chain(after.lock().unwrap().iter().cloned())
                .collect();
            for name in ["a", "b", "c"] {
                assert!(
                    full.contains(&format!("do:{name}")),
                    "crash@{n}: the run reports success but '{name}' never ran: {full:?}"
                );
            }
        }

        // ── CompensationFollowsCompletion ──────────────────────────────────
        let full: Vec<String> = survived
            .iter()
            .cloned()
            .chain(after.lock().unwrap().iter().cloned())
            .collect();
        for name in ["a", "b", "c"] {
            if full.contains(&format!("undo:{name}")) {
                assert!(
                    full.contains(&format!("do:{name}")),
                    "crash@{n}: '{name}' was compensated but never ran — a \
                     refund for a charge nobody made: {full:?}"
                );
            }
        }
    }
}

/// Every crash point in a run that succeeds.
#[tokio::test]
async fn no_crash_point_breaks_a_successful_run() {
    sweep(None).await;
}

/// Every crash point in a run that fails and unwinds — so the sweep covers
/// compensation as well as forward progress.
#[tokio::test]
async fn no_crash_point_breaks_an_unwinding_run() {
    sweep(Some("c")).await;
}
