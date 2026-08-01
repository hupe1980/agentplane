//! Replanning: a run changing its mind, on the record.
//!
//! Two properties carry the weight.
//!
//! **Versioned, never mutative.** A successor is `PlanIR v2` carrying
//! `derived_from: v1`, and both stay in the journal. What the run *intended*
//! before it changed its mind is usually the interesting part of an incident,
//! and it is structurally absent from any system that edits a plan in place.
//!
//! **Refused once untrusted data is in play.** The frozen plan is an
//! authorization graph compiled from trusted input only. A replan changes that
//! graph, so if untrusted data has already reached working memory, anything
//! shaping the new plan may be attacker-chosen — and choosing the authorization
//! graph is the whole game.

#![cfg(feature = "sqlite")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{
    ArgSource, Budget, Outcome, PlanIR, PlanNode, Skill, SkillDescriptor, SkillError, SourceId,
    StepId, Tainted,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::plan::{ReplanError, Replanner};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

/// Always asks for a new plan — one that does not include this step.
///
/// Deliberately *not* "asks the first time, then succeeds". A skill that decides
/// from a mutable counter takes a different branch on replay, which is a
/// determinism violation rather than a test fixture. An earlier version of this
/// file did exactly that, and strict replay caught it: the run replayed as
/// finishing on the original plan because the skill no longer asked.
#[derive(Debug)]
struct AsksToReplan {
    name: &'static str,
    /// Produces an untrusted output, which must block replanning.
    untrusted: bool,
}

#[async_trait::async_trait]
impl Skill for AsksToReplan {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        if self.untrusted {
            return Ok(Outcome::done(Tainted::from_source(
                json!({ "from": "the internet" }),
                SourceId::new("mcp:web.fetch"),
            )));
        }
        Ok(Outcome::Replan {
            reason: "the cheap route is unavailable".into(),
        })
    }
}

#[derive(Debug)]
struct Plain(&'static str);

#[async_trait::async_trait]
impl Skill for Plain {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.0).provides(self.0)
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(Tainted::trusted(json!({ "step": self.0 }))))
    }
}

/// Swaps the failing step for a fallback capability.
#[derive(Debug)]
struct Fallback {
    calls: Arc<AtomicUsize>,
    /// Return a successor that forgets to name its predecessor.
    forget_lineage: bool,
    /// Decline instead of producing one.
    decline: bool,
}

#[async_trait::async_trait]
impl Replanner for Fallback {
    async fn replan(
        &self,
        current: &PlanIR,
        reason: &str,
        _completed: &[(StepId, agentplane::core::Capability)],
    ) -> Result<PlanIR, ReplanError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.decline {
            return Err(ReplanError::NoAlternative(
                "no other provider offers this capability".into(),
            ));
        }
        let nodes = vec![
            PlanNode::new(0, "expensive")
                .arg("input", ArgSource::run_input())
                .terminal(),
        ];
        if self.forget_lineage {
            return Ok(PlanIR::new(nodes));
        }
        Ok(current.succeed_with(nodes, reason))
    }
}

struct Fixture {
    store: Arc<SqliteStore>,
    rt: Runtime,
    replans: Arc<AtomicUsize>,
}

fn fixture(planner: Fallback, untrusted: bool, budget: Budget) -> Fixture {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let replans = Arc::clone(&planner.calls);
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .budget(budget)
        .replanner(Arc::new(planner))
        .skill(AsksToReplan {
            name: "cheap",
            untrusted,
        })
        .skill(Plain("expensive"))
        .build();
    Fixture { store, rt, replans }
}

fn plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "cheap")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ])
}

fn planner() -> Fallback {
    Fallback {
        calls: Arc::new(AtomicUsize::new(0)),
        forget_lineage: false,
        decline: false,
    }
}

// ── The happy path ──────────────────────────────────────────────────────────

/// A step asks for a new plan, gets one, and the run finishes on it.
#[tokio::test]
async fn a_run_can_change_its_plan_and_finish_on_the_new_one() {
    let f = fixture(planner(), false, Budget::default().replans(2));

    let out = f.rt.run_plan(plan(), json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        f.replans.load(Ordering::SeqCst),
        1,
        "the planner was asked once"
    );
    assert_eq!(
        out.output.as_ref().and_then(|v| v.get("step")),
        Some(&json!("expensive")),
        "the successor's terminal step produced the result"
    );
}

/// **Versioned, never mutative.** Both plans are in the journal, and the
/// successor names its predecessor.
#[tokio::test]
async fn both_plan_versions_are_journaled_and_the_successor_names_its_parent() {
    let f = fixture(planner(), false, Budget::default().replans(2));
    let out = f.rt.run_plan(plan(), json!({})).await.unwrap();

    let plans: Vec<PlanIR> = f
        .store
        .read(out.run_id, 1)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::PlanFrozen { plan, .. } => serde_json::from_value(plan.clone()).ok(),
            _ => None,
        })
        .collect();

    assert_eq!(plans.len(), 2, "the original survives beside its successor");
    assert_eq!(plans[0].version, 1);
    assert_eq!(plans[1].version, 2);
    assert_eq!(
        plans[1].derived_from,
        Some(plans[0].digest()),
        "the successor names what it replaced — without it the audit trail has a \
         hole where the lineage should be"
    );
    assert!(plans[1].reason.is_some(), "and why");
    f.store.verify(out.run_id).await.unwrap();
}

// ── The security gate ───────────────────────────────────────────────────────

/// **The rule that matters.**
///
/// Once untrusted data is in working memory, the plan may not change. A run that
/// wants a different authorization graph *after* reading attacker-influenced
/// input is describing exactly the attack.
#[tokio::test]
async fn replanning_is_refused_once_untrusted_data_is_in_working_memory() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .owner("test")
        .budget(Budget::default().replans(5))
        .replanner(Arc::new(Fallback {
            calls: Arc::clone(&calls),
            forget_lineage: false,
            decline: false,
        }))
        .skill(AsksToReplan {
            name: "fetch",
            untrusted: true,
        })
        .skill(AsksToReplan {
            name: "cheap",
            untrusted: false,
        })
        .skill(Plain("expensive"))
        .build();

    // `fetch` reads the internet, then `cheap` asks to replan.
    let p = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "cheap")
            .arg("x", ArgSource::node(StepId(0)))
            .terminal(),
    ]);

    let out = rt.run_plan(p, json!({})).await.unwrap();
    match &out.status {
        RunStatus::Failed(m) => {
            assert!(m.contains("untrusted"), "the refusal must say why: {m}");
            assert!(
                m.contains("mcp:web.fetch"),
                "and name the source, or an operator searches the whole run: {m}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the planner is never even consulted — the gate is before it"
    );
}

// ── Bounds and honesty ──────────────────────────────────────────────────────

/// A run that replans without bound has stopped making progress.
#[tokio::test]
async fn the_replan_budget_bounds_thrashing() {
    /// Always asks for a new plan.
    #[derive(Debug)]
    struct Never;
    #[async_trait::async_trait]
    impl Skill for Never {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("cheap").provides("cheap")
        }
        async fn invoke(
            &self,
            _c: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::Replan {
                reason: "still not happy".into(),
            })
        }
    }

    /// Hands back a plan that asks the same step again.
    #[derive(Debug)]
    struct Loops;
    #[async_trait::async_trait]
    impl Replanner for Loops {
        async fn replan(
            &self,
            current: &PlanIR,
            reason: &str,
            _c: &[(StepId, agentplane::core::Capability)],
        ) -> Result<PlanIR, ReplanError> {
            Ok(current.succeed_with(
                vec![
                    PlanNode::new(0, "cheap")
                        .arg("input", ArgSource::run_input())
                        .terminal(),
                ],
                reason,
            ))
        }
    }

    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .budget(Budget::default().replans(2))
        .replanner(Arc::new(Loops))
        .skill(Never)
        .build();

    let out = rt.run_plan(plan(), json!({})).await.unwrap();
    match &out.status {
        RunStatus::Exhausted(e) => assert!(e.to_string().contains("replan"), "got: {e}"),
        other => panic!("expected the ceiling to stop it, got {other:?}"),
    }
}

/// A runtime with no planner says so, rather than failing obscurely.
#[tokio::test]
async fn asking_to_replan_without_a_planner_names_the_missing_piece() {
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(AsksToReplan {
            name: "cheap",
            untrusted: false,
        })
        .build();

    let out = rt.run_plan(plan(), json!({})).await.unwrap();
    match &out.status {
        RunStatus::Failed(m) => assert!(m.contains(".replanner("), "got: {m}"),
        other => panic!("expected a named refusal, got {other:?}"),
    }
}

/// A planner that declines stops the run with its reason.
#[tokio::test]
async fn a_planner_that_declines_stops_the_run_with_its_reason() {
    let f = fixture(
        Fallback {
            calls: Arc::new(AtomicUsize::new(0)),
            forget_lineage: false,
            decline: true,
        },
        false,
        Budget::default().replans(2),
    );

    let out = f.rt.run_plan(plan(), json!({})).await.unwrap();
    match &out.status {
        RunStatus::Failed(m) => assert!(m.contains("no other provider"), "got: {m}"),
        other => panic!("expected the planner's reason to survive, got {other:?}"),
    }
}

/// A successor that does not name its predecessor is rejected — an audit trail
/// with a hole in it is not an audit trail.
#[tokio::test]
async fn a_successor_without_lineage_is_rejected() {
    let f = fixture(
        Fallback {
            calls: Arc::new(AtomicUsize::new(0)),
            forget_lineage: true,
            decline: false,
        },
        false,
        Budget::default().replans(2),
    );

    let out = f.rt.run_plan(plan(), json!({})).await.unwrap();
    match &out.status {
        RunStatus::Failed(m) => assert!(m.contains("predecessor"), "got: {m}"),
        other => panic!("expected rejection, got {other:?}"),
    }
}

// ── Replay ──────────────────────────────────────────────────────────────────

/// **The successor is read back, never re-synthesised.**
///
/// A planner asked twice can answer differently — a changed router, a different
/// model — and replay would then verify the run against a plan that never
/// governed it. Same rule the first plan follows, for the same reason.
#[tokio::test]
async fn replay_reads_the_successor_back_instead_of_asking_again() {
    let f = fixture(planner(), false, Budget::default().replans(2));

    let first = f.rt.run_plan(plan(), json!({})).await.unwrap();
    assert_eq!(first.status, RunStatus::Succeeded);
    assert_eq!(f.replans.load(Ordering::SeqCst), 1);

    let again = f.rt.replay(first.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(
        f.replans.load(Ordering::SeqCst),
        1,
        "strict replay must not consult the planner again"
    );
    assert_eq!(again.output, first.output);
}

// ── Replanning meets the saga ───────────────────────────────────────────────

mod unwinding {
    use super::*;
    use agentplane::core::{
        Capability, Compensation, Effect, EffectDescriptor, EffectError, Recovery, RetryPolicy,
    };
    use std::sync::Mutex;

    type Log = Arc<Mutex<Vec<String>>>;

    #[derive(Debug, Clone)]
    struct M(String, Log, bool);

    #[async_trait::async_trait]
    impl Effect for M {
        type Output = Value;
        fn descriptor(&self) -> EffectDescriptor {
            EffectDescriptor::new("t.m", json!({ "w": self.0 }))
        }
        fn mutates(&self) -> bool {
            true
        }
        fn recovery(&self) -> Recovery {
            Recovery::Retry
        }
        fn retry(&self) -> RetryPolicy {
            RetryPolicy::never()
        }
        async fn perform(&self) -> Result<Value, EffectError> {
            self.1.lock().unwrap().push(self.0.clone());
            if self.2 {
                return Err(EffectError::Rejected("no".into()));
            }
            Ok(json!({ "did": self.0 }))
        }
    }

    #[derive(Debug)]
    struct Undoable {
        name: &'static str,
        log: Log,
        fails: bool,
    }

    #[async_trait::async_trait]
    impl Skill for Undoable {
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
            cx.effect(M(
                format!("do:{}", self.name),
                Arc::clone(&self.log),
                self.fails,
            ))
            .await?;
            // Deliberately *not* forwarding the effect's result. A step that
            // writes to a ledger reports that it wrote; it does not hand the
            // ledger's response onward as the thing that steers the rest of the
            // run. Forwarding it would put untrusted data in working memory and
            // the replan below would be refused — correctly, and these tests are
            // about the unwind, not about that refusal (which
            // `tests/boundary.rs` covers).
            Ok(Outcome::done(Tainted::trusted(
                serde_json::json!({ "step": self.name }),
            )))
        }
        async fn compensate(
            &self,
            cx: &mut StepCtx<'_>,
            _o: &Tainted<Value>,
        ) -> Result<(), SkillError> {
            cx.effect(M(
                format!("undo:{}", self.name),
                Arc::clone(&self.log),
                false,
            ))
            .await?;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Asks;
    #[async_trait::async_trait]
    impl Skill for Asks {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("asks").provides("asks")
        }
        async fn invoke(
            &self,
            _c: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::Replan {
                reason: "switch route".into(),
            })
        }
    }

    /// Successor that reuses a completed step's id for *different* work.
    #[derive(Debug)]
    struct Swaps;
    #[async_trait::async_trait]
    impl Replanner for Swaps {
        async fn replan(
            &self,
            current: &PlanIR,
            reason: &str,
            _c: &[(StepId, Capability)],
        ) -> Result<PlanIR, ReplanError> {
            Ok(current.succeed_with(
                vec![
                    PlanNode::new(0, "gamma").arg("input", ArgSource::run_input()),
                    PlanNode::new(1, "boom")
                        .arg("x", ArgSource::node(StepId(0)))
                        .terminal(),
                ],
                reason,
            ))
        }
    }

    /// Successor that leaves the completed step alone and adds a failing one.
    #[derive(Debug)]
    struct Extends;
    #[async_trait::async_trait]
    impl Replanner for Extends {
        async fn replan(
            &self,
            current: &PlanIR,
            reason: &str,
            _c: &[(StepId, Capability)],
        ) -> Result<PlanIR, ReplanError> {
            Ok(current.succeed_with(
                vec![
                    PlanNode::new(0, "alpha").arg("input", ArgSource::run_input()),
                    PlanNode::new(2, "boom")
                        .arg("x", ArgSource::node(StepId(0)))
                        .terminal(),
                ],
                reason,
            ))
        }
    }

    /// Successor that drops the completed step entirely.
    #[derive(Debug)]
    struct Drops;
    #[async_trait::async_trait]
    impl Replanner for Drops {
        async fn replan(
            &self,
            current: &PlanIR,
            reason: &str,
            _c: &[(StepId, Capability)],
        ) -> Result<PlanIR, ReplanError> {
            Ok(current.succeed_with(
                vec![
                    PlanNode::new(2, "boom")
                        .arg("input", ArgSource::run_input())
                        .terminal(),
                ],
                reason,
            ))
        }
    }

    fn runtime(planner: Arc<dyn Replanner>, log: &Log) -> Runtime {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        Runtime::builder(store as Arc<dyn JournalStore>)
            .owner("test")
            .budget(Budget::default().replans(2))
            .replanner(planner)
            .skill(Undoable {
                name: "alpha",
                log: Arc::clone(log),
                fails: false,
            })
            .skill(Asks)
            .skill(Undoable {
                name: "gamma",
                log: Arc::clone(log),
                fails: false,
            })
            .skill(Undoable {
                name: "boom",
                log: Arc::clone(log),
                fails: true,
            })
            .build()
    }

    fn v1() -> PlanIR {
        PlanIR::new(vec![
            PlanNode::new(0, "alpha").arg("input", ArgSource::run_input()),
            PlanNode::new(1, "asks")
                .arg("x", ArgSource::node(StepId(0)))
                .terminal(),
        ])
    }

    /// **A successor may not put new work at a completed step's id.**
    ///
    /// Effect keys are derived from the step id, so new work at a used id cannot
    /// be replayed — and the unwind, which undoes what `completed` says ran,
    /// would compensate whatever now occupies that slot. Before this check the
    /// run produced `["do:alpha", "do:boom", "undo:gamma"]`: `alpha` mutated and
    /// was never undone, while `gamma` — which never ran — was compensated.
    /// That is a refund for a charge nobody made, which is exactly what the
    /// `CompensationFollowsCompletion` invariant forbids.
    #[tokio::test]
    async fn a_successor_may_not_reuse_a_completed_step_id_for_other_work() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let rt = runtime(Arc::new(Swaps), &log);

        let out = rt.run_plan(v1(), json!({})).await.unwrap();
        match &out.status {
            RunStatus::Failed(m) => {
                assert!(m.contains("reuses step"), "got: {m}");
                assert!(m.contains("alpha") && m.contains("gamma"), "name both: {m}");
            }
            other => panic!("expected rejection, got {other:?}"),
        }

        let entries = log.lock().unwrap().clone();
        assert!(
            entries.contains(&"undo:alpha".to_string()),
            "the step that ran is undone: {entries:?}"
        );
        assert!(
            !entries.iter().any(|e| e.starts_with("undo:gamma")),
            "and the step that never ran is not: {entries:?}"
        );
    }

    /// **A step that ran under the old plan is still compensated.**
    ///
    /// The unwind resolves the skill from what *ran*, not from what the plan in
    /// force happens to have at that id — which after a replan can be different
    /// work, or nothing at all.
    #[tokio::test]
    async fn a_step_completed_before_the_replan_is_compensated_after_it() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let rt = runtime(Arc::new(Extends), &log);

        let out = rt.run_plan(v1(), json!({})).await.unwrap();
        assert!(
            matches!(out.status, RunStatus::Failed(_)),
            "got {:?}",
            out.status
        );

        let entries = log.lock().unwrap().clone();
        assert_eq!(
            entries,
            vec!["do:alpha", "do:boom", "undo:alpha"],
            "the successor's failure unwinds work done under its predecessor"
        );
    }

    /// **A completed step the successor drops is still compensated.**
    ///
    /// This is the case that makes recording the capability load-bearing rather
    /// than belt-and-braces. The successor has nothing at step 0, so resolving
    /// the compensation from the plan in force finds nothing and silently skips
    /// it — leaving `alpha`'s mutation in place with no trace that anything was
    /// missed. What ran is a fact about the run, not about the current plan.
    #[tokio::test]
    async fn a_completed_step_the_successor_drops_is_still_compensated() {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let rt = runtime(Arc::new(Drops), &log);

        let out = rt.run_plan(v1(), json!({})).await.unwrap();
        assert!(
            matches!(out.status, RunStatus::Failed(_)),
            "got {:?}",
            out.status
        );

        let entries = log.lock().unwrap().clone();
        assert_eq!(
            entries,
            vec!["do:alpha", "do:boom", "undo:alpha"],
            "dropping a step from the successor does not un-run it"
        );
    }
}
