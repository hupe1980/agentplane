//! Plans: the contract, the ready-set, and provenance through the graph.
//!
//! Roughly four fifths of observed multi-agent failures are specification and
//! coordination problems rather than model-quality problems — that is, things a
//! graph checker can see before anything runs. These tests are that checker's
//! specification.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{
    ArgSource, Capability, Collaboration, Outcome, PlanError, PlanIR, PlanNode, Skill,
    SkillDescriptor, SkillError, StepId, Tainted, Topology,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::plan::{Contract, validate};
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

// ── Contract validation ─────────────────────────────────────────────────────

fn contract() -> Contract {
    Contract::new([
        Capability::new("fetch"),
        Capability::new("validate"),
        Capability::new("post"),
    ])
}

fn ok_plan() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "validate").arg("data", ArgSource::node(StepId(0))),
        PlanNode::new(2, "post")
            .arg("checked", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

#[test]
fn a_well_formed_plan_validates() {
    validate(&ok_plan(), &contract()).unwrap();
}

#[test]
fn an_empty_plan_is_refused() {
    assert_eq!(
        validate(&PlanIR::new(vec![]), &contract()).unwrap_err(),
        PlanError::Empty
    );
}

/// A cycle means the run can never finish, and would sit there looking busy.
#[test]
fn a_cycle_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("a", ArgSource::node(StepId(1)))
            .terminal(),
        PlanNode::new(1, "validate").arg("b", ArgSource::node(StepId(0))),
    ]);
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::Cycle(_)
    ));
}

/// Without a terminal node nothing declares the plan finished.
#[test]
fn a_plan_with_no_terminal_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
    ]);
    assert_eq!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::NoTerminal
    );
}

/// A dependency on a node that is not in the plan describes something that is
/// not there.
#[test]
fn a_dangling_dependency_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("a", ArgSource::node(StepId(9)))
            .terminal(),
    ]);
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::MissingDependency {
            missing: StepId(9),
            ..
        }
    ));
}

/// Work whose result nothing reads is almost always a plan that meant to wire it
/// somewhere.
#[test]
fn an_unreachable_step_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("input", ArgSource::run_input())
            .terminal(),
        PlanNode::new(1, "validate").arg("orphaned", ArgSource::run_input()),
    ]);
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::Unreachable { step: StepId(1) }
    ));
}

/// A plan may only ask for what the runtime can actually do.
#[test]
fn an_unprovidable_capability_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "launch-missiles")
            .arg("input", ArgSource::run_input())
            .terminal(),
    ]);
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::NoProvider { .. }
    ));
}

/// An argument read from a node that is not a dependency would race it.
#[test]
fn an_argument_from_a_non_dependency_is_refused() {
    let mut plan = ok_plan();
    // Bypass the builder, which would have recorded the dependency.
    plan.nodes[0]
        .args
        .insert("sneaky".into(), ArgSource::node(StepId(2)));
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::ArgumentNotUpstream {
            step: StepId(0),
            ..
        }
    ));
}

/// A verifier that depends on nothing cannot have seen what it claims to check.
#[test]
fn a_verifier_with_no_subject_is_refused() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "validate")
            .arg("input", ArgSource::run_input())
            .verifies()
            .terminal(),
    ]);
    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::VerifierWithoutSubject { .. }
    ));
}

/// Nothing checking the work is a fifth of observed multi-agent failures, so a
/// contract can insist on a verifier.
#[test]
fn a_required_verifier_can_be_demanded() {
    assert_eq!(
        validate(&ok_plan(), &contract().require_verifier()).unwrap_err(),
        PlanError::VerifierRequired
    );

    let with_verifier = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "validate")
            .arg("data", ArgSource::node(StepId(0)))
            .verifies()
            .terminal(),
    ]);
    validate(&with_verifier, &contract().require_verifier()).unwrap();
}

#[test]
fn a_plan_larger_than_the_budget_is_refused() {
    assert!(matches!(
        validate(&ok_plan(), &contract().max_steps(2)).unwrap_err(),
        PlanError::TooManySteps {
            steps: 3,
            allowed: 2
        }
    ));
}

// ── Topology ────────────────────────────────────────────────────────────────

/// **False parallelism.** Steps that read the same source are not disjoint, so
/// the coordination cost is paid for parallelism that is not there.
#[test]
fn collaboration_claiming_disjoint_inputs_must_actually_be_disjoint() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("shared")),
        PlanNode::new(1, "validate").arg("b", ArgSource::input_field("shared")),
        PlanNode::new(2, "post")
            .arg("x", ArgSource::node(StepId(0)))
            .arg("y", ArgSource::node(StepId(1)))
            .terminal(),
    ])
    .topology(Topology::Collaborative(Collaboration::ParallelDisjoint));

    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::FalseParallelism { .. }
    ));
}

/// Genuinely disjoint inputs are accepted.
#[test]
fn genuinely_disjoint_collaboration_validates() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("left")),
        PlanNode::new(1, "validate").arg("b", ArgSource::input_field("right")),
        PlanNode::new(2, "post")
            .arg("x", ArgSource::node(StepId(0)))
            .arg("y", ArgSource::node(StepId(1)))
            .terminal(),
    ])
    .topology(Topology::Collaborative(Collaboration::ParallelDisjoint));

    validate(&plan, &contract()).unwrap();
}

/// Splitting for authority requires there to be authority to split.
#[test]
fn collaboration_for_authority_needs_differing_capabilities() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("x")),
        PlanNode::new(1, "fetch")
            .arg("b", ArgSource::node(StepId(0)))
            .terminal(),
    ])
    .topology(Topology::Collaborative(Collaboration::DistinctAuthority));

    assert!(matches!(
        validate(&plan, &contract()).unwrap_err(),
        PlanError::NoAuthorityToSeparate { .. }
    ));
}

/// A single-agent plan carries no coordination surface, so nothing to justify.
#[test]
fn single_topology_needs_no_justification() {
    validate(&ok_plan().topology(Topology::Single), &contract()).unwrap();
}

// ── The ready-set ───────────────────────────────────────────────────────────

/// Dispatch order is a deterministic total order, so replay reproduces it.
#[test]
fn the_ready_set_is_deterministically_ordered() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("l")),
        PlanNode::new(1, "fetch").arg("b", ArgSource::input_field("r")),
        PlanNode::new(2, "post")
            .arg("x", ArgSource::node(StepId(0)))
            .arg("y", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let mut done = std::collections::BTreeSet::new();
    assert_eq!(
        plan.ready(&done),
        vec![StepId(0), StepId(1)],
        "both are ready"
    );

    done.insert(StepId(0));
    assert_eq!(plan.ready(&done), vec![StepId(1)], "2 still waits on 1");

    done.insert(StepId(1));
    assert_eq!(plan.ready(&done), vec![StepId(2)]);

    done.insert(StepId(2));
    assert!(plan.ready(&done).is_empty());
    assert!(plan.is_complete(&done));
}

/// Completion is structural: every terminal node must have run.
#[test]
fn completeness_requires_every_terminal_node() {
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("a", ArgSource::input_field("l"))
            .terminal(),
        PlanNode::new(1, "post")
            .arg("b", ArgSource::input_field("r"))
            .terminal(),
    ]);
    let mut done = std::collections::BTreeSet::new();
    done.insert(StepId(0));
    assert!(
        !plan.is_complete(&done),
        "one terminal node is not all of them"
    );
    done.insert(StepId(1));
    assert!(plan.is_complete(&done));
}

// ── Execution ───────────────────────────────────────────────────────────────

/// Records what it was given and returns a marker, so a test can see how inputs
/// flowed through the graph.
#[derive(Debug)]
struct Echo {
    name: &'static str,
    seen: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
    untrusted: bool,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Echo {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.name)
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap()
            .push((self.name.to_owned(), input.peek().clone()));

        let out = json!({ "from": self.name, "input": input.peek() });
        Ok(Outcome::done(if self.untrusted {
            Tainted::from_source(out, agentplane::core::SourceId::new("external"))
        } else {
            input.map(|_| out)
        }))
    }
}

struct Harness {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
    seen: Arc<std::sync::Mutex<Vec<(String, Value)>>>,
    calls: Arc<AtomicUsize>,
}

fn harness(untrusted: &[&'static str]) -> Harness {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));

    let mut b = Runtime::builder(store.clone() as Arc<dyn JournalStore>);
    for name in ["fetch", "validate", "post"] {
        b = b.skill(Echo {
            name,
            seen: Arc::clone(&seen),
            untrusted: untrusted.contains(&name),
            calls: Arc::clone(&calls),
        });
    }
    Harness {
        store,
        rt: b.build(),
        seen,
        calls,
    }
}

/// A multi-step plan runs every step, in dependency order.
#[tokio::test]
async fn a_multi_step_plan_executes_in_dependency_order() {
    let h = harness(&[]);
    let out = h.rt.run_plan(ok_plan(), json!({ "id": 1 })).await.unwrap();

    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(h.calls.load(Ordering::SeqCst), 3);

    let order: Vec<String> = h
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert_eq!(order, vec!["fetch", "validate", "post"]);
}

/// Each step is journaled under its own id, and the chain verifies.
#[tokio::test]
async fn every_step_is_journaled_separately() {
    let h = harness(&[]);
    let out = h.rt.run_plan(ok_plan(), json!({})).await.unwrap();

    let records = h.store.read(out.run_id, 1).await.unwrap();
    let starts: Vec<_> = records
        .iter()
        .filter(|r| r.kind().kind_str() == "StepStarted")
        .filter_map(|r| r.body.step)
        .collect();
    assert_eq!(starts, vec![StepId(0), StepId(1), StepId(2)]);
    h.store.verify(out.run_id).await.unwrap();
}

/// The frozen plan is in the journal, so the run can be audited against what it
/// was permitted to do.
#[tokio::test]
async fn the_frozen_plan_is_journaled() {
    let h = harness(&[]);
    let plan = ok_plan();
    let out = h.rt.run_plan(plan.clone(), json!({})).await.unwrap();

    let records = h.store.read(out.run_id, 1).await.unwrap();
    let frozen = records.iter().find_map(|r| match r.kind() {
        RecordKind::PlanFrozen { digest, plan, .. } => Some((*digest, plan.clone())),
        _ => None,
    });
    let (digest, recorded) = frozen.expect("the plan must be part of the record");
    assert_eq!(digest, plan.digest(), "content-addressed");
    assert_eq!(
        serde_json::from_value::<PlanIR>(recorded).unwrap(),
        plan,
        "the plan itself is recoverable, not just its hash"
    );
}

/// A step reads exactly what its arguments declare.
#[tokio::test]
async fn arguments_are_assembled_from_their_declared_sources() {
    let h = harness(&[]);
    h.rt.run_plan(ok_plan(), json!({ "id": 7 })).await.unwrap();

    let seen = h.seen.lock().unwrap();
    assert_eq!(seen[0].1, json!({ "id": 7 }), "step 0 reads the run input");
    assert_eq!(
        seen[1].1,
        json!({ "from": "fetch", "input": { "id": 7 } }),
        "step 1 reads step 0's output"
    );
}

/// **Provenance flows through the graph.**
///
/// A step downstream of anything untrusted receives untrusted input, without the
/// plan author having to say so.
#[tokio::test]
async fn untrust_propagates_downstream() {
    #[derive(Debug)]
    struct AssertsUntrusted;

    #[async_trait::async_trait]
    impl Skill for AssertsUntrusted {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("post").provides("post")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            assert!(
                input.label().is_untrusted(),
                "a step downstream of untrusted data must receive untrusted input"
            );
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Echo {
            name: "fetch",
            seen: Arc::clone(&seen),
            // Step 0 reads from outside.
            untrusted: true,
            calls: Arc::clone(&calls),
        })
        .skill(Echo {
            name: "validate",
            seen: Arc::clone(&seen),
            untrusted: false,
            calls: Arc::clone(&calls),
        })
        .skill(AssertsUntrusted)
        .build();

    let out = rt.run_plan(ok_plan(), json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
}

/// A plan that fails validation never begins.
///
/// The cost of finding out early is microseconds of graph checking; the cost of
/// finding out late is half an operation performed and half not.
#[tokio::test]
async fn an_invalid_plan_is_rejected_before_anything_runs() {
    let h = harness(&[]);
    let bad = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("a", ArgSource::node(StepId(1)))
            .terminal(),
        PlanNode::new(1, "validate").arg("b", ArgSource::node(StepId(0))),
    ]);

    let err = h.rt.run_plan(bad, json!({})).await.unwrap_err();
    assert!(err.to_string().contains("cycle"), "got: {err}");
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        0,
        "not a single step may run from a plan that could not finish"
    );
}

/// Strict replay reproduces a multi-step run without performing anything.
#[tokio::test]
async fn a_multi_step_run_replays_strictly() {
    let h = harness(&[]);
    let first = h.rt.run_plan(ok_plan(), json!({ "id": 3 })).await.unwrap();
    let before = h.calls.load(Ordering::SeqCst);

    let again = h.rt.replay(first.run_id, Mode::Strict).await.unwrap();

    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(first.output, again.output);
    assert_eq!(
        h.calls.load(Ordering::SeqCst),
        before + 3,
        "the skills re-run — but their effects come from the journal"
    );
    assert_eq!(
        first.chain_head, again.chain_head,
        "verification does not extend the chain"
    );
}

/// A bare target still works: it compiles to the degenerate one-node plan.
#[tokio::test]
async fn a_bare_target_compiles_to_a_single_node_plan() {
    let h = harness(&[]);
    let out = h.rt.run("fetch", json!({ "x": 1 })).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(h.calls.load(Ordering::SeqCst), 1);
}

/// A diamond: two independent branches that rejoin.
#[tokio::test]
async fn a_diamond_plan_runs_both_branches_then_joins() {
    let h = harness(&[]);
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "validate").arg("left", ArgSource::node_field(StepId(0), "from")),
        PlanNode::new(2, "post")
            .arg("a", ArgSource::node(StepId(0)))
            .arg("b", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = h.rt.run_plan(plan, json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);

    let seen = h.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    // The join step receives both branches, keyed by argument name.
    let join = &seen[2].1;
    assert!(join.get("a").is_some() && join.get("b").is_some());
}

/// A field selector picks one part of an upstream output.
#[tokio::test]
async fn a_field_selector_narrows_an_upstream_output() {
    let h = harness(&[]);
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "post")
            .arg("only", ArgSource::node_field(StepId(0), "from"))
            .terminal(),
    ]);

    h.rt.run_plan(plan, json!({})).await.unwrap();
    let seen = h.seen.lock().unwrap();
    assert_eq!(seen[1].1, json!("fetch"), "only the selected field arrives");
}

/// A constant is trusted by construction: it was frozen before anything
/// untrusted was read.
#[tokio::test]
async fn a_constant_argument_is_trusted() {
    #[derive(Debug)]
    struct AssertsTrusted;

    #[async_trait::async_trait]
    impl Skill for AssertsTrusted {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("fetch").provides("fetch")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            assert!(!input.label().is_untrusted());
            assert_eq!(*input.peek(), json!("frozen"));
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(AssertsTrusted)
        .build();

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch")
            .arg("k", ArgSource::constant(json!("frozen")))
            .terminal(),
    ]);
    assert_eq!(
        rt.run_plan(plan, json!({})).await.unwrap().status,
        RunStatus::Succeeded
    );
}

// ── Concurrent dispatch ─────────────────────────────────────────────────────

/// **The ready set actually runs concurrently.**
///
/// Proven by a rendezvous rather than by timing: two sibling steps each signal
/// their own barrier and wait for the other's. If dispatch were sequential the
/// first step would wait for a signal that cannot arrive until it returns, and
/// the test would hang — so passing *is* the evidence, and it cannot pass by
/// accident on a fast machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sibling_steps_in_the_ready_set_run_concurrently() {
    use tokio::sync::Barrier;

    #[derive(Debug)]
    struct Rendezvous {
        name: &'static str,
        gate: Arc<Barrier>,
    }

    #[async_trait::async_trait]
    impl Skill for Rendezvous {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.name).provides(self.name)
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            // Blocks until *both* siblings arrive. Only reachable if they are
            // in flight at the same time.
            self.gate.wait().await;
            Ok(Outcome::done(Tainted::trusted(
                json!({ "step": self.name }),
            )))
        }
    }

    let gate = Arc::new(Barrier::new(2));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store as Arc<dyn JournalStore>)
        .skill(Rendezvous {
            name: "left",
            gate: Arc::clone(&gate),
        })
        .skill(Rendezvous {
            name: "right",
            gate: Arc::clone(&gate),
        })
        .skill(Join)
        .build();

    // A diamond: `left` and `right` are siblings with no dependency between
    // them, so they are in the ready set together.
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
        PlanNode::new(2, "join")
            .arg("l", ArgSource::node(StepId(0)))
            .arg("r", ArgSource::node(StepId(1)))
            .terminal(),
    ]);

    let out = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rt.run_plan(plan, json!({})),
    )
    .await
    .expect("sequential dispatch would deadlock here")
    .unwrap();

    assert_eq!(out.status, RunStatus::Succeeded);
}

#[derive(Debug)]
struct Join;

#[async_trait::async_trait]
impl Skill for Join {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("join").provides("join")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

/// Concurrency must not leak into the record. Sibling steps write interleaved,
/// but each step's *own* effect order is what replay verifies — which is why
/// the cursor is per-step and why this replays strictly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrently_dispatched_run_replays_strictly() {
    #[derive(Debug)]
    struct Chatty(&'static str, Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl Skill for Chatty {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new(self.0).provides(self.0)
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            // Several effects each, so the two steps' records interleave.
            for i in 0..4 {
                let arguments = Tainted::trusted(Value::Null);
                cx.sink(
                    agentplane::runtime::effects::Recorded::new(format!("{}-{i}", self.0)),
                    &arguments,
                )
                .await?;
                tokio::task::yield_now().await;
            }
            self.1.fetch_add(1, Ordering::SeqCst);
            Ok(Outcome::done(Tainted::trusted(json!({ "step": self.0 }))))
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Chatty("left", Arc::clone(&calls)))
        .skill(Chatty("right", Arc::clone(&calls)))
        .skill(Join)
        .build();

    let plan = || {
        PlanIR::new(vec![
            PlanNode::new(0, "left").arg("input", ArgSource::run_input()),
            PlanNode::new(1, "right").arg("input", ArgSource::run_input()),
            PlanNode::new(2, "join")
                .arg("l", ArgSource::node(StepId(0)))
                .arg("r", ArgSource::node(StepId(1)))
                .terminal(),
        ])
    };

    let out = rt.run_plan(plan(), json!({})).await.unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);
    let ran = calls.load(Ordering::SeqCst);

    let again = rt.replay(out.run_id, Mode::Strict).await.unwrap();
    assert_eq!(again.status, RunStatus::Succeeded);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        ran + 2,
        "the skills re-execute, but their effects come from the journal"
    );
    store.verify(out.run_id).await.unwrap();
}

// ── Quorum ──────────────────────────────────────────────────────────────────
//
// §1.2 is the argument: an agent at 61 % pass^1 is around 25 % at pass^8, so a
// single execution of a high-stakes judgement is not adequate evidence. What a
// panel must never do is resolve its own disagreement.

/// A panel needs something to judge.
///
/// Declared on a node with no subject, a quorum repeats *the work* rather than
/// reviewing it — and for a mutating step that means repeating it on the world.
#[test]
fn a_quorum_on_a_node_that_judges_nothing_is_refused() {
    use agentplane::core::Quorum;

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "validate")
            .arg("input", ArgSource::run_input())
            .with_quorum(Quorum::new(2, ["correctness", "policy", "arithmetic"]).unwrap())
            .terminal(),
    ]);
    assert!(
        matches!(
            validate(&plan, &contract()).unwrap_err(),
            PlanError::QuorumWithoutSubject { .. }
        ),
        "a panel with nothing to judge repeats the work rather than reviewing it"
    );
}

/// With a subject it is a review, and permitted.
#[test]
fn a_quorum_over_a_predecessor_is_accepted() {
    use agentplane::core::Quorum;

    let plan = PlanIR::new(vec![
        PlanNode::new(0, "fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "validate")
            .after(0)
            .arg("subject", ArgSource::node(StepId(0)))
            .with_quorum(Quorum::new(2, ["correctness", "policy", "arithmetic"]).unwrap())
            .terminal(),
    ]);
    validate(&plan, &contract()).expect("a panel with a subject is fine");
}

/// The declaration itself is refused before a plan can carry it.
#[test]
fn a_panel_of_identical_judges_cannot_be_declared() {
    use agentplane::core::{Quorum, QuorumError};

    assert_eq!(
        Quorum::new(2, ["correctness", "correctness", "policy"]).expect_err("identical"),
        QuorumError::RepeatedLens,
        "identical judges share their blind spots, so this is repetition \
         wearing diversity's clothing"
    );
}

/// Every collaboration justification must reject *something*.
///
/// The three reasons ask different questions, so a plan failing one may
/// legitimately satisfy another — that is not a bypass. What *is* a bypass is a
/// justification that accepts every plan ever constructed: it costs nothing to
/// claim, so anyone blocked by a real check writes that word instead, and the
/// checked reasons become optional.
///
/// This is the collaboration equivalent of a permissive default. A gate with a
/// free door is a gate nobody walks through.
#[test]
fn every_collaboration_justification_rejects_some_plan() {
    // Two branches reading one field: not disjoint.
    let overlapping = || {
        vec![
            PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("shared")),
            PlanNode::new(1, "validate").arg("b", ArgSource::input_field("shared")),
            PlanNode::new(2, "post")
                .arg("x", ArgSource::node(StepId(0)))
                .arg("y", ArgSource::node(StepId(1)))
                .terminal(),
        ]
    };
    // One capability throughout: no authority to separate.
    let single = || {
        vec![
            PlanNode::new(0, "fetch").arg("a", ArgSource::input_field("left")),
            PlanNode::new(1, "fetch").arg("b", ArgSource::input_field("right")),
            PlanNode::new(2, "fetch")
                .arg("x", ArgSource::node(StepId(0)))
                .arg("y", ArgSource::node(StepId(1)))
                .terminal(),
        ]
    };

    for reason in [
        Collaboration::ParallelDisjoint,
        Collaboration::DistinctAuthority,
    ] {
        let refused = [overlapping(), single()].into_iter().any(|nodes| {
            validate(
                &PlanIR::new(nodes).topology(Topology::Collaborative(reason)),
                &contract(),
            )
            .is_err()
        });
        assert!(
            refused,
            "{reason:?} accepted every plan put to it, so declaring it costs \
             nothing — and a justification that costs nothing is the one every \
             plan blocked by a real check will claim instead"
        );
    }
}
