//! An approval of a consultation shows, and binds, the agent it hands work to.
//!
//! A reviewer asked *may this agent consult `tool://agent/pay.execute`* is
//! approving a delegation. What the callee may do is in front of them —
//! derived from its registered declaration, never from anything the run
//! wrote — and an approval covers that callee: a redeployed one is refused
//! before it runs, naming the revision approved and the one that would run.

#![cfg(all(feature = "redb", feature = "manifest", feature = "testkit"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    CorrelationKey, Decision, Outcome, Reach, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::runtime::{Agent, RunStatus, Runtime, RuntimeBuilder, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// The ledger the payer may move money through. Never reached here: every
/// test stops before the payer runs, or consults the auditor instead.
#[derive(Debug)]
struct Ledger;

#[async_trait::async_trait]
impl agentplane::tools::ToolClient for Ledger {
    async fn call(
        &self,
        _tool: &agentplane::tools::ToolId,
        _arguments: &Value,
        _p: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, agentplane::tools::ToolError> {
        unreachable!("no test here lets the payer move money")
    }

    fn destination(&self, _tool: &agentplane::tools::ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

/// The desk: asks a person before consulting the payer.
const DESK: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  topology:
    mode: collaborative
    role: orchestrator
    reason: distinct-authority
  security:
    max_delegation_depth: 2
    max_sensitivity_egress: internal
  capabilities: { provides: [desk.settle] }
  models: { privileged: { provider: fake, model: desk-1 } }
  execution: { kind: tool-calling, max_turns: 4 }
  oversight:
    approval: tools-only
    deadline: { name: settlement-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://agent/pay.execute
      mutates: true
      requires_approval: true
      description: Hand the settlement to the payer.
      arguments:
        type: object
        additionalProperties: false
        properties:
          invoice: { type: string }
        required: [invoice]
  budgets: {}
"#;

/// The payer, at the revision a reviewer is shown.
const PAYER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: payer, version: "1.0.0" }
spec:
  topology:
    mode: collaborative
    role: orchestrator
    reason: distinct-authority
  security:
    max_delegation_depth: 1
    max_sensitivity_egress: internal
  capabilities: { provides: [pay.execute] }
  models: { privileged: { provider: fake, model: payer-1 } }
  execution: { kind: tool-calling, max_turns: 4 }
  oversight:
    approval: required
    deadline: { name: refund-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      description: Move funds.
      protected_fields:
        - path: /amount
          allowed_sources: [model:fake/payer-1]
          max_sensitivity: internal
    - ref: tool://ledger/refund
      mutates: true
      requires_approval: true
      description: Reverse a transfer.
      protected_fields:
        - path: /amount
          allowed_sources: [model:fake/payer-1]
          max_sensitivity: internal
    - ref: tool://agent/audit.note
      description: Leave a note with the auditor.
      arguments:
        type: object
        additionalProperties: false
        properties:
          note: { type: string }
        required: [note]
  budgets: { max_effects: 12 }
"#;

/// The auditor the payer may consult in turn.
const AUDITOR: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: auditor, version: "1.0.0" }
spec:
  identity: { role: "Acknowledge a note." }
  topology: { mode: single, role: specialist }
  security: { max_sensitivity_egress: internal }
  capabilities: { provides: [audit.note] }
  models: { privileged: { provider: fake, model: auditor-1 } }
  execution: { kind: completion }
  budgets: {}
"#;

/// The payer, redeployed: another version under the same capability.
fn payer_b() -> Manifest {
    Manifest::parse(&PAYER.replace(r#"version: "1.0.0""#, r#"version: "1.1.0""#)).expect("payer B")
}

fn key(v: &str) -> CorrelationKey {
    CorrelationKey::new("invoice", v)
}

fn by(actor: &str) -> agentplane::core::Operator {
    agentplane::core::Operator::asserted(actor).expect("a fixture names its operator")
}

fn plane(
    store: &Arc<RedbStore>,
    provider: &Arc<agentplane::testkit::FakeProvider>,
    desk: &str,
    payer: &Manifest,
    add: impl FnOnce(RuntimeBuilder) -> RuntimeBuilder,
) -> Arc<Runtime> {
    add(Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(store) as Arc<dyn CaseStore>)
        .events(Arc::clone(store) as Arc<dyn EventStore>)
        .tasks(Arc::clone(store) as Arc<dyn TaskStore>)
        .provider(
            "fake",
            Arc::clone(provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .tool_server("ledger", Arc::new(Ledger))
        .agent(Agent::new(&Manifest::parse(desk).expect("desk")))
        .agent(Agent::new(payer))
        .agent(Agent::new(&Manifest::parse(AUDITOR).expect("auditor"))))
    .build()
}

/// The desk run, suspended on its approval of `tool`, and the task it opened.
async fn proposed_by(
    store: &Arc<RedbStore>,
    desk: &str,
    tool: &str,
    payer: &Manifest,
    add: impl FnOnce(RuntimeBuilder) -> RuntimeBuilder,
) -> (Arc<Runtime>, agentplane::core::Task) {
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_call_tool("call_1", tool, json!({ "invoice": "INV-7" }));
    let rt = plane(store, &provider, desk, payer, add);
    rt.run_correlated(
        "desk.settle",
        Tainted::trusted(json!({ "q": "settle INV-7" })),
        "settlement",
        &[key("INV-7")],
    )
    .await
    .expect("the run suspends on the approval");
    let task = store.queue(&[], 10).await.unwrap().pop().expect("a task");
    (rt, task)
}

async fn proposed(
    store: &Arc<RedbStore>,
    payer: &Manifest,
) -> (Arc<Runtime>, agentplane::core::Task) {
    proposed_by(store, DESK, "agent__pay-execute", payer, |b| b).await
}

/// **The reviewer sees the callee's reach, and the digest covers it.** The
/// section names the payer's revision, every grant with whether it mutates
/// and whether the payer's own run asks a person first, its budgets and its
/// delegation ceiling; and the same call to a redeployed payer is a different
/// approval.
#[tokio::test]
async fn an_approval_of_a_consultation_shows_the_callee_s_reach() {
    let payer = Manifest::parse(PAYER).expect("payer");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let (_rt, task) = proposed(&store, &payer).await;

    let reach: &Reach = task
        .justification
        .reach
        .as_ref()
        .expect("the approval of a consultation shows the callee's reach");
    assert_eq!(reach.capability, "pay.execute");
    let declared = reach.declaration.as_ref().expect("the payer is declared");
    assert_eq!(declared.agent, "payer");
    assert_eq!(declared.version, "1.0.0");
    assert_eq!(declared.digest, payer.digest().unwrap());
    assert_eq!(declared.max_delegation_depth, Some(1));
    assert_eq!(declared.budgets["max_effects"], 12);
    let grant = |reference: &str| {
        declared
            .grants
            .iter()
            .find(|g| g.reference == reference)
            .unwrap_or_else(|| panic!("{reference} is not shown: {declared:?}"))
    };
    assert!(grant("tool://ledger/transfer").mutates);
    assert!(
        !grant("tool://ledger/transfer").requires_approval,
        "a mutating grant nobody approves must say so"
    );
    assert!(grant("tool://ledger/refund").requires_approval);

    let other = Arc::new(RedbStore::open_in_memory().unwrap());
    let (_rt, redeployed) = proposed(&other, &payer_b()).await;
    assert_eq!(
        redeployed.justification.proposed_action, task.justification.proposed_action,
        "the call is the same; only the callee moved"
    );
    assert_ne!(
        redeployed.justification.digest(),
        task.justification.digest(),
        "an approval of the call to one payer would approve another"
    );
}

/// **One level.** The agents the callee may consult in turn are named and
/// marked, and nothing of their own reach is derived.
#[tokio::test]
async fn the_reach_names_but_does_not_expand_the_callee_s_agents() {
    let payer = Manifest::parse(PAYER).expect("payer");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let (_rt, task) = proposed(&store, &payer).await;
    let declared = task.justification.reach.unwrap().declaration.unwrap();
    let consults: Vec<&str> = declared
        .grants
        .iter()
        .filter(|g| g.consults)
        .map(|g| g.reference.as_str())
        .collect();
    assert_eq!(consults, vec!["tool://agent/audit.note"]);
    let shown = serde_json::to_string(&declared).unwrap();
    assert!(
        !shown.contains("auditor"),
        "the auditor's own declaration was expanded: {shown}"
    );
}

/// **Every surface shows it,** through the one rendering, and on a withheld
/// proposal too.
#[tokio::test]
async fn the_rendering_shows_the_callee_s_reach() {
    let payer = Manifest::parse(PAYER).expect("payer");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let (_rt, mut task) = proposed(&store, &payer).await;
    let rendered = task
        .rendering()
        .reach
        .expect("the rendering shows the reach");
    assert_eq!(
        rendered["declaration"]["digest"],
        payer.digest().unwrap().to_string()
    );
    task.withheld = Some(agentplane::core::Withheld::Sealed);
    assert!(
        task.rendering().reach.is_some(),
        "a withheld proposal still shows whom it hands work to"
    );
}

/// **The approved callee is the one that runs.** The task is opened under
/// payer A; the plane restarts with payer B; the approval arrives and the
/// resumed run reads back the reach it showed — so the approval holds — and
/// the consultation, pinned to A, is refused naming both revisions. Payer B
/// never runs.
#[tokio::test]
async fn a_redeployed_callee_is_named_in_the_refusal() {
    let payer = Manifest::parse(PAYER).expect("payer");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let (_first, task) = proposed(&store, &payer).await;

    let provider = agentplane::testkit::FakeProvider::new();
    let restarted = plane(&store, &provider, DESK, &payer_b(), |b| b);
    restarted
        .decide_task(task.id, &Decision::approve(by("carol"), "settle it"), &[])
        .await
        .expect("the approval is recorded");
    restarted
        .replay(task.run, agentplane::runtime::Mode::Resume)
        .await
        .expect("resumes");

    let records = store.read(task.run, 1).await.unwrap();
    let refusal = records
        .iter()
        .find_map(|r| match r.kind() {
            agentplane::journal::RecordKind::EffectFailed {
                error, permanent, ..
            } => Some((error.clone(), *permanent)),
            _ => None,
        })
        .expect("the consultation was refused");
    let a = payer.digest().unwrap().to_string();
    let b = payer_b().digest().unwrap().to_string();
    assert!(
        refusal.0.contains(&a) && refusal.0.contains(&b) && refusal.1,
        "the refusal must be final and name the revision approved and the one that would run: {refusal:?}"
    );
    for (run, _) in store.recent_runs(None, 50).await.unwrap() {
        let first = store.read_page(run, 1, 1).await.unwrap();
        assert!(
            !matches!(
                first.first().map(agentplane::journal::Record::kind),
                Some(agentplane::journal::RecordKind::RunAdmitted { capability, .. })
                    if capability == "pay.execute"
            ),
            "the redeployed payer was consulted"
        );
    }
}

/// A coded skill that consults the payer pinned to a revision it was told.
#[derive(Debug)]
struct PinnedConsultation(agentplane::core::Digest);

#[async_trait::async_trait]
impl Skill for PinnedConsultation {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pinned").provides("desk.pinned")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let answer = cx
            .commission_pinned(
                "audit.note",
                Tainted::trusted(json!({ "note": "settled" })),
                self.0,
            )
            .await?;
        Ok(Outcome::done(answer))
    }
}

/// **A code-tier consultation pinned to an approved revision is refused when
/// another answers** — before any sub-run, as a refusal and not a doubt — and
/// dispatched when the pinned one does.
#[tokio::test]
async fn a_changed_callee_is_refused_after_approval() {
    let payer = Manifest::parse(PAYER).expect("payer");
    let auditor = Manifest::parse(AUDITOR).expect("auditor").digest().unwrap();
    let approved = payer.digest().unwrap();

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let provider = agentplane::testkit::FakeProvider::new();
    let rt = plane(&store, &provider, DESK, &payer, |b| {
        b.skill(PinnedConsultation(approved))
    });
    let out = rt
        .run("desk.pinned", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    let reason = match &out.status {
        RunStatus::Failed(reason) => reason.clone(),
        other => panic!("a pinned consultation of another revision was not refused: {other:?}"),
    };
    assert!(
        reason.contains(&approved.to_string()) && reason.contains(&auditor.to_string()),
        "the refusal must name the pinned revision and the one that answers: {reason}"
    );
    assert!(provider.asked().is_empty(), "the auditor ran");
    // Final and clean: nothing ran, so the refusal is not a doubt, and no
    // retry can change which revision answers.
    let failures: Vec<(agentplane::core::Disposition, bool)> = rt
        .journal()
        .read(out.run_id, 1)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| match r.kind() {
            agentplane::journal::RecordKind::EffectFailed {
                disposition,
                permanent,
                ..
            } => Some((*disposition, *permanent)),
            _ => None,
        })
        .collect();
    assert_eq!(
        failures,
        vec![(agentplane::core::Disposition::DidNotHappen, true)],
        "a pin refusal is one final, clean failure"
    );

    // Pinned to the revision that answers, the consultation goes ahead.
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_say("noted");
    let rt = plane(&store, &provider, DESK, &payer, |b| {
        b.skill(PinnedConsultation(auditor))
    });
    let out = rt
        .run("desk.pinned", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
}

/// A coded skill consulting an agent no declaration governs, under approval.
#[derive(Debug)]
struct Undeclared;

#[async_trait::async_trait]
impl Skill for Undeclared {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("undeclared").provides("coded.answer")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(Tainted::trusted(json!("answered"))))
    }
}

/// **A callee no declaration governs is said to be undeclared,** and nothing
/// about its reach is stated — the approval does not go silent about it.
#[tokio::test]
async fn an_undeclared_callee_is_named_as_such() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let desk = DESK.replace("pay.execute", "coded.answer");
    let (_rt, task) = proposed_by(
        &store,
        &desk,
        "agent__coded-answer",
        &Manifest::parse(PAYER).expect("payer"),
        |b| b.skill(Undeclared),
    )
    .await;
    let reach = task
        .justification
        .reach
        .expect("an undeclared callee is still named");
    assert_eq!(reach.capability, "coded.answer");
    assert!(reach.declaration.is_none(), "{reach:?}");
}

/// **A consultation already approved and run replays after its callee is
/// redeployed.** The reach the reviewer saw is read back from the journal,
/// never re-derived from the plane as it is now, so a later revision changes
/// nothing about a history already written.
#[tokio::test]
async fn a_finished_consultation_replays_after_its_callee_is_redeployed() {
    // A payer that answers without asking a person, so its sub-run finishes.
    let unattended = PAYER
        .replace(
            "  oversight:\n    approval: required\n    deadline: { name: refund-review, kind: hours, params: { n: 4 } }\n",
            "",
        )
        .replace("      requires_approval: true\n      description: Reverse a transfer.", "      description: Reverse a transfer.");
    let payer = Manifest::parse(&unattended).expect("payer");
    let payer_b = || {
        Manifest::parse(&unattended.replace(r#"version: "1.0.0""#, r#"version: "1.1.0""#))
            .expect("payer B")
    };
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "agent__pay-execute",
        json!({ "invoice": "INV-7" }),
    );
    let rt = plane(&store, &provider, DESK, &payer, |b| b);
    rt.run_correlated(
        "desk.settle",
        Tainted::trusted(json!({ "q": "settle INV-7" })),
        "settlement",
        &[key("INV-7")],
    )
    .await
    .expect("the run suspends on the approval");
    let task = store.queue(&[], 10).await.unwrap().pop().expect("a task");
    // The payer answers without a tool, and the desk closes the loop.
    provider.will_say("settled");
    provider.will_say("INV-7 is settled");
    rt.decide_task(task.id, &Decision::approve(by("carol"), "settle it"), &[])
        .await
        .expect("the approval is recorded");
    let done = rt
        .replay(task.run, agentplane::runtime::Mode::Resume)
        .await
        .expect("resumes");
    assert!(matches!(done.status, RunStatus::Succeeded), "{done:?}");

    let redeployed = plane(
        &store,
        &agentplane::testkit::FakeProvider::new(),
        DESK,
        &payer_b(),
        |b| b,
    );
    let replayed = redeployed
        .replay(task.run, agentplane::runtime::Mode::Strict)
        .await
        .expect("replays");
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "a redeployed callee rewrote a finished run's approval: {replayed:?}"
    );
}
