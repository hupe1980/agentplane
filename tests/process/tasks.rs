//! Human tasks and the sweeper.
//!
//! Oversight fails through *approval fatigue*, not refusal: a queue of proposals
//! nobody can evaluate becomes a queue of rubber stamps, and that is worse than
//! no oversight because it launders the decision. So the tests here care as much
//! about what a task *carries* as about whether the plumbing works.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    CaseStatus, CorrelationKey, DeadlineSpec, DeadlineState, Decision, Justification, OnExpiry,
    Outcome, Priority, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec, TaskState, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

fn key(v: &str) -> CorrelationKey {
    CorrelationKey::new("document", v)
}

/// Proposes a refund and waits for a human.
#[derive(Debug)]
struct ProposesRefund {
    on_expiry: OnExpiry,
    allow_unattended: bool,
    exclude: Option<&'static str>,
}

impl ProposesRefund {
    fn new(on_expiry: OnExpiry) -> Self {
        Self {
            on_expiry,
            allow_unattended: false,
            exclude: None,
        }
    }
}

#[async_trait::async_trait]
impl Skill for ProposesRefund {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("proposes-refund").provides("demo.refund")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("approval", &DeadlineSpec::days(2), None)
            .await?;

        let justification = Justification::new(
            "invoice disputed; deviation exceeds the 20% threshold",
            json!({ "action": "refund", "amount_eur": 4200 }),
        )
        .confidence(0.62)
        .cost("€4,200")
        .evidence("meter reading is 35% above the twelve-month mean")
        .evidence("no correction was filed by the counterparty");

        let mut spec = TaskSpec::new("refund-approval", justification, "approval")
            .role("compliance-officer")
            .priority(Priority::High)
            .on_expiry(self.on_expiry);

        if let Some(a) = self.exclude {
            spec = spec.excluding(a);
        }
        if self.allow_unattended {
            spec = spec.allow_unattended();
        }

        let decision = cx.task(&spec).await?;

        Ok(Outcome::done(Tainted::trusted(json!({
            "approved": decision.approved,
            "by": decision.actor,
        }))))
    }
}

struct Fixture {
    store: Arc<RedbStore>,
    rt: Arc<Runtime>,
}

fn fixture(skill: ProposesRefund) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .skill(skill)
        .build();
    Fixture { store, rt }
}

fn officer() -> Vec<String> {
    vec!["compliance-officer".to_owned()]
}

// ── The queue ───────────────────────────────────────────────────────────────

/// A run that needs a human suspends, and the proposal lands in a queue.
#[tokio::test]
async fn a_run_awaiting_a_human_suspends_and_queues_a_task() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));

    let out =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-1")])
            .await
            .unwrap();
    assert!(out.status.is_suspended(), "got {:?}", out.status);

    let queue = f.store.queue(&officer(), 10).await.unwrap();
    assert_eq!(queue.len(), 1);
    let task = &queue[0];
    assert_eq!(task.state, TaskState::Open);
    assert_eq!(task.priority, Priority::High);
    assert!(
        task.due_at.is_some(),
        "the reviewer inherits the case's window"
    );
}

/// **The control against approval fatigue.**
///
/// A task carries what a reviewer needs in order to *disagree*: the action
/// itself, the confidence behind it, what it costs, and the evidence. An
/// approval you cannot evaluate is not a control.
#[tokio::test]
async fn a_task_carries_what_a_reviewer_needs_to_disagree() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-2")])
        .await
        .unwrap();

    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();
    let j = &task.justification;

    assert!(j.summary.contains("deviation"), "the reviewer sees why");
    assert_eq!(
        j.proposed_action,
        json!({ "action": "refund", "amount_eur": 4200 }),
        "the reviewer sees what will happen, not a description of it"
    );
    assert_eq!(
        j.confidence,
        Some(0.62),
        "a confident-sounding proposal is not evidence"
    );
    assert_eq!(j.cost.as_deref(), Some("€4,200"));
    assert_eq!(
        j.evidence.len(),
        2,
        "the trail behind the proposal travels with it"
    );
}

/// A decision resumes the run and is recorded with the name of whoever made it.
#[tokio::test]
async fn a_decision_resumes_the_run_and_names_the_decider() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    let out =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-3")])
            .await
            .unwrap();

    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();
    f.rt.decide_task(
        task.id,
        &Decision::approve("alice", "reading confirmed by the field team"),
        &officer(),
    )
    .await
    .unwrap();

    let finished = f.store.read(out.run_id, 1).await.unwrap();
    assert!(
        finished
            .iter()
            .any(|r| r.kind().kind_str() == "StepFinished"),
        "the run must complete once the decision lands"
    );
    assert_eq!(
        f.store.task(task.id).await.unwrap().unwrap().state,
        TaskState::Completed
    );
}

/// **Four eyes.** Whoever proposed an action does not get to approve it.
///
/// Without an enforced exclusion, dual control is a naming convention.
#[tokio::test]
async fn the_proposer_may_not_approve_their_own_proposal() {
    let mut skill = ProposesRefund::new(OnExpiry::Deny);
    skill.exclude = Some("alice");
    let f = fixture(skill);

    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-4")])
        .await
        .unwrap();
    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();

    let err =
        f.rt.decide_task(
            task.id,
            &Decision::approve("alice", "looks fine to me"),
            &officer(),
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("may not also decide"),
        "the refusal must name the reason, got: {err}"
    );

    // A different person can.
    f.rt.decide_task(
        task.id,
        &Decision::approve("bob", "independently verified"),
        &officer(),
    )
    .await
    .unwrap();
}

/// Role eligibility is enforced, and the refusal says which check failed.
#[tokio::test]
async fn a_reviewer_without_the_role_is_refused() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-5")])
        .await
        .unwrap();
    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();

    let err =
        f.rt.decide_task(
            task.id,
            &Decision::approve("carol", "sure"),
            &["intern".to_owned()],
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("role"), "got: {err}");
}

/// Two reviewers cannot both hold one task.
#[tokio::test]
async fn a_task_is_claimed_by_exactly_one_reviewer() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-6")])
        .await
        .unwrap();
    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();

    f.store.claim(task.id, "alice", &officer()).await.unwrap();
    let err = f.store.claim(task.id, "bob", &officer()).await.unwrap_err();
    assert!(err.to_string().contains("alice"), "got: {err}");

    // Releasing puts it back on the queue.
    f.store.release(task.id, "alice").await.unwrap();
    f.store.claim(task.id, "bob", &officer()).await.unwrap();
}

/// The queue only shows work the claim would actually permit.
#[tokio::test]
async fn the_queue_respects_roles() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-7")])
        .await
        .unwrap();

    assert_eq!(f.store.queue(&officer(), 10).await.unwrap().len(), 1);
    assert!(
        f.store
            .queue(&["intern".to_owned()], 10)
            .await
            .unwrap()
            .is_empty(),
        "showing work that cannot be claimed wastes a reviewer's attention"
    );
}

/// **Two runs of one plan are two decisions.**
///
/// The bug this pins was not exotic. A task id was derived from the awaiting
/// effect's key, which is unique *within a run* — the journal enforces
/// `(run, effect_key)` and needs nothing more. The worklist is a table shared by
/// every run, and two runs of one plan reach the same step, at the same ordinal,
/// with the same descriptor, and derive the same key.
///
/// `TaskStore::open` is idempotent by id, so the second run's task was silently
/// not created. One proposal appeared, carrying the *first* run's amount; the
/// second run waited for an answer nobody would ever be shown. Two refunds
/// became one approval and nothing reported a problem.
///
/// The amounts differ here on purpose: identical justifications would let a
/// collision look like correct deduplication.
#[tokio::test]
async fn two_runs_of_one_plan_do_not_share_one_task() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));

    let a =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-8")])
            .await
            .unwrap();
    let b =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-9")])
            .await
            .unwrap();
    assert!(a.status.is_suspended());
    assert!(b.status.is_suspended());

    let queued = f.store.queue(&officer(), 10).await.unwrap();
    assert_eq!(
        queued.len(),
        2,
        "two independent runs collapsed into one decision — the second run is \
         waiting for an answer to a proposal nobody will ever see"
    );

    let runs: Vec<_> = queued.iter().map(|t| t.run).collect();
    assert!(
        runs.contains(&a.run_id) && runs.contains(&b.run_id),
        "the worklist does not name both runs: {runs:?}"
    );

    // And deciding one does not decide the other.
    let first = queued[0].id;
    f.rt.decide_task(first, &Decision::approve("bob", "checked"), &officer())
        .await
        .unwrap();

    let still_open = f.store.queue(&officer(), 10).await.unwrap();
    assert_eq!(
        still_open.len(),
        1,
        "one decision answered both proposals: {still_open:?}"
    );
}

// ── Expiry ──────────────────────────────────────────────────────────────────

/// **What happens when nobody answers is declared up front, not decided in the
/// moment.** The safe default refuses.
#[tokio::test]
async fn an_unanswered_task_denies_by_default() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    let out =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-8")])
            .await
            .unwrap();
    assert!(out.status.is_suspended());

    // Long after the window closed.
    let later = Timestamp::now_utc() + time::Duration::days(30);
    let report = f.rt.sweep(later, time::Duration::days(365)).await.unwrap();

    assert_eq!(report.tasks_expired, 1);
    assert!(
        report.needs_attention(),
        "an unanswered approval is not routine"
    );

    // The run resumed with a refusal rather than hanging.
    let finished = f.store.read(out.run_id, 1).await.unwrap();
    assert!(
        finished
            .iter()
            .any(|r| r.kind().kind_str() == "StepFinished"),
        "the run must not be left hanging"
    );
}

/// Acting unattended requires an explicit, separate opt-in.
#[tokio::test]
async fn proceeding_unattended_requires_explicit_consent() {
    // `OnExpiry::Proceed` without `allow_unattended()`.
    let f = fixture(ProposesRefund::new(OnExpiry::Proceed));
    let out =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-9")])
            .await
            .unwrap();

    match out.status {
        RunStatus::Failed(msg) => assert!(
            msg.contains("allow_unattended"),
            "the refusal must name the missing opt-in, got: {msg}"
        ),
        other => panic!("unattended action must not be available by accident: {other:?}"),
    }
}

/// With consent, an unanswered task proceeds — and the record says who did.
#[tokio::test]
async fn a_pre_authorised_task_proceeds_unattended() {
    let mut skill = ProposesRefund::new(OnExpiry::Proceed);
    skill.allow_unattended = true;
    let f = fixture(skill);

    let out =
        f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-10")])
            .await
            .unwrap();
    assert!(out.status.is_suspended());

    let later = Timestamp::now_utc() + time::Duration::days(30);
    f.rt.sweep(later, time::Duration::days(365)).await.unwrap();

    let done =
        f.rt.replay(out.run_id, agentplane::runtime::Mode::Strict)
            .await;
    assert!(
        done.is_ok(),
        "the run resumed with the pre-authorised answer"
    );
}

/// Escalation widens the audience and keeps waiting, and is idempotent so the
/// sweep is safe on a timer.
#[tokio::test]
async fn an_escalating_task_is_escalated_once() {
    let f = fixture(ProposesRefund::new(OnExpiry::Escalate));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-11")])
        .await
        .unwrap();

    let later = Timestamp::now_utc() + time::Duration::days(30);
    let first = f.rt.sweep(later, time::Duration::days(365)).await.unwrap();
    assert_eq!(first.tasks_escalated, 1);

    let second = f.rt.sweep(later, time::Duration::days(365)).await.unwrap();
    assert_eq!(second.tasks_escalated, 0, "escalating twice is a no-op");

    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();
    assert_eq!(task.state, TaskState::Escalated);
    assert!(task.state.is_pending(), "escalation keeps it actionable");
}

// ── Deadline breach ─────────────────────────────────────────────────────────

/// **A breached obligation stops being silent.**
///
/// This is the whole reason the sweeper exists: a missed regulatory window that
/// nothing announced is indistinguishable, from outside, from one that was met.
#[tokio::test]
async fn a_breached_obligation_escalates_the_case() {
    #[derive(Debug)]
    struct JustObliges;

    #[async_trait::async_trait]
    impl Skill for JustObliges {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("obliges").provides("demo.obliges")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline(
                "acknowledgement",
                &DeadlineSpec::days(5),
                Some(time::Duration::days(1)),
            )
            .await?;
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(JustObliges)
        .build();

    rt.run_in_case("demo.obliges", json!({}), "matter", &[key("INV-12")])
        .await
        .unwrap();

    let case_id = store.correlate(&[key("INV-12")]).await.unwrap().unwrap();
    assert_eq!(
        store.deadlines(case_id).await.unwrap()[0].state,
        DeadlineState::Pending
    );

    // A day in: the warning threshold has passed but the window has not.
    let warn_time = Timestamp::now_utc() + time::Duration::days(4) + time::Duration::hours(12);
    let warned = rt
        .sweep(warn_time, time::Duration::days(365))
        .await
        .unwrap();
    assert_eq!(warned.warned, 1);
    assert_eq!(warned.breached, 0, "a warning is not a breach");
    assert_eq!(
        store.deadlines(case_id).await.unwrap()[0].state,
        DeadlineState::Warned
    );

    // Past the window with the obligation unmet.
    let after = Timestamp::now_utc() + time::Duration::days(30);
    let breached = rt.sweep(after, time::Duration::days(365)).await.unwrap();
    assert_eq!(breached.breached, 1);
    assert!(breached.needs_attention());

    assert_eq!(
        store.deadlines(case_id).await.unwrap()[0].state,
        DeadlineState::Breached
    );
    assert_eq!(
        store.case(case_id).await.unwrap().unwrap().status,
        CaseStatus::Escalated,
        "the matter itself must be escalated, not just the row"
    );
}

/// A satisfied obligation is never breached, however late the sweep runs.
#[tokio::test]
async fn a_met_obligation_is_not_breached() {
    #[derive(Debug)]
    struct MeetsIt;

    #[async_trait::async_trait]
    impl Skill for MeetsIt {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("meets").provides("demo.meets")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("ack", &DeadlineSpec::days(1), None).await?;
            cx.meet_deadline("ack").await?;
            Ok(Outcome::done(input))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .skill(MeetsIt)
        .build();

    rt.run_in_case("demo.meets", json!({}), "matter", &[key("INV-13")])
        .await
        .unwrap();

    let report = rt
        .sweep(
            Timestamp::now_utc() + time::Duration::days(365),
            time::Duration::days(365),
        )
        .await
        .unwrap();
    assert_eq!(report.breached, 0);
    assert!(report.is_quiet(), "a met obligation generates no noise");
}

/// A sweep on a healthy plane is silent — so a non-silent one means something.
#[tokio::test]
async fn a_quiet_plane_sweeps_quietly() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    let report =
        f.rt.sweep(Timestamp::now_utc(), time::Duration::days(365))
            .await
            .unwrap();
    assert!(report.is_quiet());
    assert!(!report.needs_attention());
}

/// Human tasks need a task store, and saying so beats hanging forever.
#[tokio::test]
async fn tasks_without_a_task_store_are_refused() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .skill(ProposesRefund::new(OnExpiry::Deny))
        .build();

    let out = rt
        .run_in_case("demo.refund", json!({}), "dispute", &[key("INV-14")])
        .await
        .unwrap();
    match out.status {
        RunStatus::Failed(msg) => assert!(msg.contains("task store"), "got: {msg}"),
        other => panic!("expected an actionable refusal, got {other:?}"),
    }
}

/// A second submission of the same decision is a duplicate, not a second answer.
#[tokio::test]
async fn a_resubmitted_decision_is_a_duplicate() {
    let f = fixture(ProposesRefund::new(OnExpiry::Deny));
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-15")])
        .await
        .unwrap();
    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();

    let d = Decision::approve("alice", "ok");
    f.rt.decide_task(task.id, &d, &officer()).await.unwrap();

    let again = f.rt.answer_task(task.id, &d).await.unwrap();
    assert_eq!(again, agentplane::core::Delivery::Duplicate);
}

// ── Declarative oversight ───────────────────────────────────────────────────
//
// Two defects lived here, and both were invisible because every test in this
// repository approved. `Decision::reject` had no caller at all.

#[cfg(all(feature = "manifest", feature = "testkit"))]
fn overseen_agent(kind: &str, tools: &str) -> agentplane::manifest::Manifest {
    let mut manifest = agentplane::manifest::Manifest::parse(&format!(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: overseen, version: "1.0.0" }}
spec:
  capabilities: {{ provides: [overseen.answer] }}
  models: {{ privileged: {{ provider: fake, model: m-1 }} }}
  execution: {{ kind: {kind} }}
  oversight:
    approval: required
    deadline: {{ name: review, kind: hours, params: {{ n: 4 }} }}
{tools}
  memory_formation:
    subject: team/support
    purpose: learned-facts
    instruction: Extract stable facts only.
    max_items: 2
    max_sensitivity: confidential
  budgets: {{}}
"#
    ))
    .expect("manifest");
    manifest.spec.security.max_sensitivity_egress =
        Some(agentplane::core::Sensitivity::Confidential);
    manifest
}

/// A rejected answer does not become a durable memory.
///
/// The defect this pins: memories were formed **before** the human decided, so
/// `oversight.approval: required` refused the answer as a return value while the
/// same answer had already been written into the agent's own memory — which a
/// later run reads into its context window as established fact. A reviewer's
/// refusal accomplished nothing except failing the run that produced it.
///
/// Memory is delayed code. A control that governs the reply and not the write
/// governs the less important half.
#[cfg(all(feature = "manifest", feature = "testkit"))]
#[tokio::test]
async fn a_refused_answer_is_not_written_into_memory() {
    use agentplane::memory::{MemoryStore, Recall};
    use agentplane::runtime::Agent;

    let manifest = overseen_agent("completion", "");
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_say("the customer speaks German");
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .memory(Arc::clone(&store) as Arc<dyn MemoryStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn agentplane::case::EventStore>)
        .tasks(Arc::clone(&store) as Arc<dyn agentplane::case::TaskStore>)
        .provider(
            "fake",
            Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .build();

    rt.run_in_case(
        "overseen.answer",
        json!({ "q": "x" }),
        "review",
        &[key("doc-1")],
    )
    .await
    .expect("the run suspends on the task");

    // Nothing is formed while a decision is outstanding, either.
    assert!(
        store
            .recall(&Recall::about("team/support"))
            .await
            .unwrap()
            .is_empty(),
        "a memory was formed while the answer was still awaiting a human"
    );

    let task = store.queue(&officer(), 10).await.unwrap().pop().unwrap();
    rt.decide_task(
        task.id,
        &Decision::reject("carol", "that is not what the customer said"),
        &officer(),
    )
    .await
    .expect("the rejection is recorded");

    assert!(
        store
            .recall(&Recall::about("team/support"))
            .await
            .unwrap()
            .is_empty(),
        "the answer a human refused was written into durable memory anyway, \
         where a later run reads it as established fact"
    );
}

/// A `tool-calling` agent reaches oversight too.
///
/// It did not, and nothing said so: `oversight` parsed, the plane built, the run
/// completed, and no human was ever asked. That is a declared control the
/// runtime silently did not apply — on the execution kind that most needs it,
/// since a tool-calling agent has already touched the world by the time it
/// answers.
#[cfg(all(feature = "manifest", feature = "testkit"))]
#[tokio::test]
async fn a_tool_calling_agent_still_asks_a_human() {
    use agentplane::memory::MemoryStore;
    use agentplane::runtime::Agent;
    use agentplane::tools::{Tool, ToolBox, ToolFailure};

    /// Read a ledger account's balance.
    #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
    struct ReadBalance {
        /// The account to read.
        account: String,
    }

    #[async_trait::async_trait]
    impl Tool for ReadBalance {
        const SERVER: &'static str = "ledger";
        const NAME: &'static str = "read";
        fn mutates() -> bool {
            false
        }
        async fn call(self) -> Result<Value, ToolFailure> {
            Ok(json!({ "account": self.account, "balance": 42 }))
        }
    }

    let manifest = overseen_agent(
        "tool-calling",
        "  tools:\n    - ref: tool://ledger/read\n      mutates: false\n      \
         description: Read a ledger account's balance.",
    );
    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__read", json!({ "account": "AC-1" }));
    provider.will_say("AC-1 holds 42.");

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .memory(Arc::clone(&store) as Arc<dyn MemoryStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn agentplane::case::EventStore>)
        .tasks(Arc::clone(&store) as Arc<dyn agentplane::case::TaskStore>)
        .provider(
            "fake",
            Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .toolbox(ToolBox::new().with::<ReadBalance>())
        .build();

    rt.run_in_case(
        "overseen.answer",
        json!({ "q": "AC-1?" }),
        "review",
        &[key("doc-2")],
    )
    .await
    .expect("the run suspends on the task");

    let waiting = store.queue(&officer(), 10).await.unwrap();
    assert_eq!(
        waiting.len(),
        1,
        "a tool-calling agent declaring oversight returned without asking anyone"
    );
}

/// A withdrawn obligation stops blocking the case it was on.
///
/// `cancel_deadline` is the third of the three obligation transitions and the
/// only one nothing exercised — `deadline` and `meet_deadline` both had tests,
/// so the lifecycle looked covered. It is the transition that matters when a
/// matter goes away: a case cannot close while an obligation is open, so an
/// obligation that can be registered and met but not *withdrawn* leaves every
/// no-longer-applicable case permanently unclosable.
#[tokio::test]
async fn a_cancelled_obligation_no_longer_blocks_closing_the_case() {
    #[derive(Debug)]
    struct Withdraws;

    #[async_trait::async_trait]
    impl Skill for Withdraws {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("withdraws").provides("demo.withdraw")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("dispute-window", &DeadlineSpec::days(5), None)
                .await?;
            cx.cancel_deadline("dispute-window").await?;
            Ok(Outcome::done(Tainted::trusted(json!({}))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .skill(Withdraws)
        .build();

    let out = rt
        .run_in_case("demo.withdraw", json!({}), "dispute", &[key("INV-9")])
        .await
        .unwrap();
    assert_eq!(out.status, RunStatus::Succeeded);

    let case = store
        .correlate(&[key("INV-9")])
        .await
        .unwrap()
        .expect("the case exists");
    let deadline = store
        .deadlines(case)
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.name == "dispute-window")
        .expect("the obligation is still on the record");
    assert_eq!(
        deadline.state,
        DeadlineState::Cancelled,
        "a withdrawn obligation must be recorded as cancelled, not deleted — \
         the case's history has to say it was withdrawn rather than never set"
    );

    store
        .close(case)
        .await
        .expect("a case with no open obligation closes");
}

/// A high-impact call waits for a person, and the person sees the call.
///
/// The gap this closes: oversight gated the agent's **answer**, which for a
/// tool-calling agent is a review that arrives after the money moved. The tool
/// ran several turns earlier, so a reviewer refusing then was refusing a summary
/// of something that had already happened.
///
/// Both halves are checked, because only one of them is the interesting one:
/// the world must be untouched while the task is outstanding, and the task must
/// carry the **exact tool and arguments** rather than a description of them.
#[cfg(all(feature = "manifest", feature = "testkit"))]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_call_needing_approval_does_not_happen_until_it_is_approved() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use agentplane::runtime::Agent;
    use agentplane::tools::{Tool, ToolBox, ToolFailure};

    static POSTED: AtomicUsize = AtomicUsize::new(0);

    /// Move funds between accounts.
    #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
    struct Transfer {
        /// Where the money goes.
        recipient: String,
        /// How much, in minor units.
        amount: i64,
    }

    #[async_trait::async_trait]
    impl Tool for Transfer {
        const SERVER: &'static str = "ledger";
        const NAME: &'static str = "transfer";
        async fn call(self) -> Result<Value, ToolFailure> {
            POSTED.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "moved": self.amount, "to": self.recipient }))
        }
    }

    let manifest = agentplane::manifest::Manifest::parse(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  capabilities: { provides: [desk.pay] }
  models: { privileged: { provider: fake, model: m-1 } }
  execution: { kind: tool-calling, max_turns: 4 }
  oversight:
    # Only the call waits. The answer returns unattended, which is the shape
    # most deployments actually want.
    approval: tools-only
    deadline: { name: payment-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      description: Move funds between accounts.
      requires_approval: true
      # The model may choose these, within a ceiling. Declaring them is what
      # lifts the blanket refusal a mutating tool otherwise applies to untrusted
      # arguments — and the human gate below is a second, independent control.
      protected_fields:
        - path: /recipient
          max_sensitivity: internal
        - path: /amount
          max_sensitivity: internal
  budgets: {}
"#,
    )
    .expect("manifest");

    let provider = agentplane::testkit::FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "ledger__transfer",
        json!({ "recipient": "AC-9", "amount": 250_000 }),
    );
    provider.will_say("done");

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .tasks(Arc::clone(&store) as Arc<dyn TaskStore>)
        .provider(
            "fake",
            Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .toolbox(ToolBox::new().with::<Transfer>())
        .build();

    rt.run_in_case(
        "desk.pay",
        json!({ "q": "pay AC-9" }),
        "payment",
        &[key("PAY-1")],
    )
    .await
    .expect("the run suspends on the approval");

    assert_eq!(
        POSTED.load(Ordering::SeqCst),
        0,
        "the transfer happened before anyone approved it"
    );

    let task = store.queue(&officer(), 10).await.unwrap().pop().unwrap();
    let shown = &task.justification.proposed_action;
    assert_eq!(
        shown["tool"], "tool://ledger/transfer",
        "the reviewer was not shown which tool would run: {shown}"
    );
    assert_eq!(
        shown["arguments"]["amount"], 250_000,
        "the reviewer was not shown the exact arguments: {shown}"
    );
    // The summary must describe what is *actually* being approved. A tool
    // approval that says "approve this agent's answer" tells the reviewer they
    // are vetting a reply while the thing in front of them is a call that will
    // move money — the exact conflation `oversight.approval: tools-only`
    // exists to prevent.
    assert!(
        task.justification
            .summary
            .contains("tool://ledger/transfer"),
        "the reviewer is told what they are approving by the summary, and it \
         does not name the call: {:?}",
        task.justification.summary
    );

    rt.decide_task(
        task.id,
        &Decision::reject("carol", "that account is not on the settlement list"),
        &officer(),
    )
    .await
    .expect("the rejection is recorded");

    assert_eq!(
        POSTED.load(Ordering::SeqCst),
        0,
        "a refused call was dispatched anyway"
    );
}

/// A deadline transition journals the state it moved **from**, for that deadline.
///
/// `meet_deadline` and `cancel_deadline` both discard the prior state, so it
/// looks dead — but the effect's output is journaled, which is what lets an
/// auditor read *this obligation was Pending when it was met* rather than only
/// that it is Met now. Nothing tested it: a mutation flipping the lookup from
/// `d.name == name` to `!=` — picking some **other** deadline's state — survived
/// the whole suite.
///
/// Two obligations on one case, in different states, so the wrong lookup gives a
/// visibly wrong answer. With one deadline the mutation is unobservable, which
/// is exactly the fixture mistake that let it survive.
#[tokio::test]
async fn a_deadline_transition_records_the_state_that_deadline_moved_from() {
    use agentplane::core::DeadlineState;

    #[derive(Debug)]
    struct TwoWindows;

    #[async_trait::async_trait]
    impl Skill for TwoWindows {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("two-windows").provides("demo.windows")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            cx.deadline("first", &DeadlineSpec::days(1), None).await?;
            cx.deadline("second", &DeadlineSpec::days(2), None).await?;
            // Move `first` out of Pending, so the two differ.
            cx.cancel_deadline("first").await?;
            // Now meet `second`: its prior state must be Pending, not
            // `first`'s Cancelled.
            cx.meet_deadline("second").await?;
            Ok(Outcome::done(Tainted::trusted(json!({}))))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .cases(store.clone() as Arc<dyn CaseStore>)
        .events(store.clone() as Arc<dyn EventStore>)
        .tasks(store.clone() as Arc<dyn TaskStore>)
        .skill(TwoWindows)
        .build();

    let out = rt
        .run_in_case("demo.windows", json!({}), "windows", &[key("W-1")])
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);

    // The journaled outputs of the two transitions, in order.
    let records = store.read(out.run_id, 1).await.expect("read");
    // `EffectDone` carries the output; the *kind* is on the `EffectStarted`
    // that precedes it, so walk in order and attribute each completion to the
    // announcement it answers.
    let mut priors: Vec<DeadlineState> = Vec::new();
    let mut pending_kind: Option<String> = None;
    for record in &records {
        match record.kind() {
            RecordKind::EffectStarted { descriptor, .. } => {
                pending_kind = Some(descriptor.kind.clone());
            }
            RecordKind::EffectDone { output, .. } => {
                if pending_kind.as_deref() == Some("case.transition_deadline")
                    && let Ok(state) = serde_json::from_value::<DeadlineState>(output.clone())
                {
                    priors.push(state);
                }
                pending_kind = None;
            }
            _ => {}
        }
    }

    assert_eq!(
        priors,
        vec![DeadlineState::Pending, DeadlineState::Pending],
        "each transition must record the prior state of *its own* obligation; \
         reading another's makes the journal say a deadline moved from a state \
         it was never in"
    );

    let deadlines = store
        .deadlines(
            store
                .correlate(&[key("W-1")])
                .await
                .expect("correlate")
                .expect("case"),
        )
        .await
        .expect("deadlines");
    let state = |name: &str| {
        deadlines
            .iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("no deadline {name}"))
            .state
    };
    assert_eq!(state("first"), DeadlineState::Cancelled);
    assert_eq!(state("second"), DeadlineState::Met);
}
