//! Human tasks and the sweeper.
//!
//! Oversight fails through *approval fatigue*, not refusal: a queue of proposals
//! nobody can evaluate becomes a queue of rubber stamps, and that is worse than
//! no oversight because it launders the decision. So the tests here care as much
//! about what a task *carries* as about whether the plumbing works.

#![cfg(feature = "turso")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{
    CaseStatus, CorrelationKey, DeadlineSpec, DeadlineState, Decision, Justification, OnExpiry,
    Outcome, Priority, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec, TaskState, Timestamp,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::TursoStore;
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
    store: Arc<TursoStore>,
    rt: Runtime,
}

async fn fixture(skill: ProposesRefund) -> Fixture {
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;

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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(skill).await;

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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;

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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let f = fixture(ProposesRefund::new(OnExpiry::Proceed)).await;
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
    let f = fixture(skill).await;

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
    let f = fixture(ProposesRefund::new(OnExpiry::Escalate)).await;
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

    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
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

    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
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
    let store = Arc::new(TursoStore::open_in_memory().await.unwrap());
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
    let f = fixture(ProposesRefund::new(OnExpiry::Deny)).await;
    f.rt.run_in_case("demo.refund", json!({}), "dispute", &[key("INV-15")])
        .await
        .unwrap();
    let task = f.store.queue(&officer(), 10).await.unwrap().pop().unwrap();

    let d = Decision::approve("alice", "ok");
    f.rt.decide_task(task.id, &d, &officer()).await.unwrap();

    let again = f.rt.answer_task(task.id, &d).await.unwrap();
    assert_eq!(again, agentplane::core::Delivery::Duplicate);
}
