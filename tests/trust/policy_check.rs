//! A policy verdict re-derived from the export.
//!
//! The record claims a permit's inputs are on it. These tests hold that claim
//! to what the gate was actually asked: a recording engine captures every live
//! request, the run is exported, and the offline check must rebuild exactly
//! those requests from the file — through the same builders the gates call.
//! A request the check cannot rebuild must be reported as such, never read as
//! agreement.

#![cfg(all(feature = "cedar", feature = "redb", feature = "manifest"))]
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use agentplane::core::{
    ACTION_ADMIT, ACTION_DECLARED, ACTION_PERFORM, ACTION_RELEASE, Delegation, Digest, Effect,
    EffectDescriptor, EffectError, EffectKey, GroupOutcome, Label, Outcome, Phase, PlanIR,
    PlanNode, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Principal,
    Recovery, Release, ReleaseScope, RetryPolicy, RunId, Scope, Skill, SkillDescriptor, SkillError,
    SourceId, StepId, Tainted,
};
use agentplane::journal::{Append, JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::policy::CedarEngine;
use agentplane::policy::check::{Check, Mode, TenantSource, Unevaluable, Verdict};
use agentplane::runtime::{Agent, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

const TENANT: &str = "default";

// ── Engines ─────────────────────────────────────────────────────────────────

/// Delegates to Cedar and keeps every request it was asked.
#[derive(Debug)]
struct Recording {
    inner: CedarEngine,
    asked: Mutex<Vec<String>>,
}

impl Recording {
    fn new(rules: &str) -> Arc<Self> {
        Arc::new(Self {
            inner: CedarEngine::new(rules).expect("rules"),
            asked: Mutex::default(),
        })
    }
}

/// One request, spelled so two can be compared whole — canonically, because
/// a live context holds its keys in the order they were inserted and one read
/// back from the record holds them sorted, and neither order is part of the
/// question.
fn spelled(principal: &str, action: &str, resource: &str, context: &Value) -> String {
    String::from_utf8(agentplane::core::canon::value_bytes(&json!([
        principal, action, resource, context
    ])))
    .expect("canonical bytes are UTF-8")
}

impl PolicyEngine for Recording {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        self.asked
            .lock()
            .unwrap()
            .push(spelled(r.principal, r.action, r.resource, r.context));
        self.inner.authorize(r)
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        self.inner.bundle()
    }
}

/// Refuses the effect kinds it names and permits everything else, under one
/// identity whatever it refuses.
///
/// Stands for the case the check exists to find: the record says a call was
/// permitted, and the bundle the run names says it is not.
#[derive(Debug)]
struct Refuses(&'static [&'static str]);

impl PolicyEngine for Refuses {
    fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
        if r.action == ACTION_PERFORM && self.0.contains(&r.resource) {
            PolicyDecision::deny(format!("rule `no-{}` forbids it", r.resource))
        } else {
            PolicyDecision::Permit
        }
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"refuses"), "agentplane-test/check-v1")
    }
}

const PERMIT_ALL: &str = "permit(principal, action, resource);";

const FORBID_TRANSFER: &str = r#"permit(principal, action, resource);
@id("no-transfer") forbid(principal, action == Action::"effect:perform", resource == Resource::"ledger.transfer");"#;

// ── The corpus ──────────────────────────────────────────────────────────────

/// A plain effect of the kind named.
#[derive(Debug)]
struct Touch(&'static str);

#[async_trait::async_trait]
impl Effect for Touch {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(self.0, json!({ "account": "AC-1" }))
    }
    fn mutates(&self) -> bool {
        false
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "did": self.0 }))
    }
}

/// A tool call whose catalogue entry says it only reads, under a grant that
/// declares it mutating.
#[derive(Debug)]
struct ReadsPerTheCatalogue;

#[async_trait::async_trait]
impl Effect for ReadsPerTheCatalogue {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "tool.call",
            json!({
                "server": "ledger",
                "tool": "read",
                "arguments": { "account": "AC-1" },
                "protected_fields": [],
            }),
        )
    }
    fn mutates(&self) -> bool {
        false
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "balance": 42 }))
    }
}

/// A sink that binds a labelled value.
#[derive(Debug)]
struct Posts(Value);

#[async_trait::async_trait]
impl Effect for Posts {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.post_entry", self.0.clone())
    }
    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.0)
    }
    fn max_sensitivity(&self) -> agentplane::core::Sensitivity {
        agentplane::core::Sensitivity::Internal
    }
    fn mutates(&self) -> bool {
        false
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "posted": true }))
    }
}

/// Every shape a gate asks: a plain effect, a grant-widened tool call, a
/// labelled sink and a release.
#[derive(Debug)]
struct Corpus;

#[async_trait::async_trait]
impl Skill for Corpus {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("corpus")
            .provides("corpus.run")
            .provides("corpus.next")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Touch("ledger.read")).await?;
        cx.effect(ReadsPerTheCatalogue).await?;
        let memo = Tainted::from_source(json!({ "memo": "close" }), SourceId::new("peer:broker"));
        cx.sink(Posts(memo.peek().clone()), &memo).await?;
        let released = cx
            .release(
                Tainted::from_source(json!({ "account": "customer" }), SourceId::new("crm")),
                Release::whole(
                    ReleaseScope::trust(),
                    "reviewed against the settlement record",
                    "run.output",
                    ["review:SET-42"],
                ),
            )
            .await?;
        Ok(Outcome::done(released))
    }
}

const CORPUS: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: corpus, version: "1.0.0" }
spec:
  capabilities: { provides: [corpus.run, corpus.next] }
  tools:
    - ref: tool://ledger/read
      mutates: true
      description: Read a balance.
  budgets: {}
"#;

/// Two steps of one skill, so the second runs under a capability that is not
/// the admitted one and must still be asked under the admitted principal.
fn two_steps() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "corpus.run").arg("input", agentplane::core::ArgSource::run_input()),
        PlanNode::new(1, "corpus.next")
            .arg("previous", agentplane::core::ArgSource::node(StepId(0)))
            .terminal(),
    ])
}

fn chain() -> Delegation {
    Delegation::root(Principal::new("user:auditor", Scope::root()))
        .delegate(Principal::new("agent:corpus", Scope::of(["corpus.*"])))
        .expect("narrows")
}

fn plane(
    store: &Arc<RedbStore>,
    engine: Arc<dyn PolicyEngine>,
    acting_as: Option<Delegation>,
) -> Arc<Runtime> {
    let manifest = Manifest::parse(CORPUS).expect("manifest");
    let mut b = Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .owner("policy-check")
        .policy(engine)
        .agent(Agent::new(&manifest).skill(Corpus));
    if let Some(chain) = acting_as {
        b = b.acting_as(chain);
    }
    b.build()
}

async fn export(store: &Arc<RedbStore>, runs: &[RunId]) -> Vec<u8> {
    let journal = Arc::clone(store) as Arc<dyn JournalStore>;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&journal, None, runs, &mut out)
        .await
        .expect("export");
    out
}

fn check() -> Check<'static> {
    Check::new(TENANT, TenantSource::Supplied)
}

// ── One builder ─────────────────────────────────────────────────────────────

/// **The request rebuilt from the export is the request the gate was asked.**
///
/// The whole claim of the record, as one equality. A key a gate adds after
/// the shared builder, a `mutates` the record keeps from the effect instead of
/// the gate, a principal a plan step derives differently — each makes a
/// captured request with no rebuilt twin, and the offline verdict would then
/// be about a question nobody asked.
#[tokio::test]
async fn a_rebuilt_request_equals_the_one_the_gate_was_asked() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let engine = Recording::new(PERMIT_ALL);

    let chainless = plane(&store, engine.clone(), None)
        .run_plan(two_steps(), Tainted::trusted(json!({ "ticket": "T-1" })))
        .await
        .unwrap();
    assert_eq!(chainless.status, RunStatus::Succeeded, "{chainless:?}");
    let chained = plane(&store, engine.clone(), Some(chain()))
        .run_plan(two_steps(), Tainted::trusted(json!({ "ticket": "T-2" })))
        .await
        .unwrap();
    assert_eq!(chained.status, RunStatus::Succeeded, "{chained:?}");

    let file = export(&store, &[chainless.run_id, chained.run_id]).await;
    let rebuilt = check().rebuild(file.as_slice()).await.expect("reads");

    let asked: BTreeSet<String> = engine.asked.lock().unwrap().iter().cloned().collect();
    let again: BTreeSet<String> = rebuilt
        .iter()
        .flat_map(|run| &run.requests)
        .map(|r| {
            spelled(
                &r.request.principal,
                r.request.action,
                &r.request.resource,
                &r.request.context,
            )
        })
        .collect();
    assert_eq!(
        asked.difference(&again).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the gate asked these and the export does not rebuild them"
    );
    assert_eq!(
        again.difference(&asked).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the export rebuilds these and the gate never asked them"
    );
    for run in &rebuilt {
        assert!(
            run.not_evaluable.is_empty(),
            "a clear corpus left requests unrebuilt: {:?}",
            run.not_evaluable
        );
    }

    // The corpus has every shape, so the equality above covers each of them
    // rather than passing over a corpus that lacked one.
    let requests: Vec<_> = rebuilt.iter().flat_map(|run| &run.requests).collect();
    let has = |pred: &dyn Fn(&agentplane::policy::requests::GatedRequest) -> bool| {
        requests.iter().any(|r| pred(&r.request))
    };
    assert!(has(&|r| r.action == ACTION_ADMIT), "no admission");
    assert!(has(&|r| r.action == ACTION_RELEASE), "no release");
    assert!(
        has(&|r| r.resource == "tool.call" && r.context["mutates"] == true),
        "no grant-widened tool call: the gate asks `mutates: true` for it"
    );
    assert!(
        has(&|r| r.context.get("label").is_some()),
        "no labelled sink"
    );
    assert!(has(&|r| r.context.get("agent").is_some()), "no agent block");
    assert!(has(&|r| r.context["owner"] == "user:auditor"), "no chain");
    assert!(
        has(&|r| r.context["step"] == 1 && r.principal == "corpus.run"),
        "no plan step asked under the admitted capability"
    );
}

// ── Recorded mode ───────────────────────────────────────────────────────────

/// A run that tried a transfer its bundle forbids.
#[derive(Debug)]
struct Pays;

#[async_trait::async_trait]
impl Skill for Pays {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("pay").provides("pay")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Touch("ledger.read")).await?;
        cx.effect(Touch("ledger.transfer")).await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "paid": true }))))
    }
}

async fn pays_under(engine: Arc<dyn PolicyEngine>) -> (Arc<RedbStore>, RunId, RunStatus) {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("policy-check")
        .policy(engine)
        .skill(Pays)
        .build()
        .run("pay", Tainted::trusted(json!({})))
        .await
        .unwrap();
    (store, out.run_id, out.status)
}

/// **An export checked against its own bundle agrees with it.**
///
/// The runtime refused the transfer, so the record holds a permit for the read
/// and a refusal for the transfer. Re-derived under the same rules the permit
/// stands and the refusal is reported as not evaluable, never as a finding. A
/// gate that let one effect kind past the bundle is the defect this reports: the
/// transfer then starts, and the same check finds it.
#[tokio::test]
async fn an_export_checked_against_its_own_bundle_has_no_findings() {
    let engine = Arc::new(CedarEngine::new(FORBID_TRANSFER).unwrap());
    let (store, run, status) = pays_under(engine).await;

    let file = export(&store, &[run]).await;
    let bundle = CedarEngine::new(FORBID_TRANSFER).unwrap();
    let report = check()
        .run(file.as_slice(), &bundle, None)
        .await
        .expect("reads");

    let r = &report.runs[0];
    assert_eq!(r.mode, Mode::Recorded);
    assert_eq!(
        r.findings,
        vec![],
        "the record and its own bundle disagree — a permit the bundle refuses reached \
         the world"
    );
    assert!(r.evaluated >= 2, "admission and the read: {r:?}");
    assert!(
        r.not_evaluable.iter().any(
            |n| n.reason == Unevaluable::RequestNotJournaled && n.resource == "ledger.transfer"
        ),
        "the refusal was not reported as unevaluable: {:?}",
        r.not_evaluable
    );
    assert_eq!(report.verdict(), Verdict::Clean);
    // After the check, so a gate that let the transfer through is reported by
    // the finding above rather than by this line.
    assert!(matches!(status, RunStatus::Failed(_)), "{status:?}");
}

/// **A recorded permit the recorded bundle refuses is a finding**, naming where.
#[tokio::test]
async fn a_permit_the_recorded_bundle_refuses_is_a_finding() {
    let (store, run, status) = pays_under(Arc::new(Refuses(&[]))).await;
    assert_eq!(status, RunStatus::Succeeded);
    let file = export(&store, &[run]).await;

    let report = check()
        .run(file.as_slice(), &Refuses(&["ledger.transfer"]), None)
        .await
        .expect("reads");
    let r = &report.runs[0];
    assert_eq!(r.mode, Mode::Recorded);
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(f.action, ACTION_PERFORM);
    assert_eq!(f.resource, "ledger.transfer");
    assert_eq!(f.step, Some(StepId(0)));
    assert!(f.effect_key.is_some(), "a finding must say which effect");
    assert!(f.reason.contains("no-ledger.transfer"), "{}", f.reason);
    assert!(!f.malformed);
    assert_eq!(report.verdict(), Verdict::Findings);
}

/// **A run that recorded another bundle is a mismatch, not a verdict.**
#[tokio::test]
async fn a_mismatched_bundle_is_reported_not_evaluated() {
    let (store, run, _) = pays_under(Arc::new(Refuses(&[]))).await;
    let file = export(&store, &[run]).await;
    let other = CedarEngine::new("forbid(principal, action, resource);").unwrap();

    let report = check()
        .run(file.as_slice(), &other, None)
        .await
        .expect("reads");
    let r = &report.runs[0];
    assert_eq!(r.mode, Mode::Mismatch);
    assert_eq!(r.recorded_bundle, Some(Refuses(&[]).digest()));
    assert_eq!(report.bundle, other.digest());
    assert_eq!(r.evaluated, 0);
    assert!(
        r.findings.is_empty(),
        "a mismatched run was judged by a bundle it never ran under: {:?}",
        r.findings
    );
    assert_eq!(report.verdict(), Verdict::Findings);
}

/// **An ungoverned run is reported as ungoverned, never as clean.**
#[tokio::test]
async fn an_ungoverned_run_is_not_reported_clean() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("policy-check")
        .skill(Pays)
        .build()
        .run("pay", Tainted::trusted(json!({})))
        .await
        .unwrap();
    let file = export(&store, &[out.run_id]).await;

    let report = check()
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .expect("reads");
    assert_eq!(report.runs[0].mode, Mode::Ungoverned);
    assert_eq!(report.evaluated(), 0);
    assert_eq!(report.verdict(), Verdict::Partial);
}

// ── Candidate mode ──────────────────────────────────────────────────────────

/// **A candidate is measured against what happened.**
///
/// One added `forbid` newly denies exactly its calls. And the comparison is
/// with the recorded outcome, not with the supplied bundle re-evaluated: a run
/// that recorded another bundle still happened, and a candidate refusing its
/// transfer changes it even when the supplied bundle refuses it too.
#[tokio::test]
async fn a_candidate_diff_is_against_the_recorded_outcome() {
    let (store, run, _) = pays_under(Arc::new(Refuses(&[]))).await;
    let file = export(&store, &[run]).await;
    let candidate = CedarEngine::new(FORBID_TRANSFER).unwrap();

    // The recorded bundle supplied: one call newly denied, and only that one.
    let report = check()
        .run(file.as_slice(), &Refuses(&[]), Some(&candidate))
        .await
        .expect("reads");
    let diff = report.runs[0].diff.as_ref().expect("a diff");
    assert_eq!(
        diff.newly_denied
            .iter()
            .map(|f| f.resource.as_str())
            .collect::<Vec<_>>(),
        vec!["ledger.transfer"]
    );
    assert!(diff.malformed_under_candidate.is_empty());
    assert_eq!(report.candidate, Some(candidate.digest()));
    assert_eq!(report.verdict(), Verdict::Findings);

    // A supplied bundle that is not the recorded one, and refuses the same
    // call: the run is a mismatch, and the candidate still changes it.
    let supplied = CedarEngine::new(FORBID_TRANSFER).unwrap();
    let report = check()
        .run(file.as_slice(), &supplied, Some(&candidate))
        .await
        .expect("reads");
    assert_eq!(report.runs[0].mode, Mode::Mismatch);
    let diff = report.runs[0].diff.as_ref().expect("a diff");
    assert_eq!(
        diff.newly_denied
            .iter()
            .map(|f| f.resource.as_str())
            .collect::<Vec<_>>(),
        vec!["ledger.transfer"],
        "the candidate was compared with the supplied bundle, not with what happened"
    );
}

/// **A candidate that cannot evaluate a request is malformed, not a denial.**
#[tokio::test]
async fn a_candidate_that_errors_is_malformed_not_denied() {
    let (store, run, _) = pays_under(Arc::new(Refuses(&[]))).await;
    let file = export(&store, &[run]).await;
    // Reads an attribute no effect request carries, unguarded.
    let broken = CedarEngine::new(
        r#"permit(principal, action, resource);
           @id("unguarded") forbid(principal, action == Action::"effect:perform", resource) when { context.nope == 1 };"#,
    )
    .unwrap();

    let report = check()
        .run(file.as_slice(), &Refuses(&[]), Some(&broken))
        .await
        .expect("reads");
    let diff = report.runs[0].diff.as_ref().expect("a diff");
    assert!(
        !diff.malformed_under_candidate.is_empty(),
        "an unevaluable candidate read as a set of ordinary refusals: {diff:?}"
    );
    assert!(
        diff.newly_denied.is_empty(),
        "a malformed decision was reported as a rule firing: {diff:?}"
    );
}

// ── What the gate never saw ─────────────────────────────────────────────────

/// Append `records(run)` to a fresh run and export it.
async fn exported(records: impl FnOnce(RunId) -> Vec<Append>) -> Vec<u8> {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let run = RunId::generate();
    let lease = journal
        .acquire(run, "policy-check", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    journal.append(lease.epoch, records(run)).await.unwrap();
    export(&store, &[run]).await
}

fn admitted(run: RunId, input: Value) -> Append {
    Append::new(
        run,
        RecordKind::RunAdmitted {
            capability: "pay".into(),
            governed_by: None,
            input,
            input_label: Label::trusted(),
            policy_bundle: Some(Box::new(Refuses(&[]).bundle())),
            canon: agentplane::core::canon::VERSION,
            idempotency_key: None,
            admitted_by: None,
            served_unchained: false,
        },
    )
}

fn started(run: RunId, step: u32, phase: Phase, ordinal: u32, kind: &str, args: Value) -> Append {
    // Distinct per position; the check reads the key back, it never derives one.
    let key = EffectKey::from_hex(&format!(
        "{step:08x}{:08x}{ordinal:048x}",
        u8::from(phase == Phase::Compensating)
    ))
    .expect("a key");
    Append::new(
        run,
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::new(kind, args),
            recovery: Recovery::Retry,
            mutates: true,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: None,
            outbound_bytes: None,
        },
    )
    .step(StepId(step))
    .phase(phase)
    .effect(key)
}

/// **An undo is not judged.** A compensating effect never passes the gate, so
/// a bundle refusing it disagrees with nothing the runtime claimed.
#[tokio::test]
async fn a_compensation_is_not_judged() {
    let file = exported(|run| {
        vec![
            admitted(run, json!({})),
            started(run, 0, Phase::Forward, 0, "ledger.charge", json!({})),
            started(run, 0, Phase::Compensating, 0, "ledger.refund", json!({})),
        ]
    })
    .await;
    let report = check()
        .run(file.as_slice(), &Refuses(&["ledger.refund"]), None)
        .await
        .expect("reads");
    let r = &report.runs[0];
    assert!(
        r.findings.is_empty(),
        "an undo the gate never saw was judged: {:?}",
        r.findings
    );
    assert!(
        r.not_evaluable
            .iter()
            .any(|n| n.reason == Unevaluable::GateSkipped && n.resource == "ledger.refund")
    );
    assert_eq!(r.evaluated, 2, "admission and the charge");
}

/// **A record that may have skipped the gate is not judged.**
///
/// A reversing group's undo members are forward-phase records nothing marks,
/// and a durable wait's kind is one a skill may also use. Either would be a
/// finding about a call the runtime never claimed to have gated.
#[tokio::test]
async fn a_record_the_gate_may_have_skipped_is_not_judged() {
    let file = exported(|run| {
        vec![
            admitted(run, json!({})),
            Append::new(
                run,
                RecordKind::GroupOpened {
                    group: "hold".into(),
                    resources: vec!["ledger".into()],
                },
            )
            .step(StepId(0)),
            started(run, 0, Phase::Forward, 0, "ledger.hold", json!({})),
            started(run, 0, Phase::Forward, 1, "ledger.release_hold", json!({})),
            Append::new(
                run,
                RecordKind::GroupSettled {
                    group: "hold".into(),
                    outcome: GroupOutcome::Aborted,
                    detail: None,
                },
            )
            .step(StepId(0)),
            started(run, 0, Phase::Forward, 2, "timer.sleep", json!({ "ms": 5 })),
        ]
    })
    .await;
    let report = check()
        .run(
            file.as_slice(),
            &Refuses(&["ledger.release_hold", "timer.sleep"]),
            None,
        )
        .await
        .expect("reads");
    let r = &report.runs[0];
    assert!(
        r.findings.is_empty(),
        "a record that may have skipped the gate was judged: {:?}",
        r.findings
    );
    let indistinct: Vec<_> = r
        .not_evaluable
        .iter()
        .filter(|n| n.reason == Unevaluable::GateIndistinguishable)
        .map(|n| n.resource.as_str())
        .collect();
    assert_eq!(
        indistinct,
        vec!["ledger.hold", "ledger.release_hold", "timer.sleep"]
    );
}

/// A committed group's members all passed the gate, and are judged.
#[tokio::test]
async fn a_committed_groups_members_are_judged() {
    let file = exported(|run| {
        vec![
            admitted(run, json!({})),
            Append::new(
                run,
                RecordKind::GroupOpened {
                    group: "pair".into(),
                    resources: vec!["ledger".into()],
                },
            )
            .step(StepId(0)),
            started(run, 0, Phase::Forward, 0, "ledger.debit", json!({})),
            Append::new(
                run,
                RecordKind::GroupSettled {
                    group: "pair".into(),
                    outcome: GroupOutcome::Committed,
                    detail: None,
                },
            )
            .step(StepId(0)),
        ]
    })
    .await;
    let report = check()
        .run(file.as_slice(), &Refuses(&["ledger.debit"]), None)
        .await
        .expect("reads");
    assert_eq!(report.runs[0].findings.len(), 1);
}

/// **Only a policy verdict is judged.** A manifest refusal and a sink refusal
/// are written as the same record and no bundle decided them.
#[tokio::test]
async fn a_manifest_or_sink_refusal_is_not_judged() {
    let file = exported(|run| {
        vec![
            admitted(run, json!({})),
            Append::new(
                run,
                RecordKind::PolicyDenied {
                    reason: "manifest 'pay' does not grant it".into(),
                    action: ACTION_DECLARED.into(),
                    resource: "tool.call".into(),
                },
            )
            .step(StepId(0)),
            Append::new(
                run,
                RecordKind::PolicyDenied {
                    reason: "rule `no-transfer` forbids it".into(),
                    action: ACTION_PERFORM.into(),
                    resource: "ledger.transfer".into(),
                },
            )
            .step(StepId(0)),
        ]
    })
    .await;
    let report = check()
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .expect("reads");
    let actions: Vec<_> = report.runs[0]
        .not_evaluable
        .iter()
        .map(|n| (n.action.as_str(), n.reason))
        .collect();
    assert_eq!(
        actions,
        vec![(ACTION_PERFORM, Unevaluable::RequestNotJournaled)],
        "a refusal no bundle decided was reported as a verdict"
    );
}

/// **A check that read nothing does not pass.**
#[tokio::test]
async fn an_export_with_nothing_evaluable_fails_the_check() {
    // Sealed payloads, as a plane with a key ring writes them, and no ring.
    let sealed = json!({ "$sealed": "AAAA" });
    let file = exported(|run| {
        vec![
            admitted(run, sealed.clone()),
            started(run, 0, Phase::Forward, 0, "ledger.read", sealed.clone()),
        ]
    })
    .await;
    let report = check()
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .expect("reads");
    let r = &report.runs[0];
    assert_eq!(r.evaluated, 0);
    assert!(
        r.not_evaluable
            .iter()
            .all(|n| n.reason == Unevaluable::Sealed),
        "{:?}",
        r.not_evaluable
    );
    assert_eq!(r.not_evaluable.len(), 2);
    assert_eq!(
        report.verdict(),
        Verdict::Partial,
        "a check that could read nothing reported a clean bill"
    );
}

/// The report states once what no export holds.
#[tokio::test]
async fn the_report_says_what_is_outside_every_export() {
    let file = exported(|run| vec![admitted(run, json!({}))]).await;
    let report = check()
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .expect("reads");
    assert!(report.outside_export.contains("refused admission"));
    assert!(report.outside_export.contains("served surfaces"));
    assert_eq!(report.tenant.source, TenantSource::Supplied);
}

/// **Sealed and erased are told apart.** Without a ring a sealed argument is
/// sealed; with one, a destroyed key is an erasure and an intact one opens.
#[cfg(feature = "keyring")]
#[tokio::test]
async fn a_sealed_and_an_erased_run_are_not_evaluable_for_their_own_reasons() {
    use agentplane::core::{TenantId, Timestamp};
    use agentplane::keyring::{KeyRing, SealedJournal};
    use agentplane::testkit::MemoryKeyRing;

    let tenant = TenantId::default();
    let keys = Arc::new(MemoryKeyRing::default());
    let ring = Arc::clone(&keys) as Arc<dyn KeyRing>;
    let raw = Arc::new(RedbStore::open_in_memory().unwrap());
    let journal = SealedJournal::wrap(
        Arc::clone(&raw) as Arc<dyn JournalStore>,
        Arc::clone(&ring),
        tenant.clone(),
    ) as Arc<dyn JournalStore>;

    let mut runs = Vec::new();
    for account in ["AC-kept", "AC-erased"] {
        let run = RunId::generate();
        let lease = journal
            .acquire(run, "policy-check", std::time::Duration::from_mins(1))
            .await
            .unwrap();
        journal
            .append(
                lease.epoch,
                vec![
                    admitted(run, json!({ "account": account })),
                    started(
                        run,
                        0,
                        Phase::Forward,
                        0,
                        "ledger.read",
                        json!({ "account": account }),
                    ),
                ],
            )
            .await
            .unwrap();
        runs.push(run);
    }
    agentplane::blob::erase_run(
        ring.as_ref(),
        &tenant,
        runs[1],
        Timestamp::from_unix_timestamp(1_760_000_000).unwrap(),
        "subject exercised the right to erasure",
    )
    .await
    .unwrap();

    let mut file = Vec::new();
    agentplane::export::to_jsonl(&journal, None, &runs, &mut file)
        .await
        .unwrap();

    let reasons = |report: &agentplane::policy::check::Report, i: usize| {
        report.runs[i]
            .not_evaluable
            .iter()
            .map(|n| n.reason)
            .collect::<Vec<_>>()
    };

    let blind = Check::new(tenant.as_str(), TenantSource::Supplied)
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .unwrap();
    assert_eq!(reasons(&blind, 0), vec![Unevaluable::Sealed; 2]);
    assert_eq!(reasons(&blind, 1), vec![Unevaluable::Sealed; 2]);

    let keyed = Check::new(tenant.as_str(), TenantSource::Supplied)
        .with_keys(ring.as_ref())
        .run(file.as_slice(), &Refuses(&[]), None)
        .await
        .unwrap();
    assert_eq!(keyed.runs[0].evaluated, 2, "{:?}", keyed.runs[0]);
    assert!(reasons(&keyed, 0).is_empty());
    assert_eq!(
        reasons(&keyed, 1),
        vec![Unevaluable::Erased; 2],
        "an erased payload read as one merely sealed"
    );
    let _ = keys;
}
