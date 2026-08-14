//! Memory scoped to the party a run is about, and tasks opened beside an answer.
//!
//! # Why these two live together
//!
//! Both are the same shape of gap, found by the same kind of deployment: a plane
//! of advisory specialists reasoning about one customer at a time, under a
//! regime where *whose data is this* and *who was told* are questions with legal
//! answers.
//!
//! A literal `memory_formation.subject` pools every customer's facts under one
//! key — so one customer's history is recalled into another's run, and an
//! erasure request naming one person cannot be satisfied without destroying
//! everybody's. And `oversight.approval` could gate an answer or gate a call,
//! but could not say *return the answer and open a task when it says something
//! alarming* — which is the only shape an advisory plane has, since a
//! `tool-calling` agent that grants no mutating tool cannot act at all.

#![cfg(all(feature = "redb", feature = "manifest", feature = "testkit"))]

use std::sync::Arc;

use agentplane::case::{CaseStore, TaskStore};
use agentplane::core::{CorrelationKey, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::memory::{MemoryStore, Recall};
use agentplane::model::ModelProvider;
use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use serde_json::json;

/// An advisory agent: one model call, an answer in a declared shape.
fn agent_yaml(subject: &str, extra: &str) -> String {
    format!(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: watcher, version: "1.0.0" }}
spec:
  capabilities: {{ provides: [watch.deadline] }}
  models: {{ privileged: {{ provider: fake, model: m-1 }} }}
  execution: {{ kind: completion }}
  security: {{ max_sensitivity_egress: internal }}
  output:
    schema:
      type: object
      additionalProperties: false
      required: [deadline_status]
      properties:
        deadline_status: {{ type: string }}
        days_left: {{ type: number }}
  memory_formation:
    subject: "{subject}"
    purpose: clearing
    instruction: Extract stable facts only.
    max_items: 2
    max_sensitivity: internal
  budgets: {{}}
{extra}
"#
    )
}

struct Plane {
    rt: Arc<Runtime>,
    store: Arc<RedbStore>,
}

fn plane(manifest: &Manifest, answer: serde_json::Value) -> Plane {
    let provider = agentplane::testkit::FakeProvider::new();
    // Two answers: the agent's own, then whatever memory formation extracts.
    provider.will_structure(answer);
    provider.will_structure(json!({
        "memories": [{ "key": "language", "content": "prefers German" }]
    }));
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    // One backend, all six stores: the `builder_on` path a real deployment on
    // a single file takes, exercised by every test through this helper.
    let rt = Runtime::builder_on(Arc::clone(&store))
        .provider("fake", Arc::clone(&provider) as Arc<dyn ModelProvider>)
        .agent(Agent::new(manifest))
        .try_build()
        .expect("a coherent plane");
    Plane { rt, store }
}

fn malo(value: &str) -> CorrelationKey {
    CorrelationKey::new("malo", value)
}

// ── Subject bindings ────────────────────────────────────────────────────────

/// Two customers, one declaration, two piles.
///
/// The whole point: with a literal subject both runs write into one key, so the
/// second customer's next run recalls the first customer's facts — and an
/// erasure naming one of them takes the other's with it. `forget_subject` is
/// what an erasure request actually names, so the subject has to *be* the party.
#[tokio::test]
async fn a_correlation_binding_files_each_party_under_its_own_subject() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);

    let filed = p
        .store
        .recall(&Recall::about("DE-1111"))
        .await
        .expect("recall");
    assert_eq!(
        filed.len(),
        1,
        "the memory is filed under the customer's own key, not a literal"
    );
    assert_eq!(filed[0].content, json!("prefers German"));

    // The other customer's scope is empty, which is the property that makes an
    // erasure request answerable.
    assert!(
        p.store
            .recall(&Recall::about("DE-2222"))
            .await
            .expect("recall")
            .is_empty()
    );
    // And the binding text itself was never used as a key.
    assert!(
        p.store
            .recall(&Recall::about("$correlation/malo"))
            .await
            .expect("recall")
            .is_empty(),
        "the binding was filed literally, which would pool every party again"
    );
}

/// The quarantined role's own ceilings ride the formation call.
///
/// A manifest that designates a quarantined model for untrusted contact
/// declares `max_tokens` beside it, and formation is untrusted contact. The
/// ceiling used to stop at the `form_memories` seam — the role's model id
/// travelled and its ceilings were dropped, a declared control the runtime
/// silently did not apply. The proof is the journal: the formation effect's
/// descriptor must carry the quarantined model *and* its declared ceiling.
#[tokio::test]
async fn a_quarantined_roles_ceilings_govern_the_formation_call() {
    let manifest = Manifest::parse(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: watcher, version: "1.0.0" }
spec:
  capabilities: { provides: [watch.deadline] }
  models:
    privileged: { provider: fake, model: m-1 }
    quarantined: { provider: fake, model: q-1, max_tokens: 77 }
  execution: { kind: completion }
  security: { max_sensitivity_egress: internal }
  memory_formation:
    subject: "clearing-desk"
    purpose: clearing
    instruction: Extract stable facts only.
    max_items: 2
    max_sensitivity: internal
  budgets: {}
"#,
    )
    .expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));

    let out =
        p.rt.run("watch.deadline", Tainted::trusted(json!({ "q": "x" })))
            .await
            .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);

    let records = (Arc::clone(&p.store) as Arc<dyn JournalStore>)
        .read(out.run_id, 1)
        .await
        .expect("read");
    let formation = records
        .iter()
        .find_map(|record| match record.kind() {
            agentplane::journal::RecordKind::EffectStarted { descriptor, .. }
                if descriptor.kind == "model.complete"
                    && descriptor.args["model"] == json!("q-1") =>
            {
                Some(descriptor.args.clone())
            }
            _ => None,
        })
        .expect("the formation call runs on the quarantined model");
    assert_eq!(
        formation["max_output_tokens"],
        json!(77),
        "the quarantined role's declared max_tokens must reach the journaled \
         formation call, or the digest covers a ceiling nothing applies"
    );
}

/// A binding the run cannot resolve fails the run rather than guessing.
///
/// The two wrong answers are both worse than a failure: filing under the literal
/// pools every party under a key that reads like a scope, and filing under a
/// default silently moves one party's facts into another's pile. Neither shows
/// up at write time, and both show up at an erasure request.
#[tokio::test]
async fn an_unresolvable_binding_fails_the_run() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/meter", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            // Keyed by `malo`, and the declaration asks for `meter`.
            &[malo("DE-1111")],
        )
        .await
        .expect("the run reaches a verdict");
    let RunStatus::Failed(why) = out.status else {
        panic!("a run that cannot resolve its memory scope must fail: {out:?}");
    };
    assert!(why.contains("$correlation/meter"), "{why}");
    assert!(
        why.contains("[\"malo\"]"),
        "the message names what it has: {why}"
    );
}

/// An input binding is refused unless the field it names is trusted.
///
/// A subject taken from untrusted input is whoever supplied it choosing whose
/// memories this run writes into — strictly worse than the pooling bindings
/// exist to fix, and invisible at the time.
#[tokio::test]
async fn an_untrusted_input_may_not_choose_the_subject() {
    let manifest = Manifest::parse(&agent_yaml("$input/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));

    let untrusted = Tainted::object([(
        "malo".to_owned(),
        Tainted::from_source(
            json!("DE-9999"),
            agentplane::core::SourceId::new("inbound:edifact"),
        ),
    )]);
    let out =
        p.rt.run_correlated("watch.deadline", untrusted, "clearing", &[malo("DE-1111")])
            .await
            .expect("the run reaches a verdict");
    let RunStatus::Failed(why) = out.status else {
        panic!("an untrusted subject must be refused: {out:?}");
    };
    assert!(why.contains("untrusted"), "{why}");

    // The trusted twin is accepted, so the refusal is about the label and not
    // about input bindings being unimplemented.
    let manifest = Manifest::parse(&agent_yaml("$input/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));
    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "malo": "DE-9999" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        p.store
            .recall(&Recall::about("DE-9999"))
            .await
            .expect("recall")
            .len(),
        1
    );
}

/// The keys a binding resolves against come from the journal, not the store.
///
/// A case accumulates business keys over months. If a resumed run re-read them
/// it could resolve a subject the live run never saw — a second memory under a
/// second scope, and a history that disagrees with itself. So the binding record
/// carries the keys, and a strict replay reaches the same subject.
#[tokio::test]
async fn a_replay_resolves_the_subject_the_live_run_resolved() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);

    // Strict replay performs nothing and reads every effect back. A subject
    // resolved differently would derive a different `memory.remember` key and
    // report divergence rather than succeeding.
    let replayed =
        p.rt.replay(out.run_id, Mode::Strict)
            .await
            .expect("the run replays");
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        p.store
            .recall(&Recall::about("DE-1111"))
            .await
            .expect("recall")
            .len(),
        1,
        "a replay reads the write back rather than performing a second one"
    );
}

/// A coded skill reads back what a declaration wrote, from the same keys.
#[tokio::test]
async fn a_skill_can_scope_its_own_recall_to_the_runs_correlation() {
    // `cx.correlation_value` is the same lookup the binding performs, exposed so
    // a hand-written skill reaching the same memories does not have to guess at
    // the naming convention.
    #[derive(Debug)]
    struct Reads;
    #[async_trait::async_trait]
    impl agentplane::core::Skill for Reads {
        fn descriptor(&self) -> agentplane::core::SkillDescriptor {
            agentplane::core::SkillDescriptor::new("reads").provides("watch.read")
        }
        async fn invoke(
            &self,
            cx: &mut agentplane::runtime::StepCtx<'_>,
            _input: Tainted<serde_json::Value>,
        ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
            let subject = cx
                .correlation_value("malo")
                .ok_or_else(|| agentplane::core::SkillError::Other("no malo key".into()))?
                .to_owned();
            let found = cx.recall(Recall::about(subject)).await?;
            Ok(agentplane::core::Outcome::done(Tainted::trusted(json!(
                found.len()
            ))))
        }
    }

    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));
    p.rt.run_correlated(
        "watch.deadline",
        Tainted::trusted(json!({ "q": "x" })),
        "clearing",
        &[malo("DE-1111")],
    )
    .await
    .expect("the run completes");

    let rt = Runtime::builder(Arc::clone(&p.store) as Arc<dyn JournalStore>)
        .memory(Arc::clone(&p.store) as Arc<dyn MemoryStore>)
        .cases(Arc::clone(&p.store) as Arc<dyn CaseStore>)
        .skill(Reads)
        .try_build()
        .expect("a coherent plane");
    let out = rt
        .run_correlated(
            "watch.read",
            Tainted::trusted(json!({})),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.output.as_ref().map(Tainted::peek), Some(&json!(1)));
}

// ── Triage ──────────────────────────────────────────────────────────────────

const TRIAGE: &str = r#"
  oversight:
    approval: none
    deadline: { name: unused, kind: hours, params: { n: 4 } }
    triage:
      - name: breach
        summary: "a regulatory deadline was missed"
        audience: [grid-operations]
        priority: high
        when:
          - path: /deadline_status
            equals: BREACH
        deadline: { name: triage-breach, kind: hours, params: { n: 8 } }
"#;

/// A matching answer returns *and* opens a task.
///
/// The mode that was missing. `required` would have suspended the run until
/// somebody approved a report; `tools-only` would have gated nothing, because an
/// advisory agent has no mutating call to gate.
#[tokio::test]
async fn a_matching_answer_returns_and_opens_a_task_beside_it() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", TRIAGE)).expect("manifest");
    let p = plane(
        &manifest,
        json!({ "deadline_status": "BREACH", "days_left": 0 }),
    );

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(
        out.status,
        RunStatus::Succeeded,
        "the run must not wait for the desk it just notified"
    );
    assert_eq!(
        out.output.as_ref().map(Tainted::peek),
        Some(&json!({ "deadline_status": "BREACH", "days_left": 0 }))
    );

    let queued = p
        .store
        .queue(&["grid-operations".to_owned()], 10)
        .await
        .expect("queue");
    assert_eq!(queued.len(), 1, "the matching rule opened one task");
    assert_eq!(queued[0].kind, "agent.triage/breach");
    assert_eq!(queued[0].priority, agentplane::core::Priority::High);
    assert_eq!(
        queued[0].justification.summary,
        "a regulatory deadline was missed"
    );
    assert_eq!(
        queued[0].justification.proposed_action,
        json!({ "deadline_status": "BREACH", "days_left": 0 }),
        "a reviewer sees the answer itself, not a description of it"
    );
    // A row created now and due later, which is what the two fields say.
    assert!(
        queued[0].due_at.expect("a horizon") > queued[0].created_at,
        "created_at must be the run's clock, not the obligation's instant"
    );
}

/// A non-matching answer opens nothing, and still returns.
#[tokio::test]
async fn a_quiet_answer_opens_no_task() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", TRIAGE)).expect("manifest");
    let p = plane(
        &manifest,
        json!({ "deadline_status": "OK", "days_left": 9 }),
    );

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);
    assert!(
        p.store
            .queue(&["grid-operations".to_owned()], 10)
            .await
            .expect("queue")
            .is_empty()
    );
}

/// A replayed run does not open a second row.
///
/// The task id is derived from the effect key, and the open is a journaled
/// effect — so a resume addresses the row it already opened. Without both, a
/// worklist grows one row per resume and a compliance desk sees the same finding
/// as many times as the plane restarted.
#[tokio::test]
async fn a_replay_does_not_open_the_task_again() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", TRIAGE)).expect("manifest");
    let p = plane(
        &manifest,
        json!({ "deadline_status": "BREACH", "days_left": 0 }),
    );

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    p.rt.replay(out.run_id, Mode::Strict)
        .await
        .expect("the run replays");

    assert_eq!(
        p.store
            .queue(&["grid-operations".to_owned()], 10)
            .await
            .expect("queue")
            .len(),
        1,
        "a replay must read the task back rather than opening a second one"
    );
}

/// An **untrusted** finding reaches the worklist, and that is the feature.
///
/// A model's answer is untrusted by construction, so a gate that refused
/// untrusted content at a worklist would mean a task could only ever carry
/// findings nobody needs to look at. The row still records where the content
/// came from — the label is on the run's journal — and the control a reviewer
/// exists for *is* the review.
///
/// Pinned because the opposite is a plausible-looking hardening, and shipping it
/// would silently empty every triage queue in the deployment.
#[tokio::test]
async fn an_untrusted_finding_still_reaches_the_worklist() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", TRIAGE)).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "BREACH" }));

    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "q": "x" })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        out.output.as_ref().map(Tainted::label).map(|l| l.trust),
        Some(Trust::Untrusted),
        "the answer this row carries is a model completion"
    );
    assert_eq!(
        p.store
            .queue(&["grid-operations".to_owned()], 10)
            .await
            .expect("queue")
            .len(),
        1
    );
}

/// Correlation keys reach a skill, and are empty for an uncorrelated run.
#[tokio::test]
async fn a_run_with_no_case_has_no_correlation() {
    #[derive(Debug)]
    struct Peeks;
    #[async_trait::async_trait]
    impl agentplane::core::Skill for Peeks {
        fn descriptor(&self) -> agentplane::core::SkillDescriptor {
            agentplane::core::SkillDescriptor::new("peeks").provides("peek")
        }
        async fn invoke(
            &self,
            cx: &mut agentplane::runtime::StepCtx<'_>,
            _input: Tainted<serde_json::Value>,
        ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
            Ok(agentplane::core::Outcome::done(Tainted::trusted(json!({
                "keys": cx.correlation().len(),
                "malo": cx.correlation_value("malo"),
            }))))
        }
    }
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .skill(Peeks)
        .try_build()
        .expect("a coherent plane");

    let plain = rt
        .run("peek", Tainted::trusted(json!({})))
        .await
        .expect("the run completes");
    assert_eq!(
        plain.output.as_ref().map(Tainted::peek),
        Some(&json!({ "keys": 0, "malo": null }))
    );

    let correlated = rt
        .run_correlated(
            "peek",
            Tainted::trusted(json!({})),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(
        correlated.output.as_ref().map(Tainted::peek),
        Some(&json!({ "keys": 1, "malo": "DE-1111" }))
    );
}

/// The input a binding resolves against is the run's, not the prompt object.
///
/// The prompt folds the input under `/input` beside a trusted `/system`, so
/// resolving `$input/malo` against *that* would be wrong by one level and every
/// pointer in a reviewed file would silently select nothing.
#[tokio::test]
async fn an_input_binding_resolves_against_the_runs_input() {
    let manifest = Manifest::parse(&agent_yaml("$input/party/id", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));
    let out =
        p.rt.run_correlated(
            "watch.deadline",
            Tainted::trusted(json!({ "party": { "id": "DE-7777" } })),
            "clearing",
            &[malo("DE-1111")],
        )
        .await
        .expect("the run completes");
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(
        p.store
            .recall(&Recall::about("DE-7777"))
            .await
            .expect("recall")
            .len(),
        1
    );
}

/// A formed memory keeps the model's label whatever scope it lands in.
///
/// Worth pinning beside the binding tests: a per-party subject is a *scoping*
/// improvement and must not read as a provenance one. The content still came
/// from a model.
#[tokio::test]
async fn a_scoped_memory_is_still_untrusted() {
    let manifest = Manifest::parse(&agent_yaml("$correlation/malo", "")).expect("manifest");
    let p = plane(&manifest, json!({ "deadline_status": "OK" }));
    p.rt.run_correlated(
        "watch.deadline",
        Tainted::trusted(json!({ "q": "x" })),
        "clearing",
        &[malo("DE-1111")],
    )
    .await
    .expect("the run completes");

    let filed = p
        .store
        .recall(&Recall::about("DE-1111"))
        .await
        .expect("recall");
    assert_eq!(filed[0].trust, Trust::Untrusted);
}
