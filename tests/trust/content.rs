//! Content rules: a declared predicate over a value's strings that may refuse
//! it, raise its sensitivity, or redact it at a sink — and nothing else.

#![cfg(all(feature = "manifest", feature = "testkit"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, StepError, Tainted};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::model::{ModelCall, ModelId, ModelProvider};
use agentplane::runtime::{Agent, Mode, RunOutcome, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

/// A manifest declaring `rules` under `spec.security.content` and `budgets`.
fn manifest(rules: &str, budgets: &str) -> Manifest {
    let mut source = String::from(
        "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: ruled, version: \"1.0.0\" }
spec:
  capabilities: { provides: [work.do] }
  models:
    privileged: { provider: fake, model: m-1 }
",
    );
    source.push_str("  budgets: ");
    source.push_str(budgets);
    source.push('\n');
    if !rules.is_empty() {
        source.push_str("  security:\n    content:\n      rules:\n");
        for line in rules.lines() {
            source.push_str("        ");
            source.push_str(line);
            source.push('\n');
        }
    }
    Manifest::parse(&source).expect("the manifest parses")
}

const CODENAME: &str = "- id: codename
  match: {contains: [project-falcon], case: fold}
  at: {sinks: [model.complete]}
  then: refuse";

/// Sends `prompt` to the model `attempts` times, answering each policy
/// refusal by asking again, as a tool-calling loop does.
#[derive(Debug)]
struct Prompts {
    provider: Arc<FakeProvider>,
    prompt: Value,
    attempts: usize,
    refused: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Prompts {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("work.do").provides("work.do")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let prompt = Tainted::trusted(self.prompt.clone());
        for attempt in 1..=self.attempts {
            let provider = Arc::clone(&self.provider) as Arc<dyn ModelProvider>;
            match cx
                .sink_with(&prompt, |value| {
                    ModelCall::new(provider, ModelId::new("fake", "m-1"), value)
                })
                .await
            {
                Ok(completion) => {
                    return Ok(Outcome::done(completion.map(|c| json!({ "text": c.text }))));
                }
                Err(StepError::Policy(refusal)) => {
                    self.refused.fetch_add(1, Ordering::SeqCst);
                    if attempt == self.attempts {
                        return Err(StepError::Policy(refusal).into());
                    }
                }
                Err(other) => return Err(other.into()),
            }
        }
        unreachable!("every attempt returns or is refused")
    }
}

struct Plane {
    store: Arc<RedbStore>,
    provider: Arc<FakeProvider>,
    refused: Arc<AtomicUsize>,
}

impl Plane {
    fn new() -> Self {
        Self {
            store: Arc::new(RedbStore::open_in_memory().expect("store")),
            provider: FakeProvider::new(),
            refused: Arc::default(),
        }
    }

    fn runtime(&self, manifest: &Manifest, prompt: Value, attempts: usize) -> Arc<Runtime> {
        Runtime::builder(Arc::clone(&self.store) as Arc<dyn JournalStore>)
            .agent(Agent::new(manifest).skill(Prompts {
                provider: Arc::clone(&self.provider),
                prompt,
                attempts,
                refused: Arc::clone(&self.refused),
            }))
            .build()
    }

    async fn run(&self, manifest: &Manifest, prompt: Value, attempts: usize) -> RunOutcome {
        self.runtime(manifest, prompt, attempts)
            .run("work.do", Tainted::trusted(json!({})))
            .await
            .expect("run")
    }

    async fn records(&self, out: &RunOutcome) -> Vec<RecordKind> {
        self.store
            .read(out.run_id, 1)
            .await
            .expect("history")
            .iter()
            .map(|r| r.kind().clone())
            .collect()
    }
}

/// **A declared pattern refuses a value at its sink**, before anything is
/// announced or sent, and the refusal is on the record naming the rule.
#[tokio::test]
async fn a_content_rule_refuses_a_value_at_its_sink() {
    let plane = Plane::new();
    let ruled = manifest(CODENAME, "{}");
    let out = plane
        .run(&ruled, json!({ "q": "status of Project-Falcon?" }), 1)
        .await;
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "{:?}",
        out.status
    );
    assert_eq!(
        plane.provider.calls(),
        0,
        "a refused prompt reached the model"
    );
    let records = plane.records(&out).await;
    let denial = records
        .iter()
        .find_map(|k| match k {
            RecordKind::PolicyDenied {
                reason,
                action,
                resource,
            } => Some((reason.clone(), action.clone(), resource.clone())),
            _ => None,
        })
        .expect("the refusal is recorded");
    assert_eq!(denial.1, agentplane::core::ACTION_CONTENT);
    assert_eq!(denial.2, "model.complete");
    assert!(
        denial.0.contains("codename") && denial.0.contains("/q"),
        "{}",
        denial.0
    );
    assert!(
        !records
            .iter()
            .any(|k| matches!(k, RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "model.complete")),
        "a refused call was announced"
    );

    plane.provider.will_say("fine");
    let passed = plane
        .run(&ruled, json!({ "q": "status of the audit?" }), 1)
        .await;
    assert!(
        matches!(passed.status, RunStatus::Succeeded),
        "{:?}",
        passed.status
    );
    let judged = plane
        .records(&passed)
        .await
        .into_iter()
        .find_map(|k| match k {
            RecordKind::EffectStarted { content_rules, .. } => Some(content_rules),
            _ => None,
        });
    assert_eq!(
        judged,
        Some(Some(vec!["codename".to_owned()])),
        "a passed call names the rules it was judged by"
    );
}

/// **A content refusal replays as the sink refusal it was**, not as a denial
/// that ends the run — also under a declaration that no longer has the rule.
#[tokio::test]
async fn a_content_refusal_strict_replays_to_the_same_conclusion() {
    let plane = Plane::new();
    let ruled = manifest(CODENAME, "{}");
    let prompt = json!({ "q": "project-falcon" });
    plane.provider.will_say("after the refusal");
    let out = plane.run(&ruled, prompt.clone(), 2).await;
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "both attempts are refused: {:?}",
        out.status
    );
    for declaration in [ruled, manifest("", "{}")] {
        let replay = plane
            .runtime(&declaration, prompt.clone(), 2)
            .replay(out.run_id, Mode::Strict)
            .await
            .expect("replay");
        assert_eq!(replay.status, out.status);
    }
}

/// **A content refusal counts toward `max_denials`**, because it reaches a
/// loop as `REFUSED` and the loop may ask again.
#[tokio::test]
async fn a_content_refusal_counts_against_the_denial_ceiling() {
    let plane = Plane::new();
    let out = plane
        .run(
            &manifest(CODENAME, "{max_denials: 1}"),
            json!({ "q": "project-falcon" }),
            4,
        )
        .await;
    assert!(
        matches!(out.status, RunStatus::Exhausted(_)),
        "{:?}",
        out.status
    );
    assert_eq!(plane.refused.load(Ordering::SeqCst), 1);
}

/// **No record and no error carries the matched text.** The pointer names
/// where; an object key a rule matches is written `*`.
#[tokio::test]
async fn no_content_refusal_records_the_matched_text() {
    let plane = Plane::new();
    let out = plane
        .run(
            &manifest(CODENAME, "{}"),
            json!({ "notes": { "Project-Falcon": "launch" } }),
            1,
        )
        .await;
    let RunStatus::Failed(reason) = &out.status else {
        panic!("{:?}", out.status);
    };
    assert!(reason.contains("/notes/*"), "{reason}");
    for text in std::iter::once(reason.clone()).chain(
        plane
            .records(&out)
            .await
            .iter()
            .map(|k| serde_json::to_string(k).expect("a record serializes")),
    ) {
        assert!(!text.to_lowercase().contains("falcon"), "{text}");
    }
}

/// A manifest declaring `rule` alone, unparsed.
fn declaring(rule: &str) -> String {
    let mut source = String::from(
        "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: ruled, version: \"1.0.0\" }
spec:
  capabilities: { provides: [work.do] }
  budgets: {}
  security:
    content:
      rules:
",
    );
    for line in rule.lines() {
        source.push_str("        ");
        source.push_str(line);
        source.push('\n');
    }
    source
}

/// **A rule that could do anything but refuse, raise or redact is refused at
/// parse**, and so is one that could never apply or whose pattern the
/// linear-time engine will not run. Each refusal names the rule.
#[test]
fn a_content_rule_that_cannot_refuse_is_refused_at_parse() {
    let oversize = format!("(?:{})", "a{1000}".repeat(64));
    let cases: Vec<(&str, &str, String)> = vec![
        ("flag", "unknown variant", "- id: r1\n  match: {invisible: true}\n  at: {admission: true}\n  then: flag".to_owned()),
        ("warn", "unknown variant", "- id: r1\n  match: {invisible: true}\n  at: {admission: true}\n  then: warn".to_owned()),
        ("allow", "unknown variant", "- id: r1\n  match: {invisible: true}\n  at: {admission: true}\n  then: allow".to_owned()),
        ("a score", "unknown field", "- id: r1\n  match: {invisible: true, score: 0.5}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("two matchers", "exactly one", "- id: r1\n  match: {invisible: true, contains: [x]}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("no matcher", "exactly one", "- id: r1\n  match: {}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("no boundary", "names no boundary", "- id: r1\n  match: {invisible: true}\n  at: {}\n  then: refuse".to_owned()),
        ("redact at a source", "sinks only", "- id: r1\n  match: {contains: [x]}\n  at: {sources: [tool.call]}\n  then: {redact: '[x]'}".to_owned()),
        ("redact at admission", "sinks only", "- id: r1\n  match: {contains: [x]}\n  at: {admission: true}\n  then: {redact: '[x]'}".to_owned()),
        ("an awaited event as a sink", "is not a sink", "- id: r1\n  match: {contains: [x]}\n  at: {sinks: [event.await]}\n  then: refuse".to_owned()),
        ("a fetch as a source", "is not a source", "- id: r1\n  match: {contains: [x]}\n  at: {sources: [media.fetch]}\n  then: refuse".to_owned()),
        ("a backreference", "does not compile", "- id: r1\n  match: {pattern: '(a)\\1'}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("an oversize pattern", "does not compile", format!("- id: r1\n  match: {{pattern: '{oversize}'}}\n  at: {{admission: true}}\n  then: refuse")),
        ("luhn without a pattern", "qualifies a `pattern`", "- id: r1\n  match: {contains: [x], luhn: true}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("an empty literal", "matches everything", "- id: r1\n  match: {contains: ['']}\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("a field that is not a pointer", "not a JSON pointer", "- id: r1\n  match: {invisible: true}\n  fields: [messages]\n  at: {admission: true}\n  then: refuse".to_owned()),
        ("a duplicate id", "declared twice", "- id: r1\n  match: {invisible: true}\n  at: {admission: true}\n  then: refuse\n- id: r1\n  match: {contains: [x]}\n  at: {admission: true}\n  then: refuse".to_owned()),
    ];
    for (case, because, rule) in cases {
        let refused = Manifest::parse(&declaring(&rule))
            .err()
            .unwrap_or_else(|| panic!("{case}: parsed"))
            .to_string();
        assert!(
            refused.contains(because),
            "{case}: refused for another reason: {refused}"
        );
        assert!(
            refused.contains("'r1'") || refused.contains("rules[0]"),
            "{case}: the refusal does not name the rule: {refused}"
        );
    }
}

/// **The `invisible` matcher is the plane's hidden-code-point set**, and the
/// residue no matcher of this kind catches is pinned rather than forgotten.
#[test]
fn the_invisible_matcher_refuses_hidden_code_points_and_passes_the_named_residue() {
    use agentplane::content::At;

    let manifest = Manifest::parse(&declaring(
        "- id: hidden\n  match: {invisible: true}\n  at: {admission: true}\n  then: refuse",
    ))
    .expect("parses");
    let rules = manifest
        .spec
        .security
        .content
        .as_ref()
        .expect("declared")
        .rules()
        .expect("compiled");
    let refused = |text: &str| {
        !rules
            .at(At::Admission, &json!({ "m": text }))
            .refused
            .is_empty()
    };
    for (name, text) in [
        ("a tag character", "pay\u{E0041}me"),
        ("a variation selector", "ok\u{FE0F}"),
        ("a supplementary variation selector", "ok\u{E0100}"),
        ("a zero-width joiner", "a\u{200D}b"),
        ("a zero-width space", "a\u{200B}b"),
        ("a bidirectional override", "a\u{202E}b"),
    ] {
        assert!(refused(text), "{name} passed");
    }
    // The named residue: a pattern over code points sees none of these.
    for (name, text) in [
        ("a Cyrillic letter in a Latin word", "p\u{0430}y"),
        ("a base64-encoded tag sequence", "8J+HrA=="),
        ("plain text", "nothing to see"),
    ] {
        assert!(!refused(text), "{name} was refused");
    }
}

/// **No verdict lowers a label.** Every declared level, every value level:
/// a classification joins, so the result is never below what was declared and
/// never below what the rule names.
#[test]
fn no_content_verdict_lowers_a_label() {
    use agentplane::content::At;
    use agentplane::core::Sensitivity;

    let levels = [
        Sensitivity::Public,
        Sensitivity::Internal,
        Sensitivity::Confidential,
        Sensitivity::Secret,
    ];
    for ruled in levels {
        let manifest = Manifest::parse(&declaring(&format!(
            "- id: c\n  match: {{contains: [k]}}\n  at: {{admission: true}}\n  then: {{classify: {ruled}}}\n- id: d\n  match: {{contains: [k]}}\n  at: {{admission: true}}\n  then: {{classify: public}}"
        )))
        .expect("parses");
        let rules = manifest
            .spec
            .security
            .content
            .as_ref()
            .expect("declared")
            .rules()
            .expect("compiled");
        let outcome = rules.at(At::Admission, &json!({ "k": "k" }));
        for declared in levels {
            let raised = outcome.raise(declared);
            assert!(
                raised >= declared && raised >= ruled,
                "{declared} under {ruled} became {raised}"
            );
            assert_eq!(raised, declared.max(ruled));
        }
        let untouched = rules.at(At::Admission, &json!({ "x": "y" }));
        for declared in levels {
            assert_eq!(untouched.raise(declared), declared);
        }
    }
}

/// Asks the model, then sends what it answered to the model again: the
/// second call is a sink the first answer's label must clear.
#[derive(Debug)]
struct Relays {
    provider: Arc<FakeProvider>,
}

#[async_trait::async_trait]
impl Skill for Relays {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("work.do").provides("work.do")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let first = self
            .ask(cx, Tainted::trusted(json!({ "q": "fetch the key" })))
            .await?;
        let relayed = first.map(|c| json!({ "q": c.text }));
        let second = self.ask(cx, relayed).await?;
        Ok(Outcome::done(second.map(|c| json!({ "text": c.text }))))
    }
}

impl Relays {
    async fn ask(
        &self,
        cx: &mut StepCtx<'_>,
        prompt: Tainted<Value>,
    ) -> Result<Tainted<agentplane::model::Completion>, StepError> {
        let provider = Arc::clone(&self.provider) as Arc<dyn ModelProvider>;
        cx.sink_with(&prompt, |value| {
            ModelCall::new(provider, ModelId::new("fake", "m-1"), value)
                .with_max_sensitivity(agentplane::core::Sensitivity::Internal)
        })
        .await
    }
}

const AWS_KEY: &str = "the key is AKIAABCDEFGHIJKLMNOP";

fn relay(store: &Arc<RedbStore>, provider: &Arc<FakeProvider>, rules: &str) -> Arc<Runtime> {
    let declared = manifest(rules, "{}");
    Runtime::builder(Arc::clone(store) as Arc<dyn JournalStore>)
        .agent(Agent::new(&declared).skill(Relays {
            provider: Arc::clone(provider),
        }))
        .build()
}

/// **A source rule raises the label of what arrives, and replay keeps it.**
/// The raised label is what the next sink judges; the verdict is on the
/// record, so a replay under a declaration without the rule reaches the same
/// refusal without evaluating anything.
#[tokio::test]
async fn a_source_escalation_survives_strict_replay_without_the_rule() {
    let rule = "- id: aws-key
  match: {pattern: 'AKIA[0-9A-Z]{16}'}
  at: {sources: [model.complete]}
  then: {classify: secret}";
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say(AWS_KEY).will_say("relayed");
    let out = relay(&store, &provider, rule)
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    let RunStatus::Failed(reason) = &out.status else {
        panic!("a secret crossed a confidential ceiling: {:?}", out.status);
    };
    assert!(reason.contains("secret"), "{reason}");
    assert_eq!(provider.calls(), 1, "the relayed key reached the model");
    let records = store.read(out.run_id, 1).await.expect("history");
    let verdict = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectDone { content, .. } => content.clone(),
            _ => None,
        })
        .expect("the verdict is on the record");
    assert_eq!(verdict.rules, vec!["aws-key".to_owned()]);
    assert_eq!(
        verdict.sensitivity,
        Some(agentplane::core::Sensitivity::Secret)
    );
    assert!(records.iter().any(|r| matches!(
        r.kind(),
        RecordKind::PolicyDenied { action, .. } if action == agentplane::core::ACTION_EGRESS
    )));

    let replay = relay(&store, &provider, "")
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(
        replay.status, out.status,
        "the replay re-judged the arrival"
    );

    // Without the rule the same answer is relayed.
    let unruled = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say(AWS_KEY).will_say("relayed");
    let out = relay(&unruled, &provider, "")
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "{:?}",
        out.status
    );
}

/// **A classification never lowers**: a rule naming a level below what the
/// effect declared leaves the declared level.
#[tokio::test]
async fn a_classification_below_the_declared_level_changes_nothing() {
    let rule = "- id: low
  match: {pattern: 'AKIA'}
  at: {sources: [model.complete]}
  then: {classify: public}";
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say(AWS_KEY).will_say("relayed");
    let out = relay(&store, &provider, rule)
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "{:?}",
        out.status
    );
    let declared_and_judged = store
        .read(out.run_id, 1)
        .await
        .expect("history")
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectDone {
                declared, content, ..
            } => Some((declared.sensitivity, content.clone())),
            _ => None,
        })
        .expect("the first answer");
    let raised = agentplane::core::ContentVerdict::raise(
        declared_and_judged.1.as_ref(),
        declared_and_judged.0,
    );
    assert_eq!(raised, declared_and_judged.0);
}

/// **A source rule that refuses keeps the value from the step, not from the
/// journal**: the output is recorded with the refusal beside it, the step is
/// refused, and a replay hands it the same refusal.
#[tokio::test]
async fn a_source_refusal_is_recorded_beside_the_output_and_replayed() {
    let rule = "- id: aws-key
  match: {pattern: 'AKIA[0-9A-Z]{16}'}
  at: {sources: [model.complete]}
  then: refuse";
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say(AWS_KEY).will_say("relayed");
    let out = relay(&store, &provider, rule)
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    let RunStatus::Failed(reason) = &out.status else {
        panic!("{:?}", out.status);
    };
    assert!(reason.contains("aws-key"), "{reason}");
    assert!(!reason.contains("AKIA"), "{reason}");
    let refused = store
        .read(out.run_id, 1)
        .await
        .expect("history")
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::EffectDone { content, .. } => content.clone(),
            _ => None,
        })
        .and_then(|c| c.refused)
        .expect("the refusal is recorded beside the output");
    assert_eq!(refused.rule, "aws-key");
    let replay = relay(&store, &provider, "")
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(replay.status, out.status);
}

/// **An admission rule refuses a run before it exists**: no record, and the
/// caller is told which rule and where — never what matched.
#[tokio::test]
async fn an_admission_rule_refuses_hidden_code_points_with_nothing_recorded() {
    let plane = Plane::new();
    let ruled = manifest(
        "- id: tag-smuggling
  match: {invisible: true}
  at: {admission: true}
  then: refuse
- id: internal-only
  match: {contains: [salary]}
  at: {admission: true}
  then: {classify: confidential}",
        "{}",
    );
    let refused = plane
        .runtime(&ruled, json!({}), 1)
        .run(
            "work.do",
            Tainted::trusted(json!({ "msg": "pay\u{E0041}me" })),
        )
        .await
        .expect_err("refused at admission")
        .to_string();
    assert!(
        refused.contains("tag-smuggling") && refused.contains("/msg"),
        "{refused}"
    );
    assert!(
        plane
            .store
            .recent_runs(None, 10)
            .await
            .expect("listing")
            .is_empty(),
        "a refused admission left a record"
    );

    plane.provider.will_say("ok");
    let admitted = plane
        .runtime(&ruled, json!({ "q": "hi" }), 1)
        .run(
            "work.do",
            Tainted::trusted(json!({ "msg": "the salary table" })),
        )
        .await
        .expect("run");
    let label = plane
        .records(&admitted)
        .await
        .into_iter()
        .find_map(|k| match k {
            RecordKind::RunAdmitted { input_label, .. } => Some(input_label),
            _ => None,
        })
        .expect("admitted");
    assert_eq!(
        label.sensitivity,
        agentplane::core::Sensitivity::Confidential
    );
}

/// Waits for one reply and returns it.
#[derive(Debug)]
struct AwaitsReply;

#[async_trait::async_trait]
impl Skill for AwaitsReply {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("work.do").provides("work.do")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("reply", &agentplane::core::DeadlineSpec::days(5), None)
            .await?;
        let wait = agentplane::core::AwaitSpec::new("reply.received", "reply")
            .correlate(agentplane::core::CorrelationKey::new("document", "D-1"));
        Ok(Outcome::done(cx.await_event(&wait).await?))
    }
}

/// **A source rule judges an awaited event on both paths it arrives by**:
/// claimed from the buffer by the waiting step, and delivered by the plane to
/// a run that is suspended.
#[tokio::test]
async fn a_source_rule_applies_to_an_event_delivered_while_suspended() {
    use agentplane::case::{CaseStore, EventStore};

    let ruled = manifest(
        "- id: hidden
  match: {invisible: true}
  at: {sources: [event.await]}
  then: refuse",
        "{}",
    );
    let reply = || {
        agentplane::core::InboundEvent::new(
            "urn:test:acme",
            "EV-1",
            "reply.received",
            json!({ "text": "ok\u{200B}" }),
        )
        .correlate(agentplane::core::CorrelationKey::new("document", "D-1"))
    };
    let start = |rt: Arc<Runtime>| async move {
        rt.run_under(
            "work.do",
            Tainted::trusted(json!({})),
            agentplane::runtime::RunTerms::default().correlated(
                "matter",
                &[agentplane::core::CorrelationKey::new("document", "D-1")],
            ),
        )
        .await
        .expect("admitted")
        .outcome()
        .expect("a fresh run")
        .clone()
    };
    let judged = |store: Arc<RedbStore>, run| async move {
        store
            .read(run, 1)
            .await
            .expect("history")
            .iter()
            .find_map(|r| match r.kind() {
                RecordKind::EffectDone {
                    content, source, ..
                } if source.is_some() => content.clone(),
                _ => None,
            })
    };
    for buffered in [false, true] {
        let store = Arc::new(RedbStore::open_in_memory().expect("store"));
        let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
            .events(Arc::clone(&store) as Arc<dyn EventStore>)
            .agent(Agent::new(&ruled).skill(AwaitsReply))
            .build();
        let out = if buffered {
            rt.deliver(&reply()).await.expect("buffered");
            start(Arc::clone(&rt)).await
        } else {
            let out = start(Arc::clone(&rt)).await;
            assert!(out.status.is_suspended(), "{:?}", out.status);
            rt.deliver(&reply()).await.expect("delivered");
            out
        };
        let verdict = judged(Arc::clone(&store), out.run_id)
            .await
            .unwrap_or_else(|| panic!("buffered={buffered}: the arrival was not judged"));
        assert_eq!(
            verdict.refused.map(|r| (r.rule, r.pointer)),
            Some(("hidden".to_owned(), "/text".to_owned())),
            "buffered={buffered}"
        );
    }
}

/// **A replayed arrival carries the label its recorded verdict gave it**,
/// under a declaration that no longer has the rule: the label is history,
/// not a fresh reading of the manifest.
#[tokio::test]
async fn a_replayed_arrival_keeps_its_recorded_label() {
    let plane = Plane::new();
    let ruled = manifest(
        "- id: aws-key
  match: {pattern: 'AKIA[0-9A-Z]{16}'}
  at: {sources: [model.complete]}
  then: {classify: secret}",
        "{}",
    );
    plane.provider.will_say(AWS_KEY);
    let prompt = json!({ "q": "fetch the key" });
    let out = plane.run(&ruled, prompt.clone(), 1).await;
    let sensitivity = |out: &RunOutcome| {
        out.output
            .as_ref()
            .map(|o| o.label().sensitivity)
            .expect("an answer")
    };
    assert_eq!(sensitivity(&out), agentplane::core::Sensitivity::Secret);
    let replay = plane
        .runtime(&manifest("", "{}"), prompt, 1)
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(sensitivity(&replay), agentplane::core::Sensitivity::Secret);
}

const CARD: &str = "- id: card
  match: {pattern: '\\b\\d(?:[ -]?\\d){12,18}\\b', luhn: true}
  fields: [/q]
  at: {sinks: [model.complete]}
  then: {redact: '[card]'}";

/// **A redaction changes what is sent, and the journal commits to what was
/// sent**: the model receives the token, the record holds no number, the
/// label is the one the value had, and a strict replay reproduces the call.
#[tokio::test]
async fn a_redacted_call_sends_and_records_only_the_redacted_bytes() {
    let plane = Plane::new();
    let ruled = manifest(CARD, "{}");
    let prompt = json!({
        "q": "charge 4111 1111 1111 1111 now, not order 4111 1111 1111 1112",
        "note": "4111 1111 1111 1111",
    });
    plane.provider.will_say("done");
    let out = plane.run(&ruled, prompt.clone(), 1).await;
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "{:?}",
        out.status
    );
    let sent = plane.provider.asked()[0].prompt.clone();
    assert_eq!(
        sent,
        json!({
            "q": "charge [card] now, not order 4111 1111 1111 1112",
            "note": "4111 1111 1111 1111",
        }),
        "the redaction reached outside its field, or missed a Luhn-valid number"
    );
    let (args, label) = plane
        .records(&out)
        .await
        .into_iter()
        .find_map(|k| match k {
            RecordKind::EffectStarted {
                descriptor,
                outbound_label,
                ..
            } => Some((descriptor.args, outbound_label)),
            _ => None,
        })
        .expect("announced");
    assert_eq!(
        args["prompt"], sent,
        "the record is not over the bytes sent"
    );
    assert_eq!(label, Some(agentplane::core::Label::trusted()));

    let replay = plane
        .runtime(&ruled, prompt, 1)
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(replay.status, out.status, "the replay computed another key");
}

/// An effect at a ruled sink that cannot be rebound to new arguments.
#[derive(Debug)]
struct Fixed {
    arguments: Value,
}

#[async_trait::async_trait]
impl agentplane::core::Effect for Fixed {
    type Output = Value;
    fn descriptor(&self) -> agentplane::core::EffectDescriptor {
        agentplane::core::EffectDescriptor::new("tool.call", self.arguments.clone())
    }
    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }
    fn recovery(&self) -> agentplane::core::Recovery {
        agentplane::core::Recovery::Retry
    }
    async fn perform(&self) -> Result<Value, agentplane::core::EffectError> {
        Ok(json!({}))
    }
}

/// Sends one fixed effect.
#[derive(Debug)]
struct SendsFixed {
    arguments: Value,
    sent: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for SendsFixed {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("work.do").provides("work.do")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let value = Tainted::trusted(self.arguments.clone());
        let out = cx
            .sink(
                Fixed {
                    arguments: self.arguments.clone(),
                },
                &value,
            )
            .await?;
        self.sent.fetch_add(1, Ordering::SeqCst);
        Ok(Outcome::done(out))
    }
}

/// **A redaction an effect cannot take refuses it**, rather than sending the
/// value whole — and so does a redact rule matching an object key, because
/// redaction rewrites strings and never the shape.
#[tokio::test]
async fn a_redact_rule_at_a_prebuilt_sink_refuses() {
    let rule = "- id: card
  match: {contains: ['4111']}
  at: {sinks: [tool.call]}
  then: {redact: '[card]'}";
    for (case, arguments) in [
        ("an effect that cannot be rebound", json!({ "pan": "4111" })),
        ("a matched key", json!({ "4111": "x" })),
    ] {
        let store = Arc::new(RedbStore::open_in_memory().expect("store"));
        let sent = Arc::new(AtomicUsize::new(0));
        let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .agent(Agent::new(&manifest(rule, "{}")).skill(SendsFixed {
                arguments,
                sent: Arc::clone(&sent),
            }))
            .build()
            .run("work.do", Tainted::trusted(json!({})))
            .await
            .expect("run");
        assert!(
            matches!(out.status, RunStatus::Failed(_)),
            "{case}: {:?}",
            out.status
        );
        assert_eq!(sent.load(Ordering::SeqCst), 0, "{case}: sent whole");
        assert!(
            store
                .read(out.run_id, 1)
                .await
                .expect("history")
                .iter()
                .any(|r| matches!(
                    r.kind(),
                    RecordKind::PolicyDenied { action, .. } if action == agentplane::core::ACTION_CONTENT
                )),
            "{case}: the refusal is not on the record"
        );
    }
}

/// A checker answering from a script, one answer per call; it panics if it is
/// called with nothing scripted, which is what a replay must never do.
#[derive(Debug)]
struct Scripted {
    answers: std::sync::Mutex<std::collections::VecDeque<Result<Vec<&'static str>, String>>>,
    categories: std::collections::BTreeSet<String>,
    ceiling: agentplane::core::Sensitivity,
}

impl Scripted {
    fn new(answers: Vec<Result<Vec<&'static str>, String>>) -> Arc<Self> {
        Arc::new(Self {
            answers: std::sync::Mutex::new(answers.into()),
            categories: ["S1", "S7"].iter().map(ToString::to_string).collect(),
            ceiling: agentplane::core::Sensitivity::Secret,
        })
    }
}

#[async_trait::async_trait]
impl agentplane::content::ContentChecker for Scripted {
    fn name(&self) -> &'static str {
        "guard"
    }
    fn revision(&self) -> &'static str {
        "1"
    }
    fn categories(&self) -> &std::collections::BTreeSet<String> {
        &self.categories
    }
    fn max_sensitivity(&self) -> agentplane::core::Sensitivity {
        self.ceiling
    }
    async fn check(&self, _value: &Value) -> Result<agentplane::content::Assessment, String> {
        let answer = self
            .answers
            .lock()
            .expect("script")
            .pop_front()
            .expect("the checker was called with nothing scripted");
        answer.map(|categories| agentplane::content::Assessment {
            categories: categories.into_iter().map(ToOwned::to_owned).collect(),
            spend: agentplane::core::Spend::default(),
        })
    }
}

fn guarded(at: &str) -> Manifest {
    let mut source = String::from(
        "apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: guarded, version: \"1.0.0\" }
spec:
  capabilities: { provides: [work.do] }
  models:
    privileged: { provider: fake, model: m-1 }
  budgets: {}
  security:
    content:
      checks:
        - id: guard
          checker: guard
",
    );
    source.push_str("          at: ");
    source.push_str(at);
    source.push('\n');
    source.push_str("          on: {S1: refuse, S7: {classify: confidential}}\n");
    Manifest::parse(&source).expect("the manifest parses")
}

/// **A check nothing could run refuses the build**: a checker no builder
/// registered, and a category the registered checker never reports.
#[test]
fn a_check_naming_an_unregistered_checker_refuses_the_build() {
    let store = || Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn JournalStore>;
    let manifest = guarded("{sinks: [model.complete]}");
    let unregistered = Runtime::builder(store())
        .agent(Agent::new(&manifest).skill(AwaitsReply))
        .try_build()
        .map(|_| ())
        .expect_err("refused")
        .to_string();
    assert!(
        unregistered.contains("no checker named 'guard'"),
        "{unregistered}"
    );

    let narrow = Arc::new(Scripted {
        answers: std::sync::Mutex::default(),
        categories: ["S1"].iter().map(ToString::to_string).collect(),
        ceiling: agentplane::core::Sensitivity::Secret,
    });
    let undeclared = Runtime::builder(store())
        .content_checker(narrow)
        .agent(Agent::new(&manifest).skill(AwaitsReply))
        .try_build()
        .map(|_| ())
        .expect_err("refused")
        .to_string();
    assert!(
        undeclared.contains("'S7' is not a category"),
        "{undeclared}"
    );
}

/// **A checker describes and the table decides; an outage refuses.** Each
/// answer at a sink: a refused category refuses the call, a classified one
/// raises the label past the model's ceiling, an error and an undeclared
/// category refuse. A strict replay reaches every verdict without calling
/// the checker.
#[tokio::test]
async fn a_checker_outage_refuses_the_guarded_call() {
    for (case, answer, refused_by) in [
        (
            "a refused category",
            Ok(vec!["S1"]),
            Some(agentplane::core::ACTION_CONTENT),
        ),
        (
            "a classified category",
            Ok(vec!["S7"]),
            Some(agentplane::core::ACTION_EGRESS),
        ),
        (
            "an outage",
            Err("timed out".to_owned()),
            Some(agentplane::core::ACTION_CONTENT),
        ),
        (
            "an undeclared category",
            Ok(vec!["S9"]),
            Some(agentplane::core::ACTION_CONTENT),
        ),
        ("nothing to report", Ok(vec![]), None),
    ] {
        let store = Arc::new(RedbStore::open_in_memory().expect("store"));
        let provider = FakeProvider::new();
        provider.will_say("fine");
        let build = |checker: Arc<Scripted>| {
            Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
                .content_checker(checker)
                .agent(
                    Agent::new(&guarded("{sinks: [model.complete]}")).skill(Prompts {
                        provider: Arc::clone(&provider),
                        prompt: json!({ "q": "hello" }),
                        attempts: 1,
                        refused: Arc::default(),
                    }),
                )
                .build()
        };
        let out = build(Scripted::new(vec![answer]))
            .run("work.do", Tainted::trusted(json!({})))
            .await
            .expect("run");
        let records = store.read(out.run_id, 1).await.expect("history");
        let denial = records.iter().find_map(|r| match r.kind() {
            RecordKind::PolicyDenied { action, .. } => Some(action.clone()),
            _ => None,
        });
        assert_eq!(denial.as_deref(), refused_by, "{case}: {:?}", out.status);
        assert!(
            records.iter().any(|r| matches!(
                r.kind(),
                RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "content.check"
            )),
            "{case}: the check is not on the record"
        );
        let replay = build(Scripted::new(vec![]))
            .replay(out.run_id, Mode::Strict)
            .await
            .expect("replay");
        assert_eq!(replay.status, out.status, "{case}: the replay re-judged");
    }
}

/// **Sending a value to a checker is egress**: a value above the checker's
/// own ceiling is refused at the check's sink gate, and the guarded call with
/// it.
#[tokio::test]
async fn a_value_above_the_checkers_ceiling_refuses_the_guarded_call() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say("fine");
    let checker = || {
        Arc::new(Scripted {
            answers: std::sync::Mutex::new(vec![Ok(vec![]), Ok(vec![])].into()),
            categories: ["S1", "S7"].iter().map(ToString::to_string).collect(),
            ceiling: agentplane::core::Sensitivity::Public,
        })
    };
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .content_checker(checker())
        .agent(
            Agent::new(&guarded("{sinks: [model.complete]}")).skill(Prompts {
                provider: Arc::clone(&provider),
                prompt: json!({ "q": "hello" }),
                attempts: 1,
                refused: Arc::default(),
            }),
        )
        .build()
        .run(
            "work.do",
            Tainted::with_label(json!({}), agentplane::core::Label::trusted()),
        )
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "a public value: {:?}",
        out.status
    );

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .content_checker(checker())
        .agent(
            Agent::new(&guarded("{sinks: [model.complete]}")).skill(Relays {
                provider: Arc::clone(&provider),
            }),
        )
        .build()
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Failed(_)),
        "{:?}",
        out.status
    );
    assert_eq!(
        provider.calls(),
        2,
        "the first half's call and this half's first: the internal answer was \
         relayed past the check"
    );
}

/// **A check on a call's output** refuses it or raises its label, from the
/// check's record on replay.
#[tokio::test]
async fn a_check_at_a_source_judges_what_the_call_returned() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say(AWS_KEY).will_say("relayed");
    let build = |checker: Arc<Scripted>| {
        Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
            .content_checker(checker)
            .agent(
                Agent::new(&guarded("{sources: [model.complete]}")).skill(Relays {
                    provider: Arc::clone(&provider),
                }),
            )
            .build()
    };
    let out = build(Scripted::new(vec![Ok(vec!["S7"])]))
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    let RunStatus::Failed(reason) = &out.status else {
        panic!(
            "a confidential answer crossed an internal model: {:?}",
            out.status
        );
    };
    assert!(reason.contains("confidential"), "{reason}");
    let replay = build(Scripted::new(vec![]))
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(replay.status, out.status);
}

/// **A sink rule that classifies raises the label the sink judges** — a
/// declared `classify` at a sink is enforced, never decoration.
#[tokio::test]
async fn a_sink_classification_raises_the_label_the_gates_judge() {
    let rule = "- id: salary
  match: {contains: [salary]}
  at: {sinks: [model.complete]}
  then: {classify: confidential}";
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let provider = FakeProvider::new();
    provider.will_say("the salary table").will_say("relayed");
    let out = relay(&store, &provider, rule)
        .run("work.do", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        store
            .read(out.run_id, 1)
            .await
            .expect("history")
            .iter()
            .any(|r| matches!(
                r.kind(),
                RecordKind::PolicyDenied { action, .. } if action == agentplane::core::ACTION_EGRESS
            )),
        "a classified value crossed the model's ceiling: {:?}",
        out.status
    );
}
