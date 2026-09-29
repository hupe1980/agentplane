//! A changed declaration, replayed against the runs it would have made.
//!
//! `Runtime::verify` replays a recorded run strictly under the declarations
//! the plane holds and answers verified, diverged or cannot replay — naming
//! the revision the run was admitted under and the one in hand every time.
//! These tests hold the verdict to what it claims: an edit reaching an effect
//! names that effect and both digests; an edit reaching none says so without
//! calling the revisions the same; a faithful replay of a failure is verified;
//! nothing is written, called or dialled; and an export is a source.
#![cfg(all(feature = "manifest", feature = "testkit"))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::Tainted;
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::runtime::{Agent, Finding, RunStatus, Runtime, replay_only};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

const SUMMARISER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution: { kind: completion }
  identity:
    role: "Summarise a support ticket"
    constraints: "One sentence. No speculation."
  capabilities: { provides: [support.summarise] }
  models:
    privileged: { provider: fake, model: sum-1 }
  output:
    schema:
      type: object
      additionalProperties: false
      required: [summary]
      properties: { summary: { type: string } }
  budgets: { max_tokens: 10000 }
"#;

fn manifest(yaml: &str) -> Manifest {
    Manifest::parse(yaml).expect("the fixture parses")
}

/// Record one run of `yaml` on a fresh store with `provider` answering.
async fn record(
    yaml: &str,
    provider: &Arc<FakeProvider>,
) -> (Arc<RedbStore>, agentplane::core::RunId) {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .provider(
            "fake",
            Arc::clone(provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest(yaml)))
        .build();
    let out = rt
        .run(
            "support.summarise",
            Tainted::trusted(json!({ "ticket": "printer on fire" })),
        )
        .await
        .expect("the run completes");
    (store, out.run_id)
}

/// A plane holding `yaml`, wired with nothing but replay-only drivers.
async fn verifier(
    store: &Arc<RedbStore>,
    run: agentplane::core::RunId,
    yaml: &str,
) -> Arc<Runtime> {
    let journal = Arc::clone(store) as Arc<dyn JournalStore>;
    let history = journal.read(run, 1).await.expect("history");
    let manifests = [manifest(yaml)];
    replay_only::wire(Runtime::builder(journal), &manifests, &history)
        .agent(Agent::new(&manifests[0]))
        .build()
}

fn edited_instruction() -> String {
    let edited = SUMMARISER.replace("One sentence.", "Two sentences.");
    assert_ne!(edited, SUMMARISER, "the fixture edited nothing");
    edited
}

/// **An edit that reaches an effect names it, and both revisions.**
///
/// The instruction is an argument of the model call, so the edit recomputes a
/// different key at the first completion. What an author needs is where, and
/// under which two declarations — a report naming two effect keys and neither
/// revision cannot be acted on, and one that drops the candidate's digest
/// reads as a verdict on the recorded revision alone.
#[tokio::test]
async fn a_strict_replay_under_an_edited_instruction_names_both_revisions_and_the_step() {
    let provider = FakeProvider::new();
    let (store, run) = record(SUMMARISER, &provider).await;
    let calls = provider.calls();

    let edited = edited_instruction();
    let verdict = verifier(&store, run, &edited)
        .await
        .verify(run)
        .await
        .expect("a verdict, not an error");

    let Finding::Diverged(divergence) = &verdict.finding else {
        panic!("an edited instruction replayed without diverging: {verdict}");
    };
    assert_eq!(divergence.step.to_string(), "s0");
    assert_eq!(divergence.kind.as_deref(), Some("model.complete"));
    assert!(
        divergence.recorded.is_some() && divergence.recomputed.is_some(),
        "a changed argument has both keys: {divergence:?}"
    );
    let recorded = verdict.recorded.as_ref().expect("the recorded revision");
    let candidate = verdict.candidate.as_ref().expect("the candidate revision");
    assert_eq!(recorded.digest, manifest(SUMMARISER).digest().unwrap());
    assert_eq!(candidate.digest, manifest(&edited).digest().unwrap());
    assert!(!verdict.same_revision());

    let report = verdict.to_string();
    for needle in [
        recorded.digest.to_string(),
        candidate.digest.to_string(),
        "step s0".to_owned(),
        "different digest".to_owned(),
    ] {
        assert!(
            report.contains(&needle),
            "the report omits `{needle}`:\n{report}"
        );
    }
    assert_eq!(provider.calls(), calls, "a strict replay called the model");
}

/// **No divergence under a different digest names both, and says so.**
///
/// An annotation is never read, so it reaches no effect — and it changes the
/// digest. The honest answer is *no divergence on this run*, beside both
/// digests; a report reading as *the same revision* would tell a reviewer an
/// edit is inert when all it shows is that this run never reached it.
#[tokio::test]
async fn an_edit_no_effect_reaches_verifies_with_both_digests_named() {
    let provider = FakeProvider::new();
    let (store, run) = record(SUMMARISER, &provider).await;
    let annotated = SUMMARISER.replace(
        r#"metadata: { name: summariser, version: "1.0.0" }"#,
        r#"metadata: { name: summariser, version: "1.0.0", annotations: { example.com/owner: "support" } }"#,
    );
    assert_ne!(annotated, SUMMARISER, "the fixture edited nothing");

    let verdict = verifier(&store, run, &annotated)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(verdict.is_verified(), "{verdict}");
    assert!(!verdict.same_revision(), "the annotation moved the digest");

    let report = verdict.to_string();
    assert!(
        report.contains("no divergence on this run"),
        "a verified replay under another digest read as the same revision:\n{report}"
    );
    for digest in [&verdict.recorded, &verdict.candidate] {
        let digest = digest.as_ref().expect("both revisions").digest.to_string();
        assert!(report.contains(&digest), "{report}");
    }

    // And under the recorded revision itself, the plain answer.
    let same = verifier(&store, run, SUMMARISER)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(same.is_verified() && same.same_revision(), "{same}");
    assert!(same.to_string().contains("same digest"), "{same}");
}

/// **A faithful replay of a run that recorded a failure is verified.**
///
/// The recorded ending is what is verified, not whether it was a success. A
/// verdict that called every failed run a failure would have CI read a
/// perfectly reproduced refusal as a regression.
#[tokio::test]
async fn a_faithful_replay_of_a_failed_run_is_verified() {
    let provider = FakeProvider::new();
    provider.will_fail(agentplane::model::ModelError::Refused {
        model: agentplane::model::ModelId::new("fake", "sum-1"),
        detail: "the provider refused".to_owned(),
    });
    let (store, run) = record(SUMMARISER, &provider).await;
    let recorded = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .build()
        .recorded_outcome(run)
        .await
        .expect("outcome");
    assert!(
        matches!(
            recorded.as_ref().map(|o| &o.status),
            Some(RunStatus::Failed(_))
        ),
        "the fixture was meant to fail: {recorded:?}"
    );

    let verdict = verifier(&store, run, SUMMARISER)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert_eq!(
        verdict.finding,
        Finding::Verified {
            outcome: "failed".to_owned()
        },
        "{verdict}"
    );
}

/// **A strict replay under an edit writes nothing, diverging or not.**
///
/// The chain head, the log and the outcome index are compared before and
/// after. A verification pass that appended its conclusion would put a
/// quarantine for a divergence nobody ran into a run's permanent history.
#[tokio::test]
async fn a_strict_replay_under_an_edited_declaration_leaves_the_store_unchanged() {
    let provider = FakeProvider::new();
    let (store, run) = record(SUMMARISER, &provider).await;
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let before = (
        journal.checkpoint().await.unwrap(),
        journal.head(run).await.unwrap(),
        journal.count_by_outcome("succeeded").await.unwrap(),
        journal.count_by_outcome("quarantined").await.unwrap(),
    );

    let diverged = verifier(&store, run, &edited_instruction())
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(diverged.is_diverged(), "{diverged}");
    let verified = verifier(&store, run, SUMMARISER)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(verified.is_verified(), "{verified}");

    let after = (
        journal.checkpoint().await.unwrap(),
        journal.head(run).await.unwrap(),
        journal.count_by_outcome("succeeded").await.unwrap(),
        journal.count_by_outcome("quarantined").await.unwrap(),
    );
    assert_eq!(before, after, "a strict replay moved the store");
}

/// **An export is a source: every run it holds, listed and replayed.**
///
/// The file is rebuilt in memory and checked against its own checkpoint, so a
/// CI job holding exports and a pull request's manifest needs no store and
/// writes none.
#[tokio::test]
async fn a_run_replays_from_an_export_with_no_store_path() {
    let provider = FakeProvider::new();
    let (store, run) = record(SUMMARISER, &provider).await;
    let mut file = Vec::new();
    agentplane::export::to_jsonl(
        &(Arc::clone(&store) as Arc<dyn JournalStore>),
        Some(&(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)),
        &[run],
        &mut file,
    )
    .await
    .expect("export");

    let source = agentplane::export::open_for_replay(file.as_slice())
        .await
        .expect("the export restores into memory");
    assert_eq!(source.runs, vec![run], "the source lists the runs it holds");

    let diverged = verifier(&source.store, run, &edited_instruction())
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(diverged.is_diverged(), "{diverged}");
    let verified = verifier(&source.store, run, SUMMARISER)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(verified.is_verified(), "{verified}");
}

// ── Tool calls, with nothing to call ────────────────────────────────────────

const TELLER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  capabilities:
    provides: [ledger.ask]
  identity:
    role: A teller.
  models:
    privileged: { provider: fake, model: teller-1 }
  tools:
    - ref: tool://ledger/read
      mutates: false
      max_sensitivity: internal
      description: Read a balance.
  execution: { kind: tool-calling, max_turns: 3 }
  security: { max_sensitivity_egress: internal }
  budgets: {}
"#;

/// A tool server that answers and counts.
#[derive(Debug, Default)]
struct Ledger(AtomicUsize);

#[async_trait::async_trait]
impl agentplane::tools::ToolClient for Ledger {
    async fn call(
        &self,
        _tool: &agentplane::tools::ToolId,
        _arguments: &Value,
        _provenance: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, agentplane::tools::ToolError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({ "balance": 42 }))
    }

    fn destination(&self, _tool: &agentplane::tools::ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

/// **A tool-calling run replays with no transport and no credential.**
///
/// Recorded against a real tool server and a model; verified with only the
/// replay-only drivers, which refuse every call. A verdict at all is the
/// proof that nothing was reached — a call would have been refused and the
/// run would have ended otherwise — and the counters say it twice.
#[tokio::test]
async fn a_tool_calling_run_replays_with_no_transport_and_no_credentials() {
    let provider = FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__read", json!({ "account": "AC-1" }));
    provider.will_say("the balance is 42");
    let ledger = Arc::new(Ledger::default());

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .provider(
            "fake",
            Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .tool_server(
            "ledger",
            Arc::clone(&ledger) as Arc<dyn agentplane::tools::ToolClient>,
        )
        .agent(Agent::new(&manifest(TELLER)))
        .build();
    let out = rt
        .run("ledger.ask", Tainted::trusted(json!({ "q": "AC-1?" })))
        .await
        .expect("the run completes");
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(
        ledger.0.load(Ordering::SeqCst),
        1,
        "the fixture called the tool once"
    );
    let calls = provider.calls();

    let verdict = verifier(&store, out.run_id, TELLER)
        .await
        .verify(out.run_id)
        .await
        .expect("a verdict");
    assert!(verdict.is_verified(), "{verdict}");
    assert_eq!(
        ledger.0.load(Ordering::SeqCst),
        1,
        "a strict replay called the tool"
    );
    assert_eq!(provider.calls(), calls, "a strict replay called the model");
}

// ── What cannot be replayed is not a divergence ─────────────────────────────

/// **History under another canonicalization rule cannot be replayed here.**
///
/// Every effect key comes out of the canonicalizer, so a rule change moves
/// all of them at once: reported as divergence, it would tell an author their
/// edit broke a run it never reached.
#[tokio::test]
async fn a_run_under_another_canonicalization_rule_cannot_be_replayed() {
    use agentplane::journal::{Append, RecordKind};
    use agentplane::runtime::CannotReplay;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let run = agentplane::core::RunId::generate();
    let lease = journal
        .acquire(run, "canon", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    journal
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "support.summarise".into(),
                    governed_by: None,
                    input: json!({}),
                    input_label: agentplane::core::Label::trusted(),
                    policy_bundle: None,
                    canon: 999,
                    idempotency_key: None,
                    admitted_by: None,
                    served_unchained: false,
                },
            )],
        )
        .await
        .unwrap();

    let verdict = verifier(&store, run, SUMMARISER)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert!(
        matches!(
            verdict.finding,
            Finding::CannotReplay(CannotReplay::CanonicalizationChanged { recorded: 999, .. })
        ),
        "a rule change was reported as something else: {verdict}"
    );
}

/// **An edit that removes the run's entry point says so, with both
/// revisions.**
///
/// The run executed a capability the edited file no longer provides. That is
/// a finding about the edit, and a precise one: not *diverged at an effect*,
/// which it never reached.
#[tokio::test]
async fn a_manifest_that_no_longer_provides_the_capability_cannot_replay_it() {
    use agentplane::runtime::CannotReplay;

    let provider = FakeProvider::new();
    let (store, run) = record(SUMMARISER, &provider).await;
    let renamed = SUMMARISER.replace(
        "provides: [support.summarise]",
        "provides: [support.digest]",
    );
    assert_ne!(renamed, SUMMARISER, "the fixture edited nothing");

    let verdict = verifier(&store, run, &renamed)
        .await
        .verify(run)
        .await
        .expect("a verdict");
    assert_eq!(
        verdict.finding,
        Finding::CannotReplay(CannotReplay::EntryPointRemoved {
            capability: "support.summarise".to_owned()
        }),
        "{verdict}"
    );
    assert!(verdict.recorded.is_some() && verdict.candidate.is_some());
    assert!(!verdict.same_revision(), "{verdict}");
}
