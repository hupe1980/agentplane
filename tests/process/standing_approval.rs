//! A call somebody approved in advance opens no task, and the journal says who.
//!
//! The plane is the approval plane from `tasks.rs`: a tool-calling teller whose
//! one grant requires approval. What varies is the standing approval issued to
//! the run's holder, and each test pins one way it must fail to apply.

#![cfg(all(feature = "manifest", feature = "testkit"))]

use std::sync::Arc;

use agentplane::authority::{ApprovalRule, AuthorityStore, Holder, Matcher, StandingAuthority};
use agentplane::case::{CaseStore, EventStore, TaskStore};
use agentplane::core::{CorrelationKey, Operator, Tainted, Timestamp};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use agentplane::tools::{Tool, ToolBox, ToolFailure};
use serde_json::{Value, json};

/// Long after any run here.
fn later() -> Timestamp {
    Timestamp::from_unix_timestamp(4_102_444_800).expect("2100-01-01")
}

/// Long before any run here.
fn earlier() -> Timestamp {
    Timestamp::from_unix_timestamp(946_684_800).expect("2000-01-01")
}

fn rule(recipient: &str) -> ApprovalRule {
    ApprovalRule::new(
        "tool://ledger/transfer",
        "/recipient",
        Matcher::Exact(json!(recipient)),
    )
}

fn dana() -> Operator {
    Operator::asserted("dana").expect("an operator")
}

struct Plane {
    rt: Arc<Runtime>,
    store: Arc<RedbStore>,
}

/// The teller, with `protected` as its `/recipient` rule, and one scripted
/// transfer to `AC-9` per run.
fn plane(protected: &str, runs: usize) -> Plane {
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
            Ok(json!({ "moved": self.amount, "to": self.recipient }))
        }
    }

    let manifest = agentplane::manifest::Manifest::parse(&format!(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: teller, version: "1.0.0" }}
spec:
  capabilities: {{ provides: [desk.pay] }}
  models: {{ privileged: {{ provider: fake, model: m-1 }} }}
  execution: {{ kind: tool-calling, max_turns: 4 }}
  security: {{ max_sensitivity_egress: internal }}
  oversight:
    approval: tools-only
    deadline: {{ name: payment-review, kind: hours, params: {{ n: 4 }} }}
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      description: Move funds between accounts.
      requires_approval: true
      max_sensitivity: internal
      protected_fields:
{protected}
  budgets: {{}}
"#
    ))
    .expect("manifest");

    let provider = FakeProvider::new();
    for i in 0..runs {
        provider.will_call_tool(
            format!("call_{i}"),
            "ledger__transfer",
            json!({ "recipient": "AC-9", "amount": 250_000 }),
        );
        provider.will_say("done");
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .tasks(Arc::clone(&store) as Arc<dyn TaskStore>)
        .authorities(Arc::clone(&store) as Arc<dyn AuthorityStore>)
        .provider(
            "fake",
            provider as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(Agent::new(&manifest))
        .toolbox(ToolBox::new().with::<Transfer>())
        .build();
    Plane { rt, store }
}

/// The model's own authorship is allowed, so the field rule admits the call
/// and only the approval gate stands between it and the ledger.
const MODEL_AUTHORED: &str =
    "        - path: /recipient\n          allowed_sources: [model:fake/m-1]";

async fn pay(plane: &Plane, invoice: &str) -> agentplane::runtime::RunOutcome {
    plane
        .rt
        .run_correlated(
            "desk.pay",
            Tainted::trusted(json!({ "instruction": format!("pay {invoice}") })),
            "payment",
            &[CorrelationKey::new("invoice", invoice)],
        )
        .await
        .expect("the run is admitted")
}

/// How many effects of `kind` the run started.
async fn started(plane: &Plane, run: agentplane::core::RunId, kind: &str) -> usize {
    plane
        .store
        .read(run, 1)
        .await
        .expect("read")
        .iter()
        .filter(|r| {
            matches!(r.kind(), RecordKind::EffectStarted { descriptor, .. }
                if descriptor.kind == kind)
        })
        .count()
}

/// A matching call dispatches with no task, the draw is on the record, and a
/// strict replay reads it back even after the rule is revoked.
#[tokio::test]
async fn a_call_approved_in_advance_opens_no_task_and_replays_from_the_record() {
    let plane = plane(MODEL_AUTHORED, 1);
    let approval = StandingAuthority::approval(
        "pay-ac9",
        Holder::Tenant,
        dana(),
        "INV standing order",
        rule("AC-9"),
        later(),
    );
    plane.store.issue(&approval).await.expect("issue");

    let out = pay(&plane, "INV-1").await;
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "{:?}",
        out.status
    );
    assert_eq!(
        started(&plane, out.run_id, "tool.call").await,
        1,
        "the approved call did not dispatch"
    );
    assert_eq!(
        started(&plane, out.run_id, "authority.draw").await,
        1,
        "the approval is not on the record"
    );

    plane
        .store
        .revoke(&approval.id, "order cancelled", later())
        .await
        .expect("revoke");
    let replayed = plane
        .rt
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("strict replay");
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "replay re-matched against today's rules instead of reading the recorded decision: {:?}",
        replayed.status
    );
}

/// Every way a rule may fail to apply leaves the call to a person.
#[tokio::test]
async fn a_rule_that_does_not_apply_leaves_the_call_to_a_person() {
    let cases: Vec<(&str, StandingAuthority)> = vec![
        (
            "another recipient",
            StandingAuthority::approval("r", Holder::Tenant, dana(), "b", rule("AC-1"), later()),
        ),
        (
            "an expired rule",
            StandingAuthority::approval("r", Holder::Tenant, dana(), "b", rule("AC-9"), earlier()),
        ),
        (
            "another holder",
            StandingAuthority::approval(
                "r",
                Holder::subject("alice"),
                dana(),
                "b",
                rule("AC-9"),
                later(),
            ),
        ),
        (
            "another tool",
            StandingAuthority::approval(
                "r",
                Holder::Tenant,
                dana(),
                "b",
                ApprovalRule::new(
                    "tool://ledger/refund",
                    "/recipient",
                    Matcher::Exact(json!("AC-9")),
                ),
                later(),
            ),
        ),
    ];
    for (case, authority) in cases {
        let plane = plane(MODEL_AUTHORED, 1);
        plane.store.issue(&authority).await.expect("issue");
        let out = pay(&plane, "INV-2").await;
        assert!(
            matches!(out.status, RunStatus::Suspended(_)),
            "{case}: the call was approved without asking anybody: {:?}",
            out.status
        );
        assert_eq!(
            started(&plane, out.run_id, "tool.call").await,
            0,
            "{case}: money moved"
        );
    }
}

/// A revoked rule and a spent one are refused at the draw.
#[tokio::test]
async fn a_revoked_or_spent_rule_leaves_the_call_to_a_person() {
    let plane = plane(MODEL_AUTHORED, 3);
    let once =
        StandingAuthority::approval("once", Holder::Tenant, dana(), "b", rule("AC-9"), later())
            .max_draws(1);
    plane.store.issue(&once).await.expect("issue");

    let first = pay(&plane, "INV-3").await;
    assert!(
        matches!(first.status, RunStatus::Succeeded),
        "{:?}",
        first.status
    );
    let second = pay(&plane, "INV-4").await;
    assert!(
        matches!(second.status, RunStatus::Suspended(_)),
        "a rule good for one call approved a second: {:?}",
        second.status
    );

    let plane = plane_with_revoked().await;
    let out = pay(&plane, "INV-5").await;
    assert!(
        matches!(out.status, RunStatus::Suspended(_)),
        "a revoked rule approved a call: {:?}",
        out.status
    );
}

async fn plane_with_revoked() -> Plane {
    let plane = plane(MODEL_AUTHORED, 1);
    let rule =
        StandingAuthority::approval("gone", Holder::Tenant, dana(), "b", rule("AC-9"), later());
    plane.store.issue(&rule).await.expect("issue");
    plane
        .store
        .revoke(&rule.id, "withdrawn", earlier())
        .await
        .expect("revoke");
    plane
}

/// A rule decides approval and nothing else: the grant's field rule still
/// refuses the model as the recipient's author.
#[tokio::test]
async fn a_rule_cannot_admit_what_the_field_rules_refuse() {
    let plane = plane(
        "        - path: /recipient\n          require_trusted: true",
        1,
    );
    let approval = StandingAuthority::approval(
        "pay-ac9",
        Holder::Tenant,
        dana(),
        "b",
        rule("AC-9"),
        later(),
    );
    plane.store.issue(&approval).await.expect("issue");
    let out = pay(&plane, "INV-6").await;
    // The rule applied — no task was opened — so what refused the call is the
    // field rule and not the absence of an approval.
    assert!(
        !matches!(out.status, RunStatus::Suspended(_)),
        "the rule did not apply, so this test proves nothing: {:?}",
        out.status
    );
    assert_eq!(started(&plane, out.run_id, "authority.draw").await, 1);
    assert_eq!(
        started(&plane, out.run_id, "tool.call").await,
        0,
        "an approval issued in advance released an argument the grant refuses"
    );
}
