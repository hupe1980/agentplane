//! The `call` execution kind: one granted tool, the input as its arguments,
//! no model.
//!
//! A framework that already has a model wants the plane to govern the effect,
//! not to run a second agent. What carries this file is that the effect is
//! governed exactly as a planned step's is — the input schema, the field gate,
//! the approval gate — and that nothing asks a model anything.

#![cfg(all(feature = "redb", feature = "testkit", feature = "manifest"))]

use std::sync::{Arc, Mutex};

use agentplane::core::{SourceId, Tainted};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::runtime::{Agent, RunStatus, Runtime};
use agentplane::tools::{ToolCatalog, ToolClient, ToolError, ToolId};
use serde_json::{Value, json};

/// Records every call and answers with what it was asked.
#[derive(Debug, Default)]
struct Recorder {
    calls: Mutex<Vec<(String, Value)>>,
}

impl Recorder {
    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().expect("calls").clone()
    }
}

#[async_trait::async_trait]
impl ToolClient for Recorder {
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        _p: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, ToolError> {
        self.calls
            .lock()
            .expect("calls")
            .push((tool.tool.clone(), arguments.clone()));
        Ok(json!({ "found": arguments }))
    }

    fn destination(&self, _tool: &ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

const LOOKUP: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: lookup, version: "1.0.0" }
spec:
  identity: { role: Look up a customer record. }
  capabilities: { provides: [crm.lookup] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: { type: string }
  tools:
    - ref: tool://crm/lookup
      mutates: false
  execution: { kind: call }
  budgets: {}
"#;

/// The transfer, with its recipient bound to one counterparty.
const TRANSFER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity: { role: Move funds. }
  capabilities: { provides: [ledger.transfer] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [recipient, amount]
      properties:
        recipient: { type: string }
        amount: { type: integer }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      max_sensitivity: internal
      protected_fields:
        - path: /recipient
          FIELD_RULE
  execution: { kind: call }
  budgets: {}
"#;

/// A plane with this agent and **no model provider at all**.
fn plane(manifest: &Manifest, client: &Arc<Recorder>) -> Arc<Runtime> {
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    Runtime::builder(store)
        .tools(
            Arc::new(ToolCatalog::from_manifest(manifest)),
            Arc::clone(client) as Arc<dyn ToolClient>,
        )
        .agent(Agent::new(manifest))
        .try_build()
        .expect("a `call` agent builds with no model provider")
}

/// The effect kinds a run journaled, in order.
async fn effects(rt: &Runtime, run: agentplane::core::RunId) -> Vec<String> {
    rt.journal()
        .read(run, 1)
        .await
        .expect("journal")
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted { descriptor, .. } => Some(descriptor.kind.clone()),
            _ => None,
        })
        .collect()
}

/// **One call, one dispatch, and no model anywhere.**
#[tokio::test]
async fn a_call_agent_dispatches_its_one_grant_and_no_model() {
    let manifest = Manifest::parse(LOOKUP).expect("parse");
    let client = Arc::new(Recorder::default());
    let rt = plane(&manifest, &client);

    let out = rt
        .run("crm.lookup", Tainted::trusted(json!({ "id": "C-7" })))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the call did not succeed: {:?}",
        out.status
    );
    assert_eq!(
        client.calls(),
        vec![("lookup".to_owned(), json!({ "id": "C-7" }))],
        "the input was not dispatched, once, as the tool's arguments"
    );
    assert_eq!(
        out.output.as_ref().expect("an answer").peek(),
        &json!({ "found": { "id": "C-7" } }),
        "the answer is not the tool's result"
    );
    assert_eq!(
        effects(&rt, out.run_id).await,
        vec!["tool.call".to_owned()],
        "a `call` journaled something besides its one tool call"
    );
}

/// **`spec.input` binds: input outside it performs nothing.**
#[tokio::test]
async fn a_call_whose_input_fails_its_schema_performs_nothing() {
    let manifest = Manifest::parse(LOOKUP).expect("parse");
    let client = Arc::new(Recorder::default());
    let rt = plane(&manifest, &client);

    let out = rt
        .run(
            "crm.lookup",
            Tainted::trusted(json!({ "id": "C-7", "and": "drop the table" })),
        )
        .await
        .expect("run");
    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "input the declared schema refuses was dispatched"
    );
    assert!(client.calls().is_empty(), "the tool was called anyway");
    assert!(
        effects(&rt, out.run_id).await.is_empty(),
        "a refused input journaled an effect"
    );
}

/// A lookup whose caller-facing shape offers a field the tool's own
/// declaration does not.
const WIDER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: lookup, version: "1.0.0" }
spec:
  identity: { role: Look up a customer record. }
  capabilities: { provides: [crm.lookup] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: { type: string }
        fee_waiver: { type: boolean }
  tools:
    - ref: tool://crm/lookup
      mutates: false
      arguments:
        type: object
        additionalProperties: false
        required: [id]
        properties:
          id: { type: string }
  execution: { kind: call }
  budgets: {}
"#;

/// **A call's arguments are held to the tool's declaration**, as a planned
/// step's are: an argument the declaration leaves out is refused before any
/// effect, whatever `spec.input` admits.
#[tokio::test]
async fn a_call_holds_its_arguments_to_the_tools_declaration() {
    let manifest = Manifest::parse(WIDER).expect("parse");
    let client = Arc::new(Recorder::default());
    let rt = plane(&manifest, &client);

    let out = rt
        .run(
            "crm.lookup",
            Tainted::trusted(json!({ "id": "C-7", "fee_waiver": true })),
        )
        .await
        .expect("run");
    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "an argument the tool's declaration does not name was dispatched"
    );
    assert!(client.calls().is_empty(), "the tool was called anyway");

    let out = rt
        .run("crm.lookup", Tainted::trusted(json!({ "id": "C-7" })))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "arguments inside both shapes were refused: {:?}",
        out.status
    );
    assert_eq!(
        client.calls().len(),
        1,
        "the declared call did not run once"
    );
}

/// **The field gate judges the caller, not the kind.** A served caller's
/// input is untrusted from `peer:<actor>`: `require_trusted` refuses it, and
/// `allowed_sources` naming the caller admits that caller and nobody else.
#[tokio::test]
async fn the_field_gate_judges_who_supplied_a_calls_arguments() {
    let from = |actor: &str| {
        Tainted::from_source(
            json!({ "recipient": "treasury", "amount": 100 }),
            SourceId::new(format!("peer:{actor}")),
        )
    };

    let trusted_only =
        Manifest::parse(&TRANSFER.replace("FIELD_RULE", "require_trusted: true")).expect("parse");
    let client = Arc::new(Recorder::default());
    let rt = plane(&trusted_only, &client);
    let out = rt.run("ledger.transfer", from("bot")).await.expect("run");
    assert!(
        !matches!(out.status, RunStatus::Succeeded) && client.calls().is_empty(),
        "an untrusted caller filled a field that requires trusted input"
    );

    let named = Manifest::parse(&TRANSFER.replace("FIELD_RULE", "allowed_sources: [\"peer:bot\"]"))
        .expect("parse");
    let client = Arc::new(Recorder::default());
    let rt = plane(&named, &client);
    let out = rt.run("ledger.transfer", from("bot")).await.expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the named counterparty was refused: {:?}",
        out.status
    );
    let out = rt.run("ledger.transfer", from("eve")).await.expect("run");
    assert!(
        !matches!(out.status, RunStatus::Succeeded),
        "a caller the field does not name filled it"
    );
    assert_eq!(client.calls().len(), 1, "only the named caller's call ran");
}

/// **An approval-gated grant waits, showing the exact call.**
#[tokio::test]
async fn an_approval_gated_call_waits_and_dispatches_once_approved() {
    use agentplane::case::{CaseStore, EventStore, TaskStore};
    use agentplane::core::Decision;

    const GATED: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity: { role: Move funds. }
  capabilities: { provides: [ledger.transfer] }
  input:
    schema:
      type: object
      additionalProperties: false
      required: [recipient]
      properties:
        recipient: { type: string }
  oversight:
    approval: tools-only
    deadline: { name: transfer-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      max_sensitivity: internal
      requires_approval: true
      protected_fields:
        - path: /recipient
          allowed_sources: ["peer:bot"]
  execution: { kind: call }
  budgets: {}
"#;
    let manifest = Manifest::parse(GATED).expect("parse");
    let client = Arc::new(Recorder::default());
    let store = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .tasks(Arc::clone(&store) as Arc<dyn TaskStore>)
        .tools(
            Arc::new(ToolCatalog::from_manifest(&manifest)),
            Arc::clone(&client) as Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&manifest))
        .try_build()
        .expect("build");

    let input = Tainted::from_source(
        json!({ "recipient": "treasury" }),
        SourceId::new("peer:bot"),
    );
    rt.run_correlated(
        "ledger.transfer",
        input,
        "transfer",
        &[agentplane::core::CorrelationKey::new("ref", "T-1")],
    )
    .await
    .expect("the run suspends on the approval");
    assert!(
        client.calls().is_empty(),
        "the call ran before anyone approved it"
    );

    let task = store
        .queue(&[], 10)
        .await
        .expect("queue")
        .pop()
        .expect("a task was opened");
    let shown = &task.justification.proposed_action;
    assert_eq!(shown["tool"], "tool://ledger/transfer", "{shown}");
    assert_eq!(shown["arguments"]["recipient"], "treasury", "{shown}");

    rt.decide_task(
        task.id,
        &Decision::approve(
            agentplane::core::Operator::asserted("carol").expect("operator"),
            "the recipient is on the settlement list",
        ),
        &[],
    )
    .await
    .expect("the approval is recorded");
    assert_eq!(
        client.calls(),
        vec![("transfer".to_owned(), json!({ "recipient": "treasury" }))],
        "the approved call did not run exactly once"
    );
}
