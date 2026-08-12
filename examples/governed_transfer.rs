//! Field-level provenance at the boundary that matters: a mutating tool call.
//!
//! ```sh
//! cargo run --example governed_transfer --features manifest
//! ```
//!
//! The recipient is authority-bearing; the memo is ordinary content. The
//! runtime therefore permits an untrusted memo beside a trusted recipient,
//! refuses an untrusted recipient before the client is called, and accepts a
//! precisely scoped, policy-authorized release carrying evidence.
//!
//! # The reach a coded skill has is the reach its manifest declared
//!
//! This example used to hand-build a `ToolCatalog` inside the skill and call
//! `ToolCall::prepare` against it, which is what a reader copies. Nothing bound
//! that catalogue to the declaration governing the skill, so the reach it
//! granted was whatever the code said — and it could be *laxer* than the
//! manifest, which is the dangerous direction: a `read_only` entry for a tool
//! the manifest calls mutating exempts it from the whole-value taint gate and
//! makes a timed-out payment retryable.
//!
//! So the catalogue comes from the manifest — `ToolCatalog::from_manifest`,
//! stated once — and the skill dispatches through `cx.call_tool`, which uses the
//! plane's own checked catalogue. The `protected_fields` rule below is declared
//! in the YAML a reviewer reads, and nowhere else.

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Outcome, Release, ReleaseScope, Skill, SkillDescriptor, SkillError, SourceId, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::runtime::{Agent, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::tools::{ToolCatalog, ToolClient, ToolError, ToolId};
use serde_json::{Value, json};

/// The whole declaration, including the field rule that does the work.
const MANIFEST: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: treasury
  version: "1.0.0"
spec:
  capabilities:
    provides: [ledger.transfer]
  budgets: { max_effects: 8 }
  security:
    max_sensitivity_egress: internal
  tools:
    - ref: "tool://ledger/transfer"
      mutates: true
      max_sensitivity: internal
      protected_fields:
        - path: /recipient
          require_trusted: true
"#;

fn transfer() -> ToolId {
    ToolId::new("ledger", "transfer")
}

#[derive(Debug, Default)]
struct Ledger {
    calls: Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl ToolClient for Ledger {
    async fn call(
        &self,
        _tool: &ToolId,
        arguments: &Value,
        _provenance: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, ToolError> {
        self.calls.lock().unwrap().push(arguments.clone());
        Ok(json!({ "posted": true }))
    }
}

/// No catalogue, no client, no `Arc<dyn ToolClient>`.
///
/// The skill holds nothing that could disagree with the declaration governing
/// it. That is the whole difference from the earlier version of this file.
#[derive(Debug)]
struct Transfer;

#[async_trait::async_trait]
impl Skill for Transfer {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("transfer").provides("ledger.transfer")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let scenario = input
            .peek()
            .get("scenario")
            .and_then(Value::as_str)
            .unwrap_or("trusted");

        let recipient = match scenario {
            "trusted" => Tainted::trusted(json!("treasury")),
            _ => Tainted::from_source(json!("treasury"), SourceId::new("model.complete")),
        };
        let arguments = Tainted::object([
            ("recipient".to_owned(), recipient),
            (
                "memo".to_owned(),
                Tainted::from_source(
                    json!("model-written description may remain untrusted"),
                    SourceId::new("model.complete"),
                ),
            ),
            ("amount".to_owned(), Tainted::trusted(json!(1250))),
        ]);

        let arguments = if scenario == "released" {
            cx.release(
                arguments,
                Release::fields(
                    ReleaseScope::trust(),
                    ["/recipient".to_owned()],
                    "operator matched the account to settlement SET-42",
                    "tool://ledger/transfer",
                    ["approval:SET-42".to_owned()],
                ),
            )
            .await?
        } else {
            arguments
        };

        // The labels travel with the arguments, so the protected-field rule the
        // manifest declares is decided on the value that will actually be sent.
        Ok(Outcome::done(cx.call_tool(transfer(), arguments).await?))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let ledger = Arc::new(Ledger::default());
    let manifest = Manifest::parse(MANIFEST)?;

    // One declaration, read twice: the plane's catalogue is *derived* from it,
    // so the ceiling and the field rule are stated in the reviewed file and
    // nowhere else. Stating them again in Rust would be one decision written
    // twice and a chance to disagree about it.
    let catalog = ToolCatalog::from_manifest(&manifest);

    let runtime = Runtime::builder(Arc::clone(&store))
        .tools(
            Arc::new(catalog),
            Arc::clone(&ledger) as Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&manifest).skill(Transfer))
        .try_build()?;

    let trusted = runtime
        .run(
            "ledger.transfer",
            Tainted::trusted(json!({ "scenario": "trusted" })),
        )
        .await?;
    println!(
        "1. trusted recipient + untrusted memo → {:?}",
        trusted.status
    );
    assert_eq!(trusted.status, RunStatus::Succeeded);
    assert_eq!(ledger.calls.lock().unwrap().len(), 1);

    let refused = runtime
        .run(
            "ledger.transfer",
            Tainted::trusted(json!({ "scenario": "untrusted" })),
        )
        .await?;
    println!(
        "2. untrusted recipient                → {:?}",
        refused.status
    );
    assert!(matches!(refused.status, RunStatus::Failed(_)));
    assert_eq!(
        ledger.calls.lock().unwrap().len(),
        1,
        "refused before dispatch"
    );

    let released = runtime
        .run(
            "ledger.transfer",
            Tainted::trusted(json!({ "scenario": "released" })),
        )
        .await?;
    println!(
        "3. field release with evidence        → {:?}",
        released.status
    );
    assert_eq!(released.status, RunStatus::Succeeded);
    assert_eq!(ledger.calls.lock().unwrap().len(), 2);

    for run in [trusted.run_id, refused.run_id, released.run_id] {
        store.verify(run).await?;
    }
    println!("4. all three decision trails verify");

    Ok(())
}
