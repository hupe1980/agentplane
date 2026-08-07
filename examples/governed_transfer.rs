//! Field-level provenance at the boundary that matters: a mutating tool call.
//!
//! ```sh
//! cargo run --example governed_transfer
//! ```
//!
//! The recipient is authority-bearing; the memo is ordinary content. The
//! runtime therefore permits an untrusted memo beside a trusted recipient,
//! refuses an untrusted recipient before the client is called, and accepts a
//! precisely scoped, policy-authorized release carrying evidence.

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Outcome, ProtectedField, Release, ReleaseScope, Sensitivity, Skill, SkillDescriptor,
    SkillError, SourceId, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::tools::{ToolCall, ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety};
use serde_json::{Value, json};

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

#[derive(Debug)]
struct Transfer {
    catalog: ToolCatalog,
    ledger: Arc<Ledger>,
}

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

        let call = ToolCall::prepare(
            &self.catalog,
            Arc::clone(&self.ledger) as Arc<dyn ToolClient>,
            transfer(),
            arguments.peek().clone(),
        )?;

        // Tool calls cannot use `cx.effect`: carrying outbound arguments forces
        // them through `sink`, which binds the exact bytes to these labels.
        let result = cx.sink(call, &arguments).await?;
        Ok(Outcome::done(result))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let ledger = Arc::new(Ledger::default());
    let catalog = ToolCatalog::new().allow(
        transfer(),
        ToolSafety::default()
            .max_sensitivity(Sensitivity::Internal)
            .protect(ProtectedField::trusted("/recipient")),
    );
    let runtime = Runtime::builder(Arc::clone(&store))
        .skill(Transfer {
            catalog,
            ledger: Arc::clone(&ledger),
        })
        .build();

    let trusted = runtime
        .run("ledger.transfer", json!({ "scenario": "trusted" }))
        .await?;
    println!(
        "1. trusted recipient + untrusted memo → {:?}",
        trusted.status
    );
    assert_eq!(trusted.status, RunStatus::Succeeded);
    assert_eq!(ledger.calls.lock().unwrap().len(), 1);

    let refused = runtime
        .run("ledger.transfer", json!({ "scenario": "untrusted" }))
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
        .run("ledger.transfer", json!({ "scenario": "released" }))
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
