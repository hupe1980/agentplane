//! This plane **as** an MCP server: a host calls a tool, a governed run happens.
//!
//! The other direction from [`mcp_tools`], which consumes somebody else's
//! server. Here a model host reaches in, and the gate stays where it always is
//! — inside effect dispatch, under the same admission an A2A message gets.
//!
//! Two things are worth watching. The tool a model is offered carries the
//! **manifest's** `spec.input`, not a shape this crate invented: an agent that
//! declares none cannot be served at all, because the only honest argument
//! shape to hand a model is one somebody reviewed. And every cacheable result
//! says `private` with no freshness window — the protocol's default is
//! `public`, and a cached copy of a governed declaration is a copy no erasure
//! reaches.
//!
//! The client here is the real SDK over an in-process pipe, so what it sees is
//! what a desktop host would see.
//!
//! Run with: `cargo run --example serve_mcp --features mcp-server,redb,testkit`
//!
//! [`mcp_tools`]: https://github.com/hupe1980/agentplane/blob/main/examples/mcp_tools.rs

use std::sync::Arc;

use agentplane::manifest::Manifest;
use agentplane::prelude::*;
use agentplane::tools::serve::McpServer;
use rmcp::model::{CallToolRequestParams, ProtocolVersion};
use serde_json::{Value, json};

const AGENT: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: settlement-checker
  version: "1.0.0"
spec:
  identity:
    role: Says whether a settlement cleared, and names the rule if it did not.
  capabilities:
    provides: [settlement.check]
  input:
    schema:
      type: object
      additionalProperties: false
      required: [reference]
      properties:
        reference:
          type: string
  budgets:
    max_tokens: 40000
    max_steps: 8
"#;

#[derive(Debug)]
struct Checker;

#[async_trait::async_trait]
impl Skill for Checker {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("checker").provides("settlement.check")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let reference = input
            .peek()
            .get("reference")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        // The arguments arrived from a model, so they are untrusted by
        // construction and stay that way: `map` keeps the label.
        Ok(Outcome::done(input.map(
            |_| json!({ "reference": reference, "cleared": true }),
        )))
    }
}

/// A client with nothing special about it: the SDK's own, declaring the Tasks
/// extension because a governed run may suspend for a person.
#[derive(Debug, Clone)]
struct Host;

impl rmcp::ClientHandler for Host {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        let mut info = rmcp::model::ClientConfig::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = rmcp::model::ClientCapabilities::builder()
            .enable_tasks()
            .build();
        info
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::service::{ClientLifecycleMode, ClientServiceExt};

    let manifest = Manifest::parse(AGENT)?;
    let digest = manifest.digest()?.to_hex();
    let store =
        Arc::new(RedbStore::open_in_memory()?) as Arc<dyn agentplane::journal::JournalStore>;
    let plane = Runtime::builder(store).owner("desk").skill(Checker).build();
    let server = McpServer::new(plane, std::slice::from_ref(&manifest))?;

    // In-process, so the example needs no second process — but it is the real
    // SDK on both ends, over a real session.
    let (client_side, server_side) = tokio::io::duplex(16 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(async move {
        if let Ok(running) = Box::pin(rmcp::serve_server(server, (sr, sw))).await {
            let _ = running.waiting().await;
        }
    });
    let (cr, cw) = tokio::io::split(client_side);
    let client = Host
        .serve_with_lifecycle(
            (cr, cw),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await?;

    // ── 1. The catalogue ────────────────────────────────────────────────────
    let tools = client.list_tools(Option::default()).await?;
    println!("1. what a host is offered");
    for tool in &tools.tools {
        println!(
            "   tool           → {} — {}",
            tool.name,
            tool.description.as_deref().unwrap_or("")
        );
        println!(
            "   inputSchema    → {} (the manifest's `spec.input`, reviewed under its digest)",
            serde_json::to_string(&tool.input_schema)?
        );
    }
    println!(
        "   cacheScope     → {:?}, ttlMs → {:?}",
        tools.cache_scope, tools.ttl_ms
    );

    // ── 2. A call is a governed run ─────────────────────────────────────────
    let answer = client
        .call_tool(
            CallToolRequestParams::new("settlement.check").with_arguments(
                json!({ "reference": "GB-4471" })
                    .as_object()
                    .cloned()
                    .expect("an object"),
            ),
        )
        .await?;
    println!("\n2. the host calls it");
    if let Some(block) = answer.content.first() {
        println!("   answer         → {}", serde_json::to_string(block)?);
    }
    println!("   — admitted, journaled and dispatched under the agent's declared");
    println!("     authority and budget; a refusal here is an answer, not an outage");

    // ── 3. What is not served ───────────────────────────────────────────────
    let resources = client.list_resources(Option::default()).await?;
    println!("\n3. resources: the declaration, and nothing carrying a payload");
    for r in &resources.resources {
        println!("   {}  (digest {})", r.uri, &digest[..12]);
    }
    println!(
        "   journals, cases and audit reports are refused: a resource read is an\n   \
         egress into a model's context, not an operator reading their own journal"
    );

    client.cancel().await?;
    Ok(())
}
