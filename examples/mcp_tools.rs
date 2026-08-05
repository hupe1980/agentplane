//! One agent, two tool transports: a real MCP server and a typed Rust tool.
//!
//! ```sh
//! cargo run --example mcp_tools --features redb,testkit,manifest,mcp
//! ```
//!
//! A genuine `rmcp` server runs in this process over a duplex pipe, so this is a
//! real round trip — no network, no child process, no key. What it demonstrates
//! is the part that is not transport:
//!
//! 1. **A grant names a tool, not a wire.** `tool://tickets/read` and
//!    `tool://ledger/read` are declared the same way; which transport reaches
//!    each server is a deployment decision. The same manifest runs against an
//!    in-process double in a test and a real server in production.
//! 2. **One client per server.** Both servers offer a tool called `read`. Only
//!    the server component distinguishes them, and a single client handed every
//!    id cannot — it answers both from whichever connection it holds.
//! 3. **A server's annotations are read, recorded, and disobeyed.** The server
//!    here marks its state-changing `close` tool `readOnlyHint: true`. Believing
//!    that would make the call retryable after a timeout — the one condition
//!    under which this runtime does something twice.
//! 4. **Discovery grants nothing.** `discover()` is a diff against the
//!    operator's catalogue, never a source for it.

use std::sync::Arc;

use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use agentplane::tools::{McpClient, Tool, ToolBox, ToolClient, ToolFailure, ToolId};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
    Implementation, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerInfo, Tool as McpTool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ServiceExt, serve_server};
use serde_json::{Value, json};

/// The agent. Two servers, two grants, and no mention of a transport.
const TELLER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity:
    role: "Answer questions using the ledger and the ticket system."
    constraints: "Use the tools. Do not guess."
  capabilities:
    provides: [desk.ask]
  models:
    privileged: { provider: fake, model: teller-1 }
  security:
    max_sensitivity_egress: internal
  tools:
    # Implemented in this binary, as a typed Rust tool.
    - ref: tool://ledger/read
      mutates: false
      max_sensitivity: internal
      description: Read a ledger account's balance.
    # Served by the MCP server below. Declared identically — the manifest states
    # *which tool*, and the wiring states how it is reached.
    - ref: tool://tickets/read
      mutates: false
      max_sensitivity: internal
      description: Read a support ticket.
  execution: { kind: tool-calling, max_turns: 4 }
  budgets:
    max_tokens: 100000
"#;

// ── The typed tool, in this binary ──────────────────────────────────────────

/// Read a ledger account's balance.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReadBalance {
    /// The account to read.
    account: String,
}

#[async_trait::async_trait]
impl Tool for ReadBalance {
    const SERVER: &'static str = "ledger";
    const NAME: &'static str = "read";

    fn mutates() -> bool {
        false
    }

    async fn call(self) -> Result<Value, ToolFailure> {
        println!("      → ledger/read {} (in process)", self.account);
        Ok(json!({ "account": self.account, "balance": 42 }))
    }
}

// ── The MCP server, also in this process ────────────────────────────────────

/// A server that describes itself generously.
///
/// `close` changes state and advertises `readOnlyHint: true`. The specification
/// says a client must not believe that, and here believing it would make the
/// tool non-mutating, which defaults its recovery to retry, which means a
/// timeout closes the ticket twice.
#[derive(Debug, Clone)]
struct TicketServer;

impl ServerHandler for TicketServer {
    fn get_info(&self) -> ServerInfo {
        let mut me = Implementation::default();
        me.name = "tickets".into();
        me.version = "0.0.0".into();
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = me;
        info
    }

    async fn list_tools(
        &self,
        _p: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let schema = Arc::new(
            json!({ "type": "object", "properties": { "id": { "type": "string" } } })
                .as_object()
                .cloned()
                .unwrap_or_default(),
        );
        let mut generous = ToolAnnotations::default();
        generous.read_only_hint = Some(true);

        let read = McpTool::new("read", "read a ticket", Arc::clone(&schema));
        let mut close = McpTool::new("close", "close a ticket", schema);
        close.annotations = Some(generous);

        Ok(ListToolsResult {
            tools: vec![read, close],
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        p: CallToolRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        match p.name.as_ref() {
            "read" => {
                println!("      → tickets/read (over MCP)");
                Ok(
                    CallToolResult::success(vec![ContentBlock::text("ticket 7: printer on fire")])
                        .into(),
                )
            }
            other => Err(ErrorData::invalid_params(
                format!("no such tool: {other}"),
                None,
            )),
        }
    }
}

async fn connect() -> McpClient {
    let (client_side, server_side) = tokio::io::duplex(8 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    let (cr, cw) = tokio::io::split(client_side);
    tokio::spawn(async move {
        if let Ok(running) = serve_server(TicketServer, (sr, sw)).await {
            let _ = running.waiting().await;
        }
    });
    let service = ().serve((cr, cw)).await.expect("client initialises");
    McpClient::new("tickets", Arc::new(service))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tickets = Arc::new(connect().await);

    // ── 1. Discovery is a diff, never a source ─────────────────────────────
    println!("1. what the server says about itself");
    for (id, advertised) in tickets.discover().await? {
        println!("   {id}: read_only_hint={:?}", advertised.read_only);
    }
    println!(
        "   → recorded for comparison. Nothing here entered a catalogue: a tool\n\
         \x20    absent from the operator's grants cannot be called however the\n\
         \x20    server describes it, and `close` is not granted at all."
    );

    // ── 2. One manifest, two transports ────────────────────────────────────
    let manifest = Manifest::parse(TELLER)?;
    let provider = FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__read", json!({ "account": "AC-1" }));
    provider.will_call_tool("call_2", "tickets__read", json!({ "id": "7" }));
    provider.will_say("AC-1 holds 42, and ticket 7 says the printer is on fire.");

    let store = Arc::new(RedbStore::open_in_memory()?);
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .provider("fake", Arc::clone(&provider) as Arc<dyn ModelProvider>)
        .agent(Agent::new(&manifest))
        // Tools compiled into this binary. The box answers for every server its
        // own tools name — here, `ledger`.
        .toolbox(ToolBox::new().with::<ReadBalance>())
        // And the MCP connection answers for `tickets`.
        .tool_server("tickets", Arc::clone(&tickets) as Arc<dyn ToolClient>)
        .build();

    println!("\n2. the model uses both, and neither knows about the other");
    let out = rt
        .run(
            "desk.ask",
            json!({ "question": "AC-1 balance and ticket 7?" }),
        )
        .await?;
    assert_eq!(out.status, RunStatus::Succeeded);
    println!("   answered: {}", out.output.as_ref().unwrap());

    // ── 3. The server component is load-bearing ────────────────────────────
    //
    // Both servers offer `read`. Handing the ticket connection a ledger id used
    // to *succeed*, against the wrong server, under the ledger's declared
    // safety — and nothing downstream could tell.
    println!("\n3. a tool id belonging to the other server");
    match tickets
        .call(&ToolId::new("ledger", "read"), &json!({}), None)
        .await
    {
        Err(e) => println!("   → refused: {e}"),
        Ok(v) => panic!("the ticket server answered a ledger tool: {v}"),
    }

    // ── 4. Every turn is on the record ─────────────────────────────────────
    let before = provider.calls();
    let replayed = rt.replay(out.run_id, Mode::Strict).await?;
    assert_eq!(replayed.output, out.output);
    assert_eq!(
        provider.calls(),
        before,
        "strict replay called the model again"
    );
    println!(
        "\n4. strict replay reassembled the conversation with zero model calls\n   \
         and zero tool calls — including the one that went over MCP"
    );
    store.verify(out.run_id).await?;
    println!("   and the chain verifies end to end");

    Ok(())
}
