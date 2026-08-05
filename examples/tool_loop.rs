//! The shape most people mean by "an agent": a model choosing tools in a loop.
//!
//! ```sh
//! cargo run --example tool_loop --features redb,testkit,manifest
//! ```
//!
//! Every other example here drives an effect from *code*. This one hands the
//! decision to the model — which is where the interesting failures live, because
//! the thing choosing the tool is the thing an attacker writes to.
//!
//! Four refusals are demonstrated, and none of them is a filter on the model's
//! output. Each is a property of the arrangement:
//!
//! 1. **A tool the manifest never listed is not callable**, however the model
//!    spells it. The name is matched byte for byte against the operator's
//!    grants; a resolver that corrected a near miss would let a model reach a
//!    tool by describing it.
//! 2. **A refusal goes back to the model**, not to the operator. A model that
//!    asked for something it may not have should get told and try again — the
//!    run failing would turn every mistaken guess into an incident.
//! 3. **The model's arguments are untrusted**, so a *granted* mutating tool
//!    with no field policy refuses them outright. The model may choose what to
//!    *read*; it may not choose what to *change* unless the operator said which
//!    fields it may influence.
//! 4. **The loop is bounded.** An agent still asking when `max_turns` runs out
//!    fails rather than passing off half-formed reasoning as an answer.
//!
//! And the whole conversation is journaled as effects, so a strict replay
//! reassembles it without calling a model or a tool.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use agentplane::tools::{Tool, ToolBox, ToolError};
use serde_json::{Value, json};

/// The agent is a file. The only Rust below is deployment wiring.
const TELLER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity:
    role: "Answer questions about a ledger account."
    constraints: "Use the tools. Do not guess a balance."
  capabilities:
    provides: [ledger.ask]
  models:
    privileged: { provider: fake, model: teller-1 }
  security:
    max_sensitivity_egress: internal
  tools:
    # Exactly what this agent may reach. A tool absent from here cannot be
    # called however the model spells it — the grant is the operator's decision
    # and the model's suggestion is only a suggestion.
    - ref: mcp://ledger/read
      mutates: false
      max_sensitivity: internal
      description: Read a ledger account's balance.
    - ref: mcp://ledger/post
      # Declared mutating, and with **no protected fields**. That pair is what
      # makes the refusal below structural rather than a matter of the model
      # behaving: a mutating tool that has not been told which fields a model
      # may influence refuses untrusted arguments outright.
      mutates: true
      max_sensitivity: internal
      description: Post an amount to an account.
  execution: { kind: tool-calling, max_turns: 4 }
  budgets:
    max_tokens: 100000
"#;

// ── Two tools, each defined once ────────────────────────────────────────────
//
// The type *is* the tool: its name, its arguments, what a model is told, and
// what it does. The schema comes from the fields, so the arguments a model is
// shown and the arguments the body receives are the same declaration — there is
// no `arguments["id"].as_str().unwrap_or(...)` to misspell.

/// How many times the world was actually touched.
///
/// Process-wide because a tool is a *type*, not an instance — which is the point
/// of the design and a thing to know when counting.
static READS: AtomicUsize = AtomicUsize::new(0);
static POSTS: AtomicUsize = AtomicUsize::new(0);

/// Start a section from zero, so each assertion is about its own section.
fn reset() {
    READS.store(0, Ordering::Relaxed);
    POSTS.store(0, Ordering::Relaxed);
}

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

    async fn call(self) -> Result<Value, ToolError> {
        READS.fetch_add(1, Ordering::Relaxed);
        println!("      → read {}", self.account);
        Ok(json!({ "account": self.account, "balance": 42 }))
    }
}

/// Post an amount to a ledger account.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PostEntry {
    /// The account to post to.
    ///
    /// Never read in this example, and the compiler is right to say so: every
    /// call to this tool is refused before the body runs. That is the point of
    /// step 3.
    #[allow(dead_code)]
    account: String,
    /// The amount, in minor units.
    amount: i64,
}

#[async_trait::async_trait]
impl Tool for PostEntry {
    const SERVER: &'static str = "ledger";
    const NAME: &'static str = "post";

    // Mutating, and the manifest declares no protected fields for it. That pair
    // is what makes the refusal in step 3 structural rather than a matter of the
    // model behaving.
    async fn call(self) -> Result<Value, ToolError> {
        POSTS.fetch_add(1, Ordering::Relaxed);
        Ok(json!({ "posted": self.amount }))
    }
}

fn plane(provider: &Arc<FakeProvider>) -> (Arc<Runtime>, Arc<RedbStore>) {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let manifest = Manifest::parse(TELLER).expect("the agent parses");

    // The implementations. One call: the catalogue is derived from the agent's
    // own declaration, and the build **refuses** if the tools this binary
    // implements and the manifest a reviewer approved have drifted apart.
    //
    // Both of those were possible before and both were optional, which is the
    // same as not having them: a control a caller may forget is advice that
    // reads like a control.
    let tools = ToolBox::new().with::<ReadBalance>().with::<PostEntry>();

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .provider("fake", Arc::clone(provider) as Arc<dyn ModelProvider>)
        .agent(Agent::new(&manifest))
        .toolbox(tools)
        .build();
    (rt, store)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. The ordinary path: the model asks, the tool answers, it replies ──
    let provider = FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__read", json!({ "account": "AC-1" }));
    provider.will_say("AC-1 holds 42.");
    let (rt, store) = plane(&provider);

    println!("1. the model chooses a tool");
    let first = rt
        .run("ledger.ask", json!({ "question": "what is in AC-1?" }))
        .await?;
    let out = &first;
    assert_eq!(out.status, RunStatus::Succeeded);
    assert_eq!(READS.load(Ordering::Relaxed), 1);
    let asked = provider.asked();
    let read = asked[0]
        .tools
        .iter()
        .find(|tool| tool.name == "ledger__read")
        .expect("the typed read tool was offered");
    assert_eq!(
        read.parameters["properties"]["account"]["type"], "string",
        "the model was not shown the schema derived from ReadBalance"
    );
    println!("   answered: {}", out.output.as_ref().unwrap());

    // Every turn is a journaled effect, so the conversation is reconstructable
    // without asking anyone anything.
    let before = (provider.calls(), READS.load(Ordering::Relaxed));
    let replayed = rt.replay(out.run_id, Mode::Strict).await?;
    assert_eq!(replayed.output, out.output);
    assert_eq!(
        (provider.calls(), READS.load(Ordering::Relaxed)),
        before,
        "strict replay called the model or the tool again"
    );
    println!("   strict replay reassembled it with zero calls");

    reset();
    // ── 2. A tool nobody granted ───────────────────────────────────────────
    //
    // The model asks for something plausible that the manifest never listed.
    // The name is matched byte for byte: `ledger__write` is not `ledger__read`,
    // and nothing resolves the near miss.
    let provider = FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__write", json!({ "account": "AC-1" }));
    provider.will_say("I could not do that, so here is the balance instead.");
    let (rt, _) = plane(&provider);

    let out = rt
        .run("ledger.ask", json!({ "question": "empty AC-1" }))
        .await?;
    println!("\n2. the model asks for a tool nobody granted");
    assert_eq!(
        READS.load(Ordering::Relaxed),
        0,
        "an ungranted tool was called"
    );
    // The run does *not* fail. The refusal goes back to the model as a failed
    // call, so it can correct itself — a mistaken guess is not an incident.
    assert_eq!(out.status, RunStatus::Succeeded);
    println!("   → refused, reported to the model, and the run continued");

    reset();
    // ── 3. The model may choose what to read, never what to change ────────
    //
    // The tool *is* granted, so this is not the refusal above. It is refused
    // because the arguments came from the model: untrusted data may not select
    // the fields of a mutating call unless an operator said which ones it may
    // influence.
    let provider = FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "ledger__post",
        json!({ "account": "AC-1", "amount": 1_000_000 }),
    );
    provider.will_say("I was not able to post that.");
    let (rt, _) = plane(&provider);

    let out = rt
        .run("ledger.ask", json!({ "question": "put a million in AC-1" }))
        .await?;
    println!("\n3. the model asks to *change* something");
    assert_eq!(
        POSTS.load(Ordering::Relaxed),
        0,
        "a model chose the arguments of a mutating call"
    );
    assert_eq!(out.status, RunStatus::Succeeded);
    println!("   → refused: untrusted arguments may not select a mutating call");

    reset();
    // ── 4. The loop is bounded ─────────────────────────────────────────────
    //
    // An agent that keeps asking runs out of turns. It fails rather than
    // returning whatever it had — half-formed reasoning presented as an answer
    // is the failure this bound exists to prevent.
    let provider = FakeProvider::new();
    for i in 0..8 {
        provider.will_call_tool(
            format!("call_{i}"),
            "ledger__read",
            json!({ "account": "AC-1" }),
        );
    }
    let (rt, _) = plane(&provider);

    let out = rt.run("ledger.ask", json!({ "question": "loop" })).await?;
    println!("\n4. the model never stops asking");
    match &out.status {
        RunStatus::Failed(why) => println!("   → {why}"),
        other => panic!("an unbounded loop was allowed to finish: {other:?}"),
    }

    // ── 5. The turns are on the record, not only in the answer ────────────
    //
    // Read from the *first* run's store: this is what makes the replay above
    // possible, and what an auditor reads to see which tools were offered and
    // which the model asked for.
    let records = store.read(first.run_id, 1).await?;
    let kinds: Vec<&str> = records.iter().map(|r| r.kind().kind_str()).collect();
    let effects = kinds.iter().filter(|k| **k == "EffectStarted").count();
    println!(
        "\n5. the first run left {} records, {effects} of them effects — one per \
         model turn and one per tool call",
        records.len()
    );
    assert!(
        effects >= 2,
        "a model turn and a tool call should both be effects: {kinds:?}"
    );
    store.verify(first.run_id).await?;
    println!("   and its chain verifies end to end");

    Ok(())
}
