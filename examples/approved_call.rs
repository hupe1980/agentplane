//! Human oversight on the *call*, not a summary of it.
//!
//! ```sh
//! cargo run --example approved_call --features redb,testkit,manifest
//! ```
//!
//! `requires_approval: true` on a tool grant opens a task carrying the **exact
//! tool and the exact arguments** about to be dispatched, and nothing happens
//! until somebody decides. Gating the agent's *answer* instead is a review that
//! arrives after the money moved — for a tool-calling agent the transfer ran
//! turns ago, and refusing then refuses a summary of something that already
//! happened.
//!
//! What it demonstrates, in order:
//!
//! 1. **The world waits.** The model asks for a transfer; the run suspends; the
//!    worklist holds a task naming `tool://ledger/transfer` and the exact
//!    arguments. The transfer has not happened. A suspended run is a row, not a
//!    thread — the reviewer can take an hour.
//! 2. **Approval admits exactly that call.** The reviewer approves, the run
//!    resumes where it was, the transfer dispatches once, and the model
//!    finishes its answer.
//! 3. **Refusal is not an incident.** A second run's reviewer says no. The
//!    refusal goes back to the model as a failed call — without the reviewer's
//!    words, which are for the journal, not the prompt — and the model answers
//!    accordingly. Nothing was dispatched.
//! 4. **An amendment is the call.** A third run's reviewer approves *with*
//!    arguments, and exactly those dispatch — schema-checked, labelled as the
//!    reviewer's own trusted value, and judged by every field rule. The
//!    manifest names `task:agent.approve_call` beside the model in
//!    `allowed_sources`, which is the reviewed decision that admits the
//!    channel.
//! 5. **The decision is history.** Strict replay reassembles the approved run —
//!    including the human decision — without opening a task, calling a model,
//!    or moving money again.
//!
//! The manifest below pairs the gate with a field rule, and the pair is the
//! point: `/recipient` says out loud that the model may author it
//! (`allowed_sources` names the privileged model), and `requires_approval`
//! puts a person in front of every dispatch. Two independent controls, both in
//! the reviewed file.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::case::TaskStore;
use agentplane::core::{Decision, Tainted};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::model::ModelProvider;
use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use agentplane::tools::{Tool, ToolBox, ToolFailure};
use serde_json::{Value, json};

/// The agent. `approval: tools-only` gates the calls and leaves the answer
/// unattended — the shape most deployments want, and under it every mutating
/// grant **must** declare `requires_approval` or the manifest is refused.
const TELLER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  identity:
    role: "Make payments a person has approved."
    constraints: "Use the transfer tool. Never promise a payment you did not make."
  capabilities: { provides: [desk.pay] }
  models:
    privileged: { provider: fake, model: teller-1 }
  security:
    max_sensitivity_egress: internal
  oversight:
    approval: tools-only
    approvers: [payment-officer]
    deadline: { name: payment-review, kind: hours, params: { n: 4 } }
  tools:
    - ref: tool://ledger/transfer
      mutates: true
      max_sensitivity: internal
      description: Move funds between accounts.
      # A person sees this exact call, with these exact arguments, first.
      requires_approval: true
      protected_fields:
        # The recipient's two legitimate authors, named out loud: the
        # privileged model, and a reviewer's amendment on the approval task.
        # The source rule is the reviewed decision that lifts the blanket
        # refusal a mutating tool applies to untrusted arguments — and the
        # human gate above is the second, independent control. Drop the task
        # source and an amended recipient is refused at dispatch.
        - path: /recipient
          allowed_sources: [model:fake/teller-1, task:agent.approve_call]
          max_sensitivity: internal
  execution: { kind: tool-calling, max_turns: 4 }
  budgets:
    max_tokens: 100000
"#;

/// How many times money actually moved. Process-wide, because a tool is a type.
static POSTED: AtomicUsize = AtomicUsize::new(0);

/// Move funds between accounts.
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
        POSTED.fetch_add(1, Ordering::SeqCst);
        println!("      → transferred {} to {}", self.amount, self.recipient);
        Ok(json!({ "moved": self.amount, "to": self.recipient }))
    }
}

fn plane(provider: &Arc<FakeProvider>) -> (Arc<Runtime>, Arc<RedbStore>) {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let manifest = Manifest::parse(TELLER).expect("the agent parses");
    let driver: Arc<dyn ModelProvider> = provider.clone();
    // `builder_on`: the approval task and the case it lives on need the case
    // layer, and this wires the whole of it to the same store in one call.
    let rt = Runtime::builder_on(Arc::clone(&store))
        .provider("fake", driver)
        .agent(Agent::new(&manifest))
        .toolbox(ToolBox::new().with::<Transfer>())
        .build();
    (rt, store)
}

fn officer() -> Vec<String> {
    vec!["payment-officer".to_owned()]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. The model asks; the world waits ─────────────────────────────────
    let provider = FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "ledger__transfer",
        json!({ "recipient": "AC-9", "amount": 250_000 }),
    );
    provider.will_say("Paid: 250000 to AC-9.");
    let (rt, store) = plane(&provider);

    let run = rt
        .run_correlated(
            "desk.pay",
            Tainted::trusted(json!({ "instruction": "pay invoice INV-7 from AC-9" })),
            "payment",
            &[agentplane::core::CorrelationKey::new("invoice", "INV-7")],
        )
        .await?;
    println!("1. the model asks to move money");
    println!("   run          → {}", run.status.as_str());
    println!(
        "   transfers    → {} — nothing happens while the task is open",
        POSTED.load(Ordering::SeqCst)
    );
    assert!(matches!(run.status, RunStatus::Suspended(_)));
    assert_eq!(POSTED.load(Ordering::SeqCst), 0);

    let task = store
        .queue(&officer(), 10)
        .await?
        .pop()
        .expect("the call is on the worklist");
    let shown = &task.justification.proposed_action;
    println!("   the reviewer sees the call itself, not a description of it:");
    println!("     summary    → {}", task.justification.summary);
    println!("     tool       → {}", shown["tool"]);
    println!("     arguments  → {}", shown["arguments"]);
    assert_eq!(shown["arguments"]["amount"], 250_000);

    // ── 2. Approval admits exactly that call ───────────────────────────────
    // The header before the decision: the tool prints its own line the moment
    // the approved call dispatches, and it belongs under this section.
    println!("\n2. dana approves the call as proposed");
    rt.decide_task(
        task.id,
        &Decision::approve("dana", "matches the approved invoice INV-7"),
        &officer(),
    )
    .await?;
    // `recorded_outcome` answers *status* from the journal without resuming
    // anything; the answer itself is reconstructed by replay, below.
    let done = rt
        .recorded_outcome(run.run_id)
        .await?
        .expect("the run concluded");
    println!("   run          → {:?}", done.status);
    println!("   transfers    → {}", POSTED.load(Ordering::SeqCst));
    assert_eq!(done.status, RunStatus::Succeeded);
    assert_eq!(POSTED.load(Ordering::SeqCst), 1, "approved means once");

    refusal_is_not_an_incident().await?;
    an_amendment_is_the_call().await?;

    // ── 5. The decision is history ─────────────────────────────────────────
    let calls = provider.calls();
    let replayed = rt.replay(run.run_id, Mode::Strict).await?;
    assert_eq!(POSTED.load(Ordering::SeqCst), 2, "replay moved money");
    assert!(
        store.queue(&officer(), 10).await?.is_empty(),
        "replay opened a fresh approval task"
    );
    println!("\n5. strict replay → {:?}", replayed.status);
    println!(
        "   answer       → {}",
        replayed.output.as_ref().expect("the run answered").peek()
    );
    println!(
        "   the approved run reassembles — decision included — with no new task, \
         {} new model calls, and no second transfer",
        provider.calls() - calls
    );
    store.verify(run.run_id).await?;
    println!("   and its chain verifies end to end");

    Ok(())
}

/// A reviewer answering with the arguments — see the module docs, point 4.
async fn an_amendment_is_the_call() -> Result<(), Box<dyn std::error::Error>> {
    let provider = FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "ledger__transfer",
        json!({ "recipient": "AC-13", "amount": 900_000 }),
    );
    provider.will_say("Paid as directed.");
    let (rt, store) = plane(&provider);

    let run = rt
        .run_correlated(
            "desk.pay",
            Tainted::trusted(json!({ "instruction": "pay 900000 to AC-13" })),
            "payment",
            &[agentplane::core::CorrelationKey::new("invoice", "INV-9")],
        )
        .await?;
    let task = store
        .queue(&officer(), 10)
        .await?
        .pop()
        .expect("the call is on the worklist");
    let before = POSTED.load(Ordering::SeqCst);
    // The header goes out before the decision, because the tool prints its
    // own line the moment the amended call dispatches — after the header, or
    // the line files under the previous section.
    println!("\n4. dana amends the call to AC-2, capped at 120000");
    // The amendment is the call: dana answers with the settlement account and
    // a capped amount, and exactly those dispatch — as her value, not the
    // model's. It passes `/recipient`'s source rule because the manifest
    // lists `task:agent.approve_call` beside the model.
    rt.decide_task(
        task.id,
        &Decision::approve("dana", "wrong account; settle via AC-2, capped")
            .amend(json!({ "recipient": "AC-2", "amount": 120_000 })),
        &officer(),
    )
    .await?;

    let done = rt
        .recorded_outcome(run.run_id)
        .await?
        .expect("the run concluded");
    println!("   run          → {:?}", done.status);
    println!(
        "   transfers    → {} — the reviewer's arguments ran, the model's never did",
        POSTED.load(Ordering::SeqCst)
    );
    assert_eq!(done.status, RunStatus::Succeeded);
    assert_eq!(
        POSTED.load(Ordering::SeqCst),
        before + 1,
        "the amended call dispatched once"
    );
    Ok(())
}

/// A reviewer saying no — see the module docs, point 3.
async fn refusal_is_not_an_incident() -> Result<(), Box<dyn std::error::Error>> {
    let provider = FakeProvider::new();
    provider.will_call_tool(
        "call_1",
        "ledger__transfer",
        json!({ "recipient": "AC-13", "amount": 900_000 }),
    );
    provider.will_say("I was not able to make that payment.");
    let (rt, store) = plane(&provider);

    let refused = rt
        .run_correlated(
            "desk.pay",
            Tainted::trusted(json!({ "instruction": "pay 900000 to AC-13" })),
            "payment",
            &[agentplane::core::CorrelationKey::new("invoice", "INV-8")],
        )
        .await?;
    let task = store
        .queue(&officer(), 10)
        .await?
        .pop()
        .expect("the call is on the worklist");
    rt.decide_task(
        task.id,
        &Decision::reject("dana", "AC-13 is not on the settlement list"),
        &officer(),
    )
    .await?;
    // The answer is read back by a strict replay — which is also the proof
    // that reading it dispatches nothing.
    let outcome = rt.replay(refused.run_id, Mode::Strict).await?;
    println!("\n3. dana refused  → {:?}", outcome.status);
    println!(
        "   answer       → {}",
        outcome.output.as_ref().expect("the run answered").peek()
    );
    println!(
        "   transfers    → still {} — the refusal went back to the model as a \
         failed call,\n                  without the reviewer's words, and the run \
         went on",
        POSTED.load(Ordering::SeqCst)
    );
    assert_eq!(outcome.status, RunStatus::Succeeded);
    assert_eq!(
        POSTED.load(Ordering::SeqCst),
        1,
        "a refused call dispatched"
    );
    Ok(())
}
