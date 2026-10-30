//! A tool loop in a coded skill, turn by turn, with nothing joined by hand.
//!
//! ```sh
//! cargo run --example coded_tool_loop --features embed,fake-model
//! ```
//!
//! What a skill that drives its own loop needs:
//!
//! 1. **The prompt is built once.** `/system` is trusted and stays trusted on
//!    every turn; the run's input sits beside it in `messages`.
//! 2. **A `Transcript` carries the conversation.** Each tool result and each
//!    relayed failure joins its label, and `continuing(&transcript)` hands it
//!    to the model sink, which judges it beside the prompt and labels the
//!    answer with it. A loop that relayed bare values would send a confidential
//!    result to any model, unjudged.
//! 3. **A tool with no arguments is granted by its one call.** `format` mutates
//!    and takes `{}`; its grant names the whole value, `""`, and admits exactly
//!    that, whoever the model read before asking.
//! 4. **A refusal reaches the model as one word.** `StepCtx::relayed` answers
//!    what a failed call may tell the model and with which label, or hands the
//!    error back to the executor when it is not the model's business.
//! 5. **The offer answers the call.** Each tool is offered with
//!    `ToolDeclaration::offering` under a name the skill chose, and
//!    `call_tool_for` runs the tool behind the offer the model named — the
//!    skill keeps no table of its own from names to tools.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::ProtectedField;
use agentplane::manifest::{Budgets, Manifest, ModelRef, ToolGrant};
use agentplane::model::fake::FakeProvider;
use agentplane::model::{ModelProvider, ToolDeclaration, Transcript};
use agentplane::prelude::*;
use agentplane::runtime::Agent;
use agentplane::tools::{Tool, ToolBox, ToolFailure};
use serde_json::{Value, json};

static FORMATTED: AtomicUsize = AtomicUsize::new(0);

/// Read a file in the working tree.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ReadFile {
    /// Relative to the working tree.
    path: String,
}

#[async_trait]
impl Tool for ReadFile {
    const SERVER: &'static str = "fs";
    const NAME: &'static str = "read";
    fn mutates() -> bool {
        false
    }
    async fn call(self) -> Result<Value, ToolFailure> {
        Ok(json!({ "path": self.path, "text": "fn main(){println!(\"hi\")}" }))
    }
}

/// Format the working tree. Takes nothing.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct Format {}

#[async_trait]
impl Tool for Format {
    const SERVER: &'static str = "repo";
    const NAME: &'static str = "format";
    async fn call(self) -> Result<Value, ToolFailure> {
        FORMATTED.fetch_add(1, Ordering::SeqCst);
        Ok(json!({ "changed": 1 }))
    }
}

/// Read, format, report — however many turns the model takes.
#[derive(Debug)]
struct Tidy {
    /// What the model is offered. Each offer names the tool it stands for, so
    /// a call is answered from the offer it named — no second table.
    offered: Vec<ToolDeclaration>,
}

#[async_trait]
impl Skill for Tidy {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("tidy").provides("code.tidy")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let prompt = Tainted::object([
            (
                "system",
                Tainted::trusted(json!("Tidy the working tree, then say what changed.")),
            ),
            (
                "messages",
                Tainted::array([input.map(|i| json!({ "role": "user", "content": i }))]),
            ),
        ]);
        let mut transcript = Transcript::new(&prompt);

        for _turn in 0..4 {
            let answer = cx
                .complete_with(&prompt, |call| {
                    call.with_tools(self.offered.clone())
                        .continuing(&transcript)
                })
                .await?;
            let calls = transcript.asked(&answer);
            if calls.is_empty() {
                return Ok(Outcome::done(answer.map(|c| json!({ "text": c.text }))));
            }
            for call in calls {
                // The arguments are the model's words, labelled as its answer.
                let arguments = Tainted::with_label(call.arguments.clone(), answer.label().clone());
                // A name nothing was offered under is refused before dispatch,
                // and relayed to the model so it can correct itself.
                match cx.call_tool_for(&call, &self.offered, arguments).await {
                    Ok(output) => transcript.answered(call, &output),
                    Err(error) => match cx.relayed(&error) {
                        Some(detail) => transcript.failed(call, detail),
                        None => return Err(error.into()),
                    },
                }
            }
        }
        Ok(Outcome::fail("the model did not finish within four turns"))
    }
}

fn declaration() -> Result<Manifest, agentplane::manifest::ManifestError> {
    Manifest::builder("tidier", "1.0.0")
        .provides("code.tidy")
        .privileged_model(ModelRef::new("fake", "coder-1"))
        .egress_ceiling(Sensitivity::Internal)
        .tool(ToolGrant {
            description: Some("Read a file.".to_owned()),
            mutates: false,
            max_sensitivity: Some(Sensitivity::Internal),
            ..ToolGrant::new("tool://fs/read")
        })
        // An argument-less mutating tool: the whole value, and only `{}`.
        .tool(ToolGrant {
            description: Some("Format the working tree.".to_owned()),
            max_sensitivity: Some(Sensitivity::Internal),
            protected_fields: vec![ProtectedField::one_of("", [json!({})])],
            ..ToolGrant::new("tool://repo/format")
        })
        .budgets(Budgets {
            max_tokens: Some(100_000),
            ..Budgets::default()
        })
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let toolbox = ToolBox::new().with::<ReadFile>().with::<Format>();
    // Offered under names of the skill's choosing; the offer remembers the
    // tool behind each.
    let offered = [
        (ToolId::new("fs", "read"), "read_file"),
        (ToolId::new("repo", "format"), "format"),
    ]
    .into_iter()
    .map(|(id, name)| {
        let (description, schema, _) = toolbox.declared(&id).expect("registered");
        let (description, schema) = (description.to_owned(), schema.clone());
        ToolDeclaration::offering(id, description, schema).named(name)
    })
    .collect();

    let provider = FakeProvider::new();
    provider
        .will_call_tool("c1", "read_file", json!({ "path": "src/main.rs" }))
        .will_call_tool("c2", "format", json!({}))
        .will_say("Formatted src/main.rs.");
    let driver: Arc<dyn ModelProvider> = provider.clone();

    let manifest = declaration()?;
    let rt = Runtime::builder_on(Arc::clone(&store))
        .provider("fake", driver)
        .agent(Agent::new(&manifest).skill(Tidy { offered }))
        .toolbox(toolbox)
        .build();

    let run = rt
        .start("code.tidy", Tainted::trusted(json!("tidy up")))
        .run()
        .await?;
    println!("run      → {}", run.status.as_str());
    assert!(
        matches!(run.status, RunStatus::Succeeded),
        "{:?}",
        run.status
    );
    assert_eq!(FORMATTED.load(Ordering::SeqCst), 1);

    // Turn three read the file's text and the format result: the answer says so.
    let label = run.output.as_ref().expect("an answer").label();
    println!("answer   → read {} source(s)", label.provenance.len());
    assert!(
        label
            .provenance
            .iter()
            .any(|s| s.to_string() == "tool://fs/read"),
        "{label:?}"
    );

    // Turn two saw what turn one relayed, and turn three what turn two did.
    let turns = provider.asked();
    println!("turns    → {}", turns.len());
    assert_eq!(turns.len(), 3);
    assert_eq!(turns[2].exchanges[0].call.name, "format");

    let replayed = rt
        .replay(run.run_id, agentplane::runtime::Mode::Strict)
        .await?;
    println!("replay   → {}", replayed.status.as_str());
    assert_eq!(
        FORMATTED.load(Ordering::SeqCst),
        1,
        "replay formatted nothing"
    );
    Ok(())
}
