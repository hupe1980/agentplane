//! A governed coded agent in a local program: a file, Rust, and no YAML.
//!
//! ```sh
//! cargo run --example local_coded_agent --features embed,fake-model
//! ```
//!
//! What a single-binary tool embedding the runtime needs, and nothing else:
//!
//! 1. **The plane is two lines.** A redb file and `Runtime::builder_on`, which
//!    wires journal, cases, tasks, timers and memory to it. No tenant, no key,
//!    no policy engine — each is an addition, not a prerequisite.
//! 2. **The declaration is Rust.** `Manifest::builder` runs the same
//!    validation `Manifest::parse` does, and the leaf constructors take only
//!    what has no default. The model may author `/path` and `/contents`
//!    because a field rule says so out loud; without it the mutating tool would
//!    refuse the model's arguments.
//! 3. **A person sees the exact call.** A coded skill asks when it chooses to,
//!    with `cx.task`, carrying the arguments it is about to send. A grant flag
//!    would not do it: per-call approval is the declarative loops', and a
//!    manifest that set it beside a coded skill is refused.
//! 4. **The decision is history.** Strict replay re-reads the model's answer,
//!    the decision and the write from the journal, and performs none of them.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::case::TaskStore;
use agentplane::core::{
    CorrelationKey, DeadlineSpec, Decision, Justification, Operator, ProtectedField, SourceId,
    TaskSpec,
};
use agentplane::manifest::{Budgets, Manifest, ModelRef, Models, ToolGrant};
use agentplane::model::ModelProvider;
use agentplane::model::fake::FakeProvider;
use agentplane::prelude::*;
use agentplane::runtime::Agent;
use agentplane::tools::{Tool, ToolFailure};
use serde_json::{Value, json};

/// How many files were written. Process-wide, because a tool is a type.
static WRITTEN: AtomicUsize = AtomicUsize::new(0);

/// Write a file in the working tree.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct WriteFile {
    /// Relative to the working tree.
    path: String,
    /// The whole new contents.
    contents: String,
}

#[async_trait]
impl Tool for WriteFile {
    const SERVER: &'static str = "fs";
    const NAME: &'static str = "write";

    async fn call(self) -> Result<Value, ToolFailure> {
        WRITTEN.fetch_add(1, Ordering::SeqCst);
        println!(
            "      → wrote {} bytes to {}",
            self.contents.len(),
            self.path
        );
        Ok(json!({ "path": self.path, "bytes": self.contents.len() }))
    }
}

/// Ask the model for a patch, show it to a person, write it if they agree.
#[derive(Debug)]
struct Patch;

#[async_trait]
impl Skill for Patch {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("patch").provides("code.patch")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // The model's answer comes back labelled as the model's.
        let answer = cx.complete(&input).await?;
        let call = answer.map(|c| serde_json::from_str::<Value>(&c.text).unwrap_or(Value::Null));

        // The reviewer is shown the arguments that will be sent, not a summary.
        cx.deadline("review", &DeadlineSpec::hours(4), None).await?;
        let shown = Justification::new(
            Tainted::trusted("write the file the model proposed".to_owned()),
            json!({ "tool": "tool://fs/write", "arguments": call.peek() }),
        );
        let task = TaskSpec::new("patch-review", shown, "review").role("maintainer");
        if !cx.task(&task).await?.approved {
            return Ok(Outcome::done(Tainted::trusted(json!({ "written": false }))));
        }

        let written = cx.call_tool(ToolId::new("fs", "write"), call).await?;
        Ok(Outcome::done(
            written.map(|v| json!({ "written": true, "file": v })),
        ))
    }
}

/// The agent, declared in Rust.
fn declaration() -> Result<Manifest, agentplane::manifest::ManifestError> {
    let model = SourceId::new("model:fake/coder-1");
    Manifest::builder("patcher", "1.0.0")
        .configure(|spec| {
            spec.capabilities.provides.push("code.patch".to_owned());
            spec.models = Some(Models {
                privileged: Some(ModelRef::new("fake", "coder-1")),
                ..Models::default()
            });
            // A model's answer is labelled `internal`, and the default egress
            // ceiling is `public`: what may leave is declared, never assumed.
            spec.security.max_sensitivity_egress = Some(Sensitivity::Internal);
            spec.tools.push(ToolGrant {
                description: Some("Write a file in the working tree.".to_owned()),
                max_sensitivity: Some(Sensitivity::Internal),
                protected_fields: vec![
                    ProtectedField::from_sources("/path", [model.clone()]),
                    ProtectedField::from_sources("/contents", [model]),
                ],
                ..ToolGrant::new("tool://fs/write")
            });
            spec.budgets = Some(Budgets {
                max_tokens: Some(100_000),
                ..Budgets::default()
            });
        })
        .build()
}

fn maintainers() -> Vec<String> {
    vec!["maintainer".to_owned()]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── 1. The plane: a file ──────────────────────────────────────────────
    let dir = std::env::temp_dir().join(format!("agentplane-local-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let store = Arc::new(RedbStore::open(dir.join("journal.redb"))?);

    let provider = FakeProvider::new();
    provider.will_say(r#"{ "path": "src/lib.rs", "contents": "pub fn answer() -> u8 { 42 }\n" }"#);
    let driver: Arc<dyn ModelProvider> = provider.clone();

    // ── 2. The declaration: Rust ──────────────────────────────────────────
    let manifest = declaration()?;
    let rt = Runtime::builder_on(Arc::clone(&store))
        .provider("fake", driver)
        .agent(Agent::new(&manifest).skill(Patch))
        .toolbox(ToolBox::new().with::<WriteFile>())
        .build();

    // ── 3. A person sees the exact call ───────────────────────────────────
    let run = rt
        .run_correlated(
            "code.patch",
            Tainted::trusted(json!("make `answer` return 42")),
            "feature",
            &[CorrelationKey::new("feature", "F-1")],
        )
        .await?;
    println!("1. the model proposes a write, and the run waits");
    println!("   run      → {}", run.status.as_str());
    assert!(matches!(run.status, RunStatus::Suspended(_)));
    assert_eq!(
        WRITTEN.load(Ordering::SeqCst),
        0,
        "nothing is written before the decision"
    );

    let task = store
        .queue(&maintainers(), 10)
        .await?
        .pop()
        .expect("the review is queued");
    let shown = &task.justification.proposed_action;
    println!(
        "   shown    → {} {}",
        shown["tool"], shown["arguments"]["path"]
    );
    assert_eq!(shown["arguments"]["path"], "src/lib.rs");

    println!("\n2. the maintainer approves");
    rt.decide_task(
        task.id,
        &Decision::approve(
            Operator::asserted("sam")?,
            "the patch is what was asked for",
        ),
        &maintainers(),
    )
    .await?;
    let done = rt
        .recorded_outcome(run.run_id)
        .await?
        .expect("the run concluded");
    println!("   run      → {}", done.status.as_str());
    assert!(
        matches!(done.status, RunStatus::Succeeded),
        "{:?}",
        done.status
    );
    assert_eq!(WRITTEN.load(Ordering::SeqCst), 1);

    // ── 4. The decision is history ────────────────────────────────────────
    let replayed = rt
        .replay(run.run_id, agentplane::runtime::Mode::Strict)
        .await?;
    println!("\n3. strict replay");
    println!("   run      → {}", replayed.status.as_str());
    assert!(matches!(replayed.status, RunStatus::Succeeded));
    assert_eq!(WRITTEN.load(Ordering::SeqCst), 1, "replay wrote nothing");

    drop(rt);
    drop(store);
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
