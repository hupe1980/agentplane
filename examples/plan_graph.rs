//! A multi-step plan: the contract, the ready-set, and provenance.
//!
//! ```sh
//! cargo run --example plan_graph
//! ```
//!
//! A plan is not just a schedule. Because it is compiled from *trusted* input
//! and frozen before anything untrusted is read, it is a statement of what the
//! run is permitted to do — made before anything could have influenced it. The
//! journal that follows can then be checked against it.
//!
//! What this shows, in order:
//!
//! 1. A three-node graph runs in dependency order, each step reading exactly
//!    what its arguments declare.
//! 2. Provenance flows: a step downstream of untrusted data receives untrusted
//!    input without the plan author saying so.
//! 3. A plan that could never finish is refused **before the first step runs**.
//! 4. Collaboration must justify itself — and "parallel" work over a shared
//!    input is rejected as the false parallelism it is.

use std::sync::Arc;

use agentplane::core::{
    ArgSource, Collaboration, Outcome, PlanIR, PlanNode, Skill, SkillDescriptor, SkillError,
    SourceId, StepId, Tainted, Topology,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};

/// Reads meter data from outside the trust boundary.
#[derive(Debug)]
struct Fetch;

#[async_trait::async_trait]
impl Skill for Fetch {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("fetch").provides("meter.fetch")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let meter = input.peek().get("meter").cloned().unwrap_or(Value::Null);
        cx.note(format!("reading intervals for {meter}")).await?;

        // Whatever a counterparty sends is external data, whoever they are.
        Ok(Outcome::done(Tainted::from_source(
            json!({ "meter": meter, "kwh": 4210, "quality": "estimated" }),
            SourceId::new("mcp://metering"),
        )))
    }
}

/// Checks the reading against a threshold.
#[derive(Debug)]
struct Validate;

#[async_trait::async_trait]
impl Skill for Validate {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("validate").provides("meter.validate")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Deterministic arithmetic — no model involved, and none needed.
        let kwh = input.peek().get("kwh").and_then(Value::as_i64).unwrap_or(0);
        let over = kwh > 4000;
        cx.note(format!("{kwh} kWh, threshold breached: {over}"))
            .await?;

        Ok(Outcome::done(
            input.map(move |v| json!({ "reading": v, "anomalous": over })),
        ))
    }
}

/// Would post the result. Asserts what it was handed.
#[derive(Debug)]
struct Post;

#[async_trait::async_trait]
impl Skill for Post {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("post").provides("meter.post")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Two steps downstream of the fetch, and still marked untrusted —
        // nobody had to thread that through by hand.
        assert!(input.label().is_untrusted());
        cx.note("posting result").await?;
        Ok(Outcome::done(input))
    }
}

/// fetch → validate → post
fn pipeline() -> PlanIR {
    PlanIR::new(vec![
        PlanNode::new(0, "meter.fetch").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "meter.validate").arg("reading", ArgSource::node(StepId(0))),
        PlanNode::new(2, "meter.post")
            .arg("checked", ArgSource::node(StepId(1)))
            .terminal(),
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(SqliteStore::open_in_memory()?);
    let rt = Runtime::builder(Arc::clone(&store))
        .skill(Fetch)
        .skill(Validate)
        .skill(Post)
        .build();

    // ── 1. A graph runs in dependency order ────────────────────────────────
    let plan = pipeline();
    println!("plan digest      → {}", plan.digest());

    let out = rt
        .run_plan(plan.clone(), json!({ "meter": "51238696781" }))
        .await?;
    println!("run              → {}", out.status.as_str());
    println!("output           → {}", out.output.as_ref().unwrap());

    // ── 2. Every step is journaled under its own id ────────────────────────
    let records = store.read(out.run_id, 1).await?;
    let steps: Vec<String> = records
        .iter()
        .filter(|r| r.kind().kind_str() == "StepStarted")
        .filter_map(|r| r.body.step.map(|s| s.to_string()))
        .collect();
    println!("steps            → {}", steps.join(" → "));

    let frozen = records.iter().any(
        |r| matches!(r.kind(), RecordKind::PlanFrozen { digest, .. } if *digest == plan.digest()),
    );
    println!("plan in journal  → {frozen} (the run can be audited against it)");
    store.verify(out.run_id).await?;
    println!("chain            → verifies");

    // ── 3. A plan that could never finish never starts ─────────────────────
    let circular = PlanIR::new(vec![
        PlanNode::new(0, "meter.fetch")
            .arg("a", ArgSource::node(StepId(1)))
            .terminal(),
        PlanNode::new(1, "meter.validate").arg("b", ArgSource::node(StepId(0))),
    ]);
    match rt.run_plan(circular, json!({})).await {
        Err(e) => println!("\ncircular plan    → refused: {e}"),
        Ok(_) => panic!("a plan with a cycle must not run"),
    }

    // A capability nothing provides is caught the same way.
    let ungrounded = PlanIR::single("meter.delete-everything");
    match rt.run_plan(ungrounded, json!({})).await {
        Err(e) => println!("ungrounded plan  → refused: {e}"),
        Ok(_) => panic!("a plan asking for what we cannot do must not run"),
    }

    // ── 4. Collaboration must justify itself ───────────────────────────────
    // Two "parallel" steps that read the same input are not parallel: the
    // coordination cost is paid and no parallelism is obtained.
    let false_parallelism = PlanIR::new(vec![
        PlanNode::new(0, "meter.fetch").arg("a", ArgSource::input_field("meter")),
        PlanNode::new(1, "meter.validate").arg("b", ArgSource::input_field("meter")),
        PlanNode::new(2, "meter.post")
            .arg("x", ArgSource::node(StepId(0)))
            .arg("y", ArgSource::node(StepId(1)))
            .terminal(),
    ])
    .topology(Topology::Collaborative(Collaboration::ParallelDisjoint));

    match rt.run_plan(false_parallelism, json!({})).await {
        Err(e) => println!("\nfalse parallel   → refused: {e}"),
        Ok(_) => panic!("overlapping inputs are not disjoint"),
    }

    // The same shape over genuinely separate inputs is fine.
    let genuine = PlanIR::new(vec![
        PlanNode::new(0, "meter.fetch").arg("a", ArgSource::input_field("meter")),
        PlanNode::new(1, "meter.validate").arg("b", ArgSource::input_field("other")),
        PlanNode::new(2, "meter.post")
            .arg("x", ArgSource::node(StepId(0)))
            .arg("y", ArgSource::node(StepId(1)))
            .terminal(),
    ])
    .topology(Topology::Collaborative(Collaboration::ParallelDisjoint));

    let ok = rt
        .run_plan(genuine, json!({ "meter": "A", "other": "B" }))
        .await?;
    println!("genuine parallel → {}", ok.status.as_str());
    assert_eq!(ok.status, RunStatus::Succeeded);

    Ok(())
}
