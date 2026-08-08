//! Three agents writing a blog post: an orchestrator and two specialists.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example blog_room --features redb,testkit,manifest
//! ```
//!
//! No API key, no network.
//!
//! **One plane, three agents.** A runtime is not an agent: it owns the journal,
//! the drivers and the process identity, and *runs* whichever agents are
//! registered on it. Each of the three here — `blog-editor.yaml`,
//! `room.yaml`'s desk, researcher and writer — keeps its own manifest, prompt,
//! model and ceilings, and is separately answerable. What they share is
//! infrastructure, which is what infrastructure is for.
//!
//! What it demonstrates:
//!
//! 1. Only the orchestrator may delegate, and it had to say **why**.
//! 2. A specialist that tries to grant itself delegation is refused at parse.
//!    The *runtime* half — a specialist refused when it actually hands off —
//!    is enforced by the same ceiling and covered in the test suite; this
//!    example shows the declaration, not the dispatch.
//! 3. Delegation is a **journaled effect**, so a replay reassembles the post
//!    without waking a single specialist.
//! 4. Budgets compose: the specialists' spend is billed to the run that
//!    commissioned it, because a delegation is an effect and effects report
//!    what they cost.
//! 5. The same room again with **nobody writing an orchestrator**: a
//!    `tool-calling` desk (`room.yaml`, first document) is granted the specialists as
//!    `tool://agent/...` tools, and the model decides whom to consult. The
//!    choice between the two shapes is the real lesson — the coded `Editor`
//!    *dictates* the sequence (the writer always receives the researcher's
//!    claims, because code says so), while the desk leaves consultation to
//!    the model's judgement. A sequence that is policy belongs in code or a
//!    plan; a consultation that is a judgement call can be a grant.
//!
//! Point 3 is what makes this more than a function call. `cx.commission` is an
//! **effect**: journaled under a key, so a replay reads the answer back instead
//! of commissioning the work again. A skill that reached another runtime
//! directly would be doing non-deterministic work outside the journal, and
//! replay would re-run the whole room.
//!
//! It lives on `StepCtx` rather than being wired by the caller for a structural
//! reason: a skill cannot hold its own runtime, because the runtime needs the
//! skill before the skill can have the runtime. Commissioning belongs to the
//! plane, and this is how a step reaches it.

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted, Trust};
use agentplane::journal::JournalStore;
use agentplane::manifest::{Manifest, ManifestError};
use agentplane::model::ModelProvider;
use agentplane::runtime::{Agent, Mode, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

const EDITOR: &str = include_str!("blog-editor.yaml");
/// The YAML room: desk, researcher and writer in **one file**, separated by
/// `---` — the Kubernetes packaging convention, and what lets the `agentplane`
/// CLI run this same room with no Rust at all. The file is packaging; each
/// document keeps its own digest.
const ROOM: &str = include_str!("room.yaml");

// ── The orchestrator ────────────────────────────────────────────────────────

/// Commissions research, then a draft, then assembles.
#[derive(Debug)]
struct Editor;

#[async_trait::async_trait]
impl Skill for Editor {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("editor").provides("blog.commission")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // The manifest is what permits this at all: a `specialist` reaching this
        // code would have been refused at parse for declaring a delegation depth
        // above zero.
        let brief = input.peek().clone();

        let claims = cx.commission("blog.research", input).await?;

        // The researcher's answer came from a model, so the writer is
        // commissioned with an untrusted brief — and the label travels with it
        // rather than being re-asserted by hand.
        let for_writer = claims.map(|c| json!({ "brief": brief, "claims": c }));
        let draft = cx.commission("blog.draft", for_writer).await?;

        assert_eq!(draft.label().trust, Trust::Untrusted);
        Ok(Outcome::done(draft))
    }
}

// ── Wiring ──────────────────────────────────────────────────────────────────

/// A specialist, assembled from its file.
///
/// Note what is *not* here: no skill, no prompt, no model id, no result shape.
/// The only Rust is which driver answers to the name `fake`, which is deployment
/// wiring rather than a property of the agent — an agent's declaration must not
/// change when its API key does.
fn parse(yaml: &str) -> Manifest {
    Manifest::parse(yaml).expect("a specialist manifest")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

    let provider = FakeProvider::new();
    // One file, three documents. `parse_all` validates every document — a
    // room two-thirds of which deploys is worse than one that refuses whole.
    let room = Manifest::parse_all(ROOM).expect("the room parses");
    let by_name = |name: &str| {
        room.iter()
            .find(|m| m.metadata.name == name)
            .cloned()
            .expect("the room names it")
    };
    let (desk_m, research_m, write_m) = (
        by_name("blog-desk"),
        by_name("blog-researcher"),
        by_name("blog-writer"),
    );

    // **One plane, three agents.** A runtime is not an agent: it owns the
    // journal, the drivers and the process identity, and runs whichever agents
    // are registered on it. Each keeps its own manifest, its own ceilings and
    // its own answerability; what they share is infrastructure.
    let editor_m = parse(EDITOR);
    let plane = Runtime::builder(Arc::clone(&store))
        .provider("fake", Arc::clone(&provider) as Arc<dyn ModelProvider>)
        .agent(Agent::new(&research_m))
        .agent(Agent::new(&write_m))
        .agent(Agent::new(&editor_m).skill(Editor))
        // The fourth agent needs no skill at all: its manifest grants the
        // specialists as tools, and the runtime supplies the loop.
        .agent(Agent::new(&desk_m))
        .build();

    println!("the room, each with its own declaration:");
    for m in [&editor_m, &research_m, &write_m] {
        let t = m.spec.topology.as_ref().expect("declared");
        let shape = format!("{:?}/{:?}", t.mode, t.role);
        println!(
            "  {:<17} {:<27} {:>6} tokens  {}",
            m.metadata.name,
            shape,
            m.budget().max_tokens.unwrap_or_default(),
            &m.digest()?.to_hex()[..12]
        );
    }

    // One process, one lease owner, three agents. A runtime-per-agent design
    // could not express that: it would have claimed three process identities for
    // what is plainly one.

    // ── 1. The room writes a post ──────────────────────────────────────────
    let brief = json!({ "topic": "why durable execution beats a retry loop" });
    let post = plane
        .run("blog.commission", Tainted::trusted(brief.clone()))
        .await?;
    println!("\n1. commissioned    → {:?}", post.status);
    println!(
        "   provider calls: {} (one per specialist)",
        provider.calls()
    );
    assert_eq!(provider.calls(), 2);

    // ── 2. Replay reassembles without waking the room ──────────────────────
    let replayed = plane.replay(post.run_id, Mode::Strict).await?;
    println!("\n2. strict replay   → {:?}", replayed.status);
    println!("   provider calls: {} — unchanged", provider.calls());
    assert_eq!(
        provider.calls(),
        2,
        "a replay that re-commissioned the specialists would pay the whole room \
         twice and could assemble a different post — delegation is journaled \
         precisely so it cannot"
    );
    assert_eq!(post.output, replayed.output, "the room replays exactly");

    // ── 3. A specialist may not grant itself a handoff ─────────────────────
    let overreaching = ROOM.replace("max_delegation_depth: 0", "max_delegation_depth: 1");
    match Manifest::parse_all(&overreaching).map(|_| ()) {
        Err(ManifestError::IncoherentTopology { .. }) => {
            println!("\n3. specialist granting itself delegation → refused at parse");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(()) => panic!(
            "a specialist declared a delegation ceiling above zero, which the \
             role forbids"
        ),
    }

    // And collaboration without a stated reason is refused just as firmly.
    assert!(
        Manifest::parse(&EDITOR.replace("    reason: distinct-authority\n", "")).is_err(),
        "collaboration was accepted without saying why it is worth its cost"
    );
    println!("   collaboration without a declared reason  → refused");

    // ── 4. Each agent spent against its own ceiling ────────────────────────
    // Budgets compose, and the mechanism is the ordinary one: a delegation is an
    // effect, and every effect reports what it consumed. `Delegate::spend`
    // returns the specialist's spend, so the editor's ledger carries the room's
    // cost and its `max_tokens` bounds the whole commission rather than its own
    // idling.
    //
    // Two properties fall out, and both are the same ones any metered effect
    // has. The spend is journaled in `EffectDone`, so a replay adds up the same
    // figures instead of asking the specialists again. And it is billed *after*
    // the fact, so the room overshoots by at most one commission — which is what
    // `max_effects` is for.
    assert!(
        post.spend.tokens > 0,
        "the editor's ledger shows nothing, so its ceiling bounds only its own \
         idling and a `max_tokens` on a delegating agent stops nothing"
    );
    println!(
        "\n4. the editor's run carries {} tokens — the specialists' spend, billed \
         through the delegation effect",
        post.spend.tokens
    );
    println!(
        "   so its max_tokens bounds the room; max_effects ({}) bounds the overshoot",
        editor_m.budget().max_effects.unwrap_or_default()
    );
    println!("   every journal in the room verifies");
    for run in [post.run_id] {
        store.verify(run).await?;
    }

    yaml_room(&plane, &provider, &store, brief).await?;

    Ok(())
}

/// The same room, from files alone — see the module docs, point 5.
async fn yaml_room(
    plane: &Runtime,
    provider: &FakeProvider,
    store: &Arc<dyn JournalStore>,
    brief: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    // ── 5. The same room, from files alone ─────────────────────────────────
    // `blog-desk.yaml` grants the specialists as `tool://agent/...` tools, so
    // the orchestrator is a file too — the model chooses whom to consult, and
    // every consultation is the same journaled commission the coded editor
    // used. Scripted here because a fake model has no judgement to exercise;
    // the order below is one a real model would plausibly choose.
    provider.will_call_tool(
        "call_research",
        "agent__blog_dresearch",
        json!({ "topic": "why durable execution beats a retry loop" }),
    );
    // Schema-shaped, because `room.yaml`'s researcher declares `output.schema`.
    // The fake enforces a declared schema exactly as a real driver does, so
    // prose here is a metered `Unusable` rather than a run that quietly yields
    // `Null` — which is what a real provider would have done all along.
    provider.will_say(r#"{"claims": ["Retries repeat work; journals replay it."]}"#);
    provider.will_call_tool(
        "call_draft",
        "agent__blog_ddraft",
        json!({
            "brief": "why durable execution beats a retry loop",
            "claims": "Retries repeat work; journals replay it.",
        }),
    );
    // The writer declares `{title, body}`; the desk's own answer is free text.
    provider.will_say(
        r#"{"title": "Journals over retries", "body": "A retry loop forgets; a journal remembers."}"#,
    );
    provider.will_say("Final: a retry loop forgets; a journal remembers.");

    let before = provider.calls();
    let desked = plane.run("blog.desk", Tainted::trusted(brief)).await?;
    println!("\n5. the YAML room   → {:?}", desked.status);
    println!(
        "   provider calls: {} — three desk turns and two specialists",
        provider.calls() - before
    );
    assert_eq!(provider.calls() - before, 5);
    assert!(
        desked.spend.tokens > 0,
        "the desk's ledger must carry the specialists' spend, exactly as the \
         coded editor's did"
    );

    let desked_again = plane.replay(desked.run_id, Mode::Strict).await?;
    assert_eq!(
        desked.output, desked_again.output,
        "the YAML room replays exactly"
    );
    assert_eq!(
        provider.calls() - before,
        5,
        "a strict replay woke the room"
    );
    println!(
        "   strict replay      → {:?} — nobody woken",
        desked_again.status
    );
    store.verify(desked.run_id).await?;
    Ok(())
}
