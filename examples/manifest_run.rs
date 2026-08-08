//! An agent whose prompt, model, result shape and ceilings come from a file.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example manifest_run --features redb,testkit,manifest
//! ```
//!
//! No API key, no network — `testkit::FakeProvider` stands in for the provider.
//!
//! The claim this example exists to make concrete: **a builder call is invisible
//! in review, and a file is not.** Everything security-relevant here —
//! instructions, tools, model, ceilings, result contract — is in
//! `examples/triage.yaml`, where changing it is a diff with a reviewer on it.
//!
//! What it demonstrates, in order:
//!
//! 1. The prompt and schema in the file are the ones the provider is asked with.
//! 2. The ceiling in the file binds the run.
//! 3. A typo is refused rather than ignored — the failure mode that makes
//!    permissive config formats dangerous.
//! 4. A published version cannot be rewritten, and a pinned resolve refuses
//!    content the caller never reviewed.
//!
//! Point 3 is the one worth pausing on. `max_tokns: 100` in a tolerant parser
//! does not mean "a ceiling with a typo" — it means *no ceiling at all*, in the
//! one document whose purpose was to make the ceiling reviewable.

use std::sync::Arc;

use agentplane::core::{Outcome, Sensitivity, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::manifest::{Manifest, ManifestError, MemoryRegistry, Registry, RegistryError};
use agentplane::model::{ModelCall, ModelId, ModelProvider};
use agentplane::runtime::{Agent, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::FakeProvider;
use serde_json::{Value, json};

/// The declaration, checked in beside the code that runs it.
const AGENT: &str = include_str!("triage.yaml");

/// One of the agent's skills.
///
/// It holds **no manifest**. An agent has skills, not the other way round — the
/// runtime is the agent, it owns the declaration, and a skill asks its execution
/// context which agent it is part of. A skill separately configured with its own
/// copy could disagree with the agent about what the agent is, which is exactly
/// the drift a single reviewable file is supposed to remove.
///
/// So nothing in this struct decides what the agent is told, which model
/// answers, or what shape the answer takes.
#[derive(Debug)]
struct Triage {
    provider: Arc<FakeProvider>,
}

#[async_trait::async_trait]
impl Skill for Triage {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("triage").provides("support.triage")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // Asked of the context, not held by this skill. Read into owned
        // values up front, so nothing borrows the agent while the effects run.
        let (system, model, schema) = {
            let manifest = cx.manifest().expect("this agent runs under a manifest");
            let spec = &manifest.spec;

            // The words the agent is given. agentplane does not own them; it
            // owns their hash, and the layout this renders to is pinned by a
            // test.
            let system = spec
                .identity
                .as_ref()
                .map(agentplane::manifest::Identity::system_prompt)
                .unwrap_or_default();

            // The model the file names, not one chosen here.
            let m = spec
                .models
                .as_ref()
                .and_then(|m| m.privileged.as_ref())
                .expect("triage.yaml declares a privileged model");

            (
                system,
                ModelId::new(&m.provider, &m.model),
                manifest.output_schema().cloned(),
            )
        };

        // Built twice, because a verifier pass is a second question rather than
        // the same one asked again — and an effect key derived from an identical
        // prompt would collide with the first call's.
        let build = |prompt: Value| {
            let mut call = ModelCall::new(
                Arc::clone(&self.provider) as Arc<dyn ModelProvider>,
                model.clone(),
                prompt,
            )
            .with_max_sensitivity(Sensitivity::Internal);
            // The declared result contract. Handed to `expecting`, it goes into
            // the **effect key** — so editing the schema makes a replay report
            // divergence rather than quietly reinterpreting a stored answer
            // under today's rules.
            if let Some(schema) = &schema {
                call = call.expecting(schema.clone());
            }
            call
        };

        let first_prompt = Tainted::object([
            ("system".to_owned(), Tainted::trusted(json!(system.clone()))),
            ("ticket".to_owned(), input),
        ]);
        let first = cx
            .sink(build(first_prompt.peek().clone()), &first_prompt)
            .await?;

        let draft = first.map(|completion| {
            completion
                .structured
                .unwrap_or_else(|| json!({ "text": completion.text }))
        });

        // A verifier pass over the first answer — `plan-then-execute` agents
        // routinely have one, and it is what makes the ceiling in step 2
        // demonstrable at all: a metered budget **overshoots by one operation**,
        // because a call's cost is not known until it has run. What is enforced
        // is *once consumption has reached the limit, nothing further starts*,
        // so a one-call skill completes whatever the token ceiling says.
        let checked_prompt = Tainted::object([
            ("system".to_owned(), Tainted::trusted(json!(system))),
            ("verify".to_owned(), draft),
        ]);
        let checked = cx
            .sink(build(checked_prompt.peek().clone()), &checked_prompt)
            .await?;

        Ok(Outcome::done(checked.map(|c| {
            c.structured.unwrap_or_else(|| json!({ "text": c.text }))
        })))
    }
}

fn runtime_for(
    store: &Arc<dyn JournalStore>,
    manifest: &Arc<Manifest>,
    provider: &Arc<FakeProvider>,
) -> Arc<Runtime> {
    Runtime::builder(Arc::clone(store))
        // The declaration and the skills that serve it arrive together: the
        // manifest governs *this agent's* steps — its budget, its grants, its
        // ceilings — while the runtime keeps the journal and the drivers.
        .agent(Agent::new(manifest).skill(Triage {
            provider: Arc::clone(provider),
        }))
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let manifest = Arc::new(Manifest::parse(AGENT)?);

    println!(
        "agent:    {} {}",
        manifest.metadata.name, manifest.metadata.version
    );
    println!("governed by: {}", manifest.digest()?.to_hex());

    // ── 1. The file's declarations reach the provider ──────────────────────
    let provider = FakeProvider::new();
    let rt = runtime_for(&store, &manifest, &provider);

    let ticket = json!({ "id": "T-4711", "body": "checkout returns 500 for EU cards" });
    let live = rt
        .run("support.triage", Tainted::trusted(ticket.clone()))
        .await?;
    println!("\n1. live run       → {:?}", live.status);
    assert_eq!(
        live.status,
        RunStatus::Succeeded,
        "the nominal manifest run failed — this example is the executable proof that a \
         declared prompt can handle untrusted input without making its system instruction \
         untrusted"
    );

    let asked = provider.asked();
    let ask = asked.first().expect("the provider was asked");
    println!(
        "   system prompt:  {}",
        ask.prompt["system"].as_str().unwrap_or("<none>")
    );
    println!("   schema sent:    {}", ask.schema.is_some());

    assert_eq!(
        ask.prompt["system"].as_str(),
        Some("Support ticket triage\n\nClassify severity. Never promise a refund."),
        "the provider was asked with something other than the prompt in the file, \
         which would make the manifest's digest a record of the wrong thing"
    );
    assert_eq!(
        ask.schema.as_ref(),
        manifest.output_schema(),
        "the declared result contract did not reach the provider, where the \
         constraint is enforced during generation rather than rejected afterwards"
    );
    assert_eq!(ask.model, ModelId::new("fake", "triage-1"), "wrong model");

    // ── 2. The ceiling in the file binds ───────────────────────────────────
    // Same declaration, one number changed. Nothing in this file's Rust knows
    // what the ceiling is.
    let tight = Arc::new(Manifest::parse(
        &AGENT.replace("max_tokens: 120000", "max_tokens: 1"),
    )?);
    assert_ne!(
        manifest.digest()?,
        tight.digest()?,
        "changing a ceiling must change the declaration's identity"
    );

    let provider = FakeProvider::new();
    let rt = runtime_for(&store, &tight, &provider);
    let capped = rt.run("support.triage", Tainted::trusted(ticket)).await?;
    println!("\n2. one-token ceiling → {:?}", capped.status);
    println!("   spend:          {} tokens", capped.spend.tokens);
    println!(
        "   provider calls: {} of 2 — the second never started",
        provider.calls()
    );
    assert!(
        !matches!(capped.status, RunStatus::Succeeded),
        "a ceiling declared in the manifest did not bind the run, so the file \
         documents a limit the runtime does not apply"
    );
    assert_eq!(
        provider.calls(),
        1,
        "the first call is always allowed — its cost is unknown until it runs — \
         but the second must not start once consumption has reached the limit"
    );

    // ── 3. A typo is refused, not ignored ──────────────────────────────────
    let typo = AGENT.replace("max_tokens:", "max_tokns:");
    match Manifest::parse(&typo) {
        Err(ManifestError::Syntax(detail)) => {
            println!(
                "\n3. `max_tokns:` refused → {}",
                detail.lines().next().unwrap_or(&detail)
            );
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(m) => panic!(
            "a typo was ignored and the token ceiling silently became {:?} — this \
             is the failure mode the format exists to prevent",
            m.budget().max_tokens
        ),
    }

    // ── 4. A version is an artifact, not a moment ──────────────────────────
    registry_refusals(&manifest).await?;

    // ── 5. The journals verify ─────────────────────────────────────────────
    for run in [live.run_id, capped.run_id] {
        store.verify(run).await?;
    }
    println!("\n5. both journals verify");

    Ok(())
}

/// A published version cannot be rewritten, and a pin does not need to trust the
/// registry.
///
/// The two are deliberately not redundant: immutability catches the honest
/// mistake at write time while trusting the registry, and a pin catches the
/// dishonest one at read time while trusting nothing.
async fn registry_refusals(manifest: &Manifest) -> Result<(), Box<dyn std::error::Error>> {
    let registry = MemoryRegistry::new();
    let published = registry.publish(manifest).await?;
    println!("\n4. published      → {}", published.to_hex());

    // A retried deploy is not an attack.
    assert_eq!(
        registry.publish(manifest).await?,
        published,
        "republishing identical content must succeed"
    );

    // The supply-chain shape: same name, same version, one more tool. Nothing a
    // version-pinned consumer would notice.
    let widened = Manifest::parse(
        &AGENT.replace("  tools:\n", "  tools:\n    - ref: \"tool://shell/exec\"\n"),
    )?;
    match registry.publish(&widened).await {
        Err(RegistryError::Immutable { .. }) => {
            println!("   rewriting 2.0.0 with a wider grant → refused");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a published version was replaced with a wider grant"),
    }

    // And a pin is the half that survives the registry itself being the
    // compromised party.
    let hostile = MemoryRegistry::new();
    hostile.publish(&widened).await?;
    match hostile
        .resolve_pinned("support-triage", "2.0.0", published)
        .await
    {
        Err(RegistryError::PinBroken { .. }) => {
            println!("   pinned resolve against substituted content → refused");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a pinned resolve accepted content the caller never reviewed"),
    }

    Ok(())
}
