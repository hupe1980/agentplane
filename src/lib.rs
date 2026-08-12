//! # agentplane
//!
//! A durable, replayable, policy-governed runtime for agents whose steps invoke
//! non-deterministic models and mutate real systems.
//!
//! One sentence carries the rest:
//!
//! > **The journal is the plan of record.** Orchestration is deterministic and
//! > replayable; every non-deterministic act — inference, tool call, clock, RNG,
//! > deadline resolution — is an [`Effect`](core::Effect) performed *at most
//! > once*, journaled, and read back on replay.
//!
//! ## The determinism boundary
//!
//! ```text
//! ┌──────────────── DETERMINISTIC ZONE ────────────────┐
//! │ plan traversal · guards · retry decisions · budget  │
//! │ policy evaluation · label joins · record upcasting  │
//! │                                                     │
//! │ Replay re-executes this and MUST reproduce the      │
//! │ identical sequence of effect keys.                  │
//! └───────────────────────┬─────────────────────────────┘
//!                         │ cx.effect(…)
//! ┌───────────────────────▼─────────────────────────────┐
//! │            NON-DETERMINISTIC ZONE                    │
//! │ inference · tools · clock · RNG · network · humans   │
//! │                                                      │
//! │ Executed at most once. Journaled. Replay reads.      │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! Three layers enforce it, because convention is not enforcement:
//!
//! 1. **Lint gating** — `clippy.toml` denies `SystemTime::now`, `rand::random`,
//!    `Ulid::new` and friends crate-wide.
//! 2. **Effect-key verification** — on replay, a recomputed key that differs
//!    from the journaled one quarantines the run rather than diverging silently
//!    ([`core::StepError::NonDeterminism`]).
//! 3. **Storage constraints** — the journal's unique index makes "an effect is
//!    started at most once per run" a database invariant, not a code path.
//!
//! ## Example
//!
//! ```no_run
//! use agentplane::core::{Outcome, Skill, SkillDescriptor, Tainted};
//! use agentplane::journal::JournalStore;
//! use agentplane::runtime::{Mode, Runtime, StepCtx};
//! use std::sync::Arc;
//!
//! #[derive(Debug)]
//! struct Greet;
//!
//! #[async_trait::async_trait]
//! impl Skill for Greet {
//!     fn descriptor(&self) -> SkillDescriptor {
//!         SkillDescriptor::new("greet").provides("demo.greet")
//!     }
//!
//!     async fn invoke(
//!         &self,
//!         cx: &mut StepCtx<'_>,
//!         input: Tainted<serde_json::Value>,
//!     ) -> Result<Outcome, agentplane::core::SkillError> {
//!         // `now()` is a journaled effect: on replay it returns the recorded
//!         // instant rather than reading the clock again.
//!         let at = cx.now().await?;
//!         Ok(Outcome::done(input.map(|v| serde_json::json!({
//!             "greeted": v, "at": at.to_string(),
//!         }))))
//!     }
//! }
//!
//! # async fn run(store: Arc<dyn JournalStore>) -> Result<(), Box<dyn std::error::Error>> {
//! // With the default features, `agentplane::store::RedbStore` is one.
//! let runtime = Runtime::builder(store).skill(Greet).build();
//! let outcome = runtime.run("greet", Tainted::trusted(serde_json::json!({"name": "world"}))).await?;
//!
//! // Replaying re-executes the deterministic zone and reads every effect back
//! // from the journal. No clock is read; no tool is called twice. `Strict`
//! // additionally fails if this build wants an effect the journal lacks.
//! runtime.replay(outcome.run_id, Mode::Strict).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "http")]
pub mod api;
pub mod audit;
pub mod authority;
pub mod batch;
pub mod blob;
pub mod case;
pub mod core;
pub mod export;
pub mod journal;
#[cfg(feature = "keyring")]
pub mod keyring;
#[cfg(feature = "manifest")]
pub mod manifest;
#[cfg(feature = "media")]
pub mod media;
pub mod memory;
pub mod model;
pub mod netguard;
pub mod peers;
pub mod plan;
pub mod policy;
#[cfg(feature = "push")]
pub mod push;
pub mod quota;
pub mod runtime;
pub mod tools;

#[cfg(any(feature = "redb", feature = "postgres"))]
pub mod store;

#[cfg(feature = "testkit")]
pub mod testkit;

// A backend feature must deliver its backend.
//
// `store` was declared under `redb` alone while holding both backends, so
// `--no-default-features --features postgres` compiled cleanly, pulled in
// `tokio-postgres` and `deadpool-postgres`, and exposed *no store module at
// all* — the Postgres deployment paid for three dependency crates and could not
// name `PostgresStore`. `just features` reported success throughout, because
// building a feature and reaching what it names are different questions and it
// only ever asked the first.
//
// These make the compiler ask the second. Naming the type is what a consumer
// does, so a gate that configures it out fails here rather than in their editor.
#[cfg(feature = "redb")]
const _: fn() = || {
    let _: Option<&crate::store::RedbStore> = None;
};
#[cfg(feature = "postgres")]
const _: fn() = || {
    let _: Option<&crate::store::PostgresStore> = None;
};

// The same question, asked of the embedding drivers, because they failed it the
// same way. `model::embeddings` was gated on `providers` while holding
// `BedrockEmbedder` — so `--features bedrock` bought the AWS SDK, documented
// Titan and Cohere embeddings, and exposed no embedder at all. Semantic
// retrieval was unavailable to exactly the deployments that chose Bedrock
// because their data may not leave one account, which is the population the
// driver exists for.
#[cfg(feature = "providers")]
const _: fn() = || {
    let _: Option<&crate::model::embeddings::OpenAiEmbedder> = None;
    let _: Option<&crate::model::embeddings::GeminiEmbedder> = None;
};
#[cfg(feature = "bedrock")]
const _: fn() = || {
    let _: Option<&crate::model::embeddings::BedrockEmbedder> = None;
};

/// Embed a directory of single-agent manifests, keyed by declared name.
///
/// One `include_str!` per path, handed to [`Manifest::parse_each`] with the path
/// literal as the origin for diagnostics. The result is
/// `Result<BTreeMap<String, Manifest>, ManifestError>` keyed by each document's
/// own `metadata.name`.
///
/// ```ignore
/// let agents = agentplane::manifests![
///     "agents/obligation-watch.yaml",
///     "agents/clearing-triage.yaml",
/// ]?;
/// let watch = &agents["obligation-watch"];
/// ```
///
/// # Why this exists rather than a hand-written table
///
/// The obvious form is `&[(&str, &str)]` with a name typed beside each path.
/// The name is **already in the document**, so that table is one fact written
/// twice with nothing checking that the two agree — and a file included under
/// two constants, which is what happens while adding the next agent, builds and
/// runs with one agent registered twice and another silently absent. Here the
/// key comes from the document and a duplicate name is a compile-time-embedded,
/// run-time-refused error naming both paths.
///
/// Paths are relative to the invoking file, exactly as `include_str!` resolves
/// them, and each is recorded in the diagnostic for the document it failed on.
/// There is no glob: a macro that expanded a directory listing would make the
/// set of agents a plane runs depend on what is on disk at build time rather
/// than on what is in the source a reviewer reads.
///
/// [`Manifest::parse_each`]: crate::manifest::Manifest::parse_each
#[cfg(feature = "manifest")]
#[macro_export]
macro_rules! manifests {
    ($($path:literal),+ $(,)?) => {
        $crate::manifest::Manifest::parse_each([
            $(($path, include_str!($path))),+
        ])
    };
}

pub use crate::core::{
    AgentRef, Capability, CaseId, Digest, EffectKey, Label, Outcome, Recovery, RunId, RuntimeError,
    Sensitivity, Seq, Skill, SkillDescriptor, SourceId, StepId, Tainted, Trust,
};
pub use crate::journal::{JournalStore, Record, RecordKind};
pub use crate::runtime::{Runtime, StepCtx};

/// The names every program needs, so the first one is one `use` line.
///
/// ```
/// use agentplane::prelude::*;
/// ```
///
/// # What is in here, and the rule
///
/// A prelude earns its place by being *predictable*, so this one is chosen by a
/// stated rule rather than by taste: **a name belongs here if a program that
/// does nothing unusual needs it.** Measured, not guessed — every name below
/// appears in a third or more of the crate's own examples, and the set is
/// exactly what the getting-started program imports, which is why that program
/// now opens with one line instead of five.
///
/// The four groups are the four things any program touches: the skill you write
/// (`Skill`, `SkillDescriptor`, `SkillError`, `Outcome`), the context it is
/// handed (`StepCtx`), the labels its data carries (`Tainted`, `Trust`,
/// `Sensitivity`), and the plane that runs it (`Runtime`, `RunStatus`, `Mode`,
/// `JournalStore`, and the default store).
///
/// # What is deliberately left out
///
/// Names that are common in this crate but collision-prone in somebody else's:
/// `Record`, `Digest`, `Label`, `Capability`, `Seq`. A prelude that shadows a
/// user's own `Record` costs more than the import it saved, and each of those is
/// one explicit `use` away. Anything feature-gated beyond the default backend is
/// out for the same reason a glob would be: what a prelude imports must not
/// depend on which features happen to be on, or the same `use` line means
/// different things in two crates.
///
/// Everything here is also reachable by its full path; the prelude adds no API.
pub mod prelude {
    pub use crate::core::{
        Outcome, Sensitivity, Skill, SkillDescriptor, SkillError, Tainted, Trust,
    };
    pub use crate::journal::JournalStore;
    pub use crate::runtime::{Mode, RunStatus, Runtime, StepCtx};

    /// The default embedded backend, present whenever `redb` is.
    ///
    /// The one feature-gated name here, because it is on by default and a
    /// prelude that made the first program still need a second `use` line for
    /// its store would not have done its job.
    #[cfg(feature = "redb")]
    pub use crate::store::RedbStore;
}
