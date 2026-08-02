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
//!    ([`core::RuntimeError::NonDeterminism`]).
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
//! // With the default features, `agentplane::store::TursoStore` is one.
//! let runtime = Runtime::builder(store).skill(Greet).build();
//! let outcome = runtime.run("greet", serde_json::json!({"name": "world"})).await?;
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
pub mod batch;
pub mod blob;
pub mod case;
pub mod core;
pub mod journal;
pub mod model;
pub mod peers;
pub mod plan;
pub mod policy;
pub mod runtime;
pub mod tools;

#[cfg(feature = "redb")]
pub mod store;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use crate::core::{
    AgentRef, Capability, CaseId, Digest, EffectKey, Label, Outcome, Recovery, RunId, RuntimeError,
    Sensitivity, Seq, Skill, SkillDescriptor, SourceId, StepId, Tainted, Trust,
};
pub use crate::journal::{JournalStore, Record, RecordKind};
pub use crate::runtime::{Runtime, StepCtx};
