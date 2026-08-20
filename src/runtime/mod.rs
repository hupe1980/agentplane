//! Execution: the step context, the effect protocol, and the executor.

pub mod batch;
mod build_error;
mod ctx;
#[cfg(feature = "manifest")]
mod declarative;
pub mod effects;
mod executor;
pub mod group;
pub mod metrics;
mod sweeper;
pub mod telemetry;

pub use batch::BatchSpec;
pub use build_error::BuildError;
pub use ctx::{BuildsEffect, Mode, StepCtx};
#[cfg(feature = "manifest")]
pub use executor::Agent;
/// The one `RunStatus` list, shared by every test that owes a per-variant
/// decision — resume, sealing, and the A2A state mapping. Test-only.
#[cfg(test)]
pub(crate) use executor::every_status;
pub use executor::{
    Admission, FullBackend, LEASE_TTL, MAX_ADMISSION_KEY_BYTES, MIN_LEASE_TTL, RunFailure,
    RunOutcome, RunStatus, Runtime, RuntimeBuilder, SEALED_OUTCOMES, Spawned,
};
pub use group::{EffectGroup, Invariant};

/// The embedder and the index it embeds for, wired as one thing.
///
/// They are one field rather than two because neither is usable without the
/// other and the *pair* is what carries the invariant: a query vector means
/// something only against an index built in the same space, and a plane that
/// held them separately could be wired with two that disagree. `build` refuses
/// that pairing — see [`RuntimeBuilder::semantic_memory`] — so by the time a
/// run can reach this, the check has already happened.
#[derive(Debug)]
pub struct SemanticMemory {
    pub(crate) embedder: std::sync::Arc<dyn crate::memory::Embedder>,
    pub(crate) retriever: std::sync::Arc<dyn crate::memory::SemanticRetriever>,
}
pub use sweeper::{Saturation, SweepReport, WokenRuns};
