//! Execution: the step context, the effect protocol, and the executor.

mod attention;
pub mod batch;
mod build_error;
mod ctx;
#[cfg(feature = "manifest")]
mod declarative;
mod drain;
#[cfg(feature = "manifest")]
pub use declarative::PREVIEW_EVIDENCE_BYTES;
pub mod effects;
mod executor;
pub mod group;
pub mod metrics;
mod sweeper;
pub mod telemetry;

pub use attention::{Attention, Condition};
pub use batch::BatchSpec;
pub use build_error::BuildError;
pub use ctx::{BuildsEffect, Mode, StepCtx};
pub use drain::DrainReport;
#[cfg(feature = "manifest")]
pub use executor::Agent;
/// The one `RunStatus` list, shared by every test that owes a per-variant
/// decision — resume, sealing, and the A2A state mapping. Test-only.
#[cfg(test)]
pub(crate) use executor::every_status;
/// The one reader of "what does this run's history say its state is", shared by
/// every surface that answers the question. Crate-internal: the public form is
/// [`Runtime::recorded_outcome`], which is what an embedder holds.
///
/// Ungated, because both in-crate consumers are: the operator API reads it to
/// answer `GET /runs/{run}`, and a restore reads it to name the runs that came
/// back waiting. Two surfaces, one reader — a second copy of the match is the
/// copy that disagrees the day a record kind arrives.
pub(crate) use executor::observed_status;
pub use executor::{
    Admission, FullBackend, LEASE_TTL, LiveRun, MAX_ADMISSION_KEY_BYTES, MIN_LEASE_TTL,
    OBSERVED_OUTCOME, OUTCOMES_OF_RECORD, RunFailure, RunOutcome, RunStatus, RunTerms, Runtime,
    RuntimeBuilder, SEALED_OUTCOMES, Spawned, Stores,
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
pub use sweeper::{Redelivered, Saturation, SweepReport, WokenRuns};
