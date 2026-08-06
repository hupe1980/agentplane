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
pub use ctx::{Mode, StepCtx};
#[cfg(feature = "manifest")]
pub use executor::Agent;
pub use executor::{LEASE_TTL, MIN_LEASE_TTL, RunOutcome, RunStatus, Runtime, RuntimeBuilder};
pub use group::{EffectGroup, Invariant};
pub use sweeper::{Saturation, SweepReport};
