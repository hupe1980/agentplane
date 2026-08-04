//! Execution: the step context, the effect protocol, and the executor.

pub mod batch;
mod ctx;
#[cfg(feature = "manifest")]
mod declarative;
pub mod effects;
mod executor;
pub mod metrics;
mod sweeper;
pub mod telemetry;

pub use batch::BatchSpec;
pub use ctx::{Mode, StepCtx};
#[cfg(feature = "manifest")]
pub use executor::Agent;
pub use executor::{LEASE_TTL, MIN_LEASE_TTL, RunOutcome, RunStatus, Runtime, RuntimeBuilder};
pub use sweeper::SweepReport;
