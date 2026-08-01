//! Execution: the step context, the effect protocol, and the executor.

pub mod batch;
mod ctx;
pub mod effects;
mod executor;
pub mod metrics;
mod sweeper;
pub mod telemetry;

pub use batch::BatchSpec;
pub use ctx::{Mode, StepCtx};
pub use executor::{RunOutcome, RunStatus, Runtime, RuntimeBuilder};
pub use sweeper::SweepReport;
