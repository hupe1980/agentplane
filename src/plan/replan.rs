//! Replanning — a run changing its mind, on the record.
//!
//! # Versioned, never mutative
//!
//! A replan produces `PlanIR v2` carrying `derived_from: v1`, rather than
//! editing the plan in place. What the run *intended* before it changed its mind
//! is usually the interesting part of an incident, and it is structurally absent
//! from any system that edits a plan. Both versions stay in the journal.
//!
//! # Why replanning is refused once untrusted data is in play
//!
//! The frozen plan is an authorization graph: it is compiled from trusted input
//! only, and every argument is bound to a declared provenance. That property is
//! what makes it safe to check the journal against the plan afterwards.
//!
//! A replan *changes the graph*. If untrusted data has already reached working
//! memory, then anything influencing the new plan may be attacker-shaped — and
//! the attacker gets to choose the authorization graph, which is the whole game.
//! So the `plan-then-execute` rule is enforced structurally: once any
//! `Untrusted` value is in the run's outputs, `Outcome::Replan` is refused.
//!
//! This is the one place where refusing looks unhelpful and is not. A run that
//! wants a different plan after reading untrusted input is describing exactly
//! the attack.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{Capability, PlanIR, StepId};

/// Produces a new plan version for a run that asked for one.
///
/// Deliberately a seam rather than a built-in: where a new plan comes from —
/// a router, a rules table, a model call — is a deployment decision, and the
/// runtime's job is to make whichever choice auditable rather than to make it.
#[async_trait]
pub trait Replanner: Send + Sync + Debug {
    /// Produce a successor to `current`.
    ///
    /// `completed` names the steps that already ran, with the capability each
    /// one used. Their effects are in the journal and will not be performed
    /// again, so a successor that drops them is not undoing them — it is only
    /// declining to do more.
    ///
    /// **A completed step's id may not be reused for different work.** Keep it
    /// with the same capability, or leave it out. Effect keys are derived from
    /// the step id, so putting new work at a used id makes the run unreplayable
    /// and makes the saga compensate something that never happened. The runtime
    /// checks this and refuses a successor that breaks it.
    ///
    /// The result is validated against the same contract a first plan faces. A
    /// successor that fails validation stops the run rather than half-applying.
    async fn replan(
        &self,
        current: &PlanIR,
        reason: &str,
        completed: &[(StepId, Capability)],
    ) -> Result<PlanIR, ReplanError>;
}

/// Why a new plan could not be produced.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplanError {
    /// The planner declined — no better plan exists for this fault.
    #[error("no alternative plan: {0}")]
    NoAlternative(String),

    #[error("{0}")]
    Other(String),
}

impl PlanIR {
    /// Derive a successor from this plan.
    ///
    /// Sets the version, the lineage, and the reason together, because a
    /// successor missing any of the three is an audit trail with a hole in it.
    #[must_use]
    pub fn succeed_with(
        &self,
        nodes: Vec<crate::core::PlanNode>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            version: self.version + 1,
            derived_from: Some(self.digest()),
            reason: Some(reason.into()),
            topology: self.topology,
            nodes,
        }
    }
}
