//! Skills — the only code an integrator writes.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{SkillError, Tainted};
use crate::runtime::StepCtx;

/// An abstract, domain-neutral capability name.
///
/// The engine compares these; it never interprets them. `de.mako.billing.audit`
/// and `system.audit.invariant-checking` are equally meaningless to the runtime,
/// which is what keeps it domain-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// A fully-pinned reference to an agent: name, version, and manifest digest.
///
/// A run records the digest it executed under, so "which exact configuration
/// produced this decision?" is answerable months later, byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRef {
    pub name: String,
    pub version: String,
    pub digest: crate::core::Digest,
}

/// What a skill is and what it promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillDescriptor {
    pub name: String,
    pub provides: Vec<Capability>,
}

impl SkillDescriptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            provides: Vec::new(),
        }
    }

    #[must_use]
    pub fn provides(mut self, cap: impl Into<Capability>) -> Self {
        self.provides.push(cap.into());
        self
    }
}

/// What a step produced.
#[derive(Debug)]
#[non_exhaustive]
pub enum Outcome {
    /// Finished, with a labeled result.
    Done(Tainted<Value>),
    /// Hand off to another agent or a remote peer.
    ///
    /// Requires a `collaborative` topology with a declared justification:
    /// collaboration buys parallelism at the price of the single largest
    /// measured failure category in multi-agent systems, so it is never a
    /// default.
    Delegate {
        target: String,
        input: Tainted<Value>,
    },
    /// Recoverable fault; ask the planner for a new plan version.
    Replan { reason: String },
    /// Terminal failure.
    Fail { reason: String },
}

impl Outcome {
    pub fn done(v: Tainted<Value>) -> Self {
        Self::Done(v)
    }

    pub fn fail(reason: impl Into<String>) -> Self {
        Self::Fail {
            reason: reason.into(),
        }
    }
}

/// A step's place in the saga, and what undoing it means.
///
/// A plan that touches real systems cannot be a transaction — there is nothing
/// to roll back across a payment provider and a warehouse. The saga answer is
/// to undo forward: when a later step fails, earlier steps are compensated in
/// reverse order. Compensation is a *recovery design, not a time machine*, and
/// what a step declares here is what the runtime is allowed to assume about it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compensation {
    /// Nothing declared.
    ///
    /// **Resolved from evidence rather than assumed.** A step that performed no
    /// mutating effect has nothing to undo, and the journal proves it — that
    /// step passes. A step that *did* mutate and declared nothing is escalated,
    /// because silently leaving a charge in place while unwinding everything
    /// around it is the failure this whole mechanism exists to prevent.
    ///
    /// The default, so forgetting to declare is loud rather than convenient.
    #[default]
    Undeclared,

    /// [`Skill::compensate`] undoes this step.
    Compensatable,

    /// The saga's point of no return.
    ///
    /// Once a pivot commits, the business is committed: nothing before it is
    /// undone, because undoing it would reverse a decision the outside world
    /// has already acted on. A failure after the pivot escalates rather than
    /// unwinding.
    Pivot,

    /// Nothing to undo, and the author says so.
    ///
    /// Distinct from [`Undeclared`](Self::Undeclared): this is a claim someone
    /// made, and it appears in the journal as one.
    Unnecessary,
}

/// A stateless unit of logic.
///
/// Statelessness is not a style preference: it is what makes replay sound.
/// All state lives in the journal, so re-running a skill against a replayed
/// context reproduces its decisions exactly.
///
/// Note the absent variant: there is no `Outcome::SuspensionRequired`. Suspension
/// is `cx.suspend().await`, so skill authors never hand-roll state
/// serialization — the runtime persists the frame and drops the task.
#[async_trait]
pub trait Skill: Send + Sync + std::fmt::Debug + 'static {
    fn descriptor(&self) -> SkillDescriptor;

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError>;

    /// This step's place in the saga.
    ///
    /// Defaults to [`Compensation::Undeclared`], which is resolved against the
    /// journal rather than waved through — see that variant.
    fn compensation(&self) -> Compensation {
        Compensation::Undeclared
    }

    /// Undo this step, because a later one failed.
    ///
    /// Called in reverse order of completion, with the output this step
    /// produced. The context is a full [`StepCtx`](crate::runtime::StepCtx):
    /// compensating effects are journaled, retried, reconciled, and replayed
    /// exactly like forward ones, because they are exposed to the same world
    /// and can fail the same ways.
    ///
    /// Errors are not retried by unwinding further. A failed compensation is
    /// not a problem more compensation solves, so the run is quarantined and an
    /// operator is told which step could not be undone.
    async fn compensate(
        &self,
        _cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        Err(SkillError::Other(
            "this step declares Compensation::Compensatable but does not implement \
             compensate()"
                .into(),
        ))
    }
}
