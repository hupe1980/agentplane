//! Authorization: who may do what to which resource.
//!
//! # What this is not
//!
//! It is not the information-flow lattice. Labels answer *may this value go
//! there* — a sensitivity ceiling on a sink, a taint gate on a mutation — and
//! they travel with the data. Policy answers *may this principal do this at
//! all*, and it travels with the request. Both gates exist because either one
//! alone leaves a hole: a correctly-labelled value sent by someone with no
//! authority, or an authorized caller exfiltrating a secret through a sink that
//! looks innocuous.
//!
//! # Evaluation is total and side-effect free
//!
//! [`PolicyEngine::authorize`] is synchronous and returns a [`PolicyDecision`], not a
//! `Result`. There is deliberately no way to express "the policy service was
//! unreachable", because a runtime that can fail *open* under load has no policy
//! layer — it has a policy layer that turns itself off exactly when a system is
//! under stress, which is when authorization matters most.
//!
//! This is the constraint that points at an embedded evaluator over a network
//! call: a policy set loaded into the process, evaluated against a request, with
//! no I/O in the path. Cedar is the obvious fit and this trait is shaped for it —
//! `principal`, `action`, `resource`, `context` is Cedar's vocabulary — but the
//! crate ships no engine. Picking one for the embedder would be the same mistake
//! as picking their tracing exporter.
//!
//! # Determinism, and why decisions are not journaled wholesale
//!
//! A policy decision made inside a run is a non-deterministic input in exactly
//! the sense the rest of this crate means it: the answer depends on a policy set
//! that can change between the run and its replay. The naive fixes are both
//! wrong. Journaling every permit doubles the journal to record "yes" over and
//! over. Re-evaluating on replay means a policy edit silently rewrites history —
//! last year's run is re-judged under this year's rules, and the audit trail
//! quietly becomes a lie.
//!
//! The answer is the one the effect protocol already gives, applied unchanged:
//!
//! > **Policy is evaluated only when an effect is actually dispatched.**
//!
//! A replayed effect never reaches the gate, because it never reaches the world
//! — its result comes back from the journal. So a permit needs no record: the
//! effect's own `EffectDone` *is* the record that it was allowed. What does need
//! a record is a **denial**, because a denial is a place the run stopped, and a
//! stop with no record replays as "this build performs more effects than the
//! recorded one". That is precisely why `BudgetRefused` exists, and
//! `PolicyDenied` is its twin.
//!
//! What is journaled once, at admission, is the **policy digest** — which rules
//! governed this run. That is an audit question (§17), not a replay one, and it
//! makes "the policy changed" visible without making it fatal.

use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::Digest;

/// What is being asked.
///
/// Borrowed rather than owned: this is built at every effect dispatch, and a
/// gate that allocates four strings per call is a gate people turn off.
#[derive(Debug, Clone, Copy)]
pub struct PolicyRequest<'a> {
    /// Who is acting — the agent, or an operator on whose behalf it runs.
    pub principal: &'a str,
    /// What they are doing, e.g. `"effect:perform"`, `"run:admit"`.
    pub action: &'a str,
    /// What they are doing it to, e.g. an effect kind or a capability.
    pub resource: &'a str,
    /// Everything else the rules may read: labels, amounts, the case kind.
    ///
    /// Opaque to the engine's caller. Whether a rule keys on `amount_eur > 5000`
    /// is the deployment's business, not this crate's.
    pub context: &'a Value,
}

/// The answer.
///
/// Not a `Result`, on purpose: there is no error case. See the module docs on
/// why a policy layer that can fail open is not a policy layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Permit,
    /// Refused, with a reason an operator can act on.
    ///
    /// The reason is required. "Denied by policy" sends someone to read a policy
    /// set looking for which of forty rules fired, which is how an authorization
    /// layer becomes something people route around.
    Deny {
        reason: String,
    },
}

impl PolicyDecision {
    /// Deny with a reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self, Self::Permit)
    }
}

/// Decides whether an action is allowed.
///
/// Implementations must be **total** — every request gets an answer — and
/// **pure**: no I/O, no clock, no randomness. Two calls with the same request
/// against the same policy set must return the same decision, or a run stops
/// being replayable for reasons nobody can see.
pub trait PolicyEngine: Send + Sync + Debug {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision;

    /// Identifies the policy set in force.
    ///
    /// Journaled at admission, so "which rules governed this run" is answerable
    /// years later against a rule set that has since changed a hundred times.
    /// Without it a run's authorization history is only as good as whatever the
    /// policy repository happens to still contain.
    fn digest(&self) -> Digest;
}

/// Refuses everything, naming itself.
///
/// Exists for tests and as the thing to reach for when wiring a policy layer
/// before its rules are written: starting closed and opening deliberately is the
/// order that fails safe. There is deliberately **no** `AllowAll` counterpart —
/// a permissive engine and no engine at all are the same behaviour, and having
/// two ways to spell it is how a plane ends up with a policy layer that
/// everybody believes is switched on.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl PolicyEngine for DenyAll {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::deny(format!(
            "no policy set is configured; '{}' on '{}' is refused by default",
            request.action, request.resource
        ))
    }

    fn digest(&self) -> Digest {
        Digest::of(b"agentplane.policy.deny-all")
    }
}

/// The action string for performing an effect.
pub const ACTION_PERFORM: &str = "effect:perform";
/// The action string for starting a run.
pub const ACTION_ADMIT: &str = "run:admit";
