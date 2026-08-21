//! Human tasks — the oversight surface.
//!
//! Suspension gives a run a durable way to wait. A worklist gives that wait an
//! operational surface: a queue somebody can see, claim, and decide.
//!
//! # Why a task carries its own justification
//!
//! The failure mode for human oversight is not refusal, it is *approval
//! fatigue*: a queue of proposals nobody can evaluate becomes a queue of
//! rubber stamps, and the oversight is then worse than none because it launders
//! the decision. So a task carries what a reviewer needs to disagree — the
//! proposed action, the confidence behind it, what it will cost, the evidence,
//! and the deadline pressure they are under.
//!
//! An approval you cannot evaluate is not a control.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{CaseId, Digest, EffectKey, RunId, StoreError, Timestamp};

/// Why a claim was refused.
///
/// Beside [`Task`] because it is the claim protocol's own vocabulary —
/// [`Task::may_decide`] states the predicate, this names the refusals — and
/// because [`RuntimeError`](crate::core::RuntimeError) carries it: "does not
/// exist", "not yours to decide" and "held by somebody else" call for three
/// different responses, and a class that flattens them teaches a caller to
/// retry the permanent and abandon the transient.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimError {
    #[error("task {0} does not exist")]
    NotFound(TaskId),

    #[error("task {task} is already {state:?}")]
    NotPending { task: TaskId, state: TaskState },

    #[error("task {task} is held by '{holder}'")]
    AlreadyClaimed { task: TaskId, holder: String },

    /// The four-eyes control: whoever proposed an action does not approve it.
    #[error("'{actor}' proposed this action and may not also decide it")]
    Excluded { actor: String },

    #[error("'{actor}' holds none of the roles this task requires")]
    WrongRole { actor: String },

    /// A release from somebody who is not the holder.
    ///
    /// Distinct from [`NotFound`](ClaimError::NotFound) because the two call for
    /// opposite responses: a task that does not exist means the id is wrong, and
    /// a task held by someone else means the release did nothing — which is the
    /// answer a caller must not receive as success.
    #[error("task {task} is not held by '{actor}'")]
    NotHeld { task: TaskId, actor: String },

    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Identifies a task.
///
/// Derived rather than minted, so it is stable across replay: a resumed run
/// addresses the same task instead of opening a second one for the same
/// decision.
///
/// # Why the run is in the hash
///
/// An [`EffectKey`] is unique **within a run** — the journal enforces
/// `(run, effect_key)`, and nothing more is needed there. A task id lives in a
/// table shared by every run, and that is a different namespace.
///
/// Deriving a task id from the effect key alone therefore collides, and not in
/// an exotic way: two runs of one plan reach the same step, at the same ordinal,
/// with the same descriptor, and produce the same key. The store's `open` is
/// idempotent by id, so the second run's task is silently *not created* — an
/// operator sees one proposal carrying the first run's amount, decides it, and
/// the second run waits for an answer it will never be shown. Two €900 refunds
/// become one €100 approval, and nothing anywhere reports a problem.
///
/// The rule this encodes: **an effect key is unique within its run; anything
/// that escapes into a shared namespace has to mix the run back in.** The same
/// applies to the `("task", …)` correlation key, which is derived from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(Digest);

impl TaskId {
    /// Derive from the run and the awaiting effect.
    ///
    /// Both inputs render at fixed length, so the concatenation is unambiguous
    /// without framing.
    #[must_use]
    pub fn derive(run: RunId, effect: EffectKey) -> Self {
        let mut bytes = run.to_string().into_bytes();
        bytes.extend_from_slice(effect.to_hex().as_bytes());
        Self(Digest::of(&bytes))
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    pub fn parse(s: &str) -> Result<Self, hex::FromHexError> {
        Digest::from_hex(s).map(Self)
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task_{}", self.0.to_hex())
    }
}

/// The BPMN-shaped lifecycle, minus the states this runtime has no use for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Visible to its candidate roles; nobody has taken it.
    Open,
    /// Reserved by one person, who is expected to decide.
    Claimed,
    /// Decided.
    Completed,
    /// The window passed. What happens next was declared up front, not decided
    /// in the moment.
    Expired,
    /// Passed to a wider or higher audience.
    Escalated,
}

impl TaskState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Claimed => "claimed",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Escalated => "escalated",
        }
    }

    /// Whether the task is still somebody's to act on.
    #[must_use]
    pub fn is_pending(self) -> bool {
        matches!(self, Self::Open | Self::Claimed | Self::Escalated)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

impl Priority {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
            Self::Urgent => "urgent",
        }
    }
}

/// What happens when nobody answers in time.
///
/// **Declared up front, never defaulted.** "The human did not answer, so we did
/// it anyway" must be a decision somebody signed before the fact — deciding it
/// in the moment, under time pressure, is how an unattended queue turns into an
/// unattended action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnExpiry {
    /// Refuse the proposed action. The safe default.
    Deny,
    /// Widen the audience and keep waiting.
    ///
    /// Requires [`TaskSpec::escalate_to`] to name who is added: a promise to
    /// widen an audience with nobody to widen it to is a state flag wearing a
    /// control's name.
    Escalate,
    /// Proceed unattended.
    ///
    /// Requires [`TaskSpec::allow_unattended`], which exists so that choosing
    /// this is an explicit, greppable act rather than an enum variant someone
    /// picked because it was in the list.
    Proceed,
}

/// What a reviewer needs in order to disagree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Justification {
    /// One line: what is being proposed and why.
    pub summary: String,
    /// The action itself, so the reviewer sees what will happen rather than a
    /// description of it.
    pub proposed_action: Value,
    /// How sure the proposer is, where that is meaningful.
    ///
    /// Present because agents are measurably worse at repeating a success than
    /// at achieving one: a proposal that looks confident is not evidence that it
    /// is right.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// What acting will cost, in whatever unit the deployment uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<String>,
    /// Journal notes, tool outputs, prior decisions — the trail behind the
    /// proposal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl Justification {
    pub fn new(summary: impl Into<String>, proposed_action: Value) -> Self {
        Self {
            summary: summary.into(),
            proposed_action,
            confidence: None,
            cost: None,
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = Some(c);
        self
    }

    #[must_use]
    pub fn cost(mut self, c: impl Into<String>) -> Self {
        self.cost = Some(c.into());
        self
    }

    #[must_use]
    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
}

/// A request for a human decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub kind: String,
    pub justification: Justification,
    /// Who may decide. Empty means anyone.
    pub candidate_roles: Vec<String>,
    pub priority: Priority,
    /// The obligation that bounds this wait, by name.
    pub deadline: String,
    pub on_expiry: OnExpiry,
    /// Roles added to the audience when the task escalates.
    ///
    /// Required by [`OnExpiry::Escalate`] and refused beside anything else:
    /// escalation's one enforceable meaning is *these people can now see it*,
    /// so the declaration must say who they are, and naming them under a
    /// policy that never escalates is a declaration nothing reads.
    pub escalate_to: Vec<String>,
    /// Actors who may **not** decide this — the four-eyes control.
    ///
    /// Whoever proposed an action does not get to approve it. Without this,
    /// dual control is a naming convention rather than a check.
    pub excluded_actors: Vec<String>,
    /// Explicit consent to act unattended on expiry.
    pub allow_unattended: bool,
}

impl TaskSpec {
    pub fn new(
        kind: impl Into<String>,
        justification: Justification,
        deadline: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            justification,
            candidate_roles: Vec::new(),
            priority: Priority::Normal,
            deadline: deadline.into(),
            on_expiry: OnExpiry::Deny,
            escalate_to: Vec::new(),
            excluded_actors: Vec::new(),
            allow_unattended: false,
        }
    }

    #[must_use]
    pub fn role(mut self, r: impl Into<String>) -> Self {
        self.candidate_roles.push(r.into());
        self
    }

    #[must_use]
    pub fn priority(mut self, p: Priority) -> Self {
        self.priority = p;
        self
    }

    /// Bar an actor from deciding — typically whoever proposed the action.
    #[must_use]
    pub fn excluding(mut self, actor: impl Into<String>) -> Self {
        self.excluded_actors.push(actor.into());
        self
    }

    #[must_use]
    pub fn on_expiry(mut self, e: OnExpiry) -> Self {
        self.on_expiry = e;
        self
    }

    /// Name a role added to the audience when the task escalates.
    #[must_use]
    pub fn escalate_to(mut self, r: impl Into<String>) -> Self {
        self.escalate_to.push(r.into());
        self
    }

    /// Consent to acting unattended when the window passes.
    ///
    /// Separate from `on_expiry` on purpose: `OnExpiry::Proceed` without this is
    /// refused, so choosing to act without a human is a deliberate, greppable
    /// act rather than a variant someone picked off a list.
    #[must_use]
    pub fn allow_unattended(mut self) -> Self {
        self.allow_unattended = true;
        self
    }
}

/// A pending item of human work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub id: TaskId,
    pub run: RunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<CaseId>,
    pub kind: String,
    pub justification: Justification,
    pub candidate_roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub priority: Priority,
    pub state: TaskState,
    pub on_expiry: OnExpiry,
    /// Roles [`escalate`](Self::escalate) adds to the audience.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalate_to: Vec<String>,
    pub excluded_actors: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: Timestamp,
    /// When the window closes. Taken from the obligation that bounds the wait,
    /// so the reviewer's deadline and the case's are the same fact.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub due_at: Option<Timestamp>,
}

impl Task {
    /// Whether `actor` is permitted to decide this.
    ///
    /// Two checks: the four-eyes exclusion, then role eligibility.
    #[must_use]
    pub fn may_decide(&self, actor: &str, roles: &[String]) -> bool {
        if self.excluded_actors.iter().any(|a| a == actor) {
            return false;
        }
        self.candidate_roles.is_empty() || self.candidate_roles.iter().any(|r| roles.contains(r))
    }

    /// Apply this task's declared escalation to its own fields.
    ///
    /// The one implementation of what escalating *means*, called by every
    /// [`TaskStore::escalate`](crate::case::TaskStore::escalate) backend so the
    /// semantics cannot drift per store. Three fields move together:
    ///
    /// * the state becomes [`TaskState::Escalated`], so listings say what
    ///   happened;
    /// * the reservation is cleared — the claim belonged to the window that
    ///   closed, and an escalation that leaves the task assigned to whoever sat
    ///   on it has widened the audience to people who cannot claim the row;
    /// * the audience is **widened** by [`escalate_to`](Self::escalate_to) —
    ///   a union, because the original reviewers remain eligible; replacing
    ///   them would make an escalation a reassignment wearing a wider name.
    ///
    /// An empty audience stays empty: it already means *anyone*, and adding
    /// roles to it would narrow the widest audience there is. The parser and
    /// [`StepCtx`](crate::runtime::StepCtx) refuse that combination at
    /// declaration, but the semantics must not depend on a parser upstream —
    /// a store contract enforced only by its callers is a request.
    ///
    /// What deliberately does not move: `excluded_actors`. Four-eyes does not
    /// thin because nobody answered — the proposer is barred from the wider
    /// audience exactly as from the narrow one.
    pub fn escalate(&mut self) {
        self.state = TaskState::Escalated;
        self.assignee = None;
        if !self.candidate_roles.is_empty() {
            for role in &self.escalate_to {
                if !self.candidate_roles.contains(role) {
                    self.candidate_roles.push(role.clone());
                }
            }
        }
    }
}

/// A human's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub approved: bool,
    /// Who decided. Recorded permanently: an approval with no name attached is
    /// not an approval.
    pub actor: String,
    pub reason: String,
    /// Anything the decision adds — an amended amount, a chosen option.
    #[serde(default)]
    pub amendment: Value,
}

impl Decision {
    pub fn approve(actor: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            approved: true,
            actor: actor.into(),
            reason: reason.into(),
            amendment: Value::Null,
        }
    }

    pub fn reject(actor: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            approved: false,
            actor: actor.into(),
            reason: reason.into(),
            amendment: Value::Null,
        }
    }

    #[must_use]
    pub fn amend(mut self, v: Value) -> Self {
        self.amendment = v;
        self
    }

    /// The decision the runtime records when a window closes unanswered.
    #[must_use]
    pub fn expired(on_expiry: OnExpiry) -> Self {
        match on_expiry {
            OnExpiry::Proceed => Self {
                approved: true,
                actor: "system:unattended".into(),
                reason: "no answer within the window; proceeding was pre-authorised".into(),
                amendment: Value::Null,
            },
            OnExpiry::Deny | OnExpiry::Escalate => Self {
                approved: false,
                actor: "system:expiry".into(),
                reason: "no answer within the window".into(),
                amendment: Value::Null,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `amend` attaches the amendment and disturbs nothing else.
    ///
    /// An approval's other three fields are what make it an approval — who, and
    /// whether — so a builder that quietly reset one while adding an amount
    /// would turn "approved by Rita, capped at 5000" into an unattributed yes.
    /// The builder had no caller and no test, so nothing could tell.
    #[test]
    fn an_amendment_rides_along_without_disturbing_the_verdict() {
        let plain = Decision::approve("rita", "within her limit");
        let amended = Decision::approve("rita", "within her limit").amend(json!({"cap": 5000}));

        assert_eq!(amended.amendment, json!({"cap": 5000}));
        assert_eq!(plain.amendment, Value::Null, "the default carries none");
        assert_eq!(amended.approved, plain.approved);
        assert_eq!(amended.actor, plain.actor);
        assert_eq!(amended.reason, plain.reason);

        // A rejection may be amended too — "no, and here is what would pass".
        let rejected = Decision::reject("rita", "over her limit").amend(json!({"cap": 5000}));
        assert!(!rejected.approved, "amending must not approve");
    }
}
