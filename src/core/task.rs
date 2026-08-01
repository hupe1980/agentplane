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

use crate::core::{CaseId, Digest, EffectKey, RunId, Timestamp};

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

    #[must_use]
    pub fn is_overdue(&self, now: Timestamp) -> bool {
        self.state.is_pending() && self.due_at.is_some_and(|d| now >= d)
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
