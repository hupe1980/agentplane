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

use crate::core::{CaseId, Digest, EffectKey, Operator, RunId, StoreError, Timestamp};

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

    /// The run already consumed a different answer to this task.
    ///
    /// A decision races the expiry sweep, and the run takes whichever answer
    /// reached it first. The loser is refused rather than recorded: the
    /// worklist saying *completed by alice* while the journal holds the
    /// expiry policy's answer is a contradiction nobody can resolve later.
    #[error("task {task} was already answered; the run consumed another decision")]
    AlreadyAnswered { task: TaskId },

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

    /// Read a task id in either written form: the bare hex, or the `task_<hex>`
    /// that [`Display`](std::fmt::Display) prints — so an id copied from any
    /// listing parses, as a [`RunId`] does.
    ///
    /// # Errors
    ///
    /// If what follows the optional prefix is not a 64-character hex digest.
    pub fn parse(s: &str) -> Result<Self, hex::FromHexError> {
        Digest::from_hex(s.strip_prefix("task_").unwrap_or(s)).map(Self)
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
    /// Its run concluded closed before anybody answered, so there is nothing
    /// left to decide.
    Withdrawn,
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
            Self::Withdrawn => "withdrawn",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    ///
    /// [`CaseStatus::parse`]: crate::core::CaseStatus::parse
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every state a task can be in.
    pub const ALL: [Self; 6] = [
        Self::Open,
        Self::Claimed,
        Self::Completed,
        Self::Expired,
        Self::Escalated,
        Self::Withdrawn,
    ];

    /// Whether the task is still somebody's to act on.
    ///
    /// Wider than [`is_queued`](Self::is_queued): a claimed task has left the
    /// queue and is still a decision the plane is waiting on, so a backlog that
    /// shrank the moment a reviewer opened something would report progress that
    /// had not happened.
    #[must_use]
    pub const fn is_pending(self) -> bool {
        match self {
            Self::Open | Self::Claimed | Self::Escalated => true,
            Self::Completed | Self::Expired | Self::Withdrawn => false,
        }
    }

    /// Whether the task is offered to a candidate who has not claimed it.
    ///
    /// An escalated task is queued again: escalation releases the claim and
    /// widens the audience, which is only a remedy if somebody can then see it.
    #[must_use]
    pub const fn is_queued(self) -> bool {
        match self {
            Self::Open | Self::Escalated => true,
            Self::Claimed | Self::Completed | Self::Expired | Self::Withdrawn => false,
        }
    }

    /// Whether the expiry sweep still owes this task anything.
    ///
    /// Narrower than [`is_pending`](Self::is_pending): an escalated task is
    /// still claimable, but its expiry policy has already fired — see
    /// [`TaskStore::overdue`] for what keeping it in that scan starves.
    ///
    /// [`TaskStore::overdue`]: crate::case::TaskStore::overdue
    #[must_use]
    pub const fn awaits_expiry(self) -> bool {
        match self {
            Self::Open | Self::Claimed => true,
            Self::Completed | Self::Expired | Self::Escalated | Self::Withdrawn => false,
        }
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

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    ///
    /// [`CaseStatus::parse`]: crate::core::CaseStatus::parse
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every priority, most urgent last — the order [`rank`](Self::rank)
    /// inverts.
    pub const ALL: [Self; 4] = [Self::Low, Self::Normal, Self::High, Self::Urgent];

    /// Queue order, most urgent first, as the sort key a worklist index holds.
    ///
    /// Exhaustive rather than a table with a fallback. A rank is a *position*,
    /// and the position a fallback hands an unnamed priority is the end of the
    /// queue — so the failure of forgetting to rank a new one is that the most
    /// urgent work sorts last, silently, in the one index whose whole job is
    /// order.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Urgent => 0,
            Self::High => 1,
            Self::Normal => 2,
            Self::Low => 3,
        }
    }
}

/// What happens when nobody answers in time, as a stored task records it.
///
/// **Declared up front, never defaulted.** "The human did not answer, so we did
/// it anyway" must be a decision somebody signed before the fact — deciding it
/// in the moment, under time pressure, is how an unattended queue turns into an
/// unattended action.
///
/// This is the vocabulary a [`Task`] row carries beside its
/// [`escalate_to`](Task::escalate_to). A skill declares the policy with
/// [`Expiry`], which carries what each answer needs inside the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnExpiry {
    /// Refuse the proposed action. The safe default.
    Deny,
    /// Widen the audience and keep waiting.
    Escalate,
    /// Proceed unattended.
    Proceed,
}

/// What a skill declares should happen when nobody answers its task in time.
///
/// Each answer carries what it needs, so the ones that mean nothing cannot be
/// written: an escalation names who is added — a promise to widen an audience
/// with nobody to widen it to is a state flag wearing a control's name — and
/// acting without a human is spelled [`ProceedUnattended`](Self::ProceedUnattended),
/// so it is an explicit, greppable act rather than a variant somebody picked
/// off a list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Expiry {
    /// Refuse the proposed action. The safe default.
    #[default]
    Deny,
    /// Widen the audience by these roles and keep waiting.
    ///
    /// The task is then answered by a person or never. Needs at least one role
    /// and a bounded initial audience, both refused at the task otherwise.
    Escalate {
        /// Roles added to the audience when the window closes.
        to: Vec<String>,
    },
    /// Act without a human when the window closes.
    ProceedUnattended,
}

impl Expiry {
    /// Escalate to these roles.
    #[must_use]
    pub fn escalate_to<R: Into<String>>(roles: impl IntoIterator<Item = R>) -> Self {
        Self::Escalate {
            to: roles.into_iter().map(Into::into).collect(),
        }
    }

    /// The stored policy this declaration becomes.
    #[must_use]
    pub const fn policy(&self) -> OnExpiry {
        match self {
            Self::Deny => OnExpiry::Deny,
            Self::Escalate { .. } => OnExpiry::Escalate,
            Self::ProceedUnattended => OnExpiry::Proceed,
        }
    }

    /// The roles an escalation adds; empty for every other answer.
    #[must_use]
    pub fn escalate_roles(&self) -> &[String] {
        match self {
            Self::Escalate { to } => to,
            Self::Deny | Self::ProceedUnattended => &[],
        }
    }
}

impl OnExpiry {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Escalate => "escalate",
            Self::Proceed => "proceed",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    ///
    /// [`CaseStatus::parse`]: crate::core::CaseStatus::parse
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every declared answer to an unanswered window.
    pub const ALL: [Self; 3] = [Self::Deny, Self::Escalate, Self::Proceed];
}

/// What a reviewer needs in order to disagree.
///
/// # Every sentence carries who wrote it
///
/// A reviewer is a control, and the thing that defeats a control made of
/// human judgement is not refusal — it is being told something persuasive by
/// the party under review. So each free-text field here is a
/// [`Tainted<String>`](crate::core::Tainted): the run's own words arrive as
/// [`Tainted::trusted`](crate::core::Tainted::trusted), and anything a model,
/// a tool or a counterparty produced keeps the label it was handed out with.
///
/// **A `String` would launder it, and did.** A dry-run preview is a tool's
/// answer to *what would this call do*; it is exactly the sentence a reviewer
/// leans on, and reading it out of a `Tainted` with `peek` dropped the one
/// fact that says whether to lean on it. The type is what keeps that from
/// being a matter of remembering.
///
/// This does not refuse untrusted content, deliberately. A worklist that only
/// carried trusted sentences would carry nothing worth reviewing; what a
/// reviewer is owed is not a sanitised task but an honest one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Justification {
    /// One line: what is being proposed and why.
    pub summary: crate::core::Tainted<String>,
    /// The action itself, so the reviewer sees what will happen rather than a
    /// description of it.
    ///
    /// Unlabelled on purpose: this is the artifact under review, and that the
    /// agent proposed it is the premise of the task rather than news.
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
    pub cost: Option<crate::core::Tainted<String>>,
    /// Journal notes, tool outputs, prior decisions — the trail behind the
    /// proposal.
    ///
    /// The field where the two authors mix: a runtime's own note about why no
    /// preview could be computed sits beside the preview itself, which is a
    /// tool's output over the caller's data. One `Vec`, two provenances, and
    /// the label is what tells them apart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::core::Tainted<String>>,
}

impl Justification {
    /// The digest of exactly what a reviewer is shown.
    ///
    /// An approval names this, so a task edited in the store between the run
    /// proposing it and a person deciding it is an approval of something the
    /// run never proposed — and is refused where the run reads the answer.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let value = serde_json::to_value(self)
            .expect("a justification holds only infallibly serializable fields");
        let mut framed = b"agentplane.task.justification.v1\0".to_vec();
        framed.extend_from_slice(&crate::core::canon::value_bytes(&value));
        Digest::of(&framed)
    }

    /// A proposal, with the sentence that heads it and where it came from.
    ///
    /// `Tainted::trusted(..)` for the run's own words — a manifest summary, a
    /// constant, an operator's catalogue reference. Anything derived from a
    /// completion or a tool answer keeps the label it arrived with.
    pub fn new(summary: crate::core::Tainted<String>, proposed_action: Value) -> Self {
        Self {
            summary,
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
    pub fn cost(mut self, c: crate::core::Tainted<String>) -> Self {
        self.cost = Some(c);
        self
    }

    #[must_use]
    pub fn evidence(mut self, e: crate::core::Tainted<String>) -> Self {
        self.evidence.push(e);
        self
    }

    /// Whether any sentence here was written by something the run does not
    /// trust.
    ///
    /// The question a reviewer's surface asks once, rather than walking three
    /// fields and remembering which ones are text. `proposed_action` is not
    /// consulted: it is the artifact under review, not a claim about it.
    #[must_use]
    pub fn has_untrusted_prose(&self) -> bool {
        let untrusted =
            |t: &crate::core::Tainted<String>| t.label().trust != crate::core::Trust::Trusted;
        untrusted(&self.summary)
            || self.cost.as_ref().is_some_and(untrusted)
            || self.evidence.iter().any(untrusted)
    }
}

/// A request for a human decision.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskSpec {
    pub kind: String,
    pub justification: Justification,
    /// Who may decide. Empty means anyone.
    pub candidate_roles: Vec<String>,
    pub priority: Priority,
    /// The obligation that bounds this wait, by name.
    pub deadline: String,
    /// What happens when nobody answers in time.
    pub on_expiry: Expiry,
    /// Actors who may **not** decide this — the four-eyes control.
    ///
    /// Whoever proposed an action does not get to approve it. Without this,
    /// dual control is a naming convention rather than a check.
    pub excluded_actors: Vec<String>,
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
            on_expiry: Expiry::Deny,
            excluded_actors: Vec::new(),
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

    /// What happens when nobody answers in time. [`Expiry::Deny`] unless said.
    #[must_use]
    pub fn on_expiry(mut self, e: Expiry) -> Self {
        self.on_expiry = e;
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
    /// Why this task's proposal cannot be shown, when it cannot.
    ///
    /// Set by whoever sealed or opened the row — never inferred from what the
    /// proposal looks like. A proposal whose clear arguments happen to be
    /// spelled `{"$sealed": "…"}` is a proposal like any other, and reading
    /// the shape instead let untrusted input make a task unapprovable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld: Option<Withheld>,
}

/// Why a task's proposal cannot be shown.
///
/// The reason is carried out of band, by the store decorator that sealed the
/// row and the one that tried to open it, so an argument value can never
/// spell it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Withheld {
    /// Sealed at rest, and whoever read the row holds no key ring to open it.
    /// This is what the stored row says; a plane holding the ring replaces it.
    Sealed,
    /// The key it was sealed under was destroyed: the matter was erased.
    Erased,
    /// The key opened the envelope and what came out does not decode as the
    /// value it replaced — damage, not an erasure.
    Undecodable,
}

impl Withheld {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Erased => "erased",
            Self::Undecodable => "undecodable",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    ///
    /// [`CaseStatus::parse`]: crate::core::CaseStatus::parse
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    pub const ALL: [Self; 3] = [Self::Sealed, Self::Erased, Self::Undecodable];
}

impl std::fmt::Display for Withheld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sealed => "it is sealed, and this plane holds no key ring to open it",
            Self::Erased => "it was erased: the key it was sealed under is destroyed",
            Self::Undecodable => "its sealed bytes opened and do not decode",
        })
    }
}

/// What every surface shows a person for one task: the one rendering.
///
/// A pure function of the stored task, so what a reviewer reads and what
/// [`Justification::digest`] binds are read from the same value. Every string
/// has its hidden code points escaped in place (see [`escaped`](Self::escaped));
/// every word mixing scripts is listed in [`mixed_script`](Self::mixed_script)
/// and left as written. Nothing is cut: a value is shown whole.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Rendering {
    /// Why the proposal cannot be shown, when it cannot — and then
    /// `proposed_action` is null and `evidence` empty rather than an envelope
    /// a client might display as a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withheld: Option<Withheld>,
    pub summary: String,
    pub proposed_action: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// Whether any text above had a code point escaped because it renders as
    /// nothing or reorders what surrounds it.
    pub escaped: bool,
    /// Words that mix alphabets, where they occur.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mixed_script: Vec<MixedScript>,
}

/// One word mixing alphabets, flagged beside the text it appears in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct MixedScript {
    /// Where: `summary`, `cost`, `evidence/<n>`, or `proposed_action` and the
    /// path to the string inside it.
    pub at: String,
    /// The word, escaped like the text around it.
    pub word: String,
    pub scripts: Vec<&'static str>,
}

/// The rendering being assembled: escaping and flagging as one walk.
struct Renderer {
    escaped: bool,
    mixed_script: Vec<MixedScript>,
}

impl Renderer {
    fn text(&mut self, at: &str, text: &str) -> String {
        for word in text.split_whitespace() {
            if let Some(scripts) = crate::core::visible::mixed_scripts(word) {
                self.mixed_script.push(MixedScript {
                    at: at.to_owned(),
                    word: crate::core::visible::escape(word).0,
                    scripts,
                });
            }
        }
        let (shown, escaped) = crate::core::visible::escape(text);
        self.escaped |= escaped;
        shown
    }

    fn value(&mut self, at: &str, value: &Value) -> Value {
        match value {
            Value::String(s) => Value::String(self.text(at, s)),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| self.value(&format!("{at}/{i}"), v))
                    .collect(),
            ),
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(k, v)| {
                        let key = self.text(&format!("{at} (a key)"), k);
                        let inner = self.value(&format!("{at}/{k}"), v);
                        (key, inner)
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

impl Task {
    /// The one rendering every surface shows for this task.
    #[must_use]
    pub fn rendering(&self) -> Rendering {
        let j = &self.justification;
        let mut r = Renderer {
            escaped: false,
            mixed_script: Vec::new(),
        };
        let summary = r.text("summary", j.summary.peek());
        let cost = j.cost.as_ref().map(|c| r.text("cost", c.peek()));
        let (proposed_action, evidence) = if self.withheld.is_some() {
            (Value::Null, Vec::new())
        } else {
            (
                r.value("proposed_action", &j.proposed_action),
                j.evidence
                    .iter()
                    .enumerate()
                    .map(|(i, line)| r.text(&format!("evidence/{i}"), line.peek()))
                    .collect(),
            )
        };
        Rendering {
            withheld: self.withheld,
            summary,
            proposed_action,
            cost,
            evidence,
            escaped: r.escaped,
            mixed_script: r.mixed_script,
        }
    }

    /// The stored justification with nothing withheld served as a value.
    ///
    /// A withheld proposal and its evidence are replaced by null and nothing,
    /// so a client that renders the structured form cannot display an
    /// envelope as if it were the arguments. [`withheld`](Self::withheld) says
    /// why beside it.
    #[must_use]
    pub fn shown_justification(&self) -> Justification {
        let mut shown = self.justification.clone();
        if self.withheld.is_some() {
            shown.proposed_action = Value::Null;
            shown.evidence.clear();
        }
        shown
    }

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

/// Who answered, and on what footing.
///
/// Two variants rather than one name with reserved spellings, because they are
/// two different facts. `system:unattended` in an actor field puts *nobody
/// answered* into the shape of *somebody did*: a reader has to know the
/// convention to tell an approval from a timeout, every consumer re-implements
/// the same prefix test, and nothing stops a deployment having a principal by
/// that name. [`I14`](crate::journal) forbids the flattening for the same
/// reason [`ActorView`](crate::api::ActorView) is two fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decided {
    /// A person answered, with what established their name.
    By(Operator),
    /// Nobody answered inside the window, and the declared
    /// [`OnExpiry`] was applied.
    OnExpiry(OnExpiry),
}

impl Decided {
    /// The operator who answered, when a person did.
    ///
    /// `None` for an expiry, and that is the distinction callers need: a
    /// four-eyes check has nobody to exclude when nobody decided, and an
    /// eligibility check run against a fabricated name would pass or fail for
    /// reasons unrelated to the control.
    #[must_use]
    pub const fn operator(&self) -> Option<&Operator> {
        match self {
            Self::By(op) => Some(op),
            Self::OnExpiry(_) => None,
        }
    }
}

impl std::fmt::Display for Decided {
    /// What a message names, where a sentence needs a subject.
    ///
    /// The basis is deliberately absent: it belongs on the record, and a
    /// rendered `alice (asserted)` is a string a reader would have to parse
    /// back — the defect [`ActorView`](crate::api::ActorView) exists to avoid.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::By(op) => f.write_str(op.actor()),
            Self::OnExpiry(policy) => write!(f, "the declared policy ({})", policy.as_str()),
        }
    }
}

/// A human's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub approved: bool,
    /// Who decided. Recorded permanently: an approval with no name attached is
    /// not an approval.
    pub decided: Decided,
    pub reason: String,
    /// Anything the decision adds — and on an approved call task, the call:
    /// the declarative tiers dispatch an approving reviewer's amendment in
    /// place of the model's arguments, schema-checked and labelled as the
    /// reviewer's own trusted value. On a rejection it is recorded advice.
    #[serde(default)]
    pub amendment: Value,
    /// What the decider was shown: [`Justification::digest`] of the task as
    /// the store held it when the decision was recorded.
    ///
    /// Stamped by the runtime, never by the caller. A person's approval binds
    /// to it, and the run refuses one whose digest is not that of the task it
    /// proposed — the arguments reviewed are the arguments dispatched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed: Option<Digest>,
}

impl Decision {
    /// An approval, from a named operator.
    ///
    /// Taking an [`Operator`] rather than a name is the point: an approval is
    /// evidence about a person, and how strongly the name is established is
    /// half of what it is worth. A caller who has only a string has to say
    /// which constructor applies, and that is the claim a reviewer reads.
    pub fn approve(by: Operator, reason: impl Into<String>) -> Self {
        Self {
            approved: true,
            decided: Decided::By(by),
            reason: reason.into(),
            amendment: Value::Null,
            reviewed: None,
        }
    }

    /// A refusal, from a named operator.
    pub fn reject(by: Operator, reason: impl Into<String>) -> Self {
        Self {
            approved: false,
            decided: Decided::By(by),
            reason: reason.into(),
            amendment: Value::Null,
            reviewed: None,
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
        Self {
            approved: on_expiry == OnExpiry::Proceed,
            decided: Decided::OnExpiry(on_expiry),
            reason: match on_expiry {
                OnExpiry::Proceed => {
                    "no answer within the window; proceeding was pre-authorised".to_owned()
                }
                OnExpiry::Deny | OnExpiry::Escalate => "no answer within the window".to_owned(),
            },
            amendment: Value::Null,
            reviewed: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rita() -> Operator {
        Operator::asserted("rita").expect("a fixture names its operator")
    }

    /// `amend` attaches the amendment and disturbs nothing else.
    ///
    /// An approval's other three fields are what make it an approval — who, and
    /// whether — so a builder that quietly reset one while adding an amount
    /// would turn "approved by Rita, capped at 5000" into an unattributed yes.
    /// The builder had no caller and no test, so nothing could tell.
    #[test]
    fn an_amendment_rides_along_without_disturbing_the_verdict() {
        let plain = Decision::approve(rita(), "within her limit");
        let amended = Decision::approve(rita(), "within her limit").amend(json!({"cap": 5000}));

        assert_eq!(amended.amendment, json!({"cap": 5000}));
        assert_eq!(plain.amendment, Value::Null, "the default carries none");
        assert_eq!(amended.approved, plain.approved);
        assert_eq!(amended.decided, plain.decided);
        assert_eq!(amended.reason, plain.reason);

        // A rejection may be amended too — "no, and here is what would pass".
        let rejected = Decision::reject(rita(), "over her limit").amend(json!({"cap": 5000}));
        assert!(!rejected.approved, "amending must not approve");
    }

    /// A task id parses back from the form it prints.
    ///
    /// An operator copies the id out of whatever listed it, and a listing
    /// prints `Display`; a parser that took only the bare hex refused the one
    /// spelling a person was most likely to paste.
    #[test]
    fn a_task_id_parses_from_its_own_display_form() {
        let id = TaskId::derive(
            crate::core::RunId::generate(),
            crate::core::EffectKey::from_hex(&format!("{:064x}", 7)).expect("hex key"),
        );
        assert_eq!(TaskId::parse(&id.to_string()).expect("display form"), id);
        assert_eq!(TaskId::parse(&id.to_hex()).expect("bare hex"), id);
        assert!(TaskId::parse("run_0123").is_err());
    }
}
