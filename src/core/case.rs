//! Cases — durable state that outlives a run.
//!
//! A run is one goal, one plan, one lifetime. Real business processes are not
//! that. A supplier switch spans days: a request goes out, an acknowledgement
//! must arrive inside a regulatory window, a confirmation or rejection follows,
//! a cancellation may arrive later, and an invoice dispute may land weeks after
//! that. Each is a *separate inbound trigger at an unpredictable time*, and all
//! of them belong to **one business fact**.
//!
//! # Why a case rather than one very long-lived run
//!
//! Durable-execution engines usually model this as a workflow that lives for
//! weeks. That is a versioning trap: a six-week workflow pins your code version
//! for six weeks, and every deploy needs a migration story for in-flight
//! instances.
//!
//! agentplane inverts it — **runs stay short, longevity lives in the case.**
//! Runs are minutes; cases are months; deploys are free. The cost is that
//! continuity must be explicit (case state, not local variables), which is the
//! right trade when the alternative is an auditor asking about a process whose
//! code no longer exists.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{CaseId, Digest, RunId, Timestamp};

/// A business key that identifies a case from the outside.
///
/// Inbound messages do not know run ids. They carry document numbers, meter
/// ids, order references — so that is what correlation matches on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CorrelationKey {
    /// What kind of identifier this is, e.g. `"document-number"`, `"meter"`.
    pub namespace: String,
    pub value: String,
}

impl CorrelationKey {
    pub fn new(namespace: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            value: value.into(),
        }
    }
}

impl std::fmt::Display for CorrelationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.namespace, self.value)
    }
}

/// Where a case is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    /// Waiting for an inbound message that has not arrived.
    AwaitingExternal,
    /// Waiting for a person.
    AwaitingHuman,
    /// An obligation was missed and someone has been told.
    Escalated,
    Closed,
}

impl CaseStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AwaitingExternal => "awaiting_external",
            Self::AwaitingHuman => "awaiting_human",
            Self::Escalated => "escalated",
            Self::Closed => "closed",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), for a status arriving as text.
    ///
    /// **The reason every enum in this crate that reaches a stored column has
    /// this pair, and the reason nothing else may spell the vocabulary.**
    /// Written over [`ALL`](Self::ALL) rather than as a second `match`, so the
    /// two directions cannot disagree. `as_str` is exhaustive because the
    /// compiler insists; a hand-written reader is *total*, so it keeps
    /// compiling when a variant is added and starts refusing — or worse,
    /// silently defaulting — a value the writer beside it emits. Every store
    /// backend reads through here for that reason: two backends deciding a
    /// vocabulary apart is two answers to one question about the same data.
    ///
    /// Unknown text is `None` rather than a default. A status filter that
    /// silently became `Open` on a typo would answer *what is escalated* with a
    /// list of healthy cases, which reads as an empty backlog.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every status, so a caller can enumerate them without matching.
    pub const ALL: [Self; 5] = [
        Self::Open,
        Self::AwaitingExternal,
        Self::AwaitingHuman,
        Self::Escalated,
        Self::Closed,
    ];

    #[must_use]
    pub fn is_closed(self) -> bool {
        self == Self::Closed
    }
}

/// A long-lived, correlated business fact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub id: CaseId,
    /// Opaque to the engine — `"gpke.supplier-switch"` means nothing here.
    pub kind: String,
    pub status: CaseStatus,
    pub correlation: Vec<CorrelationKey>,
    /// Schema-validated per kind by the adapter; opaque to the engine.
    pub state: Value,
    /// Which revision of [`state`](Self::state) this is.
    ///
    /// Every write bumps it, and a write must name the version it read. See
    /// [`CaseVersion`].
    pub version: CaseVersion,
    #[serde(with = "time::serde::rfc3339")]
    pub opened_at: Timestamp,
    pub runs: Vec<RunId>,
}

/// Which revision of a case's state a reader saw.
///
/// # Why case state needs this and a run's journal does not
///
/// A run is owned: the fencing lease means exactly one writer appends to its
/// journal, so "read, decide, append" cannot interleave with anybody. A **case**
/// is the opposite by construction — it is the thing several runs share, over
/// days, and the topology this crate exists to serve has several plane instances
/// writing to one store.
///
/// The window between reading case state and writing it back therefore contains
/// an *inference*, which is unbounded. Classical lost-update reasoning assumes a
/// read-to-write window measured in milliseconds; here it is measured in however
/// long a model takes to answer, and two runs on one case will overlap. A blind
/// `UPDATE ... SET state = ?` in that window silently discards whichever write
/// lost the race, and nothing in the record shows it happened.
///
/// So a write names the version it read, the store rejects it if the case has
/// moved on ([`StoreError::CaseConflict`](crate::core::StoreError::CaseConflict)),
/// and the caller re-reads. The check is a database predicate rather than
/// application logic for the same reason exactly-once is: application logic can
/// be bypassed by the next caller, a constraint cannot.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, Hash,
)]
pub struct CaseVersion(pub u64);

impl CaseVersion {
    /// The version a case has before anybody has written to it.
    pub const INITIAL: Self = Self(0);

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl std::fmt::Display for CaseVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// A domain-specific deadline description.
///
/// Deliberately opaque: "5 working days at 17:00 Europe/Berlin, excluding
/// public holidays observed in any federal state" is domain knowledge and does
/// not belong in a domain-agnostic engine. The engine carries the spec to a
/// [`Calendar`](crate::core::Calendar) and enforces whatever instant comes back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineSpec {
    /// Which resolution rule to apply, e.g. `"hours"`, `"working-days"`.
    pub kind: String,
    /// Parameters for that rule.
    pub params: Value,
}

impl DeadlineSpec {
    pub fn new(kind: impl Into<String>, params: Value) -> Self {
        Self {
            kind: kind.into(),
            params,
        }
    }

    /// A plain wall-clock offset, understood by the built-in calendar.
    ///
    /// One constructor per rule `WallClock` accepts, and the set is closed for
    /// a reason: a rule with no canonical spelling is where `"minutes"`,
    /// `"minute"` and `"mins"` diverge between an application and the calendar
    /// adapter meant to resolve them — and a calendar that does not recognise a
    /// kind refuses it, so the drift surfaces as a failed obligation rather
    /// than a wrong one. `minutes` was the rule that had this hole:
    /// `WallClock` resolved it and nothing here spelled it.
    #[must_use]
    pub fn minutes(n: u32) -> Self {
        Self::new("minutes", serde_json::json!({ "n": n }))
    }

    /// A plain wall-clock offset, understood by the built-in calendar.
    #[must_use]
    pub fn hours(n: u32) -> Self {
        Self::new("hours", serde_json::json!({ "n": n }))
    }

    /// Calendar days, understood by the built-in calendar.
    #[must_use]
    pub fn days(n: u32) -> Self {
        Self::new("days", serde_json::json!({ "n": n }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineState {
    Pending,
    /// The warning threshold passed and an alert was emitted.
    Warned,
    /// The instant passed with the obligation unmet.
    Breached,
    /// Satisfied before the instant.
    Met,
    Cancelled,
}

impl DeadlineState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Warned => "warned",
            Self::Breached => "breached",
            Self::Met => "met",
            Self::Cancelled => "cancelled",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }

    /// Every state an obligation can be in.
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Warned,
        Self::Breached,
        Self::Met,
        Self::Cancelled,
    ];

    /// Whether this deadline still constitutes an open obligation.
    #[must_use]
    pub fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Warned)
    }

    /// Whether an obligation in this state may be moved to `to`.
    ///
    /// The three ways an obligation ends — met, missed, withdrawn — are
    /// terminal, and [`Breached`](Self::Breached) is the one that has to be.
    /// It is the only record that a window closed unmet, and
    /// [`set_deadline_state`] is reachable from a skill: `cx.meet_deadline` on
    /// an obligation the sweep had already breached would take the miss off the
    /// operator's listing and out of the row at once, leaving no account of it
    /// anywhere. Answering late is a fact to record beside the breach — an
    /// [`acknowledge_breach`] note says so — not a way to unsay it.
    ///
    /// Re-applying the state already held is allowed. Every writer here is a
    /// sweep or a resumed run, and both repeat their own last write by design:
    /// refusing that would turn an idempotent retry into a failure.
    ///
    /// Fails **closed** on a state this relation does not name, so a new
    /// variant is unmovable until somebody says where it may go rather than
    /// silently movable anywhere.
    ///
    /// [`set_deadline_state`]: crate::case::CaseStore::set_deadline_state
    /// [`acknowledge_breach`]: crate::case::CaseStore::acknowledge_breach
    #[must_use]
    pub const fn may_become(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Pending, Self::Pending | Self::Warned)
                | (Self::Warned, Self::Warned)
                | (Self::Met, Self::Met)
                | (Self::Breached, Self::Breached)
                | (Self::Cancelled, Self::Cancelled)
                | (
                    Self::Pending | Self::Warned,
                    Self::Met | Self::Breached | Self::Cancelled
                )
        )
    }
}

/// Somebody's account of a breach.
///
/// A missed obligation is a fact and does not stop being one. What can end is
/// the *question* it puts to an operator — has anybody looked at this. The
/// obligation keeps [`Breached`](DeadlineState::Breached); the listing that asks
/// the question stops returning it. Why that listing has to drain is on
/// [`CaseStore::breached`].
///
/// [`CaseStore::breached`]: crate::case::CaseStore::breached
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachNote {
    /// The authenticated actor who accounted for it. Never taken from a request
    /// body: an account of a missed obligation that names whoever the caller
    /// said they were is not an account.
    pub by: String,
    /// What they had to say. May be empty — an operator who has looked and has
    /// nothing to add has still answered the question the listing asked.
    pub note: String,
    #[serde(with = "time::serde::rfc3339")]
    pub at: Timestamp,
}

/// A registered obligation with a resolved instant.
///
/// # The instant is a fact, not a formula
///
/// `resolved_at` is stored, and never recomputed. Calendars change — a
/// corrected holiday table, a new regulatory notice — and recomputing on replay
/// would silently move a legally binding instant under an audit. The
/// `calendar_digest` records which calendar version produced it, so a shifted
/// rule is *visible* rather than retroactive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Deadline {
    pub case: CaseId,
    /// Unique within the case.
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub resolved_at: Timestamp,
    /// Which calendar version produced `resolved_at`.
    pub calendar_digest: Digest,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub warn_at: Option<Timestamp>,
    pub state: DeadlineState,
    /// Who accounted for the breach, once somebody has.
    ///
    /// Only ever set on a [`Breached`](DeadlineState::Breached) obligation, and
    /// it is what takes the breach off the obligation listing — see
    /// [`CaseStore::acknowledge_breach`]. `None` on every other state, because
    /// there is nothing to account for.
    ///
    /// [`CaseStore::acknowledge_breach`]: crate::case::CaseStore::acknowledge_breach
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged: Option<BreachNote>,
}

impl Deadline {
    #[must_use]
    pub fn is_due(&self, now: Timestamp) -> bool {
        self.state.is_open() && now >= self.resolved_at
    }

    /// A breach nobody has accounted for yet.
    ///
    /// The predicate behind the obligation listing, written once so the two
    /// backends compare the same two things rather than each deciding what
    /// "still on the list" means.
    #[must_use]
    pub const fn is_unaccounted(&self) -> bool {
        matches!(self.state, DeadlineState::Breached) && self.acknowledged.is_none()
    }

    #[must_use]
    pub fn needs_warning(&self, now: Timestamp) -> bool {
        self.state == DeadlineState::Pending
            && self.warn_at.is_some_and(|w| now >= w)
            && now < self.resolved_at
    }
}

/// What the sweeper did to something nobody was watching.
///
/// # Why these are on the record and not only in a log
///
/// The sweeper makes the plane's most consequential *automated* decisions: it
/// breaches an obligation, escalates a case, expires a person's task. Nothing
/// asked it to — that is the point of it — so there is no run whose history
/// explains why the state changed.
///
/// Without a record, *why is this case escalated* is answerable only from the
/// resulting state, and state cannot distinguish "the sweep breached this at
/// 02:00" from "somebody set it". That is the same distinction
/// [`RecordKind::StepCompensated`](crate::journal::RecordKind::StepCompensated)
/// exists for, and it matters more here because no human was present.
///
/// A typed enum rather than a message: an operator alerting on breaches should
/// not be matching on prose, and a variant added here is one every reader must
/// consider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweptAction {
    /// An obligation is approaching and its warning instant passed.
    DeadlineWarned,
    /// An obligation passed unmet.
    DeadlineBreached,
    /// A case was escalated because one of its obligations was breached.
    CaseEscalated,
    /// A person's task window closed and the declared policy was applied.
    TaskExpired,
    /// A task's audience was widened because nobody answered in time.
    TaskEscalated,
    /// A run an instance died holding was taken over and resumed.
    ///
    /// The one action in this vocabulary that is the system healing rather
    /// than a finding — recorded anyway, because a takeover bumps the run's
    /// epoch and fences its previous owner, and *who fenced whom, and why*
    /// must be answerable from the journal rather than inferred from an epoch
    /// gap. The detail names the outcome the resume reached.
    RunRecovered,
}
