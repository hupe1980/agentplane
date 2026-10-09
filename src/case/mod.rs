//! Case storage: correlation, state, obligations, and inbound events.

mod events;
mod tasks;
mod timers;

pub use events::{
    ADDRESSEE_CONCLUDED_REASON, BufferedEvent, ERASED_REASON, EventStore, Minter, Retired,
    TargetedDelivery,
};
pub use tasks::{ClaimError, TaskStore};
pub use timers::TimerStore;

use std::fmt::Debug;

use async_trait::async_trait;
use serde_json::Value;

use crate::core::{
    BreachNote, Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineState,
    Digest, LegalHold, RunId, StoreError, Timestamp,
};

/// What admission did with an inbound trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correlation {
    /// No open case matched; a new one was created.
    Opened(CaseId),
    /// An open case matched and this run joined it.
    Attached(CaseId),
}

impl Correlation {
    #[must_use]
    pub fn case_id(self) -> CaseId {
        match self {
            Self::Opened(id) | Self::Attached(id) => id,
        }
    }

    #[must_use]
    pub fn is_new(self) -> bool {
        matches!(self, Self::Opened(_))
    }
}

/// Long-lived case state, correlated by business key.
///
/// Correlation is a deterministic lookup — never a model call. It runs at
/// admission, before planning, because which case a message belongs to is a
/// question of fact, not of judgement.
#[async_trait]
pub trait CaseStore: Send + Sync + Debug {
    /// Whose rows this handle can reach.
    ///
    /// Defaults to [`TenantId::DEFAULT`](crate::core::TenantId::DEFAULT), the
    /// tenant a store serves until told otherwise. Override it with the tenant
    /// the handle is actually scoped to.
    ///
    /// This exists so a mismatch with the plane's tenant is a **startup
    /// refusal**. When a key ring is wired, `build()` seals case state under
    /// the plane's tenant while the store writes rows under its own; the two
    /// disagreeing is not a leak — the scopes simply differ — but it puts case
    /// state under a scope `erase_case` will never destroy. That is an erasure
    /// that reports success and misses, which is the one failure a deletion
    /// guarantee cannot have.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

    /// Find an **open** case matching any of these keys.
    ///
    /// Closed cases are not matched: a new message about a settled matter opens
    /// a new case rather than reanimating one that was concluded and audited.
    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError>;

    /// Correlate, or open a new case if nothing matched.
    ///
    /// Implementations must make this atomic. Two messages for the same new case
    /// arriving concurrently must produce one case, not two — otherwise a
    /// process fragments across cases and its obligations are tracked in neither.
    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, StoreError>;

    /// Fetch one case.
    ///
    /// Named for what it returns rather than `get`: a single store commonly
    /// implements several of these traits, and same-named methods make every
    /// call site ambiguous.
    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError>;

    /// Every case, one bounded page at a time, in stable id order.
    ///
    /// This is the export's read. `by_status` cannot serve it: a bounded list
    /// with no cursor enumerates a prefix and calls it everything — the silent
    /// truncation this project refuses elsewhere, at the one boundary whose
    /// whole job is completeness. `after` is the last id a caller saw, and
    /// paging resumes strictly beyond it.
    ///
    /// Ordered by id rather than by anything business-shaped, because the
    /// order's only job is that two pages never overlap and never gap.
    ///
    /// Returns state **as stored**. A sealing decorator does not open it here,
    /// unlike [`case`](Self::case): this read exists for the export, and an
    /// export of plaintext would quietly undo erasure — the key destroyed
    /// tomorrow would no longer reach the copy taken today.
    async fn cases(&self, after: Option<CaseId>, limit: usize) -> Result<Vec<Case>, StoreError>;

    /// Write one complete case, exactly as given — an **import authority**, not
    /// a runtime path.
    ///
    /// The ordinary write paths refuse to say some of what a restore must:
    /// `put_state` allocates versions one at a time, `correlate_or_open` mints
    /// a fresh id, and neither can reproduce a case at version 4 000 with the
    /// id every exported record already names. This is the same seam governed
    /// memory keeps for the same reason — direct complete-item writes are a
    /// deployment/import authority at the store boundary, never something a
    /// skill reaches.
    ///
    /// Implementations must leave the imported case reachable by **every**
    /// read path — `case`, `correlate`, `by_status`, `due`, `blobs_of` — which
    /// is what the conformance battery holds them to: the read paths are the
    /// check on this method's index maintenance, because an import that
    /// rebuilds five indexes out of six reads perfectly until somebody queries
    /// the sixth.
    ///
    /// # Errors
    ///
    /// A store that already holds this case id refuses: a restore rebuilds a
    /// case layer, it does not merge one.
    async fn import_case(
        &self,
        case: &Case,
        deadlines: &[Deadline],
        blobs: &[Digest],
    ) -> Result<(), StoreError>;

    /// Record that a run touched this case.
    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError>;

    /// Record that a case produced a blob.
    ///
    /// The case is what an erasure request actually names — nobody asks to
    /// forget a digest — so something has to know which bytes belong to which
    /// matter. That association cannot live in the blob store, which is
    /// content-addressed on purpose and has no idea what a case is, and it
    /// cannot be recomputed later: a digest is deliberately not reversible.
    ///
    /// Recording the same blob twice is the same record. Two runs on one case
    /// storing identical bytes land on one digest by construction, and that is
    /// one artifact, not two.
    ///
    /// # Errors
    ///
    /// If the store rejects the write.
    async fn link_blob(
        &self,
        case: CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), StoreError>;

    /// Every blob this case produced, oldest first.
    ///
    /// # Errors
    ///
    /// If the store cannot be read.
    async fn blobs_of(&self, case: CaseId) -> Result<Vec<Digest>, StoreError>;

    /// Replace a case's state, if it is still at `expected`.
    ///
    /// # Why this takes a version
    ///
    /// A case is shared by every run correlated to it, and the window between
    /// reading its state and writing it back contains a model call — which is
    /// unbounded. Two runs on one case *will* overlap, and a blind write in that
    /// window silently discards whichever one lost. See [`CaseVersion`].
    ///
    /// Implementations must make the check part of the write itself — a single
    /// `UPDATE ... WHERE version = ?` — and not a read followed by a write. A
    /// check performed in application code is a check the next caller can race.
    ///
    /// # Errors
    ///
    /// * [`StoreError::CaseConflict`] if the case has moved past `expected`. The
    ///   caller re-reads and decides again; retrying the same write is the lost
    ///   update this exists to prevent.
    /// * [`StoreError::NotFound`] if there is no such case. Implementations must
    ///   tell these apart — reporting a missing case as a conflict sends the
    ///   caller into a re-read loop against something that will never exist.
    /// * [`StoreError::CaseErased`] if the case carries an erasure marker:
    ///   state written after the erasure began is sealed under a scope that is
    ///   gone or going.
    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StoreError>;

    /// Move a case to a status.
    ///
    /// `Closed` routes through [`close`](Self::close), because closure releases
    /// the correlation keys as well as writing the column, and the two spellings
    /// of *closed* must not drift.
    ///
    /// **Leaving `Closed` re-claims them**, which is the same rule read
    /// backwards. Without it a matter reopened by any route — a run calling
    /// `set_case_status`, or the sweep escalating over an expired task — comes
    /// back as a case no inbound message can ever correlate to again, which
    /// looks exactly like a live matter and is not one. A key another case has
    /// since claimed stays with that case: the identifier belongs to whichever
    /// matter is open for it now, and reopening must not take one back.
    ///
    /// **An erased case is refused**, whatever the status: reopening one would
    /// re-claim its keys and route new work into a matter whose data is gone.
    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError>;

    /// Close a case.
    ///
    /// **Fails while an obligation is open.** A case with an unmet deadline
    /// cannot be closed silently: that is precisely how a missed regulatory
    /// window becomes invisible.
    async fn close(&self, case: CaseId) -> Result<(), StoreError>;

    /// Register an obligation. The resolved instant is stored as given and never
    /// recomputed.
    ///
    /// **A name is registered once.** Registering it again with the same
    /// instant, calendar and warning is the same registration and does
    /// nothing; with anything different it is refused, because the journal
    /// records each registration and a store that kept the first silently
    /// would enforce terms the journal does not show as current.
    ///
    /// # Errors
    ///
    /// [`StoreError::DeadlineExists`] if the name is registered with other
    /// terms. [`StoreError::CaseClosed`] if the matter is closed. [`close`](Self::close)
    /// refuses while an obligation is outstanding, and that check is worth
    /// nothing on its own: it holds at one instant, and this is the write that
    /// walks past it afterwards. Both halves are needed for *a closed case owes
    /// nothing* to be a property of the store rather than of the order two
    /// callers happened to run in.
    ///
    /// Implementations must make the two decide one at a time. The redb backend
    /// gets that from its single write transaction; a SQL backend has to take
    /// the case row's lock, because two snapshots each reading the other's
    /// pre-state is how both writes commit and the matter ends up closed and
    /// owing.
    async fn register_deadline(&self, deadline: &Deadline) -> Result<(), StoreError>;

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError>;

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError>;

    /// Breach an obligation and escalate its case, in one transaction, if it
    /// is still outstanding and due at `now`. Returns whether it applied.
    ///
    /// One verb because the sweep decides from a read that is already stale
    /// when it acts: a run can meet the obligation and close the case in
    /// between. Spelled as separate writes, the sweep then escalates a closed
    /// case — reopening it and re-claiming its correlation keys — and breaches
    /// an obligation that was met. Here the check and both writes are one
    /// decision, and `false` means somebody got there first.
    ///
    /// The case is escalated only while it is not
    /// [`Closed`](CaseStatus::Closed).
    ///
    /// An applied breach is also marked as **owing its account**, in the same
    /// transaction: the sweep acts first and writes its notes after, so a
    /// crash between the two leaves a breach [`due`](Self::due) no longer
    /// lists. [`breaches_to_note`](Self::breaches_to_note) is where the next
    /// tick finds it, and [`mark_breach_noted`](Self::mark_breach_noted) is
    /// what the notes landing retires.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case or the obligation does not exist.
    async fn breach_deadline(
        &self,
        case: CaseId,
        name: &str,
        now: Timestamp,
    ) -> Result<bool, StoreError>;

    /// Breaches [`breach_deadline`](Self::breach_deadline) applied whose
    /// account the sweep has not yet written, longest-overdue first.
    async fn breaches_to_note(&self, limit: usize) -> Result<Vec<Deadline>, StoreError>;

    /// Record that a breach's account is on the journal. Idempotent.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the obligation does not exist.
    async fn mark_breach_noted(&self, case: CaseId, name: &str) -> Result<(), StoreError>;

    /// Obligations that are due or approaching, oldest first.
    ///
    /// The sweep that turns a passing instant into an escalation. Without it a
    /// deadline is a stored number that nobody reads.
    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError>;

    /// Missed obligations nobody has accounted for, longest-overdue first.
    ///
    /// Reads the obligation's own row, which outlives every status its case
    /// passes through — the escalation a breach causes is retired by
    /// [`close`](Self::close), and closure is when people stop looking.
    ///
    /// Not derivable from [`due`](Self::due), which answers *what still needs
    /// attention*. A breach is past attention; it needs an account.
    ///
    /// **Acknowledged breaches are excluded**, which is what makes this a backlog
    /// rather than a level that only rises: taken oldest-first and bounded by a
    /// page, a listing nothing ever leaves shows the same head forever, and the
    /// entries an operator could still act on are the ones they never see.
    /// [`acknowledge_breach`](Self::acknowledge_breach) is the verb that empties
    /// it; the obligation stays [`Breached`](crate::core::DeadlineState::Breached)
    /// either way, because what ends is the question, not the fact.
    async fn breached(&self, limit: usize) -> Result<Vec<Deadline>, StoreError>;

    /// Record that somebody has accounted for a breach.
    ///
    /// Takes it off [`breached`](Self::breached) and leaves the obligation
    /// `Breached`, with the account readable through
    /// [`deadlines`](Self::deadlines) — the fact and the answer to it are
    /// different things and both are kept.
    ///
    /// **Idempotent, first account wins.** Returns whether this call was the one
    /// that recorded it, so a retry cannot rewrite who looked or when — the same
    /// rule [`KeyRing::destroy`] follows for the same reason.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case or the obligation does not exist,
    /// and [`StoreError::NotBreached`] if it exists and has not been breached —
    /// accepting an account before the breach would take an obligation off the
    /// listing while it was still going to be missed.
    ///
    /// [`KeyRing::destroy`]: crate::keyring::KeyRing::destroy
    async fn acknowledge_breach(
        &self,
        case: CaseId,
        name: &str,
        note: &BreachNote,
    ) -> Result<bool, StoreError>;

    /// Preserve this matter against every erasure verb until somebody lifts it.
    ///
    /// A held case refuses erasure. The hold exists because a retention pass
    /// is automatic: it runs on a window nobody re-reads, and a matter under a
    /// preservation order looks exactly like every other closed case old
    /// enough to sweep.
    ///
    /// **Idempotent, first placement wins**, returning whether this call placed
    /// it — [`acknowledge_breach`](Self::acknowledge_breach)'s rule, for its
    /// reason: a retry must not rewrite when the hold began or why.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case does not exist — a hold on a matter
    /// that is not there preserves nothing and reads as effective in the
    /// listing. [`StoreError::CaseErased`] if the case carries an erasure
    /// marker ([`begin_erasure`](Self::begin_erasure)): a hold accepted on a
    /// matter whose erasure has begun preserves nothing and reads as effective.
    async fn place_hold(&self, case: CaseId, hold: &LegalHold) -> Result<bool, StoreError>;

    /// Lift a hold, returning whether one was there to lift.
    ///
    /// The verb that empties [`holds`](Self::holds); without it that listing is
    /// a level that only rises, which [`breached`](Self::breached) refuses for
    /// the same reason.
    ///
    /// **The register answers *what is preserved now*, not *what ever was*.**
    /// The register keeps no row for a released hold, deliberately: a kept row
    /// would make its free-text reason outlive the matter it preserved. The
    /// history is the journal's —
    /// [`Runtime::release_hold`](crate::runtime::Runtime::release_hold)
    /// records who released the hold, when, and who had placed it, stamped
    /// with the case and without the reason, before removing the hold through
    /// [`release_hold_if`](Self::release_hold_if); both of the plane's doors
    /// release through that. This is the raw register verb: a
    /// direct call is the embedder's own act, and nothing records it.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case does not exist.
    async fn release_hold(&self, case: CaseId) -> Result<bool, StoreError>;

    /// Lift the hold on `case` only if it is still `standing` — same instant,
    /// same reason, same operator.
    ///
    /// Answers whether that hold was removed. `false` when the matter is not
    /// held or holds a different hold; a different hold is left standing.
    ///
    /// The compare and the removal MUST be one write. A release followed by a
    /// re-place puts a new hold where the old one was, so an unconditional
    /// removal by a releaser that read the old one would delete the new hold
    /// under a record that names the old.
    /// [`Runtime::release_hold`](crate::runtime::Runtime::release_hold)
    /// removes through this, with the hold it journaled.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case does not exist; otherwise if the
    /// store cannot be reached, or holds a row it cannot read.
    async fn release_hold_if(&self, case: CaseId, standing: &LegalHold)
    -> Result<bool, StoreError>;

    /// The hold on one matter, if it is held.
    ///
    /// The question every erasure verb asks before it destroys anything.
    async fn hold(&self, case: CaseId) -> Result<Option<LegalHold>, StoreError>;

    /// Record that `case` is being erased, deciding against a hold in the same
    /// write — the step [`erase_case`](crate::blob::erase_case) takes before it
    /// destroys anything.
    ///
    /// A hold read and then acted on is a check a concurrent
    /// [`place_hold`](Self::place_hold) walks past: the hold is accepted and
    /// the key is destroyed anyway. Here the hold check, the status check and
    /// the marker are one decision, and `place_hold` refuses a case carrying
    /// the marker, so of a hold and an erasure racing exactly one wins and the
    /// loser is told.
    ///
    /// Answers [`ErasureStart::Held`] or [`ErasureStart::NotClosed`] — writing
    /// nothing — or [`ErasureStart::Marked`] with the marker that stands.
    /// **First marker wins**: a retry gets the original instant and reason
    /// back, so tombstones and key destructions written by the retry say what
    /// the first attempt said.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case does not exist.
    async fn begin_erasure(
        &self,
        case: CaseId,
        at: Timestamp,
        reason: &str,
    ) -> Result<ErasureStart, StoreError>;

    /// Record that the erasure [`begin_erasure`](Self::begin_erasure) marked
    /// has destroyed everything it reaches. Idempotent.
    ///
    /// Separate from the marker because the marker has to land before the
    /// destruction and this after it: a crash in between leaves an erasure
    /// that is begun and not complete, which a retention pass runs again
    /// rather than skipping.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`] if the case does not exist, and an error if no
    /// erasure was begun on it.
    async fn complete_erasure(&self, case: CaseId) -> Result<(), StoreError>;

    /// The erasure record on one matter, if an erasure was begun on it.
    ///
    /// The plane's own account of *erased by us*: a destroyed key with no
    /// record here is a key that went missing, which is a finding rather than
    /// a completed erasure.
    async fn erasure(&self, case: CaseId) -> Result<Option<Erasure>, StoreError>;

    /// Every matter under hold, **oldest hold first**.
    ///
    /// The half that makes this a control: a store answering only
    /// [`hold`](Self::hold) can be queried solely by somebody who already knows
    /// which case to ask about, which delivers nothing to the person whose job
    /// is to find out what is still preserved and why.
    ///
    /// Ascending legitimately — [`release_hold`](Self::release_hold) removes
    /// entries, so the head is not permanent, and the longest-standing unlifted
    /// hold is the one that needs a question asked about it.
    async fn holds(
        &self,
        after: Option<CaseId>,
        limit: usize,
    ) -> Result<Vec<(CaseId, LegalHold)>, StoreError>;

    /// Cases matching a status, newest first.
    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError>;

    /// How much is open right now, for the gauges in `runtime::metrics`.
    ///
    /// Deliberately not expressible as `by_status(...).len()`: that is bounded
    /// by a `limit`, and a gauge computed from a truncated list is a number that
    /// stops rising exactly when the backlog becomes worth knowing about. It is
    /// also the only consumer of a case's `opened_at` — a count alone cannot
    /// distinguish ten cases open for an hour from ten open for a month.
    ///
    /// `now` is passed in so the reading is testable against arbitrary ageing
    /// and needs no escape from the determinism gate.
    async fn census(&self, now: Timestamp) -> Result<CaseCensus, StoreError>;

    /// Record what the last recovery rehearsal found.
    ///
    /// **One row, replaced.** A history of drills is a different artifact and
    /// a larger promise; what an audit asks is *when did you last rehearse and
    /// did it pass*, and a row that the latest write replaces answers exactly
    /// that without becoming a table nobody prunes.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the store is unreachable. A rehearsal whose verdict
    /// could not be written is reported to its caller rather than swallowed:
    /// the next audit would otherwise read the *previous* drill's date as the
    /// most recent one.
    async fn record_drill(&self, record: &DrillRecord) -> Result<(), StoreError>;

    /// The last recovery rehearsal, or `None` if this plane has never run one.
    ///
    /// `None` is the honest answer and a meaningful one: *nobody has
    /// rehearsed* is what an auditor most wants to know and is exactly what a
    /// missing CI log cannot distinguish from *the log rotated*.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the store is unreachable.
    async fn last_drill(&self) -> Result<Option<DrillRecord>, StoreError>;
}

/// What the last recovery rehearsal found, and when.
///
/// # Why a row rather than a journal record
///
/// A drill is about the **plane**, not a run: it walks the case layer against
/// the blob store and the key ring it is actually wired to. It has no run id
/// and no chain to append to, which is the position a standing halt is in and
/// gets the same answer — a row that the latest write replaces.
///
/// # Why it is stored at all
///
/// What an audit asks is not *can you rehearse* but **when you last did, and
/// whether it passed**. Left in the process that ran the verb, that answer is
/// a CI log or a wiki page — the artifact this project argues against relying
/// on everywhere else. `serve --drill-every` makes the rehearsal a scheduled
/// job; this makes its verdict a fact the plane can be asked for.
///
/// # What it does not carry
///
/// The findings themselves. A drill's report names each unrecoverable
/// reference and is unbounded in a way a single row must not be; what belongs
/// here is the verdict and enough to re-run for detail. The counts are kept
/// **separately from `sound`** because a pass over nothing is not a pass: a
/// drill that could not check the blob store reports no findings and has
/// established almost nothing, which is the same rule
/// [`AuditReport::not_checked`](crate::audit::AuditReport::not_checked) is
/// held to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DrillRecord {
    /// When the rehearsal ran. The caller's clock: a drill is an operational
    /// act in the outside world, not a journaled observation.
    #[serde(with = "time::serde::rfc3339")]
    pub at: Timestamp,
    /// Whether it found nothing unrecoverable.
    pub sound: bool,
    /// Cases walked.
    pub cases: u64,
    /// Unrecoverable references found.
    pub findings: u64,
    /// Questions this pass could not answer — an absent blob store, a key
    /// ring it was not given. Non-zero with `sound` true means *incomplete*,
    /// not *clean*.
    pub not_checked: u64,
    /// The log this plane was serving when it ran, and how far along it was.
    ///
    /// **Which store, answered so a reader cannot be fooled by the obvious
    /// mistake**: a drill against a restored copy proves that copy
    /// recoverable and says nothing about production. An origin and a size
    /// pin both, and both come from the plane's own checkpoint rather than
    /// from a string somebody typed.
    pub origin: String,
    /// The checkpoint size at the time of the rehearsal.
    pub size: u64,
}

/// The record an erasure leaves on its case.
///
/// Written by [`CaseStore::begin_erasure`] before anything is destroyed and
/// never removed, so it outlives the key it describes: a key service that
/// keeps no tombstone (Vault transit does not) can say a key is missing, and
/// only this says the plane erased it, when, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Erasure {
    /// The instant the erasure was asked for, as its caller stated it.
    pub at: Timestamp,
    /// Why, in the words of whoever asked.
    pub reason: String,
    /// Whether every tombstone and the key destruction landed.
    pub complete: bool,
}

/// What [`CaseStore::begin_erasure`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErasureStart {
    /// The case carries an erasure marker — this call's, or an earlier
    /// attempt's, whose instant and reason stand.
    Marked(Erasure),
    /// The case is under this hold; nothing was written.
    Held(LegalHold),
    /// The case is in this status rather than closed; nothing was written.
    NotClosed(CaseStatus),
}

/// The refusal a write to an erased case gets.
///
/// One constructor, so every backend refuses with the same variant.
#[cfg(any(feature = "redb", feature = "postgres"))]
pub(crate) fn case_erased(case: &str, erasure: &Erasure) -> StoreError {
    StoreError::CaseErased {
        case: case.to_owned(),
        at: erasure.at.to_string(),
        reason: erasure.reason.clone(),
    }
}

/// The refusal for a state write past the last version a case can carry.
///
/// Reachable only through an imported or damaged row — a case that wrote once
/// a nanosecond would take centuries — so it is reported as the row's fault
/// rather than wrapped back to zero, where a stale writer holding version 0
/// would win.
#[cfg(any(feature = "redb", feature = "postgres"))]
pub(crate) fn version_exhausted(case: &str) -> StoreError {
    StoreError::Corrupt {
        seq: 0,
        detail: format!(
            "case {case} is at the last version a case can carry, so no further state \
             write can be told apart from a stale one"
        ),
    }
}

/// The refusal a second, different registration of a named obligation gets.
#[cfg(any(feature = "redb", feature = "postgres"))]
pub(crate) fn deadline_exists(case: &str, name: &str) -> StoreError {
    StoreError::DeadlineExists {
        case: case.to_owned(),
        name: name.to_owned(),
    }
}

/// What the case store is currently holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaseCensus {
    /// Cases in any status other than `Closed`.
    pub open: u64,
    /// The longest-open case's age in seconds, or `None` if none are open.
    pub oldest_age_secs: Option<u64>,
    /// Obligations at or past their instant, still `Pending` or `Warned`.
    pub due: u64,
    /// Breaches nobody has accounted for.
    ///
    /// A gauge rather than a counter, and the distinction is the point: this
    /// number falls when somebody acknowledges one, so an alert on it says
    /// *there is unattended work* rather than *this deployment has ever missed
    /// something*. A monotonic instrument cannot express the first, which is
    /// the only one anybody can act on.
    pub breached: u64,
}
