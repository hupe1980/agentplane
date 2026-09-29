//! Per-tenant ceilings on concurrent work and spend.
//!
//! Budgets bound one run. They do not bound a *tenant*: a caller that can start
//! runs can start a thousand of them, each perfectly within its own ceiling, and
//! the plane's compute and the deployment's model bill are both somebody else's
//! problem. That is the noisy-neighbour case, and it is the one failure mode
//! multi-tenancy adds that isolation alone does not answer.
//!
//! # Why this is in the store
//!
//! An in-process counter is a ceiling that vanishes the moment a second instance
//! starts — and several instances sharing one store is the topology the Postgres
//! backend exists for. Worse, it fails *open*: the limit silently doubles when
//! somebody scales out, which is exactly when it was needed.
//!
//! So the accounting is durable, and the reservation is **one transaction that
//! counts and inserts**. A read-then-write has a window, and with two instances
//! admitting at once that window is the whole guarantee — the same reason
//! exactly-once is a unique index here rather than a `SELECT` before an
//! `INSERT`.
//!
//! # What each ceiling actually bounds
//!
//! Stating this precisely matters more than the mechanism, because a ceiling
//! believed to bound something it does not is worse than none.
//!
//! **Concurrency** bounds runs *executing at once*. A slot is taken at admission
//! and given back when this instance finishes with the run — sealed, failed, or
//! **suspended**. A suspended run costs a row, not a thread, so holding its slot
//! would mean a tenant waiting on a hundred human approvals could start nothing.
//!
//! It follows that a **resume is not gated**. The work was admitted already, and
//! refusing to resume it would strand a run that is waiting on something that
//! has now happened. So concurrent execution can exceed the ceiling by the
//! number of runs resuming at once; what the ceiling bounds is how much *new*
//! work a tenant can push in, which is the lever a noisy neighbour actually
//! pulls.
//!
//! **Spend** bounds what a period's admitted work can cost, by **reserving**
//! it. Admission holds each run's worst case against the period in the same
//! transaction that checks the ceiling and takes the slot, and refuses when
//! settled spend plus every outstanding reservation plus this one would pass
//! the ceiling. A run's worst case is its own ceiling plus the overshoot the
//! ledger permits: a metered cost is known only when the call returns, so a
//! run stops once it has *reached* its ceiling and can end one operation past
//! it per step in flight. So the reservation is
//! `ceiling + width × per-call bound` — the width being the run's
//! `max_parallel_steps`, or its admitted plan's node count, to which its
//! dispatch is then held — and a run whose budget leaves either term
//! unbounded is refused under a quota on that unit rather than admitted
//! holding nothing.
//!
//! Every pass settlement moves that pass's spend out of the run's reservation
//! and into the settled total, and the pass that concludes the run releases
//! what is left — in the transaction that writes the receipt. A suspended run
//! keeps its remainder, and a resume is never refused for spend: the work was
//! admitted already, and refusing it strands a run mid-saga.
//!
//! **What this bounds, exactly.** A period's settled total never exceeds its
//! ceiling through work admitted in it, however many runs suspend, run
//! concurrently or admit from several instances at once. Two things still
//! reach past it, and both are stated rather than hidden:
//!
//! * **A resume in a later period** brings its run's remainder with it: the
//!   old period's hold is released and what is left of the run's budget is
//!   held in the new one, unconditionally, because a resume is not refused. A
//!   period can therefore start with holds it never admitted, and new
//!   admissions are refused until they settle.
//! * **An operation that reports more than the per-call bound.** A model call
//!   is held to its role's `max_input_tokens` by the usage the provider
//!   reports, and one that sent more fails — billed as reported, so that one
//!   call's excess is outside the bound. An embedder's own effects and the
//!   `Budget` figures it declares for them cannot be inspected: for those the
//!   bound is as exact as the declaration, the footing a price stands on. A
//!   compensating call is exempt from every ceiling, so what an undo reports
//!   is outside it too.
//!
//! A commissioned run is its own run: it reserves and settles its own spend,
//! and the commissioning run's ledger is billed the same figure for its own
//! ceiling without settling it a second time into the period.
//!
//! A run that never concludes — quarantined, or waiting on something nothing
//! will answer — holds its remainder indefinitely. That is a backlog, and a
//! refusal says how much of the period is reserved rather than settled; the
//! holders are listed by [`QuotaStore::reservations`], and `attention` names
//! the stopped ones with the verb that releases them. A halt does not release
//! a reservation, and [`Runtime::set_halt`](crate::runtime::Runtime::set_halt)
//! says what it does reach: the workload scopes stop admission, and only a
//! subject-scoped halt reaches work already running.
//!
//! One live execution pass belongs to the period in which it starts. Admission
//! reserves against that period and settlement accrues the pass's spend to the
//! same key, even if midnight or month-end passes while work is running. A
//! later resume is a new pass in the period in which it resumes. Without that
//! identity a run can be authorized against the old period and charged to the
//! new one, leaving both ledgers wrong in opposite directions.
//!
//! # The window is a billing period, not an arbitrary bucket
//!
//! Fixed windows are usually criticised for boundary amplification: spend the
//! ceiling at the end of one window and again at the start of the next, and you
//! have used twice the ceiling in a short span. That criticism assumes the
//! window is arbitrary. Here it is the deployment's billing period — spending a
//! month's budget in the last hour of one month and the first hour of the next
//! *is* two months of budget, correctly accounted. A sliding window would be the
//! wrong answer to a question nobody asked.
//!
//! # A rate ceiling slides
//!
//! A grant's rate ceiling — *at most twenty refunds an hour* — is not a billing
//! period, and a fixed hourly bucket would admit forty refunds in the two
//! minutes around its boundary, which is the burst the ceiling exists to stop.
//! So it counts [`RateReservation`]s whose instant falls inside the window
//! ending now. One row per dispatch, keyed by the run and the dispatch's first
//! attempt, so a retry or a recovered re-dispatch spends once and two runs
//! making the same call each spend. Rows are never refunded early: nothing
//! proves an unannounced call did not reach the world. They age out with the
//! window.
//!
//! The count is per tenant per tool reference, judged against every ceiling
//! the dispatching plane's declarations state for that reference. Instances
//! sharing a store share the count; each judges it against the declarations
//! it holds, and the instant is each instance's own clock, so a window across
//! instances inherits their skew.
//!
//! The rows are operational state, not evidence: replay never reads them, a
//! refusal is journaled on the run, and they stay out of the export.

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{Budget, EffectKey, RunId, Spend, StoreError, Timestamp};

/// At most `count` dispatches in any `window_seconds`, across runs.
///
/// Declared on a grant, and never zero in either figure: a manifest refuses
/// both at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RateCeiling {
    pub count: u32,
    pub window_seconds: u64,
}

impl std::fmt::Display for RateCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "at most {} per {} second(s)",
            self.count, self.window_seconds
        )
    }
}

/// One dispatch asking for room under the rate ceilings on its tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateReservation {
    /// The tool reference the count is kept for, `tool://server/name`.
    pub grant: String,
    /// The dispatching run. Part of the key because an effect key does not
    /// contain it: two runs making the same call would otherwise share a row.
    pub run: RunId,
    /// The dispatch's **first** attempt's key, which a retry, a recovered
    /// re-dispatch and a resumed pass all derive again. Each attempt's own key
    /// would charge every retry.
    pub dispatch: EffectKey,
    /// Every ceiling the dispatch is judged against; each must have room.
    pub ceilings: Vec<RateCeiling>,
    /// The plane clock at reservation.
    pub at: Timestamp,
    /// Counted and never refused: an undo. Refusing to undo is how a run ends
    /// with a charged card and no order.
    pub exempt: bool,
}

/// The first instant a window ending at `at` no longer counts.
///
/// A row counts when its instant is **after** this, which makes the window
/// slide with `at` rather than restart at a bucket boundary. Shared by both
/// backends so the boundary is one comparison.
#[must_use]
pub fn rate_window_start(at: i64, window_seconds: u64) -> i64 {
    at.saturating_sub(i64::try_from(window_seconds).unwrap_or(i64::MAX))
}

/// Refuse a dispatch whose tool has no room under one of its ceilings.
///
/// `instants` are the reservation instants the store holds for the tool, read
/// inside the transaction that would insert this one. A row stamped after `at`
/// — another instance's clock running ahead — counts, so skew errs toward
/// refusing.
///
/// # Errors
///
/// [`QuotaError::RateLimited`] naming the first ceiling without room.
pub fn check_rate(
    tenant: &str,
    grant: &str,
    ceilings: &[RateCeiling],
    instants: &[i64],
    at: Timestamp,
) -> Result<(), QuotaError> {
    let at = at.unix_timestamp();
    for ceiling in ceilings {
        let start = rate_window_start(at, ceiling.window_seconds);
        let reached = instants.iter().filter(|&&t| t > start).count();
        if reached >= ceiling.count as usize {
            return Err(QuotaError::RateLimited {
                tenant: tenant.to_owned(),
                grant: grant.to_owned(),
                ceiling: *ceiling,
                reached: u64::try_from(reached).unwrap_or(u64::MAX),
            });
        }
    }
    Ok(())
}

/// The instant at or before which no ceiling in `ceilings` counts a row.
///
/// Rows at or before it are pruned in the reserving transaction.
#[must_use]
pub fn rate_prune_floor(at: Timestamp, ceilings: &[RateCeiling]) -> i64 {
    let widest = ceilings.iter().map(|c| c.window_seconds).max().unwrap_or(0);
    rate_window_start(at.unix_timestamp(), widest)
}

/// One live execution pass to settle exactly once.
///
/// `epoch` is the pass identity: every takeover receives a new fencing epoch,
/// so suspension/resume and crash recovery cannot collide with an earlier
/// charge from the same run. A store keeps the full payload as a receipt;
/// repeating the same settlement is a no-op, while changing any field under an
/// existing key is corruption rather than a second charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaSettlement {
    pub run: RunId,
    pub epoch: u64,
    pub period: Option<String>,
    pub spend: Spend,
    /// Whether this pass took the run's admission slot.
    ///
    /// Fresh admission does; resume does not. Settlement removes the slot in
    /// the same transaction that records the receipt and accrues spend.
    pub release_slot: bool,
    /// Whether this pass concluded the run.
    ///
    /// Every settlement moves its spend out of the run's reservation; the
    /// concluding one also releases what is left, so a run that finished under
    /// its budget gives the period back the difference. Part of the receipt,
    /// so a retry that disagrees about it is corruption like any other field.
    pub concludes: bool,
}

/// Spend one admission holds against a period until the run settles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendHold {
    /// The period the admitting pass starts in.
    pub period: String,
    /// What the run can cost at most: see [`reservation`].
    pub amount: Spend,
}

/// One run holding spend against this tenant's period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub run: RunId,
    /// The period the hold is counted in.
    pub period: String,
    /// What is still held: the reservation, less every pass settled since.
    pub remaining: Spend,
}

/// What admitting a run under `quota` holds against the period.
///
/// Per unit the quota bounds: the run's ceiling, plus `width` steps' worth of
/// the one-operation overshoot the ledger permits — `ceiling + width × per-call
/// bound`, saturating. A unit the quota does not bound is held at zero, and
/// nothing is held — `Ok(None)` — when the quota bounds no spend at all.
///
/// `width` is how many steps the run may have in flight: each can be holding
/// an operation the ledger admitted below the ceiling and has not yet billed.
///
/// # Errors
///
/// The [`Budget`] field that leaves a bounded unit unbounded, for the refusal
/// to name — an unbounded run is an unbounded reservation.
pub fn reservation(
    quota: &TenantQuota,
    budget: &Budget,
    width: u64,
) -> Result<Option<Spend>, &'static str> {
    if !quota.bounds_spend() {
        return Ok(None);
    }
    let hold = |bounded: bool,
                ceiling: Option<u64>,
                call: Option<u64>,
                names: (&'static str, &'static str)|
     -> Result<u64, &'static str> {
        if !bounded {
            return Ok(0);
        }
        let ceiling = ceiling.ok_or(names.0)?;
        let call = call.ok_or(names.1)?;
        Ok(ceiling.saturating_add(width.saturating_mul(call)))
    };
    Ok(Some(Spend {
        tokens: hold(
            quota.max_tokens_per_period.is_some(),
            budget.max_tokens,
            budget.max_call_tokens,
            ("max_tokens", "max_call_tokens"),
        )?,
        minor_units: hold(
            quota.max_minor_units_per_period.is_some(),
            budget.max_minor_units,
            budget.max_call_minor_units,
            ("max_minor_units", "max_call_minor_units"),
        )?,
    }))
}

/// What one tenant may consume.
///
/// Every field is optional and `None` means *unlimited*, which is the default: a
/// deployment that has not thought about quotas gets the behaviour it had before
/// they existed, rather than a ceiling somebody has to discover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TenantQuota {
    /// Runs this tenant may have executing at once.
    pub max_concurrent_runs: Option<u32>,
    /// Tokens this tenant may spend in one period.
    pub max_tokens_per_period: Option<u64>,
    /// Money, in minor units, this tenant may spend in one period.
    pub max_minor_units_per_period: Option<u64>,
    /// How long a spend period lasts.
    pub period: Period,
}

impl TenantQuota {
    /// Whether this quota constrains anything at all.
    #[must_use]
    pub const fn is_unlimited(&self) -> bool {
        self.max_concurrent_runs.is_none()
            && self.max_tokens_per_period.is_none()
            && self.max_minor_units_per_period.is_none()
    }

    /// Whether any spend ceiling is set.
    #[must_use]
    pub const fn bounds_spend(&self) -> bool {
        self.max_tokens_per_period.is_some() || self.max_minor_units_per_period.is_some()
    }
}

/// The window a spend ceiling applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Period {
    /// Calendar month, UTC — the usual billing period.
    #[default]
    Monthly,
    /// Calendar day, UTC.
    Daily,
}

impl Period {
    /// The key this instant falls in.
    ///
    /// Lexicographically ordered, so a range scan over a tenant's periods reads
    /// in time order without parsing anything.
    #[must_use]
    pub fn key_for(self, at: Timestamp) -> String {
        let d = at.date();
        match self {
            Self::Monthly => format!("{:04}-{:02}", d.year(), u8::from(d.month())),
            Self::Daily => format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day()),
        }
    }
}

/// What an emergency stop covers.
///
/// A plane hosts many agents, and *agent 12 of 28 is misbehaving at three in
/// the morning* is the ordinary incident — a switch that can only stop all 28
/// is not an emergency stop for it. So a halt names its scope. Every standing
/// halt is checked together and a run is refused if **any** matches, so a
/// broad stop and a narrow one coexist and lifting the narrow one leaves the
/// broad one standing.
///
/// [`Revision`](Self::Revision) names exact reviewed bytes, so a fix published
/// as a new version runs while the broken revision stays stopped — prefer it
/// when a deploy is the incident. [`Agent`](Self::Agent) covers every revision
/// of a declared name. [`Tenant`](Self::Tenant) is the power switch.
///
/// **[`Subject`](Self::Subject) is keyed on the other axis**, and it is the one
/// to reach for when the incident is not the workload but the *authority*: a
/// credential somebody has withdrawn, a service account that turned out to be
/// shared, a person who has left. The three scopes above ask *what is running*;
/// this one asks *who it is running for*, which is the delegation subject bound
/// at admission and carried on every run's `IdentityBound` record. A run with no
/// chain of its own is covered by none of them — there is nothing to key on, and
/// inventing a match would stop work for a reason nobody could look up.
///
/// A name is a string the manifest's author typed, and a halt is still keyed
/// on one because it is a **refusal**: a name-keyed refusal at worst stops
/// work somebody did not mean to stop, which an operator sees at once and
/// lifts — the opposite of a name-keyed *grant*, which `context.agent.name` is
/// therefore never used for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HaltScope {
    /// Everything this tenant would start. The power switch.
    Tenant,
    /// Every revision of one declared agent, by `metadata.name`.
    Agent { name: String },
    /// One exact reviewed revision, by manifest digest.
    ///
    /// The form that is precise about *which* revision is stopped, so a fix
    /// published as a new version is not stopped with it.
    Revision { digest: crate::core::Digest },
    /// Everything acting for one delegation subject.
    ///
    /// The authority axis rather than the workload axis. Ordered last so that
    /// it wins the *message* when several scopes cover one run: an operator who
    /// withdrew a credential and whoever is refused are looking for different
    /// sentences, and "the tenant is halted" sends the second one to the wrong
    /// incident.
    Subject { id: String },
}

impl HaltScope {
    /// Every revision of one declared agent.
    pub fn agent(name: impl Into<String>) -> Self {
        Self::Agent { name: name.into() }
    }

    /// One exact reviewed revision.
    #[must_use]
    pub const fn revision(digest: crate::core::Digest) -> Self {
        Self::Revision { digest }
    }

    /// Everything acting for one delegation subject.
    pub fn subject(id: impl Into<String>) -> Self {
        Self::Subject { id: id.into() }
    }

    /// The durable key, and the form an operator types on the command line.
    ///
    /// Round-trips through [`parse`](Self::parse). One column rather than a
    /// discriminant beside a value, because a scope stored in two columns is a
    /// scope two backends can disagree about the emptiness rules of.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Tenant => "tenant".to_owned(),
            Self::Agent { name } => format!("agent:{name}"),
            Self::Revision { digest } => format!("revision:{digest}"),
            Self::Subject { id } => format!("subject:{id}"),
        }
    }

    /// Every form [`parse`](Self::parse) accepts, written the way an operator
    /// types it.
    ///
    /// One list, because a scope an operator cannot learn the spelling of is a
    /// control they cannot reach — and the CLI's help, its refusal and the
    /// operator API all have to say the same thing this parser accepts. Held to
    /// the list rather than to the variant count: a count agrees with itself
    /// while a form is missing.
    pub const FORMS: [&'static str; 4] = [
        "tenant",
        "agent:<metadata.name>",
        "revision:<manifest digest>",
        "subject:<delegation subject>",
    ];

    /// The forms, joined for a refusal a person reads.
    #[must_use]
    pub fn forms() -> String {
        Self::FORMS
            .iter()
            .map(|f| format!("'{f}'"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Read back a stored key.
    ///
    /// `None` for anything this build does not understand — a scope written by
    /// a newer version, say. A caller reading standing halts must treat that as
    /// corruption rather than skipping the row: a halt this instance cannot
    /// read is one it must not run through.
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        if key == "tenant" {
            return Some(Self::Tenant);
        }
        if let Some(name) = key.strip_prefix("agent:")
            && !name.is_empty()
        {
            return Some(Self::agent(name));
        }
        if let Some(hex) = key.strip_prefix("revision:") {
            return crate::core::Digest::from_hex(hex).ok().map(Self::revision);
        }
        if let Some(id) = key.strip_prefix("subject:")
            && !id.is_empty()
        {
            return Some(Self::subject(id));
        }
        None
    }

    /// The authority this halt withdraws, when it withdraws one.
    ///
    /// **The one scope that reaches work already running.** The others stop
    /// admission, because cutting a saga mid-flight leaves reversals unrun; here
    /// the incident *is* the authority, and a run carrying on under a withdrawn
    /// credential is the harm. It **pauses**: the run stops at its next step
    /// boundary, its mutations stand, and lifting the halt continues it.
    ///
    /// Returns the subject rather than a `bool` so the in-flight check has
    /// nothing to pass and so nothing to get wrong — a caller asking `covers`
    /// with the agent but not the subject would match nothing, which is a
    /// refusal that does not happen.
    #[must_use]
    pub fn withdrawn_subject(&self) -> Option<&str> {
        match self {
            Self::Subject { id } => Some(id.as_str()),
            Self::Tenant | Self::Agent { .. } | Self::Revision { .. } => None,
        }
    }

    /// Whether this halt stops a run governed by `agent` and acting for
    /// `subject`.
    ///
    /// **Both, because the scopes ask different questions.** Three of them ask
    /// what is running and one asks who it runs for, so a caller that passed
    /// only the agent would silently never match a withdrawn authority — the
    /// worst failure available here, since it is a refusal that does not happen
    /// and therefore leaves no trace at all.
    ///
    /// A run with neither — a skill registered directly on the plane, with no
    /// manifest and no chain — is stopped only by [`Tenant`](Self::Tenant).
    /// There is nothing narrower to key it on, and inventing a match would stop
    /// work for a reason nobody could look up.
    #[must_use]
    pub fn covers(
        &self,
        agent: Option<&crate::journal::AgentIdentity>,
        subject: Option<&str>,
    ) -> bool {
        match self {
            Self::Tenant => true,
            Self::Agent { name } => agent.is_some_and(|a| &a.name == name),
            Self::Revision { digest } => agent.is_some_and(|a| &a.digest == digest),
            Self::Subject { id } => subject.is_some_and(|s| s == id),
        }
    }
}

impl std::fmt::Display for HaltScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tenant => f.write_str("the whole tenant"),
            Self::Agent { name } => write!(f, "agent '{name}'"),
            Self::Revision { digest } => write!(f, "manifest revision {digest}"),
            Self::Subject { id } => write!(f, "everything acting for '{id}'"),
        }
    }
}

/// One standing emergency stop.
///
/// The runtime cannot check this instruction — there is no verdict to re-derive
/// and no policy that authorized the judgement — so its whole evidentiary weight
/// is the name beside it, and [`Operator`] carries what established that name.
///
/// **Who lifted one is not kept.** Lifting removes the row; retaining lifted
/// rows would be a listing that grows with nothing to empty it. Where the stop
/// reached a running run, [`AuthorityWithheld`] holds the operator from this row.
///
/// [`Operator`]: crate::core::Operator
/// [`AuthorityWithheld`]: crate::journal::RecordKind::AuthorityWithheld
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halt {
    pub scope: HaltScope,
    /// Why. Required when halting, because the next person to look will be
    /// somebody else, possibly at three in the morning, and *why* is the whole
    /// question.
    pub reason: String,
    /// Who threw it, and what established the name.
    pub by: crate::core::Operator,
    /// When it was thrown. Supplied by the caller, never read from a clock
    /// here, for the reason every other lifecycle instant in this crate is: a
    /// pass that reads its own clock cannot be tested against an ageing plane.
    pub at: crate::core::Timestamp,
}

/// Why a run was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QuotaError {
    /// The tenant already has as many runs executing as it may.
    ///
    /// Retryable, and that is the point: this is back-pressure, not a fault. The
    /// caller should try again rather than treat the work as impossible.
    #[error(
        "tenant '{tenant}' already has {running} runs executing, which is its limit — \
         this is back-pressure, not a fault: retry when one finishes"
    )]
    TooManyRuns { tenant: String, running: u32 },

    /// Admitting this run would let the period pass its ceiling.
    ///
    /// Settled and reserved are named apart, because they call for different
    /// answers: settled spend is gone until the period turns, while reserved
    /// spend is held by open runs — some of which may be quarantined or waiting
    /// on nothing, and releasing theirs is an operator's act.
    #[error(
        "tenant '{tenant}' has {settled} {unit} settled and {reserved} reserved by open \
         runs against its {limit} for period {period}, and this run holds up to \
         {requested} — settled spend resets with the period; reserved spend is released \
         as its runs conclude, and `agentplane attention` names the stopped ones"
    )]
    SpentOut {
        tenant: String,
        period: String,
        unit: &'static str,
        settled: u64,
        reserved: u64,
        requested: u64,
        limit: u64,
    },

    /// The tenant bounds a unit per period and this run declares no bound on it.
    ///
    /// A run with no ceiling, or no per-call bound, would hold an unbounded
    /// reservation — the period ceiling would stop binding the moment it was
    /// admitted. `field` is the [`Budget`] field that is absent.
    #[error(
        "tenant '{tenant}' bounds {unit} per period, and this run declares no {field}, so \
         what it can cost is unbounded and cannot be reserved — a manifest sets \
         spec.budgets.max_tokens / max_minor_units, and bounds one call with \
         max_input_tokens (and a price) on every model role; an embedder sets the same \
         fields on its Budget"
    )]
    Unbounded {
        tenant: String,
        unit: &'static str,
        field: &'static str,
    },

    /// An operator stopped this work from starting.
    ///
    /// Deliberately its own variant rather than a zero ceiling. A ceiling says
    /// *not right now*, and a caller is right to retry it; a halt says *somebody
    /// is dealing with an incident*, and retrying is exactly what an operator
    /// pulling the switch is trying to stop. Collapsing the two would teach
    /// callers to hammer through the one refusal that means stop.
    ///
    /// `scope` says **what** was stopped, because "halted" alone is a different
    /// message on a plane hosting one agent and on a plane hosting twenty-eight:
    /// whoever is refused needs to know whether the plane is down or their agent
    /// is.
    #[error("{scope} is halted by an operator (tenant '{tenant}'): {reason}")]
    Halted {
        tenant: String,
        scope: HaltScope,
        reason: String,
    },

    /// A tool's rate ceiling has no room in the window ending now.
    ///
    /// Back-pressure, like [`TooManyRuns`](Self::TooManyRuns): the window
    /// slides, and the refused dispatch fits once enough of the counted ones
    /// age out of it.
    #[error(
        "'{grant}' is limited to {ceiling} for tenant '{tenant}', and {reached} dispatch(es) \
         already fall in the window ending now — wait for the window to pass"
    )]
    RateLimited {
        tenant: String,
        grant: String,
        ceiling: RateCeiling,
        reached: u64,
    },

    /// The accounting itself could not be reached.
    ///
    /// Fails **closed**. A quota that yields when its store is unreachable is a
    /// quota an attacker removes by making the store unreachable.
    #[error(
        "the quota store could not be reached, and a ceiling that yields under load is not a ceiling: {0}"
    )]
    Unavailable(String),
}

impl From<StoreError> for QuotaError {
    fn from(e: StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

/// Durable accounting for what a tenant is using.
///
/// Implemented by the same store types that implement the journal, so a
/// deployment gets it from the backend it already wired.
#[async_trait]
pub trait QuotaStore: Send + Sync + Debug {
    /// Which tenant this handle accounts for.
    ///
    /// Required with no default: a plane and quota store scoped differently
    /// work perfectly while reserving and billing the wrong tenant, so the
    /// mismatch must be refused at build rather than inferred from behavior.
    fn tenant(&self) -> &str;

    /// Take a concurrency slot for `run`, and hold its spend, or refuse.
    ///
    /// **Must decide and insert in one transaction.** The slot count against
    /// `quota.max_concurrent_runs`, and — when `hold` is given — settled spend
    /// plus every outstanding reservation in the hold's period plus this one
    /// against the period ceilings, through [`check_spend`]. A read followed
    /// by a write leaves a window two instances admit through, and the ceiling
    /// is then a suggestion — worse under exactly the load it exists for.
    ///
    /// Idempotent per run: reserving a run that already holds a slot, or
    /// already holds spend, must succeed without taking a second, so a retried
    /// admission cannot consume two.
    ///
    /// # Errors
    ///
    /// [`QuotaError::TooManyRuns`] at the concurrency ceiling,
    /// [`QuotaError::SpentOut`] when the hold does not fit, or
    /// [`QuotaError::Unavailable`] if the store cannot be reached.
    async fn reserve(
        &self,
        run: RunId,
        quota: &TenantQuota,
        hold: Option<&SpendHold>,
        at: Timestamp,
    ) -> Result<(), QuotaError>;

    /// Give back, idempotently, the slot and the spend hold of an admission
    /// whose journal never landed, or of a run that concluded with no pass to
    /// settle.
    ///
    /// Normal pass completion MUST use [`settle`](Self::settle), which couples
    /// release to the receipt and spend transaction.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn release(&self, run: RunId) -> Result<(), StoreError>;

    /// Move a run's spend hold into `period`, where a resume is about to spend.
    ///
    /// Releases what the run held in its old period and holds the same
    /// remainder in the new one, in one transaction. Unconditional — a resume
    /// is never refused for spend — and a no-op when the run holds nothing or
    /// already holds it in `period`.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn carry(&self, run: RunId, period: &str) -> Result<(), StoreError>;

    /// Every run holding spend against this tenant's periods, by run id.
    ///
    /// The listing a [`QuotaError::SpentOut`] refusal points at: reserved
    /// spend belongs to named runs, and one that is quarantined or waiting on
    /// nothing holds its remainder until somebody concludes it.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn reservations(&self, limit: usize) -> Result<Vec<Held>, StoreError>;

    /// What open runs hold against `period`.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn reserved(&self, period: &str) -> Result<Spend, StoreError>;

    /// Stop work at `scope` from starting.
    ///
    /// Throwing and lifting are **separate verbs** rather than one call taking
    /// an `Option`, for the reason acquiring and renewing a lease are: they are
    /// different acts with different arguments. Throwing one names who threw it
    /// and when; lifting names neither, because the row goes.
    ///
    /// **In the store, not in the process.** An in-memory flag is a switch that
    /// only stops the instance it was thrown on — which is the same failure an
    /// in-process quota counter has, arriving at the worst possible moment. One
    /// tenant's halt does not touch another's.
    ///
    /// Scopes are **independent rows**, not one flag that the last writer wins.
    /// Halting an agent while the tenant is halted, and lifting the agent's,
    /// must leave the tenant's standing — an incident that widens and then
    /// partly resolves is the ordinary shape, and a single overwritable flag
    /// gets it wrong in the direction that lets work through.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn set_halt(
        &self,
        scope: &HaltScope,
        by: &crate::core::Operator,
        at: crate::core::Timestamp,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Let work at `scope` start again.
    ///
    /// Answers whether one was standing, so an operator who lifts a scope
    /// nobody halted is told that rather than told *done*.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn lift_halt(&self, scope: &HaltScope) -> Result<bool, StoreError>;

    /// Every standing halt for this tenant.
    ///
    /// One read rather than a lookup per scope: admission has to consider all
    /// of them, and three round trips per admitted run is a gate people turn
    /// off. It is also the operator's question — *what is stopped right now?* —
    /// which a per-scope lookup cannot answer without already knowing what to
    /// ask about.
    ///
    /// A stored scope this build cannot parse MUST be reported as
    /// [`StoreError::Corrupt`] rather than skipped. A halt an instance silently
    /// ignores is a halt that reads, from the outside, exactly like one that was
    /// lifted.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached, or holds a scope it cannot read.
    async fn halts(&self) -> Result<Vec<Halt>, StoreError>;

    /// Settle one live pass exactly once.
    ///
    /// The receipt, spend accrual, the reduction of the run's spend hold by
    /// the pass's spend (floored at zero), the hold's release when the pass
    /// concludes the run, and admission-slot release MUST commit in one
    /// transaction. Repeating an identical settlement MUST succeed without
    /// accruing again. Reusing `(run, epoch)` with a different period, spend,
    /// slot flag or conclusion MUST fail as corruption: accepting it makes retries a way to
    /// rewrite the bill.
    ///
    /// `period: None` records the receipt and releases the slot without adding a
    /// billing total, which is the correct shape when only concurrency or halt
    /// is configured.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached or the pass key already names a different
    /// settlement.
    async fn settle(&self, settlement: &QuotaSettlement) -> Result<(), StoreError>;

    /// What this tenant has settled in `period` — spend that happened, not
    /// spend held.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn spent(&self, period: &str) -> Result<Spend, StoreError>;

    /// How many runs this tenant has executing.
    ///
    /// For an operator answering "why is my tenant being throttled?", which a
    /// refusal alone does not answer.
    /// A runtime with this store wired records active runs even when every
    /// configured ceiling is `None`, so the answer stays truthful before a
    /// limit is introduced and while the store is used only for emergency halt.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn running(&self) -> Result<u32, StoreError>;

    /// **Which** runs hold this tenant's slots.
    ///
    /// [`running`](Self::running) says *five of five*, and one of those five may
    /// not be a run at all: a slot is taken at admission and given back at
    /// settlement, so an instance that dies in between strands one —
    /// indistinguishable from live work in a count, and the tenant is throttled
    /// by a run that stopped existing.
    ///
    /// The answer is one join away. A stranded slot is a run this listing holds
    /// whose lease has lapsed, which [`JournalStore::abandoned_runs`] returns;
    /// the recovery sweep resumes it and settlement gives the slot back. Ordered
    /// by run id, and legitimately ascending because a settled run leaves.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    ///
    /// [`JournalStore::abandoned_runs`]: crate::journal::JournalStore::abandoned_runs
    async fn running_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError>;

    /// Take room for one dispatch under its tool's rate ceilings, or refuse.
    ///
    /// **Must decide and insert in one transaction**, through [`check_rate`],
    /// for the reason [`reserve`](Self::reserve) must: two instances reading a
    /// window with one place left both land otherwise. The window slides —
    /// see the module's *A rate ceiling slides*.
    ///
    /// Idempotent per `(grant, run, dispatch)`: a key already present succeeds
    /// without inserting and without being judged, so a retry and a recovered
    /// re-dispatch spend once. An [`exempt`](RateReservation::exempt)
    /// reservation inserts without being judged. Rows at or before
    /// [`rate_prune_floor`] are deleted in the same transaction.
    ///
    /// # Errors
    ///
    /// [`QuotaError::RateLimited`] when a ceiling has no room, or
    /// [`QuotaError::Unavailable`] if the store cannot be reached.
    async fn reserve_rate(&self, reservation: &RateReservation) -> Result<(), QuotaError>;

    /// Whether a dispatch of `grant` would have room now, taking none.
    ///
    /// A resume at a standing rate refusal asks this before re-admitting: a
    /// window still full re-concludes the run on the refusal already on its
    /// record, rather than stacking a re-admission and a second refusal.
    ///
    /// # Errors
    ///
    /// As [`reserve_rate`](Self::reserve_rate).
    async fn rate_room(
        &self,
        grant: &str,
        ceilings: &[RateCeiling],
        at: Timestamp,
    ) -> Result<(), QuotaError>;
}

/// Refuse a hold that would take a period past its ceiling.
///
/// Separate from the store so both backends share one comparison: two
/// implementations of "is this over the line" is two chances to get `>` wrong,
/// and the one that is wrong is whichever nobody tested at the boundary. Both
/// call it **inside** the transaction that inserts the hold.
///
/// Admits when `settled + reserved + request` stays at or under the ceiling:
/// the reservation is a run's worst case, so a period filled exactly is a
/// period its admitted work can reach and not pass.
///
/// # Errors
///
/// [`QuotaError::SpentOut`] naming the first unit that would not fit.
pub fn check_spend(
    tenant: &str,
    period: &str,
    quota: &TenantQuota,
    settled: Spend,
    reserved: Spend,
    request: Spend,
) -> Result<(), QuotaError> {
    for (unit, limit, settled, reserved, requested) in [
        (
            "tokens",
            quota.max_tokens_per_period,
            settled.tokens,
            reserved.tokens,
            request.tokens,
        ),
        (
            "minor units",
            quota.max_minor_units_per_period,
            settled.minor_units,
            reserved.minor_units,
            request.minor_units,
        ),
    ] {
        if let Some(limit) = limit
            && settled.saturating_add(reserved).saturating_add(requested) > limit
        {
            return Err(QuotaError::SpentOut {
                tenant: tenant.to_owned(),
                period: period.to_owned(),
                unit,
                settled,
                reserved,
                requested,
                limit,
            });
        }
    }
    Ok(())
}
