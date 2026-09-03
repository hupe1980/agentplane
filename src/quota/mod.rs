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
//! **Spend** bounds a period, and it is checked at admission rather than
//! mid-run. A run already executing when the ceiling is crossed finishes. The
//! overshoot is therefore bounded and computable rather than unknown: at most
//! the concurrency ceiling times the per-run budget, both of which the
//! deployment sets. A tighter cap would mean consulting the store on every
//! effect, which buys exactness at the cost of a round trip per step.
//!
//! One live execution pass belongs to the period in which it starts. Admission
//! checks that period and settlement accrues the pass's spend to the same key,
//! even if midnight or month-end passes while work is running. A later resume
//! is a new pass in the period in which it resumes. Without that identity a run
//! can be authorized against the old period and charged to the new one, leaving
//! both ledgers wrong in opposite directions.
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

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{RunId, Spend, StoreError, Timestamp};

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
        }
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
        None
    }

    /// Whether this halt stops a run governed by `agent`.
    ///
    /// An ungoverned run — a skill registered directly on the plane, with no
    /// manifest — is stopped only by [`Tenant`](Self::Tenant). There is nothing
    /// narrower to key it on, and inventing a match would stop work for a
    /// reason nobody could look up.
    #[must_use]
    pub fn covers(&self, agent: Option<&crate::journal::AgentIdentity>) -> bool {
        match self {
            Self::Tenant => true,
            Self::Agent { name } => agent.is_some_and(|a| &a.name == name),
            Self::Revision { digest } => agent.is_some_and(|a| &a.digest == digest),
        }
    }
}

impl std::fmt::Display for HaltScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tenant => f.write_str("the whole tenant"),
            Self::Agent { name } => write!(f, "agent '{name}'"),
            Self::Revision { digest } => write!(f, "manifest revision {digest}"),
        }
    }
}

/// One standing emergency stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halt {
    pub scope: HaltScope,
    /// Why. Required when halting, because the next person to look will be
    /// somebody else, possibly at three in the morning, and *why* is the whole
    /// question.
    pub reason: String,
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

    /// The tenant has spent its ceiling for this period.
    #[error(
        "tenant '{tenant}' has spent {spent} of its {limit} {unit} for period {period} — \
         this does not reset until the period does"
    )]
    SpentOut {
        tenant: String,
        period: String,
        unit: &'static str,
        spent: u64,
        limit: u64,
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

    /// Take a concurrency slot for `run`, or refuse.
    ///
    /// **Must count and insert in one transaction.** A read followed by a write
    /// leaves a window two instances admit through, and the ceiling is then a
    /// suggestion — worse under exactly the load it exists for.
    ///
    /// Idempotent per run: reserving a run that already holds a slot must
    /// succeed without taking a second, so a retried admission cannot consume
    /// two.
    ///
    /// # Errors
    ///
    /// [`QuotaError::TooManyRuns`] at the ceiling, or
    /// [`QuotaError::Unavailable`] if the store cannot be reached.
    async fn reserve(
        &self,
        run: RunId,
        limit: Option<u32>,
        at: Timestamp,
    ) -> Result<(), QuotaError>;

    /// Give back a reservation whose admission journal never landed. Idempotent.
    ///
    /// Normal pass completion MUST use [`settle`](Self::settle), which couples
    /// release to the receipt and spend transaction. This separate verb exists
    /// only for the pre-journal admission cleanup path.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn release(&self, run: RunId) -> Result<(), StoreError>;

    /// Stop work at `scope` from starting, or let it start again.
    ///
    /// `Some(reason)` halts; `None` lifts. The reason is required when halting
    /// because the next person to look will be someone else, possibly at 3am,
    /// and *why* is the whole question.
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
    async fn set_halt(&self, scope: &HaltScope, reason: Option<&str>) -> Result<(), StoreError>;

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
    /// The receipt, spend accrual, and admission-slot release MUST commit in one
    /// transaction. Repeating an identical settlement MUST succeed without
    /// accruing again. Reusing `(run, epoch)` with a different period, spend, or
    /// slot flag MUST fail as corruption: accepting it makes retries a way to
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

    /// What this tenant has spent in `period`.
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
}

/// Refuse a run whose tenant has already spent its ceiling.
///
/// Separate from the store so both backends share one comparison: two
/// implementations of "is this over the line" is two chances to get `>=` wrong,
/// and the one that is wrong is whichever nobody tested at the boundary.
///
/// # Errors
///
/// [`QuotaError::SpentOut`] when a ceiling is reached.
pub fn check_spend(
    tenant: &str,
    period: &str,
    quota: &TenantQuota,
    spent: Spend,
) -> Result<(), QuotaError> {
    if let Some(limit) = quota.max_tokens_per_period
        && spent.tokens >= limit
    {
        return Err(QuotaError::SpentOut {
            tenant: tenant.to_owned(),
            period: period.to_owned(),
            unit: "tokens",
            spent: spent.tokens,
            limit,
        });
    }
    if let Some(limit) = quota.max_minor_units_per_period
        && spent.minor_units >= limit
    {
        return Err(QuotaError::SpentOut {
            tenant: tenant.to_owned(),
            period: period.to_owned(),
            unit: "minor units",
            spent: spent.minor_units,
            limit,
        });
    }
    Ok(())
}
