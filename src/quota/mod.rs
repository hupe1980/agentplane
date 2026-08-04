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
    pub max_minor_units_per_period: Option<i64>,
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
        spent: i64,
        limit: i64,
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

    /// Give the slot back. Idempotent.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn release(&self, run: RunId) -> Result<(), StoreError>;

    /// Add to what this tenant has spent in `period`.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn accrue(&self, period: &str, spend: Spend) -> Result<(), StoreError>;

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
            spent: i64::try_from(spent.tokens).unwrap_or(i64::MAX),
            limit: i64::try_from(limit).unwrap_or(i64::MAX),
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
