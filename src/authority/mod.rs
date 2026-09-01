//! Standing authority: a ceiling that outlives a run and is narrower than a
//! tenant.
//!
//! # The gap this fills
//!
//! Two ceilings existed and neither has this shape. A [`Budget`] bounds **one
//! run**; a [`TenantQuota`] bounds **one tenant over a billing period**. Both
//! are resource controls — they answer *how much may this computation consume*.
//!
//! What neither answers is *how much was this **authorization** good for*. A
//! customer approves up to €500 of purchases. A purchase order covers three
//! draws against one supplier. A subscriber authorizes a recurring charge until
//! they cancel. Each is a ceiling that
//!
//! * spans many runs, so a per-run budget cannot hold it;
//! * is narrower than the tenant and has no billing period, so a quota cannot;
//! * is bound to an artifact somebody agreed to, and can be **revoked** when
//!   they change their mind.
//!
//! That last property is what makes this an authorization rather than a
//! throttle, and it is why this is not a third field on `TenantQuota`. A quota
//! that is exhausted refuses *for now*; a standing authority that is revoked
//! refuses *from here on*, and conflating them teaches a caller to retry a
//! decision that will never change — the same distinction [`QuotaError`] draws
//! against a policy denial.
//!
//! [`Budget`]: crate::core::Budget
//! [`TenantQuota`]: crate::quota::TenantQuota
//! [`QuotaError`]: crate::quota::QuotaError
//!
//! # Drawing is an effect, and it has to be
//!
//! The remaining balance is mutable state outside the journal. Reading it inside
//! the deterministic zone would make a replay depend on what the store happens
//! to hold *now*: a run replayed after a later draw would see a different
//! balance, reach a different verdict, and produce a history that disagrees with
//! itself. So [`StepCtx::draw`] journals the draw, and replay reads the recorded
//! receipt rather than consuming again.
//!
//! [`StepCtx::draw`]: crate::runtime::StepCtx::draw
//!
//! # Idempotent by *dispatch* identifier — not by effect key, and not by amount
//!
//! A draw is a mutation, so a retry has to be safe. The store keys each draw by
//! the identifier of the logical call that made it and returns the original
//! receipt for a repeat, which is the same shape as the journal's own
//! exactly-once guarantee and works for the same reason: a read-then-write
//! leaves a window two instances draw through, and that window is the whole
//! guarantee when a ceiling is nearly spent.
//!
//! Which identifier is load-bearing, and the two wrong answers are instructive.
//!
//! * **The effect key** hashes the attempt number — it must, or a retry would
//!   collide with the journaled failure before it and replay would read back the
//!   failure. That makes it exactly wrong here: two attempts at one draw would
//!   carry two keys and consume the authority twice. The type below is still an
//!   [`EffectKey`], because [`Provenance::dispatch`] is one — it is the same key
//!   with the attempt pinned to zero. Same type, different question.
//! * **The amount** would collapse two legitimate €20 draws against one
//!   authority into one.
//!
//! [`Provenance::dispatch`]: crate::core::Provenance::dispatch
//!
//! # What this is not
//!
//! It is not a payments protocol, an escrow, or a settlement record. It holds no
//! payment instrument and speaks no wire. It is the ceiling and the revocation —
//! the part a runtime can enforce — and it is deliberately domain-neutral so a
//! purchase mandate, a spend envelope and a support-credit allowance are one
//! mechanism rather than three.

use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::core::{EffectKey, Spend, StoreError, Timestamp};

/// Identifies one standing authority.
///
/// Opaque to this crate: a mandate id, an approval reference, a purchase-order
/// number. It is stored per tenant, so two tenants may use the same string
/// without colliding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityId(pub String);

impl AuthorityId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AuthorityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What somebody authorized, and how far it goes.
///
/// Issued once and thereafter immutable: the ceiling a person agreed to must not
/// be editable under them, or the record of what they agreed to is worth
/// nothing. Changing a ceiling means revoking this authority and issuing
/// another, which leaves both on the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingAuthority {
    pub id: AuthorityId,
    /// Why this exists, in the issuer's terms — an approval reference, a
    /// mandate id, a ticket.
    ///
    /// Required, and required to be non-empty. An authority with no stated basis
    /// is a ceiling nobody can trace to a decision, which is the thing an audit
    /// asks for first.
    pub basis: String,
    /// The total this authority is good for, across every draw.
    pub ceiling: Spend,
    /// How many draws it permits, if the issuer bounded that too.
    ///
    /// Separate from the ceiling because they bound different abuses: a spend
    /// ceiling stops one large wrong charge, a draw count stops a thousand small
    /// ones that never reach it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_draws: Option<u32>,
    /// When it stops being drawable, if it expires.
    ///
    /// Evaluated against the run's **journaled** clock, never an ambient one, so
    /// a replay reaches the same verdict as the live run did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

impl StandingAuthority {
    /// Issue an authority for `ceiling`, stating why it exists.
    #[must_use]
    pub fn new(id: impl Into<String>, basis: impl Into<String>, ceiling: Spend) -> Self {
        Self {
            id: AuthorityId::new(id),
            basis: basis.into(),
            ceiling,
            max_draws: None,
            expires_at: None,
        }
    }

    /// Bound how many times it may be drawn on.
    #[must_use]
    pub const fn max_draws(mut self, n: u32) -> Self {
        self.max_draws = Some(n);
        self
    }

    /// Stop it being drawable after `at`.
    #[must_use]
    pub const fn expires_at(mut self, at: Timestamp) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Whether the declaration is well formed.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Malformed`] for an empty id or basis, or a ceiling of
    /// nothing. A zero ceiling is refused rather than treated as unlimited: the
    /// two readings are opposite, and a format that guesses between them is one
    /// whose meaning changes under you.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        if self.id.as_str().trim().is_empty() {
            return Err(AuthorityError::Malformed("the authority has no id"));
        }
        if self.basis.trim().is_empty() {
            return Err(AuthorityError::Malformed(
                "the authority states no basis — a ceiling nobody can trace to a decision \
                 is the thing an audit asks for first",
            ));
        }
        if self.ceiling.is_zero() {
            return Err(AuthorityError::Malformed(
                "the authority permits nothing — issue a ceiling, or do not issue it. \
                 Zero and unlimited are opposite readings of the same silence",
            ));
        }
        Ok(())
    }
}

/// What one authority has consumed, and whether it still stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityState {
    pub authority: StandingAuthority,
    /// The sum of every draw taken so far.
    pub drawn: Spend,
    pub draws: u32,
    /// Set when somebody withdrew it, with their reason.
    ///
    /// Kept rather than deleted: an authority that vanishes on revocation takes
    /// the record of what it once permitted with it, and that record is what an
    /// audit of the draws already taken depends on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Revocation>,
}

impl AuthorityState {
    /// What is left, floored at zero on both axes.
    #[must_use]
    pub fn remaining(&self) -> Spend {
        Spend {
            tokens: self
                .authority
                .ceiling
                .tokens
                .saturating_sub(self.drawn.tokens),
            minor_units: self
                .authority
                .ceiling
                .minor_units
                .saturating_sub(self.drawn.minor_units),
        }
    }
}

/// Why an authority was withdrawn, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub at: Timestamp,
    /// Required, for the same reason a halt's reason is: the next person to look
    /// is somebody else, and *why* is the whole question.
    pub reason: String,
}

/// One draw, as the store recorded it.
///
/// Returned by a live draw *and* read back on replay, so a skill sees the same
/// value either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drawn {
    pub authority: AuthorityId,
    pub amount: Spend,
    /// What remained **after** this draw, so the receipt answers "how much is
    /// left" without a second read that a replay could not reproduce.
    pub remaining: Spend,
    pub draws: u32,
}

/// Why a draw was refused.
///
/// Each variant is a different instruction to the caller, which is the whole
/// reason they are not one error with a message: exhausted and revoked look
/// identical in prose and mean opposite things about whether to try again.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorityError {
    /// No such authority for this tenant.
    #[error(
        "no standing authority '{0}' — it was never issued, or it belongs to \
         another tenant"
    )]
    Unknown(AuthorityId),

    /// The draw would exceed what was authorized.
    ///
    /// Reports the whole arithmetic rather than a bare refusal: an operator
    /// reconciling this needs to know what was asked against what was left.
    #[error(
        "standing authority '{authority}' has {remaining:?} left and the draw asked \
         for {asked:?} — this does not replenish; issue another authority if more \
         was intended"
    )]
    Exhausted {
        authority: AuthorityId,
        asked: Spend,
        remaining: Spend,
    },

    /// It permitted a number of draws and they are used up.
    #[error(
        "standing authority '{authority}' permitted {allowed} draws and has taken \
         them all"
    )]
    DrawsSpent {
        authority: AuthorityId,
        allowed: u32,
    },

    /// Somebody withdrew it.
    ///
    /// **Not retryable, ever.** Distinct from [`Exhausted`](Self::Exhausted)
    /// because that one could in principle be followed by a larger authority,
    /// while this one is a decision that has been taken back.
    #[error("standing authority '{authority}' was revoked: {reason}")]
    Revoked {
        authority: AuthorityId,
        reason: String,
    },

    /// It ran out of time rather than out of ceiling.
    #[error("standing authority '{authority}' expired at {expired_at}")]
    Expired {
        authority: AuthorityId,
        expired_at: Timestamp,
    },

    /// The declaration itself is not well formed.
    #[error("the standing authority is not well formed: {0}")]
    Malformed(&'static str),

    /// Re-issuing an id under a different declaration.
    ///
    /// Refused rather than overwritten: an id that can be redefined makes every
    /// draw already recorded against it refer to terms nobody can reconstruct.
    /// Re-issuing the *identical* declaration succeeds, because a retried
    /// deployment is not an attack.
    #[error(
        "standing authority '{0}' is already issued with different terms — a \
         ceiling somebody agreed to must not be editable under them; revoke it \
         and issue another"
    )]
    AlreadyIssued(AuthorityId),

    /// The store could not be reached.
    #[error("the standing-authority store is unavailable: {0}")]
    Unavailable(String),
}

impl From<StoreError> for AuthorityError {
    fn from(e: StoreError) -> Self {
        Self::Unavailable(e.to_string())
    }
}

/// Durable accounting for standing authorities.
///
/// In the store rather than the process for the same reason quotas are: an
/// in-memory balance fails **open** the moment a second instance starts, which
/// is exactly when a shared ceiling was needed.
#[async_trait]
pub trait AuthorityStore: Send + Sync + Debug {
    /// Which tenant this handle's standing authorities belong to.
    fn tenant(&self) -> &str;

    /// Record a new authority.
    ///
    /// Idempotent for an identical re-issue and refused for a differing one —
    /// see [`AuthorityError::AlreadyIssued`].
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Malformed`] if the declaration is unsound,
    /// [`AuthorityError::AlreadyIssued`] on a conflicting re-issue, or
    /// [`AuthorityError::Unavailable`].
    async fn issue(&self, authority: &StandingAuthority) -> Result<(), AuthorityError>;

    /// Consume `amount`, or refuse and consume nothing.
    ///
    /// **Must check and accumulate in one transaction.** A read followed by a
    /// write leaves a window two instances draw through, and that window is the
    /// entire guarantee when an authority is nearly spent.
    ///
    /// **Must be idempotent by `key`.** A retried draw returns the original
    /// receipt without consuming again; a partially-applied retry would spend a
    /// customer's authorization twice for one purchase.
    ///
    /// `at` is the run's journaled instant, so expiry is evaluated against
    /// history rather than against whatever the store's clock says now.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] naming which of the five refusals applies.
    async fn draw(
        &self,
        id: &AuthorityId,
        key: EffectKey,
        amount: Spend,
        at: Timestamp,
    ) -> Result<Drawn, AuthorityError>;

    /// Withdraw it. Idempotent; the first reason stands.
    ///
    /// The first reason stands because a later revocation of an
    /// already-revoked authority is a retry, and overwriting would lose the
    /// account of why it was withdrawn in the first place.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Unknown`] or [`AuthorityError::Unavailable`].
    async fn revoke(
        &self,
        id: &AuthorityId,
        reason: &str,
        at: Timestamp,
    ) -> Result<(), AuthorityError>;

    /// What this authority permitted and has consumed.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn state(&self, id: &AuthorityId) -> Result<Option<AuthorityState>, StoreError>;
}

/// The five refusals, in the order they must be asked.
///
/// Public because it is the contract, not an implementation detail. An embedder
/// writing [`AuthorityStore`] for their own database needs exactly this
/// decision, and having each backend re-derive it is precisely how two of them
/// come to disagree about what a revoked authority does. The shipped redb and
/// `PostgreSQL` backends both call this; a third should too.
///
/// What a backend still owns is the part this cannot do: reading the balance and
/// writing the result **atomically**. That is where the two shipped backends
/// genuinely differ, and it is not expressible here.
///
/// # Errors
///
/// Whichever of [`AuthorityError::Revoked`], [`Expired`](AuthorityError::Expired),
/// [`DrawsSpent`](AuthorityError::DrawsSpent) or
/// [`Exhausted`](AuthorityError::Exhausted) applies. Returns what remains when
/// the draw is permitted, so a caller does not compute the remainder twice and
/// risk the two disagreeing.
///
/// The **ordering is the design**. Revocation and expiry come before the
/// balance, because "you took this back" and "this ran out of time" are answers
/// a caller must not be able to mistake for "ask for less" — a caller told
/// `Exhausted` may reasonably retry with a smaller amount, and against a revoked
/// authority that is a loop.
pub fn permits(
    authority: &StandingAuthority,
    amount: Spend,
    drawn: Spend,
    taken: u32,
    revoked: Option<&str>,
    now: i64,
) -> Result<Spend, AuthorityError> {
    let id = || authority.id.clone();

    if let Some(reason) = revoked {
        return Err(AuthorityError::Revoked {
            authority: id(),
            reason: reason.to_owned(),
        });
    }
    // Against the run's journaled instant, never the store's clock: a replay has
    // to reach the same verdict the live run did.
    if let Some(expires) = authority.expires_at
        && now >= expires.unix_timestamp()
    {
        return Err(AuthorityError::Expired {
            authority: id(),
            expired_at: expires,
        });
    }
    if let Some(allowed) = authority.max_draws
        && taken >= allowed
    {
        return Err(AuthorityError::DrawsSpent {
            authority: id(),
            allowed,
        });
    }

    let remaining = Spend {
        tokens: authority.ceiling.tokens.saturating_sub(drawn.tokens),
        minor_units: authority
            .ceiling
            .minor_units
            .saturating_sub(drawn.minor_units),
    };
    // Both axes, and either one exceeding refuses the whole draw. A draw that
    // took the money and declined the tokens would leave the caller having spent
    // something it was told it had not.
    if amount.tokens > remaining.tokens || amount.minor_units > remaining.minor_units {
        return Err(AuthorityError::Exhausted {
            authority: id(),
            asked: amount,
            remaining,
        });
    }
    Ok(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sound() -> StandingAuthority {
        StandingAuthority::new("mandate-42", "approval:SET-42", Spend::money(50_000))
    }

    /// Every rule `validate` enforces, each with the case it rejects.
    ///
    /// A validator with only a happy-path test is one that could `Ok(())`
    /// unconditionally and stay green.
    #[test]
    fn a_malformed_authority_is_refused_and_a_sound_one_is_not() {
        sound().validate().expect("the baseline is sound");

        let mut no_id = sound();
        no_id.id = AuthorityId::new("  ");
        assert!(matches!(
            no_id.validate(),
            Err(AuthorityError::Malformed(_))
        ));

        let mut no_basis = sound();
        no_basis.basis = "\t".to_owned();
        assert!(matches!(
            no_basis.validate(),
            Err(AuthorityError::Malformed(_))
        ));

        let mut nothing = sound();
        nothing.ceiling = Spend::default();
        assert!(
            matches!(nothing.validate(), Err(AuthorityError::Malformed(_))),
            "a zero ceiling must be refused, not read as unlimited"
        );
    }

    /// `remaining` floors at zero rather than reporting a negative balance.
    ///
    /// The store refuses an over-draw, so `drawn > ceiling` should be
    /// unreachable — which is exactly why this is worth pinning. If it ever
    /// becomes reachable, a wrapped subtraction would report an authority with
    /// billions remaining, and the ceiling would stop being one.
    #[test]
    fn remaining_never_reports_more_than_was_authorized() {
        let state = AuthorityState {
            authority: sound(),
            drawn: Spend::money(50_001),
            draws: 1,
            revoked: None,
        };
        assert_eq!(state.remaining(), Spend::default());

        let half = AuthorityState {
            authority: sound(),
            drawn: Spend::money(20_000),
            draws: 1,
            revoked: None,
        };
        assert_eq!(half.remaining(), Spend::money(30_000));
    }
}
