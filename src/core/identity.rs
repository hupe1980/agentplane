//! On whose behalf: workload identity and attenuating delegation.
//!
//! # The question the protocols cannot answer
//!
//! "Which agent did this" is answerable from a log line. "**On whose behalf**"
//! is not, and it is the one an auditor asks. A run that refunded €4,200 was
//! started by some agent, which was delegated to by another, which was
//! authorized by a person — and unless that chain is carried and recorded, the
//! answer is reconstructed from timestamps and hope.
//!
//! So a principal here is not a config string. It is a link in a chain that runs
//! from a human owner down to the workload actually calling a tool, and the
//! chain travels with the request and lands in the journal.
//!
//! # Attenuation is the property, not the credential format
//!
//! SPIFFE, WIMSE, AIP and the OAuth agent drafts are all still moving — 2026
//! Internet-Drafts, not RFCs. Binding the runtime to any of their wire formats
//! would mean a rewrite when they settle. What the runtime actually *depends on*
//! is one property they all provide:
//!
//! > **Scope is monotonically non-increasing.** A delegate can never hold more
//! > authority than its delegator.
//!
//! That is what [`Delegation::delegate`] enforces, and it is enforced at
//! construction rather than checked in review — a widened scope is not
//! representable, so there is no code path that has to remember to look. The
//! credential format sits behind [`DelegationScheme`]; swapping JWT for
//! something else is a driver change, not a redesign.
//!
//! # Verified once, then journaled
//!
//! A credential expires. Re-verifying a chain during replay would fail for any
//! run older than its tokens, so an audit of last year's decision would report a
//! problem that did not exist when the decision was made — and the obvious
//! "fix", skipping verification on replay, would let a forged chain in through
//! the audit path.
//!
//! The resolution is the one the effect protocol already gives, and the one
//! `core::policy` uses for the same reason: **verify at admission, journal the
//! result, read it back on replay.** The chain in `IdentityBound` is what
//! governed the run, and it stays true regardless of what has since expired.

use std::collections::BTreeSet;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::core::Capability;

/// What a principal is allowed to do.
///
/// A set of capability patterns. Two forms, and deliberately only two:
///
/// * `"billing.reconcile"` — exactly that capability.
/// * `"billing.*"` — that prefix and everything under it.
///
/// A richer grammar (regex, negation, conditions) is where scope stops being
/// *checkable* — attenuation has to be decidable by containment, and negation
/// makes containment undecidable in the general case. Conditions belong in the
/// policy engine, which is built to evaluate them; this is the part that must be
/// simple enough to be provably monotonic.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(BTreeSet<String>);

impl Scope {
    /// Authority over everything. The root of a chain, held by an owner.
    #[must_use]
    pub fn root() -> Self {
        Self(BTreeSet::from(["*".to_owned()]))
    }

    /// No authority at all.
    ///
    /// Not the same as [`Scope::root`] with nothing in it — an empty scope
    /// permits nothing, which is what an over-attenuated chain ends at.
    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Build from patterns.
    pub fn of<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(patterns.into_iter().map(Into::into).collect())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The patterns, in a stable order.
    ///
    /// Sorted, because this is hashed into the journal: a set that serialized in
    /// iteration order would give the same chain two different digests.
    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Whether one pattern covers a capability.
    ///
    /// `"billing.*"` covers `"billing.reconcile"` and `"billing"` itself, but
    /// **not** `"billingx.y"` — the boundary is a segment, not a character. A
    /// prefix match without that check is the classic authorization bug where
    /// `admin.*` also grants `administrator-override`.
    fn pattern_covers(pattern: &str, capability: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        let Some(prefix) = pattern.strip_suffix(".*") else {
            return pattern == capability;
        };
        capability == prefix
            || (capability.starts_with(prefix)
                && capability.as_bytes().get(prefix.len()) == Some(&b'.'))
    }

    /// Whether this scope permits a capability.
    #[must_use]
    pub fn permits(&self, capability: &Capability) -> bool {
        self.0
            .iter()
            .any(|p| Self::pattern_covers(p, &capability.0))
    }

    /// Whether this scope covers everything `other` covers.
    ///
    /// The attenuation test. `other` must be no wider than `self`, which means
    /// **every** pattern in `other` is covered by **some** pattern in `self`.
    ///
    /// A pattern covers another pattern when it covers everything that pattern
    /// could match — so `"billing.*"` contains `"billing.reconcile"`, and
    /// `"billing.reconcile"` does not contain `"billing.*"`.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        other.0.iter().all(|o| self.0.iter().any(|s| covers(s, o)))
    }
}

/// Whether pattern `a` covers everything pattern `b` can match.
///
/// Split out from [`Scope::contains`] because the wildcard-versus-wildcard case
/// is where this is easy to get wrong: `"billing.*"` covers `"billing.eu.*"`,
/// but `"billing.eu.*"` covers neither `"billing.*"` nor `"billing.fr"`.
fn covers(a: &str, b: &str) -> bool {
    if a == "*" {
        return true;
    }
    if b == "*" {
        // Only `*` covers `*`, and that was handled above.
        return false;
    }
    match (a.strip_suffix(".*"), b.strip_suffix(".*")) {
        // Both wildcards: a's prefix must be a segment-prefix of b's.
        (Some(pa), Some(pb)) => pb == pa || (pb.starts_with(pa) && pb.as_bytes()[pa.len()] == b'.'),
        // a is a wildcard, b is exact.
        (Some(_), None) => Scope::pattern_covers(a, b),
        // a is exact and b is a wildcard: an exact pattern can never cover a
        // family, however similar they look.
        (None, Some(_)) => false,
        // Both exact.
        (None, None) => a == b,
    }
}

/// One link in a delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Workload or human identity. A SPIFFE ID in practice, but opaque here —
    /// the runtime depends on attenuation, not on a naming scheme.
    pub id: String,
    /// What this link may do. Never wider than its delegator's.
    pub scope: Scope,
}

impl Principal {
    pub fn new(id: impl Into<String>, scope: Scope) -> Self {
        Self {
            id: id.into(),
            scope,
        }
    }
}

/// Why a delegation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DelegationError {
    /// The delegate asked for authority the delegator does not hold.
    ///
    /// Rejected at construction, not detected in review: this is the escalation
    /// the whole mechanism exists to make unrepresentable.
    #[error(
        "'{to}' would hold authority '{widened}' that its delegator '{from}' does not — \
         delegation may only narrow"
    )]
    ScopeWidened {
        from: String,
        to: String,
        widened: String,
    },

    /// The chain is longer than the manifest allows.
    ///
    /// A depth cap is not about scope; it bounds how far a request can travel
    /// from the human who authorized it before nobody can reason about it.
    #[error("delegation depth {depth} exceeds the limit of {max}")]
    TooDeep { depth: usize, max: usize },

    /// A chain arrived with no links, or with no owner at its root.
    #[error("delegation chain is empty: there is no principal to act as")]
    Empty,
}

/// A verified chain from a human owner down to the acting workload.
///
/// Constructed only through [`Delegation::root`] and [`Delegation::delegate`],
/// so **every value of this type has already been checked**. There is no
/// `Delegation::new(links)` that would let an unverified chain exist — the
/// invariant is carried by the type rather than by a function somebody has to
/// remember to call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Owner first, acting workload last.
    links: Vec<Principal>,
}

/// How deep a chain may go before nobody can reason about it.
///
/// Three is the shape §11.1 describes: owner → agent → sub-agent → peer. A
/// deployment can lower it; raising it is a decision someone should have to make
/// deliberately, which is why it is a constant here rather than a default that
/// quietly grows.
pub const MAX_DELEGATION_DEPTH: usize = 3;

impl Delegation {
    /// Start a chain at its owner.
    #[must_use]
    pub fn root(owner: Principal) -> Self {
        Self { links: vec![owner] }
    }

    /// Extend the chain, narrowing authority.
    ///
    /// # Errors
    ///
    /// [`DelegationError::ScopeWidened`] if the delegate asks for anything the
    /// delegator does not hold, and [`DelegationError::TooDeep`] past
    /// [`MAX_DELEGATION_DEPTH`].
    pub fn delegate(&self, to: Principal) -> Result<Self, DelegationError> {
        let from = self.subject();
        if !from.scope.contains(&to.scope) {
            let widened = to
                .scope
                .patterns()
                .find(|p| !from.scope.contains(&Scope::of([*p])))
                .unwrap_or("<unknown>")
                .to_owned();
            return Err(DelegationError::ScopeWidened {
                from: from.id.clone(),
                to: to.id,
                widened,
            });
        }
        if self.depth() + 1 > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::TooDeep {
                depth: self.depth() + 1,
                max: MAX_DELEGATION_DEPTH,
            });
        }
        let mut links = self.links.clone();
        links.push(to);
        Ok(Self { links })
    }

    /// The human at the root.
    #[must_use]
    pub fn owner(&self) -> &Principal {
        self.links.first().expect("a chain always has a root")
    }

    /// The workload actually acting. The policy principal.
    #[must_use]
    pub fn subject(&self) -> &Principal {
        self.links.last().expect("a chain always has a root")
    }

    /// Hops below the owner. A bare owner has depth 0.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.links.len() - 1
    }

    /// What this chain may actually do.
    ///
    /// The subject's scope, which by construction is already no wider than every
    /// link above it — so there is no intersection to compute here, and if there
    /// were, that would mean the invariant had been violated somewhere upstream.
    #[must_use]
    pub fn effective_scope(&self) -> &Scope {
        &self.subject().scope
    }

    /// The chain, owner first.
    pub fn links(&self) -> impl Iterator<Item = &Principal> {
        self.links.iter()
    }

    /// Rebuild a chain read back from the journal, re-checking it.
    ///
    /// Replay must not re-verify *credentials* — they expire, and a run older
    /// than its tokens would fail an audit for a problem that did not exist when
    /// the decision was made. But the *structural* property is timeless and
    /// costs nothing to confirm, so a journal that has been tampered into
    /// holding a widening chain is caught rather than trusted.
    ///
    /// # Errors
    ///
    /// If the recorded chain is empty, too deep, or widens at any hop.
    pub fn rehydrate(links: Vec<Principal>) -> Result<Self, DelegationError> {
        let mut it = links.into_iter();
        let root = it.next().ok_or(DelegationError::Empty)?;
        let mut chain = Self::root(root);
        for link in it {
            chain = chain.delegate(link)?;
        }
        Ok(chain)
    }
}

impl Delegation {
    /// The chain as policy context.
    ///
    /// §11.1 caps delegation depth "by manifest and by Cedar" — and a rule can
    /// only say `context.delegation_depth >= 3` if depth is actually in the
    /// context. Likewise a rule keyed on the human owner needs the owner, not
    /// just the workload that happens to be acting.
    #[must_use]
    pub fn as_context(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": self.owner().id,
            "subject": self.subject().id,
            "delegation_depth": self.depth(),
            "scope": self.effective_scope().patterns().collect::<Vec<_>>(),
        })
    }
}

/// Verifies a credential and produces the chain it asserts.
///
/// Behind a trait because AIP, WIMSE and the OAuth agent drafts are all still
/// Internet-Drafts: the credential format will change, and when it does this is
/// a driver swap rather than a redesign. What the runtime depends on is the
/// [`Delegation`] that comes out, whose attenuation is guaranteed by its own
/// constructors regardless of how it was obtained.
pub trait DelegationScheme: Send + Sync + Debug {
    /// Verify a presented credential.
    ///
    /// # Errors
    ///
    /// If the credential does not verify, or asserts a chain that widens.
    fn verify(&self, credential: &str) -> Result<Delegation, DelegationError>;
}
