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
//! > **Authority is monotonically non-increasing.** A delegate can never hold
//! > more than its delegator — not a wider scope, not a later expiry, not
//! > another audience.
//!
//! That is what [`Delegation::delegate`] enforces, over all three axes, and it
//! is enforced at construction rather than checked in review — a widened link
//! is not representable, so there is no code path that has to remember to
//! look. The credential format is the authenticator's business: whatever
//! parses a bearer token, a JWT or a signed gateway header hands the runtime a
//! [`Delegation`], and the chain's own constructors guarantee the property
//! however it was obtained.
//!
//! # Three bounds, and where each is checked
//!
//! * **Scope** — what the chain may do. Structural: checked at every hop and
//!   again at admission against the plan, which is the authorization graph.
//! * **Validity** — until when. [`Principal::not_after`] attenuates like
//!   scope (a delegate may not outlive its delegator), and the *effective*
//!   instant is compared against the admission clock once, by
//!   [`Delegation::admissible`]. Never re-checked on replay: see below.
//! * **Audience** — for which plane. [`Principal::audience`] names the tenant
//!   a link is spendable at; a chain naming one is refused by every other
//!   plane, so a credential minted for `acme` cannot be presented to `globex`
//!   and act there. A chain naming none is admitted anywhere — absence is
//!   absence, not a wildcard somebody chose, and a deployment that needs the
//!   bound sets it in the token or the credential it issues.
//!
//! A chain is **per request, never per plane.** The plane's own chain
//! (`RuntimeBuilder::acting_as`) is the identity a run acts under when the
//! embedder starts it in-process; a served surface admits each run under the
//! chain its authenticated caller presented (`RunTerms::acting_as`), because a
//! plane that bound its own chain to every peer's run would be an ambient
//! credential — every caller acting as the owner, and "on whose behalf"
//! answered with the same name for all of them.
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

use serde::{Deserialize, Serialize};

use crate::core::{Capability, Timestamp, format_timestamp};

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
///
/// Three bounds ride on a link, and every one of them attenuates through
/// [`Delegation::delegate`]: a delegate's scope is inside its delegator's, its
/// expiry is no later, and its audience is the same one or none. The two
/// optional bounds are **absent, never null**, on the wire — a chain written
/// before they existed reads back as one that declares neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Workload or human identity. A SPIFFE ID in practice, but opaque here —
    /// the runtime depends on attenuation, not on a naming scheme.
    pub id: String,
    /// What this link may do. Never wider than its delegator's.
    pub scope: Scope,
    /// The plane this link is spendable at, as a tenant name.
    ///
    /// A credential minted for one plane and presented to another is the
    /// replay every audience claim exists to stop, so a chain naming an
    /// audience is admitted only by the plane it names. `None` inherits the
    /// delegator's; a chain in which nobody names one is admitted anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The instant after which this link no longer authorizes anything.
    ///
    /// Compared against the admission clock exactly once, at admission — a run
    /// admitted under a live chain stays a valid run after the chain expires,
    /// which is why replay reads the chain back instead of re-judging it.
    /// `None` inherits the delegator's, and a chain in which nobody names one
    /// never expires by itself.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub not_after: Option<Timestamp>,
}

impl Principal {
    pub fn new(id: impl Into<String>, scope: Scope) -> Self {
        Self {
            id: id.into(),
            scope,
            audience: None,
            not_after: None,
        }
    }

    /// Bind this link to one plane.
    #[must_use]
    pub fn for_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Bound this link in time.
    #[must_use]
    pub const fn until(mut self, not_after: Timestamp) -> Self {
        self.not_after = Some(not_after);
        self
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

    /// The delegate would outlive its delegator.
    ///
    /// The same rule as scope, on the time axis: a link that expires later
    /// than the one above it holds authority its delegator will no longer
    /// have, which is how a short-lived credential buys a long-lived one.
    #[error(
        "'{to}' would stay valid until {delegate_until}, later than its delegator '{from}' \
         ({delegator_until}) — delegation may only narrow"
    )]
    ValidityWidened {
        from: String,
        to: String,
        delegator_until: String,
        delegate_until: String,
    },

    /// The delegate names a plane its delegator was not issued for.
    ///
    /// An audience is a bound on *where* a chain may be spent. A delegate
    /// naming a different one would carry its delegator's authority to a plane
    /// the delegator never held it at.
    #[error(
        "'{to}' names audience '{delegate_audience}' but its delegator '{from}' is bound to \
         '{delegator_audience}' — delegation may only narrow"
    )]
    AudienceWidened {
        from: String,
        to: String,
        delegator_audience: String,
        delegate_audience: String,
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

    /// The chain's validity ended before this run was admitted.
    ///
    /// A refusal at admission only — never on replay, where the recorded chain
    /// is history rather than a credential being presented.
    #[error(
        "delegation to '{subject}' expired at {not_after}; this admission is at {at} — \
         obtain a fresh credential rather than retrying"
    )]
    Expired {
        subject: String,
        not_after: String,
        at: String,
    },

    /// The chain was issued for another plane.
    ///
    /// Nothing about the chain is wrong; it is being spent where it must not
    /// be. The presented credential names an audience, and this is not it.
    #[error(
        "delegation to '{subject}' is bound to audience '{audience}' and cannot act on \
         plane '{plane}'"
    )]
    WrongAudience {
        subject: String,
        audience: String,
        plane: String,
    },
}

/// A verified chain from a human owner down to the acting workload.
///
/// Constructed only through [`Delegation::root`], [`Delegation::delegate`] and
/// [`Delegation::rehydrate`], so **every value of this type has already been
/// checked**. There is no `Delegation::new(links)` that would let an unverified
/// chain exist — the invariant is carried by the type rather than by a function
/// somebody has to remember to call.
///
/// # Deserialization is one of those constructors
///
/// `#[serde(try_from)]` rather than a derived `Deserialize`, which would reach
/// the fields directly and *be* the `new(links)` this type refuses to offer.
/// The claim above is what the rest of the crate spends: an authenticator
/// parses credentials into chains, and a chain also arrives from a journal
/// record and from a peer. A derive would let any of
/// them assert a chain that widens at a hop — [`I6`] inverted, through the one
/// door nobody reads as a door.
///
/// The owner is a field rather than the head of a list for the same reason: a
/// `Vec` that must be non-empty delegates the invariant to whoever remembers to
/// check, and the accessors below would each need an `expect` that a hostile
/// record could reach.
///
/// [`I6`]: https://hupe1980.github.io/agentplane/docs/security/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "DelegationWire", try_from = "DelegationWire")]
pub struct Delegation {
    /// The human the whole chain descends from.
    root: Principal,
    /// Each narrowing hop below the owner, delegator first.
    rest: Vec<Principal>,
}

/// The wire form of a [`Delegation`]: the links, in order, owner first.
///
/// A shape `serde` can build that is not yet a chain. Everything that turns one
/// into the other goes through [`Delegation::rehydrate`], so the structural
/// property is re-established on every read rather than assumed from the fact
/// that something wrote it.
#[derive(Serialize, Deserialize)]
struct DelegationWire {
    links: Vec<Principal>,
}

impl From<Delegation> for DelegationWire {
    fn from(chain: Delegation) -> Self {
        Self {
            links: chain.links().cloned().collect(),
        }
    }
}

impl TryFrom<DelegationWire> for Delegation {
    type Error = DelegationError;

    fn try_from(wire: DelegationWire) -> Result<Self, Self::Error> {
        Self::rehydrate(wire.links)
    }
}

/// How deep a chain may go before nobody can reason about it.
///
/// Three is the shape the research converges on: owner → agent → sub-agent →
/// peer. A
/// deployment can lower it; raising it is a decision someone should have to make
/// deliberately, which is why it is a constant here rather than a default that
/// quietly grows.
pub const MAX_DELEGATION_DEPTH: usize = 3;

impl Delegation {
    /// Start a chain at its owner.
    #[must_use]
    pub fn root(owner: Principal) -> Self {
        Self {
            root: owner,
            rest: Vec::new(),
        }
    }

    /// Extend the chain, narrowing authority.
    ///
    /// Narrowing is checked on every axis a link carries: the delegate's scope
    /// must be inside the delegator's, its expiry no later than the chain's
    /// effective one, and its audience either unset or the chain's own. A
    /// delegate that sets a bound the chain had not set is narrowing, which
    /// is always permitted.
    ///
    /// # Errors
    ///
    /// [`DelegationError::ScopeWidened`] if the delegate asks for anything the
    /// delegator does not hold, [`DelegationError::ValidityWidened`] if it
    /// would outlive the chain, [`DelegationError::AudienceWidened`] if it
    /// names a plane the chain is not bound to, and
    /// [`DelegationError::TooDeep`] past [`MAX_DELEGATION_DEPTH`].
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
        if let (Some(delegator_until), Some(delegate_until)) = (self.not_after(), to.not_after)
            && delegate_until > delegator_until
        {
            return Err(DelegationError::ValidityWidened {
                from: from.id.clone(),
                to: to.id,
                delegator_until: format_timestamp(delegator_until),
                delegate_until: format_timestamp(delegate_until),
            });
        }
        if let (Some(delegator_audience), Some(delegate_audience)) =
            (self.audience(), to.audience.as_deref())
            && delegate_audience != delegator_audience
        {
            return Err(DelegationError::AudienceWidened {
                from: from.id.clone(),
                to: to.id,
                delegator_audience: delegator_audience.to_owned(),
                delegate_audience: delegate_audience.to_owned(),
            });
        }
        if self.depth() + 1 > MAX_DELEGATION_DEPTH {
            return Err(DelegationError::TooDeep {
                depth: self.depth() + 1,
                max: MAX_DELEGATION_DEPTH,
            });
        }
        let mut next = self.clone();
        next.rest.push(to);
        Ok(next)
    }

    /// The human at the root.
    #[must_use]
    pub const fn owner(&self) -> &Principal {
        &self.root
    }

    /// The workload actually acting. The policy principal.
    ///
    /// The last hop, or the owner when nobody has been delegated to yet.
    #[must_use]
    pub fn subject(&self) -> &Principal {
        self.rest.last().unwrap_or(&self.root)
    }

    /// Hops below the owner. A bare owner has depth 0.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.rest.len()
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
        std::iter::once(&self.root).chain(self.rest.iter())
    }

    /// The instant the chain stops authorizing anything, if any link set one.
    ///
    /// The earliest across the chain — which, by construction, is the
    /// innermost link that names one, since a delegate may not outlive its
    /// delegator. Computed as the minimum anyway, so the answer does not
    /// depend on the attenuation check having run.
    #[must_use]
    pub fn not_after(&self) -> Option<Timestamp> {
        self.links().filter_map(|link| link.not_after).min()
    }

    /// The plane this chain is spendable at, if any link bound one.
    ///
    /// Every link that names an audience names the same one — that is what
    /// [`delegate`](Self::delegate) enforces — so the first is the answer.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.links().find_map(|link| link.audience.as_deref())
    }

    /// Whether this chain may act on `plane` at `at`.
    ///
    /// The one clocked check, and it belongs to admission alone: a run
    /// admitted under a live chain is governed by it for good, and replay
    /// reads the recorded chain back rather than asking this again. Both
    /// bounds are enforced only where a link declared them — a chain naming
    /// no audience acts anywhere, one naming no expiry never lapses.
    ///
    /// # Errors
    ///
    /// [`DelegationError::Expired`] once the chain's effective `not_after`
    /// has passed, and [`DelegationError::WrongAudience`] when the chain is
    /// bound to a plane other than this one.
    pub fn admissible(&self, plane: &str, at: Timestamp) -> Result<(), DelegationError> {
        if let Some(not_after) = self.not_after()
            && at >= not_after
        {
            return Err(DelegationError::Expired {
                subject: self.subject().id.clone(),
                not_after: format_timestamp(not_after),
                at: format_timestamp(at),
            });
        }
        if let Some(audience) = self.audience()
            && audience != plane
        {
            return Err(DelegationError::WrongAudience {
                subject: self.subject().id.clone(),
                audience: audience.to_owned(),
                plane: plane.to_owned(),
            });
        }
        Ok(())
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
    /// If the recorded chain is empty, too deep, or widens at any hop — in
    /// scope, validity or audience.
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
    /// Depth is capped both by manifest and by policy — and a rule can
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
