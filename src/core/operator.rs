//! Who asked for an operator act, and what makes that name evidence.
//!
//! An operator act is one a person takes *about* the plane rather than through
//! it: throwing the emergency stop, placing a legal hold, cancelling a run,
//! deciding a quarantine. The runtime obeys each and can check none, so the
//! whole of its evidentiary weight is the name beside it — which makes *where
//! that name came from* part of the record rather than a detail of the call.
//!
//! # Why the basis is stored rather than inferred from the surface
//!
//! The same act arrives from an API caller an authenticator named and from
//! somebody who opened the store and typed a name. Both are legitimate — the
//! second is how an incident is handled when the plane itself is the problem —
//! and they are not the same evidence. A name alone collapses them, silently in
//! the direction that matters; recording only the authenticated ones and
//! leaving the rest blank is worse, because absence reads as an older record
//! rather than as a weaker claim.
//!
//! # Where a name may come from
//!
//! Never a request body. [`Basis::Authenticated`] is a claim the *call site*
//! makes — the type cannot see who is calling it — which is why it is a named
//! constructor a reviewer meets. What the type enforces is that a name exists
//! at all, so no act is on record attributed to nobody.

use serde::{Deserialize, Serialize};

/// What established the name on an operator act.
///
/// A closed vocabulary, spelled once, because it is written into records and
/// store rows that outlive this build.
///
/// The three differ in **what possession established the name**, which is the
/// only question a reader of an old record can still ask: a credential, a
/// connection, or the store itself. A fourth is foreseeable — an authority
/// withdrawn by a verified signal from the party that issued it is none of
/// these — and it stays absent until something produces one, because a variant
/// nothing constructs reads as a capability this runtime has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Basis {
    /// An authenticator verified a credential and this is the actor it named.
    ///
    /// The strong form. It is the only basis under which the name is evidence
    /// about a *person* rather than about whoever held a secret.
    Authenticated,
    /// Somebody with the store typed it.
    ///
    /// What this proves is narrower than it looks, and stating the narrow thing
    /// is the point: it is evidence that whoever ran the command could open the
    /// store, and the name is their own account of who that was. On the
    /// embedded backend it is the only basis available during the incident the
    /// stop exists for, because the process holding the file is the one being
    /// stopped.
    Asserted,
    /// The party on a connection this runtime accepted asked for it, and no
    /// credential named a person.
    ///
    /// The actor is a **channel** rather than somebody who can be asked about
    /// it — `mcp://client` for a host cancelling the task it started. Recording
    /// it as authenticated would claim an identity provider vouched for a name
    /// this runtime wrote itself; recording it as asserted would claim somebody
    /// typed it. What it proves is that whoever could open the connection
    /// asked, which is the same *kind* of claim the other two make and a
    /// weaker one than either.
    Connected,
}

impl Basis {
    /// The spelling every store and every record writes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::Asserted => "asserted",
            Self::Connected => "connected",
        }
    }

    /// The inverse of [`as_str`](Self::as_str), written over
    /// [`ALL`](Self::ALL) for the reason [`CaseStatus::parse`] is.
    ///
    /// [`CaseStatus::parse`]: crate::core::CaseStatus::parse
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|b| b.as_str() == s)
    }

    /// Every basis.
    pub const ALL: [Self; 3] = [Self::Authenticated, Self::Asserted, Self::Connected];

    /// The spellings, joined for a refusal a person reads.
    #[must_use]
    pub fn spellings() -> String {
        Self::ALL
            .iter()
            .map(|b| format!("'{}'", b.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl std::fmt::Display for Basis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a name was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperatorError {
    /// Nothing, or only whitespace.
    ///
    /// An act attributed to nobody is an act nobody can be asked about, and a
    /// blank is how that happens without anyone deciding it should.
    #[error("an operator act must name who asked for it")]
    Empty,

    /// Long enough to be a paste rather than a name.
    ///
    /// Bounded for the reason a tenant name is: it reaches store rows and
    /// record bodies, and an unbounded one is an unbounded row.
    #[error("an actor name is limited to {max} characters, and this one is {len}")]
    TooLong { len: usize, max: usize },

    /// A stored basis this build cannot name.
    ///
    /// Fails rather than defaulting, for the reason every decoder in this crate
    /// does: a basis read as the wrong one silently upgrades or downgrades what
    /// an act is worth, and the reader has no way to notice.
    #[error("'{basis}' is not a basis this build knows: one of {known}")]
    UnknownBasis { basis: String, known: String },
}

/// Who asked, and what established it.
///
/// # Deserialization is a constructor, and it takes the same door
///
/// `#[serde(try_from)]` rather than a derived `Deserialize`, because a derive
/// reaches the private field directly and would admit the empty name
/// [`authenticated`](Self::authenticated) exists to refuse. This value arrives
/// from a store row and from a journal record far more often than from a
/// constructor call, and a blank actor read back out of either is an act on
/// record with nobody attached. A type that documents an invariant while
/// deriving `Deserialize` enforces it on the rare path and not on the ones an
/// attacker or a damaged row takes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "OperatorWire")]
pub struct Operator {
    actor: String,
    basis: Basis,
}

/// The wire shape, carrying no invariant.
#[derive(Deserialize)]
struct OperatorWire {
    actor: String,
    basis: Basis,
}

impl TryFrom<OperatorWire> for Operator {
    type Error = OperatorError;

    fn try_from(w: OperatorWire) -> Result<Self, Self::Error> {
        Self::new(w.actor, w.basis)
    }
}

impl Operator {
    /// The longest an actor name may be.
    pub const MAX_LEN: usize = 256;

    /// An actor an authenticator named.
    ///
    /// The caller is asserting that this name came from a verified credential
    /// rather than from anything the requester supplied. Nothing here can check
    /// that, which is why it is a named constructor: a reviewer reading a call
    /// site sees the claim being made.
    ///
    /// # Errors
    ///
    /// [`OperatorError`] when the name is empty or over [`MAX_LEN`](Self::MAX_LEN).
    pub fn authenticated(actor: impl Into<String>) -> Result<Self, OperatorError> {
        Self::new(actor, Basis::Authenticated)
    }

    /// An actor somebody with the store typed.
    ///
    /// # Errors
    ///
    /// [`OperatorError`] when the name is empty or over [`MAX_LEN`](Self::MAX_LEN).
    pub fn asserted(actor: impl Into<String>) -> Result<Self, OperatorError> {
        Self::new(actor, Basis::Asserted)
    }

    /// The party on an accepted connection, named by the channel it arrived on.
    ///
    /// # Errors
    ///
    /// [`OperatorError`] when the name is empty or over [`MAX_LEN`](Self::MAX_LEN).
    pub fn connected(actor: impl Into<String>) -> Result<Self, OperatorError> {
        Self::new(actor, Basis::Connected)
    }

    fn new(actor: impl Into<String>, basis: Basis) -> Result<Self, OperatorError> {
        let actor = actor.into();
        if actor.trim().is_empty() {
            return Err(OperatorError::Empty);
        }
        if actor.len() > Self::MAX_LEN {
            return Err(OperatorError::TooLong {
                len: actor.len(),
                max: Self::MAX_LEN,
            });
        }
        Ok(Self { actor, basis })
    }

    /// Rebuild one from the two columns a store keeps.
    ///
    /// The one place a stored pair becomes a value, so four backends' decoders
    /// cannot drift on what an unknown basis means. Each caller frames the
    /// failure with its own table name; the rule itself lives here.
    ///
    /// # Errors
    ///
    /// [`OperatorError`] when the name is unusable or the basis is one this
    /// build does not know.
    pub fn from_parts(actor: impl Into<String>, basis: &str) -> Result<Self, OperatorError> {
        let basis = Basis::parse(basis).ok_or_else(|| OperatorError::UnknownBasis {
            basis: basis.to_owned(),
            known: Basis::spellings(),
        })?;
        Self::new(actor, basis)
    }

    /// The name on the record.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// What established it.
    #[must_use]
    pub const fn basis(&self) -> Basis {
        self.basis
    }
}

impl std::fmt::Display for Operator {
    /// `alice (authenticated)`.
    ///
    /// The basis is in the rendering rather than beside it because this string
    /// reaches listings and refusal messages, and the place a reader meets the
    /// name is the place they need to know what it is worth.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.actor, self.basis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_act_attributed_to_nobody_is_refused() {
        assert_eq!(Operator::authenticated(""), Err(OperatorError::Empty));
        assert_eq!(Operator::asserted("   "), Err(OperatorError::Empty));
    }

    #[test]
    fn a_deserialized_operator_takes_the_constructor_door() {
        let wire = serde_json::json!({ "actor": "", "basis": "authenticated" });
        assert!(
            serde_json::from_value::<Operator>(wire).is_err(),
            "a blank actor deserialized into a record: the derive reached the field"
        );
    }

    #[test]
    fn the_basis_survives_a_round_trip() {
        let op = Operator::asserted("alice").expect("a name");
        let text = serde_json::to_string(&op).expect("serializes");
        assert_eq!(serde_json::from_str::<Operator>(&text).expect("parses"), op);
        assert!(text.contains("asserted"), "{text}");
    }
}
