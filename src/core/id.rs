//! Identifiers, digests, and the hash-chain primitive.
//!
//! ULIDs are used for run and case ids because they are lexicographically
//! sortable: a journal scan for one run is a range scan, and cases sort by
//! creation time for free.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};

/// Wall-clock instant. Only ever obtained through a journaled effect
/// (`StepCtx::now`), never by reading the ambient clock.
pub type Timestamp = time::OffsetDateTime;

/// Per-run monotonic journal position, starting at 1.
pub type Seq = u64;

/// Ownership fencing epoch.
///
/// Every journal append carries the writer's epoch and the store rejects stale
/// epochs *in the same transaction that writes*, so a paused or partitioned
/// instance that wakes up and keeps writing is fenced by the store rather than
/// by timing. Split-brain cannot corrupt the chain by construction.
pub type Epoch = u64;

macro_rules! ulid_newtype {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub ulid::Ulid);

        impl $name {
            /// Mint a fresh id from a monotonic source.
            ///
            /// Reserved for the runtime's admission path, which journals the
            /// result. Skills must never call this — see `clippy.toml`.
            #[allow(clippy::disallowed_methods)]
            #[must_use]
            pub fn generate() -> Self {
                Self(ulid::Ulid::new())
            }

            /// Reconstruct from a stored string.
            ///
            /// Accepts both the prefixed form produced by [`std::fmt::Display`]
            /// (`run_01J8Z…`) and a bare ULID, so ids round-trip through logs,
            /// URLs, and database columns without the caller having to know
            /// which form it is holding.
            pub fn parse(s: &str) -> Result<Self, ulid::DecodeError> {
                let bare = s.strip_prefix(concat!($prefix, "_")).unwrap_or(s);
                ulid::Ulid::from_string(bare).map(Self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self}")
            }
        }
    };
}

ulid_newtype!(
    /// A single execution: one goal, one plan, one lifetime.
    ///
    /// Runs stay short *by design* — longevity lives in the [`CaseId`], so a
    /// six-week business process never pins a code version.
    RunId, "run"
);

ulid_newtype!(
    /// A long-lived, correlated business fact spanning many runs and weeks.
    CaseId, "case"
);

ulid_newtype!(
    /// One business act made of many independent ones.
    ///
    /// Owns N runs sharing one frozen plan — see [`crate::batch`]. Distinct from
    /// a [`CaseId`] because the relationship is different in kind: a case is a
    /// matter that several runs *touch* over weeks, while a batch is a single
    /// act that several runs *constitute* in one pass.
    BatchId, "batch"
);

/// Position of a step within a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StepId(pub u32);

impl fmt::Display for StepId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// SHA-256 over an artifact's canonical serialization.
///
/// Also the hash-chain link type. [`Digest::chain`] is the only way to extend a
/// chain, and it hashes `prev ‖ bytes` — where `bytes` are the record's *wire*
/// bytes, never a re-serialized or upcast form. Rehashing after an upcast would
/// destroy tamper evidence for all history the moment a schema changed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The chain's genesis link.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Hash a byte string.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(h.finalize().into())
    }

    /// Extend a hash chain: `H(prev ‖ bytes)`.
    #[must_use]
    pub fn chain(prev: Self, bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(prev.0);
        h.update(bytes);
        Self(h.finalize().into())
    }

    #[must_use]
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }

    /// First 8 hex chars — enough to identify a record in a log line.
    #[must_use]
    pub fn short(self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}…", self.short())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

/// Stable identity of one effect within one run.
///
/// `H(step ‖ ordinal ‖ kind ‖ canonical(args))`. Two properties follow:
///
/// * **Exactly-once** — the store's unique index on `(run_id, effect_key)` makes
///   "an effect is started at most once per run" a database invariant.
/// * **Divergence detection** — on replay the key is recomputed from the
///   deterministic zone. A mismatch means the code took a different path than
///   the recorded one, and the run is quarantined rather than allowed to
///   silently diverge.
///
/// Skills never construct these: the runtime derives the key from the effect's
/// descriptor plus its position, so a skill cannot forge or collide one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EffectKey(Digest);

/// Which pass of a step an effect belongs to.
///
/// A step can run twice for entirely legitimate reasons: once going forward,
/// and once again in reverse when a later step fails and the saga unwinds. The
/// two are different work with different effects, and the journal has to be
/// able to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Doing the work.
    #[default]
    Forward,
    /// Undoing it.
    Compensating,
}

impl Phase {
    #[must_use]
    pub const fn is_forward(self) -> bool {
        matches!(self, Self::Forward)
    }

    /// By-reference form, for `skip_serializing_if`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[must_use]
    pub const fn is_forward_ref(v: &Self) -> bool {
        v.is_forward()
    }
}

impl EffectKey {
    /// `phase` separates the forward pass from the compensating one.
    ///
    /// Without it a step's compensation would restart its ordinal at zero and
    /// collide with the step's own forward effects: replay would read the
    /// forward result back as the compensation's, and the store's uniqueness
    /// constraint would reject the second announcement.
    ///
    /// `attempt` is 1-based and part of the identity, so a retry is a *new*
    /// effect in the journal rather than a second record under an existing key.
    ///
    /// Without it, attempt 2 would collide with attempt 1's recorded failure:
    /// replay would read back the failure instead of the retry that followed,
    /// and the store's uniqueness constraint on `EffectStarted` would reject
    /// the second attempt outright.
    pub(crate) fn derive(
        step: StepId,
        phase: Phase,
        ordinal: u32,
        attempt: u32,
        kind: &str,
        canonical_args: &[u8],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(step.0.to_be_bytes());
        h.update([phase as u8]);
        h.update(ordinal.to_be_bytes());
        h.update(attempt.to_be_bytes());
        h.update((kind.len() as u64).to_be_bytes());
        h.update(kind.as_bytes());
        h.update(canonical_args);
        Self(Digest(h.finalize().into()))
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        Digest::from_hex(s).map(Self)
    }
}

impl fmt::Display for EffectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ek:{}", self.0.to_hex())
    }
}

impl fmt::Debug for EffectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ek:{}…", self.0.short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_is_order_sensitive() {
        let a = Digest::chain(Digest::ZERO, b"a");
        let b = Digest::chain(a, b"b");
        let swapped = Digest::chain(Digest::chain(Digest::ZERO, b"b"), b"a");
        assert_ne!(b, swapped, "chain must not be commutative");
    }

    #[test]
    fn chain_detects_any_mutation() {
        let genuine = Digest::chain(Digest::ZERO, b"record-1");
        let tampered = Digest::chain(Digest::ZERO, b"record-2");
        assert_ne!(genuine, tampered);
    }

    #[test]
    fn digest_hex_roundtrips() {
        let d = Digest::of(b"hello");
        assert_eq!(Digest::from_hex(&d.to_hex()).unwrap(), d);
    }

    #[test]
    fn effect_key_separates_step_phase_ordinal_and_attempt() {
        let fwd = Phase::Forward;
        let base = EffectKey::derive(StepId(0), fwd, 0, 1, "tool", b"{}");
        let other_ordinal = EffectKey::derive(StepId(0), fwd, 1, 1, "tool", b"{}");
        let other_step = EffectKey::derive(StepId(1), fwd, 0, 1, "tool", b"{}");
        let other_attempt = EffectKey::derive(StepId(0), fwd, 0, 2, "tool", b"{}");
        let compensating = EffectKey::derive(StepId(0), Phase::Compensating, 0, 1, "tool", b"{}");
        assert_ne!(base, other_ordinal, "ordinal must be part of the key");
        assert_ne!(base, other_step, "step must be part of the key");
        assert_ne!(
            base, other_attempt,
            "attempt must be part of the key, or a retry collides with the \
             failure it is retrying"
        );
        assert_ne!(
            base, compensating,
            "phase must be part of the key, or a step's compensation collides \
             with its own forward pass"
        );
    }

    /// Length-prefixing `kind` prevents a boundary-shifting collision: without
    /// it, `("ab", "c")` and `("a", "bc")` would hash identically.
    #[test]
    fn effect_key_kind_is_length_prefixed() {
        let a = EffectKey::derive(StepId(0), Phase::Forward, 0, 1, "ab", b"c");
        let b = EffectKey::derive(StepId(0), Phase::Forward, 0, 1, "a", b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn ids_display_with_prefix() {
        let r = RunId::generate();
        assert!(r.to_string().starts_with("run_"));
    }

    /// The property that broke first time round: `Display` and `parse` must be
    /// inverses, or every id that goes through a database column comes back
    /// unreadable.
    #[test]
    fn ids_round_trip_through_their_displayed_form() {
        let r = RunId::generate();
        assert_eq!(RunId::parse(&r.to_string()).unwrap(), r);
        let c = CaseId::generate();
        assert_eq!(CaseId::parse(&c.to_string()).unwrap(), c);
    }

    /// A bare ULID is still accepted, so ids written by other tools parse.
    #[test]
    fn bare_ulids_still_parse() {
        let r = RunId::generate();
        assert_eq!(RunId::parse(&r.0.to_string()).unwrap(), r);
    }

    /// Prefixes are not interchangeable in *meaning*, but parsing is lenient by
    /// design: a `CaseId` column holds case ids, and the prefix is a display
    /// affordance rather than a type check.
    #[test]
    fn parsing_rejects_garbage() {
        assert!(RunId::parse("run_not-a-ulid").is_err());
    }
}
