//! Information-flow labels.
//!
//! Payloads are opaque to the engine (it never parses business data) but they
//! are never *unlabeled*: policy over unlabeled blobs is policy over nothing.
//!
//! Every value carries provenance, a trust level, and a sensitivity level.
//! Combining values joins their labels on a bounded semilattice — trust degrades
//! to the worse, sensitivity escalates to the higher, provenance accumulates.
//! The single rule most systems get wrong, and the one that makes the dual-LLM
//! guarantee real rather than nominal:
//!
//! > **Model output derived from untrusted input stays untrusted.**

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Where a value came from. Free-form so the engine stays domain-agnostic; the
/// runtime stamps tool refs, peer ids, and collection names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceId(pub String);

impl SourceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a value may influence control flow.
///
/// Ordered so that `max` is the correct join: `Untrusted > Trusted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// From the operator, the manifest, or the run's own trusted input.
    Trusted,
    /// From a tool, document, peer, or any model that consumed an untrusted
    /// value. Never influences control flow.
    Untrusted,
}

/// How much damage disclosure would do.
///
/// Ordered so that `max` is the correct join, and so a sink can declare a
/// ceiling: an effect refuses arguments above its `max_sensitivity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Confidential,
    Secret,
}

/// A value's position in the information-flow lattice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub provenance: BTreeSet<SourceId>,
    pub trust: Trust,
    pub sensitivity: Sensitivity,
}

impl Label {
    /// The lattice bottom: trusted, public, no provenance.
    #[must_use]
    pub fn trusted() -> Self {
        Self {
            provenance: BTreeSet::new(),
            trust: Trust::Trusted,
            sensitivity: Sensitivity::Public,
        }
    }

    /// A value that crossed a trust boundary — every tool result, every
    /// retrieval, every peer response, *including from first-party services*.
    /// A compromised internal service is exactly what this exists for.
    #[must_use]
    pub fn untrusted(source: SourceId) -> Self {
        Self {
            provenance: BTreeSet::from([source]),
            trust: Trust::Untrusted,
            sensitivity: Sensitivity::Internal,
        }
    }

    #[must_use]
    pub fn with_sensitivity(mut self, s: Sensitivity) -> Self {
        self.sensitivity = s;
        self
    }

    /// Bounded join-semilattice: trust degrades, sensitivity escalates,
    /// provenance accumulates.
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        Self {
            provenance: self.provenance.union(&other.provenance).cloned().collect(),
            trust: self.trust.max(other.trust),
            sensitivity: self.sensitivity.max(other.sensitivity),
        }
    }

    #[must_use]
    pub fn is_untrusted(&self) -> bool {
        self.trust == Trust::Untrusted
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::trusted()
    }
}

/// A value carrying its information-flow label.
///
/// Deliberately exposes no `DerefMut` and no infallible unwrap. Reading is
/// allowed — a skill that cannot look at data cannot do anything useful, and the
/// enforcement point is at *sinks*, not at reads. Producing an owned, unlabeled
/// value requires `StepCtx::declassify`, which consults policy and writes a
/// `Declassified` journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tainted<T> {
    value: T,
    label: Label,
}

impl<T> Tainted<T> {
    /// Wrap a value the operator vouches for: manifest content, run input,
    /// constants.
    pub fn trusted(value: T) -> Self {
        Self {
            value,
            label: Label::trusted(),
        }
    }

    /// Wrap a value that crossed a trust boundary.
    pub fn from_source(value: T, source: SourceId) -> Self {
        Self {
            value,
            label: Label::untrusted(source),
        }
    }

    pub fn with_label(value: T, label: Label) -> Self {
        Self { value, label }
    }

    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Read without unwrapping. Safe by design: the lattice governs where a
    /// value may *go*, not whether it may be inspected.
    /// Take the value, dropping the label.
    ///
    /// Deliberately *not* named `unwrap` or `into_inner`: this is the one
    /// operation that leaves the lattice without a journal record, and it should
    /// read like something you had to mean. The sanctioned exit for anything
    /// derived from the outside world is
    /// [`StepCtx::declassify`](crate::runtime::StepCtx::declassify), which
    /// records the reason and the label it left with.
    ///
    /// Legitimate here only when the value never entered the lattice — the
    /// runtime unwrapping its own journaled clock, for instance.
    pub fn into_unlabelled(self) -> T {
        self.value
    }

    pub fn peek(&self) -> &T {
        &self.value
    }

    /// Transform in place; the label rides along.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Tainted<U> {
        Tainted {
            value: f(self.value),
            label: self.label,
        }
    }

    /// Combine two labeled values. Labels join, which is how untrust
    /// propagates: mixing anything with an untrusted value yields untrusted.
    pub fn zip<U>(self, other: Tainted<U>) -> Tainted<(T, U)> {
        let label = self.label.join(&other.label);
        Tainted {
            value: (self.value, other.value),
            label,
        }
    }

    /// Escape hatch for the runtime itself — declassification (which is
    /// policy-checked and journaled) is implemented in terms of this.
    pub(crate) fn into_parts(self) -> (T, Label) {
        (self.value, self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(s: &str) -> SourceId {
        SourceId::new(s)
    }

    #[test]
    fn trust_join_degrades() {
        let t = Label::trusted();
        let u = Label::untrusted(src("mcp://tool"));
        assert_eq!(t.join(&u).trust, Trust::Untrusted);
        assert_eq!(u.join(&t).trust, Trust::Untrusted, "join is commutative");
    }

    #[test]
    fn sensitivity_join_escalates() {
        let a = Label::trusted().with_sensitivity(Sensitivity::Public);
        let b = Label::trusted().with_sensitivity(Sensitivity::Secret);
        assert_eq!(a.join(&b).sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn provenance_accumulates() {
        let a = Label::untrusted(src("a"));
        let b = Label::untrusted(src("b"));
        let j = a.join(&b);
        assert_eq!(j.provenance.len(), 2);
    }

    #[test]
    fn join_is_idempotent_and_associative() {
        let a = Label::untrusted(src("a"));
        let b = Label::trusted().with_sensitivity(Sensitivity::Confidential);
        let c = Label::untrusted(src("c")).with_sensitivity(Sensitivity::Secret);
        assert_eq!(a.join(&a), a, "idempotent");
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)), "associative");
    }

    /// The rule most systems get wrong: derived data inherits untrust.
    #[test]
    fn zip_propagates_untrust_to_derived_values() {
        let trusted = Tainted::trusted(1);
        let untrusted = Tainted::from_source(2, src("mcp://tool"));
        let combined = trusted.zip(untrusted).map(|(a, b)| a + b);
        assert!(combined.label().is_untrusted());
        assert_eq!(*combined.peek(), 3);
    }

    #[test]
    fn map_preserves_label() {
        let t = Tainted::from_source("x", src("doc"));
        let mapped = t.map(str::to_uppercase);
        assert!(mapped.label().is_untrusted());
        assert_eq!(mapped.peek(), "X");
    }
}
