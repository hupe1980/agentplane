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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Where a value came from. Free-form so the engine stays domain-agnostic; the
/// runtime stamps tool refs, peer ids, and collection names.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public,
    Internal,
    Confidential,
    Secret,
}

/// A value's position in the information-flow lattice.
///
/// A pure product of three joins — provenance unions, trust degrades,
/// sensitivity escalates. Release marks are deliberately **not** part of a
/// label: a mark is scoped to the one value a release was granted over, while
/// a label flows through every join a derived value is built from, so a mark
/// stored here would ride any bare `join` onto data it never covered unless
/// every call site remembered to strip it. Marks live on [`Tainted`] instead,
/// where the operations that can prove value lineage — projection, assembly,
/// transformation — are the only ways to move one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub provenance: BTreeSet<SourceId>,
    pub trust: Trust,
    pub sensitivity: Sensitivity,
}

/// One destination-scoped improvement a [`Release`] granted, carried on the
/// [`Tainted`] value it covers.
///
/// The mark records what a *gate* needs to compute the effective label at a
/// concrete sink: the destination the release named, which part of the value
/// it covers, and which dimensions it may improve. The full [`Release`] —
/// evidence, releaser, prior label — is already journaled; the basis rides
/// along so an operator reading a mark knows which decision to look up,
/// but refusal messages never quote it.
///
/// Marks live on the [`Tainted`] wrapper — never inside a [`Label`] — with
/// `field` pointers relative to that value's root. Only the operations that
/// can prove value lineage move one: projection rebases them, assembly
/// carries them under the new pointer, and a value reshaped by
/// [`Tainted::map`] or [`Tainted::zip`] drops the marks whose scope the
/// reshaping invalidated — losing a mark refuses more, never less.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMark {
    destination: String,
    /// The covered part as an absolute RFC 6901 JSON Pointer; empty covers
    /// the whole value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    field: String,
    scope: ReleaseScope,
    basis: String,
}

impl ReleaseMark {
    fn of(release: &Release, field: String) -> Self {
        Self {
            destination: release.destination.clone(),
            field,
            scope: release.scope,
            basis: release.basis.clone(),
        }
    }

    /// The exact sink identity the release named — the same provenance-style
    /// name a [`ProtectedField::from_sources`] rule grants: `tool://server/name`,
    /// `model:provider/model`.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The covered field pointer; empty means the whole value.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    #[must_use]
    pub const fn scope(&self) -> ReleaseScope {
        self.scope
    }

    #[must_use]
    pub fn basis(&self) -> &str {
        &self.basis
    }

    /// Whether this mark's scope covers the value at `path`.
    ///
    /// A whole-value mark covers everything; a field mark covers its field and
    /// that field's descendants — the same inheritance rule
    /// [`Tainted::label_at`] applies to field labels. It never covers an
    /// ancestor: releasing `/account` says nothing about the object around it.
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.field.is_empty()
            || path == self.field
            || path
                .strip_prefix(self.field.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    }

    /// Rebase under a new parent pointer, for [`Tainted::object`]/[`Tainted::array`]
    /// assembly: a mark on the child's whole value becomes a field mark on the
    /// parent.
    fn rebased(mut self, prefix: &str) -> Self {
        self.field = format!("{prefix}{}", self.field);
        self
    }

    /// The mark as seen from the value at `pointer`, or `None` when the
    /// projection leaves its scope behind. A mark covering `pointer` or an
    /// ancestor covers the projection whole; one on a descendant is carried
    /// down rebased.
    fn projected(&self, pointer: &str) -> Option<Self> {
        if self.covers(pointer) {
            let mut mark = self.clone();
            mark.field = String::new();
            return Some(mark);
        }
        self.field
            .strip_prefix(pointer)
            .filter(|rest| rest.starts_with('/'))
            .map(|rest| Self {
                field: rest.to_owned(),
                ..self.clone()
            })
    }
}

/// A stricter information-flow rule for one JSON field sent to a sink.
///
/// Paths use RFC 6901 JSON Pointer syntax. An operator can require a protected
/// field to remain trusted, or permit it only when every contributing source is
/// in an explicit set. Ordinary content fields may remain untrusted without
/// granting them influence over recipient, amount, command, path, URL, tenant,
/// audience, model, or tool selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectedField {
    path: String,
    #[serde(default)]
    require_trusted: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    allowed_sources: BTreeSet<SourceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_sensitivity: Option<Sensitivity>,
    /// The closed set of values this field may carry, when one is declared.
    ///
    /// The content discipline beside the label disciplines, and the one
    /// fragment of release that is sound as a standing declaration: every
    /// entry was reviewed, so an untrusted influence choosing *among* them
    /// discloses only which approved option was chosen — a bounded release
    /// the reviewer priced when writing the list. Anything richer (a format,
    /// a pattern, a range over attacker-chosen strings) approves values
    /// nobody enumerated and stays out; a value the list cannot express goes
    /// through a coded skill's `release`, where basis and evidence are
    /// carried per instance and policy judges each one.
    ///
    /// A `Vec` rather than a set because [`serde_json::Value`] has no order;
    /// duplicates are refused by [`validate`](Self::validate). Matching is
    /// exact structural equality on the canonical value — never case-folded,
    /// trimmed, or coerced, for the same reason a tool name is never resolved
    /// to a near neighbour.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    one_of: Vec<serde_json::Value>,
}

/// A typed request to improve labels on a whole value or selected JSON fields.
///
/// Every release names its basis, destination, field scope, and evidence. The
/// runtime supplies the releaser identity, asks policy, and journals all of it.
/// This prevents a reason string from serving as an unstructured universal
/// escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    scope: ReleaseScope,
    basis: String,
    destination: String,
    fields: BTreeSet<String>,
    evidence: BTreeSet<String>,
}

/// Which label dimensions an authorized release may improve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseScope {
    trust: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sensitivity: Option<Sensitivity>,
}

impl ReleaseScope {
    /// Improve trust to `trusted` while retaining provenance and sensitivity.
    #[must_use]
    pub const fn trust() -> Self {
        Self {
            trust: true,
            sensitivity: None,
        }
    }

    /// Lower sensitivity to the named classification while retaining trust.
    #[must_use]
    pub const fn sensitivity(target: Sensitivity) -> Self {
        Self {
            trust: false,
            sensitivity: Some(target),
        }
    }

    /// Improve trust and lower sensitivity in one indivisible policy decision.
    #[must_use]
    pub const fn trust_and_sensitivity(target: Sensitivity) -> Self {
        Self {
            trust: true,
            sensitivity: Some(target),
        }
    }

    /// Whether this scope confers trust — what the taint gates ask when they
    /// explain a destination mismatch.
    #[must_use]
    pub const fn improves_trust(self) -> bool {
        self.trust
    }

    /// The sensitivity ceiling this scope grants, if any.
    #[must_use]
    pub const fn sensitivity_target(self) -> Option<Sensitivity> {
        self.sensitivity
    }
}

impl Release {
    /// Release an entire value.
    ///
    /// # Panics
    ///
    /// If basis, destination, or evidence is empty.
    #[must_use]
    pub fn whole(
        scope: ReleaseScope,
        basis: impl Into<String>,
        destination: impl Into<String>,
        evidence: impl IntoIterator<Item: Into<String>>,
    ) -> Self {
        Self::new(scope, [String::new()], basis, destination, evidence)
    }

    /// Release selected fields identified by absolute JSON Pointers.
    ///
    /// # Panics
    ///
    /// If the field set, basis, destination, or evidence is empty; a field is
    /// not an absolute RFC 6901 JSON Pointer; or whole-value and field scopes
    /// are mixed.
    #[must_use]
    pub fn fields(
        scope: ReleaseScope,
        fields: impl IntoIterator<Item: Into<String>>,
        basis: impl Into<String>,
        destination: impl Into<String>,
        evidence: impl IntoIterator<Item: Into<String>>,
    ) -> Self {
        Self::new(scope, fields, basis, destination, evidence)
    }

    /// The one constructor, and it is checked by the one rule set.
    ///
    /// It defers to [`validate`](Self::validate) rather than restating its five
    /// rules as asserts, because two spellings of one rule set is the *two
    /// representations of one fact* shape this crate treats as a defect
    /// everywhere else: the constructor and the deserialization gate would be
    /// free to drift, and only the second has a mutation holding it. One list,
    /// consulted from both directions — a safe constructor panics on a
    /// programmer error, a deserialized value is refused as an input, and
    /// neither can start disagreeing about which releases are legal.
    fn new(
        scope: ReleaseScope,
        fields: impl IntoIterator<Item: Into<String>>,
        basis: impl Into<String>,
        destination: impl Into<String>,
        evidence: impl IntoIterator<Item: Into<String>>,
    ) -> Self {
        let release = Self {
            scope,
            basis: basis.into(),
            destination: destination.into(),
            fields: fields.into_iter().map(Into::into).collect::<BTreeSet<_>>(),
            evidence: evidence
                .into_iter()
                .map(Into::into)
                .collect::<BTreeSet<_>>(),
        };
        assert!(
            release.validate().is_ok(),
            "invalid release: {}",
            release.validate().unwrap_err()
        );
        release
    }

    #[must_use]
    pub fn basis(&self) -> &str {
        &self.basis
    }

    #[must_use]
    pub const fn scope(&self) -> ReleaseScope {
        self.scope
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    #[must_use]
    pub fn fields_scope(&self) -> &BTreeSet<String> {
        &self.fields
    }

    #[must_use]
    pub fn evidence(&self) -> &BTreeSet<String> {
        &self.evidence
    }

    #[must_use]
    pub fn is_whole_value(&self) -> bool {
        self.fields.contains("")
    }

    /// Validate a release deserialized from outside the safe constructors.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.scope.trust && self.scope.sensitivity.is_none() {
            return Err("scope must improve trust, sensitivity, or both");
        }
        if self.basis.trim().is_empty() || self.destination.trim().is_empty() {
            return Err("basis and destination must be non-empty");
        }
        if self.fields.is_empty()
            || (self.fields.len() > 1 && self.fields.contains(""))
            || self
                .fields
                .iter()
                .any(|path| !path.is_empty() && !is_json_pointer(path))
        {
            return Err("field scope is not a valid whole-value or JSON Pointer selection");
        }
        if self.evidence.is_empty() || self.evidence.iter().any(|item| item.trim().is_empty()) {
            return Err("evidence must contain at least one non-empty reference");
        }
        Ok(())
    }
}

impl ProtectedField {
    /// Require a field to derive only from trusted data.
    ///
    /// # Panics
    ///
    /// If `path` is not an absolute JSON Pointer.
    #[must_use]
    pub fn trusted(path: impl Into<String>) -> Self {
        let path = path.into();
        assert_json_pointer(&path);
        Self {
            path,
            require_trusted: true,
            allowed_sources: BTreeSet::new(),
            max_sensitivity: None,
            one_of: Vec::new(),
        }
    }

    /// Permit an untrusted field only when all of its provenance is drawn from
    /// the named sources.
    ///
    /// An empty source set would permit nothing while looking configured, so it
    /// is rejected at construction.
    ///
    /// # Panics
    ///
    /// If `path` is not an absolute JSON Pointer or `sources` is empty.
    #[must_use]
    pub fn from_sources(
        path: impl Into<String>,
        sources: impl IntoIterator<Item = SourceId>,
    ) -> Self {
        let path = path.into();
        assert_json_pointer(&path);
        let allowed_sources = sources.into_iter().collect::<BTreeSet<_>>();
        assert!(
            !allowed_sources.is_empty(),
            "a protected field source constraint must name at least one source"
        );
        Self {
            path,
            require_trusted: false,
            allowed_sources,
            max_sensitivity: None,
            one_of: Vec::new(),
        }
    }

    /// Permit a field to carry only one of these exact values.
    ///
    /// The declarative form of the select-from-a-menu pattern: an untrusted
    /// influence may choose *which* reviewed value stands here, and nothing
    /// else. See the field's own documentation for what this deliberately
    /// cannot express.
    ///
    /// # Panics
    ///
    /// If `path` is not an absolute JSON Pointer, `values` is empty, or a
    /// value repeats.
    #[must_use]
    pub fn one_of(
        path: impl Into<String>,
        values: impl IntoIterator<Item = serde_json::Value>,
    ) -> Self {
        let field = Self {
            path: path.into(),
            require_trusted: false,
            allowed_sources: BTreeSet::new(),
            max_sensitivity: None,
            one_of: values.into_iter().collect(),
        };
        if let Err(detail) = field.validate() {
            panic!("{detail}");
        }
        field
    }

    /// Additionally restrict this field to one of these exact values.
    ///
    /// Layers the content discipline over a trust or provenance one: a value
    /// must satisfy every declared constraint, so a source-bound field with a
    /// value set refuses an allowed source answering something nobody
    /// enumerated.
    ///
    /// # Panics
    ///
    /// If `values` is empty or a value repeats.
    #[must_use]
    pub fn restricted_to(mut self, values: impl IntoIterator<Item = serde_json::Value>) -> Self {
        self.one_of = values.into_iter().collect();
        if let Err(detail) = self.validate() {
            panic!("{detail}");
        }
        self
    }

    /// Apply a field-specific sensitivity ceiling stricter than the sink-wide
    /// ceiling.
    #[must_use]
    pub const fn max_sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.max_sensitivity = Some(sensitivity);
        self
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub const fn requires_trusted(&self) -> bool {
        self.require_trusted
    }

    #[must_use]
    pub fn allowed_sources(&self) -> &BTreeSet<SourceId> {
        &self.allowed_sources
    }

    #[must_use]
    pub const fn sensitivity_ceiling(&self) -> Option<Sensitivity> {
        self.max_sensitivity
    }

    /// The closed value set, empty when no content constraint is declared.
    #[must_use]
    pub fn allowed_values(&self) -> &[serde_json::Value] {
        &self.one_of
    }

    /// Validate a rule deserialized from an external declaration.
    ///
    /// Constructors enforce these invariants for Rust callers; manifests and
    /// other serialized inputs must prove them after deserialization.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !is_json_pointer(&self.path) {
            return Err("path must be a non-empty absolute RFC 6901 JSON Pointer");
        }
        if self.require_trusted && !self.allowed_sources.is_empty() {
            return Err("require_trusted and allowed_sources are mutually exclusive");
        }
        if !self.require_trusted
            && self.allowed_sources.is_empty()
            && self.max_sensitivity.is_none()
            && self.one_of.is_empty()
        {
            return Err("at least one trust, source, sensitivity, or value constraint is required");
        }
        for (index, value) in self.one_of.iter().enumerate() {
            if self.one_of[..index].contains(value) {
                return Err("one_of must not repeat a value — one decision, written once");
            }
        }
        Ok(())
    }
}

fn assert_json_pointer(path: &str) {
    assert!(
        is_json_pointer(path),
        "a protected field path must be a non-empty absolute RFC 6901 JSON Pointer"
    );
}

fn is_json_pointer(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            index += 1;
            if index == bytes.len() || !matches!(bytes[index], b'0' | b'1') {
                return false;
            }
        }
        index += 1;
    }
    true
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
    ///
    /// Nothing else rides a join. In particular a join can never transport a
    /// release: marks live on [`Tainted`], not here, so combining labels —
    /// however a caller does it — cannot extend a grant to data the release
    /// never covered.
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
/// value is intentionally not a public operation. `StepCtx::release` consults
/// policy and improves only the named label dimensions while retaining the
/// value in the lattice and writing a `Released` journal record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tainted<T> {
    value: T,
    label: Label,
    /// Labels for structured sub-values, keyed by RFC 6901 JSON Pointer.
    /// Missing paths conservatively inherit their nearest labeled ancestor,
    /// ultimately the whole-value label.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fields: BTreeMap<String, Label>,
    /// Destination-scoped release marks over **this** value, with pointers
    /// relative to its root. A typed release does not improve the label — it
    /// attaches a mark here, honoured only at the exact sink it names (via
    /// [`effective_label`](Self::effective_label)). Kept beside the label
    /// rather than inside it so that no label join, wherever a caller
    /// performs one, can carry a release onto a value it never covered.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    releases: BTreeSet<ReleaseMark>,
}

impl<T> Tainted<T> {
    /// Wrap a value the operator vouches for: manifest content, run input,
    /// constants.
    pub fn trusted(value: T) -> Self {
        Self {
            value,
            label: Label::trusted(),
            fields: BTreeMap::new(),
            releases: BTreeSet::new(),
        }
    }

    /// Wrap a value that crossed a trust boundary.
    pub fn from_source(value: T, source: SourceId) -> Self {
        Self {
            value,
            label: Label::untrusted(source),
            fields: BTreeMap::new(),
            releases: BTreeSet::new(),
        }
    }

    pub fn with_label(value: T, label: Label) -> Self {
        Self {
            value,
            label,
            fields: BTreeMap::new(),
            releases: BTreeSet::new(),
        }
    }

    pub fn label(&self) -> &Label {
        &self.label
    }

    /// The destination-scoped release marks over this value.
    ///
    /// What an operator or a gate reads to see which sinks a release covers;
    /// the improvements themselves are computed by
    /// [`effective_label`](Self::effective_label) and
    /// [`effective_label_at`](Self::effective_label_at), never by mutating
    /// the base label.
    pub fn release_marks(&self) -> &BTreeSet<ReleaseMark> {
        &self.releases
    }

    /// Clone this value with an additional whole-value dependency.
    ///
    /// Structured field labels remain intact: a trusted selector such as a
    /// model instruction does not become untrusted merely because another
    /// provider-visible part of the same request contains tool output. The
    /// whole-value label still joins, so egress ceilings see that dependency.
    ///
    /// Release marks do not survive: absorbing a dependency is a mix, and no
    /// release covers data it was never granted over — the same rule
    /// [`zip`](Self::zip) applies. Losing a mark refuses more, never less.
    #[cfg(feature = "manifest")]
    pub(crate) fn with_joined_label(&self, other: &Label) -> Self
    where
        T: Clone,
    {
        Self {
            value: self.value.clone(),
            label: self.label.join(other),
            fields: self.fields.clone(),
            releases: BTreeSet::new(),
        }
    }

    /// Take the value, dropping the label.
    ///
    /// Deliberately *not* named `unwrap` or `into_inner`: this is the one
    /// operation that leaves the lattice without a journal record, and it should
    /// read like something you had to mean. The sanctioned exit for anything
    /// derived from the outside world is
    /// [`StepCtx::release`](crate::runtime::StepCtx::release), which records
    /// the typed scope, destination, evidence, and label it left with.
    ///
    /// Legitimate here only when the value never entered the lattice — the
    /// runtime unwrapping its own journaled clock, for instance.
    pub(crate) fn into_unlabelled(self) -> T {
        self.value
    }

    /// Read without unwrapping. Safe by design: the lattice governs where a
    /// value may *go*, not whether it may be inspected.
    pub fn peek(&self) -> &T {
        &self.value
    }

    /// Transform in place; the whole-value label rides along.
    ///
    /// Arbitrary transforms invalidate JSON Pointer paths, so structured field
    /// labels are deliberately discarded. Use [`Tainted::object`] or
    /// [`Tainted::array`] when assembling structured values whose field-level
    /// provenance must survive to a sink.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Tainted<U> {
        // Field-scoped release marks die with the field labels: the transform
        // invalidated their pointers, and a mark surviving onto whatever now
        // sits at its path would extend a grant to data it never covered. A
        // whole-value mark still covers the derived value, exactly as the
        // whole-value label does.
        let mut releases = self.releases;
        releases.retain(|mark| mark.field().is_empty());
        Tainted {
            value: f(self.value),
            label: self.label,
            fields: BTreeMap::new(),
            releases,
        }
    }

    /// Combine two labeled values. Labels join, which is how untrust
    /// propagates: mixing anything with an untrusted value yields untrusted.
    /// Arbitrary tuple construction invalidates structured JSON paths, so any
    /// field maps are deliberately discarded.
    pub fn zip<U>(self, other: Tainted<U>) -> Tainted<(T, U)> {
        // No release survives the mix: the tuple is a value neither release
        // was granted over, and a whole-value mark carried across would treat
        // the *other* half as released too. Losing a mark refuses more,
        // never less.
        Tainted {
            value: (self.value, other.value),
            label: self.label.join(&other.label),
            fields: BTreeMap::new(),
            releases: BTreeSet::new(),
        }
    }
}

impl Tainted<serde_json::Value> {
    /// Build a JSON object without flattening the labels of its fields.
    pub fn object<K: Into<String>>(fields: impl IntoIterator<Item = (K, Self)>) -> Self {
        let mut value = serde_json::Map::new();
        let mut label = Label::trusted();
        let mut field_labels = BTreeMap::new();
        let mut releases = BTreeSet::new();

        for (name, field) in fields {
            let name = name.into();
            let base = format!("/{}", escape_pointer_token(&name));
            label = label.join(&field.label);
            // Marks are carried root-relative, so the child's are rebased
            // under its new pointer rather than copied as-is — an unrebased
            // copy would cover the wrong fields of the assembled object.
            releases.extend(field.releases.into_iter().map(|mark| mark.rebased(&base)));
            field_labels.insert(base.clone(), field.label);
            for (path, nested) in field.fields {
                field_labels.insert(format!("{base}{path}"), nested);
            }
            value.insert(name, field.value);
        }

        Self {
            value: serde_json::Value::Object(value),
            label,
            fields: field_labels,
            releases,
        }
    }

    /// Build a JSON array without flattening the labels of its elements.
    pub fn array(elements: impl IntoIterator<Item = Self>) -> Self {
        let mut value = Vec::new();
        let mut label = Label::trusted();
        let mut field_labels = BTreeMap::new();
        let mut releases = BTreeSet::new();

        for (index, element) in elements.into_iter().enumerate() {
            let base = format!("/{index}");
            label = label.join(&element.label);
            // The same rebase rule as `object`, for the same reason.
            releases.extend(element.releases.into_iter().map(|mark| mark.rebased(&base)));
            field_labels.insert(base.clone(), element.label);
            for (path, nested) in element.fields {
                field_labels.insert(format!("{base}{path}"), nested);
            }
            value.push(element.value);
        }

        Self {
            value: serde_json::Value::Array(value),
            label,
            fields: field_labels,
            releases,
        }
    }

    /// The label at a JSON Pointer, inheriting conservatively from the nearest
    /// labeled ancestor when the value was not assembled field by field.
    #[must_use]
    pub fn label_at(&self, path: &str) -> Option<&Label> {
        self.value.pointer(path)?;
        if path.is_empty() {
            return Some(&self.label);
        }

        let mut candidate = path;
        loop {
            if let Some(label) = self.fields.get(candidate) {
                return Some(label);
            }
            let Some(split) = candidate.rfind('/') else {
                return Some(&self.label);
            };
            if split == 0 {
                return Some(&self.label);
            }
            candidate = &candidate[..split];
        }
    }

    /// Every explicitly tracked field label in stable pointer order.
    pub fn field_labels(&self) -> impl Iterator<Item = (&str, &Label)> {
        self.fields
            .iter()
            .map(|(path, label)| (path.as_str(), label))
    }

    /// Select a top-level object field while preserving and rebasing every
    /// tracked descendant label. Used by plan argument assembly; returning
    /// `None` distinguishes an absent field from a present JSON null.
    pub(crate) fn project_field(&self, name: &str) -> Option<Self> {
        self.project_pointer(&format!("/{}", escape_pointer_token(name)))
    }

    /// Select the value at a JSON Pointer while preserving and rebasing every
    /// tracked descendant label.
    ///
    /// The generalisation `project_field` delegates to — one implementation,
    /// because two copies of the rebase rule would agree everywhere except the
    /// nesting depth nobody probed. The projected value's own label comes from
    /// [`label_at`](Self::label_at), so a value that was never assembled field
    /// by field inherits conservatively from its nearest labelled ancestor.
    /// `None` distinguishes an absent path from a present JSON null.
    pub(crate) fn project_pointer(&self, pointer: &str) -> Option<Self> {
        if pointer.is_empty() {
            return Some(self.clone());
        }
        let value = self.value.pointer(pointer)?.clone();
        let label = self.label_at(pointer)?.clone();
        // Keep exactly the marks whose scope covers the projection, rebased to
        // the projected value's root — the same rebase rule the field labels
        // below follow. A mark that covers neither the pointer nor one of its
        // descendants is dropped, which refuses more, never less.
        let releases = self
            .releases
            .iter()
            .filter_map(|mark| mark.projected(pointer))
            .collect();
        let prefix = format!("{pointer}/");
        let fields = self
            .fields
            .iter()
            .filter_map(|(path, label)| {
                path.strip_prefix(&prefix)
                    .map(|relative| (format!("/{relative}"), label.clone()))
            })
            .collect();
        Some(Self {
            value,
            label,
            fields,
            releases,
        })
    }

    /// Apply an authorized release. The runtime owns the only call site.
    ///
    /// The release does not improve trust or sensitivity in place — it
    /// attaches [`ReleaseMark`]s to this value, and only the gates judging
    /// the exact sink the release named honour them (via
    /// [`effective_label_at`](Self::effective_label_at)). Every other
    /// consumer keeps seeing the base label: a value released "for
    /// `tool://ledger/transfer`" is still untrusted data everywhere else.
    pub(crate) fn apply_release(mut self, release: &Release) -> Option<Self> {
        if release.is_whole_value() {
            self.releases
                .insert(ReleaseMark::of(release, String::new()));
            return Some(self);
        }

        // A field release requires explicit field lineage. Falling back to the
        // whole-value label would let a caller claim precision the runtime does
        // not actually possess.
        if release
            .fields
            .iter()
            .any(|path| !self.fields.contains_key(path) || self.value.pointer(path).is_none())
        {
            return None;
        }

        for released in &release.fields {
            self.releases
                .insert(ReleaseMark::of(release, released.clone()));
        }
        Some(self)
    }

    /// The label a concrete sink sees for the whole value: the base label
    /// improved by exactly the whole-value release marks granted for
    /// `destination`. Field-scoped marks improve only their fields, so a
    /// value whose `/account` was released stays tainted as a whole.
    ///
    /// The result *is* the judgement at that sink: what the sink gates
    /// enforce, what policy is asked over, and what the dispatch journals as
    /// its outbound label.
    #[must_use]
    pub fn effective_label(&self, destination: &str) -> Label {
        Self::improved(&self.label, &self.releases, destination, "")
    }

    /// The label a concrete sink sees at a JSON Pointer: the base
    /// [`label_at`](Self::label_at) improved by exactly the marks granted for
    /// `destination` whose scope covers `path`. `None` when the path is not
    /// in the value, exactly as `label_at`.
    #[must_use]
    pub fn effective_label_at(&self, destination: &str, path: &str) -> Option<Label> {
        let base = self.label_at(path)?;
        Some(Self::improved(base, &self.releases, destination, path))
    }

    fn improved(
        base: &Label,
        marks: &BTreeSet<ReleaseMark>,
        destination: &str,
        path: &str,
    ) -> Label {
        let mut effective = base.clone();
        for mark in marks {
            if mark.destination() == destination && mark.covers(path) {
                effective = apply_release_scope(&effective, mark.scope());
            }
        }
        effective
    }
}

fn apply_release_scope(label: &Label, scope: ReleaseScope) -> Label {
    let mut released = label.clone();
    if scope.trust {
        released.trust = Trust::Trusted;
    }
    if let Some(target) = scope.sensitivity {
        released.sensitivity = label.sensitivity.min(target);
    }
    released
}

fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
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
        let u = Label::untrusted(src("tool://tool"));
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

    /// Every label over a two-source universe: 2 trusts × 4 sensitivities ×
    /// 4 provenance subsets. Small enough to quantify over exhaustively,
    /// which is what turns the sampled laws above into a checked model.
    fn every_label() -> Vec<Label> {
        let mut out = Vec::new();
        for trust in [Trust::Trusted, Trust::Untrusted] {
            for sensitivity in [
                Sensitivity::Public,
                Sensitivity::Internal,
                Sensitivity::Confidential,
                Sensitivity::Secret,
            ] {
                for provenance in [
                    BTreeSet::new(),
                    BTreeSet::from([src("a")]),
                    BTreeSet::from([src("b")]),
                    BTreeSet::from([src("a"), src("b")]),
                ] {
                    out.push(Label {
                        provenance,
                        trust,
                        sensitivity,
                    });
                }
            }
        }
        out
    }

    /// The join is a bounded semilattice over the whole finite domain, not
    /// over the three samples the test above picks.
    ///
    /// This is the algebraic core of the required field-level information-flow
    /// model, discharged as an exhaustive check rather than a state-space
    /// search: the domain is finite (32 labels over a two-source universe)
    /// and the laws are equations, so quantifying over every pair and triple
    /// *is* the model. What it proves is what every gate assumes — that no
    /// order of combination, no repetition, and no association of joins can
    /// produce a label below any contributor: `a ⊑ a ⊔ b` for every a, b.
    #[test]
    fn the_join_is_a_bounded_semilattice_over_the_whole_domain() {
        let labels = every_label();
        let bottom = Label::trusted();
        for a in &labels {
            assert_eq!(&a.join(a), a, "idempotence failed at {a:?}");
            assert_eq!(
                bottom.join(a),
                a.clone(),
                "the trusted public label is not the identity at {a:?}"
            );
            for b in &labels {
                let ab = a.join(b);
                assert_eq!(ab, b.join(a), "commutativity failed at {a:?}, {b:?}");
                // Upper bound: a join never forgets a contributor's taint,
                // sensitivity, or provenance.
                assert!(ab.trust >= a.trust && ab.trust >= b.trust);
                assert!(ab.sensitivity >= a.sensitivity && ab.sensitivity >= b.sensitivity);
                assert!(ab.provenance.is_superset(&a.provenance));
                assert!(ab.provenance.is_superset(&b.provenance));
                for c in &labels {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(&b.join(c)),
                        "associativity failed at {a:?}, {b:?}, {c:?}"
                    );
                }
            }
        }
    }

    /// Rebase and projection are inverse where a projection is defined.
    ///
    /// The mark algebra has one law worth a model: carrying a mark *into* an
    /// assembled parent ([`ReleaseMark::rebased`], used by `object`/`array`)
    /// and projecting the same field back out ([`ReleaseMark::projected`],
    /// used by `project_pointer`) must return the original mark. A drift
    /// between the two is a mark that silently covers the wrong field after a
    /// round trip through assembly — checked here over whole-value, field,
    /// and nested-field scopes.
    #[test]
    fn rebase_then_projection_returns_the_original_mark() {
        for field in ["", "/account", "/account/iban"] {
            let mark = ReleaseMark::of(
                &Release::whole(
                    ReleaseScope::trust(),
                    "reviewed",
                    "tool://ledger/transfer",
                    ["ticket:1"],
                ),
                field.to_owned(),
            );
            let carried = mark.clone().rebased("/payment");
            assert_eq!(
                carried.projected("/payment"),
                Some(mark.clone()),
                "a mark on {field:?} did not survive assembly and projection \
                 unchanged"
            );
            assert_eq!(
                carried.projected("/other"),
                None,
                "a mark rebased under /payment answered a projection of a \
                 sibling it never covered"
            );
        }
    }

    /// The rule most systems get wrong: derived data inherits untrust.
    #[test]
    fn zip_propagates_untrust_to_derived_values() {
        let trusted = Tainted::trusted(1);
        let untrusted = Tainted::from_source(2, src("tool://tool"));
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

    #[test]
    fn field_projection_preserves_only_the_selected_lineage() {
        let nested = Tainted::object([
            ("safe", Tainted::trusted(serde_json::json!("ok"))),
            (
                "body",
                Tainted::from_source(serde_json::json!("outside"), src("model")),
            ),
        ]);
        let value = Tainted::object([
            ("selected", nested),
            (
                "other",
                Tainted::from_source(serde_json::json!("noise"), src("tool")),
            ),
        ]);

        let selected = value.project_field("selected").unwrap();
        assert!(selected.label_at("/safe").unwrap().provenance.is_empty());
        assert_eq!(
            selected.label_at("/body").unwrap().provenance,
            BTreeSet::from([src("model")])
        );
        assert!(selected.label_at("/other").is_none());
    }

    /// A release improves nothing in place: it is honoured only at the sink
    /// it named, only for the fields it named.
    #[test]
    fn field_release_improves_only_its_declared_scope_at_its_destination() {
        let value = Tainted::object([
            (
                "recipient",
                Tainted::from_source(serde_json::json!("treasury"), src("model")),
            ),
            (
                "memo",
                Tainted::from_source(serde_json::json!("outside"), src("model")),
            ),
        ]);
        let release = Release::fields(
            ReleaseScope::trust(),
            ["/recipient"],
            "operator verified account",
            "tool://ledger/transfer",
            ["approval:42"],
        );

        let released = value.apply_release(&release).unwrap();

        // The base labels are untouched: a release is a destination-scoped
        // grant, not a relabelling. A consumer that reads `label_at` — a
        // memory write, a join — still sees untrusted data.
        assert!(released.label_at("/recipient").unwrap().is_untrusted());
        assert!(released.label().is_untrusted());

        // At the granted destination the effective label is improved — trust
        // only, retaining sensitivity and provenance.
        let at_dest = released
            .effective_label_at("tool://ledger/transfer", "/recipient")
            .unwrap();
        assert_eq!(at_dest.trust, Trust::Trusted);
        assert_eq!(at_dest.sensitivity, Sensitivity::Internal);
        assert_eq!(at_dest.provenance, BTreeSet::from([src("model")]));

        // A different sink sees the base label: the release does not follow
        // the value to destinations nobody authorized.
        assert!(
            released
                .effective_label_at("tool://mail/send", "/recipient")
                .unwrap()
                .is_untrusted(),
            "a release for one destination improved the label at another"
        );

        // The unreleased sibling and the whole value stay tainted even at the
        // granted destination.
        assert!(
            released
                .effective_label_at("tool://ledger/transfer", "/memo")
                .unwrap()
                .is_untrusted()
        );
        assert!(
            released
                .effective_label("tool://ledger/transfer")
                .is_untrusted(),
            "a field-scoped release must not clear the whole-value taint"
        );
    }

    /// Projection and assembly carry a mark exactly as they carry field
    /// labels: rebased, and only where its scope still covers something.
    #[test]
    fn a_release_mark_survives_projection_and_assembly_rebased() {
        let value = Tainted::object([
            (
                "account",
                Tainted::from_source(serde_json::json!("DE00"), src("crm")),
            ),
            (
                "note",
                Tainted::from_source(serde_json::json!("text"), src("model")),
            ),
        ]);
        let release = Release::fields(
            ReleaseScope::trust(),
            ["/account"],
            "operator verified account",
            "tool://ledger/transfer",
            ["approval:42"],
        );
        let released = value.apply_release(&release).unwrap();

        // Projecting the released field keeps the mark, rebased to the
        // projection's root; projecting the sibling does not acquire it.
        let account = released.project_field("account").unwrap();
        assert_eq!(
            account.effective_label("tool://ledger/transfer").trust,
            Trust::Trusted,
            "the mark did not survive projection of the field it covers"
        );
        assert!(
            account.effective_label("tool://mail/send").is_untrusted(),
            "projection widened the mark to a destination it never named"
        );
        let note = released.project_field("note").unwrap();
        assert!(
            note.effective_label("tool://ledger/transfer")
                .is_untrusted(),
            "projecting a sibling acquired a mark that never covered it"
        );

        // Reassembly rebases the mark under the new pointer.
        let assembled = Tainted::object([("payment", account)]);
        assert_eq!(
            assembled
                .effective_label_at("tool://ledger/transfer", "/payment")
                .map(|l| l.trust),
            Some(Trust::Trusted),
            "assembly lost or failed to rebase the projected mark"
        );
        assert!(
            assembled
                .effective_label("tool://ledger/transfer")
                .is_untrusted(),
            "assembly promoted a field mark to the whole value"
        );
    }

    /// A reshaped value keeps no more authority than its shape can carry.
    #[test]
    fn reshaping_a_value_drops_the_marks_its_shape_invalidated() {
        let released_whole = Tainted::from_source(serde_json::json!("x"), src("crm"))
            .apply_release(&Release::whole(
                ReleaseScope::trust(),
                "reviewed",
                "tool://ledger/transfer",
                ["ticket:1"],
            ))
            .unwrap();

        // `zip` mixes in a value the release never covered, so nothing
        // survives — not even the whole-value mark.
        let zipped = released_whole.clone().zip(Tainted::trusted(1));
        assert!(zipped.release_marks().is_empty());

        // `map` keeps the whole-value mark (it covers the derived value as
        // the whole-value label does) but a field mark dies with the field
        // labels.
        let mapped_whole = released_whole.map(|v| v);
        assert_eq!(mapped_whole.release_marks().len(), 1);

        let field_released = Tainted::object([(
            "account",
            Tainted::from_source(serde_json::json!("DE00"), src("crm")),
        )])
        .apply_release(&Release::fields(
            ReleaseScope::trust(),
            ["/account"],
            "reviewed",
            "tool://ledger/transfer",
            ["ticket:1"],
        ))
        .unwrap();
        let mapped_fields = field_released.map(|v| v);
        assert!(
            mapped_fields.release_marks().is_empty(),
            "a field mark outlived the pointer paths the transform invalidated"
        );
    }

    /// Absorbing a dependency is a mix, and no release survives a mix.
    ///
    /// `with_joined_label` is how the declarative tier folds a conversation's
    /// history into an outbound value. A mark surviving that join would let a
    /// release granted over the bare value stand for the value *plus* every
    /// untrusted dependency later mixed into it — the sink would honour a
    /// grant nobody priced against that history.
    #[cfg(feature = "manifest")]
    #[test]
    fn a_dependency_join_drops_release_marks() {
        let released = Tainted::from_source(serde_json::json!("x"), src("crm"))
            .apply_release(&Release::whole(
                ReleaseScope::trust(),
                "reviewed",
                "tool://ledger/transfer",
                ["ticket:1"],
            ))
            .unwrap();

        let joined = released.with_joined_label(&Label::untrusted(src("tool://mail")));
        assert!(
            joined.release_marks().is_empty()
                && joined
                    .effective_label("tool://ledger/transfer")
                    .is_untrusted(),
            "a release granted over a bare value survived the join that mixed \
             an untrusted dependency into it, so the sink honours a grant \
             nobody priced against that history"
        );
    }

    /// A label join is provenance, trust and sensitivity — never a release.
    ///
    /// Marks live on the [`Tainted`] value, so a label read from a released
    /// value and joined into any other label carries nothing a sink gate
    /// would honour. The invariant holds by construction — no join call site
    /// has marks to drop or rebase — and this test is its executable
    /// statement.
    #[test]
    fn a_label_join_cannot_transport_a_release() {
        let released = Tainted::from_source(serde_json::json!("x"), src("crm"))
            .apply_release(&Release::whole(
                ReleaseScope::trust(),
                "reviewed",
                "tool://ledger/transfer",
                ["ticket:1"],
            ))
            .unwrap();

        // Rebuilding a value from the released value's *label* — the shape
        // every effect boundary and every conversation join uses — yields a
        // value with no marks: at the very sink the release named, it is as
        // untrusted as it started.
        let relabelled = Tainted::with_label(serde_json::json!("y"), released.label().clone());
        assert!(relabelled.release_marks().is_empty());
        assert!(
            relabelled
                .effective_label("tool://ledger/transfer")
                .is_untrusted(),
            "a release rode a bare label onto a value it never covered"
        );
    }

    /// Each of the three scopes moves the dimensions it names, and no others.
    ///
    /// Only `trust()` had a test. The other two were reachable public API with
    /// nothing that could tell a correct implementation from one that set the
    /// wrong field — and these are the declassification primitives, so a scope
    /// that quietly improved trust when it was asked for sensitivity would be
    /// granting authority nobody wrote down.
    #[test]
    fn each_release_scope_moves_exactly_what_it_names() {
        let secret = Label::untrusted(src("model")).with_sensitivity(Sensitivity::Secret);

        let trust_only = apply_release_scope(&secret, ReleaseScope::trust());
        assert_eq!(trust_only.trust, Trust::Trusted);
        assert_eq!(
            trust_only.sensitivity,
            Sensitivity::Secret,
            "improving trust must not also declassify"
        );

        let sensitivity_only =
            apply_release_scope(&secret, ReleaseScope::sensitivity(Sensitivity::Internal));
        assert_eq!(
            sensitivity_only.trust,
            Trust::Untrusted,
            "lowering sensitivity must not also confer belief"
        );
        assert_eq!(sensitivity_only.sensitivity, Sensitivity::Internal);

        let both = apply_release_scope(
            &secret,
            ReleaseScope::trust_and_sensitivity(Sensitivity::Internal),
        );
        assert_eq!(both.trust, Trust::Trusted);
        assert_eq!(both.sensitivity, Sensitivity::Internal);
    }

    /// A release declassifies; it never reclassifies upward.
    ///
    /// The scope names a *ceiling*, not an assignment. Handing a `Public` value
    /// to a release written for `Secret` data must leave it `Public` — an
    /// assignment would silently relabel ordinary data as secret and trip every
    /// egress ceiling downstream, which reads as the gate working and is not.
    #[test]
    fn a_release_never_raises_sensitivity() {
        let public = Label::untrusted(src("model")).with_sensitivity(Sensitivity::Public);

        let released = apply_release_scope(&public, ReleaseScope::sensitivity(Sensitivity::Secret));

        assert_eq!(
            released.sensitivity,
            Sensitivity::Public,
            "a release named a higher classification and the label followed it upward"
        );
    }

    /// Provenance survives every scope.
    ///
    /// Trust and sensitivity are judgements a policy may revise. Where the value
    /// came from is a fact, and a release that dropped it would erase the
    /// evidence that the release was needed in the first place.
    #[test]
    fn no_release_scope_erases_provenance() {
        let from_model = Label::untrusted(src("model")).with_sensitivity(Sensitivity::Secret);

        for scope in [
            ReleaseScope::trust(),
            ReleaseScope::sensitivity(Sensitivity::Public),
            ReleaseScope::trust_and_sensitivity(Sensitivity::Public),
        ] {
            assert_eq!(
                apply_release_scope(&from_model, scope).provenance,
                BTreeSet::from([src("model")]),
                "a release dropped the provenance it was granted against"
            );
        }
    }

    /// A descendant inherits from its nearest labelled ancestor, not the join.
    ///
    /// Split from the test above only for length. The fixture has to make the
    /// two answers observably different, or the assertion passes either way.
    #[test]
    fn an_untracked_descendant_inherits_its_nearest_labelled_ancestor() {
        let nested = Tainted::object([
            (
                "recipient",
                Tainted::with_label(
                    serde_json::json!({ "addr": "ops@example.com" }),
                    Label::trusted(),
                ),
            ),
            (
                "note",
                Tainted::with_label(
                    serde_json::json!("n"),
                    Label::untrusted(src("tool://mail")).with_sensitivity(Sensitivity::Secret),
                ),
            ),
        ]);

        assert_eq!(
            nested.label_at("/recipient/addr").map(|l| l.sensitivity),
            Some(Sensitivity::Public),
            "a descendant of a tracked field inherited the whole-value label \
             instead of its own ancestor's, so a field-scoped ceiling reads as \
             the join of everything beside it"
        );
        assert_eq!(
            nested.label().sensitivity,
            Sensitivity::Secret,
            "the fixture no longer distinguishes the two, so the assertion \
             above would pass under either reading"
        );
    }

    /// The three field-provenance accessors, each pinned by what it returns.
    ///
    /// A sweep replaced `field_labels` with `std::iter::empty()`, flipped
    /// `label_at`'s pointer comparison, and turned `apply_release`'s lineage
    /// check from `||` into `&&` — all three survived. Together they *are*
    /// field-level provenance: what an auditor reads, what a protected field
    /// checks, and what stops a release claiming precision the runtime does not
    /// have. Every test around them asserted whole-value behaviour, which is why
    /// emptying the field map changed nothing any check could see.
    #[test]
    fn field_provenance_is_reported_rebased_and_required() {
        let value = Tainted::object([
            (
                "recipient",
                Tainted::with_label(
                    serde_json::json!("ops@example.com"),
                    Label::untrusted(src("tool://mail")),
                ),
            ),
            (
                "amount",
                Tainted::with_label(serde_json::json!(10), Label::trusted()),
            ),
        ]);

        // `field_labels` reports both, so emptying it is observable.
        let reported: Vec<&str> = value.field_labels().map(|(p, _)| p).collect();
        assert_eq!(
            reported,
            vec!["/amount", "/recipient"],
            "field labels are not reported in stable pointer order, so an audit \
             of who influenced which field reads differently run to run"
        );

        // `label_at` answers per field, and an exact hit is not the parent's.
        assert_eq!(
            value.label_at("/recipient").map(|l| l.trust),
            Some(Trust::Untrusted),
            "the tracked field's own label was not returned"
        );
        assert_eq!(
            value.label_at("/amount").map(|l| l.trust),
            Some(Trust::Trusted),
            "a trusted sibling inherited its untrusted neighbour's label"
        );
        assert!(
            value.label_at("/absent").is_none(),
            "a path that is not in the value reported a label, so a sink would \
             check a field that is not being sent"
        );

        // `apply_release` requires lineage for *every* named field: one that is
        // tracked and one that is not must still be refused.
        let release = Release {
            scope: ReleaseScope {
                trust: true,
                sensitivity: None,
            },
            basis: "reviewed".to_owned(),
            destination: "tool://ledger/post".to_owned(),
            fields: ["/recipient".to_owned(), "/absent".to_owned()]
                .into_iter()
                .collect(),
            evidence: ["ticket:1".to_owned()].into_iter().collect(),
        };
        assert!(
            value.clone().apply_release(&release).is_none(),
            "a release naming one tracked field and one untracked field was \
             applied, so the untracked half was promoted on the strength of the \
             whole-value label — precision the runtime does not have"
        );

        // The half that separates the two conditions. A value assembled whole
        // carries no per-field lineage, so `/a` is **present in the value and
        // untracked** — which `||` refuses and `&&` would allow, promoting a
        // field on the strength of the whole-value label alone.
        let untracked = Tainted::with_label(
            serde_json::json!({ "a": "x" }),
            Label::untrusted(src("tool://mail")),
        );
        let over_untracked = Release {
            scope: ReleaseScope {
                trust: true,
                sensitivity: None,
            },
            basis: "reviewed".to_owned(),
            destination: "tool://ledger/post".to_owned(),
            fields: ["/a".to_owned()].into_iter().collect(),
            evidence: ["ticket:1".to_owned()].into_iter().collect(),
        };
        assert!(
            untracked.apply_release(&over_untracked).is_none(),
            "a field present in the value but with no tracked lineage was \
             released, so the promotion rests on the whole-value label while \
             the decision reads as field-scoped"
        );

        // And the positive half, so a refuse-everything change cannot pass.
        let ok = Release {
            fields: ["/recipient".to_owned()].into_iter().collect(),
            ..release
        };
        let good = value
            .clone()
            .apply_release(&ok)
            .expect("a release over a field with real lineage was refused");
        assert_eq!(
            good.effective_label_at("tool://ledger/post", "/recipient")
                .map(|l| l.trust),
            Some(Trust::Trusted),
            "the released field was not promoted at its granted destination"
        );
        assert_eq!(
            good.label_at("/recipient").map(|l| l.trust),
            Some(Trust::Untrusted),
            "the release relabelled the base value instead of marking it"
        );
    }
}

/// Every rule `Release::validate` enforces, each with the case it rejects.
///
/// It had none. A mutation sweep replaced the whole function with `Ok(())` and
/// the suite stayed green — so all five rules were, as far as any check knew,
/// decoration. That matters more here than in most validators: this is the gate
/// on a request to **raise a label**, the one operation that turns untrusted
/// data into trusted data, and the constructors are not the only way in. A
/// `Release` deserialized from a config or a request body reaches `validate`
/// and nothing else.
#[cfg(test)]
mod release_validation_tests {
    use std::collections::BTreeSet;

    use super::{ProtectedField, Release, ReleaseScope, Sensitivity, SourceId, is_json_pointer};

    /// A release that the rules accept, which each case below then breaks in
    /// exactly one way. Without this baseline a rejection proves nothing — it
    /// could be failing for a reason the case did not intend.
    fn sound() -> Release {
        Release::fields(
            ReleaseScope::trust(),
            ["/recipient"],
            "operator matched the account to settlement SET-42",
            "tool://ledger/transfer",
            ["approval:SET-42"],
        )
    }

    #[test]
    fn the_baseline_is_accepted() {
        sound()
            .validate()
            .expect("the baseline must pass, or every case below rejects for the wrong reason");
    }

    /// A release that improves nothing is a decision record for a non-decision.
    #[test]
    fn a_scope_that_improves_nothing_is_refused() {
        let mut r = sound();
        r.scope = ReleaseScope {
            trust: false,
            sensitivity: None,
        };
        assert!(r.validate().is_err(), "a no-op release was accepted");
    }

    /// Basis and destination are what make the record answerable later.
    #[test]
    fn an_unexplained_or_undirected_release_is_refused() {
        for (field, broken) in [
            ("basis", {
                let mut r = sound();
                r.basis = "   ".to_owned();
                r
            }),
            ("destination", {
                let mut r = sound();
                r.destination = String::new();
                r
            }),
        ] {
            assert!(
                broken.validate().is_err(),
                "a release with an empty {field} was accepted, so the journal \
                 would record a decision that answers nothing"
            );
        }
    }

    /// Whole-value and field selection are alternatives, not a mixture.
    ///
    /// `""` means the whole value. Listing it *beside* paths asks for both at
    /// once, and the wider one silently wins — which is a broad release wearing
    /// a narrow one's declaration.
    #[test]
    fn a_field_scope_that_is_neither_whole_nor_valid_pointers_is_refused() {
        let empty = {
            let mut r = sound();
            r.fields.clear();
            r
        };
        assert!(
            empty.validate().is_err(),
            "a release selecting nothing was accepted"
        );

        let both = {
            let mut r = sound();
            r.fields.insert(String::new());
            r
        };
        assert!(
            both.validate().is_err(),
            "whole-value and field selection were accepted together, so the \
             broader one applies while the declaration reads narrow"
        );

        let malformed = {
            let mut r = sound();
            r.fields.clear();
            r.fields.insert("recipient".to_owned()); // no leading slash
            r
        };
        assert!(
            malformed.validate().is_err(),
            "a path that is not a JSON Pointer was accepted, so it would match \
             no field and release nothing while reading as a release"
        );
    }

    /// RFC 6901 escapes, from both sides of every branch.
    ///
    /// `is_json_pointer` decides which declared field paths are real, and its
    /// escape handling had no test at all: a sweep flipped `+= 1` to `-= 1`,
    /// `==` to `!=`, and dropped the `!` in the escape check, and every one
    /// survived. A pointer parser that accepts `~2` matches no field, so a
    /// protected-field rule written with one silently guards nothing while the
    /// manifest reads as if it does.
    #[test]
    fn a_json_pointer_is_judged_by_rfc_6901_escapes() {
        for good in [
            "/a", "/a/b", "/",     // the whole-document child, a legal pointer
            "/a~0b", // escaped tilde
            "/a~1b", // escaped solidus
            "/a~0",  // escape as the final token
            "/a~1", "/~0~1",  // adjacent escapes
            "/a~01b", // `~0` followed by an ordinary `1`
        ] {
            assert!(
                is_json_pointer(good),
                "{good} is a valid RFC 6901 pointer and was refused, so a \
                 legitimate protected field would be rejected at parse"
            );
        }

        for bad in [
            "",  // empty
            "a", // no leading solidus
            "a/b", "/a~", // trailing tilde: an escape with nothing after it
            "/~", "/a~2b", // `~` may only be followed by 0 or 1
            "/a~xb", "/~9",
        ] {
            assert!(
                !is_json_pointer(bad),
                "{bad:?} is not a valid RFC 6901 pointer and was accepted, so a \
                 rule written with it would match no field and guard nothing"
            );
        }
    }

    /// The two rules that decide whether a protected field constrains anything.
    ///
    /// Both are conjunctions, and a sweep turning either `&&` into `||` survived
    /// — so the gate on a rule arriving from a manifest was, as far as any check
    /// knew, decoration. Each case below is paired with an acceptance, because a
    /// refuse-everything mutation passes a file of refusals perfectly.
    #[test]
    fn a_protected_field_must_constrain_something_and_not_contradict_itself() {
        let trusted_and_sources = ProtectedField {
            path: "/recipient".to_owned(),
            require_trusted: true,
            allowed_sources: BTreeSet::from([SourceId::new("crm")]),
            max_sensitivity: None,
            one_of: Vec::new(),
        };
        assert!(
            trusted_and_sources.validate().is_err(),
            "require_trusted beside allowed_sources was accepted; one demands \
             the lattice's top and the other names who may supply it, so a \
             reviewer cannot tell which is in force"
        );

        let constrains_nothing = ProtectedField {
            path: "/recipient".to_owned(),
            require_trusted: false,
            allowed_sources: BTreeSet::new(),
            max_sensitivity: None,
            one_of: Vec::new(),
        };
        assert!(
            constrains_nothing.validate().is_err(),
            "a rule with no trust, source or sensitivity constraint was \
             accepted, so a field reads as protected while permitting anything"
        );

        // The three acceptances, one per constraint, so a refuse-everything
        // change cannot pass this test.
        for (label, field) in [
            (
                "trust alone",
                ProtectedField {
                    path: "/recipient".to_owned(),
                    require_trusted: true,
                    allowed_sources: BTreeSet::new(),
                    max_sensitivity: None,
                    one_of: Vec::new(),
                },
            ),
            (
                "sources alone",
                ProtectedField {
                    path: "/recipient".to_owned(),
                    require_trusted: false,
                    allowed_sources: BTreeSet::from([SourceId::new("crm")]),
                    max_sensitivity: None,
                    one_of: Vec::new(),
                },
            ),
            (
                "a sensitivity ceiling alone",
                ProtectedField {
                    path: "/recipient".to_owned(),
                    require_trusted: false,
                    allowed_sources: BTreeSet::new(),
                    max_sensitivity: Some(Sensitivity::Internal),
                    one_of: Vec::new(),
                },
            ),
            (
                "a value set alone",
                ProtectedField {
                    path: "/recipient".to_owned(),
                    require_trusted: false,
                    allowed_sources: BTreeSet::new(),
                    max_sensitivity: None,
                    one_of: vec![serde_json::json!("ACME-7")],
                },
            ),
        ] {
            assert!(
                field.validate().is_ok(),
                "{label} is a legitimate rule and was refused"
            );
        }

        let repeated_value = ProtectedField {
            path: "/recipient".to_owned(),
            require_trusted: false,
            allowed_sources: BTreeSet::new(),
            max_sensitivity: None,
            one_of: vec![serde_json::json!("ACME-7"), serde_json::json!("ACME-7")],
        };
        assert!(
            repeated_value.validate().is_err(),
            "a repeated value in one_of was accepted — one decision, written \
             twice, is the drift this crate refuses everywhere"
        );

        let bad_path = ProtectedField {
            path: "recipient".to_owned(),
            require_trusted: true,
            allowed_sources: BTreeSet::new(),
            max_sensitivity: None,
            one_of: Vec::new(),
        };
        assert!(
            bad_path.validate().is_err(),
            "a path that is not a JSON Pointer was accepted"
        );
    }

    /// Exactly one field is a field selection, not a whole-value one.
    ///
    /// `fields.len() > 1` guards the "whole value and named fields together"
    /// contradiction. A sweep relaxing it to `>=` survived, which would refuse
    /// the ordinary single-field release — the common case — while the
    /// contradiction it exists to catch still needs two entries.
    #[test]
    fn a_single_named_field_is_a_release_and_not_a_contradiction() {
        let one = {
            let mut r = sound();
            r.fields.clear();
            r.fields.insert("/recipient".to_owned());
            r
        };
        assert!(
            one.validate().is_ok(),
            "releasing exactly one named field was refused, which is the \
             ordinary shape of a field-scoped release"
        );
    }

    /// The accessors an audit reads report what was decided, not a constant.
    ///
    /// `AuditReport::releases` names the releaser, basis, **destination**,
    /// **fields** and **evidence** of every discretionary label change — the one
    /// discretionary act in the system. A sweep replaced `destination`,
    /// `fields_scope` and `evidence` with fabricated values and all three
    /// survived, including under a feature set that compiles the integration
    /// tests: every test around them asserted that a release was *refused* or
    /// *applied*, and none read back what it said it was for. An audit listing
    /// a destination nobody chose is worse than no listing, because it reads as
    /// corroboration.
    ///
    /// The values below are deliberately unalike, so a getter returning any
    /// fixed string or any other field's value is caught rather than
    /// coincidentally right.
    #[test]
    fn a_release_reports_the_decision_it_was_given() {
        let release = Release::fields(
            ReleaseScope::trust(),
            ["/recipient"],
            "four-eyes approval AC-1",
            "tool://ledger/post_entry",
            ["ticket:AC-1", "reviewer:sam"],
        );

        assert_eq!(
            release.basis(),
            "four-eyes approval AC-1",
            "the basis an audit reports is not the one the releaser gave"
        );
        assert_eq!(
            release.destination(),
            "tool://ledger/post_entry",
            "the destination an audit reports is not the sink the release named"
        );
        assert_eq!(
            release.fields_scope(),
            &["/recipient".to_owned()].into_iter().collect(),
            "the field scope an audit reports is not what was released"
        );
        assert_eq!(
            release.evidence(),
            &["reviewer:sam".to_owned(), "ticket:AC-1".to_owned()]
                .into_iter()
                .collect(),
            "the evidence an audit reports is not what was supplied — evidence \
             is the difference between a decision and an assertion"
        );
        assert!(
            !release.is_whole_value(),
            "a field-scoped release reported itself as whole-value, which is a \
             broader claim than was authorized"
        );

        let whole = Release::whole(
            ReleaseScope::trust(),
            "operator override",
            "tool://ledger/post_entry",
            ["ticket:AC-2"],
        );
        assert!(
            whole.is_whole_value(),
            "a whole-value release did not report itself as one"
        );
    }

    /// The safe constructors refuse a path that is not a JSON Pointer.
    ///
    /// `assert_json_pointer` replaced with `()` survived. The first attempt at
    /// this test aimed at `Release::fields`, which panics through `validate`
    /// rather than through the assert — so it passed with the mutation applied
    /// and proved nothing. The assert's only callers are the two
    /// `ProtectedField` constructors, and those are what a mutation of it must
    /// be caught by.
    #[test]
    fn a_protected_field_constructor_refuses_a_path_that_is_not_a_pointer() {
        for build in [
            (|| ProtectedField::trusted("recipient")) as fn() -> ProtectedField,
            || ProtectedField::from_sources("recipient", [SourceId::new("crm")]),
        ] {
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build));
            assert!(
                refused.is_err(),
                "a path with no leading solidus was accepted, so the rule would \
                 match no field and guard nothing"
            );
        }

        // The acceptance, so a panic-on-everything change cannot pass.
        let ok = ProtectedField::trusted("/recipient");
        assert_eq!(ok.path(), "/recipient");
    }

    /// Evidence is the difference between a decision and an assertion.
    #[test]
    fn a_release_with_no_usable_evidence_is_refused() {
        let none = {
            let mut r = sound();
            r.evidence.clear();
            r
        };
        assert!(
            none.validate().is_err(),
            "an evidence-free release was accepted"
        );

        let blank = {
            let mut r = sound();
            r.evidence.clear();
            r.evidence.insert("  ".to_owned());
            r
        };
        assert!(
            blank.validate().is_err(),
            "blank evidence was accepted, which passes the count and says nothing"
        );
    }

    /// A sensitivity-only release is legitimate, so the first rule must not
    /// over-reject. The negative cases above would all still pass if `validate`
    /// simply refused everything.
    #[test]
    fn improving_sensitivity_alone_is_accepted() {
        let mut r = sound();
        r.scope = ReleaseScope {
            trust: false,
            sensitivity: Some(Sensitivity::Internal),
        };
        r.validate()
            .expect("a sensitivity-only release is a legitimate decision");
    }
}
