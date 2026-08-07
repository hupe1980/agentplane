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

/// A stricter information-flow rule for one JSON field sent to a sink.
///
/// Paths use RFC 6901 JSON Pointer syntax. An operator can require a protected
/// field to remain trusted, or permit it only when every contributing source is
/// in an explicit set. Ordinary content fields may remain untrusted without
/// granting them influence over recipient, amount, command, path, URL, tenant,
/// audience, model, or tool selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedField {
    path: String,
    #[serde(default)]
    require_trusted: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    allowed_sources: BTreeSet<SourceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_sensitivity: Option<Sensitivity>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        evidence: impl IntoIterator<Item = String>,
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
        fields: impl IntoIterator<Item = String>,
        basis: impl Into<String>,
        destination: impl Into<String>,
        evidence: impl IntoIterator<Item = String>,
    ) -> Self {
        Self::new(scope, fields, basis, destination, evidence)
    }

    fn new(
        scope: ReleaseScope,
        fields: impl IntoIterator<Item = String>,
        basis: impl Into<String>,
        destination: impl Into<String>,
        evidence: impl IntoIterator<Item = String>,
    ) -> Self {
        let basis = basis.into();
        let destination = destination.into();
        let fields = fields.into_iter().collect::<BTreeSet<_>>();
        let evidence = evidence.into_iter().collect::<BTreeSet<_>>();
        assert!(
            scope.trust || scope.sensitivity.is_some(),
            "a release scope must improve trust, sensitivity, or both"
        );
        assert!(!basis.trim().is_empty(), "a release must state its basis");
        assert!(
            !destination.trim().is_empty(),
            "a release must name its destination"
        );
        assert!(!fields.is_empty(), "a release must name at least one field");
        assert!(
            fields.len() == 1 || !fields.contains(""),
            "a whole-value release cannot be mixed with field releases"
        );
        for path in &fields {
            if !path.is_empty() {
                assert_json_pointer(path);
            }
        }
        assert!(
            !evidence.is_empty() && evidence.iter().all(|item| !item.trim().is_empty()),
            "a release must carry non-empty evidence"
        );
        Self {
            scope,
            basis,
            destination,
            fields,
            evidence,
        }
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
        }
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
        {
            return Err("at least one trust, source, or sensitivity constraint is required");
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
}

impl<T> Tainted<T> {
    /// Wrap a value the operator vouches for: manifest content, run input,
    /// constants.
    pub fn trusted(value: T) -> Self {
        Self {
            value,
            label: Label::trusted(),
            fields: BTreeMap::new(),
        }
    }

    /// Wrap a value that crossed a trust boundary.
    pub fn from_source(value: T, source: SourceId) -> Self {
        Self {
            value,
            label: Label::untrusted(source),
            fields: BTreeMap::new(),
        }
    }

    pub fn with_label(value: T, label: Label) -> Self {
        Self {
            value,
            label,
            fields: BTreeMap::new(),
        }
    }

    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Clone this value with an additional whole-value dependency.
    ///
    /// Structured field labels remain intact: a trusted selector such as a
    /// model instruction does not become untrusted merely because another
    /// provider-visible part of the same request contains tool output. The
    /// whole-value label still joins, so egress ceilings see that dependency.
    #[cfg(feature = "manifest")]
    pub(crate) fn with_joined_label(&self, other: &Label) -> Self
    where
        T: Clone,
    {
        Self {
            value: self.value.clone(),
            label: self.label.join(other),
            fields: self.fields.clone(),
        }
    }

    /// Read without unwrapping. Safe by design: the lattice governs where a
    /// value may *go*, not whether it may be inspected.
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
        Tainted {
            value: f(self.value),
            label: self.label,
            fields: BTreeMap::new(),
        }
    }

    /// Combine two labeled values. Labels join, which is how untrust
    /// propagates: mixing anything with an untrusted value yields untrusted.
    /// Arbitrary tuple construction invalidates structured JSON paths, so any
    /// field maps are deliberately discarded.
    pub fn zip<U>(self, other: Tainted<U>) -> Tainted<(T, U)> {
        let label = self.label.join(&other.label);
        Tainted {
            value: (self.value, other.value),
            label,
            fields: BTreeMap::new(),
        }
    }
}

impl Tainted<serde_json::Value> {
    /// Build a JSON object without flattening the labels of its fields.
    pub fn object(fields: impl IntoIterator<Item = (String, Self)>) -> Self {
        let mut value = serde_json::Map::new();
        let mut label = Label::trusted();
        let mut field_labels = BTreeMap::new();

        for (name, field) in fields {
            let base = format!("/{}", escape_pointer_token(&name));
            label = label.join(&field.label);
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
        }
    }

    /// Build a JSON array without flattening the labels of its elements.
    pub fn array(elements: impl IntoIterator<Item = Self>) -> Self {
        let mut value = Vec::new();
        let mut label = Label::trusted();
        let mut field_labels = BTreeMap::new();

        for (index, element) in elements.into_iter().enumerate() {
            let base = format!("/{index}");
            label = label.join(&element.label);
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
        })
    }

    /// Apply an authorized release. The runtime owns the only call site.
    pub(crate) fn apply_release(mut self, release: &Release) -> Option<Self> {
        if release.is_whole_value() {
            self.label = apply_release_scope(&self.label, release.scope);
            for label in self.fields.values_mut() {
                *label = apply_release_scope(label, release.scope);
            }
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
            let descendants = format!("{released}/");
            for (path, label) in &mut self.fields {
                if path == released || path.starts_with(&descendants) {
                    *label = apply_release_scope(label, release.scope);
                }
            }
        }
        self.label = self
            .fields
            .values()
            .fold(Label::trusted(), |joined, label| joined.join(label));
        Some(self)
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
            ("safe".to_owned(), Tainted::trusted(serde_json::json!("ok"))),
            (
                "body".to_owned(),
                Tainted::from_source(serde_json::json!("outside"), src("model")),
            ),
        ]);
        let value = Tainted::object([
            ("selected".to_owned(), nested),
            (
                "other".to_owned(),
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

    #[test]
    fn field_release_improves_only_its_declared_scope() {
        let value = Tainted::object([
            (
                "recipient".to_owned(),
                Tainted::from_source(serde_json::json!("treasury"), src("model")),
            ),
            (
                "memo".to_owned(),
                Tainted::from_source(serde_json::json!("outside"), src("model")),
            ),
        ]);
        let release = Release::fields(
            ReleaseScope::trust(),
            ["/recipient".to_owned()],
            "operator verified account",
            "ledger.transfer",
            ["approval:42".to_owned()],
        );

        let released = value.apply_release(&release).unwrap();
        let recipient = released.label_at("/recipient").unwrap();
        assert_eq!(recipient.trust, Trust::Trusted);
        assert_eq!(recipient.sensitivity, Sensitivity::Internal);
        assert_eq!(recipient.provenance, BTreeSet::from([src("model")]));
        assert!(released.label_at("/memo").unwrap().is_untrusted());
        assert!(
            released.label().is_untrusted(),
            "unreleased content still taints"
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
    use super::{Release, ReleaseScope, Sensitivity};

    /// A release that the rules accept, which each case below then breaks in
    /// exactly one way. Without this baseline a rejection proves nothing — it
    /// could be failing for a reason the case did not intend.
    fn sound() -> Release {
        Release::fields(
            ReleaseScope::trust(),
            ["/recipient".to_owned()],
            "operator matched the account to settlement SET-42",
            "tool://ledger/transfer",
            ["approval:SET-42".to_owned()],
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
