//! Calling tools on other people's servers.
//!
//! # The security decision this module exists to make
//!
//! MCP servers advertise their tools with *annotations*: `readOnlyHint`,
//! `destructiveHint`, `idempotentHint`. They read like a safety contract. The
//! specification is explicit that they are not:
//!
//! > Clients **MUST** consider tool annotations to be untrusted unless they come
//! > from trusted servers.
//!
//! That warning lands harder here than in most runtimes, because of how the
//! declarations compose. `readOnlyHint: true` would mean [`Effect::mutates`] is
//! false; a non-mutating effect defaults to [`Recovery::Retry`]; and a retried
//! call is a second real call. So a server that marks its own money-moving tool
//! read-only could arrange for that tool to be **retried after a timeout** —
//! choosing, from the far side of the trust boundary, the one condition under
//! which this runtime performs something twice.
//!
//! So safety is not taken from the wire. It comes from a [`ToolCatalog`] the
//! operator writes, and:
//!
//! * **A tool absent from the catalogue cannot be called at all.** Fail closed:
//!   an unknown tool is one nobody has reasoned about, and discovering tools at
//!   runtime is exactly how an agent acquires authority nobody granted.
//! * **Advertised hints are recorded and compared, never obeyed.** A server
//!   claiming more safety than the operator granted is not a nuisance to
//!   normalise away — it is a signal, and it is reported.
//!
//! # What is *not* second-guessed
//!
//! The tool's output. It arrives as [`Tainted`](crate::core::Tainted) and
//! untrusted, like every other effect result, because it is the outside world's
//! data. Nothing in the catalogue can change that: the catalogue governs
//! authority, not provenance.

#[cfg(feature = "mcp")]
mod mcp;
// Not gated on a transport: a typed tool is a tool this process implements, and
// needs no wire at all.
mod typed;

#[cfg(feature = "mcp")]
pub use mcp::McpClient;
pub use typed::{Tool, ToolBox};

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    Disposition, Effect, EffectDescriptor, EffectError, ProtectedField, Recovery, RetryPolicy,
    Sensitivity, Trust,
};

/// Which tool, on which server.
///
/// The server is part of the identity because two servers may both offer
/// `transfer`, and they are not the same tool — the catalogue must be able to
/// permit one and refuse the other.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolId {
    pub server: String,
    pub tool: String,
}

impl ToolId {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
        }
    }

    /// How a **manifest** names this tool: `mcp://server/tool`.
    ///
    /// The one spelling a grant is matched against. Built here rather than at
    /// each call site because it was built at each call site, in two formats,
    /// and a tool that resolved in the catalogue then failed the manifest gate
    /// was the result.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("mcp://{}/{}", self.server, self.tool)
    }

    /// The inverse of [`reference`](Self::reference).
    ///
    /// `None` for anything that is not `mcp://server/tool`. Refusing rather
    /// than guessing: a reference this cannot parse is one the transport cannot
    /// dial either, and inventing an id from it would grant a tool nobody
    /// wrote down.
    #[must_use]
    pub fn parse(reference: &str) -> Option<Self> {
        let rest = reference.strip_prefix("mcp://")?;
        let (server, tool) = rest.split_once('/')?;
        (!server.is_empty() && !tool.is_empty() && !tool.contains('/'))
            .then(|| Self::new(server, tool))
    }

    /// How a **model** names this tool: `server__tool`.
    ///
    /// Neither `mcp://server/tool` nor `server/tool` is a legal function name —
    /// providers restrict them to letters, digits, underscore and hyphen, so a
    /// `:` or `/` is rejected before the model ever sees the tool. The double
    /// underscore is the separator because a single one appears inside ordinary
    /// tool names and would make `a_b/c` and `a/b_c` collide.
    ///
    /// This is the name [`ToolCatalog::resolve`] matches, because it is the only
    /// one a model can actually emit.
    #[must_use]
    pub fn wire_name(&self) -> String {
        format!("{}__{}", self.server, self.tool)
    }
}

impl std::fmt::Display for ToolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.server, self.tool)
    }
}

/// What the *operator* says about a tool.
///
/// Every field here decides something the runtime will do when a call goes
/// wrong, which is why none of them may come from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSafety {
    /// Whether calling this changes the world.
    ///
    /// Defaults to `true`, and the default is the whole point: an operator who
    /// has not thought about a tool gets the answer that makes the runtime
    /// cautious rather than the one that makes it fast.
    pub mutates: bool,
    /// What to do when an attempt's outcome is unknown.
    pub recovery: Recovery,
    /// The highest sensitivity this tool may be *sent*.
    pub max_sensitivity: Sensitivity,
    /// The lowest sensitivity its results carry.
    pub output_sensitivity: Sensitivity,
    /// How many attempts, and how spaced.
    pub retry: RetryPolicy,
    /// High-risk JSON arguments whose source constraints are stricter than
    /// ordinary content fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_fields: Vec<ProtectedField>,
}

impl Default for ToolSafety {
    fn default() -> Self {
        Self {
            mutates: true,
            recovery: Recovery::RequiresOperator,
            max_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
            retry: RetryPolicy::never(),
            protected_fields: Vec::new(),
        }
    }
}

/// Protected fields in a canonical order.
///
/// Order carries no meaning here — the set is what matters — so anything that
/// hashes or compares these must not be able to see it.
pub(crate) fn sorted_fields(fields: &[ProtectedField]) -> Vec<ProtectedField> {
    let mut out = fields.to_vec();
    out.sort_by(|left, right| left.path().cmp(right.path()));
    out
}

impl ToolSafety {
    /// A tool that only reads.
    ///
    /// Named for what the operator is asserting, not for what a server claimed.
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            mutates: false,
            recovery: Recovery::Retry,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn recovery(mut self, r: Recovery) -> Self {
        self.recovery = r;
        self
    }

    #[must_use]
    pub const fn max_sensitivity(mut self, s: Sensitivity) -> Self {
        self.max_sensitivity = s;
        self
    }

    #[must_use]
    pub const fn output_sensitivity(mut self, s: Sensitivity) -> Self {
        self.output_sensitivity = s;
        self
    }

    #[must_use]
    pub fn retry(mut self, r: RetryPolicy) -> Self {
        self.retry = r;
        self
    }

    /// Add a field-level information-flow rule.
    #[must_use]
    pub fn protect(mut self, field: ProtectedField) -> Self {
        assert!(
            !self
                .protected_fields
                .iter()
                .any(|existing| existing.path() == field.path()),
            "a protected tool argument may be declared only once"
        );
        self.protected_fields.push(field);
        self.protected_fields
            .sort_by(|left, right| left.path().cmp(right.path()));
        self
    }
}

/// What a server said about its own tool.
///
/// Recorded so an operator can see it and so disagreements are visible. Never
/// consulted when deciding what the runtime will do.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advertised {
    pub read_only: Option<bool>,
    pub destructive: Option<bool>,
    pub idempotent: Option<bool>,
}

impl Advertised {
    /// Whether the server claims more safety than the operator granted.
    ///
    /// Not an error — a server is entitled to describe itself, and an operator
    /// is entitled to disagree. It is reported because the interesting case is
    /// a server that *starts* claiming to be read-only after an update, which
    /// is what a compromised or swapped-out server looks like from here.
    #[must_use]
    pub fn overclaims(&self, safety: &ToolSafety) -> bool {
        (self.read_only == Some(true) && safety.mutates)
            || (self.idempotent == Some(true)
                && safety.mutates
                && matches!(safety.recovery, Recovery::RequiresOperator))
    }
}

/// Why a tool call could not be made, or did not work.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// The call never left. Safe to repeat.
    #[error("could not reach '{tool}': {detail}")]
    Unreachable { tool: ToolId, detail: String },

    /// The server received the request and declined it without running the tool
    /// — unknown method, invalid arguments. The request is intact.
    #[error("'{tool}' refused the request: {detail}")]
    Refused { tool: ToolId, detail: String },

    /// It was sent and the outcome is unknown.
    ///
    /// The dangerous one, and the reason [`ToolSafety::recovery`] exists: a
    /// timeout is not evidence that nothing happened.
    #[error("'{tool}' did not answer in time: {detail}")]
    TimedOut { tool: ToolId, detail: String },

    /// The server ran the tool and the tool reported failure.
    ///
    /// Distinct from the two above because the call *landed*: repeating it would
    /// be a second real invocation.
    #[error("'{tool}' reported an error: {detail}")]
    ToolFailed { tool: ToolId, detail: String },

    /// The server answered with something that is not a tool result.
    #[error("'{tool}' returned a malformed response: {detail}")]
    Malformed { tool: ToolId, detail: String },
}

impl ToolError {
    /// What this failure says about whether the call reached the world.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::Unreachable { .. } | Self::Refused { .. } => Disposition::DidNotHappen,
            Self::TimedOut { .. } => Disposition::InDoubt,
            // The tool ran. Both of these mean the far side did work.
            Self::ToolFailed { .. } | Self::Malformed { .. } => Disposition::Landed,
        }
    }
}

/// Transports a tool call. Implemented by the MCP adapter, or by anything else.
#[async_trait]
pub trait ToolClient: Send + Sync + Debug {
    /// Invoke a tool and return its result.
    ///
    /// # Errors
    ///
    /// A [`ToolError`] whose variant states what is known about whether the call
    /// reached the far side. Getting that wrong is how a payment happens twice,
    /// so an implementation that cannot tell must say [`ToolError::TimedOut`].
    /// `provenance` is what the callee may check: which run, which effect,
    /// which agent, signed for exactly this call. A transport that has nowhere
    /// to put it ignores it — that is a weaker deployment, not a broken one —
    /// but it must never *invent* one, because a fabricated block is precisely
    /// the compromised-intermediary case the signature exists to detect.
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, ToolError>;
}

/// The tools this plane may call, and what the operator says about each.
#[derive(Debug, Default, Clone)]
pub struct ToolCatalog {
    entries: BTreeMap<ToolId, (ToolSafety, Advertised)>,
}

impl ToolCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every tool a manifest declares, with the safety it declared.
    ///
    /// # Why this exists
    ///
    /// A manifest and a catalogue are two parties speaking: the agent's author
    /// says what it needs, the operator says what it may have. That separation
    /// is real in a deployment where those are different people — and pure tax
    /// when they are the same one, which is most of the time. Stating `mutates`,
    /// `max_sensitivity` and the protected fields **twice** is not two
    /// decisions, it is one decision and a chance to disagree about it.
    ///
    /// So the common case is one declaration. An operator who wants to say
    /// something different still can: `allow` after this replaces an entry, and
    /// the manifest's own grant is re-checked at dispatch regardless — a
    /// catalogue cannot widen what a declaration never asked for.
    ///
    /// The fields a manifest does not carry — retry, recovery, output
    /// sensitivity — take their cautious defaults, which is the same posture a
    /// hand-written `ToolSafety::default()` starts from.
    #[cfg(feature = "manifest")]
    #[must_use]
    pub fn from_manifest(manifest: &crate::manifest::Manifest) -> Self {
        let mut catalog = Self::new();
        for grant in &manifest.spec.tools {
            let Some(id) = ToolId::parse(&grant.reference) else {
                // A reference the transport cannot name is refused by manifest
                // validation, so reaching here means the two disagree about
                // what a reference is — and inventing an id would grant a tool
                // nobody wrote down.
                continue;
            };
            let safety = ToolSafety {
                mutates: grant.mutates,
                protected_fields: grant.protected_fields.clone(),
                // The fields a manifest does not carry take their cautious
                // defaults, which is where a hand-written safety starts too.
                max_sensitivity: grant
                    .max_sensitivity
                    .unwrap_or(ToolSafety::default().max_sensitivity),
                ..ToolSafety::default()
            };
            catalog = catalog.allow(id, safety);
        }
        catalog
    }

    /// Permit a tool, with the operator's declaration of what it does.
    #[must_use]
    pub fn allow(mut self, id: ToolId, safety: ToolSafety) -> Self {
        self.entries.insert(id, (safety, Advertised::default()));
        self
    }

    /// Every entry, so several agents' catalogues can be combined.
    ///
    /// Owned rather than borrowed because a merge builds a new catalogue: two
    /// agents on one plane may each declare tools, and the plane needs both.
    #[must_use]
    pub fn entries(self) -> Vec<(ToolId, ToolSafety)> {
        self.entries
            .into_iter()
            .map(|(id, (safety, _))| (id, safety))
            .collect()
    }

    /// Resolve a name a **model** chose to a tool the operator granted.
    ///
    /// This is the bridge between a completion and a dispatch, and it is where
    /// most of the risk in tool-calling lives. A model emits a flat string it
    /// generated; everything downstream treats the result as authority. So the
    /// match is exact and total: the name must equal a granted tool's
    /// `server/tool` rendering, byte for byte.
    ///
    /// **Nothing is resolved approximately.** No case folding, no trimming, no
    /// nearest neighbour, no prefix. A model that writes `ledger/Transfer` or
    /// `ledger/transfer ` gets a refusal, not the tool it nearly named — because
    /// the whole point of a catalogue is that authority comes from the
    /// operator's list rather than from a string a model produced, and a
    /// resolver that helpfully corrects a near miss has handed the model the
    /// power to reach a tool by describing it.
    ///
    /// The name compared is [`ToolId::wire_name`] — the only spelling a
    /// provider permits a model to emit.
    ///
    /// `None` means refused. The caller must not fall back.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<ToolId> {
        self.entries
            .keys()
            .find(|id| id.wire_name() == name)
            .cloned()
    }

    /// Find a tool by the spelling a **manifest** uses.
    ///
    /// The counterpart to [`resolve`](Self::resolve), which takes the spelling a
    /// *model* uses. Two spellings because a manifest reference is a URI a human
    /// reviews and a wire name is what a provider permits a model to emit — and
    /// both are derived in one place each, because they were once derived in
    /// three places in two formats.
    #[must_use]
    pub fn resolve_reference(&self, reference: &str) -> Option<ToolId> {
        self.entries
            .keys()
            .find(|id| id.reference() == reference)
            .cloned()
    }

    /// Every granted tool, for declaring to a model.
    ///
    /// Declare from here rather than from a hand-written list: offering a model
    /// a tool the catalogue does not grant produces a call that is refused after
    /// the tokens are paid for, and offering fewer than are granted hides
    /// capability for no reason. One source, so the two cannot disagree.
    pub fn granted(&self) -> impl Iterator<Item = &ToolId> {
        self.entries.keys()
    }

    /// Record what a server advertised about a tool it offers.
    ///
    /// Changes nothing about how the tool is treated. It exists so the
    /// disagreement is visible.
    #[must_use]
    pub fn observed(mut self, id: &ToolId, advertised: Advertised) -> Self {
        if let Some(entry) = self.entries.get_mut(id) {
            entry.1 = advertised;
        }
        self
    }

    /// The operator's declaration, if this tool is permitted at all.
    #[must_use]
    pub fn safety(&self, id: &ToolId) -> Option<&ToolSafety> {
        self.entries.get(id).map(|(s, _)| s)
    }

    #[must_use]
    pub fn advertised(&self, id: &ToolId) -> Option<&Advertised> {
        self.entries.get(id).map(|(_, a)| a)
    }

    /// Tools where the server claims more safety than the operator granted.
    ///
    /// Worth surfacing at startup: a server that begins advertising itself as
    /// read-only after an upgrade is indistinguishable, from here, from one that
    /// has been replaced.
    pub fn overclaiming(&self) -> impl Iterator<Item = &ToolId> {
        self.entries
            .iter()
            .filter(|(_, (safety, adv))| adv.overclaims(safety))
            .map(|(id, _)| id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// One call to one tool.
///
/// Built through [`ToolCatalog`], so a tool nobody declared cannot be
/// constructed — the refusal happens before an effect exists, rather than inside
/// one.
#[derive(Debug)]
pub struct ToolCall {
    id: ToolId,
    arguments: Value,
    safety: ToolSafety,
    client: std::sync::Arc<dyn ToolClient>,
    /// Who is calling, sealed for this call. Set by the runtime via
    /// [`Effect::attach`](crate::core::Effect::attach), because it contains the
    /// effect key and an effect does not know its own.
    provenance: Option<crate::core::Provenance>,
}

impl ToolCall {
    /// Prepare a call, if the operator permits this tool.
    ///
    /// # Errors
    ///
    /// [`ToolError::Unreachable`] when the tool is not in the catalogue. It is
    /// deliberately not a separate "unknown tool" error at the call site: from
    /// the run's point of view an undeclared tool is one it cannot reach, and
    /// treating it as anything softer invites a fallback.
    pub fn prepare(
        catalog: &ToolCatalog,
        client: std::sync::Arc<dyn ToolClient>,
        id: ToolId,
        arguments: Value,
    ) -> Result<Self, ToolError> {
        let Some(safety) = catalog.safety(&id) else {
            return Err(ToolError::Unreachable {
                detail: "this tool is not in the catalogue; a tool nobody declared is a \
                         tool nobody has reasoned about"
                    .into(),
                tool: id,
            });
        };
        Ok(Self {
            safety: safety.clone(),
            id,
            arguments,
            client,
            provenance: None,
        })
    }
}

#[async_trait]
impl Effect for ToolCall {
    fn gen_ai_operation(&self) -> Option<&'static str> {
        Some(crate::runtime::telemetry::GEN_AI_EXECUTE_TOOL)
    }

    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        // The server and tool are part of the key, so two servers offering the
        // same tool name are two different effects and cannot replay into each
        // other.
        EffectDescriptor::new(
            "mcp.tools/call",
            serde_json::json!({
                "server": self.id.server,
                "tool": self.id.tool,
                "arguments": self.arguments,
                // Sorted here, not merely by the builder. `protect()` sorts,
                // but a `ToolSafety` built by struct literal or deserialised
                // from config never passes through it — and declaration order
                // would then change the **effect key**, so the same call
                // replayed against a differently-ordered catalogue would report
                // divergence. Canonicalising at the one place the value is
                // hashed makes the order unobservable.
                "protected_fields": sorted_fields(&self.safety.protected_fields),
            }),
        )
    }

    fn mutates(&self) -> bool {
        self.safety.mutates
    }

    fn recovery(&self) -> Recovery {
        self.safety.recovery.clone()
    }

    fn retry(&self) -> RetryPolicy {
        self.safety.retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.safety.max_sensitivity
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.arguments)
    }

    fn protected_fields(&self) -> &[ProtectedField] {
        &self.safety.protected_fields
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.safety.output_sensitivity
    }

    /// A tool result is the outside world's data.
    ///
    /// Stated rather than inherited, because this is the one effect where a
    /// reader is most likely to wonder whether the catalogue could relax it. It
    /// cannot: the catalogue governs authority, not provenance.
    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn attach(&mut self, provenance: &crate::core::Provenance) {
        self.provenance = Some(provenance.clone());
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.client
            .call(&self.id, &self.arguments, self.provenance.as_ref())
            .await
            .map_err(|e| {
                let detail = e.to_string();
                // The disposition is what decides whether this is ever tried
                // again, so the mapping is explicit rather than a default arm.
                match e.disposition() {
                    Disposition::DidNotHappen => EffectError::Rejected(detail),
                    Disposition::InDoubt => EffectError::Interrupted {
                        driver: self.id.to_string(),
                        detail,
                    },
                    Disposition::Landed => EffectError::Performed(detail),
                }
            })
    }
}
