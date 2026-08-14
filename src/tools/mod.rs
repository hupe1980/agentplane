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
pub use mcp::{
    McpAccess, McpClient, McpDataSafety, McpPrompt, McpResource, McpTask, McpTaskCancel,
    McpTaskPoll, McpTaskSnapshot, McpTaskState, McpTaskUpdate,
};
pub use typed::{Tool, ToolBox, ToolFailure};

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

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
///
/// The server name is the **operator's local name for a provider**, not
/// anything the far side chose, and it is what [`ToolRouter`] dispatches on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolId {
    pub server: String,
    pub tool: String,
}

/// The scheme a manifest grant is written in.
///
/// Deliberately transport-neutral, and it did not start that way. Grants were
/// spelled `mcp://server/tool` — including for tools compiled into this binary,
/// which never touch MCP. A manifest is a **review artifact** and an Agent Card
/// republishes its tool references, so that scheme was asserting a supply-chain
/// fact the document cannot know, to readers who have no way to check it. A
/// false statement in a reviewed file is the defect this crate refuses
/// everywhere else.
///
/// A reference names *which tool*. Which transport reaches its server is a
/// **deployment** decision, made by [`ToolRouter`] — and keeping it there is
/// also what lets one manifest run against an in-process double in a test and a
/// real MCP server in production, which a transport-bearing reference forbids.
pub const TOOL_SCHEME: &str = "tool://";

/// The reserved server that names **agents on this plane** rather than a
/// transport.
///
/// A grant spelled `tool://agent/<capability>` offers another agent's
/// capability to a tool-calling model. Dispatch is `StepCtx::commission`, not
/// a wire: the consultation is a journaled delegation effect, so it replays,
/// the label travels, the sub-run's spend bills the run that asked, and the
/// specialist's own manifest still governs everything it does. The server
/// component is reserved — wiring a remote transport or a typed tool under
/// this name is refused at build, because a name that could mean either "an
/// agent here" or "somebody's server" would let a deployment change which one
/// answers without changing any reviewed document.
pub const AGENT_SERVER: &str = "agent";

impl ToolId {
    pub fn new(server: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
        }
    }

    /// How a **manifest** names this tool: `tool://server/name`.
    ///
    /// The one spelling a grant is matched against. Built here rather than at
    /// each call site because it was built at each call site, in two formats,
    /// and a tool that resolved in the catalogue then failed the manifest gate
    /// was the result.
    #[must_use]
    pub fn reference(&self) -> String {
        format!("{TOOL_SCHEME}{}/{}", self.server, self.tool)
    }

    /// The inverse of [`reference`](Self::reference).
    ///
    /// `None` for anything that is not `tool://server/name`, and for
    /// components no wire name could carry — see [`wire_name`](Self::wire_name)
    /// for the charset. Refusing rather than guessing: a reference this cannot
    /// parse is one no router can dial, and inventing an id from it would
    /// grant a tool nobody wrote down.
    #[must_use]
    pub fn parse(reference: &str) -> Option<Self> {
        let rest = reference.strip_prefix(TOOL_SCHEME)?;
        let (server, tool) = rest.split_once('/')?;
        (valid_component(server) && valid_component(tool) && !tool.contains('/'))
            .then(|| Self::new(server, tool))
    }

    /// How a **model** names this tool: `server__tool`, dots rendered as `-`.
    ///
    /// Neither `tool://server/tool` nor `server/tool` is a legal function name
    /// — providers restrict them to letters, digits, underscore and hyphen
    /// (Gemini also permits dots, but a name must be legal everywhere) — so a
    /// `:` or `/` is rejected before the model ever sees the tool. Two rules
    /// make the rendering readable *and* injective:
    ///
    /// * **`.` becomes `-`.** Capabilities are conventionally dotted
    ///   (`blog.research`), and `-` is legal in every shipped provider's
    ///   charset — so `tool://agent/blog.research` reads as
    ///   `agent__blog-research` rather than an escape soup.
    /// * **The separator is `__`, and it cannot occur elsewhere.** Components
    ///   are refused at declaration if they contain `-` (which would collide
    ///   with a rendered dot), contain `__`, or start or end with `_` (either
    ///   of which would let ordinary underscores run into the separator). The
    ///   one `__` in a wire name is therefore the boundary, and the mapping
    ///   back is exact.
    ///
    /// An earlier scheme escaped `_`→`_u` and `.`→`_d`, which was injective
    /// and unreadable — `agent__blog_dresearch` — and its readability cost was
    /// paid at exactly the wrong moment: by someone diffing a model's chosen
    /// tool against an operator's grant. Refusing a few pathological names at
    /// declaration ([`ToolCatalog::allow`] panics; [`ToolId::parse`] returns
    /// `None`) is the better trade.
    ///
    /// This is the name [`ToolCatalog::resolve`] matches, because it is the
    /// only one a model can actually emit.
    #[must_use]
    pub fn wire_name(&self) -> String {
        format!(
            "{}__{}",
            wire_component(&self.server),
            wire_component(&self.tool)
        )
    }
}

/// Render one component for the wire: dots become hyphens.
///
/// Injective because [`valid_component`] refuses a literal `-` on the way in —
/// every hyphen a model sees denotes a dot, and every other byte is itself.
fn wire_component(value: &str) -> String {
    value.replace('.', "-")
}

/// Whether a server or tool name may appear in a wire name.
///
/// Letters, digits, `_` and `.` only; no `__`; no leading or trailing `_`; no
/// `-`. Each refusal protects the wire rendering's injectivity or the
/// providers' charsets — see [`ToolId::wire_name`] — and each is enforced
/// where a tool is *declared*, never against a name a model emitted: a model's
/// near-miss is a failed resolve, not a panic.
fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && !value.contains("__")
        && !value.starts_with('_')
        && !value.ends_with('_')
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
        // Every overclaim is a safety promise about a tool the operator declared
        // *mutating*; a read-only grant has nothing to overclaim against.
        if !safety.mutates {
            return false;
        }
        // Read-only or "not destructive" on a mutating grant are the same signal
        // — a server claiming more safety than it was given, which is what a
        // swapped-out server looks like from here. `destructive` was recorded and
        // never read, so the claim that most invites "this is safe to repeat"
        // went unchecked.
        self.read_only == Some(true)
            || self.destructive == Some(false)
            // Idempotent, but only where repeating is genuinely unsafe.
            || (self.idempotent == Some(true)
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
    /// What a model is shown. Separate from safety because presentation is not
    /// authority, and absent for catalogues used only by hand-written skills.
    #[cfg(feature = "manifest")]
    declarations: BTreeMap<ToolId, (String, Value)>,
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
            catalog = catalog.allow(id.clone(), safety);
            if grant.description.is_some() || grant.arguments.is_some() {
                catalog = catalog.declare(
                    id,
                    grant.description.clone().unwrap_or_default(),
                    grant
                        .arguments
                        .clone()
                        .unwrap_or_else(|| serde_json::json!({ "type": "object" })),
                );
            }
        }
        catalog
    }

    /// Permit a tool, with the operator's declaration of what it does.
    ///
    /// # Panics
    ///
    /// If either component of the id could not appear in a wire name — a
    /// literal `-`, a `__`, a leading or trailing `_`, or a byte outside
    /// letters, digits, `_` and `.` — because a granted tool the model cannot
    /// be offered under an unambiguous name is a wiring mistake, and this is
    /// the one place every declaration passes. See [`ToolId::wire_name`].
    #[must_use]
    pub fn allow(mut self, id: ToolId, safety: ToolSafety) -> Self {
        assert!(
            valid_component(&id.server) && valid_component(&id.tool),
            "tool id '{id}' cannot be rendered as a wire name: server and tool may \
             hold letters, digits, `_` and `.`, with no `-`, no `__`, and no leading \
             or trailing `_` — a name outside that set would collide with, or split \
             on, the `__` separator and the `.`→`-` rendering"
        );
        self.entries.insert(id, (safety, Advertised::default()));
        self
    }

    /// Attach the description and argument schema a model is shown.
    ///
    /// Crate-private because callers should either derive this from a
    /// [`ToolBox`] or keep it in the digest-covered manifest. A third public
    /// declaration path would recreate the drift this method removes.
    #[cfg(feature = "manifest")]
    pub(crate) fn declare(mut self, id: ToolId, description: String, arguments: Value) -> Self {
        self.declarations.insert(id, (description, arguments));
        self
    }

    /// Model-facing declaration, when this catalogue carries one.
    #[cfg(feature = "manifest")]
    pub(crate) fn declaration(&self, id: &ToolId) -> Option<(&str, &Value)> {
        self.declarations
            .get(id)
            .map(|(description, arguments)| (description.as_str(), arguments))
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
            // Recorded and compared, never obeyed — and the "compared" half
            // must reach somebody: an advertisement that outgrows its grant
            // is the first observable move of a server going bad, and a
            // discrepancy only visible to code that calls `overclaiming()` by
            // hand is detection without delivery. A warning, not an error,
            // because the grant is the ceiling either way; what the operator
            // is being told is that the server now *wants* more than they
            // gave it.
            if advertised.overclaims(&entry.0) {
                tracing::warn!(
                    tool = %id,
                    "this tool's server now advertises more safety than the \
                     operator granted; the grant still rules, but the \
                     advertisement changed"
                );
            }
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

/// Which client reaches which server.
///
/// # Why a plane needs one at all
///
/// A [`ToolId`] carries a server because two servers may both offer `transfer`
/// and they are not the same tool. Nothing enforced that: a plane held exactly
/// one [`ToolClient`] and handed it every id, so a deployment could grant
/// `tool://ledger/read` and wire a client connected to a *different* server —
/// which then answered, because a transport that never reads the server
/// component cannot tell the difference. The realistic shape is two servers with
/// a tool of the same name, where the wrong one runs and reports success.
///
/// One client per server, resolved by name, makes that unspellable. A server
/// nobody registered is [`ToolError::Unreachable`] — the honest answer, since
/// there is no transport that could carry the call.
///
/// It is also what lets a plane use more than one kind of tool at once. A
/// [`ToolBox`] of typed in-process tools and an MCP server are two transports,
/// and before this a plane could have exactly one of them.
#[derive(Debug, Default)]
pub struct ToolRouter {
    routes: BTreeMap<String, Arc<dyn ToolClient>>,
}

impl ToolRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route one server's tools to one client.
    ///
    /// # Panics
    ///
    /// If the server is already routed. Silently replacing would make
    /// registration order decide which transport carries a call, which is the
    /// same defect this type exists to remove.
    #[must_use]
    pub fn server(mut self, name: impl Into<String>, client: Arc<dyn ToolClient>) -> Self {
        let name = name.into();
        assert!(
            !self.routes.contains_key(&name),
            "tool server '{name}' is routed twice — one of the two transports would \
             silently never be called"
        );
        self.routes.insert(name, client);
        self
    }

    /// Route every server the box implements to the box.
    ///
    /// A typed tool names its own server, so the box already knows which ones it
    /// answers for; asking a caller to repeat them would be one decision written
    /// twice.
    #[must_use]
    pub fn toolbox(self, tools: &Arc<ToolBox>) -> Self {
        let servers: Vec<String> = tools.servers().map(ToOwned::to_owned).collect();
        servers.into_iter().fold(self, |router, name| {
            router.server(name, Arc::clone(tools) as Arc<dyn ToolClient>)
        })
    }

    /// The servers this router can reach.
    pub fn servers(&self) -> impl Iterator<Item = &str> {
        self.routes.keys().map(String::as_str)
    }
}

#[async_trait]
impl ToolClient for ToolRouter {
    async fn call(
        &self,
        tool: &ToolId,
        arguments: &Value,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, ToolError> {
        let Some(client) = self.routes.get(&tool.server) else {
            return Err(ToolError::Unreachable {
                tool: tool.clone(),
                detail: format!(
                    "no transport is wired for tool server '{}'; this plane routes {:?}",
                    tool.server,
                    self.routes.keys().collect::<Vec<_>>()
                ),
            });
        };
        client.call(tool, arguments, provenance).await
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
    /// # Prefer `StepCtx::call_tool`
    ///
    /// This takes whatever catalogue it is handed, and **nothing here binds that
    /// catalogue to the manifest governing the caller**. A hand-built one —
    /// which is the obvious thing to write, and what an older version of
    /// `examples/governed_transfer.rs` demonstrated — compiles, runs, and can be
    /// *laxer* than the declaration: a [`ToolSafety::read_only`] entry for a tool
    /// the manifest calls mutating exempts it from the whole-value taint gate and
    /// carries [`Recovery::Retry`], so a timed-out money-moving call is sent
    /// again. The plane's own catalogue is refused at build for exactly that
    /// divergence; a skill's is not checked by anything.
    ///
    /// [`StepCtx::call_tool`](crate::runtime::StepCtx::call_tool) dispatches
    /// over the plane's checked catalogue and makes the drift unrepresentable.
    /// Where a skill genuinely needs its own — a catalogue assembled before a
    /// runtime exists, or one for a test — build it with
    /// [`ToolCatalog::from_manifest`], which derives the reach from the
    /// declaration rather than restating it.
    ///
    /// [`ToolSafety::read_only`]: ToolSafety::read_only
    /// [`Recovery::Retry`]: crate::core::Recovery::Retry
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
            "tool.call",
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

    /// The tool's own reference, so a source rule can name *this* tool.
    ///
    /// `tool://server/name` — the spelling a manifest grants and a reviewer
    /// reads. Under the family-level default every granted tool answered as
    /// `effect:tool.call`, so a `ProtectedField::from_sources` rule could not
    /// distinguish the CRM lookup from the ticket search: "the recipient must
    /// come from the CRM" was unsatisfiable strictly, and satisfiable loosely
    /// by whichever tool an injected prompt reached first.
    fn source(&self) -> crate::core::SourceId {
        crate::core::SourceId::new(self.id.reference())
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

#[cfg(test)]
mod overclaim_tests {
    use super::*;

    /// Each safety claim is checked on its own, so removing any one clause is a
    /// real regression rather than one masked by another firing on the same
    /// fixture. `destructive == Some(false)` on a mutating grant is the clause
    /// that was recorded and never read.
    #[test]
    fn a_server_claiming_more_safety_than_granted_is_flagged_per_clause() {
        let mutating = ToolSafety::default(); // mutates: true, Recovery::default
        let operator_needs_operator = ToolSafety::default().recovery(Recovery::RequiresOperator);

        // read-only lie
        assert!(
            Advertised {
                read_only: Some(true),
                ..Advertised::default()
            }
            .overclaims(&mutating)
        );

        // not-destructive lie — the clause under test
        assert!(
            Advertised {
                destructive: Some(false),
                ..Advertised::default()
            }
            .overclaims(&mutating)
        );

        // idempotent lie, but only when repeating is unsafe
        assert!(
            Advertised {
                idempotent: Some(true),
                ..Advertised::default()
            }
            .overclaims(&operator_needs_operator)
        );

        // Honest advertisements and honest silence do not flag.
        assert!(
            !Advertised {
                destructive: Some(true),
                read_only: Some(false),
                idempotent: Some(false),
            }
            .overclaims(&mutating)
        );
        assert!(!Advertised::default().overclaims(&mutating));
        assert!(
            !Advertised {
                read_only: Some(true),
                destructive: Some(false),
                idempotent: Some(true),
            }
            .overclaims(&ToolSafety::read_only())
        );
    }
}
