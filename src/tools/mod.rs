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
#[cfg(feature = "mcp")]
pub use mcp::McpClient;

use std::collections::BTreeMap;
use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    Disposition, Effect, EffectDescriptor, EffectError, Recovery, RetryPolicy, Sensitivity, Trust,
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
}

impl Default for ToolSafety {
    fn default() -> Self {
        Self {
            mutates: true,
            recovery: Recovery::RequiresOperator,
            max_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
            retry: RetryPolicy::never(),
        }
    }
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

    /// Permit a tool, with the operator's declaration of what it does.
    #[must_use]
    pub fn allow(mut self, id: ToolId, safety: ToolSafety) -> Self {
        self.entries.insert(id, (safety, Advertised::default()));
        self
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
