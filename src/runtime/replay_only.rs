//! Drivers for a pass that calls nobody.
//!
//! A strict replay serves every model completion, tool result and peer reply
//! from the journal, so it needs no provider credential, no tool server and no
//! peer. It still needs *something registered* under each name the
//! declaration uses — a declarative agent's tool catalogue is derived from its
//! grants and refuses to build with a grant nothing answers — and each of
//! these answers that name while refusing every call. A strict replay that
//! reached one would be reaching the world, and the refusal says so.
//!
//! **What they must reproduce is the effect identity.** A model call's key
//! commits to the driver's request profile (its endpoint, schema mode,
//! streaming), which is deployment wiring rather than declaration, so
//! [`Provider`] reads it back from the history it is replaying: the verdict is
//! about the declaration in hand, not about this machine's provider setup. A
//! grant served by an A2A peer dispatches a different effect than one served
//! by a tool server, so [`wire`] registers as a peer every server the history
//! called as one.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use serde_json::Value;

use crate::journal::{Record, RecordKind};

const REFUSAL: &str = "a strict replay reached for the world: every call it makes must be \
                       served from the recorded history, and this one was not";

/// A model provider that answers with the recorded request profile and
/// refuses every completion.
#[derive(Debug, Default, Clone)]
pub struct Provider {
    profiles: BTreeMap<(String, String), Value>,
}

impl Provider {
    /// The request profile each `(provider, model)` pair was called with, read
    /// from `history`'s model calls.
    #[must_use]
    pub fn from_history(history: &[Record]) -> Self {
        let mut profiles = BTreeMap::new();
        for record in history {
            let RecordKind::EffectStarted { descriptor, .. } = record.kind() else {
                continue;
            };
            if descriptor.kind != "model.complete" {
                continue;
            }
            let field = |name: &str| {
                descriptor
                    .args
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            if let (Some(provider), Some(model)) = (field("provider"), field("model")) {
                profiles.entry((provider, model)).or_insert_with(|| {
                    descriptor
                        .args
                        .get("provider_profile")
                        .cloned()
                        .unwrap_or(Value::Null)
                });
            }
        }
        Self { profiles }
    }
}

#[async_trait]
impl crate::model::ModelProvider for Provider {
    fn request_profile(&self, model: &crate::model::ModelId) -> Value {
        self.profiles
            .get(&(model.provider.clone(), model.model.clone()))
            .cloned()
            .unwrap_or(Value::Null)
    }

    async fn complete(
        &self,
        request: crate::model::Request<'_>,
    ) -> Result<crate::model::Completion, crate::model::ModelError> {
        Err(crate::model::ModelError::Refused {
            model: request.model.clone(),
            detail: REFUSAL.to_owned(),
        })
    }
}

/// A tool transport that refuses every call and opens no connection.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tools;

#[async_trait]
impl crate::tools::ToolClient for Tools {
    async fn call(
        &self,
        tool: &crate::tools::ToolId,
        _arguments: &Value,
        _provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, crate::tools::ToolError> {
        Err(crate::tools::ToolError::Refused {
            tool: tool.clone(),
            detail: REFUSAL.to_owned(),
        })
    }

    fn destination(&self, _tool: &crate::tools::ToolId) -> crate::tools::Destination {
        crate::tools::Destination::Local
    }
}

/// A peer transport that refuses every request and dials nobody.
#[derive(Debug, Default, Clone, Copy)]
pub struct Peers;

#[async_trait]
impl crate::peers::PeerClient for Peers {
    async fn send(
        &self,
        peer: &crate::peers::PeerId,
        _capability: &str,
        _payload: &Value,
        _acting_as: &crate::core::Delegation,
        _credential: Option<&crate::peers::PeerCredential>,
        _provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, crate::peers::PeerError> {
        Err(crate::peers::PeerError::Refused {
            peer: peer.clone(),
            detail: REFUSAL.to_owned(),
        })
    }
}

/// Every peer `history` called, by the name its grants use.
#[must_use]
pub fn peers_called(history: &[Record]) -> BTreeSet<String> {
    history
        .iter()
        .filter_map(|record| match record.kind() {
            RecordKind::EffectStarted { descriptor, .. } if descriptor.kind.starts_with("a2a.") => {
                descriptor
                    .args
                    .get("peer")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            }
            _ => None,
        })
        .collect()
}

/// Register a replay-only driver under every name `manifests` use.
///
/// Every provider the declarations name gets a [`Provider`] reading its
/// profile from `history`; every server a grant names gets [`Tools`], except
/// `agent` (this plane's own agents) and the servers `history` called as
/// peers, which are registered as peers over [`Peers`] with the grants'
/// scope. Nothing registered can reach anything.
#[cfg(feature = "manifest")]
#[must_use]
pub fn wire(
    mut builder: super::RuntimeBuilder,
    manifests: &[crate::manifest::Manifest],
    history: &[Record],
) -> super::RuntimeBuilder {
    use std::sync::Arc;

    let provider: Arc<dyn crate::model::ModelProvider> = Arc::new(Provider::from_history(history));
    let mut named = BTreeSet::new();
    for m in manifests {
        let Some(models) = &m.spec.models else {
            continue;
        };
        for role in [models.privileged.as_ref(), models.quarantined.as_ref()]
            .into_iter()
            .flatten()
        {
            named.insert(role.provider.clone());
        }
    }
    for name in named {
        builder = builder.provider(name, Arc::clone(&provider));
    }

    let peers = peers_called(history);
    let mut grants: BTreeMap<String, Vec<(String, &crate::manifest::ToolGrant)>> = BTreeMap::new();
    for grant in manifests.iter().flat_map(|m| &m.spec.tools) {
        if let Some(id) = crate::tools::ToolId::parse(&grant.reference)
            && id.server != crate::tools::AGENT_SERVER
        {
            grants.entry(id.server).or_default().push((id.tool, grant));
        }
    }
    let mut registry = crate::peers::PeerRegistry::new();
    let mut any_peer = false;
    for (server, tools) in grants {
        if peers.contains(&server) {
            let grant = crate::peers::PeerGrant::from_grants(tools);
            registry = registry.allow(crate::peers::PeerId::new(server), grant);
            any_peer = true;
        } else {
            builder = builder.tool_server(server, Arc::new(Tools));
        }
    }
    if any_peer {
        builder = builder.peers(registry, Arc::new(Peers));
    }
    builder
}
