//! The Agent Card a peer reads before it trusts anything.
//!
//! [A2A] agents publish a card at `/.well-known/agent-card.json` describing what
//! they are and what they can do. It is the first thing a caller fetches and the
//! basis on which it decides to call at all — which makes it the most
//! consequential piece of prose an agent publishes, and the easiest to get
//! quietly wrong.
//!
//! # It is derived, never written
//!
//! The card is built from the [`Manifest`], so what an agent *advertises* and
//! what it is *permitted* cannot drift: both come from one digested document. A
//! hand-written card is a second source of truth about capability, and the two
//! disagree the first time somebody edits one.
//!
//! This crate already refuses an agent whose manifest advertises a capability no
//! skill provides — a card that lies, caught at startup. Deriving the published
//! card from the same field extends that refusal outward: a peer cannot be told
//! about a capability the plane would not dispatch.
//!
//! # What it will not claim
//!
//! Every capability flag is true only when the thing behind it exists. Push
//! notifications are advertised as **false** by derivation and enabled by the
//! A2A server only when that deployment wires both durable callback storage and
//! governed outbound delivery. A compiled feature is not a deployed capability,
//! and a card is a promise a caller plans against.
//!
//! Streaming and the extended card are true because both are implemented, not
//! because they sounded good on a card.
//!
//! [A2A]: https://a2a-protocol.org/latest/specification/

use serde::{Deserialize, Serialize};

use crate::manifest::Manifest;

/// Where a conforming client looks for the card.
pub const WELL_KNOWN_PATH: &str = "/.well-known/agent-card.json";

/// The one protocol binding this crate implements, spelled as the spec spells it.
pub const BINDING: &str = "JSONRPC";

/// One thing an agent can be asked to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSkill {
    /// Stable identifier — the capability, exactly as the plane dispatches it.
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
}

/// What a peer may expect this agent to support.
///
/// A field is `true` only when the thing behind it exists in this crate. There
/// is deliberately no builder that sets one: an embedder cannot turn on a
/// capability by asking, because the caller who believes the card does not care
/// who wrote it. Turning one on means editing this file, next to the code that
/// implements it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardCapabilities {
    /// Server-sent events for incremental results.
    pub streaming: bool,
    /// Webhook callbacks for long tasks, when this deployment wires them.
    pub push_notifications: bool,
    /// A richer card for authenticated callers — see [`ExtendedAgentCard`].
    pub extended_agent_card: bool,
    /// Declared protocol extensions, in the spec's own slot for them.
    ///
    /// This is where anything the A2A schema does not name belongs. The card
    /// once carried this crate's extras (`manifestDigest`; the extended card's
    /// tools and budget) as top-level fields, and the official conformance kit
    /// rejected the document: `AgentCard` forbids unknown properties, so a
    /// spec-conforming peer is entitled to refuse the whole card over them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<AgentExtension>,
}

/// One declared extension, as A2A 1.0 shapes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentExtension {
    /// Identifies the extension. Stable, versioned, and documented at the URI.
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether a caller must understand the extension to use the agent.
    ///
    /// Everything this crate declares is `false`: the extras are disclosure,
    /// and a peer that ignores them loses information rather than correctness.
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// The extension that carries the manifest digest on every derived card.
pub const EXT_MANIFEST_PROVENANCE: &str =
    "https://hupe1980.github.io/agentplane/a2a/ext/manifest-provenance/v1";

/// The extension that carries tools, budget and topology on the extended card.
pub const EXT_GOVERNANCE: &str = "https://hupe1980.github.io/agentplane/a2a/ext/governance/v1";

/// The extension that lists every agent a plane serves, and where each card is.
///
/// # Why an extension rather than `AgentInterface::tenant`
///
/// A2A's well-known card path is singular per host, so a plane hosting several
/// declared agents could give each its own card only by running a server per
/// agent — 28 specialists, 28 processes. The obvious shortcut is the `tenant`
/// field A2A already puts on every interface, and it is the wrong one: its
/// documented meaning is *the tenant id to send back on a request*, so
/// overloading it to select an **agent** would make every caller echo an agent
/// name into a field the protocol reserves for tenancy — and a plane that also
/// serves several tenants would then have two meanings in one string.
///
/// So the discriminator is a path, and this extension is the directory that
/// makes the paths discoverable. The well-known card stays exactly what the
/// specification says it is: one valid `AgentCard`, describing one real agent.
pub const EXT_AGENT_DIRECTORY: &str =
    "https://hupe1980.github.io/agentplane/a2a/ext/agent-directory/v1";

/// Where one agent's own card is served.
///
/// A path rather than a full URL, because the card is served from whatever host
/// the caller reached and a card that hard-coded one would be wrong behind a
/// proxy — the same reason the interface URL is deployment configuration.
#[must_use]
pub fn agent_card_path(agent: &str) -> String {
    format!("/agents/{agent}/agent-card.json")
}

impl CardCapabilities {
    /// What this crate can actually do.
    const fn implemented() -> Self {
        Self {
            // `SendStreamingMessage` and `SubscribeToTask`, served from the
            // journal — see `api::a2a_stream`.
            streaming: true,
            // Conservative until a durable outbox and delivery worker exist.
            // Config storage plus a best-effort callback cannot satisfy A2A's
            // at-least-once delivery contract across process failure.
            push_notifications: false,
            extended_agent_card: true,
            extensions: Vec::new(),
        }
    }
}

/// How a peer can reach this agent — A2A's `AgentInterface`.
///
/// All four fields are the spec's, spelled the spec's way. An earlier version of
/// this type called the binding `transport` and omitted the version, which
/// serialized to a card a conforming 1.0 client cannot read: `protocolVersion`
/// is required, and a field named `transport` is not one it looks at. A card is
/// the one artifact whose whole job is being parsed by software nobody here
/// wrote, so drift in it is not cosmetic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardInterface {
    pub url: String,
    /// `JSONRPC`, the one binding this crate speaks.
    pub protocol_binding: String,
    /// The A2A version spoken at this URL.
    pub protocol_version: String,
    /// An opaque routing identifier for multi-tenant endpoints.
    ///
    /// A2A's own answer to serving several tenants behind one address: the
    /// client echoes this back in every request, and the server routes on it.
    /// Absent when the plane serves the default tenant, because a card that
    /// names a tenant is telling callers to send one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// HTTP authentication advertised by an A2A interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpAuthSecurityScheme {
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bearer_format: Option<String>,
}

/// One A2A security scheme.
///
/// This release exposes the scheme the shipped client already uses: HTTP
/// bearer authentication. More variants belong here only when a transport can
/// actually acquire and send them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardSecurityScheme {
    pub http_auth_security_scheme: HttpAuthSecurityScheme,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityScopeList {
    pub list: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSecurityRequirement {
    pub schemes: std::collections::BTreeMap<String, SecurityScopeList>,
}

/// Deployment authentication published on an Agent Card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardSecurity {
    name: String,
    scheme: CardSecurityScheme,
    scopes: Vec<String>,
}

impl CardSecurity {
    /// Advertise HTTP bearer authentication under `name`.
    #[must_use]
    pub fn bearer(
        name: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            scheme: CardSecurityScheme {
                http_auth_security_scheme: HttpAuthSecurityScheme {
                    scheme: "Bearer".to_owned(),
                    bearer_format: None,
                },
            },
            scopes: scopes.into_iter().map(Into::into).collect(),
        }
    }

    #[cfg(feature = "a2a-server")]
    pub(crate) fn apply(&self, card: &mut AgentCard) {
        card.security_schemes
            .insert(self.name.clone(), self.scheme.clone());
        card.security_requirements.push(CardSecurityRequirement {
            schemes: std::collections::BTreeMap::from([(
                self.name.clone(),
                SecurityScopeList {
                    list: self.scopes.clone(),
                },
            )]),
        });
    }
}

/// An A2A Agent Card, derived from a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub version: String,
    pub capabilities: CardCapabilities,
    pub supported_interfaces: Vec<CardInterface>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<CardSkill>,
    /// How to authenticate every non-card operation on this interface.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub security_schemes: std::collections::BTreeMap<String, CardSecurityScheme>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_requirements: Vec<CardSecurityRequirement>,
    /// Detached JWS signatures over this card.
    ///
    /// Several are allowed so a publisher can rotate keys without a window in
    /// which nobody can verify the card.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<super::card_sig::CardSignature>,
}

impl AgentCard {
    /// Derive a card from a declaration.
    ///
    /// `url` is deployment wiring rather than a property of the agent — the same
    /// split as an API key: where an agent is reachable changes with the
    /// deployment, and an agent's declaration must not change when its address
    /// does.
    ///
    /// # Errors
    ///
    /// If the manifest's digest cannot be computed.
    pub fn derive(
        manifest: &Manifest,
        url: impl Into<String>,
    ) -> Result<Self, crate::manifest::ManifestError> {
        let description = manifest.spec.identity.as_ref().map_or_else(
            || format!("The {} agent.", manifest.metadata.name),
            |identity| identity.role.clone(),
        );

        // One skill per advertised capability, and no others. The plane refuses
        // to start if a capability here has no skill behind it, so a card built
        // from this field cannot advertise work the plane would not dispatch.
        let skills = manifest
            .spec
            .capabilities
            .provides
            .iter()
            .map(|capability| CardSkill {
                id: capability.clone(),
                name: capability.clone(),
                description: description.clone(),
                tags: Vec::new(),
            })
            .collect();

        Ok(Self {
            name: manifest.metadata.name.clone(),
            description,
            version: manifest.metadata.version.clone(),
            capabilities: {
                let mut capabilities = CardCapabilities::implemented();
                capabilities.extensions.push(AgentExtension {
                    uri: EXT_MANIFEST_PROVENANCE.to_owned(),
                    description: Some(
                        "The digest of the manifest this card was derived from.".to_owned(),
                    ),
                    required: false,
                    params: Some(serde_json::json!({
                        "manifestDigest": manifest.digest()?.to_hex(),
                    })),
                });
                capabilities
            },
            supported_interfaces: vec![CardInterface {
                url: url.into(),
                protocol_binding: BINDING.to_owned(),
                protocol_version: crate::peers::PROTOCOL_VERSION.to_owned(),
                tenant: None,
            }],
            // Text only. Declaring a modality this plane cannot accept produces
            // a caller that sends bytes nobody will read.
            default_input_modes: vec!["text/plain".to_owned(), "application/json".to_owned()],
            default_output_modes: vec!["text/plain".to_owned(), "application/json".to_owned()],
            skills,
            security_schemes: std::collections::BTreeMap::new(),
            security_requirements: Vec::new(),
            // Unsigned until somebody signs it. An empty list serializes as an
            // absent field, so an unsigned card is not a card with an empty
            // promise on it.
            signatures: Vec::new(),
        })
    }

    /// The digest of the manifest this card was derived from, when the card
    /// declares one.
    ///
    /// Carried as a declared extension rather than a top-level field: the A2A
    /// schema forbids unknown properties on a card, so a spec-conforming peer
    /// could refuse the whole document over an extra key. The information
    /// survives — it is what lets a caller tell two cards with the same name
    /// and version apart when the declaration behind them changed. A version
    /// string is what an author remembered to bump; a digest is what the
    /// document actually says.
    #[must_use]
    pub fn manifest_digest(&self) -> Option<&str> {
        self.capabilities
            .extensions
            .iter()
            .find(|e| e.uri == EXT_MANIFEST_PROVENANCE)?
            .params
            .as_ref()?
            .get("manifestDigest")?
            .as_str()
    }
}

/// The card an **authenticated** peer may fetch: the same agent, in more detail.
///
/// A2A's `GetExtendedAgentCard` exists because the public card is read by
/// anyone, and some of what a peer legitimately wants to know is not for
/// everyone: which tools an agent may reach, what it is allowed to spend, and
/// what part it plays in a larger arrangement.
///
/// # Why this is a separate type
///
/// Serving the wrong card is a one-line mistake with no symptom — the response
/// is valid JSON either way, and the extra fields simply appear on a public
/// endpoint where nobody notices until somebody reads them. A distinct type
/// makes that a compile error instead: a handler for the public path cannot
/// return this, because it is not an [`AgentCard`].
///
/// # What it still will not say
///
/// Not the model, and not the protected-field rules. Which model an agent runs
/// on is a fact about a supply chain, and the exact fields a sink guards is a
/// map of where to push — both are disclosure that helps an attacker more than
/// a caller. The tool *names* are here because a peer deciding whether to
/// delegate genuinely needs to know what the far side can reach.
/// # Where the extra detail lives
///
/// In the [`EXT_GOVERNANCE`] extension under `capabilities.extensions` — the
/// spec's own slot for what its schema does not name — rather than as top-level
/// fields, which the official conformance kit rejects outright. Injected at
/// **derive** time, not at serialization, so a signature taken over the card
/// covers the disclosure: an extension added after signing would be exactly the
/// unverifiable claim the signature exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtendedAgentCard {
    /// The card, with the governance extension included.
    pub public: AgentCard,
}

/// A tool an agent may reach, as an authenticated peer is told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedTool {
    pub reference: String,
    /// The manifest's own words, when it has any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether calling it changes the world.
    ///
    /// The field a peer most needs when deciding whether to delegate: an agent
    /// that can only read is a different risk from one that can move money.
    pub mutates: bool,
}

/// What an agent may spend on one run.
///
/// The figures serialize as **strings**, for two reasons that happen to agree:
/// `ProtoJSON` — the encoding A2A documents are defined in — renders 64-bit
/// integers as strings, and a signed card must carry no JSON numbers because
/// ECMAScript number formatting is the one JCS rule this crate does not
/// implement (see `peers::card_sig`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedBudget {
    #[serde(default, with = "stringly", skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<u64>,
    #[serde(default, with = "stringly", skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<u64>,
    #[serde(default, with = "stringly", skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
}

/// `Option<u64>` as a decimal string, the `ProtoJSON` int64 convention.
mod stringly {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        // `&Option<T>` is the signature `serde(with)` hands a field serializer;
        // the idiomatic `Option<&T>` is not this seam's to choose.
        match v {
            Some(n) => s.serialize_str(&n.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        let raw: Option<String> = Option::deserialize(d)?;
        raw.map(|v| v.parse().map_err(D::Error::custom)).transpose()
    }
}

impl ExtendedAgentCard {
    /// Derive the authenticated card.
    ///
    /// # Errors
    ///
    /// If the manifest's digest cannot be computed.
    pub fn derive(
        manifest: &Manifest,
        url: impl Into<String>,
    ) -> Result<Self, crate::manifest::ManifestError> {
        let tools: Vec<ExtendedTool> = manifest
            .spec
            .tools
            .iter()
            .map(|g| ExtendedTool {
                reference: g.reference.clone(),
                description: g.description.clone(),
                mutates: g.mutates,
            })
            .collect();

        let budget = manifest.spec.budgets.as_ref().map(|b| ExtendedBudget {
            max_steps: b.max_steps.map(|n| n as u64),
            max_effects: b.max_effects.map(|n| n as u64),
            max_tokens: b.max_tokens,
        });

        let topology = manifest
            .spec
            .topology
            .as_ref()
            .map(|t| format!("{:?}/{:?}", t.mode, t.role));

        let mut public = AgentCard::derive(manifest, url)?;
        let mut params = serde_json::Map::new();
        params.insert(
            "tools".to_owned(),
            serde_json::to_value(&tools).unwrap_or(serde_json::Value::Null),
        );
        if let Some(budget) = budget {
            params.insert(
                "budget".to_owned(),
                serde_json::to_value(budget).unwrap_or(serde_json::Value::Null),
            );
        }
        if let Some(topology) = topology {
            params.insert("topology".to_owned(), serde_json::Value::String(topology));
        }
        public.capabilities.extensions.push(AgentExtension {
            uri: EXT_GOVERNANCE.to_owned(),
            description: Some(
                "What this agent may reach and spend, for a peer deciding whether to delegate."
                    .to_owned(),
            ),
            required: false,
            params: Some(serde_json::Value::Object(params)),
        });
        Ok(Self { public })
    }

    /// The tools the governance extension discloses.
    #[must_use]
    pub fn tools(&self) -> Vec<ExtendedTool> {
        self.governance("tools")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default()
    }

    /// The per-run budget the governance extension discloses, when one is.
    #[must_use]
    pub fn budget(&self) -> Option<ExtendedBudget> {
        self.governance("budget")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// The declared topology, when one is.
    #[must_use]
    pub fn topology(&self) -> Option<String> {
        self.governance("topology")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
    }

    fn governance(&self, key: &str) -> Option<&serde_json::Value> {
        self.public
            .capabilities
            .extensions
            .iter()
            .find(|e| e.uri == EXT_GOVERNANCE)?
            .params
            .as_ref()?
            .get(key)
    }
}
