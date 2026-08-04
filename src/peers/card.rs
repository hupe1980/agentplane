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
//! Streaming and push notifications are advertised as **false**, because both
//! need an A2A *server* and there is not one. A card is a promise a caller plans
//! against: advertising an unimplemented transport does not degrade gracefully,
//! it produces a caller that hangs waiting for events nobody will send.
//!
//! The extended card **is** implemented — see [`ExtendedAgentCard`] — so that
//! flag is true, and it is true because the thing exists rather than because it
//! sounded good on a card.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardCapabilities {
    /// Server-sent events for incremental results. Not implemented.
    pub streaming: bool,
    /// Webhook callbacks for long tasks. Not implemented.
    pub push_notifications: bool,
    /// A richer card for authenticated callers — see [`ExtendedAgentCard`].
    pub extended_agent_card: bool,
}

impl CardCapabilities {
    /// What this crate can actually do.
    const fn implemented() -> Self {
        Self {
            // Both need an A2A server, and there is not one.
            streaming: false,
            push_notifications: false,
            // This one exists.
            extended_agent_card: true,
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
    /// The digest of the manifest this card was derived from.
    ///
    /// Not part of the A2A schema, and carried anyway: it is what lets a caller
    /// tell two cards with the same name and version apart when the declaration
    /// behind them changed. A version string is what an author remembered to
    /// bump; a digest is what the document actually says.
    pub manifest_digest: String,
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
            capabilities: CardCapabilities::implemented(),
            supported_interfaces: vec![CardInterface {
                url: url.into(),
                protocol_binding: BINDING.to_owned(),
                protocol_version: crate::peers::PROTOCOL_VERSION.to_owned(),
                tenant: None,
            }],
            // Text only. Declaring a modality this plane cannot accept produces
            // a caller that sends bytes nobody will read.
            default_input_modes: vec!["text/plain".to_owned()],
            default_output_modes: vec!["text/plain".to_owned()],
            skills,
            manifest_digest: manifest.digest()?.to_hex(),
        })
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedAgentCard {
    /// Everything the public card says, unchanged.
    #[serde(flatten)]
    pub public: AgentCard,
    /// The tools this agent may reach, by manifest reference.
    pub tools: Vec<ExtendedTool>,
    /// What it may spend on one run, when the manifest bounds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<ExtendedBudget>,
    /// Its part in a multi-agent arrangement, when one is declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology: Option<String>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedBudget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
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
        let tools = manifest
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
            max_steps: b.max_steps,
            max_effects: b.max_effects,
            max_tokens: b.max_tokens,
        });

        let topology = manifest
            .spec
            .topology
            .as_ref()
            .map(|t| format!("{:?}/{:?}", t.mode, t.role));

        Ok(Self {
            public: AgentCard::derive(manifest, url)?,
            tools,
            budget,
            topology,
        })
    }
}
