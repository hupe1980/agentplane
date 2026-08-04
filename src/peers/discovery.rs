//! Reading another agent's card: fetch it, check it, pick an interface.
//!
//! # A card is a description, never a grant
//!
//! Everything here produces *reachability* — which URL speaks which binding, at
//! which version, for which tenant. None of it produces authority. What a peer
//! is allowed to be sent, and what may be believed from its answer, comes from
//! [`PeerRegistry`](super::PeerRegistry), which an operator writes.
//!
//! That split is the whole reason a forged card is survivable. A party
//! describing its own privileges is not a source of truth about them, so the
//! worst a bad card can do is send a request somewhere useless — not widen a
//! grant. Verification below raises the bar on *who answered*; it deliberately
//! does not turn the card into a permission.
//!
//! # Fetching a URL is an egress decision
//!
//! Discovery dereferences a URL, so it is subject to the same rule as every
//! other outbound fetch in this crate: an [`Egress`](crate::core::Egress) may be
//! set, and once set it is deny-by-default. A card URL is frequently the first
//! attacker-influenced string a deployment handles — it arrives in a config, a
//! registry entry, or a message — and "just fetch it" is how a plane is made to
//! probe its own network.

use std::sync::Arc;

use crate::core::Egress;

use super::card::{AgentCard, CardInterface, WELL_KNOWN_PATH};
use super::card_sig::{CardSignatureError, CardVerifier};

/// The binding this crate speaks, as the spec spells it.
pub const JSONRPC: &str = "JSONRPC";

/// Why a card could not be obtained or believed.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("this client may not connect to '{0}'")]
    Refused(String),
    #[error("the card could not be fetched: {0}")]
    Unreachable(String),
    #[error("the card at '{url}' is not a valid Agent Card: {detail}")]
    Malformed { url: String, detail: String },
    #[error("the card's signature was not acceptable: {0}")]
    Signature(#[from] CardSignatureError),
    #[error(
        "the agent at '{url}' offers no {binding} interface speaking A2A {version} — \
         it advertises: {offered}"
    )]
    NoUsableInterface {
        url: String,
        binding: String,
        version: String,
        offered: String,
    },
}

/// Fetches and checks the cards other agents publish.
#[derive(Debug, Clone, Default)]
pub struct CardClient {
    egress: Option<Egress>,
    verifier: Option<Arc<dyn CardVerifier>>,
}

impl CardClient {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict where cards may be fetched from.
    #[must_use]
    pub fn egress(mut self, egress: Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Require a signature from a key this verifier trusts.
    ///
    /// Off by default, and that is a deliberate choice rather than an oversight:
    /// most cards in the wild are unsigned today, and a client that refused them
    /// all would simply not be used. Setting this makes verification
    /// **mandatory** — an unsigned card is then refused, because a verifier that
    /// accepts an unsigned card whenever one arrives is one an attacker
    /// downgrades by stripping the signature.
    #[must_use]
    pub fn verifying_with(mut self, verifier: Arc<dyn CardVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Fetch the card an agent publishes at its well-known path.
    ///
    /// `origin` is a scheme and host — the path is the spec's, not the caller's,
    /// which is the point of a well-known location.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Refused`] when egress forbids the host,
    /// [`DiscoveryError::Unreachable`] on a transport failure,
    /// [`DiscoveryError::Malformed`] when the body is not a card, and
    /// [`DiscoveryError::Signature`] when verification is required and fails.
    pub async fn discover(&self, origin: &str) -> Result<AgentCard, DiscoveryError> {
        let url = format!("{}{WELL_KNOWN_PATH}", origin.trim_end_matches('/'));
        self.fetch(&url).await
    }

    /// Fetch a card from an exact URL.
    ///
    /// # Errors
    ///
    /// As [`discover`](Self::discover).
    pub async fn fetch(&self, url: &str) -> Result<AgentCard, DiscoveryError> {
        if let Some(egress) = &self.egress {
            // Before the request is built, so a refused host is never resolved
            // and never connected to — a refusal issued after a DNS lookup has
            // already told somebody the name was interesting.
            //
            // The host is extracted here and matched by `Egress` on the host
            // alone: that type never parses URLs, because URL parsing is where
            // allowlists break.
            let host = reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(ToOwned::to_owned));
            if let Err(e) = egress.permits(host.as_deref()) {
                return Err(DiscoveryError::Refused(e.to_string()));
            }
        }

        let response = reqwest::Client::new()
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| DiscoveryError::Unreachable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(DiscoveryError::Unreachable(format!(
                "{url} answered {}",
                response.status()
            )));
        }

        let card: AgentCard = response
            .json()
            .await
            .map_err(|e| DiscoveryError::Malformed {
                url: url.to_owned(),
                detail: e.to_string(),
            })?;

        if let Some(verifier) = &self.verifier {
            // Mandatory once configured. Verifying "if the card happens to carry
            // a signature" is the downgrade an attacker performs by removing it.
            card.verify(verifier.as_ref())?;
        }
        Ok(card)
    }
}

impl AgentCard {
    /// The interface a client should use, following the spec's selection rules.
    ///
    /// Ordered: the **first** entry that speaks the requested binding at a
    /// compatible version wins. The order is the publisher's preference, and
    /// scanning for a "best" one instead would quietly override the operator of
    /// the agent being called.
    ///
    /// Version is matched on `Major.Minor`, as the spec requires. An agent may
    /// publish the same binding at several versions, so ignoring the version
    /// would pick an endpoint that speaks a protocol this client does not.
    #[must_use]
    pub fn select_interface(&self, binding: &str, version: &str) -> Option<&CardInterface> {
        let want = major_minor(version);
        self.supported_interfaces
            .iter()
            .find(|i| i.protocol_binding == binding && major_minor(&i.protocol_version) == want)
    }

    /// An endpoint for this crate's A2A client, taken from the card.
    ///
    /// The tenant travels with it, which is the part a hand-written endpoint
    /// gets wrong: A2A says to echo the selected interface's `tenant` on every
    /// request and to omit it when the interface omits it. A client that skips
    /// that can only ever reach an agent serving the default tenant.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::NoUsableInterface`] when nothing on the card speaks
    /// JSON-RPC at this crate's protocol version.
    #[cfg(feature = "a2a")]
    pub fn endpoint(&self) -> Result<super::a2a::Endpoint, DiscoveryError> {
        let version = super::PROTOCOL_VERSION;
        let iface = self.select_interface(JSONRPC, version).ok_or_else(|| {
            DiscoveryError::NoUsableInterface {
                url: self.name.clone(),
                binding: JSONRPC.to_owned(),
                version: version.to_owned(),
                offered: self
                    .supported_interfaces
                    .iter()
                    .map(|i| format!("{} {}", i.protocol_binding, i.protocol_version))
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        })?;

        let endpoint = super::a2a::Endpoint::new(iface.url.clone());
        Ok(match &iface.tenant {
            Some(t) => endpoint.for_tenant(t.clone()),
            None => endpoint,
        })
    }
}

/// `Major.Minor`, which is what the spec compares.
fn major_minor(v: &str) -> (&str, &str) {
    let mut parts = v.split('.');
    (parts.next().unwrap_or(""), parts.next().unwrap_or(""))
}
