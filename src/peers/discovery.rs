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
//! # Fetching a card is a dereference, and gets what every dereference here gets
//!
//! A card URL is frequently the first attacker-influenced string a deployment
//! handles — it arrives in a config, a registry entry, or a message — and "just
//! fetch it" is how a plane is made to probe its own network. So discovery is
//! held to the same four controls as governed media and push delivery, which
//! are the crate's other two URL dereferences:
//!
//! * an [`Egress`](crate::core::Egress) host allowlist, deny-by-default once
//!   set;
//! * every resolved address checked against [`netguard`](crate::netguard), with
//!   the connection **pinned** to exactly those addresses — resolving twice is
//!   how a rebinding attack passes a check and then connects somewhere else;
//! * **no redirects**, because a check on the URL a caller supplied says
//!   nothing about the third host an allowed one forwards to;
//! * a whole-request timeout, so a card server that never finishes answering
//!   does not hold a task open.
//!
//! The allowlist is optional and the other three are not. That asymmetry is
//! deliberate: an allowlist is a deployment's statement about who it talks to
//! and cannot be guessed on its behalf, while a plane fetching its own metadata
//! service is wrong in every deployment. `netguard` documents itself as the
//! *second* lock rather than the first, so a deployment discovering cards from
//! the open internet should still set an allowlist — but with none set, the
//! address rule is what stands between a hostile card URL and the internal
//! network, and it stands unconditionally.

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
#[derive(Debug, Clone)]
pub struct CardClient {
    egress: Option<Egress>,
    verifier: Option<Arc<dyn CardVerifier>>,
    timeout: std::time::Duration,
    /// The one pooled client cards are fetched through. Built on first use,
    /// because the timeout and the loopback exception arrive through builder
    /// methods that run after the constructor.
    http: std::sync::OnceLock<reqwest::Client>,
    /// Lift the public-address check for a card served from this machine.
    /// `testkit` only, and absent from any other build.
    #[cfg(feature = "testkit")]
    loopback: bool,
}

impl Default for CardClient {
    fn default() -> Self {
        Self {
            egress: None,
            verifier: None,
            timeout: Self::DEFAULT_TIMEOUT,
            http: std::sync::OnceLock::new(),
            #[cfg(feature = "testkit")]
            loopback: false,
        }
    }
}

impl CardClient {
    /// How long a card fetch may take in total.
    ///
    /// Ten seconds: a card is a small static document, and a server that cannot
    /// produce one in that time is not one worth waiting on. Unbounded is the
    /// wrong default anywhere, and here it lets an unknown host hold a task
    /// open for as long as it likes.
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit a card served from this machine.
    ///
    /// Behind `testkit` and therefore **absent from a production build**, which
    /// is the property that matters: an exception that can only be compiled
    /// into a test binary cannot be left on by accident in a deployment.
    ///
    /// It applies to a host that *is* a loopback literal or `localhost` — never
    /// to one that merely resolved to one, which is the rebinding attack and
    /// stays refused with the flag set. See
    /// [`netguard::is_loopback_name`](crate::netguard::is_loopback_name).
    #[cfg(feature = "testkit")]
    #[must_use]
    pub const fn allow_loopback(mut self) -> Self {
        self.loopback = true;
        self
    }

    /// How far this client is allowed to reach.
    ///
    /// One answer, read by both the pre-flight and the client's resolver, so
    /// the check that reports and the check that enforces cannot disagree.
    fn reach(&self) -> crate::netguard::Reach {
        if self.loopback_allowed() {
            crate::netguard::Reach::PublicOrLoopbackName
        } else {
            crate::netguard::Reach::Public
        }
    }

    /// The pooled client, built once. A failure is not cached, so one bad start
    /// does not leave a client that can never fetch.
    fn http(&self) -> Result<&reqwest::Client, DiscoveryError> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        // A card is somebody else's document: no ambient identity and no
        // redirects, which `guarded_client` carries along with the address rule.
        let client = crate::netguard::guarded_client(self.reach())
            .timeout(self.timeout)
            .build()
            .map_err(|e| DiscoveryError::Unreachable(e.to_string()))?;
        Ok(self.http.get_or_init(|| client))
    }

    /// Whether the loopback exception is in force. Always false without
    /// `testkit`, which is what lets the fetch path read one flag.
    #[allow(clippy::unused_self)]
    const fn loopback_allowed(&self) -> bool {
        #[cfg(feature = "testkit")]
        {
            self.loopback
        }
        #[cfg(not(feature = "testkit"))]
        {
            false
        }
    }

    /// Change the whole-request timeout.
    ///
    /// # Panics
    ///
    /// If zero, which would spell *never fetch a card* as if it were a policy.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        assert!(
            !timeout.is_zero(),
            "a card-fetch timeout of zero refuses every card; configure no discovery instead"
        );
        self.timeout = timeout;
        self
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
        let parsed = reqwest::Url::parse(url).map_err(|e| DiscoveryError::Malformed {
            url: url.to_owned(),
            detail: e.to_string(),
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| DiscoveryError::Malformed {
                url: url.to_owned(),
                detail: "the card URL names no host".to_owned(),
            })?
            .to_owned();

        if let Some(egress) = &self.egress {
            // Before the request is built, so a refused host is never resolved
            // and never connected to — a refusal issued after a DNS lookup has
            // already told somebody the name was interesting.
            //
            // Matched by `Egress` on the host alone: that type never parses
            // URLs, because URL parsing is where allowlists break.
            if let Err(e) = egress.permits(Some(host.as_str())) {
                return Err(DiscoveryError::Refused(e.to_string()));
            }
        }

        // `Url::host_str` keeps the brackets on an IPv6 literal and the
        // resolver refuses them. Only the lookup uses the bare form; the
        // refusal messages keep the spelling the URL carries.
        let lookup = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(&host)
            .to_owned();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let resolved = tokio::net::lookup_host((lookup.as_str(), port))
            .await
            .map_err(|e| DiscoveryError::Unreachable(format!("DNS for '{host}': {e}")))?;
        // Judged before anything is sent, so a card this plane may not fetch is
        // refused with a typed answer rather than attempted — a forbidden
        // address is `Refused` and an outage is `Unreachable`, which a connect
        // error cannot distinguish. The socket obeys the same rule again, in
        // the client's own resolver.
        crate::netguard::judge(self.reach(), &host, resolved).map_err(|e| match e {
            crate::netguard::NetGuardError::NoAddresses { .. } => {
                DiscoveryError::Unreachable(e.to_string())
            }
            crate::netguard::NetGuardError::Forbidden { .. } => {
                DiscoveryError::Refused(e.to_string())
            }
        })?;

        let client = self.http()?;

        let response = client
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
        let want = super::protocol_major_minor(version)?;
        self.supported_interfaces.iter().find(|i| {
            i.protocol_binding == binding
                && super::protocol_major_minor(&i.protocol_version) == Some(want)
        })
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
