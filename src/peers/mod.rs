//! Calling other agents.
//!
//! A peer hop is a tool call with two extra problems, and both are about
//! identity rather than transport.
//!
//! # Token confusion
//!
//! To call a peer you hand it a credential. If that credential is not bound to
//! *that peer*, the peer can replay it somewhere else — and it does not need to
//! be malicious to do so, only compromised or confused. A bearer token sent to
//! peer B and accepted by peer A is the whole vulnerability class, and it is why
//! OAuth grew Resource Indicators (RFC 8707): the token says which audience it
//! is for, and everyone else refuses it.
//!
//! This runtime cannot make peer A check that. What it *can* do — and what
//! [`PeerRegistry`] enforces — is never send a credential to an audience it was
//! not minted for. A credential for `settlement.example` is structurally
//! unusable when calling `reviewer.example`; the call is refused before anything
//! leaves.
//!
//! # Authority must narrow at the boundary
//!
//! A peer acts on our behalf, so the chain it receives is our chain with one
//! more link. [`Delegation::delegate`] already refuses to widen and caps depth,
//! so a hop cannot hand a peer more authority than the caller holds, and a
//! request cannot wander arbitrarily far from the human who authorised it.
//!
//! The registry decides what each peer is *granted*, and that is an operator's
//! declaration. It is not taken from the peer's agent card, for exactly the
//! reason MCP annotations are not taken from a server: a party describing its own
//! privileges is not a source of truth about them.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The A2A protocol version this crate speaks, as client and as server.
///
/// One definition because it is one fact. The client sends it in `A2A-Version`,
/// the published card names it on every interface, and the server refuses a
/// request that asks for something else — three places that must agree, and a
/// version that disagrees with the card is the kind of drift a caller finds
/// before we do.
pub const PROTOCOL_VERSION: &str = "1.0";

#[cfg(feature = "a2a")]
pub mod a2a;
#[cfg(feature = "manifest")]
mod card;
#[cfg(feature = "manifest")]
mod card_sig;
#[cfg(all(feature = "manifest", feature = "a2a"))]
mod discovery;
#[cfg(feature = "manifest")]
pub use card::{
    AgentCard, CardCapabilities, CardInterface, CardSkill, ExtendedAgentCard, ExtendedBudget,
    ExtendedTool, WELL_KNOWN_PATH,
};
#[cfg(feature = "manifest")]
pub use card_sig::{
    ALG, CardSignature, CardSignatureError, CardSigner, CardVerifier, signing_input,
};
#[cfg(all(feature = "manifest", feature = "a2a"))]
pub use discovery::{CardClient, DiscoveryError, JSONRPC};
mod credentials;
pub use credentials::{Cached, CredentialError, CredentialSource, Fixed, TokenExchange};

use std::time::Duration;

use crate::core::{
    Delegation, DelegationError, Disposition, Effect, EffectDescriptor, EffectError, Principal,
    Recovery, RetryPolicy, Scope, Secret, Sensitivity, Timestamp, Trust,
};

/// Another agent, addressed by the name this plane knows it by.
///
/// Local, like a tool's server name. A peer that could choose its own identifier
/// could step into another peer's grant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PeerId(pub String);

impl PeerId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A credential, and the single audience it may be presented to.
///
/// The audience is not decoration. A bearer token with no stated audience is one
/// that any recipient can replay at any other, and the whole point of RFC 8707 is
/// that a token names where it is allowed to be spent.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerCredential {
    audience: PeerId,
    /// Wiped when it drops, and compared in constant time.
    ///
    /// The redacting `Debug` and the absent `Serialize` stop it being *written*
    /// somewhere. Neither stops it *staying* in freed heap after the credential
    /// is gone, where a core dump or a swap file finds it — which is what
    /// [`Secret`] is for.
    secret: Secret,
    /// When it stops being accepted, if the issuer said.
    ///
    /// `None` means the issuer gave no expiry — treated as usable, because
    /// inventing one here would either reject working credentials or invent a
    /// guarantee the issuer did not make.
    expires_at: Option<Timestamp>,
}

impl PeerCredential {
    /// Mint a credential for exactly one peer.
    pub fn for_audience(audience: PeerId, secret: impl Into<String>) -> Self {
        Self {
            audience,
            secret: Secret::new(secret),
            expires_at: None,
        }
    }

    /// Say when this credential stops being accepted.
    #[must_use]
    pub const fn expiring_at(mut self, at: Timestamp) -> Self {
        self.expires_at = Some(at);
        self
    }

    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Whether this is still worth sending at `now`.
    ///
    /// `skew` is subtracted from the expiry, so a credential that expires in two
    /// seconds is treated as already spent. Without that margin a token is sent
    /// *just* before it lapses and is rejected in flight — which arrives as a
    /// peer failure of unknown disposition, when it was really a refresh nobody
    /// scheduled.
    ///
    /// `now` is a parameter rather than a clock read: expiry is transport
    /// metadata and this keeps it testable at arbitrary instants.
    #[must_use]
    pub fn is_usable_at(&self, now: Timestamp, skew: Duration) -> bool {
        let Some(expiry) = self.expires_at else {
            return true;
        };
        let margin = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
        now.unix_timestamp().saturating_add(margin) < expiry.unix_timestamp()
    }

    #[must_use]
    pub const fn audience(&self) -> &PeerId {
        &self.audience
    }

    /// The bearer value.
    ///
    /// Reachable only once a caller has already been past the audience check, so
    /// there is no path that sends this to the wrong peer without going around
    /// [`PeerRegistry::credential_for`] deliberately.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.secret.expose()
    }
}

/// Never renders the secret.
///
/// A credential that prints itself ends up in a log, a span attribute, or an
/// error message — and this crate writes all three. The audience is shown
/// because that is the part worth debugging.
impl Debug for PeerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerCredential")
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// What the operator grants a peer.
#[derive(Debug, Clone)]
pub struct PeerGrant {
    /// The authority this peer may hold. Narrowed further by the caller's own
    /// scope at every hop — a grant is a ceiling, not an entitlement.
    pub scope: Scope,
    /// Whether a call to this peer changes the world.
    pub mutates: bool,
    pub recovery: Recovery,
    pub max_sensitivity: Sensitivity,
    pub output_sensitivity: Sensitivity,
    pub retry: RetryPolicy,
    credential: Option<PeerCredential>,
}

impl PeerGrant {
    /// A grant with the conservative posture: mutating, operator-resolved.
    #[must_use]
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            mutates: true,
            recovery: Recovery::RequiresOperator,
            max_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
            retry: RetryPolicy::never(),
            credential: None,
        }
    }

    /// Attach the credential this peer is called with.
    ///
    /// # Panics
    ///
    /// If the credential's audience is not this peer. That is a configuration
    /// error the operator must see at startup rather than a refusal at 3am, and
    /// there is no sensible way to continue: the alternative is holding a
    /// credential that can only ever be sent to the wrong place.
    #[must_use]
    pub fn with_credential(mut self, peer: &PeerId, credential: PeerCredential) -> Self {
        assert_eq!(
            credential.audience(),
            peer,
            "a credential for '{}' was attached to peer '{peer}'. An audience-bound \
             credential presented to the wrong peer is exactly what binding exists \
             to prevent",
            credential.audience()
        );
        self.credential = Some(credential);
        self
    }

    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.mutates = false;
        self.recovery = Recovery::Retry;
        self
    }

    #[must_use]
    pub const fn output_sensitivity(mut self, s: Sensitivity) -> Self {
        self.output_sensitivity = s;
        self
    }
}

/// Why a peer call could not be made, or did not work.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// This peer is not in the registry.
    #[error(
        "peer '{peer}' is not registered; a peer nobody declared is a peer nobody granted anything"
    )]
    Unknown { peer: PeerId },

    /// The hop would hand the peer authority the caller does not hold, or would
    /// take the request too far from the human who authorised it.
    #[error("delegating to '{peer}' is refused: {source}")]
    Delegation {
        peer: PeerId,
        #[source]
        source: DelegationError,
    },

    /// The credential on hand is for someone else.
    #[error(
        "the credential held for this call is bound to '{held_for}', not '{peer}' — \
         presenting it would let '{peer}' replay it at '{held_for}'"
    )]
    WrongAudience { peer: PeerId, held_for: PeerId },

    /// The call never left.
    #[error("could not reach '{peer}': {detail}")]
    Unreachable { peer: PeerId, detail: String },

    /// The peer received it and declined without acting.
    #[error("'{peer}' refused the request: {detail}")]
    Refused { peer: PeerId, detail: String },

    /// Sent, and the outcome is unknown.
    #[error("'{peer}' did not answer in time: {detail}")]
    TimedOut { peer: PeerId, detail: String },

    /// Sent, but the peer's response did not conform to the negotiated protocol.
    ///
    /// The request may already have caused work, so this is in doubt rather
    /// than a clean refusal.
    #[error("'{peer}' returned an invalid response: {detail}")]
    InvalidResponse { peer: PeerId, detail: String },

    /// The peer acted and reported failure.
    #[error("'{peer}' reported a failure: {detail}")]
    Failed { peer: PeerId, detail: String },
}

impl PeerError {
    /// What this failure says about whether the request reached the peer.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            // Nothing was sent: refused locally, or refused by the peer before
            // it acted.
            Self::Unknown { .. }
            | Self::Delegation { .. }
            | Self::WrongAudience { .. }
            | Self::Unreachable { .. }
            | Self::Refused { .. } => Disposition::DidNotHappen,
            Self::TimedOut { .. } | Self::InvalidResponse { .. } => Disposition::InDoubt,
            Self::Failed { .. } => Disposition::Landed,
        }
    }
}

/// Carries a request to a peer.
#[async_trait]
pub trait PeerClient: Send + Sync + Debug {
    /// Send a request on behalf of a delegation chain.
    ///
    /// # Errors
    ///
    /// A [`PeerError`] whose variant states what is known about whether the
    /// request reached the peer.
    async fn send(
        &self,
        peer: &PeerId,
        capability: &str,
        payload: &Value,
        acting_as: &Delegation,
        credential: Option<&PeerCredential>,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, PeerError>;
}

/// The peers this plane may call, and what each is granted.
#[derive(Debug, Default, Clone)]
pub struct PeerRegistry {
    peers: BTreeMap<PeerId, PeerGrant>,
}

impl PeerRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn allow(mut self, peer: PeerId, grant: PeerGrant) -> Self {
        self.peers.insert(peer, grant);
        self
    }

    #[must_use]
    pub fn grant(&self, peer: &PeerId) -> Option<&PeerGrant> {
        self.peers.get(peer)
    }

    /// The credential for this peer, if one is held *and* bound to it.
    ///
    /// The audience check is here rather than at the call site so that no code
    /// path can reach a credential without passing it.
    ///
    /// # Errors
    ///
    /// [`PeerError::WrongAudience`] if a credential is held whose audience is a
    /// different peer.
    pub fn credential_for(&self, peer: &PeerId) -> Result<Option<&PeerCredential>, PeerError> {
        let Some(grant) = self.peers.get(peer) else {
            return Ok(None);
        };
        match grant.credential.as_ref() {
            None => Ok(None),
            Some(c) if c.audience() == peer => Ok(Some(c)),
            Some(c) => Err(PeerError::WrongAudience {
                peer: peer.clone(),
                held_for: c.audience().clone(),
            }),
        }
    }
}

/// One request to one peer.
#[derive(Debug)]
pub struct PeerCall {
    peer: PeerId,
    capability: String,
    payload: Value,
    grant: PeerGrant,
    /// The chain the *peer* acts under: ours, narrowed, with the peer appended.
    acting_as: Delegation,
    credential: Option<PeerCredential>,
    client: Arc<dyn PeerClient>,
    /// Who is calling, sealed for this hop. Set by the runtime via
    /// [`Effect::attach`](crate::core::Effect::attach).
    provenance: Option<crate::core::Provenance>,
}

impl PeerCall {
    /// Prepare a hop, attenuating the caller's authority onto the peer.
    ///
    /// # Errors
    ///
    /// * [`PeerError::Unknown`] if the peer is not registered — fail closed.
    /// * [`PeerError::Delegation`] if the grant would widen the caller's own
    ///   authority, or if the chain is already at its depth limit.
    /// * [`PeerError::WrongAudience`] if the credential held is for someone else.
    pub fn prepare(
        registry: &PeerRegistry,
        client: Arc<dyn PeerClient>,
        caller: &Delegation,
        peer: PeerId,
        capability: impl Into<String>,
        payload: Value,
    ) -> Result<Self, PeerError> {
        let held = registry.credential_for(&peer)?.cloned();
        Self::prepare_with_credential(registry, client, caller, peer, capability, payload, held)
    }

    /// Prepare a hop with a credential the caller obtained itself.
    ///
    /// For a [`CredentialSource`], which mints
    /// against an expiry and therefore has to run at call time rather than at
    /// configuration time. The audience is re-checked here regardless of where
    /// the credential came from: a source is another place a mistake can be
    /// made, and this is the last point before it goes on the wire.
    ///
    /// # Errors
    ///
    /// As [`PeerCall::prepare`], plus [`PeerError::WrongAudience`] if the
    /// supplied credential is bound to a different peer.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_with_credential(
        registry: &PeerRegistry,
        client: Arc<dyn PeerClient>,
        caller: &Delegation,
        peer: PeerId,
        capability: impl Into<String>,
        payload: Value,
        credential: Option<PeerCredential>,
    ) -> Result<Self, PeerError> {
        if let Some(c) = credential.as_ref()
            && c.audience() != &peer
        {
            return Err(PeerError::WrongAudience {
                held_for: c.audience().clone(),
                peer,
            });
        }
        Self::build(
            registry, client, caller, peer, capability, payload, credential,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        registry: &PeerRegistry,
        client: Arc<dyn PeerClient>,
        caller: &Delegation,
        peer: PeerId,
        capability: impl Into<String>,
        payload: Value,
        credential: Option<PeerCredential>,
    ) -> Result<Self, PeerError> {
        let Some(grant) = registry.grant(&peer) else {
            return Err(PeerError::Unknown { peer });
        };

        // The grant is a ceiling. What the peer actually receives is bounded by
        // what *we* hold, which is what `delegate` enforces — a grant wider than
        // the caller's own authority is refused rather than silently clipped,
        // because silently clipping hides a misconfiguration that matters.
        let acting_as = caller
            .delegate(Principal::new(peer.to_string(), grant.scope.clone()))
            .map_err(|source| PeerError::Delegation {
                peer: peer.clone(),
                source,
            })?;

        Ok(Self {
            provenance: None,
            grant: grant.clone(),
            capability: capability.into(),
            payload,
            acting_as,
            credential,
            peer,
            client,
        })
    }

    /// The chain the peer will act under.
    #[must_use]
    pub const fn acting_as(&self) -> &Delegation {
        &self.acting_as
    }
}

#[async_trait]
impl Effect for PeerCall {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new(
            "a2a.peer/call",
            serde_json::json!({
                "peer": self.peer.0,
                "capability": self.capability,
                "payload": self.payload,
            }),
        )
    }

    fn mutates(&self) -> bool {
        self.grant.mutates
    }

    fn recovery(&self) -> Recovery {
        self.grant.recovery.clone()
    }

    fn retry(&self) -> RetryPolicy {
        self.grant.retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.grant.max_sensitivity
    }

    fn delegation_depth(&self) -> Option<usize> {
        Some(self.acting_as.depth())
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.grant.output_sensitivity
    }

    /// A peer's answer is another party's data.
    ///
    /// Stated rather than inherited because a peer feels more trusted than a
    /// tool — it is *our* agent, on our side. It is not: it runs somewhere else,
    /// under someone else's control, and it may itself have read the internet.
    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn attach(&mut self, provenance: &crate::core::Provenance) {
        self.provenance = Some(provenance.clone());
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.client
            .send(
                &self.peer,
                &self.capability,
                &self.payload,
                &self.acting_as,
                self.credential.as_ref(),
                self.provenance.as_ref(),
            )
            .await
            .map_err(|e| {
                let detail = e.to_string();
                match e.disposition() {
                    Disposition::DidNotHappen => EffectError::Rejected(detail),
                    Disposition::InDoubt => EffectError::Interrupted {
                        driver: self.peer.to_string(),
                        detail,
                    },
                    Disposition::Landed => EffectError::Performed(detail),
                }
            })
    }
}
