//! Obtaining credentials that are bound to one audience.
//!
//! [`PeerCredential`] models a token already minted for a single peer. Getting
//! one is OAuth **token exchange** (RFC 8693): present a subject token, name the
//! `resource` you intend to spend it at (RFC 8707), and receive a token the
//! issuer has bound to that audience. Everyone else then refuses it, which is
//! what makes handing it to a peer safe.
//!
//! # A credential must never enter the journal
//!
//! This is the rule the module is shaped around, and it is not a style
//! preference.
//!
//! The journal is append-only, hash-chained, permanent, and read by auditors. A
//! bearer token in an `EffectDone` record is a secret with unbounded lifetime in
//! a log that cannot be rewritten — not redacted later, not rotated out, not
//! expired away, because the record's hash covers it and the chain would break.
//!
//! So acquiring a credential is deliberately **not** a journaled effect. It is
//! transport metadata, in exactly the sense a run's lease is: it never enters
//! history and never influences a replayed decision. The journal records that a
//! peer was called and under which delegation chain. It does not record what was
//! presented.
//!
//! Three things enforce that rather than describing it:
//!
//! * [`PeerCredential`] has no `Serialize` — it cannot be written by accident.
//! * Its `Debug` redacts the secret, so it cannot reach a log line or a span.
//! * `tests/trust/peers.rs` runs a real peer call and scans the whole journal for the
//!   secret.
//!
//! # Freshness
//!
//! A token that expires in two seconds is already spent: it will lapse in
//! flight, and the rejection arrives as a peer failure of *unknown disposition*
//! when it was really a refresh nobody scheduled. [`Cached`] therefore refreshes
//! against a skew margin rather than against the expiry itself.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::core::Timestamp;

use super::{PeerCredential, PeerId};

/// Why a credential could not be obtained.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The issuer could not be reached or refused.
    #[error("could not obtain a credential for '{audience}': {detail}")]
    Unavailable { audience: PeerId, detail: String },

    /// The issuer returned a token bound to somebody else.
    ///
    /// A misconfigured `resource` parameter, or an issuer that ignores it. Either
    /// way the token is unusable here: presenting it would hand this peer a
    /// credential it can spend elsewhere.
    #[error(
        "the issuer returned a credential for '{issued_for}' when '{audience}' was \
         requested — an unbound token is one the recipient can replay"
    )]
    WrongAudience {
        audience: PeerId,
        issued_for: PeerId,
    },

    /// The issuer returned a token that is already expired, or expires within
    /// the skew margin.
    #[error("the credential issued for '{audience}' is already spent")]
    Stale { audience: PeerId },
}

/// Exchanges one token for another bound to a named audience.
///
/// The RFC 8693 shape, reduced to what the runtime depends on. A real
/// implementation posts to a token endpoint with `resource` set; a test
/// implementation hands back whatever it was told to.
#[async_trait]
pub trait TokenExchange: Send + Sync + Debug {
    /// Obtain a credential valid only at `audience`.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] if the issuer is unreachable, refuses, or returns a
    /// token bound to the wrong audience.
    async fn exchange(&self, audience: &PeerId) -> Result<PeerCredential, CredentialError>;
}

/// Supplies the credential for a peer at call time.
#[async_trait]
pub trait CredentialSource: Send + Sync + Debug {
    /// The credential to present to `audience`, fresh at `now`.
    ///
    /// # Errors
    ///
    /// If none can be obtained.
    async fn credential(
        &self,
        audience: &PeerId,
        now: Timestamp,
    ) -> Result<PeerCredential, CredentialError>;
}

/// A credential held for one audience, with no expiry.
///
/// For deployments that provision long-lived, audience-bound tokens out of band.
/// The binding still holds — this is not a way to opt out of it.
#[derive(Debug)]
pub struct Fixed(PeerCredential);

impl Fixed {
    #[must_use]
    pub const fn new(credential: PeerCredential) -> Self {
        Self(credential)
    }
}

#[async_trait]
impl CredentialSource for Fixed {
    async fn credential(
        &self,
        audience: &PeerId,
        _now: Timestamp,
    ) -> Result<PeerCredential, CredentialError> {
        if self.0.audience() != audience {
            return Err(CredentialError::WrongAudience {
                audience: audience.clone(),
                issued_for: self.0.audience().clone(),
            });
        }
        Ok(self.0.clone())
    }
}

/// Exchanges on demand and keeps the result until it is nearly expired.
#[derive(Debug)]
pub struct Cached {
    exchange: std::sync::Arc<dyn TokenExchange>,
    /// How far before expiry a credential stops being used.
    skew: Duration,
    held: Mutex<BTreeMap<PeerId, PeerCredential>>,
}

impl Cached {
    /// Default margin: a minute.
    ///
    /// Long enough to cover a slow hop and a slow peer, short enough that a
    /// five-minute token is still worth caching.
    pub const DEFAULT_SKEW: Duration = Duration::from_mins(1);

    #[must_use]
    pub fn new(exchange: std::sync::Arc<dyn TokenExchange>) -> Self {
        Self {
            exchange,
            skew: Self::DEFAULT_SKEW,
            held: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub const fn skew(mut self, skew: Duration) -> Self {
        self.skew = skew;
        self
    }
}

#[async_trait]
impl CredentialSource for Cached {
    async fn credential(
        &self,
        audience: &PeerId,
        now: Timestamp,
    ) -> Result<PeerCredential, CredentialError> {
        // Scoped so the guard is gone before the await below: a lock held across
        // a suspension is held on the *thread*, and this one would be held for
        // the length of a network round trip.
        {
            let held = self.held.lock().expect("credential cache");
            if let Some(c) = held.get(audience)
                && c.is_usable_at(now, self.skew)
            {
                return Ok(c.clone());
            }
        }

        let fresh = self.exchange.exchange(audience).await?;

        // The issuer is not taken at its word about who the token is for. An
        // issuer that ignores `resource` hands back something the peer can spend
        // elsewhere, and that is the failure this whole design exists to avoid.
        if fresh.audience() != audience {
            return Err(CredentialError::WrongAudience {
                audience: audience.clone(),
                issued_for: fresh.audience().clone(),
            });
        }
        if !fresh.is_usable_at(now, self.skew) {
            return Err(CredentialError::Stale {
                audience: audience.clone(),
            });
        }

        self.held
            .lock()
            .expect("credential cache")
            .insert(audience.clone(), fresh.clone());
        Ok(fresh)
    }
}
