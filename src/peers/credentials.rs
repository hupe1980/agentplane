//! Obtaining credentials that are bound to one audience and one subject.
//!
//! [`PeerCredential`] models a token already minted for a single peer. Getting
//! one is OAuth **token exchange** (RFC 8693): name the subject the token is for
//! and the plane as the actor, name the `resource` you intend to spend it at
//! (RFC 8707), and receive a token the issuer has bound to both. Every other
//! audience then refuses it, which is what makes handing it to a peer safe; and
//! the peer sees who the call is for, rather than only the plane that carried
//! it.
//!
//! # Whom the credential names
//!
//! The run's chain's **owner** — the person the run acts for, whom a commission
//! shares with its parent — never the acting workload. The issuer accepts the
//! plane's say-so about that subject on the strength of the plane's own
//! authentication: the plane admitted the run, and the issuer trusts it to name
//! the subjects it admitted. The plane never holds the caller's inbound token,
//! which a run resumed a day later would not have.
//!
//! A credential is checked on arrival for both: an issuer is trusted to mint,
//! not to say whom it minted for.
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

    /// The issuer returned a token for another subject, or for none.
    ///
    /// Presenting it would tell the peer the call is for somebody it is not
    /// for — the one thing a subject-bound credential exists to state.
    #[error(
        "the issuer returned a credential for {} when '{subject}' was requested at \
         '{audience}'",
        issued_for.as_deref().map_or_else(|| "no subject".to_owned(), |s| format!("'{s}'"))
    )]
    WrongSubject {
        audience: PeerId,
        subject: String,
        issued_for: Option<String>,
    },

    /// The issuer answered, and declined to mint for this subject or
    /// audience. Final: asking again asks the same rule the same question.
    #[error("the issuer refused a credential for '{audience}': {detail}")]
    Refused { audience: PeerId, detail: String },

    /// The issuer returned a token that is already expired, or expires within
    /// the skew margin.
    #[error("the credential issued for '{audience}' is already spent")]
    Stale { audience: PeerId },
}

/// Exchanges for a token bound to one audience and one subject.
///
/// The RFC 8693 shape, reduced to what the runtime depends on. A real
/// implementation posts to the deployment's token endpoint with the subject
/// as `subject_token`, the plane's own credential as `actor_token`, and
/// `resource` set to the audience; a test implementation hands back whatever
/// it was told to.
#[async_trait]
pub trait TokenExchange: Send + Sync + Debug {
    /// Obtain a credential naming `subject`, valid only at `audience`.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] if the issuer is unreachable or refuses.
    async fn exchange(
        &self,
        audience: &PeerId,
        subject: &str,
    ) -> Result<PeerCredential, CredentialError>;
}

/// Supplies the credential a call for `subject` presents to a peer.
#[async_trait]
pub trait CredentialSource: Send + Sync + Debug {
    /// The credential naming `subject` to present to `audience`, fresh at
    /// `now`.
    ///
    /// # Errors
    ///
    /// If none can be obtained.
    async fn credential(
        &self,
        audience: &PeerId,
        subject: &str,
        now: Timestamp,
    ) -> Result<PeerCredential, CredentialError>;

    /// Drop everything held for `subject`, at every audience, including what
    /// an exchange already in flight for them would bring back.
    ///
    /// Called when an operator withdraws or restores the subject's authority:
    /// a held credential outlives the halt until it expires, and must not be
    /// served to the next run that asks once the halt is lifted. Required
    /// rather than defaulted, so a source that holds credentials cannot
    /// compile without saying how it lets go of them; one that holds nothing
    /// implements it as nothing.
    fn forget(&self, subject: &str);
}

/// The wall clock, for a credential's freshness.
///
/// Transport metadata in the sense a lease is: read only where a call is
/// performed, which replay never reaches, and never journaled — so it decides
/// nothing a replay must reproduce.
#[allow(clippy::disallowed_methods)]
pub(super) fn now() -> Timestamp {
    Timestamp::now_utc()
}

/// `credential`, if it is for `audience` and `subject`.
///
/// The one check every credential crosses before it is presented, whichever
/// source produced it.
///
/// # Errors
///
/// [`CredentialError::WrongAudience`] or [`CredentialError::WrongSubject`].
pub(super) fn bound_to(
    credential: PeerCredential,
    audience: &PeerId,
    subject: &str,
) -> Result<PeerCredential, CredentialError> {
    if credential.audience() != audience {
        return Err(CredentialError::WrongAudience {
            audience: audience.clone(),
            issued_for: credential.audience().clone(),
        });
    }
    if credential.subject() != Some(subject) {
        return Err(CredentialError::WrongSubject {
            audience: audience.clone(),
            subject: subject.to_owned(),
            issued_for: credential.subject().map(ToOwned::to_owned),
        });
    }
    Ok(credential)
}

/// Exchanges on demand and keeps the result until it is nearly expired.
///
/// Held per audience **and** subject: a credential obtained for one person is
/// never lent to a run acting for another.
#[derive(Debug)]
pub struct Cached {
    exchange: std::sync::Arc<dyn TokenExchange>,
    /// How far before expiry a credential stops being used.
    skew: Duration,
    held: Mutex<Held>,
}

/// The cache and, per subject, how many times it was forgotten — so an
/// exchange that began before a `forget` cannot put its answer back after it.
#[derive(Debug, Default)]
struct Held {
    credentials: BTreeMap<(PeerId, String), PeerCredential>,
    forgotten: BTreeMap<String, u64>,
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
            held: Mutex::new(Held::default()),
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
        subject: &str,
        now: Timestamp,
    ) -> Result<PeerCredential, CredentialError> {
        let key = (audience.clone(), subject.to_owned());
        // Scoped so the guard is gone before the await below: a lock held across
        // a suspension is held on the *thread*, and this one would be held for
        // the length of a network round trip.
        let generation = {
            let held = self.held.lock().expect("credential cache");
            if let Some(c) = held.credentials.get(&key)
                && c.is_usable_at(now, self.skew)
            {
                return Ok(c.clone());
            }
            held.forgotten.get(subject).copied().unwrap_or(0)
        };

        // The issuer is not taken at its word about who the token is for. An
        // issuer that ignores `resource` hands back something the peer can spend
        // elsewhere, and one that ignores the subject names the wrong person.
        let fresh = bound_to(
            self.exchange.exchange(audience, subject).await?,
            audience,
            subject,
        )?;
        if !fresh.is_usable_at(now, self.skew) {
            return Err(CredentialError::Stale {
                audience: audience.clone(),
            });
        }

        let mut held = self.held.lock().expect("credential cache");
        // Kept only if nobody forgot this subject while the exchange was out:
        // the answer is still presented to this caller, who asked before the
        // halt, but never lent to the next one.
        if held.forgotten.get(subject).copied().unwrap_or(0) == generation {
            let skew = self.skew;
            held.credentials.retain(|_, c| c.is_usable_at(now, skew));
            held.credentials.insert(key, fresh.clone());
        }
        Ok(fresh)
    }

    fn forget(&self, subject: &str) {
        let mut held = self.held.lock().expect("credential cache");
        held.credentials
            .retain(|(_, held_for), _| held_for != subject);
        *held.forgotten.entry(subject.to_owned()).or_default() += 1;
    }
}
