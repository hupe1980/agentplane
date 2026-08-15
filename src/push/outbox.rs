//! Outbound delivery to a destination the **deployment** chose.
//!
//! # The mirror image of push
//!
//! [`PushConfig`] is A2A-shaped by construction: a *caller* supplies the URL, it
//! is scoped to one task, and it carries a `StreamResponse`. Three controls
//! exist because of that first fact — an operator host allowlist, HTTPS only,
//! and every DNS answer checked against [`netguard`](crate::netguard) — since
//! push is the one place an untrusted party names an address this plane will
//! connect to.
//!
//! The shape a service actually needs beside it is the mirror image: **one
//! destination the operator configured**, receiving one payload the embedder
//! shapes, for every run. Because that was not available, services emitted their
//! result event at request time with retries and dropped it on failure — the one
//! outbound path in the deployment with no persist-before-dispatch, in a
//! codebase whose whole argument is that the journal is the plan of record.
//!
//! # What is relaxed, and precisely why
//!
//! An operator destination skips the three URL controls, and that is not a
//! weakening of push — it is push's controls not applying:
//!
//! * **The host allowlist** answers *may this caller name this host?* There is
//!   no caller. The URL is in the deployment's own configuration, beside the
//!   allowlist it would be checked against, written by the same person.
//! * **HTTPS only** protects a payload sent to an address *the recipient chose*.
//!   An in-cluster collector on plaintext HTTP is an ordinary deployment, and
//!   refusing it would push operators toward a sidecar that terminates TLS and
//!   forwards in clear — the same exposure with an extra hop.
//! * **The public-address check** exists to stop a name that resolves *inward*.
//!   Resolving inward is the entire point here: the destination is the
//!   deployment's own bus.
//!
//! Everything that is not about caller-supplied URLs is unchanged. The cursor
//! still advances only on 2xx, the retry ceiling still applies, a permanent
//! refusal is still abandoned and reported, and delivery still carries no
//! ambient authority — no proxy, no cookie jar, no redirects.
//!
//! # The journal is still the outbox
//!
//! A destination is registered against a run **at admission**, before the run
//! does anything, so there is no window in which a run exists and nothing is
//! watching it. Delivery then reads the run's own records past the cursor. There
//! is no separate queue to fall out of sync with the history, which is the whole
//! reason to build it this way rather than as a message the runtime remembers to
//! send.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::core::{RunId, Seq, StoreError};
use crate::journal::{Record, RecordKind};

use super::delivery::Projection;
use super::{BodySigning, PushAuthentication, PushConfig, PushStore};

/// The marker that tells an operator destination from a caller's webhook.
///
/// Both live in one [`PushStore`], because they are the same durable structure —
/// a URL and a journal cursor — and a second table would be a second copy of the
/// retry and acknowledgement logic. They must not be confused for one another
/// though: an operator's `CloudEvents` message delivered to a peer's A2A webhook is a
/// disclosure, and a `StreamResponse` posted to the deployment's bus is a
/// malformed event nobody parses.
///
/// So the id namespace is split by a prefix that a caller cannot use — the A2A
/// server refuses a `pushNotificationConfig.id` beginning with it — and each
/// worker declares its half through
/// [`Projection::namespace`](super::Projection::namespace), which the store's
/// due query filters on.
pub const OPERATOR_PREFIX: &str = "operator:";

/// Whether a registration id names an operator destination.
#[must_use]
pub fn is_operator_id(id: &str) -> bool {
    id.starts_with(OPERATOR_PREFIX)
}

/// One place the deployment sends its own events.
#[derive(Debug, Clone)]
pub struct Destination {
    /// What the operator calls it. Appears in logs and in the stored id.
    pub name: String,
    /// Where to POST. Not checked against an allowlist, because there is no
    /// caller to check — see the module docs.
    pub url: String,
    /// HTTP authentication for the receiver, if it wants any.
    pub authentication: Option<PushAuthentication>,
    /// A body signature for the receiver, if it verifies one.
    ///
    /// `None` means deliveries carry no signature at all — not an unsigned
    /// header, no header. See [`signed_with`](Self::signed_with) for what a
    /// signature is and is not evidence of.
    pub signing: Option<BodySigning>,
}

impl Destination {
    #[must_use]
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            authentication: None,
            signing: None,
        }
    }

    #[must_use]
    pub fn authenticated(
        mut self,
        scheme: impl Into<String>,
        credentials: crate::core::Secret,
    ) -> Self {
        self.authentication = Some(PushAuthentication {
            scheme: scheme.into(),
            credentials,
        });
        self
    }

    /// Sign every delivery's body, in `header`, under `secret`.
    ///
    /// `HMAC-SHA256` over the exact bytes posted, sent as `sha256=<hex>` — the
    /// convention receivers are already written against. It is beside
    /// [`authenticated`](Self::authenticated), not instead of it: a bearer
    /// header proves the *sender* held a token, which is a claim about the
    /// connection and not about the bytes, and that token transits every hop
    /// between here and the receiver.
    ///
    /// What the receiver may conclude from a matching signature, and what it
    /// may not — chiefly that the delivery is authentic but **not fresh**, so
    /// a captured POST replays forever unless the receiver deduplicates on the
    /// event's own identity — is set out on [`BodySigning`], and a receiver is
    /// being written against those limits whether or not anybody read them.
    ///
    /// # Panics
    ///
    /// If `header` is not an HTTP field name, or the secret is empty. Both are
    /// this deployment's own configuration, so both are refused where they are
    /// written rather than at the far end of a run.
    #[must_use]
    pub fn signed_with(mut self, header: impl Into<String>, secret: crate::core::Secret) -> Self {
        self.signing = Some(BodySigning::new(header, secret));
        self
    }

    /// The stored registration id for this destination.
    #[must_use]
    pub fn registration_id(&self) -> String {
        format!("{OPERATOR_PREFIX}{}", self.name)
    }

    /// The durable registration for this destination on one run.
    ///
    /// Note what is **not** here: the signing key. A caller's bearer token has
    /// to be stored, because it arrived with a request that is long over and
    /// there is no other copy of it — that is what the row exists for. An
    /// operator's signing key is the opposite: it is in this deployment's own
    /// configuration, read at every start, so persisting it would write a copy
    /// of a key that can forge every future delivery into a row per run per
    /// destination, and buy nothing. It also decides *when a rotation takes
    /// effect*: the key the sender holds signs the next sweep, where a
    /// per-registration copy would keep signing with whatever was configured
    /// when each run was admitted. The sender is given the destinations for
    /// this reason — see [`PushSender::for_operator_destinations`](super::PushSender::for_operator_destinations).
    fn config_for(&self, run: RunId) -> PushConfig {
        PushConfig {
            id: self.registration_id(),
            task: run,
            url: self.url.clone(),
            // A2A's per-task correlation secret. An operator destination has no
            // caller to correlate with, so there is nothing honest to put here.
            token: None,
            authentication: self.authentication.clone(),
        }
    }
}

/// The operator's destinations, and the registration that puts a run in front of
/// them.
#[derive(Debug, Clone)]
pub struct Outbox {
    destinations: Vec<Destination>,
    store: Arc<dyn PushStore>,
}

impl Outbox {
    /// # Panics
    ///
    /// If two destinations share a name, or a name is blank. Both would make the
    /// stored id ambiguous, and one destination's cursor would advance on the
    /// other's acknowledgements — a silent loss of every event for whichever one
    /// lost the race, which is exactly what a durable outbox exists to prevent.
    #[must_use]
    pub fn new(store: Arc<dyn PushStore>, destinations: Vec<Destination>) -> Self {
        let mut names = std::collections::BTreeSet::new();
        for destination in &destinations {
            assert!(
                !destination.name.trim().is_empty(),
                "an outbox destination needs a name: it is half of the stored \
                 registration id"
            );
            assert!(
                names.insert(destination.name.clone()),
                "outbox destination '{}' is configured twice — the two would share \
                 one cursor, so one's acknowledgement would discard the other's \
                 backlog",
                destination.name
            );
        }
        Self {
            destinations,
            store,
        }
    }

    #[must_use]
    pub fn destinations(&self) -> &[Destination] {
        &self.destinations
    }

    /// Whose rows the store behind this outbox can reach.
    ///
    /// The builder asks before it seals: the outbox is the one store here
    /// reached through a handle the embedder constructed rather than
    /// registered, so its tenant would otherwise be the one the plane never
    /// gets to check.
    pub(crate) fn store_tenant(&self) -> &str {
        self.store.tenant()
    }

    /// The same outbox, with its store's credentials sealed under `keys`.
    ///
    /// An operator destination's bearer — written by [`open`](Self::open) into
    /// every run's registration — is a credential like any caller's, and the
    /// store keeps it. This wraps the store in
    /// [`SealedPush`](crate::keyring::SealedPush), so what lands at rest is
    /// sealed and what [`Outbox`]'s worker reads back is not.
    ///
    /// One method rather than "construct with a wrapped store" because the
    /// runtime seals stores at **build** — after the embedder handed the outbox
    /// over — and a decorator only the constructor could apply is a guarantee
    /// the argument order decides. `tenant` must be the tenant the store
    /// serves, for the reason
    /// [`SealedCases::wrap`](crate::keyring::SealedCases::wrap) gives.
    #[cfg(feature = "keyring")]
    #[must_use]
    pub fn sealed(
        mut self,
        keys: Arc<dyn crate::keyring::KeyRing>,
        tenant: crate::core::TenantId,
    ) -> Self {
        self.store = crate::keyring::SealedPush::wrap(Arc::clone(&self.store), keys, tenant);
        self
    }

    /// Register every destination against a run, from its first record on.
    ///
    /// Called by the runtime at admission. Idempotent: [`PushStore::put`]
    /// preserves an existing cursor, so a re-admitted or resumed run does not
    /// rewind a receiver that has already acknowledged part of the history.
    ///
    /// # Errors
    ///
    /// [`StoreError`] if the push store cannot be written. Admission fails, which
    /// is the correct direction: a run that started without its destinations
    /// registered would produce a history nothing is watching, and the events it
    /// missed are unrecoverable without a scan nobody schedules.
    pub async fn open(&self, run: RunId) -> Result<(), StoreError> {
        for destination in &self.destinations {
            // Sequence 1: the run's first record. A destination registered at
            // admission sees the whole history, including the admission itself.
            let from: Seq = 1;
            self.store.put(&destination.config_for(run), from).await?;
        }
        Ok(())
    }
}

/// One `CloudEvents` message per **completed run**.
///
/// The default an embedder gets for free, and the shape most services want: a
/// run finished, here is its identity, its outcome and its chain head. Every
/// other record projects to nothing, so the cursor sweeps past a run's whole
/// history and delivers once.
///
/// # Why the outcome is all that travels
///
/// Not the answer. A run's output is domain data with a label on it, and a
/// projection that shipped it by default would send whatever the run happened to
/// hold to whatever the operator happened to configure, with no ceiling anybody
/// declared — an egress decision made by a default. A deployment that wants the
/// payload writes its own [`Projection`] and makes that decision explicitly.
///
/// `id` is the run id and `source` is the deployment, which is the pair
/// `CloudEvents` defines uniqueness by — so a duplicate delivery, which
/// at-least-once guarantees will happen, is detectable as a duplicate rather
/// than as a second event.
///
/// # There is no `time`, and that is honest
///
/// `CloudEvents` makes it optional, and this crate has nothing true to put in
/// it. A journal record carries no wall clock: time in a run comes from
/// journaled `clock.now` effects, precisely so that a replay sees the instant
/// the run saw. Reading the ambient clock at *delivery* would stamp an event
/// with when the outbox happened to sweep — which for a receiver that was down
/// for two hours is a lie about when the run finished, told with more precision
/// than the truth. A deployment that needs the instant projects it from its own
/// records.
#[derive(Debug, Clone)]
pub struct RunCompleted {
    source: String,
    event_type: String,
}

impl RunCompleted {
    /// `source` is the `CloudEvents` source URI for this deployment.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            event_type: "io.agentplane.run.completed".to_owned(),
        }
    }

    /// Override the `CloudEvents` `type`.
    #[must_use]
    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = event_type.into();
        self
    }
}

#[async_trait]
impl Projection for RunCompleted {
    async fn payloads(&self, record: &Record) -> Result<Vec<Value>, StoreError> {
        let RecordKind::RunSealed {
            outcome,
            chain_head,
        } = record.kind()
        else {
            return Ok(Vec::new());
        };
        Ok(vec![json!({
            "specversion": "1.0",
            "type": self.event_type,
            "source": self.source,
            "id": record.body.run.to_string(),
            "datacontenttype": "application/json",
            "data": {
                "run": record.body.run.to_string(),
                "case": record.body.case.map(|case| case.to_string()),
                "outcome": outcome,
                // The chain head the conclusion was drawn over, so a receiver
                // can ask this plane to prove the run it was told about.
                "chain_head": chain_head.to_hex(),
            },
        })])
    }

    fn namespace(&self) -> super::PushNamespace {
        super::PushNamespace::Operator
    }
}
