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
//! refusal still parks the registration and is reported, and delivery still
//! carries no ambient authority — no proxy, no cookie jar, no redirects.
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
use serde_json::json;

use crate::core::{CloudEvent, RunId, Seq, StoreError};
use crate::journal::{Record, RecordKind};

use super::delivery::Projection;
use super::{BodySigning, PushAuthentication, PushConfig, PushMessage, PushStore};

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

    /// Sign every delivery to this destination under `secret`.
    ///
    /// [Standard Webhooks]: `webhook-signature: v1,<base64>` over
    /// `{webhook-id}.{webhook-timestamp}.{body}`. It is beside
    /// [`authenticated`](Self::authenticated), not instead of it: a bearer
    /// header proves the *sender* held a token, which is a claim about the
    /// connection and not about the bytes, and that token transits every hop
    /// between here and the receiver.
    ///
    /// What the receiver must still do itself — refuse a stale
    /// `webhook-timestamp` and deduplicate on `webhook-id`, without which a
    /// captured POST replays — is set out on [`BodySigning`], and a receiver is
    /// being written against those limits whether or not anybody read them.
    ///
    /// # Panics
    ///
    /// If the key is shorter than 24 bytes, or a `whsec_`-prefixed secret is
    /// not base64. Both are this deployment's own configuration, so both are
    /// refused where they are written rather than at the far end of a run.
    ///
    /// Use [`try_signed_with`](Self::try_signed_with) where the secret is read
    /// from configuration inside a builder — a panic there takes the process
    /// down from underneath the code that was assembling it.
    ///
    /// [Standard Webhooks]: https://www.standardwebhooks.com/
    #[must_use]
    pub fn signed_with(mut self, secret: &crate::core::Secret) -> Self {
        self.signing = Some(BodySigning::new(secret));
        self
    }

    /// [`signed_with`](Self::signed_with), reporting a bad key rather than
    /// aborting.
    ///
    /// [`RuntimeBuilder::build`](crate::runtime::RuntimeBuilder::build) and
    /// [`try_build`](crate::runtime::RuntimeBuilder::try_build) in the small. A
    /// deployment reads this secret inside its own `build()`, so a mistyped one
    /// belongs in that builder's error path — with the exit code and the log
    /// line naming which destination was wrong, none of which a panic reaches.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`](super::SigningKeyError) — a `whsec_` secret that is
    /// not base64, or a key under the 24 bytes Standard Webhooks requires.
    pub fn try_signed_with(
        mut self,
        secret: &crate::core::Secret,
    ) -> Result<Self, super::SigningKeyError> {
        self.signing = Some(BodySigning::try_new(secret)?);
        Ok(self)
    }

    /// Sign every delivery under this secret **as well** — the mid-rotation
    /// form. The receiver holding either key verifies, so the old secret can
    /// be retired at the receiver's pace instead of on a flag day.
    ///
    /// # Panics
    ///
    /// As [`signed_with`](Self::signed_with); and if no primary secret was
    /// configured first, because "also" without a first key is a wiring
    /// mistake worth naming at configuration.
    #[must_use]
    pub fn also_signed_with(mut self, secret: &crate::core::Secret) -> Self {
        let signing = self
            .signing
            .take()
            .expect("also_signed_with needs signed_with first: there is no primary key");
        self.signing = Some(signing.also_with(secret));
        self
    }

    /// [`also_signed_with`](Self::also_signed_with), reporting rather than
    /// aborting — [`try_signed_with`](Self::try_signed_with)'s argument, with
    /// the same force: both secrets come from the same file, at the same
    /// moment, inside the same builder.
    ///
    /// # Errors
    ///
    /// [`SigningKeyError`](super::SigningKeyError) — a bad key, or
    /// [`NoPrimary`](super::SigningKeyError::NoPrimary) when no primary secret
    /// is configured.
    pub fn try_also_signed_with(
        mut self,
        secret: &crate::core::Secret,
    ) -> Result<Self, super::SigningKeyError> {
        let signing = self
            .signing
            .take()
            .ok_or(super::SigningKeyError::NoPrimary)?;
        self.signing = Some(signing.try_also_with(secret)?);
        Ok(self)
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
            // At configuration, like every other config error: a typo'd URL
            // otherwise surfaces per admitted run at first sweep, as one
            // permanently parked registration per run.
            assert!(
                reqwest::Url::parse(&destination.url).is_ok(),
                "outbox destination '{}' has an unparseable URL '{}'",
                destination.name,
                destination.url
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
/// than as a second event. The same id rides in the delivery's
/// [`HEADER_ID`](super::HEADER_ID) header, so a receiver can drop a repeat
/// before parsing the body and cannot end up with two answers to *which
/// message is this*.
///
/// `subject` is the run, which is what the event is about within this
/// producer. A receiver filtering by run would otherwise have to open `data` to
/// find out.
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
    tenant: Option<String>,
}

impl RunCompleted {
    /// `source` is the `CloudEvents` source URI for this deployment.
    #[must_use]
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            event_type: "io.agentplane.run.completed".to_owned(),
            tenant: None,
        }
    }

    /// Stamp every event with a `tenantid` extension.
    ///
    /// For a multi-tenant plane posting to one operator bus: without it, two
    /// tenants' completions are indistinguishable envelopes, and the inbound
    /// side of this crate already binds tenants on exactly this extension.
    #[must_use]
    pub fn for_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
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
    async fn messages(&self, record: &Record) -> Result<Vec<PushMessage>, StoreError> {
        // Every field named, no `..` — the payload-sealing list's rule, held
        // here for the same reason: a field added to `RunConcluded` must ask
        // this projection deliver-or-not at the build, not default to silence.
        let RecordKind::RunConcluded {
            outcome,
            reason,
            exhaustion,
            live_spend,
            chain_head,
        } = record.kind()
        else {
            return Ok(Vec::new());
        };
        let run = record.body.run.to_string();
        let mut event = CloudEvent::new(&self.source, &run, &self.event_type)
            // The three required attributes were checked when the source was
            // configured and the type is a constant; a run id is never empty.
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        if let Some(tenant) = &self.tenant {
            event = event
                .with_extension("tenantid", serde_json::Value::String(tenant.clone()))
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }
        let mut data = json!({
            "run": run,
            "case": record.body.case.map(|case| case.to_string()),
            "outcome": outcome,
            // The chain head the conclusion was drawn over, so a receiver
            // can ask this plane to prove the run it was told about.
            "chain_head": chain_head.to_hex(),
        });
        // Absent for a success, as the record spells it — a `null` here would
        // read as a failure with no explanation. The reason is sealed at rest
        // because it quotes what a provider or tool refused; it rides here
        // because this projection serves the operator namespace, the audience
        // the journal handle opens the seal for. The caller-facing A2A stream
        // deliberately does not carry it.
        if let Some(reason) = reason {
            data["reason"] = json!(reason);
        }
        if let Some(exhaustion) = exhaustion {
            data["exhaustion"] = json!(exhaustion);
        }
        if !live_spend.is_free() {
            data["live_spend"] = json!(live_spend);
        }
        let event = event
            // What the event is *about* within this producer. `source` names
            // the deployment and `id` is the deduplication half; without a
            // subject a receiver filtering by run has to open the data.
            .with_subject(&run)
            .with_data(data);
        Ok(vec![PushMessage::cloudevent(&event)])
    }

    fn namespace(&self) -> super::PushNamespace {
        super::PushNamespace::Operator
    }
}
