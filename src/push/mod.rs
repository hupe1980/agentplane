//! Push notifications: telling a peer's webhook that its task moved.
//!
//! Streaming holds a connection open; push does not. A peer that asked for a
//! task at 09:00 and disconnected wants to know at 14:00 that it finished, and
//! neither polling forever nor holding a socket for five hours is a reasonable
//! way to arrange that.
//!
//! # The URL comes from the caller, which is the whole problem
//!
//! Every other outbound destination in this crate is granted by an operator. A
//! webhook URL is supplied by whoever created the task — so push is the one
//! feature where an untrusted party names an address this plane will connect to,
//! with a payload describing somebody's task.
//!
//! Three controls, and none of them is sufficient alone:
//!
//! * **An operator grant.** The host must be on an allowlist. A caller may pick
//!   any URL under a host the deployment permits, and no host it does not. This
//!   is the primary control; the rest are the second lock.
//! * **Public addresses only.** Every destination is checked with
//!   [`netguard`](crate::netguard) before dispatch, and every name the client
//!   resolves is checked again as it resolves — so a host that resolves inward,
//!   or answers differently the second time, reaches nothing.
//! * **HTTPS only.** The payload describes a task; sending it in clear to an
//!   address chosen by the recipient is a disclosure with extra steps.
//!
//! # What is delivered, and what is not
//!
//! The payload is a `StreamResponse` — the same status/artifact union streaming
//! sends, so a receiver parses one thing and A2A's two delivery mechanisms do
//! not disagree. Registering a destination is therefore authorization to send
//! that task's output there: task-level policy and the operator host grant are
//! both checked rather than treating the allowlist as sufficient authority.
//!
//! What that union is *called* on the wire is the [`PushMessage`]'s to say, not
//! this module's: the same loop also carries an operator's structured-mode
//! `CloudEvents` envelope, and one hard-coded media type would make whichever
//! of the two lost a body no conformant receiver routes.
//!
//! # The journal is the outbox
//!
//! A registration stores the first journal sequence it has not acknowledged.
//! Workers derive payloads from those records and advance only after HTTP 2xx.
//! A crash after POST but before cursor persistence duplicates an event instead
//! of losing it, which is A2A's at-least-once contract — and why every delivery
//! carries a [`HEADER_ID`] the receiver can recognise a repeat by.
//!
//! A receiver that answers permanently, or that stays silent past the retry
//! ceiling, has its registration [parked](PushStore::park) rather than deleted.
//! The cursor is the only record of how far that receiver got; discarding it
//! turns a receiver outage into an unrecoverable gap, where keeping it turns
//! the same outage into a list an operator can re-arm.

mod delivery;
mod outbox;
mod sign;

pub use delivery::{DeliveryWorker, Projection, PushSweepReport};
pub use outbox::{Destination, OPERATOR_PREFIX, Outbox, RunCompleted, is_operator_id};
pub use sign::{
    BodySigning, DEFAULT_TOLERANCE, HEADER_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, SCHEME,
    SigningKeyError, VerifiedDelivery, WebhookRejected, WebhookVerifier,
};

/// Which of the two id namespaces a worker serves.
///
/// Two workers share one [`PushStore`]: the A2A worker serves caller-registered
/// webhooks, the outbox worker serves operator destinations, and the two are
/// told apart by the [`OPERATOR_PREFIX`] on the registration id. This enum is
/// that split as a value, so the **store** can filter a due query on it —
/// filtering after a bounded read cannot work, because rows of the other
/// namespace occupy the head of the stable order and starve everything behind
/// them while the report reads as a quiet plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushNamespace {
    /// Destinations the deployment configured for itself — ids carrying
    /// [`OPERATOR_PREFIX`], served by [`Outbox`]'s worker.
    Operator,
    /// Webhooks callers registered over A2A — every id without the prefix.
    Caller,
}

impl PushNamespace {
    /// Whether a registration id belongs to this namespace.
    #[must_use]
    pub fn owns_id(self, id: &str) -> bool {
        match self {
            Self::Operator => is_operator_id(id),
            Self::Caller => !is_operator_id(id),
        }
    }
}

/// One namespace's due registrations, with the other namespace's backlog
/// counted rather than silently skipped.
#[derive(Debug, Clone, Default)]
pub struct DueBatch {
    /// Due registrations of the requested namespace, in the store's stable
    /// order.
    pub rows: Vec<PushRegistration>,
    /// Due rows of the **other** namespace that were visible to this query.
    ///
    /// Counted so a deployment running only one worker can see the backlog no
    /// worker of this kind will ever serve, instead of a report shaped like a
    /// quiet plane. A lower bound: both backends' native overrides count the
    /// whole foreign due backlog, and the paging default reports what its
    /// final window happened to scan past — never more than the truth, and
    /// exact once a read exhausts the store.
    pub unserved: usize,
}

use std::fmt::Debug;

use async_trait::async_trait;

use crate::core::{RunId, Secret, Seq, StoreError};

/// Where a peer wants to be told about a task.
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// The configuration's own id, unique within a task.
    pub id: String,
    /// The task this is about.
    pub task: RunId,
    /// Where to POST. HTTPS, and on a granted host.
    pub url: String,
    /// A2A's opaque token for this task/session. It is not HTTP authentication;
    /// those credentials live in [`authentication`](Self::authentication).
    pub token: Option<Secret>,
    /// HTTP authentication for the receiver, distinct from A2A's opaque
    /// per-task/session token.
    pub authentication: Option<PushAuthentication>,
}

/// Authentication information from A2A's push configuration.
#[derive(Clone)]
pub struct PushAuthentication {
    pub scheme: String,
    pub credentials: Secret,
}

impl Debug for PushAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushAuthentication")
            .field("scheme", &self.scheme)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

impl PushAuthentication {
    /// Validate the HTTP authentication scheme and resulting header value.
    ///
    /// Kept on the protocol value rather than only on [`PushSender`], so a
    /// custom transport cannot accidentally make malformed A2A input valid.
    ///
    /// # Errors
    ///
    /// [`PushError::Malformed`] when the required scheme is not an RFC 9110
    /// token or the credentials cannot be represented in a header.
    pub fn validate(&self) -> Result<(), PushError> {
        if self.scheme.is_empty()
            || !self.scheme.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err(PushError::Malformed(
                "authentication.scheme must be an HTTP authentication token".to_owned(),
            ));
        }
        let value = format!("{} {}", self.scheme, self.credentials.expose());
        reqwest::header::HeaderValue::from_str(&value)
            .map(|_| ())
            .map_err(|error| PushError::Malformed(format!("invalid authentication: {error}")))
    }
}

/// One durable delivery cursor.
///
/// The journal is the outbox: `next_seq` names the first task record not yet
/// acknowledged by this receiver. A crash after POST and before `advance`
/// causes a duplicate, never a loss — the at-least-once direction A2A requires.
#[derive(Debug, Clone)]
pub struct PushRegistration {
    pub config: PushConfig,
    pub next_seq: Seq,
    pub attempts: u32,
    pub next_attempt_at: u64,
    pub last_error: Option<String>,
}

impl PushConfig {
    /// What a caller may see back.
    ///
    /// The token is **not** echoed. A caller that can read a config it did not
    /// create would otherwise learn another party's correlation secret, and the
    /// only party that needs the token already has it.
    #[must_use]
    pub fn redacted(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "taskId": self.task.to_string(),
            "url": self.url,
            "authentication": self.authentication.as_ref().map(|auth| serde_json::json!({
                "scheme": auth.scheme,
            })),
        })
    }
}

/// Why a webhook was not accepted or not delivered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    #[error(
        "a webhook URL must be https — the payload describes a task, and \
         sending it in clear to an address the recipient chose is a disclosure"
    )]
    NotHttps,
    #[error("this deployment does not permit webhooks to '{0}'")]
    HostNotGranted(String),
    #[error("the webhook URL is not a URL: {0}")]
    Malformed(String),
    #[error("'{0}'")]
    Unroutable(String),
}

impl PushError {
    /// Whether waiting could change this answer.
    ///
    /// The grant is re-checked at delivery because a registration outlives the
    /// configuration that permitted it — but noticing a refusal and then
    /// scheduling that same refusal again is a decision that will never change,
    /// retried forever. A scheme that is not HTTPS, a URL that does not parse,
    /// and a host the operator has taken off the allowlist are all answers no
    /// backoff improves, so the worker abandons them rather than queueing a
    /// forty-first attempt against an answer it already has.
    ///
    /// [`Unroutable`](Self::Unroutable) is deliberately **not** permanent: it
    /// covers DNS, and DNS changes. A name that resolves inward today may be
    /// repointed tomorrow, and abandoning on the first answer would make a
    /// transient misconfiguration indistinguishable from a revoked grant.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::NotHttps | Self::HostNotGranted(_) | Self::Malformed(_)
        )
    }
}

/// Durable storage for webhook registrations.
///
/// Durable because a task outlives the connection that created it, and a
/// registration that vanished on restart would leave a peer waiting for a
/// notification nobody remembers promising.
#[async_trait]
pub trait PushStore: Send + Sync + Debug {
    /// Whose rows this handle can reach.
    ///
    /// Defaults to [`TenantId::DEFAULT`](crate::core::TenantId::DEFAULT), the
    /// tenant a store serves until told otherwise. Override it with the tenant
    /// the handle is actually scoped to.
    ///
    /// This exists so a mismatch with the plane's tenant is a **startup
    /// refusal**. When a key ring is wired, `build()` seals this state under
    /// the plane's tenant while the store writes rows under its own; the two
    /// disagreeing is not a leak — the scopes simply differ — but it seals the
    /// state under a scope erasure will never destroy. That is an erasure that
    /// reports success and misses, which is the one failure a deletion
    /// guarantee cannot have.
    fn tenant(&self) -> &str {
        crate::core::TenantId::DEFAULT
    }

    /// Register or replace a configuration.
    ///
    /// Replacement preserves the existing acknowledgement cursor. Changing a
    /// URL or credentials is not permission to discard updates that receiver
    /// has not accepted.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn put(&self, config: &PushConfig, next_seq: Seq) -> Result<(), StoreError>;

    /// One configuration.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn get(&self, task: RunId, id: &str) -> Result<Option<PushConfig>, StoreError>;

    /// Every configuration for a task.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn list(&self, task: RunId) -> Result<Vec<PushConfig>, StoreError>;

    /// Registrations whose retry instant has arrived, in stable order.
    ///
    /// Parked rows are excluded — see [`park`](Self::park).
    async fn due(&self, at: u64, limit: usize) -> Result<Vec<PushRegistration>, StoreError>;

    /// The due registrations of **one namespace**, however deep in the stable
    /// order they sit — plus a count of the other namespace's due rows.
    ///
    /// The filter belongs in the query because it cannot live after it: a
    /// worker that reads a bounded window and then drops the rows it does not
    /// own is starved the moment the other namespace fills the window, and its
    /// own rows beyond it are never read at all. The id prefix is already the
    /// discriminator — see [`PushNamespace`].
    ///
    /// The default implementation pages over [`due`](Self::due) with a growing
    /// window until it holds `limit` rows of the namespace or the store is
    /// exhausted. Correct against any backend, and linear in the other
    /// namespace's backlog — a backend with an index should override it with an
    /// in-query filter on the id prefix.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn due_in(
        &self,
        at: u64,
        limit: usize,
        namespace: PushNamespace,
    ) -> Result<DueBatch, StoreError> {
        let mut window = limit.max(1);
        loop {
            let all = self.due(at, window).await?;
            // Fewer rows than asked for means the store has no more to show;
            // a full window may merely be the head of a longer order.
            let exhausted = all.len() < window;
            let mut batch = DueBatch::default();
            for registration in all {
                if namespace.owns_id(&registration.config.id) {
                    batch.rows.push(registration);
                } else {
                    batch.unserved = batch.unserved.saturating_add(1);
                }
            }
            if batch.rows.len() >= limit || exhausted {
                batch.rows.truncate(limit);
                return Ok(batch);
            }
            window = window.saturating_mul(2);
        }
    }

    /// Acknowledge every record before `next_seq`.
    async fn advance(&self, task: RunId, id: &str, next_seq: Seq) -> Result<(), StoreError>;

    /// Record a failed attempt without advancing the cursor.
    ///
    /// Clears [`park`](Self::park): an attempt was made, so the registration is
    /// live again whatever it was before.
    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError>;

    /// Stop delivering to this registration, and **keep its cursor**.
    ///
    /// What a worker does when a receiver has answered permanently, or has
    /// stayed silent past the retry ceiling. Deleting the row instead would be
    /// the one place this design loses an event: the cursor is the only record
    /// of how far a receiver got, and once it is gone the undelivered tail of
    /// that run is unrecoverable without a scan nobody schedules. A parked row
    /// is not returned by [`due`](Self::due) or [`due_in`](Self::due_in), so it
    /// costs no sweep; it is listed by [`parked`](Self::parked) and re-armed by
    /// [`unpark`](Self::unpark), which is the difference between a backlog an
    /// operator can act on and a warning line in yesterday's logs.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn park(&self, task: RunId, id: &str, error: &str) -> Result<(), StoreError>;

    /// Parked registrations, in the store's stable order.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn parked(&self, limit: usize) -> Result<Vec<PushRegistration>, StoreError>;

    /// Re-arm a parked registration: due at `at`, with its attempt count reset.
    ///
    /// The cursor is untouched, so delivery resumes at the first record the
    /// receiver never acknowledged rather than at the head of the run. Returns
    /// whether a parked registration was found — an operator re-arming one that
    /// is already live, or that never existed, must be told so rather than left
    /// waiting for a sweep that has nothing to do.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn unpark(&self, task: RunId, id: &str, at: u64) -> Result<bool, StoreError>;

    /// Forget one. Idempotent.
    ///
    /// # Errors
    ///
    /// If the store cannot be reached.
    async fn delete(&self, task: RunId, id: &str) -> Result<(), StoreError>;
}

/// Which webhook destinations this deployment permits.
///
/// Deny-by-default with no `allow_all`, for the reason
/// [`Egress`](crate::core::Egress) gives: a deployment that wants no control
/// should configure nothing, not configure something that looks like a control
/// and is not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushPolicy {
    hosts: std::collections::BTreeSet<String>,
}

impl PushPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit webhooks to this exact host.
    ///
    /// # Panics
    ///
    /// If the host is not one a URL could name. The grant is matched against
    /// `Url::host_str`, which the URL crate IDNA-encodes to punycode — so a
    /// grant only lowercased would store an internationalised host in a form
    /// no webhook URL ever presents, silently refusing every delivery to it.
    /// Canonicalised through the same helper governed media uses, so the two
    /// host-granting surfaces cannot drift the way they had.
    #[must_use]
    pub fn allow_host(mut self, host: impl AsRef<str>) -> Self {
        let raw = host.as_ref();
        let host = crate::netguard::canonical_host(raw).unwrap_or_else(|| {
            panic!(
                "push host grant '{raw}' is not a host a URL can name — give an \
                 internationalised host in the form the URL parser accepts, or it \
                 would silently never match a webhook"
            )
        });
        self.hosts.insert(host);
        self
    }

    /// Check a caller-supplied URL before anything is stored.
    ///
    /// Checked at **registration**, not only at delivery, so a caller learns
    /// immediately that its webhook will never be called — rather than waiting
    /// for a notification that silently never comes.
    ///
    /// # Errors
    ///
    /// [`PushError::NotHttps`], [`PushError::Malformed`], or
    /// [`PushError::HostNotGranted`].
    pub fn check(&self, url: &str) -> Result<(), PushError> {
        self.check_allowing_loopback(url, false)
    }

    /// The same check, with the two address-shape refusals optionally lifted.
    ///
    /// `allow_loopback` is reachable only through
    /// [`PushSender::allow_plaintext_loopback`], which exists only under
    /// `testkit`. The **host grant is not lifted** — that is the primary
    /// control and it still has to name the host.
    fn check_allowing_loopback(&self, url: &str, allow_loopback: bool) -> Result<(), PushError> {
        let parsed = reqwest::Url::parse(url).map_err(|e| PushError::Malformed(e.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| PushError::Malformed("no host".to_owned()))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if parsed.scheme() != "https"
            && !(allow_loopback && crate::netguard::is_loopback_name(&host))
        {
            return Err(PushError::NotHttps);
        }
        if !self.hosts.contains(&host) {
            return Err(PushError::HostNotGranted(host));
        }
        Ok(())
    }
}

/// Delivers notifications, under the controls in the module docs.
#[derive(Debug, Clone)]
pub struct PushSender {
    policy: PushPolicy,
    timeout: std::time::Duration,
    /// The one pooled client this sender delivers through, so a sweep reuses
    /// connections and TLS sessions instead of handshaking per message.
    ///
    /// Built on first use rather than in the constructor: the settings it needs
    /// — the timeout, and whether loopback is permitted — arrive through
    /// builder methods that run after it.
    http: std::sync::OnceLock<reqwest::Client>,
    /// Lift the HTTPS requirement and the public-address check for a webhook
    /// on this machine. `testkit` only, and absent from any other build.
    #[cfg(feature = "testkit")]
    plaintext_loopback: bool,
    /// Whether the destination is the **operator's own**, not a caller's.
    ///
    /// Set only by [`PushSender::for_operator_destinations`]. It lifts the three
    /// controls that exist because a caller names the URL — the host grant,
    /// HTTPS, and the public-address check — and nothing else. See
    /// [`outbox`](crate::push::Outbox) for why each does not apply, and note
    /// what stays: the cursor still advances only on 2xx, the retry ceiling
    /// still applies, and the request still carries no proxy, no cookie jar and
    /// no redirects.
    operator: bool,
    /// The body-signing key for each destination this sender serves, by
    /// registration id — empty for a caller-facing sender, because a caller's
    /// webhook has no key of this deployment's to sign with.
    ///
    /// Held here rather than in the stored [`PushConfig`] for the reasons
    /// [`Destination::config_for`] gives: the key is configuration this
    /// deployment reads at every start, not per-registration state, so it is
    /// never written to the push store and a rotation takes effect on the next
    /// sweep. Filled by [`for_operator_destinations`](Self::for_operator_destinations),
    /// which takes the destinations for that purpose.
    signing: std::collections::BTreeMap<String, BodySigning>,
}

/// One POST's worth of body: what to send, and what it is.
///
/// The media type travels with the message rather than being fixed by the
/// transport, because two projections share one delivery loop and speak
/// different wires — A2A's `application/a2a+json` and a `CloudEvents`
/// structured-mode `application/cloudevents+json`. A single hard-coded header
/// makes one of them a body no conformant receiver will route.
///
/// The `id` is the receiver's idempotency key. At-least-once delivery repeats
/// events on an ordinary crash, so a message a receiver cannot recognise twice
/// is one it must process twice; it must therefore be **stable across
/// retries** of the same message and distinct between messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushMessage {
    /// Stable identity for this message, sent as [`HEADER_ID`].
    ///
    /// Must be representable as an HTTP header value — a delivery whose id is
    /// not is refused as [`PushError::Malformed`], because a receiver that
    /// cannot be told which message this is has no defence against a duplicate.
    pub id: String,
    /// The media type of [`payload`](Self::payload), sent as `Content-Type`.
    pub content_type: String,
    /// The body, serialized canonically at the POST.
    pub payload: serde_json::Value,
}

impl PushMessage {
    /// A message whose body is plain JSON.
    #[must_use]
    pub fn json(id: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            id: id.into(),
            content_type: "application/json".to_owned(),
            payload,
        }
    }

    /// A message whose body is a `CloudEvents` structured-mode envelope.
    ///
    /// The media type and the idempotency id both come from the event, so the
    /// two facts a receiver needs — to route it, and to recognise it twice —
    /// cannot be set to something the body does not say.
    ///
    /// The id is the event's `id` attribute and not its
    /// [`origin_id`](crate::core::`CloudEvent`::origin_id). Uniqueness in
    /// `CloudEvents` is `(source, id)`, and the source half is fixed here by
    /// the destination: one endpoint is fed by one projection under one
    /// configured source, so `id` alone separates its messages. The pair is in
    /// the body regardless, for a receiver that fans several senders into one
    /// endpoint.
    #[must_use]
    pub fn cloudevent(event: &crate::core::CloudEvent) -> Self {
        Self {
            id: event.id().to_owned(),
            content_type: crate::core::CLOUDEVENT_CONTENT_TYPE.to_owned(),
            payload: event.to_value(),
        }
    }

    /// The same message under another media type.
    #[must_use]
    pub fn typed(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }
}

/// Delivery transport used by the durable worker.
#[async_trait]
pub trait PushTransport: Send + Sync + Debug {
    fn validate(&self, config: &PushConfig) -> Result<(), PushError>;

    /// POST one message.
    ///
    /// `at` is Unix seconds for *this attempt*, supplied by the worker rather
    /// than read here: it is signed alongside the body, and a transport reading
    /// its own clock would sign an instant no test can pin and no operator
    /// chose.
    async fn deliver(
        &self,
        config: &PushConfig,
        message: &PushMessage,
        at: u64,
    ) -> Result<Delivered, PushError>;
}

impl PushSender {
    /// The spec recommends 10–30 seconds; a webhook that needs longer is doing
    /// work it should not be doing on our thread.
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    #[must_use]
    pub fn new(policy: PushPolicy) -> Self {
        Self {
            policy,
            timeout: Self::DEFAULT_TIMEOUT,
            http: std::sync::OnceLock::new(),
            #[cfg(feature = "testkit")]
            plaintext_loopback: false,
            operator: false,
            // A caller's webhook is not signed: the secret would have to come
            // from the caller, and this crate does not accept one — an
            // unauthenticated party choosing the key a receiver verifies
            // against is not a control, it is a formality.
            signing: std::collections::BTreeMap::new(),
        }
    }

    /// A sender for destinations the **deployment** configured.
    ///
    /// Takes no [`PushPolicy`], because a host allowlist answers *may this
    /// caller name this host?* and there is no caller: the URL comes from the
    /// deployment's own configuration, written by whoever would have written the
    /// allowlist. HTTPS and the public-address check are lifted for the same
    /// reason — an in-cluster collector on plaintext HTTP at a private address
    /// is the ordinary shape here, and it is the *only* shape the inward-facing
    /// case has.
    ///
    /// This is not an off switch for push. It cannot deliver to a
    /// caller-registered webhook at all: [`Outbox`] owns the rows this serves,
    /// the A2A worker owns the others, and the two id namespaces do not overlap.
    ///
    /// # Why it takes the destinations
    ///
    /// For the signing keys of whichever of them called
    /// [`Destination::signed_with`], which live here and not in the stored
    /// registration: a caller's bearer token has to be persisted because the
    /// request that carried it is over, while an operator's signing key is this
    /// deployment's own configuration, read at every start — persisting it
    /// would put a forge-anything key in a row per run per destination and
    /// freeze rotation at admission. Taking
    /// them as an argument rather than offering a `.signing(..)` setter is the
    /// difference between a control you can forget and one you cannot: a
    /// destination configured to be signed whose sender was built without it
    /// would deliver unsigned, and nothing downstream could notice, because a
    /// receiver's own refusal is the only place a missing signature shows up.
    /// Pass [`Outbox::destinations`], which is the list that was actually
    /// registered.
    #[must_use]
    pub fn for_operator_destinations(destinations: &[Destination]) -> Self {
        Self {
            policy: PushPolicy::new(),
            timeout: Self::DEFAULT_TIMEOUT,
            http: std::sync::OnceLock::new(),
            #[cfg(feature = "testkit")]
            plaintext_loopback: false,
            operator: true,
            signing: destinations
                .iter()
                .filter_map(|destination| {
                    destination
                        .signing
                        .clone()
                        .map(|signing| (destination.registration_id(), signing))
                })
                .collect(),
        }
    }

    /// Permit `http://` to a webhook on this machine. **`testkit` only.**
    ///
    /// The A2A conformance kit's webhook receiver is an `http://localhost:PORT`
    /// server, because a kit cannot mint a public TLS endpoint for a run on a
    /// laptop. Both of this crate's address controls refuse that, correctly —
    /// and the consequence was that the kit's **ten push MUSTs could not run at
    /// all**, so the one surface where an untrusted party names an address this
    /// plane connects to had no outside-authority evidence behind it. Ten
    /// unrunnable rows is a worse answer than one named exception.
    ///
    /// What this does **not** lift is the part that is the actual control: the
    /// operator's **host grant** still has to name the host, the task-level
    /// authorization still runs, the cursor still advances only on 2xx, and
    /// every non-loopback destination is judged exactly as before — a plaintext
    /// URL to a public host stays refused with the flag set, which is the half
    /// that keeps this from being an off switch.
    ///
    /// It cannot exist in a production build: the field is `cfg(testkit)`, and
    /// `testkit` is documented as never belonging in one.
    #[cfg(feature = "testkit")]
    #[must_use]
    pub const fn allow_plaintext_loopback(mut self) -> Self {
        self.plaintext_loopback = true;
        self
    }

    /// Whether the loopback exception is in force. Always false without
    /// `testkit`, which is what lets the delivery path read one flag.
    ///
    /// Takes `&self` in every build even though the non-`testkit` body ignores
    /// it: the call site is one expression across both, and a signature that
    /// changed with a feature would move the `cfg` to every caller.
    #[allow(clippy::unused_self)]
    const fn loopback_allowed(&self) -> bool {
        #[cfg(feature = "testkit")]
        {
            self.plaintext_loopback
        }
        #[cfg(not(feature = "testkit"))]
        {
            false
        }
    }

    #[must_use]
    pub const fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout = d;
        self
    }

    /// The grant this sender enforces, so a registration can be checked against
    /// the same policy that will later be checked at delivery.
    #[must_use]
    pub const fn policy(&self) -> &PushPolicy {
        &self.policy
    }

    /// How far this sender's destinations are allowed to be.
    ///
    /// One answer, read by both the pre-flight and the client's resolver, so
    /// the check that reports and the check that enforces cannot disagree.
    fn reach(&self) -> crate::netguard::Reach {
        if self.operator {
            // The destination is the deployment's own, and resolving inward is
            // the point of it — an internal bus has no public address.
            // Refusing that would leave an operator with a sidecar that
            // terminates TLS and forwards in clear, which is the same exposure
            // with an extra hop.
            crate::netguard::Reach::Any
        } else if self.loopback_allowed() {
            crate::netguard::Reach::PublicOrLoopbackName
        } else {
            crate::netguard::Reach::Public
        }
    }

    /// The pooled client, built once. A failure is not cached, so one bad start
    /// does not leave a sender that can never deliver.
    fn http(&self) -> Result<&reqwest::Client, PushError> {
        if let Some(client) = self.http.get() {
            return Ok(client);
        }
        let client = crate::netguard::guarded_client(self.reach())
            .timeout(self.timeout)
            .build()
            .map_err(|e| PushError::Unroutable(e.to_string()))?;
        Ok(self.http.get_or_init(|| client))
    }

    /// POST one `StreamResponse` to a registered webhook.
    ///
    /// The grant is re-checked here and not only at registration. A registration
    /// outlives the configuration that permitted it: a host removed from the
    /// allowlist must stop receiving notifications for tasks registered while it
    /// was still granted, and a check performed only at write time cannot do
    /// that.
    ///
    /// Private on purpose: [`PushTransport::deliver`] is the one entry point.
    /// A second, public spelling of the same delivery was a door past the
    /// trait — callable without anything guaranteeing the validation the trait
    /// documents, and one rename away from the two drifting apart.
    ///
    /// # Errors
    ///
    /// [`PushError`] when the URL is not permitted or does not resolve to a
    /// public address. Transport failures are **not** errors here — see the
    /// return type.
    async fn deliver_validated(
        &self,
        config: &PushConfig,
        message: &PushMessage,
        at: u64,
    ) -> Result<Delivered, PushError> {
        <Self as PushTransport>::validate(self, config)?;

        let url =
            reqwest::Url::parse(&config.url).map_err(|e| PushError::Malformed(e.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| PushError::Malformed("no host".to_owned()))?
            .to_owned();
        let port = url.port_or_known_default().unwrap_or(443);

        // `Url::host_str` keeps the brackets on an IPv6 literal and the
        // resolver refuses them — so without stripping, every v6 literal fell
        // through to a DNS lookup that cannot succeed, and one whole address
        // family was dead and misreported as retryable. Only the resolution
        // uses the bare form; the granted-host comparison and the netguard
        // messages keep the spelling the URL carries.
        let lookup = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(&host)
            .to_owned();
        // Judged before anything is sent, so a destination this plane may not
        // reach is refused rather than attempted — and refused with a *typed*
        // answer, which is what the client's own resolver cannot give: a
        // forbidden address and a receiver that is down carry different retry
        // consequences, and a connect error is all reqwest can report. The
        // socket obeys the same rule again, in `netguard::guarded_client`.
        let resolved = tokio::net::lookup_host((lookup.as_str(), port))
            .await
            .map_err(|e| PushError::Unroutable(format!("DNS for '{host}': {e}")))?;
        crate::netguard::judge(self.reach(), &host, resolved)
            .map_err(|e| PushError::Unroutable(e.to_string()))?;

        let client = self.http()?;

        // Serialized here rather than left to `RequestBuilder::json`, because
        // the signature below has to cover the bytes that are actually sent: a
        // signature over a *re-serialization* covers a body nobody posted, and
        // the two stop agreeing the moment anything about the encoding differs.
        //
        // Through the canonical writer, not `serde_json` directly, for the
        // reason `core::canon` gives — with `preserve_order` on, which cargo
        // turns on for this crate from inside `cedar-policy`, plain
        // serialization emits whatever order the projection happened to build
        // the object in. That is legal JSON and a fine body, and it is a poor
        // thing to sign: a receiver that verifies by re-serializing what it
        // parsed — which is the ordinary receiver bug — has no stable form to
        // reproduce, and neither does this plane if it is ever asked to prove
        // what it sent. Sorted keys cost nothing here and make the bytes a
        // function of the payload rather than of its construction.
        let body = crate::core::canon::value_bytes(&message.payload);

        let content_type = reqwest::header::HeaderValue::from_str(&message.content_type)
            .map_err(|error| PushError::Malformed(format!("invalid content type: {error}")))?;
        let id = reqwest::header::HeaderValue::from_str(&message.id)
            .map_err(|error| PushError::Malformed(format!("invalid message id: {error}")))?;
        let mut request = client
            .post(url)
            // What the body is, so a receiver can route on it. The projection
            // decides it, because two of them share this loop and speak
            // different wires.
            .header(reqwest::header::CONTENT_TYPE, content_type)
            // The two facts a receiver needs to survive at-least-once delivery:
            // which message this is, and when this attempt was made. Sent to
            // every destination, signed or not — a duplicate is ordinary here,
            // and a receiver with nothing to deduplicate on processes it twice.
            .header(HEADER_ID, id)
            .header(HEADER_TIMESTAMP, at);
        // The destination's own key, if the deployment configured one. What a
        // receiver may conclude from it, and what it must still do itself, is
        // set out on `BodySigning`.
        if let Some(signing) = self.signing.get(&config.id) {
            request = request.header(HEADER_SIGNATURE, signing.value_for(&message.id, at, &body));
        }
        let mut request = request.body(body);
        if let Some(authentication) = &config.authentication {
            let value = format!(
                "{} {}",
                authentication.scheme,
                authentication.credentials.expose()
            );
            let value = reqwest::header::HeaderValue::from_str(&value).map_err(|error| {
                PushError::Malformed(format!("invalid authentication: {error}"))
            })?;
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }

        // A transport failure is an *outcome*, not an error of this function. A
        // webhook that is down is ordinary, and the caller decides whether to
        // retry or to give up on a configuration — a distinction lost if this
        // returned `Err` for both "you may not" and "it did not answer".
        Ok(match request.send().await {
            Ok(response) if response.status().is_success() => Delivered::Accepted,
            Ok(response) => Delivered::Rejected {
                status: response.status().as_u16(),
                retry_after: retry_after_seconds(response.headers()),
            },
            Err(e) => Delivered::Unreachable(e.to_string()),
        })
    }
}

#[async_trait]
impl PushTransport for PushSender {
    fn validate(&self, config: &PushConfig) -> Result<(), PushError> {
        // The URL checks are about a **caller-supplied** address. An operator
        // destination still has its authentication header validated, because a
        // malformed one is a malformed one whoever wrote it — and it would fail
        // at `HeaderValue::from_str` mid-delivery instead of at configuration.
        if self.operator {
            reqwest::Url::parse(&config.url).map_err(|e| PushError::Malformed(e.to_string()))?;
        } else {
            self.policy
                .check_allowing_loopback(&config.url, self.loopback_allowed())?;
        }
        if let Some(authentication) = &config.authentication {
            authentication.validate()?;
        }
        Ok(())
    }

    async fn deliver(
        &self,
        config: &PushConfig,
        message: &PushMessage,
        at: u64,
    ) -> Result<Delivered, PushError> {
        self.deliver_validated(config, message, at).await
    }
}

/// `Retry-After` in seconds, when the receiver named one this plane can act on.
///
/// The rule is [`core::retry_after_seconds`](crate::core::retry_after_seconds),
/// shared with the model drivers so no wire in this crate acts on advice
/// another wire would refuse. A missing header is the ordinary case and means
/// nothing more than "no advice" — the worker's own backoff applies.
fn retry_after_seconds(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    crate::core::retry_after_seconds(headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?)
}

/// What happened to one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// The receiver answered 2xx, which is the acknowledgement the spec asks for.
    Accepted,
    /// It answered something else.
    Rejected {
        status: u16,
        /// What the receiver asked to be waited, in seconds, if it said.
        ///
        /// A 429 or a 503 with `Retry-After` is a receiver naming its own
        /// recovery, and a sender that overrides it with a schedule of its own
        /// is choosing to be told twice. Honoured in preference to the
        /// worker's backoff, and bounded there rather than here.
        retry_after: Option<u64>,
    },
    /// It did not answer.
    Unreachable(String),
}

impl Delivered {
    /// Whether this answer will still be this answer after a wait.
    ///
    /// **410 Gone** is the one status that means it: the receiver is stating
    /// that the resource is permanently absent, which is precisely a webhook
    /// endpoint that has been retired. Every other rejection is treated as
    /// transient, including 4xx — a 404 during a deploy, a 401 while a
    /// credential rotates and a 400 from a receiver mid-upgrade are all
    /// answers that change, and abandoning a run's events on the first of them
    /// would lose more than a wasted retry costs.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        matches!(self, Self::Rejected { status: 410, .. })
    }

    /// The receiver's own advice about when to come back.
    #[must_use]
    pub const fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Rejected { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}
