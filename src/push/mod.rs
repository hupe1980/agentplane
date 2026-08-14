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
//! * **Public addresses only.** Every DNS answer is checked with
//!   [`netguard`](crate::netguard) and the connection is pinned to those
//!   addresses, so a name that resolves inward — or answers differently the
//!   second time — reaches nothing.
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
//! # The journal is the outbox
//!
//! A registration stores the first journal sequence it has not acknowledged.
//! Workers derive `StreamResponse` payloads from those records and advance only
//! after HTTP 2xx. A crash after POST but before cursor persistence duplicates
//! an event instead of losing it, which is A2A's at-least-once contract.

mod delivery;
mod outbox;

pub use delivery::{DeliveryWorker, Projection, PushSweepReport};
pub use outbox::{Destination, OPERATOR_PREFIX, Outbox, RunCompleted, is_operator_id};

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
    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError>;

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
        if parsed.scheme() != "https" && !(allow_loopback && is_loopback_name(&host)) {
            return Err(PushError::NotHttps);
        }
        if !self.hosts.contains(&host) {
            return Err(PushError::HostNotGranted(host));
        }
        Ok(())
    }
}

/// Whether a host names this machine, without resolving it.
///
/// Literals only, plus the one name every stack special-cases. Anything that
/// merely *resolves* to loopback is deliberately not covered here — that is
/// [`netguard`](crate::netguard)'s job at delivery, against the answers DNS
/// actually gave, and a name-based guess in front of it would be a second
/// implementation of one rule.
fn is_loopback_name(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Delivers notifications, under the controls in the module docs.
#[derive(Debug, Clone)]
pub struct PushSender {
    policy: PushPolicy,
    timeout: std::time::Duration,
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
}

/// Delivery transport used by the durable worker.
#[async_trait]
pub trait PushTransport: Send + Sync + Debug {
    fn validate(&self, config: &PushConfig) -> Result<(), PushError>;

    async fn deliver(
        &self,
        config: &PushConfig,
        payload: &serde_json::Value,
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
            #[cfg(feature = "testkit")]
            plaintext_loopback: false,
            operator: false,
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
    #[must_use]
    pub fn for_operator_destinations() -> Self {
        Self {
            policy: PushPolicy::new(),
            timeout: Self::DEFAULT_TIMEOUT,
            #[cfg(feature = "testkit")]
            plaintext_loopback: false,
            operator: true,
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
        payload: &serde_json::Value,
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
        // Resolved once, every answer checked, and the connection pinned to
        // exactly those addresses. Without the pin the client resolves again and
        // may be handed a different answer than the one that passed — which is
        // the rebinding attack this check would otherwise only appear to stop.
        let resolved = tokio::net::lookup_host((lookup.as_str(), port))
            .await
            .map_err(|e| PushError::Unroutable(format!("DNS for '{host}': {e}")))?;
        let addrs = if self.operator {
            // The destination is the deployment's own, and resolving inward is
            // the point of it — an internal bus has no public address. Refusing
            // that would leave an operator with a sidecar that terminates TLS
            // and forwards in clear, which is the same exposure with a hop.
            let addrs: Vec<_> = resolved.collect();
            if addrs.is_empty() {
                return Err(PushError::Unroutable(format!(
                    "DNS for '{host}' returned no addresses"
                )));
            }
            addrs
        } else if self.loopback_allowed() && is_loopback_name(&host) {
            // Named rather than inferred: the exception applies to a host that
            // *is* a loopback literal or `localhost`, not to one that merely
            // resolved to one. A name that resolves inward is the rebinding
            // attack, and it stays refused with the flag set.
            let addrs: Vec<_> = resolved.collect();
            if addrs.is_empty() {
                return Err(PushError::Unroutable(format!(
                    "DNS for '{host}' returned no addresses"
                )));
            }
            addrs
        } else {
            crate::netguard::all_public(&host, resolved)
                .map_err(|e| PushError::Unroutable(e.to_string()))?
        };

        let mut client = reqwest::Client::builder()
            .timeout(self.timeout)
            // No ambient authority: a webhook is somebody else's endpoint, and a
            // proxy, a cookie jar or a stored credential would attach this
            // plane's identity to a request it did not authorize.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        for addr in &addrs {
            client = client.resolve(&host, *addr);
        }
        let client = client
            .build()
            .map_err(|e| PushError::Unroutable(e.to_string()))?;

        let mut request = client
            .post(url)
            // The spec's media type, so a receiver can route on it.
            .header("Content-Type", "application/a2a+json")
            .json(payload);
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
            Ok(response) => Delivered::Rejected(response.status().as_u16()),
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
        payload: &serde_json::Value,
    ) -> Result<Delivered, PushError> {
        self.deliver_validated(config, payload).await
    }
}

/// What happened to one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivered {
    /// The receiver answered 2xx, which is the acknowledgement the spec asks for.
    Accepted,
    /// It answered something else. Its problem, recorded rather than retried
    /// forever.
    Rejected(u16),
    /// It did not answer.
    Unreachable(String),
}
