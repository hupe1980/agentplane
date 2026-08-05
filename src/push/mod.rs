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
    #[must_use]
    pub fn allow_host(mut self, host: impl AsRef<str>) -> Self {
        self.hosts.insert(
            host.as_ref()
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
        );
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
        let parsed = reqwest::Url::parse(url).map_err(|e| PushError::Malformed(e.to_string()))?;
        if parsed.scheme() != "https" {
            return Err(PushError::NotHttps);
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| PushError::Malformed("no host".to_owned()))?
            .trim_end_matches('.')
            .to_ascii_lowercase();
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
    /// # Errors
    ///
    /// [`PushError`] when the URL is not permitted or does not resolve to a
    /// public address. Transport failures are **not** errors here — see the
    /// return type.
    pub async fn deliver(
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

        // Resolved once, every answer checked, and the connection pinned to
        // exactly those addresses. Without the pin the client resolves again and
        // may be handed a different answer than the one that passed — which is
        // the rebinding attack this check would otherwise only appear to stop.
        let resolved = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| PushError::Unroutable(format!("DNS for '{host}': {e}")))?;
        let addrs = crate::netguard::all_public(&host, resolved).map_err(PushError::Unroutable)?;

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
        self.policy.check(&config.url)?;
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
        PushSender::deliver(self, config, payload).await
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
