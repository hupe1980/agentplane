//! A2A over the wire.
//!
//! The peer *seam* — audience-bound credentials, attenuating delegation, the
//! disposition vocabulary — lives in the parent module and is always available.
//! This is only the JSON-RPC client that carries it, behind the `a2a` feature.
//!
//! # What is actually hard here
//!
//! Not the JSON-RPC. It is deciding, for every way a call can fail, **whether
//! the peer acted** — because that answer, and nothing else, decides whether the
//! runtime may send the request again. A2A tasks are long-running and stateful:
//! a peer that accepted a task and then dropped the connection has work in
//! flight, and re-sending is a second transfer, a second refund, a second
//! anything.
//!
//! So the mapping below is written as a table of *what is known*, not of what
//! the error looked like:
//!
//! | Failure | Known | Disposition |
//! |---|---|---|
//! | DNS, TLS, connect refused | nothing was written | `DidNotHappen` |
//! | request timed out, or the connection died after the write | it may have arrived | `InDoubt` |
//! | HTTP 401/403/404, JSON-RPC parse/method/params errors | the peer read it and declined | `DidNotHappen` |
//! | HTTP 5xx, JSON-RPC internal/invalid-agent-response error | it arrived; whether it acted is unknown | `InDoubt` |
//! | a `Task` came back failed, canceled, or rejected | it created a task and may have acted | `Landed` |
//!
//! The two rows that are easy to get wrong are the last two, and they are the
//! expensive ones. `-32603 Internal error` after a task has been created is not
//! a refusal — the peer may have done half the work — and treating it as one is
//! how a partial transfer gets sent twice. Symmetrically, a task that comes back
//! `failed` is *not* in doubt: the peer has told us it acted and the action did
//! not succeed, so `Recovery` has nothing left to resolve.
//!
//! # The endpoint is reachability, never authority
//!
//! This client takes a configured endpoint. One can also be built from a peer's
//! card — see [`CardClient`](super::CardClient) — which fetches it under an
//! egress allowlist, optionally verifies its signature, and selects an interface
//! by binding and version.
//!
//! Either way the card supplies only *where to connect*. What a peer may be sent
//! comes from [`PeerRegistry`](super::PeerRegistry), which an operator writes: a
//! party describing its own capabilities is not a source of truth about its
//! authority. That split is why a forged card is survivable — the worst it can
//! do is send a request somewhere useless.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::core::{Delegation, Digest, canon};

use super::{PeerClient, PeerCredential, PeerError, PeerId};

/// Where a peer lives, and how long to wait for it.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The JSON-RPC endpoint. Taken from configuration, not from a card the
    /// peer serves about itself.
    pub url: String,
    /// How long to wait before the outcome becomes unknown.
    ///
    /// Not "how long before we retry" — a timeout here produces `InDoubt`, and
    /// what happens next is the effect's declared [`Recovery`](crate::core::Recovery).
    pub timeout: Duration,
    /// A2A's opaque routing identifier, echoed on every request.
    ///
    /// The spec's rule is exact: set it to the value declared on the interface
    /// selected from the peer's card, and omit it when that interface omits it.
    /// It is not this plane's own tenant — it names *whose agent* at the far end
    /// is being addressed, and the two are unrelated.
    ///
    /// Without it a client can only ever reach a peer serving the default
    /// tenant: anything else refuses the request as meant for somebody else.
    pub tenant: Option<String>,
}

impl Endpoint {
    /// Two minutes, which is long for a request and short for an A2A task.
    ///
    /// Long-running work is meant to come back as a task id the run waits on,
    /// not as a held connection — so a timeout here means something is wrong,
    /// rather than that the peer is thinking.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(2);

    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            timeout: Self::DEFAULT_TIMEOUT,
            tenant: None,
        }
    }

    /// Address a named tenant at the far end.
    #[must_use]
    pub fn for_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    #[must_use]
    pub const fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
}

/// The A2A extension URI under which this runtime carries its own metadata.
///
/// Declared rather than smuggled into free-form fields: A2A's extension
/// mechanism exists so a peer can say what it understood, and a peer that does
/// not understand this one still gets a well-formed message.
///
/// Under a domain the project controls: a peer may fetch this URI, so an
/// unregistered domain is both a collision risk and a broken link.
pub const EXTENSION_URI: &str = "https://hupe1980.github.io/agentplane/a2a/delegation/v1";

/// The protocol version this client speaks.
///
/// Re-exported rather than redefined: the card publishes this same value and the
/// server refuses anything else, so a second definition here would be a second
/// place to forget when the version moves.
pub use super::PROTOCOL_VERSION;

/// Talks A2A to peers.
#[derive(Debug)]
pub struct A2aClient {
    /// Where this client may connect, if the deployment says.
    egress: Option<crate::core::Egress>,
    endpoint: Endpoint,
    /// Lift the public-address check for a peer on this machine. `testkit`
    /// only, and absent from any other build.
    #[cfg(feature = "testkit")]
    loopback: bool,
}

impl A2aClient {
    /// Permit a peer served from this machine.
    ///
    /// Behind `testkit` and therefore **absent from a production build**: an
    /// exception that can only be compiled into a test binary cannot be left on
    /// by accident in a deployment. It applies to a host that *is* a loopback
    /// literal or `localhost`, never to one that merely resolved to one.
    #[cfg(feature = "testkit")]
    #[must_use]
    pub const fn allow_loopback(mut self) -> Self {
        self.loopback = true;
        self
    }

    /// Restrict where this client may connect.
    ///
    /// Deny-by-default once set: an endpoint whose host is not granted is
    /// refused before the request is built, and reported as
    /// [`PeerError::Refused`] — `DidNotHappen`, because it truly did not.
    #[must_use]
    pub fn egress(mut self, egress: crate::core::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(endpoint: Endpoint) -> Result<Self, PeerError> {
        Ok(Self {
            egress: None,
            endpoint,
            #[cfg(feature = "testkit")]
            loopback: false,
        })
    }

    /// Build the A2A 1.0 JSON-RPC body for `SendMessage`.
    ///
    /// The delegation chain rides in the message metadata under
    /// [`EXTENSION_URI`]. It is a *claim* today, not an attestation: a peer that
    /// authorizes on it is trusting whatever the last hop wrote. Signing it is
    /// designed and not built.
    fn body(
        capability: &str,
        payload: &Value,
        acting_as: &Delegation,
        provenance: Option<&crate::core::Provenance>,
        tenant: Option<&str>,
    ) -> Value {
        // Under the same declared extension the delegation chain travels in, so
        // a peer that does not implement the extension ignores both together
        // rather than half-understanding the message.
        let attested = provenance.map(|p| Value::Object(p.to_meta()));
        // A2A uses `messageId` as its duplicate-detection key, so it must be
        // stable across retries of one logical call. A runtime call carries a
        // dispatch id that is exactly that; direct transport users have no
        // provenance, so their deterministic fallback hashes the request and
        // arrives at the same property.
        let message_id = provenance.map_or_else(
            || {
                let claim = json!({
                    "capability": capability,
                    "payload": payload,
                    "chain": acting_as,
                });
                format!("msg-{}", Digest::of(&canon::value_bytes(&claim)))
            },
            // The *dispatch*, not the effect key. The effect key hashes the
            // attempt number — it must, so a retry does not collide with the
            // recorded failure before it — which makes it the wrong answer to
            // "have I already done this work?". A peer given a fresh id per
            // attempt sees unrelated messages and may act twice, defeating the
            // very deduplication this field exists for.
            |p| p.dedupe_key().to_string(),
        );
        let mut governance = serde_json::Map::new();
        governance.insert("capability".into(), json!(capability));
        governance.insert("chain".into(), json!(acting_as));
        // Inserted only when there is one. `json!` renders `None` as `null`,
        // and an absent ProtoJSON field is **omitted**, not null-valued.
        if let Some(attested) = attested {
            governance.insert("provenance".into(), json!(attested));
        }

        let mut params = serde_json::Map::new();
        insert_tenant(&mut params, tenant);
        params.insert(
            "message".into(),
            json!({
                "role": "ROLE_USER",
                "messageId": message_id,
                "parts": [{ "data": payload, "mediaType": "application/json" }],
                "extensions": [EXTENSION_URI],
                "metadata": { EXTENSION_URI: Value::Object(governance) }
            }),
        );

        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": Value::Object(params),
        })
    }

    fn get_task_body(task_id: &str, tenant: Option<&str>) -> Value {
        let mut params = serde_json::Map::new();
        insert_tenant(&mut params, tenant);
        params.insert("id".into(), json!(task_id));
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "GetTask",
            "params": Value::Object(params),
        })
    }

    /// A client that will connect only to addresses this call approved.
    async fn pinned_client(
        &self,
        peer: &PeerId,
        host: &str,
        parsed: &reqwest::Url,
    ) -> Result<reqwest::Client, PeerError> {
        // `Url::host_str` keeps the brackets on an IPv6 literal and the
        // resolver refuses them. Only the lookup uses the bare form.
        let lookup = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let resolved = tokio::net::lookup_host((lookup.as_str(), port))
            .await
            .map_err(|error| PeerError::Unreachable {
                peer: peer.clone(),
                detail: format!("DNS for '{host}': {error}"),
            })?;
        let addrs = if self.loopback_allowed() && crate::netguard::is_loopback_name(host) {
            // Named rather than inferred: the exception covers a host that *is*
            // loopback, not one that resolved there.
            resolved.collect::<Vec<_>>()
        } else {
            crate::netguard::all_public(host, resolved).map_err(|error| PeerError::Refused {
                peer: peer.clone(),
                detail: error.to_string(),
            })?
        };
        let mut client = reqwest::Client::builder()
            .timeout(self.endpoint.timeout)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        for addr in &addrs {
            client = client.resolve(host, *addr);
        }
        client.build().map_err(|error| PeerError::Unreachable {
            peer: peer.clone(),
            detail: error.to_string(),
        })
    }

    /// Whether the loopback exception is in force. Always false without
    /// `testkit`, which is what lets the call path read one flag.
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

    async fn rpc(
        &self,
        peer: &PeerId,
        body: &Value,
        credential: Option<&PeerCredential>,
    ) -> Result<Value, PeerError> {
        // Before the request is built: a refused destination must reach
        // nothing and must be `DidNotHappen`.
        let parsed =
            reqwest::Url::parse(&self.endpoint.url).map_err(|error| PeerError::Refused {
                peer: peer.clone(),
                detail: format!("the peer endpoint is not a URL: {error}"),
            })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| PeerError::Refused {
                peer: peer.clone(),
                detail: "the peer endpoint names no host".to_owned(),
            })?
            .to_owned();
        if let Some(egress) = &self.egress
            && let Err(error) = egress.permits(Some(host.as_str()))
        {
            return Err(PeerError::Refused {
                peer: peer.clone(),
                detail: error.to_string(),
            });
        }

        // An endpoint is not always the operator's own string. `PeerRegistry`
        // holds ones an operator wrote, but `AgentCard::endpoint` takes the URL
        // straight out of a **discovered card** — a document another party
        // publishes about itself. A forged card cannot widen a grant, which is
        // the property that makes discovery survivable; what it can still do is
        // name an address, and this request carries the run's payload and a
        // bearer credential to whatever it names.
        //
        // So the same rule as every other dereference here: every resolved
        // address checked, the connection pinned to exactly those, and no
        // redirects — a check on the endpoint says nothing about the third host
        // it forwards to. Resolved per call rather than at construction because
        // DNS changes, and a client that pinned once would keep answering with
        // whatever was true when it was built.
        let client = self.pinned_client(peer, &host, &parsed).await?;

        let mut request = client
            .post(&self.endpoint.url)
            .header("A2A-Version", PROTOCOL_VERSION)
            .header("A2A-Extensions", EXTENSION_URI)
            .json(body);
        if let Some(credential) = credential {
            request = request.bearer_auth(credential.expose());
        }

        let response = request
            .send()
            .await
            .map_err(|error| classify_transport(peer, &error))?;
        let status = response.status();
        let parsed: Result<RpcResponse, _> = response.json().await;
        let Ok(rpc) = parsed else {
            return Err(classify_status(peer, status));
        };
        if !status.is_success() && rpc.jsonrpc.is_none() {
            return Err(classify_status(peer, status));
        }
        if rpc.jsonrpc.as_deref() != Some("2.0") || rpc.id.as_ref() != Some(&json!(1)) {
            return Err(invalid_response(
                peer,
                "JSON-RPC response has the wrong version or does not correlate to request id 1",
            ));
        }
        let result = match (rpc.result, rpc.error) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(invalid_response(
                    peer,
                    "JSON-RPC response must contain exactly one of 'result' or 'error'",
                ));
            }
            (None, Some(error)) => return Err(classify_rpc(peer, &error)),
            (Some(result), None) => result,
        };
        if !status.is_success() {
            return Err(classify_status(peer, status));
        }
        Ok(result)
    }
}

/// A JSON-RPC error as it comes back.
#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<Value>,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

/// What a JSON-RPC error code says about whether the peer acted.
///
/// Split by *what is known*, which is why `-32603` sits with the in-doubt cases
/// and not with the other negatives: an internal error can be raised after the
/// peer has already started work.
fn classify_rpc(peer: &PeerId, e: &RpcError) -> PeerError {
    let detail = format!("{} (code {})", e.message, e.code);
    match e.code {
        // JSON-RPC validation failures and A2A failed-precondition/input errors
        // say the peer declined before this operation could act. `-32006` is
        // deliberately absent: A2A 1.0 maps InvalidAgentResponseError to
        // INTERNAL/HTTP 500, so it cannot prove that no work happened.
        -32700 | -32600 | -32601 | -32602 | -32005..=-32001 | -32009..=-32007 => {
            PeerError::Refused {
                peer: peer.clone(),
                detail,
            }
        }
        -32006 => PeerError::InvalidResponse {
            peer: peer.clone(),
            detail: format!("{detail} — the peer did not say whether it acted"),
        },
        // This runtime's own server-defined back-pressure code: the quota was
        // checked before admission, so nothing was performed and the honest
        // reading is a refusal that will pass — retry later, do not abandon.
        // A foreign server reusing -32029 for something else loses nothing:
        // the request was refused either way, and refusal is the conservative
        // class for a pre-admission answer.
        -32029 => PeerError::Refused {
            peer: peer.clone(),
            detail: format!("{detail} — the peer is at a ceiling; come back"),
        },
        // `-32603 Internal error` and anything unrecognised. The request
        // arrived; whether the peer acted is exactly what it is not saying.
        // Calling this a refusal is how a half-finished transfer is sent again
        // — and calling it a timeout is a false diagnosis of a peer that
        // answered promptly, with a fault.
        _ => PeerError::InDoubt {
            peer: peer.clone(),
            detail: format!(
                "{detail} — the peer answered with a fault and did not say whether it acted"
            ),
        },
    }
}

fn invalid_response(peer: &PeerId, detail: impl Into<String>) -> PeerError {
    PeerError::InvalidResponse {
        peer: peer.clone(),
        detail: detail.into(),
    }
}

/// Validate the A2A 1.0 `SendMessageResponse` oneof and return its member.
fn send_message_result(peer: &PeerId, result: &Value) -> Result<Value, PeerError> {
    let Some(object) = result.as_object() else {
        return Err(invalid_response(
            peer,
            "SendMessage result is not an object containing exactly one of 'task' or 'message'",
        ));
    };
    match (object.get("task"), object.get("message")) {
        (Some(task), None) if task.is_object() => Ok(task.clone()),
        (None, Some(message)) if message.is_object() => Ok(message.clone()),
        _ => Err(invalid_response(
            peer,
            "SendMessage result must contain exactly one object member named 'task' or 'message'",
        )),
    }
}

/// What an HTTP status says, when there is no JSON-RPC envelope to read.
fn classify_status(peer: &PeerId, status: reqwest::StatusCode) -> PeerError {
    if status.is_server_error() {
        // It reached them. A 500 from a gateway and a 500 from the agent are
        // indistinguishable here, and one of them may have acted. Not a
        // timeout: the peer answered, and answered with a fault.
        return PeerError::InDoubt {
            peer: peer.clone(),
            detail: format!(
                "the peer answered HTTP {status} — a fault, not a decline, and it did not \
                 say whether it acted"
            ),
        };
    }
    PeerError::Refused {
        peer: peer.clone(),
        detail: format!("HTTP {status}"),
    }
}

/// What a transport error says.
///
/// The distinction that matters: a connection that was never established sent
/// nothing, and one that died after the request was written may have delivered
/// it. `reqwest` tells us which.
fn classify_transport(peer: &PeerId, e: &reqwest::Error) -> PeerError {
    if e.is_connect() {
        return PeerError::Unreachable {
            peer: peer.clone(),
            detail: format!("could not connect: {e}"),
        };
    }
    if e.is_timeout() {
        return PeerError::TimedOut {
            peer: peer.clone(),
            detail: format!("timed out: {e}"),
        };
    }
    if e.is_body() || e.is_decode() {
        // The request went out and something came back that could not be read.
        // The peer very likely acted — and it certainly answered, so calling
        // this a timeout would misdirect whoever debugs it.
        return PeerError::InDoubt {
            peer: peer.clone(),
            detail: format!("the peer answered, and the response could not be read: {e}"),
        };
    }
    if e.is_request() {
        // A request that failed while being built or written. A partial write
        // is indistinguishable from none, so this is not `Unreachable`.
        return PeerError::InDoubt {
            peer: peer.clone(),
            detail: format!("the request failed in flight: {e}"),
        };
    }
    PeerError::InDoubt {
        peer: peer.clone(),
        detail: e.to_string(),
    }
}

/// A task's terminal state, if it reached one.
///
/// A2A tasks are stateful; `SendMessage` may answer with a task rather than a
/// result. A task in `failed` state is the peer telling us it acted and the work
/// did not succeed — which is `Landed`, not in doubt, and therefore not
/// something `Recovery` should try to resolve.
fn task_failure(peer: &PeerId, result: &Value) -> Option<PeerError> {
    let state = result.get("status")?.get("state")?.as_str()?;
    match state {
        "TASK_STATE_FAILED" | "TASK_STATE_CANCELED" | "TASK_STATE_REJECTED" => {
            Some(PeerError::Failed {
                peer: peer.clone(),
                detail: result
                    .get("status")
                    .and_then(|s| s.get("message"))
                    .map_or_else(
                        || format!("the peer returned task state {state}"),
                        std::string::ToString::to_string,
                    ),
            })
        }
        // Submitted, working, input/auth-required, and completed:
        // either finished or legitimately in progress. A run that needs to wait
        // for working to finish does so through `cx.await_event`, not by
        // holding this connection.
        _ => None,
    }
}

#[async_trait]
impl PeerClient for A2aClient {
    async fn send(
        &self,
        peer: &PeerId,
        capability: &str,
        payload: &Value,
        acting_as: &Delegation,
        credential: Option<&PeerCredential>,
        provenance: Option<&crate::core::Provenance>,
    ) -> Result<Value, PeerError> {
        let result = self
            .rpc(
                peer,
                &Self::body(
                    capability,
                    payload,
                    acting_as,
                    provenance,
                    self.endpoint.tenant.as_deref(),
                ),
                credential,
            )
            .await?;
        let result = send_message_result(peer, &result)?;
        if let Some(failure) = task_failure(peer, &result) {
            return Err(failure);
        }
        Ok(result)
    }

    async fn get_task(
        &self,
        peer: &PeerId,
        task_id: &str,
        credential: Option<&PeerCredential>,
    ) -> Result<Value, PeerError> {
        let result = self
            .rpc(
                peer,
                &Self::get_task_body(task_id, self.endpoint.tenant.as_deref()),
                credential,
            )
            .await?;
        if !result.is_object()
            || result.get("id").and_then(Value::as_str) != Some(task_id)
            || result
                .get("status")
                .and_then(|status| status.get("state"))
                .and_then(Value::as_str)
                .is_none()
        {
            return Err(invalid_response(
                peer,
                "GetTask result is not the requested Task object",
            ));
        }
        Ok(result)
    }
}

/// Add `tenant` only when the interface declares one.
///
/// One implementation, because it was written twice as `"tenant": tenant` in a
/// `json!` — where `None` renders as **`null`**, not as an absent field. A
/// comment above one of them said "omitted entirely when the interface declares
/// none", which is what the code was meant to do and not what it did.
///
/// `ProtoJSON` omits a field at its default value, and the reference server parses
/// accordingly: a `null` where a string belongs is a type error, not an absence.
/// This crate's *own* server accepted it — `serde` reads `null` into an
/// `Option` as `None` — so every in-repo test agreed with the bug. Only a server
/// nobody here wrote could find it, which is the whole argument for rung 8.
fn insert_tenant(params: &mut serde_json::Map<String, Value>, tenant: Option<&str>) {
    if let Some(tenant) = tenant {
        params.insert("tenant".into(), json!(tenant));
    }
}
