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
//! # The endpoint is operator-pinned
//!
//! This client intentionally takes a configured JSON-RPC endpoint. Agent Card
//! discovery, signature verification, and interface negotiation are separate
//! capabilities and are not implemented here. A document served by the peer
//! must never widen the grant in [`PeerRegistry`](super::PeerRegistry): a party
//! describing its own capabilities is not a source of truth about its authority.

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
        }
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
    http: reqwest::Client,
    endpoint: Endpoint,
}

impl A2aClient {
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
        let http = reqwest::Client::builder()
            .timeout(endpoint.timeout)
            .build()
            .map_err(|e| PeerError::Unreachable {
                peer: PeerId::new("<local>"),
                detail: format!("could not build an HTTP client: {e}"),
            })?;
        Ok(Self {
            egress: None,
            http,
            endpoint,
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
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "ROLE_USER",
                    "messageId": message_id,
                    "parts": [{ "data": payload, "mediaType": "application/json" }],
                    "extensions": [EXTENSION_URI],
                    "metadata": {
                        EXTENSION_URI: {
                            "capability": capability,
                            "chain": acting_as,
                            "provenance": attested,
                        }
                    }
                }
            }
        })
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
        // `-32603 Internal error` and anything unrecognised. The request
        // arrived; whether the peer acted is exactly what it is not saying.
        // Calling this a refusal is how a half-finished transfer is sent again.
        _ => PeerError::TimedOut {
            peer: peer.clone(),
            detail: format!("{detail} — the peer did not say whether it acted"),
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
        // indistinguishable here, and one of them may have acted.
        return PeerError::TimedOut {
            peer: peer.clone(),
            detail: format!("HTTP {status} — the peer did not say whether it acted"),
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
        // The peer very likely acted.
        return PeerError::TimedOut {
            peer: peer.clone(),
            detail: format!("the response could not be read: {e}"),
        };
    }
    if e.is_request() {
        // A request that failed while being built or written. A partial write
        // is indistinguishable from none, so this is not `Unreachable`.
        return PeerError::TimedOut {
            peer: peer.clone(),
            detail: format!("the request failed in flight: {e}"),
        };
    }
    PeerError::TimedOut {
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
        // Before the request is built: a refused destination must reach nothing
        // and must be `DidNotHappen`, so the runtime knows the peer never saw it.
        if let Some(egress) = &self.egress {
            let host = reqwest::Url::parse(&self.endpoint.url)
                .ok()
                .and_then(|u| u.host_str().map(ToOwned::to_owned));
            if let Err(e) = egress.permits(host.as_deref()) {
                return Err(PeerError::Refused {
                    peer: peer.clone(),
                    detail: e.to_string(),
                });
            }
        }

        let mut req = self
            .http
            .post(&self.endpoint.url)
            .header("A2A-Version", PROTOCOL_VERSION)
            .header("A2A-Extensions", EXTENSION_URI)
            .json(&Self::body(capability, payload, acting_as, provenance));

        // The credential is audience-bound before it reaches here — the registry
        // refuses to hand over one minted for somebody else — so presenting it
        // cannot arm this peer to replay it elsewhere.
        if let Some(c) = credential {
            req = req.bearer_auth(c.expose());
        }

        let response = req.send().await.map_err(|e| classify_transport(peer, &e))?;

        let status = response.status();
        // Read the body before deciding: a JSON-RPC error carried inside a 200
        // is the normal case, and a 4xx may still carry one worth reporting.
        let body: Result<RpcResponse, _> = response.json().await;

        let Ok(rpc) = body else {
            return Err(classify_status(peer, status));
        };
        // Ordinary HTTP errors are not JSON-RPC envelopes. Do not reinterpret
        // a 401/404 as a malformed agent response merely because serde can
        // deserialize an unrelated JSON object into an all-optional struct.
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
            (None, Some(e)) => return Err(classify_rpc(peer, &e)),
            (Some(result), None) => result,
        };
        if !status.is_success() {
            return Err(classify_status(peer, status));
        }
        let result = send_message_result(peer, &result)?;
        if let Some(failure) = task_failure(peer, &result) {
            return Err(failure);
        }
        Ok(result)
    }
}
