//! Serving this plane as an A2A agent, and calling it as a peer would.
//!
//! ```sh
//! cargo run --example a2a_peer --features redb,a2a-server,manifest
//! ```
//!
//! No network and no key: the router is driven in-process with `tower::oneshot`,
//! which is exactly what a conforming client's HTTP stack would deliver to it.
//! The assertions are on the **wire** — the JSON a peer receives — because a
//! test against the Rust types would pass under any `serde` rename at all,
//! including a wrong one, and the whole value of this surface is that software
//! nobody here wrote can parse it.
//!
//! What it demonstrates, in the order the output prints it:
//!
//! 1. **The card is derived from the manifest, never written beside it.** What
//!    an agent advertises and what it is permitted cannot drift, because there
//!    is only one document. Change the file, change the card.
//! 2. **The card is public and every method is not.** An authenticated card
//!    cannot be discovered, and an unauthenticated method is an open door — so
//!    the one is reachable without credentials and the other is refused without
//!    them.
//! 3. **A refusal is a JSON-RPC error with the spec's code**, not an HTTP
//!    status. `-32601` for a method that does not exist lets a caller tell "this
//!    agent cannot do that" from "you spelled it wrong". Both are refusals; only
//!    one is worth retrying differently.
//! 4. **A peer's message arrives untrusted.** It crossed a trust boundary, so it
//!    is labelled at the source rather than remembered about later. Reaching a
//!    mutating sink with it takes the same journaled release as any other
//!    untrusted value.
//!
//! The 0.3 spellings (`message/send`, `tasks/get`) are refused rather than
//! quietly accepted: a server answering both would let a client that had lost
//! half the protocol believe it was talking to a conforming peer.

use std::sync::{Arc, Mutex};

use agentplane::api::a2a::{A2aServer, method};
use agentplane::api::{AuthError, Authenticator, Caller};
use agentplane::core::{
    Outcome, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, Skill,
    SkillDescriptor, SkillError, Tainted,
};
use agentplane::manifest::Manifest;
use agentplane::peers::CardSecurity;
use agentplane::runtime::{Agent, Runtime, StepCtx};
use agentplane::store::RedbStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// The agent. One capability, which becomes the one skill on the card.
const CHECKER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: settlement-checker
  version: "1.0.0"
spec:
  identity:
    role: "Decide whether a settlement instruction may proceed."
    constraints: "Answer only from the instruction. Do not invent counterparties."
  budgets:
    max_steps: 5
  capabilities:
    provides: [settlement.check]
"#;

/// What the skill saw: whether its input was untrusted, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    untrusted: bool,
    provenance: Vec<String>,
}

/// Records the label its input carried, so the example can show the taint.
#[derive(Debug, Clone)]
struct Checks(Arc<Mutex<Vec<Seen>>>);

#[async_trait::async_trait]
impl Skill for Checks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("settlement.check").provides("settlement.check")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let label = input.label();
        self.0.lock().expect("not poisoned").push(Seen {
            untrusted: label.is_untrusted(),
            provenance: label.provenance.iter().map(ToString::to_string).collect(),
        });
        Ok(Outcome::done(Tainted::trusted(json!({"cleared": true}))))
    }
}

/// A bearer token names the caller. A real deployment verifies a JWT here; what
/// matters for the example is that the *transport* sets the identity and the
/// request body never does — a caller that could name itself could name anyone.
#[derive(Debug)]
struct BearerAuth;

#[async_trait::async_trait]
impl Authenticator for BearerAuth {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Missing)?;
        Ok(Caller::new(token, vec!["peer".to_owned()]))
    }
}

/// Permits this example's one action. A plane with no policy engine refuses to
/// serve A2A at all — every method would be an unauthorized door.
#[derive(Debug)]
struct PermitPeers;

impl PolicyEngine for PermitPeers {
    fn authorize(&self, _request: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Permit
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(
            agentplane::core::Digest::of(b"example.permit-peers"),
            "example/permit-peers-v1",
        )
    }
}

/// One JSON-RPC call, returned as (status, body).
async fn rpc(router: &axum::Router, token: Option<&str>, body: Value) -> (StatusCode, Value) {
    // A 1.0 client states the version. Without the header the spec says to read
    // the request as 0.3, and this server refuses rather than guessing — which
    // is the third demonstration below, reached on purpose.
    let mut request = Request::builder()
        .method("POST")
        .uri("/a2a")
        .header("a2a-version", "1.0");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(
            request
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router answered");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    // A refusal is still a JSON-RPC envelope, so an empty body would itself be
    // the defect worth seeing.
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = Manifest::parse(CHECKER)?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let store = Arc::new(RedbStore::open_in_memory()?);

    // An A2A server refuses a runtime without a case layer: every task must
    // carry a contextId a client can actually continue, and a continuable
    // context here is a case. `builder_on` wires it — and the rest of the
    // case layer — to the same store in one call.
    let runtime = Runtime::builder_on(store)
        .policy(Arc::new(PermitPeers))
        .agent(Agent::new(&manifest).skill(Checks(Arc::clone(&seen))))
        .build();

    let server = A2aServer::new(
        runtime,
        Arc::new(BearerAuth),
        &CardSecurity::bearer("peer-token", ["a2a:invoke"]),
        &manifest,
        "https://settlement.example/a2a",
    )?;
    let router = server.router();

    // ── 1. The card, derived and public ─────────────────────────────────────
    let card = router
        .clone()
        .oneshot(
            Request::builder()
                // No `authorization` header: discovery cannot require the
                // credential a caller is trying to discover how to present.
                .uri("/.well-known/agent-card.json")
                .body(Body::empty())?,
        )
        .await?;
    println!("1. the card is public");
    println!("   GET /.well-known/agent-card.json → {}", card.status());
    let card: Value =
        serde_json::from_slice(&axum::body::to_bytes(card.into_body(), 1 << 20).await?)?;
    println!(
        "   protocolVersion: {} (on the interface — a card may serve several)",
        card["supportedInterfaces"][0]["protocolVersion"]
    );
    println!("   name/version:    {} {}", card["name"], card["version"]);
    println!(
        "   skills:          {} — derived from `capabilities.provides`, not written",
        card["skills"][0]["id"]
    );

    // ── 2. Methods are not public ───────────────────────────────────────────
    let send = json!({
        "jsonrpc": "2.0", "id": 1, "method": method::SEND_MESSAGE,
        "params": { "message": {
            // `ROLE_USER`, not `user`: A2A 1.0 spells its enums this way, and
            // the server refuses rather than accepting both.
            "messageId": "m-1", "role": "ROLE_USER",
            "parts": [{ "text": "settle GB-4471 for 12,000" }],
        }},
    });
    let (status, body) = rpc(&router, None, send.clone()).await;
    println!("\n2. every method is not");
    println!("   POST /a2a with no credential → {status}");
    println!("   body: {}", body["error"]["message"]);

    // ── 3. A wrong method name is a JSON-RPC error, not a 404 ───────────────
    let (status, body) = rpc(
        &router,
        Some("peer-alpha"),
        json!({"jsonrpc": "2.0", "id": 2, "method": "message/send", "params": {}}),
    )
    .await;
    println!("\n3. the 0.3 method spelling is refused, as an error a client can read");
    println!(
        "   'message/send' → HTTP {status}, code {}",
        body["error"]["code"]
    );
    println!("   {}", body["error"]["message"]);

    // The other half of the same rule: a client that never says which version it
    // speaks is read as 0.3, because that is what the spec says absence means.
    let unversioned = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/a2a")
                .header("authorization", "Bearer peer-alpha")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"jsonrpc": "2.0", "id": 3, "method": method::GET_TASK, "params": {}})
                        .to_string(),
                ))?,
        )
        .await?;
    let unversioned: Value =
        serde_json::from_slice(&axum::body::to_bytes(unversioned.into_body(), 1 << 20).await?)?;
    println!(
        "   no A2A-Version header → code {}: {}",
        unversioned["error"]["code"], unversioned["error"]["message"]
    );

    // ── 4. The real call, and what the skill saw ────────────────────────────
    let (_, body) = rpc(&router, Some("peer-alpha"), send).await;
    // A2A's response is a `oneof`: a `task` when one was created, a `message`
    // when the agent declined without admitting anything. Reading `result.task`
    // rather than `result` is what makes the decline case distinguishable.
    let task = &body["result"]["task"];
    println!("\n4. an authenticated SendMessage");
    println!("   task id:    {}", task["id"]);
    println!("   state:      {}", task["status"]["state"]);
    println!(
        "   artifact:   {}",
        task["artifacts"][0]["parts"][0]["data"]
    );

    let seen = seen.lock().expect("not poisoned");
    let first = seen.first().expect("the skill ran");
    println!("\n   what the skill received:");
    println!("     untrusted:  {}", first.untrusted);
    println!("     provenance: {:?}", first.provenance);
    println!(
        "\n   A peer's message crossed a trust boundary, so it is labelled at the\n   \
         source. Reaching a mutating sink with it takes a journaled release —\n   \
         the peer being authenticated is not the same as its content being true."
    );

    Ok(())
}
