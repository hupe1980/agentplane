//! Serve this plane's A2A surface for the official conformance kit.
//!
//! ```sh
//! cargo run --example a2a_tck_live --features redb,a2a-server,manifest
//! ```
//!
//! Then, from a checkout of <https://github.com/a2aproject/a2a-tck>:
//!
//! ```sh
//! ./run_tck.py --sut-host http://127.0.0.1:9999 --transport jsonrpc --level must
//! ```
//!
//! `just test-a2a-tck` does both.
//!
//! # Why this exists
//!
//! Every A2A test in this repository drives this crate's server with this
//! crate's client, or with requests written from this crate's reading of the
//! specification. That proves symmetry, not conformance: a client and a server
//! written from the same misreading agree with each other everywhere,
//! including where both are wrong — only an outside authority
//! breaks the tie. The TCK is the outside authority: pytest conformance
//! written by the protocol's own project, exercised against a live socket. Its
//! first run found a real interoperability defect — the JSON-RPC endpoint
//! 404ing the trailing-slash URL every httpx-based client produces — plus
//! four protocol-mapping defects no in-repo test could have caught.
//!
//! # Why it is `_live`
//!
//! Not because it spends a credential — it binds a port and serves until
//! killed, so it must never run under `just examples`, which expects every
//! example to terminate. The `_live` suffix is the existing exemption for
//! "compiled always, executed only on purpose".
//!
//! # The SUT contract
//!
//! The TCK addresses the agent under test by `messageId` prefix — its
//! reference agent (`sut/a2a-python/sut_agent.py` in the TCK repository)
//! defines the vocabulary, and this skill implements the same one: exact
//! artifact contents for `tck-artifact-*`, a direct message for
//! `tck-message-response`, a journaled input wait for `tck-input-required`.
//!
//! # The fixture's deliberate weaknesses
//!
//! Two choices here would be defects in a deployment and are the point of a
//! fixture:
//!
//! * **Authentication accepts anyone.** The TCK does not present credentials,
//!   and refusing it would test this crate's refusal rather than the protocol.
//!   Every caller is authenticated as the fixed actor `tck`; a bearer token, if
//!   one arrives, names the actor instead. The invariant "every method call is
//!   authenticated" still holds — what varies is what authentication *means*,
//!   which is exactly the `Authenticator` seam's job.
//! * **Policy permits everything**, because a conformance run is about wire
//!   shapes, not about this deployment's rules. Denials have their own tests.

use std::sync::Arc;

use agentplane::api::a2a::{A2aReply, A2aServer, Part};
use agentplane::api::{AuthError, Authenticator, Caller};
use agentplane::case::{CaseStore, EventStore};
use agentplane::core::{
    AwaitSpec, CorrelationKey, DeadlineSpec, Outcome, PolicyBundleIdentity, PolicyDecision,
    PolicyEngine, PolicyRequest, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::JournalStore;
use agentplane::manifest::Manifest;
use agentplane::peers::CardSecurity;
use agentplane::runtime::{Agent, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// One capability, advertised alone — an A2A message that names no skill
/// dispatches unambiguously when the card advertises exactly one.
const ECHO: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: tck-echo
  version: "1.0.0"
spec:
  identity:
    role: "Answer conformance-kit messages per the TCK's SUT contract."
    constraints: "Dispatch on the messageId prefix; echo everything else."
  budgets:
    max_steps: 5
  capabilities:
    provides: [tck.echo]
"#;

/// The TCK's reference-agent vocabulary, spoken by a skill.
#[derive(Debug)]
struct TckAgent;

#[async_trait::async_trait]
impl Skill for TckAgent {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("tck.echo").provides("tck.echo")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let message_id = input.peek()["$a2a_message"]["messageId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        // Longest prefixes first: `tck-artifact-file` is a prefix of
        // `tck-artifact-file-url`, and a match that checks the short one first
        // answers the wrong test.
        let reply = if message_id.starts_with("tck-artifact-file-url") {
            A2aReply::artifact(vec![Part::file_url(
                "https://example.com/output.txt",
                "text/plain",
                "output.txt",
            )])
        } else if message_id.starts_with("tck-artifact-file") {
            // "dGNr" is base64 for "tck", as the reference agent sends it.
            A2aReply::artifact(vec![Part::file_raw("dGNr", "text/plain", "output.txt")])
        } else if message_id.starts_with("tck-artifact-text") {
            A2aReply::artifact(vec![Part::text("Generated text content")])
        } else if message_id.starts_with("tck-artifact-data") {
            A2aReply::artifact(vec![Part::data(json!({"key": "value", "count": 42}))])
        } else if message_id.starts_with("tck-message-response") {
            A2aReply::message(vec![Part::text("Direct message response")])
        } else if message_id.starts_with("tck-stream-artifact-text") {
            A2aReply::artifact(vec![Part::text("Streamed text content")])
        } else if message_id.starts_with("tck-stream-artifact-file") {
            A2aReply::artifact(vec![Part::file_raw("dGNr", "text/plain", "output.txt")])
        } else if message_id.starts_with("tck-stream-ordering-001") {
            A2aReply::artifact(vec![Part::text("Ordered output")])
        } else if message_id.starts_with("tck-stream-001") {
            A2aReply::artifact(vec![Part::text("Stream hello from TCK")])
        } else if message_id.starts_with("tck-stream-003") {
            A2aReply::artifact(vec![Part::text("Stream task lifecycle")])
        } else if message_id.starts_with("tck-complete-task") {
            A2aReply::artifact(vec![Part::text("Hello from TCK")])
        } else if message_id.starts_with("tck-input-required") {
            // Suspend on a journaled wait; the TCK's follow-up send names this
            // task and completes it — the exact continuation path a real
            // multi-turn client uses.
            cx.deadline("reply", &DeadlineSpec::days(1), None).await?;
            let reply = cx
                .await_event(
                    &AwaitSpec::new("a2a.task.input", "reply")
                        .correlate(CorrelationKey::new("task", "tck")),
                )
                .await?;
            cx.meet_deadline("reply").await?;
            return Ok(Outcome::done(reply));
        } else if message_id.starts_with("tck-reject-task") {
            return Ok(Outcome::fail("rejected, as the TCK asked"));
        } else {
            // Default: echo, as the reference agent does.
            return Ok(Outcome::done(input.map(
                |v| json!({ "echo": v["text"].as_str().unwrap_or_default() }),
            )));
        };
        Ok(Outcome::done(Tainted::trusted(reply.into_value())))
    }
}

/// Authenticates anyone, as the fixed actor `tck` — see the module docs for
/// why a fixture may do what a deployment must not.
#[derive(Debug)]
struct AnyoneIsTck;

#[async_trait::async_trait]
impl Authenticator for AnyoneIsTck {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        let actor = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("tck");
        Ok(Caller::new(actor, vec!["peer".to_owned()]))
    }
}

#[derive(Debug)]
struct PermitEverything;

impl PolicyEngine for PermitEverything {
    fn authorize(&self, _request: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Permit
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(
            agentplane::core::Digest::of(b"tck.permit-everything"),
            "tck/permit-everything-v1",
        )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("A2A_TCK_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".to_owned());
    // The URL on the card must be the one the kit will dial, so a kit running
    // elsewhere (a container, another host) can be pointed here by env.
    let public = std::env::var("A2A_TCK_URL").unwrap_or_else(|_| format!("http://{bind}"));

    let manifest = Manifest::parse(ECHO)?;
    let store = Arc::new(RedbStore::open_in_memory()?);
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .events(Arc::clone(&store) as Arc<dyn EventStore>)
        .policy(Arc::new(PermitEverything))
        .agent(Agent::new(&manifest).skill(TckAgent))
        .build();

    let server = A2aServer::new(
        runtime,
        Arc::new(AnyoneIsTck),
        &CardSecurity::bearer("tck", ["a2a:invoke"]),
        &manifest,
        format!("{public}/a2a"),
    )?;

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("a2a-tck fixture serving on http://{bind}");
    eprintln!("  card:     {public}/.well-known/agent-card.json");
    eprintln!("  json-rpc: {public}/a2a");
    axum::serve(listener, server.router()).await?;
    Ok(())
}
