//! Two planes in one process: a reviewer served over A2A, and a desk that
//! consults it through the plane's own peer wiring.
//!
//! The claim under demonstration is about **identity**, not transport:
//!
//! * the desk's skill never holds a registry, a client or a chain — it calls
//!   `cx.call_peer`, and the plane extends the run's own chain by one link
//!   naming the peer;
//! * the desk presents a credential obtained for the run's owner, with the
//!   desk as actor — so the reviewer's authenticator derives Alice, acting
//!   through the desk, from the credential and never from the message;
//! * the desk's journal says which credential the hop presented, and never
//!   the credential itself;
//! * a strict replay of the desk's run reads the reviewer's answer back from
//!   the journal, and the reviewer is never asked again.
//!
//! Run it: `cargo run --example peer_call --features redb,testkit,manifest,a2a,a2a-server`

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::api::a2a::A2aServer;
use agentplane::api::{AuthError, Authenticator, Caller};
use agentplane::core::{
    Delegation, Digest, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest,
    Principal, Scope,
};
use agentplane::journal::RecordKind;
use agentplane::manifest::Manifest;
use agentplane::peers::a2a::{A2aClient, Endpoint};
use agentplane::peers::{
    Cached, CardSecurity, CredentialError, PeerClient, PeerCredential, PeerGrant, PeerId,
    PeerRegistry, TokenExchange,
};
use agentplane::prelude::*;
use agentplane::runtime::{Agent, RunTerms};
use serde_json::{Value, json};

const REVIEWER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: reviewer, version: "1.0.0" }
spec:
  identity:
    role: "Check invoices."
  capabilities: { provides: [audit.check] }
  budgets: { max_steps: 3 }
"#;

/// What the stand-in issuer's tokens start with; the subject follows.
const ISSUED: &str = "issued-for:";

/// The deployment's token endpoint, in process: it mints a token naming the
/// subject the desk asked for, valid only at the peer it was asked for. A
/// deployment runs a real issuer here (`peers::TokenEndpoint` speaks RFC 8693
/// to one); the reviewer trusts whatever that issuer signs.
#[derive(Debug)]
struct Issuer;

#[async_trait::async_trait]
impl TokenExchange for Issuer {
    async fn exchange(
        &self,
        audience: &PeerId,
        subject: &str,
    ) -> Result<PeerCredential, CredentialError> {
        Ok(PeerCredential::for_subject(
            audience.clone(),
            subject,
            format!("{ISSUED}{subject}"),
        ))
    }
}

/// The reviewer's one skill: an answer, and a note of who asked.
#[derive(Debug)]
struct Checks;

#[async_trait::async_trait]
impl Skill for Checks {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("checks").provides("audit.check")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let on_behalf_of = cx.acting_as().map(|chain| chain.owner().id.clone());
        // A served run's input is the A2A message's projection: its data
        // parts under `data`, in order.
        Ok(Outcome::done(input.map(|message| {
            let invoice = message["data"][0]["invoice"].clone();
            json!({ "verdict": "approved", "invoice": invoice, "on_behalf_of": on_behalf_of })
        })))
    }
}

/// The reviewer's front door: the issuer's token names the person, the
/// desk is the party presenting it, and the credential — not the message —
/// is what the served run acts under.
#[derive(Debug)]
struct DeskToken(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Authenticator for DeskToken {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Caller, AuthError> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(AuthError::Missing)?;
        let subject = token.strip_prefix(ISSUED).ok_or(AuthError::Rejected)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        // The person the token names, acting through the desk, holding
        // exactly what the reviewer's operator granted. The chain inside the
        // message is a claim; this is the credential.
        let chain = Delegation::root(Principal::new(subject, Scope::of(["audit.*"])))
            .delegate(Principal::new("plane:desk", Scope::of(["audit.*"])))
            .map_err(|_| AuthError::Rejected)?;
        Ok(Caller::new("desk", vec!["peer".to_owned()]).acting_as(chain))
    }
}

#[derive(Debug)]
struct Permit;

impl PolicyEngine for Permit {
    fn authorize(&self, _request: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Permit
    }
    fn bundle(&self) -> PolicyBundleIdentity {
        PolicyBundleIdentity::new(Digest::of(b"example.permit"), "example/permit-v1")
    }
}

/// The desk's skill: no registry, no client, no chain of its own.
#[derive(Debug)]
struct Desk;

#[async_trait::async_trait]
impl Skill for Desk {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("desk").provides("desk.answer")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let verdict = cx
            .call_peer(&PeerId::new("reviewer"), "audit.check", &input)
            .await?;
        Ok(Outcome::done(verdict))
    }
}

/// Serve the reviewer on a loopback port; returns its RPC URL, its journal,
/// and how many authenticated requests it has seen.
async fn serve_reviewer()
-> Result<(String, Arc<RedbStore>, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let manifest = Manifest::parse(REVIEWER)?;
    let store = Arc::new(RedbStore::open_in_memory()?);
    let requests = Arc::new(AtomicUsize::new(0));
    let runtime = Runtime::builder_on(Arc::clone(&store))
        .policy(Arc::new(Permit))
        .agent(Agent::new(&manifest).skill(Checks))
        .build();
    let server = A2aServer::new(
        runtime,
        Arc::new(DeskToken(Arc::clone(&requests))),
        &CardSecurity::bearer("bearer", ["peer"]),
        &manifest,
        "http://127.0.0.1/a2a",
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = server.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((format!("http://{addr}/a2a"), store, requests))
}

/// The desk plane: the reviewer is wired once, on the plane.
fn desk_plane(url: &str) -> Result<Arc<Runtime>, Box<dyn std::error::Error>> {
    let registry = PeerRegistry::new().allow(
        PeerId::new("reviewer"),
        PeerGrant::new(Scope::of(["audit.*"]))
            .read_only()
            .with_source(Arc::new(Cached::new(Arc::new(Issuer)))),
    );
    // The loopback exception exists only in `testkit` builds; a deployment
    // reaches a peer over https.
    let client = A2aClient::new(Endpoint::new(url))?.allow_loopback();
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    Ok(Runtime::builder(store)
        .peers(registry, Arc::new(client) as Arc<dyn PeerClient>)
        .skill(Desk)
        .build())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (url, reviewer_store, requests) = serve_reviewer().await?;
    let desk = desk_plane(&url)?;

    // ── 1. The desk consults the reviewer, on Alice's behalf ────────────────
    println!("1. The desk answers for Alice, and consults the reviewer.\n");
    let alice = Delegation::root(Principal::new(
        "user:alice",
        Scope::of(["desk.*", "audit.*"]),
    ));
    let out = desk
        .run_under(
            "desk.answer",
            Tainted::trusted(json!({ "invoice": "INV-9" })),
            RunTerms::default().acting_as(alice),
        )
        .await?
        .outcome()
        .cloned()
        .expect("a fresh admission");
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    let answer = out.output.as_ref().expect("an answer");
    // The peer answers with an A2A task; its artifact carries the verdict.
    println!(
        "   reviewer said:   {}",
        answer.peek()["artifacts"][0]["parts"][0]["data"]
    );
    println!("   answer's label:  {:?}", answer.label().trust);
    println!("   requests served: {}", requests.load(Ordering::SeqCst));

    // ── 2. Whose behalf, on each side ────────────────────────────────────────
    println!("\n2. Each journal names who the run acted for.\n");
    println!(
        "   desk run:     {:?}",
        recorded_chain(desk.journal().as_ref(), out.run_id).await
    );
    println!(
        "   the hop:      {:?}  (what the credential named; never the token)",
        recorded_binding(desk.journal().as_ref(), out.run_id).await
    );
    let (reviewer_run, _) = reviewer_store
        .recent_runs(None, 1)
        .await?
        .into_iter()
        .next()
        .expect("the reviewer ran");
    println!(
        "   reviewer run: {:?}  (from the credential, not the message)",
        recorded_chain(reviewer_store.as_ref(), reviewer_run).await
    );

    // ── 3. Strict replay reaches nobody ─────────────────────────────────────
    println!("\n3. A strict replay of the desk's run reads the answer back.\n");
    let replayed = desk.replay(out.run_id, Mode::Strict).await?;
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "{replayed:?}"
    );
    assert_eq!(replayed.output, out.output, "replay reproduced the answer");
    println!(
        "   requests served: {} (unchanged)",
        requests.load(Ordering::SeqCst)
    );
    println!(
        "\nThe peer saw Alice, through the desk, in the credential; the replay saw only the journal."
    );
    Ok(())
}

/// What the run's peer hop recorded about its credential.
async fn recorded_binding(
    store: &dyn JournalStore,
    run: agentplane::core::RunId,
) -> Option<agentplane::core::CredentialBinding> {
    store
        .read(run, 1)
        .await
        .unwrap_or_default()
        .iter()
        .find_map(|record| match record.kind() {
            RecordKind::EffectStarted { credential, .. } => credential.clone(),
            _ => None,
        })
}

/// The chain a run's journal says it acted under.
async fn recorded_chain(store: &dyn JournalStore, run: agentplane::core::RunId) -> Vec<String> {
    store
        .read(run, 1)
        .await
        .unwrap_or_default()
        .iter()
        .find_map(|record| match record.kind() {
            RecordKind::IdentityBound { chain } => {
                Some(chain.iter().map(|p| p.id.clone()).collect())
            }
            _ => None,
        })
        .unwrap_or_default()
}
