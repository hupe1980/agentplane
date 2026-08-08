//! Calling other agents.
//!
//! Two properties carry the weight, and both are about identity:
//!
//! * **A credential is spent only where it was minted for.** A bearer token sent
//!   to peer B and accepted by peer A is the whole token-confusion class. This
//!   runtime cannot make A check the audience; it can refuse to hand B a token
//!   addressed to A, and that refusal happens before anything leaves.
//! * **Authority narrows at the boundary.** A peer acts on our behalf, so it
//!   receives our chain plus one link — never wider, never past the depth cap.
//!
//! The rest is the discipline every other outward call already has: fail closed
//! on an unregistered peer, untrusted responses, and a disposition that says
//! whether the request reached the far side.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Delegation, DelegationError, Disposition, Effect, MAX_DELEGATION_DEPTH, Principal, Recovery,
    Scope, Trust,
};
use agentplane::peers::{
    PeerCall, PeerClient, PeerCredential, PeerError, PeerGrant, PeerId, PeerRegistry, PeerTask,
    PeerTaskCall,
};
use serde_json::{Value, json};

/// Records what it was handed, so the tests can assert on what would go out.
#[derive(Debug, Default)]
struct Spy {
    sent: Mutex<Vec<(String, Option<String>, usize)>>,
    task_reads: Mutex<Vec<(String, String, Option<String>)>>,
    answer: Mutex<Option<PeerError>>,
}

#[async_trait::async_trait]
impl PeerClient for Spy {
    async fn send(
        &self,
        peer: &PeerId,
        _capability: &str,
        _payload: &Value,
        acting_as: &Delegation,
        credential: Option<&PeerCredential>,
        _provenance: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, PeerError> {
        self.sent.lock().unwrap().push((
            peer.to_string(),
            credential.map(|c| c.expose().to_owned()),
            acting_as.depth(),
        ));
        match self.answer.lock().unwrap().take() {
            Some(e) => Err(e),
            None => Ok(json!({ "reviewed": true })),
        }
    }

    async fn get_task(
        &self,
        peer: &PeerId,
        task_id: &str,
        credential: Option<&PeerCredential>,
    ) -> Result<Value, PeerError> {
        self.task_reads.lock().unwrap().push((
            peer.to_string(),
            task_id.to_owned(),
            credential.map(|value| value.expose().to_owned()),
        ));
        Ok(json!({
            "id": task_id,
            "contextId": "matter-1",
            "status": {"state": "TASK_STATE_COMPLETED"},
            "artifacts": [{"parts": [{"data": {"reviewed": true}}]}]
        }))
    }
}

fn owner() -> Delegation {
    Delegation::root(Principal::new("user:hupe", Scope::root()))
}

fn auditor() -> Delegation {
    owner()
        .delegate(Principal::new("agent:auditor", Scope::of(["audit.*"])))
        .expect("narrowing")
}

fn reviewer() -> PeerId {
    PeerId::new("reviewer.example")
}

fn settlement() -> PeerId {
    PeerId::new("settlement.example")
}

// ── Token confusion ─────────────────────────────────────────────────────────

/// A credential minted for one peer is never handed to another.
///
/// The registry holds a token for `settlement.example` under the entry for
/// `reviewer.example` — a plausible copy-paste — and the call must be refused
/// rather than sending `reviewer.example` a token it can replay at
/// `settlement.example`.
#[test]
fn a_credential_bound_to_one_peer_is_not_spent_at_another() {
    // The credential is attached correctly *for settlement* — the constructor's
    // assertion is satisfied — and then the whole grant is filed under
    // `reviewer`. That is the shape of a real misconfiguration: a copied block
    // where the peer key was changed and the credential was not. The constructor
    // cannot catch it, so the call-time check must.
    let registry = PeerRegistry::new().allow(reviewer(), {
        let mut grant = PeerGrant::new(Scope::of(["audit.check"]));
        grant = grant.with_credential(
            &settlement(),
            PeerCredential::for_audience(settlement(), "s3cret"),
        );
        grant
    });

    let err = registry
        .credential_for(&reviewer())
        .expect_err("a credential for another audience must not be produced");
    assert!(
        matches!(err, PeerError::WrongAudience { .. }),
        "got {err:?}"
    );
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert!(
        err.to_string().contains("replay"),
        "the message must say why this matters, not just that it failed: {err}"
    );
}

/// The right credential does go out, and only that one.
#[tokio::test]
async fn the_credential_for_the_peer_being_called_is_the_one_sent() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new()
        .allow(
            reviewer(),
            PeerGrant::new(Scope::of(["audit.check"])).with_credential(
                &reviewer(),
                PeerCredential::for_audience(reviewer(), "for-reviewer"),
            ),
        )
        .allow(
            settlement(),
            PeerGrant::new(Scope::of(["audit.check"])).with_credential(
                &settlement(),
                PeerCredential::for_audience(settlement(), "for-settlement"),
            ),
        );

    let call = PeerCall::prepare(
        &registry,
        Arc::clone(&spy) as Arc<dyn PeerClient>,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");
    call.perform().await.expect("the peer answers");

    let sent = spy.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].1.as_deref(),
        Some("for-reviewer"),
        "the token for the *other* peer must never appear on this wire"
    );
}

/// A credential never renders itself.
///
/// This crate writes logs, span attributes and error messages, and a secret that
/// prints itself ends up in all three.
#[test]
fn a_credential_does_not_print_its_secret() {
    let c = PeerCredential::for_audience(reviewer(), "hunter2");
    let rendered = format!("{c:?}");
    assert!(
        !rendered.contains("hunter2"),
        "the secret leaked into Debug output: {rendered}"
    );
    assert!(
        rendered.contains("reviewer.example"),
        "the audience should still be visible — it is the part worth debugging"
    );
}

// ── Authority at the boundary ───────────────────────────────────────────────

/// A peer receives the caller's chain plus one link, and it is narrower.
#[test]
fn a_hop_appends_a_link_and_narrows() {
    let spy = Arc::new(Spy::default());
    let registry =
        PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"])));

    let call = PeerCall::prepare(
        &registry,
        spy,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");

    let chain = call.acting_as();
    assert_eq!(chain.depth(), 2, "owner → auditor → peer");
    assert_eq!(
        Effect::delegation_depth(&call),
        Some(2),
        "the runtime must see the depth that will go on the wire"
    );
    assert_eq!(chain.subject().id, "reviewer.example");
    assert_eq!(chain.owner().id, "user:hupe", "the human survives the hop");
    assert!(chain.effective_scope().permits(&"audit.check".into()));
    assert!(
        !chain.effective_scope().permits(&"audit.write".into()),
        "the peer holds only what it was granted"
    );
}

/// A grant wider than the caller's own authority is refused, not clipped.
///
/// Silently narrowing would hide the misconfiguration. An operator who granted a
/// peer `billing.*` from an agent that only holds `audit.*` has made a mistake
/// worth seeing.
#[test]
fn a_grant_wider_than_the_caller_is_refused() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["billing.*"])));

    let err = PeerCall::prepare(
        &registry,
        spy,
        &auditor(),
        reviewer(),
        "billing.transfer",
        json!({}),
    )
    .expect_err("an auditor cannot lend billing authority it does not hold");

    assert!(
        matches!(
            err,
            PeerError::Delegation {
                source: DelegationError::ScopeWidened { .. },
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
}

/// A hop past the depth cap is refused.
#[test]
fn a_hop_beyond_the_delegation_cap_is_refused() {
    let mut chain = owner();
    for i in 0..MAX_DELEGATION_DEPTH {
        chain = chain
            .delegate(Principal::new(format!("agent:{i}"), Scope::of(["audit.*"])))
            .expect("narrowing");
    }

    let spy = Arc::new(Spy::default());
    let registry =
        PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"])));

    let err = PeerCall::prepare(&registry, spy, &chain, reviewer(), "audit.check", json!({}))
        .expect_err("past the cap");
    assert!(
        matches!(
            err,
            PeerError::Delegation {
                source: DelegationError::TooDeep { .. },
                ..
            }
        ),
        "a request must not wander arbitrarily far from the human who authorised \
         it: {err:?}"
    );
}

/// An unregistered peer cannot be called.
#[test]
fn an_unregistered_peer_is_refused() {
    let spy = Arc::new(Spy::default());
    let err = PeerCall::prepare(
        &PeerRegistry::new(),
        spy,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect_err("fail closed");
    assert!(matches!(err, PeerError::Unknown { .. }), "got {err:?}");
}

// ── Provenance and disposition ──────────────────────────────────────────────

/// A peer's answer is another party's data, however much it feels like ours.
#[test]
fn a_peer_response_is_untrusted() {
    let spy = Arc::new(Spy::default());
    let registry =
        PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"])));
    let call = PeerCall::prepare(
        &registry,
        spy,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");

    assert!(
        matches!(call.trust(), Trust::Untrusted),
        "a peer runs somewhere else, under someone else's control, and may itself \
         have read the internet"
    );
    assert!(call.mutates(), "and the conservative default still applies");
    assert!(matches!(call.recovery(), Recovery::RequiresOperator));
}

#[test]
fn each_peer_failure_says_what_it_knows() {
    let p = reviewer();
    let cases = [
        (
            PeerError::Unreachable {
                peer: p.clone(),
                detail: "no route".into(),
            },
            Disposition::DidNotHappen,
        ),
        (
            PeerError::Refused {
                peer: p.clone(),
                detail: "not authorised".into(),
            },
            Disposition::DidNotHappen,
        ),
        (
            PeerError::TimedOut {
                peer: p.clone(),
                detail: "no answer".into(),
            },
            Disposition::InDoubt,
        ),
        (
            PeerError::Failed {
                peer: p,
                detail: "review rejected".into(),
            },
            Disposition::Landed,
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(err.disposition(), expected, "for {err}");
    }
}

/// A timed-out hop stays in doubt once it reaches the runtime.
#[tokio::test]
async fn a_timed_out_hop_is_in_doubt() {
    let spy = Arc::new(Spy::default());
    *spy.answer.lock().unwrap() = Some(PeerError::TimedOut {
        peer: reviewer(),
        detail: "no answer in 30s".into(),
    });

    let registry =
        PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"])));
    let call = PeerCall::prepare(
        &registry,
        Arc::clone(&spy) as Arc<dyn PeerClient>,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");

    let err = call.perform().await.expect_err("the peer does not answer");
    assert_eq!(
        err.disposition(),
        Disposition::InDoubt,
        "the disposition must survive into EffectError, because that is what the \
         retry gate reads: {err}"
    );
}

/// Two peers are two different effects, even for the same capability.
#[test]
fn the_peer_is_part_of_the_effect_identity() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new()
        .allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"])))
        .allow(settlement(), PeerGrant::new(Scope::of(["audit.check"])));

    let a = PeerCall::prepare(
        &registry,
        Arc::clone(&spy) as Arc<dyn PeerClient>,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");
    let b = PeerCall::prepare(
        &registry,
        spy,
        &auditor(),
        settlement(),
        "audit.check",
        json!({}),
    )
    .expect("permitted");

    assert_ne!(
        a.descriptor().args,
        b.descriptor().args,
        "one peer's recorded answer must never replay as another's"
    );
}

// ── Credentials never reach the journal ─────────────────────────────────────

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted, Timestamp};
use agentplane::journal::JournalStore;
use agentplane::peers::{Cached, CredentialError, CredentialSource, Fixed, TokenExchange};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use std::time::Duration;

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

const SECRET: &str = "tok_supersecret_do_not_journal";

#[derive(Debug)]
struct Issuer {
    exchanges: Mutex<usize>,
    expires_at: Option<Timestamp>,
    /// Hand back a token bound to *this* audience, whatever was asked for.
    misbind_to: Option<PeerId>,
}

impl Issuer {
    fn new(expires_at: Option<Timestamp>) -> Arc<Self> {
        Arc::new(Self {
            exchanges: Mutex::new(0),
            expires_at,
            misbind_to: None,
        })
    }
}

#[async_trait::async_trait]
impl TokenExchange for Issuer {
    async fn exchange(&self, audience: &PeerId) -> Result<PeerCredential, CredentialError> {
        *self.exchanges.lock().unwrap() += 1;
        let bound_to = self.misbind_to.clone().unwrap_or_else(|| audience.clone());
        let mut c = PeerCredential::for_audience(bound_to, SECRET);
        if let Some(at) = self.expires_at {
            c = c.expiring_at(at);
        }
        Ok(c)
    }
}

#[derive(Debug)]
struct Calls {
    registry: PeerRegistry,
    client: Arc<Spy>,
    source: Arc<dyn CredentialSource>,
}

#[async_trait::async_trait]
impl Skill for Calls {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("review").provides("review")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let credential = self
            .source
            .credential(&reviewer(), ts(1_000))
            .await
            .map_err(|e| SkillError::Other(e.to_string()))?;

        let call = PeerCall::prepare_with_credential(
            &self.registry,
            Arc::clone(&self.client) as Arc<dyn PeerClient>,
            &auditor(),
            reviewer(),
            "audit.check",
            json!({ "invoice": "INV-1" }),
            Some(credential),
        )
        .map_err(|e| SkillError::Other(e.to_string()))?;

        let out = cx.effect(call).await?;
        Ok(Outcome::done(out))
    }
}

/// The secret is presented to the peer and appears nowhere in history.
///
/// This is the test the whole credential design exists for. The journal is
/// append-only, hash-chained and permanent: a bearer token written into an
/// `EffectDone` record cannot be redacted later, because the record's hash covers
/// it and the chain would break. So the check is not "did we remember to omit
/// it" — it is a scan of every byte the run wrote.
#[tokio::test]
async fn a_credential_is_presented_to_the_peer_and_never_written_to_the_journal() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(Some(ts(9_999)));

    let out = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Calls {
            registry: PeerRegistry::new()
                .allow(reviewer(), PeerGrant::new(Scope::of(["audit.check"]))),
            client: Arc::clone(&spy),
            source: Arc::new(Cached::new(issuer as Arc<dyn TokenExchange>)),
        })
        .build()
        .run("review", Tainted::trusted(json!({})))
        .await
        .unwrap();

    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "{:?}",
        out.status
    );

    // It really was presented.
    assert_eq!(
        spy.sent.lock().unwrap()[0].1.as_deref(),
        Some(SECRET),
        "the peer must actually receive the credential, or this test proves \
         nothing about keeping it out of the journal"
    );

    // And it is nowhere in the record.
    let records = store.read(out.run_id, 1).await.unwrap();
    assert!(!records.is_empty(), "the run wrote a journal");
    for r in &records {
        let raw = String::from_utf8_lossy(r.raw());
        assert!(
            !raw.contains(SECRET),
            "a bearer token reached record {} ({}). The journal is permanent and \
             hash-chained: this secret could never be redacted, only discovered.",
            r.seq(),
            r.kind().kind_str()
        );
    }
}

#[derive(Debug)]
struct PollsRemoteTask {
    registry: PeerRegistry,
    client: Arc<Spy>,
}

#[async_trait::async_trait]
impl Skill for PollsRemoteTask {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("poll-remote").provides("peer.poll")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let call = PeerTaskCall::prepare(
            &self.registry,
            Arc::clone(&self.client) as Arc<dyn PeerClient>,
            PeerTask {
                peer: reviewer(),
                id: "remote-task-42".to_owned(),
                context_id: Some("matter-1".to_owned()),
            },
        )
        .map_err(|error| SkillError::Other(error.to_string()))?;
        let snapshot = cx.effect(call).await?;
        Ok(Outcome::done(snapshot.map(|value| {
            serde_json::to_value(value).expect("task snapshot serializes")
        })))
    }
}

#[tokio::test]
async fn a_remote_task_poll_is_journaled_and_replay_does_not_poll_again() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let client = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(
        reviewer(),
        PeerGrant::new(Scope::of(["audit.check"]))
            .read_only()
            .with_credential(
                &reviewer(),
                PeerCredential::for_audience(reviewer(), SECRET),
            ),
    );
    let trust_probe = PeerTaskCall::prepare(
        &registry,
        Arc::clone(&client) as Arc<dyn PeerClient>,
        PeerTask {
            peer: reviewer(),
            id: "trust-probe".to_owned(),
            context_id: None,
        },
    )
    .unwrap();
    assert_eq!(trust_probe.trust(), Trust::Untrusted);
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(PollsRemoteTask {
            registry,
            client: Arc::clone(&client),
        })
        .build();

    let live = runtime
        .run("peer.poll", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert_eq!(live.status, RunStatus::Succeeded);
    assert_eq!(client.task_reads.lock().unwrap().len(), 1);
    assert_eq!(
        client.task_reads.lock().unwrap()[0].2.as_deref(),
        Some(SECRET),
        "the task read did not use the audience-bound peer credential"
    );
    let replayed = runtime
        .replay(live.run_id, agentplane::runtime::Mode::Strict)
        .await
        .unwrap();
    assert_eq!(replayed.status, RunStatus::Succeeded);
    assert_eq!(
        client.task_reads.lock().unwrap().len(),
        1,
        "strict replay polled the remote peer again"
    );
}

// ── Freshness ───────────────────────────────────────────────────────────────

/// A credential that expires inside the skew margin is refreshed, not sent.
///
/// Sending it would have it lapse in flight, and the rejection arrives as a peer
/// failure of unknown disposition — when it was really a refresh nobody
/// scheduled.
#[tokio::test]
async fn a_credential_expiring_within_the_margin_is_replaced() {
    let issuer = Issuer::new(Some(ts(1_030)));
    let cached =
        Cached::new(Arc::clone(&issuer) as Arc<dyn TokenExchange>).skew(Duration::from_mins(1));

    let err = cached
        .credential(&reviewer(), ts(1_000))
        .await
        .expect_err("30s of life left, 60s of margin");
    assert!(matches!(err, CredentialError::Stale { .. }), "got {err:?}");
}

/// A usable credential is reused rather than re-exchanged every call.
#[tokio::test]
async fn a_live_credential_is_cached() {
    let issuer = Issuer::new(Some(ts(9_999)));
    let cached = Cached::new(Arc::clone(&issuer) as Arc<dyn TokenExchange>);

    for _ in 0..3 {
        cached
            .credential(&reviewer(), ts(1_000))
            .await
            .expect("usable");
    }
    assert_eq!(
        *issuer.exchanges.lock().unwrap(),
        1,
        "a token endpoint is not free, and re-exchanging per call is how one gets \
         rate-limited at the worst moment"
    );
}

/// An issuer that ignores `resource` is not taken at its word.
#[tokio::test]
async fn a_token_bound_to_the_wrong_audience_is_refused() {
    let issuer = Arc::new(Issuer {
        exchanges: Mutex::new(0),
        expires_at: Some(ts(9_999)),
        misbind_to: Some(settlement()),
    });
    let cached = Cached::new(issuer as Arc<dyn TokenExchange>);

    let err = cached
        .credential(&reviewer(), ts(1_000))
        .await
        .expect_err("the issuer bound it to settlement");
    assert!(
        matches!(err, CredentialError::WrongAudience { .. }),
        "an issuer that ignores the resource indicator hands back a token the \
         peer can spend elsewhere: {err:?}"
    );
}

/// A fixed credential still respects the binding.
#[tokio::test]
async fn a_fixed_source_will_not_hand_over_another_peers_credential() {
    let fixed = Fixed::new(PeerCredential::for_audience(settlement(), SECRET));
    let err = fixed
        .credential(&reviewer(), ts(1_000))
        .await
        .expect_err("bound to settlement");
    assert!(matches!(err, CredentialError::WrongAudience { .. }));
}

/// A credential with no stated expiry is usable.
#[test]
fn a_credential_without_an_expiry_is_usable() {
    let c = PeerCredential::for_audience(reviewer(), SECRET);
    assert!(c.is_usable_at(ts(1_000), Duration::from_mins(1)));
    assert!(
        c.expires_at().is_none(),
        "inventing an expiry would either reject working credentials or invent a \
         guarantee the issuer never made"
    );
}
