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
    Delegation, DelegationError, Disposition, Effect, MAX_DELEGATION_DEPTH, Outcome, Principal,
    Recovery, Scope, Skill, SkillDescriptor, SkillError, Tainted, Trust,
};
use agentplane::journal::JournalStore;
use agentplane::peers::{
    PeerCall, PeerClient, PeerCredential, PeerError, PeerGrant, PeerId, PeerRegistry, PeerRouter,
    PeerTask, PeerTaskCall,
};
use agentplane::runtime::{Mode, RunStatus, RunTerms, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Records what it was handed, so the tests can assert on what would go out.
#[derive(Debug, Default)]
struct Spy {
    sent: Mutex<Vec<(String, Option<String>, usize)>>,
    /// The link ids of every chain that went out, owner first.
    chains: Mutex<Vec<Vec<String>>>,
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
        self.chains
            .lock()
            .unwrap()
            .push(acting_as.links().map(|p| p.id.clone()).collect());
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
            &err,
            PeerError::Delegation { source, .. }
                if matches!(**source, DelegationError::ScopeWidened { .. })
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
            &err,
            PeerError::Delegation { source, .. }
                if matches!(**source, DelegationError::TooDeep { .. })
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

use agentplane::core::{CredentialBinding, Timestamp};
use agentplane::journal::RecordKind;
use agentplane::peers::{Asker, Cached, CredentialError, CredentialSource, TokenExchange};
use agentplane::quota::{HaltScope, QuotaStore, TenantQuota};
use std::time::Duration;

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

const SECRET: &str = "tok_supersecret_do_not_journal";

/// The plane's own credential for a subject-bound peer.
const PLANE_TOKEN: &str = "tok_the_planes_own";

fn alice() -> Delegation {
    Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])))
}

fn bob() -> Delegation {
    Delegation::root(Principal::new("user:bob", Scope::of(["audit.*"])))
}

/// A token endpoint that records what it was asked for.
#[derive(Debug, Default)]
struct Issuer {
    /// Every exchange, as (audience, subject).
    asked: Mutex<Vec<(String, String)>>,
    expires_at: Option<Timestamp>,
    /// Hand back a token bound to *this* audience, whatever was asked for.
    misbind_to: Option<PeerId>,
    /// Hand back a token naming *this* subject, whatever was asked for.
    misname_as: Option<String>,
    /// Refuse every exchange as unreachable.
    down: bool,
}

impl Issuer {
    fn new(expires_at: Option<Timestamp>) -> Arc<Self> {
        Arc::new(Self {
            expires_at,
            ..Self::default()
        })
    }

    fn exchanges(&self) -> usize {
        self.asked.lock().unwrap().len()
    }
}

/// The token an issuer mints for `subject`.
fn token_for(subject: &str) -> String {
    format!("{SECRET}:{subject}")
}

#[async_trait::async_trait]
impl TokenExchange for Issuer {
    async fn exchange(
        &self,
        audience: &PeerId,
        subject: &str,
    ) -> Result<PeerCredential, CredentialError> {
        self.asked
            .lock()
            .unwrap()
            .push((audience.to_string(), subject.to_owned()));
        if self.down {
            return Err(CredentialError::Unavailable {
                audience: audience.clone(),
                detail: "connection refused".into(),
            });
        }
        let bound_to = self.misbind_to.clone().unwrap_or_else(|| audience.clone());
        let named = self.misname_as.as_deref().unwrap_or(subject);
        let mut c = PeerCredential::for_subject(bound_to, named, token_for(named));
        if let Some(at) = self.expires_at {
            c = c.expiring_at(at);
        }
        Ok(c)
    }
}

/// A reviewer told who each call is for, holding the plane's own credential
/// beside its source.
fn subject_bound(issuer: &Arc<Issuer>) -> PeerRegistry {
    PeerRegistry::new().allow(
        reviewer(),
        PeerGrant::new(Scope::of(["audit.*"]))
            .read_only()
            .with_credential(
                &reviewer(),
                PeerCredential::for_audience(reviewer(), PLANE_TOKEN),
            )
            .with_source(Arc::new(Cached::new(
                Arc::clone(issuer) as Arc<dyn TokenExchange>
            ))),
    )
}

/// A plane wired to `registry`, acting for `user:hupe` as its own chain.
fn wired(registry: PeerRegistry, spy: &Arc<Spy>, skill: impl Skill + 'static) -> Arc<Runtime> {
    let store = store();
    Runtime::builder(store)
        .owner("peers")
        .acting_as(owner())
        .peers(registry, Arc::clone(spy) as Arc<dyn PeerClient>)
        .skill(skill)
        .build()
}

async fn run_for(
    rt: &Runtime,
    capability: &str,
    chain: Delegation,
) -> agentplane::runtime::RunOutcome {
    rt.run_under(
        capability,
        Tainted::trusted(json!({ "invoice": "INV-1" })),
        RunTerms::default().acting_as(chain),
    )
    .await
    .expect("admitted")
    .outcome()
    .cloned()
    .expect("fresh")
}

/// What each hop's announcement recorded about its credential.
async fn bindings(rt: &Runtime, run: agentplane::core::RunId) -> Vec<Option<CredentialBinding>> {
    rt.journal()
        .read(run, 1)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectStarted {
                descriptor,
                credential,
                ..
            } if descriptor.kind.starts_with("a2a.") => Some(credential.clone()),
            _ => None,
        })
        .collect()
}

fn sent_tokens(spy: &Spy) -> Vec<Option<String>> {
    spy.sent
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.1.clone())
        .collect()
}

/// **The peer sees who each call is for.** Two runs acting for different
/// people call one peer; the token endpoint is asked twice, once per person,
/// both times for that peer, and each call presents its own person's token.
#[tokio::test]
async fn a_peer_credential_names_the_run_s_subject() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(Some(ts(i64::from(u32::MAX))));
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);

    for chain in [alice(), bob()] {
        let out = run_for(&rt, "audit.review", chain).await;
        assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    }

    assert_eq!(
        issuer.asked.lock().unwrap().as_slice(),
        &[
            ("reviewer.example".to_owned(), "user:alice".to_owned()),
            ("reviewer.example".to_owned(), "user:bob".to_owned()),
        ],
        "each exchange must name the run's owner and the peer as audience"
    );
    assert_eq!(
        sent_tokens(&spy),
        vec![Some(token_for("user:alice")), Some(token_for("user:bob"))],
    );
}

/// **The binding is on the record, and the token is not.** A subject-bound
/// hop's announcement names its subject and audience; a hop to a peer holding
/// only a static credential says it named nobody; and no byte of any token is
/// anywhere in the journal.
#[tokio::test]
async fn a_subject_bound_hop_records_its_subject_and_audience() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);
    let out = run_for(&rt, "audit.review", alice()).await;
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(
        bindings(&rt, out.run_id).await,
        vec![Some(CredentialBinding::Subject {
            audience: "reviewer.example".into(),
            subject: "user:alice".into(),
        })],
    );

    let static_spy = Arc::new(Spy::default());
    let static_rt = wired(
        PeerRegistry::new().allow(
            reviewer(),
            PeerGrant::new(Scope::of(["audit.*"])).with_credential(
                &reviewer(),
                PeerCredential::for_audience(reviewer(), SECRET),
            ),
        ),
        &static_spy,
        AsksReviewer,
    );
    let unbound = run_for(&static_rt, "audit.review", alice()).await;
    assert!(
        matches!(unbound.status, RunStatus::Succeeded),
        "{unbound:?}"
    );
    assert_eq!(
        bindings(&static_rt, unbound.run_id).await,
        vec![Some(CredentialBinding::Unbound {
            audience: "reviewer.example".into(),
        })],
        "a static credential names nobody, and the record must say so"
    );

    for (rt, run) in [(&rt, out.run_id), (&static_rt, unbound.run_id)] {
        for r in &rt.journal().read(run, 1).await.unwrap() {
            let raw = String::from_utf8_lossy(r.raw());
            assert!(
                !raw.contains(SECRET),
                "a bearer token reached record {} ({}). The journal is permanent \
                 and hash-chained: this secret could never be redacted, only \
                 discovered.",
                r.seq(),
                r.kind().kind_str()
            );
        }
    }
}

/// The secret is presented to the peer and appears nowhere in history.
///
/// This is the test the whole credential design exists for. The journal is
/// append-only, hash-chained and permanent: a bearer token written into an
/// `EffectDone` record cannot be redacted later, because the record's hash covers
/// it and the chain would break. So the check is not "did we remember to omit
/// it" — it is a scan of every byte the run wrote, after a hop that obtained a
/// credential for its subject.
#[tokio::test]
async fn a_credential_is_presented_to_the_peer_and_never_written_to_the_journal() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(Some(ts(i64::from(u32::MAX))));
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);
    let out = run_for(&rt, "audit.review", alice()).await;
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");

    // It really was presented.
    assert_eq!(
        sent_tokens(&spy),
        vec![Some(token_for("user:alice"))],
        "the peer must actually receive the credential, or this test proves \
         nothing about keeping it out of the journal"
    );

    // And it is nowhere in the record.
    let records = rt.journal().read(out.run_id, 1).await.unwrap();
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

/// **A replay reaches no token endpoint.** The credential is obtained when
/// the call is performed, which a replay never does.
#[tokio::test]
async fn replay_calls_no_token_endpoint() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);
    let out = run_for(&rt, "audit.review", alice()).await;
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(issuer.exchanges(), 1);

    let replayed = rt.replay(out.run_id, Mode::Strict).await.expect("replays");
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "{replayed:?}"
    );
    assert_eq!(
        issuer.exchanges(),
        1,
        "a strict replay asked the token endpoint for a credential"
    );
    assert_eq!(spy.sent.lock().unwrap().len(), 1);
}

/// **An issuer that names somebody else is not taken at its word.** The
/// credential is refused before anything leaves, as one for another audience
/// is.
#[tokio::test]
async fn a_credential_for_another_subject_is_refused_before_the_call() {
    let spy = Arc::new(Spy::default());
    let issuer = Arc::new(Issuer {
        misname_as: Some("user:mallory".into()),
        ..Issuer::default()
    });
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);
    let out = run_for(&rt, "audit.review", alice()).await;
    assert!(
        matches!(&out.status, RunStatus::Failed(reason)
            if reason.contains("'user:mallory'") && reason.contains("'user:alice'")),
        "{out:?}"
    );
    assert!(
        spy.sent.lock().unwrap().is_empty(),
        "a credential naming somebody else was presented"
    );
}

/// **An issuer outage is a refusal, not doubt.** Nothing was sent, so the
/// call failed cleanly rather than leaving the run in doubt about a call
/// that never left.
#[tokio::test]
async fn an_issuer_outage_fails_the_call_without_doubt() {
    let spy = Arc::new(Spy::default());
    let issuer = Arc::new(Issuer {
        down: true,
        ..Issuer::default()
    });
    // Mutating and operator-resolved, so a call in doubt would quarantine.
    let registry = PeerRegistry::new().allow(
        reviewer(),
        PeerGrant::new(Scope::of(["audit.*"])).with_source(Arc::new(Cached::new(
            Arc::clone(&issuer) as Arc<dyn TokenExchange>,
        ))),
    );
    let rt = wired(registry, &spy, AsksReviewer);
    let out = run_for(&rt, "audit.review", alice()).await;
    assert!(
        matches!(&out.status, RunStatus::Failed(reason) if reason.contains("connection refused")),
        "an outage before the call is not a call in doubt: {out:?}"
    );
    let failed: Vec<Disposition> = rt
        .journal()
        .read(out.run_id, 1)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| match r.kind() {
            RecordKind::EffectFailed { disposition, .. } => Some(*disposition),
            _ => None,
        })
        .collect();
    assert_eq!(failed, vec![Disposition::DidNotHappen]);
    assert!(spy.sent.lock().unwrap().is_empty(), "nothing may have left");
}

/// A skill that asks the reviewer, then polls a task there.
#[derive(Debug)]
struct AsksThenPolls;

#[async_trait::async_trait]
impl Skill for AsksThenPolls {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("audit.poll").provides("audit.poll")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        if cx.acting_as().is_some() {
            cx.call_peer(&reviewer(), "audit.check", &input).await?;
        }
        let snapshot = cx
            .peer_task(PeerTask {
                peer: reviewer(),
                id: "remote-task-42".to_owned(),
                context_id: None,
            })
            .await?;
        Ok(Outcome::done(snapshot.map(|s| {
            serde_json::to_value(s).expect("task snapshot serializes")
        })))
    }
}

/// **A task read presents the same person's credential as its call.** The
/// read reaches the same peer, and a read under the plane's credential would
/// tell the peer nobody asked.
#[tokio::test]
async fn a_remote_task_poll_names_the_same_subject_as_its_call() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let rt = wired(subject_bound(&issuer), &spy, AsksThenPolls);
    let out = run_for(&rt, "audit.poll", alice()).await;
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(sent_tokens(&spy), vec![Some(token_for("user:alice"))]);
    assert_eq!(
        spy.task_reads.lock().unwrap()[0].2.as_deref(),
        Some(token_for("user:alice").as_str()),
        "the task read did not present the run's owner's credential"
    );
    assert_eq!(
        issuer.exchanges(),
        1,
        "the read reuses the call's credential"
    );
}

/// **A run that acts for nobody is refused a subject-bound peer** — never
/// served with the credential held beside the source. A served caller that
/// presented no chain acts under none, whatever the plane's own chain is.
#[tokio::test]
async fn a_chainless_served_run_is_refused_a_subject_bound_peer() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let rt = wired(subject_bound(&issuer), &spy, AsksThenPolls);
    let out = rt
        .run_under(
            "audit.poll",
            Tainted::trusted(json!({})),
            RunTerms::default().served(None),
        )
        .await
        .expect("admitted")
        .outcome()
        .cloned()
        .expect("fresh");
    assert!(
        matches!(&out.status, RunStatus::Failed(reason) if reason.contains("acts for nobody")),
        "{out:?}"
    );
    assert!(
        spy.task_reads.lock().unwrap().is_empty(),
        "a run acting for nobody reached the peer under the plane's credential"
    );
    assert_eq!(issuer.exchanges(), 0);
}

/// **A run admitted as the plane presents the plane's own credential,** and
/// the record says the plane asked — never a credential naming the plane's
/// owner as if that person had.
#[tokio::test]
async fn a_run_admitted_as_the_plane_presents_no_subject_bound_credential() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let rt = wired(subject_bound(&issuer), &spy, AsksReviewer);
    let out = rt
        .run("audit.review", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(issuer.exchanges(), 0, "the plane's owner was exchanged for");
    assert_eq!(sent_tokens(&spy), vec![Some(PLANE_TOKEN.to_owned())]);
    assert_eq!(
        bindings(&rt, out.run_id).await,
        vec![Some(CredentialBinding::Plane {
            audience: "reviewer.example".into(),
        })],
    );

    // Without a credential of its own for the peer, the plane's run is
    // refused rather than served one naming its owner.
    let bare = Arc::new(Spy::default());
    let rt = wired(
        PeerRegistry::new().allow(
            reviewer(),
            PeerGrant::new(Scope::of(["audit.*"]))
                .with_source(Arc::new(Cached::new(
                    Arc::clone(&issuer) as Arc<dyn TokenExchange>
                ))),
        ),
        &bare,
        AsksReviewer,
    );
    let refused = rt
        .run("audit.review", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    assert!(
        matches!(&refused.status, RunStatus::Failed(reason) if reason.contains("plane's own")),
        "{refused:?}"
    );
    assert!(bare.sent.lock().unwrap().is_empty());
    assert_eq!(issuer.exchanges(), 0);
}

/// Asks the reviewer, withdraws its own owner once, and asks again.
#[derive(Debug)]
struct AsksAcrossAWithdrawal(Arc<dyn QuotaStore>, std::sync::atomic::AtomicBool);

#[async_trait::async_trait]
impl Skill for AsksAcrossAWithdrawal {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("audit.twice").provides("audit.twice")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.call_peer(&reviewer(), "audit.check", &input).await?;
        // Thrown once, from inside the step, so the second hop is in a step
        // that began before the halt.
        if !self.1.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.0
                .set_halt(
                    &HaltScope::subject("user:alice"),
                    &agentplane::core::Operator::asserted("ops").expect("operator"),
                    ts(1_700_000_000),
                    "credential withdrawn: laptop lost",
                )
                .await
                .expect("withdraw mid-step");
        }
        let answer = cx.call_peer(&reviewer(), "audit.check", &input).await?;
        Ok(Outcome::done(answer))
    }
}

/// **A withdrawn owner's credential is not presented — not even one already
/// held, inside a step begun before the halt.** The hop is refused before it
/// is announced, the held credential is dropped, and the run is paused as a
/// withdrawal at a step boundary pauses it. Lifted, the run continues and the
/// hop exchanges afresh; a strict replay then reads the continuation.
#[tokio::test]
async fn a_withdrawn_subjects_credential_is_not_presented() {
    let spy = Arc::new(Spy::default());
    let issuer = Issuer::new(None);
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .owner("peers")
        .quota(
            Arc::clone(&store) as Arc<dyn QuotaStore>,
            TenantQuota::default(),
        )
        .peers(
            subject_bound(&issuer),
            Arc::clone(&spy) as Arc<dyn PeerClient>,
        )
        .skill(AsksAcrossAWithdrawal(
            Arc::clone(&store) as Arc<dyn QuotaStore>,
            std::sync::atomic::AtomicBool::new(false),
        ))
        .build();
    let out = run_for(&rt, "audit.twice", alice()).await;

    match &out.status {
        RunStatus::Withheld { subject, reason } => {
            assert_eq!(subject, "user:alice");
            assert!(reason.contains("laptop lost"), "{reason}");
        }
        other => panic!("a withdrawn owner's credential went on being presented: {other:?}"),
    }
    assert_eq!(
        spy.sent.lock().unwrap().len(),
        1,
        "the hop after the halt reached the peer"
    );
    assert_eq!(issuer.exchanges(), 1, "the refused hop exchanged");
    assert_eq!(
        bindings(&rt, out.run_id).await.len(),
        1,
        "the refused hop was announced"
    );

    rt.lift_halt(
        &HaltScope::subject("user:alice"),
        &agentplane::core::Operator::asserted("ops").expect("operator"),
        ts(1_700_000_100),
    )
    .await
    .expect("lift");
    let resumed = rt.replay(out.run_id, Mode::Resume).await.expect("resumes");
    assert!(
        matches!(resumed.status, RunStatus::Succeeded),
        "{resumed:?}"
    );
    assert_eq!(spy.sent.lock().unwrap().len(), 2);
    assert_eq!(
        issuer.exchanges(),
        2,
        "the withdrawn owner's credential was still held after the halt"
    );

    let replayed = rt.replay(out.run_id, Mode::Strict).await.expect("replays");
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "a strict replay stopped at the superseded withholding: {replayed:?}"
    );
    assert_eq!(spy.sent.lock().unwrap().len(), 2);
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
            Asker::Nobody,
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
        Asker::Nobody,
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

// ── Freshness and the cache ─────────────────────────────────────────────────

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
        .credential(&reviewer(), "user:alice", ts(1_000))
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
            .credential(&reviewer(), "user:alice", ts(1_000))
            .await
            .expect("usable");
    }
    assert_eq!(
        issuer.exchanges(),
        1,
        "a token endpoint is not free, and re-exchanging per call is how one gets \
         rate-limited at the worst moment"
    );
}

/// **The cache never lends one person's credential to another.** Interleaved
/// requests for two subjects at one audience each get their own, and each is
/// still reused for its own subject.
#[tokio::test]
async fn a_cached_credential_is_never_lent_to_another_subject() {
    let issuer = Issuer::new(Some(ts(9_999)));
    let cached = Cached::new(Arc::clone(&issuer) as Arc<dyn TokenExchange>);

    for subject in ["user:alice", "user:bob", "user:alice", "user:bob"] {
        let c = cached
            .credential(&reviewer(), subject, ts(1_000))
            .await
            .expect("usable");
        assert_eq!(
            c.subject(),
            Some(subject),
            "a credential obtained for one person was presented for another"
        );
    }
    assert_eq!(issuer.exchanges(), 2, "one exchange per person");

    cached.forget("user:alice");
    cached
        .credential(&reviewer(), "user:bob", ts(1_000))
        .await
        .expect("usable");
    cached
        .credential(&reviewer(), "user:alice", ts(1_000))
        .await
        .expect("usable");
    assert_eq!(
        issuer.exchanges(),
        3,
        "forgetting one person dropped exactly their credential"
    );
}

/// An issuer that ignores `resource` is not taken at its word.
#[tokio::test]
async fn a_token_bound_to_the_wrong_audience_is_refused() {
    let issuer = Arc::new(Issuer {
        expires_at: Some(ts(9_999)),
        misbind_to: Some(settlement()),
        ..Issuer::default()
    });
    let cached = Cached::new(issuer as Arc<dyn TokenExchange>);

    let err = cached
        .credential(&reviewer(), "user:alice", ts(1_000))
        .await
        .expect_err("the issuer bound it to settlement");
    assert!(
        matches!(err, CredentialError::WrongAudience { .. }),
        "an issuer that ignores the resource indicator hands back a token the \
         peer can spend elsewhere: {err:?}"
    );
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

// ── The grant is a ceiling on what may be asked ─────────────────────────────

/// A capability the registry never granted the peer never leaves: the peer's
/// admission would refuse it anyway, and a round trip that ends in the far
/// side's journal as *their* decline is the wrong place for this plane's
/// misconfiguration to surface.
#[test]
fn a_capability_outside_the_peers_grant_never_leaves() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.*"])));
    let err = PeerCall::prepare(
        &registry,
        Arc::clone(&spy) as Arc<dyn PeerClient>,
        &auditor(),
        reviewer(),
        "billing.transfer",
        json!({}),
    )
    .expect_err("outside the grant");
    assert!(
        matches!(&err, PeerError::NotGranted { capability, .. } if capability == "billing.transfer"),
        "{err:?}"
    );
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert!(spy.sent.lock().unwrap().is_empty(), "nothing may have left");

    // Inside the grant, the same call is prepared — the refusal above is the
    // scope rule and not the fixture.
    PeerCall::prepare(
        &registry,
        spy as Arc<dyn PeerClient>,
        &auditor(),
        reviewer(),
        "audit.check",
        json!({}),
    )
    .expect("inside the grant");
}

/// A router reaches exactly the peers it routes; an unrouted peer is a
/// refusal that never left, not a guess at the nearest endpoint.
#[tokio::test]
async fn a_peer_router_reaches_only_the_peers_it_routes() {
    let spy = Arc::new(Spy::default());
    let router = PeerRouter::new().peer(reviewer(), Arc::clone(&spy) as Arc<dyn PeerClient>);
    router
        .send(
            &reviewer(),
            "audit.check",
            &json!({}),
            &auditor(),
            None,
            None,
        )
        .await
        .expect("routed");
    let err = router
        .send(
            &settlement(),
            "audit.check",
            &json!({}),
            &auditor(),
            None,
            None,
        )
        .await
        .expect_err("not routed");
    assert!(
        matches!(err, PeerError::Unreachable { .. }),
        "an unrouted peer must read as unreachable, not as a fault: {err:?}"
    );
    assert_eq!(err.disposition(), Disposition::DidNotHappen);
    assert_eq!(
        spy.sent.lock().unwrap().len(),
        1,
        "only the routed call arrived"
    );
}

// ── Reached from a run ───────────────────────────────────────────────────────

/// A skill that consults the reviewer through the plane's own wiring.
#[derive(Debug)]
struct AsksReviewer;

#[async_trait::async_trait]
impl Skill for AsksReviewer {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("audit.review").provides("audit.review")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let answer = cx.call_peer(&reviewer(), "audit.check", &input).await?;
        Ok(Outcome::done(answer))
    }
}

fn store() -> Arc<dyn JournalStore> {
    Arc::new(RedbStore::open_in_memory().unwrap())
}

/// The chain a peer receives is the **run's**, one link longer — the caller's
/// chain on a served plane, never one the skill holds — and a strict replay
/// reads the answer back without a request leaving.
#[tokio::test]
async fn a_skill_calls_a_peer_under_the_runs_chain_and_replay_calls_nobody() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.*"])));
    let rt = Runtime::builder(store())
        .owner("peers")
        // The plane's own chain is somebody else, so a hop that used it
        // instead of the run's is visible.
        .acting_as(owner())
        .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
        .skill(AsksReviewer)
        .build();
    let alice = Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));

    let out = rt
        .run_under(
            "audit.review",
            Tainted::trusted(json!({ "invoice": "INV-9" })),
            RunTerms::default().acting_as(alice),
        )
        .await
        .expect("admitted")
        .outcome()
        .cloned()
        .expect("fresh");
    assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    assert_eq!(
        spy.chains.lock().unwrap().as_slice(),
        &[vec!["user:alice".to_owned(), "reviewer.example".to_owned()]],
        "the peer must receive the run's chain plus one link naming it"
    );
    let answer = out.output.as_ref().expect("an answer");
    assert!(
        format!("{:?}", answer.label()).contains("tool://reviewer.example/audit.check"),
        "the answer's provenance must name this peer, so a source rule can: {:?}",
        answer.label()
    );

    let replayed = rt.replay(out.run_id, Mode::Strict).await.expect("replays");
    assert!(
        matches!(replayed.status, RunStatus::Succeeded),
        "{replayed:?}"
    );
    assert_eq!(
        spy.sent.lock().unwrap().len(),
        1,
        "a strict replay sent a request to the peer"
    );
}

/// A run acting under no chain has nothing to extend toward a peer, and is
/// refused rather than sent out as nobody.
#[tokio::test]
async fn a_peer_call_without_a_chain_is_refused() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.*"])));
    let rt = Runtime::builder(store())
        .owner("peers")
        .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
        .skill(AsksReviewer)
        .build();
    let out = rt
        .run("audit.review", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    assert!(
        matches!(&out.status, RunStatus::Failed(reason) if reason.contains("acts under no chain")),
        "{out:?}"
    );
    assert!(spy.sent.lock().unwrap().is_empty(), "nothing may have left");
}

// ── Declared in a manifest ──────────────────────────────────────────────────

#[cfg(feature = "manifest")]
mod declared {
    use super::*;
    use agentplane::manifest::Manifest;
    use agentplane::runtime::{Agent, BuildError};

    const ASKS_REVIEWER: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  identity:
    role: "Consult the reviewer, then answer."
  topology:
    mode: collaborative
    role: orchestrator
    reason: distinct-authority
  security:
    max_delegation_depth: 1
    max_sensitivity_egress: internal
  capabilities: { provides: [desk.answer] }
  models: { privileged: { provider: fake, model: desk-1 } }
  tools:
    - ref: tool://reviewer/audit.check
      mutates: false
      max_sensitivity: internal
      description: Ask the reviewer to check an invoice.
      arguments:
        type: object
        additionalProperties: false
        properties:
          invoice: { type: string }
        required: [invoice]
  execution: { kind: tool-calling, max_turns: 4 }
  budgets: {}
"#;

    /// A chain whose scope covers the desk's own capability and the hop —
    /// rooted at the desk's owner, so the one hop the manifest permits
    /// (`max_delegation_depth: 1`) is the peer.
    fn desk() -> Delegation {
        Delegation::root(Principal::new(
            "user:desk",
            Scope::of(["desk.*", "audit.*"]),
        ))
    }

    fn desk_plane(
        manifest: &Manifest,
        spy: &Arc<Spy>,
        chain: Delegation,
    ) -> (Arc<Runtime>, Arc<agentplane::testkit::FakeProvider>) {
        let provider = agentplane::testkit::FakeProvider::new();
        // The wiring's own ceiling admits the model's arguments, so what
        // refuses a call below is the manifest grant and nothing else.
        let mut grant = PeerGrant::new(Scope::of(["audit.*"])).read_only();
        grant.max_sensitivity = agentplane::core::Sensitivity::Internal;
        let registry = PeerRegistry::new().allow(PeerId::new("reviewer"), grant);
        let rt = Runtime::builder(store())
            .owner("peers")
            .acting_as(chain)
            .provider(
                "fake",
                Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
            )
            .peers(registry, Arc::clone(spy) as Arc<dyn PeerClient>)
            .agent(Agent::new(manifest))
            .build();
        (rt, provider)
    }

    /// A manifest grant naming a registered peer dispatches to it — no toolbox,
    /// no transport — and the hop rides the run's chain like a coded one.
    #[tokio::test]
    async fn a_declared_peer_grant_dispatches_to_the_peer_and_replay_calls_nobody() {
        let manifest = Manifest::parse(ASKS_REVIEWER).expect("parses");
        let spy = Arc::new(Spy::default());
        let (rt, provider) = desk_plane(&manifest, &spy, desk());
        provider.will_call_tool(
            "call_1",
            "reviewer__audit-check",
            json!({ "invoice": "INV-9" }),
        );
        provider.will_say("The reviewer approved INV-9.");

        let out = rt
            .run(
                "desk.answer",
                Tainted::trusted(json!({ "invoice": "INV-9" })),
            )
            .await
            .expect("run");
        assert!(
            matches!(out.status, RunStatus::Succeeded),
            "{:?}",
            out.status
        );
        assert_eq!(
            spy.chains.lock().unwrap().as_slice(),
            &[vec!["user:desk".to_owned(), "reviewer".to_owned()]],
            "the declared hop must extend the run's chain by the peer; the model was told {:?}",
            provider
                .asked()
                .get(1)
                .map(|a| a.exchanges[0].output.clone())
        );
        let asked = provider.asked();
        assert_eq!(asked.len(), 2);
        assert!(
            asked[1].exchanges[0]
                .output
                .to_string()
                .contains("reviewed"),
            "the peer's answer did not reach the next turn: {:?}",
            asked[1].exchanges[0].output
        );

        let replayed = rt.replay(out.run_id, Mode::Strict).await.expect("replay");
        assert!(
            matches!(replayed.status, RunStatus::Succeeded),
            "{replayed:?}"
        );
        assert_eq!(
            spy.sent.lock().unwrap().len(),
            1,
            "strict replay called the peer"
        );
        assert_eq!(provider.asked().len(), 2, "strict replay called the model");
    }

    /// **A manifest grant cannot widen the wiring's ceiling.** The registry
    /// entry is the operator's statement of what may reach that peer; the
    /// reviewed grant may only tighten it, as it may for a tool.
    #[tokio::test]
    async fn a_manifest_grant_cannot_widen_the_wirings_peer_ceiling() {
        let manifest = Manifest::parse(ASKS_REVIEWER).expect("parses");
        let spy = Arc::new(Spy::default());
        let provider = agentplane::testkit::FakeProvider::new();
        // The wiring left at its default ceiling, below the manifest grant's.
        let grant = PeerGrant::new(Scope::of(["audit.*"])).read_only();
        let registry = PeerRegistry::new().allow(PeerId::new("reviewer"), grant);
        let rt = Runtime::builder(store())
            .owner("peers")
            .acting_as(desk())
            .provider(
                "fake",
                Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
            )
            .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
            .agent(Agent::new(&manifest))
            .build();
        provider.will_call_tool(
            "call_1",
            "reviewer__audit-check",
            json!({ "invoice": "INV-9" }),
        );
        provider.will_say("Could not consult the reviewer.");

        let _ = rt
            .run(
                "desk.answer",
                Tainted::trusted(json!({ "invoice": "INV-9" })),
            )
            .await
            .expect("run");
        assert!(
            spy.sent.lock().unwrap().is_empty(),
            "the manifest grant's ceiling replaced the wiring's, and data above \
             what the operator allowed reached the peer"
        );
    }

    /// The grant's own fields govern the hop: a protected field the model's
    /// untrusted completion cannot satisfy refuses the call at the sink, and
    /// nothing reaches the peer.
    #[tokio::test]
    async fn a_declared_peer_grants_protected_fields_govern_the_hop() {
        let guarded = ASKS_REVIEWER.replace(
            "      mutates: false\n",
            "      mutates: true\n      protected_fields: [{ path: /invoice, require_trusted: true }]\n",
        );
        let manifest = Manifest::parse(&guarded).expect("parses");
        let spy = Arc::new(Spy::default());
        let (rt, provider) = desk_plane(&manifest, &spy, desk());
        provider.will_call_tool(
            "call_1",
            "reviewer__audit-check",
            json!({ "invoice": "INV-9" }),
        );
        provider.will_say("I could not reach the reviewer.");

        let out = rt
            .run(
                "desk.answer",
                Tainted::trusted(json!({ "invoice": "INV-9" })),
            )
            .await
            .expect("run");
        assert!(
            matches!(out.status, RunStatus::Succeeded),
            "{:?}",
            out.status
        );
        assert!(
            spy.sent.lock().unwrap().is_empty(),
            "a model-chosen value reached a protected field on a peer hop"
        );
        let asked = provider.asked();
        assert!(
            asked[1].exchanges[0]
                .output
                .to_string()
                .contains(agentplane::core::REFUSED),
            "the model was not told the call was refused: {:?}",
            asked[1].exchanges[0].output
        );
    }

    const CODED_DESK: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  identity:
    role: "A coded desk that grants no peer."
  topology:
    mode: collaborative
    role: orchestrator
    reason: distinct-authority
  security:
    max_delegation_depth: 1
  capabilities: { provides: [audit.review] }
  budgets: {}
"#;

    /// A governed skill reaches a peer only through a grant its manifest
    /// carries, exactly as it reaches a tool: the registry is wiring, and a
    /// hop the reviewed document never listed is authority nobody granted.
    #[tokio::test]
    async fn a_governed_skill_cannot_call_a_peer_its_manifest_never_granted() {
        let manifest = Manifest::parse(CODED_DESK).expect("parses");
        let spy = Arc::new(Spy::default());
        let registry =
            PeerRegistry::new().allow(reviewer(), PeerGrant::new(Scope::of(["audit.*"])));
        let rt = Runtime::builder(store())
            .owner("peers")
            .acting_as(desk())
            .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
            .agent(Agent::new(&manifest).skill(AsksReviewer))
            .build();
        let out = rt
            .run(
                "audit.review",
                Tainted::trusted(json!({ "invoice": "INV-9" })),
            )
            .await
            .expect("admitted");
        assert!(
            matches!(&out.status, RunStatus::Failed(reason) if reason.contains("does not grant")),
            "{out:?}"
        );
        assert!(spy.sent.lock().unwrap().is_empty(), "nothing may have left");
    }

    /// The three wiring mistakes a peer grant can carry are refused at build.
    #[tokio::test]
    async fn a_peer_grant_the_plane_cannot_honour_refuses_the_build() {
        let manifest = Manifest::parse(ASKS_REVIEWER).expect("parses");
        let spy = Arc::new(Spy::default());
        let provider = agentplane::testkit::FakeProvider::new();
        let plane = |registry: PeerRegistry| {
            Runtime::builder(store())
                .owner("peers")
                .acting_as(desk())
                .provider(
                    "fake",
                    Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
                )
                .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
        };

        // The registry never granted the capability the manifest asks for.
        let err = plane(PeerRegistry::new().allow(
            PeerId::new("reviewer"),
            PeerGrant::new(Scope::of(["billing.*"])),
        ))
        .agent(Agent::new(&manifest))
        .try_build()
        .expect_err("outside the registry scope");
        assert!(
            matches!(&err, BuildError::PeerGrantOutsideScope { peer, capability, .. }
                if peer == "reviewer" && capability == "audit.check"),
            "{err}"
        );

        // The peer's name is also a wired tool server.
        let err = plane(PeerRegistry::new().allow(
            PeerId::new("reviewer"),
            PeerGrant::new(Scope::of(["audit.*"])),
        ))
        .tool_server(
            "reviewer",
            Arc::new(agentplane::tools::ToolRouter::new())
                as Arc<dyn agentplane::tools::ToolClient>,
        )
        .agent(Agent::new(&manifest))
        .try_build()
        .expect_err("one name, two meanings");
        assert!(
            matches!(&err, BuildError::PeerIsAlsoAToolServer { server } if server == "reviewer"),
            "{err}"
        );

        // A specialist may not delegate, and a peer hop is delegation.
        let specialist = ASKS_REVIEWER
            .replace("role: orchestrator", "role: specialist")
            .replace("    max_delegation_depth: 1\n", "");
        let specialist = Manifest::parse(&specialist).expect("parses");
        let err = plane(PeerRegistry::new().allow(
            PeerId::new("reviewer"),
            PeerGrant::new(Scope::of(["audit.*"])),
        ))
        .agent(Agent::new(&specialist))
        .try_build()
        .expect_err("a specialist granting a peer");
        assert!(
            matches!(&err, BuildError::PeerGrantOnASpecialist { peer, .. } if peer == "reviewer"),
            "{err}"
        );

        // The baseline builds, so the refusals above are the rules and not the
        // fixture.
        plane(PeerRegistry::new().allow(
            PeerId::new("reviewer"),
            PeerGrant::new(Scope::of(["audit.*"])),
        ))
        .agent(Agent::new(&manifest))
        .try_build()
        .expect("a coherent peer grant builds");
    }
}

/// A skill reaching a peer task through the `StepCtx` wrappers rather than by
/// building the effect itself.
#[derive(Debug)]
struct UsesTheWrappers {
    cancel: bool,
}

#[async_trait::async_trait]
impl Skill for UsesTheWrappers {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("wrappers").provides("peer.wrappers")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let task = PeerTask {
            peer: reviewer(),
            id: "remote-task-42".to_owned(),
            context_id: Some("matter-1".to_owned()),
        };
        let snapshot = if self.cancel {
            cx.cancel_peer_task(task).await?
        } else {
            cx.peer_task(task).await?
        };
        Ok(Outcome::done(snapshot.map(|value| {
            serde_json::to_value(value).expect("task snapshot serializes")
        })))
    }
}

/// **The peer-task wrappers refuse when no peers are wired, rather than at the
/// socket.**
///
/// `cx.peer_task` and `cx.cancel_peer_task` are the surface an embedder writes
/// against, and the effects underneath them are covered elsewhere. What is only
/// theirs is the wiring lookup: a plane built without `.peers(..)` has no
/// registry and no client, and the documented answer is a refusal before
/// anything is dispatched. The failure this rules out is a wrapper that reaches
/// dispatch with nothing behind it and surfaces as a transport error, which
/// classifies as *in doubt* and sends an operator looking for a network.
#[tokio::test]
async fn the_peer_task_wrappers_refuse_a_plane_with_no_peers() {
    for cancel in [false, true] {
        let rt = Runtime::builder(store())
            .owner("peers")
            .skill(UsesTheWrappers { cancel })
            .build();
        let out = rt
            .run("peer.wrappers", Tainted::trusted(json!({})))
            .await
            .expect("the run is admitted; the refusal is inside the step");
        assert!(
            matches!(out.status, RunStatus::Failed(_)),
            "a plane with no peers wired must refuse the call, not attempt it \
             (cancel = {cancel}): {:?}",
            out.status
        );
    }
}

/// **And with peers wired they dispatch through the registry to the client.**
///
/// The positive half, so the test above cannot pass by the wrappers being
/// broken in every configuration. The two verbs end differently here and both
/// endings are the point: the read reaches the peer and succeeds, and the
/// cancel reaches the peer and is refused *by the transport* — a refusal that
/// can only be produced past the wiring lookup, which is the step being tested.
#[tokio::test]
async fn the_peer_task_wrappers_dispatch_through_the_registry() {
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(
        reviewer(),
        PeerGrant::new(Scope::of(["audit.check"])).read_only(),
    );
    let rt = Runtime::builder(store())
        .owner("peers")
        .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
        .skill(UsesTheWrappers { cancel: false })
        .build();

    let out = rt
        .run("peer.wrappers", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    assert_eq!(
        out.status,
        RunStatus::Succeeded,
        "cx.peer_task did not reach the peer"
    );
    assert_eq!(
        spy.task_reads.lock().unwrap().len(),
        1,
        "exactly one peer task read left the plane"
    );

    // The cancel wrapper, against a transport that does not offer cancellation.
    let spy = Arc::new(Spy::default());
    let registry = PeerRegistry::new().allow(
        reviewer(),
        PeerGrant::new(Scope::of(["audit.check"])).read_only(),
    );
    let rt = Runtime::builder(store())
        .owner("peers")
        .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
        .skill(UsesTheWrappers { cancel: true })
        .build();
    let out = rt
        .run("peer.wrappers", Tainted::trusted(json!({})))
        .await
        .expect("admitted");
    let RunStatus::Failed(reason) = &out.status else {
        panic!("expected the transport's refusal, got {:?}", out.status);
    };
    assert!(
        reason.contains("does not support task cancellation"),
        "cx.cancel_peer_task did not reach the transport — this refusal is only \
         reachable past the wiring lookup: {reason}"
    );
}

/// **A task at a peer the declaration never granted is refused.** A task
/// handle names a peer and a skill may build one for any peer the plane can
/// reach, so reading or cancelling one is held to the declaration like a call.
#[cfg(feature = "manifest")]
#[tokio::test]
async fn a_task_at_an_ungranted_peer_is_refused_by_the_declaration() {
    use agentplane::manifest::Manifest;
    use agentplane::runtime::Agent;

    let manifest = Manifest::parse(
        r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: wrappers, version: "1.0.0" }
spec:
  capabilities: { provides: [peer.wrappers] }
  tools:
    - ref: tool://settlement/pay.check
      mutates: false
      description: Another peer altogether.
  budgets: {}
"#,
    )
    .expect("parses");
    for cancel in [false, true] {
        let spy = Arc::new(Spy::default());
        let registry = PeerRegistry::new()
            .allow(
                reviewer(),
                PeerGrant::new(Scope::of(["audit.check"])).read_only(),
            )
            .allow(
                PeerId::new("settlement"),
                PeerGrant::new(Scope::of(["pay.*"])).read_only(),
            );
        let rt = Runtime::builder(store())
            .owner("peers")
            .peers(registry, Arc::clone(&spy) as Arc<dyn PeerClient>)
            .agent(Agent::new(&manifest).skill(UsesTheWrappers { cancel }))
            .build();
        let out = rt
            .run("peer.wrappers", Tainted::trusted(json!({})))
            .await
            .expect("admitted");
        assert!(
            !matches!(out.status, RunStatus::Succeeded),
            "a task at an ungranted peer was reached (cancel = {cancel})"
        );
        assert!(
            spy.task_reads.lock().unwrap().is_empty(),
            "the declaration did not stop the task read before the transport (cancel = {cancel})"
        );
        let denied = rt
            .journal()
            .read(out.run_id, 1)
            .await
            .unwrap()
            .iter()
            .any(|r| matches!(r.kind(), RecordKind::PolicyDenied { action, .. } if action == "effect:declared"));
        assert!(
            denied,
            "the refusal is not the declaration's (cancel = {cancel})"
        );
    }
}

/// **A peer wired from its manifest grants carries their ceiling.**
///
/// A call is held to the lower of the wiring's ceiling and its own grant's, so
/// a wiring left at the default would refuse every call its reviewed grant
/// allows — the peer is never asked, and the model is told only that the call
/// was refused.
#[cfg(feature = "manifest")]
#[test]
fn a_peer_wired_from_its_grants_carries_their_ceiling() {
    let grant = |reference: &str, mutates: bool, ceiling: &str| {
        serde_json::from_value::<agentplane::manifest::ToolGrant>(json!({
            "ref": reference, "mutates": mutates, "max_sensitivity": ceiling,
        }))
        .unwrap()
    };
    let check = grant("tool://reviewer/audit.check", false, "internal");
    let file = grant("tool://reviewer/audit.file", false, "confidential");
    let wired = PeerGrant::from_grants([
        ("audit.check".to_owned(), &check),
        ("audit.file".to_owned(), &file),
    ]);
    assert_eq!(
        wired.max_sensitivity,
        agentplane::core::Sensitivity::Confidential
    );
    assert!(!wired.mutates, "every grant said mutates: false");

    let writes = grant("tool://reviewer/audit.fix", true, "internal");
    let wired = PeerGrant::from_grants([
        ("audit.check".to_owned(), &check),
        ("audit.fix".to_owned(), &writes),
    ]);
    assert!(wired.mutates, "one mutating grant keeps the peer mutating");
    assert_eq!(
        wired.max_sensitivity,
        agentplane::core::Sensitivity::Internal
    );
}
