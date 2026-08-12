#![cfg(all(feature = "push", feature = "redb"))]

//! Outbound delivery to a destination the **deployment** chose.
//!
//! # The mirror image of push, and why it needed to exist
//!
//! A2A push is caller-shaped: the URL comes from whoever created the task, which
//! is why three controls exist around it. The shape a service needs beside it is
//! the mirror — one destination the operator configured, one payload the
//! embedder shapes, for every run. Without it a service emits its result event
//! at request time with retries and drops it on failure, which is the one
//! outbound path with no persist-before-dispatch in a system whose whole
//! argument is that the journal is the plan of record.
//!
//! So the property under test throughout is: **the run's own history is the
//! outbox.** Nothing is queued beside it, the cursor advances only on 2xx, and a
//! receiver that was down for the whole run catches up from sequence one.

use std::sync::{Arc, Mutex};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::push::{
    Delivered, DeliveryWorker, Destination, Outbox, PushConfig, PushError, PushStore,
    PushTransport, RunCompleted,
};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Records what it was asked to deliver, and can be told to fail.
#[derive(Debug, Default)]
struct Recording {
    payloads: Mutex<Vec<(String, Value)>>,
    failures: Mutex<u32>,
}

impl Recording {
    fn fail_next(&self, n: u32) {
        *self.failures.lock().unwrap() = n;
    }
    fn seen(&self) -> Vec<(String, Value)> {
        self.payloads.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PushTransport for Recording {
    fn validate(&self, _config: &PushConfig) -> Result<(), PushError> {
        Ok(())
    }

    async fn deliver(&self, config: &PushConfig, payload: &Value) -> Result<Delivered, PushError> {
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures -= 1;
            return Ok(Delivered::Unreachable("the bus is restarting".to_owned()));
        }
        drop(failures);
        self.payloads
            .lock()
            .unwrap()
            .push((config.id.clone(), payload.clone()));
        Ok(Delivered::Accepted)
    }
}

#[derive(Debug)]
struct Answers;

#[async_trait::async_trait]
impl Skill for Answers {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("answers").provides("answer")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

struct Fixture {
    rt: Arc<Runtime>,
    store: Arc<RedbStore>,
    transport: Arc<Recording>,
}

fn fixture(destinations: Vec<Destination>) -> Fixture {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let outbox = Arc::new(Outbox::new(
        Arc::clone(&store) as Arc<dyn PushStore>,
        destinations,
    ));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Answers)
        .outbox(outbox)
        .try_build()
        .expect("a coherent plane");
    Fixture {
        rt,
        store,
        transport: Arc::new(Recording::default()),
    }
}

impl Fixture {
    fn worker(&self) -> DeliveryWorker {
        DeliveryWorker::new(
            Arc::clone(self.rt.journal()),
            Arc::clone(&self.store) as Arc<dyn PushStore>,
            Arc::clone(&self.transport) as Arc<dyn PushTransport>,
            Arc::new(RunCompleted::new("urn:mako:agentd")),
        )
    }
}

// ── The journal is the outbox ───────────────────────────────────────────────

/// One `CloudEvents` message per completed run, from the run's own history.
#[tokio::test]
async fn a_completed_run_becomes_one_cloud_event() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    let out =
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

    let report = f.worker().run_once(10, 10).await.expect("a sweep");
    assert_eq!(report.deliveries, 1, "one event for one completed run");
    assert_eq!(
        report.completed, 1,
        "the registration is retired at the seal"
    );

    let seen = f.transport.seen();
    assert_eq!(seen.len(), 1);
    let (id, event) = &seen[0];
    assert_eq!(id, "operator:bus");
    assert_eq!(event["specversion"], json!("1.0"));
    assert_eq!(event["type"], json!("io.agentplane.run.completed"));
    assert_eq!(event["source"], json!("urn:mako:agentd"));
    // `(source, id)` is CloudEvents' uniqueness pair, so an at-least-once
    // duplicate is detectable as a duplicate rather than as a second event.
    assert_eq!(event["id"], json!(out.run_id.to_string()));
    assert_eq!(event["data"]["outcome"], json!("succeeded"));
    assert!(
        event["data"]["chain_head"].is_string(),
        "a receiver can ask this plane to prove the run it was told about"
    );

    // Nothing is left to sweep.
    assert_eq!(f.worker().run_once(11, 10).await.unwrap().registrations, 0);
}

/// A receiver that was down for the whole run catches up.
///
/// The property a request-time emit-with-retries cannot have: there is no
/// in-memory queue to lose, because the run's journal *is* the queue and the
/// cursor is durable.
#[tokio::test]
async fn a_receiver_that_was_down_catches_up_from_the_journal() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    f.transport.fail_next(1);
    f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");

    let failed = f.worker().run_once(10, 10).await.expect("a sweep");
    assert_eq!(failed.retries, 1);
    assert_eq!(failed.deliveries, 0);
    assert!(f.transport.seen().is_empty());

    // Backed off, so the same tick does nothing.
    assert_eq!(f.worker().run_once(10, 10).await.unwrap().registrations, 0);

    let recovered = f.worker().run_once(11, 10).await.expect("a retry sweep");
    assert_eq!(recovered.deliveries, 1);
    assert_eq!(f.transport.seen().len(), 1);
}

/// Every destination gets its own cursor.
#[tokio::test]
async fn two_destinations_are_delivered_to_independently() {
    let f = fixture(vec![
        Destination::new("bus", "https://bus.internal/events"),
        Destination::new("audit", "https://audit.internal/events"),
    ]);
    f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");

    let report = f.worker().run_once(10, 10).await.expect("a sweep");
    assert_eq!(report.deliveries, 2);
    let mut ids: Vec<String> = f.transport.seen().into_iter().map(|(id, _)| id).collect();
    ids.sort();
    assert_eq!(ids, vec!["operator:audit", "operator:bus"]);
}

/// Registration happens at admission, so no record can be missed.
///
/// A destination attached after the first record would silently skip it, and
/// "the journal is the outbox" only holds if the cursor starts at sequence one.
#[tokio::test]
async fn a_destination_is_registered_before_the_run_does_anything() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    let out =
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

    let registered = f.store.list(out.run_id).await.expect("registrations");
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].url, "https://bus.internal/events");

    // The cursor starts at one, so a projection that cared about admission
    // would see it.
    let due = f.store.due(0, 10).await.expect("due");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].next_seq, 1);
}

// ── The two id namespaces ───────────────────────────────────────────────────

/// Each worker claims only its own registrations.
///
/// Both live in one store because they are the same durable structure. Serving
/// each other's rows would post an operator's `CloudEvents` message to a peer's A2A webhook
/// — a disclosure — and a `StreamResponse` to the deployment's own bus.
#[tokio::test]
async fn an_operator_worker_leaves_a_callers_webhook_alone() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    let out =
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

    // A caller's own registration against the same run.
    f.store
        .put(
            &PushConfig {
                id: "peer-hook".to_owned(),
                task: out.run_id,
                url: "https://peer.example/hook".to_owned(),
                token: None,
                authentication: None,
            },
            1,
        )
        .await
        .expect("the caller registers");

    let report = f.worker().run_once(10, 10).await.expect("a sweep");
    assert_eq!(
        report.registrations, 1,
        "the operator worker saw only its own row"
    );
    assert!(
        f.transport
            .seen()
            .iter()
            .all(|(id, _)| id == "operator:bus"),
        "an operator event reached a caller's webhook"
    );
    // The caller's registration is untouched and still due.
    assert!(
        f.store
            .get(out.run_id, "peer-hook")
            .await
            .expect("get")
            .is_some()
    );
}

/// The reserved prefix is what keeps the two apart.
#[test]
fn the_operator_namespace_is_recognisable() {
    assert!(agentplane::push::is_operator_id("operator:bus"));
    assert!(!agentplane::push::is_operator_id("push-abc"));
    assert_eq!(
        Destination::new("bus", "https://bus.internal/events").registration_id(),
        format!("{}bus", agentplane::push::OPERATOR_PREFIX)
    );
}

/// Two destinations under one name would share a cursor.
#[test]
#[should_panic(expected = "configured twice")]
fn a_duplicate_destination_name_is_refused() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let _ = Outbox::new(
        Arc::clone(&store) as Arc<dyn PushStore>,
        vec![
            Destination::new("bus", "https://a.internal/events"),
            Destination::new("bus", "https://b.internal/events"),
        ],
    );
}

// ── What the default projection deliberately does not send ──────────────────

/// The answer is not in the event.
///
/// A run's output is domain data with a label on it. A default that shipped it
/// would make an egress decision nobody declared — whatever the run happened to
/// hold, to whatever the operator happened to configure. A deployment that wants
/// the payload writes its own projection and makes that decision out loud.
#[tokio::test]
async fn the_default_projection_carries_the_outcome_and_not_the_answer() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    f.rt.run(
        "answer",
        Tainted::trusted(json!({ "iban": "DE00 0000 0000 0000 0000 00" })),
    )
    .await
    .expect("the run completes");
    f.worker().run_once(10, 10).await.expect("a sweep");

    let seen = f.transport.seen();
    let body = serde_json::to_string(&seen[0].1).expect("json");
    assert!(
        !body.contains("iban"),
        "the default projection shipped the run's own data: {body}"
    );
}

// ── What an operator sender lifts, and what it does not ─────────────────────

/// The three URL controls do not apply to a destination with no caller.
///
/// Each is lifted for a stated reason, and the reasons are about *who named the
/// URL* rather than about the URL: there is no caller to check against an
/// allowlist, an in-cluster collector on plaintext HTTP is ordinary, and
/// resolving inward is the entire point of an internal bus.
///
/// Asserted against a real `PushSender`, because a double could not fail this.
#[tokio::test]
async fn an_operator_sender_reaches_a_private_plaintext_address() {
    use agentplane::push::{PushPolicy, PushSender, PushTransport};

    let operator = PushSender::for_operator_destinations();
    let config = PushConfig {
        id: Destination::new("bus", "http://localhost:1/ingest").registration_id(),
        task: agentplane::core::RunId::generate(),
        url: "http://localhost:1/ingest".to_owned(),
        token: None,
        authentication: None,
    };
    operator
        .validate(&config)
        .expect("an operator URL needs no host grant and no https");
    // Nothing is listening on port 1, so the *outcome* is unreachable — which is
    // a transport answer, not a refusal. The refusal is what is being ruled out.
    match operator.deliver(&config, &json!({ "ping": true })).await {
        Ok(Delivered::Unreachable(_)) => {}
        other => panic!("an operator destination was refused rather than dialled: {other:?}"),
    }

    // The caller-facing sender still refuses all three, so the lift is scoped to
    // the constructor rather than to the URL.
    let caller = PushSender::new(PushPolicy::new().allow_host("localhost"));
    assert!(
        matches!(
            <PushSender as PushTransport>::validate(&caller, &config),
            Err(PushError::NotHttps)
        ),
        "the caller-facing sender stopped refusing plaintext"
    );
}

/// A malformed operator URL is still refused, at configuration rather than
/// mid-delivery.
#[test]
fn an_operator_url_must_still_be_a_url() {
    use agentplane::push::{PushSender, PushTransport};

    let operator = PushSender::for_operator_destinations();
    let config = PushConfig {
        id: "operator:bus".to_owned(),
        task: agentplane::core::RunId::generate(),
        url: "not a url".to_owned(),
        token: None,
        authentication: None,
    };
    assert!(matches!(
        <PushSender as PushTransport>::validate(&operator, &config),
        Err(PushError::Malformed(_))
    ));
}
