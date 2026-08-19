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
    /// What to answer instead of an unreachable receiver, if anything.
    answer: Mutex<Option<Delivered>>,
}

impl Recording {
    fn answering(&self, answer: Delivered) {
        *self.answer.lock().unwrap() = Some(answer);
        *self.failures.lock().unwrap() = u32::MAX;
    }

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

    async fn deliver(
        &self,
        config: &PushConfig,
        message: &agentplane::push::PushMessage,
        _at: u64,
    ) -> Result<Delivered, PushError> {
        let mut failures = self.failures.lock().unwrap();
        if *failures > 0 {
            *failures = failures.saturating_sub(1);
            return Ok(self
                .answer
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| Delivered::Unreachable("the bus is restarting".to_owned())));
        }
        drop(failures);
        self.payloads
            .lock()
            .unwrap()
            .push((config.id.clone(), message.payload.clone()));
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

/// A slow receiver does not hold the sweep against everybody else.
///
/// The property under test is not a speed-up, it is **isolation**: one endpoint
/// sitting on its timeout must not decide when every other registration gets
/// its events. A sequential sweep serves the slow one to completion first, so
/// the second delivery cannot begin until the first ends — and a plane with
/// more receivers than one tick can drain falls permanently behind on all of
/// them because of the worst one.
///
/// Written as a rendezvous rather than as a stopwatch: both deliveries must be
/// **in flight at once** for the barrier to release, so a sequential worker
/// deadlocks here instead of merely being slower. A timing assertion would pass
/// on a fast machine that ran them one after another.
#[tokio::test]
async fn one_stalled_receiver_does_not_hold_up_the_others() {
    /// Blocks every delivery until as many are in flight as the barrier wants.
    #[derive(Debug)]
    struct Rendezvous {
        gate: tokio::sync::Barrier,
        seen: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl PushTransport for Rendezvous {
        fn validate(&self, _config: &PushConfig) -> Result<(), PushError> {
            Ok(())
        }

        async fn deliver(
            &self,
            config: &PushConfig,
            _message: &agentplane::push::PushMessage,
            _at: u64,
        ) -> Result<Delivered, PushError> {
            self.gate.wait().await;
            self.seen.lock().unwrap().push(config.id.clone());
            Ok(Delivered::Accepted)
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let outbox = Arc::new(Outbox::new(
        Arc::clone(&store) as Arc<dyn PushStore>,
        vec![
            Destination::new("slow", "https://slow.internal/events"),
            Destination::new("quick", "https://quick.internal/events"),
        ],
    ));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Answers)
        .outbox(outbox)
        .try_build()
        .expect("a coherent plane");
    rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");

    let transport = Arc::new(Rendezvous {
        gate: tokio::sync::Barrier::new(2),
        seen: Mutex::new(Vec::new()),
    });
    let worker = DeliveryWorker::new(
        Arc::clone(rt.journal()),
        Arc::clone(&store) as Arc<dyn PushStore>,
        Arc::clone(&transport) as Arc<dyn PushTransport>,
        Arc::new(RunCompleted::new("urn:mako:agentd")),
    );

    let report = tokio::time::timeout(std::time::Duration::from_secs(5), worker.run_once(10, 10))
        .await
        .expect(
            "the sweep never finished: two registrations were both due and only one was ever in \
             flight, so a receiver that does not answer decides when the rest of the plane's \
             events go out",
        )
        .expect("a sweep");
    assert_eq!(report.deliveries, 2);
    assert_eq!(transport.seen.lock().unwrap().len(), 2);
}

/// Concurrency is bounded, so a backlog is not answered with a socket per row.
///
/// The ceiling is what makes the fan-out safe to leave on: a sweep is the one
/// place this crate knows how much outbound work exists, and `limit` is a page
/// size rather than a concurrency budget.
#[tokio::test]
async fn a_sweep_opens_no_more_connections_than_its_ceiling() {
    /// Counts how many deliveries were in flight at the high-water mark.
    #[derive(Debug, Default)]
    struct HighWater {
        live: Mutex<usize>,
        peak: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl PushTransport for HighWater {
        fn validate(&self, _config: &PushConfig) -> Result<(), PushError> {
            Ok(())
        }

        async fn deliver(
            &self,
            _config: &PushConfig,
            _message: &agentplane::push::PushMessage,
            _at: u64,
        ) -> Result<Delivered, PushError> {
            {
                let mut live = self.live.lock().unwrap();
                *live += 1;
                let mut peak = self.peak.lock().unwrap();
                *peak = (*peak).max(*live);
            }
            // A real suspension, not `yield_now`: a self-waking yield goes
            // straight back on the ready queue, so the peak it measures is the
            // executor's polling order rather than how many deliveries the
            // sweep permitted to be outstanding.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            *self.live.lock().unwrap() -= 1;
            Ok(Delivered::Accepted)
        }
    }

    let destinations: Vec<Destination> = (0..8)
        .map(|n| Destination::new(format!("bus{n}"), format!("https://bus{n}.internal/events")))
        .collect();
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
    rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");

    let transport = Arc::new(HighWater::default());
    let worker = DeliveryWorker::new(
        Arc::clone(rt.journal()),
        Arc::clone(&store) as Arc<dyn PushStore>,
        Arc::clone(&transport) as Arc<dyn PushTransport>,
        Arc::new(RunCompleted::new("urn:mako:agentd")),
    )
    .max_in_flight(3);

    let report = worker.run_once(10, 10).await.expect("a sweep");
    assert_eq!(report.deliveries, 8, "every destination is still served");
    let peak = *transport.peak.lock().unwrap();
    assert!(
        peak <= 3,
        "{peak} deliveries were in flight at once against a ceiling of 3 — an \
         unbounded fan-out answers a backlog by opening a connection per row"
    );
    assert!(
        peak > 1,
        "the ceiling was never reached ({peak} at the peak), so this test would \
         pass against a sweep that serves one receiver at a time"
    );
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

/// A window full of the other namespace's rows starves nothing.
///
/// The defect this pins: ownership used to be filtered **after** a bounded
/// `due` read, so caller webhooks at the head of the stable order occupied the
/// whole window, the operator worker's own row beyond it was never read, and
/// the report — zero registrations, zero of everything — was byte-identical to
/// a quiet plane's. The filter now rides in the store query, so the worker's
/// rows are found however deep they sit, and the foreign backlog is a number
/// in the report instead of an invisible one.
#[tokio::test]
async fn foreign_rows_at_the_head_of_the_window_neither_starve_nor_hide() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    let out =
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

    // Five caller registrations whose ids sort ahead of `operator:bus` for the
    // same task, so they occupy the head of the stable due order.
    for n in 0..5 {
        f.store
            .put(
                &PushConfig {
                    id: format!("a-hook-{n}"),
                    task: out.run_id,
                    url: "https://peer.example/hook".to_owned(),
                    token: None,
                    authentication: None,
                },
                1,
            )
            .await
            .expect("the caller registers");
    }

    // A window of two: smaller than the caller backlog in front of the
    // operator row. Post-read filtering can never reach the row; the in-query
    // filter must.
    let report = f.worker().run_once(10, 2).await.expect("a sweep");
    assert_eq!(
        report.deliveries, 1,
        "the operator row behind five foreign rows was starved: {report:?}"
    );
    assert_eq!(report.completed, 1, "{report:?}");
    assert_eq!(
        report.unserved, 5,
        "the foreign backlog is invisible, so this report reads as a quiet \
         plane: {report:?}"
    );

    // The caller rows are untouched — visible is not served.
    for n in 0..5 {
        assert!(
            f.store
                .get(out.run_id, &format!("a-hook-{n}"))
                .await
                .expect("get")
                .is_some(),
            "the operator worker consumed a caller's registration"
        );
    }
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

    let operator = PushSender::for_operator_destinations(&[Destination::new(
        "bus",
        "http://localhost:1/ingest",
    )]);
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
    match operator
        .deliver(
            &config,
            &agentplane::push::PushMessage::json("ping", json!({ "ping": true })),
            0,
        )
        .await
    {
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

    let operator = PushSender::for_operator_destinations(&[Destination::new("bus", "not a url")]);
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

// ── What a receiver's answer means ──────────────────────────────────────────

/// **410 Gone** is the one rejection no wait improves; every other is a wait.
///
/// The distinction is the whole reason a status is read rather than counted. A
/// receiver that has been retired says so — retrying it for two hours is work
/// nobody wanted, and it buries the one signal an operator could have acted on.
/// A 500 is the opposite claim: a receiver mid-deploy, mid-rotation or
/// mid-upgrade answers 4xx and 5xx routinely, and parking a run's events on the
/// first of those loses more than the wasted retries cost.
#[tokio::test]
async fn a_gone_receiver_is_parked_at_once_and_a_failing_one_is_not() {
    for (answer, parked, retries) in [
        (
            Delivered::Rejected {
                status: 410,
                retry_after: None,
            },
            1,
            0,
        ),
        (
            Delivered::Rejected {
                status: 500,
                retry_after: None,
            },
            0,
            1,
        ),
        (
            Delivered::Rejected {
                status: 404,
                retry_after: None,
            },
            0,
            1,
        ),
    ] {
        let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
        f.transport.answering(answer.clone());
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

        let report = f.worker().run_once(10, 10).await.expect("a sweep");
        assert_eq!(
            (report.parked, report.retries),
            (parked, retries),
            "{answer:?} was classified wrongly: {report:?}"
        );
    }
}

/// A receiver naming its own recovery is believed, within a bound.
///
/// `Retry-After` on a 429 or a 503 is the one party who knows saying when to
/// come back, and a sender that overrides it with a fixed schedule is choosing
/// to be told twice. It is still *advice* from the only party with an interest
/// in never being called again, so it is clamped — a hostile or broken value
/// costs an hour, not the life of the deployment.
#[tokio::test]
async fn a_receivers_retry_after_is_honoured_and_bounded() {
    for (advice, expected) in [
        (Some(90), 90),
        (Some(u64::MAX), DeliveryWorker::MAX_RETRY_AFTER),
        (Some(0), 1),
    ] {
        let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
        f.transport.answering(Delivered::Rejected {
            status: 503,
            retry_after: advice,
        });
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");
        assert_eq!(f.worker().run_once(10, 10).await.unwrap().retries, 1);

        // Not due one second early, and due on the instant it named.
        assert!(
            PushStore::due(&*f.store, 10 + expected - 1, 10)
                .await
                .unwrap()
                .is_empty(),
            "a receiver that asked for {advice:?} seconds was called back early"
        );
        assert_eq!(
            PushStore::due(&*f.store, 10 + expected, 10)
                .await
                .unwrap()
                .len(),
            1,
            "a receiver that asked for {advice:?} seconds was not called back at all"
        );
    }
}

/// Registrations that failed together do not come back together.
///
/// Every destination pointed at one receiver fails in the same sweep, so an
/// undithered schedule sends all of them back at the same instant — and the
/// moment the receiver recovers it is hit by its whole backlog at once. That is
/// how a recovering service is knocked over by the sender that was waiting
/// politely for it.
///
/// The spread is derived from the registration rather than drawn at random,
/// because `run_once` takes its clock from the caller precisely so a schedule
/// is reproducible. Both halves are asserted: that the instants differ, and
/// that the same rows under the same clock produce the same instants — the
/// second is what makes every other backoff assertion in this crate writable.
#[tokio::test]
async fn registrations_that_failed_together_do_not_come_back_together() {
    let f = fixture(
        (0..8)
            .map(|n| Destination::new(format!("bus-{n}"), "https://bus.internal/events"))
            .collect(),
    );
    f.transport.fail_next(u32::MAX);
    let run =
        f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
            .await
            .expect("the run completes");

    // Six sweeps, so the window is wide enough for a spread to be visible at
    // all: the first windows are one and two seconds.
    let sweep_all = || async {
        let mut at = 10u64;
        for _ in 0..6 {
            f.worker().run_once(at, 10).await.expect("a sweep");
            at += 4096;
        }
        let mut instants: Vec<u64> = PushStore::due(&*f.store, u64::MAX, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.next_attempt_at)
            .collect();
        instants.sort_unstable();
        instants
    };

    let first = sweep_all().await;
    assert_eq!(first.len(), 8, "the fixture did not back all eight off");
    let distinct: std::collections::BTreeSet<_> = first.iter().collect();
    assert!(
        distinct.len() > 1,
        "eight registrations against one receiver all return at the same \
         instant, which is a thundering herd aimed at a service that just \
         came back: {first:?}"
    );

    // `put` preserves the cursor and clears the attempt count, so the same
    // rows are wound back to where the first pass started.
    for config in f.store.list(run.run_id).await.expect("the registrations") {
        f.store.put(&config, 1).await.expect("a reset");
    }
    assert_eq!(
        first,
        sweep_all().await,
        "the same registrations under the same clock produced a different \
         schedule, so no backoff assertion in this crate can be written"
    );
}

/// Parking keeps the cursor, and re-arming resumes from it.
///
/// This is the difference between a backlog and a loss. The cursor is the only
/// record of how far a receiver got; deleting the row on the retry ceiling
/// makes the undelivered tail of that run unrecoverable without a scan nobody
/// schedules, and leaves an operator who fixed the receiver with nothing to
/// resume.
#[tokio::test]
async fn a_parked_registration_keeps_its_cursor_and_can_be_re_armed() {
    let f = fixture(vec![Destination::new("bus", "https://bus.internal/events")]);
    f.transport.answering(Delivered::Rejected {
        status: 410,
        retry_after: None,
    });
    f.rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");
    assert_eq!(f.worker().run_once(10, 10).await.unwrap().parked, 1);

    let parked = f.store.parked(10).await.expect("the parked list");
    assert_eq!(parked.len(), 1, "the row was deleted, not parked");
    assert_eq!(parked[0].config.id, "operator:bus");
    assert!(
        parked[0]
            .last_error
            .as_ref()
            .is_some_and(|error| error.contains("410")),
        "a parked row says nothing about why: {parked:?}"
    );
    assert!(
        PushStore::due(&*f.store, u64::MAX, 10)
            .await
            .unwrap()
            .is_empty(),
        "a parked registration is still swept, so it costs a tick forever"
    );

    // The receiver comes back. Delivery resumes at the record it never took.
    *f.transport.answer.lock().unwrap() = None;
    f.transport.fail_next(0);
    assert!(
        f.store
            .unpark(parked[0].config.task, "operator:bus", 20)
            .await
            .unwrap()
    );
    let recovered = f.worker().run_once(20, 10).await.expect("a sweep");
    assert_eq!(
        (recovered.deliveries, recovered.completed),
        (1, 1),
        "an unparked registration did not resume: {recovered:?}"
    );
    assert_eq!(f.transport.seen().len(), 1);
}
