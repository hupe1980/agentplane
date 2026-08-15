#![cfg(all(feature = "push", feature = "http", feature = "redb"))]

//! Operator destinations, as the receiver at the other end finds them.
//!
//! Everything here asserts on the **wire**: the bytes and headers an HTTP
//! receiver actually got. The rest of the outbox's properties — cursors,
//! retries, namespaces — are proven against a doubled transport in
//! `tests/guards/outbox.rs`, and a double is exactly the wrong instrument for
//! this one, because a `PushTransport` never sees a header. A signature that
//! was computed and then not sent, or sent over a re-serialization of the
//! payload rather than over the posted bytes, passes every test that stops at
//! the trait.

use std::sync::{Arc, Mutex};

use agentplane::core::{Digest, Outcome, Secret, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::push::{
    DeliveryWorker, Destination, Outbox, PushSender, PushStore, PushTransport, RunCompleted,
};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use axum::body::Bytes;
use axum::http::HeaderMap;
use serde_json::{Value, json};

/// `HMAC-SHA256`, written out from RFC 2104 against the crate's public
/// `Digest::of`.
///
/// Deliberately a **second implementation**: it concatenates where the sender
/// streams, and it reaches SHA-256 through a different door. Calling the
/// sender's own helper would assert that a function equals itself, which is
/// what a mutation removing the signing would still satisfy.
fn expected_signature(secret: &str, body: &[u8]) -> String {
    const BLOCK: usize = 64;
    let key = secret.as_bytes();
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(Digest::of(key).as_bytes());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    inner.extend_from_slice(body);
    let inner = Digest::of(&inner);
    let mut outer: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    outer.extend_from_slice(inner.as_bytes());
    format!("sha256={}", Digest::of(&outer).to_hex())
}

/// What one POST looked like on the wire.
#[derive(Debug, Clone)]
struct Received {
    headers: HeaderMap,
    body: Bytes,
}

/// A receiver that answers 2xx and keeps what it was sent, byte for byte.
async fn receiver() -> (String, Arc<Mutex<Vec<Received>>>) {
    let seen: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
    let app = axum::Router::new().route(
        "/ingest",
        axum::routing::post({
            let seen = Arc::clone(&seen);
            move |headers: HeaderMap, body: Bytes| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock().unwrap().push(Received { headers, body });
                    axum::http::StatusCode::OK
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/ingest",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
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

/// Run one completed run through a real `PushSender` to `destination`, and
/// return what the receiver got.
async fn deliver(destination: Destination, seen: &Arc<Mutex<Vec<Received>>>) -> Received {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let outbox = Arc::new(Outbox::new(
        Arc::clone(&store) as Arc<dyn PushStore>,
        vec![destination],
    ));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Answers)
        .outbox(Arc::clone(&outbox))
        .try_build()
        .expect("a coherent plane");
    rt.run("answer", Tainted::trusted(json!({ "q": 1 })))
        .await
        .expect("the run completes");

    let worker = DeliveryWorker::new(
        Arc::clone(rt.journal()),
        Arc::clone(&store) as Arc<dyn PushStore>,
        // The production wiring: the sender is handed the destinations that
        // were registered, which is where the signing keys live.
        Arc::new(PushSender::for_operator_destinations(outbox.destinations()))
            as Arc<dyn PushTransport>,
        Arc::new(RunCompleted::new("urn:mako:agentd")),
    );
    let report = worker.run_once(10, 10).await.expect("a sweep");
    assert_eq!(report.deliveries, 1, "nothing was delivered: {report:?}");

    let received = seen.lock().unwrap();
    assert_eq!(received.len(), 1, "one completed run, one POST");
    received[0].clone()
}

/// The half that proves the signature is over what was sent.
///
/// Not "a header is present", and not "the header matches what the signer
/// computes" — the expectation is recomputed here from the **bytes the
/// receiver read off the socket**, by a second HMAC implementation, so the
/// only way to pass is to have signed exactly those bytes under exactly that
/// secret. A signature over a re-serialization, over a constant, or over an
/// empty body all fail here and nowhere else.
///
/// What this does not cover: freshness. This delivery replayed tomorrow
/// carries the same valid signature — see `BodySigning` for why that is the
/// receiver's dedup problem and not the signature's.
#[tokio::test]
async fn a_signed_destination_carries_an_hmac_of_the_exact_bytes_posted() {
    let (url, seen) = receiver().await;
    let secret = "shhh-operator-key";
    let received = deliver(
        Destination::new("bus", url).signed_with("X-Mako-Signature", Secret::new(secret)),
        &seen,
    )
    .await;

    let signature = received
        .headers
        .get("X-Mako-Signature")
        .unwrap_or_else(|| {
            panic!(
                "a signed destination delivered with no signature header: {:?}",
                received.headers
            )
        })
        .to_str()
        .expect("a signature is ASCII hex");

    assert_eq!(
        signature,
        expected_signature(secret, &received.body),
        "the signature does not MAC the posted bytes: {}",
        String::from_utf8_lossy(&received.body)
    );

    // And the bytes it covers are the event, not an empty or partial body —
    // a MAC over nothing would satisfy the comparison above if the receiver
    // had also been sent nothing.
    let event: Value = serde_json::from_slice(&received.body).expect("the body is the CloudEvent");
    assert_eq!(event["type"], json!("io.agentplane.run.completed"));
    assert_eq!(event["source"], json!("urn:mako:agentd"));
    assert!(
        event["id"].is_string(),
        "the payload carries no identity for a receiver to deduplicate on, \
         which is the only thing that closes replay: {event:#}"
    );
}

/// The negative half: no key, no header.
///
/// A destination that was never signed must not grow a signature from
/// somewhere — a sender that signed everything with some default would make
/// the positive half above pass while proving nothing about configuration.
#[tokio::test]
async fn an_unsigned_destination_carries_no_signature_header() {
    let (url, seen) = receiver().await;
    let received = deliver(Destination::new("bus", url), &seen).await;

    let signed: Vec<_> = received
        .headers
        .keys()
        .map(|name| name.as_str().to_ascii_lowercase())
        .filter(|name| name.contains("signature"))
        .collect();
    assert!(
        signed.is_empty(),
        "an unsigned destination carried {signed:?}"
    );

    // The delivery itself still happened, so "no header" is not "no POST".
    let event: Value = serde_json::from_slice(&received.body).expect("the body is the CloudEvent");
    assert_eq!(event["type"], json!("io.agentplane.run.completed"));
}
