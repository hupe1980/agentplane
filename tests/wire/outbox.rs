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

/// Standard Webhooks' `v1,<base64>` over `{id}.{timestamp}.{body}`, written
/// out from RFC 2104 against the crate's public `Digest::of`.
///
/// Deliberately a **second implementation**: it concatenates where the sender
/// streams, and it reaches SHA-256 through a different door. Calling the
/// sender's own helper would assert that a function equals itself, which is
/// what a mutation removing the signing would still satisfy.
fn expected_signature(key: &[u8], id: &str, at: u64, body: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(Digest::of(key).as_bytes());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut content = Vec::new();
    content.extend_from_slice(id.as_bytes());
    content.push(b'.');
    content.extend_from_slice(at.to_string().as_bytes());
    content.push(b'.');
    content.extend_from_slice(body);

    let mut inner: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    inner.extend_from_slice(&content);
    let inner = Digest::of(&inner);
    let mut outer: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    outer.extend_from_slice(inner.as_bytes());
    format!("v1,{}", base64(Digest::of(&outer).as_bytes()))
}

/// Standard base64, written out so this file depends on nothing the sender
/// also depends on.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The decoded bytes of a `whsec_` secret, which is what both ends MAC with.
fn key_of(secret: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let encoded = secret.trim_start_matches("whsec_").trim_end_matches('=');
    let mut bits = 0u32;
    let mut held = 0u32;
    let mut out = Vec::new();
    for byte in encoded.bytes() {
        let value = u32::try_from(
            ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .expect("the fixture secret is base64"),
        )
        .expect("a base64 index is under 64");
        bits = (bits << 6) | value;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push(u8::try_from((bits >> held) & 0xff).expect("masked to a byte"));
        }
    }
    out
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

/// The instant every sweep in this file runs at. It rides in the signature and
/// in `webhook-timestamp`, so it has to be a value the assertions can name.
const SWEPT_AT: u64 = 1_700_000_000;

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
    let report = worker.run_once(SWEPT_AT, 10).await.expect("a sweep");
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
/// only way to pass is to have signed exactly those bytes, under exactly that
/// key, bound to exactly the id and instant the delivery announced. A
/// signature over a re-serialization, over a constant, over an empty body, or
/// over the body alone all fail here and nowhere else.
#[tokio::test]
async fn a_signed_destination_carries_a_standard_webhooks_signature_over_what_it_posted() {
    let (url, seen) = receiver().await;
    let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    let received = deliver(
        Destination::new("bus", url).signed_with(&Secret::new(secret)),
        &seen,
    )
    .await;

    let header = |name: &str| {
        received
            .headers
            .get(name)
            .unwrap_or_else(|| {
                panic!(
                    "a signed destination delivered without '{name}': {:?}",
                    received.headers
                )
            })
            .to_str()
            .expect("the webhook headers are ASCII")
            .to_owned()
    };

    // The two facts the signature binds. A receiver reads them from the
    // headers and compares; if either were absent the check would degrade to a
    // signature over the body alone, which is what replays forever.
    let id = header("webhook-id");
    assert_eq!(
        header("webhook-timestamp"),
        SWEPT_AT.to_string(),
        "the instant a receiver measures its tolerance window against is not \
         the instant this attempt was made"
    );

    assert_eq!(
        header("webhook-signature"),
        expected_signature(&key_of(secret), &id, SWEPT_AT, &received.body),
        "the signature does not MAC the posted bytes under the announced id \
         and instant: {}",
        String::from_utf8_lossy(&received.body)
    );

    // And the bytes it covers are the event, not an empty or partial body —
    // a MAC over nothing would satisfy the comparison above if the receiver
    // had also been sent nothing.
    let event: Value = serde_json::from_slice(&received.body).expect("the body is the CloudEvent");
    assert_eq!(event["type"], json!("io.agentplane.run.completed"));
    assert_eq!(event["source"], json!("urn:mako:agentd"));
    assert_eq!(
        event["id"],
        json!(id),
        "the idempotency key a receiver deduplicates on is not the identity \
         inside the event, so the two disagree about what one message is: \
         {event:#}"
    );
}

/// A `whsec_`-prefixed secret is base64 **of the key**, not the key.
///
/// The one detail that decides whether an off-the-shelf verifier agrees with
/// this plane at all: a receiver handed `whsec_…` gives it to its library,
/// which decodes it. Signing with the prefixed text instead produces a MAC
/// nothing in the ecosystem accepts, and the symptom is a receiver refusing
/// every delivery for a reason no log here explains.
#[tokio::test]
async fn a_whsec_secret_names_base64_of_the_key_and_not_the_key() {
    let (url, seen) = receiver().await;
    let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    let received = deliver(
        Destination::new("bus", url).signed_with(&Secret::new(secret)),
        &seen,
    )
    .await;
    let id = received.headers["webhook-id"].to_str().unwrap();
    let signature = received.headers["webhook-signature"].to_str().unwrap();

    assert_eq!(
        signature,
        expected_signature(&key_of(secret), id, SWEPT_AT, &received.body)
    );
    assert_ne!(
        signature,
        expected_signature(secret.as_bytes(), id, SWEPT_AT, &received.body),
        "the prefixed text was MACed as if it were the key"
    );
}

/// The envelope is announced as one, and the identity a receiver needs rides
/// with it whether or not anything is signed.
///
/// `Content-Type` is how a `CloudEvents` receiver routes: a structured-mode
/// event under any other media type is a valid event that reaches nothing that
/// parses one. And `webhook-id` is the only defence a receiver has against
/// at-least-once delivery, which is the contract this outbox offers rather
/// than an unusual failure.
#[tokio::test]
async fn a_cloudevents_delivery_announces_its_media_type_and_its_identity() {
    let (url, seen) = receiver().await;
    let received = deliver(Destination::new("bus", url), &seen).await;

    let content_type = received.headers["content-type"].to_str().unwrap();
    assert_eq!(
        content_type, "application/cloudevents+json; charset=UTF-8",
        "a structured-mode CloudEvent was posted under a media type no \
         CloudEvents receiver routes on"
    );
    let event: Value = serde_json::from_slice(&received.body).expect("the body is the CloudEvent");
    assert_eq!(event["specversion"], json!("1.0"));
    assert_eq!(
        received.headers["webhook-id"].to_str().unwrap(),
        event["id"].as_str().unwrap(),
        "the idempotency key and the event's own identity disagree"
    );
    assert!(
        received.headers.contains_key("webhook-timestamp"),
        "a delivery with no instant leaves a receiver no window to judge \
         freshness in: {:?}",
        received.headers
    );
    // `subject` is what a receiver filters on without opening `data`.
    assert_eq!(event["subject"], event["data"]["run"]);
    assert!(
        event["data"].get("reason").is_none(),
        "a success has no reason, and a null key would make every success \
         read as a failure with no explanation: {event}"
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

/// A failure's event says why, and a success's carries no `reason` key.
///
/// The receiver of `io.agentplane.run.completed` is whoever answers for the
/// failure, and the reason is the only actionable part — the seal records it
/// precisely so it outlives the process that wrote it, and a completion event
/// without it hands the receiver the word "failed" one delivery further out.
/// Absence on success is asserted too: a `null` would make every success
/// carry a field whose only reading is "the failure had no explanation".
#[tokio::test]
async fn a_failed_runs_event_carries_the_reason_the_seal_records() {
    #[derive(Debug)]
    struct Refuses;

    #[async_trait::async_trait]
    impl Skill for Refuses {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("refuses").provides("answer")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Ok(Outcome::fail(
                "the counterparty ledger refused the transfer",
            ))
        }
    }

    let (url, seen) = receiver().await;
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let outbox = Arc::new(Outbox::new(
        Arc::clone(&store) as Arc<dyn PushStore>,
        vec![Destination::new("bus", url)],
    ));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Refuses)
        .outbox(Arc::clone(&outbox))
        .try_build()
        .expect("a coherent plane");
    rt.run("answer", Tainted::trusted(json!({})))
        .await
        .expect("a failed run still concludes");

    let worker = DeliveryWorker::new(
        Arc::clone(rt.journal()),
        Arc::clone(&store) as Arc<dyn PushStore>,
        Arc::new(PushSender::for_operator_destinations(outbox.destinations()))
            as Arc<dyn PushTransport>,
        Arc::new(RunCompleted::new("urn:mako:agentd")),
    );
    worker.run_once(SWEPT_AT, 10).await.expect("a sweep");

    let received = seen.lock().unwrap()[0].clone();
    let event: Value = serde_json::from_slice(&received.body).expect("the body is the CloudEvent");
    assert_eq!(event["data"]["outcome"], json!("failed"));
    assert_eq!(
        event["data"]["reason"],
        json!("the counterparty ledger refused the transfer"),
        "the delivered event must say what the record says: {event}"
    );
}

/// The rotation half of signing is configurable without a panic in reach.
///
/// Both secrets come from the same file, read at the same moment, inside the
/// same builder — so both misconfigurations belong on that builder's error
/// path, naming the destination, rather than aborting from underneath it. The
/// missing-primary refusal is its own variant: "also" without a first key is
/// a wiring mistake, not a bad byte.
#[tokio::test]
async fn a_rotation_secret_is_refused_without_a_panic_in_reach() {
    use agentplane::push::SigningKeyError;

    let (url, _seen) = receiver().await;

    // No primary: refused, not aborted.
    let err = Destination::new("bus", url.clone())
        .try_also_signed_with(&Secret::new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"))
        .expect_err("'also' with no first key is a wiring mistake");
    assert!(matches!(err, SigningKeyError::NoPrimary), "got: {err}");

    // A bad rotation key after a good primary: the same refusal the primary's
    // own try_ form gives.
    let err = Destination::new("bus", url.clone())
        .try_signed_with(&Secret::new("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"))
        .expect("a sound primary")
        .try_also_signed_with(&Secret::new("whsec_not-base64!"))
        .expect_err("a rotation secret whose prefix and bytes disagree");
    assert!(matches!(err, SigningKeyError::NotBase64), "got: {err}");

    // The sound path signs under both keys, so a receiver holding either
    // verifies — checked on the wire, where the signature actually is.
    let old = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
    let new = "whsec_wpZ0rboM3Wt2WRb0nb5kUmLAYHkPvwUV";
    let (url, seen) = receiver().await;
    let destination = Destination::new("bus", url)
        .try_signed_with(&Secret::new(old))
        .expect("a sound primary")
        .try_also_signed_with(&Secret::new(new))
        .expect("a sound rotation secret");
    let received = deliver(destination, &seen).await;
    let id = received.headers["webhook-id"].to_str().unwrap();
    let signature = received.headers["webhook-signature"].to_str().unwrap();
    for secret in [old, new] {
        let expected = expected_signature(&key_of(secret), id, SWEPT_AT, &received.body);
        assert!(
            signature.split(' ').any(|part| part == expected),
            "a receiver holding '{secret}' cannot verify: {signature}"
        );
    }
}
