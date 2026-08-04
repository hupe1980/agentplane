//! The remote witness, against a server that answers like the specification.
//!
//! The protocol's whole subtlety is that two failures look alike and mean
//! opposite things — a stale cursor and a forked history — so most of this file
//! is about keeping them apart.

#![cfg(all(feature = "witness-http", feature = "redb"))]

use std::sync::Arc;

use agentplane::core::{Digest, merkle};
use agentplane::journal::{Checkpoint, HttpWitness, NoteSignature, Witness, WitnessError};
use axum::Router;
use axum::extract::State;
use axum::routing::post;

type Canned = Arc<std::sync::Mutex<(u16, String)>>;
type LastBody = Arc<std::sync::Mutex<String>>;

async fn handler(
    State((canned, seen)): State<(Canned, LastBody)>,
    body: String,
) -> (axum::http::StatusCode, String) {
    *seen.lock().unwrap() = body;
    let (status, reply) = canned.lock().unwrap().clone();
    (axum::http::StatusCode::from_u16(status).unwrap(), reply)
}

/// A witness that answers however the test says.
async fn server(status: u16, reply: &str) -> (String, LastBody) {
    let canned: Canned = Arc::new(std::sync::Mutex::new((status, reply.to_owned())));
    let seen: LastBody = Arc::new(std::sync::Mutex::new(String::new()));
    let app = Router::new()
        .route("/add-checkpoint", post(handler))
        .with_state((canned, Arc::clone(&seen)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn leaves(size: u64) -> Vec<Digest> {
    (0..size)
        .map(|i| merkle::leaf_hash(&Digest::of(format!("run-{i}").as_bytes())))
        .collect()
}

fn checkpoint(size: u64) -> Checkpoint {
    let leaves = leaves(size);
    Checkpoint {
        origin: "example.com/plane-a".into(),
        size,
        root: merkle::root(&leaves),
    }
}

fn log_sig() -> NoteSignature {
    NoteSignature {
        name: "plane-a".into(),
        key_id: [1, 2, 3, 4],
        signature: vec![9; 8],
    }
}

/// The request is shaped the way the specification says.
///
/// Checked against the wire rather than the code, because every field here is
/// one a witness rejects: `old` with a leading zero, a missing blank line, or a
/// checkpoint without its own signature all produce a 4xx from a real operator
/// and nothing from a unit test that only inspects Rust values.
#[tokio::test]
async fn the_request_body_follows_the_protocol() {
    let (url, seen) = server(200, "\u{2014} witness-1 AQIDBAUGBwg=\n").await;
    let w = HttpWitness::new(&url, log_sig()).unwrap();

    // Realistic numbers on purpose. A consistency proof is O(log n) hashes, so
    // a 50→100 proof carries seven — and an implementation computing
    // `size - proof.len()` would send `old 93`. The first version of this test
    // used size 4 with two hashes, where that arithmetic coincidentally gives
    // the right answer, and it passed against exactly that bug.
    let cp = checkpoint(100);
    let proof = merkle::consistency_proof(&leaves(100), 50);
    assert_eq!(proof.len(), 7, "a 50→100 proof is seven hashes, not fifty");
    w.cosign(&cp, 50, &proof).await.expect("a 200 must cosign");

    let body = seen.lock().unwrap().clone();
    let mut lines = body.lines();

    assert_eq!(
        lines.next().unwrap(),
        "old 50",
        "the first line must be `old` and the size the caller states — never a \
         number inferred from the proof, which is O(log n) and reveals no such thing"
    );
    // One line per proof hash — all of them, not a fixed two, so the count is
    // tied to the proof rather than to whatever the fixture happened to produce.
    for _ in 0..proof.len() {
        assert_eq!(
            lines.next().unwrap().len(),
            44,
            "a base64 sha-256 is 44 chars"
        );
    }
    assert_eq!(
        lines.next().unwrap(),
        "",
        "a blank line separates the proof from the checkpoint"
    );
    assert_eq!(
        lines.next().unwrap(),
        "example.com/plane-a",
        "then the checkpoint origin"
    );

    assert!(
        body.contains('\u{2014}'),
        "the checkpoint must carry its own signature, or a witness answers 403 — it \
         cosigns a named log's claim, not an anonymous triple of numbers"
    );
}

/// A 409 is a stale cursor, and must never be reported as a fork.
///
/// This is the distinction the whole client exists to get right. A 409 says
/// "you built a proof from a checkpoint I have moved past", which is routine and
/// self-healing; a fork is an integrity incident. A team paged twice for the
/// first stops believing the alert for the second.
#[tokio::test]
async fn a_stale_cursor_is_not_a_fork() {
    let (url, _) = server(409, "97\n").await;
    let w = HttpWitness::new(&url, log_sig()).unwrap();

    match w.cosign(&checkpoint(4), 0, &[]).await {
        Err(WitnessError::Stale { witness_size, .. }) => {
            assert_eq!(
                witness_size, 97,
                "the witness's own size must be carried through, or the caller cannot \
                 build the proof that would succeed"
            );
        }
        Err(WitnessError::Forked { .. }) => panic!(
            "a stale cursor was reported as a forked history — the one confusion that \
             turns a retry into a 3am page"
        ),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("a 409 must not yield a cosignature"),
    }
}

/// A 422 is a proof that does not verify, which *is* a fork.
#[tokio::test]
async fn an_unverifiable_proof_is_a_fork() {
    let (url, _) = server(422, "").await;
    let w = HttpWitness::new(&url, log_sig()).unwrap();
    assert!(
        matches!(
            w.cosign(&checkpoint(4), 0, &[]).await,
            Err(WitnessError::Forked { .. })
        ),
        "a proof the witness could not verify is a history that does not extend"
    );
}

/// A 200 carrying no signature is not a cosignature.
///
/// The failure that looks like success: a caller trusting the status code would
/// record that a witness vouched when none did.
#[tokio::test]
async fn an_empty_two_hundred_is_not_a_cosignature() {
    let (url, _) = server(200, "").await;
    let w = HttpWitness::new(&url, log_sig()).unwrap();
    let err = w
        .cosign(&checkpoint(1), 0, &[])
        .await
        .expect_err("200 with an empty body must not be read as a cosignature");
    assert!(err.to_string().contains("no signature"), "got: {err}");
}

/// An untrusted log key is reported as such, not as an integrity problem.
#[tokio::test]
async fn an_untrusted_key_says_what_to_do_about_it() {
    let (url, _) = server(403, "").await;
    let w = HttpWitness::new(&url, log_sig()).unwrap();
    let err = w.cosign(&checkpoint(1), 0, &[]).await.unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("registered"),
        "a 403 is a configuration step nobody has done yet, and the error should say \
         which: {text}"
    );
    assert!(
        !matches!(err, WitnessError::Forked { .. }),
        "an unregistered key is not a forked history"
    );
}
