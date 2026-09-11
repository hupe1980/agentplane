//! The remote witness, against a server that answers like the specification.
//!
//! The protocol's whole subtlety is that two failures look alike and mean
//! opposite things — a stale cursor and a forked history — so most of this file
//! is about keeping them apart.

#![cfg(all(feature = "witness-http", feature = "redb"))]

use std::sync::Arc;

use agentplane::core::{Digest, merkle};
use agentplane::journal::{Checkpoint, HttpWitness, LogKey, TrustedWitness, Witness, WitnessError};
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

/// A witness that actually signs what it was sent.
///
/// The canned server above answers a fixed string, which is the right shape for
/// the status-code tests and exactly wrong for the 200 path: this file used to
/// assert a cosignature was recorded from a body containing eight bytes of
/// `AQIDBAUGBwg=`, and it passed — because nothing verified it. A test whose
/// witness cannot sign cannot tell a cosignature from a well-formed string.
struct SigningWitness {
    key: ed25519_dalek::SigningKey,
    name: String,
    /// The instant this witness claims. Configurable so the forbidden zero can
    /// be sent by something that is otherwise a correct witness.
    time: u64,
    /// The last checkpoint note it cosigned, for the monitoring endpoint.
    held: std::sync::Mutex<Option<(String, String)>>,
}

impl SigningWitness {
    fn new(name: &str, seed: u8) -> Self {
        // Fixed bytes: a test that regenerates a key on every run cannot pin
        // the id its verifier is matched against. `seed` is what lets two
        // witnesses share a name and differ in key, which is the case the
        // ignore-unknown-keys rule exists for.
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        Self {
            key,
            name: name.to_owned(),
            // The worked example's instant from `tlog-cosignature`, which the
            // in-module codec vectors already pin.
            time: 1_679_315_147,
            held: std::sync::Mutex::new(None),
        }
    }

    fn trusted(&self) -> TrustedWitness {
        TrustedWitness::ed25519(&self.name, self.key.verifying_key().to_bytes())
    }

    /// The witness's four-byte key id, computed from the spec's words rather
    /// than by calling the crate's own helper. A fake that imports the
    /// implementation's functions to build its answers can only ever confirm
    /// the implementation — the fake this replaced derived its id through the
    /// crate and signed the bytes the crate verified, so the pair agreed with
    /// each other and with no witness that exists.
    fn key_id(&self) -> [u8; 4] {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(self.name.as_bytes());
        h.update([0x0A]);
        // `tlog-cosignature`: 0x04 is the Ed25519 cosignature algorithm.
        h.update([0x04]);
        h.update(self.key.verifying_key().to_bytes());
        let full = h.finalize();
        [full[0], full[1], full[2], full[3]]
    }

    /// The signature line for whatever note the request carried, built as the
    /// specification describes a witness building one: the note body without
    /// its signature lines, under the `cosignature/v1` header and a `time`
    /// line, with the timestamp leading the payload big-endian.
    /// Claim a different observation instant — including the forbidden zero.
    fn at_time(mut self, time: u64) -> Self {
        self.time = time;
        self
    }

    fn cosign_line(&self, request: &str) -> String {
        use ed25519_dalek::Signer as _;
        let time = self.time;
        let note = request.split_once("\n\n").map_or(request, |(_, note)| note);
        let text = note
            .split_once("\n\n")
            .map_or_else(|| note.to_owned(), |(text, _)| format!("{text}\n"));
        let message = format!("cosignature/v1\ntime {time}\n{text}");
        let signature = self.key.sign(message.as_bytes());
        let mut payload = self.key_id().to_vec();
        payload.extend_from_slice(&time.to_be_bytes());
        payload.extend_from_slice(&signature.to_bytes());
        // A line from someone else comes first, because `tlog-witness` allows a
        // 200 to carry one *or more* signatures and a client that reads only
        // the head lets the answering server decide which cosignature counts by
        // reordering its own reply.
        format!(
            "\u{2014} other-witness {}\n\u{2014} {} {}\n",
            base64_standard(&[0x5Au8; 76]),
            self.name,
            base64_standard(&payload)
        )
    }
}

/// Minimal RFC 4648 §4, so the test encodes independently of the crate.
fn base64_standard(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = chunk.len() * 8 / 6 + usize::from(chunk.len() < 3);
        for i in 0..4 {
            if i < take {
                out.push(A[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A server that cosigns each request with `witness`, answering 200.
async fn signing_server(witness: Arc<SigningWitness>) -> (String, LastBody) {
    let seen: LastBody = Arc::new(std::sync::Mutex::new(String::new()));
    let state = (Arc::clone(&witness), Arc::clone(&seen));
    let app = Router::new()
        .route(
            "/add-checkpoint",
            post(
                |State((w, seen)): State<(Arc<SigningWitness>, LastBody)>, body: String| async move {
                    // The spec's MUST, before anything else: a witness cosigns
                    // a *specific log's* claim, and answers 403 when it cannot
                    // attribute the checkpoint to a key it trusts.
                    if !log_signature_verifies(&body) {
                        *seen.lock().unwrap() = body;
                        return (axum::http::StatusCode::FORBIDDEN, String::new());
                    }
                    let line = w.cosign_line(&body);
                    *seen.lock().unwrap() = body;
                    (axum::http::StatusCode::OK, line)
                },
            ),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

/// A witness that also serves what it cosigned, at the monitoring path.
///
/// The reply is the note the client submitted with the witness's cosignature
/// line appended, which is what `tlog-witness` says the endpoint returns: the
/// checkpoint, the witness's cosignature(s), *and* the log's own signature
/// that the witness verified.
async fn monitoring_server(witness: Arc<SigningWitness>) -> (String, LastBody) {
    let seen: LastBody = Arc::new(std::sync::Mutex::new(String::new()));
    let state = (Arc::clone(&witness), Arc::clone(&seen));
    let app = Router::new()
        .route(
            "/add-checkpoint",
            post(
                |State((w, seen)): State<(Arc<SigningWitness>, LastBody)>, body: String| async move {
                    if !log_signature_verifies(&body) {
                        return (axum::http::StatusCode::FORBIDDEN, String::new());
                    }
                    let line = w.cosign_line(&body);
                    let note = body
                        .split_once("\n\n")
                        .map_or(body.as_str(), |(_, note)| note)
                        .to_owned();
                    let origin = note.lines().next().unwrap_or_default().to_owned();
                    *w.held.lock().unwrap() = Some((origin, format!("{note}{line}")));
                    *seen.lock().unwrap() = body;
                    (axum::http::StatusCode::OK, line)
                },
            ),
        )
        .route(
            "/{hash}/checkpoint",
            axum::routing::get(
                |State((w, _)): State<(Arc<SigningWitness>, LastBody)>,
                 axum::extract::Path(hash): axum::extract::Path<String>| async move {
                    use sha2::{Digest as _, Sha256};
                    let held = w.held.lock().unwrap().clone();
                    match held {
                        Some((origin, note))
                            if hex::encode(Sha256::digest(origin.as_bytes())) == hash =>
                        {
                            (axum::http::StatusCode::OK, note)
                        }
                        _ => (axum::http::StatusCode::NOT_FOUND, String::new()),
                    }
                },
            ),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn leaves(size: u64) -> Vec<merkle::LeafHash> {
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

/// The client, pointed at `url`, trusting `witness-1`.
///
/// Every test needs a non-empty trusted set now: a client with no keys cannot
/// verify anything, so `HttpWitness::new` refuses to build one.
fn client(url: &str) -> HttpWitness {
    HttpWitness::new(
        url,
        log_key(),
        vec![SigningWitness::new("witness-1", 7).trusted()],
    )
    .unwrap()
}

/// The log's own note name, shared by the client and by every fake witness
/// that has to recognise it.
const LOG_NAME: &str = "plane-a";

/// This log's signing key, fixed so the id is stable across runs.
fn log_signer() -> Arc<agentplane::policy::Ed25519Signer> {
    Arc::new(agentplane::policy::Ed25519Signer::new(
        "log-key",
        &[0x11u8; 32],
    ))
}

fn log_key() -> LogKey {
    let signer = log_signer();
    LogKey::ed25519(LOG_NAME, signer.verifying_key(), signer).expect("a valid note key name")
}

/// What a conformant witness checks before it cosigns anything: that the
/// submitted checkpoint carries a signature from a key it trusts for this
/// origin, over the note body it was sent.
///
/// `tlog-witness` makes this a MUST and gives it a status — *403 Forbidden if
/// either no signature from a trusted key for the origin is present, or a
/// signature line's key name and ID match a trusted key but the signature
/// itself fails to verify*. A fake witness that skips it is a fake witness
/// that accepts a signature made over some other checkpoint, which is exactly
/// the defect this file could not see.
fn log_signature_verifies(request: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let Some((_, note)) = request.split_once("\n\n") else {
        return false;
    };
    let Some((text, lines)) = note.split_once("\n\n") else {
        return false;
    };
    let body = format!("{text}\n");
    let key_id = agentplane::journal::key_id(LOG_NAME, 0x01, &log_signer().verifying_key());
    let verifying =
        VerifyingKey::from_bytes(&log_signer().verifying_key()).expect("a valid public key");
    for line in lines.lines() {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((name, payload)) = rest.split_once(' ') else {
            continue;
        };
        if name != LOG_NAME {
            continue;
        }
        let Some(bytes) = decode_base64(payload) else {
            continue;
        };
        if bytes.len() < 4 || bytes[..4] != key_id {
            continue;
        }
        let Ok(signature) = Signature::from_slice(&bytes[4..]) else {
            continue;
        };
        if verifying.verify(body.as_bytes(), &signature).is_ok() {
            return true;
        }
    }
    false
}

/// Minimal RFC 4648 §4 decode, so the fake witness reads a line without the
/// crate's own decoder.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut have = 0u32;
    let mut out = Vec::new();
    for c in text.trim().bytes() {
        if c == b'=' {
            break;
        }
        let v = u32::try_from(A.iter().position(|a| *a == c)?).ok()?;
        bits = (bits << 6) | v;
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push(u8::try_from((bits >> have) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Each checkpoint is signed over its own note, not once at configuration.
///
/// The load-bearing part is that the witness here **verifies** the log
/// signature, as `tlog-witness` says it MUST. Against a fake witness that
/// skips that check, a client holding one signature as configuration passes
/// every test in this file and receives `403 Forbidden` from every real
/// witness, forever — while the message it prints says the log's key is not
/// registered, which sends the operator to ask an operator who registered it
/// correctly.
///
/// Two submissions of *different* checkpoints, because one proves nothing: a
/// fixed signature made over the first note would satisfy a single-checkpoint
/// test.
#[tokio::test]
async fn every_checkpoint_is_signed_over_its_own_note() {
    let witness = Arc::new(SigningWitness::new("witness-1", 7));
    let (url, seen) = signing_server(Arc::clone(&witness)).await;
    let w = HttpWitness::new(&url, log_key(), vec![witness.trusted()]).unwrap();

    w.cosign(&checkpoint(4), 0, &[])
        .await
        .expect("a checkpoint carrying its own signature is cosigned");
    let first = seen.lock().unwrap().clone();

    let proof = merkle::consistency_proof(&leaves(8), 4);
    w.cosign(&checkpoint(8), 4, &proof)
        .await
        .expect("the second checkpoint must carry the second checkpoint's signature");
    let second = seen.lock().unwrap().clone();

    let line = |body: &str| {
        body.rsplit_once(&format!("\u{2014} {LOG_NAME} "))
            .map(|(_, sig)| sig.trim().to_owned())
            .expect("the log's own signature line")
    };
    assert_ne!(
        line(&first),
        line(&second),
        "both checkpoints were submitted under one signature, so at most one of \
         them was actually signed — and a witness that verifies, as the \
         specification requires it to, refuses the other with 403"
    );
}

/// A witness's own record of this log is reachable, and it is what an auditor
/// holds.
///
/// The submission direction leaves the evidence with the party under audit.
/// This is the other one: the monitoring endpoint answers with a checkpoint
/// the plane did not write, carrying cosignatures from keys the *reader*
/// chose. Without it, "an independent party observed this log" is a claim the
/// plane makes about itself.
#[tokio::test]
async fn a_witness_serves_back_what_it_cosigned() {
    let witness = Arc::new(SigningWitness::new("witness-1", 7));
    let (url, _) = monitoring_server(Arc::clone(&witness)).await;
    let w = HttpWitness::new(&url, log_key(), vec![witness.trusted()]).unwrap();

    let cp = checkpoint(4);
    w.cosign(&cp, 0, &[]).await.expect("cosigned");

    let reader = w.reader().expect("a reader for the same witness");
    let held = reader
        .latest(&cp.origin)
        .await
        .expect("the witness answers for a log it cosigned")
        .expect("a log it has cosigned is not unknown");
    assert_eq!(
        held.checkpoint, cp,
        "the anchor names this log at this size"
    );
    assert_eq!(
        held.cosignatures.len(),
        1,
        "exactly the one trusted cosignature; the log's own signature travels on \
         the same note and must not be counted as corroboration"
    );

    let unknown = reader
        .latest("example.com/some-other-plane")
        .await
        .expect("an unknown log is an answer, not an outage");
    assert!(
        unknown.is_none(),
        "a log this witness never cosigned answered with something — which an \
         auditor would read as an anchor"
    );
}

/// A monitoring endpoint serving the plane's own checkpoint is not an anchor.
///
/// The failure that looks like success, at the one place it would be worst: a
/// reader that returned whatever the URL served would hand an auditor the
/// plane's own claim under the name of an independent party's — and the
/// auditor would then run the deletion check against the very history they are
/// checking.
#[tokio::test]
async fn an_uncosigned_checkpoint_is_not_an_anchor() {
    use agentplane::journal::WitnessReader;

    // Serves a checkpoint note carrying the log's own signature and no
    // witness line — which is exactly what a plane could publish about itself.
    let cp = checkpoint(4);
    let signer = log_signer();
    let body = cp.to_note();
    let signature = {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        key.sign(body.as_bytes())
    };
    let mut payload = agentplane::journal::key_id(LOG_NAME, 0x01, &signer.verifying_key()).to_vec();
    payload.extend_from_slice(&signature.to_bytes());
    // The blank line is `signed-note`'s boundary between body and signatures.
    let note = format!(
        "{body}\n\u{2014} {LOG_NAME} {}\n",
        base64_standard(&payload)
    );

    let origin = cp.origin.clone();
    let app = Router::new().route(
        "/{hash}/checkpoint",
        axum::routing::get(
            move |axum::extract::Path(hash): axum::extract::Path<String>| {
                let note = note.clone();
                let origin = origin.clone();
                async move {
                    use sha2::{Digest as _, Sha256};
                    if hex::encode(Sha256::digest(origin.as_bytes())) == hash {
                        (axum::http::StatusCode::OK, note)
                    } else {
                        (axum::http::StatusCode::NOT_FOUND, String::new())
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let reader =
        WitnessReader::new(&url, vec![SigningWitness::new("witness-1", 7).trusted()]).unwrap();
    let refused = reader.latest(&cp.origin).await;
    assert!(
        matches!(&refused, Err(WitnessError::Unavailable(d))
            if d.contains("nobody independent signed")),
        "a checkpoint carrying only the log's own signature was returned as an \
         anchor: {refused:?}"
    );
}

/// A reader with no trusted key is refused at construction.
#[test]
fn a_reader_with_no_keys_cannot_report_an_anchor() {
    let refused = agentplane::journal::WitnessReader::new("http://example.invalid", Vec::new())
        .expect_err("a reader that verifies nothing is not a reader");
    assert!(
        refused.to_string().contains("at least one trusted key"),
        "wrong refusal: {refused}"
    );
}

/// A cosignature with a zero timestamp is not counted.
///
/// `tlog-witness`: *the cosignature MUST NOT omit the timestamp, i.e. the
/// timestamp MUST NOT be zero*. A zero says nothing about when the witness saw
/// the log, and that instant is half of what a cosignature is for — it is what
/// separates a witness that is watching from one that answered once and
/// stopped.
#[tokio::test]
async fn a_cosignature_without_an_observation_time_is_not_counted() {
    let witness = Arc::new(SigningWitness::new("witness-1", 7).at_time(0));
    let (url, _) = signing_server(Arc::clone(&witness)).await;
    let w = HttpWitness::new(&url, log_key(), vec![witness.trusted()]).unwrap();

    let refused = w.cosign(&checkpoint(4), 0, &[]).await;
    assert!(
        matches!(&refused, Err(WitnessError::Unavailable(d))
            if d.contains("verified against a trusted key")),
        "a zero-timestamp cosignature was counted: {refused:?}"
    );
}

/// The request is shaped the way the specification says.
///
/// Checked against the wire rather than the code, because every field here is
/// one a witness rejects: `old` with a leading zero, a missing blank line, or a
/// checkpoint without its own signature all produce a 4xx from a real operator
/// and nothing from a unit test that only inspects Rust values.
#[tokio::test]
async fn the_request_body_follows_the_protocol() {
    let witness = Arc::new(SigningWitness::new("witness-1", 7));
    let (url, seen) = signing_server(Arc::clone(&witness)).await;
    let w = HttpWitness::new(&url, log_key(), vec![witness.trusted()]).unwrap();

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
    let w = client(&url);

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

/// **An unreadable 409 body is not a witness at size zero.**
///
/// The 409 body is the witness's own tree size, and the caller acts on it: it
/// builds a consistency proof from that size and resubmits. Reading an
/// unparseable body as `0` — which `unwrap_or_default()` did — invents a
/// numeric claim the witness never made, and the invention is not harmless.
/// The resubmission carries a proof from 0, the witness rejects it, and that
/// rejection is classified as `Forked` or `Shrank`: the integrity bucket. So a
/// blank body, an HTML error page or a stray word would manufacture the exact
/// 3am page `a_stale_cursor_is_not_a_fork` exists to prevent — arriving from
/// the other side, through the routine path rather than the alarming one.
///
/// A witness is untrusted, so what it did not say it does not get to have said.
/// An unreadable size is reported as unavailable: routine, retried, and not an
/// integrity finding.
#[tokio::test]
async fn a_stale_reply_without_a_size_is_not_an_integrity_event() {
    for body in [
        "",
        "  \n",
        "the log is unknown",
        "<html>502</html>",
        "-1",
        "12x",
    ] {
        let (url, _) = server(409, body).await;
        let w = client(&url);

        match w.cosign(&checkpoint(4), 0, &[]).await {
            Err(WitnessError::Unavailable(_)) => {}
            Err(WitnessError::Stale { witness_size, .. }) => panic!(
                "a 409 body of {body:?} was read as the witness being at size \
                 {witness_size} — a claim it never made, and one the caller acts \
                 on by resubmitting a proof that comes back as a fork"
            ),
            Err(e) => panic!("a 409 with an unreadable size became {e}"),
            Ok(_) => panic!("a 409 must not yield a cosignature"),
        }
    }

    // The positive half, so this is a parse rule rather than a client that has
    // stopped reading 409 bodies at all.
    let (url, _) = server(409, "97\n").await;
    let w = client(&url);
    assert!(
        matches!(
            w.cosign(&checkpoint(4), 0, &[]).await,
            Err(WitnessError::Stale {
                witness_size: 97,
                ..
            })
        ),
        "a well-formed size stopped being carried through"
    );
}

/// **A 400 is a shrunken log, and it must reach the integrity bucket.**
///
/// C2SP specifies `400 Bad Request` for *old size exceeds checkpoint size*: the
/// witness is at N, this log now offers a checkpoint smaller than N, and runs it
/// already cosigned are gone. `WitnessError::Shrank` calls that the single most
/// important thing a witness catches, and the one an operator auditing itself
/// structurally cannot — the smaller log is internally perfect and nothing
/// inside it remembers what is missing.
///
/// There was no arm for it. A 400 fell to the catch-all and became
/// `Unavailable`, which the quorum classifies as **routine** — beside a
/// timeout. So `Shrank` was reachable only from `MemoryWitness`, the in-process
/// witness explicitly documented as useless as a trust anchor, and on the only
/// witness that can be a real one a deleted run raised nothing.
#[tokio::test]
async fn a_shrunken_log_is_an_integrity_finding_not_a_routine_one() {
    // The body is deliberately empty: C2SP does not require 400 to carry the
    // size, so a client that needed one would be reading a field that may not
    // be there. Both numbers are already in hand.
    let (url, _) = server(400, "").await;
    let w = client(&url);

    match w.cosign(&checkpoint(3), 5, &[]).await {
        Err(WitnessError::Shrank { seen, offered, .. }) => {
            assert_eq!(
                (seen, offered),
                (5, 3),
                "the refusal must name where the witness was and what it was offered"
            );
        }
        Err(WitnessError::Unavailable(detail)) => panic!(
            "a shrunken log was reported as routine unavailability, so it never reaches \
             the integrity bucket and nobody is paged for the one event a witness exists \
             to catch: {detail}"
        ),
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("a witness cosigned a log that had shrunk"),
    }
}

/// A 400 for a request whose own numbers do not show a shrink is off-spec,
/// and off-spec is routine, not an integrity finding.
///
/// C2SP's 400 is a statement about the request's two sizes — `old` exceeds the
/// checkpoint's — and both are in hand before the witness answers. A witness
/// is untrusted: its reply can *confirm* a shrink the request evidences, and
/// it must not be able to *invent* one, because a fork alert manufactured by a
/// confused counterparty is how the alert that matters stops being believed.
/// The same rule the 409 arm applies to an unparseable size.
#[tokio::test]
async fn an_off_spec_400_cannot_invent_a_shrink() {
    let (url, _) = server(400, "").await;
    let w = client(&url);

    // old (3) ≤ checkpoint size (5): nothing about this request shows a shrink.
    match w.cosign(&checkpoint(5), 3, &[]).await {
        Err(WitnessError::Unavailable(detail)) => assert!(
            detail.contains("off-spec"),
            "the refusal must say the witness answered outside its protocol: {detail}"
        ),
        Err(WitnessError::Shrank { .. }) => panic!(
            "a witness answering 400 off-spec manufactured a shrink finding for a \
             request whose own numbers show none"
        ),
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("a 400 was read as a cosignature"),
    }
}

/// A 422 names three different things, and only one of them is a fork.
///
/// The specification gives the status three causes: a size-zero checkpoint
/// whose root is not the empty tree's, a consistency proof that does not
/// verify, and equal sizes with unequal roots. Only the last is evidence about
/// the log — no proof-building mistake produces two roots for one size — and
/// the split has to be made by the client, because the status does not carry
/// it.
///
/// Reporting all three as `Forked` is the mistake this test exists to hold
/// shut: it pages an operator for an integrity incident over a proof their own
/// log built wrongly, and the alert that matters stops being believed.
#[tokio::test]
async fn a_422_is_a_fork_only_where_the_witness_removed_the_ambiguity() {
    let (url, _) = server(422, "").await;
    let w = client(&url);

    // Equal sizes: the witness is at 4, this log offers 4, and the roots
    // differ. Unambiguous.
    match w.cosign(&checkpoint(4), 4, &[]).await {
        Err(WitnessError::Forked { seen, offered, .. }) => {
            assert_eq!((seen, offered), (4, 4), "the two sizes the fork was at");
        }
        other => panic!("equal sizes with unequal roots is the split view: {other:?}"),
    }

    // Growth: the proof did not verify. Either this log built it wrongly or
    // its history moved, and the reply does not say which.
    match w
        .cosign(&checkpoint(4), 2, &[Digest::from_bytes([7u8; 32])])
        .await
    {
        Err(WitnessError::Inconsistent {
            old_size, offered, ..
        }) => {
            assert_eq!(
                (old_size, offered),
                (2, 4),
                "the growth that failed to verify"
            );
        }
        other => panic!(
            "a proof that did not verify names a cause the witness did not, and \
             `Forked` is that cause: {other:?}"
        ),
    }
}

/// The two 422 causes this client can see are refused before a request goes out.
///
/// Both are its own inputs, and both come back from a witness under the same
/// status as a history that does not extend — so sending them spends a
/// submission to receive an answer that has to be reclassified by guessing.
#[tokio::test]
async fn a_request_a_witness_would_refuse_is_refused_here_first() {
    // A server that would answer 200 to anything, so a request that reaches it
    // succeeds and the assertions below can only pass if none does.
    let (url, seen) = server(200, "").await;
    let w = client(&url);

    let incoherent = Checkpoint {
        origin: "test-log".into(),
        size: 0,
        root: Digest::from_bytes([3u8; 32]),
    };
    let refused = w.cosign(&incoherent, 0, &[]).await;
    assert!(
        matches!(&refused, Err(WitnessError::Unavailable(d))
            if d.contains("empty tree's root")),
        "a size-0 checkpoint with a root the empty tree does not have: {refused:?}"
    );

    let refused = w
        .cosign(&checkpoint(4), 0, &[Digest::from_bytes([5u8; 32])])
        .await;
    assert!(
        matches!(&refused, Err(WitnessError::Unavailable(d))
            if d.contains("must carry no consistency proof")),
        "a submission from size 0 carrying a proof: {refused:?}"
    );

    assert!(
        seen.lock().unwrap().is_empty(),
        "a request the specification says is unprocessable was still sent, so a \
         422 that comes back cannot be told from one about the log"
    );
}

/// A 200 carrying no signature is not a cosignature.
///
/// The failure that looks like success: a caller trusting the status code would
/// record that a witness vouched when none did.
#[tokio::test]
async fn an_empty_two_hundred_is_not_a_cosignature() {
    let (url, _) = server(200, "").await;
    let w = client(&url);
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
    let w = client(&url);
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

/// **A cosignature nobody can verify is not a cosignature.**
///
/// This is the whole point of the client. The quorum's `met` is a *count* of
/// cosignatures, and a cosignature is the only evidence that anyone outside
/// this process ever saw the log — so if the count can be raised by a string,
/// every guarantee downstream of it is a guarantee about string formatting.
///
/// The four cases below are the four ways an attacker gets to choose the
/// response body: they control the endpoint (a DNS or config change points the
/// client at them), or they sit on the wire. In each, the client must decline
/// rather than count it.
#[tokio::test]
async fn a_cosignature_is_counted_only_if_it_verifies() {
    let real = Arc::new(SigningWitness::new("witness-1", 7));
    let cp = checkpoint(4);

    // The positive half first, so the negatives below are a verification rule
    // rather than a client that refuses everything.
    let (url, _) = signing_server(Arc::clone(&real)).await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    let co = w
        .cosign(&cp, 0, &[])
        .await
        .expect("a witness that really signed the note must be counted");
    assert_eq!(co.key_id, "witness-1", "the cosignature names who gave it");
    assert_eq!(
        co.note_key_id,
        real.trusted().note_key_id(),
        "and which of that name's keys, or a key rotation silently keeps counting \
         the retired key"
    );

    // 1. An unrelated key. The signature is real, over the real note — it is
    //    simply not from anyone this client trusts.
    let stranger = Arc::new(SigningWitness::new("witness-1", 42));
    let (url, _) = signing_server(Arc::clone(&stranger)).await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    let err = w
        .cosign(&cp, 0, &[])
        .await
        .expect_err("a signature from an unconfigured key was counted");
    assert!(
        err.to_string().contains("trusted key"),
        "the refusal should say the signature matched nothing configured: {err}"
    );

    // 2. The right name, the wrong key. `signed-note`'s MUST-ignore rule is
    //    keyed on the 4-byte id, not the name, and the name is attacker-chosen
    //    text: matching on it alone means anyone who calls themselves
    //    `witness-1` is `witness-1`.
    let (url, _) = server(
        200,
        &format!("\u{2014} witness-1 {}\n", base64_standard(&[0xAA; 68])),
    )
    .await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    assert!(
        w.cosign(&cp, 0, &[]).await.is_err(),
        "a line claiming a trusted witness's name under a different key was counted"
    );

    // 3. A well-formed line from the right key whose signature is over
    //    nothing: a plausible timestamp, sixty-four zero bytes of signature.
    //    This is the canned fixture this file used to accept.
    let id = real.trusted().note_key_id();
    let mut payload = id.to_vec();
    payload.extend_from_slice(&1_679_315_147u64.to_be_bytes());
    payload.extend_from_slice(&[0u8; 64]);
    let (url, _) = server(
        200,
        &format!("\u{2014} witness-1 {}\n", base64_standard(&payload)),
    )
    .await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    assert!(
        w.cosign(&cp, 0, &[]).await.is_err(),
        "sixty-four zero bytes under a trusted key id were counted as that \
         witness's signature"
    );

    // 3b. Key rotation: the same name, two keys, and the witness signs with
    //     the newer one. This is what the four-byte id is *for* — a matcher
    //     keyed on the name alone finds whichever entry happens to be first,
    //     verifies the new key's signature against the old key, fails, and
    //     drops a perfectly good cosignature. The quorum then falls short
    //     during a routine rotation, which reads as a witness being down.
    let rotated = Arc::new(SigningWitness::new("witness-1", 99));
    let (url, _) = signing_server(Arc::clone(&rotated)).await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted(), rotated.trusted()]).unwrap();
    let co = w
        .cosign(&cp, 0, &[])
        .await
        .expect("a second key registered under the same name must still count");
    assert_eq!(
        co.note_key_id,
        rotated.trusted().note_key_id(),
        "the cosignature must be attributed to the key that actually signed it"
    );

    // 4. A real signature over a *different* checkpoint. The bytes verify; they
    //    just do not say what the client is about to record them as saying.
    let other = checkpoint(9);
    let (url, _) = signing_server(Arc::clone(&real)).await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    let good = w.cosign(&other, 0, &[]).await.expect("baseline");
    let (url, _) = server(
        200,
        &format!(
            "\u{2014} witness-1 {}\n",
            base64_standard(&[id.to_vec(), good.signature.clone()].concat())
        ),
    )
    .await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    assert!(
        w.cosign(&cp, 0, &[]).await.is_err(),
        "a genuine signature over a different checkpoint was replayed onto this one"
    );

    // 5. A real signature from the trusted key over the bare note text —
    //    the shape of a *log's own* signature, without `cosignature/v1`'s
    //    domain separation. Counting it would let anyone who can obtain a
    //    log-style signature from the witness key pass it off as an
    //    observation of growth, which is the confusion the header exists to
    //    rule out.
    let bare = {
        use ed25519_dalek::Signer as _;
        let mut payload = id.to_vec();
        payload.extend_from_slice(&1_679_315_147u64.to_be_bytes());
        payload.extend_from_slice(real.key.sign(cp.to_note().as_bytes()).to_bytes().as_slice());
        payload
    };
    let (url, _) = server(
        200,
        &format!("\u{2014} witness-1 {}\n", base64_standard(&bare)),
    )
    .await;
    let w = HttpWitness::new(&url, log_key(), vec![real.trusted()]).unwrap();
    assert!(
        w.cosign(&cp, 0, &[]).await.is_err(),
        "a signature over the bare note — the log's own claim-shape — was counted as \
         a witness's cosignature"
    );
}

/// A client with nothing to trust cannot verify, and must not pretend to.
///
/// The alternative — an empty trusted set that accepts everything, or that
/// accepts nothing while still being constructible — is the configuration
/// mistake that turns the whole quorum into theatre. It is refused at
/// construction, where a human is present to read the message.
#[test]
fn a_witness_client_with_no_keys_is_not_a_witness_client() {
    let err = HttpWitness::new("http://example.invalid", log_key(), Vec::new())
        .expect_err("a client that trusts nobody must not be constructible");
    assert!(
        err.to_string().contains("trusted"),
        "the refusal should name what is missing: {err}"
    );
}

/// A run removed from the store is caught, using an anchor no operator handed
/// over.
///
/// This is the whole point of the tier, end to end, and it is the one check
/// nothing else in this crate can make. The chain verifies, the signatures
/// verify, the inclusion proofs verify — and all three draw both halves of
/// their comparison from the store, so an operator who drops a run and
/// recomputes the tree passes every one of them. `audit` says so in
/// `not_checked` and can do nothing about it, because the missing input is a
/// checkpoint from somewhere else.
///
/// So: seal three runs, submit the checkpoint to a witness, delete a run,
/// then audit against what the *witness* holds.
#[tokio::test]
async fn a_deleted_run_is_caught_by_the_anchor_a_witness_holds() {
    use agentplane::journal::{Append, JournalStore, RecordKind, WitnessReader};

    let store = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let journal: Arc<dyn JournalStore> = store.clone();
    let mut runs = Vec::new();
    for _ in 0..3 {
        let run = agentplane::RunId::generate();
        let lease = store
            .acquire(run, "w", std::time::Duration::from_mins(1))
            .await
            .expect("lease");
        store
            .append(
                lease.epoch,
                vec![Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "witnessed".into(),
                        governed_by: None,
                        input_label: agentplane::core::Label::trusted(),
                        input: serde_json::Value::Null,
                        policy_bundle: None,
                        canon: agentplane::core::canon::VERSION,
                        idempotency_key: None,
                    },
                )],
            )
            .await
            .expect("append");
        store
            .seal(run, lease.epoch, "succeeded")
            .await
            .expect("seal");
        runs.push(run);
    }

    let witness = Arc::new(SigningWitness::new("witness-1", 7));
    let (url, _) = monitoring_server(Arc::clone(&witness)).await;
    let client = HttpWitness::new(&url, log_key(), vec![witness.trusted()]).unwrap();
    let cp = journal.checkpoint().await.expect("checkpoint");
    client
        .cosign(&cp, 0, &[])
        .await
        .expect("the witness cosigns");

    // The operator removes a run and carries on.
    store.delete_run_for_test(runs[1]).await.expect("deleted");
    let survivors = vec![runs[0], runs[2]];

    let blind = agentplane::audit::audit(
        &journal,
        &survivors,
        &agentplane::audit::Evidence::default(),
    )
    .await
    .expect("an audit");
    assert!(
        blind.is_sound(),
        "the store-only audit found something it has no way to find, so this test \
         is not measuring what it claims: {:?}",
        blind.findings
    );
    assert!(
        blind.not_checked.iter().any(|n| n.contains("deletion")),
        "the store-only audit did not say the check it could not make: {:?}",
        blind.not_checked
    );

    // The anchor, from the party that is not the operator.
    let reader = WitnessReader::new(&url, vec![witness.trusted()]).expect("a reader");
    let anchor = reader
        .latest(&cp.origin)
        .await
        .expect("the witness answers")
        .expect("it cosigned this log");
    let armed = agentplane::audit::audit(
        &journal,
        &survivors,
        &agentplane::audit::Evidence {
            prior: Some(&anchor.checkpoint),
            ..Default::default()
        },
    )
    .await
    .expect("an audit");
    assert!(
        armed.findings.iter().any(|f| matches!(
            f,
            agentplane::audit::Finding::Shrunk { .. }
                | agentplane::audit::Finding::NotAppendOnly { .. }
        )),
        "a checkpoint fetched from a witness did not catch a deleted run, so the \
         one attack the rest of this crate structurally cannot see is still \
         invisible: {:?}",
        armed.findings
    );
}
