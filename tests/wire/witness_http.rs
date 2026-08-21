//! The remote witness, against a server that answers like the specification.
//!
//! The protocol's whole subtlety is that two failures look alike and mean
//! opposite things — a stale cursor and a forked history — so most of this file
//! is about keeping them apart.

#![cfg(all(feature = "witness-http", feature = "redb"))]

use std::sync::Arc;

use agentplane::core::{Digest, merkle};
use agentplane::journal::{
    Checkpoint, HttpWitness, NoteSignature, TrustedWitness, Witness, WitnessError,
};
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
    fn cosign_line(&self, request: &str) -> String {
        use ed25519_dalek::Signer as _;
        const TIME: u64 = 1_679_315_147;
        let note = request.split_once("\n\n").map_or(request, |(_, note)| note);
        let text = note
            .split_once("\n\n")
            .map_or_else(|| note.to_owned(), |(text, _)| format!("{text}\n"));
        let message = format!("cosignature/v1\ntime {TIME}\n{text}");
        let signature = self.key.sign(message.as_bytes());
        let mut payload = self.key_id().to_vec();
        payload.extend_from_slice(&TIME.to_be_bytes());
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
        log_sig(),
        vec![SigningWitness::new("witness-1", 7).trusted()],
    )
    .unwrap()
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
    let witness = Arc::new(SigningWitness::new("witness-1", 7));
    let (url, seen) = signing_server(Arc::clone(&witness)).await;
    let w = HttpWitness::new(&url, log_sig(), vec![witness.trusted()]).unwrap();

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

/// A 422 is a proof that does not verify, which *is* a fork.
#[tokio::test]
async fn an_unverifiable_proof_is_a_fork() {
    let (url, _) = server(422, "").await;
    let w = client(&url);
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted(), rotated.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
    let good = w.cosign(&other, 0, &[]).await.expect("baseline");
    let (url, _) = server(
        200,
        &format!(
            "\u{2014} witness-1 {}\n",
            base64_standard(&[id.to_vec(), good.signature.clone()].concat())
        ),
    )
    .await;
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let w = HttpWitness::new(&url, log_sig(), vec![real.trusted()]).unwrap();
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
    let err = HttpWitness::new("http://example.invalid", log_sig(), Vec::new())
        .expect_err("a client that trusts nobody must not be constructible");
    assert!(
        err.to_string().contains("trusted"),
        "the refusal should name what is missing: {err}"
    );
}
