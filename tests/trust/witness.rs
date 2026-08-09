//! A witness is the only thing here that a dishonest operator cannot satisfy.
//!
//! Every other mechanism verifies the record against itself, and whoever
//! controls the store controls every input to that check. A witness remembers
//! independently, so "show a different history to each auditor" stops being
//! invisible.

#![cfg(all(feature = "redb", feature = "testkit"))]

use std::sync::Arc;

use agentplane::core::{Digest, merkle};
use agentplane::journal::{Checkpoint, MemoryWitness, Witness, WitnessError};
use agentplane::testkit::StubSigner;

fn witness() -> MemoryWitness {
    MemoryWitness::new(Arc::new(StubSigner::default()))
}

/// Leaves for a log of `n` runs, and the checkpoint over them.
fn log(n: usize) -> (Vec<Digest>, Checkpoint) {
    let leaves: Vec<Digest> = (0..n)
        .map(|i| merkle::leaf_hash(&Digest::of(format!("run-{i}").as_bytes())))
        .collect();
    let cp = Checkpoint {
        origin: "plane-a".into(),
        size: n as u64,
        root: merkle::root(&leaves),
    };
    (leaves, cp)
}

/// A log that only grows is cosigned every time.
#[tokio::test]
async fn a_growing_log_is_cosigned() {
    let w = witness();
    let (_, first) = log(3);
    w.cosign(&first, 0, &[]).await.expect("first checkpoint");

    let (leaves, second) = log(5);
    let proof = merkle::consistency_proof(&leaves, 3);
    w.cosign(&second, first.size, &proof)
        .await
        .expect("an extension");

    assert_eq!(w.last_seen("plane-a").map(|(n, _)| n), Some(5));
}

/// **A log that shrank is refused.**
///
/// Runs were removed. This is the case an operator auditing its own store
/// structurally cannot catch: the smaller log is internally perfect, and
/// nothing inside it remembers the runs that are gone.
#[tokio::test]
async fn a_shrunken_log_is_refused() {
    let w = witness();
    let (_, big) = log(5);
    w.cosign(&big, 0, &[]).await.expect("first checkpoint");

    let (_, small) = log(3);
    match w.cosign(&small, big.size, &[]).await {
        Err(WitnessError::Shrank { seen, offered, .. }) => {
            assert_eq!((seen, offered), (5, 3), "the refusal must name both sizes");
        }
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("a witness cosigned a log that lost two runs"),
    }
}

/// **The split view: two histories of one log cannot both be cosigned.**
///
/// The forked checkpoint is the *same size* as the one already cosigned, so
/// nothing about its shape is suspicious — only the witness's memory of a
/// different root exposes it. Without that memory an operator can hand one
/// history to an auditor and another to a regulator, and both verify.
#[tokio::test]
async fn a_forked_history_is_refused() {
    let w = witness();
    let (_, real) = log(4);
    w.cosign(&real, 0, &[]).await.expect("the real history");

    let forged = Checkpoint {
        origin: "plane-a".into(),
        size: 4,
        root: Digest::of(b"a different history of the same four runs"),
    };
    match w.cosign(&forged, 4, &[]).await {
        Err(WitnessError::Forked { seen, offered, .. }) => {
            assert_eq!((seen, offered), (4, 4), "a fork can be the same size");
        }
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!("a witness cosigned a second, contradictory history"),
    }
}

/// An extension without a valid proof is refused, not trusted.
///
/// The operator supplies the proof because only the operator has the log. That
/// is safe *because* an absent or forged one fails here — otherwise "extends"
/// would mean "claims to extend".
#[tokio::test]
async fn an_extension_without_a_proof_is_refused() {
    let w = witness();
    let (_, first) = log(3);
    w.cosign(&first, 0, &[]).await.expect("first checkpoint");

    let (_, second) = log(6);
    match w.cosign(&second, 3, &[]).await {
        Err(WitnessError::ProofMissing { seen, .. }) => assert_eq!(seen, 3),
        Err(other) => panic!(
            "a missing proof must be reported as such, not as {other} — a caller \
             that forgot the proof and a history that does not extend are \
             different problems"
        ),
        Ok(_) => panic!("a growth claim with no proof was taken on trust"),
    }
}

/// A proof that is present but wrong is a fork, not a missing proof.
///
/// The pair with the check above: if either collapsed into the other, one of
/// the two diagnoses would be permanently wrong.
#[tokio::test]
async fn a_forged_proof_is_reported_as_a_fork() {
    let w = witness();
    let (_, first) = log(3);
    w.cosign(&first, 0, &[]).await.expect("first checkpoint");

    let (_, second) = log(6);
    let nonsense = vec![Digest::of(b"not a real audit path")];
    match w.cosign(&second, 3, &nonsense).await {
        Err(WitnessError::Forked { .. }) => {}
        Err(other) => panic!("a forged proof was reported as {other}"),
        Ok(_) => panic!("a forged proof was accepted"),
    }
}

/// Re-submitting the same checkpoint is not a fork.
///
/// An operator polling a witness, or retrying after a timeout, sends the same
/// checkpoint twice. Treating that as a contradiction would make the mechanism
/// unusable and train people to ignore its refusals.
#[tokio::test]
async fn resubmitting_the_same_checkpoint_is_allowed() {
    let w = witness();
    let (_, cp) = log(4);
    w.cosign(&cp, 0, &[]).await.expect("first");
    w.cosign(&cp, 4, &[])
        .await
        .expect("the very same checkpoint again");
}

/// A witness that cannot sign says so, and does not return a cosignature.
///
/// Once the signing key may live in a KMS, signing acquires a failure mode it
/// never had with a local key: throttled, unreachable, revoked. The dangerous
/// handling is the quiet one — a `cosign` that returned successfully having
/// signed nothing, or that fabricated bytes, would be indistinguishable to an
/// auditor from a witness that was never asked. That is precisely the state
/// witnessing exists to rule out.
#[tokio::test]
async fn a_witness_that_cannot_sign_reports_it() {
    use agentplane::core::{CheckpointSigner, Digest, KeyId, SignError};

    /// A KMS having a bad day.
    #[derive(Debug)]
    struct Unreachable;

    #[async_trait::async_trait]
    impl CheckpointSigner for Unreachable {
        fn key_id(&self) -> KeyId {
            "kms-key".into()
        }
        async fn sign(&self, _hash: &Digest) -> Result<Vec<u8>, SignError> {
            Err(SignError::Unavailable("connection reset".into()))
        }
    }

    let w = MemoryWitness::new(Arc::new(Unreachable));
    let (_, cp) = log(1);

    match w.cosign(&cp, 0, &[]).await {
        Err(WitnessError::Unavailable(detail)) => {
            assert!(
                detail.contains("connection reset"),
                "the operator needs to know why: {detail}"
            );
        }
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!(
            "a cosignature came back from a signer that produced nothing — an \
             auditor would read that as a witness having vouched"
        ),
    }
}

/// A refused key is reported as refused, naming the key.
#[tokio::test]
async fn a_revoked_signing_key_names_itself() {
    use agentplane::core::{CheckpointSigner, Digest, KeyId, SignError};

    #[derive(Debug)]
    struct Revoked;

    #[async_trait::async_trait]
    impl CheckpointSigner for Revoked {
        fn key_id(&self) -> KeyId {
            "retired-key".into()
        }
        async fn sign(&self, _hash: &Digest) -> Result<Vec<u8>, SignError> {
            Err(SignError::Refused {
                key_id: "retired-key".into(),
                detail: "key is scheduled for deletion".into(),
            })
        }
    }

    let w = MemoryWitness::new(Arc::new(Revoked));
    let err = w
        .cosign(&log(1).1, 0, &[])
        .await
        .expect_err("a revoked key must not yield a cosignature");
    let text = err.to_string();
    assert!(
        text.contains("retired-key") && text.contains("scheduled for deletion"),
        "a refusal must name the key and the reason, or rotation is guesswork: {text}"
    );
}

// ── The signed note: the artifact that leaves the operator's control ────────

/// A checkpoint round-trips through the interoperable envelope.
#[test]
fn a_signed_note_round_trips() {
    use agentplane::journal::{NoteSignature, SignedNote};

    let (_, cp) = log(3);
    let note = SignedNote::new(cp.to_note())
        .expect("a checkpoint body is a valid note body")
        .with_signature(NoteSignature {
            name: "plane-a".into(),
            key_id: [0xDE, 0xAD, 0xBE, 0xEF],
            signature: vec![1, 2, 3, 4, 5],
        })
        .with_signature(NoteSignature {
            name: "witness-1".into(),
            key_id: [0x01, 0x02, 0x03, 0x04],
            signature: vec![9, 9],
        });

    let back = SignedNote::parse(&note.to_wire()).expect("parse");
    assert_eq!(back, note, "the envelope did not survive a round trip");

    // Cosignatures accumulate rather than replace: the whole value of
    // witnessing is several independent parties signing *the same bytes*.
    assert_eq!(back.signatures.len(), 2);
    assert_eq!(back.text, cp.to_note());
}

/// A hyphen is not an em dash.
///
/// The two are indistinguishable in most terminals, diffs and code review, so
/// this is the interop bug that survives every human check and fails at the
/// witness. Accepting it here would produce notes that half the ecosystem
/// rejects.
#[test]
fn a_hyphen_is_not_a_signature_line() {
    use agentplane::journal::SignedNote;

    let (_, cp) = log(1);
    let wire = format!("{}\n- plane-a 3q2+7wECAwQF\n", cp.to_note());
    let err = SignedNote::parse(&wire)
        .expect_err("a hyphen must not be accepted where the format specifies U+2014");
    assert!(
        err.to_string().contains("em dash"),
        "the error must name the character, since the two look identical: {err}"
    );
}

/// The body's trailing newline is part of what gets signed.
#[test]
fn a_body_without_its_trailing_newline_is_refused() {
    use agentplane::journal::SignedNote;

    let err = SignedNote::new("example.com/plane-a\n3\nabc")
        .expect_err("a body with no trailing newline signs different bytes than a verifier hashes");
    assert!(err.to_string().contains("newline"), "got: {err}");

    // And the separator is not part of the body: a parsed note's text carries
    // its own newline and no more.
    let (_, cp) = log(1);
    let note = SignedNote::new(cp.to_note()).expect("valid");
    let back = SignedNote::parse(&note.to_wire()).expect("parse");
    assert!(back.text.ends_with('\n'));
    assert!(
        !back.text.ends_with("\n\n"),
        "the separating blank line was absorbed into the signed body, so every \
         signature would cover bytes the verifier does not hash"
    );
}

/// The key id is derived the way the specification says.
#[test]
fn the_key_id_follows_the_specification() {
    use agentplane::journal::key_id;
    use sha2::{Digest as _, Sha256};

    let (name, alg, public) = ("plane-a", 0x01u8, b"public-key-bytes".as_slice());

    // SHA-256(name ‖ 0x0A ‖ signature type ‖ public key)[..4]
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0A]);
    h.update([alg]);
    h.update(public);
    let expected = &h.finalize()[..4];

    assert_eq!(
        key_id(name, alg, public).as_slice(),
        expected,
        "a key id computed differently addresses a different key, so every \
         signature would be attributed to nobody"
    );
}

/// The base64 is RFC 4648, checked against the RFC's own vectors.
///
/// A round trip proves the encoder and decoder agree with *each other*, which a
/// pair of matching mistakes satisfies perfectly. The note format's whole
/// purpose is that other implementations read it, so the only test that means
/// anything compares against values this project did not compute.
#[test]
fn the_note_payload_is_rfc4648_base64() {
    use agentplane::journal::{NoteSignature, SignedNote};

    // RFC 4648 §10: "foobar" encodes to "Zm9vYmFy", and the padded cases are
    // where hand-rolled encoders go wrong.
    for (payload, expected) in [
        (b"foobar".as_slice(), "Zm9vYmFy"),
        (b"fooba".as_slice(), "Zm9vYmE="),
        (b"foob".as_slice(), "Zm9vYg=="),
        // Indices 62 and 63 — the *only* two positions where the standard
        // alphabet differs from the URL-safe one. Without a vector that reaches
        // them, this test passes just as happily against base64url, which no
        // witness would accept. The first version of it did exactly that.
        ([0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF].as_slice(), "+///////"),
        ([0xFF; 6].as_slice(), "////////"),
    ] {
        let note = SignedNote::new("log\n1\nx\n")
            .expect("valid")
            .with_signature(NoteSignature {
                name: "k".into(),
                key_id: [payload[0], payload[1], payload[2], payload[3]],
                signature: payload[4..].to_vec(),
            });
        let wire = note.to_wire();
        assert!(
            wire.contains(expected),
            "payload {payload:?} must encode to {expected}, but the wire form was:\n{wire}"
        );
        // Round-tripped only where the payload is a *valid* one. Four bytes is
        // a key id with no signature, which the parser rightly refuses — so
        // that case checks the encoder alone.
        if payload.len() > 4 {
            let back = SignedNote::parse(&wire).expect("parse");
            let s = &back.signatures[0];
            let mut round = s.key_id.to_vec();
            round.extend_from_slice(&s.signature);
            assert_eq!(round, payload, "decode disagreed with encode");
        }
    }
}

/// A note body containing a blank line is refused at construction.
///
/// `parse` splits at the first blank line, so such a body cannot be read back
/// as itself — and every signature over it would cover more bytes than a
/// verifier hashes. The note looks perfectly well-formed until somebody checks
/// a signature, which is why it is caught when it is built.
#[test]
fn a_body_with_a_blank_line_cannot_round_trip_and_is_refused() {
    use agentplane::journal::SignedNote;

    let err = SignedNote::new("example.com/log\n\n42\n")
        .expect_err("a body containing the separator cannot round-trip");
    assert!(
        err.to_string().contains("blank line"),
        "the refusal must name what is wrong: {err}"
    );

    // The ordinary shape is unaffected: a checkpoint body is three lines.
    SignedNote::new(log(1).1.to_note()).expect("a checkpoint body is valid");
}

/// An unseen origin is at size zero, not "whatever you say".
///
/// The in-process witness stands in for the remote one, so it has to refuse the
/// same submissions. Treating an unknown origin as accepting any `old_size`
/// made it *more permissive* than the thing it models — a submission would pass
/// here and come back 409 in production.
#[tokio::test]
async fn an_unseen_origin_starts_at_zero() {
    let w = witness();
    let (_, cp) = log(4);

    match w.cosign(&cp, 3, &[]).await {
        Err(WitnessError::Stale { witness_size, .. }) => {
            assert_eq!(witness_size, 0, "an unseen log has no entries");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!(
            "a first submission claiming to extend from size 3 was accepted — the \
             remote witness would answer 409"
        ),
    }

    // Claiming zero is the honest first submission, and must work.
    w.cosign(&cp, 0, &[])
        .await
        .expect("a first checkpoint extends from nothing");
}

// ── Quorum: the policy half ─────────────────────────────────────────────────
//
// The number of cosignatures that suffice is a trust decision only a
// deployment can make. What the runtime owns is making the declared number
// enforceable and its shortfall loud — and never letting a met quorum silence
// a witness that remembers a different history.

/// A witness that is down. Routine, not an integrity event.
#[derive(Debug)]
struct Down;

#[async_trait::async_trait]
impl Witness for Down {
    async fn cosign(
        &self,
        _checkpoint: &Checkpoint,
        _old_size: u64,
        _proof: &[Digest],
    ) -> Result<agentplane::journal::Cosignature, WitnessError> {
        Err(WitnessError::Unavailable("connection refused".into()))
    }
}

/// Seal `n` runs so the store has a real log to prove consistency over.
async fn sealed_store(n: usize) -> Arc<agentplane::store::RedbStore> {
    use agentplane::journal::{Append, JournalStore, RecordKind};
    let store = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    for _ in 0..n {
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
                    },
                )],
            )
            .await
            .expect("append");
        store
            .seal(run, lease.epoch, "succeeded")
            .await
            .expect("seal");
    }
    store
}

/// Enough fresh witnesses cosign, and the report says nothing needs a person.
#[tokio::test]
async fn a_met_quorum_with_no_refusals_needs_nobody() {
    use agentplane::journal::{JournalStore, WitnessQuorum, cosign_quorum};

    let store = sealed_store(3).await;
    let cp = store.checkpoint().await.expect("checkpoint");
    let witnesses: Vec<Arc<dyn Witness>> = vec![Arc::new(witness()), Arc::new(witness())];

    let outcome = cosign_quorum(
        store.as_ref(),
        &cp,
        &witnesses,
        WitnessQuorum::of(2).expect("two"),
    )
    .await
    .expect("submission");

    assert!(outcome.met(), "two fresh witnesses did not cosign");
    assert_eq!(outcome.shortfall(), 0);
    assert!(!outcome.needs_attention());
    assert_eq!(outcome.cosignatures.len(), 2);
}

/// A shortfall is a finding, not a log line: the declared bar was not reached.
#[tokio::test]
async fn a_shortfall_demands_attention_and_says_how_much() {
    use agentplane::journal::{JournalStore, WitnessQuorum, cosign_quorum};

    let store = sealed_store(2).await;
    let cp = store.checkpoint().await.expect("checkpoint");
    let witnesses: Vec<Arc<dyn Witness>> = vec![Arc::new(witness()), Arc::new(Down)];

    let outcome = cosign_quorum(
        store.as_ref(),
        &cp,
        &witnesses,
        WitnessQuorum::of(2).expect("two"),
    )
    .await
    .expect("submission");

    assert!(!outcome.met());
    assert_eq!(outcome.shortfall(), 1);
    assert!(outcome.needs_attention());
    assert_eq!(
        outcome.routine.len(),
        1,
        "the outage is routine, on the record"
    );
    assert!(outcome.integrity.is_empty(), "an outage is not a fork");
}

/// **A met quorum does not silence a fork.** One witness among three remembers
/// a different history at this size; two honest cosigners are not a reason to
/// look away from the third — they may simply never have seen what it saw.
#[tokio::test]
async fn a_fork_report_survives_a_met_quorum() {
    use agentplane::journal::{JournalStore, WitnessQuorum, cosign_quorum};

    let store = sealed_store(3).await;
    let cp = store.checkpoint().await.expect("checkpoint");

    // This witness cosigned a *different* history of the same origin and size.
    let poisoned = witness();
    let forged = Checkpoint {
        origin: cp.origin.clone(),
        size: cp.size,
        root: Digest::of(b"a history that never happened"),
    };
    poisoned
        .cosign(&forged, 0, &[])
        .await
        .expect("the forged history is internally consistent");

    let witnesses: Vec<Arc<dyn Witness>> =
        vec![Arc::new(witness()), Arc::new(witness()), Arc::new(poisoned)];
    let outcome = cosign_quorum(
        store.as_ref(),
        &cp,
        &witnesses,
        WitnessQuorum::of(2).expect("two"),
    )
    .await
    .expect("submission");

    assert!(outcome.met(), "the two honest witnesses cosigned");
    assert_eq!(outcome.integrity.len(), 1, "the fork is on the record");
    assert!(
        matches!(outcome.integrity[0].1, WitnessError::Forked { .. }),
        "wrong classification: {:?}",
        outcome.integrity[0].1
    );
    assert!(
        outcome.needs_attention(),
        "a met quorum silenced a fork report — the alarm witnessing exists for"
    );
}

/// The stale answer heals itself: the witness names its cursor, the caller
/// builds the proof from there, and the retry cosigns. The C2SP 409 dance.
#[tokio::test]
async fn a_stale_witness_is_healed_with_a_proof_from_its_cursor() {
    use agentplane::journal::{Append, JournalStore, RecordKind, WitnessQuorum, cosign_quorum};

    let store = sealed_store(1).await;
    let early = store.checkpoint().await.expect("first checkpoint");
    let w = Arc::new(witness());
    w.cosign(&early, 0, &[]).await.expect("first sight");

    // The log grows while the witness is not looking.
    for _ in 0..2 {
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
                    },
                )],
            )
            .await
            .expect("append");
        store
            .seal(run, lease.epoch, "succeeded")
            .await
            .expect("seal");
    }
    let late = store.checkpoint().await.expect("grown checkpoint");

    let witnesses: Vec<Arc<dyn Witness>> = vec![w];
    let outcome = cosign_quorum(
        store.as_ref(),
        &late,
        &witnesses,
        WitnessQuorum::of(1).expect("one"),
    )
    .await
    .expect("submission");

    assert!(
        outcome.met(),
        "the stale cursor was not healed: routine {:?}, integrity {:?}",
        outcome.routine,
        outcome.integrity
    );
    assert!(!outcome.needs_attention());
}
