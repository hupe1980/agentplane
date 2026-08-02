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
    w.cosign(&first, &[]).await.expect("first checkpoint");

    let (leaves, second) = log(5);
    let proof = merkle::consistency_proof(&leaves, 3);
    w.cosign(&second, &proof).await.expect("an extension");

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
    w.cosign(&big, &[]).await.expect("first checkpoint");

    let (_, small) = log(3);
    match w.cosign(&small, &[]).await {
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
    w.cosign(&real, &[]).await.expect("the real history");

    let forged = Checkpoint {
        origin: "plane-a".into(),
        size: 4,
        root: Digest::of(b"a different history of the same four runs"),
    };
    match w.cosign(&forged, &[]).await {
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
    w.cosign(&first, &[]).await.expect("first checkpoint");

    let (_, second) = log(6);
    match w.cosign(&second, &[]).await {
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
    w.cosign(&first, &[]).await.expect("first checkpoint");

    let (_, second) = log(6);
    let nonsense = vec![Digest::of(b"not a real audit path")];
    match w.cosign(&second, &nonsense).await {
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
    w.cosign(&cp, &[]).await.expect("first");
    w.cosign(&cp, &[])
        .await
        .expect("the very same checkpoint again");
}
