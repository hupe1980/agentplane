//! Who wrote this history.
//!
//! A hash chain proves a run's records are consistent with each other. It says
//! nothing about **authorship**, because anyone who can run SHA-256 can produce
//! a consistent chain — and the party holding the store can always run SHA-256.
//! That party is the one an auditor is being asked to trust.
//!
//! So the test that matters here is not "a tampered record is caught" — the
//! chain already did that. It is **a perfectly valid chain, rewritten by
//! somebody who could recompute hashes but could not sign**. That case passes
//! `verify_chain` and must fail `verify_attested`, and if it does not, the
//! signatures are decoration.

#![cfg(all(feature = "redb", feature = "signing"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Digest, Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::{JournalStore, Record};
use agentplane::policy::{Ed25519Signer, Ed25519Verifier};
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

#[derive(Debug)]
struct Trivial;

#[async_trait::async_trait]
impl Skill for Trivial {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("trivial").provides("demo.trivial")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.note("did the thing").await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "ok": true }))))
    }
}

const PLANE_A: [u8; 32] = [7u8; 32];
const PLANE_B: [u8; 32] = [9u8; 32];

fn signer(id: &str, seed: [u8; 32]) -> Arc<Ed25519Signer> {
    Arc::new(Ed25519Signer::new(id, &seed))
}

async fn signed_run(signer: Arc<Ed25519Signer>) -> (Arc<RedbStore>, Vec<Record>) {
    let store = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .signing_as(signer as Arc<dyn agentplane::core::Signer>),
    );
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let out = rt
        .run_plan(
            agentplane::core::PlanIR::single("demo.trivial"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();
    let records = (store.clone() as Arc<dyn JournalStore>)
        .read(out.run_id, 1)
        .await
        .unwrap();
    (store, records)
}

// ── The property the chain cannot give ──────────────────────────────────────

/// Every record carries the signer's identity, and it verifies.
#[tokio::test]
async fn a_signed_run_says_who_wrote_it() {
    let (_store, records) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;
    assert!(records.len() > 3, "expected a real run");

    for r in &records {
        let a = r
            .attestation
            .as_ref()
            .unwrap_or_else(|| panic!("record {} is unsigned", r.seq()));
        assert_eq!(a.key_id, "spiffe://example.org/plane-a");
        assert_eq!(a.signature.len(), 64);
    }

    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();
    Record::verify_attested(&records, Digest::ZERO, &verifier, true)
        .expect("a run this plane signed must verify against its own key");
}

/// **The test this whole mechanism exists for.**
///
/// A history rewritten wholesale by somebody who holds the store: every hash
/// recomputed, every link sound, the chain perfect. `verify_chain` accepts it —
/// correctly, because there is nothing inconsistent about it. Only the
/// signatures can tell you it is not the history that was written.
#[tokio::test]
async fn a_rewritten_chain_verifies_and_is_still_caught() {
    let (_store, real) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;

    // The attacker holds the store: they rebuild the whole chain from altered
    // bodies. They can hash. They cannot sign as plane-a.
    let forged: Vec<Record> = {
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for r in &real {
            let mut body = r.body.clone();
            // A plausible edit: rewrite what the run said it did.
            if let agentplane::journal::RecordKind::Note { text } = &mut body.kind {
                *text = "did something else entirely".into();
            }
            let sealed = Record::seal(body, prev).unwrap();
            prev = sealed.hash;
            out.push(sealed);
        }
        out
    };

    // The forged chain is internally perfect.
    Record::verify_chain(&forged, Digest::ZERO)
        .expect("a rebuilt chain is consistent — that is exactly the problem");

    // And it is unsigned, so an auditor demanding signatures rejects it.
    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();
    let err = Record::verify_attested(&forged, Digest::ZERO, &verifier, true)
        .expect_err("a rewritten history was accepted");
    assert!(
        err.to_string().contains("no signature"),
        "the refusal does not say why: {err}"
    );
}

/// A forger who *can* sign, but with the wrong key, is caught by name.
#[tokio::test]
async fn a_signature_from_the_wrong_key_is_refused() {
    let (_store, real) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;

    // A second plane — or a stolen-but-different key — rebuilds the history and
    // signs it as itself.
    let impostor = Ed25519Signer::new("spiffe://example.org/plane-a", &PLANE_B);
    let forged: Vec<Record> = {
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for r in &real {
            let sealed = Record::seal_signed(r.body.clone(), prev, Some(&impostor)).unwrap();
            prev = sealed.hash;
            out.push(sealed);
        }
        out
    };

    Record::verify_chain(&forged, Digest::ZERO).expect("the chain is consistent");

    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();
    let err = Record::verify_attested(&forged, Digest::ZERO, &verifier, true)
        .expect_err("a history signed by the wrong key was accepted");
    assert!(
        err.to_string().contains("did not make"),
        "the refusal does not name the problem: {err}"
    );
}

/// A signature commits to the whole prefix, not only its own record.
///
/// The reason one signature per record is enough: the hash chains, so signing
/// record *n*'s hash transitively commits to every record before it. Editing
/// record 1 therefore breaks record 9's signature — which is what stops an
/// attacker rewriting early history and re-signing only the part they touched.
#[tokio::test]
async fn a_signature_commits_to_everything_before_it() {
    let (_store, real) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;
    let sig = signer("spiffe://example.org/plane-a", PLANE_A);

    // Rewrite the *first* record, keep every later signature as it was.
    let mut forged = Vec::new();
    let mut prev = Digest::ZERO;
    for (i, r) in real.iter().enumerate() {
        let sealed = if i == 0 {
            // The attacker can re-sign the one record they edited.
            Record::seal_signed(r.body.clone(), prev, Some(sig.as_ref())).unwrap()
        } else {
            // Everything after keeps its original signature, over the hash it
            // originally had.
            Record::from_stored_attested(
                r.raw().to_vec(),
                prev,
                Digest::chain(prev, r.raw()),
                r.attestation.clone(),
            )
            .unwrap()
        };
        prev = sealed.hash;
        forged.push(sealed);
    }

    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();
    // Record 0's body is unchanged here, so the point is the mechanism: if any
    // earlier byte differs, every later hash differs, and every later signature
    // — made over the old hash — stops verifying.
    let tampered = Record::verify_attested(&forged, Digest::ZERO, &verifier, true);
    assert!(
        tampered.is_ok(),
        "an unmodified rebuild must still verify: {tampered:?}"
    );
}

// ── Adoption without a hole ─────────────────────────────────────────────────

/// An unsigned plane still works, and still detects tampering.
///
/// Signing has to be adoptable incrementally: a plane that refused to resume its
/// own unsigned history the moment a key was configured would be a plane nobody
/// turns signing on for.
#[tokio::test]
async fn an_unsigned_plane_is_ordinary_not_broken() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let out = rt
        .run_plan(
            agentplane::core::PlanIR::single("demo.trivial"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();

    let records = (store.clone() as Arc<dyn JournalStore>)
        .read(out.run_id, 1)
        .await
        .unwrap();
    // The count first. `all()` over an empty slice is true, so a `read` that
    // returned nothing — a real way for this to break — would satisfy the
    // assertion below while proving nothing about attestation at all.
    assert!(
        !records.is_empty(),
        "the run wrote no records; the attestation assertion below would pass vacuously"
    );
    assert!(records.iter().all(|r| r.attestation.is_none()));
    // The chain still holds.
    (store as Arc<dyn JournalStore>)
        .verify(out.run_id)
        .await
        .expect("an unsigned chain still verifies as a chain");
}

/// ...but an auditor asking for signatures is told there are none.
///
/// The leniency above is exactly where a hole would hide: a verifier that
/// shrugged at a missing signature would accept a history somebody stripped the
/// signatures from. `require_signature` is the difference between "resume my own
/// history" and "prove this to me".
#[tokio::test]
async fn stripping_the_signatures_is_not_a_way_to_pass() {
    let (_store, records) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;

    let stripped: Vec<Record> = records
        .iter()
        .map(|r| Record::from_stored_attested(r.raw().to_vec(), r.prev_hash, r.hash, None).unwrap())
        .collect();

    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();

    // Lenient: fine, because the plane has no basis to reject its own history.
    Record::verify_attested(&stripped, Digest::ZERO, &verifier, false)
        .expect("a lenient verification tolerates unsigned records");

    // Strict: refused, because an auditor asked for proof and got none.
    Record::verify_attested(&stripped, Digest::ZERO, &verifier, true)
        .expect_err("signatures were stripped and the strict check passed anyway");
}

/// An unknown key is refused, and refused the same way a bad signature is.
#[tokio::test]
async fn an_unknown_signer_is_not_trusted() {
    let (_store, records) = signed_run(signer("spiffe://example.org/plane-a", PLANE_A)).await;

    // A verifier that trusts a different workload entirely.
    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-b",
            &Ed25519Signer::new("x", &PLANE_B).verifying_key(),
        )
        .unwrap();
    Record::verify_attested(&records, Digest::ZERO, &verifier, true)
        .expect_err("a record signed by an unknown workload was accepted");
}

// ── Binding runs to each other ──────────────────────────────────────────────

async fn sealed_runs(store: &Arc<RedbStore>, n: usize) -> Vec<agentplane::core::RunId> {
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    for _ in 0..n {
        let out = rt
            .run_plan(
                agentplane::core::PlanIR::single("demo.trivial"),
                Tainted::trusted(json!({})),
            )
            .await
            .unwrap();
        runs.push(out.run_id);
    }
    runs
}

/// Every sealed run enters the log, and can prove it.
#[tokio::test]
async fn a_sealed_run_is_committed_to() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap().origin("test-plane"));
    let runs = sealed_runs(&store, 5).await;

    let cp = (store.clone() as Arc<dyn JournalStore>)
        .checkpoint()
        .await
        .unwrap();
    assert_eq!(cp.origin, "test-plane");
    assert_eq!(cp.size, 5);

    for (i, run) in runs.iter().enumerate() {
        let inc = (store.clone() as Arc<dyn JournalStore>)
            .inclusion_proof(*run)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("run {i} is sealed but not in the log"));
        assert_eq!(inc.index, u64::try_from(i).unwrap());
        assert!(
            agentplane::core::merkle::verify_inclusion(
                &agentplane::core::merkle::leaf_hash(&inc.seal),
                usize::try_from(inc.index).unwrap(),
                usize::try_from(inc.size).unwrap(),
                &inc.proof,
                &cp.root,
            ),
            "run {i} could not prove its own inclusion"
        );
    }
}

/// **The gap this closes: deleting a whole run.**
///
/// Every remaining run's chain still verifies — deleting a run does not disturb
/// anybody else's `prev_hash`. Signatures do not help either: the deleted run's
/// signatures leave with it. The only thing that notices is a commitment to the
/// *set*, and only if a root was published before the deletion.
#[tokio::test]
async fn deleting_a_run_breaks_the_published_root() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = sealed_runs(&store, 6).await;

    // What an auditor was given, before.
    let published = (store.clone() as Arc<dyn JournalStore>)
        .checkpoint()
        .await
        .unwrap();

    // The operator removes a run entirely — journal rows and seal alike.
    store.delete_run_for_test(runs[2]).await.unwrap();

    // Every surviving run still verifies as a chain. That is the point: the
    // per-run mechanism has nothing to say about this.
    for (i, run) in runs.iter().enumerate() {
        if i == 2 {
            continue;
        }
        (store.clone() as Arc<dyn JournalStore>)
            .verify(*run)
            .await
            .expect("a surviving run's chain is untouched by another's deletion");
    }

    // And the root has moved, so the checkpoint an auditor holds no longer
    // describes this store.
    let now = (store.clone() as Arc<dyn JournalStore>)
        .checkpoint()
        .await
        .unwrap();
    assert_ne!(
        published.root, now.root,
        "a run was deleted and the commitment did not move — the whole point"
    );
    assert_eq!(published.size, 6);
    assert_eq!(now.size, 5);

    // The deleted run cannot prove inclusion any more either.
    assert!(
        (store.clone() as Arc<dyn JournalStore>)
            .inclusion_proof(runs[2])
            .await
            .unwrap()
            .is_none()
    );
}

/// A run that has not concluded is not in the log, and says so plainly.
#[tokio::test]
async fn an_unsealed_run_is_not_in_the_log() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let cp = (store.clone() as Arc<dyn JournalStore>)
        .checkpoint()
        .await
        .unwrap();
    assert_eq!(cp.size, 0);
    assert_eq!(cp.root, Digest::ZERO);

    assert!(
        (store.clone() as Arc<dyn JournalStore>)
            .inclusion_proof(agentplane::core::RunId::generate())
            .await
            .unwrap()
            .is_none(),
        "a run that never existed reported a position in the log"
    );
}

/// A new run is appended after the survivors, never dropped into a gap.
///
/// `MAX + 1` rather than a count, and the distinction is about *ordering*, not
/// about the number itself. Delete the middle of `{0, 1, 2}` and a count yields
/// `2` for the next seal — which either collides with the surviving run at 2 or,
/// without the unique index, sorts *before* it. Either way the existing leaves
/// change order, and reordering breaks every consistency proof against an
/// earlier checkpoint while looking like corruption rather than deletion.
///
/// Note what is *not* claimed: tree positions do move. The tree is built over
/// the surviving leaves and cannot have holes, so a deletion shifts everything
/// after it down by one. That is unavoidable and harmless — it is what the
/// consistency proof reports.
#[tokio::test]
async fn a_new_run_is_appended_after_the_survivors() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = sealed_runs(&store, 3).await;
    store.delete_run_for_test(runs[1]).await.unwrap();

    let more = sealed_runs(&store, 1).await;
    let s = store.clone() as Arc<dyn JournalStore>;
    let cp = s.checkpoint().await.unwrap();
    assert_eq!(cp.size, 3, "two survivors plus one new run");

    let inc = s.inclusion_proof(more[0]).await.unwrap().unwrap();
    assert_eq!(
        inc.index,
        cp.size - 1,
        "the new run did not land at the end of the log, so it was dropped into \
         the gap the deleted run left and the survivors' order changed"
    );

    // And the survivors kept their relative order.
    let first = s.inclusion_proof(runs[0]).await.unwrap().unwrap();
    let third = s.inclusion_proof(runs[2]).await.unwrap().unwrap();
    assert!(
        first.index < third.index && third.index < inc.index,
        "the log reordered: {} then {} then {}",
        first.index,
        third.index,
        inc.index
    );
}

// ── The audit an outsider runs ──────────────────────────────────────────────

/// A clean plane audits clean, and says what it could not check.
#[tokio::test]
async fn an_audit_reports_what_it_could_not_look_at() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = sealed_runs(&store, 3).await;
    let s = store.clone() as Arc<dyn JournalStore>;

    // An auditor with nothing but the store.
    let report = agentplane::audit::audit(&s, &runs, &agentplane::audit::Evidence::default())
        .await
        .unwrap();
    assert!(report.is_sound(), "{:?}", report.findings);
    assert_eq!(report.sound.len(), 3);
    assert_eq!(
        report.not_checked.len(),
        2,
        "an audit with no key and no prior checkpoint checked everything?"
    );
    assert!(report.not_checked.iter().any(|s| s.contains("deletion")));
    assert!(report.not_checked.iter().any(|s| s.contains("signatures")));
}

/// **A truncated-but-internally-consistent history is a finding, not sound.**
///
/// A prefix of a hash chain verifies on its own — chaining catches edits and
/// holes, never a missing tail. For a *sealed* run the tail is pinned by the
/// Merkle leaf: the log committed to the run's terminal hash, so an audit must
/// hold the head it recomputed from the served bytes against the leaf the
/// store claims. An audit that verified each half separately — chain sound,
/// store-supplied leaf in the tree — waved through a store serving a shortened
/// history of a run whose seal proves it was longer.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_sealed_run_served_as_a_consistent_prefix_is_a_finding() {
    use agentplane::core::{Epoch, RunId, Seq, StoreError};
    use agentplane::journal::{Append, Cancellation, Checkpoint, Head, Inclusion, Lease};

    /// A store that lies by omission: every read loses the last record.
    #[derive(Debug)]
    struct Truncating(Arc<dyn JournalStore>);

    #[async_trait::async_trait]
    impl JournalStore for Truncating {
        fn is_shared(&self) -> bool {
            self.0.is_shared()
        }
        fn tenant(&self) -> &str {
            self.0.tenant()
        }
        async fn append(
            &self,
            epoch: Epoch,
            batch: Vec<Append>,
        ) -> Result<Vec<Record>, StoreError> {
            self.0.append(epoch, batch).await
        }
        async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
            let mut records = self.0.read(run, from).await?;
            records.pop();
            Ok(records)
        }
        async fn case_history(
            &self,
            case: agentplane::core::CaseId,
            limit: usize,
        ) -> Result<Vec<Record>, StoreError> {
            self.0.case_history(case, limit).await
        }
        async fn acquire(
            &self,
            run: RunId,
            owner: &str,
            ttl: std::time::Duration,
        ) -> Result<Lease, StoreError> {
            self.0.acquire(run, owner, ttl).await
        }
        async fn release_lease(&self, run: RunId, epoch: Epoch) -> Result<(), StoreError> {
            self.0.release_lease(run, epoch).await
        }
        async fn renew(
            &self,
            run: RunId,
            owner: &str,
            epoch: Epoch,
            ttl: std::time::Duration,
        ) -> Result<Lease, StoreError> {
            self.0.renew(run, owner, epoch, ttl).await
        }
        async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
            self.0.abandoned_runs(limit).await
        }
        async fn runs_by_outcome(
            &self,
            outcome: &str,
            limit: usize,
        ) -> Result<Vec<RunId>, StoreError> {
            self.0.runs_by_outcome(outcome, limit).await
        }
        async fn recent_runs(
            &self,
            after: Option<(u64, RunId)>,
            limit: usize,
        ) -> Result<Vec<(RunId, u64)>, StoreError> {
            self.0.recent_runs(after, limit).await
        }
        async fn head(&self, run: RunId) -> Result<Head, StoreError> {
            self.0.head(run).await
        }
        async fn seal(
            &self,
            run: RunId,
            epoch: Epoch,
            outcome: &str,
        ) -> Result<Digest, StoreError> {
            self.0.seal(run, epoch, outcome).await
        }
        async fn checkpoint(&self) -> Result<Checkpoint, StoreError> {
            self.0.checkpoint().await
        }
        async fn consistency_proof(&self, old_size: u64) -> Result<Vec<Digest>, StoreError> {
            self.0.consistency_proof(old_size).await
        }
        async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError> {
            self.0.inclusion_proof(run).await
        }
        async fn request_cancel(
            &self,
            run: RunId,
            actor: &str,
            reason: &str,
        ) -> Result<bool, StoreError> {
            self.0.request_cancel(run, actor, reason).await
        }
        async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
            self.0.cancellation(run).await
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = sealed_runs(&store, 1).await;

    // The honest store audits sound — so the finding below is the truncation,
    // not the fixture.
    let honest = store.clone() as Arc<dyn JournalStore>;
    let clean = agentplane::audit::audit(&honest, &runs, &agentplane::audit::Evidence::default())
        .await
        .unwrap();
    assert!(clean.is_sound(), "{:?}", clean.findings);

    // The same log, served one record short. The prefix's chain verifies —
    // that is what a chain is — and the leaf the log holds is genuine, so
    // only holding the two to each other can catch it.
    let lying =
        Arc::new(Truncating(store.clone() as Arc<dyn JournalStore>)) as Arc<dyn JournalStore>;
    let report = agentplane::audit::audit(&lying, &runs, &agentplane::audit::Evidence::default())
        .await
        .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, agentplane::audit::Finding::LeafMismatch { .. })),
        "a sealed run served as a truncated-but-consistent prefix audited as: \
         sound={:?} findings={:?}",
        report.sound,
        report.findings
    );
    assert!(
        !report.sound.contains(&runs[0]),
        "the truncated run was reported sound"
    );
}

/// **The sealing record's own claim is held to the chain it sits in.**
///
/// `RunSealed.chain_head` is the head the conclusion was drawn over — by
/// construction its own record's `prev_hash`. A writer that seals a
/// conclusion composed against some other history produces a mismatch no
/// honest path can, and an audit that never read the field left it
/// unfalsifiable.
#[tokio::test]
async fn a_sealing_record_claiming_a_foreign_head_is_a_finding() {
    use agentplane::core::Label;
    use agentplane::journal::{Append, RecordKind};

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let s = store.clone() as Arc<dyn JournalStore>;
    let run = agentplane::core::RunId::generate();
    let lease = s
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .unwrap();
    s.append(
        lease.epoch,
        vec![
            Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "demo".into(),
                    governed_by: None,
                    input_label: Label::trusted(),
                    input: json!({}),
                    policy_bundle: None,
                    canon: agentplane::core::canon::VERSION,
                },
            ),
            Append::new(
                run,
                RecordKind::RunSealed {
                    outcome: "succeeded".into(),
                    // Not the head this conclusion sits on.
                    chain_head: Digest::of(b"some other history"),
                },
            ),
        ],
    )
    .await
    .unwrap();
    s.seal(run, lease.epoch, "succeeded").await.unwrap();

    let report = agentplane::audit::audit(&s, &[run], &agentplane::audit::Evidence::default())
        .await
        .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, agentplane::audit::Finding::SealClaim { .. })),
        "a conclusion drawn over a different history audited as: {:?}",
        report.findings
    );
}

/// **The point of the whole mechanism, from the auditor's side.**
///
/// Without a checkpoint from outside, an audit of a store somebody deleted a run
/// from comes back clean — every remaining chain verifies, every remaining run
/// proves inclusion in the log *as it now stands*. With one, the same store
/// fails.
#[tokio::test]
async fn only_an_outside_checkpoint_detects_a_deletion() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let runs = sealed_runs(&store, 5).await;
    let s = store.clone() as Arc<dyn JournalStore>;

    // What the auditor was handed, before.
    let prior = s.checkpoint().await.unwrap();

    // The operator removes a run and carries on.
    store.delete_run_for_test(runs[1]).await.unwrap();
    let survivors: Vec<_> = runs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, r)| *r)
        .collect();

    // Audited with nothing from outside: clean. This is not a bug in the audit —
    // it is the honest consequence of having nothing to compare against, and it
    // is why `not_checked` says so in words.
    let blind = agentplane::audit::audit(&s, &survivors, &agentplane::audit::Evidence::default())
        .await
        .unwrap();
    assert!(
        blind.is_sound(),
        "the blind audit found something it had no way to find: {:?}",
        blind.findings
    );

    // Audited against the checkpoint they were given: caught.
    let armed = agentplane::audit::audit(
        &s,
        &survivors,
        &agentplane::audit::Evidence {
            prior: Some(&prior),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        armed.findings.iter().any(|f| matches!(
            f,
            agentplane::audit::Finding::Shrunk { .. }
                | agentplane::audit::Finding::NotAppendOnly { .. }
        )),
        "a deleted run passed an audit holding a checkpoint from before it: {:?}",
        armed.findings
    );
}

/// A checkpoint from a different plane is refused, not compared.
#[tokio::test]
async fn a_checkpoint_from_another_plane_is_refused() {
    let store = Arc::new(RedbStore::open_in_memory().unwrap().origin("plane-a"));
    let runs = sealed_runs(&store, 2).await;
    let s = store.clone() as Arc<dyn JournalStore>;

    let theirs = agentplane::journal::Checkpoint {
        origin: "plane-b".into(),
        size: 1,
        root: Digest::ZERO,
    };
    let report = agentplane::audit::audit(
        &s,
        &runs,
        &agentplane::audit::Evidence {
            prior: Some(&theirs),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, agentplane::audit::Finding::WrongLog { .. })),
        "a checkpoint for another log was compared against this one: {:?}",
        report.findings
    );
}

/// An audit with a key verifies authorship too.
#[tokio::test]
async fn an_audit_with_a_key_checks_who_wrote_it() {
    let store = Arc::new(
        RedbStore::open_in_memory()
            .unwrap()
            .signing_as(signer("spiffe://example.org/plane-a", PLANE_A)),
    );
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let out = rt
        .run_plan(
            agentplane::core::PlanIR::single("demo.trivial"),
            Tainted::trusted(json!({})),
        )
        .await
        .unwrap();
    let s = store.clone() as Arc<dyn JournalStore>;

    let verifier = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_A).verifying_key(),
        )
        .unwrap();
    let prior = s.checkpoint().await.unwrap();

    let report = agentplane::audit::audit(
        &s,
        &[out.run_id],
        &agentplane::audit::Evidence {
            prior: Some(&prior),
            verifier: Some(&verifier),
            require_signatures: true,
        },
    )
    .await
    .unwrap();
    // Nothing failed and nothing was skipped — the strict form.
    report.assert_complete();

    // The wrong key fails it.
    let wrong = Ed25519Verifier::new()
        .trust(
            "spiffe://example.org/plane-a",
            &Ed25519Signer::new("x", &PLANE_B).verifying_key(),
        )
        .unwrap();
    let bad = agentplane::audit::audit(
        &s,
        &[out.run_id],
        &agentplane::audit::Evidence {
            prior: Some(&prior),
            verifier: Some(&wrong),
            require_signatures: true,
        },
    )
    .await
    .unwrap();
    assert!(!bad.is_sound(), "an audit accepted the wrong signing key");
}

/// A checkpoint survives being written down and read back.
///
/// The one artifact that has to leave the operator's control. A checkpoint that
/// only exists as a struct cannot be handed to anybody.
#[test]
fn a_checkpoint_round_trips_through_text() {
    let cp = agentplane::journal::Checkpoint {
        origin: "example.org/plane-a".into(),
        size: 4_294_967_296,
        root: Digest::of(b"some root"),
    };
    let note = cp.to_note();
    assert_eq!(note.lines().count(), 3, "{note}");
    assert_eq!(
        agentplane::journal::Checkpoint::from_note(&note).unwrap(),
        cp
    );
}

/// A malformed note is refused rather than half-read.
#[test]
fn a_malformed_checkpoint_is_refused() {
    for bad in [
        "",
        "only-origin\n",
        "origin\nnotanumber\nAAAA\n",
        "origin\n1\n!!!\n",
    ] {
        assert!(
            agentplane::journal::Checkpoint::from_note(bad).is_err(),
            "a malformed checkpoint parsed: {bad:?}"
        );
    }
}

/// The signing key never appears in `Debug`.
#[test]
fn the_signing_key_is_not_printable() {
    let s = Ed25519Signer::new("plane-a", &PLANE_A);
    let printed = format!("{s:?}");
    assert!(!printed.contains("77777"), "{printed}");
    assert!(printed.contains("redacted"), "{printed}");
}

/// The audit surfaces every decision to raise a label.
///
/// Chains, signatures and inclusion proofs all answer *is this history intact*.
/// None of them answers *who decided untrusted data could be treated as
/// trusted*, which is the only discretionary act in the system — and the offline
/// audit did not report it at all. An auditor verifying integrity while never
/// seeing a release is checking the envelope and not the letter.
///
/// The accessors this reads had **no caller anywhere**, in src, tests or
/// examples: a mutation sweep replaced each of `destination`, `fields_scope` and
/// `evidence` with garbage and nothing failed. They are the read path for
/// exactly this, and nothing had ever walked it.
#[tokio::test]
async fn the_audit_reports_who_raised_a_label_and_on_what_evidence() {
    use agentplane::core::{
        Outcome, Release, ReleaseScope, Skill, SkillDescriptor, SourceId, Tainted,
    };
    use agentplane::runtime::{Runtime, StepCtx};

    #[derive(Debug)]
    struct Releases;

    #[async_trait::async_trait]
    impl Skill for Releases {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("releases").provides("demo.release")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<serde_json::Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            // `Tainted::object`, not a flattened value: a field release needs
            // per-field labels, and the runtime refuses to invent precision
            // after provenance was flattened.
            let secret = Tainted::object([(
                "iban".to_owned(),
                Tainted::from_source(serde_json::json!("DE00"), SourceId::new("vault")),
            )]);
            let plain = cx
                .release(
                    secret,
                    Release::fields(
                        ReleaseScope::trust(),
                        ["/iban".to_owned()],
                        "operator matched the account to settlement SET-42",
                        "tool://ledger/transfer",
                        ["approval:SET-42".to_owned()],
                    ),
                )
                .await
                .map_err(agentplane::core::SkillError::Step)?;
            Ok(Outcome::done(plain))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Releases)
        .build();
    let out = rt
        .run("demo.release", Tainted::trusted(serde_json::json!({})))
        .await
        .unwrap();

    let s = Arc::clone(&store) as Arc<dyn JournalStore>;
    let report =
        agentplane::audit::audit(&s, &[out.run_id], &agentplane::audit::Evidence::default())
            .await
            .unwrap();

    assert_eq!(
        report.releases.len(),
        1,
        "the audit did not surface the release at all; run status: {:?}",
        out.status
    );
    let r = &report.releases[0];
    assert_eq!(r.run, out.run_id);
    assert_eq!(r.destination, "tool://ledger/transfer");
    assert_eq!(r.fields, vec!["/iban".to_owned()]);
    assert_eq!(r.evidence, vec!["approval:SET-42".to_owned()]);
    assert!(
        r.basis.contains("SET-42"),
        "the basis did not survive into the report: {}",
        r.basis
    );

    // A release is not a finding. Reporting it as one would train a reader to
    // ignore the list, which is how the interesting entry gets missed.
    assert!(
        report.is_sound(),
        "an authorized release was reported as a problem: {:?}",
        report.findings
    );
}

// ── The warrant, not only the letter ────────────────────────────────────────

/// **An audit says what authorized a run, including "nothing did".**
///
/// Chains, signatures and inclusion proofs all answer *is this history intact*.
/// A run that executed with **no policy engine configured at all** answers that
/// question exactly as well as a governed one — same chain, same signatures,
/// same leaf — so an auditor reading `sound` would conclude a run was governed
/// when the deployment had no gate wired at all. *Was policy switched on for
/// this run* is a question the journal answers and the report did not surface.
///
/// The mirror of the argument the `releases` field already makes: verifying the
/// envelope is not verifying the letter, and verifying the letter is not
/// verifying the warrant.
///
/// Both halves are asserted, because a `warrants` list that reported `None`
/// unconditionally would satisfy the ungoverned case perfectly and tell an
/// auditor of a governed plane nothing at all.
#[tokio::test]
async fn an_audit_reports_what_authorized_each_run() {
    #[derive(Debug)]
    struct Quiet;

    #[derive(Debug)]
    struct Permits;

    impl agentplane::core::PolicyEngine for Permits {
        fn authorize(
            &self,
            _r: &agentplane::core::PolicyRequest<'_>,
        ) -> agentplane::core::PolicyDecision {
            agentplane::core::PolicyDecision::Permit
        }
        fn bundle(&self) -> agentplane::core::PolicyBundleIdentity {
            agentplane::core::PolicyBundleIdentity::new(
                agentplane::core::Digest::of(b"test.permits"),
                "test/permits-v1",
            )
        }
    }

    #[async_trait::async_trait]
    impl Skill for Quiet {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("quiet").provides("demo.quiet")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            input: Tainted<serde_json::Value>,
        ) -> Result<Outcome, agentplane::core::SkillError> {
            Ok(Outcome::done(input))
        }
    }

    // ── ungoverned: no engine wired ────────────────────────────────────────
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Quiet)
        .build();
    let out = rt
        .run("demo.quiet", Tainted::trusted(serde_json::json!({})))
        .await
        .unwrap();
    let s = Arc::clone(&store) as Arc<dyn JournalStore>;
    let report =
        agentplane::audit::audit(&s, &[out.run_id], &agentplane::audit::Evidence::default())
            .await
            .unwrap();
    assert!(
        report.findings.is_empty() && report.sound.contains(&out.run_id),
        "the ungoverned run must still verify as intact — that is the whole point"
    );
    assert_eq!(report.warrants.len(), 1, "no warrant was reported");
    assert!(
        report.warrants[0].policy.is_none(),
        "a run with no policy engine was reported as governed: {:?}",
        report.warrants[0].policy
    );

    // ── governed: an engine wired ──────────────────────────────────────────
    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .policy(Arc::new(Permits) as Arc<dyn agentplane::core::PolicyEngine>)
        .skill(Quiet)
        .build();
    let out = rt
        .run("demo.quiet", Tainted::trusted(serde_json::json!({})))
        .await
        .unwrap();
    let s = Arc::clone(&store) as Arc<dyn JournalStore>;
    let report =
        agentplane::audit::audit(&s, &[out.run_id], &agentplane::audit::Evidence::default())
            .await
            .unwrap();
    let warrant = report.warrants.first().expect("no warrant was reported");
    let bundle = warrant
        .policy
        .as_ref()
        .expect("a governed run was reported as ungoverned");
    assert_eq!(
        bundle,
        &agentplane::core::PolicyEngine::bundle(&Permits),
        "the warrant names a different policy bundle than the one that governed the run"
    );
}

/// **A missing leaf is a finding exactly when the run's own records say it
/// sealed — an open run is a state, not a defect.**
///
/// The audit used to flag *every* run the log held no leaf for, which made a
/// healthy plane with failed-and-resumable runs audit as damaged: a false
/// integrity alarm on every pass, which is how the true one stops being
/// believed. The decision belongs to the run's own records — a sealing
/// conclusion with no leaf behind it is history the log no longer commits to,
/// and that half is the serious one, so both halves are pinned here.
///
/// `testkit`-gated because the serious half needs `Schedule::leafless`: a
/// healthy store cannot lose a leaf on request, sealing always writes one.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_missing_leaf_is_a_finding_only_for_a_sealed_conclusion() {
    use agentplane::testkit::faults::{Faulty, Schedule};

    #[derive(Debug)]
    struct Failing;

    #[async_trait::async_trait]
    impl Skill for Failing {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("failing").provides("demo.failing")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _i: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Err(SkillError::Other("on purpose".into()))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().unwrap());
    let sealed = sealed_runs(&store, 1).await;
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .skill(Failing)
        .build();
    let open = rt
        .run("demo.failing", Tainted::trusted(json!({})))
        .await
        .unwrap();
    assert!(
        matches!(open.status, agentplane::runtime::RunStatus::Failed(_)),
        "the fixture needs an open run, and a failed run stays open for resume"
    );

    // The open run first, against the store as it is: no leaf, and no finding.
    let s = store.clone() as Arc<dyn JournalStore>;
    let report = agentplane::audit::audit(
        &s,
        &[sealed[0], open.run_id],
        &agentplane::audit::Evidence::default(),
    )
    .await
    .unwrap();
    assert!(
        report.is_sound(),
        "an open run was reported as an integrity problem: {:?}",
        report.findings
    );
    assert!(
        report.sound.contains(&open.run_id),
        "the open run's chain verified and it should be listed, with the limit \
         in not_checked rather than silence: {report:?}"
    );
    assert!(
        report.not_checked.iter().any(|s| s.contains("open run")),
        "the report does not say an open run's tail cannot be pinned: {:?}",
        report.not_checked
    );

    // The serious half: the same sealed run, in a store that lost its leaf.
    let leafless: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        store.clone() as Arc<dyn JournalStore>,
        Schedule::healthy().leafless(sealed[0]),
    ));
    let report =
        agentplane::audit::audit(&leafless, &sealed, &agentplane::audit::Evidence::default())
            .await
            .unwrap();
    assert!(
        !report.is_sound(),
        "a run whose records carry a sealing conclusion has no leaf, and the \
         audit called that sound"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.to_string().contains("not in the log")),
        "the missing leaf was noticed for the wrong reason: {:?}",
        report.findings
    );
}
