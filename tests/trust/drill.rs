//! The live half of the case-layer drill: erasure is an answer, loss is a
//! finding, and the difference is the entire value of the pass.
//!
//! The offline verifier proves an export sound from its own bytes and reports
//! blob presence and key availability as beyond it. These tests hold the live
//! half to the three-way distinction it exists for: intact, erased by design,
//! and lost — where only the third may page anyone.

#![cfg(all(feature = "redb", feature = "keyring", feature = "testkit"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::blob::{BlobStore, MemoryBlobs, ScopedBlobs, unit_address};
use agentplane::case::CaseStore;
use agentplane::core::{CaseVersion, CorrelationKey, Digest, TenantId, Timestamp, erasure_scope};
use agentplane::drill::{Stores, drill};
use agentplane::keyring::{EncryptedBlobs, KeyRing, SealedCases};
use agentplane::store::RedbStore;
use agentplane::testkit::MemoryKeyRing;
use serde_json::json;

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

struct Fixture {
    cases: Arc<dyn CaseStore>,
    blobs: Arc<dyn BlobStore>,
    /// The bare store underneath, concretely, for planting tampered bytes at
    /// the address a case's write actually landed at.
    raw: Arc<MemoryBlobs>,
    keys: Arc<dyn KeyRing>,
    /// The same ring, concretely, for the operator actions only a real key
    /// service exposes — moving a decryption floor under an envelope that is
    /// already sealed.
    ring: Arc<MemoryKeyRing>,
    tenant: TenantId,
}

impl Fixture {
    /// The handle a run of `case` writes blobs through: unit-scoped addresses,
    /// sealed under the case's key — exactly what `StepCtx::store_blob` builds.
    fn case_blobs(&self, case: agentplane::core::CaseId) -> Arc<dyn BlobStore> {
        let scope = erasure_scope(&self.tenant, &case.to_string());
        Arc::new(EncryptedBlobs::new(
            Arc::new(ScopedBlobs::new(Arc::clone(&self.blobs), scope.clone())),
            Arc::clone(&self.keys),
            scope,
        ))
    }
}

fn fixture() -> Fixture {
    let redb = Arc::new(RedbStore::open_in_memory().expect("store"));
    let ring = Arc::new(MemoryKeyRing::new());
    let tenant = TenantId::new(TenantId::DEFAULT).expect("valid");
    let sealed = SealedCases::wrap(
        redb as Arc<dyn CaseStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        tenant.clone(),
    );
    let raw = Arc::new(MemoryBlobs::new());
    Fixture {
        cases: sealed as Arc<dyn CaseStore>,
        blobs: Arc::clone(&raw) as Arc<dyn BlobStore>,
        raw,
        keys: Arc::clone(&ring) as Arc<dyn KeyRing>,
        ring,
        tenant,
    }
}

/// Open a case with sealed state and one stored, linked artifact.
///
/// The artifact is written the way a ring deployment writes one — through the
/// case's unit-scoped, sealing handle — because a fixture that wrote plaintext
/// at bare content addresses would be drilling a store no sealed plane
/// produces, and the pass would be green over the wrong deployment shape.
async fn matter(f: &Fixture, key: &str, bytes: &[u8]) -> agentplane::core::CaseId {
    let case = f
        .cases
        .correlate_or_open("matter", &[CorrelationKey::new("doc", key)], ts(1_000))
        .await
        .expect("open")
        .case_id();
    f.cases
        .put_state(case, CaseVersion::INITIAL, json!({ "about": key }))
        .await
        .expect("sealed state");
    let digest = f.case_blobs(case).put(bytes).await.expect("stored");
    f.cases
        .link_blob(case, digest, ts(1_001))
        .await
        .expect("linked");
    case
}

/// **The three-way distinction.** One matter intact, one erased, one lost —
/// and only the loss is a finding.
#[tokio::test]
async fn the_drill_tells_erasure_from_loss() {
    let f = fixture();

    // Intact: sealed state that opens, bytes that hash.
    matter(&f, "SOUND-1", b"the artifact").await;

    // Erased: the full ceremony — tombstones, then the case scope key.
    let erased = matter(&f, "ERASED-1", b"personal data").await;
    agentplane::blob::erase_case(
        Some(f.blobs.as_ref()),
        f.cases.as_ref(),
        Some(f.keys.as_ref()),
        &f.tenant,
        erased,
        ts(2_000),
        "erasure request",
    )
    .await
    .expect("erase");

    // Lost: a linked digest nothing ever stored, and no tombstone to explain it.
    let lossy = f
        .cases
        .correlate_or_open("matter", &[CorrelationKey::new("doc", "LOST-1")], ts(1_000))
        .await
        .expect("open")
        .case_id();
    f.cases
        .link_blob(lossy, Digest::of(b"bytes nobody stored"), ts(1_001))
        .await
        .expect("linked");

    let report = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");

    assert_eq!(report.cases, 3);
    assert_eq!(report.blobs_present, 1, "the intact artifact hashes");
    assert_eq!(
        report.blobs_erased, 1,
        "a tombstoned blob is retention working, never a finding"
    );
    assert_eq!(report.sealed_open, 1, "the intact state opened");
    assert_eq!(
        report.sealed_erased, 1,
        "a destroyed key is a completed erasure reporting itself"
    );
    assert_eq!(
        report.findings.len(),
        1,
        "exactly the loss is a finding: {:#?}",
        report.findings
    );
    assert!(
        report.findings[0].contains("no tombstone"),
        "the finding must name what separates loss from erasure: {}",
        report.findings[0]
    );
    assert!(!report.is_sound(), "a loss must fail the drill");
}

/// Altered bytes are the one state somebody is paged about, and `has` cannot
/// see them — which is why the drill reads.
#[tokio::test]
async fn altered_bytes_are_a_finding_not_a_presence() {
    let f = fixture();
    let case = f
        .cases
        .correlate_or_open(
            "matter",
            &[CorrelationKey::new("doc", "TAMPER-1")],
            ts(1_000),
        )
        .await
        .expect("open")
        .case_id();
    // Written properly, then altered in the backing store — what tampering
    // looks like from here. The alteration lands at the address the case's
    // write actually used, because that is the object the drill will read.
    let claimed = f
        .case_blobs(case)
        .put(b"what was written")
        .await
        .expect("stored");
    f.cases
        .link_blob(case, claimed, ts(1_001))
        .await
        .expect("linked");
    let address = unit_address(&erasure_scope(&f.tenant, &case.to_string()), claimed);
    f.raw
        .tamper_for_test(address, b"what is there now".to_vec());

    let report = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");

    assert_eq!(report.blobs_present, 0, "altered bytes are not presence");
    assert_eq!(
        report.findings.len(),
        1,
        "tampering is a finding: {:#?}",
        report.findings
    );
    assert!(
        report.findings[0].contains("altered") || report.findings[0].contains("hashes to"),
        "the finding names the alteration: {}",
        report.findings[0]
    );
}

/// A store the drill was not given is unchecked, not silently passed — and
/// the runtime's own wrapper wires the stores the plane actually runs with.
#[tokio::test]
async fn missing_stores_are_unchecked_not_passed() {
    let f = fixture();
    matter(&f, "SOUND-2", b"artifact").await;

    let report = drill(&Stores {
        cases: &f.cases,
        blobs: None,
        keys: None,
        tenant: &f.tenant,
    })
    .await
    .expect("drill");

    assert!(report.is_sound(), "nothing checked, nothing wrong");
    assert!(
        report.not_checked.iter().any(|n| n.contains("blob bytes"))
            && report
                .not_checked
                .iter()
                .any(|n| n.contains("sealed-state keys")),
        "both absent stores must be named: {:#?}",
        report.not_checked
    );

    // The runtime fills in from its own wiring, so the drill runs against the
    // stores the runs actually used.
    let redb = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = agentplane::runtime::Runtime::builder(
        Arc::clone(&redb) as Arc<dyn agentplane::journal::JournalStore>
    )
    .cases(Arc::clone(&f.cases))
    .blobs(Arc::clone(&f.blobs))
    .build();
    let wired = rt.drill().await.expect("runtime drill");
    assert_eq!(wired.cases, report.cases, "same case layer walked");
    assert!(
        wired.not_checked.iter().any(|n| n.contains("key ring"))
            || wired
                .not_checked
                .iter()
                .any(|n| n.contains("sealed-state keys")),
        "a runtime with no ring says so: {:#?}",
        wired.not_checked
    );
}

/// **A key ring in hand and nothing sealed is named, not silently passed.**
///
/// Two planes produce a drill in which zero states open and zero were
/// erased: one that keeps case state plaintext by design, and one whose
/// operator wired the ring and forgot to wrap the case store in
/// `SealedCases` — the misconfiguration in which every "sealed" case is
/// silently plaintext and erasure-by-key-destruction reaches nothing. The
/// stores the drill holds cannot tell them apart, so the report must say the
/// coverage was not established — as unchecked, not as a finding, because a
/// finding would page every plaintext-by-design plane on every drill.
#[tokio::test]
async fn a_ring_with_nothing_sealed_is_unestablished_coverage() {
    // A case store deliberately not wrapped in SealedCases: state lands
    // plaintext, exactly what forgotten wiring produces.
    let redb = Arc::new(RedbStore::open_in_memory().expect("store"));
    let cases = redb as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open(
            "matter",
            &[CorrelationKey::new("doc", "PLAIN-1")],
            ts(1_000),
        )
        .await
        .expect("open")
        .case_id();
    cases
        .put_state(case, CaseVersion::INITIAL, json!({ "about": "plaintext" }))
        .await
        .expect("state");
    let keys = Arc::new(MemoryKeyRing::new()) as Arc<dyn KeyRing>;

    let tenant = TenantId::default();
    let report = drill(&Stores {
        cases: &cases,
        blobs: None,
        keys: Some(&keys),
        tenant: &tenant,
    })
    .await
    .expect("drill");

    assert!(
        report.is_sound(),
        "ambiguous coverage is not loss, and must not page anyone: {:#?}",
        report.findings
    );
    assert!(
        report
            .not_checked
            .iter()
            .any(|n| n.contains("sealed-state coverage")),
        "a ring that opened nothing went unremarked — 'sealing was never \
         wired' and 'nothing is sealed by design' collapsed into silence: {:#?}",
        report.not_checked
    );

    // The positive half: a plane whose sealed state actually opened carries
    // no such entry — coverage was established, one opened state at a time.
    let f = fixture();
    matter(&f, "SEALED-9", b"the artifact").await;
    let covered = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");
    assert!(covered.sealed_open > 0, "the fixture sealed nothing");
    assert!(
        !covered
            .not_checked
            .iter()
            .any(|n| n.contains("sealed-state coverage")),
        "established coverage was reported as unestablished: {:#?}",
        covered.not_checked
    );
}

/// **An operator's version floor is neither an erasure nor a loss.**
///
/// A key service that refuses to decrypt below a floor — Vault's
/// `min_decryption_version` — makes un-erased history unreadable the moment
/// that floor passes a live envelope. Sealed bytes are rotation-immutable, so
/// an envelope names its wrapping-key version for as long as it is retained
/// and nothing here can move it out of the way.
///
/// Both obvious classifications are wrong, in opposite directions, and this
/// pins each. Counted as `sealed_erased` it claims an obligation discharged
/// that nobody requested, and writes off data that is intact and one setting
/// away from readable. Left in the arm below it reports *neither opens nor was
/// its key destroyed* — the sentence that sends somebody hunting for tampering
/// while a reversible configuration line is the whole cause.
///
/// So it is a finding, because this plane cannot read a case it is holding,
/// and the finding must carry its own remedy.
#[tokio::test]
async fn a_retired_key_version_is_not_reported_as_loss_or_as_erasure() {
    let f = fixture();
    matter(&f, "RETIRED-1", b"the artifact").await;

    // The state is sealed under the generation in force now; the floor moves
    // afterwards, which is the only order in which this hazard exists.
    f.ring.rotate();
    f.ring.retire_below(1);

    let report = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");

    assert_eq!(
        report.sealed_open, 0,
        "state behind a version floor cannot have opened"
    );
    assert_eq!(
        report.sealed_erased, 0,
        "a retired version was counted as a completed erasure — an obligation \
         reported discharged that nobody requested, over data that is intact"
    );
    assert_eq!(report.findings.len(), 1, "{:#?}", report.findings);
    let finding = &report.findings[0];
    assert!(
        !finding.contains("loss or tampering"),
        "a reversible version floor reached the operator as an incident: {finding}"
    );
    assert!(
        finding.contains("retired") && finding.contains("lower the floor"),
        "the finding must name the remedy, or it is an incident by another \
         name: {finding}"
    );
    assert!(
        !report.is_sound(),
        "un-erased history nobody can read must fail the drill"
    );

    // Reversible, which is what distinguishes it from erasure: the same drill
    // over the same bytes comes back clean once the floor readmits them.
    f.ring.retire_below(0);
    let readmitted = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");
    assert_eq!(readmitted.sealed_open, 1);
    assert!(
        readmitted.is_sound(),
        "lowering the floor did not make the case readable again, so the \
         refusal was never really a version floor: {:#?}",
        readmitted.findings
    );
}

// ── Retention: the window, and what it honestly cannot reach ────────────────

/// A retention pass erases closed cases past the window, and only those.
///
/// The three cases here are the three answers the pass has to keep apart: a
/// closed matter past its window (erase), a closed matter inside it (keep), and
/// a matter still open (keep — erasing under a live run turns a retention pass
/// into an outage).
///
/// Checked through the **drill**, which is the point: after retention runs, the
/// erased case must read as *erased by design* rather than as loss, or a real
/// loss six months later is indistinguishable from a discharged obligation.
#[tokio::test]
async fn retention_erases_closed_cases_past_the_window_and_nothing_else() {
    use agentplane::core::CaseStatus;
    use agentplane::retention::{Stores as RetentionStores, retain};

    let f = fixture();

    let old_closed = matter(&f, "OLD-CLOSED", b"personal data, long past").await;
    let recent_closed = matter(&f, "NEW-CLOSED", b"personal data, still in window").await;
    let still_open = matter(&f, "OPEN", b"a live matter").await;

    // Two closed, one open. `matter` opens every case at t=1000, so the window
    // is moved rather than the cases: only `old_closed` is aged deliberately.
    for case in [old_closed, recent_closed] {
        f.cases
            .set_status(case, CaseStatus::Closed)
            .await
            .expect("close");
    }

    // The cutoff sits between the two closed cases' `opened_at`.
    let report = retain(
        &RetentionStores {
            cases: &f.cases,
            blobs: Some(&f.blobs),
            keys: Some(&f.keys),
            tenant: &f.tenant,
        },
        ts(1_001),
        ts(5_000),
        "retention: 1 day",
    )
    .await
    .expect("retention");

    assert_eq!(report.scanned, 3, "every case must be considered");
    assert_eq!(
        report.erased, 2,
        "both closed cases opened before the cutoff must be erased: {report:#?}"
    );
    assert!(report.is_complete(), "{:#?}", report.failures);
    assert!(
        report
            .not_erasable
            .iter()
            .any(|line| line.contains("append-only")),
        "a count with no coverage statement beside it is how a deployment comes \
         to believe an obligation is discharged: {:#?}",
        report.not_erasable
    );

    // The open matter is untouched, and the drill still reads it as intact.
    let after = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");
    assert_eq!(
        after.sealed_erased, 2,
        "the erased cases must read as erased by design: {after:#?}"
    );
    assert_eq!(
        after.blobs_erased, 2,
        "their blobs must carry tombstones, not be missing"
    );
    assert_eq!(
        after.sealed_open, 1,
        "the live matter was erased underneath a running case"
    );
    assert!(
        after.is_sound(),
        "retention produced a finding, so an erasure it performed reads as a \
         loss: {:#?}",
        after.findings
    );
    let _ = still_open;
}

/// Without a key ring the pass says so, rather than reporting a clean number.
///
/// The residual the erasure page names: blob tombstones cover the live store
/// only, and journal payloads stay verbatim. A report that omitted this would
/// be the shape that lets a deployment believe an erasure obligation is
/// discharged while the chain still holds the payload.
#[tokio::test]
async fn retention_without_a_key_ring_reports_what_it_cannot_reach() {
    use agentplane::retention::{Stores as RetentionStores, retain};

    let f = fixture();
    let report = retain(
        &RetentionStores {
            cases: &f.cases,
            blobs: Some(&f.blobs),
            keys: None,
            tenant: &f.tenant,
        },
        ts(1_001),
        ts(5_000),
        "retention: 1 day",
    )
    .await
    .expect("retention");

    assert!(
        report
            .not_erasable
            .iter()
            .any(|line| line.contains("no key ring")),
        "the pass must name the residual rather than reporting a clean zero: {:#?}",
        report.not_erasable
    );
}

/// A sealed plane with no blob store is still erased: the unit is the key.
///
/// Sealing the journal with a ring and storing no blobs is an ordinary shape,
/// and the erasure that reaches every copy is the key destruction, not the
/// tombstone. A pass that skipped such a case for want of a store to tombstone
/// would leave the one act that matters undone because a lesser act had
/// nowhere to land.
#[tokio::test]
async fn retention_without_a_blob_store_still_destroys_the_case_key() {
    use agentplane::core::CaseStatus;
    use agentplane::retention::{Stores as RetentionStores, retain};

    let f = fixture();
    let case = matter(&f, "SEALED-ONLY", b"personal data").await;
    f.cases
        .set_status(case, CaseStatus::Closed)
        .await
        .expect("close");

    let report = retain(
        &RetentionStores {
            cases: &f.cases,
            blobs: None,
            keys: Some(&f.keys),
            tenant: &f.tenant,
        },
        ts(1_001),
        ts(5_000),
        "retention: 1 day",
    )
    .await
    .expect("retention");
    assert_eq!(
        report.erased, 1,
        "the case must be erased through its key: {report:#?}"
    );
    assert_eq!(
        report.blobs_expired, 0,
        "nothing could be tombstoned, and the count says so"
    );
    assert!(
        report
            .not_erasable
            .iter()
            .any(|line| line.contains("no blob store")),
        "the missing tombstones must be named: {:#?}",
        report.not_erasable
    );

    let after = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
        tenant: &f.tenant,
    })
    .await
    .expect("drill");
    assert_eq!(
        after.sealed_erased, 1,
        "the sealed state must read as erased by design through the key: {after:#?}"
    );
}
