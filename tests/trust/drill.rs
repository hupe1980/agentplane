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

use agentplane::blob::{BlobStore, MemoryBlobs};
use agentplane::case::CaseStore;
use agentplane::core::{CaseVersion, CorrelationKey, Digest, TenantId, Timestamp};
use agentplane::drill::{Stores, drill};
use agentplane::keyring::{KeyRing, SealedCases};
use agentplane::store::RedbStore;
use agentplane::testkit::MemoryKeyRing;
use serde_json::json;

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

struct Fixture {
    cases: Arc<dyn CaseStore>,
    blobs: Arc<dyn BlobStore>,
    keys: Arc<dyn KeyRing>,
    tenant: TenantId,
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
    Fixture {
        cases: sealed as Arc<dyn CaseStore>,
        blobs: Arc::new(MemoryBlobs::new()) as Arc<dyn BlobStore>,
        keys: ring as Arc<dyn KeyRing>,
        tenant,
    }
}

/// Open a case with sealed state and one stored, linked artifact.
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
    let digest = f.blobs.put(bytes).await.expect("stored");
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
        f.blobs.as_ref(),
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
    // Planted at an address the bytes do not hash to — what tampering in the
    // backing store looks like from here.
    let claimed = Digest::of(b"what was written");
    f.blobs
        .put_at(claimed, b"what is there now")
        .await
        .expect("planted");
    f.cases
        .link_blob(case, claimed, ts(1_001))
        .await
        .expect("linked");

    let report = drill(&Stores {
        cases: &f.cases,
        blobs: Some(&f.blobs),
        keys: Some(&f.keys),
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

    let report = drill(&Stores {
        cases: &cases,
        blobs: None,
        keys: Some(&keys),
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
