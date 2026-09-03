//! Content-addressed storage, and the property that makes it safe to keep bytes
//! outside the hash chain.
//!
//! The journal refuses an oversized record; blobs are where those bytes go. That
//! only preserves tamper-evidence if a swapped blob is *detected*, so that is
//! what these check — against every backend, because a verification implemented
//! in one and forgotten in another is the failure the seam exists to prevent.

#![cfg(feature = "redb")]

use std::sync::Arc;

use agentplane::blob::{BlobError, BlobStore, MemoryBlobs};
use agentplane::core::{Digest, Timestamp};

fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

fn stores() -> Vec<(&'static str, Arc<dyn BlobStore>)> {
    // `mut` only when a second backend exists to push. Without the annotation
    // this is an unused-mut error in every build that does not enable
    // `opendal` — which `--all-features` can never show you.
    #[cfg_attr(not(feature = "opendal"), allow(unused_mut))]
    let mut out: Vec<(&'static str, Arc<dyn BlobStore>)> =
        vec![("memory", Arc::new(MemoryBlobs::new()))];

    #[cfg(feature = "opendal")]
    {
        use agentplane::blob::OpenDalBlobs;
        let dir = std::env::temp_dir().join(format!("agentplane-blobs-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let op =
            opendal::Operator::new(opendal::services::Fs::default().root(&dir.to_string_lossy()))
                .expect("fs operator");
        out.push(("opendal-fs", Arc::new(OpenDalBlobs::new(op, "blobs"))));
    }
    out
}

#[tokio::test]
async fn bytes_come_back_from_the_address_they_went_to() {
    for (name, store) in stores() {
        let digest = store.put(b"printer on fire").await.expect("put");
        let back = store.get(digest).await.expect("get");
        assert_eq!(back, b"printer on fire", "{name} returned other bytes");
        assert!(
            store.has(digest).await.expect("has"),
            "{name} lost the blob"
        );
    }
}

/// The address is the content, so writing twice is writing once.
///
/// This is what makes a blob write safe to retry after an unknown outcome — the
/// disposition every effect in this crate has to reason about. A store that
/// allocated a fresh location per write would turn a retry into a leak.
#[tokio::test]
async fn the_same_bytes_land_at_the_same_address() {
    for (name, store) in stores() {
        let a = store.put(b"same").await.expect("put");
        let b = store.put(b"same").await.expect("put again");
        assert_eq!(a, b, "{name} gave one payload two addresses");
    }
    let mem = MemoryBlobs::new();
    mem.put(b"same").await.expect("put");
    mem.put(b"same").await.expect("put again");
    assert_eq!(
        mem.len(),
        1,
        "a second identical write stored a second copy"
    );
}

/// A blob the caller never wrote is absent, not empty.
#[tokio::test]
async fn a_missing_blob_is_not_silently_empty() {
    for (name, store) in stores() {
        match store.get(Digest::of(b"never written")).await {
            Err(BlobError::NotFound(_)) => {}
            Err(other) => panic!("{name} reported the wrong error: {other}"),
            Ok(bytes) => panic!("{name} invented {} bytes", bytes.len()),
        }
    }
}

/// Altered bytes are refused, not returned.
///
/// The point of keeping the digest in the chain rather than the payload: the
/// journal still commits to exactly these bytes, so storage is the least
/// trusted component and is treated that way. If this check were missing, a
/// blob could be edited by anyone with filesystem access and every later read
/// would hand the altered content to a caller that believed the chain vouched
/// for it.
#[tokio::test]
async fn altered_bytes_are_detected_rather_than_served() {
    let store = MemoryBlobs::new();
    let digest = store.put("€4,200 refund".as_bytes()).await.expect("put");

    store.tamper_for_test(digest, "$42,000 refund".as_bytes().to_vec());

    match store.get(digest).await {
        Err(BlobError::Corrupt { expected, actual }) => {
            assert_eq!(expected, digest.to_hex());
            assert_ne!(actual, expected, "a corrupt read must name what it found");
        }
        Err(other) => panic!("tampering was reported as something else: {other}"),
        Ok(bytes) => panic!(
            "altered bytes were served as authentic: {}",
            String::from_utf8_lossy(&bytes)
        ),
    }
}

/// **Erasure and loss are different answers, and the store must tell them apart.**
///
/// This is what makes retention possible at all. An Article 17 request removes
/// the bytes; an Article 12 obligation still requires proof of what happened.
/// Both hold *because* the chain committed to a digest rather than to content —
/// but only if a reader arriving afterwards can distinguish "deliberately
/// expired on this date, for this reason" from "gone, cause unknown". Collapse
/// the two and every erasure looks like data loss six months later.
#[tokio::test]
async fn an_expired_blob_is_not_reported_as_missing() {
    for (name, store) in stores() {
        let digest = store.put("personal data".as_bytes()).await.expect("put");
        store
            .expire(digest, ts(1_700_000_000), "art-17 erasure request")
            .await
            .expect("expire");

        match store.get(digest).await {
            Err(BlobError::Expired { at, reason, .. }) => {
                assert_eq!(at, 1_700_000_000, "{name} lost when the data went");
                assert!(
                    reason.contains("art-17"),
                    "{name} lost why the data went: {reason}"
                );
            }
            Err(BlobError::NotFound(_)) => panic!(
                "{name} reports a deliberate erasure as a missing blob — an \
                 operator cannot tell retention from data loss"
            ),
            Err(other) => panic!("{name}: wrong error: {other}"),
            Ok(b) => panic!("{name} served {} bytes that were erased", b.len()),
        }
    }
}

/// A blob nobody ever wrote is still simply absent.
///
/// Stated separately because the fix for the check above — returning `Expired`
/// for anything unreadable — would pass it while making the distinction
/// meaningless in the other direction.
#[tokio::test]
async fn a_blob_that_never_existed_is_still_not_found() {
    for (name, store) in stores() {
        match store.get(Digest::of(b"never written at all")).await {
            Err(BlobError::NotFound(_)) => {}
            Err(other) => panic!("{name}: wrong error for an absent blob: {other}"),
            Ok(_) => panic!("{name} invented a blob"),
        }
    }
}

/// Expiring twice does not rewrite when the data went.
///
/// The same rule as a repeated stop request: the first record of an
/// intervention is the one on the record, or "when was this erased?" has a
/// wrong answer that looks authoritative.
#[tokio::test]
async fn a_repeated_expiry_keeps_the_first_tombstone() {
    for (name, store) in stores() {
        let digest = store.put("twice".as_bytes()).await.expect("put");
        store
            .expire(digest, ts(1_000), "first")
            .await
            .expect("expire");
        store
            .expire(digest, ts(9_999), "second")
            .await
            .expect("again");

        match store.get(digest).await {
            Err(BlobError::Expired { at, reason, .. }) => {
                assert_eq!(at, 1_000, "{name} let a retry rewrite the erasure date");
                assert_eq!(reason, "first", "{name} let a retry rewrite the reason");
            }
            other => panic!("{name}: expected an expired blob, got {other:?}"),
        }
    }
}

/// **Erasure is scoped to the case, which is the only unit anyone asks about.**
///
/// Nobody requests that a digest be forgotten; they name a person, and that
/// resolves to a matter. So the link from case to bytes has to be recorded when
/// the bytes are written — a digest cannot be reversed to find its case, and
/// nothing can reconstruct it afterwards.
///
/// The second case is the point of the test, and the **shared bytes** are the
/// point of the second case. Content addressing gives identical bytes one
/// digest, so with the bare digest as the storage key two matters holding the
/// same document hold one object — and erasing either destroys the other's
/// copy while the drill reads the loss as *erased by design*, the one verdict
/// that pages nobody. The erasure unit therefore leads the storage address:
/// same bytes in two matters are two objects, and one matter's tombstones
/// cannot reach the other's. A fixture whose cases share no bytes cannot see
/// any of that.
#[cfg(feature = "redb")]
#[tokio::test]
async fn erasing_a_case_leaves_other_cases_alone() {
    use agentplane::blob::{ScopedBlobs, erase_case};
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, erasure_scope};
    use agentplane::store::RedbStore;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let cases: Arc<dyn CaseStore> = Arc::clone(&store) as Arc<dyn CaseStore>;
    let blobs: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());
    let tenant = agentplane::core::TenantId::default();

    let mine = cases
        .correlate_or_open("matter", &[CorrelationKey::new("ns", "SUBJECT-1")], ts(10))
        .await
        .expect("open")
        .case_id();
    let theirs = cases
        .correlate_or_open("matter", &[CorrelationKey::new("ns", "SUBJECT-2")], ts(10))
        .await
        .expect("open")
        .case_id();

    // Each case writes through its own unit-scoped handle, exactly as
    // `StepCtx::store_blob` does.
    let mine_blobs = ScopedBlobs::new(
        Arc::clone(&blobs),
        erasure_scope(&tenant, &mine.to_string()),
    );
    let their_blobs = ScopedBlobs::new(
        Arc::clone(&blobs),
        erasure_scope(&tenant, &theirs.to_string()),
    );

    let shared = "the same PDF, fetched in both matters".as_bytes();
    let a = mine_blobs.put(shared).await.expect("put");
    let b = mine_blobs
        .put("subject one, document b".as_bytes())
        .await
        .expect("put");
    // The other matter holds the identical bytes: one digest, two objects.
    let other = their_blobs.put(shared).await.expect("put");
    assert_eq!(a, other, "identical bytes carry one content digest");
    // And bytes of its own. Both halves are needed: the shared digest is what
    // a scoped *address* protects, and this distinct one is what a scoped
    // `blobs_of` protects — a list that answered with every case's artifacts
    // would be invisible against the shared digest alone, because the extra
    // entry is one the erasing case already holds.
    let only_theirs = their_blobs
        .put("subject two, their own document".as_bytes())
        .await
        .expect("put");
    cases.link_blob(mine, a, ts(11)).await.expect("link");
    cases.link_blob(mine, b, ts(12)).await.expect("link");
    cases.link_blob(theirs, other, ts(11)).await.expect("link");
    cases
        .link_blob(theirs, only_theirs, ts(12))
        .await
        .expect("link");

    let n = erase_case(
        Some(blobs.as_ref()),
        cases.as_ref(),
        #[cfg(feature = "keyring")]
        None,
        &tenant,
        mine,
        ts(500),
        "art-17 request",
    )
    .await
    .expect("erase");
    assert_eq!(
        n, 2,
        "the erasure walked a list that is not this case's own — it expired \
         {n} artifacts where the matter holds two"
    );

    for (label, digest) in [("a", a), ("b", b)] {
        match mine_blobs.get(digest).await {
            Err(BlobError::Expired { reason, at, digest }) => {
                assert_eq!(at, 500);
                assert!(reason.contains("art-17"), "blob {label} lost its reason");
                assert!(
                    digest.contains(&a.to_hex()) || digest.contains(&b.to_hex()),
                    "the tombstone names a derived address, not the content \
                     digest a reader can find in a journal: {digest}"
                );
            }
            other => panic!("blob {label} was not expired: {other:?}"),
        }
    }

    // Both of the other matter's artifacts survive: its copy of the shared
    // bytes, and its own.
    assert_eq!(
        their_blobs
            .get(other)
            .await
            .expect("the other case's identical bytes are untouched"),
        shared,
        "erasing one case destroyed another case's copy of the same bytes"
    );
    assert!(
        their_blobs.get(only_theirs).await.is_ok(),
        "erasing one case reached an artifact only the other matter holds"
    );
}

/// Re-linking the same bytes is one artifact, not two.
///
/// Two runs on one case storing identical content land on one digest by
/// construction. Counting it twice would report an erasure that did not happen.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_case_storing_the_same_bytes_twice_has_one_blob() {
    use agentplane::case::CaseStore;
    use agentplane::core::CorrelationKey;
    use agentplane::store::RedbStore;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let cases: Arc<dyn CaseStore> = Arc::clone(&store) as Arc<dyn CaseStore>;
    let case = cases
        .correlate_or_open("matter", &[CorrelationKey::new("ns", "DUP")], ts(10))
        .await
        .expect("open")
        .case_id();

    let d = Digest::of(b"the same bytes");
    cases.link_blob(case, d, ts(11)).await.expect("link");
    cases.link_blob(case, d, ts(99)).await.expect("link again");

    assert_eq!(
        cases.blobs_of(case).await.expect("read").len(),
        1,
        "the same content linked twice was counted as two artifacts"
    );
}

// ── Tenancy ─────────────────────────────────────────────────────────────────
//
// Every test below hands the attacker a **valid** identifier belonging to the
// other tenant, because that is the realistic leak: not a guessed id, but a real
// one arriving through a path that never checked whose it was. Each also carries
// a positive half — the owning tenant must still reach its own — since a lookup
// broken for everybody passes every negative assertion here.

/// Two producers using the same id are two events, not one.
///
/// `CloudEvents` defines uniqueness as `(source, id)`, and the reason is exactly
/// this: an id is unique *within* a producer, so deduplicating on it alone makes
/// two producers swallow each other's messages. The collision is silent, because
/// the second message looks precisely like a retry of the first — the failure
/// mode is a message that was never processed and never reported missing.
#[cfg(feature = "redb")]
#[tokio::test]
async fn two_producers_sharing_an_id_are_not_one_event() {
    use agentplane::case::EventStore;
    use agentplane::core::{CorrelationKey, InboundEvent};
    use agentplane::store::RedbStore;

    let store = RedbStore::open_in_memory().expect("store");
    let from = |source: &str| InboundEvent {
        source: source.to_owned(),
        // The same id from both — ordinary, since each producer numbers its own.
        id: "42".to_owned(),
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("document", "DOC-1")],
        payload: serde_json::json!({"from": source}),
    };

    assert!(
        store.buffer(&from("erp"), ts(1)).await.expect("first"),
        "the first event was not buffered"
    );
    assert!(
        store.buffer(&from("crm"), ts(2)).await.expect("second"),
        "a second producer's message with the same id was swallowed as a \
         duplicate — it will never be processed and nothing will report it"
    );

    // And a genuine retry *is* still deduplicated, so this did not simply
    // disable the dedup it is checking.
    assert!(
        !store.buffer(&from("erp"), ts(3)).await.expect("retry"),
        "the same producer's retry was accepted twice, so deduplication is off \
         rather than correctly scoped"
    );
}

/// A store handle for one tenant cannot read another's journal.
///
/// The base case the rest of tenancy rests on. The attacker holds a **valid**
/// run id belonging to the other tenant — which is the realistic leak, since ids
/// travel in URLs, logs and error messages — and the read must find nothing
/// rather than find it filtered.
#[cfg(feature = "redb")]
#[tokio::test]
async fn a_tenant_cannot_read_another_tenants_run_even_holding_its_id() {
    use agentplane::core::{Label, RunId, TenantId};
    use agentplane::journal::{Append, JournalStore, RecordKind};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    let run = RunId::generate();
    let lease = acme
        .acquire(run, "acme-worker", std::time::Duration::from_mins(1))
        .await
        .expect("acme leases");
    acme.append(
        lease.epoch,
        vec![Append::new(
            run,
            RecordKind::RunAdmitted {
                capability: "settlement.check".into(),
                governed_by: None,
                input_label: Label::trusted(),
                input: serde_json::Value::Null,
                policy_bundle: None,
                canon: agentplane::core::canon::VERSION,
                idempotency_key: None,
            },
        )],
    )
    .await
    .expect("acme appends");

    assert!(
        globex.read(run, 0).await.expect("globex reads").is_empty(),
        "a store handle for one tenant read another tenant's journal while \
         holding nothing but a valid run id"
    );
    assert_eq!(
        globex.head(run).await.expect("globex head").seq,
        0,
        "another tenant's chain head leaked, which tells them a run exists"
    );

    // The owning tenant still reads its own, so this isolated rather than
    // broke reads.
    assert_eq!(
        acme.read(run, 0).await.expect("acme reads").len(),
        1,
        "the owning tenant lost its own record"
    );
}

/// A sweeper does not claim another tenant's timers.
///
/// Timers are swept by due time, which is a global ordering: without the tenant
/// leading the index, the soonest timer anywhere is the next one this plane
/// fires. It would then wake another tenant's run under this plane's identity.
#[cfg(feature = "redb")]
#[tokio::test]
async fn a_sweep_does_not_claim_another_tenants_timers() {
    use agentplane::case::TimerStore;
    use agentplane::core::{EffectKey, Phase, RunId, StepId, TenantId, Timer};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    let timer = |run| Timer {
        run,
        effect: EffectKey::from_hex(&"aa".repeat(32)).expect("a key"),
        case: None,
        step: StepId(0),
        phase: Phase::Forward,
        fire_at: ts(10),
    };

    let acme_run = RunId::generate();
    acme.arm(&timer(acme_run)).await.expect("acme arms");

    let mine = globex.claim_due(ts(100), 10).await.expect("globex sweeps");
    assert!(
        mine.is_empty(),
        "a sweeper claimed another tenant's timer, which wakes that tenant's \
         run under this plane's identity: {mine:?}"
    );

    let ours = acme.claim_due(ts(100), 10).await.expect("acme sweeps");
    assert_eq!(
        ours.len(),
        1,
        "the owning tenant must still find its own timer, or the scoping \
         removed the feature rather than isolating it"
    );
    assert_eq!(ours[0].run, acme_run);
}

/// One tenant's event never resumes another tenant's waiting run.
///
/// The worst thing an event store can do. Subscriptions are matched by kind and
/// correlation — both business-shaped values that two tenants will legitimately
/// share, since `document`/`DOC-1` means something different to each. Without
/// the tenant leading the match index, a delivery would find the other tenant's
/// waiter and resume *their* run with *this* payload.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_event_does_not_resume_another_tenants_run() {
    use agentplane::case::EventStore;
    use agentplane::core::{
        CorrelationKey, EffectKey, InboundEvent, Phase, RunId, StepId, Subscription, TenantId,
    };
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    // Globex is waiting on a correlation key acme also uses — the realistic
    // case, since business keys are not globally unique.
    let waiting = RunId::generate();
    let sub = Subscription {
        run: waiting,
        effect: EffectKey::from_hex(&"bb".repeat(32)).expect("a key"),
        case: None,
        step: StepId(0),
        phase: Phase::Forward,
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("document", "DOC-1")],
    };
    globex.subscribe(&sub, ts(1)).await.expect("globex waits");

    let event = InboundEvent {
        source: "erp".to_owned(),
        id: "evt-1".to_owned(),
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("document", "DOC-1")],
        payload: serde_json::json!({"ok": true}),
    };

    // Buffered *in acme*, which is what makes this a tenancy question rather
    // than a "no such event" one: the row exists, under the wrong tenant.
    assert!(acme.buffer(&event, ts(2)).await.expect("acme buffers"));
    assert!(
        acme.match_waiter(&event, ts(3))
            .await
            .expect("acme matches")
            .is_none(),
        "one tenant's message resumed another tenant's waiting run, handing it \
         a payload nobody sent it"
    );

    // The same message inside globex does resume it, so the match path works
    // and the assertion above failed for the reason it claims.
    assert!(globex.buffer(&event, ts(4)).await.expect("globex buffers"));
    let matched = globex
        .match_waiter(&event, ts(5))
        .await
        .expect("globex matches")
        .expect("globex's own event must resume its own waiter");
    assert_eq!(matched.run, waiting);
}

/// One tenant's run never joins another tenant's case.
///
/// Correlation keys are business values — `document`/`DOC-1` means something
/// different to every tenant, and two of them using the same one is ordinary,
/// not a collision. Without the tenant leading the correlation index, the second
/// tenant's run would be attached to the first's case: they would share a
/// history, a deadline set, and an erasure unit.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_run_does_not_join_another_tenants_case() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, TenantId};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));
    let key = [CorrelationKey::new("document", "DOC-1")];

    let theirs = acme
        .correlate_or_open("clearing", &key, ts(1))
        .await
        .expect("acme opens");
    let mine = globex
        .correlate_or_open("clearing", &key, ts(2))
        .await
        .expect("globex opens");

    assert_ne!(
        theirs.case_id(),
        mine.case_id(),
        "globex joined acme's case on a shared business key — the two would \
         share a history, a deadline set and an erasure unit"
    );

    // And each still finds its own, so this isolated rather than broke it.
    assert_eq!(
        acme.correlate(&key).await.expect("acme correlates"),
        Some(theirs.case_id()),
        "acme cannot find the case it just opened"
    );
    assert_eq!(
        globex.correlate(&key).await.expect("globex correlates"),
        Some(mine.case_id()),
        "globex cannot find the case it just opened"
    );
}

/// One tenant's worklist is not another tenant's, even holding a valid id.
///
/// A task id is derived, travels in URLs and webhook payloads, and is not a
/// secret — so the attacker here holds a **valid** id belonging to the other
/// tenant, because a guessed one proves nothing. Reading it must be a miss;
/// claiming or deciding it must fail as *not found*, not as *held*; and the
/// other tenant's queue must not list it. Each half is paired with the owner
/// still finding its own row, since a query broken for everybody passes every
/// negative assertion.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_tasks_are_not_another_tenants_to_decide() {
    use agentplane::case::{ClaimError, TaskStore};
    use agentplane::core::{
        EffectKey, Justification, OnExpiry, Priority, RunId, Task, TaskId, TaskState, TenantId,
    };
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    let run = RunId::generate();
    let task = Task {
        id: TaskId::derive(run, EffectKey::from_hex(&"cc".repeat(32)).expect("a key")),
        run,
        case: None,
        kind: "approval".into(),
        justification: Justification::new("needs a person", serde_json::json!({})),
        candidate_roles: vec!["ops".into()],
        escalate_to: Vec::new(),
        excluded_actors: Vec::new(),
        assignee: None,
        priority: Priority::Normal,
        state: TaskState::Open,
        on_expiry: OnExpiry::Deny,
        created_at: ts(1_000),
        due_at: None,
    };
    acme.open(&task).await.expect("acme opens");

    // The valid id, presented across the boundary: a miss, never a row.
    assert!(
        globex.task(task.id).await.expect("globex reads").is_none(),
        "a tenant read another tenant's task while holding nothing but its id"
    );
    assert!(
        matches!(
            globex.claim(task.id, "carol", &["ops".to_owned()]).await,
            Err(ClaimError::NotFound(_))
        ),
        "a claim across the tenant boundary was answered with something other \
         than not-found — even 'held by alice' leaks who is reviewing what"
    );
    assert!(
        globex
            .queue(&["ops".to_owned()], 10)
            .await
            .expect("globex queue")
            .is_empty(),
        "another tenant's task appeared in this tenant's queue"
    );
    assert_eq!(globex.open_count().await.expect("globex count"), 0);

    // The positive halves: the owner still sees and claims its own work.
    assert_eq!(
        acme.queue(&["ops".to_owned()], 10)
            .await
            .expect("acme queue")
            .len(),
        1,
        "the owning tenant lost its own queue"
    );
    assert_eq!(acme.open_count().await.expect("acme count"), 1);
    assert!(
        acme.claim(task.id, "alice", &["ops".to_owned()])
            .await
            .is_ok(),
        "the owning tenant could not claim its own task"
    );
}

/// One tenant's batch reservations are not another tenant's.
///
/// A batch id and an item key are both caller-chosen strings, so two tenants
/// using `batch-1`/`item-001` is ordinary. A reservation that crossed the
/// boundary would hand one tenant the other's run id — the exactly-once
/// arbiter for work that is not theirs.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_batch_reservations_are_not_another_tenants() {
    use agentplane::batch::BatchStore;
    use agentplane::core::{BatchId, RunId, TenantId};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    let batch = BatchId::generate();
    let theirs = RunId::generate();
    acme.open(batch, "digest").await.expect("acme opens");
    acme.reserve(batch, "item-001", theirs)
        .await
        .expect("acme reserves");
    acme.mark_exhausted(batch).await.expect("acme exhausts");

    // The same batch id, the same item key, across the boundary: globex must
    // get its *own* reservation, not acme's run id.
    let mine = RunId::generate();
    globex.open(batch, "digest").await.expect("globex opens");
    let reserved = globex
        .reserve(batch, "item-001", mine)
        .await
        .expect("globex reserves");
    assert_eq!(
        reserved.run, mine,
        "a reservation crossed the tenant boundary and handed this tenant \
         another tenant's run id"
    );
    assert!(
        !globex.is_exhausted(batch).await.expect("globex reads"),
        "another tenant's exhaustion closed this tenant's batch"
    );
    // The positive half: acme's original reservation still stands.
    let original = acme
        .reserve(batch, "item-001", RunId::generate())
        .await
        .expect("acme re-reserves");
    assert_eq!(
        original.run, theirs,
        "the owning tenant's reservation lost its original run id"
    );
    assert!(acme.is_exhausted(batch).await.expect("acme reads"));
}

/// One tenant's dead letters are not another tenant's to read.
///
/// The dead-letter view is read by an operator deciding what went wrong, and
/// event payloads are the caller's data — a listing that walked every tenant's
/// retired events would show one tenant the traffic of all of them.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_dead_letters_are_not_another_tenants() {
    use agentplane::case::EventStore;
    use agentplane::core::{CorrelationKey, InboundEvent, TenantId};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    let event = InboundEvent {
        source: "erp".to_owned(),
        id: "evt-dead-1".to_owned(),
        kind: "ack.received".to_owned(),
        correlation: vec![CorrelationKey::new("document", "DOC-9")],
        payload: serde_json::json!({"payer": "Ada Lovelace"}),
    };
    assert!(acme.buffer(&event, ts(1)).await.expect("acme buffers"));
    assert_eq!(
        acme.sweep_unclaimed(ts(100), "nobody was waiting")
            .await
            .expect("acme sweeps"),
        1
    );

    assert!(
        globex
            .dead_letters(10)
            .await
            .expect("globex reads")
            .is_empty(),
        "another tenant's dead letters appeared in this tenant's listing"
    );
    // The positive half: the owner still reads its own.
    let letters = acme.dead_letters(10).await.expect("acme reads");
    assert_eq!(
        letters.len(),
        1,
        "the owning tenant lost its own dead letter"
    );
    assert_eq!(letters[0].event.id, "evt-dead-1");
}

/// A plane and a store scoped to different tenants is refused at build.
///
/// The two are set separately — the plane's tenant scopes data keys and the
/// policy request, the store's scopes its keys — and nothing about the mismatch
/// is visible afterwards. It works: runs are admitted, effects are authorized
/// under the right tenant, blobs are sealed under the right key, and every row
/// lands in a keyspace belonging to somebody else.
#[cfg(feature = "redb")]
#[test]
fn a_plane_will_not_start_over_another_tenants_store() {
    use agentplane::core::TenantId;
    use agentplane::runtime::Runtime;
    use agentplane::store::RedbStore;

    let store = std::sync::Arc::new(
        RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(TenantId::new("globex").expect("valid")),
    );
    let acme = TenantId::new("acme").expect("valid");

    let mismatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        drop(Runtime::builder(store).tenant(acme).build());
    }));
    assert!(
        mismatched.is_err(),
        "a plane started as 'acme' over a store serving 'globex' — its runs go \
         into globex's keyspace and nothing about that is visible at runtime"
    );

    // Matched, it starts — so the check is a check and not a refusal to run.
    let store = std::sync::Arc::new(
        RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(TenantId::new("acme").expect("valid")),
    );
    let _ = Runtime::builder(store)
        .tenant(TenantId::new("acme").expect("valid"))
        .build();
}

/// Every independently wired operational store must serve the plane's tenant.
#[cfg(feature = "redb")]
#[test]
fn a_plane_refuses_mismatched_timer_batch_and_authority_stores() {
    use agentplane::authority::AuthorityStore;
    use agentplane::batch::BatchStore;
    use agentplane::case::TimerStore;
    use agentplane::core::TenantId;
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{BuildError, Runtime};
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = || TenantId::new("acme").expect("tenant");
    let journal = || Arc::new(base.clone().for_tenant(acme()));
    let globex = || {
        Arc::new(
            base.clone()
                .for_tenant(TenantId::new("globex").expect("tenant")),
        )
    };
    let assert_store = |result: Result<Arc<Runtime>, BuildError>, expected| {
        assert!(matches!(
            result,
            Err(BuildError::StateStoreTenant {
                store,
                plane,
                tenant,
            }) if store == expected && plane == "acme" && tenant == "globex"
        ));
    };

    assert_store(
        Runtime::builder(journal() as Arc<dyn JournalStore>)
            .tenant(acme())
            .timers(globex() as Arc<dyn TimerStore>)
            .try_build(),
        "timer",
    );
    assert_store(
        Runtime::builder(journal() as Arc<dyn JournalStore>)
            .tenant(acme())
            .batches(globex() as Arc<dyn BatchStore>)
            .try_build(),
        "batch",
    );
    assert_store(
        Runtime::builder(journal() as Arc<dyn JournalStore>)
            .tenant(acme())
            .authorities(globex() as Arc<dyn AuthorityStore>)
            .try_build(),
        "authority",
    );
}

/// A plane will not start over another tenant's blob store.
///
/// The same mismatch as the journal one and a separate wire: a plane can be
/// given a correctly-scoped journal and a blob store still on `default`, and
/// nothing about that is visible at runtime. Its artifacts would land in another
/// tenant's erasure unit — so an erasure request for *that* tenant destroys
/// this one's data, and this tenant's own erasure reaches nothing.
#[cfg(feature = "redb")]
#[test]
fn a_plane_will_not_start_over_another_tenants_blobs() {
    use agentplane::blob::{BlobStore, MemoryBlobs};
    use agentplane::core::TenantId;
    use agentplane::runtime::Runtime;
    use agentplane::store::RedbStore;

    let acme = || TenantId::new("acme").expect("valid");
    let store = || {
        std::sync::Arc::new(
            RedbStore::open_in_memory()
                .expect("store")
                .for_tenant(acme()),
        )
    };

    let mismatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(
            Runtime::builder(store())
                .tenant(acme())
                // Correct journal, blob store left on the default tenant.
                .blobs(std::sync::Arc::new(MemoryBlobs::new()) as std::sync::Arc<dyn BlobStore>)
                .build(),
        );
    }));
    assert!(
        mismatched.is_err(),
        "a plane on 'acme' started over a blob store serving another tenant — \
         its artifacts land in that tenant's erasure unit, so their erasure \
         destroys this tenant's data and this tenant's erasure reaches nothing"
    );

    // Matched, it starts, so this is a check rather than a refusal to run.
    let _ = Runtime::builder(store())
        .tenant(acme())
        .blobs(std::sync::Arc::new(MemoryBlobs::new().for_tenant(acme()))
            as std::sync::Arc<dyn BlobStore>)
        .build();
}

/// Erasing one tenant's blob does not destroy another tenant's.
///
/// The severe half of blob tenancy, and the one encryption does not fix. Blobs
/// are content-addressed, so two tenants writing identical bytes — a standard
/// form, an empty document, a common attachment — land on one object when the
/// path has no tenant in it. Expiring it to discharge one tenant's erasure
/// request then destroys the other tenant's data *and reports both requests
/// satisfied*: the request nobody made is marked done, and the data that should
/// have survived is gone.
#[cfg(feature = "opendal")]
#[tokio::test]
async fn erasing_one_tenants_blob_leaves_another_tenants_alone() {
    use agentplane::blob::OpenDalBlobs;
    use agentplane::core::TenantId;

    let dir = std::env::temp_dir().join(format!("agentplane-tenant-blobs-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let op = opendal::Operator::new(opendal::services::Fs::default().root(&dir.to_string_lossy()))
        .expect("fs operator");

    let base = OpenDalBlobs::new(op, "blobs");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    // The realistic collision: the same bytes, written independently.
    let shared = b"the standard terms, filed by everyone";
    let mine = acme.put(shared).await.expect("acme put");
    let theirs = globex.put(shared).await.expect("globex put");
    assert_eq!(
        mine, theirs,
        "content addressing must still give one digest — this test is about \
         the storage path, not the address"
    );

    acme.expire(mine, ts(1), "an article 17 request")
        .await
        .expect("acme erases");

    assert!(
        globex.get(theirs).await.is_ok(),
        "erasing one tenant's blob destroyed another tenant's identical bytes, \
         and reported an erasure nobody asked for as discharged"
    );
    // And the erasure did reach acme's own copy, so it isolated rather than
    // simply failing to erase.
    assert!(
        acme.get(mine).await.is_err(),
        "the erasure reached nothing at all"
    );
}

/// One tenant's dead runs are not another tenant's to recover.
///
/// `abandoned_runs` feeds the recovery sweep, which **resumes** everything it
/// returns — so a cross-tenant row here is not a leaked identifier but another
/// tenant's run executed under this plane's identity, policy engine and
/// budget. The attacker half holds a *valid* dead lease from the other tenant,
/// because a guessed id proves nothing; the positive half proves the scoping
/// isolated the feature rather than removing it.
#[cfg(feature = "redb")]
#[tokio::test]
async fn one_tenants_dead_runs_are_not_another_tenants_to_recover() {
    use agentplane::core::{RunId, TenantId};
    use agentplane::journal::JournalStore;
    use agentplane::store::RedbStore;

    let base = RedbStore::open_in_memory().expect("store");
    let acme = base
        .clone()
        .for_tenant(TenantId::new("acme").expect("valid"));
    let globex = base.for_tenant(TenantId::new("globex").expect("valid"));

    // A real acme instance dies holding a real acme run.
    let dead = RunId::generate();
    acme.acquire(dead, "acme-worker", std::time::Duration::from_secs(1))
        .await
        .expect("acme leases");
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;

    let theirs = globex.abandoned_runs(10).await.expect("globex sweeps");
    assert!(
        theirs.is_empty(),
        "another tenant's dead run was offered for recovery — it would be \
         resumed under this plane's identity and policy: {theirs:?}"
    );

    let ours = acme.abandoned_runs(10).await.expect("acme sweeps");
    assert_eq!(
        ours,
        vec![dead],
        "the owning tenant must still find its own dead run, or the scoping \
         removed the feature rather than isolating it"
    );
}
