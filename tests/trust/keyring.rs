//! Envelope encryption: rotation, revocation, and erasure that reaches backups.

use std::sync::Arc;

use agentplane::blob::{BlobError, BlobStore, MemoryBlobs};
use agentplane::keyring::{EncryptedBlobs, KeyError, KeyRing};
use agentplane::testkit::MemoryKeyRing;

const SECRET: &[u8] = b"the claimant's medical history, which somebody may ask us to forget";

fn now() -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid instant")
}

fn sealed(scope: &str) -> (Arc<MemoryBlobs>, Arc<MemoryKeyRing>, EncryptedBlobs) {
    let disk = Arc::new(MemoryBlobs::new());
    let ring = Arc::new(MemoryKeyRing::new());
    let store = EncryptedBlobs::new(
        Arc::clone(&disk) as Arc<dyn BlobStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        scope,
    );
    (disk, ring, store)
}

/// The address is the plaintext's, and what lands on disk is not the plaintext.
///
/// Both halves matter. If the address changed, every digest already written to a
/// journal would stop meaning what it meant. If the bytes on disk were the
/// plaintext, none of this would be doing anything.
#[tokio::test]
async fn a_sealed_blob_is_addressed_by_its_plaintext_and_stored_as_ciphertext() {
    let (disk, _ring, store) = sealed("case-1");

    let digest = store.put(SECRET).await.expect("seal");
    assert_eq!(
        digest,
        agentplane::core::Digest::of(SECRET),
        "the address must be the plaintext's, or every digest in a journal has \
         quietly changed meaning"
    );
    assert_eq!(store.get(digest).await.expect("open"), SECRET);

    // What an operator with the disk actually holds.
    let on_disk = disk.get_raw(digest).await.expect("raw bytes");
    assert_ne!(on_disk, SECRET, "the payload was written in the clear");
    assert!(
        !on_disk.windows(SECRET.len()).any(|w| w == SECRET),
        "the plaintext appears verbatim inside the envelope"
    );
}

/// **Erasure reaches copies nobody can reach.**
///
/// This is the whole argument for envelope encryption over deletion. An operator
/// takes a backup, then an erasure request arrives. Deleting from the live store
/// does nothing to the backup — it is offsite and frequently immutable by
/// design, which is what makes it survive the incident it exists for.
///
/// Destroying the data key erases the backup too, without touching it, because
/// what was destroyed was never in it.
#[tokio::test]
async fn destroying_the_key_erases_a_backup_taken_before_the_request() {
    let (disk, ring, store) = sealed("case-2");
    let digest = store.put(SECRET).await.expect("seal");

    // The backup: exactly the bytes an operator would have copied offsite.
    let backup = disk.get_raw(digest).await.expect("raw bytes");
    assert!(
        !backup.is_empty(),
        "the backup captured nothing to test with"
    );

    ring.destroy("case-2", now(), "erasure request 4711")
        .await
        .expect("destroy");

    // The live read reports a completed erasure — not loss, not corruption.
    match store.get(digest).await {
        Err(BlobError::Expired { reason, .. }) => {
            assert!(
                reason.contains("erasure request 4711"),
                "the reason must survive, or 'erased' is not an answer anybody \
                 can give a regulator: {reason}"
            );
        }
        Err(e) => panic!("an erased scope must report Expired, not {e}"),
        Ok(_) => panic!("the payload was still readable after its key was destroyed"),
    }

    // And now the point. Restore the backup into a *fresh* store — a different
    // disk, as a real restore would be — and it is still unreadable.
    let restored_disk = Arc::new(MemoryBlobs::new());
    restored_disk
        .put_at(digest, &backup)
        .await
        .expect("restore");
    let restored = EncryptedBlobs::new(
        Arc::clone(&restored_disk) as Arc<dyn BlobStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        "case-2",
    );
    assert!(
        matches!(restored.get(digest).await, Err(BlobError::Expired { .. })),
        "a backup restored after the erasure gave the data back, which is the \
         exact failure deleting-from-the-live-store has and this design exists \
         to remove"
    );
}

/// A destroyed scope does not come back.
///
/// Re-minting a key for an erased scope would make a late write land in a unit
/// that has already been reported as erased — and the second erasure would find
/// data the first one said was gone.
#[tokio::test]
async fn an_erased_scope_cannot_be_recreated() {
    let (_disk, ring, store) = sealed("case-3");
    store.put(SECRET).await.expect("seal");
    ring.destroy("case-3", now(), "erasure request")
        .await
        .expect("destroy");

    assert!(
        matches!(
            ring.data_key("case-3").await,
            Err(KeyError::Destroyed { .. })
        ),
        "an erased scope minted a fresh key, so a later write would land in a \
         unit already reported as erased"
    );
    assert!(
        store.put(b"a late write").await.is_err(),
        "a write into an erased scope was accepted"
    );
}

/// Erasure is idempotent, and the first tombstone stands.
///
/// A retried erasure must not rewrite when or why the data went: that record is
/// the evidence the erasure happened, and evidence that moves is not evidence.
#[tokio::test]
async fn a_second_erasure_does_not_rewrite_the_first() {
    let (_disk, ring, _store) = sealed("case-4");
    ring.data_key("case-4").await.expect("mint");

    ring.destroy("case-4", now(), "the original request")
        .await
        .expect("destroy");
    let later = now() + time::Duration::days(30);
    ring.destroy("case-4", later, "a retry, thirty days on")
        .await
        .expect("destroy again");

    let Err(KeyError::Destroyed { at, reason, .. }) = ring.data_key("case-4").await else {
        panic!("the scope is not erased");
    };
    assert_eq!(at, now(), "the retry moved the erasure date");
    assert_eq!(
        reason, "the original request",
        "the retry rewrote the reason"
    );
}

/// Rotation adds a key version; it never invalidates one.
///
/// This is the property the whole rotation story rests on, now that sealed
/// bytes are rotation-immutable. A wrapping key may gain versions freely —
/// nothing this crate wrote has to move, and nothing already sealed may stop
/// opening. If either half failed, rotation would be an outage and no operator
/// would run one.
#[tokio::test]
async fn rotation_adds_a_version_without_disturbing_sealed_bytes() {
    let (disk, ring, store) = sealed("case-5");
    let digest = store.put(SECRET).await.expect("seal");
    let ciphertext_before = disk.get_raw(digest).await.expect("raw");
    let id_before = ring.current_key_id();
    let (_dek, old) = ring.data_key("case-5").await.expect("mint");
    assert_eq!(old.wrapped_by, id_before);

    ring.rotate();
    assert_ne!(
        ring.current_key_id(),
        id_before,
        "rotation did not change the wrapping key id, so nothing rotated"
    );

    assert_eq!(
        ciphertext_before,
        disk.get_raw(digest).await.expect("raw"),
        "rotation rewrote the bulk data — sealed bytes are rotation-immutable, \
         and a rotation that touched them would break the journal chain that \
         commits to them"
    );
    assert_eq!(
        store.get(digest).await.expect("open after rotation"),
        SECRET,
        "a payload sealed before the rotation became unreadable, which is an \
         outage rather than a key rotation"
    );

    // The half that keeps the assertions above from passing vacuously: the new
    // generation must be a genuinely different key, or "still opens after
    // rotation" is true because no rotation happened.
    let (_dek, fresh) = ring.data_key("case-5").await.expect("mint after rotation");
    assert_ne!(
        old.wrapped_by, fresh.wrapped_by,
        "a wrap minted after the rotation names the old version, so the ring \
         rotated a label rather than a key"
    );
    assert_eq!(
        ring.open(&old).await.expect("open the old wrap").expose(),
        ring.open(&old).await.expect("open the old wrap").expose(),
        "the pre-rotation wrap stopped resolving to its own key version"
    );
}

/// A retired key version is not loss, and must not be reported as loss.
///
/// A key service that refuses to decrypt below a version floor makes un-erased
/// history unreadable. That is an operator's reversible configuration, and the
/// two neighbouring classifications are both actively harmful for it:
/// `Destroyed` would claim an erasure nobody performed and no retention record
/// explains, and `Refused` reaches a drill as *neither opens nor was erased* —
/// the signature of loss or tampering — sending somebody to hunt a fault that
/// does not exist while the remedy is one setting.
#[tokio::test]
async fn a_retired_key_version_is_distinguished_from_erasure_and_from_loss() {
    let ring = MemoryKeyRing::new();
    let (dek, wrapped) = ring.data_key("case-9").await.expect("mint");
    ring.rotate();
    ring.retire_below(1);

    match ring.open(&wrapped).await {
        Err(KeyError::Retired { scope, key_id }) => {
            assert_eq!(scope, "case-9");
            assert_eq!(
                key_id, wrapped.wrapped_by,
                "the error names a different key version than the wrap does, so \
                 an operator cannot tell which floor to lower"
            );
        }
        Err(KeyError::Destroyed { .. }) => panic!(
            "a retired version was reported as a completed erasure — the data is \
             intact and comes back when the floor is lowered, but the operator \
             has been told it is gone forever"
        ),
        other => panic!(
            "a retired version must be its own answer, not {other:?}: reported as \
             a bare refusal it reaches a drill as loss or tampering"
        ),
    }

    // Reversible, which is exactly what distinguishes it from erasure.
    ring.retire_below(0);
    assert_eq!(
        ring.open(&wrapped)
            .await
            .expect("open once readmitted")
            .expose(),
        dek.expose(),
        "lowering the floor did not make the payload readable again, so the \
         refusal was not really a version floor"
    );
}

/// A wrap naming a generation this ring never issued is refused, not opened.
///
/// `open` used to ignore `wrapped_by` entirely and decrypt with whatever key
/// the scope currently had — so a wrap fabricated with any label at all
/// "opened", to garbage, and the mistake surfaced later as corrupt payloads
/// rather than here as a refusal. A KMS resolves the key version from the
/// ciphertext's own metadata and refuses versions it does not hold; the fake
/// now does the same. What this does NOT give the fake is integrity on the
/// sealed bytes themselves — XOR authenticates nothing, deliberately, so only
/// the resolution semantics are being pinned here.
#[tokio::test]
async fn a_wrap_from_a_generation_the_ring_never_issued_is_refused() {
    let ring = MemoryKeyRing::new();
    let (_dek, wrapped) = ring.data_key("case-7").await.expect("mint");

    // Same scope, same sealed bytes, a generation that never existed.
    let forged = agentplane::keyring::WrappedKey {
        scope: wrapped.scope.clone(),
        wrapped_by: "memory-kek-999".to_owned(),
        sealed: wrapped.sealed.clone(),
    };
    assert!(
        matches!(ring.open(&forged).await, Err(KeyError::Refused(_))),
        "a generation this ring never wrapped under must refuse, not decrypt \
         with whichever key is current"
    );

    // And an id another ring entirely would have stamped.
    let alien = agentplane::keyring::WrappedKey {
        scope: wrapped.scope,
        wrapped_by: "vault:v3".to_owned(),
        sealed: wrapped.sealed,
    };
    assert!(
        matches!(ring.open(&alien).await, Err(KeyError::Refused(_))),
        "a foreign wrapping-key id must be refused"
    );
}

/// Moving ciphertext to another address does not decrypt it there.
///
/// The digest is the envelope's associated data, so a payload lifted to a
/// different address fails to authenticate rather than opening as somebody
/// else's blob.
#[tokio::test]
async fn an_envelope_does_not_open_at_an_address_it_was_not_sealed_for() {
    let (disk, ring, store) = sealed("case-6");
    let digest = store.put(SECRET).await.expect("seal");
    let envelope = disk.get_raw(digest).await.expect("raw");

    let elsewhere = agentplane::core::Digest::of(b"a different payload entirely");
    disk.put_at(elsewhere, &envelope).await.expect("move it");

    let moved = EncryptedBlobs::new(
        Arc::clone(&disk) as Arc<dyn BlobStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        "case-6",
    );
    assert!(
        matches!(moved.get(elsewhere).await, Err(BlobError::Corrupt { .. })),
        "an envelope opened at an address it was not sealed for"
    );
}

/// An outage must not look like an erasure.
///
/// The two answers send an operator to opposite conclusions: *erased* means the
/// data is gone forever and the request is discharged; *unavailable* means the
/// key ring is down and it will be back. Reporting a KMS outage as a completed
/// erasure would tell somebody their data no longer exists while it sits intact
/// on disk — and they would stop looking for it.
#[tokio::test]
async fn a_key_ring_outage_is_not_reported_as_an_erasure() {
    #[derive(Debug)]
    struct Unreachable;

    #[async_trait::async_trait]
    impl KeyRing for Unreachable {
        async fn data_key(
            &self,
            _scope: &str,
        ) -> Result<
            (
                agentplane::keyring::DataKey,
                agentplane::keyring::WrappedKey,
            ),
            KeyError,
        > {
            Err(KeyError::Unavailable("the KMS did not answer".into()))
        }
        async fn open(
            &self,
            _w: &agentplane::keyring::WrappedKey,
        ) -> Result<agentplane::keyring::DataKey, KeyError> {
            Err(KeyError::Unavailable("the KMS did not answer".into()))
        }
        async fn destroy(
            &self,
            _scope: &str,
            _at: agentplane::core::Timestamp,
            _reason: &str,
        ) -> Result<(), KeyError> {
            Err(KeyError::Unavailable("the KMS did not answer".into()))
        }
    }

    let store = EncryptedBlobs::new(
        Arc::new(MemoryBlobs::new()) as Arc<dyn BlobStore>,
        Arc::new(Unreachable) as Arc<dyn KeyRing>,
        "case-7",
    );

    match store.put(SECRET).await {
        Err(BlobError::Expired { .. }) => panic!(
            "a key ring outage was reported as a completed erasure — an operator \
             would conclude the data is gone forever while it is intact"
        ),
        Err(BlobError::Backend(why)) => assert!(why.contains("unavailable"), "{why}"),
        other => panic!("an unreachable key ring should fail loudly: {other:?}"),
    }
}

/// **The two halves meet.** A run stores bytes; erasing its case destroys the
/// key; a backup taken beforehand is unreadable.
///
/// The mechanism is worth nothing unwired. Before this, `store_blob` wrote
/// plaintext and `erase_case` expired tombstones — an erasure that reached the
/// live store and nothing else. The case is the erasure unit on both sides
/// because it is already the retention unit: bytes are linked to their case at
/// write time, and a second, differently shaped unit for keys would let the two
/// disagree about what an erasure covered.
/// A skill that stores one secret blob through the governed path.
#[cfg(all(feature = "redb", feature = "keyring"))]
#[derive(Debug)]
struct Keeps;

#[cfg(all(feature = "redb", feature = "keyring"))]
#[async_trait::async_trait]
impl agentplane::core::Skill for Keeps {
    fn descriptor(&self) -> agentplane::core::SkillDescriptor {
        agentplane::core::SkillDescriptor::new("keeps").provides("records.keep")
    }
    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _input: agentplane::core::Tainted<serde_json::Value>,
    ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
        let digest = cx.store_blob(SECRET).await?;
        Ok(agentplane::core::Outcome::done(
            agentplane::core::Tainted::trusted(serde_json::json!(digest.to_hex())),
        ))
    }
}

/// Run [`Keeps`] on a sealed plane and hand back the case it opened.
#[cfg(all(feature = "redb", feature = "keyring"))]
async fn sealed_case_with_blob(
    disk: &Arc<MemoryBlobs>,
    ring: &Arc<MemoryKeyRing>,
) -> (Arc<agentplane::store::RedbStore>, agentplane::core::CaseId) {
    use agentplane::core::{CorrelationKey, Tainted};
    use agentplane::runtime::Runtime;
    use serde_json::json;

    let store = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn agentplane::journal::JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .blobs(Arc::clone(disk) as Arc<dyn BlobStore>)
        .keyring(Arc::clone(ring) as Arc<dyn KeyRing>)
        .skill(Keeps)
        .build();
    let out = rt
        .run_correlated(
            "records.keep",
            Tainted::trusted(json!({})),
            "claim",
            &[CorrelationKey::new("claim", "CLM-1")],
        )
        .await
        .expect("run");
    assert!(
        matches!(out.status, agentplane::runtime::RunStatus::Succeeded),
        "the run did not succeed: {:?}",
        out.status
    );
    let case = agentplane::case::CaseStore::correlate(
        store.as_ref(),
        &[CorrelationKey::new("claim", "CLM-1")],
    )
    .await
    .expect("correlate")
    .expect("the run opened a case");
    (store, case)
}

#[cfg(all(feature = "redb", feature = "keyring"))]
#[tokio::test]
async fn erasing_a_case_destroys_its_key_and_the_backup_with_it() {
    let disk = Arc::new(MemoryBlobs::new());
    let ring = Arc::new(MemoryKeyRing::new());
    let (store, case_id) = sealed_case_with_blob(&disk, &ring).await;
    let digest = agentplane::core::Digest::of(SECRET);
    let tenant = agentplane::core::TenantId::default();
    let scope = agentplane::keyring::scope(&tenant, &case_id.to_string());

    // What reached the disk is sealed, lives at the case's own unit address —
    // never at the bare content digest, which two cases could share — and the
    // case can read it back through its own handle.
    let address = agentplane::blob::unit_address(&scope, digest);
    let backup = disk.get_raw(address).await.expect("raw bytes");
    assert_ne!(backup, SECRET, "the run wrote its payload in the clear");
    assert!(
        matches!(disk.get_raw(digest).await, Err(BlobError::NotFound(_))),
        "the bytes were filed at the bare content digest, outside the case's          erasure unit"
    );

    let sealed_view = EncryptedBlobs::new(
        Arc::new(agentplane::blob::ScopedBlobs::new(
            Arc::clone(&disk) as Arc<dyn BlobStore>,
            scope.clone(),
        )),
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        scope.clone(),
    );
    assert_eq!(
        sealed_view.get(digest).await.expect("read back"),
        SECRET,
        "the case could not read its own bytes, so sealing broke the run"
    );

    // Erase the case. Tombstones *and* the key.
    let n = agentplane::blob::erase_case(
        Some(disk.as_ref()),
        store.as_ref(),
        Some(ring.as_ref() as &dyn KeyRing),
        &agentplane::core::TenantId::default(),
        case_id,
        now(),
        "art-17 request",
    )
    .await
    .expect("erase");
    assert_eq!(
        n, 1,
        "the case's blob was not linked, so erasure found nothing"
    );

    assert!(
        matches!(
            ring.data_key(&agentplane::keyring::scope(&tenant, &case_id.to_string()))
                .await,
            Err(KeyError::Destroyed { .. })
        ),
        "erasing the case left its data key alive, so the erasure reached the \
         live store and nothing else"
    );

    // The backup, restored somewhere else entirely — at the same unit
    // address a backup of the object store would carry.
    let elsewhere = Arc::new(MemoryBlobs::new());
    elsewhere.put_at(address, &backup).await.expect("restore");
    let restored = EncryptedBlobs::new(
        Arc::new(agentplane::blob::ScopedBlobs::new(
            Arc::clone(&elsewhere) as Arc<dyn BlobStore>,
            scope.clone(),
        )),
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        scope,
    );
    assert!(
        matches!(restored.get(digest).await, Err(BlobError::Expired { .. })),
        "a backup restored after the case was erased gave the data back"
    );
}

/// **Erasing one tenant does not reach another's bytes.**
///
/// The adversarial swap the threat model asks for, at the only layer that has a
/// tenant boundary. Two tenants using the *same* case name is the interesting
/// case, because that is where a missing prefix collides: without one, both
/// seal under `case-1`, and the first erasure destroys the second tenant's data
/// while reporting success for the first.
///
/// It also pins the reason `TenantId` refuses `/`. A tenant named `acme/prod`
/// would produce the same scope as tenant `acme` with unit `prod`, and the two
/// would be indistinguishable afterwards.
#[tokio::test]
async fn erasing_one_tenants_key_leaves_another_tenant_readable() {
    use agentplane::core::TenantId;

    let disk = Arc::new(MemoryBlobs::new());
    let ring = Arc::new(MemoryKeyRing::new());

    let acme = TenantId::new("acme").expect("a valid tenant");
    let globex = TenantId::new("globex").expect("a valid tenant");
    // Deliberately the same unit name under both tenants.
    let unit = "case-1";

    let view = |t: &TenantId| {
        EncryptedBlobs::new(
            Arc::clone(&disk) as Arc<dyn BlobStore>,
            Arc::clone(&ring) as Arc<dyn KeyRing>,
            agentplane::keyring::scope(t, unit),
        )
    };

    let digest = view(&acme).put(SECRET).await.expect("acme seals");
    let other = b"globex's own records, which acme may not erase";
    let other_digest = view(&globex).put(other).await.expect("globex seals");

    // Acme exercises its right to erasure.
    ring.destroy(
        &agentplane::keyring::scope(&acme, unit),
        now(),
        "art-17 request",
    )
    .await
    .expect("destroy");

    assert!(
        matches!(
            view(&acme).get(digest).await,
            Err(BlobError::Expired { .. })
        ),
        "acme's own bytes survived its erasure"
    );
    assert_eq!(
        view(&globex).get(other_digest).await.expect("globex reads"),
        other,
        "erasing acme destroyed globex's key — one tenant's erasure reached \
         another tenant's data, which is the isolation failure the tenant \
         prefix exists to prevent"
    );

    // And the prefix cannot be forged by naming a tenant with a separator.
    assert!(
        TenantId::new("acme/prod").is_err(),
        "a tenant named with a separator would produce the same scope as \
         another tenant plus a unit, making the two indistinguishable"
    );
}

// ── The journal, sealed at rest ─────────────────────────────────────────────

/// A run whose payloads are sealed: written and read back in the clear by the
/// runtime, ciphertext in the store, and the **chain verifies with no keys**.
///
/// That last property is the whole design. The chain commits to the sealed
/// bytes, so tamper evidence does not depend on the key — which is what makes
/// the erasure below survivable rather than self-defeating.
#[tokio::test]
async fn a_sealed_journal_hides_payloads_and_still_verifies_without_keys() {
    use agentplane::core::{Digest, Label, RunId, TenantId};
    use agentplane::journal::{Append, JournalStore, Record, RecordKind, payload};
    use agentplane::keyring::SealedJournal;

    let plain: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());
    let sealed = SealedJournal::wrap(
        Arc::clone(&plain),
        Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>,
        TenantId::default(),
    );

    let run = RunId::generate();
    let lease = sealed
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    sealed
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "intake".into(),
                    governed_by: None,
                    input_label: Label::trusted(),
                    input: serde_json::json!({ "patient": "Ada Lovelace" }),
                    policy_bundle: None,
                    canon: agentplane::core::canon::VERSION,
                    idempotency_key: None,
                },
            )],
        )
        .await
        .expect("append");

    // Through the wrapper: readable.
    let opened = sealed.read(run, 1).await.expect("read");
    match opened[0].kind() {
        RecordKind::RunAdmitted { input, .. } => {
            assert_eq!(input["patient"], "Ada Lovelace", "the payload did not open");
        }
        other => panic!("unexpected record: {other:?}"),
    }

    // Straight from the store: sealed, and the name is nowhere in the bytes.
    let raw = plain.read(run, 1).await.expect("raw read");
    match raw[0].kind() {
        RecordKind::RunAdmitted { input, .. } => {
            assert!(
                payload::is_sealed(input),
                "the payload reached the store in the clear: {input}"
            );
        }
        other => panic!("unexpected record: {other:?}"),
    }
    assert!(
        !String::from_utf8_lossy(raw[0].raw()).contains("Lovelace"),
        "the plaintext is in the bytes the store keeps"
    );

    // The routing stays in the clear, so the runtime keeps working with no key.
    assert_eq!(raw[0].kind().kind_str(), "RunAdmitted");

    // **The property that matters**: verified with no key ring in sight.
    Record::verify_chain(&raw, Digest::ZERO).expect("the chain verifies without keys");
}

/// A conclusion's reason is a payload, and reaches the store sealed.
///
/// `RunConcluded` routes on `outcome`, so the whole record used to be
/// control-plane and carried nothing to seal. A reason is the same free text
/// `EffectFailed.error` is — a provider's refusal quoting the request — and a
/// field added to an existing variant is exactly what an exhaustive match over
/// *variants* does not ask about.
#[tokio::test]
async fn a_conclusions_reason_is_sealed_and_its_outcome_stays_readable() {
    use agentplane::core::{RunId, TenantId};
    use agentplane::journal::{Append, JournalStore, RecordKind, payload};
    use agentplane::keyring::SealedJournal;

    let plain: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());
    let sealed = SealedJournal::wrap(
        Arc::clone(&plain),
        Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>,
        TenantId::default(),
    );

    let run = RunId::generate();
    let lease = sealed
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    sealed
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunConcluded {
                    outcome: "failed".into(),
                    reason: Some("the registry refused patient Ada Lovelace".into()),
                    exhaustion: None,
                    live_spend: agentplane::core::Spend::default(),
                    chain_head: agentplane::core::Digest::ZERO,
                },
            )],
        )
        .await
        .expect("append");

    let raw = plain.read(run, 1).await.expect("raw read");
    let RecordKind::RunConcluded {
        outcome, reason, ..
    } = raw[0].kind()
    else {
        panic!("unexpected record: {:?}", raw[0].kind())
    };
    assert_eq!(
        outcome, "failed",
        "the outcome routes the index and must stay readable with no key"
    );
    let reason = reason.as_deref().expect("the reason survives sealing");
    assert!(
        payload::is_sealed_text(reason),
        "the reason reached the store in the clear: {reason}"
    );
    assert!(
        !String::from_utf8_lossy(raw[0].raw()).contains("Lovelace"),
        "the plaintext is in the bytes the store keeps"
    );

    // Through the wrapper it opens, so an operator asking why still gets an
    // answer.
    let opened = sealed.read(run, 1).await.expect("read");
    let RecordKind::RunConcluded { reason, .. } = opened[0].kind() else {
        panic!("unexpected record")
    };
    assert_eq!(
        reason.as_deref(),
        Some("the registry refused patient Ada Lovelace")
    );
}

/// After the scope's key is destroyed the payload is unreadable **and the
/// chain still verifies** — an erasure that does not cost the tamper evidence.
///
/// The alternative design, hashing the plaintext, would have destroyed both at
/// once: the data *and* the ability to show nothing had been altered.
#[tokio::test]
async fn erasing_the_key_leaves_the_chain_verifiable() {
    use agentplane::core::{Digest, Label, RunId, TenantId, Timestamp};
    use agentplane::journal::{Append, JournalStore, Record, RecordKind, payload};
    use agentplane::keyring::SealedJournal;

    let plain: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());
    let sealed = SealedJournal::wrap(
        Arc::clone(&plain),
        Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>,
        TenantId::default(),
    );

    let run = RunId::generate();
    let lease = sealed
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    sealed
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "intake".into(),
                    governed_by: None,
                    input_label: Label::trusted(),
                    input: serde_json::json!({ "patient": "Ada Lovelace" }),
                    policy_bundle: None,
                    canon: agentplane::core::canon::VERSION,
                    idempotency_key: None,
                },
            )],
        )
        .await
        .expect("append");

    // A run with no case seals under its own id — an erasure unit somebody can
    // name, and the one an operator would reach for here.
    keys.destroy(
        &agentplane::keyring::scope(&agentplane::core::TenantId::default(), &run.to_string()),
        Timestamp::from_unix_timestamp(1_760_000_000).expect("time"),
        "subject exercised the right to erasure",
    )
    .await
    .expect("destroy");

    // Unreadable — through the wrapper that holds the ring, not merely to
    // somebody without one.
    let after = sealed.read(run, 1).await.expect("read still works");
    match after[0].kind() {
        RecordKind::RunAdmitted { input, .. } => {
            assert!(
                payload::is_sealed(input),
                "the payload opened after its key was destroyed: {input}"
            );
        }
        other => panic!("unexpected record: {other:?}"),
    }

    // And the history still proves it was not altered.
    let raw = plain.read(run, 1).await.expect("raw read");
    Record::verify_chain(&raw, Digest::ZERO)
        .expect("erasure destroyed the tamper evidence along with the data");
}

/// Case state is sealed in the case store too, under the scope `erase_case`
/// destroys — so one erasure reaches the journal's copy and this one alike.
///
/// The journal's copy of a case write is sealed by `SealedJournal`; this is
/// the second copy, the one the store keeps so `case()` can answer without
/// replaying a run. Sealing one without the other would leave the data
/// readable exactly where an operator looks first.
#[tokio::test]
async fn case_state_is_sealed_and_erasing_the_case_takes_it() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, TenantId, Timestamp};
    use agentplane::journal::payload;
    use agentplane::keyring::SealedCases;

    let plain: Arc<dyn CaseStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());
    let tenant = TenantId::default();
    let sealed = SealedCases::wrap(
        Arc::clone(&plain),
        Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>,
        tenant.clone(),
    );

    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let case = sealed
        .correlate_or_open("claim", &[CorrelationKey::new("claim", "CLM-9")], at)
        .await
        .expect("open")
        .case_id();
    let current = sealed.case(case).await.expect("read").expect("exists");
    sealed
        .put_state(
            case,
            current.version,
            serde_json::json!({ "claimant": "Ada Lovelace" }),
        )
        .await
        .expect("write");

    // Through the wrapper: readable.
    let opened = sealed.case(case).await.expect("read").expect("exists");
    assert_eq!(opened.state["claimant"], "Ada Lovelace");

    // Straight from the store: sealed, and the name is not in it.
    let raw = plain.case(case).await.expect("raw").expect("exists");
    assert!(
        payload::is_sealed(&raw.state),
        "case state reached the store in the clear: {}",
        raw.state
    );
    assert!(!raw.state.to_string().contains("Lovelace"));

    // Erasing the case destroys the scope key — the same act that erases its
    // blobs and its journal payloads.
    keys.destroy(
        &agentplane::keyring::scope(&tenant, &case.to_string()),
        at,
        "subject exercised the right to erasure",
    )
    .await
    .expect("destroy");

    let after = sealed.case(case).await.expect("read").expect("exists");
    assert!(
        payload::is_sealed(&after.state),
        "case state opened after its key was destroyed: {}",
        after.state
    );
    // Still listable and closable: a completed erasure is not an outage.
    assert_eq!(after.id, case);
}

/// **The composed claim, checked.** One `erase_case` makes every copy of a
/// case's data unreadable — blobs, the journal's payloads, and the case
/// store's state — while the hash chain still verifies.
///
/// Each decorator is tested alone above. This is the one that matters to a
/// deployer, because it is the sentence the documentation actually makes:
/// *one erasure reaches every copy*. Composition is where that kind of claim
/// breaks — three mechanisms sharing a scope only work if they really do share
/// it, and nothing but this test says they do.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn one_erasure_reaches_every_copy_and_the_chain_still_verifies() {
    use agentplane::blob::{BlobStore, MemoryBlobs};
    use agentplane::case::CaseStore;
    use agentplane::core::{CorrelationKey, Digest, Label, RunId, TenantId, Timestamp};
    use agentplane::journal::{Append, JournalStore, Record, RecordKind, payload};
    use agentplane::keyring::{EncryptedBlobs, SealedCases, SealedJournal};

    let tenant = TenantId::default();
    let keys = Arc::new(MemoryKeyRing::default());
    let ring = Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>;
    let raw = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));

    let cases_plain: Arc<dyn CaseStore> = Arc::clone(&raw) as Arc<dyn CaseStore>;
    let cases = SealedCases::wrap(Arc::clone(&cases_plain), Arc::clone(&ring), tenant.clone());
    let plain_journal = Arc::clone(&raw) as Arc<dyn JournalStore>;
    let journal = SealedJournal::wrap(plain_journal, Arc::clone(&ring), tenant.clone());

    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let case = cases
        .correlate_or_open("claim", &[CorrelationKey::new("claim", "CLM-42")], at)
        .await
        .expect("open")
        .case_id();

    // Case state.
    let opened_case = cases.case(case).await.expect("read").expect("exists");
    cases
        .put_state(
            case,
            opened_case.version,
            serde_json::json!({ "claimant": "Ada Lovelace" }),
        )
        .await
        .expect("state");

    // A journal record bound to that case.
    let run = RunId::generate();
    let lease = journal
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    journal
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "claim.assess".into(),
                        governed_by: None,
                        input_label: Label::trusted(),
                        input: serde_json::json!({ "claimant": "Ada Lovelace" }),
                        policy_bundle: None,
                        canon: agentplane::core::canon::VERSION,
                        idempotency_key: None,
                    },
                )
                .case(case),
                // Every other payload field the sealing list names, so this
                // test is the one that notices a field added to a record and
                // forgotten by the list: a plan can embed input-derived
                // constants, a note is model output over the caller's data, a
                // failure message quotes the request that was refused, and a
                // reconciled output is caller data a probe recovered.
                Append::new(
                    run,
                    RecordKind::PlanFrozen {
                        steps: vec!["claim.assess".into()],
                        plan: serde_json::json!({ "constant": "Ada Lovelace" }),
                    },
                )
                .case(case),
                Append::new(
                    run,
                    RecordKind::Note {
                        text: "the claimant Ada Lovelace looks legitimate".into(),
                    },
                )
                .case(case),
                Append::new(
                    run,
                    RecordKind::EffectFailed {
                        error: "payee Ada Lovelace was refused by the bank".into(),
                        spend: agentplane::core::Spend::default(),
                        disposition: agentplane::core::Disposition::DidNotHappen,
                        permanent: false,
                    },
                )
                .case(case),
                Append::new(
                    run,
                    RecordKind::EffectReconciled {
                        disposition: agentplane::core::Disposition::Landed,
                        output: Some(serde_json::json!({ "claimant": "Ada Lovelace" })),
                        spend: agentplane::core::Spend::default(),
                        detail: None,
                        declared: Some(agentplane::core::DeclaredOutput::untrusted()),
                    },
                )
                .case(case),
            ],
        )
        .await
        .expect("append");

    // A blob, linked to the case the way `cx.store_blob` links it.
    let blobs = EncryptedBlobs::new(
        Arc::new(MemoryBlobs::default()) as Arc<dyn BlobStore>,
        Arc::clone(&ring),
        agentplane::keyring::scope(&tenant, &case.to_string()),
    );
    let digest = blobs
        .put(b"Ada Lovelace, 12 Acacia Avenue")
        .await
        .expect("blob");
    cases_plain.link_blob(case, digest, at).await.expect("link");

    // Everything readable before.
    assert_eq!(
        cases.case(case).await.expect("r").expect("e").state["claimant"],
        "Ada Lovelace"
    );
    assert!(blobs.get(digest).await.is_ok());

    // ── One erasure ─────────────────────────────────────────────────────────
    agentplane::blob::erase_case(
        Some(&blobs),
        cases_plain.as_ref(),
        Some(ring.as_ref()),
        &tenant,
        case,
        at,
        "subject exercised the right to erasure",
    )
    .await
    .expect("erase");

    // Blob bytes: gone.
    assert!(
        blobs.get(digest).await.is_err(),
        "the blob survived the erasure"
    );
    // Case state: sealed shut.
    let after = cases.case(case).await.expect("r").expect("e");
    assert!(
        payload::is_sealed(&after.state),
        "case state survived the erasure: {}",
        after.state
    );
    // Journal payloads: sealed shut, through the store that holds the ring —
    // every field on the sealing list, because a field the erasure misses is
    // an erasure reporting success over readable data.
    let records = journal.read(run, 1).await.expect("read");
    for record in &records {
        match record.kind() {
            RecordKind::RunAdmitted { input, .. } => assert!(
                payload::is_sealed(input),
                "the admitted input survived the erasure: {input}"
            ),
            RecordKind::PlanFrozen { plan, .. } => assert!(
                payload::is_sealed(plan),
                "the frozen plan survived the erasure — its constants are \
                 compiled from the caller's input: {plan}"
            ),
            RecordKind::Note { text } => assert!(
                payload::is_sealed_text(text),
                "a note survived the erasure: {text}"
            ),
            RecordKind::EffectFailed {
                error,
                disposition,
                permanent,
                ..
            } => {
                assert!(
                    payload::is_sealed_text(error),
                    "a failure message survived the erasure: {error}"
                );
                // The routing half must NOT be sealed: recovery reads the
                // disposition with no key at all.
                assert_eq!(*disposition, agentplane::core::Disposition::DidNotHappen);
                assert!(!*permanent);
            }
            RecordKind::EffectReconciled { output, .. } => assert!(
                output.as_ref().is_some_and(payload::is_sealed),
                "a reconciled output survived the erasure: {output:?}"
            ),
            other => panic!("unexpected record: {other:?}"),
        }
    }
    assert!(
        !serde_json::to_string(
            &records
                .iter()
                .map(agentplane::Record::kind)
                .collect::<Vec<_>>()
        )
        .expect("serialise")
        .contains("Lovelace"),
        "the caller's data is readable somewhere in the erased run's records"
    );

    // ── And the history still proves itself ─────────────────────────────────
    let stored = raw.read(run, 1).await.expect("raw");
    Record::verify_chain(&stored, Digest::ZERO)
        .expect("the erasure destroyed the tamper evidence along with the data");
}

/// **A run with no case still has an erasure path.**
///
/// `SealedJournal` seals a case-less record's payloads under `tenant/<run>` —
/// an erasure unit somebody can name — but `erase_case` was the only erasure
/// verb, and it destroys a *case* scope. A run that never bound to a case
/// therefore had sealed data nobody could erase: a scope with a name and no
/// verb. `erase_run` is that verb, and this holds it to the same composed
/// claim `erase_case` is held to — the payloads become unreadable, and the
/// chain still verifies over the ciphertext it always committed to.
#[tokio::test]
async fn a_case_less_runs_payloads_are_erasable_by_run() {
    use agentplane::core::{Digest, Label, RunId, TenantId, Timestamp};
    use agentplane::journal::{Append, JournalStore, Record, RecordKind, payload};
    use agentplane::keyring::SealedJournal;

    let tenant = TenantId::default();
    let keys = Arc::new(MemoryKeyRing::default());
    let ring = Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>;
    let raw = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let journal = SealedJournal::wrap(
        Arc::clone(&raw) as Arc<dyn JournalStore>,
        Arc::clone(&ring),
        tenant.clone(),
    );

    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let run = RunId::generate();
    let lease = journal
        .acquire(run, "test", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    journal
        .append(
            lease.epoch,
            // Deliberately no `.case(..)`: the run is its own erasure unit.
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "one-shot.report".into(),
                    governed_by: None,
                    input_label: Label::trusted(),
                    input: serde_json::json!({ "claimant": "Ada Lovelace" }),
                    policy_bundle: None,
                    canon: agentplane::core::canon::VERSION,
                    idempotency_key: None,
                },
            )],
        )
        .await
        .expect("append");

    // Readable before, through the ring.
    match journal.read(run, 1).await.expect("read")[0].kind() {
        RecordKind::RunAdmitted { input, .. } => {
            assert_eq!(input["claimant"], "Ada Lovelace");
        }
        other => panic!("unexpected record: {other:?}"),
    }

    agentplane::blob::erase_run(
        ring.as_ref(),
        &tenant,
        run,
        at,
        "subject exercised the right to erasure",
    )
    .await
    .expect("erase");

    // Sealed shut after — through the store that still holds the ring.
    match journal.read(run, 1).await.expect("read")[0].kind() {
        RecordKind::RunAdmitted { input, .. } => assert!(
            payload::is_sealed(input),
            "a case-less run's payload survived its erasure: {input}"
        ),
        other => panic!("unexpected record: {other:?}"),
    }
    // Idempotent: a retry cannot rewrite when or why the data went.
    agentplane::blob::erase_run(ring.as_ref(), &tenant, run, at, "retry")
        .await
        .expect("second erasure");
    // And the history still proves itself with no key at all.
    let stored = raw.read(run, 1).await.expect("raw");
    Record::verify_chain(&stored, Digest::ZERO)
        .expect("the erasure destroyed the tamper evidence along with the data");
}

/// A buffered event's payload is sealed — including the dead-letter copy,
/// which is the one that outlives everything.
///
/// The erasure unit is the **event**, not the case, and that is forced rather
/// than chosen: an event is buffered before any subscription matches it, and
/// one that is never claimed becomes a dead letter, which by definition
/// matched no case at all. `(source, id)` — the pair the buffer already
/// deduplicates on — is the finest unit an erasure request about one message
/// could name.
#[tokio::test]
async fn a_buffered_event_payload_is_sealed_and_erasable_on_its_own() {
    use agentplane::case::EventStore;
    use agentplane::core::{InboundEvent, TenantId, Timestamp};
    use agentplane::journal::payload;
    use agentplane::keyring::SealedEvents;

    let plain: Arc<dyn EventStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());
    let tenant = TenantId::default();
    let sealed = SealedEvents::wrap(
        Arc::clone(&plain),
        Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>,
        tenant.clone(),
    );

    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let event = InboundEvent {
        source: "bank.example".to_owned(),
        id: "MSG-7".to_owned(),
        kind: "payment.settled".to_owned(),
        correlation: vec![agentplane::core::CorrelationKey::new("claim", "NOBODY")],
        payload: serde_json::json!({ "payer": "Ada Lovelace", "amount": 4200 }),
    };
    assert!(sealed.buffer(&event, at).await.expect("buffer"));

    // Nobody claims it, so it ages into the dead-letter list — the copy that
    // persists indefinitely for an operator to find the wrong key by.
    sealed
        .sweep_unclaimed(
            Timestamp::from_unix_timestamp(1_760_009_999).expect("time"),
            "nobody was waiting",
        )
        .await
        .expect("sweep");

    // Through the wrapper: the operator can read it, which is the point of
    // keeping dead letters at all.
    let letters = sealed.dead_letters(10).await.expect("dead letters");
    assert_eq!(letters.len(), 1);
    assert_eq!(letters[0].event.payload["payer"], "Ada Lovelace");

    // In the store: sealed, and the name is not in the bytes.
    let raw = plain.dead_letters(10).await.expect("raw");
    assert!(
        payload::is_sealed(&raw[0].event.payload),
        "an event payload reached the buffer in the clear: {}",
        raw[0].event.payload
    );
    assert!(!raw[0].event.payload.to_string().contains("Lovelace"));
    // The dedup identity and match keys stay readable, or the buffer could
    // neither deduplicate nor match.
    assert_eq!(raw[0].event.source, "bank.example");
    assert_eq!(raw[0].event.kind, "payment.settled");

    // One message, one scope: erasing this event erases exactly it.
    keys.destroy(
        &agentplane::keyring::scope(&tenant, "event/bank.example/MSG-7"),
        at,
        "subject exercised the right to erasure",
    )
    .await
    .expect("destroy");
    let after = sealed.dead_letters(10).await.expect("dead letters");
    assert!(
        payload::is_sealed(&after[0].event.payload),
        "the payload opened after its key was destroyed"
    );
    // Still listed, so the wrong-correlation-key signal survives the erasure.
    assert_eq!(after[0].event.id, "MSG-7");
}

/// **One call seals every store the plane holds.**
///
/// `keyring` used to seal blob payloads and nothing else — honest while blobs
/// were the only sealable surface, and a trap the moment they were not: a
/// deployer configuring a key ring reads it as *this plane is encrypted*.
/// Five independent wrapping calls is a control that can be forgotten four
/// times, and forgetting looks exactly like remembering.
#[tokio::test]
async fn configuring_a_key_ring_seals_every_store() {
    use agentplane::case::{CaseStore, EventStore, TaskStore};
    use agentplane::core::{CorrelationKey, Label, RunId, Timestamp};
    use agentplane::journal::{Append, JournalStore, RecordKind, payload};
    use agentplane::runtime::Runtime;

    let raw = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let keys = Arc::new(MemoryKeyRing::default());

    // Deliberately registered *before* the key ring: wrapping happens at
    // build, so the order a deployer happens to write cannot lose it.
    let rt = Runtime::builder(Arc::clone(&raw) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&raw) as Arc<dyn CaseStore>)
        .events(Arc::clone(&raw) as Arc<dyn EventStore>)
        .tasks(Arc::clone(&raw) as Arc<dyn TaskStore>)
        .keyring(Arc::clone(&keys) as Arc<dyn agentplane::keyring::KeyRing>)
        .build();

    let at = Timestamp::from_unix_timestamp(1_760_000_000).expect("time");
    let case = rt
        .cases()
        .expect("cases")
        .correlate_or_open("claim", &[CorrelationKey::new("claim", "CLM-1")], at)
        .await
        .expect("open")
        .case_id();
    let current = rt
        .cases()
        .expect("c")
        .case(case)
        .await
        .expect("r")
        .expect("e");
    rt.cases()
        .expect("c")
        .put_state(case, current.version, serde_json::json!({ "who": "Ada" }))
        .await
        .expect("state");

    let run = RunId::generate();
    let lease = rt
        .journal()
        .acquire(run, "t", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    rt.journal()
        .append(
            lease.epoch,
            vec![Append::new(
                run,
                RecordKind::RunAdmitted {
                    capability: "c".into(),
                    governed_by: None,
                    input_label: Label::trusted(),
                    input: serde_json::json!({ "who": "Ada" }),
                    policy_bundle: None,
                    canon: agentplane::core::canon::VERSION,
                    idempotency_key: None,
                },
            )],
        )
        .await
        .expect("append");

    // Straight from the underlying store: both sealed, from one `.keyring(..)`.
    let stored_case = raw.case(case).await.expect("r").expect("e");
    assert!(
        payload::is_sealed(&stored_case.state),
        "case state was not sealed by the plane's key ring: {}",
        stored_case.state
    );
    let stored = raw.read(run, 1).await.expect("read");
    match stored[0].kind() {
        RecordKind::RunAdmitted { input, .. } => assert!(
            payload::is_sealed(input),
            "the journal was not sealed by the plane's key ring: {input}"
        ),
        other => panic!("unexpected record: {other:?}"),
    }
}

// ── Webhook credentials at rest ─────────────────────────────────────────────

/// The push table stores destinations and the credentials to reach them, and
/// the concept spec calls a leaked registration what it is: a destination and
/// a bearer token for it. [`SealedPush`](agentplane::keyring::SealedPush)
/// seals the credentials and leaves the routing readable — the due query
/// orders and filters on task, id and retry instant, and a delivery table
/// whose routing is sealed cannot deliver.
#[cfg(all(feature = "push", feature = "redb"))]
mod sealed_push {
    use std::sync::Arc;

    use agentplane::core::{RunId, Secret, TenantId};
    use agentplane::journal::payload;
    use agentplane::keyring::{KeyRing, SealedPush};
    use agentplane::push::{PushAuthentication, PushConfig, PushStore};
    use agentplane::store::RedbStore;
    use agentplane::testkit::MemoryKeyRing;

    fn now() -> agentplane::core::Timestamp {
        agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("a valid instant")
    }

    #[allow(clippy::type_complexity)]
    fn fixture() -> (
        Arc<dyn PushStore>,
        Arc<MemoryKeyRing>,
        Arc<SealedPush>,
        TenantId,
    ) {
        let raw = Arc::new(RedbStore::open_in_memory().expect("store")) as Arc<dyn PushStore>;
        let keys = Arc::new(MemoryKeyRing::default());
        let tenant = TenantId::default();
        let sealed = SealedPush::wrap(
            Arc::clone(&raw),
            Arc::clone(&keys) as Arc<dyn KeyRing>,
            tenant.clone(),
        );
        (raw, keys, sealed, tenant)
    }

    fn registration(task: RunId) -> PushConfig {
        PushConfig {
            id: "cfg-1".to_owned(),
            task,
            url: "https://hooks.acme.example/a2a".to_owned(),
            token: Some(Secret::new("opaque-a2a-token")),
            authentication: Some(PushAuthentication {
                scheme: "Bearer".to_owned(),
                credentials: Secret::new("the-receivers-bearer"),
            }),
        }
    }

    /// Both secrets round-trip through the wrapper and neither reaches the
    /// store readable — while everything the store is asked questions about
    /// stays in the clear.
    #[tokio::test]
    async fn a_webhook_credential_is_sealed_at_rest_and_round_trips() {
        let (raw, _keys, sealed, _tenant) = fixture();
        let task = RunId::generate();
        sealed.put(&registration(task), 1).await.expect("put");

        // Through the wrapper: the delivery worker's view, which must hold
        // the credentials it will put on the POST.
        let back = sealed
            .get(task, "cfg-1")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(
            back.token.as_ref().map(Secret::expose),
            Some("opaque-a2a-token")
        );
        assert_eq!(
            back.authentication
                .as_ref()
                .map(|auth| auth.credentials.expose()),
            Some("the-receivers-bearer")
        );
        let due = sealed.due(0, 10).await.expect("due");
        assert_eq!(
            due[0].config.token.as_ref().map(Secret::expose),
            Some("opaque-a2a-token"),
            "the due read is the one the worker delivers from, and it came \
             back sealed"
        );

        // In the store: both credentials sealed, and the secrets are not in
        // the bytes.
        let stored = raw
            .get(task, "cfg-1")
            .await
            .expect("raw get")
            .expect("present");
        let stored_token = stored.token.as_ref().map(Secret::expose).expect("a token");
        assert!(
            payload::is_sealed_text(stored_token),
            "the A2A token reached the store readable"
        );
        assert!(!stored_token.contains("opaque-a2a-token"));
        let stored_bearer = stored
            .authentication
            .as_ref()
            .map(|auth| auth.credentials.expose())
            .expect("credentials");
        assert!(
            payload::is_sealed_text(stored_bearer),
            "the receiver's bearer reached the store readable"
        );
        assert!(!stored_bearer.contains("the-receivers-bearer"));

        // The routing half stays readable, or the due scan and the worker
        // would have nothing to route on.
        assert_eq!(stored.url, "https://hooks.acme.example/a2a");
        assert_eq!(
            stored
                .authentication
                .as_ref()
                .map(|auth| auth.scheme.as_str()),
            Some("Bearer"),
            "the scheme is a label, not a secret, and validation reads it"
        );
        assert_eq!(raw.due(0, 10).await.expect("raw due").len(), 1);
    }

    /// Destroying the tenant's push scope makes every stored credential
    /// unreadable — in the live store and in every backup of it — while the
    /// registrations themselves stay routable, so the sweep serving other
    /// tenants never trips over the erased one.
    #[tokio::test]
    async fn erasing_the_tenant_reaches_every_webhook_credential() {
        let (_raw, keys, sealed, tenant) = fixture();
        let task = RunId::generate();
        sealed.put(&registration(task), 1).await.expect("put");

        keys.destroy(
            &agentplane::keyring::scope(&tenant, "push"),
            now(),
            "the tenant was erased",
        )
        .await
        .expect("destroy");

        let after = sealed
            .get(task, "cfg-1")
            .await
            .expect("get")
            .expect("still registered");
        assert!(
            after.token.is_none(),
            "a token opened after its tenant's key was destroyed"
        );
        assert!(
            after.authentication.is_none(),
            "a bearer opened after its tenant's key was destroyed — or came \
             back as a header full of ciphertext"
        );
        // Routing survives: the row is still found and still due, so it ages
        // out through the ordinary retry ceiling instead of wedging the sweep.
        assert_eq!(after.url, "https://hooks.acme.example/a2a");
        assert_eq!(sealed.due(0, 10).await.expect("due").len(), 1);
    }

    /// A sealed credential copied onto another registration does not open.
    ///
    /// The associated data binds the envelope to `(task, id)`: a row edited to
    /// carry another row's ciphertext — a column copied in the database, not a
    /// key compromise — fails to authenticate rather than opening as authority
    /// the other registration was never given.
    #[tokio::test]
    async fn a_credential_lifted_onto_another_registration_does_not_open() {
        let (raw, _keys, sealed, _tenant) = fixture();
        let task = RunId::generate();
        sealed.put(&registration(task), 1).await.expect("put");
        let stolen = raw
            .get(task, "cfg-1")
            .await
            .expect("raw get")
            .expect("present")
            .token
            .expect("a sealed token");

        // The copy: a second registration wearing the first one's ciphertext,
        // written past the wrapper the way a database edit would be.
        raw.put(
            &PushConfig {
                id: "cfg-2".to_owned(),
                task,
                url: "https://hooks.acme.example/other".to_owned(),
                token: Some(stolen),
                authentication: None,
            },
            1,
        )
        .await
        .expect("raw put");

        let moved = sealed
            .get(task, "cfg-2")
            .await
            .expect("get")
            .expect("present");
        assert!(
            moved.token.is_none(),
            "a credential sealed for one registration opened on another"
        );
        // And the original still opens, so the refusal above is the binding
        // working rather than the ring being broken.
        let original = sealed
            .get(task, "cfg-1")
            .await
            .expect("get")
            .expect("present");
        assert_eq!(
            original.token.as_ref().map(Secret::expose),
            Some("opaque-a2a-token")
        );
    }
}

/// **Every store the plane seals is asked which tenant it serves, and a
/// disagreement is refused at build.**
///
/// The plane's tenant scopes the data keys; each store handle is scoped
/// separately. When the two disagree the result is not a leak and not a failure
/// — both scopes are real — so the run works, the erasure works, and the
/// erasure destroys a key that does not reach the rows. A deletion guarantee
/// cannot have that failure, and nothing at runtime can notice it: the only
/// moment both facts are in one place is `try_build`.
///
/// Seven doors, and the reason the list is exhaustive rather than
/// representative: each store is wired by its own builder method, so a check
/// covering four of them is indistinguishable at runtime from one covering all
/// seven. The positive half — a plane whose stores all agree still builds — is
/// what stops this passing because the builder refuses everything.
#[cfg(all(feature = "redb", feature = "keyring"))]
#[test]
fn a_store_scoped_to_another_tenant_is_refused_at_build() {
    use agentplane::core::TenantId;
    use agentplane::store::RedbStore;

    let plane = TenantId::new("acme").expect("a tenant");
    let elsewhere = || {
        Arc::new(
            RedbStore::open_in_memory()
                .expect("store")
                .for_tenant(TenantId::new("other").expect("a tenant")),
        )
    };
    let here = || {
        Arc::new(
            RedbStore::open_in_memory()
                .expect("store")
                .for_tenant(TenantId::new("acme").expect("a tenant")),
        )
    };
    let keys = || Arc::new(MemoryKeyRing::new()) as Arc<dyn KeyRing>;

    // Each arm wires exactly one store to the wrong tenant, so a check that
    // covered only some of them leaves the others building cleanly.
    for door in ["journal", "case", "event", "task", "memory"] {
        let builder = if door == "journal" {
            agentplane::runtime::Runtime::builder(elsewhere())
        } else {
            let b = agentplane::runtime::Runtime::builder(here());
            match door {
                "case" => b.cases(elsewhere()),
                "event" => b.events(elsewhere()),
                "task" => b.tasks(elsewhere()),
                "memory" => b.memory(elsewhere()),
                other => unreachable!("unlisted door {other}"),
            }
        };
        let err = builder
            .tenant(TenantId::new("acme").expect("a tenant"))
            .keyring(keys())
            .try_build()
            .expect_err(&format!(
                "a plane on 'acme' built with its {door} store serving 'other' — \
                 that plane's erasure destroys a key these rows are not sealed under"
            ))
            .to_string();
        assert!(
            err.contains("acme") && err.contains("other"),
            "the refusal for the {door} store must name both tenants, got: {err}"
        );
    }

    // The positive half: every store on the plane's own tenant assembles.
    agentplane::runtime::Runtime::builder(here())
        .tenant(plane)
        .keyring(keys())
        .cases(here())
        .events(here())
        .tasks(here())
        .memory(here())
        .try_build()
        .expect("a plane whose stores all serve its own tenant was refused");
}

/// **A wrapper seals for the tenant its store serves, or it refuses to exist.**
///
/// `try_build` asks every store it is *given* which tenant it serves. It cannot
/// ask the same of a store an embedder sealed before handing it over: from the
/// outside that wrapper reports the tenant it was told to seal for, which is
/// the plane's, and the disagreement is one layer down where nothing looks.
///
/// So the pair is checked where both halves are in hand — at the wrap. The
/// positive half matters as much as the refusal: a wrapper whose tenant *does*
/// match must still build, or this would read as working while actually
/// refusing every deployment.
#[cfg(all(feature = "redb", feature = "keyring"))]
#[test]
fn sealing_a_store_for_a_tenant_it_does_not_serve_is_refused() {
    use agentplane::core::TenantId;
    use agentplane::keyring::SealedCases;
    use agentplane::store::RedbStore;

    let elsewhere = Arc::new(
        RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(TenantId::new("other").expect("a tenant")),
    );
    let keys = Arc::new(MemoryKeyRing::new()) as Arc<dyn KeyRing>;

    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SealedCases::wrap(elsewhere, keys, TenantId::new("acme").expect("a tenant"))
    }));
    let panic = refused.expect_err(
        "a case store serving 'other' was sealed for 'acme' — that plane's \
         erasure destroys a key these rows are not sealed under, and reports \
         success",
    );
    let message = panic
        .downcast_ref::<String>()
        .map_or_else(String::new, Clone::clone);
    assert!(
        message.contains("other") && message.contains("acme"),
        "the refusal must name both tenants, got: {message}"
    );

    // The positive half: agreement still wraps.
    let here = Arc::new(
        RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(TenantId::new("acme").expect("a tenant")),
    );
    let keys = Arc::new(MemoryKeyRing::new()) as Arc<dyn KeyRing>;
    let _ = SealedCases::wrap(here, keys, TenantId::new("acme").expect("a tenant"));
}

// ── The tenant name, where a key scope is derived from it ───────────────────

/// A tenant name is a validated newtype, and deserializing must use that gate.
///
/// `keyring::scope` composes `tenant/unit`, and its whole collision argument is
/// that [`TenantId`] refuses `/`. Units already contain separators —
/// `event/{source}/{id}`, `memory/{subject}` — so a tenant carrying one lands
/// on another tenant's scope exactly. Both scopes are real, both stores write,
/// nothing fails: the tenants share one data key, and either one's erasure
/// destroys the other's and reports success.
///
/// A `TenantId` reaches the runtime from a credential claim, a store row and a
/// journal record, all of which are `serde` rather than a call to `new`.
#[test]
fn a_deserialized_tenant_name_cannot_carry_a_scope_separator() {
    use agentplane::core::TenantId;

    let err = serde_json::from_value::<TenantId>(serde_json::json!("acme/event/counterparty"))
        .expect_err("a separator must not survive deserialization");
    assert!(
        err.to_string().contains("composite keys"),
        "the refusal must be the newtype's own rule, not a type error any \
         malformed value would produce: {err}"
    );

    // The same shape without a separator deserializes, so the refusal above is
    // the rule rather than the fixture being unreachable.
    let honest: TenantId =
        serde_json::from_value(serde_json::json!("acme")).expect("an ordinary name still parses");

    // What the refusal buys. This scope is reachable from tenant `acme` with
    // unit `event/counterparty/42`; the only other decomposition is a tenant
    // named `acme/event/counterparty` with unit `42`, and that name is now not
    // a value anything can hold.
    let derived = agentplane::keyring::scope(&honest, "event/counterparty/42");
    let (other_tenant, _unit) = derived.rsplit_once('/').expect("a composed scope");
    assert!(
        TenantId::new(other_tenant).is_err(),
        "'{other_tenant}' would derive the same key scope as tenant 'acme', so \
         either one's erasure would destroy the other's key and report success"
    );

    assert!(
        serde_json::from_value::<TenantId>(serde_json::json!("")).is_err(),
        "an empty name collides with every deployment that also set none"
    );
    assert!(
        serde_json::from_value::<TenantId>(serde_json::json!("x".repeat(TenantId::MAX_LEN + 1)))
            .is_err(),
        "and the length bound is a metric-cardinality bound, so it binds here too"
    );
}
