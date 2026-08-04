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

/// Rotation does not rewrite data, and does not lock anyone out.
///
/// Bulk data is never re-encrypted — that is what makes rotating cheap enough to
/// do on a schedule rather than in a plan nobody executes. Payloads sealed
/// before the rotation must stay readable, or a rotation is an outage; payloads
/// sealed after it must be stamped with the new key, or nothing rotated.
#[tokio::test]
async fn rotation_rewraps_without_touching_the_payload() {
    let (disk, ring, store) = sealed("case-5");
    let digest = store.put(SECRET).await.expect("seal");
    let ciphertext_before = disk.get_raw(digest).await.expect("raw");
    let id_before = ring.current_key_id();
    // Minted *before* the rotation, so rewrapping it has somewhere to move to.
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
        "rotation rewrote the bulk data — the point of envelope encryption is \
         that it does not have to"
    );
    assert_eq!(
        store.get(digest).await.expect("open after rotation"),
        SECRET,
        "a payload sealed before the rotation became unreadable, which is an \
         outage rather than a key rotation"
    );

    // A key wrapped under the old generation is re-wrappable under the new one
    // without the plaintext ever leaving the ring.
    let fresh = ring.rewrap(&old).await.expect("rewrap");
    assert_ne!(
        old.wrapped_by, fresh.wrapped_by,
        "rewrapping did not move the key to the current generation"
    );
    assert_eq!(fresh.scope, old.scope, "rewrapping moved the erasure unit");
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
        async fn rewrap(
            &self,
            _w: &agentplane::keyring::WrappedKey,
        ) -> Result<agentplane::keyring::WrappedKey, KeyError> {
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
#[cfg(all(feature = "redb", feature = "keyring"))]
#[tokio::test]
async fn erasing_a_case_destroys_its_key_and_the_backup_with_it() {
    use agentplane::core::{CorrelationKey, Outcome, Skill, SkillDescriptor, SkillError, Tainted};
    use agentplane::runtime::{Runtime, StepCtx};
    use serde_json::{Value, json};

    #[derive(Debug)]
    struct Keeps;

    #[async_trait::async_trait]
    impl Skill for Keeps {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("keeps").provides("records.keep")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let digest = cx.store_blob(SECRET).await?;
            Ok(Outcome::done(Tainted::trusted(json!(digest.to_hex()))))
        }
    }

    let store = Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let disk = Arc::new(MemoryBlobs::new());
    let ring = Arc::new(MemoryKeyRing::new());

    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn agentplane::journal::JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn agentplane::case::CaseStore>)
        .blobs(Arc::clone(&disk) as Arc<dyn BlobStore>)
        .keyring(Arc::clone(&ring) as Arc<dyn KeyRing>)
        .skill(Keeps)
        .build();

    let out = rt
        .run_in_case(
            "records.keep",
            json!({}),
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
    let digest = agentplane::core::Digest::of(SECRET);

    // What reached the disk is sealed, and the case can read it back.
    let backup = disk.get_raw(digest).await.expect("raw bytes");
    assert_ne!(backup, SECRET, "the run wrote its payload in the clear");

    let case_id = agentplane::case::CaseStore::correlate(
        store.as_ref(),
        &[CorrelationKey::new("claim", "CLM-1")],
    )
    .await
    .expect("correlate")
    .expect("the run opened a case");
    let tenant = agentplane::core::TenantId::default();
    let sealed_view = EncryptedBlobs::new(
        Arc::clone(&disk) as Arc<dyn BlobStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        agentplane::keyring::scope(&tenant, &case_id.to_string()),
    );
    assert_eq!(
        sealed_view.get(digest).await.expect("read back"),
        SECRET,
        "the case could not read its own bytes, so sealing broke the run"
    );

    // Erase the case. Tombstones *and* the key.
    let n = agentplane::blob::erase_case(
        disk.as_ref(),
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

    // The backup, restored somewhere else entirely.
    let elsewhere = Arc::new(MemoryBlobs::new());
    elsewhere.put_at(digest, &backup).await.expect("restore");
    let restored = EncryptedBlobs::new(
        Arc::clone(&elsewhere) as Arc<dyn BlobStore>,
        Arc::clone(&ring) as Arc<dyn KeyRing>,
        agentplane::keyring::scope(&tenant, &case_id.to_string()),
    );
    assert!(
        matches!(restored.get(digest).await, Err(BlobError::Expired { .. })),
        "a backup restored after the case was erased gave the data back"
    );
}

/// **Erasing one tenant does not reach another's bytes.**
///
/// The adversarial swap §9 asks for, at the only layer that currently has a
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
