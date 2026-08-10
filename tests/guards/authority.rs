#![cfg(feature = "redb")]

//! Standing authority: the ceiling that outlives a run.
//!
//! A budget bounds one run and a quota bounds a tenant's billing period. Neither
//! can say *this customer approved €500, across however many runs it takes,
//! until they take it back*. That is an authorization rather than a throttle,
//! and the difference shows up in the failure modes these tests cover.
//!
//! Three properties carry the file, and each fails silently if it is wrong:
//!
//! * **A retry must not spend twice.** The draw is keyed on the dispatch
//!   identifier, which is stable across attempts — unlike the effect key, which
//!   deliberately is not. Getting this backwards double-spends a customer's
//!   authorization, and only under retry.
//! * **A replay must not spend at all.** The balance is mutable state outside
//!   the journal, so a replay that consumed again would make the run's own
//!   history disagree with the store.
//! * **Revoked and exhausted are different answers.** One may be followed by a
//!   larger authority; the other is a decision that has been taken back.
//!   Collapsing them teaches a caller to retry something that will never change.

use std::sync::Arc;

use agentplane::authority::{AuthorityError, AuthorityId, AuthorityStore, StandingAuthority};
use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Spend, Tainted, Timestamp};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

fn mandate() -> StandingAuthority {
    StandingAuthority::new("mandate-42", "approval:SET-42", Spend::money(50_000))
}

/// A distinct dispatch key per logical draw.
///
/// Built from hex rather than derived, because what matters here is only that
/// two draws carry different keys and a retry carries the same one — the
/// derivation is the runtime's business and is exercised through it below.
fn key(n: u8) -> agentplane::core::EffectKey {
    agentplane::core::EffectKey::from_hex(&format!("{n:064x}")).expect("32 bytes of hex")
}

fn at() -> Timestamp {
    Timestamp::UNIX_EPOCH
}

// ── The store contract ──────────────────────────────────────────────────────

#[tokio::test]
async fn draws_accumulate_across_calls_until_the_ceiling_refuses() {
    let store = RedbStore::open_in_memory().expect("store");
    store.issue(&mandate()).await.expect("issue");
    let id = AuthorityId::new("mandate-42");

    let first = store
        .draw(&id, key(1), Spend::money(30_000), at())
        .await
        .expect("within the ceiling");
    assert_eq!(first.remaining, Spend::money(20_000));
    assert_eq!(first.draws, 1);

    // The point of the whole type: the second draw is bounded by what the first
    // one took, across what would be a different run entirely.
    let error = store
        .draw(&id, key(2), Spend::money(25_000), at())
        .await
        .expect_err("the ceiling is cumulative, not per draw");
    assert!(
        matches!(error, AuthorityError::Exhausted { ref remaining, .. } if *remaining == Spend::money(20_000)),
        "got: {error}"
    );

    // And a refused draw consumed nothing — otherwise a caller probing the
    // ceiling would drain it.
    let after = store
        .draw(&id, key(3), Spend::money(20_000), at())
        .await
        .expect("exactly the remainder is still available");
    assert_eq!(after.remaining, Spend::default());
}

/// A retry of one draw takes the authority once.
///
/// The store deduplicates on the key the caller passes, and `StepCtx::draw`
/// passes the **dispatch** identifier — stable across attempts. If it passed the
/// effect key instead, which hashes the attempt number, this test would show two
/// draws for one purchase.
#[tokio::test]
async fn a_repeated_draw_under_one_key_consumes_once() {
    let store = RedbStore::open_in_memory().expect("store");
    store.issue(&mandate()).await.expect("issue");
    let id = AuthorityId::new("mandate-42");

    let first = store
        .draw(&id, key(1), Spend::money(30_000), at())
        .await
        .expect("draw");
    let repeat = store
        .draw(&id, key(1), Spend::money(30_000), at())
        .await
        .expect("a retry is not a second draw");

    assert_eq!(first, repeat, "the retry returned a different receipt");
    let state = store.state(&id).await.expect("state").expect("issued");
    assert_eq!(state.drawn, Spend::money(30_000), "the retry spent twice");
    assert_eq!(state.draws, 1);
}

/// A draw that already landed is reported as landed, even after revocation.
///
/// The alternative is worse than it looks: reporting the retry as refused would
/// make a caller compensate a draw that stands, and the money has already moved.
#[tokio::test]
async fn a_landed_draw_survives_a_later_revocation_on_retry() {
    let store = RedbStore::open_in_memory().expect("store");
    store.issue(&mandate()).await.expect("issue");
    let id = AuthorityId::new("mandate-42");

    let original = store
        .draw(&id, key(1), Spend::money(10_000), at())
        .await
        .expect("draw");
    store
        .revoke(&id, "customer withdrew consent", at())
        .await
        .expect("revoke");

    let repeat = store
        .draw(&id, key(1), Spend::money(10_000), at())
        .await
        .expect("the draw already happened; a retry must report it");
    assert_eq!(original, repeat);

    // A *new* draw is refused, which is the half revocation is for.
    let error = store
        .draw(&id, key(2), Spend::money(10_000), at())
        .await
        .expect_err("revoked");
    assert!(
        matches!(error, AuthorityError::Revoked { .. }),
        "got: {error}"
    );
}

/// Revoked, exhausted, expired and out-of-draws are four answers, not one.
#[tokio::test]
async fn each_refusal_is_distinguishable_from_the_others() {
    let store = RedbStore::open_in_memory().expect("store");

    // Unknown.
    let unknown = store
        .draw(&AuthorityId::new("nope"), key(1), Spend::money(1), at())
        .await
        .expect_err("never issued");
    assert!(
        matches!(unknown, AuthorityError::Unknown(_)),
        "got: {unknown}"
    );

    // Out of draws, while ceiling remains — the two bound different abuses.
    let capped = StandingAuthority::new("capped", "approval:1", Spend::money(50_000)).max_draws(1);
    store.issue(&capped).await.expect("issue");
    let id = AuthorityId::new("capped");
    store
        .draw(&id, key(1), Spend::money(1), at())
        .await
        .expect("first");
    let spent = store
        .draw(&id, key(2), Spend::money(1), at())
        .await
        .expect_err("one draw was all it permitted");
    assert!(
        matches!(spent, AuthorityError::DrawsSpent { allowed: 1, .. }),
        "a draw ceiling must refuse even with money left over; got: {spent}"
    );

    // Expired, evaluated against the instant handed in rather than a store clock.
    let expiring = StandingAuthority::new("expiring", "approval:2", Spend::money(500))
        .expires_at(Timestamp::from_unix_timestamp(1_000).expect("timestamp"));
    store.issue(&expiring).await.expect("issue");
    let expired = store
        .draw(
            &AuthorityId::new("expiring"),
            key(1),
            Spend::money(1),
            Timestamp::from_unix_timestamp(2_000).expect("timestamp"),
        )
        .await
        .expect_err("past its expiry");
    assert!(
        matches!(expired, AuthorityError::Expired { .. }),
        "got: {expired}"
    );

    // ...and still drawable before it.
    store
        .draw(
            &AuthorityId::new("expiring"),
            key(2),
            Spend::money(1),
            Timestamp::from_unix_timestamp(999).expect("timestamp"),
        )
        .await
        .expect("before expiry, the same authority still stands");
}

/// Re-issuing identical terms is a retried deploy; differing terms is a rewrite.
#[tokio::test]
async fn terms_are_immutable_but_an_identical_reissue_is_not_an_error() {
    let store = RedbStore::open_in_memory().expect("store");
    store.issue(&mandate()).await.expect("issue");
    store
        .issue(&mandate())
        .await
        .expect("an identical re-issue is a retried deploy, not an attack");

    let raised = StandingAuthority::new("mandate-42", "approval:SET-42", Spend::money(500_000));
    let error = store
        .issue(&raised)
        .await
        .expect_err("a ceiling somebody agreed to must not be editable under them");
    assert!(
        matches!(error, AuthorityError::AlreadyIssued(_)),
        "got: {error}"
    );

    let state = store
        .state(&AuthorityId::new("mandate-42"))
        .await
        .expect("state")
        .expect("issued");
    assert_eq!(
        state.authority.ceiling,
        Spend::money(50_000),
        "the original terms were overwritten"
    );
}

/// One tenant's authority is not another's.
#[tokio::test]
async fn authorities_do_not_cross_tenants() {
    let store = RedbStore::open_in_memory().expect("store");
    store.issue(&mandate()).await.expect("issue");

    let other = store
        .clone()
        .for_tenant(agentplane::core::TenantId::new("other").expect("tenant"));
    let error = other
        .draw(
            &AuthorityId::new("mandate-42"),
            key(1),
            Spend::money(1),
            at(),
        )
        .await
        .expect_err("a valid id from another tenant is the realistic leak");
    assert!(matches!(error, AuthorityError::Unknown(_)), "got: {error}");
}

// ── Through the runtime ─────────────────────────────────────────────────────

/// Draws once per run, so a replay's effect on the balance is observable.
#[derive(Debug)]
struct Buys(Spend);

#[async_trait::async_trait]
impl Skill for Buys {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("buy").provides("commerce.buy")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let drawn = cx.draw(&AuthorityId::new("mandate-42"), self.0).await?;
        Ok(Outcome::done(Tainted::trusted(json!({
            "remaining": drawn.remaining.minor_units,
            "draws": drawn.draws,
        }))))
    }
}

/// Strict replay reproduces the receipt and consumes nothing.
///
/// This is the property that forced the draw to be an effect at all. A skill
/// reading the balance directly would see whatever the store holds *now*, so a
/// run replayed after a later draw would reach a different verdict than the one
/// its own journal records.
#[tokio::test]
async fn strict_replay_reads_the_receipt_and_does_not_draw_again() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    store.issue(&mandate()).await.expect("issue");

    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .authorities(Arc::clone(&store) as Arc<dyn AuthorityStore>)
        .skill(Buys(Spend::money(12_000)))
        .build();

    let live = runtime
        .run("commerce.buy", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert_eq!(live.status, RunStatus::Succeeded);

    let after_live = store
        .state(&AuthorityId::new("mandate-42"))
        .await
        .expect("state")
        .expect("issued");
    assert_eq!(after_live.drawn, Spend::money(12_000));

    let replayed = runtime
        .replay(live.run_id, Mode::Strict)
        .await
        .expect("replay");
    assert_eq!(
        replayed.output, live.output,
        "the receipt was not reproduced"
    );

    let after_replay = store
        .state(&AuthorityId::new("mandate-42"))
        .await
        .expect("state")
        .expect("issued");
    assert_eq!(
        after_replay.drawn, after_live.drawn,
        "replay consumed the authority a second time"
    );
    assert_eq!(after_replay.draws, 1);
}

/// A refusal stops the run rather than being reported as success.
#[tokio::test]
async fn a_run_that_cannot_draw_does_not_succeed() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    store
        .issue(&StandingAuthority::new(
            "mandate-42",
            "approval:SET-42",
            Spend::money(100),
        ))
        .await
        .expect("issue");

    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .authorities(Arc::clone(&store) as Arc<dyn AuthorityStore>)
        .skill(Buys(Spend::money(90_000)))
        .build();

    let outcome = runtime
        .run("commerce.buy", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(outcome.status, RunStatus::Failed(_)),
        "a draw over the ceiling must not read as success; got {:?}",
        outcome.status
    );

    let state = store
        .state(&AuthorityId::new("mandate-42"))
        .await
        .expect("state")
        .expect("issued");
    assert_eq!(
        state.drawn,
        Spend::default(),
        "a refused draw consumed part of the authority"
    );
}

/// A run without an authority store is refused, not silently unbounded.
#[tokio::test]
async fn drawing_without_a_store_refuses_rather_than_proceeding() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Buys(Spend::money(1)))
        .build();

    let outcome = runtime
        .run("commerce.buy", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(
        matches!(outcome.status, RunStatus::Failed(_)),
        "an unwired ceiling must refuse, not wave the draw through; got {:?}",
        outcome.status
    );
}

/// The shared contract, on redb.
///
/// Gated on `testkit` as well as `redb`: the battery lives there, because it is
/// as much for an embedder bringing their own store as for this one.
///
/// The same battery runs against `PostgreSQL` in `postgres.rs`. Two backends and
/// one contract is the project's rule, and it earns its keep here: the
/// idempotence and cumulative-ceiling guarantees hold on a single-writer
/// embedded store almost by accident, and have to be built on a shared one.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn redb_satisfies_the_authority_store_contract() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    agentplane::testkit::conformance::authority(store as Arc<dyn AuthorityStore>).await;
}

/// **A revoked draw is an answer: one attempt, a failed run — never a
/// quarantine claiming it may have been applied.**
///
/// The refusal's own documentation says "not retryable, ever", and the module
/// docs open with the reason the type exists: conflating revoked with
/// exhausted teaches a caller to retry a decision that has been taken back.
/// The effect's error mapping then flattened every refusal to `Other`, which
/// reads as **in-doubt** — so a revoked draw was retried under the full
/// policy, and reported upward as a call that may have landed. The journal is
/// the witness here: one `EffectStarted` for the draw means one attempt, and
/// the run must conclude `Failed` (an answer), not `Quarantined` (a doubt).
#[tokio::test]
async fn a_revoked_draw_is_answered_once_and_never_retried() {
    use agentplane::journal::RecordKind;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    store
        .issue(&StandingAuthority::new(
            "mandate-42",
            "approval:SET-42",
            Spend::money(50_000),
        ))
        .await
        .expect("issue");
    store
        .revoke(
            &AuthorityId::new("mandate-42"),
            "customer withdrew consent",
            Timestamp::from_unix_timestamp(1_760_000_000).expect("time"),
        )
        .await
        .expect("revoke");

    let runtime = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .authorities(Arc::clone(&store) as Arc<dyn AuthorityStore>)
        .skill(Buys(Spend::money(10)))
        .build();

    let outcome = runtime
        .run("commerce.buy", Tainted::trusted(json!({})))
        .await
        .expect("run");
    match &outcome.status {
        RunStatus::Failed(why) => assert!(
            why.contains("revoked"),
            "the failure must carry which refusal it was: {why}"
        ),
        RunStatus::Quarantined(why) => panic!(
            "a refusal the store answered with certainty was reported as a doubt \
             an operator must resolve: {why}"
        ),
        other => panic!("expected a failed run, got {other:?}"),
    }

    let attempts = (Arc::clone(&store) as Arc<dyn JournalStore>)
        .read(outcome.run_id, 1)
        .await
        .expect("journal")
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                RecordKind::EffectStarted { descriptor, .. } if descriptor.kind == "authority.draw"
            )
        })
        .count();
    assert_eq!(
        attempts, 1,
        "a refusal that will never change was retried — every further attempt \
         asks the same rule the same question"
    );
}
