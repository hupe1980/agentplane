//! A ceiling that outlives the run: what one customer approved, spent across
//! however many runs it takes, until they take it back.
//!
//! A `Budget` bounds one run and a `TenantQuota` bounds a billing period.
//! Neither can hold *this customer approved €500* — so a delegated spend
//! envelope had nowhere to live, and the three properties below are the reason
//! it is an authorization rather than a throttle.
//!
//! Run with:
//! `cargo run --example standing_authority --features redb,testkit`

use std::sync::Arc;

use agentplane::authority::{AuthorityError, AuthorityId, AuthorityStore, StandingAuthority};
use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Spend, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Spends against a mandate the customer issued, not against this run's budget.
#[derive(Debug)]
struct Purchase;

#[async_trait::async_trait]
impl Skill for Purchase {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("purchase").provides("procurement.purchase")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let cents = input.peek()["cents"].as_u64().unwrap_or(0);

        // A journaled effect, because the balance is mutable state outside the
        // chain: a skill reading it directly would make a replay depend on what
        // the store happens to hold now rather than on what this run saw.
        match cx
            .draw(&AuthorityId::new("mandate-42"), Spend::money(cents))
            .await
        {
            Ok(drawn) => Ok(Outcome::done(Tainted::trusted(json!({
                "charged": cents,
                "remaining": drawn.remaining.minor_units,
                "draw": drawn.draws,
            })))),
            // Five distinguishable refusals rather than one message. Which one
            // arrived decides what the caller does next, which is the whole
            // reason they are not a string.
            Err(refused) => Ok(Outcome::done(Tainted::trusted(json!({
                "refused": refused.to_string(),
            })))),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);

    // Issued once and thereafter immutable: a ceiling somebody agreed to must
    // not be editable under them. Changing it means revoking this one and
    // issuing another, so both stay on the record.
    store
        .issue(&StandingAuthority::new(
            "mandate-42",
            "approval:SET-42",
            Spend::money(50_000),
        ))
        .await?;

    let journal: Arc<dyn JournalStore> = store.clone();
    let authorities: Arc<dyn AuthorityStore> = store.clone();
    let runtime = Runtime::builder(journal)
        .authorities(authorities)
        .skill(Purchase)
        .build();

    // 1. The ceiling is cumulative across *runs*. Two separate runs, one
    //    envelope — which is the thing a per-run budget cannot express.
    let first = runtime
        .run(
            "procurement.purchase",
            Tainted::trusted(json!({"cents": 30_000})),
        )
        .await?;
    assert_eq!(
        first.output.as_ref().unwrap().peek()["remaining"],
        json!(20_000)
    );
    println!("1. issued          → mandate-42: 50000 minor units against 'approval:SET-42'");
    println!("   first run drew  → 30000, remaining 20000");

    let second = runtime
        .run(
            "procurement.purchase",
            Tainted::trusted(json!({"cents": 15_000})),
        )
        .await?;
    assert_eq!(
        second.output.as_ref().unwrap().peek()["remaining"],
        json!(5_000)
    );
    println!("   second run drew → 15000, remaining 5000 — one envelope across separate runs,");
    println!("                     which is the thing a per-run budget cannot hold");

    // 2. Over the ceiling is `Exhausted`, and a refused draw consumes nothing —
    //    otherwise a caller probing the remainder would drain it.
    let over = runtime
        .run(
            "procurement.purchase",
            Tainted::trusted(json!({"cents": 10_000})),
        )
        .await?;
    let message = over.output.as_ref().unwrap().peek()["refused"]
        .as_str()
        .unwrap();
    assert!(message.contains("does not replenish"), "got: {message}");
    println!("\n2. 10000 refused   → {message}");
    assert_eq!(
        store
            .state(&AuthorityId::new("mandate-42"))
            .await?
            .expect("issued")
            .remaining(),
        Spend::money(5_000),
        "a refusal must not consume"
    );
    println!(
        "   remaining       → still 5000: a refused draw consumes nothing, so probing cannot drain"
    );

    revocation(&runtime, &store).await?;
    Ok(())
}

/// 3–4. Revocation is a different answer from exhaustion, and the terms survive.
///
/// The difference is operational: `Exhausted` may reasonably be followed by
/// asking for less, and against a revoked authority that is a loop.
async fn revocation(
    runtime: &Runtime,
    store: &Arc<RedbStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    store
        .revoke(
            &AuthorityId::new("mandate-42"),
            "the customer cancelled",
            agentplane::core::Timestamp::UNIX_EPOCH,
        )
        .await?;

    let after = runtime
        .run(
            "procurement.purchase",
            Tainted::trusted(json!({"cents": 1_000})),
        )
        .await?;
    let message = after.output.as_ref().unwrap().peek()["refused"]
        .as_str()
        .unwrap();
    assert!(message.contains("was revoked"), "got: {message}");
    println!("\n3. after revocation → {message}");
    println!("   a different answer from exhaustion: asking for less is pointless now");

    // The terms survive revocation. An authority that vanished would take with
    // it the record of what the draws already taken were authorized *by*, which
    // is the first thing an audit asks for.
    let state = store
        .state(&AuthorityId::new("mandate-42"))
        .await?
        .expect("revoked, not deleted");
    assert_eq!(state.authority.basis, "approval:SET-42");
    assert_eq!(state.draws, 2);

    // Refunds are deliberately not expressible: `Spend` is unsigned, so no draw
    // can un-spend a ceiling. Restoring headroom means issuing another
    // authority, which leaves both decisions on the record.
    let err = store
        .issue(&StandingAuthority::new(
            "mandate-42",
            "approval:SET-42",
            Spend::money(90_000),
        ))
        .await
        .expect_err("an id cannot be redefined under the draws already taken");
    assert!(matches!(err, AuthorityError::AlreadyIssued(_)));

    println!(
        "\n4. the terms survive → {} drawn over {} draws against '{}'; revoked: \"{}\"",
        state.drawn.minor_units,
        state.draws,
        state.authority.basis,
        state.revoked.expect("revoked").reason,
    );
    println!("   and the id cannot be reissued under the draws already taken");
    Ok(())
}
