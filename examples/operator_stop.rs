//! Two brakes: stop one run and have it unwind, or halt a tenant's front door.
//!
//! ```sh
//! cargo run --example operator_stop
//! ```
//!
//! Oversight is not only approving things. The half most runtimes omit is the
//! ability to **intervene** — and a stop is only a control if what it means is
//! pinned down. Here it means two different things, deliberately:
//!
//! 1. **Cancelling a run undoes what it did.** A run suspended on a human task
//!    has already placed a hold. Cancelling it reverses the hold — stopping a
//!    run that moved money and leaving the movement in place is not stopping
//!    it — and the journal records **who** asked and **why**. A second asker
//!    does not take the first one's place, and the conclusion is `Cancelled`,
//!    not `Failed`: an operator scanning for faults should not have to
//!    mentally subtract their own interventions.
//!
//! 2. **A halt stops new admissions, and only new admissions.** The emergency
//!    stop lives in the store, so every instance sharing it refuses at once —
//!    and the refusal carries the operator's reason, because the next person
//!    to look will be somebody else at three in the morning. What it
//!    deliberately does *not* stop: work already executing, and suspended
//!    runs resuming. Those are existing work, and stranding them mid-saga
//!    would turn an incident into a second one — to stop work in flight,
//!    cancel it, which is what the first half is for.

use std::sync::{Arc, Mutex};

use agentplane::core::{
    Compensation, DeadlineSpec, Effect, EffectDescriptor, EffectError, Justification, Outcome,
    Recovery, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::quota::TenantQuota;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// What the outside world has seen, in order.
type World = Arc<Mutex<Vec<String>>>;

/// One posting against a system of record.
#[derive(Debug)]
struct Post {
    world: World,
    what: &'static str,
}

#[async_trait::async_trait]
impl Effect for Post {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.post", json!({ "what": self.what }))
    }

    fn recovery(&self) -> Recovery {
        Recovery::Idempotent {
            key: format!("ledger:{}", self.what),
        }
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        self.world.lock().expect("world").push(self.what.to_owned());
        Ok(json!({ "posted": self.what }))
    }
}

/// Places a hold, then waits for a person. Compensatable — which is what makes
/// cancelling it meaningful rather than merely possible.
#[derive(Debug)]
struct HoldThenAsk {
    world: World,
}

#[async_trait::async_trait]
impl Skill for HoldThenAsk {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("dispute.hold")
    }

    fn compensation(&self) -> Compensation {
        Compensation::Compensatable
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Post {
            world: Arc::clone(&self.world),
            what: "hold placed",
        })
        .await?;

        cx.deadline("review", &DeadlineSpec::days(2), None).await?;
        let decision = cx
            .task(
                &TaskSpec::new(
                    "release-hold",
                    Justification::new("a person decides whether the hold stands", json!({})),
                    "review",
                )
                .role("dispute-officer"),
            )
            .await?;
        Ok(Outcome::done(Tainted::trusted(
            json!({ "approved": decision.approved }),
        )))
    }

    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _out: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.effect(Post {
            world: Arc::clone(&self.world),
            what: "hold released",
        })
        .await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    stop_one_run().await?;
    halt_the_front_door().await?;
    Ok(())
}

/// Brake one: an operator stops a specific run, and it unwinds.
async fn stop_one_run() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let world: World = Arc::default();
    let rt = Runtime::builder_on(Arc::clone(&store))
        .skill(HoldThenAsk {
            world: Arc::clone(&world),
        })
        .build();

    let run = rt
        .run_correlated(
            "dispute.hold",
            Tainted::trusted(json!({ "dispute": "D-311" })),
            "dispute",
            &[agentplane::core::CorrelationKey::new("dispute", "D-311")],
        )
        .await?;
    println!("1. a run places a hold, then waits for a person");
    println!("   run       → {}", run.status.as_str());
    println!("   world     → {:?}", world.lock().expect("world"));
    assert!(run.status.is_suspended());

    // The counterparty withdraws the dispute. Waiting out the review deadline
    // would be days; the operator stops the run now, with a reason on record.
    let first = rt
        .request_cancel(run.run_id, "ops-carol", "counterparty withdrew the dispute")
        .await?;
    assert!(first, "the first request is the intervention of record");

    // A second asker does not take the first one's place.
    let second = rt.request_cancel(run.run_id, "ops-bob", "me too").await?;
    assert!(!second);

    println!("\n   ops-carol stopped it — and the stop *undid* the hold:");
    println!("   world     → {:?}", world.lock().expect("world"));
    assert_eq!(
        *world.lock().expect("world"),
        ["hold placed", "hold released"],
        "a cancelled run must unwind what it had already done"
    );

    let out = rt.replay(run.run_id, Mode::Resume).await?;
    println!(
        "   run       → {} — not Failed: this was intended",
        out.status.as_str()
    );
    assert!(out.status.is_cancelled());

    // Who asked, and why, are in the hash chain — not only in a flag beside it.
    let journal: Arc<dyn JournalStore> = store;
    let records = journal.read(run.run_id, 1).await?;
    let (actor, reason) = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunCancelled { actor, reason } => Some((actor.clone(), reason.clone())),
            _ => None,
        })
        .expect("the intervention is journaled");
    println!("   on record → cancelled by {actor}: \"{reason}\"");
    assert_eq!(actor, "ops-carol");
    journal.verify(run.run_id).await?;
    println!("   and the chain verifies with the intervention in it\n");
    Ok(())
}

/// Acknowledges a message. The halt demonstration needs work to refuse, not
/// work that is interesting.
#[derive(Debug)]
struct Ack;

#[async_trait::async_trait]
impl Skill for Ack {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("desk.ack")
    }

    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

/// Brake two: the emergency stop, which lives in the store.
async fn halt_the_front_door() -> Result<(), Box<dyn std::error::Error>> {
    let store = RedbStore::open_in_memory()?;
    let tenant = agentplane::core::TenantId::new("acme")?;

    // Two instances of one plane, sharing the store — as a deployment would.
    let plane = || {
        let scoped = Arc::new(store.clone().for_tenant(tenant.clone()));
        Runtime::builder(scoped.clone() as Arc<dyn JournalStore>)
            .tenant(tenant.clone())
            // Deliberately no ceilings: a halt is not a ceiling, and the
            // tenant an operator most needs to stop is the unlimited one.
            .quota(
                scoped as Arc<dyn agentplane::quota::QuotaStore>,
                TenantQuota::default(),
            )
            .skill(Ack)
            .build()
    };
    let one = plane();
    let two = plane();

    one.set_halt(Some("incident 42: ledger reconciliation is wrong"))
        .await?;
    println!("2. instance one throws the emergency stop");

    // Both instances refuse new work at admission — the flag is in the store,
    // and the refusal is its own error, not a ceiling inviting a retry.
    for (name, rt) in [("one", &one), ("two", &two)] {
        match rt.run("desk.ack", Tainted::trusted(json!({}))).await {
            Err(refusal) => println!("   instance {name} → refused: {refusal}"),
            Ok(out) => panic!("a halted tenant admitted a run: {:?}", out.status),
        }
    }

    one.set_halt(None).await?;
    let lifted = two.run("desk.ack", Tainted::trusted(json!({}))).await?;
    println!(
        "   lifted     → instance two admits again ({})",
        lifted.status.as_str()
    );
    assert_eq!(lifted.status, RunStatus::Succeeded);
    Ok(())
}
