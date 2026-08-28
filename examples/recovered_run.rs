//! An instance dies mid-run, and the survivor takes the work over.
//!
//! ```sh
//! cargo run --example recovered_run      # takes ~3s: a real lease has to lapse
//! ```
//!
//! `durable_pipeline` shows a crash resumed *by whoever asks*. This one shows
//! the harder half: nobody asks. A run whose process died mid-step appears in
//! no backlog, waits on no timer and holds no open task — from the outside it
//! looks exactly like work in progress. Recovery here is **initiated, not
//! merely possible**: the candidate set is exact, because every clean exit —
//! sealed, failed, suspended — hands its lease back, so a lease that expired
//! *without release* names a run somebody was executing when their process
//! stopped.
//!
//! What happens, in order:
//!
//! 1. Instance A starts a three-stage settlement, performs stage one, and
//!    dies — the task is aborted mid-run, the way `kill -9` would.
//! 2. Nothing happens for a lease TTL. Then the store itself can answer the
//!    question an operator would ask: *who died holding work?*
//! 3. Instance B's ordinary sweep finds the run, takes the lease over
//!    (fencing: the resume bumps the epoch, so the dead owner's next append
//!    would be refused), and resumes it. Stage one is read back from the
//!    journal; stages two and three are performed — **once each, total,
//!    across both instances.**
//! 4. The takeover is evidence: the sweep journals it in its own sealed run,
//!    and the recovered run's chain verifies end to end.
//!
//! A deployment gets this for free: `agentplane serve` sweeps on a timer, and
//! any instance's tick recovers any instance's dead. This example drives one
//! tick by hand so the mechanism is visible.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A three-stage settlement that can be told to stall after stage one —
/// standing in for the process being killed there.
#[derive(Debug)]
struct Settlement {
    /// While set, the skill parks forever after stage one — the state a real
    /// instance is in when the operating system takes it away.
    stalled: Arc<AtomicBool>,
    /// Set once stage one is journaled and the skill is parked, so the demo
    /// aborts the task at a moment with a clean journal prefix. (An abort
    /// between an effect's announcement and its record is the *unknown
    /// outcome* case, which quarantines rather than resumes — a different
    /// example.)
    parked: Arc<AtomicBool>,
    /// How many times the outside world was actually touched.
    world: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Skill for Settlement {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("billing.settle")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        for stage in 0..3 {
            let arguments = Tainted::trusted(json!(null));
            cx.sink(
                Recorded::new(format!("stage-{stage}")).counter(Arc::clone(&self.world)),
                &arguments,
            )
            .await?;
            if stage == 0 && self.stalled.load(Ordering::SeqCst) {
                // Between effects, deliberately: a death here leaves a clean
                // journal prefix.
                self.parked.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            }
        }
        Ok(Outcome::done(input))
    }
}

fn instance(
    store: &Arc<dyn JournalStore>,
    owner: &str,
    flags: &(Arc<AtomicBool>, Arc<AtomicBool>),
    world: &Arc<AtomicUsize>,
) -> Arc<Runtime> {
    Runtime::builder(Arc::clone(store))
        .owner(owner)
        // The crash-detection bound: how long a dead instance can look alive.
        // Short here so the example runs in seconds; 30s by default.
        .lease_ttl(Duration::from_secs(2))
        .skill(Settlement {
            stalled: Arc::clone(&flags.0),
            parked: Arc::clone(&flags.1),
            world: Arc::clone(world),
        })
        .build()
}

/// The wall clock, handed to the sweep — the sweeper takes its clock from the
/// caller, so a scheduler (or a simulation) owns time. Outside any run, so
/// outside the journal's determinism rule.
#[allow(clippy::disallowed_methods)]
fn now() -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::now_utc()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);
    let flags = (
        Arc::new(AtomicBool::new(true)),  // stalled
        Arc::new(AtomicBool::new(false)), // parked
    );
    let world = Arc::new(AtomicUsize::new(0));

    // ── 1. Instance A dies mid-run ─────────────────────────────────────────
    let a = instance(&store, "instance-a", &flags, &world);
    let task = tokio::spawn({
        let a = Arc::clone(&a);
        async move {
            let _ = a
                .run(
                    "billing.settle",
                    Tainted::trusted(json!({ "invoice": "INV-9" })),
                )
                .await;
        }
    });
    // Let it journal stage one and park, then take the process away.
    while !flags.1.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    task.abort();
    drop(a);
    println!("1. instance-a performed stage one, then died mid-run");
    println!("   external calls → {}", world.load(Ordering::SeqCst));

    // ── 2. The store names the dead ────────────────────────────────────────
    // Immediately after the crash the lease still looks held — a dead owner is
    // indistinguishable from a slow one until the TTL bounds the doubt.
    assert!(store.abandoned_runs(10).await?.is_empty());
    println!("\n2. for one lease TTL, the dead look exactly like the busy…");
    tokio::time::sleep(Duration::from_millis(3200)).await;

    let stranded = store.abandoned_runs(10).await?;
    let run = *stranded.first().expect("the lease lapsed without release");
    println!("   …then the lease lapses unreleased, and the store can say who:");
    println!("   abandoned      → {run}");

    // ── 3. Instance B's ordinary sweep takes it over ───────────────────────
    flags.0.store(false, Ordering::SeqCst); // B's build does not stall
    let b = instance(&store, "instance-b", &flags, &world);
    let report = b.sweep(now(), Duration::from_secs(3600)).await?;
    println!("\n3. instance-b sweeps");
    println!("   runs recovered → {}", report.runs_recovered);
    println!(
        "   external calls → {} — stage one was replayed, not repeated",
        world.load(Ordering::SeqCst)
    );
    assert_eq!(report.runs_recovered, 1);
    assert_eq!(world.load(Ordering::SeqCst), 3, "three stages, once each");

    let outcome = b
        .recorded_outcome(run)
        .await?
        .expect("the recovered run concluded");
    assert_eq!(outcome.status, RunStatus::Succeeded);
    println!("   run            → {}", outcome.status.as_str());

    // ── 4. The takeover is evidence ────────────────────────────────────────
    let evidence = report.record.expect("the sweep sealed its account");
    println!("\n4. the sweep journaled its takeover in its own run: {evidence}");
    store.verify(run).await?;
    store.verify(evidence).await?;
    println!("   both chains verify — the recovery is on the record, not just done");

    Ok(())
}
