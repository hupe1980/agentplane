//! A pipeline that crashes and resumes without redoing its work.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example durable_pipeline
//! ```
//!
//! What it demonstrates, in order:
//!
//! 1. A run performs three externally visible stages and journals each one.
//! 2. Strict replay re-executes the logic and performs **nothing** — every
//!    effect is read back from the journal.
//! 3. A run interrupted after stage 1 resumes at stage 2, so stage 1 happens
//!    exactly once across both attempts.
//! 4. Changing the code makes replay diverge, and the run is quarantined
//!    instead of quietly rewriting history.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// Counts how many times the outside world was actually touched.
///
/// The number that matters in every scenario below: it must not go up when a
/// run is replayed.
#[derive(Debug, Clone, Default)]
struct World(Arc<AtomicUsize>);

impl World {
    fn touched(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A settlement pipeline: three stages, then a timestamp.
///
/// Two knobs, and the distinction between them is the whole lesson:
///
/// * `crash_at` stops the *same program* partway, the way a `kill -9` would.
///   The journal is then a genuine prefix of a complete run, which is what
///   makes resuming meaningful.
/// * `stages` changes the program itself. Replaying a journal written by a
///   different program is divergence, not recovery — and the runtime says so.
#[derive(Debug)]
struct Settlement {
    stages: Arc<AtomicUsize>,
    crash_at: Arc<AtomicUsize>,
    world: World,
}

/// Sentinel meaning "do not crash".
const NO_CRASH: usize = usize::MAX;

#[async_trait::async_trait]
impl Skill for Settlement {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("settlement").provides("billing.settle")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let n = self.stages.load(Ordering::SeqCst);
        let crash_at = self.crash_at.load(Ordering::SeqCst);

        for i in 0..n {
            let arguments = Tainted::trusted(json!(null));
            cx.sink(
                Recorded::new(format!("stage-{i}")).counter(Arc::clone(&self.world.0)),
                &arguments,
            )
            .await?;

            // Stand-in for the process dying here: the journal keeps everything
            // written so far and nothing after it.
            if i == crash_at {
                return Err(SkillError::Other(format!(
                    "simulated crash after stage {i}"
                )));
            }
        }

        let at = cx.now().await?;
        Ok(Outcome::done(
            input.map(|v| json!({ "settled": v, "at": at.to_string() })),
        ))
    }
}

fn runtime(
    store: &Arc<dyn JournalStore>,
    stages: &Arc<AtomicUsize>,
    crash_at: &Arc<AtomicUsize>,
    world: &World,
) -> Arc<Runtime> {
    Runtime::builder(Arc::clone(store))
        .owner("example")
        .skill(Settlement {
            stages: Arc::clone(stages),
            crash_at: Arc::clone(crash_at),
            world: world.clone(),
        })
        .build()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory()?);

    // ── 1. A normal run ────────────────────────────────────────────────────
    let stages = Arc::new(AtomicUsize::new(3));
    let crash_at = Arc::new(AtomicUsize::new(NO_CRASH));
    let world = World::default();
    let rt = runtime(&store, &stages, &crash_at, &world);

    let first = rt
        .run(
            "billing.settle",
            Tainted::trusted(json!({ "invoice": "INV-4711" })),
        )
        .await?;
    println!("1. live run      → {:?}", first.status);
    println!("   external calls: {}", world.touched());
    println!("   chain head:     {}", first.chain_head);

    // ── 2. Strict replay performs nothing ──────────────────────────────────
    let before = world.touched();
    let replayed = rt.replay(first.run_id, Mode::Strict).await?;
    println!("\n2. strict replay → {:?}", replayed.status);
    println!(
        "   external calls: {} (unchanged: {})",
        world.touched(),
        world.touched() == before
    );
    assert_eq!(world.touched(), before, "replay must not touch the world");
    assert_eq!(
        first.output, replayed.output,
        "replay must reproduce the output"
    );

    // ── 3. Crash and resume ────────────────────────────────────────────────
    // Same three-stage program, but the process dies after stage 0.
    let stages = Arc::new(AtomicUsize::new(3));
    let crash_at = Arc::new(AtomicUsize::new(0));
    let world = World::default();
    let rt = runtime(&store, &stages, &crash_at, &world);

    let crashed = rt
        .run(
            "billing.settle",
            Tainted::trusted(json!({ "invoice": "INV-4712" })),
        )
        .await?;
    println!("\n3. run crashed   → {:?}", crashed.status);
    println!("   external calls: {}", world.touched());

    // The process comes back up. Same code, same program — just alive again.
    crash_at.store(NO_CRASH, Ordering::SeqCst);
    let resumed = rt.replay(crashed.run_id, Mode::Resume).await?;
    println!("   resumed        → {:?}", resumed.status);
    println!(
        "   external calls: {} — stage 0 was replayed, not repeated",
        world.touched()
    );
    assert_eq!(world.touched(), 3, "three stages total, none of them twice");

    // ── 4. A changed build cannot silently rewrite history ─────────────────
    // Note the difference from case 3: there, the *program* was unchanged and
    // only the process had died. Here the code itself is different, so the
    // recorded history no longer describes what this build does.
    let stages = Arc::new(AtomicUsize::new(2));
    let crash_at = Arc::new(AtomicUsize::new(NO_CRASH));
    let world = World::default();
    let rt = runtime(&store, &stages, &crash_at, &world);
    let recorded = rt
        .run(
            "billing.settle",
            Tainted::trusted(json!({ "invoice": "INV-4713" })),
        )
        .await?;

    // Ship a change: one extra stage.
    stages.store(3, Ordering::SeqCst);
    let diverged = rt.replay(recorded.run_id, Mode::Strict).await?;
    println!("\n4. changed build → {:?}", diverged.status);
    assert!(
        matches!(diverged.status, RunStatus::Quarantined(_)),
        "divergence must be caught, not absorbed"
    );

    // ── 5. The chain verifies end to end ───────────────────────────────────
    for run in [first.run_id, crashed.run_id, recorded.run_id] {
        store.verify(run).await?;
    }
    println!("\n5. all journals verify — no record was altered after the fact");

    Ok(())
}
