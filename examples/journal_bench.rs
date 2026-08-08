//! What does an effect cost?
//!
//! The question an adopter asks first about a runtime whose central claim is
//! *the journal is the plan of record*, and one this repository could not answer
//! until it had a way to produce a number. Every performance sentence in the
//! docs comes from here, and carries the command that re-derives it — a figure
//! nobody can reproduce is decoration, not evidence.
//!
//! # What is being measured
//!
//! One effect crosses the protocol **twice**: `EffectStarted` before dispatch,
//! then its terminal record. Both are durable commits, because I2 says the
//! announcement must survive the process before anything reaches the world.
//! `cx.now()` is used as the effect precisely because it does nothing else —
//! what is timed is the protocol, not a model.
//!
//! So the on-disk figure is two fsyncs, and that is the honest price of the
//! guarantee rather than an inefficiency to tune away. The useful comparison is
//! not against a faster store but against **what an effect normally is**: a
//! model call is seconds, a tool call is tens of milliseconds, and against those
//! the journal is noise. It stops being noise when effects are cheap and many.
//!
//! Run it:
//!
//! ```sh
//! just perf
//! N=2000 DISK=1 cargo run --release --example journal_bench --features redb
//! ```
//!
//! Named `_bench` so `just examples` leaves it alone: it is a measurement rather
//! than a demonstration, it takes twenty seconds, and CI time is a real cost.
//! The same exemption `_live` has, for a different reason.

// This file measures the runtime from *outside* it, so its clock reads are not
// part of any run's determinism — nothing here is replayed, and the numbers are
// the point. That is a different exception from the runtime's own driver layer,
// which reads a clock and journals what it read; here there is no journal record
// to name, because the reading is the output. The gate firing on this file the
// moment it was added is the gate working.
#![allow(clippy::disallowed_methods)]
// Effect counts are small and exact; the division is for a human-readable rate.
#![allow(clippy::cast_precision_loss)]

use std::sync::Arc;
use std::time::Instant;

use agentplane::prelude::*;
use serde_json::{Value, json};

#[derive(Debug)]
struct Burst(usize);

#[async_trait::async_trait]
impl Skill for Burst {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("burst").provides("perf.burst")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        for _ in 0..self.0 {
            let _ = cx.now().await?;
        }
        Ok(Outcome::done(input))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let on_disk = std::env::var("DISK").is_ok();

    let store: Arc<dyn JournalStore> = if on_disk {
        let path =
            std::env::temp_dir().join(format!("agentplane-bench-{}.redb", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Arc::new(RedbStore::open(&path)?)
    } else {
        Arc::new(RedbStore::open_in_memory()?)
    };
    let runtime = Runtime::builder(Arc::clone(&store)).skill(Burst(n)).build();

    let started = Instant::now();
    let outcome = runtime.run("perf.burst", json!({})).await?;
    let live = started.elapsed();

    // Replay performs nothing and reads every effect back, so this is the cost
    // of the *read* path — which is what an audit, a divergence check and a
    // crash recovery all pay.
    let started = Instant::now();
    runtime.replay(outcome.run_id, Mode::Strict).await?;
    let replay = started.elapsed();

    let per = live.as_secs_f64() / n as f64 * 1000.0;
    println!(
        "{n} effects, redb {}\n  \
         live    {live:>9.1?}   {:>8.0} effects/sec   {per:.2} ms/effect\n  \
         replay  {replay:>9.1?}   {:>8.0} effects/sec   {:.0}x faster than live",
        if on_disk { "on disk" } else { "in memory" },
        n as f64 / live.as_secs_f64(),
        n as f64 / replay.as_secs_f64(),
        live.as_secs_f64() / replay.as_secs_f64(),
    );
    Ok(())
}
