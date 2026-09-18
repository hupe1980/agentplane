//! What does the gate cost, and which part of it dominates?
//!
//! The question an adopter asks first about a runtime whose central claim is
//! *the journal is the plan of record*, and one this repository could not answer
//! until it had a way to produce a number. Every performance sentence in the
//! docs comes from here, and carries the command that re-derives it — a figure
//! nobody can reproduce is decoration, not evidence.
//!
//! # A total would answer nothing
//!
//! The useful result is not what an effect costs; it is **which axis it is
//! spent on**, because that is the one an adopter can trade against and the one
//! a regression would show up in. So each control this design adds is measured
//! on its own, against the same store, and reported as the delta it adds to a
//! bare effect:
//!
//! | axis | what it adds per effect |
//! |---|---|
//! | `journal` | canonicalization, the chain digest, and the durable commit |
//! | `policy` | one `PolicyEngine::authorize` before dispatch |
//! | `sink` | the label gate over a protected field |
//!
//! # The durability point is the measurement
//!
//! One effect crosses the protocol **twice**: `EffectStarted` before dispatch,
//! then its terminal record. Both are durable commits, because I2 says the
//! announcement must survive the process before anything reaches the world.
//! `cx.now()` is used as the bare effect precisely because it does nothing else
//! — what is timed is the protocol, not a model.
//!
//! So the on-disk figure is two fsyncs, and that is the honest price of the
//! guarantee rather than an inefficiency to tune away. Run it in memory and on
//! disk: the gap between them is the whole story, and it is why the other two
//! axes are reported beside it rather than alone.
//!
//! # What it does not measure
//!
//! The effect it sits beside. A model call is seconds and a tool call is tens
//! of milliseconds, so every figure here is noise against a real agent's wall
//! clock — a comparison that omitted that would be dishonest by framing. It
//! stops being noise when effects are cheap and many.
//!
//! It also does not measure what a *refusal* costs. A policy that denies work
//! costs the deployment task success and spend rather than microseconds, that
//! cost is the bundle's rather than the plane's, and measuring it needs agents
//! running against two bundles rather than a loop.
//!
//! Run it:
//!
//! ```sh
//! just perf
//! N=2000 DISK=1 cargo run --release --example gate_bench --features redb,cedar
//! ```
//!
//! Named `_bench` so `just examples` leaves it alone: it is a measurement rather
//! than a demonstration, it takes twenty seconds, and CI time is a real cost.
//! The same exemption `_live` has, for a different reason.

// This file measures the runtime from *outside* it, so its clock reads are not
// part of any run's determinism — nothing here is replayed, and the numbers are
// the point. That is a different exception from the runtime's own driver layer,
// which reads a clock and journals what it read; here there is no journal record
// to name, because the reading is the output. That the gate fires on this file
// at all is the gate working.
#![allow(clippy::disallowed_methods)]
// Effect counts are small and exact; the division is for a human-readable rate.
#![allow(clippy::cast_precision_loss)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentplane::core::{Effect, EffectDescriptor, EffectError, ProtectedField, Recovery};
use agentplane::prelude::*;
use serde_json::{Value, json};

/// A permit-all bundle, with the shape a deployment's own would have.
///
/// Evaluation cost scales with the rule set, so the rule count is part of the
/// configuration this prints rather than a detail: a plane running forty rules
/// pays more than this, proportionally, and that is the number to scale from.
const RULES: &str = r#"
@id("permit-effects")
permit (principal, action == Action::"effect:perform", resource);
@id("permit-admission")
permit (principal, action == Action::"run:admit", resource);
@id("permit-release")
permit (principal, action == Action::"information_flow.release", resource);
"#;

const RULE_COUNT: usize = 3;

/// The bare effect: it reaches nothing, so what is timed is the protocol.
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

/// An effect carrying one authority-bearing argument, so the sink gate has
/// something to check.
#[derive(Debug)]
struct Pay {
    args: Value,
    protected: Vec<ProtectedField>,
}

#[async_trait::async_trait]
impl Effect for Pay {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("ledger.pay", self.args.clone())
    }

    fn mutates(&self) -> bool {
        true
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    /// The exact value the sink gate checks. Without it `sink` refuses the
    /// call, which is the gate working — and is what this axis is timing.
    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.args)
    }

    fn protected_fields(&self) -> &[ProtectedField] {
        &self.protected
    }

    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "ok": true }))
    }
}

/// The same loop, dispatched through the label gate instead of past it.
#[derive(Debug)]
struct Sinking(usize);

#[async_trait::async_trait]
impl Skill for Sinking {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("sinking").provides("perf.sink")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let protected = vec![ProtectedField::trusted("/account")];
        for i in 0..self.0 {
            let args = Tainted::trusted(json!({ "account": "DE-1", "seq": i }));
            let effect = Pay {
                args: args.peek().clone(),
                protected: protected.clone(),
            };
            let _ = cx.sink(effect, &args).await?;
        }
        Ok(Outcome::done(input))
    }
}

fn store(on_disk: bool, tag: &str) -> Result<Arc<dyn JournalStore>, Box<dyn std::error::Error>> {
    if on_disk {
        let path = std::env::temp_dir().join(format!(
            "agentplane-bench-{tag}-{}.redb",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Ok(Arc::new(RedbStore::open(&path)?))
    } else {
        Ok(Arc::new(RedbStore::open_in_memory()?))
    }
}

/// One axis: how long `n` effects take, and how long reading them back takes.
///
/// # It refuses to time a run that did not do the work
///
/// A refused effect is *faster* than a performed one, so an axis that stops
/// working reports as an improvement. That is not hypothetical: the sink axis
/// was written without binding its outbound arguments, the gate refused the
/// first call exactly as it should, and the harness printed a hundredfold
/// speed-up for a run that journaled five records. So the run must succeed and
/// the journal must hold what the axis claims to have measured, or nothing is
/// printed at all.
async fn time(
    runtime: &Arc<agentplane::runtime::Runtime>,
    capability: &str,
    expected: usize,
) -> Result<(Duration, Duration), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let outcome = runtime.run(capability, Tainted::trusted(json!({}))).await?;
    let live = started.elapsed();

    // Replay performs nothing and reads every effect back, so this is the cost
    // of the *read* path — which is what an audit, a divergence check and a
    // crash recovery all pay.
    let started = Instant::now();
    runtime.replay(outcome.run_id, Mode::Strict).await?;
    let replay = started.elapsed();

    if outcome.status != RunStatus::Succeeded {
        return Err(format!("{capability} did not succeed: {:?}", outcome.status).into());
    }
    let journaled = runtime.journal().read(outcome.run_id, 0).await?.len();
    if journaled != expected {
        return Err(format!(
            "{capability} journaled {journaled} records, not {expected} — the axis is \
             not performing the work it is being timed for"
        )
        .into());
    }
    Ok((live, replay))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let on_disk = std::env::var("DISK").is_ok();
    // Fewer effects on disk, because each one is two fsyncs: the figure is
    // established just as well and the repeats below stay affordable.
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(if on_disk { 400 } else { 2000 });
    let repeats: usize = std::env::var("REPEATS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);

    // Two records per effect — the announcement and its terminal record — plus
    // the five a run of one step carries whatever it does: admission, the
    // frozen plan, the step's two ends and the conclusion.
    let records = n * 2 + 5;

    // Each axis is run `repeats` times on its own store and reported by its
    // **best** sample. A latency figure's fast end is the one with the least
    // interference in it; the slow end is whatever else the machine was doing,
    // which is not a property of this runtime. The baseline's own spread is
    // reported beside them as what the method resolves.
    let mut baseline = Vec::new();
    let mut replay = Duration::MAX;
    for i in 0..repeats {
        let rt = Runtime::builder(store(on_disk, &format!("journal-{i}"))?)
            .skill(Burst(n))
            .build();
        let (live, read) = time(&rt, "perf.burst", records).await?;
        baseline.push(live);
        replay = replay.min(read);
    }
    let journal = *baseline.iter().min().expect("at least one run");
    // `saturating_sub` because a `Duration` cannot go negative and the max is
    // the max: the zero it would give on one sample is the honest answer there
    // — one run resolves nothing.
    let spread = baseline
        .iter()
        .max()
        .expect("at least one run")
        .saturating_sub(journal);

    let mut policy = Duration::MAX;
    for i in 0..repeats {
        let engine = agentplane::policy::CedarEngine::new(RULES)?;
        let rt = Runtime::builder(store(on_disk, &format!("policy-{i}"))?)
            .skill(Burst(n))
            .policy(Arc::new(engine))
            .build();
        policy = policy.min(time(&rt, "perf.burst", records).await?.0);
    }

    let mut sink = Duration::MAX;
    for i in 0..repeats {
        let rt = Runtime::builder(store(on_disk, &format!("sink-{i}"))?)
            .skill(Sinking(n))
            .build();
        sink = sink.min(time(&rt, "perf.sink", records).await?.0);
    }

    let per = |d: Duration| d.as_secs_f64() / n as f64 * 1000.0;
    let resolves = per(spread);
    // Below the spread there is nothing to report but the spread. Printing a
    // signed delta there invites the one reading it cannot support — a control
    // that made the run *faster* — and the honest answer is that this harness
    // cannot see it from here.
    let delta = |d: Duration| {
        let d = per(d) - per(journal);
        if d.abs() <= resolves {
            "    under the spread".to_owned()
        } else {
            format!("{d:+8.3} ms vs journal")
        }
    };

    println!(
        "{n} effects × {repeats} runs, redb {}, {RULE_COUNT} policy rules\n  \
         journal  {:>8.3} ms/effect   {:>8.0} effects/sec   canonicalize, chain, commit\n  \
         policy   {:>8.3} ms/effect   {}  one authorize per effect\n  \
         sink     {:>8.3} ms/effect   {}  label gate, one protected field\n  \
         replay   {:>8.3} ms/effect   {:>8.0} effects/sec   the read path, nothing performed\n  \
         spread   {resolves:>8.3} ms/effect                     across {repeats} baseline runs, what this resolves",
        if on_disk { "on disk" } else { "in memory" },
        per(journal),
        n as f64 / journal.as_secs_f64(),
        per(policy),
        delta(policy),
        per(sink),
        delta(sink),
        per(replay),
        n as f64 / replay.as_secs_f64(),
    );
    Ok(())
}
