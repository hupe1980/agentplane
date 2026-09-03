//! From *instrumented* to *monitored*: the last mile, in runnable form.
//!
//! ```sh
//! cargo run --example observability
//! ```
//!
//! This crate ships no exporter, for the same reason it ships no policy engine:
//! picking your collector is not its decision. That is the right call and it
//! leaves a gap, because the distance between **instrumented** and
//! **monitored** is exactly where an evaluation writes *not fulfilled*. Three
//! things stand in that gap, none of them obvious from the API docs, and each
//! one is a real bridge layer here rather than a snippet in prose:
//!
//! 1. **Latency must exclude replayed effects.** A replayed effect reads its
//!    result from the journal and never touches the world. Counted as latency
//!    it does not add noise — it silently *improves* your p99 in proportion to
//!    how much recovery you are doing, which is precisely when you want the
//!    number to be honest.
//!
//!    The runtime already makes this easy, in a way worth stating because it
//!    is not what a reader assumes: **a replayed effect opens no span at all.**
//!    It emits a `debug` *event* on the `agentplane.effect` target carrying
//!    `replayed = true`, and the `agentplane.effects_replayed` counter. So a
//!    histogram built from *spans* is clean by construction. What is not safe
//!    is keying on the **target** and treating everything on it as a span —
//!    that view sees both, and it is the one in which replays contaminate
//!    latency. The bridge below separates them and asserts on the split.
//!
//! 2. **Gauges come from a census, not from increments.** "Open cases" cannot
//!    be counted by incrementing on open and decrementing on close: a crash
//!    between the state change and the emission loses a decrement forever, and
//!    the dashboard slowly invents cases that do not exist. The runtime
//!    therefore emits gauges only when something queries the stores — the
//!    sweeper — so *scheduling the sweep is scheduling your gauges*. A plane
//!    with no sweep loop has counters and no gauges, and nothing says so.
//!
//! 3. **`SweepReport::needs_attention()` is the alert predicate.** It is
//!    already written, it already folds in breaches, expiries, dead letters,
//!    saturation, failed recoveries and lost evidence, and it is the one call
//!    an alert rule should key on. Re-deriving it from individual counters is
//!    how a new failure mode ends up alerting on nothing.
//!
//! # The OTLP wiring, verbatim
//!
//! What runs below is a `tracing_subscriber::Layer` that reads exactly the
//! fields an OTLP bridge reads. To send them to a real collector, keep the
//! filtering rules and swap the sink:
//!
//! ```toml
//! # Cargo.toml
//! opentelemetry            = "0.32"
//! opentelemetry_sdk        = { version = "0.32", features = ["rt-tokio"] }
//! opentelemetry-otlp       = { version = "0.32", features = ["grpc-tonic", "metrics"] }
//! tracing-opentelemetry    = "0.33"
//! tracing-subscriber       = { version = "0.3", features = ["registry", "env-filter"] }
//! ```
//!
//! ```ignore
//! use tracing_subscriber::prelude::*;
//!
//! let tracer = opentelemetry_otlp::SpanExporter::builder().with_tonic().build()?;
//! let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
//!     .with_batch_exporter(tracer)
//!     .build();
//!
//! tracing_subscriber::registry()
//!     // Spans → OTLP. `agentplane.run` / `.step` / `.effect` nest correctly,
//!     // so the collector derives every duration; see `runtime::metrics` on
//!     // why this crate measures none of them itself.
//!     .with(tracing_opentelemetry::layer().with_tracer(
//!         opentelemetry::trace::TracerProvider::tracer(&provider, "agentplane"),
//!     ))
//!     // Metric events → your meter. `MetricBridge` below is the whole of it:
//!     // one target, five fixed fields, and the catalogue names the label.
//!     .with(MetricBridge::default())
//!     // The one rule that is not mechanical. Everything else a bridge does
//!     // for you; this it cannot guess.
//!     .with(DropReplayedEffects)
//!     .init();
//! ```
//!
//! Then schedule the two loops — `sweep` for gauges and the backlog, `drill`
//! for the recovery rehearsal — or run `agentplane serve --sweep-every 30
//! --drill-every 86400`, which is the same two loops with no Rust.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use agentplane::case::CaseStore;
use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::effects::Recorded;
use agentplane::runtime::telemetry;
use agentplane::runtime::{Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};
use tracing::field::{Field, Visit};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

// ── What a collector would hold ─────────────────────────────────────────────

/// Everything the bridge decided to keep, so the example can assert on it.
///
/// A real deployment's equivalent is the collector; the shape is the same
/// because the decisions are the same.
#[derive(Debug, Default)]
struct Collected {
    /// Effect spans that reached the world, by kind. The latency series.
    live_effects: Vec<String>,
    /// Effect spans dropped because they were replayed.
    ///
    /// Counted rather than discarded silently: *how much of this plane's work
    /// is recovery* is a real question, and it is a different series from
    /// latency rather than a contaminant in it.
    replayed_effects: usize,
    /// `metric` → `dim` → summed value. What a meter would hold.
    metrics: BTreeMap<String, BTreeMap<String, f64>>,
}

type Sink = Arc<Mutex<Collected>>;

// ── 1. Latency that excludes replay ─────────────────────────────────────────

/// Keeps live effect spans out of the same series as replayed ones.
///
/// The whole rule: an `agentplane.effect` span carrying
/// `agentplane.effect.replayed = true` performed nothing. Its duration is a
/// journal read, and a histogram that mixes the two reports better latency the
/// more recovery a plane is doing.
///
/// Implemented on span **creation**, where the field is recorded, rather than on
/// close: `tracing` fields are written once at creation, so this is the cheap
/// point and it is also the point at which a real bridge can decline to start
/// an `OTel` span at all.
struct DropReplayedEffects(Sink);

impl<S> Layer<S> for DropReplayedEffects
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    /// A **span** on this target is a live dispatch. Its duration is a real
    /// call, and it is the only thing a latency series should contain.
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: Context<'_, S>,
    ) {
        if attrs.metadata().name() != telemetry::EFFECT_SPAN {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        // Belt and braces. The field is always `false` on a live span today,
        // and reading it costs nothing — a bridge that assumed the invariant
        // and was wrong would report the fastest p99 in the company.
        if fields.bools.get(telemetry::EFFECT_REPLAYED).copied() == Some(true) {
            self.0.lock().expect("collector").replayed_effects += 1;
            return;
        }
        let kind = fields
            .strings
            .get(telemetry::EFFECT_KIND)
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned());
        self.0.lock().expect("collector").live_effects.push(kind);
    }

    /// An **event** on the same target is a replay: no world contact, no
    /// duration, nothing for a histogram. Counted, because *how much of this
    /// plane's work is recovery* is a real question — just a different series.
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != telemetry::EFFECT_SPAN {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        if fields.bools.get("replayed").copied() == Some(true) {
            self.0.lock().expect("collector").replayed_effects += 1;
        }
    }
}

// ── 2. Metric events → a meter ──────────────────────────────────────────────

/// Every metric this plane emits, on one target with five fixed fields.
///
/// `metric`, `kind`, `unit`, `value`, `dim`. The *meaning* of `dim` is declared
/// per instrument in the catalogue, so a bridge reads
/// [`metrics::CATALOGUE`](agentplane::runtime::metrics::CATALOGUE) once at
/// startup and knows the label name for every stream — rather than inferring it
/// from samples, which is how a label ends up named `dim` on a dashboard.
struct MetricBridge(Sink);

impl<S: tracing::Subscriber> Layer<S> for MetricBridge {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != agentplane::runtime::metrics::METRIC {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let Some(metric) = fields.strings.get("metric") else {
            return;
        };
        let dim = fields
            .strings
            .get("dim")
            .cloned()
            .unwrap_or_else(|| "-".to_owned());
        let value = fields.numbers.get("value").copied().unwrap_or_default();

        let mut out = self.0.lock().expect("collector");
        let series = out.metrics.entry(metric.clone()).or_default();
        // A gauge is *replaced*, a counter accumulates. The catalogue says
        // which, and reading it is the difference between "open cases now" and
        // "every open case this process ever saw".
        let is_gauge = agentplane::runtime::metrics::CATALOGUE
            .iter()
            .find(|i| i.name == metric.as_str())
            .is_some_and(|i| matches!(i.kind, agentplane::runtime::metrics::Kind::Gauge));
        let slot = series.entry(dim).or_default();
        if is_gauge {
            *slot = value;
        } else {
            *slot += value;
        }
    }
}

/// Pulls typed fields out of a span or event without allocating a JSON tree.
#[derive(Default)]
struct Fields {
    strings: BTreeMap<String, String>,
    bools: BTreeMap<String, bool>,
    numbers: BTreeMap<String, f64>,
}

#[allow(clippy::cast_precision_loss)]
impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.strings
            .insert(field.name().to_owned(), value.to_owned());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.bools.insert(field.name().to_owned(), value);
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.numbers.insert(field.name().to_owned(), value as f64);
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.numbers.insert(field.name().to_owned(), value as f64);
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.numbers.insert(field.name().to_owned(), value);
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // `%foo` and `?foo` arrive here. The runtime records `kind` and `dim`
        // with `%`, so a bridge that only implemented `record_str` would see an
        // empty catalogue and report nothing at all.
        self.strings.insert(
            field.name().to_owned(),
            format!("{value:?}").trim_matches('"').to_owned(),
        );
    }
}

// ── The plane under observation ─────────────────────────────────────────────

/// Performs one externally visible effect, so there is something to measure.
#[derive(Debug)]
struct Post;

#[async_trait::async_trait]
impl Skill for Post {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("ledger.post").provides("ledger.post")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        // `Recorded` binds its payload as the value a sink would send, so it
        // goes through `cx.sink` with the *same* value the gate is shown. Pass
        // anything else and the argument binding refuses the call — correctly,
        // and the refusal now names the first differing JSON pointer.
        let arguments = Tainted::trusted(json!(null));
        let posted = cx.sink(Recorded::new("ledger.post"), &arguments).await?;
        Ok(Outcome::done(posted))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let collected: Sink = Arc::default();

    // The whole bridge. In a real deployment `tracing_opentelemetry::layer()`
    // sits beside these two and does the exporting; what these two do is the
    // part it cannot do for you.
    tracing_subscriber::registry()
        .with(DropReplayedEffects(Arc::clone(&collected)))
        .with(MetricBridge(Arc::clone(&collected)))
        .init();

    let store = Arc::new(RedbStore::open_in_memory()?);
    let plane = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&store) as Arc<dyn CaseStore>)
        .skill(Post)
        .build();

    // ── A live run: one effect that reached the world ───────────────────────
    let out = plane
        .run("ledger.post", Tainted::trusted(json!({})))
        .await?;
    assert_eq!(out.status, RunStatus::Succeeded);

    // ── The same run, replayed: the effect happens zero more times ──────────
    let replayed = plane.replay(out.run_id, Mode::Strict).await?;
    assert_eq!(replayed.status, RunStatus::Succeeded);

    {
        let seen = collected.lock().expect("collector");
        println!("1. latency series");
        println!("   live effect spans  : {:?}", seen.live_effects);
        println!("   replays, not timed : {}", seen.replayed_effects);
        assert_eq!(
            seen.live_effects.len(),
            1,
            "exactly one effect reached the world, and only it belongs in a \
             latency histogram"
        );
        assert!(
            seen.replayed_effects >= 1,
            "the replay must be visible as a replay: 'how much of this plane's \
             work is recovery' is a question an operator asks, and the answer \
             is not zero just because it is not latency"
        );
    }

    // ── 2. Gauges arrive with the sweep, and only with the sweep ────────────
    //
    // Scheduling the sweep *is* scheduling your gauges. Before the first tick a
    // plane has counters and no gauges, which reads on a dashboard exactly like
    // a plane holding nothing.
    {
        let seen = collected.lock().expect("collector");
        assert!(
            !seen
                .metrics
                .contains_key(agentplane::runtime::metrics::OPEN_CASES.name),
            "gauges must not appear before something queries the stores"
        );
    }

    #[allow(clippy::disallowed_methods)]
    let now = time::OffsetDateTime::now_utc();
    let report = plane
        .sweep(now, std::time::Duration::from_secs(3600))
        .await?;

    println!("\n2. the census, from the sweep");
    println!("   open cases   : {}", report.census.open_cases);
    println!("   open tasks   : {}", report.census.open_tasks);
    println!("   due deadlines: {}", report.census.due_deadlines);
    {
        let seen = collected.lock().expect("collector");
        assert!(
            seen.metrics
                .contains_key(agentplane::runtime::metrics::OPEN_CASES.name),
            "the sweep must emit the census, or a plane's gauges never exist"
        );
    }

    // ── 3. The alert predicate is already written ───────────────────────────
    //
    // One call, not a hand-rolled disjunction over counters: when the runtime
    // learns a new way for a tick to need a human, this is what learns it.
    println!("\n3. alerting");
    println!("   needs_attention(): {}", report.needs_attention());
    println!("   is_quiet()       : {}", report.is_quiet());
    if report.needs_attention() {
        // In production: `tracing::warn!(?report, ...)`, and the alert rule
        // keys on this event rather than on any single counter.
        println!("   → page somebody: {report:?}");
    }
    println!(
        "\n   census_unavailable is part of needs_attention() on purpose: gauges\n\
         \x20  that could not be read are a blind spot wearing a default, and\n\
         \x20  'zero open cases' and 'I could not count them' must not look alike."
    );

    println!("\n4. what a meter would hold");
    for (metric, series) in &collected.lock().expect("collector").metrics {
        for (dim, value) in series {
            println!("   {metric:<34} {dim:<12} {value}");
        }
    }

    Ok(())
}
