//! Metrics: proving the numbers are real.
//!
//! These assert on what a subscriber **received**, not on what the source
//! contains, for the same reason `tests/telemetry.rs` does: a test that greps
//! for a call site checks the author's intent rather than the runtime's
//! behaviour.
//!
//! The gauge tests matter more than they look. A gauge is the one instrument
//! that can be confidently, silently wrong — a counter that is never emitted
//! reads as zero and so does a counter for something that never happened, but a
//! *gauge* read from a `limit`-bounded query flattens exactly when the backlog
//! becomes worth alerting on, and looks healthy while doing it.

#![cfg(feature = "sqlite")]
#![allow(clippy::disallowed_methods)]
// Holding a `std::sync::Mutex` across an `.await` is normally a deadlock risk,
// and here it is the point: the lock must span the whole run, because what it
// serialises is an ambient `tracing` subscriber that the run's events dispatch
// to. Each `#[tokio::test]` builds its own current-thread runtime, so there is
// no second task on this runtime to contend for it.
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use agentplane::case::{CaseStore, TaskStore, TimerStore};
use agentplane::core::{
    CorrelationKey, DeadlineSpec, Effect, EffectDescriptor, EffectError, Justification, OnExpiry,
    Outcome, Recovery, RetryPolicy, Skill, SkillDescriptor, SkillError, Tainted, TaskSpec,
    Timestamp,
};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Runtime, StepCtx, metrics};
use agentplane::store::SqliteStore;
use serde_json::{Value, json};
use tracing::{Event, Metadata, Subscriber, span};

/// One metric event, flattened to what a bridge would forward.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    metric: String,
    kind: String,
    unit: String,
    value: u64,
    dim: String,
}

#[derive(Debug, Default, Clone)]
struct Meter {
    samples: Arc<Mutex<Vec<Sample>>>,
}

impl Meter {
    fn samples(&self) -> Vec<Sample> {
        self.samples.lock().unwrap().clone()
    }
    fn named(&self, name: &str) -> Vec<Sample> {
        self.samples()
            .into_iter()
            .filter(|s| s.metric == name)
            .collect()
    }
    fn total(&self, name: &str) -> u64 {
        self.named(name).iter().map(|s| s.value).sum()
    }
}

/// Pulls the fixed metric field set off an event.
#[derive(Default)]
struct Fields {
    metric: String,
    kind: String,
    unit: String,
    value: u64,
    dim: String,
}

impl tracing::field::Visit for Fields {
    fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
        if f.name() == "value" {
            self.value = v;
        }
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        match f.name() {
            "metric" => self.metric = v.to_string(),
            "kind" => self.kind = v.to_string(),
            "unit" => self.unit = v.to_string(),
            "dim" => self.dim = v.to_string(),
            _ => {}
        }
    }
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        let s = format!("{v:?}");
        self.record_str(f, s.trim_matches('"'));
    }
}

impl Subscriber for Meter {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != metrics::METRIC {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        self.samples.lock().unwrap().push(Sample {
            metric: f.metric,
            kind: f.kind,
            unit: f.unit,
            value: f.value,
            dim: f.dim,
        });
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

// ── Fixtures ────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Ping;

#[async_trait::async_trait]
impl Effect for Ping {
    type Output = Value;
    fn descriptor(&self) -> EffectDescriptor {
        EffectDescriptor::new("metrics.ping", json!({}))
    }
    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::never()
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        Ok(json!({ "pong": true }))
    }
}

#[derive(Debug)]
struct Pinger;

#[async_trait::async_trait]
impl Skill for Pinger {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("ping").provides("ping")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Ping).await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "ok": true }))))
    }
}

#[derive(Debug)]
struct NeedsApproval;

#[async_trait::async_trait]
impl Skill for NeedsApproval {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("approve").provides("approve")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _i: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.deadline("approval", &DeadlineSpec::days(2), None)
            .await?;
        let spec = TaskSpec::new(
            "approval",
            Justification::new("needs a person", json!({})),
            "approval",
        )
        .role("ops")
        .on_expiry(OnExpiry::Deny);
        cx.task(&spec).await?;
        Ok(Outcome::done(Tainted::trusted(json!({}))))
    }
}

fn store() -> Arc<SqliteStore> {
    Arc::new(SqliteStore::open_in_memory().unwrap())
}

fn runtime(s: &Arc<SqliteStore>) -> Runtime {
    Runtime::builder(Arc::clone(s) as Arc<dyn JournalStore>)
        .cases(Arc::clone(s) as Arc<dyn CaseStore>)
        .tasks(Arc::clone(s) as Arc<dyn TaskStore>)
        .timers(Arc::clone(s) as Arc<dyn TimerStore>)
        .skill(Pinger)
        .build()
}

fn t(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).unwrap()
}

// ── Counters ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_run_reports_its_outcome_and_its_effects() {
    let meter = Meter::default();
    let db = store();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(meter.clone());
    runtime(&db).run("ping", json!({})).await.unwrap();
    drop(guard);

    let runs = meter.named(metrics::RUNS.name);
    assert_eq!(runs.len(), 1, "one run, one terminal count: {runs:?}");
    assert_eq!(runs[0].dim, "succeeded");
    assert_eq!(runs[0].kind, "counter");
    assert_eq!(runs[0].value, 1);

    let effects = meter.named(metrics::EFFECTS.name);
    assert_eq!(effects.len(), 1, "one effect performed: {effects:?}");
    assert_eq!(
        effects[0].dim, "metrics.ping",
        "the dimension is the effect kind, so 'which driver' is answerable"
    );
}

/// A replayed effect must not be counted as one performed against the world.
///
/// This is the metrics-side twin of `agentplane.effect.replayed`: without the
/// split, "effects performed" doubles every time a run is audited, and cost
/// attribution built on it is wrong in the safe-looking direction.
#[tokio::test]
async fn a_replayed_effect_is_counted_separately_from_a_performed_one() {
    let db = store();
    let out = runtime(&db).run("ping", json!({})).await.unwrap();

    let meter = Meter::default();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(meter.clone());
    runtime(&db)
        .replay(out.run_id, agentplane::runtime::Mode::Strict)
        .await
        .unwrap();
    drop(guard);

    assert_eq!(
        meter.total(metrics::EFFECTS.name),
        0,
        "a replay performs nothing, so it must report no performed effects"
    );
    assert_eq!(
        meter.total(metrics::EFFECTS_REPLAYED.name),
        1,
        "the journal read is reported, under its own instrument"
    );
}

// ── Gauges ──────────────────────────────────────────────────────────────────

/// The reading that finally consumes a case's `opened_at`.
///
/// A count alone cannot distinguish ten cases open for an hour from ten open for
/// a month, which is the difference between a healthy plane and a stuck one.
#[tokio::test]
async fn the_census_reports_open_cases_and_how_long_the_oldest_has_waited() {
    let db = store();
    let rt = runtime(&db);

    let empty = rt.census(t(10_000)).await.unwrap();
    assert_eq!(empty.open_cases, 0);
    assert_eq!(
        empty.oldest_case_age_secs, None,
        "no open case is not an age of zero — zero means one was opened this \
         instant, and an empty plane is not that"
    );

    db.correlate_or_open("gpke", &[CorrelationKey::new("k", "1")], t(1_000))
        .await
        .unwrap();
    db.correlate_or_open("gpke", &[CorrelationKey::new("k", "2")], t(5_000))
        .await
        .unwrap();

    let c = rt.census(t(10_000)).await.unwrap();
    assert_eq!(c.open_cases, 2);
    assert_eq!(
        c.oldest_case_age_secs,
        Some(9_000),
        "the age is the *oldest* case's, not the newest's"
    );
}

/// A closed case leaves the gauge, and the age follows the remaining oldest.
#[tokio::test]
async fn closing_a_case_moves_the_gauge_and_the_age_with_it() {
    let db = store();
    let rt = runtime(&db);

    let old = db
        .correlate_or_open("k", &[CorrelationKey::new("k", "old")], t(1_000))
        .await
        .unwrap();
    db.correlate_or_open("k", &[CorrelationKey::new("k", "new")], t(8_000))
        .await
        .unwrap();

    db.close(old.case_id()).await.unwrap();

    let c = rt.census(t(10_000)).await.unwrap();
    assert_eq!(c.open_cases, 1, "a closed case is not open");
    assert_eq!(
        c.oldest_case_age_secs,
        Some(2_000),
        "the age must track the oldest *remaining* case — a gauge that kept \
         reporting the closed one would show a backlog that no longer exists"
    );
}

/// The gauge counts everything, not one page of it.
///
/// Reading a gauge from a `limit`-bounded list is the specific bug this method
/// exists to avoid: the number rises, flattens at the page size, and looks like
/// a plateau rather than a backlog.
#[tokio::test]
async fn the_census_is_not_bounded_by_a_page_size() {
    let db = store();
    let rt = runtime(&db);
    for i in 0..250 {
        db.correlate_or_open("bulk", &[CorrelationKey::new("n", i.to_string())], t(1_000))
            .await
            .unwrap();
    }
    assert_eq!(rt.census(t(2_000)).await.unwrap().open_cases, 250);
}

#[tokio::test]
async fn the_census_reports_humans_the_plane_is_waiting_on() {
    let db = store();
    let rt = Runtime::builder(Arc::clone(&db) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&db) as Arc<dyn CaseStore>)
        .tasks(Arc::clone(&db) as Arc<dyn TaskStore>)
        .timers(Arc::clone(&db) as Arc<dyn TimerStore>)
        .events(Arc::clone(&db) as Arc<dyn agentplane::case::EventStore>)
        .skill(NeedsApproval)
        .build();

    assert_eq!(rt.census(t(1_000)).await.unwrap().open_tasks, 0);

    let out = rt
        .run_in_case(
            "approve",
            json!({}),
            "approval",
            &[CorrelationKey::new("req", "1")],
        )
        .await
        .unwrap();
    assert!(
        out.status.is_suspended(),
        "the run should be waiting on a person: {:?}",
        out.status
    );

    assert_eq!(
        rt.census(t(1_000)).await.unwrap().open_tasks,
        1,
        "a run suspended on a human decision is a decision the plane is \
         waiting on, and the gauge is how anyone finds out"
    );
}

/// A sweep emits the gauges, so a plane that is merely idle still reports.
///
/// Without this, "open cases" stops updating whenever nothing happens — and a
/// stalled plane looks exactly like a quiet one on the dashboard.
#[tokio::test]
async fn a_sweep_emits_every_gauge() {
    let db = store();
    db.correlate_or_open("k", &[CorrelationKey::new("k", "1")], t(1_000))
        .await
        .unwrap();

    let meter = Meter::default();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(meter.clone());
    runtime(&db)
        .sweep(t(2_000), time::Duration::hours(1))
        .await
        .unwrap();
    drop(guard);

    for i in metrics::CATALOGUE
        .iter()
        .filter(|i| i.kind == metrics::Kind::Gauge)
    {
        assert!(
            !meter.named(i.name).is_empty(),
            "gauge {} was not emitted by a sweep, so it only ever reports when \
             something else happens to run",
            i.name
        );
    }
    assert_eq!(meter.total(metrics::OPEN_CASES.name), 1);
    assert_eq!(meter.total(metrics::OLDEST_CASE_AGE.name), 1_000);
}

// ── The catalogue itself ────────────────────────────────────────────────────

/// Every sample matches its declared kind and unit.
///
/// Emission sites pass the instrument, so this cannot drift by hand — but it
/// can drift by a copy-pasted constant, which is the realistic mistake.
#[tokio::test]
async fn every_sample_matches_its_declaration() {
    let meter = Meter::default();
    let db = store();
    let _ambient = crate::ambient_subscriber();
    let guard = tracing::subscriber::set_default(meter.clone());
    runtime(&db).run("ping", json!({})).await.unwrap();
    runtime(&db)
        .sweep(t(2_000), time::Duration::hours(1))
        .await
        .unwrap();
    drop(guard);

    let samples = meter.samples();
    assert!(!samples.is_empty(), "nothing was emitted at all");
    for s in samples {
        let declared = metrics::CATALOGUE
            .iter()
            .find(|i| i.name == s.metric)
            .unwrap_or_else(|| panic!("emitted '{}', which is not in CATALOGUE", s.metric));
        assert_eq!(s.kind, declared.kind.as_str(), "kind for {}", s.metric);
        assert_eq!(s.unit, declared.unit, "unit for {}", s.metric);
        if declared.dimension.is_none() {
            assert!(
                s.dim.is_empty(),
                "{} declares no dimension but emitted dim={:?}",
                s.metric,
                s.dim
            );
        }
    }
}
