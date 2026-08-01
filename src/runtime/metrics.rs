//! The metric catalogue: what a plane reports about itself, declared once.
//!
//! # Why the runtime does not measure durations
//!
//! The obvious metric set starts with "run duration" and "effect latency", and
//! the obvious implementation reads a clock at both ends. This crate cannot do
//! that, and the constraint turns out to be the right design rather than an
//! obstacle to work around.
//!
//! Ambient clocks are lint-denied crate-wide (`clippy.toml`), with three named
//! escapes, each for a value that gets journaled or is store metadata. A fourth
//! escape *for instrumentation* would be the moment the rule stopped meaning
//! anything, because timing is exactly the plausible-sounding reason someone
//! reaches for a clock. And a replayed run would re-measure durations that
//! belong to a call it did not make, so "effect latency by driver" would average
//! real network time with journal reads — the same failure `EFFECT_REPLAYED`
//! exists to prevent, arriving through the metrics door.
//!
//! So: **durations are derived from spans, by the collector.** Every `OTel`,
//! Prometheus, and Datadog bridge already computes span duration; the runtime's
//! job is to emit correctly named, correctly attributed, correctly nested spans,
//! which `runtime::telemetry` does. `agentplane.run`, `agentplane.step`, and
//! `agentplane.effect` carry `agentplane.mode` and `agentplane.effect.replayed`,
//! so a collector can compute latency *and* exclude replays, which a naive
//! in-crate histogram could not.
//!
//! What is left is what a clock cannot give you anyway:
//!
//! | Family | Needs | How |
//! |---|---|---|
//! | Counters | nothing | emitted where the thing happens |
//! | Gauges | current state | [`Census`], queried with a `now` passed in |
//!
//! # Why gauges are observed, not accumulated
//!
//! "Open cases" cannot be counted by incrementing on open and decrementing on
//! close. A counter drifts: a crash between the state change and the emission
//! loses a decrement forever, and the dashboard slowly invents open cases that
//! do not exist. Worse, it is *plausibly* wrong — nothing looks broken.
//!
//! A gauge that matters is queried from the state that is authoritative, which
//! here is the store. [`Census`] is that query, and the sweeper — which already
//! runs periodically and already takes its `now` as a parameter — is what emits
//! it. No clock is read and nothing accumulates.
//!
//! # The catalogue is not a wish list
//!
//! Every instrument here is emitted by something. That rule is the whole reason
//! `runtime::telemetry` exists as a module rather than as string literals, and
//! it applies with more force to metrics: a declared-but-unemitted *event* is a
//! panel that stays empty, while a declared-but-unemitted *counter* reads as a
//! hard zero. An operator cannot tell "this never happens" from "nothing reports
//! it", and the second one is how an incident stays invisible.
//!
//! `tests/guards/layering.rs` fails the build if an entry in [`CATALOGUE`] has no
//! emitter, and `tests/guards/metrics.rs` asserts on what a subscriber actually
//! received.
//!
//! # Wire format
//!
//! Metrics are `tracing` events on the [`METRIC`] target, so the crate picks no
//! exporter for its embedder — the same decision the tracing layer makes. Fields
//! are fixed: `metric`, `kind`, `unit`, `value`, and `dim`. The *meaning* of
//! `dim` is declared per instrument in [`Instrument::dimension`], so a bridge
//! reads the catalogue once and knows the label name for every stream.

use crate::core::Timestamp;

/// The `tracing` target every metric event carries.
///
/// A dedicated target rather than a naming convention: a subscriber filters
/// metrics from logs by target, which is a cheap static check, instead of by
/// inspecting fields on every event.
pub const METRIC: &str = "agentplane.metric";

/// What a backend should build from a metric stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Monotonic count of occurrences. `value` is the increment, normally 1.
    Counter,
    /// A current reading, valid only at the instant it was observed.
    Gauge,
}

impl Kind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

/// One declared instrument.
#[derive(Debug, Clone, Copy)]
pub struct Instrument {
    pub name: &'static str,
    pub kind: Kind,
    /// UCUM-style unit, or `"1"` for a dimensionless count.
    pub unit: &'static str,
    /// The label carried in the event's `dim` field, if this instrument has one.
    ///
    /// Declared here rather than at the call site so a collector learns every
    /// stream's label name from the catalogue instead of guessing from samples.
    pub dimension: Option<&'static str>,
    pub description: &'static str,
}

// ── Counters ────────────────────────────────────────────────────────────────

pub const RUNS: Instrument = Instrument {
    name: "agentplane.runs",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("outcome"),
    description: "Runs that reached a terminal status. The dimension is that status, \
                  so 'how many failed' needs no second instrument.",
};

pub const EFFECTS: Instrument = Instrument {
    name: "agentplane.effects",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("kind"),
    description: "Effect attempts dispatched to the world. A retry counts again.",
};

pub const EFFECTS_REPLAYED: Instrument = Instrument {
    name: "agentplane.effects.replayed",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("kind"),
    description: "Effect results served from the journal rather than performed.",
};

pub const DIVERGENCES: Instrument = Instrument {
    name: "agentplane.replay.divergences",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Replays that recomputed a different effect key than the journal holds.",
};

pub const QUARANTINES: Instrument = Instrument {
    name: "agentplane.quarantines",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Runs set aside for a human because an outcome could not be \
                  determined and guessing was forbidden. Never self-healing: this \
                  number only falls when someone acts.",
};

pub const UNDECIDABLE: Instrument = Instrument {
    name: "agentplane.effects.undecidable",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Effect outcomes that could not be determined and where guessing was forbidden.",
};

pub const RECONCILIATIONS: Instrument = Instrument {
    name: "agentplane.effects.reconciled",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("verdict"),
    description: "Unknown outcomes resolved by asking the provider.",
};

pub const BUDGET_REFUSALS: Instrument = Instrument {
    name: "agentplane.budget.refusals",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("limit"),
    description: "Operations refused by a limit before they started.",
};

pub const COMPENSATIONS: Instrument = Instrument {
    name: "agentplane.saga.compensations",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("outcome"),
    description: "Completed steps undone during an unwind, by whether the \
                  compensation itself succeeded. A failed one leaves the run \
                  partly unwound and is the loudest thing here.",
};

pub const DEAD_LETTERS: Instrument = Instrument {
    name: "agentplane.events.dead_lettered",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Events that aged out with nobody waiting — a correlation bug somewhere.",
};

pub const DEADLINE_BREACHES: Instrument = Instrument {
    name: "agentplane.deadlines.breached",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Obligations whose instant passed with the obligation unmet. \
                  A regulatory window that closed, counted at the moment it closed \
                  rather than when someone noticed.",
};

pub const TIMERS_FIRED: Instrument = Instrument {
    name: "agentplane.timers.fired",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Durable wake-ups delivered to sleeping runs. Not a fault: a \
                  fired timer is the system working, reported so a quiet plane is \
                  distinguishable from a stalled one.",
};

pub const REPLANS: Instrument = Instrument {
    name: "agentplane.replans",
    kind: Kind::Counter,
    unit: "1",
    dimension: None,
    description: "Runs that replaced their plan with a versioned successor. \
                  Rising sharply means plans are being written that do not survive \
                  contact with their own first step.",
};

pub const POLICY_DENIALS: Instrument = Instrument {
    name: "agentplane.policy.denials",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("action"),
    description: "Actions refused by the authorization layer before they were \
                  attempted. A denial is not a fault — it is the policy working — \
                  but a sudden rise means an agent is asking for something new.",
};

pub const BATCH_ITEMS: Instrument = Instrument {
    name: "agentplane.batch.items",
    kind: Kind::Counter,
    unit: "1",
    dimension: Some("outcome"),
    description: "Batch items that reached an outcome. The dimension is what makes \
                  partial failure visible without reading every item record.",
};

// ── Gauges ──────────────────────────────────────────────────────────────────

pub const OPEN_CASES: Instrument = Instrument {
    name: "agentplane.cases.open",
    kind: Kind::Gauge,
    unit: "1",
    dimension: None,
    description: "Cases not yet closed. Read with the oldest-age gauge: a count \
                  alone cannot distinguish a healthy queue from a stuck one.",
};

pub const OLDEST_CASE_AGE: Instrument = Instrument {
    name: "agentplane.cases.oldest_age",
    kind: Kind::Gauge,
    unit: "s",
    dimension: None,
    description: "Age of the longest-open case. A backlog that is quietly ageing is \
                  invisible in a count alone: ten cases open for an hour and ten open \
                  for a month are the same number.",
};

pub const DUE_DEADLINES: Instrument = Instrument {
    name: "agentplane.deadlines.due",
    kind: Kind::Gauge,
    unit: "1",
    dimension: None,
    description: "Obligations at or past their instant and not yet resolved.",
};

pub const PENDING_TIMERS: Instrument = Instrument {
    name: "agentplane.timers.pending",
    kind: Kind::Gauge,
    unit: "1",
    dimension: None,
    description: "Runs sleeping on a durable timer. Each costs a row, not a \
                  thread, so a large number here is capacity rather than load.",
};

pub const OPEN_TASKS: Instrument = Instrument {
    name: "agentplane.tasks.open",
    kind: Kind::Gauge,
    unit: "1",
    dimension: None,
    description: "Human decisions awaiting an answer, including claimed ones. A \
                  reviewer opening a task does not reduce the backlog; answering \
                  it does.",
};

/// Every instrument this crate emits.
///
/// Guarded in `tests/guards/layering.rs`: an entry with no emitter fails the build.
pub const CATALOGUE: &[Instrument] = &[
    RUNS,
    EFFECTS,
    EFFECTS_REPLAYED,
    DIVERGENCES,
    QUARANTINES,
    UNDECIDABLE,
    RECONCILIATIONS,
    BUDGET_REFUSALS,
    COMPENSATIONS,
    DEAD_LETTERS,
    DEADLINE_BREACHES,
    TIMERS_FIRED,
    REPLANS,
    BATCH_ITEMS,
    POLICY_DENIALS,
    OPEN_CASES,
    OLDEST_CASE_AGE,
    DUE_DEADLINES,
    PENDING_TIMERS,
    OPEN_TASKS,
];

/// Emit a counter occurrence.
pub(crate) fn count(i: Instrument, dim: &str) {
    tracing::info!(
        target: METRIC,
        metric = i.name,
        kind = i.kind.as_str(),
        unit = i.unit,
        value = 1_u64,
        dim,
    );
}

/// Emit several occurrences at once.
///
/// A sweep retires a whole batch of dead letters in one pass; emitting the batch
/// as one event with `value = n` keeps the counter honest without pretending the
/// sweep saw them one at a time.
pub(crate) fn count_by(i: Instrument, dim: &str, by: u64) {
    tracing::info!(
        target: METRIC,
        metric = i.name,
        kind = i.kind.as_str(),
        unit = i.unit,
        value = by,
        dim,
    );
}

/// Emit a gauge reading.
pub(crate) fn gauge(i: Instrument, value: u64) {
    tracing::info!(
        target: METRIC,
        metric = i.name,
        kind = i.kind.as_str(),
        unit = i.unit,
        value,
        dim = "",
    );
}

/// A point-in-time reading of everything a plane is holding.
///
/// Assembled by querying the stores rather than by accumulating deltas — see the
/// module docs on why an incremented gauge drifts.
///
/// `now` is a parameter for the same reason the sweeper's is: a census that read
/// the clock itself could not be tested against a year of ageing obligations,
/// and would need an escape from the determinism gate to exist at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Census {
    pub open_cases: u64,
    /// Seconds since the longest-open case was opened, or `None` if none are open.
    pub oldest_case_age_secs: Option<u64>,
    pub due_deadlines: u64,
    pub pending_timers: u64,
    pub open_tasks: u64,
}

impl Census {
    /// Emit every gauge in this reading.
    ///
    /// `oldest_case_age_secs` is skipped when no case is open, rather than
    /// reported as zero: zero is a real reading meaning "a case was opened this
    /// instant", and an empty plane is not that.
    pub fn emit(&self) {
        gauge(OPEN_CASES, self.open_cases);
        if let Some(age) = self.oldest_case_age_secs {
            gauge(OLDEST_CASE_AGE, age);
        }
        gauge(DUE_DEADLINES, self.due_deadlines);
        gauge(PENDING_TIMERS, self.pending_timers);
        gauge(OPEN_TASKS, self.open_tasks);
    }
}

/// Seconds between two instants, floored at zero.
///
/// A case opened "in the future" is a clock-skew artefact across writers, not a
/// negative age. Reporting it as a large unsigned number would be worse than
/// reporting zero.
#[must_use]
pub fn age_secs(opened_at: Timestamp, now: Timestamp) -> u64 {
    u64::try_from(now.unix_timestamp() - opened_at.unix_timestamp()).unwrap_or(0)
}
