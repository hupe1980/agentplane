//! The observability vocabulary, defined once.
//!
//! # Why the names live here and not at the call sites
//!
//! A span or event name typed inline at twelve call sites is twelve chances to
//! drift, and drift in telemetry is invisible: the dashboard simply stops
//! matching and nobody is told. These constants are the contract, and
//! `tests/guards/layering.rs` checks that every event P7 promises is actually emitted
//! by something.
//!
//! Span names, event names, and *span* attribute keys are taken from these
//! constants at every call site. Field names inside `tracing` **events** are
//! short idents instead — the event macro accepts only idents there, not
//! computed keys — so an event's semantic identity lives in its `target`, which
//! is a constant. That is the whole reason events are targeted rather than
//! merely named.
//!
//! # What is instrumented, and why that set
//!
//! Principle P7 is *no silent anything*. The failures this runtime exists to
//! surface — divergence, an undecidable outcome, a refused budget, a
//! compensation that could not run, an event nobody claimed — are exactly the
//! ones that otherwise present as a process quietly not finishing. Each has a
//! dedicated event here, so "did this happen" is a query rather than an
//! archaeology exercise over logs.
//!
//! # Replay is marked, always
//!
//! A replayed run re-executes its skills, so it emits spans again. Without a
//! mode attribute an operator sees each run twice and metrics like "effect
//! latency by driver" silently average real calls with journal reads. Every span
//! carries [`MODE`], and every effect span carries [`EFFECT_REPLAYED`].
//!
//! # Semantic conventions
//!
//! OpenTelemetry's `GenAI` conventions still classify **agent spans as
//! Development**, and the June 2026 repository split confirms the work is
//! mid-flight rather than finished. Following `main` would mean silently
//! changing an operator's dashboards. So a pinned snapshot is vendored here and
//! exposed as [`SEMCONV_VERSION`]; upstream movement is a versioned migration,
//! not something that happens to you.

/// The pinned `GenAI` semantic-convention snapshot these names follow.
///
/// Emitted on the run span so a collector can tell which vocabulary produced a
/// trace, and so a future change is a visible migration rather than a silent
/// reinterpretation of old data.
pub const SEMCONV_VERSION: &str = "genai-2026-07-28/development";

// ── Span names ──────────────────────────────────────────────────────────────

/// One per run. The trace root.
pub const RUN_SPAN: &str = "agentplane.run";
/// One per step execution, including a compensating pass.
pub const STEP_SPAN: &str = "agentplane.step";
/// One per effect *attempt*, so a retried call shows as several.
pub const EFFECT_SPAN: &str = "agentplane.effect";

// ── Attributes ──────────────────────────────────────────────────────────────

/// From the `GenAI` conventions: this span is an agent invocation.
pub const GEN_AI_OPERATION: &str = "gen_ai.operation.name";
/// The value of [`GEN_AI_OPERATION`] for a run.
pub const GEN_AI_INVOKE_AGENT: &str = "invoke_agent";
/// The value of [`GEN_AI_OPERATION`] for a tool call.
pub const GEN_AI_EXECUTE_TOOL: &str = "execute_tool";
/// The value of [`GEN_AI_OPERATION`] for a model completion.
pub const GEN_AI_CHAT: &str = "chat";

/// Which provider served a completion — `anthropic`, `openai`.
pub const GEN_AI_PROVIDER: &str = "gen_ai.provider.name";
/// The model asked for, which is not always the model that answered.
pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";
/// The model that actually answered, as the provider reported it.
pub const GEN_AI_RESPONSE_MODEL: &str = "gen_ai.response.model";
/// Prompt tokens billed.
pub const GEN_AI_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
/// Completion tokens billed.
pub const GEN_AI_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
/// The tool a call named, for `execute_tool` spans.
pub const GEN_AI_TOOL_NAME: &str = "gen_ai.tool.name";

pub const RUN_ID: &str = "agentplane.run.id";
pub const CASE_ID: &str = "agentplane.case.id";
pub const AGENT: &str = "agentplane.agent";
/// `live` | `resume` | `strict` — see the module docs on why this is on
/// every span.
pub const MODE: &str = "agentplane.mode";
pub const STEP: &str = "agentplane.step.id";
pub const CAPABILITY: &str = "agentplane.step.capability";
/// `forward` | `compensating`.
pub const PHASE: &str = "agentplane.phase";
pub const EFFECT_KIND: &str = "agentplane.effect.kind";
pub const EFFECT_ATTEMPT: &str = "agentplane.effect.attempt";
pub const EFFECT_MUTATES: &str = "agentplane.effect.mutates";
/// True when the result came from the journal rather than from the world.
///
/// Without this, "effect latency by driver" averages real calls with journal
/// reads and means nothing.
pub const EFFECT_REPLAYED: &str = "agentplane.effect.replayed";
pub const OUTCOME: &str = "agentplane.outcome";

// ── Events: the ones P7 exists for ──────────────────────────────────────────

/// Replay recomputed a different effect key than the journal holds.
pub const NONDETERMINISM: &str = "agentplane.run.nondeterminism_detected";
/// A run was set aside for a human.
pub const QUARANTINED: &str = "agentplane.run.quarantined";
/// A run concluded `failed`, with the reason it gives an operator.
///
/// A failure is an ordinary conclusion here rather than an incident — it stays
/// open, findable under `GET /runs?outcome=failed`, and resumable. But *ordinary*
/// is not *invisible*: an operator running the shipped server had no way at all
/// to learn why a run failed, because the outcome index needs the HTTP surface
/// and the reason otherwise reached only the journal. That is I13's
/// detection-without-delivery on the most common conclusion there is. The
/// reason string is the same one the outcome index already hands an operator,
/// so this discloses nothing new — it delivers it to somebody watching.
pub const RUN_FAILED: &str = "agentplane.run.failed";
/// An outcome could not be determined and guessing was forbidden.
pub const UNDECIDABLE: &str = "agentplane.effect.undecidable";
/// A probe was asked whether a call landed.
pub const RECONCILED: &str = "agentplane.effect.reconciled";
/// A limit refused an operation before it started.
pub const BUDGET_REFUSED: &str = "agentplane.budget.refused";
/// A completed step was undone.
pub const COMPENSATED: &str = "agentplane.saga.compensated";
/// A compensation failed, leaving the run partly unwound.
pub const COMPENSATION_FAILED: &str = "agentplane.saga.compensation_failed";
/// An event aged out with nobody waiting for it — a correlation bug somewhere.
pub const DEAD_LETTERED: &str = "agentplane.event.dead_lettered";
/// An obligation passed unmet.
pub const DEADLINE_BREACHED: &str = "agentplane.deadline.breached";
/// A sleeping run's instant arrived.
pub const TIMER_FIRED: &str = "agentplane.timer.fired";
/// A run an instance died holding was taken over and resumed.
pub const RUN_RECOVERED: &str = "agentplane.run.recovered";
/// Policy refused an action before it was attempted.
pub const POLICY_DENIED: &str = "agentplane.policy.denied";
/// A run changed its plan; the successor is journaled beside its predecessor.
pub const REPLANNED: &str = "agentplane.run.replanned";

/// Every event name P7 promises, for the guard in `tests/guards/layering.rs`.
///
/// A constant nobody emits is the telemetry equivalent of a dead API: the
/// dashboard has a panel and the panel is always empty.
pub const LOUD_EVENTS: &[&str] = &[
    NONDETERMINISM,
    QUARANTINED,
    UNDECIDABLE,
    RECONCILED,
    BUDGET_REFUSED,
    COMPENSATED,
    COMPENSATION_FAILED,
    DEAD_LETTERED,
    DEADLINE_BREACHED,
    TIMER_FIRED,
    RUN_RECOVERED,
    REPLANNED,
    POLICY_DENIED,
];

/// How a run is being executed, as a span attribute.
#[must_use]
pub const fn mode_str(mode: super::Mode) -> &'static str {
    match mode {
        super::Mode::Live => "live",
        super::Mode::Resume => "resume",
        super::Mode::Strict => "strict",
    }
}
