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
//! latency by driver" silently average real calls with journal reads. Every
//! span carries [`MODE`].
//!
//! For effects the marking is sharper than an attribute, and a bridge author
//! should know exactly what it is: **a replayed effect opens no span at all.**
//! It never reaches the world, so there is no duration to record; what it emits
//! instead is a `debug` **event** on the [`EFFECT_SPAN`] target carrying
//! `replayed = true`, plus the `agentplane.effects_replayed` counter. The
//! [`EFFECT_REPLAYED`] field on a live effect span is therefore always `false`,
//! and it is there so a collector filtering on one attribute name gets a
//! uniform answer rather than an absent field.
//!
//! The consequence is the one that matters: a span-derived latency histogram is
//! clean **by construction**, because replays contribute no spans to it. What a
//! bridge must not do is key on the *target* and treat every record on it as a
//! span — that view sees both, and it is the view in which replays contaminate
//! latency. `examples/observability.rs` does it the correct way and asserts on
//! the difference.
//!
//! # Semantic conventions
//!
//! OpenTelemetry's `GenAI` conventions still classify **agent spans as
//! Development**, and the June 2026 repository split confirms the work is
//! mid-flight rather than finished. Following `main` would mean silently
//! changing an operator's dashboards. So a pinned snapshot is vendored here and
//! exposed as [`SEMCONV_VERSION`]; upstream movement is a versioned migration,
//! not something that happens to you.
//!
//! # What is deliberately never emitted
//!
//! The conventions define Opt-In attributes that carry the content of a call:
//! `gen_ai.input.messages`, `gen_ai.output.messages`,
//! `gen_ai.system_instructions`, `gen_ai.tool.definitions` and
//! `gen_ai.tool.call.arguments`. This crate emits none of them, and the decision
//! is not a default anyone may flip: a prompt is exactly the place governed
//! values arrive, the sink gates exist to keep those values inside a declared
//! ceiling, and a trace exporter is an egress the gates do not cover. Sensitivity
//! is a property of the value, and a span is not a sink that can carry one.
//!
//! What a deployment gets instead is the shape of the call — who was asked, what
//! it cost, which tool ran, how it ended — and the journal for the content, where
//! the same values are sealed, labelled and erasable.
//!
//! Three more the convention defines that this plane does not emit, each for its
//! own reason. `gen_ai.response.id`, because no shared part of a [`Completion`]
//! carries one. `gen_ai.provider.name` on the **run** span, because the agent is
//! executed here rather than served by anyone — the completion spans beneath it
//! each name the provider that answered them. And `server.address`, because a
//! driver's endpoint is deployment configuration that is identical for every call
//! it makes: that belongs on the `OTel` *resource*, which the embedder owns,
//! rather than repeated on every span this crate opens.
//!
//! [`Completion`]: crate::model::Completion

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
/// The model that answered, as the provider reported it.
///
/// Absent where the wire does not say — never filled from the request, which
/// would report a substitution had been ruled out when nothing looked.
pub const GEN_AI_RESPONSE_MODEL: &str = "gen_ai.response.model";
/// Why generation stopped, in the provider's own words.
///
/// The convention's name is plural because a provider may return several
/// candidates. A [`Completion`](crate::model::Completion) carries exactly one
/// answer and therefore one reason, so the attribute holds a single value.
pub const GEN_AI_FINISH_REASON: &str = "gen_ai.response.finish_reasons";
/// Prompt tokens billed.
pub const GEN_AI_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
/// Completion tokens billed.
pub const GEN_AI_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
/// Of the prompt tokens, how many came from a provider-managed cache.
///
/// Recorded because the *rate* differs by about a factor of ten: a panel adding
/// input tokens alone over-states a heavily cached deployment's bill on exactly
/// the portion it is cheapest on.
pub const GEN_AI_CACHE_READ_TOKENS: &str = "gen_ai.usage.cache_read.input_tokens";
/// Of the prompt tokens, how many were written into that cache — billed at a
/// premium over ordinary input, which is the other half of the same argument.
pub const GEN_AI_CACHE_WRITE_TOKENS: &str = "gen_ai.usage.cache_write.input_tokens";
/// The tool a call named, for `execute_tool` spans.
pub const GEN_AI_TOOL_NAME: &str = "gen_ai.tool.name";
/// Which declaration a run is executing.
///
/// The convention's name for it, rather than one in this crate's namespace: an
/// agent's name is a fact the convention already defines, and a second spelling
/// is read by nothing generic.
pub const GEN_AI_AGENT_NAME: &str = "gen_ai.agent.name";
/// The thread a run belongs to — this plane's case.
///
/// A case is what the A2A surface already answers `contextId` with, and
/// `contextId` is that protocol's conversation identifier, so the mapping is not
/// this crate's invention.
pub const GEN_AI_CONVERSATION_ID: &str = "gen_ai.conversation.id";

/// The class of fault an attempt ended with, from `OpenTelemetry`'s own
/// cross-signal attribute rather than a `GenAI` one.
///
/// Separate from [`OUTCOME`], which says *whether* an attempt succeeded. This
/// says what went wrong, in the vocabulary [`EffectError`] classifies faults
/// with — so "which driver fails how" is a group-by rather than a search
/// through free text.
///
/// [`EffectError`]: crate::core::EffectError
pub const ERROR_TYPE: &str = "error.type";

pub const RUN_ID: &str = "agentplane.run.id";
/// Which tenant's plane produced this run, under [`TenantLabel`].
///
/// Absent under the default policy, which is what `Omitted` means — not an empty
/// string, so a collector cannot mistake *not disclosed* for *no tenant*.
pub const TENANT: &str = "agentplane.tenant";
/// Which `GenAI` convention snapshot produced this trace.
pub const SEMCONV: &str = "agentplane.semconv";
/// `live` | `resume` | `strict` — see the module docs on why this is on
/// every span.
pub const MODE: &str = "agentplane.mode";
pub const STEP: &str = "agentplane.step.id";
pub const CAPABILITY: &str = "agentplane.step.capability";
/// `forward` | `compensating`.
pub const PHASE: &str = "agentplane.phase";
pub const EFFECT_KIND: &str = "agentplane.effect.kind";
/// The journal's own identity for this attempt.
///
/// The join between a trace and the evidence. Everything else on the span names
/// a *category* — which run, which step, which kind — and none of them lands a
/// reader on the record that attempt wrote; `GET /runs/{run}/history` answers by
/// key. Without it the two histories of one run can only be lined up by eye.
///
/// A digest over the step, phase, ordinal, attempt, kind and canonical
/// arguments. It **names** the attempt without carrying what it sent — which is
/// the claim to make, since a digest is still a commitment to the values it was
/// taken over and anyone holding a guess can test it.
pub const EFFECT_KEY: &str = "agentplane.effect.key";
pub const EFFECT_ATTEMPT: &str = "agentplane.effect.attempt";
pub const EFFECT_MUTATES: &str = "agentplane.effect.mutates";
/// True when the result came from the journal rather than from the world.
///
/// Without this, "effect latency by driver" averages real calls with journal
/// reads and means nothing.
pub const EFFECT_REPLAYED: &str = "agentplane.effect.replayed";
pub const OUTCOME: &str = "agentplane.outcome";

// ── Tenant attribution ──────────────────────────────────────────────────────

/// Whether and how a tenant appears on what this plane reports about itself.
///
/// Two separate problems, and a design that answers only one of them is worse
/// than none.
///
/// **Cardinality.** An unbounded label is what makes a metrics backend fall
/// over, and a tenant read from a *request* would be exactly that. This label is
/// the plane's own tenant, so the number of streams is the number of planes an
/// operator configured — a configuration fact, not a data fact. There is no
/// input that can grow it.
///
/// One policy for **both** signals. A deployment that decides customer names may
/// travel to its observability stack has decided it once, and answering *which
/// tenant is this* on the metrics while leaving it unanswerable on the traces is
/// the same decision honoured on one channel.
///
/// **Disclosure.** A tenant name is frequently a customer name, and a metrics
/// backend is usually the least protected system in a deployment: sampled into
/// third-party services, on a dashboard nobody signs into, retained past every other
/// record. So the default is to emit nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenantLabel {
    /// No tenant dimension at all. The default.
    ///
    /// A single-tenant plane learns nothing from the label, and a deployment
    /// that has not decided where its telemetry goes has not decided that
    /// customer names may travel there.
    #[default]
    Omitted,
    /// The tenant's own name.
    ///
    /// Appropriate when the tenant id is not itself sensitive — an operator's own
    /// environments, or ids that were opaque to begin with. On the metrics it is
    /// the `tenant` field of every event; on the traces it is [`TENANT`] on the
    /// run span, and only there — every other span is inside that run's trace,
    /// so repeating a per-plane constant on each of them is bytes without
    /// information.
    Name,
}

impl TenantLabel {
    /// The label for this tenant under this policy.
    #[must_use]
    pub fn render(self, tenant: &crate::core::TenantId) -> String {
        match self {
            Self::Omitted => String::new(),
            Self::Name => tenant.to_string(),
        }
    }
}

// ── Events: the ones P7 exists for ──────────────────────────────────────────

/// Replay recomputed a different effect key than the journal holds.
pub const NONDETERMINISM: &str = "agentplane.run.nondeterminism_detected";
/// A run was set aside for a human.
pub const QUARANTINED: &str = "agentplane.run.quarantined";
/// A person closed a run whose outcome could never be established.
///
/// The end of the road for a quarantine nobody could answer, and it fires
/// **because nothing was unwound**: what the run left in the world stays there,
/// and the doubt is permanent. The person who decided that already knows; this
/// is for everybody else — the party who answers for an unexplained mutation is
/// rarely the operator holding the pager at 3 a.m., and an intervention visible
/// only to whoever made it is not oversight.
///
/// The lasting record is the `agentplane audit` finding, which is derived from
/// the journal and outlives every status. This is the notification that the
/// finding now exists.
pub const ABANDONED: &str = "agentplane.run.abandoned";
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
/// A read pinned by digest or version came back different.
///
/// Names one run, and says nothing about which *others* read the same version —
/// only an audit answers that, which is what this event exists to start.
pub const UNREPRODUCIBLE: &str = "agentplane.run.unreproducible";
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
/// A witness refused this plane's checkpoint on integrity grounds.
///
/// The log shrank, forked, or claimed growth a witness could not verify — the
/// one class of event nothing inside this plane can detect, because every
/// input to the chain, the signatures and the Merkle log comes from the party
/// an auditor is being asked to trust.
///
/// Loud for a reason no other event here has: the audience is *not* the
/// operator running the plane. A witness reporting that this history moved is
/// the finding whoever operates it has the strongest interest in nobody
/// hearing, so it goes to the same channel every other unexplained mutation
/// does rather than staying in a sweep report the plane's own operator reads.
/// It fires even when the declared quorum was met — two honest cosigners do
/// not answer a third that remembers a different history.
pub const WITNESS_INTEGRITY: &str = "agentplane.witness.integrity";

/// Every event name P7 promises, for the guard in `tests/guards/layering.rs`.
///
/// A constant nobody emits is the telemetry equivalent of a dead API: the
/// dashboard has a panel and the panel is always empty.
pub const LOUD_EVENTS: &[&str] = &[
    NONDETERMINISM,
    QUARANTINED,
    ABANDONED,
    RUN_FAILED,
    UNDECIDABLE,
    UNREPRODUCIBLE,
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
    WITNESS_INTEGRITY,
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
