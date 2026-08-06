//! Calling a model.
//!
//! A completion is an effect like any other — journaled once, replayed from the
//! record, untrusted on the way back. What is different is the meter.
//!
//! # A failed completion is not a free one
//!
//! Every other outward call this crate makes either happens or does not. A model
//! call has a third state: it ran, generated four hundred tokens, and then the
//! stream died. The provider will bill those tokens. The answer is unusable.
//!
//! Two consequences, and both are easy to get backwards.
//!
//! **The spend must be reported anyway.** [`EffectError::Metered`] carries what
//! was consumed, and the runtime bills it on the failure path. Without that, the
//! token and cost ceilings — the ones that exist to bound exactly this — count
//! zero while a retry loop against a flaky provider spends real money.
//!
//! **A died-mid-stream call is [`Disposition::Landed`], not `InDoubt`.** The
//! usual reasoning about reaching the peer is inverted here: we know perfectly
//! well that it reached the provider, because we watched it generate. What we
//! lack is the *answer*, and repeating the call buys a second bill for the same
//! question. `InDoubt` would invite [`Recovery`] to resolve an outcome that is
//! not in doubt at all.
//!
//! # Determinism
//!
//! A model is the least deterministic thing a run touches, which is exactly why
//! the completion is journaled: replay reads the recorded answer rather than
//! asking again. The prompt is part of the effect key, so a changed prompt is a
//! changed effect and shows up as divergence rather than as a quietly different
//! run.

#[cfg(feature = "providers")]
pub mod anthropic;
#[cfg(feature = "providers")]
mod anthropic_stream;
#[cfg(feature = "bedrock")]
pub mod bedrock;
#[cfg(feature = "bedrock")]
mod bedrock_stream;
#[cfg(feature = "providers")]
pub mod chat_completions;
#[cfg(feature = "providers")]
mod chat_completions_stream;
#[cfg(feature = "providers")]
pub mod openai;
#[cfg(feature = "providers")]
mod openai_stream;
#[cfg(feature = "providers")]
mod sse;
#[cfg(feature = "providers")]
mod wire;

use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
#[cfg(feature = "media")]
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    Disposition, Effect, EffectDescriptor, EffectError, Recovery, RetryPolicy, Sensitivity, Spend,
    Trust,
};

#[cfg(any(feature = "manifest", feature = "providers", feature = "bedrock"))]
pub(crate) fn validate_schema(schema: &Value, value: &Value) -> Result<(), String> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|error| format!("the declared JSON Schema is invalid: {error}"))?;
    validator
        .validate(value)
        .map_err(|error| format!("value does not satisfy the declared JSON Schema: {error}"))
}

/// A provider-side media reference hidden inside a provider-native prompt.
///
/// Deliberately structural rather than a search for strings that look like
/// URLs. A user may ask a model to discuss a URL; the dangerous forms are the
/// content blocks that instruct the provider to dereference one. The built-in
/// drivers accept provider-native JSON, so both providers' spellings are
/// recognized here and the runtime applies the same hard cut to custom drivers.
fn provider_side_media_reference(value: &Value) -> Option<&'static str> {
    fn remote_url(value: Option<&Value>) -> bool {
        let url = value.and_then(|value| {
            value
                .as_str()
                .or_else(|| value.get("url").and_then(Value::as_str))
        });
        url.is_some_and(|url| !url.starts_with("data:"))
    }

    match value {
        Value::Array(values) => values.iter().find_map(provider_side_media_reference),
        Value::Object(object) => {
            let kind = object.get("type").and_then(Value::as_str);

            // Anthropic Messages: image/document source { type: "url", url: ... }.
            if matches!(kind, Some("image" | "document"))
                && object
                    .get("source")
                    .and_then(Value::as_object)
                    .is_some_and(|source| {
                        source.get("type").and_then(Value::as_str) == Some("url")
                            && source.get("url").and_then(Value::as_str).is_some()
                    })
            {
                return Some("an Anthropic image/document URL source");
            }

            // OpenAI Responses, plus the older image_url content-block spelling
            // accepted by compatible endpoints. A data URL carries bytes in the
            // request and is not a provider-side network fetch.
            if matches!(kind, Some("input_image" | "image_url"))
                && remote_url(object.get("image_url"))
            {
                return Some("an OpenAI image URL");
            }
            if kind == Some("input_file") && remote_url(object.get("file_url")) {
                return Some("an OpenAI file URL");
            }

            object.values().find_map(provider_side_media_reference)
        }
        _ => None,
    }
}

fn provider_side_media_refusal(kind: &str) -> String {
    format!(
        "{kind} was refused before dispatch: the model provider would fetch it outside \
         this plane's egress policy and journal; inline the media bytes, or fetch them \
         through an explicit governed effect first"
    )
}

pub(crate) fn refuse_provider_side_media(
    prompt: &Value,
    model: &ModelId,
) -> Result<(), ModelError> {
    let Some(kind) = provider_side_media_reference(prompt) else {
        return Ok(());
    };
    Err(ModelError::Refused {
        model: model.clone(),
        detail: provider_side_media_refusal(kind),
    })
}

/// Which model, from which provider.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModelId {
    pub provider: String,
    pub model: String,
}

impl ModelId {
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
        }
    }
}

impl std::fmt::Display for ModelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.provider, self.model)
    }
}

/// What a completion cost.
///
/// # Cached tokens are the trap
///
/// Prompt caching is the feature most likely to make a token ceiling lie, and it
/// lies in *both* directions depending on the provider:
///
/// * **Anthropic** reports `cache_creation_input_tokens` and
///   `cache_read_input_tokens` **alongside** `input_tokens`, which excludes
///   them. A driver that reads only `input_tokens` bills a cached call at close
///   to nothing while the provider charges a premium for the write and a tenth
///   of the rate for the read.
/// * **`OpenAI`** reports `input_tokens_details.cached_tokens` as a **subset** of
///   `input_tokens`. Adding it would double-count.
///
/// Same words, opposite arithmetic. So this type keeps the cached counts in
/// their own fields, `input_tokens` always means *everything sent*, and each
/// driver is responsible for normalising into that. The alternative — a bare
/// `input_tokens` each driver fills differently — is a budget whose meaning
/// depends on which provider a run happened to use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Every input token the provider processed, cached ones included.
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Of `input_tokens`, how many were written into a cache.
    ///
    /// Billed at a premium over ordinary input. Reported separately because the
    /// *rate* differs, and a deployment pricing its own runs needs the split.
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// Of `input_tokens`, how many were served from a cache.
    ///
    /// Billed at roughly a tenth of the input rate. A run that reported these as
    /// ordinary input would over-state its cost by an order of magnitude on the
    /// cached portion — which is the opposite failure to omitting them, and just
    /// as wrong.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// Money in minor units, if the provider reports it.
    ///
    /// Priced by the driver rather than derived here: rates change, differ per
    /// model, and are a deployment's contract with its provider, not this
    /// crate's guess.
    pub minor_units: u64,
}

impl Usage {
    /// What this counts against a run's ceilings.
    ///
    /// Tokens are summed flat — input plus output — because a *ceiling* is about
    /// bounding how much work a run may cause, and a cached input token is still
    /// a token the provider processed. Cost weighting belongs in `minor_units`,
    /// which the driver prices; conflating the two would make the token ceiling
    /// mean something different for every provider.
    #[must_use]
    pub const fn spend(&self) -> Spend {
        Spend {
            tokens: self.input_tokens + self.output_tokens,
            minor_units: self.minor_units,
        }
    }

    /// Input tokens that were neither written to nor read from a cache.
    #[must_use]
    pub const fn uncached_input_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_sub(self.cache_write_tokens)
            .saturating_sub(self.cache_read_tokens)
    }
}

/// A tool the model asked to call.
///
/// A **request, never an instruction**. Each one still has to pass the gate: the
/// agent's manifest must grant the tool, policy must allow the call, and the
/// budget must have room. Model output is a proposal, and this is the most
/// literal case of that rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// The provider's own identifier for this call.
    ///
    /// Load-bearing in a loop: each result must go back under the id the model
    /// used, or the model cannot tell which answer belongs to which question —
    /// and providers reject a result carrying an id they never issued.
    pub id: String,
    /// The tool's name, as the model wrote it.
    ///
    /// Untrusted like everything else a model emits. A name matching no grant is
    /// refused, never resolved to a near neighbour.
    pub name: String,
    /// The arguments, decoded.
    ///
    /// Normalised across providers — Anthropic sends an object, `OpenAI` a JSON
    /// string — so a caller need not know which driver answered in order to read
    /// them.
    pub arguments: Value,
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
    /// Tools the model asked to call.
    ///
    /// Empty for an ordinary answer, and empty for the forced-tool path used to
    /// obtain structured output: that tool is this crate's mechanism for "answer
    /// in this shape", not a request for the runtime to *do* anything, and
    /// surfacing it would make every schema-shaped completion look like a tool
    /// invocation.
    ///
    /// Filled identically by the buffered and streaming paths. Streaming is the
    /// default, so a field populated only when buffering would be silently empty
    /// in most deployments — which is worse than absent, because callers would
    /// build loops on it and see them never fire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    /// Why generation stopped, in the provider's words.
    ///
    /// Passed through unnormalised on purpose: `end_turn`, `max_tokens`,
    /// `incomplete:max_output_tokens` and `stop` mean subtly different things to
    /// the providers that emit them, and flattening them into a shared
    /// vocabulary would lose exactly the detail a caller debugging a truncated
    /// answer needs. The one thing a caller must not have to *parse* out of it
    /// is whether the answer is complete — see [`truncated`](Self::truncated).
    pub stop_reason: Option<String>,
    /// Whether the answer was cut short.
    ///
    /// A typed field rather than a string a caller has to recognise, and its own
    /// field rather than an error, for the same reason the worklist reports
    /// `truncated` beside its page: **a partial answer returned as a whole one is
    /// a silent truncation**, which this crate refuses everywhere else (P7).
    ///
    /// It is not an error because a cut-off answer is often still useful — prose
    /// that stops early is readable, and the caller is the only one who knows
    /// whether they were parsing JSON. What they must not be able to do is
    /// *overlook* it, and a `bool` in the struct they already destructure is
    /// harder to overlook than a stop reason they have to compare against a
    /// provider-specific string.
    pub truncated: bool,
    /// The answer parsed as JSON, when a schema was asked for.
    ///
    /// `None` when no schema was declared. When one was, this is the parsed
    /// value and [`text`](Self::text) still holds the raw string.
    ///
    /// Provider constrained decoding prevents malformed output before tokens
    /// are emitted; this crate then validates the parsed value locally as
    /// defense in depth. Provider bugs and forced-tool best-effort behavior are
    /// therefore loud, metered `Unusable` responses rather than malformed data
    /// reaching downstream code. External schema references are not resolved:
    /// validation performs no hidden file or network I/O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    /// Provider-owned response items required to continue this exact turn.
    ///
    /// This is deliberately opaque to the runtime. `OpenAI` uses complete
    /// Responses output items (including encrypted reasoning); Anthropic uses
    /// the complete assistant content blocks (including signed thinking). The
    /// next request returns the value only to the provider that issued it.
    /// Keeping it in the journal makes continuation independent of expiring
    /// provider-side conversation state and reproducible on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ProviderContinuation>,
}

/// Opaque, self-contained provider state for one continuation turn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderContinuation {
    /// Provider name that owns [`state`](Self::state).
    pub provider: String,
    /// Exact provider-native items emitted by the preceding response.
    pub state: Value,
}

/// A live, non-durable model-stream event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum ModelStreamEvent {
    /// Visible answer text only. Opaque reasoning is never exposed here.
    TextDelta(String),
    /// The latest provider-reported usage snapshot.
    Usage(Usage),
}

/// Receives live model progress while one terminal completion remains canonical.
pub trait ModelStreamObserver: Send + Sync + Debug {
    /// Delivery is advisory and must not block provider consumption. A caller
    /// needing network backpressure should enqueue into its own bounded channel.
    fn event(&self, event: crate::core::Tainted<ModelStreamEvent>);
}

impl ProviderContinuation {
    #[must_use]
    pub fn new(provider: impl Into<String>, state: Value) -> Self {
        Self {
            provider: provider.into(),
            state,
        }
    }
}

/// Why a completion failed.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// Never reached the provider.
    #[error("could not reach '{model}': {detail}")]
    Unreachable { model: ModelId, detail: String },

    /// The provider refused before generating: bad request, unknown model, a
    /// content filter on the *input*. Nothing was metered.
    #[error("'{model}' refused the request: {detail}")]
    Refused { model: ModelId, detail: String },

    /// Rate-limited before generating.
    ///
    /// Separate from [`Refused`](ModelError::Refused) because the response is
    /// different: this one is worth retrying, and it is the one case here where
    /// retrying is unambiguously safe.
    #[error("'{model}' is rate limiting: {detail}")]
    RateLimited { model: ModelId, detail: String },

    /// It generated, and then the stream died.
    ///
    /// The expensive case. The tokens counted here have been spent whatever
    /// happens next.
    #[error("'{model}' stopped mid-response after {} token(s): {detail}", usage.input_tokens + usage.output_tokens)]
    Interrupted {
        model: ModelId,
        usage: Usage,
        detail: String,
    },

    /// It reached the provider, and nothing came back that says whether it
    /// generated.
    ///
    /// A non-streaming 5xx, or a response that could not be read. The honest
    /// position is that this is *unknowable* from here, and both guesses are
    /// wrong in a different way: calling it `Interrupted` makes a transient blip
    /// fatal, and calling it free lets a retry loop spend real money against a
    /// ceiling that reads zero.
    ///
    /// Treated as safe to repeat, because a completion does not change the
    /// world — so repeating is a correctness no-op and only a cost. The
    /// documented price is that the spend ceiling may under-count by at most one
    /// call per occurrence.
    ///
    /// A driver that *can* see partial usage must report
    /// [`Interrupted`](ModelError::Interrupted) instead — which is what both
    /// shipped drivers do when streaming, and why they stream by default. Where
    /// the provider makes even that impossible, the answer is
    /// [`Unaccounted`](ModelError::Unaccounted), not this.
    #[error("'{model}' did not say whether it generated: {detail}")]
    Unavailable { model: ModelId, detail: String },

    /// It generated, the stream died, and the cost is unknowable.
    ///
    /// The state `OpenAI`'s Responses stream can produce and Anthropic's cannot.
    /// Usage appears there only in the terminal event, so a connection cut after
    /// four hundred tokens of deltas leaves the driver *certain* that generation
    /// happened and *ignorant* of what it cost.
    ///
    /// Neither neighbour says that, which is why this variant exists rather than
    /// being folded into one of them:
    ///
    /// * [`Unavailable`](ModelError::Unavailable) means it may never have
    ///   generated, and is therefore safe to repeat. Here we watched it generate;
    ///   asking again buys a second bill for the same question.
    /// * [`Interrupted`](ModelError::Interrupted) carries a [`Usage`], and
    ///   filling it with zeroes is the "guess free" failure this crate refuses
    ///   everywhere else — it reads as *this cost nothing* rather than as
    ///   *nobody knows*.
    ///
    /// So it is [`Disposition::Landed`] with no usage, and the under-count is
    /// admitted rather than hidden: the budget will be short by whatever this
    /// call generated. What the variant buys is that the runtime stops paying
    /// **twice** for it. A caller who needs the true figure has the provider's
    /// response id and a [`Recovery`] policy to reconcile with; a driver quietly
    /// making a second unjournaled request to find out is not the answer.
    #[error("'{model}' generated and then died without saying what it cost: {detail}")]
    Unaccounted { model: ModelId, detail: String },

    /// It answered, and the answer was not usable — truncated JSON, a refusal
    /// where a tool call was required. Metered, because it generated.
    #[error("'{model}' returned an unusable answer: {detail}")]
    Unusable {
        model: ModelId,
        usage: Usage,
        detail: String,
    },
}

impl ModelError {
    /// What this failure says about whether the call reached the provider.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::Unreachable { .. }
            | Self::Refused { .. }
            | Self::RateLimited { .. }
            // Safe to repeat despite having reached the provider: a completion
            // is the one outward call here that does not change the world, so
            // the only cost of asking again is money — which the budget bounds.
            | Self::Unavailable { .. } => Disposition::DidNotHappen,
            // We watched it generate. There is nothing in doubt: it happened,
            // it was billed, and repeating it buys a second bill for the same
            // question. `Unaccounted` belongs here for exactly that reason and
            // despite reporting no usage — what is unknown is the *amount*, not
            // whether it happened.
            Self::Interrupted { .. } | Self::Unusable { .. } | Self::Unaccounted { .. } => {
                Disposition::Landed
            }
        }
    }

    /// What was consumed before the failure.
    #[must_use]
    pub const fn usage(&self) -> Usage {
        match self {
            Self::Interrupted { usage, .. } | Self::Unusable { usage, .. } => *usage,
            _ => Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_write_tokens: 0,
                cache_read_tokens: 0,
                minor_units: 0,
            },
        }
    }
}

/// One request to a provider.
///
/// A struct rather than a widening argument list, because what a model call
/// carries is the part of this seam most likely to grow — and every growth would
/// otherwise be a breaking change to every driver.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub model: &'a ModelId,
    pub prompt: &'a Value,
    /// Maximum tokens the provider may generate for this call.
    ///
    /// Provider-neutral because both shipped APIs expose the same control, and
    /// per-call because a manifest declares it per model role. Keeping it on a
    /// driver silently discarded that declaration and kept the real request
    /// limit out of the effect key.
    pub max_output_tokens: u32,
    /// How much internal reasoning to request, when explicitly configured.
    pub reasoning_effort: Option<ReasoningEffort>,
    /// A JSON Schema the answer must conform to, if one was declared.
    ///
    /// Passed straight through to the provider's own structured-output mode —
    /// `text.format` on `OpenAI` Responses, `output_config.format` on Anthropic —
    /// where the constraint is *enforced during generation* rather than checked
    /// afterwards. That is the whole reason to use it: a schema applied after
    /// the fact rejects a bad answer you have already paid for.
    pub schema: Option<&'a Value>,
    /// The tools the model may ask for.
    ///
    /// Empty means the model is told of none, which is not the same as being
    /// forbidden: authorization happens when a call comes back, against the
    /// operator's grants. Declaring nothing simply gives it nothing to choose.
    pub tools: &'a [ToolDeclaration],
    /// Tools already run this turn, and what they returned.
    pub exchanges: &'a [ToolExchange],
    /// Exact provider-native state emitted beside those tool calls.
    pub continuation: Option<&'a ProviderContinuation>,
    /// Live observer. Not provider-visible and therefore not effect identity.
    /// Strict replay never calls it because replay never performs the provider.
    pub stream: Option<(&'a dyn ModelStreamObserver, &'a crate::core::Label)>,
}

/// Provider-neutral reasoning depth.
///
/// Providers and models support different subsets. An explicit unsupported
/// value is refused before dispatch rather than silently downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    XHigh,
    Max,
}

impl ReasoningEffort {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
        }
    }
}

#[cfg(test)]
mod reasoning_effort_tests {
    use super::ReasoningEffort;

    #[test]
    fn every_reasoning_effort_has_a_pinned_wire_spelling() {
        for (effort, wire) in [
            (ReasoningEffort::None, "none"),
            (ReasoningEffort::Minimal, "minimal"),
            (ReasoningEffort::Low, "low"),
            (ReasoningEffort::Medium, "medium"),
            (ReasoningEffort::High, "high"),
            (ReasoningEffort::XHigh, "xhigh"),
            (ReasoningEffort::Max, "max"),
        ] {
            assert_eq!(effort.as_str(), wire);
        }
    }
}

/// How a driver should obtain a schema-conforming answer.
///
/// **Native structured output is not universally available**, and that is the
/// whole reason this is a choice rather than an implementation detail. Anthropic
/// gates grammar-constrained generation on particular models; `OpenAI`'s strict
/// mode is only on newer ones, with older models offering a JSON *mode* that
/// guarantees valid JSON and nothing about its shape.
///
/// Which mode a given model supports is a fact the deployment knows and the
/// crate cannot discover — asking would be a network call on a path that must
/// not make one, and guessing from a model-name pattern is a lookup table that
/// is wrong the week a model ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SchemaMode {
    /// The provider's own constrained decoding.
    ///
    /// Strongest where it exists: the schema is enforced token by token during
    /// generation, so a non-conforming answer is not merely rejected but
    /// unproducible. The default, because a deployment that has not thought
    /// about this should get the strong thing and a loud failure, not a silent
    /// downgrade.
    #[default]
    Native,
    /// A single forced tool whose input schema *is* the desired output schema.
    ///
    /// The universal fallback, and older than native support: define one tool,
    /// force the model to call it, and read the arguments it was obliged to
    /// construct. Works on any model that can call tools at all, which is a much
    /// wider set than those with constrained decoding.
    ///
    /// Weaker in one specific way worth knowing: the model is constrained to
    /// *produce a tool call*, and providers vary in how strictly they validate
    /// its arguments against the declared schema. Native mode makes a malformed
    /// answer impossible; this makes it unlikely.
    ForcedTool,
}

/// Talks to a provider.
#[async_trait]
pub trait ModelProvider: Send + Sync + Debug {
    /// Stable, non-secret configuration that changes the provider wire request.
    ///
    /// It is part of [`ModelCall`]'s effect identity. A provider switching from
    /// native schema enforcement to a forced tool, changing endpoint/API
    /// version, or changing streaming behavior must not replay an answer
    /// produced under the old transport contract. API keys never belong here.
    fn request_profile(&self, _model: &ModelId) -> Value {
        Value::Null
    }

    /// Complete a prompt.
    ///
    /// # Errors
    ///
    /// A [`ModelError`] that states both what is known about reaching the
    /// provider *and* what was consumed. A driver that reports zero usage for an
    /// interrupted stream is telling the budget the call was free.
    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError>;
}

/// A tool the model may ask for, as the request declares it.
///
/// Provider-neutral, because the two shapes differ in ways that are easy to get
/// subtly wrong: Anthropic takes `{name, description, input_schema}` at the top
/// level, while `OpenAI` wraps it as `{type: "function", function: {name,
/// description, parameters}}`. A driver renders this into whichever it speaks,
/// so a caller writes the declaration once.
///
/// # What a declaration is *not*
///
/// It is not a grant. Declaring a tool tells the model the tool exists; it does
/// not authorize the call. The model's choice of tool and its arguments come
/// back **untrusted**, are matched against the operator's grants exactly, and
/// are dispatched through `cx.sink` where field provenance and the egress
/// ceiling apply. A framework that executes what the model asked for has
/// authorized the model; this one authorizes the operator's declaration and
/// treats the model's request as a suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDeclaration {
    /// The name the model will use when it asks for this tool.
    pub name: String,
    /// What it does, for the model's benefit.
    pub description: String,
    /// JSON Schema for the arguments.
    ///
    /// Sent with provider-side strict enforcement when the provider accepts the
    /// schema. `OpenAI` supports only a subset for strict tools, so a valid
    /// schema with optional fields is sent non-strict rather than rejected by
    /// the API; typed local tools still deserialize the result exactly. Either
    /// way this is not a security control: a well-formed argument is still an
    /// untrusted one, and the field-provenance check is what authorizes it.
    pub parameters: Value,
}

impl ToolDeclaration {
    /// Declare a tool.
    #[must_use]
    pub fn new(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }
}

/// A tool the model asked for, and what came back.
///
/// Handed to the next request so the model can see the result of what it asked
/// for. Provider-neutral because the continuation shapes differ more than the
/// declarations do, and in ways that fail loudly at the API rather than quietly
/// in the answer.
///
/// # Both halves travel, not just the result
///
/// The **call** is echoed back alongside its output. That is not redundancy: a
/// provider matches a result to the request that produced it by id, and one sent
/// without its call is rejected — `OpenAI` answers *"No tool call found for
/// function call output with `call_id`"*. Carrying the pair makes that
/// unrepresentable.
///
/// # Why the transcript is passed rather than referenced
///
/// `OpenAI` will hold the conversation for you behind `previous_response_id`.
/// This crate does not use it, and will not: replay would then depend on state
/// a provider holds, expires and can lose — so a run that replayed correctly
/// today would diverge when that state aged out, for a reason nothing in the
/// journal could explain. Everything needed to continue is in the request.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolExchange {
    /// What the model asked for, including the id it issued.
    pub call: ToolCall,
    /// What came back, as the tool produced it.
    pub output: Value,
    /// Whether the tool failed.
    ///
    /// Sent as Anthropic's `is_error`, so the model is told the difference
    /// between a tool that answered and one that could not. A failure rendered
    /// as an ordinary result teaches it that the operation succeeded and
    /// returned something strange.
    pub failed: bool,
}

impl ToolExchange {
    /// A tool that answered.
    #[must_use]
    pub fn ok(call: ToolCall, output: Value) -> Self {
        Self {
            call,
            output,
            failed: false,
        }
    }

    /// A tool that failed, with what to tell the model.
    #[must_use]
    pub fn failed(call: ToolCall, detail: impl Into<String>) -> Self {
        Self {
            call,
            output: Value::String(detail.into()),
            failed: true,
        }
    }
}

/// One completion.
#[derive(Debug)]
pub struct ModelCall {
    model: ModelId,
    prompt: Value,
    schema: Option<Value>,
    tools: Vec<ToolDeclaration>,
    exchanges: Vec<ToolExchange>,
    continuation: Option<ProviderContinuation>,
    stream: Option<Arc<dyn ModelStreamObserver>>,
    max_output_tokens: u32,
    reasoning_effort: Option<ReasoningEffort>,
    provider: Arc<dyn ModelProvider>,
    max_sensitivity: Sensitivity,
    output_sensitivity: Sensitivity,
    retry: RetryPolicy,
    #[cfg(feature = "media")]
    media: Option<Arc<dyn crate::blob::BlobStore>>,
    #[cfg(feature = "media")]
    media_grants: std::collections::BTreeSet<(crate::core::Digest, String)>,
    /// `/system` when the prompt has one, empty otherwise.
    ///
    /// Computed at construction rather than returned fresh, because
    /// [`Effect::protected_fields`] hands back a borrowed slice — and because a
    /// declared field is *mandatory*, so declaring `/system` unconditionally
    /// would refuse every prompt that legitimately has no instruction.
    protected: Vec<crate::core::ProtectedField>,
}

impl ModelCall {
    /// Conservative per-call output ceiling used when the caller does not set
    /// one explicitly.
    pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4096;

    /// A completion from this provider.
    #[must_use]
    pub fn new(provider: Arc<dyn ModelProvider>, model: ModelId, prompt: Value) -> Self {
        Self {
            model,
            prompt,
            schema: None,
            tools: Vec::new(),
            exchanges: Vec::new(),
            continuation: None,
            stream: None,
            max_output_tokens: Self::DEFAULT_MAX_OUTPUT_TOKENS,
            reasoning_effort: None,
            provider,
            max_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
            retry: RetryPolicy::never(),
            #[cfg(feature = "media")]
            media: None,
            #[cfg(feature = "media")]
            media_grants: std::collections::BTreeSet::new(),
            protected: Vec::new(),
        }
        .with_protected_instruction()
    }

    /// Require the instruction to be trusted, when there is one.
    ///
    /// # The instruction slot carries authority; the content does not
    ///
    /// A model reads its instruction and its data as the same undifferentiated
    /// text, so text that *arrives as data* and reads like an instruction is
    /// obeyed like one. The usual defence — label the data, gate the sinks —
    /// contains what the model may then *do*, and this crate does that. It does
    /// not answer the prior question of who was allowed to give the order.
    ///
    /// So `/system` is protected: if the prompt has an instruction, it must be
    /// trusted. Untrusted material belongs in `messages`, where it is content
    /// the model reasons *about* rather than a directive it reasons *under*.
    ///
    /// The consequence is deliberate and it will be met immediately. Building a
    /// prompt with `untrusted.map(|d| json!({"system": "…", "messages": [d]}))`
    /// is refused, because `map` cannot prove how a closure reshaped a value and
    /// so conservatively taints the whole thing — instruction included.
    /// [`Tainted::object`](crate::core::Tainted::object) keeps the two apart,
    /// which is what it is for.
    fn with_protected_instruction(mut self) -> Self {
        self.protected = if self.prompt.get("system").is_some_and(|s| !s.is_null()) {
            vec![crate::core::ProtectedField::trusted("/system")]
        } else {
            Vec::new()
        };
        self
    }

    /// Tell the model which tools it may ask for.
    ///
    /// What comes back is a *request*, not an action: the chosen name is matched
    /// against the operator's grants exactly — never resolved to a near
    /// neighbour — and the arguments stay untrusted until they pass the sink's
    /// field-provenance rules. Declaring is telling; authorizing is separate.
    ///
    /// Declare only what is granted. Offering the model a tool the manifest does
    /// not grant produces a call that is refused after the model has been paid
    /// for choosing it, and teaches nobody anything.
    #[must_use]
    pub fn with_tools(mut self, tools: impl IntoIterator<Item = ToolDeclaration>) -> Self {
        self.tools = tools.into_iter().collect();
        self
    }

    /// Continue after tools ran, showing the model what came back.
    ///
    /// Each exchange carries the call *and* its output: a provider matches them
    /// by the id it issued, and an output without its call is rejected.
    ///
    /// The prompt stays what it was. A continuation is the same question with
    /// more known, so re-stating it would change the effect key and make each
    /// turn of a loop a different call for replay purposes.
    #[must_use]
    pub fn continuing(mut self, exchanges: impl IntoIterator<Item = ToolExchange>) -> Self {
        self.exchanges = exchanges.into_iter().collect();
        self
    }

    /// Continue with exact provider-native state from the preceding response.
    ///
    /// This state is not interpreted, synthesized, or fetched by id. It is
    /// journaled as part of this call's identity and returned only to the
    /// provider that produced it.
    #[must_use]
    pub fn with_continuation(mut self, continuation: ProviderContinuation) -> Self {
        self.continuation = Some(continuation);
        self
    }

    /// Observe visible model text as it arrives during live execution.
    #[must_use]
    pub fn streaming_to(mut self, observer: Arc<dyn ModelStreamObserver>) -> Self {
        self.stream = Some(observer);
        self
    }

    /// Bound how many tokens this call may generate.
    #[must_use]
    pub const fn with_max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    /// Request an explicit reasoning depth.
    #[must_use]
    pub const fn with_reasoning_effort(mut self, effort: ReasoningEffort) -> Self {
        self.reasoning_effort = Some(effort);
        self
    }

    /// The highest sensitivity this model may be shown.
    ///
    /// The control that matters for a hosted model: a prompt assembled from a
    /// secret is an exfiltration whether or not anyone meant it.
    #[must_use]
    pub const fn with_max_sensitivity(mut self, s: Sensitivity) -> Self {
        self.max_sensitivity = s;
        self
    }

    #[must_use]
    pub const fn with_output_sensitivity(mut self, s: Sensitivity) -> Self {
        self.output_sensitivity = s;
        self
    }

    #[must_use]
    pub const fn with_retry(mut self, r: RetryPolicy) -> Self {
        self.retry = r;
        self
    }

    /// Permit these exact [`FetchedMedia`](crate::media::FetchedMedia) artifacts
    /// to materialize from this blob store immediately before live dispatch.
    ///
    /// The prompt and effect key contain only media digests. Strict replay does
    /// not execute `perform`, so it reads neither blob storage nor the network.
    /// A prompt marker without a matching digest/type grant is refused;
    /// knowing another case's digest is not authority to read that blob.
    /// Model output remains journaled for replay and may itself reproduce media
    /// content; digest-only input storage is not an output-redaction promise.
    #[cfg(feature = "media")]
    #[must_use]
    pub fn with_media<'a>(
        mut self,
        media: Arc<dyn crate::blob::BlobStore>,
        artifacts: impl IntoIterator<Item = &'a crate::media::FetchedMedia>,
    ) -> Self {
        self.media = Some(media);
        for artifact in artifacts {
            self.media_grants
                .insert((artifact.digest, artifact.media_type.clone()));
        }
        self
    }

    /// Require the answer to conform to a JSON Schema.
    ///
    /// The schema goes into the **effect key**, which is the point: editing a
    /// schema changes the effect, so a replayed run reports divergence instead
    /// of quietly reading back an answer shaped to different rules. A schema
    /// that lived outside the key would let today's shape re-interpret last
    /// year's stored answer.
    ///
    /// Enforcement happens at the provider, during generation, where a
    /// constraint can prevent a malformed answer rather than reject one already
    /// paid for. What this crate adds on top is the parse — see
    /// [`Completion::structured`].
    #[must_use]
    pub fn expecting(mut self, schema: Value) -> Self {
        self.schema = Some(schema);
        self
    }
}

#[async_trait]
impl Effect for ModelCall {
    type Output = Completion;

    fn gen_ai_operation(&self) -> Option<&'static str> {
        Some(crate::runtime::telemetry::GEN_AI_CHAT)
    }

    fn descriptor(&self) -> EffectDescriptor {
        // Every provider-visible input is in the key. A changed prompt, schema,
        // offered tool, or continuation transcript is a changed effect, so an
        // edit shows up on replay as divergence rather than reading an answer
        // produced for a request nobody made this time.
        EffectDescriptor::new(
            "model.complete",
            serde_json::json!({
                "provider": self.model.provider,
                "model": self.model.model,
                "provider_profile": self.provider.request_profile(&self.model),
                "prompt": self.prompt,
                // In the key for the same reason the prompt is: a changed
                // schema is a changed question, and a replay that read back an
                // answer shaped to the old one would be answering a question
                // nobody asked.
                "schema": self.schema,
                "max_output_tokens": self.max_output_tokens,
                "reasoning_effort": self.reasoning_effort,
                // Tool descriptions and schemas steer generation just as the
                // prompt does. Omitting them would let strict replay consume a
                // completion produced while a different capability surface was
                // offered.
                "tools": self.tools.iter().map(|tool| serde_json::json!({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                })).collect::<Vec<_>>(),
                // A continuation is the original question plus the exact calls
                // and results already observed. IDs, arguments, outputs and the
                // failure bit all affect the next provider response.
                "exchanges": self.exchanges.iter().map(|exchange| serde_json::json!({
                    "call": {
                        "id": exchange.call.id,
                        "name": exchange.call.name,
                        "arguments": exchange.call.arguments,
                    },
                    "output": exchange.output,
                    "failed": exchange.failed,
                })).collect::<Vec<_>>(),
                "continuation": self.continuation,
            }),
        )
    }

    /// A completion does not change the world.
    ///
    /// Said plainly because it is the one outward call in this crate where that
    /// is true, and it is what makes retrying a rate-limit sane. It is *not* free
    /// — see `spend` — but a second completion does not move money twice.
    fn mutates(&self) -> bool {
        false
    }

    /// `/system` when the prompt has an instruction.
    ///
    /// A model reads its instruction and its data as the same undifferentiated
    /// text, so text arriving as *data* that reads like a directive is obeyed
    /// like one. Every other control here bounds what the model may then **do**;
    /// this is the only one that asks who was allowed to give the order.
    /// Untrusted material belongs in `messages`.
    fn protected_fields(&self) -> &[crate::core::ProtectedField] {
        &self.protected
    }

    fn recovery(&self) -> Recovery {
        Recovery::Retry
    }

    fn retry(&self) -> RetryPolicy {
        self.retry
    }

    fn max_sensitivity(&self) -> Sensitivity {
        self.max_sensitivity
    }

    fn output_sensitivity(&self) -> Sensitivity {
        self.output_sensitivity
    }

    fn sink_arguments(&self) -> Option<&Value> {
        Some(&self.prompt)
    }

    /// Model output is untrusted, and this is the case the rule was written for.
    ///
    /// A completion is a plausible-sounding string produced from whatever was in
    /// the context window — including anything untrusted that got there. It is
    /// the canonical prompt-injection carrier.
    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    fn spend(&self, output: &Completion) -> Spend {
        output.usage.spend()
    }

    async fn perform(&self) -> Result<Completion, EffectError> {
        #[cfg(feature = "media")]
        let prompt =
            materialize_media(&self.prompt, self.media.as_ref(), &self.media_grants).await?;
        #[cfg(not(feature = "media"))]
        let prompt = self.prompt.clone();

        // The trait is public, so an embedder may supply a provider whose wire
        // implementation this crate cannot inspect. Apply the hard cut at the
        // effect boundary as well as inside the built-in drivers: no provider
        // reached through the runtime receives a remote media URL.
        refuse_provider_side_media(&prompt, &self.model)
            .map_err(|error| EffectError::Rejected(error.to_string()))?;

        let mut stream_label = crate::core::Label::untrusted(crate::core::SourceId::new(format!(
            "model:{}",
            self.model
        )));
        stream_label.sensitivity = self.output_sensitivity;
        self.provider
            .complete(Request {
                model: &self.model,
                prompt: &prompt,
                max_output_tokens: self.max_output_tokens,
                reasoning_effort: self.reasoning_effort,
                schema: self.schema.as_ref(),
                tools: &self.tools,
                exchanges: &self.exchanges,
                continuation: self.continuation.as_ref(),
                stream: self
                    .stream
                    .as_deref()
                    .map(|observer| (observer, &stream_label)),
            })
            .await
            .map_err(|e| {
                let detail = e.to_string();
                let spend = e.usage().spend();
                // A failure that consumed nothing is an ordinary failure. One
                // that generated tokens has to carry them, or the ceiling that
                // exists to bound a runaway provider counts zero.
                if spend.is_zero() {
                    match e.disposition() {
                        Disposition::DidNotHappen => EffectError::Rejected(detail),
                        Disposition::InDoubt => EffectError::Interrupted {
                            driver: self.model.to_string(),
                            detail,
                        },
                        Disposition::Landed => EffectError::Performed(detail),
                    }
                } else {
                    EffectError::Metered {
                        detail,
                        spend,
                        disposition: e.disposition(),
                    }
                }
            })
    }
}

#[cfg(feature = "media")]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MediaMaterialization {
    digest: crate::core::Digest,
    media_type: String,
    encoding: String,
}

#[cfg(feature = "media")]
async fn materialize_media(
    prompt: &Value,
    store: Option<&Arc<dyn crate::blob::BlobStore>>,
    grants: &std::collections::BTreeSet<(crate::core::Digest, String)>,
) -> Result<Value, EffectError> {
    let mut references = Vec::new();
    collect_media_references(prompt, &mut references)?;
    if references.is_empty() {
        return Ok(prompt.clone());
    }
    let store = store.ok_or_else(|| {
        EffectError::Rejected(
            "the prompt contains governed-media references but ModelCall has no media store"
                .to_owned(),
        )
    })?;
    references.sort();
    references.dedup();

    let mut replacements = std::collections::BTreeMap::new();
    for reference in references {
        if !grants.contains(&(reference.digest, reference.media_type.clone())) {
            return Err(EffectError::Rejected(format!(
                "governed media {} with type '{}' is not explicitly granted to this model call",
                reference.digest, reference.media_type
            )));
        }
        let bytes = store.get(reference.digest).await.map_err(|error| {
            EffectError::Rejected(format!(
                "governed media {} could not be materialized: {error}",
                reference.digest
            ))
        })?;
        crate::media::verify_materialized(&reference.media_type, &bytes)
            .map_err(EffectError::Rejected)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let value = match reference.encoding.as_str() {
            "base64" => encoded,
            "data_url" => format!("data:{};base64,{encoded}", reference.media_type),
            other => {
                return Err(EffectError::Rejected(format!(
                    "unknown governed-media encoding '{other}'"
                )));
            }
        };
        replacements.insert(reference, Value::String(value));
    }

    replace_media_references(prompt, &replacements)
}

#[cfg(feature = "media")]
fn collect_media_references(
    value: &Value,
    out: &mut Vec<MediaMaterialization>,
) -> Result<(), EffectError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_media_references(value, out)?;
            }
        }
        Value::Object(object) => {
            if object.contains_key("$agentplane_media") {
                out.push(parse_media_reference(value)?);
            } else {
                for value in object.values() {
                    collect_media_references(value, out)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "media")]
fn replace_media_references(
    value: &Value,
    replacements: &std::collections::BTreeMap<MediaMaterialization, Value>,
) -> Result<Value, EffectError> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| replace_media_references(value, replacements))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) if object.contains_key("$agentplane_media") => replacements
            .get(&parse_media_reference(value)?)
            .cloned()
            .ok_or_else(|| {
                EffectError::Rejected("governed-media replacement is missing".to_owned())
            }),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| Ok((key.clone(), replace_media_references(value, replacements)?)))
            .collect::<Result<serde_json::Map<_, _>, EffectError>>()
            .map(Value::Object),
        _ => Ok(value.clone()),
    }
}

#[cfg(feature = "media")]
fn parse_media_reference(value: &Value) -> Result<MediaMaterialization, EffectError> {
    let outer = value.as_object().ok_or_else(|| {
        EffectError::Rejected("governed-media marker must be an object".to_owned())
    })?;
    if outer.len() != 1 {
        return Err(EffectError::Rejected(
            "governed-media marker may not contain sibling fields".to_owned(),
        ));
    }
    let marker = outer
        .get("$agentplane_media")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            EffectError::Rejected("governed-media marker body must be an object".to_owned())
        })?;
    if marker.len() != 3 {
        return Err(EffectError::Rejected(
            "governed-media marker must contain exactly digest, media_type, and encoding"
                .to_owned(),
        ));
    }
    let digest = marker
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| EffectError::Rejected("governed-media digest is missing".to_owned()))?;
    let digest = crate::core::Digest::from_hex(digest).map_err(|error| {
        EffectError::Rejected(format!("invalid governed-media digest: {error}"))
    })?;
    let media_type = marker
        .get("media_type")
        .and_then(Value::as_str)
        .ok_or_else(|| EffectError::Rejected("governed-media media_type is missing".to_owned()))?
        .to_owned();
    let encoding = marker
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(|| EffectError::Rejected("governed-media encoding is missing".to_owned()))?
        .to_owned();
    Ok(MediaMaterialization {
        digest,
        media_type,
        encoding,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "media")]
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    #[derive(Debug)]
    struct RecordingProvider(Arc<AtomicUsize>);

    #[async_trait]
    impl ModelProvider for RecordingProvider {
        async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(ModelError::Unavailable {
                model: request.model.clone(),
                detail: "recording provider was called".to_owned(),
            })
        }
    }

    /// `with_retry` replaces the policy, and the default declines to retry.
    ///
    /// The default is `never` on purpose: a model call that reached the provider
    /// and died mid-stream is `Landed`, so repeating it buys a second bill for
    /// the same question. A deployment that has decided otherwise sets its own
    /// policy here — and the builder had no caller and no test, so a `with_retry`
    /// that dropped the value on the floor would have left every such deployment
    /// silently on the default.
    #[test]
    fn with_retry_replaces_a_deliberately_unretrying_default() {
        let provider: Arc<dyn ModelProvider> =
            Arc::new(RecordingProvider(Arc::new(AtomicUsize::new(0))));
        let plain = ModelCall::new(
            Arc::clone(&provider),
            ModelId::new("custom", "m"),
            json!({"q": "hi"}),
        );
        assert_eq!(
            Effect::retry(&plain).max_attempts,
            RetryPolicy::never().max_attempts,
            "a model call must not retry by default — a died-mid-stream call already landed"
        );

        let insistent = ModelCall::new(provider, ModelId::new("custom", "m"), json!({"q": "hi"}))
            .with_retry(RetryPolicy::default());
        assert_eq!(
            Effect::retry(&insistent).max_attempts,
            RetryPolicy::default().max_attempts
        );
    }

    /// The effect boundary protects custom providers, not only the built-ins.
    #[tokio::test]
    async fn a_model_call_refuses_provider_side_media_before_any_provider() {
        let calls = Arc::new(AtomicUsize::new(0));
        let call = ModelCall::new(
            Arc::new(RecordingProvider(Arc::clone(&calls))),
            ModelId::new("custom", "vision"),
            json!({
                "input": [{
                    "role": "user",
                    "content": [{
                        "type": "input_image",
                        "image_url": "https://media.example/private.png"
                    }]
                }]
            }),
        );

        let error = call
            .perform()
            .await
            .expect_err("remote media must be refused");
        assert!(matches!(error, EffectError::Rejected(_)), "{error}");
        assert_eq!(calls.load(Ordering::Relaxed), 0, "the provider was called");
    }

    #[cfg(feature = "media")]
    #[derive(Debug, Default)]
    struct CapturingProvider(Mutex<Option<Value>>);

    #[cfg(feature = "media")]
    #[async_trait]
    impl ModelProvider for CapturingProvider {
        async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
            *self.0.lock().unwrap() = Some(request.prompt.clone());
            Ok(Completion {
                tool_calls: Vec::new(),
                text: "described".to_owned(),
                usage: Usage::default(),
                stop_reason: Some("stop".to_owned()),
                truncated: false,
                structured: None,
                continuation: None,
            })
        }
    }

    #[cfg(feature = "media")]
    #[tokio::test]
    async fn governed_media_is_digest_only_until_live_model_dispatch() {
        use crate::blob::{BlobStore, MemoryBlobs};
        use crate::media::{FetchedMedia, MediaRetention};

        let blobs = Arc::new(MemoryBlobs::new());
        let bytes = b"\x89PNG\r\n\x1a\nbody";
        let digest = blobs.put(bytes).await.unwrap();
        let fetched = FetchedMedia {
            digest,
            media_type: "image/png".to_owned(),
            bytes: bytes.len(),
            source_url: "https://media.example/a.png".to_owned(),
            final_url: "https://media.example/a.png".to_owned(),
            redirects: 0,
            validated_by: Vec::new(),
            hops: Vec::new(),
            retention: MediaRetention::External {
                policy: "test".to_owned(),
            },
        };
        let provider = Arc::new(CapturingProvider::default());
        let call = ModelCall::new(
            Arc::clone(&provider) as Arc<dyn ModelProvider>,
            ModelId::new("openai", "vision"),
            json!({ "input": [{ "content": [fetched.openai_image()] }] }),
        )
        .with_media(blobs as Arc<dyn BlobStore>, [&fetched]);

        let identity = serde_json::to_string(&call.descriptor()).unwrap();
        assert!(identity.contains(&digest.to_hex()));
        assert!(
            !identity.contains("iVBOR"),
            "media bytes entered the effect key"
        );

        call.perform().await.unwrap();
        let prompt = provider.0.lock().unwrap().clone().unwrap();
        let data_url = prompt["input"][0]["content"][0]["image_url"]
            .as_str()
            .unwrap();
        assert!(data_url.starts_with("data:image/png;base64,iVBOR"));
    }

    #[cfg(feature = "media")]
    #[tokio::test]
    async fn knowing_a_media_digest_is_not_authority_to_materialize_its_blob() {
        use crate::blob::{BlobStore, MemoryBlobs};
        use crate::media::FetchedMedia;

        let blobs = Arc::new(MemoryBlobs::new());
        let bytes = b"\x89PNG\r\n\x1a\nprivate";
        let digest = blobs.put(bytes).await.unwrap();
        let provider = Arc::new(RecordingProvider(Arc::new(AtomicUsize::new(0))));
        let calls = Arc::clone(&provider.0);
        let call = ModelCall::new(
            provider as Arc<dyn ModelProvider>,
            ModelId::new("openai", "vision"),
            json!({
                "input": [{
                    "content": [{
                        "type": "input_image",
                        "image_url": {
                            "$agentplane_media": {
                                "digest": digest,
                                "media_type": "image/png",
                                "encoding": "data_url"
                            }
                        }
                    }]
                }]
            }),
        )
        .with_media(
            blobs as Arc<dyn BlobStore>,
            std::iter::empty::<&FetchedMedia>(),
        );

        let error = call.perform().await.expect_err("ungranted digest");
        assert!(
            error.to_string().contains("not explicitly granted"),
            "{error}"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0, "the provider was called");
    }

    #[test]
    fn provider_side_media_url_shapes_are_classified_structurally() {
        for remote in [
            json!({
                "type": "image",
                "source": { "type": "url", "url": "https://media.example/image.png" }
            }),
            json!({
                "type": "document",
                "source": { "type": "url", "url": "https://media.example/document.pdf" }
            }),
            json!({ "type": "input_image", "image_url": "https://media.example/image.png" }),
            json!({ "type": "image_url", "image_url": { "url": "https://media.example/image.png" } }),
            json!({ "type": "input_file", "file_url": "https://media.example/document.pdf" }),
        ] {
            assert!(provider_side_media_reference(&remote).is_some(), "{remote}");
        }

        for inline_or_text in [
            json!({
                "type": "image",
                "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" }
            }),
            json!({
                "type": "document",
                "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0=" }
            }),
            json!({
                "type": "input_image",
                "image_url": "data:image/png;base64,iVBORw0KGgo="
            }),
            json!({
                "type": "input_file",
                "filename": "document.pdf",
                "file_data": "data:application/pdf;base64,JVBERi0="
            }),
            json!({ "type": "input_text", "text": "Discuss https://example.com/image.png" }),
            json!("https://example.com/image.png"),
        ] {
            assert!(
                provider_side_media_reference(&inline_or_text).is_none(),
                "{inline_or_text}"
            );
        }
    }
}
