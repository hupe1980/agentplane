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
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{
    Disposition, Effect, EffectDescriptor, EffectError, Recovery, RetryPolicy, Sensitivity, Spend,
    Trust,
};

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
    pub minor_units: i64,
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

/// What came back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Completion {
    pub text: String,
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
    /// **This crate does not re-validate against the schema**, and that is a
    /// decision rather than an omission. The provider enforces the constraint
    /// during generation; a second JSON Schema implementation here could
    /// disagree with the one that did the enforcing, and the disagreement would
    /// surface as a run refusing an answer that is in fact conformant. What the
    /// driver *does* guarantee is that a declared schema means the text parsed —
    /// so a provider bug becomes a loud, metered `Unusable` rather than a panic
    /// three steps downstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
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
    /// A JSON Schema the answer must conform to, if one was declared.
    ///
    /// Passed straight through to the provider's own structured-output mode —
    /// `text.format` on `OpenAI` Responses, `output_config.format` on Anthropic —
    /// where the constraint is *enforced during generation* rather than checked
    /// afterwards. That is the whole reason to use it: a schema applied after
    /// the fact rejects a bad answer you have already paid for.
    pub schema: Option<&'a Value>,
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
    /// Complete a prompt.
    ///
    /// # Errors
    ///
    /// A [`ModelError`] that states both what is known about reaching the
    /// provider *and* what was consumed. A driver that reports zero usage for an
    /// interrupted stream is telling the budget the call was free.
    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError>;
}

/// One completion.
#[derive(Debug)]
pub struct ModelCall {
    model: ModelId,
    prompt: Value,
    schema: Option<Value>,
    provider: Arc<dyn ModelProvider>,
    max_sensitivity: Sensitivity,
    output_sensitivity: Sensitivity,
    retry: RetryPolicy,
}

impl ModelCall {
    /// A completion from this provider.
    #[must_use]
    pub fn new(provider: Arc<dyn ModelProvider>, model: ModelId, prompt: Value) -> Self {
        Self {
            model,
            prompt,
            schema: None,
            provider,
            max_sensitivity: Sensitivity::Public,
            output_sensitivity: Sensitivity::Public,
            retry: RetryPolicy::never(),
        }
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

    fn descriptor(&self) -> EffectDescriptor {
        // The prompt is in the key. A changed prompt is a changed effect, so an
        // edited template shows up on replay as divergence rather than as a run
        // that quietly did something else.
        EffectDescriptor::new(
            "model.complete",
            serde_json::json!({
                "provider": self.model.provider,
                "model": self.model.model,
                "prompt": self.prompt,
                // In the key for the same reason the prompt is: a changed
                // schema is a changed question, and a replay that read back an
                // answer shaped to the old one would be answering a question
                // nobody asked.
                "schema": self.schema,
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
        self.provider
            .complete(Request {
                model: &self.model,
                prompt: &self.prompt,
                schema: self.schema.as_ref(),
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
