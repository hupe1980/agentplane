//! A `ModelProvider` for the `OpenAI` **Responses** API.
//!
//! Behind the `providers` feature.
//!
//! # Why Responses and not Chat Completions
//!
//! Responses is `OpenAI`'s current primitive and the recommended surface for new
//! work; Chat Completions remains supported as an industry-standard shape, and
//! the Assistants API sunsets in August 2026. Targeting the older surface would
//! mean adopting a vocabulary that is already being migrated away from.
//!
//! It also reports what this crate needs more directly. Responses returns
//! `usage.input_tokens` / `usage.output_tokens` — including
//! `output_tokens_details.reasoning_tokens`, which are billed and which a
//! completion-token count silently omits — and it carries an explicit `status`
//! with `incomplete_details`, so "the answer was cut off" is a fact the API
//! states rather than something inferred from a finish reason.
//!
//! # The failure table
//!
//! Status classification is shared doctrine, in `model::wire`; what is
//! specific here is the *success* envelope, which has three outcomes that are
//! easy to conflate:
//!
//! | Response | Meaning | Metered |
//! |---|---|---|
//! | `status: "completed"` | it answered | yes |
//! | `status: "incomplete"` | it answered and was cut off | **yes**, and [`Completion::truncated`] |
//! | `status: "failed"` | it started and gave up | **yes** |
//! | a `refusal` content part | it generated, and declined | **yes** |
//!
//! The middle row is the one worth being careful about. A truncated answer is
//! not an error — prose that stops early is still readable, and only the caller
//! knows whether they were parsing JSON — but it must not be returned as a whole
//! one. That is what [`Completion::truncated`] is for, and why this driver does
//! not quietly hand back a shortened string.
//!
//! Reasoning tokens are counted. They are billed, and a driver that reported
//! only visible output would tell a reasoning-heavy run's budget that it cost a
//! fraction of what it did.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::core::Secret;

#[cfg(test)]
use super::ModelCall;
use super::wire::{
    RESPOND_TOOL, classify_status, classify_transport, strict_schema_problem, structured,
};
use super::{
    Completion, ModelError, ModelId, ModelProvider, Request, SchemaMode, Usage, openai_stream, sse,
};

/// Calls the `OpenAI` Responses API.
pub struct OpenAi {
    http: reqwest::Client,
    key: Secret,
    base: String,
    /// Whether `OpenAI` may retain Responses objects after the call.
    ///
    /// The API defaults to retention. This driver does not: provider-held
    /// conversation state is neither replay truth nor a safe default for
    /// prompts that may contain governed data. An operator can opt in when
    /// response retrieval is part of its incident/accounting procedure.
    retain_responses: bool,
    /// The mode to use for a model with no explicit entry.
    default_schema_mode: SchemaMode,
    /// Per-model overrides.
    ///
    /// Keyed by model **because that is what the constraint is about**. One
    /// driver instance serves many models over one key and one connection pool;
    /// a capability setting on the driver would force a second instance per
    /// model, which is a strange thing to make somebody do to say that
    /// `claude-haiku-3` cannot do what `claude-opus-4-5` can.
    schema_modes: std::collections::BTreeMap<String, SchemaMode>,
    /// Whether to ask for the response as a stream.
    ///
    /// On by default, but it buys less here than it does for Anthropic. Usage
    /// arrives only in the terminal event, so a severed stream cannot say what
    /// it cost — what it *can* say is that generation happened, which is the
    /// difference between a call that must not be repeated and one that is safe
    /// to send again. See [`ModelError::Unaccounted`].
    stream: bool,
    /// Where this driver may connect, if the deployment says.
    egress: Option<crate::core::Egress>,
    /// Whole HTTP request, including a streamed response body.
    timeout: std::time::Duration,
}

impl std::fmt::Debug for OpenAi {
    /// Redacts the key: a secret that can be printed is a secret in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAi")
            .field("base", &self.base)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl OpenAi {
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

    /// A ceiling every request carries.
    ///
    /// An output limit is the cheapest spend control there is. The run-level
    /// ceilings in `core::budget` bound the run; this bounds the call.
    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(key: impl Into<String>) -> Result<Self, ModelError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ModelError::Unreachable {
                model: ModelId::new("openai", "*"),
                detail: format!("could not build an HTTP client: {e}"),
            })?;
        Ok(Self {
            http,
            key: Secret::new(key),
            base: "https://api.openai.com".to_owned(),
            retain_responses: false,
            default_schema_mode: SchemaMode::Native,
            schema_modes: std::collections::BTreeMap::new(),
            stream: true,
            egress: None,
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// Bound connection, generation, and response streaming as one operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Point at a different host — a gateway, or a test server.
    #[must_use]
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    /// Permit `OpenAI` to retain response objects.
    ///
    /// Disabled by default. Retention can make a response id useful during an
    /// accounting incident, but it also stores provider-side model inputs and
    /// outputs. The choice is included in [`ModelProvider::request_profile`],
    /// so changing it changes effect identity rather than silently changing a
    /// run's data-handling behavior.
    #[must_use]
    pub const fn retain_responses(mut self) -> Self {
        self.retain_responses = true;
        self
    }

    /// How to obtain a schema-conforming answer from this model.
    ///
    /// Strict constrained decoding is only on newer models; older ones offer a
    /// JSON *mode* that guarantees valid JSON and nothing about its shape, which
    /// is not what a schema was asked for. [`SchemaMode::ForcedTool`] is the
    /// fallback that works wherever tool calling does.
    #[must_use]
    pub fn structured_via(mut self, mode: SchemaMode) -> Self {
        self.default_schema_mode = mode;
        self
    }

    /// How to obtain a schema-conforming answer from **one** model.
    ///
    /// Takes precedence over the driver default. This is the knob that matches
    /// the shape of the problem: constrained decoding is gated per *model*, and
    /// one driver serves many.
    #[must_use]
    pub fn structured_via_for(mut self, model: impl Into<String>, mode: SchemaMode) -> Self {
        self.schema_modes.insert(model.into(), mode);
        self
    }

    /// Restrict where this driver may connect.
    ///
    /// Deny-by-default once set: a base URL whose host is not granted is refused
    /// **before the request is built**, so nothing leaves and nothing is
    /// metered. Unset means no egress control, spelled the same way an absent
    /// policy engine is — see [`Egress`](crate::core::Egress).
    #[must_use]
    pub fn egress(mut self, egress: crate::core::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Ask for the whole response at once instead of streaming it.
    ///
    /// The cost is that a response dying in transit becomes
    /// [`Unavailable`](ModelError::Unavailable) — *may never have generated,
    /// safe to repeat* — when in fact it may have generated and been billed.
    #[must_use]
    pub const fn buffered(mut self) -> Self {
        self.stream = false;
        self
    }

    /// Refuse a base URL the deployment never granted.
    fn check_egress(&self, model: &ModelId) -> Result<(), ModelError> {
        let Some(egress) = &self.egress else {
            return Ok(());
        };
        let host = reqwest::Url::parse(&self.base)
            .ok()
            .and_then(|u| u.host_str().map(ToOwned::to_owned));
        egress
            .permits(host.as_deref())
            .map_err(|e| ModelError::Refused {
                model: model.clone(),
                detail: e.to_string(),
            })
    }

    /// The mode in force for a model.
    fn mode_for(&self, model: &ModelId) -> SchemaMode {
        self.schema_modes
            .get(&model.model)
            .copied()
            .unwrap_or(self.default_schema_mode)
    }

    /// Put the schema on the request, in whichever mode this driver was told to
    /// use.
    ///
    /// # Errors
    ///
    /// [`ModelError::Refused`] if the schema cannot be used with strict
    /// constrained decoding — before anything is sent, so nothing is billed.
    fn apply_schema(
        body: &mut Value,
        schema: &Value,
        model: &ModelId,
        mode: SchemaMode,
    ) -> Result<(), ModelError> {
        // Strict mode accepts a *subset* of JSON Schema, and a schema that is
        // perfectly valid elsewhere comes back as a 400 that does not say which
        // rule it broke. Checked here so the refusal names the problem.
        //
        // Not auto-corrected: rewriting the caller's schema would mean the
        // effect key records one shape while the wire carries another, and a run
        // whose journal disagrees with what it asked is the quiet divergence
        // this crate exists to prevent.
        if let Some(problem) = strict_schema_problem(schema) {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: format!(
                    "the schema cannot be used with strict constrained decoding: {problem}"
                ),
            });
        }

        match mode {
            // `strict: true` is the point: without it the schema is a
            // suggestion, and a suggestion the model may ignore is not a
            // constraint.
            SchemaMode::Native => {
                body["text"] = json!({
                    "format": {
                        "type": "json_schema",
                        "name": RESPOND_TOOL,
                        "strict": true,
                        "schema": schema,
                    }
                });
            }
            // The universal fallback, for models without constrained decoding:
            // one function the model is obliged to call, whose parameters are
            // the answer's shape.
            SchemaMode::ForcedTool => {
                body["tools"] = json!([{
                    "type": "function",
                    "name": RESPOND_TOOL,
                    "description": "Return the answer in the required shape.",
                    "strict": true,
                    "parameters": schema,
                }]);
                body["tool_choice"] = json!({ "type": "function", "name": RESPOND_TOOL });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Deserialize)]
struct TokenDetails {
    #[serde(default)]
    reasoning_tokens: u64,
}

#[derive(Debug, Default, Deserialize)]
struct InputDetails {
    /// Served from the cache. **A subset of** `input_tokens`, unlike Anthropic's
    /// separate counters — adding it would double-count.
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct ApiUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    input_tokens_details: Option<InputDetails>,
    #[serde(default)]
    output_tokens_details: Option<TokenDetails>,
}

#[derive(Debug, Deserialize)]
struct Incomplete {
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    /// Raw by design: every field, including fields this SDK version does not
    /// know, must be returned to Responses on a tool continuation.
    output: Vec<Value>,
    #[serde(default)]
    usage: Option<ApiUsage>,
    #[serde(default)]
    incomplete_details: Option<Incomplete>,
    #[serde(default)]
    error: Option<Value>,
}

impl ApiResponse {
    /// Everything billed, including tokens the caller never sees.
    ///
    /// `output_tokens` already includes reasoning tokens in the Responses API;
    /// the detail is read only so a driver bug that double-counts or omits them
    /// is visible in the one place that would notice.
    fn usage(&self) -> Usage {
        let u = self.usage.as_ref();
        Usage {
            // Already includes cached tokens here — the opposite of Anthropic,
            // where they sit beside the count. Nothing is added back.
            input_tokens: u.map_or(0, |u| u.input_tokens),
            output_tokens: u.map_or(0, |u| u.output_tokens),
            // Responses reports no cache-write counter; a write is billed as
            // ordinary input, so leaving this zero is accurate rather than
            // unknown.
            cache_write_tokens: 0,
            cache_read_tokens: u
                .and_then(|u| u.input_tokens_details.as_ref())
                .map_or(0, |d| d.cached_tokens),
            // Priced by the deployment: rates change, differ per model, and are
            // a contract with the provider rather than this crate's guess.
            minor_units: 0,
        }
    }

    fn reasoning_tokens(&self) -> u64 {
        self.usage
            .as_ref()
            .and_then(|u| u.output_tokens_details.as_ref())
            .map_or(0, |d| d.reasoning_tokens)
    }

    fn text(&self) -> String {
        self.output
            .iter()
            // A `phase: "commentary"` message is the model narrating on its
            // way to the answer — typically the preamble beside a tool call.
            // Concatenated into `text` it pollutes the answer, and on a
            // schema-bearing final turn it breaks the JSON parse of an
            // otherwise valid answer. Absent `phase` means the final answer,
            // which is what every model before the field emitted. The
            // commentary itself is not lost: the continuation carries the
            // output items verbatim, and a live observer streams the deltas.
            .filter(|item| item.get("phase").and_then(Value::as_str) != Some("commentary"))
            .filter_map(|item| item.get("content").and_then(Value::as_array))
            .flatten()
            .filter(|part| part.get("type").and_then(Value::as_str) == Some("output_text"))
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("")
    }

    /// The arguments a forced function call carried, as the raw JSON string.
    fn forced_tool_arguments(&self) -> Option<&str> {
        self.output
            .iter()
            .find(|item| {
                item.get("type").and_then(Value::as_str) == Some("function_call")
                    && item.get("name").and_then(Value::as_str) == Some(RESPOND_TOOL)
            })
            .and_then(|item| item.get("arguments").and_then(Value::as_str))
    }

    /// Tool calls the model asked for, excluding this crate's forced one.
    ///
    /// Must agree with the streaming path: streaming is the default, so a
    /// difference here would surface as a loop that fires in tests and never in
    /// production.
    ///
    /// `OpenAI` sends arguments as a JSON **string**, so unlike Anthropic there
    /// is parsing to do. A malformed call is a provider-protocol failure, not
    /// "no call": silently dropping it can turn a response containing one bad
    /// and one good side effect into permission to execute only the good one.
    fn tool_calls(&self) -> Result<Vec<super::ToolCall>, String> {
        self.output
            .iter()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .filter(|item| item.get("name").and_then(Value::as_str) != Some(RESPOND_TOOL))
            .map(|item| {
                let id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| "a function call carried no call_id".to_owned())?;
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| format!("function call '{id}' carried no name"))?;
                let raw = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        format!("function call '{id}' for '{name}' carried no arguments")
                    })?;
                let arguments = serde_json::from_str(raw).map_err(|error| {
                    format!(
                        "function call '{id}' for '{name}' carried malformed JSON arguments: {error}"
                    )
                })?;
                Ok(super::ToolCall {
                    id,
                    name,
                    arguments,
                })
            })
            .collect()
    }

    /// The model's own refusal, if it emitted one.
    fn refusal(&self) -> Option<&str> {
        self.output
            .iter()
            .filter_map(|item| item.get("content").and_then(Value::as_array))
            .flatten()
            .find(|part| part.get("type").and_then(Value::as_str) == Some("refusal"))
            .and_then(|part| part.get("refusal").and_then(Value::as_str))
    }

    /// Every output item exactly as the next Responses request needs it.
    fn continuation(&self) -> Value {
        Value::Array(self.output.clone())
    }
}

/// The prompt shapes this driver accepts.
///
/// A bare string, the API's own `input` array, or an object carrying one.
/// Whatever the shape, it is part of the effect key — so a changed prompt is a
/// changed effect and shows up on replay as divergence rather than as a run that
/// quietly did something else.
fn input(prompt: &Value) -> Value {
    match prompt {
        Value::String(s) => json!(s),
        Value::Array(_) => prompt.clone(),
        other => other.get("input").cloned().unwrap_or_else(|| {
            // `system` is an instruction about the content, not content; leaving
            // it in would show the caller's instruction to the model as part of
            // the question it is answering.
            let mut rest = other.clone();
            if let Some(map) = rest.as_object_mut() {
                map.remove("system");
            }
            json!(rest.to_string())
        }),
    }
}

/// Append the turn that already happened, as Responses items.
///
/// The input array holds typed items, so a continuation is two per call: the
/// `function_call` the model emitted, then a `function_call_output` carrying the
/// same `call_id`. Both are required — an output whose call is missing is
/// rejected with *"No tool call found for function call output with `call_id`"*,
/// which is the single most common mistake against this API.
///
/// A string input becomes a message item first, because items and a bare string
/// cannot be mixed in one array.
fn continue_with(
    input: Value,
    exchanges: &[super::ToolExchange],
    continuation: Option<&super::ProviderContinuation>,
) -> Value {
    if exchanges.is_empty() {
        return input;
    }
    let mut out = match input {
        Value::Array(v) => v,
        other => vec![json!({ "role": "user", "content": other })],
    };
    if let Some(state) = continuation.and_then(|state| state.state.as_array()) {
        out.extend(state.iter().cloned());
    } else {
        // Compatibility path for manually assembled, non-reasoning exchanges.
        // Built-in completions always carry their exact provider output.
        out.extend(exchanges.iter().map(|e| {
            json!({
                "type": "function_call",
                "call_id": e.call.id,
                "name": e.call.name,
                "arguments": e.call.arguments.to_string(),
            })
        }));
    }
    for e in exchanges {
        out.push(json!({
            "type": "function_call_output",
            "call_id": e.call.id,
            "output": match &e.output {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        }));
    }
    Value::Array(out)
}

fn function_outputs(exchanges: &[super::ToolExchange]) -> impl Iterator<Item = Value> + '_ {
    exchanges.iter().map(|exchange| {
        json!({
            "type": "function_call_output",
            "call_id": exchange.call.id,
            "output": match &exchange.output {
                Value::String(value) => value.clone(),
                other => other.to_string(),
            },
        })
    })
}

/// Extend the provider transcript after a successful response.
fn accumulate_continuation(
    completion: &mut Completion,
    prior: Option<&super::ProviderContinuation>,
    exchanges: &[super::ToolExchange],
) {
    let Some(current) = completion.continuation.as_mut() else {
        return;
    };
    let mut state = prior
        .and_then(|value| value.state.as_array())
        .cloned()
        .unwrap_or_default();
    state.extend(function_outputs(exchanges));
    if let Some(items) = current.state.as_array() {
        state.extend(items.iter().cloned());
    }
    current.state = Value::Array(state);
}

/// The system instruction, if the caller set one.
///
/// Spelled `system` by the caller and `instructions` on the wire, because that
/// is what the Responses API calls it. One vocabulary across providers is the
/// point of the seam: a prompt written once should not have to know which
/// driver is linked.
fn instructions(prompt: &Value) -> Option<Value> {
    prompt.get("system").cloned().filter(|s| !s.is_null())
}

impl OpenAi {
    /// The request body, identical either way but for the `stream` flag.
    #[cfg(test)]
    fn body(
        &self,
        model: &ModelId,
        prompt: &Value,
        schema: Option<&Value>,
        tools: &[super::ToolDeclaration],
        exchanges: &[super::ToolExchange],
    ) -> Result<Value, ModelError> {
        self.body_with_max(
            model,
            prompt,
            ModelCall::DEFAULT_MAX_OUTPUT_TOKENS,
            None,
            schema,
            tools,
            exchanges,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn body_with_max(
        &self,
        model: &ModelId,
        prompt: &Value,
        max_output_tokens: u32,
        reasoning_effort: Option<super::ReasoningEffort>,
        schema: Option<&Value>,
        tools: &[super::ToolDeclaration],
        exchanges: &[super::ToolExchange],
        continuation: Option<&super::ProviderContinuation>,
    ) -> Result<Value, ModelError> {
        if let Some(state) = continuation
            && (state.provider != "openai" || !state.state.is_array())
        {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "the continuation was not an OpenAI output-item array".to_owned(),
            });
        }
        if reasoning_effort.is_some() && !exchanges.is_empty() && continuation.is_none() {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "reasoning-enabled tool continuation requires the complete opaque \
                         output items from the prior OpenAI response"
                    .to_owned(),
            });
        }
        if continuation.is_some() && exchanges.is_empty() {
            // Silently dropping it would journal an effect key that records a
            // continuation the wire never carried. OpenAI continuations carry
            // a model turn only across tool calls.
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "a continuation without tool exchanges has no request to follow".to_owned(),
            });
        }
        let mut body = json!({
            "model": model.model,
            "max_output_tokens": max_output_tokens,
            "input": continue_with(input(prompt), exchanges, continuation),
            // Responses are retained by API default. State held by a provider
            // cannot be this runtime's replay truth, and retaining governed
            // prompts is a deployment decision rather than an invisible SDK
            // default.
            "store": self.retain_responses,
        });
        if !self.retain_responses {
            // Without this, an unstored response returns reasoning items as
            // bare ids — and the next turn sends ids the provider no longer
            // resolves, so the stateless multi-turn pattern the continuation
            // promises fails on the wire. The encrypted payload is what makes
            // "the model's turn is carried verbatim" true when nothing is
            // retained provider-side.
            body["include"] = json!(["reasoning.encrypted_content"]);
        }
        if let Some(effort) = reasoning_effort {
            body["reasoning"] = json!({ "effort": effort.as_str() });
        }
        if let Some(system) = instructions(prompt) {
            body["instructions"] = system;
        }
        if let Some(schema) = schema {
            if self.mode_for(model) == SchemaMode::ForcedTool && !tools.is_empty() {
                // The fallback spends `tools` and `tool_choice` on the
                // answer's shape; merged with real tools, whichever was
                // written second would silently replace the first while
                // `tool_choice` still forced the replaced one — a request
                // this driver itself constructed invalid.
                return Err(ModelError::Refused {
                    model: model.clone(),
                    detail: format!(
                        "model '{}' has no native structured output here, so a declared \
                         response schema is obtained by forcing a synthetic tool — which \
                         cannot be combined with the {} tool(s) this request declares. \
                         Use a model with native structured output, or drop the schema \
                         and validate the answer yourself",
                        model.model,
                        tools.len()
                    ),
                });
            }
            Self::apply_schema(&mut body, schema, model, self.mode_for(model))?;
        }
        if self.stream {
            body["stream"] = json!(true);
        }
        // **Flat**, which is what Responses takes: `{type, name, description,
        // parameters, strict}`. Chat Completions is the API that nests them
        // under a `function` object; sending that shape here answers `Missing
        // required parameter: 'tools[0].name'` and the call never reaches a
        // model.
        //
        // A stubbed provider accepts either shape, so nothing local can tell
        // them apart — this is what the live tests exist for. Keep it in step
        // with the forced-tool path a few lines above, which spells the same
        // rule.
        //
        // `strict` enforces the argument schema *during* generation rather than
        // checking afterwards — worth having, and not a security control: a
        // well-formed argument is still an untrusted one, and the sink's
        // field-provenance rules are what refuse it.
        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        // Responses rejects `strict: true` when a schema falls
                        // outside its documented subset (notably optional
                        // object fields). Such schemas are still valid tool
                        // contracts and local typed tools still deserialize
                        // their arguments exactly, so retain the declaration
                        // and make the wire's weaker guarantee explicit rather
                        // than turning every optional Rust field into a remote
                        // 400 response.
                        let strict = strict_schema_problem(&t.parameters).is_none();
                        json!({
                            "type": "function",
                            "name": t.name,
                            "description": t.description,
                            "parameters": t.parameters,
                            "strict": strict,
                        })
                    })
                    .collect(),
            );
        }
        Ok(body)
    }

    /// Turn a completed Responses object into a [`Completion`].
    ///
    /// Shared by both paths, and shared *exactly*: the streaming terminal events
    /// nest the same `response` object the buffered call returns, so there is one
    /// interpretation of what counts as a usable answer rather than two that can
    /// drift apart.
    fn interpret(
        &self,
        parsed: &ApiResponse,
        model: &ModelId,
        schema: Option<&Value>,
    ) -> Result<Completion, ModelError> {
        let usage = parsed.usage();

        // It generated and then declined. `Unusable` rather than `Refused`
        // precisely because it *generated*: a refusal before generating costs
        // nothing, and one after costs whatever it took to decide.
        if let Some(why) = parsed.refusal() {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: format!("the model declined to answer: {why}"),
            });
        }

        // `failed` means it started and gave up. Metered for the same reason.
        if parsed.status == "failed" {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: parsed
                    .error
                    .as_ref()
                    .map_or_else(|| "the response failed".to_owned(), ToString::to_string),
            });
        }

        let text = parsed.text();
        let truncated = parsed.status == "incomplete";

        // Empty *and* not truncated is an answer with nothing in it — unusable,
        // and billed. Empty *because* it was cut off is reported through
        // `truncated`, so a caller can tell "it said nothing" from "it was still
        // talking".
        //
        // **A tool call is not an empty answer.** Responses returns a
        // `function_call` item and no text whenever the model calls a tool —
        // both when this crate forces one to emulate structured output, and when
        // the model picks a declared tool of its own accord. Only the first was
        // exempted here, so an ordinary tool call came back as `Unusable` and
        // every declared-tool loop against `OpenAI` failed on a response that
        // had worked perfectly.
        //
        // It survived because a stubbed provider always returns text: nothing in
        // the suite could produce the shape a real model produces. A live test
        // found it on its first run.
        let emulating = schema.is_some() && self.mode_for(model) == SchemaMode::ForcedTool;
        let calls = parsed.tool_calls().map_err(|detail| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail,
        })?;
        if text.is_empty() && calls.is_empty() && !truncated && !emulating {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: format!(
                    "the answer carried no text content (status '{}', {} reasoning token(s))",
                    parsed.status,
                    parsed.reasoning_tokens()
                ),
            });
        }

        // Emulated mode answers with a `function_call` item and no text. Unlike
        // Anthropic, the arguments arrive as a JSON *string*, so they are parsed
        // through the same path a native answer takes — and a provider that
        // emits malformed arguments produces the same loud, metered failure.
        let (text, structured_value) = if emulating {
            let Some(raw) = parsed.forced_tool_arguments() else {
                return Err(ModelError::Unusable {
                    model: model.clone(),
                    usage,
                    detail: "a tool call was forced and the answer carried none — \
                             the model did not honour `tool_choice`"
                        .to_owned(),
                });
            };
            (raw.to_owned(), structured(schema, raw, &[], model, usage)?)
        } else {
            let parsed_schema = structured(schema, &text, &calls, model, usage)?;
            (text, parsed_schema)
        };

        let continuation = (!calls.is_empty())
            .then(|| super::ProviderContinuation::new("openai", parsed.continuation()));
        Ok(Completion {
            structured: structured_value,
            tool_calls: calls,
            text,
            usage,
            stop_reason: Some(parsed.incomplete_details.as_ref().map_or_else(
                || parsed.status.clone(),
                |i| format!("incomplete:{}", i.reason),
            )),
            truncated,
            continuation,
        })
    }

    async fn read_buffered(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
    ) -> Result<Completion, ModelError> {
        // Read under this plane's ceiling rather than to end-of-stream: a
        // provider is a counterparty, and a counterparty must not decide how
        // much of this process's memory its answer costs.
        let body = crate::netguard::intake::read(response, crate::netguard::intake::ANSWER)
            .await
            .map_err(|e| super::wire::classify_intake(model, Usage::default(), &e))?;
        let parsed: ApiResponse =
            serde_json::from_slice(&body).map_err(|e| ModelError::Unusable {
                // A 200 whose body will not parse still generated: those tokens are
                // spent whatever shape came back. Reporting zero here is the one
                // place this path knowingly under-counts, bounded by one response.
                model: model.clone(),
                usage: Usage::default(),
                detail: format!("the response body did not parse: {e}"),
            })?;
        self.interpret(&parsed, model, schema)
    }

    /// Read the response as it arrives.
    ///
    /// **This buys less than it does for Anthropic, and the difference is the
    /// point.** Anthropic reports usage incrementally, so a severed stream there
    /// still knows what it burned. `OpenAI` carries `usage` only in the terminal
    /// event, so a stream cut mid-answer knows that generation *happened* and
    /// nothing about its cost — which is
    /// [`ModelError::Unaccounted`], and which is still strictly better than the
    /// buffered path's `Unavailable`, because that one says the call may never
    /// have run and is safe to send again.
    async fn read_streamed(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
        observer: Option<(&dyn super::ModelStreamObserver, &crate::core::Label)>,
    ) -> Result<Completion, ModelError> {
        use futures_util::StreamExt;

        let mut decoder = sse::Decoder::new();
        let mut acc = openai_stream::Accumulator::new();
        let mut body = response.bytes_stream();
        // The same ceiling the buffered path applies, to the same bytes.
        // `sse::Decoder` already bounds one event, which is the unterminated
        // line; this bounds the *number* of them. A stream of well-formed
        // hundred-byte deltas passes every check the decoder makes and grows
        // the accumulator until the process dies.
        let mut meter = crate::netguard::intake::Meter::new(crate::netguard::intake::ANSWER);

        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => return Err(severed(model, &acc, &e.to_string())),
            };
            // Charged before the chunk is kept: what the ceiling bounds is
            // what this process holds, not what it has already held. The
            // refusal is `Unusable` rather than `severed` — it is this
            // plane's rather than the provider's, and the call generated.
            // This wire reports no usage until the end, so the figure is
            // zero here for the same reason `severed` reports `Unaccounted`:
            // what is unknown is the amount, not whether it happened.
            if let Err(e) = meter.charge(chunk.len()) {
                return Err(super::wire::classify_intake(model, Usage::default(), &e));
            }
            // A decode failure ends the stream exactly as a dead connection
            // does, and is classified by the same ladder rather than pinned to
            // one rung.
            let events = match decoder.push(&chunk) {
                Ok(events) => events,
                Err(error) => return Err(severed(model, &acc, &error.to_string())),
            };
            for event in events {
                // Fed from the accumulator's own parse, so the live text and
                // the assembled outcome are one stream by construction.
                let delta = acc.event(&event.name, &event.data);
                if let Some(text) = delta
                    && let Some((observer, label)) = observer
                {
                    observer.event(crate::core::Tainted::with_label(
                        super::ModelStreamEvent::TextDelta(text),
                        label.clone(),
                    ));
                }
            }
            if let Some(message) = acc.error() {
                // An `error` event inside a 200. If output had already been
                // seen, the call was billed and must not be retried for free.
                return Err(severed(model, &acc, message));
            }
            if acc.outcome().is_some() {
                break;
            }
        }

        let Some(terminal) = acc.terminal() else {
            return Err(severed(
                model,
                &acc,
                "the stream ended before a terminal `response.*` event",
            ));
        };

        // The terminal event nests the same object the buffered call returns, so
        // this is the identical parse and the identical interpretation.
        let parsed: ApiResponse =
            serde_json::from_value(terminal.clone()).map_err(|e| ModelError::Unusable {
                model: model.clone(),
                usage: Usage::default(),
                detail: format!("the terminal stream event did not parse: {e}"),
            })?;
        let completion = self.interpret(&parsed, model, schema)?;
        if let Some((observer, label)) = observer {
            observer.event(crate::core::Tainted::with_label(
                super::ModelStreamEvent::Usage(completion.usage),
                label.clone(),
            ));
        }
        Ok(completion)
    }
}

/// A stream that stopped before its terminal event.
///
/// The whole judgement is `generated()`: whether any output delta was seen.
/// Before the first one, nothing is known to have happened and the call is safe
/// to repeat; after it, the provider will bill for tokens this driver cannot
/// count, and repeating buys a second bill for the same question.
fn severed(model: &ModelId, acc: &openai_stream::Accumulator, detail: &str) -> ModelError {
    if acc.generated() {
        return ModelError::Unaccounted {
            model: model.clone(),
            detail: match acc.id() {
                // The id is still valuable for provider support and billing
                // correlation. It is not necessarily retrievable: private-by-
                // default requests explicitly set `store: false`.
                Some(id) => format!("{detail} (provider response id: '{id}')"),
                None => detail.to_owned(),
            },
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: format!("the stream ended before it generated: {detail}"),
    }
}

#[async_trait]
impl ModelProvider for OpenAi {
    fn request_profile(&self, model: &ModelId) -> Value {
        let schema_mode = match self.mode_for(model) {
            SchemaMode::Native => "native",
            SchemaMode::ForcedTool => "forced-tool",
        };
        json!({
            "driver": "openai-responses/v1",
            "base": self.base,
            "store": self.retain_responses,
            "schema_mode": schema_mode,
            "stream": self.stream,
            "timeout_ms": self.timeout.as_millis(),
        })
    }

    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        let Request {
            model,
            prompt,
            max_output_tokens,
            reasoning_effort,
            schema,
            tools,
            exchanges,
            continuation,
            stream,
        } = request;

        super::refuse_provider_side_media(prompt, model)?;
        super::refuse_in_thread_instructions(prompt, model)?;

        self.check_egress(model)?;

        let response = self
            .http
            .post(format!("{}/v1/responses", self.base))
            .timeout(self.timeout)
            .bearer_auth(self.key.expose())
            .json(&self.body_with_max(
                model,
                prompt,
                max_output_tokens,
                reasoning_effort,
                schema,
                tools,
                exchanges,
                continuation,
            )?)
            .send()
            .await
            .map_err(|e| classify_transport(model, &e))?;

        let status = response.status();
        if !status.is_success() {
            let headers = response.headers().clone();
            // Bounded, and the ceiling is the small one: this body is read
            // only to say *why* the call failed, so an endpoint answering a
            // failure with a gigabyte gets an unexplained failure rather than
            // this process's memory.
            let detail =
                crate::netguard::intake::read_text(response, crate::netguard::intake::METADATA)
                    .await
                    .unwrap_or_default();
            return Err(classify_status(model, status.as_u16(), &headers, &detail));
        }

        let mut completion = if self.stream {
            self.read_streamed(response, model, schema, stream).await?
        } else {
            self.read_buffered(response, model, schema).await?
        };
        if !self.stream
            && let Some((observer, label)) = stream
        {
            observer.event(crate::core::Tainted::with_label(
                super::ModelStreamEvent::Usage(completion.usage),
                label.clone(),
            ));
        }
        accumulate_continuation(&mut completion, continuation, exchanges);
        Ok(completion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Effect as _;

    fn driver() -> OpenAi {
        OpenAi::new("test-key").expect("build the driver")
    }

    #[test]
    fn provider_wire_profile_is_part_of_effect_identity() {
        let model = ModelId::new("openai", "gpt-x");
        let native = ModelCall::new(
            std::sync::Arc::new(driver()),
            model.clone(),
            json!("answer"),
        )
        .expecting(json!({"type": "object"}));
        let forced = ModelCall::new(
            std::sync::Arc::new(driver().structured_via(SchemaMode::ForcedTool)),
            model,
            json!("answer"),
        )
        .expecting(json!({"type": "object"}));

        assert_ne!(
            native.descriptor(),
            forced.descriptor(),
            "native constrained output and forced-tool output reused one effect identity"
        );
    }

    #[test]
    fn provider_retention_is_private_by_default_and_replay_visible_when_enabled() {
        let model = ModelId::new("openai", "gpt-x");
        let private = driver()
            .body(&model, &json!("sensitive"), None, &[], &[])
            .expect("private body");
        assert_eq!(
            private["store"],
            json!(false),
            "omitting `store: false` opts into OpenAI's provider-side retention default"
        );
        // The half that makes "the model's turn is carried verbatim" true on
        // the wire: without the `include`, an unstored response returns
        // reasoning items as bare ids, and the next turn sends ids the
        // provider no longer resolves — the stateless multi-turn pattern
        // fails against the live API while every local round trip passes.
        assert_eq!(
            private["include"],
            json!(["reasoning.encrypted_content"]),
            "an unstored request must ask for the encrypted reasoning payload"
        );

        let retained_driver = driver().retain_responses();
        let retained = retained_driver
            .body(&model, &json!("sensitive"), None, &[], &[])
            .expect("retained body");
        assert_eq!(retained["store"], json!(true));
        assert!(
            retained.get("include").is_none(),
            "a retained response resolves reasoning ids provider-side"
        );

        let private_call = ModelCall::new(
            std::sync::Arc::new(driver()),
            model.clone(),
            json!("sensitive"),
        );
        let retained_call = ModelCall::new(
            std::sync::Arc::new(retained_driver),
            model,
            json!("sensitive"),
        );
        assert_ne!(
            private_call.descriptor(),
            retained_call.descriptor(),
            "provider retention changed without changing effect identity"
        );
    }

    /// The Responses API spells it `instructions`; the caller spells it `system`.
    ///
    /// One vocabulary across providers is the point of the seam — a prompt
    /// written once should not have to know which driver is linked.
    #[test]
    fn a_system_instruction_becomes_the_instructions_field() {
        let body = driver()
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "system": "answer only in French", "input": "hi" }),
                None,
                &[],
                &[],
            )
            .expect("body");
        assert_eq!(
            body["instructions"], "answer only in French",
            "the system instruction must become `instructions`: {body}"
        );
        assert_eq!(body["input"], "hi", "the question must survive: {body}");
    }

    #[test]
    fn a_system_instruction_is_not_shown_as_the_question() {
        let body = driver()
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "system": "be terse", "ticket": "printer on fire" }),
                None,
                &[],
                &[],
            )
            .expect("body");
        let asked = body["input"].as_str().unwrap_or_default();
        assert!(
            !asked.contains("be terse"),
            "the instruction leaked into the question: {asked}"
        );
        assert!(
            asked.contains("printer on fire"),
            "the actual content went missing: {asked}"
        );
    }

    #[test]
    fn a_prompt_without_a_system_sends_no_instructions() {
        let body = driver()
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!("hi"),
                None,
                &[],
                &[],
            )
            .expect("body");
        assert!(
            body.get("instructions").is_none(),
            "an unset instruction must not become an empty one: {body}"
        );
    }
}

#[cfg(test)]
mod tool_tests {
    use super::*;
    use crate::model::ToolDeclaration;

    /// A tool call is an answer, not an empty one.
    ///
    /// Responses returns a `function_call` item and **no text** whenever the
    /// model calls a tool. The emptiness check exempted only the forced call
    /// this crate makes to emulate structured output, so an ordinary declared
    /// tool call came back `Unusable` — a response that had worked perfectly,
    /// reported as a fault, and billed.
    ///
    /// Nothing offline could produce that shape, because a stubbed provider
    /// always returns text. This pins it without needing an API key.
    #[test]
    fn a_tool_call_with_no_text_is_a_usable_answer() {
        let response: ApiResponse = serde_json::from_value(json!({
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call_1",
                "name": "weather_lookup",
                "arguments": "{\"city\":\"Berlin\"}"
            }],
            "usage": { "input_tokens": 55, "output_tokens": 15 }
        }))
        .expect("a Responses payload carrying only a function call");

        let completion = OpenAi::new("test-key")
            .expect("driver")
            .interpret(&response, &ModelId::new("openai", "gpt-x"), None)
            .expect(
                "a tool call with no text was rejected as an empty answer, so \
                 every declared-tool loop against OpenAI fails on a response \
                 that worked",
            );

        assert_eq!(completion.tool_calls.len(), 1);
        assert_eq!(completion.tool_calls[0].name, "weather_lookup");
        assert_eq!(completion.tool_calls[0].arguments["city"], "Berlin");
    }

    /// An answer with neither text nor a tool call is still unusable.
    ///
    /// The other half: the fix must not turn the emptiness check off, only
    /// teach it that a tool call counts.
    #[test]
    fn an_answer_with_neither_text_nor_a_tool_call_is_unusable() {
        let response: ApiResponse = serde_json::from_value(json!({
            "status": "completed",
            "output": [],
            "usage": { "input_tokens": 10, "output_tokens": 0 }
        }))
        .expect("an empty Responses payload");

        assert!(
            OpenAi::new("test-key")
                .expect("driver")
                .interpret(&response, &ModelId::new("openai", "gpt-x"), None)
                .is_err(),
            "an answer carrying nothing at all was accepted, so the emptiness \
             check was removed rather than corrected"
        );
    }

    /// A malformed call is not silently equivalent to no call.
    #[test]
    fn malformed_tool_arguments_are_a_metered_provider_failure() {
        let response: ApiResponse = serde_json::from_value(json!({
            "status": "completed",
            "output": [{
                "type": "function_call",
                "call_id": "call_1",
                "name": "ledger.transfer",
                "arguments": "{\"amount\":"
            }],
            "usage": { "input_tokens": 55, "output_tokens": 15 }
        }))
        .expect("response");

        let error = OpenAi::new("test-key")
            .expect("driver")
            .interpret(&response, &ModelId::new("openai", "gpt-x"), None)
            .expect_err("malformed arguments disappeared as if no call was emitted");
        match error {
            ModelError::Unusable { usage, detail, .. } => {
                assert_eq!(usage.input_tokens, 55);
                assert_eq!(usage.output_tokens, 15);
                assert!(detail.contains("malformed JSON arguments"), "{detail}");
            }
            other => panic!("malformed generated output was not a metered failure: {other:?}"),
        }
    }

    /// Responses takes a **flat** declaration; Chat Completions nests one.
    ///
    /// `{type, name, description, parameters, strict}` — not
    /// `{type, function: {…}}`, which is the Chat Completions shape and which
    /// Responses rejects outright with *"Missing required parameter:
    /// `tools[0].name`"*.
    ///
    /// This test previously asserted the nested shape. It was written from the
    /// same misreading as the code, so it passed forever and gave the wrong
    /// contract the appearance of being pinned — a stubbed provider accepts any
    /// shape, so nothing else could disagree. A live call against the real API
    /// found it on its first run.
    #[test]
    fn a_declared_tool_is_rendered_in_openais_shape() {
        let body = OpenAi::new("test-key")
            .expect("driver")
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "input": "hi" }),
                None,
                &[ToolDeclaration::new(
                    "ledger.read",
                    "Read a ledger entry.",
                    json!({
                        "type": "object",
                        "properties": {},
                        "required": [],
                        "additionalProperties": false,
                    }),
                )],
                &[],
            )
            .expect("a body with tools");

        let f = &body["tools"][0];
        assert_eq!(f["type"], "function", "{body}");
        assert_eq!(
            f["name"], "ledger.read",
            "the name must be at the top level — Responses answers `Missing \
             required parameter: tools[0].name` to the nested Chat Completions \
             shape, and the call never reaches a model: {body}"
        );
        assert!(
            f["function"].is_null(),
            "the declaration is nested under `function`, which is the Chat \
             Completions shape and is rejected by Responses: {body}"
        );
        assert_eq!(
            f["parameters"]["type"], "object",
            "OpenAI names the argument schema `parameters`; `input_schema` is \
             Anthropic's spelling: {body}"
        );
        assert_eq!(
            f["strict"], true,
            "strict mode enforces the argument schema during generation rather \
             than checking after the tokens are paid for: {body}"
        );

        let optional = OpenAi::new("test-key")
            .expect("driver")
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "input": "hi" }),
                None,
                &[ToolDeclaration::new(
                    "ledger.search",
                    "Search ledger entries.",
                    json!({
                        "type": "object",
                        "properties": { "cursor": { "type": "string" } },
                        "required": [],
                        "additionalProperties": false,
                    }),
                )],
                &[],
            )
            .expect("a valid non-strict tool schema remains usable");
        assert_eq!(
            optional["tools"][0]["strict"], false,
            "an optional field was advertised as strict even though OpenAI rejects that schema subset"
        );

        // The same shape the forced-tool path already used. They disagreed, and
        // only the half nothing exercised was wrong.
        let forced = OpenAi::new("test-key")
            .expect("driver")
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "input": "hi" }),
                Some(&json!({ "type": "object", "additionalProperties": false })),
                &[],
                &[],
            )
            .expect("a body with a schema");
        if let Some(tool) = forced["tools"].get(0) {
            assert!(
                tool["name"].is_string(),
                "the two tool-rendering paths in this file disagree about where \
                 the name goes: {forced}"
            );
        }
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::*;
    use crate::model::{
        ProviderContinuation, ReasoningEffort, ToolCall as ModelToolCall, ToolExchange,
    };

    /// Responses pairs a `function_call` with a `function_call_output`.
    ///
    /// An output whose call is absent is rejected — *"No tool call found for
    /// function call output with `call_id`"* — which is the commonest mistake
    /// against this API, so the pairing is pinned rather than assumed. Note the
    /// arguments are a JSON **string** here and an object on Anthropic.
    #[test]
    fn a_continuation_pairs_the_call_with_its_output() {
        let body = OpenAi::new("test-key")
            .expect("driver")
            .body(
                &ModelId::new("openai", "gpt-x"),
                &json!({ "input": "balance?" }),
                None,
                &[],
                &[ToolExchange::ok(
                    ModelToolCall {
                        id: "call_01".to_owned(),
                        name: "ledger.read".to_owned(),
                        arguments: json!({ "id": "AC-1" }),
                    },
                    json!({ "balance": 42 }),
                )],
            )
            .expect("a continuation body");

        let items = body["input"].as_array().expect("input items");
        let call = items
            .iter()
            .find(|i| i["type"] == "function_call")
            .expect("the call");
        let out = items
            .iter()
            .find(|i| i["type"] == "function_call_output")
            .expect("the output");

        assert_eq!(
            call["call_id"], out["call_id"],
            "an output without its call is rejected by the API: {body}"
        );
        assert!(
            call["arguments"].is_string(),
            "Responses carries arguments as a JSON string, unlike Anthropic's \
             object: {body}"
        );
    }

    /// Commentary narration never joins the answer's text.
    ///
    /// Responses marks the model's on-the-way narration `phase:
    /// "commentary"`; the final answer arrives unmarked or as
    /// `final_answer`. Concatenating both pollutes `Completion::text`, and
    /// on a schema-bearing turn the preamble breaks the JSON parse of an
    /// otherwise valid answer. The narration is not lost — the continuation
    /// carries every output item verbatim.
    #[test]
    fn commentary_phase_text_stays_out_of_the_answer() {
        let parsed: ApiResponse = serde_json::from_value(json!({
            "status": "completed",
            "output": [
                { "type": "message", "role": "assistant", "phase": "commentary",
                  "content": [{ "type": "output_text", "text": "Let me check the ledger. " }] },
                { "type": "message", "role": "assistant", "phase": "final_answer",
                  "content": [{ "type": "output_text", "text": "{\"balance\":42}" }] },
            ],
        }))
        .expect("parse");
        assert_eq!(
            parsed.text(),
            "{\"balance\":42}",
            "commentary narration joined the final answer"
        );
    }

    #[test]
    fn encrypted_reasoning_and_assistant_phase_round_trip_unchanged() {
        let opaque = json!([
            {
                "id": "rs_1",
                "type": "reasoning",
                "encrypted_content": "opaque-ciphertext",
                "summary": []
            },
            {
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "phase": "commentary",
                "status": "completed",
                "content": [{"type": "output_text", "text": "checking"}]
            },
            {
                "id": "fc_1",
                "type": "function_call",
                "call_id": "call_01",
                "name": "ledger.read",
                "arguments": "{\"id\":\"AC-1\"}",
                "status": "completed"
            }
        ]);
        let state = ProviderContinuation::new("openai", opaque.clone());
        let body = OpenAi::new("test-key")
            .expect("driver")
            .body_with_max(
                &ModelId::new("openai", "gpt-x"),
                &json!({"input": "balance?"}),
                4096,
                Some(ReasoningEffort::High),
                None,
                &[],
                &[ToolExchange::ok(
                    ModelToolCall {
                        id: "call_01".to_owned(),
                        name: "ledger.read".to_owned(),
                        arguments: json!({"id": "AC-1"}),
                    },
                    json!({"balance": 42}),
                )],
                Some(&state),
            )
            .expect("lossless reasoning continuation");

        assert_eq!(
            &body["input"].as_array().unwrap()[1..4],
            opaque.as_array().unwrap()
        );
        assert_eq!(body["input"][4]["type"], "function_call_output");
    }

    #[test]
    fn continuation_accumulates_every_prior_tool_turn() {
        let prior = ProviderContinuation::new(
            "openai",
            json!([{"type": "reasoning", "encrypted_content": "first"}]),
        );
        let exchange = ToolExchange::ok(
            ModelToolCall {
                id: "call_1".to_owned(),
                name: "lookup".to_owned(),
                arguments: json!({}),
            },
            json!({"value": 1}),
        );
        let mut completion = Completion {
            text: String::new(),
            tool_calls: vec![ModelToolCall {
                id: "call_2".to_owned(),
                name: "lookup".to_owned(),
                arguments: json!({}),
            }],
            usage: Usage::default(),
            stop_reason: Some("completed".to_owned()),
            truncated: false,
            structured: None,
            continuation: Some(ProviderContinuation::new(
                "openai",
                json!([{"type": "function_call", "call_id": "call_2"}]),
            )),
        };
        accumulate_continuation(&mut completion, Some(&prior), &[exchange]);
        let state = completion.continuation.unwrap().state;
        assert_eq!(state[0]["encrypted_content"], "first");
        assert_eq!(state[1]["type"], "function_call_output");
        assert_eq!(state[2]["call_id"], "call_2");
    }
}
