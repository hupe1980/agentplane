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
    max_output_tokens: u32,
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
}

impl std::fmt::Debug for OpenAi {
    /// Redacts the key: a secret that can be printed is a secret in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAi")
            .field("base", &self.base)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl OpenAi {
    /// A ceiling every request carries.
    ///
    /// An output limit is the cheapest spend control there is. The run-level
    /// ceilings in `core::budget` bound the run; this bounds the call.
    pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4096;

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
            max_output_tokens: Self::DEFAULT_MAX_OUTPUT_TOKENS,
            default_schema_mode: SchemaMode::Native,
            schema_modes: std::collections::BTreeMap::new(),
            stream: true,
            egress: None,
        })
    }

    /// Point at a different host — a gateway, or a test server.
    #[must_use]
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = base.into();
        self
    }

    #[must_use]
    pub const fn max_output_tokens(mut self, n: u32) -> Self {
        self.max_output_tokens = n;
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
struct ContentPart {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    refusal: String,
}

#[derive(Debug, Deserialize)]
struct OutputItem {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    content: Vec<ContentPart>,
    /// A forced function call's arguments — a JSON **string**, unlike
    /// Anthropic's decoded object.
    #[serde(default)]
    arguments: Option<String>,
    #[serde(default)]
    name: Option<String>,
    /// The call id a result must be returned under.
    #[serde(default)]
    call_id: Option<String>,
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
    output: Vec<OutputItem>,
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
            .flat_map(|i| i.content.iter())
            .filter(|c| c.kind == "output_text")
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join("")
    }

    /// The arguments a forced function call carried, as the raw JSON string.
    fn forced_tool_arguments(&self) -> Option<&str> {
        self.output
            .iter()
            .find(|i| i.kind == "function_call" && i.name.as_deref() == Some(RESPOND_TOOL))
            .and_then(|i| i.arguments.as_deref())
    }

    /// Tool calls the model asked for, excluding this crate's forced one.
    ///
    /// Must agree with the streaming path: streaming is the default, so a
    /// difference here would surface as a loop that fires in tests and never in
    /// production.
    ///
    /// `OpenAI` sends arguments as a JSON **string**, so unlike Anthropic there is
    /// parsing to do — and a call whose arguments do not parse is dropped rather
    /// than passed on half-built, since dispatching a real side effect from a
    /// fragment is worse than reporting nothing.
    fn tool_calls(&self) -> Vec<super::ToolCall> {
        self.output
            .iter()
            .filter(|i| i.kind == "function_call")
            .filter(|i| i.name.as_deref() != Some(RESPOND_TOOL))
            .filter_map(|i| {
                Some(super::ToolCall {
                    id: i.call_id.clone()?,
                    name: i.name.clone()?,
                    arguments: serde_json::from_str(i.arguments.as_deref()?).ok()?,
                })
            })
            .collect()
    }

    /// The model's own refusal, if it emitted one.
    fn refusal(&self) -> Option<&str> {
        self.output
            .iter()
            .flat_map(|i| i.content.iter())
            .find(|c| c.kind == "refusal")
            .map(|c| c.refusal.as_str())
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
fn continue_with(input: Value, exchanges: &[super::ToolExchange]) -> Value {
    if exchanges.is_empty() {
        return input;
    }
    let mut out = match input {
        Value::Array(v) => v,
        other => vec![json!({ "role": "user", "content": other })],
    };
    for e in exchanges {
        out.push(json!({
            "type": "function_call",
            "call_id": e.call.id,
            "name": e.call.name,
            // Responses carries arguments as a JSON *string*, unlike the object
            // Anthropic takes.
            "arguments": e.call.arguments.to_string(),
        }));
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
    fn body(
        &self,
        model: &ModelId,
        prompt: &Value,
        schema: Option<&Value>,
        tools: &[super::ToolDeclaration],
        exchanges: &[super::ToolExchange],
    ) -> Result<Value, ModelError> {
        let mut body = json!({
            "model": model.model,
            "max_output_tokens": self.max_output_tokens,
            "input": continue_with(input(prompt), exchanges),
        });
        if let Some(system) = instructions(prompt) {
            body["instructions"] = system;
        }
        if let Some(schema) = schema {
            Self::apply_schema(&mut body, schema, model, self.mode_for(model))?;
        }
        if self.stream {
            body["stream"] = json!(true);
        }
        // Responses wraps each declaration: `{type: "function", function: {name,
        // description, parameters}}`, where Anthropic takes the three fields at
        // the top level under `input_schema`. `strict` enforces the argument
        // schema *during* generation rather than checking afterwards — worth
        // having, and not a security control: a well-formed argument is still
        // an untrusted one, and the sink's field-provenance rules are what
        // refuse it.
        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description,
                                "parameters": t.parameters,
                                "strict": true,
                            }
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
        // Skipped in emulated mode, and the skip is load-bearing: a forced
        // function call answers with a `function_call` item and **no text**, so
        // an unguarded emptiness check here rejects a call that worked.
        let emulating = schema.is_some() && self.mode_for(model) == SchemaMode::ForcedTool;
        if text.is_empty() && !truncated && !emulating {
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
            (raw.to_owned(), structured(schema, raw, model, usage)?)
        } else {
            let parsed_schema = structured(schema, &text, model, usage)?;
            (text, parsed_schema)
        };

        Ok(Completion {
            structured: structured_value,
            tool_calls: parsed.tool_calls(),
            text,
            usage,
            stop_reason: Some(parsed.incomplete_details.as_ref().map_or_else(
                || parsed.status.clone(),
                |i| format!("incomplete:{}", i.reason),
            )),
            truncated,
        })
    }

    async fn read_buffered(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
    ) -> Result<Completion, ModelError> {
        let parsed: ApiResponse = response.json().await.map_err(|e| ModelError::Unusable {
            model: model.clone(),
            // A 200 whose body will not parse still generated: those tokens are
            // spent whatever shape came back. Reporting zero here is the one
            // place this path knowingly under-counts, bounded by one response.
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
    ) -> Result<Completion, ModelError> {
        use futures_util::StreamExt;

        let mut decoder = sse::Decoder::new();
        let mut acc = openai_stream::Accumulator::new();
        let mut body = response.bytes_stream();

        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => return Err(severed(model, &acc, &e.to_string())),
            };
            for event in decoder.push(&chunk) {
                acc.event(&event.name, &event.data);
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
        self.interpret(&parsed, model, schema)
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
                Some(id) => {
                    format!("{detail} (response '{id}' can be read back to account for it)")
                }
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
    async fn complete(&self, request: Request<'_>) -> Result<Completion, ModelError> {
        let Request {
            model,
            prompt,
            schema,
            tools,
            exchanges,
        } = request;

        super::refuse_provider_side_media(prompt, model)?;

        self.check_egress(model)?;

        let response = self
            .http
            .post(format!("{}/v1/responses", self.base))
            .bearer_auth(self.key.expose())
            .json(&self.body(model, prompt, schema, tools, exchanges)?)
            .send()
            .await
            .map_err(|e| classify_transport(model, &e))?;

        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            return Err(classify_status(model, status.as_u16(), &detail));
        }

        if self.stream {
            self.read_streamed(response, model, schema).await
        } else {
            self.read_buffered(response, model, schema).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver() -> OpenAi {
        OpenAi::new("test-key").expect("build the driver")
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

    /// Responses wraps a declaration; Anthropic does not.
    ///
    /// `{type: "function", function: {name, description, parameters}}` against
    /// Anthropic's three top-level fields under `input_schema`. Sending either
    /// shape to the other provider is rejected, so both are pinned.
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
                    json!({ "type": "object" }),
                )],
                &[],
            )
            .expect("a body with tools");

        let f = &body["tools"][0];
        assert_eq!(
            f["type"], "function",
            "Responses requires the wrapper: {body}"
        );
        assert_eq!(f["function"]["name"], "ledger.read");
        assert_eq!(
            f["function"]["parameters"]["type"], "object",
            "OpenAI names the argument schema `parameters`; `input_schema` is \
             Anthropic's spelling: {body}"
        );
        assert_eq!(
            f["function"]["strict"], true,
            "strict mode enforces the argument schema during generation rather \
             than checking after the tokens are paid for: {body}"
        );
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::*;
    use crate::model::{ToolCall as ModelToolCall, ToolExchange};

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
}
