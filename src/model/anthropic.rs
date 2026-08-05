//! A `ModelProvider` for the Anthropic Messages API.
//!
//! Behind the `providers` feature. The [`ModelProvider`] trait and the metering
//! rules are always available; this is one concrete driver, and it exists mostly
//! to prove the seam is the right shape — in particular that a driver can report
//! *what a failure consumed*, which is the whole reason [`ModelError`] carries
//! usage at all.
//!
//! # The only interesting part is the failure table
//!
//! Everything else is JSON. What a driver has to get right is the distinction
//! between a call that cost nothing and a call that cost money and produced
//! nothing, because the budget ceiling is only as honest as this mapping:
//!
//! | Response | Meaning | Metered |
//! |---|---|---|
//! | connect/DNS/TLS failure | never arrived | no |
//! | `400 invalid_request_error` | refused before generating | no |
//! | `401`, `403` | refused before generating | no |
//! | `429`, `529 overloaded` | rate limited before generating | no |
//! | `5xx` | arrived; whether it generated is unknowable here | see below |
//! | `200` with `stop_reason: "refusal"` | it generated, and declined | **yes** |
//! | `200` with no text content | it generated something unusable | **yes** |
//!
//! # The 5xx row, stated honestly
//!
//! A non-streaming 5xx has reached the provider. Whether tokens were generated
//! and billed cannot be known from the response, and guessing in either
//! direction is wrong in a different way: calling it `Interrupted` makes a
//! transient blip fatal to the run, and calling it free lets a retry loop spend
//! real money against a ceiling that reads zero.
//!
//! [`ModelError::Unavailable`] names the case rather than hiding it. It is
//! treated as safe to repeat — a completion does not change the world, so
//! repeating is a correctness no-op — and the documented cost is that the spend
//! ceiling may under-count by at most one call per occurrence.
//!
//! **That row describes [`Anthropic::buffered`], which is not the default.**
//! This driver streams, because Anthropic reports usage incrementally:
//! `message_start` carries the input tokens and both cache counters before a
//! single output token exists, and every `message_delta` updates a cumulative
//! output count. A connection that dies mid-answer therefore reports
//! [`ModelError::Interrupted`] with what it actually burned, rather than
//! shrugging and being billed as zero.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::core::Secret;

#[cfg(test)]
use super::ModelCall;
use super::wire::{RESPOND_TOOL, classify_status, classify_transport, structured};
use super::{
    Completion, ModelError, ModelId, ModelProvider, Request, SchemaMode, Usage, anthropic_stream,
    sse,
};

/// Calls the Anthropic Messages API.
///
/// The key is held here and never journaled — it is transport metadata in
/// exactly the sense a peer credential is, and the same rule applies: a secret
/// in a hash-chained record cannot be redacted afterwards, only discovered.
pub struct Anthropic {
    http: reqwest::Client,
    key: Secret,
    base: String,
    version: String,
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
    /// **On by default**, which is a deliberate departure from the obvious. This
    /// runtime is not rendering tokens to anybody, so streaming buys no latency
    /// here; what it buys is that Anthropic reports usage *incrementally*, so a
    /// severed connection can say what it burned instead of shrugging. That
    /// turns an [`Unavailable`](ModelError::Unavailable) — treated as safe to
    /// repeat, billed as zero — into an [`Interrupted`](ModelError::Interrupted)
    /// carrying real tokens. Strictly better accounting for the same call, so
    /// the honest setting is the default one.
    stream: bool,
    /// Where this driver may connect, if the deployment says.
    egress: Option<crate::core::Egress>,
    /// Whole HTTP request, including a streamed response body.
    timeout: std::time::Duration,
}

impl std::fmt::Debug for Anthropic {
    /// Redacts the key. Deriving `Debug` would print it into every log line and
    /// span that touches the provider.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anthropic")
            .field("base", &self.base)
            .field("version", &self.version)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Anthropic {
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

    /// The API version this driver speaks.
    ///
    /// Pinned rather than tracking the newest: a provider that changes its
    /// response shape under a running plane changes what replay reads back.
    pub const VERSION: &'static str = "2023-06-01";

    /// A ceiling the request must carry, because the API requires one.
    ///
    /// Deliberately not unbounded-by-default: an output limit is the cheapest
    /// spend control there is, and the budget ceilings in `core::budget` govern
    /// the run rather than the individual call.
    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(key: impl Into<String>) -> Result<Self, ModelError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ModelError::Unreachable {
                model: ModelId::new("anthropic", "*"),
                detail: format!("could not build an HTTP client: {e}"),
            })?;
        Ok(Self {
            http,
            key: Secret::new(key),
            base: "https://api.anthropic.com".to_owned(),
            version: Self::VERSION.to_owned(),
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

    /// How to obtain a schema-conforming answer from this model.
    ///
    /// Native constrained decoding is gated on particular models. Point this
    /// driver at one that predates it and the request is rejected outright —
    /// which is loud, but the fix is [`SchemaMode::ForcedTool`], and it is here
    /// rather than discovered because the crate cannot ask a model what it
    /// supports without a network call on a path that must not make one.
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
    /// The cost of turning streaming off is stated plainly because it is easy to
    /// reach for: a non-streaming response that dies in transit reports
    /// [`Unavailable`](ModelError::Unavailable) — cost unknown, treated as safe
    /// to repeat, billed as zero. The streaming path reports what it actually
    /// burned. Reasons to do it anyway are real (a proxy that buffers SSE into
    /// uselessness, a gateway that does not forward it), which is why the knob
    /// exists rather than the behaviour being fixed.
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
        // Parsed by the same library that will do the connecting, so the
        // allowlist cannot disagree with the client about what the host is.
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
}

/// Mirrors the provider's field names exactly, postfixes and all.
///
/// Renaming them to something tidier would mean a `serde` rename on every field
/// and a mapping nobody can check against the API docs at a glance — which is
/// how a driver ends up reading the wrong counter.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct ApiUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    /// Written into the cache this call. **Not** included in `input_tokens`.
    #[serde(default)]
    cache_creation_input_tokens: u64,
    /// Served from the cache. **Not** included in `input_tokens` either.
    #[serde(default)]
    cache_read_input_tokens: u64,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    #[serde(default)]
    content: Vec<Value>,
    #[serde(default)]
    usage: Option<ApiUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

impl ApiResponse {
    fn usage(&self) -> Usage {
        let u = self.usage.as_ref();
        let write = u.map_or(0, |u| u.cache_creation_input_tokens);
        let read = u.map_or(0, |u| u.cache_read_input_tokens);
        Usage {
            // Anthropic reports cached tokens *beside* `input_tokens`, not
            // inside it. Reading only `input_tokens` bills a heavily cached call
            // at nearly nothing while the provider charges a premium for the
            // write and a tenth of the rate for the read. Added back here, so
            // `Usage::input_tokens` means everything processed whichever
            // provider produced it.
            input_tokens: u.map_or(0, |u| u.input_tokens) + write + read,
            output_tokens: u.map_or(0, |u| u.output_tokens),
            cache_write_tokens: write,
            cache_read_tokens: read,
            // Priced by the deployment, not guessed here: rates change, differ
            // per model, and are a contract with the provider rather than this
            // crate's business.
            minor_units: 0,
        }
    }

    fn text(&self) -> String {
        self.content
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("")
    }

    /// The answer a forced tool call carried.
    ///
    /// Anthropic returns tool arguments as a decoded object rather than a JSON
    /// string, so there is nothing to parse — which is also why the emulated
    /// path cannot produce the "declared a schema and the answer is not JSON"
    /// failure the native path can.
    /// Tool calls the model asked for, excluding this crate's forced one.
    ///
    /// The buffered twin of `Accumulator::tool_calls`, and it must agree with
    /// it: streaming is the default, so a difference here would show up as a
    /// loop that fires in tests and never in production.
    fn tool_calls(&self) -> Result<Vec<super::ToolCall>, String> {
        self.content
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
            .filter(|block| block.get("name").and_then(Value::as_str) != Some(RESPOND_TOOL))
            .map(|block| {
                let id = block
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        "Anthropic returned a tool_use block without an id".to_owned()
                    })?;
                let name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        "Anthropic returned a tool_use block without a name".to_owned()
                    })?;
                let arguments = block
                    .get("input")
                    .cloned()
                    .ok_or_else(|| format!("Anthropic tool_use '{id}' has no input arguments"))?;
                Ok(super::ToolCall {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    arguments,
                })
            })
            .collect()
    }

    /// The forced structured-output tool's arguments.
    ///
    /// Matched **by name**, not by being the first `tool_use` block. A model may
    /// emit a caller's tool call before this one, and taking whichever came
    /// first would hand that call's arguments back as the structured answer —
    /// a wrong answer that parses, which is the worst kind. The streaming path
    /// matches by name for the same reason, and the two must agree.
    fn forced_tool_input(&self) -> Option<&Value> {
        self.content
            .iter()
            .find(|b| {
                b.get("type").and_then(Value::as_str) == Some("tool_use")
                    && b.get("name").and_then(Value::as_str) == Some(RESPOND_TOOL)
            })
            .and_then(|b| b.get("input"))
    }
}

/// Append the turn that already happened: what the model asked, what came back.
///
/// Anthropic wants both, as two messages — an `assistant` turn holding the
/// `tool_use` blocks it emitted, then a `user` turn holding one `tool_result`
/// per call, matched by `tool_use_id`. Sending only the results is rejected:
/// there is no request for them to answer.
///
/// All results go in **one** user message. A separate message per result is
/// accepted by the API and reads to the model as several conversational turns,
/// which is not what happened — the calls were parallel.
fn continue_with(
    messages: Value,
    exchanges: &[super::ToolExchange],
    continuation: Option<&super::ProviderContinuation>,
) -> Value {
    if exchanges.is_empty() {
        return messages;
    }
    let mut out = match messages {
        Value::Array(v) => v,
        other => vec![json!({ "role": "user", "content": other })],
    };
    if let Some(state) = continuation.and_then(|state| state.state.as_array()) {
        out.extend(state.iter().cloned());
    } else {
        out.push(json!({
            "role": "assistant",
            "content": exchanges
                .iter()
                .map(|e| json!({
                    "type": "tool_use",
                    "id": e.call.id,
                    "name": e.call.name,
                    "input": e.call.arguments,
                }))
                .collect::<Vec<_>>(),
        }));
    }
    out.push(tool_results(exchanges));
    Value::Array(out)
}

fn tool_results(exchanges: &[super::ToolExchange]) -> Value {
    json!({
        "role": "user",
        "content": exchanges
            .iter()
            .map(|exchange| json!({
                "type": "tool_result",
                "tool_use_id": exchange.call.id,
                "content": match &exchange.output {
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                },
                "is_error": exchange.failed,
            }))
            .collect::<Vec<_>>(),
    })
}

fn accumulate_continuation(
    completion: &mut Completion,
    prior: Option<&super::ProviderContinuation>,
    exchanges: &[super::ToolExchange],
) {
    let Some(current) = completion.continuation.as_mut() else {
        return;
    };
    let mut transcript = prior
        .and_then(|value| value.state.as_array())
        .cloned()
        .unwrap_or_default();
    if !exchanges.is_empty() {
        transcript.push(tool_results(exchanges));
    }
    if let Some(messages) = current.state.as_array() {
        transcript.extend(messages.iter().cloned());
    }
    current.state = Value::Array(transcript);
}

/// The prompt shape this driver accepts.
///
/// Either a bare string, the API's own `messages` array, or an object carrying
/// `messages` beside a `system` instruction. Accepting all three keeps the
/// simple case simple without hiding the real shape from a caller who needs it —
/// and the prompt is part of the effect key either way, so a changed prompt is a
/// changed effect rather than a quietly different run.
fn messages(prompt: &Value) -> Value {
    match prompt {
        Value::String(s) => json!([{ "role": "user", "content": s }]),
        Value::Array(_) => prompt.clone(),
        other => other.get("messages").cloned().unwrap_or_else(|| {
            // An object with no `messages` is content, not an envelope — except
            // for `system`, which is an instruction *about* the content and
            // would otherwise be shown to the model as part of the question.
            let mut rest = other.clone();
            if let Some(map) = rest.as_object_mut() {
                map.remove("system");
            }
            json!([{ "role": "user", "content": rest.to_string() }])
        }),
    }
}

/// The system instruction, if the caller set one.
///
/// Anthropic takes this as a **top-level parameter**, not a message role — it
/// rejects `role: "system"` inside `messages`. So a system prompt could not be
/// expressed through this driver at all until it was lifted out here, and one
/// supplied in the obvious place was silently dropped.
fn system(prompt: &Value) -> Option<Value> {
    prompt.get("system").cloned().filter(|s| !s.is_null())
}

/// Turn an assembled answer into a [`Completion`], or say why it is not one.
///
/// Shared by the streaming and buffered paths. The two differ in how bytes
/// become an answer and **not at all** in what counts as a usable one — and a
/// second copy of this reasoning would be the place the two quietly disagreed
/// about whether an empty response is a failure.
/// Everything a response yielded, however it arrived.
///
/// A struct rather than a parameter list because the buffered and streaming
/// paths must hand `interpret` the *same* things — and a positional list of
/// eight is where one path quietly stops supplying one of them.
struct Assembled {
    text: String,
    /// The forced structured-output tool's arguments.
    forced: Option<Value>,
    /// Tool calls the caller may act on, forced tool excluded.
    tool_calls: Vec<super::ToolCall>,
    usage: Usage,
    stop_reason: Option<String>,
    /// Exact provider-native assistant blocks for a subsequent tool turn.
    continuation: Value,
}

fn interpret(
    model: &ModelId,
    schema: Option<&Value>,
    emulating: bool,
    assembled: Assembled,
) -> Result<Completion, ModelError> {
    let Assembled {
        text,
        forced,
        tool_calls,
        usage,
        stop_reason,
        continuation,
    } = assembled;
    // It generated and then declined. Metered, because generation happened —
    // and `Unusable` rather than `Refused` for exactly that reason: a refusal
    // costs nothing, this costs whatever it took to decide.
    if stop_reason.as_deref() == Some("refusal") {
        return Err(ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: "the model declined to answer".to_owned(),
        });
    }

    // Emulated mode first, and the ordering matters: a forced tool call answers
    // with a `tool_use` block and **no text**, so an emptiness check ahead of
    // this would reject a call that worked perfectly.
    let (text, structured_value) = if emulating {
        let Some(value) = forced else {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "a tool call was forced and no usable arguments came back — \
                         the model did not honour `tool_choice`, or its streamed \
                         fragments did not reassemble into JSON"
                    .to_owned(),
            });
        };
        if let Some(schema) = schema {
            super::validate_schema(schema, &value).map_err(|detail| ModelError::Unusable {
                model: model.clone(),
                usage,
                detail,
            })?;
        }
        (value.to_string(), Some(value))
    } else {
        if text.is_empty() {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "the answer carried no text content".to_owned(),
            });
        }
        let parsed_schema = structured(schema, &text, model, usage)?;
        (text, parsed_schema)
    };

    let continuation = (!tool_calls.is_empty()).then(|| {
        super::ProviderContinuation::new(
            "anthropic",
            json!([{ "role": "assistant", "content": continuation }]),
        )
    });
    Ok(Completion {
        structured: structured_value,
        tool_calls,
        text,
        usage,
        // `max_tokens` is the provider saying it stopped because it ran out of
        // room, not because it finished.
        truncated: stop_reason.as_deref() == Some("max_tokens"),
        stop_reason,
        continuation,
    })
}

impl Anthropic {
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
            && (state.provider != "anthropic" || !state.state.is_array())
        {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "the continuation was not an Anthropic assistant-content array".to_owned(),
            });
        }
        if reasoning_effort.is_some() && !exchanges.is_empty() && continuation.is_none() {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "reasoning-enabled tool continuation requires the signed thinking \
                         and assistant blocks from the prior Anthropic response"
                    .to_owned(),
            });
        }
        let mut body = json!({
            "model": model.model,
            "max_tokens": max_output_tokens,
            "messages": continue_with(messages(prompt), exchanges, continuation),
        });
        if let Some(effort) = reasoning_effort {
            if matches!(
                effort,
                super::ReasoningEffort::None
                    | super::ReasoningEffort::Minimal
                    | super::ReasoningEffort::XHigh
            ) {
                return Err(ModelError::Refused {
                    model: model.clone(),
                    detail: format!(
                        "Anthropic adaptive thinking does not support reasoning effort '{}'",
                        effort.as_str()
                    ),
                });
            }
            body["thinking"] = json!({ "type": "adaptive" });
            body["output_config"]["effort"] = json!(effort.as_str());
        }
        if let Some(system) = system(prompt) {
            body["system"] = system;
        }
        // Anthropic takes declarations at the top level: `name`, `description`,
        // `input_schema` — no `function` wrapper, and `input_schema` rather than
        // `parameters`. Rendered here so a caller writes one declaration.
        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "description": t.description,
                            "input_schema": t.parameters,
                            "strict": true,
                        })
                    })
                    .collect(),
            );
        }
        if let Some(schema) = schema {
            match self.mode_for(model) {
                // GA in 2026 as `output_config.format`, without the beta header
                // the November 2025 preview required.
                SchemaMode::Native => {
                    body["output_config"]["format"] =
                        json!({ "type": "json_schema", "schema": schema });
                }
                // The universal fallback: one tool whose input schema is the
                // answer's shape, and a `tool_choice` the model cannot decline.
                // Older than native support and available on far more models.
                SchemaMode::ForcedTool => {
                    // The fallback spends `tools` and `tool_choice` on the
                    // answer's shape, so it cannot coexist with real tools:
                    // whichever were written first would be silently replaced,
                    // and the model would either lose its tools or return prose
                    // where a schema was promised. Refused rather than merged,
                    // because merging means guessing which the caller wanted.
                    if !tools.is_empty() {
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
                    body["tools"] = json!([{
                        "name": RESPOND_TOOL,
                        "description": "Return the answer in the required shape.",
                        "input_schema": schema,
                    }]);
                    body["tool_choice"] = json!({ "type": "tool", "name": RESPOND_TOOL });
                }
            }
        }
        if self.stream {
            body["stream"] = json!(true);
        }
        Ok(body)
    }

    /// Read a whole response at once.
    async fn read_buffered(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
    ) -> Result<Completion, ModelError> {
        let parsed: ApiResponse = response.json().await.map_err(|e| ModelError::Unusable {
            model: model.clone(),
            // A 200 whose body will not parse still generated: the tokens are
            // spent whatever the shape of what came back. Reporting zero usage
            // here is the one place this path knowingly under-counts, and it is
            // bounded by one response.
            usage: Usage::default(),
            detail: format!("the response body did not parse: {e}"),
        })?;

        let emulating = schema.is_some() && self.mode_for(model) == SchemaMode::ForcedTool;
        let usage = parsed.usage();
        let tool_calls = parsed.tool_calls().map_err(|detail| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail,
        })?;
        interpret(
            model,
            schema,
            emulating,
            Assembled {
                text: parsed.text(),
                forced: parsed.forced_tool_input().cloned(),
                tool_calls,
                usage,
                stop_reason: parsed.stop_reason.clone(),
                continuation: Value::Array(parsed.content.clone()),
            },
        )
    }

    /// Read the response as it arrives, so a severed connection can still say
    /// what it burned.
    ///
    /// The reason the whole streaming path exists. Every early return below
    /// carries [`Accumulator::billed`](anthropic_stream::Accumulator::billed) —
    /// what the provider had reported *by that point* — because a failure that
    /// reports zero is indistinguishable to the budget from a call that never
    /// happened.
    async fn read_streamed(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
        observer: Option<(&dyn super::ModelStreamObserver, &crate::core::Label)>,
    ) -> Result<Completion, ModelError> {
        use futures_util::StreamExt;

        let mut decoder = sse::Decoder::new();
        let mut acc = anthropic_stream::Accumulator::new();
        let mut body = response.bytes_stream();

        while let Some(chunk) = body.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                // The case this file was written for: the connection died with
                // an answer half-delivered.
                Err(e) => return Err(severed(model, &acc, &e.to_string())),
            };
            let events = decoder
                .push(&chunk)
                .map_err(|error| ModelError::Unaccounted {
                    model: model.clone(),
                    detail: error.to_string(),
                })?;
            for event in events {
                if event.name == "content_block_delta"
                    && let Ok(value) = serde_json::from_str::<Value>(&event.data)
                    && value
                        .get("delta")
                        .and_then(|delta| delta.get("type"))
                        .and_then(Value::as_str)
                        == Some("text_delta")
                    && let Some(delta) = value
                        .get("delta")
                        .and_then(|delta| delta.get("text"))
                        .and_then(Value::as_str)
                    && let Some((observer, label)) = observer
                {
                    observer.event(crate::core::Tainted::with_label(
                        super::ModelStreamEvent::TextDelta(delta.to_owned()),
                        label.clone(),
                    ));
                }
                acc.event(&event.name, &event.data);
            }
            // An `error` event inside a 200. Handled as soon as it lands rather
            // than after the loop: the provider may hold the connection open
            // afterwards, and there is nothing further worth waiting for.
            if let Some(err) = acc.error() {
                return Err(stream_error(model, &acc, err));
            }
        }

        // The stream ended without `message_stop`. A clean EOF rather than a
        // transport error, but an equally incomplete answer — and a driver that
        // returned the partial text as a whole answer would be committing the
        // silent truncation this crate refuses everywhere else.
        if !acc.complete() {
            return Err(severed(
                model,
                &acc,
                "the stream ended before `message_stop`",
            ));
        }

        let emulating = schema.is_some() && self.mode_for(model) == SchemaMode::ForcedTool;
        let usage = acc.billed();
        let tool_calls = acc.tool_calls().map_err(|detail| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail,
        })?;
        let completion = interpret(
            model,
            schema,
            emulating,
            Assembled {
                text: acc.text().to_owned(),
                forced: acc.forced_tool_input(),
                tool_calls,
                usage,
                stop_reason: acc.stop_reason().map(ToOwned::to_owned),
                continuation: acc.continuation_content(),
            },
        )?;
        if let Some((observer, label)) = observer {
            observer.event(crate::core::Tainted::with_label(
                super::ModelStreamEvent::Usage(completion.usage),
                label.clone(),
            ));
        }
        Ok(completion)
    }
}

/// A stream that stopped early.
///
/// The distinction that matters is whether `message_start` arrived. It carries
/// the input tokens and both cache counters before a single output token exists,
/// so its presence is exactly the line between "we know this was billed" and "we
/// know nothing".
fn severed(model: &ModelId, acc: &anthropic_stream::Accumulator, detail: &str) -> ModelError {
    if acc.started() {
        return ModelError::Interrupted {
            model: model.clone(),
            usage: acc.billed(),
            detail: detail.to_owned(),
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: format!("the stream ended before it began: {detail}"),
    }
}

/// An `error` event delivered inside a 200 response.
///
/// `overloaded_error` is the documented in-stream spelling of a 529, so it maps
/// where a 529 maps — but only while nothing has been generated. Once
/// `message_start` has arrived the call has been billed, and reporting it as a
/// free, safe-to-repeat rate limit would lose the spend and invite a second one.
fn stream_error(
    model: &ModelId,
    acc: &anthropic_stream::Accumulator,
    err: &anthropic_stream::StreamError,
) -> ModelError {
    let detail = format!("{}: {}", err.kind, err.message);
    if acc.started() {
        return ModelError::Interrupted {
            model: model.clone(),
            usage: acc.billed(),
            detail,
        };
    }
    match err.kind.as_str() {
        "overloaded_error" | "rate_limit_error" => ModelError::RateLimited {
            model: model.clone(),
            detail,
        },
        "invalid_request_error"
        | "authentication_error"
        | "permission_error"
        | "not_found_error" => ModelError::Refused {
            model: model.clone(),
            detail,
        },
        _ => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },
    }
}

#[async_trait]
impl ModelProvider for Anthropic {
    fn request_profile(&self, model: &ModelId) -> Value {
        let schema_mode = match self.mode_for(model) {
            SchemaMode::Native => "native",
            SchemaMode::ForcedTool => "forced-tool",
        };
        json!({
            "driver": "anthropic-messages/v1",
            "base": self.base,
            "api_version": self.version,
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

        // Before the request is built: a refused destination must cost nothing
        // and reach nothing.
        self.check_egress(model)?;

        let response = self
            .http
            .post(format!("{}/v1/messages", self.base))
            .timeout(self.timeout)
            .header("x-api-key", self.key.expose())
            .header("anthropic-version", &self.version)
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
            let detail = response.text().await.unwrap_or_default();
            // Shared doctrine, in `super::wire`: which statuses mean the call
            // never generated, which mean it was throttled, and which mean the
            // provider will not say. Two copies of that table would drift.
            return Err(classify_status(model, status.as_u16(), &detail));
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

    fn driver() -> Anthropic {
        Anthropic::new("test-key").expect("build the driver")
    }

    /// The forced tool is found by name, not by being first.
    ///
    /// A model may emit a caller's tool call before the synthetic one this crate
    /// forces to shape the answer. Taking whichever `tool_use` block arrived
    /// first hands that call's arguments back as the structured answer — a wrong
    /// answer that parses cleanly, so nothing downstream catches it. The
    /// streaming accumulator matches by name; this is the buffered twin, and the
    /// two must agree or the bug appears only in whichever mode production uses.
    #[test]
    fn the_forced_tool_is_found_by_name_not_by_position() {
        let parsed: ApiResponse = serde_json::from_value(json!({
            "content": [
                { "type": "tool_use", "id": "c1", "name": "refund",
                  "input": { "amount": 999 } },
                { "type": "tool_use", "id": "c2", "name": RESPOND_TOOL,
                  "input": { "verdict": "ship" } },
            ],
        }))
        .expect("parse");

        assert_eq!(
            parsed.forced_tool_input(),
            Some(&json!({ "verdict": "ship" })),
            "the structured answer was taken from the caller's tool call"
        );

        let calls = parsed.tool_calls().expect("well-formed tool calls");
        assert_eq!(calls.len(), 1, "the forced tool is not a caller tool call");
        assert_eq!(calls[0].name, "refund");
        assert_eq!(calls[0].id, "c1");
    }

    #[test]
    fn a_malformed_buffered_tool_call_is_loud() {
        let parsed: ApiResponse = serde_json::from_value(json!({
            "content": [
                { "type": "tool_use", "name": "refund", "input": { "amount": 999 } }
            ],
            "usage": { "input_tokens": 10, "output_tokens": 4 }
        }))
        .expect("response envelope");

        assert!(
            parsed.tool_calls().is_err(),
            "a missing call id was silently turned into no tool calls"
        );
    }

    /// A system instruction has to leave as a top-level parameter.
    ///
    /// Anthropic rejects `role: "system"` inside `messages`, so this is the only
    /// place it can go. It used to be dropped on the floor: the caller set it,
    /// nothing complained, and the model was never told.
    #[test]
    fn a_system_instruction_rides_beside_the_messages() {
        let body = driver().body(
            &ModelId::new("anthropic", "claude-x"),
            &json!({ "system": "answer only in French", "messages": [{"role": "user", "content": "hi"}] }),
            None,
            &[],
            &[],
        )
        .expect("a body without tools");
        assert_eq!(
            body["system"], "answer only in French",
            "the system instruction must be a top-level parameter: {body}"
        );
        assert_eq!(
            body["messages"],
            json!([{ "role": "user", "content": "hi" }]),
            "it must not also be pushed into the conversation: {body}"
        );
    }

    /// An instruction is not content.
    ///
    /// Without `messages` to key on, the object used to be stringified whole and
    /// handed to the model as the user's question — so the caller's instruction
    /// arrived as part of the thing being asked about.
    #[test]
    fn a_system_instruction_is_not_shown_as_the_question() {
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!({ "system": "be terse", "ticket": "printer on fire" }),
                None,
                &[],
                &[],
            )
            .expect("a body without tools");
        let asked = body["messages"][0]["content"].as_str().unwrap_or_default();
        assert!(
            !asked.contains("be terse"),
            "the instruction leaked into the question: {asked}"
        );
        assert!(
            asked.contains("printer on fire"),
            "the actual content went missing: {asked}"
        );
    }

    /// Image and document parts reach the wire unaltered.
    ///
    /// Multimodal content is not a separate feature here: a `messages` array is
    /// passed through verbatim, so the provider's own content-block shapes work
    /// without this crate modelling any of them. Worth a test anyway, because
    /// "passes through untouched" is exactly the property a well-meaning
    /// normalisation would break.
    #[test]
    fn a_multimodal_message_is_passed_through_verbatim() {
        let parts = json!([{
            "role": "user",
            "content": [
                { "type": "text", "text": "what is in this image?" },
                { "type": "image", "source": {
                    "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" } }
            ]
        }]);
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!({ "messages": parts }),
                None,
                &[],
                &[],
            )
            .expect("a body without tools");
        assert_eq!(
            body["messages"], parts,
            "content blocks must survive untouched: {body}"
        );
    }

    /// No instruction, no key — an absent field is not an empty one.
    #[test]
    fn a_prompt_without_a_system_sends_no_system() {
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!("hi"),
                None,
                &[],
                &[],
            )
            .expect("a body without tools");
        assert!(
            body.get("system").is_none(),
            "an unset instruction must not become an empty one: {body}"
        );
    }
}

#[cfg(test)]
mod tool_tests {
    use super::*;
    use crate::model::ToolDeclaration;

    fn driver() -> Anthropic {
        Anthropic::new("test-key").expect("build the driver")
    }

    fn decl() -> ToolDeclaration {
        ToolDeclaration::new(
            "ledger.read",
            "Read a ledger entry.",
            json!({ "type": "object", "properties": { "id": { "type": "string" } } }),
        )
    }

    /// Anthropic takes the three fields at the top level, under `input_schema`.
    ///
    /// The shape differs from `OpenAI`'s in exactly the way that is easy to get
    /// wrong: no `function` wrapper, and `input_schema` rather than
    /// `parameters`. A request in the other shape is rejected by the API, so
    /// this is pinned rather than assumed.
    #[test]
    fn a_declared_tool_is_rendered_in_anthropics_shape() {
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!({ "messages": [] }),
                None,
                &[decl()],
                &[],
            )
            .expect("a body with tools");

        let tool = &body["tools"][0];
        assert_eq!(tool["name"], "ledger.read");
        assert_eq!(
            tool["strict"], true,
            "strict tool use must enforce the declared input schema during generation: {body}"
        );
        assert_eq!(
            tool["input_schema"]["type"], "object",
            "Anthropic names the argument schema `input_schema`; `parameters` is              OpenAI's spelling and this request would be rejected: {body}"
        );
        assert!(
            tool.get("function").is_none(),
            "the OpenAI `function` wrapper must not appear: {body}"
        );
    }

    /// A forced-tool schema and real tools cannot share one request.
    ///
    /// The fallback spends `tools` and `tool_choice` on the answer's shape. Left
    /// to overwrite each other, the model either loses its tools or returns
    /// prose where a schema was promised — and which happens depends on
    /// statement order, which is not a thing a caller should have to know.
    #[test]
    fn a_forced_schema_and_declared_tools_are_refused_together() {
        // A deployment that declared this model has no native structured
        // output, so the answer's shape is obtained by forcing a synthetic tool.
        let model = ModelId::new("anthropic", "claude-x");
        let forced = driver().structured_via(SchemaMode::ForcedTool);
        let schema = json!({ "type": "object" });
        let out = forced.body(
            &model,
            &json!({ "messages": [] }),
            Some(&schema),
            &[decl()],
            &[],
        );

        match out {
            Err(ModelError::Refused { detail, .. }) => assert!(
                detail.contains("structured output") && detail.contains("tool"),
                "the refusal must say which two things collided: {detail}"
            ),
            Err(e) => panic!("wrong refusal: {e}"),
            Ok(body) => panic!(
                "a schema and declared tools were combined, so one silently \
                 replaced the other: {body}"
            ),
        }

        // Each alone is fine.
        assert!(
            forced
                .body(&model, &json!({ "messages": [] }), Some(&schema), &[], &[])
                .is_ok(),
            "a schema alone must still work"
        );
        assert!(
            forced
                .body(&model, &json!({ "messages": [] }), None, &[decl()], &[])
                .is_ok(),
            "tools alone must still work"
        );
        // And a model with native structured output has no conflict at all:
        // the schema goes in `output_config`, leaving `tools` to the caller.
        let native = driver()
            .body(
                &model,
                &json!({ "messages": [] }),
                Some(&schema),
                &[decl()],
                &[],
            )
            .expect("native structured output coexists with tools");
        assert_eq!(native["tools"][0]["name"], "ledger.read");
        assert!(native["output_config"].is_object());
    }
}

#[cfg(test)]
mod continuation_tests {
    use super::*;
    use crate::model::{
        ProviderContinuation, ReasoningEffort, ToolCall as ModelToolCall, ToolExchange,
    };

    fn driver() -> Anthropic {
        Anthropic::new("test-key").expect("build the driver")
    }

    fn exchange(failed: bool) -> ToolExchange {
        let call = ModelToolCall {
            id: "toolu_01".to_owned(),
            name: "ledger.read".to_owned(),
            arguments: json!({ "id": "AC-1" }),
        };
        if failed {
            ToolExchange::failed(call, "the ledger was unreachable")
        } else {
            ToolExchange::ok(call, json!({ "balance": 42 }))
        }
    }

    /// A continuation carries the call *and* its result, as two turns.
    ///
    /// Anthropic matches a `tool_result` to the `tool_use` that asked for it by
    /// id, so sending results alone is rejected: there is no request for them to
    /// answer. Both turns, and the ids must line up.
    #[test]
    fn a_continuation_echoes_the_call_beside_its_result() {
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!({ "messages": [{"role": "user", "content": "balance?"}] }),
                None,
                &[],
                &[exchange(false)],
            )
            .expect("a continuation body");

        let msgs = body["messages"].as_array().expect("messages");
        assert_eq!(msgs.len(), 3, "question, the call, the result: {body}");

        let used = &msgs[1];
        assert_eq!(used["role"], "assistant");
        assert_eq!(used["content"][0]["type"], "tool_use");
        assert_eq!(
            used["content"][0]["input"],
            json!({ "id": "AC-1" }),
            "Anthropic takes arguments as an object, not a JSON string: {body}"
        );

        let result = &msgs[2];
        assert_eq!(result["role"], "user");
        assert_eq!(result["content"][0]["type"], "tool_result");
        assert_eq!(
            result["content"][0]["tool_use_id"], used["content"][0]["id"],
            "the result must carry the id of the call it answers, or the API \
             rejects it: {body}"
        );
    }

    #[test]
    fn signed_thinking_round_trips_unchanged_before_tool_results() {
        let content = json!([
            {"type": "thinking", "thinking": "private reasoning", "signature": "signed-value"},
            {"type": "text", "text": "checking"},
            {"type": "tool_use", "id": "toolu_01", "name": "ledger.read", "input": {"id": "AC-1"}}
        ]);
        let state = ProviderContinuation::new(
            "anthropic",
            json!([{ "role": "assistant", "content": content.clone() }]),
        );
        let body = driver()
            .body_with_max(
                &ModelId::new("anthropic", "claude-x"),
                &json!({"messages": [{"role": "user", "content": "balance?"}]}),
                4096,
                Some(ReasoningEffort::High),
                None,
                &[],
                &[exchange(false)],
                Some(&state),
            )
            .expect("lossless thinking continuation");

        assert_eq!(body["messages"][1]["content"], content);
        assert_eq!(body["messages"][2]["content"][0]["type"], "tool_result");
    }

    #[test]
    fn continuation_accumulates_every_prior_message() {
        let prior = ProviderContinuation::new(
            "anthropic",
            json!([{ "role": "assistant", "content": [{"type": "thinking", "signature": "first"}] }]),
        );
        let mut completion = Completion {
            text: String::new(),
            tool_calls: vec![ModelToolCall {
                id: "toolu_02".to_owned(),
                name: "ledger.read".to_owned(),
                arguments: json!({}),
            }],
            usage: Usage::default(),
            stop_reason: Some("tool_use".to_owned()),
            truncated: false,
            structured: None,
            continuation: Some(ProviderContinuation::new(
                "anthropic",
                json!([{ "role": "assistant", "content": [{"type": "tool_use", "id": "toolu_02"}] }]),
            )),
        };
        accumulate_continuation(&mut completion, Some(&prior), &[exchange(false)]);
        let state = completion.continuation.unwrap().state;
        assert_eq!(state[0]["content"][0]["signature"], "first");
        assert_eq!(state[1]["role"], "user");
        assert_eq!(state[2]["content"][0]["id"], "toolu_02");
    }

    /// A failed tool is reported as failed, not as a strange answer.
    #[test]
    fn a_failed_tool_is_marked_is_error() {
        let body = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &json!({ "messages": [] }),
                None,
                &[],
                &[exchange(true)],
            )
            .expect("body");
        // From the end: the two appended turns, whatever preceded them.
        let msgs = body["messages"].as_array().expect("messages");
        let (used, result) = (&msgs[msgs.len() - 2], &msgs[msgs.len() - 1]);
        assert_eq!(
            used["content"][0]["type"], "tool_use",
            "the call is echoed even when it failed: {body}"
        );
        assert_eq!(
            result["content"][0]["is_error"], true,
            "a failure rendered as an ordinary result teaches the model the \
             operation succeeded and returned something strange: {body}"
        );
    }

    /// No exchanges, no change. A first turn must look exactly as it did.
    #[test]
    fn a_first_turn_is_untouched() {
        let prompt = json!({ "messages": [{"role": "user", "content": "hi"}] });
        let plain = driver()
            .body(
                &ModelId::new("anthropic", "claude-x"),
                &prompt,
                None,
                &[],
                &[],
            )
            .expect("body");
        assert_eq!(plain["messages"].as_array().expect("messages").len(), 1);
    }
}
