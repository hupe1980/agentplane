//! A `ModelProvider` for the `OpenAI`-compatible **Chat Completions** wire.
//!
//! Behind the `providers` feature.
//!
//! # Why this driver exists beside the Responses one
//!
//! Chat Completions is the de-facto wire of **self-hosted** inference: TGI,
//! vLLM, Ollama, llama.cpp's server and LM Studio all speak it, and Hugging
//! Face's hosted router is literally this endpoint. One driver therefore
//! reaches every local host — and the whole Hugging Face catalogue those hosts
//! serve — behind a process boundary, which is where an inference engine
//! belongs: embedding one in-process would put gigabytes of weights and
//! GPU faults inside the component whose one job is to keep the journal,
//! leases and sweeper alive, and "serve models" is an explicit non-goal.
//!
//! Against `api.openai.com` itself, prefer the Responses driver: it is the
//! current primitive there and reports what this crate needs more directly.
//! This driver is for everything that *imitates* the older wire.
//!
//! # The honest smaller contract
//!
//! Compatible servers implement the shape, not the semantics, and this driver
//! refuses to smooth the difference over:
//!
//! * **Usage is as-reported.** Every implementation returns `usage` on a
//!   buffered call; on a stream it arrives only in the final chunk, and only
//!   when `stream_options.include_usage` is honoured. A server that reports
//!   nothing meters **zero** — visible in the journal as a completion with no
//!   usage, not silently backfilled with a guess. Choosing a server that
//!   cannot count is a deployment decision this driver declines to hide.
//! * **`reasoning_effort` is refused.** The compatible wire has no
//!   model-family-neutral spelling for it — the same refusal the Bedrock
//!   driver makes, for the same reason: a control silently dropped is worse
//!   than one honestly refused.
//! * **Media is refused.** Multimodal content on this wire is a per-server
//!   dialect; a driver that guessed one would ship bytes some servers
//!   misread. Governed media stays on the drivers that declare it.
//!
//! # The failure table
//!
//! Status classification is shared doctrine in the crate's wire module,
//! common to every HTTP driver. What is
//! specific here is the success envelope: `choices[0].finish_reason` is
//! `"length"` for a truncated answer (reported through
//! [`Completion::truncated`], never as a silently shortened string), a
//! `message.refusal` is a **metered** decline, and tool-call arguments arrive
//! as JSON strings that must parse — a malformed one is a loud, metered
//! [`ModelError::Unusable`], not a dropped call.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::core::Secret;

use super::wire::{RESPOND_TOOL, classify_status, classify_transport, structured};
use super::{
    Completion, ModelError, ModelId, ModelProvider, Request, SchemaMode, Usage,
    chat_completions_stream, sse,
};

/// The provider tag a continuation from this driver carries.
const PROVIDER: &str = "chat-completions";

/// Calls an `OpenAI`-compatible `/v1/chat/completions` endpoint.
pub struct ChatCompletions {
    http: reqwest::Client,
    /// Optional because the common local server needs none. When set it is
    /// sent as a bearer token — which is what TGI, vLLM and Hugging Face's
    /// router expect.
    key: Option<Secret>,
    base: String,
    /// The mode to use for a model with no explicit entry.
    ///
    /// Defaults to [`SchemaMode::ForcedTool`] — the opposite of the `OpenAI`
    /// driver, deliberately: `json_schema` response format is honoured by
    /// vLLM and llama.cpp and *ignored or half-implemented* by others, and a
    /// constraint a server silently drops is worse than the fallback that
    /// works wherever tool calling does. A deployment that knows its server
    /// enforces `json_schema` opts up to [`SchemaMode::Native`].
    default_schema_mode: SchemaMode,
    /// Per-model overrides, keyed by model because that is what the
    /// constraint is about — one driver serves many models over one pool.
    schema_modes: std::collections::BTreeMap<String, SchemaMode>,
    /// Whether to ask for the response as a stream.
    stream: bool,
    /// Where this driver may connect, if the deployment says.
    egress: Option<crate::core::Egress>,
    /// Whole HTTP request, including a streamed response body.
    timeout: std::time::Duration,
}

impl std::fmt::Debug for ChatCompletions {
    /// Redacts the key: a secret that can be printed is a secret in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatCompletions")
            .field("base", &self.base)
            .field("key", &self.key.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl ChatCompletions {
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

    /// Point at a server.
    ///
    /// `base` is **required** because there is no canonical one: Ollama is
    /// `http://localhost:11434`, vLLM `http://localhost:8000`, TGI
    /// `http://localhost:8080`, Hugging Face's router
    /// `https://router.huggingface.co/v1`... a default would just be the
    /// wrong one of those. A base already ending in `/v1` is respected;
    /// otherwise `/v1` is appended, so both spellings in the wild work.
    ///
    /// # Errors
    ///
    /// If the HTTP client cannot be built.
    pub fn new(base: impl Into<String>) -> Result<Self, ModelError> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| ModelError::Unreachable {
                model: ModelId::new(PROVIDER, "*"),
                detail: format!("could not build an HTTP client: {e}"),
            })?;
        let mut base = base.into();
        while base.ends_with('/') {
            base.pop();
        }
        if !base.ends_with("/v1") {
            base.push_str("/v1");
        }
        Ok(Self {
            http,
            key: None,
            base,
            default_schema_mode: SchemaMode::ForcedTool,
            schema_modes: std::collections::BTreeMap::new(),
            stream: true,
            egress: None,
            timeout: Self::DEFAULT_TIMEOUT,
        })
    }

    /// Present a bearer token — Hugging Face's router, a TGI behind auth.
    #[must_use]
    pub fn bearer(mut self, key: impl Into<String>) -> Self {
        self.key = Some(Secret::new(key));
        self
    }

    /// Bound connection, generation, and response streaming as one operation.
    #[must_use]
    pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How to obtain a schema-conforming answer from every model.
    #[must_use]
    pub fn structured_via(mut self, mode: SchemaMode) -> Self {
        self.default_schema_mode = mode;
        self
    }

    /// How to obtain a schema-conforming answer from **one** model.
    #[must_use]
    pub fn structured_via_for(mut self, model: impl Into<String>, mode: SchemaMode) -> Self {
        self.schema_modes.insert(model.into(), mode);
        self
    }

    /// Restrict where this driver may connect.
    ///
    /// Deny-by-default once set — see [`Egress`](crate::core::Egress).
    #[must_use]
    pub fn egress(mut self, egress: crate::core::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Ask for the whole response at once instead of streaming it.
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
}

// ── The wire shapes ─────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
struct PromptDetails {
    /// Served from the cache. A **subset** of `prompt_tokens`, exactly as the
    /// Responses API reports it — adding it back would double-count.
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ApiUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<PromptDetails>,
}

impl ApiUsage {
    fn normalised(&self) -> Usage {
        Usage {
            input_tokens: self.prompt_tokens,
            output_tokens: self.completion_tokens,
            // The wire has no cache-write counter; a write bills as ordinary
            // input, so zero is accurate rather than unknown.
            cache_write_tokens: 0,
            cache_read_tokens: self
                .prompt_tokens_details
                .as_ref()
                .map_or(0, |d| d.cached_tokens),
            // Priced by the deployment — and for a local server there is no
            // provider bill at all.
            minor_units: 0,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ApiFunction {
    #[serde(default)]
    name: String,
    /// A JSON **string**, as the `OpenAI` shape has always had it.
    #[serde(default)]
    arguments: String,
}

#[derive(Debug, Default, Deserialize)]
struct ApiToolCall {
    #[serde(default)]
    id: String,
    #[serde(default)]
    function: ApiFunction,
}

#[derive(Debug, Default)]
struct ApiMessage {
    content: Option<String>,
    tool_calls: Vec<ApiToolCall>,
    /// The model's own decline, as the newer compatible servers spell it.
    refusal: Option<String>,
    /// The message **exactly as the server sent it**.
    ///
    /// Kept because the continuation is this value, not a copy of the fields
    /// this driver happens to understand. "OpenAI-compatible" is a wire many
    /// servers extend, and a driver that re-emits only the keys it knows breaks
    /// on every key added after it was written — silently, because `serde`
    /// discards the rest on the way in and the rebuilt message still looks
    /// well-formed.
    ///
    /// The concrete case is Gemini through Google's compatibility endpoint. Its
    /// thinking models attach an encrypted `thought_signature` to each tool
    /// call — `tool_calls[].extra_content.google.thought_signature` — and
    /// **reject** the follow-up turn that does not carry it back. `LiteLLM`,
    /// which normalises every provider into this shape, had nowhere to keep it
    /// and ended up smuggling it inside the tool-call `id`; that leaked into
    /// requests to other providers and still degenerates multi-turn tool
    /// calling. The lesson is not to learn one vendor's field. It is that a
    /// provider's own turn is not this driver's to reconstruct.
    raw: Value,
}

impl<'de> Deserialize<'de> for ApiMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            #[serde(default)]
            content: Option<String>,
            #[serde(default)]
            tool_calls: Vec<ApiToolCall>,
            #[serde(default)]
            refusal: Option<String>,
        }
        let raw = Value::deserialize(deserializer)?;
        let fields: Fields =
            serde_json::from_value(raw.clone()).map_err(serde::de::Error::custom)?;
        Ok(Self {
            content: fields.content,
            tool_calls: fields.tool_calls,
            refusal: fields.refusal,
            raw,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ApiChoice {
    #[serde(default)]
    message: ApiMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse {
    #[serde(default)]
    choices: Vec<ApiChoice>,
    #[serde(default)]
    usage: Option<ApiUsage>,
}

impl ApiResponse {
    fn usage(&self) -> Usage {
        self.usage
            .as_ref()
            .map(ApiUsage::normalised)
            .unwrap_or_default()
    }
}

// ── Request assembly ────────────────────────────────────────────────────────

/// The caller's prompt as chat messages.
///
/// The same vocabulary every driver accepts: a bare string is the user turn;
/// an object may carry `system` (the instruction) and `input` (the content).
/// Whatever the shape, it is part of the effect key — a changed prompt is a
/// changed effect.
fn messages(prompt: &Value) -> Vec<Value> {
    // An array is the wire's own turn list and passes through verbatim, as
    // every other driver passes its native transcript — stringified, a whole
    // conversation would arrive as one quoted user string, silently.
    if let Value::Array(turns) = prompt {
        return turns.clone();
    }
    let mut out = Vec::new();
    if let Some(system) = prompt.get("system").filter(|s| !s.is_null()) {
        let content = match system {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.push(json!({ "role": "system", "content": content }));
    }
    // `messages` beside `system`: the wire's turn list with the instruction
    // kept in the one vocabulary every driver shares.
    if let Some(Value::Array(turns)) = prompt.get("messages") {
        out.extend(turns.iter().cloned());
        return out;
    }
    let user = match prompt {
        Value::String(s) => s.clone(),
        other => match other.get("input") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => {
                // `system` is an instruction about the content, not content.
                let mut rest = other.clone();
                if let Some(map) = rest.as_object_mut() {
                    map.remove("system");
                }
                rest.to_string()
            }
        },
    };
    out.push(json!({ "role": "user", "content": user }));
    out
}

/// Append the turns that already happened.
///
/// The continuation state is the exact assistant messages the server emitted
/// — `tool_calls` ids included — because a tool result must be delivered
/// under the id the model issued, and reconstructing the assistant turn from
/// this side's records is how an id gets subtly rewritten. Each exchange then
/// contributes one `tool` message carrying the same `call_id`.
fn continue_with(
    out: &mut Vec<Value>,
    exchanges: &[super::ToolExchange],
    continuation: Option<&super::ProviderContinuation>,
) {
    if exchanges.is_empty() {
        return;
    }
    if let Some(state) = continuation.and_then(|c| c.state.as_array()) {
        out.extend(state.iter().cloned());
    } else {
        // Compatibility path for manually assembled exchanges: rebuild the
        // assistant turn the wire needs from the calls the caller carries.
        out.push(json!({
            "role": "assistant",
            "tool_calls": exchanges.iter().map(|e| json!({
                "id": e.call.id,
                "type": "function",
                "function": {
                    "name": e.call.name,
                    "arguments": e.call.arguments.to_string(),
                },
            })).collect::<Vec<_>>(),
        }));
    }
    for e in exchanges {
        out.push(json!({
            "role": "tool",
            "tool_call_id": e.call.id,
            "content": match &e.output {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        }));
    }
}

/// One `tool` result message per exchange, for continuation accumulation.
///
/// This wire has no `is_error` flag on a tool message — unlike Anthropic —
/// so a failed exchange is distinguishable only by its content, which the
/// runtime's failed-call text already carries. Nothing is dropped; the wire
/// simply has one field fewer to say it in.
fn tool_messages(exchanges: &[super::ToolExchange]) -> impl Iterator<Item = Value> + '_ {
    exchanges.iter().map(|e| {
        json!({
            "role": "tool",
            "tool_call_id": e.call.id,
            "content": match &e.output {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        })
    })
}

impl ChatCompletions {
    #[allow(clippy::too_many_arguments)]
    fn body(
        &self,
        model: &ModelId,
        prompt: &Value,
        max_output_tokens: u32,
        schema: Option<&Value>,
        tools: &[super::ToolDeclaration],
        exchanges: &[super::ToolExchange],
        continuation: Option<&super::ProviderContinuation>,
    ) -> Result<Value, ModelError> {
        if let Some(state) = continuation
            && (state.provider != PROVIDER || !state.state.is_array())
        {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "the continuation was not a chat-completions message array".to_owned(),
            });
        }
        if continuation.is_some() && exchanges.is_empty() {
            // Silently dropping it would journal an effect key that records a
            // continuation the wire never carried.
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "a continuation without tool exchanges has no request to follow".to_owned(),
            });
        }
        let mut msgs = messages(prompt);
        continue_with(&mut msgs, exchanges, continuation);
        let mut body = json!({
            "model": model.model,
            "messages": msgs,
            // `max_tokens` rather than the newer `max_completion_tokens`: the
            // compatible servers all accept the former, and several only it.
            "max_tokens": max_output_tokens,
        });
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
                        "model '{}' obtains a declared response schema by forcing a \
                         synthetic tool, which cannot be combined with the {} tool(s) \
                         this request declares. Use a server with native `json_schema` \
                         support, or drop the schema and validate the answer yourself",
                        model.model,
                        tools.len()
                    ),
                });
            }
            match self.mode_for(model) {
                SchemaMode::Native => {
                    // `strict: true` is what turns the schema from a
                    // suggestion into a constraint on servers that honour it
                    // — and whether a server honours `json_schema` at all is
                    // exactly why ForcedTool is this driver's default.
                    body["response_format"] = json!({
                        "type": "json_schema",
                        "json_schema": {
                            "name": RESPOND_TOOL,
                            "strict": true,
                            "schema": schema,
                        },
                    });
                }
                SchemaMode::ForcedTool => {
                    body["tools"] = json!([{
                        "type": "function",
                        "function": {
                            "name": RESPOND_TOOL,
                            "description": "Return the answer in the required shape.",
                            "parameters": schema,
                        },
                    }]);
                    body["tool_choice"] =
                        json!({ "type": "function", "function": { "name": RESPOND_TOOL } });
                }
            }
        }
        // **Nested** under `function`, which is what Chat Completions takes —
        // the opposite of Responses, whose flat shape is the mistake waiting
        // on this line. See the Responses driver for the war story.
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
                            },
                        })
                    })
                    .collect(),
            );
        }
        if self.stream {
            body["stream"] = json!(true);
            // Without this the final chunk omits usage on every server that
            // implements it, and a stream that completes cleanly would meter
            // zero when the figure was one flag away.
            body["stream_options"] = json!({ "include_usage": true });
        }
        Ok(body)
    }

    /// Turn a response envelope into a [`Completion`] — one interpretation
    /// shared exactly by the buffered and streaming paths.
    fn interpret(
        &self,
        parsed: &ApiResponse,
        model: &ModelId,
        schema: Option<&Value>,
    ) -> Result<Completion, ModelError> {
        let usage = parsed.usage();
        let Some(choice) = parsed.choices.first() else {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: "the response carried no choices".to_owned(),
            });
        };

        // It generated and then declined — metered, because deciding cost
        // whatever it cost.
        if let Some(why) = choice.message.refusal.as_deref().filter(|r| !r.is_empty()) {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: format!("the model declined to answer: {why}"),
            });
        }

        let text = choice.message.content.clone().unwrap_or_default();
        let truncated = choice.finish_reason.as_deref() == Some("length");
        let emulating = schema.is_some() && self.mode_for(model) == SchemaMode::ForcedTool;

        // Arguments are JSON strings and must parse. A malformed call is a
        // provider-protocol failure, not "no call": dropping it can turn one
        // bad and one good side effect into permission for only the good one.
        let mut calls = Vec::new();
        let mut forced: Option<String> = None;
        for c in &choice.message.tool_calls {
            if c.function.name == RESPOND_TOOL {
                forced = Some(c.function.arguments.clone());
                continue;
            }
            let arguments =
                serde_json::from_str(&c.function.arguments).map_err(|e| ModelError::Unusable {
                    model: model.clone(),
                    usage,
                    detail: format!(
                        "tool call '{}' for '{}' carried malformed JSON arguments: {e}",
                        c.id, c.function.name
                    ),
                })?;
            calls.push(super::ToolCall {
                id: c.id.clone(),
                name: c.function.name.clone(),
                arguments,
            });
        }

        if text.is_empty() && calls.is_empty() && !truncated && !emulating {
            return Err(ModelError::Unusable {
                model: model.clone(),
                usage,
                detail: format!(
                    "the answer carried no content (finish_reason {:?})",
                    choice.finish_reason
                ),
            });
        }

        let (text, structured_value) = if emulating {
            let Some(raw) = forced else {
                return Err(ModelError::Unusable {
                    model: model.clone(),
                    usage,
                    detail: "a tool call was forced and the answer carried none — \
                             the model did not honour `tool_choice`"
                        .to_owned(),
                });
            };
            let parsed_schema = structured(schema, &raw, &[], model, usage)?;
            (raw, parsed_schema)
        } else {
            let parsed_schema = structured(schema, &text, &calls, model, usage)?;
            (text, parsed_schema)
        };

        // The continuation is the assistant turn exactly as the server sent it
        // — the whole message, byte for byte, not a copy of the fields this
        // driver understands. See `ApiMessage::raw` for what rebuilding it
        // costs; the short version is that an extension this driver has never
        // heard of is exactly the thing the next request has to return.
        //
        // The `role` is asserted rather than echoed: a server that omits it, or
        // sends something other than `assistant`, would produce a history entry
        // the next request cannot use, and the message's own position in the
        // conversation is this driver's fact rather than the server's.
        let continuation = (!calls.is_empty()).then(|| {
            let mut message = choice.message.raw.clone();
            match message.as_object_mut() {
                Some(object) => {
                    object.insert("role".to_owned(), json!("assistant"));
                }
                // A message that is not an object cannot be replayed as one.
                // Fall back to the shape the wire requires, which loses any
                // extension but keeps the ids the model issued.
                None => {
                    message = json!({
                        "role": "assistant",
                        "content": choice.message.content,
                        "tool_calls": choice.message.tool_calls.iter().map(|c| json!({
                            "id": c.id,
                            "type": "function",
                            "function": {
                                "name": c.function.name,
                                "arguments": c.function.arguments,
                            },
                        })).collect::<Vec<_>>(),
                    });
                }
            }
            super::ProviderContinuation::new(PROVIDER, json!([message]))
        });

        Ok(Completion {
            structured: structured_value,
            tool_calls: calls,
            text,
            usage,
            stop_reason: choice.finish_reason.clone(),
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
                // A 200 whose body will not parse still generated.
                model: model.clone(),
                usage: Usage::default(),
                detail: format!("the response body did not parse: {e}"),
            })?;
        self.interpret(&parsed, model, schema)
    }

    async fn read_streamed(
        &self,
        response: reqwest::Response,
        model: &ModelId,
        schema: Option<&Value>,
        observer: Option<(&dyn super::ModelStreamObserver, &crate::core::Label)>,
    ) -> Result<Completion, ModelError> {
        use futures_util::StreamExt;

        let mut decoder = sse::Decoder::new();
        let mut acc = chat_completions_stream::Accumulator::new();
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
            let events = decoder
                .push(&chunk)
                .map_err(|error| severed(model, &acc, &error.to_string()))?;
            for event in events {
                if let Some(delta) = acc.push(&event.data)
                    && let Some((observer, label)) = observer
                {
                    observer.event(crate::core::Tainted::with_label(
                        super::ModelStreamEvent::TextDelta(delta),
                        label.clone(),
                    ));
                }
            }
            if acc.done() {
                break;
            }
        }
        if !acc.done() {
            return Err(severed(
                model,
                &acc,
                "the stream ended before its `[DONE]` terminal",
            ));
        }

        // The accumulator emits the exact envelope a buffered call returns, so
        // this is the identical parse and the identical interpretation.
        let parsed: ApiResponse =
            serde_json::from_value(acc.into_response()).map_err(|e| ModelError::Unusable {
                model: model.clone(),
                usage: Usage::default(),
                detail: format!("the reassembled stream did not parse: {e}"),
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

/// A stream that stopped before `[DONE]`.
///
/// The whole judgement is whether any delta was seen. Before the first one,
/// nothing is known to have happened and the call is safe to repeat; after
/// it, the server generated tokens this driver cannot count — the same state
/// the Responses stream can produce, and the same honest answer.
fn severed(
    model: &ModelId,
    acc: &chat_completions_stream::Accumulator,
    detail: &str,
) -> ModelError {
    if acc.generated() {
        return ModelError::Unaccounted {
            model: model.clone(),
            detail: detail.to_owned(),
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: format!("the stream ended before it generated: {detail}"),
    }
}

/// Extend the provider transcript after a successful tool-calling response.
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
    state.extend(tool_messages(exchanges));
    if let Some(items) = current.state.as_array() {
        state.extend(items.iter().cloned());
    }
    current.state = Value::Array(state);
}

#[async_trait]
impl ModelProvider for ChatCompletions {
    fn request_profile(&self, model: &ModelId) -> Value {
        let schema_mode = match self.mode_for(model) {
            SchemaMode::Native => "native",
            SchemaMode::ForcedTool => "forced-tool",
        };
        json!({
            "driver": "chat-completions/v1",
            "base": self.base,
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

        // No model-family-neutral spelling exists on this wire. Refused
        // rather than dropped: a declared control that silently does nothing
        // is the shape this crate refuses everywhere.
        if reasoning_effort.is_some() {
            return Err(ModelError::Refused {
                model: model.clone(),
                detail: "the chat-completions wire has no neutral reasoning-effort \
                         mapping; configure the model's own default instead"
                    .to_owned(),
            });
        }

        self.check_egress(model)?;

        let body = self.body(
            model,
            prompt,
            max_output_tokens,
            schema,
            tools,
            exchanges,
            continuation,
        )?;
        let mut http = self
            .http
            .post(format!("{}/chat/completions", self.base))
            .timeout(self.timeout)
            .json(&body);
        if let Some(key) = &self.key {
            http = http.bearer_auth(key.expose());
        }
        let response = http
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
            let text =
                crate::netguard::intake::read_text(response, crate::netguard::intake::METADATA)
                    .await
                    .unwrap_or_default();
            return Err(classify_status(model, status.as_u16(), &headers, &text));
        }

        let mut completion = if self.stream {
            self.read_streamed(response, model, schema, stream).await?
        } else {
            self.read_buffered(response, model, schema).await?
        };
        // A buffered call still answers the observer's one guaranteed
        // question — what did this cost — as every driver does on both paths.
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
