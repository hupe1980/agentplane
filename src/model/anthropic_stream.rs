//! Rebuilding an Anthropic message from its event stream.
//!
//! Kept apart from the driver because it is a **pure** function of the events —
//! no network, no client, no key — which is the only reason the interesting case
//! is testable at all. What has to be checked here is what the accumulator knows
//! *at the moment the stream dies*, and a test that had to arrange a real
//! connection failure to check that would check it once, badly.
//!
//! # Why the accounting works here and not everywhere
//!
//! Anthropic reports usage **incrementally**:
//!
//! * `message_start` carries `input_tokens` and both cache counters immediately,
//!   before a single token of output exists;
//! * every `message_delta` carries a *cumulative* `output_tokens`.
//!
//! So a stream cut off halfway has still told us what the prompt cost and
//! roughly what had been generated — which is exactly
//! [`ModelError::Interrupted`](super::ModelError::Interrupted), the variant that
//! existed with nothing able to produce it until this file.
//!
//! `OpenAI`'s Responses stream does not do this — usage appears only in the
//! terminal event — and that asymmetry is why the two drivers report a severed
//! connection differently. See `openai_stream`.

use serde::Deserialize;
use serde_json::Value;

use super::Usage;

/// One tool block, reassembled across deltas.
#[derive(Debug, Default, Clone)]
struct ToolBlock {
    id: String,
    name: String,
    /// Fragments of the argument object, in arrival order.
    json: String,
}

/// A message being rebuilt from events.
#[derive(Debug, Default)]
pub struct Accumulator {
    text: String,
    /// Complete provider-native content blocks, in their original order.
    ///
    /// These are returned to Anthropic on the next tool turn. In particular,
    /// thinking text and its signature must remain together; dropping either
    /// makes an extended-thinking continuation invalid or silently weaker.
    blocks: std::collections::BTreeMap<u64, Value>,
    /// Every tool block being reassembled, keyed by content-block index.
    ///
    /// Anthropic hands tool input over as *fragments of a JSON string* when
    /// streaming, unlike the non-streaming path where it arrives already
    /// decoded. So the emulated structured-output mode can fail here in a way it
    /// cannot there: the fragments may not reassemble into valid JSON.
    ///
    /// Keyed by index rather than accumulated into one buffer because a model
    /// may emit several tool calls at once, and their fragments interleave.
    /// Concatenating them yields JSON that parses into the wrong arguments —
    /// worse than failing, because it succeeds.
    tools: std::collections::BTreeMap<u64, ToolBlock>,
    /// Which content block index is the forced structured-output tool.
    tool_index: Option<u64>,
    usage: Usage,
    /// Whether `message_start` arrived — i.e. whether generation began.
    ///
    /// The whole point of the file. If this is false when the connection dies,
    /// nothing is known about cost and the honest answer is `Unavailable`; if it
    /// is true, the call generated and must be billed.
    started: bool,
    stop_reason: Option<String>,
    /// The provider's stated grounds for the stop, populated on a refusal.
    stop_details: Option<Value>,
    /// Whether `message_stop` arrived — i.e. whether this is a whole answer.
    complete: bool,
    /// An `error` event delivered inside a 200 response.
    error: Option<StreamError>,
}

/// An error the provider sent *inside* an otherwise successful response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamError {
    pub kind: String,
    pub message: String,
}

/// Mirrors the provider's field names exactly, postfixes and all — the same
/// reasoning as `ApiUsage` in the driver: renaming them means a `serde` rename
/// per field and a mapping nobody can check against the API docs at a glance,
/// which is how a driver ends up reading the wrong counter.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Deserialize)]
struct WireUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
    #[serde(default)]
    cache_creation_input_tokens: Option<u64>,
    #[serde(default)]
    cache_read_input_tokens: Option<u64>,
}

impl Accumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether generation began, and therefore whether anything was billed.
    #[must_use]
    pub const fn started(&self) -> bool {
        self.started
    }

    /// Whether the stream reached `message_stop`.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn error(&self) -> Option<&StreamError> {
        self.error.as_ref()
    }

    #[must_use]
    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }

    /// The provider's `stop_details`, when the wire carried one.
    #[must_use]
    pub fn stop_details(&self) -> Option<&Value> {
        self.stop_details.as_ref()
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The forced tool call's argument object, if one was streamed and parses.
    ///
    /// `None` covers both "no tool block" and "the fragments did not reassemble
    /// into JSON". The caller tells them apart by whether it asked for one, and
    /// reports `Unusable` either way — the call generated regardless.
    #[must_use]
    pub fn forced_tool_input(&self) -> Option<Value> {
        let index = self.tool_index?;
        serde_json::from_str(&self.tools.get(&index)?.json).ok()
    }

    /// Tool calls the model asked for, excluding this crate's forced one.
    ///
    /// A block whose fragments did not reassemble into JSON is a loud failure.
    /// It is never dispatched half-built, and it is not silently dropped: the
    /// latter would make a `tool_use` stop look like an empty final answer.
    pub fn tool_calls(&self) -> Result<Vec<super::ToolCall>, String> {
        self.tools
            .iter()
            .filter(|(index, _)| Some(**index) != self.tool_index)
            .map(|(_, block)| {
                if block.id.is_empty() || block.name.is_empty() {
                    return Err(
                        "Anthropic streamed a tool_use block without an id or name".to_owned()
                    );
                }
                // No argument deltas at all is a zero-argument call, which the
                // buffered path reads as `{}` — the streaming twin must not
                // turn the same wire answer into a parse failure.
                let arguments = if block.json.is_empty() {
                    serde_json::Value::Object(serde_json::Map::new())
                } else {
                    serde_json::from_str(&block.json).map_err(|error| {
                        format!(
                            "Anthropic tool_use '{}' arguments did not form JSON: {error}",
                            block.id
                        )
                    })?
                };
                Ok(super::ToolCall {
                    id: block.id.clone(),
                    name: block.name.clone(),
                    arguments,
                })
            })
            .collect()
    }

    /// Exact assistant content to round-trip on a tool continuation.
    #[must_use]
    pub fn continuation_content(&self) -> Value {
        Value::Array(
            self.blocks
                .iter()
                .map(|(index, block)| {
                    let mut block = block.clone();
                    if block.get("type").and_then(Value::as_str) == Some("tool_use")
                        && let Some(tool) = self.tools.get(index)
                        && let Ok(input) = serde_json::from_str::<Value>(&tool.json)
                    {
                        block["input"] = input;
                    }
                    block
                })
                .collect(),
        )
    }

    /// Absorb one event.
    ///
    /// Unknown event types are ignored on purpose: Anthropic's versioning policy
    /// reserves the right to add them, and a driver that rejected an unrecognised
    /// event would break on a provider release that changed nothing it uses.
    /// Absorb one SSE event. Returns the visible text this event appended, so
    /// a live observer is fed from the same parse the answer is assembled
    /// from — a second, weaker parse at the call site is how an observer and
    /// the journal end up describing two different streams.
    pub fn event(&mut self, name: &str, data: &str) -> Option<String> {
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            // A single malformed event must not lose the answer. If it mattered,
            // the absence shows up as missing text or a missing stop reason,
            // both of which the caller already reports.
            return None;
        };
        // The SSE `event:` name and the JSON `type` always agree; prefer the
        // name and fall back, so a stream that omits one still parses.
        let kind = if name.is_empty() {
            value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
        } else {
            name
        };

        match kind {
            "message_start" => {
                self.started = true;
                if let Some(u) = value.get("message").and_then(|m| m.get("usage")) {
                    self.absorb_usage(u);
                }
            }
            "content_block_start" => {
                let block = value.get("content_block");
                if let Some(index) = value.get("index").and_then(Value::as_u64)
                    && let Some(block) = block
                {
                    self.blocks.insert(index, block.clone());
                }
                let is_tool =
                    block.and_then(|b| b.get("type")).and_then(Value::as_str) == Some("tool_use");
                if is_tool && let Some(index) = value.get("index").and_then(Value::as_u64) {
                    let str_of = |k: &str| {
                        block
                            .and_then(|b| b.get(k))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    let name = str_of("name");
                    // The forced tool is remembered separately: it is this
                    // crate's own mechanism for getting a schema-shaped answer,
                    // not something the caller asked the model to invoke.
                    if name == crate::model::wire::RESPOND_TOOL {
                        self.tool_index = Some(index);
                    }
                    self.tools.insert(
                        index,
                        ToolBlock {
                            id: str_of("id"),
                            name,
                            json: String::new(),
                        },
                    );
                }
            }
            "content_block_delta" => return self.delta(&value),
            "message_delta" => {
                if let Some(reason) = value
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(reason.to_owned());
                }
                if let Some(details) = value
                    .get("delta")
                    .and_then(|d| d.get("stop_details"))
                    .filter(|d| !d.is_null())
                {
                    self.stop_details = Some(details.clone());
                }
                if let Some(u) = value.get("usage") {
                    self.absorb_usage(u);
                }
            }
            "message_stop" => self.complete = true,
            "error" => {
                let e = value.get("error");
                self.error = Some(StreamError {
                    kind: e
                        .and_then(|e| e.get("type"))
                        .and_then(Value::as_str)
                        .unwrap_or("error")
                        .to_owned(),
                    message: e
                        .and_then(|e| e.get("message"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
            // `ping`, and whatever ships next.
            _ => {}
        }
        None
    }

    fn delta(&mut self, value: &Value) -> Option<String> {
        let delta = value.get("delta")?;
        match delta.get("type").and_then(Value::as_str) {
            Some("text_delta") => {
                if let Some(t) = delta.get("text").and_then(Value::as_str) {
                    self.text.push_str(t);
                    self.append_block_string(value, "text", t);
                    return Some(t.to_owned());
                }
            }
            Some("input_json_delta") => {
                // Routed to the block it belongs to. Fragments from concurrent
                // tool calls interleave, so one shared buffer would reassemble
                // into JSON that parses into the wrong arguments — worse than
                // failing, because it succeeds.
                if let Some(index) = value.get("index").and_then(Value::as_u64)
                    && let Some(p) = delta.get("partial_json").and_then(Value::as_str)
                    && let Some(block) = self.tools.get_mut(&index)
                {
                    block.json.push_str(p);
                }
            }
            Some("thinking_delta") => {
                if let Some(thinking) = delta.get("thinking").and_then(Value::as_str) {
                    self.append_block_string(value, "thinking", thinking);
                }
            }
            Some("signature_delta") => {
                if let Some(signature) = delta.get("signature").and_then(Value::as_str) {
                    self.append_block_string(value, "signature", signature);
                }
            }
            _ => {}
        }
        None
    }

    fn append_block_string(&mut self, event: &Value, field: &str, fragment: &str) {
        let Some(index) = event.get("index").and_then(Value::as_u64) else {
            return;
        };
        let Some(block) = self.blocks.get_mut(&index).and_then(Value::as_object_mut) else {
            return;
        };
        let value = block
            .entry(field.to_owned())
            .or_insert_with(|| Value::String(String::new()));
        if let Some(text) = value.as_str() {
            *value = Value::String(format!("{text}{fragment}"));
        }
    }

    /// Merge a usage object.
    ///
    /// Every field is taken as an absolute, not an increment: Anthropic
    /// documents `message_delta`'s counts as **cumulative**, so adding them
    /// would over-bill a long answer in proportion to how many events it took.
    /// Absent fields are left alone rather than zeroed, because `message_delta`
    /// often carries only `output_tokens` and zeroing the input count there
    /// would throw away what `message_start` already told us.
    fn absorb_usage(&mut self, u: &Value) {
        let Ok(w) = serde_json::from_value::<WireUsage>(u.clone()) else {
            return;
        };
        if let Some(v) = w.cache_creation_input_tokens {
            self.usage.cache_write_tokens = v;
        }
        if let Some(v) = w.cache_read_input_tokens {
            self.usage.cache_read_tokens = v;
        }
        if let Some(v) = w.input_tokens {
            // Cached tokens are reported *beside* `input_tokens` here, not
            // inside it, so they are added back — `Usage::input_tokens` means
            // everything the provider processed, whichever provider produced it.
            self.usage.input_tokens = v;
        }
        if let Some(v) = w.output_tokens {
            self.usage.output_tokens = v;
        }
    }

    /// The prompt cost, with the cache counters folded back in.
    ///
    /// Kept separate from the running total because the two cache fields arrive
    /// independently of `input_tokens` and folding on arrival would double-count
    /// when a later event repeats one of them.
    #[must_use]
    pub const fn billed(&self) -> Usage {
        // The same call the buffered path makes: Anthropic reports cached
        // counts beside `input_tokens`, and one spelling of that arithmetic is
        // what keeps the two paths from billing a cached call differently.
        Usage::with_cache_beside_input(
            self.usage.input_tokens,
            self.usage.output_tokens,
            self.usage.cache_write_tokens,
            self.usage.cache_read_tokens,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real event sequence, from the provider's own documentation.
    fn feed(acc: &mut Accumulator, events: &[(&str, &str)]) {
        for (name, data) in events {
            acc.event(name, data);
        }
    }

    const START: (&str, &str) = (
        "message_start",
        r#"{"type":"message_start","message":{"id":"msg_1","role":"assistant","content":[],
            "model":"claude-opus-5","stop_reason":null,
            "usage":{"input_tokens":25,"output_tokens":1}}}"#,
    );

    fn text_delta(t: &str) -> (String, String) {
        (
            "content_block_delta".to_owned(),
            format!(
                r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"{t}"}}}}"#
            ),
        )
    }

    #[test]
    fn a_whole_stream_rebuilds_the_message() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[START]);
        let (n, d) = text_delta("Hello");
        acc.event(&n, &d);
        let (n, d) = text_delta(" world");
        acc.event(&n, &d);
        feed(
            &mut acc,
            &[
                (
                    "content_block_stop",
                    r#"{"type":"content_block_stop","index":0}"#,
                ),
                (
                    "message_delta",
                    r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},
                        "usage":{"output_tokens":15}}"#,
                ),
                ("message_stop", r#"{"type":"message_stop"}"#),
            ],
        );

        assert!(acc.complete());
        assert_eq!(acc.text(), "Hello world");
        assert_eq!(acc.stop_reason(), Some("end_turn"));
        assert_eq!(acc.billed().input_tokens, 25);
        assert_eq!(acc.billed().output_tokens, 15);
    }

    #[test]
    fn thinking_and_signature_are_reassembled_for_continuation() {
        let mut acc = Accumulator::new();
        acc.event(
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#,
        );
        acc.event(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"private reasoning"}}"#,
        );
        acc.event(
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signed-value"}}"#,
        );

        assert_eq!(
            acc.continuation_content()[0],
            serde_json::json!({
                "type": "thinking",
                "thinking": "private reasoning",
                "signature": "signed-value"
            })
        );
        assert!(acc.text().is_empty(), "thinking is not visible answer text");
    }

    /// The property the whole streaming path exists for.
    ///
    /// If this is wrong, a severed call reports zero and the token ceiling that
    /// bounds a runaway provider counts nothing while it spends.
    #[test]
    fn usage_is_known_the_moment_generation_starts() {
        let mut acc = Accumulator::new();
        assert!(!acc.started(), "nothing is known before message_start");
        assert_eq!(acc.billed().spend().tokens, 0);

        feed(&mut acc, &[START]);
        assert!(acc.started());
        assert_eq!(
            acc.billed().input_tokens,
            25,
            "the prompt cost is known before a single output token exists — this \
             is what lets a severed stream report Interrupted rather than shrug"
        );
    }

    /// Anthropic documents `message_delta` usage as CUMULATIVE.
    ///
    /// Summing them over-bills a long answer in proportion to how many events it
    /// took to deliver, which is a bug that grows with the response.
    #[test]
    fn cumulative_output_counts_are_not_summed() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "message_delta",
                    r#"{"type":"message_delta","usage":{"output_tokens":10}}"#,
                ),
                (
                    "message_delta",
                    r#"{"type":"message_delta","usage":{"output_tokens":25}}"#,
                ),
                (
                    "message_delta",
                    r#"{"type":"message_delta","usage":{"output_tokens":40}}"#,
                ),
            ],
        );
        assert_eq!(
            acc.billed().output_tokens,
            40,
            "these counts are cumulative; adding them bills 75 for a 40-token answer"
        );
    }

    /// A `message_delta` carrying only output must not erase the input count.
    #[test]
    fn a_partial_usage_object_does_not_zero_what_is_already_known() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "message_delta",
                    r#"{"type":"message_delta","usage":{"output_tokens":9}}"#,
                ),
            ],
        );
        assert_eq!(
            acc.billed().input_tokens,
            25,
            "message_start already said so"
        );
        assert_eq!(acc.billed().output_tokens, 9);
    }

    /// Cached tokens sit *beside* `input_tokens` here, not inside it.
    #[test]
    fn cached_tokens_are_added_back_into_the_input_count() {
        let mut acc = Accumulator::new();
        acc.event(
            "message_start",
            r#"{"type":"message_start","message":{"usage":{"input_tokens":100,
                "cache_creation_input_tokens":40,"cache_read_input_tokens":60,"output_tokens":1}}}"#,
        );
        let billed = acc.billed();
        assert_eq!(
            billed.input_tokens, 200,
            "reading only input_tokens bills a heavily cached call at half price"
        );
        assert_eq!(billed.cache_write_tokens, 40);
        assert_eq!(billed.cache_read_tokens, 60);
    }

    /// Build events with `json!` rather than by hand.
    ///
    /// Tool fragments are JSON *inside* a JSON string, so hand-written fixtures
    /// need two levels of escaping. The first version of these tests got that
    /// wrong, the events failed to parse, the accumulator ignored them exactly
    /// as it ignores any malformed event — and the test reported the feature
    /// broken when the fixture was.
    fn tool_start(index: u64, id: &str, name: &str) -> String {
        serde_json::json!({
            "type": "content_block_start",
            "index": index,
            "content_block": { "type": "tool_use", "id": id, "name": name },
        })
        .to_string()
    }

    fn tool_fragment(index: u64, partial: &str) -> String {
        serde_json::json!({
            "type": "content_block_delta",
            "index": index,
            "delta": { "type": "input_json_delta", "partial_json": partial },
        })
        .to_string()
    }

    /// Two tool calls streamed at once do not contaminate each other.
    ///
    /// Anthropic sends arguments as JSON *fragments*, and fragments from
    /// concurrent blocks interleave. A single shared buffer reassembles them
    /// into JSON that parses — into the wrong arguments. That failure succeeds,
    /// which is why it earns its own test: a tool dispatched with another
    /// call's arguments is a real side effect on the wrong thing.
    #[test]
    fn concurrent_tool_calls_keep_their_own_arguments() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[START]);
        acc.event("content_block_start", &tool_start(0, "call_a", "refund"));
        acc.event("content_block_start", &tool_start(1, "call_b", "notify"));

        // Interleaved on purpose: block 1's fragment lands between block 0's.
        acc.event("content_block_delta", &tool_fragment(0, r#"{"amount":"#));
        acc.event("content_block_delta", &tool_fragment(1, r#"{"to":"#));
        acc.event("content_block_delta", &tool_fragment(0, "250}"));
        acc.event("content_block_delta", &tool_fragment(1, r#""ops"}"#));

        let calls = acc.tool_calls().expect("well-formed tool calls");
        assert_eq!(calls.len(), 2, "both tool calls must survive");
        assert_eq!(calls[0].id, "call_a");
        assert_eq!(calls[0].name, "refund");
        assert_eq!(
            calls[0].arguments,
            serde_json::json!({ "amount": 250 }),
            "block 0 picked up block 1's fragments"
        );
        assert_eq!(calls[1].id, "call_b");
        assert_eq!(calls[1].arguments, serde_json::json!({ "to": "ops" }));
    }

    /// The forced structured-output tool is not a tool call.
    ///
    /// It is this crate's own mechanism for obtaining a schema-shaped answer. A
    /// caller looping over `tool_calls` would try to dispatch a tool that exists
    /// nowhere, and refuse the run for a grant nobody could have written.
    #[test]
    fn the_forced_tool_is_not_reported_as_a_tool_call() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[START]);
        acc.event(
            "content_block_start",
            &tool_start(0, "t1", crate::model::wire::RESPOND_TOOL),
        );
        acc.event(
            "content_block_delta",
            &tool_fragment(0, r#"{"verdict":"ship"}"#),
        );

        assert!(
            acc.tool_calls()
                .expect("well-formed forced tool")
                .is_empty(),
            "the schema-shaping tool must not look like a request to act"
        );
        assert_eq!(
            acc.forced_tool_input(),
            Some(serde_json::json!({ "verdict": "ship" })),
            "and it must still be readable as the structured answer"
        );
    }

    /// Arguments that never reassemble are rejected, not silently dropped.
    #[test]
    fn a_truncated_tool_call_is_loud_rather_than_guessed() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[START]);
        acc.event("content_block_start", &tool_start(0, "t1", "refund"));
        acc.event("content_block_delta", &tool_fragment(0, r#"{"amount":25"#));

        assert!(acc.tool_calls().is_err());
    }

    #[test]
    fn a_stream_that_stops_early_is_not_complete() {
        let mut acc = Accumulator::new();
        feed(&mut acc, &[START]);
        let (n, d) = text_delta("half an ans");
        acc.event(&n, &d);
        assert!(acc.started(), "it generated");
        assert!(!acc.complete(), "and it never finished");
    }

    #[test]
    fn an_error_event_inside_a_200_is_captured() {
        let mut acc = Accumulator::new();
        acc.event(
            "error",
            r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        );
        let e = acc.error().expect("captured");
        assert_eq!(e.kind, "overloaded_error");
        assert_eq!(e.message, "Overloaded");
    }

    /// The forced-tool path: arguments arrive as *fragments of a JSON string*.
    #[test]
    fn forced_tool_fragments_are_reassembled_and_parsed() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "content_block_start",
                    r#"{"type":"content_block_start","index":1,
                        "content_block":{"type":"tool_use","id":"t1","name":"agentplane_respond","input":{}}}"#,
                ),
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":1,
                        "delta":{"type":"input_json_delta","partial_json":"{\"verdict\":"}}"#,
                ),
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":1,
                        "delta":{"type":"input_json_delta","partial_json":" \"ship\"}"}}"#,
                ),
            ],
        );
        assert_eq!(
            acc.forced_tool_input(),
            Some(serde_json::json!({"verdict": "ship"}))
        );
    }

    /// Fragments from a *different* block must not be mixed in.
    ///
    /// Mixing them produces JSON that parses into the wrong answer, which is
    /// worse than failing because it succeeds.
    #[test]
    fn another_blocks_fragments_are_not_mixed_into_the_forced_tool() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "content_block_start",
                    r#"{"type":"content_block_start","index":1,
                        "content_block":{"type":"tool_use","name":"agentplane_respond"}}"#,
                ),
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":1,
                        "delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}"#,
                ),
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":2,
                        "delta":{"type":"input_json_delta","partial_json":"GARBAGE"}}"#,
                ),
            ],
        );
        assert_eq!(acc.forced_tool_input(), Some(serde_json::json!({"a": 1})));
    }

    /// Truncated fragments do not parse, and that is a failure the buffered path
    /// cannot produce.
    #[test]
    fn half_a_tool_argument_is_not_an_answer() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "content_block_start",
                    r#"{"type":"content_block_start","index":1,
                        "content_block":{"type":"tool_use","name":"agentplane_respond"}}"#,
                ),
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":1,
                        "delta":{"type":"input_json_delta","partial_json":"{\"verdict\":"}}"#,
                ),
            ],
        );
        assert_eq!(acc.forced_tool_input(), None);
    }

    /// Reasoning text is billed but is not the answer.
    #[test]
    fn thinking_deltas_do_not_become_the_answer() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                (
                    "content_block_delta",
                    r#"{"type":"content_block_delta","index":0,
                        "delta":{"type":"thinking_delta","thinking":"maybe 21, maybe not"}}"#,
                ),
            ],
        );
        let (n, d) = text_delta("21");
        acc.event(&n, &d);
        assert_eq!(
            acc.text(),
            "21",
            "concatenating reasoning would hand back a conclusion the model did \
             not reach"
        );
    }

    /// The provider reserves the right to add event types.
    #[test]
    fn unknown_events_and_pings_are_ignored() {
        let mut acc = Accumulator::new();
        feed(
            &mut acc,
            &[
                START,
                ("ping", r#"{"type":"ping"}"#),
                (
                    "something_new_in_2027",
                    r#"{"type":"something_new_in_2027"}"#,
                ),
                ("message_stop", r#"{"type":"message_stop"}"#),
            ],
        );
        assert!(acc.complete());
        assert_eq!(acc.billed().input_tokens, 25);
    }

    #[test]
    fn a_malformed_event_does_not_lose_the_rest() {
        let mut acc = Accumulator::new();
        acc.event("message_start", "{not json");
        feed(
            &mut acc,
            &[START, ("message_stop", r#"{"type":"message_stop"}"#)],
        );
        assert!(acc.complete());
    }
}
