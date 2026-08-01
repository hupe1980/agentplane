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

/// A message being rebuilt from events.
#[derive(Debug, Default)]
pub struct Accumulator {
    text: String,
    /// Partial JSON for the forced-tool block, accumulated across deltas.
    ///
    /// Anthropic hands tool input over as *fragments of a JSON string* when
    /// streaming, unlike the non-streaming path where it arrives already
    /// decoded. So the emulated structured-output mode can fail here in a way it
    /// cannot there: the fragments may not reassemble into valid JSON.
    tool_json: String,
    /// Which content block index is the forced tool call.
    tool_index: Option<u64>,
    usage: Usage,
    /// Whether `message_start` arrived — i.e. whether generation began.
    ///
    /// The whole point of the file. If this is false when the connection dies,
    /// nothing is known about cost and the honest answer is `Unavailable`; if it
    /// is true, the call generated and must be billed.
    started: bool,
    stop_reason: Option<String>,
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
        self.tool_index?;
        serde_json::from_str(&self.tool_json).ok()
    }

    /// Absorb one event.
    ///
    /// Unknown event types are ignored on purpose: Anthropic's versioning policy
    /// reserves the right to add them, and a driver that rejected an unrecognised
    /// event would break on a provider release that changed nothing it uses.
    pub fn event(&mut self, name: &str, data: &str) {
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            // A single malformed event must not lose the answer. If it mattered,
            // the absence shows up as missing text or a missing stop reason,
            // both of which the caller already reports.
            return;
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
                let is_tool = value
                    .get("content_block")
                    .and_then(|b| b.get("type"))
                    .and_then(Value::as_str)
                    == Some("tool_use");
                if is_tool {
                    self.tool_index = value.get("index").and_then(Value::as_u64);
                }
            }
            "content_block_delta" => self.delta(&value),
            "message_delta" => {
                if let Some(reason) = value
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    self.stop_reason = Some(reason.to_owned());
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
    }

    fn delta(&mut self, value: &Value) {
        let Some(delta) = value.get("delta") else {
            return;
        };
        match delta.get("type").and_then(Value::as_str) {
            Some("text_delta") => {
                if let Some(t) = delta.get("text").and_then(Value::as_str) {
                    self.text.push_str(t);
                }
            }
            Some("input_json_delta") => {
                // Only the forced tool's block. A model may emit other tool
                // calls, and mixing their fragments into one buffer produces
                // JSON that parses into the wrong answer — which is worse than
                // failing, because it succeeds.
                if value.get("index").and_then(Value::as_u64) == self.tool_index
                    && let Some(p) = delta.get("partial_json").and_then(Value::as_str)
                {
                    self.tool_json.push_str(p);
                }
            }
            // `thinking_delta` and `signature_delta` are deliberately dropped.
            // Reasoning tokens are billed and *are* counted — they are in
            // `output_tokens`, which is read above — but the reasoning text is
            // not the answer, and concatenating it into `text` would hand the
            // caller a completion that says something the model did not
            // conclude.
            _ => {}
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
        Usage {
            input_tokens: self.usage.input_tokens
                + self.usage.cache_write_tokens
                + self.usage.cache_read_tokens,
            output_tokens: self.usage.output_tokens,
            cache_write_tokens: self.usage.cache_write_tokens,
            cache_read_tokens: self.usage.cache_read_tokens,
            minor_units: 0,
        }
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
