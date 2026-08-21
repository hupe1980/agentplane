//! Rebuilding a Chat Completions answer from its chunk stream.
//!
//! The wire is simpler than the Responses event stream — every chunk is a
//! `data:` line holding a partial `chat.completion.chunk`, and the stream ends
//! with the literal `data: [DONE]` — but the reassembly has one genuinely
//! fiddly part: **tool-call arguments arrive as string fragments**, keyed by a
//! call `index`, with the id and name only on the first fragment. An
//! accumulator that keyed on id would attach every later fragment to nothing.
//!
//! The failure mapping mirrors the Responses stream's, because the wire shares
//! its blind spot: usage arrives only at the end (and only when
//! `stream_options.include_usage` is honoured), so a connection cut after
//! visible deltas leaves the driver certain generation happened and ignorant
//! of the cost — [`Unaccounted`](super::ModelError::Unaccounted), never a
//! free retry.

use serde_json::{Value, json};

/// A Chat Completions answer being rebuilt from chunks.
#[derive(Debug, Default)]
pub struct Accumulator {
    content: String,
    refusal: String,
    /// Keyed by the wire's `index`, which is the only field present on every
    /// fragment of one call.
    calls: std::collections::BTreeMap<u64, PartialCall>,
    finish_reason: Option<String>,
    usage: Option<Value>,
    /// Whether any content or tool-call fragment was seen — the judgement the
    /// severed-stream mapping turns on.
    generated: bool,
    done: bool,
    /// Message-level keys this accumulator does not itself understand, kept
    /// for the reason [`PartialCall::extra`] keeps its own: the extension is
    /// what the next request has to return, and `reasoning_content` on
    /// DeepSeek-style wires lives here. String values arrive as fragments and
    /// are concatenated, as `content` is; anything else is a complete value
    /// where the last writer wins.
    extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    /// Every key on the fragment this accumulator does not itself understand.
    ///
    /// Kept for the reason the buffered path keeps the whole message:
    /// "OpenAI-compatible" is a wire servers **extend**, and the extension is
    /// exactly what the next request has to return. Gemini through Google's
    /// compatibility endpoint puts its encrypted `thought_signature` in
    /// `extra_content` and rejects a follow-up turn without it, so an
    /// accumulator that rebuilt a call from the three fields it knows would
    /// drop it — and would do so only on the **streaming** path, which is this
    /// driver's default. That is the worst version of the bug: fixed where it
    /// was looked for, live where it actually runs.
    ///
    /// Whole values rather than concatenated fragments, because these are not
    /// deltas — a server sends an extension once, complete. Last writer wins, so
    /// a server that repeats it on every chunk is harmless.
    extra: serde_json::Map<String, Value>,
}

impl Accumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one `data:` payload. Returns the visible text delta, if this chunk
    /// carried one, for a live observer.
    pub fn push(&mut self, data: &str) -> Option<String> {
        let data = data.trim();
        if data == "[DONE]" {
            self.done = true;
            return None;
        }
        let chunk: Value = serde_json::from_str(data).ok()?;
        // The usage-bearing chunk has an empty `choices` array on the real
        // wire, so usage is read independently of the choice.
        if let Some(usage) = chunk.get("usage").filter(|u| !u.is_null()) {
            self.usage = Some(usage.clone());
        }
        let delta = chunk.get("choices")?.get(0).map_or(&Value::Null, |c| {
            if let Some(reason) = c.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_owned());
            }
            c.get("delta").unwrap_or(&Value::Null)
        });
        if let Some(refusal) = delta.get("refusal").and_then(Value::as_str) {
            self.refusal.push_str(refusal);
            self.generated = true;
        }
        for fragment in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = fragment.get("index").and_then(Value::as_u64).unwrap_or(0);
            let call = self.calls.entry(index).or_default();
            if let Some(id) = fragment.get("id").and_then(Value::as_str) {
                call.id.push_str(id);
            }
            if let Some(f) = fragment.get("function") {
                if let Some(name) = f.get("name").and_then(Value::as_str) {
                    call.name.push_str(name);
                }
                if let Some(arguments) = f.get("arguments").and_then(Value::as_str) {
                    call.arguments.push_str(arguments);
                }
            }
            // Anything else the server attached. `index` is this wire's own
            // framing and `type` is re-emitted as the constant it must be, so
            // neither is carried; everything beyond them belongs to the server
            // and is not this driver's to discard.
            for (key, value) in fragment.as_object().into_iter().flatten() {
                if !matches!(key.as_str(), "index" | "id" | "type" | "function") {
                    call.extra.insert(key.clone(), value.clone());
                }
            }
            self.generated = true;
        }
        for (key, value) in delta.as_object().into_iter().flatten() {
            if matches!(key.as_str(), "role" | "content" | "refusal" | "tool_calls")
                || value.is_null()
            {
                continue;
            }
            // An extension delta is generation: DeepSeek-style
            // `reasoning_content` is billed output, and a stream cut during it
            // must not read as safe to repeat.
            self.generated = true;
            match (self.extra.get_mut(key), value.as_str()) {
                (Some(Value::String(existing)), Some(fragment)) => existing.push_str(fragment),
                _ => {
                    self.extra.insert(key.clone(), value.clone());
                }
            }
        }
        let text = delta.get("content").and_then(Value::as_str)?;
        if text.is_empty() {
            return None;
        }
        self.content.push_str(text);
        self.generated = true;
        Some(text.to_owned())
    }

    /// Whether any output was seen — see the module docs.
    #[must_use]
    pub const fn generated(&self) -> bool {
        self.generated
    }

    /// Whether the `[DONE]` terminal arrived.
    #[must_use]
    pub const fn done(&self) -> bool {
        self.done
    }

    /// The reassembled answer, in the exact envelope a buffered call returns —
    /// so the driver reuses one parser and one interpretation for both paths.
    #[must_use]
    pub fn into_response(self) -> Value {
        let mut message = json!({
            "content": self.content,
            "refusal": if self.refusal.is_empty() { Value::Null } else { Value::String(self.refusal) },
            "tool_calls": self.calls.into_values().map(|c| {
                let mut call = json!({
                    "id": c.id,
                    "type": "function",
                    "function": { "name": c.name, "arguments": c.arguments },
                });
                // Re-attached at the top level, where the server put
                // them, so the envelope this produces is the one a
                // buffered call returns — which is what lets the driver
                // keep one parser and one interpretation for both paths.
                if let Some(object) = call.as_object_mut() {
                    object.extend(c.extra);
                }
                call
            }).collect::<Vec<_>>(),
        });
        // Message-level extensions, re-attached where the server put them —
        // the continuation carries this message verbatim, and an extension
        // dropped only on the streaming path is the worst version of the bug.
        if let Some(object) = message.as_object_mut() {
            object.extend(self.extra);
        }
        json!({
            "choices": [{
                "message": message,
                "finish_reason": self.finish_reason,
            }],
            "usage": self.usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concatenating every delta must reproduce the buffered text byte for
    /// byte — the property an observer that appends into a buffer depends on.
    #[test]
    fn deltas_reassemble_the_text_exactly() {
        let mut acc = Accumulator::new();
        let mut seen = String::new();
        for (data, expect) in [
            (
                r#"{"choices":[{"delta":{"role":"assistant","content":"Hel"}}]}"#,
                Some("Hel"),
            ),
            (r#"{"choices":[{"delta":{"content":"lo"}}]}"#, Some("lo")),
            (r#"{"choices":[{"delta":{},"finish_reason":"stop"}]}"#, None),
            (
                r#"{"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2}}"#,
                None,
            ),
            ("[DONE]", None),
        ] {
            let delta = acc.push(data);
            assert_eq!(delta.as_deref(), expect, "for {data}");
            if let Some(d) = delta {
                seen.push_str(&d);
            }
        }
        assert!(acc.done());
        let out = acc.into_response();
        assert_eq!(out["choices"][0]["message"]["content"], "Hello");
        assert_eq!(seen, "Hello");
        assert_eq!(out["usage"]["prompt_tokens"], 3);
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
    }

    /// Tool-call arguments arrive as string fragments keyed by `index`, with
    /// the id and name only on the first — the reassembly this module exists
    /// for.
    #[test]
    fn tool_call_fragments_reassemble_under_their_index() {
        let mut acc = Accumulator::new();
        for data in [
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":""}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"id\":"}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"x\"}"}}]}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            "[DONE]",
        ] {
            acc.push(data);
        }
        assert!(acc.generated());
        let out = acc.into_response();
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["id"], "call_1");
        assert_eq!(call["function"]["name"], "lookup");
        assert_eq!(call["function"]["arguments"], r#"{"id":"x"}"#);
    }

    /// Nothing seen means nothing generated — the severed-stream mapping's
    /// safe-to-repeat half.
    #[test]
    fn an_empty_stream_reports_nothing_generated() {
        let acc = Accumulator::new();
        assert!(!acc.generated());
        assert!(!acc.done());
    }
}
