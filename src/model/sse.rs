//! Server-sent events, for the one thing streaming buys this runtime.
//!
//! Nothing here is waiting to render tokens to a person. Streaming is used for
//! **partial usage on failure** — the ability to say "it generated four hundred
//! tokens and then the connection died" instead of shrugging. That distinction
//! is the difference between [`ModelError::Interrupted`] and
//! [`ModelError::Unavailable`](super::ModelError::Unavailable), which is the
//! difference between a budget ceiling that binds and one that reads zero while
//! a retry loop spends real money.
//!
//! [`ModelError::Interrupted`]: super::ModelError::Interrupted
//!
//! # Hand-rolled, and why
//!
//! An SSE crate would bring an async-stream framework, its own error type, and
//! usually a reconnection policy. Reconnection is the part that disqualifies
//! them: this crate performs an effect **at most once**, and a client library
//! that silently re-establishes a dropped stream turns one journaled model call
//! into two billed ones with nothing in the record to show it. The parser below
//! is the part that is actually wanted, it is forty lines, and it never retries.
//!
//! Follows the WHATWG event-stream rules, including the parts the two providers
//! happen not to use — multi-line `data`, `\r\n` and bare `\r` terminators,
//! comment lines. Implementing only the observed subset is how a parser breaks
//! the week a provider reformats its output.

/// One event cannot be larger than the journal record that must eventually
/// hold the completion it contributes to. More importantly, this bounds a
/// malicious or broken provider that sends an endless line without a newline.
const DEFAULT_MAX_EVENT_BYTES: usize = 1 << 20;

/// A stream exceeded the amount of event data this decoder will retain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an SSE line or event exceeded the {limit}-byte limit")]
pub struct DecodeError {
    limit: usize,
}

/// One dispatched event: its name and its accumulated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The `event:` field, or empty when the stream did not name one.
    pub name: String,
    /// The `data:` field(s), joined by newlines.
    pub data: String,
}

/// Feeds bytes in, hands events out.
///
/// Stateful because a chunk boundary lands wherever TCP puts it — routinely in
/// the middle of a line, and occasionally between the `\n\n` that dispatches an
/// event. A parser that assumed one chunk was one event would work in every test
/// and fail against a real network.
#[derive(Debug)]
pub struct Decoder {
    /// Bytes received but not yet terminated by a newline.
    partial: String,
    /// The event being built.
    name: String,
    data: String,
    /// Whether any field at all has been seen since the last dispatch.
    ///
    /// Tracked separately from `data` being non-empty: a `data:` line with an
    /// empty value is still a data line, and the spec dispatches it.
    started: bool,
    /// Maximum bytes retained by one partial line or assembled event.
    max_event_bytes: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            partial: String::new(),
            name: String::new(),
            data: String::new(),
            started: false,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
        }
    }
}

impl Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_max_event_bytes(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            ..Self::default()
        }
    }

    /// Push a chunk; get back whatever it completed.
    ///
    /// Lossy on invalid UTF-8 rather than failing. A malformed byte in a
    /// provider's stream should degrade the text of one event, not abort a call
    /// that has already been paid for.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Event>, DecodeError> {
        self.partial.push_str(&String::from_utf8_lossy(chunk));
        let mut out = Vec::new();

        // Consume whole lines only. Whatever trails the last terminator stays in
        // `partial` — it is the front half of a line whose back half is still in
        // flight.
        while let Some((line, rest)) = split_line(&self.partial) {
            if line.len() > self.max_event_bytes {
                return Err(self.too_large());
            }
            // Every split must shrink the buffer. It does by construction —
            // a terminator is always consumed — but this is a parser fed by a
            // remote peer, and the failure mode of getting it wrong is not a
            // wrong answer, it is a run that never returns. A loop that cannot
            // make progress is worth one comparison to rule out.
            //
            // `cargo mutants` is what made this concrete: ten mutations of
            // `split_line` were reported as timeouts rather than catches,
            // because each one spun here forever.
            if rest.len() >= self.partial.len() {
                break;
            }
            let line = line.to_owned();
            self.partial = rest.to_owned();
            if let Some(event) = self.line(&line) {
                out.push(event);
            }
            if self.name.len().saturating_add(self.data.len()) > self.max_event_bytes {
                return Err(self.too_large());
            }
        }
        if self.partial.len() > self.max_event_bytes {
            return Err(self.too_large());
        }
        Ok(out)
    }

    fn too_large(&self) -> DecodeError {
        DecodeError {
            limit: self.max_event_bytes,
        }
    }

    /// Process one line, returning an event if it dispatched one.
    fn line(&mut self, line: &str) -> Option<Event> {
        // Blank line: dispatch.
        if line.is_empty() {
            if !self.started {
                return None;
            }
            let name = std::mem::take(&mut self.name);
            let data = std::mem::take(&mut self.data);
            self.started = false;
            return Some(Event { name, data });
        }

        // A comment. Providers use these as keep-alives; they carry nothing.
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            // The spec strips exactly one leading space from the value, and only
            // one — `data:  x` carries a leading space deliberately.
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            // A field name with no colon has an empty value.
            None => (line, ""),
        };

        match field {
            "event" => {
                value.clone_into(&mut self.name);
                self.started = true;
            }
            "data" => {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.started = true;
            }
            // `id` and `retry` exist and are deliberately ignored. Both serve
            // reconnection, which this decoder must never do — see the module
            // note: a silently re-established stream is a second bill for one
            // journaled effect.
            _ => {}
        }
        None
    }
}

/// Split off the first complete line, handling all three terminators.
///
/// Returns `None` when no terminator has arrived yet. The `\r` case has to look
/// ahead: a bare `\r` at the very end of the buffer might be the front half of a
/// `\r\n` whose `\n` is in the next chunk, and treating it as a terminator would
/// dispatch an event one chunk early and then see a stray empty line.
fn split_line(buf: &str) -> Option<(&str, &str)> {
    let bytes = buf.as_bytes();
    let idx = bytes.iter().position(|&b| b == b'\n' || b == b'\r')?;
    match bytes[idx] {
        b'\n' => Some((&buf[..idx], &buf[idx + 1..])),
        // Bare `\r` at the buffer's end: wait for more, in case it is `\r\n`.
        _ if idx + 1 == bytes.len() => None,
        _ if bytes[idx + 1] == b'\n' => Some((&buf[..idx], &buf[idx + 2..])),
        _ => Some((&buf[..idx], &buf[idx + 1..])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(chunks: &[&str]) -> Vec<Event> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for c in chunks {
            out.extend(d.push(c.as_bytes()).expect("valid SSE"));
        }
        out
    }

    #[test]
    fn a_named_event_with_data_dispatches_on_the_blank_line() {
        assert_eq!(
            all(&["event: message_start\ndata: {\"a\":1}\n\n"]),
            vec![Event {
                name: "message_start".to_owned(),
                data: "{\"a\":1}".to_owned(),
            }]
        );
    }

    /// The case a naive parser gets wrong: TCP does not deliver whole events.
    #[test]
    fn an_event_split_across_chunks_is_reassembled() {
        assert_eq!(
            all(&["event: mess", "age_start\nda", "ta: {\"a\":", "1}\n", "\n"]),
            vec![Event {
                name: "message_start".to_owned(),
                data: "{\"a\":1}".to_owned(),
            }]
        );
    }

    /// A chunk boundary landing *inside* the dispatching `\n\n`.
    #[test]
    fn a_boundary_inside_the_terminator_still_dispatches_once() {
        let events = all(&["data: x\n", "\ndata: y\n\n"]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].data, "x");
        assert_eq!(events[1].data, "y");
    }

    #[test]
    fn multi_line_data_is_joined_with_newlines() {
        assert_eq!(all(&["data: one\ndata: two\n\n"])[0].data, "one\ntwo");
    }

    #[test]
    fn comments_are_ignored() {
        let events = all(&[": keep-alive\ndata: x\n\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "x");
    }

    /// A comment alone must not dispatch an empty event.
    #[test]
    fn a_comment_alone_dispatches_nothing() {
        assert!(all(&[": ping\n\n"]).is_empty());
    }

    #[test]
    fn crlf_and_bare_cr_terminate_lines() {
        assert_eq!(all(&["data: a\r\n\r\n"])[0].data, "a");
        // Note the trailing byte: a bare `\r` is only known to be a terminator
        // once something that is not `\n` follows it. See the test below.
        assert_eq!(all(&["data: b\r\rx"])[0].data, "b");
    }

    /// `\r\n` is **one** terminator, not two.
    ///
    /// The existing CRLF test above passes either way, which is why this one
    /// exists: consuming the `\r` alone leaves the `\n` to start the next line,
    /// and an empty line is what *dispatches an event*. So a parser that gets
    /// this wrong does not drop data — it cuts every event in half at the first
    /// CRLF, which is worse, because each half looks like a complete event.
    ///
    /// Found by `cargo mutants`: two mutations of that match guard survived the
    /// hand-written tests.
    #[test]
    fn crlf_is_one_terminator_not_two() {
        let events = all(&["data: a\r\ndata: b\r\n\r\n"]);
        assert_eq!(
            events.len(),
            1,
            "the CRLF was read as two terminators, so the blank line it \
             manufactured dispatched an event early: {events:?}"
        );
        assert_eq!(events[0].data, "a\nb");
    }

    /// The same, across a chunk boundary that splits the `\r\n`.
    #[test]
    fn a_crlf_split_across_chunks_is_still_one_terminator() {
        let events = all(&["data: a\r", "\ndata: b\r\n\r\n"]);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].data, "a\nb");
    }

    /// A stream ending on a bare `\r` dispatches nothing, and that is correct.
    ///
    /// The `\r` might be the front half of a `\r\n` still in flight. Guessing
    /// costs an event dispatched one chunk early followed by a stray empty line
    /// — and for a *cut-off* stream, refusing to dispatch is exactly right:
    /// half a line is not an event, and the caller is about to report an
    /// interrupted call anyway.
    #[test]
    fn a_stream_ending_on_a_bare_cr_holds_it_back() {
        assert!(all(&["data: b\r"]).is_empty());
    }

    /// A `\r` at a chunk boundary might be the front half of `\r\n`.
    #[test]
    fn a_split_crlf_is_not_read_as_two_terminators() {
        let events = all(&["data: a\r", "\n\r\n"]);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].data, "a");
    }

    /// Exactly one leading space is stripped, per the spec.
    #[test]
    fn only_one_leading_space_is_stripped() {
        assert_eq!(all(&["data:  x\n\n"])[0].data, " x");
        assert_eq!(all(&["data:x\n\n"])[0].data, "x");
    }

    #[test]
    fn a_field_with_no_colon_has_an_empty_value() {
        let events = all(&["data\n\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    /// `id` and `retry` are reconnection machinery this decoder must not honour.
    #[test]
    fn reconnection_fields_are_ignored_but_do_not_break_the_event() {
        let events = all(&["id: 7\nretry: 3000\nevent: e\ndata: d\n\n"]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name, "e");
        assert_eq!(events[0].data, "d");
    }

    /// An unterminated tail is not an event. It is half a line.
    #[test]
    fn an_incomplete_trailing_line_is_not_dispatched() {
        assert!(all(&["event: message_start\ndata: {\"a\""]).is_empty());
    }

    #[test]
    fn an_unnamed_event_still_carries_its_data() {
        let events = all(&["data: x\n\n"]);
        assert_eq!(events[0].name, "");
        assert_eq!(events[0].data, "x");
    }

    #[test]
    fn invalid_utf8_degrades_rather_than_aborting() {
        let mut d = Decoder::new();
        let events = d.push(b"data: \xff\xfe\n\n").expect("valid SSE");
        assert_eq!(events.len(), 1, "a bad byte must not lose the event");
    }

    #[test]
    fn an_unterminated_line_cannot_grow_without_bound() {
        let mut d = Decoder::with_max_event_bytes(8);
        let err = d
            .push(b"123456789")
            .expect_err("an endless line must be bounded");
        assert_eq!(err.limit, 8);
    }

    #[test]
    fn multi_line_event_data_cannot_grow_without_bound() {
        let mut d = Decoder::with_max_event_bytes(8);
        d.push(b"data: 1\n").expect("first line fits");
        d.push(b"data: 2\n").expect("second line fits");
        d.push(b"data: 3\n").expect("third line fits");
        d.push(b"data: 4\n").expect("fourth line fits");
        d.push(b"data: 5\n")
            .expect_err("the assembled event exceeds the limit");
    }
}
