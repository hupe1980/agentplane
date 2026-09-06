//! How much an answer from somewhere else may cost this process.
//!
//! The address rule next door answers *where may we connect*, and
//! [`Egress`](crate::core::Egress) answers *which hosts may we reach*. Neither
//! answers the question a counterparty decides on its own: **how many bytes come
//! back**. Every outbound call here carries a timeout, so the time an answer may
//! take is bounded; a timeout says nothing about how much may arrive inside it,
//! and a fast endpoint delivers a gigabyte long before one fires. The model, the
//! tools and the peers are untrusted here, so a tool server answering a
//! directory listing with a gigabyte and a hostile one are the same case.
//!
//! The ceiling is applied twice per call. Once against a declared
//! `Content-Length`, which refuses the honest large answer before a byte is
//! read; then against the accumulated bytes, because the header is a claim by
//! the party under suspicion and a check that stopped there would be a control
//! the attacker configures.
//!
//! [`ANSWER`] bounds a reply that carries work — a model completion, a peer's
//! answer. [`METADATA`] bounds a description of something: an Agent Card, a
//! checkpoint note, a wrapped key, a body read only to say why a call failed.
//! Both are constants rather than knobs, because a ceiling nobody can raise is a
//! ceiling nobody quietly raises to whatever the last failure needed. Governed
//! media keeps its own configurable limit, since there the payload size is the
//! subject rather than the overhead.
//!
//! # Two responses this crate never holds
//!
//! Named rather than left to be inferred from a missing call, for the reason
//! [`Egress`](crate::core::Egress) names its own exception: an uncovered surface
//! that says it is uncovered gets revisited, and one that says nothing does not.
//!
//! * **MCP over stdio or streamable HTTP**, whose framing belongs to `rmcp` —
//!   this crate hands that transport a process or a URL and never sees the bytes.
//! * **Bedrock**, for the same reason it takes no `Egress`: the AWS SDK owns the
//!   response.
//!
//! # Why this is public
//!
//! The shipped drivers are not the only drivers, and the version of this control
//! that gets written by hand is the unbounded one. The cost is stated rather
//! than hidden: these signatures name `reqwest` types, so this crate's HTTP
//! client is part of its public surface on the features that link one.

use futures_util::StreamExt as _;

/// The most an answer carrying work may cost: 16 MiB.
///
/// Roughly twenty times the largest answer any shipped driver can legitimately
/// produce — two hundred thousand tokens of text is under a megabyte, plus the
/// reasoning blobs and tool arguments beside it. Wide enough that no real call
/// meets it, narrow enough that meeting it is a fault.
///
/// A peer's reply is held to the same figure: an A2A artifact past it is a file,
/// and a file belongs in a blob store addressed by digest rather than inlined
/// into a response about to become a journal record.
pub const ANSWER: usize = 16 * 1024 * 1024;

/// The most a description of something may cost: 1 MiB.
///
/// An Agent Card, a `tlog-checkpoint` note, a wrapped data key, or the body of
/// a failed response read only to say why it failed. Every one of these is
/// small by construction, and the largest of them — a card advertising a few
/// hundred skills — is three orders of magnitude under this.
pub const METADATA: usize = 1024 * 1024;

/// Why an answer was not read.
///
/// The three arms are kept apart because they call for different next steps and
/// because two of them are the counterparty's fault while the third may be the
/// network's. Collapsing them would file *this peer is misbehaving* under *try
/// again later*, which is the retry loop that never ends.
#[derive(Debug)]
pub enum IntakeError {
    /// The response declared a body past the ceiling. Refused before reading.
    Declared { limit: usize, declared: u64 },
    /// The body grew past the ceiling while it was being read.
    Exceeded { limit: usize },
    /// The stream failed. Not a size refusal — the counterparty may be blameless.
    Transport(reqwest::Error),
}

impl std::fmt::Display for IntakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Declared { limit, declared } => write!(
                f,
                "the answer declared {declared} bytes and this plane reads at most {limit}"
            ),
            Self::Exceeded { limit } => write!(
                f,
                "the answer grew past {limit} bytes, which is the most this plane reads"
            ),
            Self::Transport(e) => write!(f, "the answer could not be read: {e}"),
        }
    }
}

impl std::error::Error for IntakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl IntakeError {
    /// Whether this was a size refusal rather than a failure to read.
    ///
    /// The distinction a caller needs in order to classify: a size refusal is
    /// permanent and repeating the call reaches the same wall, while a transport
    /// failure is the ordinary interrupted-call case every driver already has a
    /// ladder for.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(self, Self::Declared { .. } | Self::Exceeded { .. })
    }

    /// The transport failure inside, when that is what this is.
    #[must_use]
    pub const fn transport(&self) -> Option<&reqwest::Error> {
        match self {
            Self::Transport(e) => Some(e),
            _ => None,
        }
    }
}

/// A running byte budget for one answer.
///
/// Separate from [`read`] because a streamed answer is consumed event by event
/// by a decoder that has to see each chunk — there is no whole body to hand
/// back. The same ceiling applies to the same bytes; only the consumer differs.
///
/// What it bounds on that path is the **number** of events, not their size: a
/// per-event ceiling stops the unterminated line and lets well-formed hundred-
/// byte deltas accumulate until the process dies.
#[derive(Debug)]
pub struct Meter {
    limit: usize,
    seen: usize,
}

impl Meter {
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self { limit, seen: 0 }
    }

    /// Charge a chunk against the budget.
    ///
    /// # Errors
    ///
    /// [`IntakeError::Exceeded`] once the answer has cost more than the budget.
    /// Checked *before* the caller keeps the chunk, so the ceiling bounds what
    /// is held rather than what has already been held.
    pub fn charge(&mut self, bytes: usize) -> Result<(), IntakeError> {
        // Saturating rather than wrapping: an answer big enough to overflow a
        // `usize` is one this refuses either way, and a wrap would refuse
        // nothing.
        self.seen = self.seen.saturating_add(bytes);
        if self.seen > self.limit {
            return Err(IntakeError::Exceeded { limit: self.limit });
        }
        Ok(())
    }
}

/// Read a whole response body, refusing one that will not fit.
///
/// # Errors
///
/// [`IntakeError`], which distinguishes a size refusal from a stream that
/// failed.
pub async fn read(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, IntakeError> {
    // The header, not `Response::content_length()`. What this check is about is
    // the *claim* the counterparty made, and the accessor answers from the body
    // when there is no claim at all — which would make the cheap refusal depend
    // on how the body happened to be framed. This crate links no decompression
    // feature, so the two agree on every real response anyway.
    let declared = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if let Some(declared) = declared
        && declared > limit as u64
    {
        return Err(IntakeError::Declared { limit, declared });
    }

    let mut meter = Meter::new(limit);
    // With capacity from the declared length when there is one, capped at the
    // ceiling: a body that lies about being small still cannot make this
    // allocate more than the ceiling up front.
    let mut body = Vec::with_capacity(
        declared
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0)
            .min(limit),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(IntakeError::Transport)?;
        meter.charge(chunk.len())?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read a whole response body as text, refusing one that will not fit.
///
/// Lossy on invalid UTF-8, matching `Response::text`. Every caller of this is
/// reading a body to *explain* something — a provider's error message, a
/// service's refusal — and a decode failure there would replace the explanation
/// with a second error about the explanation.
///
/// # Errors
///
/// [`IntakeError`], as [`read`].
pub async fn read_text(response: reqwest::Response, limit: usize) -> Result<String, IntakeError> {
    let bytes = read(response, limit).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_refuses_the_chunk_that_crosses_it() {
        let mut meter = Meter::new(10);
        assert!(meter.charge(6).is_ok());
        // The chunk that crosses is refused rather than accepted and reported
        // afterwards: the ceiling bounds what is held.
        let err = meter.charge(6).expect_err("11 bytes is past 10");
        assert!(err.is_refusal());
        assert!(matches!(err, IntakeError::Exceeded { limit: 10 }));
    }

    #[test]
    fn a_budget_admits_an_answer_of_exactly_the_ceiling() {
        // The boundary is inclusive on the permitted side. An answer that fits
        // exactly is an answer that fits, and an off-by-one here would refuse
        // the honest call that sized itself to the documented limit.
        let mut meter = Meter::new(10);
        assert!(meter.charge(10).is_ok());
        assert!(meter.charge(1).is_err());
    }

    /// Built from an `http::Response`, so both halves of the rule can be probed
    /// without a socket. The streamed half needs a real server and has one in
    /// `tests/wire/drivers.rs`; this is the half a stub can state exactly.
    fn response(body: &'static str, declared: Option<u64>) -> reqwest::Response {
        let mut builder = http::Response::builder();
        if let Some(n) = declared {
            builder = builder.header(http::header::CONTENT_LENGTH, n);
        }
        reqwest::Response::from(builder.body(body).expect("a response"))
    }

    #[tokio::test]
    async fn a_declared_oversize_is_refused_before_a_byte_is_read() {
        // The cheap half: an honest counterparty says how big the answer is, and
        // there is no reason to spend a single allocation finding out.
        let err = read(response("hello", Some(9_000)), 10)
            .await
            .expect_err("9000 declared against a ceiling of 10");
        assert!(matches!(
            err,
            IntakeError::Declared {
                limit: 10,
                declared: 9_000
            }
        ));
        assert!(err.is_refusal());
    }

    #[tokio::test]
    async fn a_body_that_understates_itself_is_still_refused() {
        // The half that matters. `Content-Length` is a claim by the party under
        // suspicion, so a check that stopped at the header would be a control the
        // attacker configures: declare five, send fifty.
        let err = read(response("hello world", Some(2)), 4)
            .await
            .expect_err("eleven bytes past a ceiling of four");
        assert!(
            matches!(err, IntakeError::Exceeded { limit: 4 }),
            "the header said it would fit; the bytes are what decides"
        );
    }

    #[tokio::test]
    async fn an_answer_within_the_ceiling_is_returned_whole() {
        // The positive half, which a refuse-everything implementation would
        // otherwise satisfy.
        let body = read(response("hello", Some(5)), 16).await.expect("it fits");
        assert_eq!(body, b"hello");
    }

    #[test]
    fn an_answer_big_enough_to_overflow_is_still_refused() {
        // Wrapping addition would carry `seen` back under the limit and admit
        // it, which is the arithmetic that turns a ceiling into nothing.
        let mut meter = Meter::new(10);
        assert!(meter.charge(usize::MAX).is_err());
    }
}
