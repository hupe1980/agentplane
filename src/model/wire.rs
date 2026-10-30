//! What an HTTP failure means for a model call.
//!
//! Shared by every driver that speaks HTTP, because the mapping is **doctrine
//! rather than vendor detail** and two copies of it would drift. The question a
//! driver has to answer is not "what did the provider say" but:
//!
//! 1. did it reach them, and
//! 2. did it cost anything.
//!
//! Those two answers decide whether the runtime may ask again and whether the
//! budget ceiling is telling the truth. Everything else — field names, envelope
//! shapes, which key holds the token counts — is per-provider and stays in the
//! driver.

use super::{ModelError, ModelId};

/// Classify a non-success HTTP status.
///
/// Every driver routes its non-2xx responses through here, so the rules live in
/// one place:
///
/// * **429 and 529** are rate limiting. Separate from an ordinary refusal
///   because the response is different: this one is worth retrying, and it is
///   the one case where retrying is unambiguously safe *and* free. The
///   provider's `Retry-After` rides along, because it is the only number that
///   makes the retry useful — see [`ModelError::RateLimited`]. A 429 whose
///   body names an **exhausted quota** is the exception: `OpenAI` sends its
///   billing refusal with the throttle's status, and no wait ends it.
/// * **408 and 425** are the transient 4xx: a request the *server* timed out
///   or declined to process early, not one it judged wrong. Classed with the
///   retryable failures, because `Refused` means *repeating is pointless* and
///   these are the two 4xx codes for which repeating is the documented remedy.
/// * **every other 4xx** is a refusal before generating — bad request, unknown
///   model, bad key, content filtered on the way in. Nothing was metered, and
///   repeating is pointless rather than merely unsafe: the retry loop spends
///   no attempt on it.
/// * **every 3xx** is this plane's own decision, not the provider's. The
///   client does not follow redirects, because the host a `Location` names is
///   one no egress grant covers and the credential travels: `reqwest` strips
///   only `Authorization`, `Cookie` and `Proxy-Authorization` across origins,
///   so `x-api-key` and `x-goog-api-key` would arrive at whatever host the
///   endpoint chose. It is [`ModelError::Egress`] for the retry semantics as
///   much as the audience — an endpoint's redirect will not stop being a
///   redirect on the second attempt, and reported as an outage it costs the
///   whole ladder before saying so.
/// * **anything else** reached the provider and did not say what it cost. See
///   [`ModelError::Unavailable`]: guessing "free" lets a retry loop spend
///   against a ceiling reading zero, and guessing "fatal" makes a transient blip
///   end a run.
pub fn classify_status(
    model: &ModelId,
    status: u16,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> ModelError {
    let detail = format!("HTTP {status}: {}", trim(body));
    match status {
        429 if names_exhausted_quota(body) => ModelError::Refused {
            account: true,
            model: model.clone(),
            code: body_code(body),
            detail,
        },
        429 | 529 => ModelError::RateLimited {
            model: model.clone(),
            detail,
            retry_after: retry_after(headers),
        },
        408 | 425 => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },
        // 401, 402 and 403 refuse the credential or the account whatever the
        // body says, which matters for a compatible server that names no code.
        400..=499 => {
            let code = body_code(body);
            ModelError::Refused {
                account: matches!(status, 401..=403) || code.as_deref().is_some_and(account_code),
                model: model.clone(),
                code,
                detail,
            }
        }
        // The `Location` is named because it is the whole diagnosis: whoever
        // reads this has a gateway, a proxy or a DNS entry sending the call
        // somewhere else, and the header says where. Absent when the endpoint
        // sent a 3xx with no target, which is its own answer.
        300..=399 => ModelError::Egress {
            model: model.clone(),
            detail: format!(
                "HTTP {status}: this client does not follow redirects, and the endpoint \
                 redirected to {} — a host no egress grant covers, reached with this \
                 plane's credential",
                headers
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map_or_else(
                        || "a target it did not name".to_owned(),
                        |l| format!("'{l}'")
                    ),
            ),
        },
        _ => ModelError::Unavailable {
            model: model.clone(),
            detail,
        },
    }
}

/// Classify an error a provider named in its body rather than by status.
///
/// The in-stream twin of [`classify_status`]: an `error` event arrives inside
/// a 200, so its status is gone and the error's own `type` and `code` are all
/// there is. `kind` is both, joined; the vocabulary is the one the
/// `OpenAI`-shaped wires share. Only for a call that has not generated — one
/// that has is billed whatever the error says.
///
/// An exhausted quota or a billing fault is a refusal, not a throttle: it ends
/// when somebody pays, so a retry spends the ladder learning nothing.
pub fn classify_named(model: &ModelId, error: &serde_json::Value, detail: String) -> ModelError {
    const REFUSED: [&str; 8] = [
        "insufficient_quota",
        "billing",
        "invalid_request",
        "invalid_api_key",
        "authentication",
        "permission",
        "not_found",
        "context_length",
    ];
    let named = |key: &str| {
        error
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    };
    let kind = format!("{} {}", named("type"), named("code"));
    if REFUSED.iter().any(|name| kind.contains(name)) {
        let code = error_code(error);
        ModelError::Refused {
            account: code.as_deref().is_some_and(account_code),
            model: model.clone(),
            code,
            detail,
        }
    } else if kind.contains("rate_limit") {
        ModelError::RateLimited {
            model: model.clone(),
            detail,
            // Inside a 200 whose headers were accepted before the first byte
            // of the body: there is no `Retry-After`, and no window is invented.
            retry_after: None,
        }
    } else {
        ModelError::Unavailable {
            model: model.clone(),
            detail,
        }
    }
}

/// Whether a provider's error code refuses the **account** rather than the
/// request: an exhausted quota or credit, billing, a missing, invalid or
/// expired key, a permission the key lacks — paying, rotating the key or
/// granting the permission changes the answer; rewording the request does not.
///
/// The vocabulary of the wires classified here: `OpenAI`-shaped
/// `insufficient_quota`, `billing_*`, `invalid_api_key` and a code naming a
/// credit balance; Anthropic's `authentication_error`, `billing_error` and
/// `permission_error`; Gemini's `PERMISSION_DENIED` and `UNAUTHENTICATED`.
/// A wire that gives an account refusal no code of its own decides it in its
/// driver.
pub(crate) fn account_code(code: &str) -> bool {
    const ACCOUNT: [&str; 8] = [
        "insufficient_quota",
        "credit",
        "billing",
        "invalid_api_key",
        "authentication",
        "permission_error",
        "PERMISSION_DENIED",
        "UNAUTHENTICATED",
    ];
    ACCOUNT.iter().any(|name| code.contains(name))
}

/// The provider's own name for an error, from a response body: the `error`
/// object's code, when the body is JSON and has one.
#[must_use]
pub fn body_code(body: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    error_code(
        value
            .get("error")
            .filter(|e| e.is_object())
            .unwrap_or(&value),
    )
}

/// The provider's own name for an error, from its error object: `type` and
/// `code` joined by `:` where both are present and differ (`OpenAI`'s
/// `invalid_request_error:invalid_api_key`), else whichever is present —
/// Anthropic's `type`, Gemini's `status`.
///
/// Held to an identifier by [`bounded_code`](super::bounded_code).
#[must_use]
pub fn error_code(error: &serde_json::Value) -> Option<String> {
    let named = |key: &str| {
        error
            .get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let code = match (named("type"), named("code").or_else(|| named("status"))) {
        (Some(kind), Some(code)) if kind != code => format!("{kind}:{code}"),
        (Some(one), _) | (None, Some(one)) => one.to_owned(),
        (None, None) => return None,
    };
    super::bounded_code(code)
}

/// Whether an error body names an exhausted quota (`OpenAI`'s
/// `insufficient_quota`, in `error.code` or `error.type`).
fn names_exhausted_quota(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let error = &value["error"];
    ["code", "type"]
        .iter()
        .any(|key| error[*key].as_str() == Some("insufficient_quota"))
}

/// The provider's `Retry-After`, in seconds, when it named one.
///
/// The parsing rule is [`core::retry_after_seconds`](crate::core::retry_after_seconds),
/// shared with every other wire this crate reads advice on: delta-seconds only,
/// because the HTTP-date form means trusting somebody else's clock against ours.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    crate::core::retry_after_seconds(headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?)
}

/// Classify a failure to read a provider's answer.
///
/// One table, because the two arms are not the same claim and four drivers
/// would otherwise each decide. A **size refusal is this plane's**: the call
/// generated, so it is billed and `Landed`, and repeating it reaches the same
/// wall — that is [`ModelError::Unusable`], the same variant a 200 whose body
/// will not parse already produces, and for the same reason. A **transport
/// failure is the provider's or the network's**, and goes down the ladder every
/// driver already has for a call that died mid-answer.
///
/// `usage` is what the wire had already reported when the read stopped, and it
/// is the caller's to supply because only the caller knows. Zero on the buffered
/// path, which knowingly under-counts exactly as the parse-failure arm beside it
/// does. On the streamed path it is Anthropic's accumulator figure — that wire
/// reports usage incrementally — and zero for the other three, which report it
/// only at the end, for the same reason a severed stream there is `Unaccounted`:
/// what is unknown is the amount, not whether it happened.
pub fn classify_intake(
    model: &ModelId,
    usage: crate::model::Usage,
    e: &crate::netguard::intake::IntakeError,
) -> ModelError {
    if let Some(transport) = e.transport() {
        return classify_transport(model, transport);
    }
    ModelError::Unusable {
        model: model.clone(),
        usage,
        detail: e.to_string(),
    }
}

/// Classify a transport failure.
///
/// The distinction that matters is whether anything was written. A connection
/// that was never established sent nothing; one that failed later may have
/// delivered the request and generated an answer nobody will see.
pub fn classify_transport(model: &ModelId, e: &reqwest::Error) -> ModelError {
    if e.is_connect() {
        return ModelError::Unreachable {
            model: model.clone(),
            detail: format!("could not connect: {}", crate::netguard::transport_text(e)),
        };
    }
    ModelError::Unavailable {
        model: model.clone(),
        detail: crate::netguard::transport_text(e),
    }
}

/// The answer's text around byte `at`, quoted: what an unusable answer says
/// about itself, so the failure can be diagnosed from the journal.
///
/// The words are the model's, over the caller's data. They travel only in a
/// failure's detail, which the journal seals and telemetry reduces to a
/// digest, exactly as a provider's error text does.
pub(crate) fn excerpt(text: &str, at: usize) -> String {
    const SPAN: usize = 48;
    let floor = |mut i: usize| {
        i = i.min(text.len());
        while !text.is_char_boundary(i) {
            i -= 1;
        }
        i
    };
    let start = floor(at.saturating_sub(SPAN));
    let end = floor(at.saturating_add(SPAN));
    format!(
        "{}{:?}{}",
        if start > 0 { "…" } else { "" },
        &text[start..end],
        if end < text.len() { "…" } else { "" }
    )
}

/// The byte a JSON error points at, from its one-based line and column.
fn error_offset(text: &str, error: &serde_json::Error) -> usize {
    let line_start: usize = text
        .split_inclusive('\n')
        .take(error.line().saturating_sub(1))
        .map(str::len)
        .sum();
    line_start + error.column().saturating_sub(1)
}

/// Parse the answer when a schema was declared.
///
/// Provider constrained generation is the first line of defence. This also
/// parses and locally validates the answer against the exact requested schema,
/// so a provider bug or ignored constraint becomes a loud, metered `Unusable`
/// rather than invalid data reaching a later step. External schema reference
/// resolution is disabled, so validation cannot introduce hidden I/O.
///
/// # Errors
///
/// [`ModelError::Unusable`], carrying the usage — because a malformed answer was
/// still generated and still billed.
pub fn structured(
    schema: Option<&serde_json::Value>,
    text: &str,
    tool_calls: &[super::ToolCall],
    model: &ModelId,
    usage: super::Usage,
) -> Result<Option<serde_json::Value>, ModelError> {
    let Some(schema) = schema else {
        return Ok(None);
    };
    // A turn that asks for tools is not the final answer, and a schema binds
    // only the final answer — the same exemption `honour_declared_schema`
    // applies at the effect boundary. Spelled once here rather than once per
    // driver, because the copy that drifts is on whichever driver a
    // deployment does not exercise: failing a tool-asking turn does worse
    // than waste it — the error path carries no continuation, so a provider's
    // signed reasoning blocks are dropped from the retry, which the provider
    // then rejects. Emulated forced-tool answers pass an empty slice: there
    // the tool call *is* the answer, and its arguments must parse.
    if !tool_calls.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ModelError::Unusable {
            model: model.clone(),
            usage,
            detail: format!(
                "a schema was required and the answer is not JSON: {e}; the answer is \
                 {} bytes, and reads {} there",
                text.len(),
                excerpt(text, error_offset(text, &e))
            ),
        })?;
    super::validate_schema(schema, &value).map_err(|detail| ModelError::Unusable {
        model: model.clone(),
        usage,
        detail,
    })?;
    Ok(Some(value))
}

/// The name of the single tool used when emulating structured output.
///
/// Fixed rather than caller-chosen: it goes into the request, and a name that
/// varied per call would change the request bytes without changing the
/// question, which is noise in anything that diffs them.
pub const RESPOND_TOOL: &str = "agentplane_respond";

/// Keep an error body short enough to log.
///
/// A provider's error payload can carry the echoed prompt, and a prompt can
/// carry whatever the run was working on. Truncating here keeps a failure from
/// becoming an exfiltration channel into the operator's log aggregator.
fn trim(body: &str) -> String {
    const LIMIT: usize = 400;
    if body.len() <= LIMIT {
        return body.to_owned();
    }
    let mut cut = LIMIT;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… ({} bytes)", &body[..cut], body.len())
}

#[cfg(test)]
mod tests {
    /// An answer that is not JSON says where and what: the journal keeps the
    /// failure's detail and not the answer, so the detail is all a later
    /// reader has.
    #[test]
    fn an_unparsable_answer_quotes_itself_where_it_broke() {
        let schema = serde_json::json!({ "type": "object" });
        let answer = format!(r#"{{"note":"{}"}}{{"note":"again"}}"#, "x".repeat(200));
        let error = super::structured(
            Some(&schema),
            &answer,
            &[],
            &crate::model::ModelId::new("openai", "gpt-x"),
            crate::model::Usage::default(),
        )
        .expect_err("two objects are not one");
        let detail = error.to_string();
        assert!(
            detail.contains("trailing characters")
                && detail.contains(&format!("{} bytes", answer.len()))
                && detail.contains(r#"xx\"}{\"note"#),
            "the detail does not quote the answer where it broke: {detail}"
        );
    }

    #[test]
    fn an_excerpt_never_splits_a_character() {
        let text = "ä".repeat(100);
        for at in 0..=text.len() + 4 {
            let _ = super::excerpt(&text, at);
        }
    }

    use super::*;
    use crate::core::Disposition;

    fn model() -> ModelId {
        ModelId::new("test", "m")
    }

    fn no_headers() -> reqwest::header::HeaderMap {
        reqwest::header::HeaderMap::new()
    }

    fn advising(value: &str) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_str(value).expect("a header value"),
        );
        headers
    }

    /// The window is the whole point of the classification: without it the
    /// retry loop computes a schedule in hundreds of milliseconds against a
    /// limit measured in tens of seconds, spends every permitted attempt
    /// inside the window, and reports the provider as down.
    #[test]
    fn a_named_rate_limit_window_survives_classification() {
        let e = classify_status(&model(), 429, &advising("42"), "");
        assert!(
            matches!(
                e,
                ModelError::RateLimited {
                    retry_after: Some(42),
                    ..
                }
            ),
            "the provider named its window and the classification dropped it: {e}"
        );
    }

    /// A provider that throttles without saying when to come back is ordinary,
    /// and the effect's own schedule applies. What must not happen is a
    /// fabricated window: `None` is *no advice*, not zero seconds.
    #[test]
    fn an_unnamed_window_is_absent_rather_than_invented() {
        for value in [
            "",
            "  ",
            "0",
            "later",
            "-5",
            "Wed, 21 Oct 2026 07:28:00 GMT",
        ] {
            let e = classify_status(&model(), 429, &advising(value), "");
            assert!(
                matches!(
                    e,
                    ModelError::RateLimited {
                        retry_after: None,
                        ..
                    }
                ),
                "'{value}' is not advice this crate can act on, and reading it as \
                 one would replace a real backoff with a made-up schedule: {e}"
            );
        }
        assert!(matches!(
            classify_status(&model(), 429, &no_headers(), ""),
            ModelError::RateLimited {
                retry_after: None,
                ..
            }
        ));
    }

    #[test]
    fn rate_limiting_is_told_apart_from_refusal() {
        for s in [429u16, 529] {
            assert!(matches!(
                classify_status(&model(), s, &no_headers(), ""),
                ModelError::RateLimited { .. }
            ));
        }
    }

    #[test]
    fn a_client_error_did_not_generate() {
        for s in [400u16, 401, 403, 404, 422] {
            let e = classify_status(&model(), s, &no_headers(), "");
            assert_eq!(e.disposition(), Disposition::DidNotHappen);
            assert_eq!(e.usage().spend().tokens, 0);
            assert!(
                matches!(e, ModelError::Refused { .. }),
                "HTTP {s} is a judgement about the request, and repeating a \
                 judged request asks the same rule the same question"
            );
        }
    }

    /// 408 and 425 are the transient 4xx: the server timed out or declined to
    /// process *early*, not judged the request wrong. Classing them as
    /// `Refused` would make a hiccup terminal — the retry loop spends no
    /// attempt on a refusal, and these are the two 4xx codes whose documented
    /// remedy is the retry.
    #[test]
    fn the_transient_4xx_are_not_judgements() {
        for s in [408u16, 425] {
            let e = classify_status(&model(), s, &no_headers(), "");
            assert_eq!(e.disposition(), Disposition::DidNotHappen);
            assert!(
                matches!(e, ModelError::Unavailable { .. }),
                "HTTP {s} is transient and must stay retryable, got: {e}"
            );
        }
    }

    #[test]
    fn a_server_error_says_it_does_not_know() {
        assert!(matches!(
            classify_status(&model(), 500, &no_headers(), ""),
            ModelError::Unavailable { .. }
        ));
    }

    /// A provider's error body can echo the prompt back.
    #[test]
    fn a_long_error_body_is_trimmed() {
        let secret = "x".repeat(5_000);
        let e = classify_status(&model(), 400, &no_headers(), &secret);
        let rendered = e.to_string();
        assert!(
            rendered.len() < 600,
            "an error body went into the log at full length ({} chars), and a \
             provider echoes the prompt back in it",
            rendered.len()
        );
        assert!(rendered.contains("5000 bytes"), "{rendered}");
    }

    /// Multi-byte characters must not be cut through.
    #[test]
    fn trimming_respects_character_boundaries() {
        let body = "ü".repeat(1_000);
        let _ = trim(&body);
    }
}

#[cfg(test)]
mod schema_validation_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parseable_but_nonconforming_structured_output_is_unusable() {
        let model = ModelId::new("test", "structured");
        let usage = super::super::Usage {
            output_tokens: 5,
            ..Default::default()
        };
        let error = structured(
            Some(&json!({
                "type": "object",
                "properties": {"id": {"type": "string", "minLength": 5}},
                "required": ["id"]
            })),
            r#"{"id":"abc"}"#,
            &[],
            &model,
            usage,
        )
        .expect_err("provider-constrained output still needs defense-in-depth validation");
        assert!(matches!(error, ModelError::Unusable { usage: u, .. } if u == usage));
    }
}

#[cfg(test)]
mod account_tests {
    use super::*;

    /// Each wire's account refusals read as the account's, and a request's as
    /// the request's.
    #[test]
    fn the_account_is_told_apart_from_the_request() {
        for code in [
            "insufficient_quota:credit_balance_exhausted",
            "invalid_request_error:invalid_api_key",
            "authentication_error",
            "billing_error",
            "permission_error",
            "PERMISSION_DENIED",
            "UNAUTHENTICATED",
        ] {
            assert!(account_code(code), "{code} read as the request's");
        }
        for code in [
            "invalid_request_error",
            "invalid_request_error:context_length_exceeded",
            "not_found_error",
            "INVALID_ARGUMENT",
        ] {
            assert!(!account_code(code), "{code} read as the account's");
        }
    }

    /// A 401, 402 or 403 refuses the credential or the account even from a
    /// compatible server whose body names no code.
    #[test]
    fn a_credential_status_is_the_accounts_without_a_code() {
        let model = ModelId::new("compatible", "m");
        let headers = reqwest::header::HeaderMap::new();
        for status in [401, 402, 403] {
            let refused = classify_status(&model, status, &headers, "denied");
            assert!(refused.refuses_the_account(), "{status}: {refused}");
        }
        let bad = classify_status(&model, 400, &headers, "malformed");
        assert!(!bad.refuses_the_account(), "{bad}");
    }
}
