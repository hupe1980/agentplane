//! Which effect ended a failed run, read from its records.

use crate::core::{Disposition, EffectKey, StepId};

use super::{Record, RecordKind};

/// The effect whose failure ended a run, as its journal records it.
///
/// Derived from the records rather than carried beside the outcome, so a live
/// run, its replay and a reader holding only its history reach one answer by
/// one path. See [`failed_effect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedEffect {
    /// The step it failed in.
    pub step: Option<StepId>,
    /// The failed attempt's key.
    pub key: EffectKey,
    /// What kind of effect it was — `model.complete`, `tool.call`.
    pub kind: String,
    /// What the failure says about whether the call reached the world.
    pub disposition: Disposition,
    /// Whether the peer answered *no* rather than failed: no retry changes it.
    pub permanent: bool,
    /// The peer's own name for a refusal, where it gave one.
    pub code: Option<String>,
}

impl FailedEffect {
    /// Whether the peer refused the **account** rather than the request — see
    /// [`refuses_the_account`].
    #[must_use]
    pub fn refuses_the_account(&self) -> bool {
        self.code.as_deref().is_some_and(refuses_the_account)
    }
}

/// The effect a failed run ended on: the last forward-phase failure its step
/// never got past.
///
/// A failure is *got past* when its step later answers an effect — a retry
/// that succeeded, or a skill that handled the failure and carried on — or
/// finishes successfully. Compensation runs after a failure and is never the
/// failure. `None` when no effect failure is left standing: a skill that
/// failed on its own account, a refused admission, a run that did not fail.
#[must_use]
pub fn failed_effect(records: &[Record]) -> Option<FailedEffect> {
    let mut standing: Option<FailedEffect> = None;
    for record in records {
        let body = &record.body;
        if !body.phase.is_forward() {
            continue;
        }
        match &body.kind {
            RecordKind::EffectFailed {
                disposition,
                permanent,
                code,
                ..
            } => {
                let Some(key) = body.effect_key else {
                    continue;
                };
                standing = Some(FailedEffect {
                    step: body.step,
                    key,
                    kind: started_kind(records, key).unwrap_or_default(),
                    disposition: *disposition,
                    permanent: *permanent,
                    code: code.clone(),
                });
            }
            RecordKind::EffectDone { .. } | RecordKind::EffectReconciled { .. }
                if standing.as_ref().is_some_and(|f| f.step == body.step) =>
            {
                standing = None;
            }
            RecordKind::StepFinished { outcome }
                if outcome == "succeeded"
                    && standing.as_ref().is_some_and(|f| f.step == body.step) =>
            {
                standing = None;
            }
            _ => {}
        }
    }
    standing
}

/// The kind the effect under `key` was announced as.
fn started_kind(records: &[Record], key: EffectKey) -> Option<String> {
    records.iter().find_map(|r| match &r.body.kind {
        RecordKind::EffectStarted { descriptor, .. } if r.body.effect_key == Some(key) => {
            Some(descriptor.kind.clone())
        }
        _ => None,
    })
}

/// Whether a provider's refusal code refuses the **account** rather than the
/// request.
///
/// An exhausted quota or credit, billing, a missing, invalid or expired key,
/// or a permission the key lacks: paying, rotating the key or granting the
/// permission changes the answer; rewording the request does not.
///
/// The vocabulary is each shipped wire's: `OpenAI`-shaped `insufficient_quota`,
/// `billing_*` and `invalid_api_key`; Anthropic's `authentication_error`,
/// `billing_error` and `permission_error`; Gemini's `PERMISSION_DENIED` and
/// `UNAUTHENTICATED`; Bedrock's `AccessDeniedException`,
/// `UnrecognizedClientException` and `ExpiredTokenException`.
#[must_use]
pub fn refuses_the_account(code: &str) -> bool {
    const ACCOUNT: [&str; 12] = [
        "insufficient_quota",
        "credit",
        "billing",
        "invalid_api_key",
        "authentication",
        "permission_error",
        "PERMISSION_DENIED",
        "UNAUTHENTICATED",
        "AccessDenied",
        "UnrecognizedClient",
        "ExpiredToken",
        "InvalidSignature",
    ];
    ACCOUNT.iter().any(|name| code.contains(name))
}

#[cfg(test)]
mod tests {
    use super::{failed_effect, refuses_the_account};
    use crate::core::{
        Digest, Disposition, EffectDescriptor, EffectKey, Recovery, RunId, Spend, StepId,
    };
    use crate::journal::{Append, Record, RecordKind};

    fn key(n: u8) -> EffectKey {
        EffectKey::from_hex(&Digest::of(&[n]).to_hex()).unwrap()
    }

    fn records(entries: Vec<(StepId, Option<EffectKey>, RecordKind)>) -> Vec<Record> {
        let run = RunId::generate();
        let mut prev = Digest::ZERO;
        let mut out = Vec::new();
        for (i, (step, k, kind)) in entries.into_iter().enumerate() {
            let mut a = Append::new(run, kind).step(step);
            if let Some(k) = k {
                a = a.effect(k);
            }
            let r = Record::seal(a.into_body(i as u64 + 1, 1), prev).unwrap();
            prev = r.hash;
            out.push(r);
        }
        out
    }

    fn started() -> RecordKind {
        RecordKind::EffectStarted {
            descriptor: EffectDescriptor::nullary("model.complete"),
            recovery: Recovery::Retry,
            mutates: false,
            attempt: 1,
            backoff_ms: 0,
            outbound_label: None,
            outbound_bytes: None,
            content_rules: None,
            credential: None,
        }
    }

    fn failed(code: &str) -> RecordKind {
        RecordKind::EffectFailed {
            error: "no".into(),
            spend: Spend::default(),
            disposition: Disposition::DidNotHappen,
            permanent: false,
            unreproducible: None,
            elapsed_ms: None,
            code: Some(code.into()),
        }
    }

    /// A failure its step got past — a retry that answered — is not the
    /// failure the run ended on; the one left standing is.
    #[test]
    fn a_failure_its_step_got_past_is_not_the_runs() {
        let s0 = StepId(0);
        let s1 = StepId(1);
        let history = records(vec![
            (s0, Some(key(1)), started()),
            (s0, Some(key(1)), failed("overloaded")),
            (s0, Some(key(2)), started()),
            (
                s0,
                Some(key(2)),
                RecordKind::EffectDone {
                    declared: crate::core::DeclaredOutput::untrusted(),
                    output: serde_json::json!(1),
                    source: None,
                    by: None,
                    spend: Spend::default(),
                    content: None,
                    elapsed_ms: None,
                },
            ),
            (s1, Some(key(3)), started()),
            (s1, Some(key(3)), failed("billing_error")),
        ]);
        let failed = failed_effect(&history).expect("the standing failure");
        assert_eq!(failed.key, key(3));
        assert_eq!(failed.code.as_deref(), Some("billing_error"));
        assert_eq!(failed.kind, "model.complete");
        assert!(
            failed_effect(&history[..4]).is_none(),
            "an answered retry left a failure standing"
        );
    }

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
            "AccessDeniedException",
            "ExpiredTokenException",
        ] {
            assert!(refuses_the_account(code), "{code} read as the request's");
        }
        for code in [
            "invalid_request_error",
            "invalid_request_error:context_length_exceeded",
            "not_found_error",
            "INVALID_ARGUMENT",
            "ValidationException",
        ] {
            assert!(!refuses_the_account(code), "{code} read as the account's");
        }
    }
}
