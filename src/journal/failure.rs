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
    /// Whether the peer refused the **account** rather than the request, as
    /// the driver that read the wire decided and the record keeps.
    pub account: bool,
    /// What the failure said, as recorded — sealed text when the journal is
    /// read without the key that opens it.
    pub detail: String,
}

impl FailedEffect {
    /// Whether the peer refused the **account** rather than the request: an
    /// exhausted quota or credit, billing, a missing, invalid or expired
    /// credential, a permission it lacks. Paying, rotating the credential or
    /// granting the permission changes the answer; rewording the request does
    /// not, so a batch should stop.
    #[must_use]
    pub const fn refuses_the_account(&self) -> bool {
        self.account
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
                error,
                disposition,
                permanent,
                code,
                account,
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
                    account: *account,
                    detail: error.clone(),
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

#[cfg(test)]
mod tests {
    use super::failed_effect;
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

    fn failed(code: &str, account: bool) -> RecordKind {
        RecordKind::EffectFailed {
            account,
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
            (s0, Some(key(1)), failed("overloaded", false)),
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
            (s1, Some(key(3)), failed("billing_error", true)),
        ]);
        let failed = failed_effect(&history).expect("the standing failure");
        assert_eq!(failed.key, key(3));
        assert_eq!(failed.code.as_deref(), Some("billing_error"));
        assert!(
            failed.refuses_the_account(),
            "the record's verdict was not read"
        );
        assert_eq!(failed.detail, "no");
        assert_eq!(failed.kind, "model.complete");
        assert!(
            failed_effect(&history[..4]).is_none(),
            "an answered retry left a failure standing"
        );
    }
}
