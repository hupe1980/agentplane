//! Sealing the payload fields a record carries, without hiding the record.
//!
//! # Why a field and not the whole record
//!
//! Wrapping a whole [`RecordKind`](super::RecordKind) in a sealed variant is the obvious design
//! and it is wrong here, for a reason that compiles and passes tests: both
//! store backends match on the concrete variant. redb keys the **exactly-once**
//! index off `EffectStarted`, and both backends key the outcome index off
//! `RunConcluded`. A record whose variant became a sealed wrapper would still
//! build, still pass every test that writes unsealed records, and silently stop
//! enforcing exactly-once — the guarantee whose failure is a payment taken
//! twice.
//!
//! So the variant stays exactly what it was and only the *payload* is sealed —
//! every field that carries the caller's data, enumerated in `payloads`
//! (crate-private: the list is a rule this crate applies, not a surface a
//! caller selects from).
//! Everything the runtime routes on (`seq`, `run`, `case`, `step`, `phase`,
//! `epoch`, `effect_key`, and the variant itself) stays in the clear, so
//! exactly-once, the case scan, the outcome index and the chain all keep
//! working with no key at all.
//!
//! # The chain commits to ciphertext
//!
//! A sealed payload is an ordinary JSON value, so the record serialises and
//! hashes exactly as it always did — over the sealed bytes. That is the
//! decision worth stating, because the alternative is tempting and worse:
//! hashing the plaintext would tie tamper evidence to the key, and destroying
//! the key would erase both the data *and* the ability to prove nothing had
//! been altered. Committing to ciphertext means an auditor with **no keys**
//! still verifies the chain of a run whose payloads are gone — the same shape
//! blobs already have, where the chain commits to a digest and the bytes stay
//! erasable.

use serde_json::{Value, json};

/// The reserved key marking a sealed payload.
///
/// A payload that legitimately contained this key as its *only* key would be
/// indistinguishable from a sealed one, so the name is deliberately not
/// something a business document would carry, and the shape is checked
/// exactly: one key, whose value is a string.
pub(crate) const SEALED: &str = "$sealed";

/// Whether this value is a sealed payload rather than a readable one.
#[must_use]
pub fn is_sealed(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == 1 && o.get(SEALED).is_some_and(serde_json::Value::is_string))
}

/// Whether this string field is a sealed payload rather than readable text.
///
/// The string counterpart of [`is_sealed`], for the fields whose schema is a
/// string rather than a value — a note's text, a failure's message. The same
/// caveat applies in the same shape: text that legitimately began with the
/// marker and decoded as base64 to its end would be indistinguishable, so the
/// marker is deliberately not something prose would open with.
#[must_use]
pub fn is_sealed_text(text: &str) -> bool {
    use base64::Engine;
    text.strip_prefix(SEALED)
        .and_then(|rest| rest.strip_prefix(':'))
        .is_some_and(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .is_ok()
        })
}

/// Wrap an envelope as the JSON a record carries in place of its payload.
pub(crate) fn wrap(envelope: &[u8]) -> Value {
    use base64::Engine;
    json!({ SEALED: base64::engine::general_purpose::STANDARD.encode(envelope) })
}

/// The envelope inside a sealed payload, if this is one.
pub(crate) fn unwrap(value: &Value) -> Option<Vec<u8>> {
    use base64::Engine;
    if !is_sealed(value) {
        return None;
    }
    let encoded = value.as_object()?.get(SEALED)?.as_str()?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
}

/// Wrap an envelope as the string a record carries in place of a text field.
pub(crate) fn wrap_text(envelope: &[u8]) -> String {
    use base64::Engine;
    format!(
        "{SEALED}:{}",
        base64::engine::general_purpose::STANDARD.encode(envelope)
    )
}

/// The envelope inside a sealed text field, if this is one.
pub(crate) fn unwrap_text(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let encoded = text.strip_prefix(SEALED)?.strip_prefix(':')?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
}

/// One sealable field of a record, by the shape its schema gives it.
///
/// Two arms rather than coercing text into a JSON value, because the record's
/// wire format is the field's declared type: a `Note`'s `text` is a string on
/// the wire, and sealing must replace it with a string or every reader of the
/// serialized record changes shape with the key configuration.
pub(crate) enum SealedField<'a> {
    /// A JSON payload — input, output, arguments, a frozen plan.
    Value(&'a mut Value),
    /// A free-text payload — a note, a failure message.
    Text(&'a mut String),
}

/// The payload fields of a record kind, for sealing and opening in place.
///
/// One list, consulted by both directions, because a field sealed on the way
/// in and forgotten on the way out is a record nobody can read — and the
/// reverse is a payload that was never sealed at all.
///
/// The dividing rule: *what a store is asked questions about stays readable;
/// what it merely holds is sealed.* Neither backend matches or
/// indexes on any field below — routing lives in `seq`, `run`, `case`,
/// `effect_key`, the variant, and `RunConcluded.outcome`, all of which stay
/// clear.
pub(crate) fn payloads(kind: &mut super::RecordKind) -> Vec<SealedField<'_>> {
    use super::RecordKind as K;
    match kind {
        K::RunAdmitted { input, .. } => vec![SealedField::Value(input)],
        // The frozen plan is sealed because it can *embed* the caller's data,
        // not merely reference it: a `planned` agent's planner reads the
        // (trusted) input to write the plan, and any constant it binds —
        // `ArgSource::Const` — is a value derived from that input, frozen into
        // the graph. Trusted is not non-sensitive. Everything that routes on
        // the plan (the step list, the digest) is recomputed from the opened
        // value by a runtime that holds the key; with the key erased the run's
        // data is gone and its replay legitimately goes with it, exactly as it
        // does for `RunAdmitted.input`.
        K::PlanFrozen { plan, .. } => vec![SealedField::Value(plan)],
        K::EffectStarted { descriptor, .. } => vec![SealedField::Value(&mut descriptor.args)],
        K::EffectDone { output, .. } => vec![SealedField::Value(output)],
        // A reconciled effect's recovered result is the same object an
        // `EffectDone.output` is — caller data a probe happened to fetch —
        // and its `detail` is the same free text an `EffectFailed.error` is:
        // a probe's failure message from a provider, which echoes the request
        // it was asked about. `disposition` stays clear, and so does the
        // detail's *presence* — recovery routes on whether the probe spoke,
        // never on what it said, so the Option survives while the words seal.
        K::EffectReconciled { output, detail, .. } => output
            .as_mut()
            .map(SealedField::Value)
            .into_iter()
            .chain(detail.as_mut().map(SealedField::Text))
            .collect(),
        // A settlement's `detail` names the failing invariant or the abort
        // reason in the skill author's words over the caller's values — "hold
        // h-73 does not cover order for alice@…" — while `outcome` is the
        // routing fact and stays clear.
        K::GroupSettled { detail, .. } => {
            detail.as_mut().map(SealedField::Text).into_iter().collect()
        }
        // The message is free text a provider or tool wrote — it quotes the
        // request it refused, which is the caller's data. `disposition` and
        // `permanent` MUST stay clear: retry and reconciliation route on them,
        // and a recovery that needed a key to decide whether a call reached
        // the world would fail closed into an outage.
        K::EffectFailed { error, .. } => vec![SealedField::Text(error)],
        // Reasoning recorded beside the effects it explains — model output
        // over the caller's data, and nothing routes on it.
        K::Note { text } => vec![SealedField::Text(text)],
        // A conclusion's reason is the same free text `EffectFailed.error` is —
        // a provider or tool's refusal, quoting the request it refused — lifted
        // to the run. `outcome` and `chain_head` route and stay clear.
        K::RunConcluded {
            reason,
            outcome: _,
            exhaustion: _,
            live_spend: _,
            chain_head: _,
        } => reason.as_mut().map(SealedField::Text).into_iter().collect(),

        // Control-plane: names, states, digests, counts. Sealing them would
        // cost the readability that makes an unopenable journal still useful,
        // and buy nothing — none of them carries the caller's data.
        //
        // **Every field is named, and none of these arms uses `..`.** An
        // exhaustive match over *variants* asks the question when a record kind
        // is added and stays silent when a **field** is added to one that
        // already exists — which compiles, passes every test, and seals
        // nothing. Naming each field is what makes the compiler ask the second
        // question too, and it is the question that was missed: a run's
        // conclusion gained a reason, and the arm above is where that field's
        // answer now lives.
        // One arm, because the answer is one answer. The fields are still all
        // named: that is what makes a field added later a build error rather
        // than a silent no.
        K::QuotaPassStarted {
            period: _,
            release_slot: _,
        }
        | K::StepStarted { skill: _ }
        | K::StepFinished { outcome: _ }
        | K::CaseBound {
            case_kind: _,
            opened: _,
            correlation: _,
        }
        | K::DeadlineRegistered {
            name: _,
            resolved_at: _,
            calendar_digest: _,
        }
        | K::DeadlineTransition {
            name: _,
            from: _,
            to: _,
        }
        // What a run waits for: a kind and a correlation key, both of which the
        // buffer is asked questions about.
        | K::RunSuspended { reason: _ }
        | K::BudgetRefused { limit: _, used: _ }
        | K::BudgetReadmitted { limit: _ }
        | K::IdentityBound { chain: _ }
        // The rule's own words, written by the operator who wrote the rule —
        // never the request. Naming a reason to a caller is what this crate
        // refuses; recording it for the operator is why the record exists.
        | K::PolicyDenied {
            reason: _,
            action: _,
            resource: _,
        }
        | K::GroupOpened {
            group: _,
            resources: _,
        }
        | K::StepCompensated {
            compensation: _,
            outcome: _,
        }
        // `value` is a **digest**, not the value: the record binds a release
        // decision to bytes it does not hold, and a digest is not the bytes.
        | K::Released {
            releaser: _,
            release: _,
            label: _,
            field_labels: _,
            value: _,
        }
        | K::RunCancelled {
            actor: _,
            reason: _,
        }
        | K::BreakGlass {
            actor: _,
            roles: _,
            reason: _,
        }
        | K::Swept {
            subject: _,
            action: _,
            detail: _,
        } => Vec::new(),
    }
}
