//! Sealing the payload fields a record carries, without hiding the record.
//!
//! # Why a field and not the whole record
//!
//! Wrapping a whole [`RecordKind`](super::RecordKind) in a sealed variant is the obvious design
//! and it is wrong here, for a reason that compiles and passes tests: both
//! store backends match on the concrete variant. redb keys the **exactly-once**
//! index off `EffectStarted`, and both backends key the outcome index off
//! `RunSealed`. A record whose variant became a sealed wrapper would still
//! build, still pass every test that writes unsealed records, and silently stop
//! enforcing exactly-once — the guarantee whose failure is a payment taken
//! twice.
//!
//! So the variant stays exactly what it was and only the *payload* is sealed:
//! `RunAdmitted.input`, `EffectStarted.descriptor.args` — which is where model
//! prompts and tool arguments live — and `EffectDone.output`. Everything the
//! runtime routes on (`seq`, `run`, `case`, `step`, `phase`, `epoch`,
//! `effect_key`, and the variant itself) stays in the clear, so exactly-once,
//! the case scan, the outcome index and the chain all keep working with no key
//! at all.
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

/// The payload fields of a record kind, for sealing and opening in place.
///
/// One list, consulted by both directions, because a field sealed on the way
/// in and forgotten on the way out is a record nobody can read — and the
/// reverse is a payload that was never sealed at all.
pub(crate) fn payloads(kind: &mut super::RecordKind) -> Vec<&mut Value> {
    use super::RecordKind as K;
    match kind {
        K::RunAdmitted { input, .. } => vec![input],
        K::EffectStarted { descriptor, .. } => vec![&mut descriptor.args],
        K::EffectDone { output, .. } => vec![output],
        // Everything else is control-plane: names, states, digests, counts.
        // Sealing them would cost the readability that makes an unopenable
        // journal still useful, and buy nothing — none of them carries the
        // caller's data.
        _ => Vec::new(),
    }
}
