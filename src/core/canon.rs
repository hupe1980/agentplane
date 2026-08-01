//! Canonical serialization.
//!
//! Every hash in the system — record hashes, effect keys, plan digests — is
//! taken over *canonical* bytes. Canonical means: given two values that are
//! semantically equal, the byte strings are equal. Without that, replay would
//! see a different effect key for the same call and quarantine a healthy run.
//!
//! # Why this sorts keys itself
//!
//! `serde_json`'s `Map` is a `BTreeMap` — so it already serializes keys in
//! sorted order — *unless* the `preserve_order` feature is on, in which case it
//! is an `IndexMap` and preserves insertion order instead.
//!
//! This crate never enables that feature, and for a long time that was the whole
//! argument. It was not good enough. Cargo unifies features across the entire
//! dependency graph, so **any** dependency that wants `preserve_order` turns it
//! on for this crate too. Enabling the `cedar` feature did exactly that:
//! `cedar-policy` pulls it in, and with it every effect key in the system would
//! have started depending on the order a caller happened to build a JSON object.
//! Two runs performing the same call would derive different keys — replay
//! divergence at best, and a second real payment at worst.
//!
//! A guard caught it, which is why the invariant is no longer left to a feature
//! flag a stranger controls. Canonical form is produced here, explicitly: object
//! keys are sorted at serialization time, so the output is identical whether
//! `Map` is ordered or not.
//!
//! Keys sort by Rust's `str` ordering, which is UTF-8 byte order. RFC 8785 (JSON
//! Canonicalization Scheme) specifies UTF-16 code-unit order, and the two differ
//! only for characters outside the Basic Multilingual Plane. That is noted
//! rather than fixed because nothing here interoperates with another
//! implementation's canonical bytes — what matters is that *this* crate is
//! self-consistent and deterministic. If cross-implementation canonicalization
//! is ever needed, this is the function to change and the digests are what move.

use serde::Serialize;
use serde_json::Value;

/// Serialize to canonical bytes.
///
/// # Errors
/// Propagates any `serde_json` failure (non-string map keys, non-finite floats
/// in a struct, or a `Serialize` impl that errors).
pub fn to_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    // Through `Value` so that one canonical writer covers every hash in the
    // crate. Serializing `T` directly would leave any `Value` field inside it
    // at the mercy of `Map`'s iteration order — which is the whole problem.
    let value = serde_json::to_value(value)?;
    Ok(value_bytes(&value))
}

/// Canonical bytes for a JSON value, used when deriving effect keys.
///
/// # Panics
/// Only if `serde_json` cannot serialize a `Value`, which is unreachable: object
/// keys are `String` by construction and `Value` cannot hold a non-finite float.
///
/// This deliberately panics rather than falling back to a placeholder. A
/// fallback would make two *different* values hash identically, so two distinct
/// effects would share a key — and replay would hand one of them the other's
/// recorded output. A loud abort is the only safe failure here.
#[must_use]
pub fn value_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

/// Write a value in canonical form: sorted keys, no insignificant whitespace.
///
/// Scalars are delegated to `serde_json`, whose escaping and number formatting
/// are already deterministic for a given value. Only *ordering* is taken over,
/// because ordering is the only part that a feature flag can change.
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_scalar(&Value::String((*key).to_owned()), out);
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => write_scalar(scalar, out),
    }
}

/// # Panics
///
/// Only if `serde_json` cannot serialize a scalar `Value`, which is
/// unreachable: `Value` cannot hold a non-finite float and object keys are
/// `String` by construction. See [`value_bytes`] on why this aborts rather than
/// substituting a placeholder.
fn write_scalar(value: &Value, out: &mut Vec<u8>) {
    serde_json::to_writer(&mut *out, value).expect("serde_json cannot fail on a scalar Value");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The load-bearing assumption of every hash in this crate.
    ///
    /// If this fails, `serde_json/preserve_order` has been enabled somewhere in
    /// the dependency graph and insertion order is leaking into our hashes.
    /// Effect keys would stop being stable across processes and replay would
    /// break in a way that looks like a runtime bug.
    #[test]
    fn sorted_keys_guard() {
        let a = json!({"z": 1, "a": 2, "m": 3});
        let b = json!({"a": 2, "m": 3, "z": 1});
        assert_eq!(
            value_bytes(&a),
            value_bytes(&b),
            "serde_json must sort object keys — is `preserve_order` enabled?"
        );
        assert_eq!(
            String::from_utf8(value_bytes(&a)).unwrap(),
            r#"{"a":2,"m":3,"z":1}"#
        );
    }

    #[test]
    fn nested_objects_are_also_sorted() {
        let a = json!({"outer": {"z": 1, "a": 2}});
        let b = json!({"outer": {"a": 2, "z": 1}});
        assert_eq!(value_bytes(&a), value_bytes(&b));
    }

    /// Arrays are ordered data, not sets — order must survive canonicalization.
    #[test]
    fn array_order_is_significant() {
        assert_ne!(value_bytes(&json!([1, 2])), value_bytes(&json!([2, 1])));
    }
}
