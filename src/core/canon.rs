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
//! This crate never enables that feature, and that is not enough on its own.
//! Cargo unifies features across the entire dependency graph, so **any**
//! dependency that wants `preserve_order` turns it on for this crate too — the
//! `cedar` feature does, because `cedar-policy` pulls it in. Under an ordered
//! `Map` every effect key in the system would depend on the order a caller
//! happened to build a JSON object, so two runs performing the same call would
//! derive different keys: replay divergence at best, and a second real payment
//! at worst.
//!
//! So the invariant is not left to a feature flag a stranger controls.
//! Canonical form is produced here, explicitly: object keys are sorted at
//! serialization time, so the output is identical whether `Map` is ordered or
//! not.
//!
//! # Keys sort by UTF-16 code unit, per RFC 8785
//!
//! Not by Rust's `str` ordering, which compares UTF-8 bytes. The two agree
//! throughout the Basic Multilingual Plane and disagree above it, so an
//! ASCII-only test suite passes under either and cannot tell them apart.
//!
//! It stopped being an internal detail once a signed Agent Card left the
//! process. That signature is over bytes canonicalized per RFC 8785 and checked
//! by verifiers nobody here writes, so UTF-8 ordering would have produced a card
//! that verifies against this crate and nothing else. `utf16_order` is the fix
//! and `keys_sort_by_utf16_code_unit_not_utf8_byte` is the vector that
//! distinguishes them.
//!
//! # Numbers format per RFC 8785's ECMAScript rules
//!
//! A double is written the way `Number::toString(10)` writes it — shortest
//! round-tripping digits, positional notation between `1e-6` and `1e21`,
//! exponential with an explicit sign outside it — because that is the one part
//! of JCS where `serde_json`'s own formatting disagrees (`1e30` where the
//! standard says `1e+30`, `100.0` where it says `100`), and a signed Agent
//! Card is verified by software nobody here writes. It is the one JCS rule
//! that would otherwise be tempting to skip — the cards this crate emits carry
//! no numbers — and skipping it would put the constraint *cards carry no
//! numbers* on every future field rather than on this function.
//!
//! **Integers stay exact, and that is a decision rather than a gap.** JCS
//! treats every number as an IEEE-754 double, under which two distinct `u64`s
//! above 2⁵³ collapse into one representation — and a canonicalizer that
//! collapses two different values into one byte string would give two
//! different effects one key, which is the fallback [`value_bytes`] exists to
//! refuse. Inside ±2⁵³ exact and double formatting agree, so nothing
//! interoperable is lost; outside it, I-JSON draws the same line and the one
//! externally-verified artifact refuses at signing — see `peers::card_sig`.

use serde::Serialize;
use serde_json::Value;

/// Which canonicalization rule this build implements.
///
/// **1** is RFC 8785: UTF-16 code-unit ordering of object keys (so a signed
/// Agent Card verifies against the standard rather than only against this
/// crate) and ECMAScript number formatting for doubles — `4.5` stays `4.5`
/// but `1e30` becomes `1e+30` and `100.0` becomes `100` — completing JCS for
/// everything a `Value` can hold except integers beyond ±2⁵³, which stay
/// exact for the reason the module docs give.
///
/// # Why a digest is not enough on its own
///
/// A rule change moves every derived digest — effect keys, manifest digests,
/// plan digests — and nothing on the record would say which rule produced
/// them. The journal chain is never at risk, because it hashes the bytes it
/// stored rather than re-canonicalizing them. The exposure is **replay**: a
/// run recorded under one rule and replayed by a build implementing another
/// recomputes different effect keys and is quarantined as *non-determinism* —
/// a healthy run, reported as the most serious conclusion this runtime
/// reaches, with nothing on the record to say the rule moved underneath it.
///
/// So the version is journaled at admission and replay compares it first. A run
/// written under another rule is **unverifiable by this build**, which is a
/// different sentence from *this run diverged* and the one the evidence
/// supports. That distinction is the whole point: an audit must report unknown
/// scope as prominently as corruption, and never as corruption.
pub const VERSION: u16 = 1;

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

/// Where two JSON values first differ, as an RFC 6901 pointer.
///
/// `None` when they are equal. The empty string — RFC 6901's pointer to the
/// whole document — when they differ at the root, which is the common case and
/// the one a bare "they differ" message hides worst: an object was expected and
/// `null` arrived.
///
/// # Why a comparison has a diagnostic in it
///
/// A refusal that says *these two values are not the same* leaves the reader
/// holding two documents and a diff to do by eye. The gate this serves is the
/// sink argument binding, where the two documents are the value policy checked
/// and the value the effect will send, and the difference between them is the
/// whole finding. Naming the path costs one walk of a value already in hand.
///
/// Deterministic: object members are visited in the same UTF-16 key order
/// [`value_bytes`] writes them, so the pointer this reports does not depend on
/// how a caller built the map. A member present on one side and absent on the
/// other is reported at that member's own path rather than at its parent's,
/// because "the object differs" is the answer the reader already had.
#[must_use]
pub fn first_difference(left: &Value, right: &Value) -> Option<String> {
    fn escape(token: &str) -> String {
        // RFC 6901: `~` is `~0` and `/` is `~1`, in that order.
        token.replace('~', "~0").replace('/', "~1")
    }

    fn walk(left: &Value, right: &Value, at: &str) -> Option<String> {
        match (left, right) {
            (Value::Object(l), Value::Object(r)) => {
                let mut keys: Vec<&String> = l.keys().chain(r.keys()).collect();
                keys.sort_by(|a, b| utf16_order(a, b));
                keys.dedup();
                for key in keys {
                    let path = format!("{at}/{}", escape(key));
                    match (l.get(key), r.get(key)) {
                        (Some(lv), Some(rv)) => {
                            if let Some(found) = walk(lv, rv, &path) {
                                return Some(found);
                            }
                        }
                        // Present on one side only: the member's own path is
                        // the finding, not its parent's.
                        _ => return Some(path),
                    }
                }
                None
            }
            (Value::Array(l), Value::Array(r)) => {
                for (index, (lv, rv)) in l.iter().zip(r.iter()).enumerate() {
                    if let Some(found) = walk(lv, rv, &format!("{at}/{index}")) {
                        return Some(found);
                    }
                }
                // Equal prefixes, different lengths: the first index only one
                // side has.
                (l.len() != r.len()).then(|| format!("{at}/{}", l.len().min(r.len())))
            }
            // Scalars, and any two values of different shape. Comparing the
            // canonical bytes rather than `==` keeps this agreeing with the
            // gate that called it: `1.0` and `1` are one value to a hash taken
            // over canonical form, and a pointer that disagreed with the
            // comparison would send a reader hunting a difference that is not
            // there.
            _ => (value_bytes(left) != value_bytes(right)).then(|| at.to_owned()),
        }
    }

    walk(left, right, "")
}

/// RFC 8785 key ordering: lexicographic by UTF-16 code unit.
///
/// Not `str`'s own ordering, which compares UTF-8 bytes. The two agree for
/// everything in the Basic Multilingual Plane and disagree above it, because
/// UTF-16 encodes those as surrogate pairs beginning `0xD800..=0xDBFF` — below
/// `0xE000..=0xFFFF`, which UTF-8 sorts *before* them.
fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
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
            keys.sort_unstable_by(|a, b| utf16_order(a, b));
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
    // Doubles take the RFC 8785 path; integers stay on `serde_json`'s exact
    // rendering, which agrees with the ECMAScript form for every integer a
    // double holds exactly (±2⁵³) and refuses to lose information above it.
    if let Value::Number(n) = value
        && n.is_f64()
    {
        es_number(n.as_f64().expect("is_f64 implies as_f64"), out);
        return;
    }
    serde_json::to_writer(&mut *out, value).expect("serde_json cannot fail on a scalar Value");
}

/// ECMAScript `Number::toString(10)`, which is what RFC 8785 §3.2.2.3 requires
/// for a JSON number.
///
/// Rust's `LowerExp` already selects the same digits ECMAScript does — the
/// shortest decimal that round-trips through the double — so only *placement*
/// is implemented here: positional notation while `-6 < n ≤ 21` (where `n` is
/// the position of the decimal point relative to the digits), exponential with
/// a mandatory sign outside it. The disagreements this exists for:
/// `serde_json` writes `1e30`, `100.0` and `1e-7` where the standard writes
/// `1e+30`, `100` and `1e-7` respectively — close enough to pass every test
/// that never leaves this crate, which is exactly how it survived.
///
/// Negative zero serializes as `0`, per the standard.
fn es_number(value: f64, out: &mut Vec<u8>) {
    if value == 0.0 {
        out.push(b'0');
        return;
    }
    if value.is_sign_negative() {
        out.push(b'-');
        es_number(-value, out);
        return;
    }
    let sci = format!("{value:e}");
    let (mantissa, exponent) = sci
        .split_once('e')
        .expect("LowerExp always writes an exponent");
    let digits: Vec<u8> = mantissa.bytes().filter(|b| *b != b'.').collect();
    let exponent: i32 = exponent.parse().expect("a LowerExp exponent is an integer");
    // value = digits × 10^(n − k): k significant digits, point after position n.
    let k = i32::try_from(digits.len()).expect("shortest f64 digits fit in i32");
    let n = exponent + 1;
    if n >= k && n <= 21 {
        // Whole number: every digit, then the zeros that place the magnitude.
        out.extend_from_slice(&digits);
        out.extend(std::iter::repeat_n(
            b'0',
            usize::try_from(n - k).expect("n >= k"),
        ));
    } else if n > 0 && n <= 21 {
        // The point falls inside the digits.
        let split = usize::try_from(n).expect("n > 0");
        out.extend_from_slice(&digits[..split]);
        out.push(b'.');
        out.extend_from_slice(&digits[split..]);
    } else if n > -6 && n <= 0 {
        // Small: leading zeros after the point.
        out.extend_from_slice(b"0.");
        out.extend(std::iter::repeat_n(
            b'0',
            usize::try_from(-n).expect("n <= 0"),
        ));
        out.extend_from_slice(&digits);
    } else {
        // Exponential, with the sign ECMAScript always writes.
        out.push(digits[0]);
        if digits.len() > 1 {
            out.push(b'.');
            out.extend_from_slice(&digits[1..]);
        }
        out.push(b'e');
        let e = n - 1;
        out.push(if e < 0 { b'-' } else { b'+' });
        out.extend_from_slice(e.unsigned_abs().to_string().as_bytes());
    }
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

    /// Keys sort by UTF-16 code unit, which is what RFC 8785 requires.
    ///
    /// The case that distinguishes the two orderings: a non-BMP character is one
    /// UTF-16 surrogate pair starting at `0xD800`, which is **below** a BMP
    /// character like `\u{ffff}` — while in UTF-8 bytes the same non-BMP
    /// character sorts *above* it. Sorting by `str`'s natural order passes every
    /// ASCII test and produces bytes a conforming verifier rejects.
    #[test]
    fn keys_sort_by_utf16_code_unit_not_utf8_byte() {
        let bmp = "\u{ffff}";
        let astral = "\u{10000}";
        // The two orderings genuinely disagree here, which is what makes this a
        // test rather than a restatement: in UTF-8 bytes `\u{ffff}` is EF BF BF
        // and `\u{10000}` is F0 90 80 80, so the BMP one sorts first. In UTF-16
        // the astral one is the surrogate pair D800 DC00, which sorts *below*
        // FFFF — the opposite answer.
        assert!(
            bmp < astral,
            "the fixture no longer distinguishes the orderings"
        );

        let bytes = value_bytes(&json!({ astral: 1, bmp: 2 }));
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.find(astral) < text.find(bmp),
            "keys came out in UTF-8 byte order, not UTF-16 — so a signed Agent \
             Card canonicalized here is rejected by any conforming verifier, and \
             every ASCII test still passes: {text}"
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

    /// RFC 8785's ECMAScript number vectors, from its own Appendix.
    ///
    /// These are cross-implementation golden vectors in the load-bearing
    /// sense: the expected strings are the standard's, not this crate's, so
    /// agreement is evidence about the bytes rather than the crate agreeing
    /// with itself.
    /// Every case here is one `serde_json` formats differently or nearly
    /// differently — which is why the partial implementation survived as long
    /// as it did: `4.5` agrees under both, and ASCII-adjacent tests never
    /// reach `1e+30`.
    // The over-precise literal is RFC 8785's own input spelling
    // (`333333333.33333329`), kept because a golden vector should carry the
    // standard's digits, not this crate's re-derivation of them; it denotes
    // the same double either way.
    #[expect(
        clippy::excessive_precision,
        reason = "the literal is RFC 8785's own vector, quoted verbatim"
    )]
    #[test]
    fn doubles_format_per_rfc_8785() {
        let vectors: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"), // ES String(-0) is "0", and JCS follows it
            (4.5, "4.5"),
            (0.002, "0.002"),
            (1e-6, "0.000001"),              // the last positional small number
            (1e-7, "1e-7"),                  // the first exponential one
            (1e20, "100000000000000000000"), // the last positional big number
            (1e21, "1e+21"),                 // the first exponential one — serde says 1e21
            (1e30, "1e+30"),
            (1e-27, "1e-27"),
            (9_007_199_254_740_992.0, "9007199254740992"), // 2^53, exact
            (333_333_333.333_333_29, "333333333.3333333"), // shortest round trip
            (9.999_999_999_999_997e22, "9.999999999999997e+22"),
            (5e-324, "5e-324"), // smallest subnormal
            (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"), // largest double
            (-4.5, "-4.5"),
            (-1e30, "-1e+30"),
        ];
        for (input, expected) in vectors {
            let mut out = Vec::new();
            es_number(*input, &mut out);
            assert_eq!(
                std::str::from_utf8(&out).unwrap(),
                *expected,
                "RFC 8785 formats {input:?} as {expected}"
            );
        }
    }

    /// The whole pipeline on a value that mixes every number shape.
    ///
    /// `serde_json` would write `{"big":1e30,"frac":4.5,"int":100,"neg":-0.0,…}`
    /// — three of the six differently — so this is the vector that fails if
    /// doubles ever fall back to the default writer.
    #[test]
    fn canonical_bytes_carry_rfc_8785_numbers() {
        let value = json!({
            "big": 1e30,
            "frac": 4.5,
            "int": 100,
            "neg": -0.0,
            "small": 1e-7,
            "whole": 100.0,
        });
        assert_eq!(
            String::from_utf8(value_bytes(&value)).unwrap(),
            r#"{"big":1e+30,"frac":4.5,"int":100,"neg":0,"small":1e-7,"whole":100}"#
        );
    }

    /// Integers beyond ±2⁵³ stay exact instead of collapsing into doubles.
    ///
    /// JCS would render both of these as `9007199254740994`? No — as the same
    /// double, which is the point: two *different* values must never share
    /// canonical bytes, because a shared byte string is a shared effect key and
    /// a shared key hands one effect the other's recorded output. The card
    /// signer refuses this range instead (`peers::card_sig`), which keeps the
    /// externally-verified artifact inside the range where exact and double
    /// agree.
    #[test]
    fn integers_beyond_double_precision_stay_distinct() {
        let a = json!(9_007_199_254_740_993_u64); // 2^53 + 1 — not a double
        let b = json!(9_007_199_254_740_992_u64); // 2^53 — the nearest double
        assert_ne!(value_bytes(&a), value_bytes(&b));
        assert_eq!(
            String::from_utf8(value_bytes(&a)).unwrap(),
            "9007199254740993"
        );
    }

    #[test]
    fn equal_values_have_no_first_difference() {
        let a = serde_json::json!({ "b": 1, "a": [1, 2, { "x": true }] });
        let b = serde_json::json!({ "a": [1, 2, { "x": true }], "b": 1 });
        assert_eq!(first_difference(&a, &b), None);
    }

    #[test]
    fn a_differing_leaf_is_named_by_its_path() {
        let a = serde_json::json!({ "to": "GB", "amount": 12000 });
        let b = serde_json::json!({ "to": "GB", "amount": 999 });
        assert_eq!(first_difference(&a, &b).as_deref(), Some("/amount"));
    }

    #[test]
    fn a_root_level_difference_is_the_empty_pointer() {
        let a = serde_json::json!(null);
        let b = serde_json::json!({ "to": "GB" });
        assert_eq!(first_difference(&a, &b).as_deref(), Some(""));
    }

    /// A member only one side has is reported at its own path.
    ///
    /// "The object differs" is the answer the reader already had.
    #[test]
    fn a_missing_member_is_named_rather_than_its_parent() {
        let a = serde_json::json!({ "outer": { "kept": 1 } });
        let b = serde_json::json!({ "outer": { "kept": 1, "added": 2 } });
        assert_eq!(first_difference(&a, &b).as_deref(), Some("/outer/added"));
    }

    #[test]
    fn a_shorter_array_is_named_at_the_first_index_it_lacks() {
        let a = serde_json::json!({ "xs": [1, 2] });
        let b = serde_json::json!({ "xs": [1, 2, 3] });
        assert_eq!(first_difference(&a, &b).as_deref(), Some("/xs/2"));
    }

    /// RFC 6901 escaping, so a key containing `/` cannot forge a path.
    #[test]
    fn pointer_tokens_are_escaped() {
        let a = serde_json::json!({ "a/b": 1, "c~d": 1 });
        let b = serde_json::json!({ "a/b": 2, "c~d": 1 });
        assert_eq!(first_difference(&a, &b).as_deref(), Some("/a~1b"));

        let c = serde_json::json!({ "a/b": 1, "c~d": 2 });
        assert_eq!(first_difference(&a, &c).as_deref(), Some("/c~0d"));
    }

    /// The pointer agrees with the comparison that asked for it.
    ///
    /// The gate compares canonical bytes, where `1.0` and `1` are one value; a
    /// pointer reported from `==` would send a reader hunting a difference the
    /// gate did not find.
    #[test]
    fn the_pointer_agrees_with_canonical_equality() {
        let a: Value = serde_json::from_str("{\"n\": 1.0}").unwrap();
        let b: Value = serde_json::from_str("{\"n\": 1}").unwrap();
        assert_eq!(value_bytes(&a), value_bytes(&b));
        assert_eq!(first_difference(&a, &b), None);
    }

    /// The reported difference does not depend on how a caller built the map.
    #[test]
    fn the_first_difference_is_reported_in_canonical_key_order() {
        let a = serde_json::json!({ "z": 1, "a": 1 });
        let b = serde_json::json!({ "z": 2, "a": 2 });
        assert_eq!(
            first_difference(&a, &b).as_deref(),
            Some("/a"),
            "keys are visited in the order canonical bytes write them"
        );
    }
}
