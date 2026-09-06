//! The two base64 dialects this crate speaks, and nothing else.
//!
//! Base64 has more variants than a call site should have to choose between —
//! two alphabets, padded and unpadded, canonical and lax — and a wire format
//! reads or writes exactly one of them. Naming the two this crate uses, once,
//! is what keeps a call site from picking a third by autocomplete.
//!
//! Both decoders are **canonical**: padding must be present and correct where
//! the dialect has it, and the bits below the last whole byte must be zero.
//! Laxity here is not the harmless kind. A signature covers the *text*, so two
//! spellings that decode to one value are two artifacts that both verify, name
//! the same thing, and are not the same bytes.

use base64::Engine as _;

/// RFC 4648 §4 — the standard alphabet, padded. Journal payloads, sealed
/// envelopes, media bytes, webhook signatures, Vault key material.
pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The inverse of [`encode`]. `None` on anything but a canonical encoding.
pub(crate) fn decode(text: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// RFC 4648 §5 — the URL-safe alphabet, unpadded. This is the JOSE dialect,
/// and it is what a JWS-signed Agent Card and an A2A task cursor are written
/// in.
///
/// Gated on the feature that carries a card, rather than allowed dead: the
/// compiler then answers *which dialects this build speaks*.
#[cfg(feature = "manifest")]
pub(crate) fn encode_url(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The inverse of [`encode_url`]. `None` on anything but a canonical encoding —
/// including a padded one, which the JOSE dialect does not have.
#[cfg(feature = "manifest")]
pub(crate) fn decode_url(text: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_standard_dialect_refuses_every_second_spelling() {
        assert_eq!(encode([0xFB, 0xFF]), "+/8=");
        assert_eq!(decode("+/8=").expect("canonical"), vec![0xFB, 0xFF]);
        // The three ways a lax decoder leaks spellings: an unpadded tail, a
        // `=` anywhere but the pad, and non-zero bits below the last whole
        // byte. `AB==` and `AC==` would otherwise be one byte under two names.
        assert!(decode("+/8").is_none(), "unpadded");
        assert!(decode("=+/8").is_none(), "padding in front");
        assert!(decode("AC==").is_none(), "non-zero trailing bits");
        assert!(
            decode("-_8=").is_none(),
            "the URL-safe alphabet is a dialect"
        );
    }

    #[cfg(feature = "manifest")]
    #[test]
    fn the_jose_dialect_is_url_safe_and_carries_no_padding() {
        assert_eq!(encode_url([0xFB, 0xFF]), "-_8");
        assert_eq!(decode_url("-_8").expect("canonical"), vec![0xFB, 0xFF]);
        assert!(decode_url("-_8=").is_none(), "JOSE has no padding");
        assert!(
            decode_url("+/8").is_none(),
            "the standard alphabet is a dialect"
        );
    }
}
