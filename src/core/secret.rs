//! A value that must not outlive its use.
//!
//! # Why `String` is not enough
//!
//! This crate already refuses to let a credential be serialized or printed —
//! [`PeerCredential`](crate::peers::PeerCredential) has no `Serialize` and a
//! redacting `Debug`, and a test scans a real journal for the secret. All of
//! that guards against a secret being *written somewhere*.
//!
//! None of it guards against the secret simply **staying in memory**. A `String`
//! dropped is a `String` freed, and freed heap keeps its bytes until something
//! else claims the page — where a core dump, a swap file, or a heap-reading
//! exploit finds them. Worse, `String` reallocates as it grows, so an unlucky
//! construction leaves *several* copies behind, none of which the eventual drop
//! can reach.
//!
//! [`Secret`] closes that: the bytes are wiped when it drops, and every copy
//! wipes its own.
//!
//! # What it cannot do
//!
//! It cannot reach a secret that existed before it. A key read from an
//! environment variable was already copied into the process by the loader; one
//! built with `format!` left an intermediate buffer. `Secret` bounds the
//! lifetime of *its* copy, which is the copy this crate is responsible for.

use std::fmt;

use zeroize::Zeroizing;

/// A secret that is wiped when it drops.
///
/// Deliberately missing: `Serialize`, `Deserialize`, and any `Display` that
/// reveals the value. The only way out is [`expose`](Self::expose), which is
/// greppable — an audit for "where does this secret go" is a search for one
/// method name.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The value, for the one call that needs to send it.
    ///
    /// Named so it reads as a deliberate act at the call site. `as_str` would
    /// look like an ordinary accessor, and this is not one.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Comparison is constant-time in the length of the shorter value.
///
/// A bearer token compared with `==` leaks its prefix through timing: an
/// attacker who can measure the comparison learns how many leading bytes they
/// guessed correctly. That is a real attack on any code path where an attacker
/// controls one side, and cheap enough to avoid that there is no reason to
/// reason about which paths those are.
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

/// Compare without short-circuiting on the first differing byte.
///
/// One implementation, because this is the whole of the defence: a secret or a
/// MAC compared with `==` leaks how many leading bytes the caller guessed,
/// which turns a forgery from infeasible into a byte-at-a-time search. A second
/// copy is a second thing to get right, and the one that is wrong is the one
/// nobody looked at.
///
/// Length is not secret — it is fixed by the scheme and visible through the
/// ciphertext of any transport — but the contents must not short-circuit.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl Eq for Secret {}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_does_not_print_itself() {
        let s = Secret::new("sk-live-abcdef");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert!(!format!("{s:#?}").contains("abcdef"));
    }

    #[test]
    fn equality_still_works() {
        assert_eq!(Secret::new("a"), Secret::new("a"));
        assert_ne!(Secret::new("a"), Secret::new("b"));
        assert_ne!(Secret::new("a"), Secret::new("aa"));
    }

    #[test]
    fn exposing_gives_the_value() {
        assert_eq!(Secret::new("k").expose(), "k");
    }
}
