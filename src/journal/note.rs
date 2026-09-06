//! The signed note: a checkpoint in the form a witness will accept.
//!
//! [`Checkpoint::to_note`] produces the *body* — origin, size, root. This is the
//! envelope around it, and it is the artifact that actually leaves the
//! operator's control: handed to an auditor, posted to a witness, pasted into a
//! ticket. A struct cannot do that; a text format can.
//!
//! The encoding is [C2SP `signed-note`], the same one Go's checksum database,
//! Sigstore and Sigsum use, so a checkpoint from this crate is checkable by
//! tools nobody here wrote and cosignable by witnesses nobody here operates.
//! Inventing a format would have cost every integrator and bought nothing.
//!
//! ```text
//! example.com/plane-a
//! 42
//! 4vTQFA0h8Nk5vX0hxJdKZ0Iy0Q1YqTWkxJ8mZ0hVxYc=
//!
//! — plane-a BAdEnwZ0aG…
//! ```
//!
//! Three details in that shape are load-bearing, and each is a place an
//! implementation drifts and still looks right:
//!
//! * the body ends in a newline, and the blank line after it is a **separator**
//!   rather than part of the body — a signature computed over the wrong one of
//!   those two strings verifies nowhere;
//! * the signature line begins with an **em dash** (U+2014), not a hyphen. They
//!   are indistinguishable in most terminals and diffs;
//! * the base64 payload is `key_id ‖ signature`, not the signature alone.
//!
//! [C2SP `signed-note`]: https://github.com/C2SP/C2SP/blob/main/signed-note.md
//! [`Checkpoint::to_note`]: crate::journal::Checkpoint::to_note

use crate::core::StoreError;

/// The character that opens a signature line. U+2014, not `-`.
const EM_DASH: char = '\u{2014}';

/// One signature over a note's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteSignature {
    /// The key's name, as it appears on the wire. No spaces: the line is
    /// space-delimited and a name containing one cannot be parsed back.
    pub name: String,
    /// The first four bytes of the base64 payload.
    ///
    /// Not derivable here. The spec computes it as
    /// `SHA-256(name ‖ 0x0A ‖ signature type ‖ public key)[..4]`, and
    /// [`Signer`](crate::core::Signer) deliberately never exposes a public key —
    /// this crate signs and verifies through traits so that a deployment may
    /// hold its key in a KMS. Whoever has the key material computes this; see
    /// [`key_id`].
    pub key_id: [u8; 4],
    /// The signature itself.
    pub signature: Vec<u8>,
}

/// A note and the signatures over it.
///
/// Signatures accumulate rather than replace: a checkpoint gains cosignatures as
/// witnesses observe it, and the whole value of witnessing is that several
/// independent parties signed *the same bytes*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedNote {
    /// The note body, ending in a newline.
    pub text: String,
    pub signatures: Vec<NoteSignature>,
}

/// The canonical key ID for a note-signing key.
///
/// `SHA-256(name ‖ 0x0A ‖ signature type ‖ public key)[..4]`. Separate from
/// [`NoteSignature`] because it needs the public key, which the signing traits
/// here do not carry — a KMS-backed signer may not be able to produce one
/// without a network call, and the note format does not need it at signing time.
#[must_use]
pub fn key_id(name: &str, signature_type: u8, public_key: &[u8]) -> [u8; 4] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0A]);
    h.update([signature_type]);
    h.update(public_key);
    let full = h.finalize();
    [full[0], full[1], full[2], full[3]]
}

impl SignedNote {
    /// A note with no signatures yet.
    ///
    /// # Errors
    ///
    /// If the text is not a valid note body — see [`SignedNote::validate_text`].
    pub fn new(text: impl Into<String>) -> Result<Self, StoreError> {
        let text = text.into();
        Self::validate_text(&text)?;
        Ok(Self {
            text,
            signatures: Vec::new(),
        })
    }

    /// What a note body must be, checked rather than assumed.
    ///
    /// The rules are the spec's, and each rejects something that would otherwise
    /// produce a note that serialises fine and verifies nowhere: a body without
    /// its trailing newline signs different bytes than the same body with one,
    /// and a control character makes the note unparseable to a verifier that
    /// enforces the rule while looking correct to one that does not.
    ///
    /// # Errors
    ///
    /// If the text is empty, does not end in a newline, or contains an ASCII
    /// control character other than newline.
    pub fn validate_text(text: &str) -> Result<(), StoreError> {
        let bad = |what: &str| StoreError::Backend(format!("signed note: {what}"));
        if text.is_empty() {
            return Err(bad("the body is empty"));
        }
        if !text.ends_with('\n') {
            return Err(bad(
                "the body does not end in a newline — the trailing newline is part of \
                 what gets signed, so a body without one signs different bytes than the \
                 verifier will check",
            ));
        }
        // A blank line inside the body would be read back as the separator, so
        // `parse` would truncate it and every signature would cover more bytes
        // than the verifier hashes. Refused at construction rather than
        // discovered at verification, because the note that cannot round-trip
        // looks perfectly well-formed until somebody checks a signature.
        if text.trim_end_matches('\n').contains("\n\n") {
            return Err(bad(
                "the body contains a blank line, which is the separator between a note \
                 and its signatures — such a note cannot be read back as the same body, \
                 so its signatures would cover bytes no verifier will hash",
            ));
        }
        if let Some(c) = text.chars().find(|c| c.is_control() && *c != '\n') {
            return Err(bad(&format!(
                "the body contains the control character {:#04x}, which the note format \
                 forbids",
                c as u32
            )));
        }
        Ok(())
    }

    /// Add a signature.
    ///
    /// Fallible, because a name is not free text. The line is
    /// `— <name> <base64>`, space-delimited and newline-terminated, so a name
    /// carrying a space, a newline or an em dash produces a line that
    /// serialises without complaint and reads back as something else — a
    /// different name, a truncated payload, or two signature lines where one
    /// was written.
    ///
    /// Checked here rather than in [`NoteSignature`] because this is the type
    /// that serialises; a `NoteSignature` nobody writes out harms nothing.
    ///
    /// # Errors
    ///
    /// If the name is empty, or contains whitespace, an em dash, or a control
    /// character.
    pub fn with_signature(mut self, signature: NoteSignature) -> Result<Self, StoreError> {
        Self::validate_name(&signature.name)?;
        self.signatures.push(signature);
        Ok(self)
    }

    /// What a key name may be, checked rather than described.
    ///
    /// # Errors
    ///
    /// If the name is empty, or contains whitespace, an em dash, or a control
    /// character.
    pub fn validate_name(name: &str) -> Result<(), StoreError> {
        let bad = |what: &str| StoreError::Backend(format!("signed note: a key name {what}"));
        if name.is_empty() {
            return Err(bad("is empty, so the signature line names nobody"));
        }
        if let Some(c) = name
            .chars()
            .find(|c| c.is_whitespace() || c.is_control() || *c == EM_DASH)
        {
            return Err(bad(&format!(
                "contains {c:?}, which the signature line uses as structure — the note \
                 would serialise and read back as a different name, a truncated payload, \
                 or an extra signature line nobody wrote"
            )));
        }
        Ok(())
    }

    /// The wire form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let mut out = self.text.clone();
        // The separator, and it is *not* part of the signed body. Getting this
        // boundary wrong is the single most common way a note implementation
        // produces signatures nobody can verify.
        out.push('\n');
        for s in &self.signatures {
            let mut payload = Vec::with_capacity(4 + s.signature.len());
            payload.extend_from_slice(&s.key_id);
            payload.extend_from_slice(&s.signature);
            out.push(EM_DASH);
            out.push(' ');
            out.push_str(&s.name);
            out.push(' ');
            out.push_str(&b64(&payload));
            out.push('\n');
        }
        out
    }

    /// Read one back.
    ///
    /// # Errors
    ///
    /// If the note is malformed. Deliberately strict throughout: a note that
    /// parses "close enough" is a note whose signatures cover something other
    /// than what a verifier will hash.
    pub fn parse(wire: &str) -> Result<Self, StoreError> {
        let bad = |what: &str| StoreError::Backend(format!("signed note: {what}"));
        // The body ends at the first blank line. Splitting on the *last* one
        // would swallow a body that legitimately contains a blank line.
        let (text, rest) = wire
            .split_once("\n\n")
            .ok_or_else(|| bad("no blank line separating the body from its signatures"))?;
        let text = format!("{text}\n");
        Self::validate_text(&text)?;

        let mut signatures = Vec::new();
        for line in rest.lines().filter(|l| !l.is_empty()) {
            let body = line.strip_prefix(EM_DASH).ok_or_else(|| {
                bad(
                    "a signature line does not begin with an em dash (U+2014). A hyphen \
                     looks identical in most terminals and is not the same byte",
                )
            })?;
            let body = body
                .strip_prefix(' ')
                .ok_or_else(|| bad("no space after the em dash"))?;
            let (name, payload) = body
                .split_once(' ')
                .ok_or_else(|| bad("a signature line has no base64 payload"))?;
            let raw = unb64(payload).ok_or_else(|| bad("the payload is not valid base64"))?;
            if raw.len() < 5 {
                return Err(bad(
                    "the payload is shorter than a key id plus a signature, so it cannot \
                     be either",
                ));
            }
            // The same rule the writer holds, so a note that parses can always
            // be written back out. `split_once(' ')` already rules out spaces;
            // an empty name and an em dash it does not.
            Self::validate_name(name)?;
            signatures.push(NoteSignature {
                name: name.to_owned(),
                key_id: [raw[0], raw[1], raw[2], raw[3]],
                signature: raw[4..].to_vec(),
            });
        }
        Ok(Self { text, signatures })
    }
}

pub(crate) use crate::core::b64::decode as unb64;
/// RFC 4648 §4, the encoding the note format specifies.
///
/// One dialect, one decoder, and a canonical one — see [`crate::core::b64`] for
/// why laxity is not the harmless kind where a signature covers the text.
pub(crate) use crate::core::b64::encode as b64;
