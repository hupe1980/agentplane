//! A witness that is somebody else, reached over HTTP.
//!
//! [`MemoryWitness`](super::MemoryWitness) proves the *logic* and is useless as
//! a trust anchor, because a witness you host yourself proves nothing about you.
//! This is the one that earns the guarantee: it speaks [C2SP `tlog-witness`] to
//! an operator who is not you.
//!
//! There is an existing network to point it at. `transparency-dev`'s omniwitness
//! and `ArmoredWitness` already cosign for Go's checksum database, Sigstore,
//! Sigsum and LVFS, and they take this protocol — so the split-view guarantee
//! becomes real without standing up any infrastructure, which is the difference
//! between a mechanism and a mechanism with a counterparty.
//!
//! # The status codes are the interesting part
//!
//! A witness answers with a small vocabulary, and two of its answers look alike
//! and mean opposite things:
//!
//! * **409** — "your `old` size is not where I am". The client is *stale*: it
//!   built a proof from a checkpoint the witness has already moved past. The
//!   body carries the witness's actual size, so the fix is to fetch a proof from
//!   there and try again. Nothing is wrong with the log.
//! * **422** — the proof does not verify against the root. That is a history
//!   that does not extend, which is the thing witnessing exists to detect.
//!
//! Reporting the first as the second would page somebody at three in the morning
//! for a retry, and a team that has been paged twice for a stale cursor stops
//! believing the third alert. So 409 gets its own error carrying the size, and
//! only 422 is a fork.
//!
//! [C2SP `tlog-witness`]: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md

use async_trait::async_trait;

use crate::core::Digest;

use super::Checkpoint;
use super::note::b64;
use super::note::{NoteSignature, SignedNote};
use super::witness::{
    Cosignature, Witness, WitnessError, cosignature_message, cosignature_payload,
};

/// A witness this deployment is willing to believe.
///
/// Carried as name **and** public key because the ignore-unknown-keys rule is
/// keyed on both: `signed-note` says a verifier MUST ignore a signature that
/// shares a name or an id with a known key but not both, and the id is derived
/// from the key. A name alone is whatever the answering server typed.
#[derive(Debug, Clone)]
pub struct TrustedWitness {
    name: String,
    public_key: [u8; 32],
    note_key_id: [u8; 4],
}

impl TrustedWitness {
    /// An Ed25519 witness key, as the operator registered it.
    #[must_use]
    pub fn ed25519(name: impl Into<String>, public_key: [u8; 32]) -> Self {
        let name = name.into();
        // `0x04` is `tlog-cosignature`'s algorithm byte for an Ed25519
        // **cosignature** — not `0x01`, which names a plain `signed-note`
        // signature. A witness only ever signs the timestamped cosignature
        // construction, so an id derived with `0x01` matches no line a
        // conforming witness sends, and every real cosignature is skipped as
        // an unknown key. The id is derived here rather than accepted from a
        // caller: an id supplied beside a key is a second copy of one fact,
        // and the copy that is wrong is the one nothing checks.
        let note_key_id = super::note::key_id(&name, 0x04, &public_key);
        Self {
            name,
            public_key,
            note_key_id,
        }
    }

    /// The four-byte `signed-note` key id this name and key hash to.
    #[must_use]
    pub const fn note_key_id(&self) -> [u8; 4] {
        self.note_key_id
    }

    /// The name the operator registered.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A remote witness reached over `tlog-witness`.
#[derive(Debug, Clone)]
pub struct HttpWitness {
    http: reqwest::Client,
    /// The submission prefix. `/add-checkpoint` is appended.
    prefix: String,
    /// The keys whose cosignatures this deployment accepts.
    ///
    /// Without them a client could only record that *something* answered 200,
    /// and the whole argument for witnessing — that an independent party
    /// observed this log — would rest on a status code.
    trusted: Vec<TrustedWitness>,
    /// The checkpoint's own signature, which the witness needs in order to
    /// recognise the log at all.
    ///
    /// Carried rather than derived: this crate signs through a trait so that a
    /// key may live in a KMS, so it never holds the public key needed to compute
    /// a note key id. Whoever configures the witness has both.
    log_signature: NoteSignature,
}

impl HttpWitness {
    /// Point at a witness.
    ///
    /// `prefix` is the submission prefix, without `/add-checkpoint`.
    ///
    /// # Errors
    ///
    /// If an HTTP client cannot be built, or if `trusted` is empty — a witness
    /// whose cosignature nothing can check is not a witness, and accepting one
    /// would make every quorum below it a count of HTTP status codes.
    pub fn new(
        prefix: impl Into<String>,
        log_signature: NoteSignature,
        trusted: Vec<TrustedWitness>,
    ) -> Result<Self, WitnessError> {
        if trusted.is_empty() {
            return Err(WitnessError::Unavailable(
                "a witness needs at least one trusted key: a cosignature nobody can \
                 verify is a 200 with a base64 string in it, and counting those toward \
                 a quorum is the failure witnessing exists to rule out"
                    .into(),
            ));
        }
        // The key name is structure on the wire, not a label: a space or a
        // newline in it produces a signature line that serialises fine and
        // reads back as a different name or an extra line. Caught here, where
        // whoever wrote the configuration is present to read the message,
        // rather than as an unparseable checkpoint an auditor is holding.
        SignedNote::validate_name(&log_signature.name)
            .map_err(|e| WitnessError::Unavailable(e.to_string()))?;
        // Bounded, like every other outbound call here. A witness is somebody
        // else's server and cosigning sits on the path that publishes a
        // checkpoint, so one that accepts the connection and never answers
        // holds that path open indefinitely — an availability failure in the
        // evidence layer, caused by a party whose whole purpose is to be
        // independent of this one.
        let http = reqwest::Client::builder()
            .timeout(Self::TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                WitnessError::Unavailable(format!("could not build an HTTP client: {e}"))
            })?;
        Ok(Self {
            http,
            prefix: prefix.into().trim_end_matches('/').to_owned(),
            trusted,
            log_signature,
        })
    }

    /// How long a cosignature request may take in total.
    ///
    /// Ten seconds: a witness signs a short checkpoint it already holds the
    /// state for, and one that cannot do so in that time is unavailable in the
    /// sense the caller already handles.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// The request body: old size, proof lines, blank line, signed checkpoint.
    fn body(&self, checkpoint: &Checkpoint, old_size: u64, proof: &[Digest]) -> String {
        let mut out = format!("old {old_size}\n");
        for hash in proof {
            out.push_str(&b64(hash.as_bytes()));
            out.push('\n');
        }
        out.push('\n');
        // The checkpoint travels *with its own signature*. A witness that cannot
        // attribute a checkpoint to a key it trusts answers 403 — it is
        // cosigning a specific log's claim, not an anonymous triple of numbers.
        let note = SignedNote::new(checkpoint.to_note())
            .and_then(|n| n.with_signature(self.log_signature.clone()))
            .unwrap_or_else(|e| {
                unreachable!("a checkpoint note is a valid body and `new` checked the name: {e}")
            });
        out.push_str(&note.to_wire());
        out
    }
}

#[async_trait]
impl Witness for HttpWitness {
    async fn cosign(
        &self,
        checkpoint: &Checkpoint,
        old_size: u64,
        proof: &[Digest],
    ) -> Result<Cosignature, WitnessError> {
        // `old_size` comes from the caller and is deliberately *not* derived
        // from the proof. A consistency proof is O(log n) hashes, so
        // `size - proof.len()` names some other size entirely — 93 rather than
        // 50 for a 50→100 proof — and every submission would be refused. Only
        // the holder of the log knows which checkpoint it proved from.
        let url = format!("{}/add-checkpoint", self.prefix);

        // The bytes actually submitted, kept because the cosignature is a
        // statement about *these* — verifying against a note rebuilt afterwards
        // would check a claim nobody made.
        let body = self.body(checkpoint, old_size, proof);
        let response = self
            .http
            .post(&url)
            .body(body.clone())
            .send()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: {e}")))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: reading the reply: {e}")))?;

        match status {
            200 => {
                // The signed note is the tail of the request: everything after
                // the blank line that ends the proof block.
                let submitted = body
                    .split_once("\n\n")
                    .map_or(body.as_str(), |(_, note)| note);
                verify_cosignature(&text, &checkpoint.origin, submitted, &self.trusted)
            }
            // Stale, not forked. The body is the witness's own size, so the
            // caller can build the right proof instead of guessing.
            //
            // A body that is not a size is *not* a size of zero, and the
            // difference is not cosmetic. Defaulting would turn an unreadable
            // reply into a definite numeric claim attributed to the witness —
            // which the caller acts on, by building a consistency proof from 0
            // and resubmitting. The witness refuses that, and the refusal is
            // classified as `Forked` or `Shrank`: the **integrity** bucket. A
            // witness answering 409 with a blank body, an HTML error page or a
            // stray newline would manufacture a fork alert, and this variant's
            // own documentation
            // says why that is the worst available outcome — a team paged twice
            // for a routine cursor mismatch stops believing the alert that
            // matters.
            //
            // A witness is untrusted (its metadata cannot widen authority or,
            // here, invent an integrity finding), so an unparseable size is
            // reported as what it is: the witness was unavailable in the only
            // sense that matters, which is routine and retried rather than
            // escalated.
            409 => match text.trim().parse::<u64>() {
                Ok(witness_size) => Err(WitnessError::Stale {
                    origin: checkpoint.origin.clone(),
                    witness_size,
                }),
                Err(_) => Err(WitnessError::Unavailable(format!(
                    "{url}: the witness answered 409 (stale) but its body is not a tree size, \
                     so there is nothing to build a proof from — refused rather than read as \
                     size 0, which would resubmit a proof the witness rejects as a fork"
                ))),
            },
            // The shrink, and the only status that carries it. C2SP specifies
            // 400 for *old size exceeds checkpoint size*: the witness is at N,
            // this log now offers a checkpoint smaller than N, and runs it
            // already cosigned are gone.
            //
            // There was no arm here, so this fell to the catch-all and became
            // an `Unavailable` — which the quorum classifies as **routine**,
            // beside a timeout. `Shrank` is documented as the single most
            // important thing a witness catches and the one an operator
            // auditing itself structurally cannot, and it was reachable only
            // from `MemoryWitness`: the in-process witness that is explicitly
            // useless as a trust anchor. So on the only witness that can be a
            // real one, a deleted run raised no alarm.
            //
            // `seen` is the size the witness told us it had reached and
            // `offered` is what this log now claims — the two numbers an
            // operator needs, and both already in hand without parsing a body
            // the spec does not require to carry them.
            //
            // And the guard on the arm is the same rule the 409 arm holds: a
            // witness is untrusted, so it cannot *invent* an integrity finding.
            // The spec's 400 is a statement about this request's own two
            // numbers — `old` exceeds the checkpoint size — and both are in
            // hand, so a 400 for a request where old ≤ size is a witness
            // answering off-spec (or mis-parsing the body), and reading that as
            // a shrink would page an operator for a counterparty's confusion.
            400 if old_size > checkpoint.size => Err(WitnessError::Shrank {
                origin: checkpoint.origin.clone(),
                seen: old_size,
                offered: checkpoint.size,
            }),
            400 => Err(WitnessError::Unavailable(format!(
                "{url}: the witness answered 400 (old size exceeds checkpoint size) for a \
                 request whose old size {old_size} does not exceed {} — an off-spec reply, \
                 refused rather than read as a shrink it does not evidence",
                checkpoint.size
            ))),
            422 => Err(WitnessError::Forked {
                origin: checkpoint.origin.clone(),
                seen: old_size,
                offered: checkpoint.size,
            }),
            403 => Err(WitnessError::Unavailable(format!(
                "{url}: the witness does not trust the key that signed this checkpoint — it \
                 cosigns for logs it recognises, so the log's key must be registered with the \
                 operator first"
            ))),
            404 => Err(WitnessError::Unavailable(format!(
                "{url}: the witness does not know the origin '{}'",
                checkpoint.origin
            ))),
            other => Err(WitnessError::Unavailable(format!(
                "{url}: unexpected status {other}: {}",
                text.trim()
            ))),
        }
    }
}

/// A 200 body is one or more note signature lines, and at least one of them
/// has to be a signature this deployment can check.
///
/// Every line is considered, not just the first: `tlog-witness` says a 200
/// carries one *or more*, and reading only the head would let the answering
/// server decide which cosignature counts by reordering its own reply.
///
/// A line is accepted only when its name **and** its four-byte key id match a
/// trusted key — `signed-note`'s rule, and it is a conjunction for a reason: a
/// server that may choose the name it sends can otherwise wear any identity
/// the operator registered. The signature is then verified as a
/// `cosignature/v1` statement about the note text that was submitted: the
/// payload's own timestamp goes into [`cosignature_message`] beside the note
/// body, and the signature must cover exactly that. The timestamp is the
/// witness's claim about when it observed the log, protected by the witness's
/// own signature and carried verbatim — this client does not judge it against
/// a local clock, because a submitter's clock is no authority on a party whose
/// whole purpose is independence.
fn verify_cosignature(
    body: &str,
    origin: &str,
    submitted_note: &str,
    trusted: &[TrustedWitness],
) -> Result<Cosignature, WitnessError> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    // Parsed by reusing the note parser rather than splitting by hand, so the
    // em dash and the payload layout are enforced in exactly one place.
    let framed = format!("witness\n\n{body}");
    let note = SignedNote::parse(&framed).map_err(|e| {
        WitnessError::Unavailable(format!("log '{origin}': unreadable cosignature: {e}"))
    })?;
    if note.signatures.is_empty() {
        // A 200 with no signature is the failure that looks like success: the
        // caller would record a cosignature nobody made.
        return Err(WitnessError::Unavailable(format!(
            "log '{origin}': the witness answered 200 with no signature, which is not a \
             cosignature however encouraging the status code is"
        )));
    }

    // What a cosignature covers is the note *body*, not the submitted wire
    // form: `signed-note`'s boundary rule keeps signature lines — the log's
    // own, and any other witness's — out of every signature's input, or two
    // witnesses could never sign one checkpoint without each invalidating the
    // other.
    let note_text = submitted_note.split_once("\n\n").map_or_else(
        || submitted_note.to_owned(),
        |(text, _)| format!("{text}\n"),
    );

    for line in &note.signatures {
        let Some(key) = trusted
            .iter()
            .find(|k| k.name == line.name && k.note_key_id == line.key_id)
        else {
            continue;
        };
        let Ok(verifying) = VerifyingKey::from_bytes(&key.public_key) else {
            continue;
        };
        let Some((timestamp, sig)) = cosignature_payload(&line.signature) else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(sig) else {
            continue;
        };
        let message = cosignature_message(timestamp, &note_text);
        if verifying.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(Cosignature {
                key_id: key.name.clone(),
                note_key_id: key.note_key_id,
                signature: line.signature.clone(),
            });
        }
    }

    // Reached when every line was from an unknown key, or was from a known one
    // and did not verify. Both are the same answer to the only question being
    // asked — *may I record that this witness saw this checkpoint* — and the
    // answer is no.
    Err(WitnessError::Unavailable(format!(
        "log '{origin}': the witness answered 200, and none of its {} signature line(s) \
         verified against a trusted key over the checkpoint that was submitted",
        note.signatures.len()
    )))
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    /// The checkpoint note from `tlog-cosignature`'s worked example, and the
    /// witness line published beside it.
    const EXAMPLE_NOTE: &str =
        "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
    const EXAMPLE_LINE_PAYLOAD: &str = "jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==";

    /// **The signed message and the payload layout, against the spec's own
    /// example — not against a round trip.** A round trip proves the verifier
    /// agrees with this crate's signer, which it would even if both were
    /// wrong; only published bytes break that tie.
    #[test]
    fn the_spec_worked_example_is_reproduced() {
        assert_eq!(
            cosignature_message(1_679_315_147, EXAMPLE_NOTE),
            "cosignature/v1\ntime 1679315147\n\
             example.com/behind-the-sofa\n20852163\n\
             CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n",
            "the message is two newline-terminated lines followed by the note \
             body, signature lines excluded"
        );

        let payload = super::super::note::unb64(EXAMPLE_LINE_PAYLOAD)
            .expect("the spec's example line is valid base64");
        // A note line's payload is `key_id ‖ timestamped_signature`.
        assert_eq!(payload.len(), 4 + 8 + 64);
        assert_eq!(
            payload[..4],
            [0x8d, 0x66, 0xcf, 0x3f],
            "the four-byte key id of the example witness"
        );
        let (timestamp, sig) =
            cosignature_payload(&payload[4..]).expect("eight bytes of timestamp, then a signature");
        assert_eq!(
            timestamp, 1_679_315_147,
            "the timestamp is big-endian and sits before the signature"
        );
        assert_eq!(sig.len(), 64);
    }

    /// A payload of the wrong length is not a cosignature — in particular, a
    /// bare 64-byte signature must not be read as one with no timestamp, which
    /// would verify it over a message nobody signed.
    #[test]
    fn a_payload_without_a_timestamp_is_not_a_cosignature() {
        assert!(cosignature_payload(&[0u8; 64]).is_none());
        assert!(cosignature_payload(&[0u8; 73]).is_none());
        assert!(cosignature_payload(&[]).is_none());
        assert!(cosignature_payload(&[0u8; 72]).is_some());
    }
}
