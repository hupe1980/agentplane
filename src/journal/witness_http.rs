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
use super::witness::{Cosignature, Witness, WitnessError};

/// A remote witness reached over `tlog-witness`.
#[derive(Debug, Clone)]
pub struct HttpWitness {
    http: reqwest::Client,
    /// The submission prefix. `/add-checkpoint` is appended.
    prefix: String,
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
    /// If an HTTP client cannot be built.
    pub fn new(
        prefix: impl Into<String>,
        log_signature: NoteSignature,
    ) -> Result<Self, WitnessError> {
        let http = reqwest::Client::builder().build().map_err(|e| {
            WitnessError::Unavailable(format!("could not build an HTTP client: {e}"))
        })?;
        Ok(Self {
            http,
            prefix: prefix.into().trim_end_matches('/').to_owned(),
            log_signature,
        })
    }

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
            .unwrap_or_else(|_| unreachable!("a checkpoint note is always a valid note body"))
            .with_signature(self.log_signature.clone());
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

        let response = self
            .http
            .post(&url)
            .body(self.body(checkpoint, old_size, proof))
            .send()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: {e}")))?;

        let status = response.status().as_u16();
        let text = response
            .text()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: reading the reply: {e}")))?;

        match status {
            200 => parse_cosignature(&text, &checkpoint.origin),
            // Stale, not forked. The body is the witness's own size, so the
            // caller can build the right proof instead of guessing.
            409 => Err(WitnessError::Stale {
                origin: checkpoint.origin.clone(),
                witness_size: text.trim().parse().unwrap_or_default(),
            }),
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

/// A 200 body is one or more note signature lines.
fn parse_cosignature(body: &str, origin: &str) -> Result<Cosignature, WitnessError> {
    // Parsed by reusing the note parser rather than splitting by hand, so the
    // em dash and the payload layout are enforced in exactly one place.
    let framed = format!("witness\n\n{body}");
    let note = SignedNote::parse(&framed).map_err(|e| {
        WitnessError::Unavailable(format!("log '{origin}': unreadable cosignature: {e}"))
    })?;
    let first = note.signatures.into_iter().next().ok_or_else(|| {
        // A 200 with no signature is the failure that looks like success: the
        // caller would record a cosignature nobody made.
        WitnessError::Unavailable(format!(
            "log '{origin}': the witness answered 200 with no signature, which is not a \
             cosignature however encouraging the status code is"
        ))
    })?;
    Ok(Cosignature {
        key_id: first.name,
        signature: first.signature,
    })
}
