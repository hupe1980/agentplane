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
//! # Two directions, and only one of them is evidence
//!
//! **Submission** gives the *plane* a cosignature it may choose to show. A
//! plane that stops submitting, or that shows one auditor a cosigned
//! checkpoint and another a different history, is unaffected by it.
//!
//! **Retrieval** — `tlog-witness`'s monitor mechanism, [`Witness::latest`] —
//! is the direction that binds the operator: an auditor asks the witness what
//! it holds for this log, and gets a checkpoint the plane cannot edit, signed
//! by a key the auditor chose to trust. A run deleted from the store is then a
//! checkpoint the witness still remembers. Both halves are here because
//! neither works alone: nothing is retrievable that was never submitted, and
//! a submission nobody reads back is a receipt in the filing cabinet of the
//! party being audited.
//!
//! # The status codes are the interesting part
//!
//! A witness answers with a small vocabulary, and three of its answers look
//! alike while meaning very different things:
//!
//! * **409** — "your `old` size is not where I am". The client is *stale*: it
//!   built a proof from a checkpoint the witness has already moved past. The
//!   body carries the witness's actual size, so the fix is to fetch a proof from
//!   there and try again. Nothing is wrong with the log.
//! * **422 at equal sizes** — one size, two roots. No mistake this client can
//!   make produces that, so it is the split view itself.
//! * **422 below equal size** — the consistency proof did not verify. Either
//!   this log built a bad proof or its history moved, and the answer does not
//!   say which; it gets its own refusal saying exactly that, rather than
//!   naming a cause the witness did not.
//!
//! Reporting the first as the second would page somebody at three in the morning
//! for a retry, and a team that has been paged twice for a stale cursor stops
//! believing the third alert. The two `422` causes this client can detect
//! *before sending* — an incoherent size-zero checkpoint, a proof supplied
//! from size zero — are refused locally, so a `422` that arrives is never
//! about a request nobody had to make.
//!
//! [C2SP `tlog-witness`]: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md

use async_trait::async_trait;

use crate::core::Digest;

use super::Checkpoint;
use super::note::b64;
use super::note::{NoteSignature, SignedNote};
use super::witness::{
    Cosignature, CosignedCheckpoint, Witness, WitnessError, cosignature_message,
    cosignature_payload,
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

/// This log's own note identity: how a witness recognises it, and what signs.
///
/// A witness `MUST verify the checkpoint signature against the public key(s)
/// it trusts for the checkpoint origin`, so a submission carries the
/// checkpoint **as a signed note**. That signature covers the note *body* —
/// origin, size, root — which changes with every checkpoint.
///
/// Which is why this holds a signer and not a signature. Holding a
/// [`NoteSignature`] would be holding one message's signature as though it
/// were configuration: correct for exactly the checkpoint it was made over,
/// and rejected with `403 Forbidden` by every conformant witness for every
/// checkpoint after it. Only the *identity* half — the name, and the key id
/// derived from the public key — is configuration.
#[derive(Debug, Clone)]
pub struct LogKey {
    name: String,
    note_key_id: [u8; 4],
    signer: std::sync::Arc<dyn crate::core::CheckpointSigner>,
}

impl LogKey {
    /// This log's Ed25519 note key, and the signer holding its private half.
    ///
    /// `0x01` is `signed-note`'s algorithm byte for a plain Ed25519 signature
    /// — the log signs the note itself, where a *witness* signs the
    /// timestamped `cosignature/v1` construction under `0x04`. Deriving the id
    /// here rather than accepting one beside the key keeps the two from being
    /// two facts, one of which nothing checks.
    ///
    /// # Errors
    ///
    /// If the name is not a valid `signed-note` key name — a space or a
    /// newline in it produces a signature line that serialises fine and reads
    /// back as a different name, or as an extra line.
    pub fn ed25519(
        name: impl Into<String>,
        public_key: [u8; 32],
        signer: std::sync::Arc<dyn crate::core::CheckpointSigner>,
    ) -> Result<Self, WitnessError> {
        let name = name.into();
        SignedNote::validate_name(&name).map_err(|e| WitnessError::Unavailable(e.to_string()))?;
        let note_key_id = super::note::key_id(&name, 0x01, &public_key);
        Ok(Self {
            name,
            note_key_id,
            signer,
        })
    }

    /// Sign `body` as a note line for this key.
    async fn sign(&self, body: &str) -> Result<NoteSignature, WitnessError> {
        let signature = self.signer.sign(body.as_bytes()).await?;
        Ok(NoteSignature {
            name: self.name.clone(),
            key_id: self.note_key_id,
            signature,
        })
    }
}

/// A remote witness reached over `tlog-witness`.
#[derive(Debug, Clone)]
pub struct HttpWitness {
    http: reqwest::Client,
    /// The submission prefix. `/add-checkpoint` is appended.
    prefix: String,
    /// The monitoring prefix, where a *reader* asks what this witness holds.
    ///
    /// Its own field because the specification defines two prefixes and says a
    /// witness `MAY` use one value for both — so a deployment where they
    /// differ is conformant, and a client with one field cannot reach it.
    /// Defaults to the submission prefix, which is the common case.
    monitoring: String,
    /// The keys whose cosignatures this deployment accepts.
    ///
    /// Without them a client could only record that *something* answered 200,
    /// and the whole argument for witnessing — that an independent party
    /// observed this log — would rest on a status code.
    trusted: Vec<TrustedWitness>,
    /// This log's own identity, which the witness needs in order to recognise
    /// the log at all — and which signs each checkpoint as it is submitted.
    log: LogKey,
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
        log: LogKey,
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
        // Bounded, like every other outbound call here. A witness is somebody
        // else's server and cosigning sits on the path that publishes a
        // checkpoint, so one that accepts the connection and never answers
        // holds that path open indefinitely — an availability failure in the
        // evidence layer, caused by a party whose whole purpose is to be
        // independent of this one.
        let http = crate::netguard::guarded_client(crate::netguard::Reach::Configured)
            .timeout(Self::TIMEOUT)
            .build()
            .map_err(|e| {
                WitnessError::Unavailable(format!("could not build an HTTP client: {e}"))
            })?;
        let prefix = prefix.into().trim_end_matches('/').to_owned();
        Ok(Self {
            http,
            monitoring: prefix.clone(),
            prefix,
            trusted,
            log,
        })
    }

    /// A reader for what this witness holds, at its monitoring prefix.
    ///
    /// The same trusted keys, so a deployment that submits and then reads back
    /// cannot end up holding one set of keys for the round trip and another
    /// for the check.
    ///
    /// # Errors
    ///
    /// If an HTTP client cannot be built.
    pub fn reader(&self) -> Result<WitnessReader, WitnessError> {
        WitnessReader::new(&self.monitoring, self.trusted.clone())
    }

    /// Read this witness at a different prefix from the one submissions go to.
    ///
    /// Only needed where the deployment splits them — a monitoring prefix
    /// delegated to a CDN, which the specification explicitly allows for.
    #[must_use]
    pub fn monitoring_at(mut self, prefix: impl Into<String>) -> Self {
        prefix
            .into()
            .trim_end_matches('/')
            .clone_into(&mut self.monitoring);
        self
    }

    /// How long a cosignature request may take in total.
    ///
    /// Ten seconds: a witness signs a short checkpoint it already holds the
    /// state for, and one that cannot do so in that time is unavailable in the
    /// sense the caller already handles.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// The request body: old size, proof lines, blank line, signed checkpoint.
    ///
    /// Fallible and awaited because the checkpoint is signed **here**, over
    /// this checkpoint's own note body. A signature made anywhere else is a
    /// signature over some other checkpoint.
    async fn body(
        &self,
        checkpoint: &Checkpoint,
        old_size: u64,
        proof: &[Digest],
    ) -> Result<String, WitnessError> {
        let mut out = format!("old {old_size}\n");
        for hash in proof {
            out.push_str(&b64(hash.as_bytes()));
            out.push('\n');
        }
        out.push('\n');
        // The checkpoint travels *with its own signature*. A witness that cannot
        // attribute a checkpoint to a key it trusts answers 403 — it is
        // cosigning a specific log's claim, not an anonymous triple of numbers.
        let body = checkpoint.to_note();
        let signature = self.log.sign(&body).await?;
        let note = SignedNote::new(body)
            .and_then(|n| n.with_signature(signature))
            .map_err(|e| {
                WitnessError::Unavailable(format!("the checkpoint note is not submittable: {e}"))
            })?;
        out.push_str(&note.to_wire());
        Ok(out)
    }

    /// The two `422` causes this client can see before it sends, and which of
    /// its own inputs each names.
    ///
    /// Both are this side's mistake, and both come back from a witness as the
    /// same status as a history that does not extend. Refusing them locally is
    /// what keeps that status meaningful: a `422` that reaches the integrity
    /// bucket should be about the log, not about a request nobody had to send.
    fn coherent(
        checkpoint: &Checkpoint,
        old_size: u64,
        proof: &[Digest],
    ) -> Result<(), WitnessError> {
        if !checkpoint.is_coherent() {
            return Err(WitnessError::Unavailable(format!(
                "log '{}': a checkpoint of size 0 must carry the empty tree's root, and \
                 this one does not — a witness answers 422 for it, which is the same \
                 status it uses for a history that does not extend",
                checkpoint.origin
            )));
        }
        if old_size == 0 && !proof.is_empty() {
            return Err(WitnessError::Unavailable(format!(
                "log '{}': a submission from size 0 must carry no consistency proof, \
                 because the empty tree is consistent with every tree — {} proof \
                 line(s) were built, and a witness answers 422 for them",
                checkpoint.origin,
                proof.len()
            )));
        }
        Ok(())
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

        // Refused here rather than learned from a 422, because a 422 is also
        // how a witness reports a history that does not extend.
        Self::coherent(checkpoint, old_size, proof)?;

        // The bytes actually submitted, kept because the cosignature is a
        // statement about *these* — verifying against a note rebuilt afterwards
        // would check a claim nobody made.
        let body = self.body(checkpoint, old_size, proof).await?;
        let response = self
            .http
            .post(&url)
            .body(body.clone())
            .send()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: {e}")))?;

        let status = response.status().as_u16();
        // A cosignature or a size line — small by construction, so the small
        // ceiling. A witness is an independent party and that is the point of
        // it; independent is not the same as trusted with this process's memory.
        let text = crate::netguard::intake::read_text(response, crate::netguard::intake::METADATA)
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
            // The specification gives `422` three causes, and only one of them
            // is evidence about the log. Two are this client's own inputs and
            // are refused above, before a request goes out. The third splits
            // by a number already in hand: at **equal** sizes a witness sends
            // 422 when the roots differ, and no proof-building mistake can
            // produce that — two roots for one size is the split view itself.
            // Below equal size, the answer is *the consistency proof did not
            // verify*, which is either a proof this log built wrongly or a
            // history that moved, and the client cannot tell which. Reporting
            // that as `Forked` names a cause the witness did not; reporting it
            // as routine would let a plane's evidence stop accumulating in
            // silence. It gets the variant that says exactly what is known.
            422 if old_size == checkpoint.size => Err(WitnessError::Forked {
                origin: checkpoint.origin.clone(),
                seen: old_size,
                offered: checkpoint.size,
            }),
            422 => Err(WitnessError::Inconsistent {
                origin: checkpoint.origin.clone(),
                old_size,
                offered: checkpoint.size,
            }),
            // Both halves of the spec's 403, because they send an operator to
            // different places and the status alone does not separate them: an
            // unregistered log is a conversation with the witness operator, a
            // signature that will not verify under a *registered* key is this
            // deployment's own signer or its own key registration.
            403 => Err(WitnessError::Unavailable(format!(
                "{url}: the witness would not attribute this checkpoint to a key it \
                 trusts for origin '{}' — either this log's key is not registered with \
                 that operator, or the signature the key '{}' produced does not verify \
                 under the public half they hold",
                checkpoint.origin, self.log.name,
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

/// One signature line, checked against the trusted set over `note_text`.
///
/// The single place a cosignature is accepted, shared by the submission reply
/// and by the monitor read — two callers, one rule, because a second copy of
/// this would be the one that skips a check.
///
/// `None` for every way of not being a cosignature this deployment can count:
/// an unknown key, an unusable payload, a signature that does not verify, and
/// a **zero timestamp**, which `tlog-witness` forbids in as many words — *the
/// cosignature MUST NOT omit the timestamp, i.e. the timestamp MUST NOT be
/// zero*. Accepting zero would count a cosignature that says nothing about
/// *when* the witness saw the log, which is half of what a cosignature is
/// for: the observation instant is what distinguishes a witness that is
/// watching from one that answered once, years ago, and stopped.
fn verify_line(
    line: &NoteSignature,
    note_text: &str,
    trusted: &[TrustedWitness],
) -> Option<Cosignature> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let key = trusted
        .iter()
        .find(|k| k.name == line.name && k.note_key_id == line.key_id)?;
    let verifying = VerifyingKey::from_bytes(&key.public_key).ok()?;
    let (timestamp, sig) = cosignature_payload(&line.signature)?;
    if timestamp == 0 {
        return None;
    }
    let signature = Signature::from_slice(sig).ok()?;
    let message = cosignature_message(timestamp, note_text);
    verifying.verify(message.as_bytes(), &signature).ok()?;
    Some(Cosignature {
        key_id: key.name.clone(),
        note_key_id: key.note_key_id,
        signature: line.signature.clone(),
    })
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
        if let Some(cosignature) = verify_line(line, &note_text, trusted) {
            return Ok(cosignature);
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

/// What a witness holds about a log, read by somebody who is not the log.
///
/// Its own type rather than a method on [`Witness`], because reading is a
/// different party's action: submitting needs the log's own signing key, and
/// this needs nothing but the URL and the witness keys the *reader* chose to
/// trust. An auditor is exactly the party who has the second and must not
/// have the first.
///
/// This is the direction that makes witnessing worth anything to somebody who
/// is not the operator. Submission leaves the cosignature with the party under
/// audit, who may show it or not; this obtains an anchor from a party the plane
/// does not control, so a run deleted from the store becomes a checkpoint the
/// witness still remembers rather than a history that has always looked like
/// this. `tlog-witness` calls it the monitor retrieval mechanism and states
/// the reason in as many words: a transparency system is only effective if
/// clients cannot be partitioned from monitors.
#[derive(Debug, Clone)]
pub struct WitnessReader {
    http: reqwest::Client,
    monitoring: String,
    trusted: Vec<TrustedWitness>,
}

impl WitnessReader {
    /// Read the witness at this monitoring prefix.
    ///
    /// # Errors
    ///
    /// If an HTTP client cannot be built, or if `trusted` is empty — a reader
    /// with no keys would return whatever the URL served, which is a
    /// checkpoint from an unauthenticated stranger presented as an anchor.
    pub fn new(
        prefix: impl Into<String>,
        trusted: Vec<TrustedWitness>,
    ) -> Result<Self, WitnessError> {
        if trusted.is_empty() {
            return Err(WitnessError::Unavailable(
                "a witness reader needs at least one trusted key: without one it can \
                 only report what a URL served, and an auditor would be holding a \
                 stranger's checkpoint as an independent anchor"
                    .into(),
            ));
        }
        let http = crate::netguard::guarded_client(crate::netguard::Reach::Configured)
            .timeout(HttpWitness::TIMEOUT)
            .build()
            .map_err(|e| {
                WitnessError::Unavailable(format!("could not build an HTTP client: {e}"))
            })?;
        Ok(Self {
            http,
            monitoring: prefix.into().trim_end_matches('/').to_owned(),
            trusted,
        })
    }

    /// The most recent checkpoint this witness holds for `origin`, cosigned.
    ///
    /// `Ok(None)` means this witness has never cosigned this log — an answer,
    /// and a different one from an outage. An auditor acts on it by asking why
    /// submission never happened, rather than by retrying.
    ///
    /// # Errors
    ///
    /// [`WitnessError::Unavailable`] when the witness cannot be reached,
    /// answers with a checkpoint for another log, or answers with a note no
    /// trusted key covers.
    pub async fn latest(&self, origin: &str) -> Result<Option<CosignedCheckpoint>, WitnessError> {
        use sha2::{Digest as _, Sha256};

        // `GET <monitoring prefix>/<origin hash>/checkpoint`, where the origin
        // hash is lowercase hex SHA-256 of the origin line. Hex of the *origin*
        // and not of the note: a reader who knows only which log they are
        // auditing can form this URL, which is what makes the endpoint usable
        // by somebody the operator did not brief.
        let hash = hex::encode(Sha256::digest(origin.as_bytes()));
        let url = format!("{}/{hash}/checkpoint", self.monitoring);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: {e}")))?;
        let status = response.status().as_u16();
        let text = crate::netguard::intake::read_text(response, crate::netguard::intake::METADATA)
            .await
            .map_err(|e| WitnessError::Unavailable(format!("{url}: reading the reply: {e}")))?;
        // An answer, not an outage: this witness has never cosigned this log.
        // Distinguished because an auditor acts on it — they go and ask why
        // submission never happened, rather than retrying a fetch.
        if status == 404 {
            return Ok(None);
        }
        if status != 200 {
            return Err(WitnessError::Unavailable(format!(
                "{url}: unexpected status {status}: {}",
                text.trim()
            )));
        }
        let note = SignedNote::parse(&text).map_err(|e| {
            WitnessError::Unavailable(format!("{url}: unreadable cosigned checkpoint: {e}"))
        })?;
        let checkpoint = Checkpoint::from_note(&note.text)
            .map_err(|e| WitnessError::Unavailable(format!("{url}: {e}")))?;
        // The witness serves whatever log the hash resolved to on its side; a
        // mismatch means the hash collided with its own bookkeeping or the
        // reply is for another log, and either way this is not the anchor that
        // was asked for.
        if checkpoint.origin != origin {
            return Err(WitnessError::Unavailable(format!(
                "{url}: the witness answered with a checkpoint for log \
                 '{}' rather than '{origin}'",
                checkpoint.origin
            )));
        }
        // Every line is checked, and only lines a trusted key covers are kept.
        // The reply also carries the *log's own* signature — the specification
        // says so — and that one is deliberately not counted: a checkpoint
        // signed by the party under audit is the claim, not the corroboration.
        let mut cosignatures = Vec::new();
        for line in &note.signatures {
            if let Some(cosignature) = verify_line(line, &note.text, &self.trusted) {
                cosignatures.push(cosignature);
            }
        }
        if cosignatures.is_empty() {
            return Err(WitnessError::Unavailable(format!(
                "{url}: the witness answered a checkpoint carrying {} signature line(s) \
                 and none of them verifies under a key this deployment trusts — a \
                 checkpoint nobody independent signed is the plane's own claim wearing \
                 a witness's URL",
                note.signatures.len()
            )));
        }
        Ok(Some(CosignedCheckpoint {
            checkpoint,
            cosignatures,
        }))
    }
}
