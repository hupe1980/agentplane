//! Getting the record out, in a form nothing here has to be present to read.
//!
//! # Why this is a deliverable and not a `serde` derive
//!
//! [`audit`](crate::audit) exists because the party under examination must not
//! also be the only party able to examine. That argument has a second half this
//! crate did not have: an auditor who can *check* the history but cannot
//! *obtain* it is still dependent on the operator, and a regulator asking a
//! financial entity to demonstrate an exit is asking about obtaining, not
//! checking. A store nobody can get data out of is a concentration risk with a
//! hash chain on top.
//!
//! So the export is a first-class operation with three properties, and each one
//! is a refusal of an easier design:
//!
//! * **Streaming, one JSON object per line.** A whole-journal `Vec` is a
//!   memory ceiling disguised as an API, and the export that matters most is
//!   the one taken from the largest store. JSON Lines also means an interrupted
//!   export is a *prefix* rather than a corrupt document — which is the failure
//!   an operator actually hits.
//! * **Self-describing.** The first line is a header naming the log, its
//!   checkpoint, and the canonicalization rule the digests were computed under.
//!   Without that, an export is bytes an auditor has to be told how to read,
//!   and being told is the dependency this module exists to remove.
//! * **It says what it did not export.** The trailer carries the counts and any
//!   run that could not be read. A truncated export shaped exactly like a
//!   complete one is the failure this project refuses everywhere else, and it
//!   is worst here: the missing run is the interesting one.
//!
//! # What it deliberately does not do
//!
//! It does not decrypt. With a key ring configured the journal commits to
//! ciphertext, and an export of plaintext would quietly undo
//! [erasure](crate::keyring) — destroying the key would no longer reach the
//! copy somebody exported last month. The export carries what the chain
//! committed to, which is also what verifies.
//!
//! It does not re-verify. [`audit`](crate::audit) answers *is this sound*, this
//! answers *here it is*, and folding them would produce an export that refuses
//! to emit the very history an auditor wants to examine *because* it is
//! suspect.
//!
//! It is scoped to one tenant, because a [`JournalStore`] handle is. There is
//! no argument here that could widen it, which is the same reason the rest of
//! the tenancy story is in keys rather than in filters.

use std::sync::Arc;

use crate::core::{RunId, StoreError};
use crate::journal::{Append, Checkpoint, JournalStore};

/// The export format's own version — see [`Header::version`].
///
/// One constant, because three readers consume it: the writer stamps it, the
/// verifier refuses what it cannot interpret, and the restore refuses what it
/// cannot faithfully replay. A version that only the writer knew about would be
/// a declaration that does nothing — a reader would parse a future format as
/// far as the lines happened to look familiar, and report findings about a
/// file it never understood.
pub const FORMAT_VERSION: u32 = 1;

/// The first line of an export: what this is and how to read it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Header {
    /// Always `"agentplane.export"`, so a reader can tell this file from any
    /// other line-delimited JSON without being told what it is.
    pub kind: &'static str,
    /// The export format's own version, which is **not** the crate's.
    ///
    /// A reader pins this. Tying it to the crate version would make every
    /// release look like a format change to anyone parsing defensively.
    pub version: u32,
    /// The log this came from, and its commitment at the moment of export.
    pub checkpoint: Checkpoint,
    /// Which canonicalization rule produced the digests in these records.
    ///
    /// Carried because it has already changed once. A digest is meaningless
    /// without the rule that computed it, and an export outlives the build that
    /// wrote it.
    pub canon: u16,
}

/// One journal record, as an export line.
///
/// Written out explicitly rather than by deriving `Serialize` on
/// [`Record`](crate::journal::Record), and the reason is that this is a
/// **durable format**. A derive makes the wire shape a side effect of the
/// struct's field list, so adding a private field or renaming a public one
/// silently changes what every downstream reader parses. Naming the four parts
/// here means the format changes when somebody edits *this*, which is the only
/// arrangement in which [`Header::version`] can mean anything.
///
/// The chain links travel with the body because an export without them is not
/// checkable: `prev_hash` and `hash` are what let a reader re-walk the chain
/// offline, which is the whole point of taking the record away.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ExportedRecord<'r> {
    pub seq: crate::core::Seq,
    pub body: &'r crate::journal::RecordBody,
    pub prev_hash: &'r crate::core::Digest,
    pub hash: &'r crate::core::Digest,
    /// Present only where the plane was configured to sign. `None` is an
    /// ordinary state and is emitted as such rather than omitted, so a reader
    /// can tell *unsigned* from *a field this export forgot*.
    pub attestation: Option<&'r crate::core::Attestation>,
}

impl<'r> From<&'r crate::journal::Record> for ExportedRecord<'r> {
    fn from(r: &'r crate::journal::Record) -> Self {
        Self {
            seq: r.seq(),
            body: &r.body,
            prev_hash: &r.prev_hash,
            hash: &r.hash,
            attestation: r.attestation.as_ref(),
        }
    }
}

/// A run's header line, emitted before its records.
///
/// It carries the one thing the record stream cannot: **where this run sits in
/// the Merkle log**. That order is store state — a monotonic index assigned at
/// seal time — and it appears in no record, so an export without it can be
/// walked but cannot be checked against the checkpoint in its own header. The
/// difference is between a transcript and evidence: a reader could confirm each
/// chain links to itself and still not know whether a run had been dropped from
/// the middle of the log.
///
/// `index` and `seal` are absent for a run that is still open. An unsealed run
/// is not in the log and has no leaf, which is a state rather than a gap.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunBlock {
    /// Always `"agentplane.export.run"`.
    pub kind: &'static str,
    pub run: RunId,
    /// Position in the Merkle log, in seal order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    /// The leaf value: this run's terminal chain hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<crate::core::Digest>,
}

/// The last line of an export: what it contains, and what it does not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Trailer {
    /// Always `"agentplane.export.end"`. Its **absence** is the signal that
    /// matters: an export cut short by a crash, a full disk or a killed pipe
    /// ends without one, so a reader can tell a prefix from a whole file
    /// without comparing counts against a source it does not have.
    pub kind: &'static str,
    /// How many runs were asked for.
    pub runs_requested: usize,
    /// How many were read in full.
    pub runs_exported: usize,
    /// How many records were written.
    pub records: usize,
    /// Runs that could not be read, and why.
    ///
    /// Named rather than counted. A count tells an auditor that something is
    /// missing and not which case to go and ask about, and the run that fails
    /// to read is not a random one.
    pub unreadable: Vec<Unreadable>,
}

/// A run the export could not read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Unreadable {
    pub run: RunId,
    pub reason: String,
}

/// Write every record of `runs` as JSON Lines, framed by a header and trailer.
///
/// The writer is `std::io::Write` rather than a path so this composes with a
/// file, a pipe, a socket or a buffer, and so the caller owns where the bytes
/// land — an export function that chose the destination would be one an
/// operator has to work around.
///
/// A run that cannot be read is recorded in the trailer and the export
/// continues. Aborting instead would make one damaged run withhold every
/// healthy one, which is the opposite of what an export is for; the trailer is
/// what keeps that from being silent.
///
/// # Errors
///
/// Only for a failure to *write*. A failure to *read* a run is data — it lands
/// in [`Trailer::unreadable`] — because the export still succeeded at the job
/// it was given, and an auditor needs the part that survived.
pub async fn to_jsonl<W: std::io::Write>(
    store: &Arc<dyn JournalStore>,
    runs: &[RunId],
    mut out: W,
) -> Result<Trailer, std::io::Error> {
    let checkpoint = store.checkpoint().await.map_err(|e| as_io(&e))?;
    // Held out of the header for the one comparison below: the header owns the
    // checkpoint from here on, and the log size is the half of it every run
    // block is checked against.
    let log_size = checkpoint.size;
    // Read from the build, never from the caller. The rule that computed the
    // digests is a fact about the store's own writes, and a parameter here was
    // a header any embedder could make lie — every caller passed
    // `canon::VERSION` verbatim, which is what a fact looks like when it is
    // asked for as an argument.
    let header = Header {
        kind: "agentplane.export",
        version: FORMAT_VERSION,
        checkpoint,
        canon: crate::core::canon::VERSION,
    };
    writeln!(out, "{}", to_line(&header)?)?;

    let mut records = 0usize;
    let mut exported = 0usize;
    let mut unreadable = Vec::new();

    for &run in runs {
        // Asked before the records so the block heads them, and asked at all
        // because the log position is the half of the evidence the records do
        // not carry. A store that cannot answer leaves the run unsealed rather
        // than failing the export: the position is missing, and the verifier
        // says so, which is better than no export.
        let placed = store.inclusion_proof(run).await.ok().flatten();
        // A run sealed *after* the header's checkpoint was taken is not in that
        // checkpoint. Stamping its position anyway would make the export
        // disagree with its own first line: the verifier rebuilds a tree one
        // leaf larger than the root it compares against, and reports tampering
        // where there was only time. Such a run is exported as still open —
        // true relative to the moment this export describes — and the next
        // export carries it sealed.
        let placed = placed.filter(|i| i.index < log_size);
        writeln!(
            out,
            "{}",
            to_line(&RunBlock {
                kind: "agentplane.export.run",
                run,
                index: placed.as_ref().map(|i| i.index),
                seal: placed.as_ref().map(|i| i.seal),
            })?
        )?;

        match store.read(run, 1).await {
            Ok(found) => {
                for record in &found {
                    writeln!(out, "{}", to_line(&ExportedRecord::from(record))?)?;
                    records += 1;
                }
                exported += 1;
            }
            Err(e) => unreadable.push(Unreadable {
                run,
                reason: e.to_string(),
            }),
        }
    }

    let trailer = Trailer {
        kind: "agentplane.export.end",
        runs_requested: runs.len(),
        runs_exported: exported,
        records,
        unreadable,
    };
    writeln!(out, "{}", to_line(&trailer)?)?;
    out.flush()?;
    Ok(trailer)
}

/// One value as one line, refusing to write a line that is not valid JSON.
fn to_line<T: serde::Serialize>(value: &T) -> Result<String, std::io::Error> {
    serde_json::to_string(value).map_err(|e| std::io::Error::other(e.to_string()))
}

fn as_io(e: &StoreError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

// ── Reading one back ────────────────────────────────────────────────────────

/// What a verification pass concluded, and what it could not look at.
///
/// The same shape as [`AuditReport`](crate::audit::AuditReport) and for the same
/// reason: a pass that reports only failures tells you about its coverage by
/// omission. An export verified without a public key has not established
/// authorship, and saying so is the difference between *this is sound* and
/// *nothing I checked was wrong*.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifyReport {
    /// The checkpoint the export claims to be a copy of.
    pub checkpoint: Checkpoint,
    /// Runs whose chain recomputed exactly.
    pub sound: Vec<RunId>,
    /// What went wrong, in the order found.
    pub findings: Vec<String>,
    /// Checks that were not performed, and why.
    pub not_checked: Vec<String>,
    /// How many records were read.
    pub records: usize,
    /// Whether the file ended with its trailer.
    ///
    /// A truncated export is otherwise a valid prefix: every line parses, every
    /// chain link joins, and the only thing wrong is what is missing.
    pub complete: bool,
}

impl VerifyReport {
    /// Whether every check that ran, passed. See [`Self::not_checked`].
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.findings.is_empty() && self.complete
    }
}

/// Recompute an export from its own bytes, and check it against its checkpoint.
///
/// **This is the restore drill, and it is the half that makes a restore worth
/// having.** Putting records back into a store proves that bytes moved; it does
/// not prove they are the bytes that were taken, in the order they were taken,
/// with nothing dropped from the middle. That is what this establishes, and it
/// establishes it without the runtime that wrote the data and without the store
/// it came from — an export and this function are the whole dependency.
///
/// Four properties, each checkable only because the export was designed to
/// carry the evidence for it:
///
/// * **Every record's hash is recomputed**, from its body and its predecessor's
///   hash, using the canonicalization rule the header names. A record whose
///   stored hash disagrees was edited after sealing. This is not a comparison of
///   the file against itself: `Record::seal` is the same function the store
///   sealed through, so agreement means the bytes are the ones that were
///   written.
/// * **Chains join, and sequences are contiguous.** A removed record breaks a
///   link; a removed *tail* does not, which is why the sequence is checked too.
/// * **The Merkle root is rebuilt** from the per-run log positions and compared
///   with the header's checkpoint. This is the one that catches a whole run
///   dropped from the middle of the export — the per-run chains all still verify,
///   and only the tree notices.
/// * **The file is framed.** A missing trailer means the export was cut short,
///   and every line before the cut is still perfectly valid.
///
/// Signatures are checked when a verifier is supplied and reported as unchecked
/// when not.
///
/// # Errors
///
/// Only for a failure to read the input. A malformed or dishonest export is a
/// *finding*, not an error — the whole point is to produce a report about it.
pub fn verify<R: std::io::BufRead>(
    input: R,
    verifier: Option<&dyn crate::core::Verifier>,
) -> Result<VerifyReport, std::io::Error> {
    use crate::core::{Digest, merkle};
    use serde_json::Value;

    let mut report = VerifyReport {
        checkpoint: Checkpoint {
            origin: String::new(),
            size: 0,
            root: Digest::ZERO,
        },
        sound: Vec::new(),
        findings: Vec::new(),
        not_checked: Vec::new(),
        records: 0,
        complete: false,
    };
    if verifier.is_none() {
        report.not_checked.push(
            "signatures — no public key was supplied, so this pass cannot say who wrote \
             anything"
                .to_owned(),
        );
    }

    let mut header_seen = false;
    // (index, leaf) for every sealed run, so the tree can be rebuilt in log
    // order rather than in the order the export happened to walk.
    let mut leaves: Vec<(u64, Digest)> = Vec::new();
    let mut pass: Option<RunPass> = None;

    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            report
                .findings
                .push("a line is not valid JSON, so the export is unreadable from there on".into());
            break;
        };
        match value.get("kind").and_then(Value::as_str) {
            Some("agentplane.export") => {
                header_seen = true;
                read_header(&value, &mut report);
            }
            Some("agentplane.export.run") => {
                finish_run(&mut report, pass.take(), verifier);
                pass = value
                    .get("run")
                    .and_then(Value::as_str)
                    .and_then(|s| RunId::parse(s).ok())
                    .map(|run| RunPass {
                        run,
                        declared_seal: value
                            .get("seal")
                            .and_then(|s| serde_json::from_value::<Digest>(s.clone()).ok()),
                        prev: Digest::ZERO,
                        last_seq: 0,
                        resealed: Vec::new(),
                        clean: true,
                    });
                if let Some(pass) = &pass
                    && let (Some(index), Some(seal)) = (
                        value.get("index").and_then(Value::as_u64),
                        pass.declared_seal,
                    )
                {
                    leaves.push((index, merkle::leaf_hash(&seal)));
                }
            }
            Some("agentplane.export.end") => report.complete = true,
            _ => {
                report.records += 1;
                let Some(pass) = pass.as_mut() else {
                    report.findings.push(
                        "a record appears before any run block, so nothing says which run it \
                         belongs to"
                            .into(),
                    );
                    continue;
                };
                read_record(&value, pass, &mut report);
            }
        }
    }
    finish_run(&mut report, pass, verifier);

    settle(&mut report, header_seen, leaves);
    Ok(report)
}

/// The verifier's working state for the run block it is inside.
///
/// One struct rather than five parallel locals, because they reset together —
/// a new run block replaces all of them at once, and a field that survived the
/// boundary would carry one run's evidence into another's verdict.
struct RunPass {
    run: RunId,
    declared_seal: Option<crate::core::Digest>,
    prev: crate::core::Digest,
    last_seq: u64,
    resealed: Vec<crate::journal::Record>,
    /// Whether every record in this block checked out so far.
    ///
    /// [`VerifyReport::sound`] promises *chain recomputed exactly*, and the
    /// leaf comparison alone cannot hold that promise for an **open** run —
    /// there is no leaf, so without this flag an edited record in an unsealed
    /// run produced a finding *and* left the run listed sound.
    clean: bool,
}

/// The checks that can only be made once the whole file has been read.
///
/// Separated because they answer a different question from the per-record pass:
/// that one asks *is each record what it says it is*, and every one of these
/// asks *is anything missing* — which no single line can reveal.
fn settle(
    report: &mut VerifyReport,
    header_seen: bool,
    mut leaves: Vec<(u64, crate::core::Digest)>,
) {
    use crate::core::merkle;

    if !header_seen {
        report
            .findings
            .push("the export has no header, so nothing says which log it came from".into());
    }

    // The tree, rebuilt in log order. This is what notices a whole run dropped
    // from the middle: every per-run chain above still verified, because a chain
    // links records within a run and knows nothing about its neighbours.
    leaves.sort_by_key(|(index, _)| *index);
    let size = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
    if size == report.checkpoint.size {
        // The positions are part of the claim, not bookkeeping: a checkpoint of
        // size N commits to leaves 0..N, so a duplicated or out-of-range
        // position is a relabelled log. Named here rather than left to surface
        // as a root mismatch, because "the root differs" tells an auditor that
        // something is wrong and not that two runs claim one place in history —
        // and a tree built over duplicated positions would compare garbage
        // against the root and report the wrong defect.
        let contiguous = leaves
            .iter()
            .enumerate()
            .all(|(at, (index, _))| u64::try_from(at) == Ok(*index));
        if contiguous {
            let rebuilt =
                merkle::root(&leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>());
            if rebuilt != report.checkpoint.root {
                report.findings.push(
                    "the Merkle root rebuilt from this export does not match the checkpoint it \
                     claims to be a copy of"
                        .to_owned(),
                );
            }
        } else {
            report.findings.push(format!(
                "the run blocks' log positions are not the contiguous 0..{} the checkpoint \
                 commits to — a position is duplicated or missing, so this file describes a \
                 different log than the one it names",
                report.checkpoint.size
            ));
        }
    } else {
        report.findings.push(format!(
            "the export carries {size} sealed run(s) and its checkpoint commits to {} — the \
             difference is runs that were in the log and are not in this file",
            report.checkpoint.size
        ));
    }

    if !report.complete {
        report.findings.push(
            "the export has no trailer, so it was cut short — every line in it is still valid, \
             which is why the frame is the signal"
                .to_owned(),
        );
    }
}

/// Read the header line: which format, which log, at what size, under which rule.
fn read_header(value: &serde_json::Value, report: &mut VerifyReport) {
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(FORMAT_VERSION)) {
        report.findings.push(format!(
            "the export claims format version {version:?} and this build reads {FORMAT_VERSION} \
             — the findings below describe the lines this build could interpret, which may not \
             be all of them"
        ));
    }
    let canon = value.get("canon").and_then(serde_json::Value::as_u64);
    if canon != Some(u64::from(crate::core::canon::VERSION)) {
        report.findings.push(format!(
            "the export was written under canonicalization rule {canon:?} and this build \
             implements {} — every digest in it is unverifiable here, which is a different \
             statement from wrong",
            crate::core::canon::VERSION
        ));
    }
    match value
        .get("checkpoint")
        .and_then(|c| serde_json::from_value::<Checkpoint>(c.clone()).ok())
    {
        Some(c) => report.checkpoint = c,
        None => report
            .findings
            .push("the header carries no readable checkpoint".to_owned()),
    }
}

/// Re-seal one record and hold it to the hash it carries.
///
/// The re-seal is the whole check. Comparing the file's `prev_hash` against the
/// previous line's `hash` would only prove the file agrees with itself, which an
/// editor who recomputed the chain also achieves; putting the body back through
/// the function the store sealed with is what makes agreement evidence about the
/// bytes.
fn read_record(value: &serde_json::Value, pass: &mut RunPass, report: &mut VerifyReport) {
    let current = pass.run;
    let (Some(body), Some(claimed)) = (
        value
            .get("body")
            .and_then(|b| serde_json::from_value::<crate::journal::RecordBody>(b.clone()).ok()),
        value
            .get("hash")
            .and_then(|h| serde_json::from_value::<crate::core::Digest>(h.clone()).ok()),
    ) else {
        report
            .findings
            .push(format!("run {current}: a record line is malformed"));
        pass.clean = false;
        return;
    };
    // The record's own body names its run, and it must be the run the block
    // claims. Without this comparison an export could relabel a whole history —
    // run B's records and B's leaf filed under A's id — and every other check
    // would pass, because chain, seal and Merkle all verify B's bytes; only the
    // *label* lied, and the label is what the reader looks a run up by.
    if body.run != current {
        report.findings.push(format!(
            "run {current}: a record in this block belongs to run {} — the block was relabelled, \
             or spliced from another history",
            body.run
        ));
        pass.clean = false;
    }
    // A removed record breaks a link; a removed *tail* does not, which is why
    // the sequence is checked as well as the chain.
    if body.seq != pass.last_seq + 1 {
        report.findings.push(format!(
            "run {current}: seq {} follows {}, so a record is missing from the middle — \
             every chain link either side of the gap still joins",
            body.seq, pass.last_seq
        ));
        pass.clean = false;
    }
    pass.last_seq = body.seq;

    match crate::journal::Record::seal(body, pass.prev) {
        Ok(mut record) => {
            if record.hash != claimed {
                report.findings.push(format!(
                    "run {current}: record {} does not recompute to the hash it carries \
                     — it was edited after it was sealed",
                    pass.last_seq
                ));
                pass.clean = false;
            }
            pass.prev = record.hash;
            record.attestation = value
                .get("attestation")
                .and_then(|a| {
                    serde_json::from_value::<Option<crate::core::Attestation>>(a.clone()).ok()
                })
                .flatten();
            pass.resealed.push(record);
        }
        Err(e) => {
            report.findings.push(format!(
                "run {current}: record {} cannot be sealed: {e}",
                pass.last_seq
            ));
            pass.clean = false;
        }
    }
}

/// Close out a run block: its terminal hash must be the leaf the log recorded,
/// and its signatures must verify if a key was supplied.
fn finish_run(
    report: &mut VerifyReport,
    pass: Option<RunPass>,
    verifier: Option<&dyn crate::core::Verifier>,
) {
    let Some(pass) = pass else {
        return;
    };
    let run = pass.run;
    let mut ok = pass.clean;

    // The one cross-check between the two halves of the export. Without it a
    // file could carry a healthy chain and a leaf belonging to some other
    // history, and each half would verify on its own.
    if let Some(seal) = pass.declared_seal
        && seal != pass.prev
    {
        report.findings.push(format!(
            "run {run}: the log's leaf is not this run's terminal hash, so the chain in this \
             file is not the chain the checkpoint committed to"
        ));
        ok = false;
    }

    // One implementation of *is this signed history sound*, and it is the
    // crate's own. `require_signature` is true because this is the auditor's
    // posture: an unsigned record inside a signed history is the one an
    // attacker who cannot sign would add.
    if let Some(v) = verifier
        && let Err(e) = crate::journal::Record::verify_attested(
            &pass.resealed,
            crate::core::Digest::ZERO,
            v,
            true,
        )
    {
        report.findings.push(format!("run {run}: {e}"));
        ok = false;
    }

    if ok {
        report.sound.push(run);
    }
}

// ── Putting one back ────────────────────────────────────────────────────────

/// What a restore did, and what it could not carry across.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RestoreReport {
    /// The checkpoint the export claimed.
    pub expected: Checkpoint,
    /// The checkpoint the rebuilt store now reports.
    ///
    /// **These matching is the whole result.** Equal roots at equal size means
    /// every record, in every run, in the order the log recorded them, rebuilt
    /// to the same commitment — which is a far stronger statement than "the
    /// rows loaded".
    pub rebuilt: Checkpoint,
    pub runs: usize,
    pub records: usize,
    /// What did not survive, named rather than counted.
    pub not_carried: Vec<String>,
}

impl RestoreReport {
    /// Whether the rebuilt store commits to exactly the history the export did.
    #[must_use]
    pub fn is_faithful(&self) -> bool {
        self.expected == self.rebuilt
    }
}

/// Rebuild a store from an export, then prove it by its own checkpoint.
///
/// # Why this goes through `append` rather than writing rows
///
/// The obvious implementation inserts records verbatim and rebuilds each index
/// beside them. It is also the one that fails quietly: `append` maintains six
/// derived structures — the case index, the exactly-once index, the outcome
/// index and its ordering counter, and both halves of the activity index — and
/// a restore that reconstructed five of them correctly would produce a store
/// that reads perfectly until somebody queries the sixth.
///
/// So this replays the ordinary write path, and every constraint the store
/// enforces is enforced here too. Three properties make that reproduce the
/// original bytes rather than merely similar ones:
///
/// * **`seq` is re-derived and lands identically**, because a run restored into
///   an empty store starts from the same genesis and receives the same records
///   in the same order.
/// * **`epoch` is carried, not re-derived.** It is a field of the hashed body,
///   so a run that ever changed hands — the ones a disaster is most likely to
///   involve — would hash differently under a single fresh lease. `append`
///   takes the epoch as a parameter and fences only when a lease row *exists*,
///   so restoring into a store with no leases writes each record under its own
///   original epoch. Records are grouped into runs of equal epoch for exactly
///   this reason.
/// * **Runs are sealed in log-index order**, so the Merkle log is rebuilt in the
///   order the original recorded, which is what makes the roots comparable at
///   all.
///
/// # What does not survive
///
/// **Signatures.** `append` attests with the *restoring* store's signer, so a
/// history signed by a key this store does not hold comes back unsigned. Hashes
/// and the Merkle root are unaffected — a signature is taken over the chain
/// hash and stored beside it — so the restore is still provably faithful, but
/// authorship is gone. It is named in `not_carried` rather than left for
/// somebody to notice, and it is why an operator restoring their own log should
/// configure the same signer.
///
/// **Activity timestamps.** The discovery index is rebuilt at restore time, so
/// `recent_runs` orders by when history was restored rather than when it
/// happened. That index is documented as ordering and cursor stability only,
/// and nothing derives a decision from it.
///
/// # Errors
///
/// If the export cannot be read, or if the store refuses a write. A store that
/// already holds any of these runs will refuse: this rebuilds a history, it does
/// not merge one.
pub async fn from_jsonl<R: std::io::BufRead>(
    store: &Arc<dyn JournalStore>,
    input: R,
) -> Result<RestoreReport, StoreError> {
    let parsed = parse(input).map_err(|e| StoreError::Backend(e.to_string()))?;

    // The one check `parse`'s no-checking rule does not cover, because it is
    // not a soundness question: a format this build does not read cannot be
    // *parsed* completely, and `parse` skips what it does not recognise — so
    // proceeding would restore whatever subset happened to look familiar and
    // report it as the whole file.
    if parsed.version != Some(u64::from(FORMAT_VERSION)) {
        return Err(StoreError::Backend(format!(
            "the export claims format version {:?} and this build reads {FORMAT_VERSION} — \
             restoring a format this build cannot fully parse would rebuild an unknowable \
             subset and call it a history",
            parsed.version
        )));
    }

    let mut records = 0usize;
    for run in &parsed.runs {
        // Grouped by epoch, in order. Each group is one `append` carrying that
        // group's own epoch, which is what reproduces the hashed bodies of a run
        // that changed owner mid-flight.
        for batch in run.bodies.chunk_by(|a, b| a.epoch == b.epoch) {
            let Some(epoch) = batch.first().map(|b| b.epoch) else {
                continue;
            };
            let appends: Vec<Append> = batch.iter().cloned().map(Append::from_body).collect();
            records += appends.len();
            store.append(epoch, appends).await?;
        }
    }

    // Sealed last, and in the log's own order, because that order *is* the
    // Merkle log. Sealing as each run finished would rebuild the tree in
    // whatever sequence the file happened to list them, and the roots would
    // differ for a history that is otherwise identical.
    let mut sealed: Vec<&RestoredRun> = parsed
        .runs
        .iter()
        .filter(|r| r.index.is_some())
        .collect::<Vec<_>>();
    sealed.sort_by_key(|r| r.index);
    for run in sealed {
        let (Some(outcome), Some(epoch)) =
            (run.outcome.as_deref(), run.bodies.last().map(|b| b.epoch))
        else {
            continue;
        };
        store.seal(run.run, epoch, outcome).await?;
    }

    let mut not_carried = Vec::new();
    if parsed.canon != Some(u64::from(crate::core::canon::VERSION)) {
        not_carried.push(format!(
            "the digests — the export was written under canonicalization rule {:?} and this \
             build implements {}, so the rebuilt store re-derives every digest under the new \
             rule and its checkpoint cannot match the export's. The data is restored; \
             `is_faithful` is unprovable, not false",
            parsed.canon,
            crate::core::canon::VERSION
        ));
    }
    if parsed.signed > 0 && !parsed.runs.is_empty() {
        not_carried.push(format!(
            "{} record(s) carried a signature that this store did not reproduce — `append` \
             attests as the restoring store's own signer, so authorship is lost unless it \
             holds the original key. Hashes and the Merkle root are unaffected",
            parsed.signed
        ));
    }
    not_carried.push(
        "activity timestamps — `recent_runs` now orders by restore time rather than by when \
         history happened. It is a discovery index for listing, and nothing derives a decision \
         from it"
            .to_owned(),
    );

    Ok(RestoreReport {
        expected: parsed.checkpoint,
        rebuilt: store.checkpoint().await?,
        runs: parsed.runs.len(),
        records,
        not_carried,
    })
}

/// One run, as an export describes it.
struct RestoredRun {
    run: RunId,
    /// Position in the Merkle log; `None` for a run that was still open.
    index: Option<u64>,
    outcome: Option<String>,
    bodies: Vec<crate::journal::RecordBody>,
}

struct Parsed {
    checkpoint: Checkpoint,
    /// The format version the header claims, `None` when there was no header.
    version: Option<u64>,
    /// The canonicalization rule the header names, `None` when absent.
    canon: Option<u64>,
    runs: Vec<RestoredRun>,
    signed: usize,
}

/// Read an export into the shape a restore replays.
///
/// Deliberately does no checking: [`verify`] answers *is this sound* and this
/// answers *what does it say*. Folding them would make a restore refuse the very
/// history an operator is trying to recover, at the moment they most need it —
/// and the right order is restore, then verify the result against its own
/// checkpoint, which [`from_jsonl`] reports.
fn parse<R: std::io::BufRead>(input: R) -> Result<Parsed, std::io::Error> {
    use serde_json::Value;

    let mut parsed = Parsed {
        checkpoint: Checkpoint {
            origin: String::new(),
            size: 0,
            root: crate::core::Digest::ZERO,
        },
        version: None,
        canon: None,
        runs: Vec::new(),
        signed: 0,
    };
    for line in input.lines() {
        let line = line?;
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        match value.get("kind").and_then(Value::as_str) {
            Some("agentplane.export") => {
                parsed.version = value.get("version").and_then(Value::as_u64);
                parsed.canon = value.get("canon").and_then(Value::as_u64);
                if let Some(c) = value
                    .get("checkpoint")
                    .and_then(|c| serde_json::from_value::<Checkpoint>(c.clone()).ok())
                {
                    parsed.checkpoint = c;
                }
            }
            Some("agentplane.export.run") => {
                if let Some(run) = value
                    .get("run")
                    .and_then(Value::as_str)
                    .and_then(|s| RunId::parse(s).ok())
                {
                    parsed.runs.push(RestoredRun {
                        run,
                        index: value.get("index").and_then(Value::as_u64),
                        outcome: None,
                        bodies: Vec::new(),
                    });
                }
            }
            Some("agentplane.export.end") => {}
            _ => {
                if value.get("attestation").is_some_and(|a| !a.is_null()) {
                    parsed.signed += 1;
                }
                let Some(body) = value.get("body").and_then(|b| {
                    serde_json::from_value::<crate::journal::RecordBody>(b.clone()).ok()
                }) else {
                    continue;
                };
                if let Some(current) = parsed.runs.last_mut() {
                    if let crate::journal::RecordKind::RunSealed { outcome, .. } = &body.kind {
                        current.outcome = Some(outcome.clone());
                    }
                    current.bodies.push(body);
                }
            }
        }
    }
    Ok(parsed)
}
