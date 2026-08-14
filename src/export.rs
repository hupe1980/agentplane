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
///
/// Two shapes are load-bearing enough to state with the constant, because
/// each was once tempting to do the other way. The case layer is mandatory,
/// never an optional extension: a reader that tolerated its absence could not
/// tell *this plane has no cases* from *the case layer was dropped from this
/// file* — and the second is the finding that matters. And every record line
/// carries `raw`, the **exact bytes the chain hashed**, which is what
/// verification recomputes over: verifying a re-serialization of the parsed
/// body would hold only while this build's canonicalization agreed
/// byte-for-byte with the writer's — the wire-bytes rule the journal itself
/// refuses to bend, bent by its own export.
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
    /// The typed view, for a reader's eyes. Verification never touches it —
    /// see `raw` — and the verifier holds the two to each other so this cannot
    /// quietly say something the hashed bytes do not.
    ///
    /// **Parsed from `raw`, never taken from the store's in-memory record.**
    /// A sealed journal hands reads back *opened* — that is its job for the
    /// runtime, whose own steps must read what they wrote — so an export that
    /// copied the record's `body` field would write every sealed payload's
    /// plaintext into a file, and destroying the key would no longer reach the
    /// copy somebody exported last month. Deriving the display copy from the
    /// hashed bytes makes body-matches-wire true by construction and keeps
    /// sealed payloads sealed, which is the same rule the case layer's export
    /// read states in prose.
    pub body: crate::journal::RecordBody,
    pub prev_hash: &'r crate::core::Digest,
    pub hash: &'r crate::core::Digest,
    /// Present only where the plane was configured to sign. `None` is an
    /// ordinary state and is emitted as such rather than omitted, so a reader
    /// can tell *unsigned* from *a field this export forgot*.
    pub attestation: Option<&'r crate::core::Attestation>,
    /// The exact bytes [`hash`](Self::hash) covers, verbatim.
    ///
    /// This is the wire-bytes rule, applied to the export: the chain is over
    /// history **as written**, and a verifier that re-serialized the parsed
    /// body was holding the file to *this build's* canonicalization rather
    /// than to the bytes the store sealed. Canonical record bytes are UTF-8
    /// JSON, so they travel as a string — escaped, exact, and recoverable
    /// byte-for-byte.
    pub raw: std::borrow::Cow<'r, str>,
}

impl<'r> ExportedRecord<'r> {
    /// Build an export line from a stored record, deriving the display copy
    /// from the wire bytes.
    ///
    /// Fallible on purpose, with no fallback to the record's opened `body`: a
    /// record whose hashed bytes do not parse is corrupt, and substituting the
    /// in-memory view would export exactly the plaintext this constructor
    /// exists to keep out of the file — a silent fallback on the one value two
    /// mechanisms must agree about.
    fn from_stored(r: &'r crate::journal::Record) -> Result<Self, String> {
        let body = serde_json::from_slice::<crate::journal::RecordBody>(r.raw())
            .map_err(|e| format!("record {}'s wire bytes do not parse: {e}", r.seq()))?;
        Ok(Self {
            seq: r.seq(),
            body,
            prev_hash: &r.prev_hash,
            hash: &r.hash,
            attestation: r.attestation.as_ref(),
            raw: String::from_utf8_lossy(r.raw()),
        })
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

/// One case, as an export line — the case layer's whole account of one matter.
///
/// Emitted after the run blocks because the two halves answer different
/// questions: the journal is *what happened*, the case is *what it happened
/// to*. A restore of the journal alone rebuilds every index the journal owns
/// and none of these rows, because case state is not derivable from records —
/// which is exactly why the export has to carry it.
///
/// `state` travels **as stored**: sealed on a sealed plane. Exporting
/// plaintext would quietly undo erasure — see the module docs, which make the
/// same refusal for record payloads.
///
/// `blobs` carries digests, never bytes. Presence and integrity of the bytes
/// are a question about a live blob store, which an offline file cannot
/// answer and honestly reports as unchecked.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CaseBlock {
    /// Always `"agentplane.export.case"`.
    pub kind: &'static str,
    pub case: crate::core::Case,
    pub deadlines: Vec<crate::core::Deadline>,
    pub blobs: Vec<crate::core::Digest>,
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
    /// How many cases the case layer contributed.
    ///
    /// Zero means this plane has no case store — a state, not a gap. A plane
    /// *with* one exports every case it holds, so a record stamped with a case
    /// this file does not carry is a finding the verifier makes.
    pub cases: usize,
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
    cases: Option<&Arc<dyn crate::case::CaseStore>>,
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
            // A run the store holds nothing for is filed as unreadable, not
            // exported as an empty block. Both backends answer an unknown run
            // with an empty read rather than an error, so without this arm a
            // mistyped run id produced a block with no records under it — a
            // shape the verifier must otherwise treat as records removed after
            // the fact. Naming it here keeps the trailer's accounting honest:
            // an empty block in a file whose trailer does not declare the run
            // unreadable is tampering, and only because no honest writer
            // produces one.
            Ok(found) if found.is_empty() => unreadable.push(Unreadable {
                run,
                reason: "the store holds no records for this run".to_owned(),
            }),
            Ok(found) => {
                // Every line is derived from its wire bytes before any is
                // written, so a record that cannot be derived files the whole
                // run as unreadable instead of leaving a half-written block
                // shaped like a complete one.
                match found
                    .iter()
                    .map(ExportedRecord::from_stored)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(lines) => {
                        for line in &lines {
                            writeln!(out, "{}", to_line(line)?)?;
                            records += 1;
                        }
                        exported += 1;
                    }
                    Err(reason) => unreadable.push(Unreadable { run, reason }),
                }
            }
            Err(e) => unreadable.push(Unreadable {
                run,
                reason: e.to_string(),
            }),
        }
    }

    // The case layer, after the runs and before the trailer. Every case, not
    // the cases these runs touch: a case is the unit an erasure request or a
    // regulator names, and a subset chosen by run membership would silently
    // drop the matter whose runs happened not to be asked for.
    let mut case_count = 0usize;
    if let Some(case_store) = cases {
        let mut after: Option<crate::core::CaseId> = None;
        loop {
            let page = case_store
                .cases(after, CASE_PAGE)
                .await
                .map_err(|e| as_io(&e))?;
            let Some(last) = page.last() else { break };
            after = Some(last.id);
            let full = page.len() >= CASE_PAGE;
            for case in page {
                let deadlines = case_store.deadlines(case.id).await.map_err(|e| as_io(&e))?;
                let blobs = case_store.blobs_of(case.id).await.map_err(|e| as_io(&e))?;
                writeln!(
                    out,
                    "{}",
                    to_line(&CaseBlock {
                        kind: "agentplane.export.case",
                        case,
                        deadlines,
                        blobs,
                    })?
                )?;
                case_count += 1;
            }
            if !full {
                break;
            }
        }
    }

    let trailer = Trailer {
        kind: "agentplane.export.end",
        runs_requested: runs.len(),
        runs_exported: exported,
        records,
        cases: case_count,
        unreadable,
    };
    writeln!(out, "{}", to_line(&trailer)?)?;
    out.flush()?;
    Ok(trailer)
}

/// How many cases one enumeration page holds — shared with the live drill
/// ([`crate::drill`]), which walks the same case layer with the same paging.
/// Interior to the crate either way: the stream out is unbounded, and the
/// page only bounds memory. One constant, because two walks that paged
/// differently would be two subtly different definitions of "every case".
pub(crate) const CASE_PAGE: usize = 256;

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
    /// How many case blocks were read.
    pub cases: usize,
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
/// * **The trailer's own accounting holds.** Its run and record counts are
///   compared against what was actually read, and a run it declares unreadable
///   is reported as *unchecked* rather than as tampering — the writer said at
///   export time that the run's records are not here, which is the opposite of
///   hiding it. An empty run block the trailer does **not** declare unreadable
///   is the tamper case: no honest writer produces one.
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
    use crate::core::Digest;
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
        cases: 0,
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
    // The reader's own tally, held against the trailer's at the end: every run
    // block seen, every block that carried at least one record, and every block
    // that carried none. The trailer adjudicates the empty ones — an export
    // that declared the run unreadable was honest about it, and one that did
    // not has had records removed — which is why they are collected rather
    // than judged on the spot: the trailer is the last line, and an
    // intermediate block closes before it is read.
    let mut run_blocks = 0usize;
    let mut read_runs = 0usize;
    let mut empty_blocks: Vec<RunId> = Vec::new();
    let mut claims = TrailerClaims::default();
    // The two halves of the case cross-check: what the records name, and what
    // the case layer carries. Settled at the end, because either side can
    // arrive first in the file.
    let mut stamped: std::collections::BTreeSet<crate::core::CaseId> =
        std::collections::BTreeSet::new();
    let mut carried: std::collections::BTreeSet<crate::core::CaseId> =
        std::collections::BTreeSet::new();
    let mut blob_digests = 0usize;

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
            Some("agentplane.export.case") => {
                read_case_block(&value, &mut report, &mut carried, &mut blob_digests);
            }
            Some("agentplane.export.run") => {
                run_blocks += 1;
                finish_run(
                    &mut report,
                    pass.take(),
                    verifier,
                    &mut read_runs,
                    &mut empty_blocks,
                );
                pass = open_run_block(&value, &mut leaves);
            }
            Some("agentplane.export.end") => read_trailer(&value, &mut report, &mut claims),
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
                read_record(&value, pass, &mut report, &mut stamped);
            }
        }
    }
    finish_run(
        &mut report,
        pass,
        verifier,
        &mut read_runs,
        &mut empty_blocks,
    );

    settle(&mut report, header_seen, leaves);
    settle_trailer(&mut report, &claims, run_blocks, read_runs, &empty_blocks);
    settle_cases(&mut report, &stamped, &carried, blob_digests);
    Ok(report)
}

/// What the trailer claims about the file, held for the settlement.
///
/// Collected rather than compared on the spot, for two reasons that are the
/// same reason: the trailer is the last line, so the totals it must be held
/// against only exist once the whole file has been read — and the per-run
/// verdicts it adjudicates (is an empty block an honestly-declared unreadable
/// run, or records removed after the fact?) close *before* it is read, because
/// each run block is finished when the next one starts.
#[derive(Default)]
struct TrailerClaims {
    runs_requested: Option<u64>,
    runs_exported: Option<u64>,
    records: Option<u64>,
    /// Runs the export itself declared unreadable, with the writer's reason.
    unreadable: Vec<(RunId, String)>,
}

/// Read the trailer: the file is complete, and its case count holds.
///
/// The case-count comparison is what catches the case layer stripped *whole*:
/// with every block gone the coverage cross-check has nothing to compare, and
/// the file would read as an export of a plane that simply had no cases —
/// while its trailer still says otherwise. The run and record counts are
/// collected here and compared in [`settle_trailer`], where the totals exist.
fn read_trailer(value: &serde_json::Value, report: &mut VerifyReport, claims: &mut TrailerClaims) {
    report.complete = true;
    if let Some(declared) = value.get("cases").and_then(serde_json::Value::as_u64)
        && declared != report.cases as u64
    {
        report.findings.push(format!(
            "the trailer says {declared} case(s) were exported and this file \
             carries {} — the case layer was cut after the export was taken",
            report.cases
        ));
    }
    claims.runs_requested = value
        .get("runs_requested")
        .and_then(serde_json::Value::as_u64);
    claims.runs_exported = value
        .get("runs_exported")
        .and_then(serde_json::Value::as_u64);
    claims.records = value.get("records").and_then(serde_json::Value::as_u64);
    if let Some(list) = value
        .get("unreadable")
        .and_then(serde_json::Value::as_array)
    {
        for entry in list {
            let Some(run) = entry
                .get("run")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| RunId::parse(s).ok())
            else {
                continue;
            };
            let reason = entry
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("no reason recorded")
                .to_owned();
            claims.unreadable.push((run, reason));
        }
    }
}

/// Hold the trailer's own accounting to what was actually read.
///
/// Before this settlement existed, only the trailer's `cases` count was ever
/// consulted — `runs_requested`, `runs_exported`, `records` and `unreadable`
/// were fields the writer stamped and no reader read, so deleting an open
/// run's tail records while keeping the trailer verified clean: an open run
/// has no leaf to pin its tail, a chain prefix verifies, and the only witness
/// left is the count.
///
/// The empty blocks are adjudicated here too, and the trailer is what decides
/// which way each one goes. A run the export *declares* unreadable is
/// unchecked, not tampering: the writer said at export time that this run's
/// records are not in the file, which is the opposite of hiding it, and
/// reporting it as "records removed after sealing" would teach an operator
/// that findings are noise. An empty block the trailer does **not** declare is
/// the tamper case — no honest writer produces one, because an unreadable or
/// empty read files the run in the trailer instead.
///
/// What this does NOT cover: a trailer rewritten to match an edited file. The
/// counts are the file's claim about itself, and holding a file to itself
/// never catches an editor who updates both halves — that is the chain, leaf
/// and Merkle-root checks' job, which tie the surviving bytes to history. Nor
/// does it cover an open run's tail cut *before* the export was taken: the
/// store served the shortened history, the writer counted what it served, and
/// no offline file can see past its own writer.
fn settle_trailer(
    report: &mut VerifyReport,
    claims: &TrailerClaims,
    run_blocks: usize,
    read_runs: usize,
    empty_blocks: &[RunId],
) {
    for (run, reason) in &claims.unreadable {
        report.not_checked.push(format!(
            "run {run}: the export declares it unreadable ({reason}), so its records are \
             not in this file and nothing about it was verified"
        ));
    }
    for run in empty_blocks {
        if claims.unreadable.iter().any(|(u, _)| u == run) {
            continue;
        }
        report.findings.push(format!(
            "run {run}: its block carries no records and the export does not declare it \
             unreadable — either the records were removed after the export was taken, or \
             the file was cut short before them"
        ));
    }
    // The counts exist only on a framed file; a missing trailer is already the
    // truncation finding in `settle`, and comparing against nothing would
    // manufacture a second finding about the same cut.
    if !report.complete {
        return;
    }
    match (claims.runs_requested, claims.runs_exported, claims.records) {
        (Some(requested), Some(exported), Some(records)) => {
            if requested != run_blocks as u64 {
                report.findings.push(format!(
                    "the trailer says {requested} run(s) were requested and this file carries \
                     {run_blocks} run block(s) — whole runs were removed or added after the \
                     export was taken"
                ));
            }
            if exported != read_runs as u64 {
                report.findings.push(format!(
                    "the trailer says {exported} run(s) were exported in full and this file \
                     carries records for {read_runs} — a run's records were removed after the \
                     export was taken"
                ));
            }
            if records != report.records as u64 {
                report.findings.push(format!(
                    "the trailer says {records} record(s) were written and this file carries \
                     {} — record lines were removed or added after the export was taken",
                    report.records
                ));
            }
        }
        _ => report.findings.push(
            "the trailer is missing counts this format always writes (runs_requested, \
             runs_exported, records) — a reader cannot hold the file to its own accounting"
                .to_owned(),
        ),
    }
}

/// Read one case block: count it, collect its id for the coverage settlement,
/// and flag the malformations a reader would otherwise trip over silently.
fn read_case_block(
    value: &serde_json::Value,
    report: &mut VerifyReport,
    carried: &mut std::collections::BTreeSet<crate::core::CaseId>,
    blob_digests: &mut usize,
) {
    use serde_json::Value;

    report.cases += 1;
    match serde_json::from_value::<crate::core::Case>(
        value.get("case").cloned().unwrap_or(Value::Null),
    ) {
        Ok(case) => {
            carried.insert(case.id);
        }
        Err(e) => report
            .findings
            .push(format!("a case block is malformed: {e}")),
    }
    if value
        .get("deadlines")
        .is_none_or(|d| serde_json::from_value::<Vec<crate::core::Deadline>>(d.clone()).is_err())
    {
        report
            .findings
            .push("a case block's deadlines are malformed".to_owned());
    }
    *blob_digests += value
        .get("blobs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
}

/// The case layer's own settlement: coverage, and what a file cannot check.
///
/// The coverage rule has a deliberate asymmetry. A record stamped with a case
/// the file does not carry is a **finding** — this plane had a case layer (the
/// stamp proves it) and the export is missing a matter the journal names. The
/// reverse is not: a case whose runs are absent is the ordinary result of
/// exporting a subset of runs, and every case travels regardless of which runs
/// were asked for.
///
/// A file with records stamped and **no** case blocks at all is reported as
/// unchecked rather than as a finding, because the export may honestly have
/// been taken from a plane whose journal was written by a case-configured
/// runtime while the export ran without the case store — the CLI wires it when
/// present, but the library caller may not. The trailer's `cases` count is
/// what distinguishes *none existed* from *none were asked for*.
fn settle_cases(
    report: &mut VerifyReport,
    stamped: &std::collections::BTreeSet<crate::core::CaseId>,
    carried: &std::collections::BTreeSet<crate::core::CaseId>,
    blob_digests: usize,
) {
    if carried.is_empty() {
        if !stamped.is_empty() {
            report.not_checked.push(format!(
                "the case layer — {} case(s) are stamped on records and this file carries no \
                 case blocks, so either the plane's case store was not supplied to the export \
                 or the layer was dropped; the two cannot be told apart from the file alone",
                stamped.len()
            ));
        }
        return;
    }
    for case in stamped.difference(carried) {
        report.findings.push(format!(
            "case {case} is stamped on exported records and missing from the case layer — \
             the journal names a matter this file does not carry"
        ));
    }
    if blob_digests > 0 {
        report.not_checked.push(format!(
            "blob bytes — the case layer references {blob_digests} blob digest(s) and this \
             file carries digests, not bytes; presence and integrity are a question about a \
             live blob store"
        ));
    }
    report.not_checked.push(
        "sealed-state keys — whether sealed case state can still be opened is a question \
         about a live key ring, which an offline file cannot answer"
            .to_owned(),
    );
}

/// Open a run block: fresh per-run state, and the block's leaf collected for
/// the tree rebuild. Returns `None` for a block whose run id does not parse —
/// the records under it are then flagged as belonging to no run, which is the
/// honest reading of a block nothing can be looked up by.
fn open_run_block(
    value: &serde_json::Value,
    leaves: &mut Vec<(u64, crate::core::Digest)>,
) -> Option<RunPass> {
    use crate::core::{Digest, merkle};
    use serde_json::Value;

    let pass = value
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
            records: 0,
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
    pass
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
    /// How many record lines this block carried. Zero is a state the trailer
    /// must explain: see [`settle_trailer`].
    records: usize,
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
    // A foreign canonicalization rule is a statement about coverage, not a
    // finding — nothing this pass checks depends on the rule. The chain
    // rehash, the leaf comparison, the Merkle root and the signatures all run
    // over the wire bytes **as written** (`Digest::chain` is plain hashing;
    // it never re-canonicalizes), so they hold under any rule; the counts,
    // the body-vs-wire comparison and the case coverage are byte and value
    // comparisons with no rule in them at all. What a foreign rule *does*
    // take off the table is re-deriving the digests inside the bodies —
    // effect keys, manifest and plan digests — which this pass never
    // recomputes anyway, and which a replaying build would. Filing it as a
    // finding made an honest cross-build export read as tampered, which
    // teaches a reader to ignore the finding that means it.
    let canon = value.get("canon").and_then(serde_json::Value::as_u64);
    if canon != Some(u64::from(crate::core::canon::VERSION)) {
        report.not_checked.push(format!(
            "derived digests — the export was written under canonicalization rule {canon:?} \
             and this build implements {}. The chain, leaf, root and signature checks still \
             ran and still hold (they hash the bytes as written, never a re-serialization); \
             what this build cannot do is re-derive the digests inside the bodies, such as \
             effect keys, under the rule that produced them",
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

/// Rehash one record's wire bytes and hold them to the hash it carries.
///
/// The rehash is the whole check, and it runs over `raw` — the exact bytes the
/// store hashed — never over a re-serialization of the parsed body. That is
/// the journal's own wire-bytes rule: re-serializing would hold the file to
/// *this build's* canonicalization instead of to what was written, so an
/// export from a build whose rule differed would report tampering where there
/// was only time, and — worse — an edit that re-serializes identically would
/// pass. Comparing the file's `prev_hash` against the previous line's `hash`
/// would only prove the file agrees with itself, which an editor who
/// recomputed the chain also achieves; rehashing the wire bytes is what makes
/// agreement evidence about them.
fn read_record(
    value: &serde_json::Value,
    pass: &mut RunPass,
    report: &mut VerifyReport,
    stamped: &mut std::collections::BTreeSet<crate::core::CaseId>,
) {
    let current = pass.run;
    pass.records += 1;
    let (Some(raw), Some(claimed)) = (
        value.get("raw").and_then(serde_json::Value::as_str),
        value
            .get("hash")
            .and_then(|h| serde_json::from_value::<crate::core::Digest>(h.clone()).ok()),
    ) else {
        report.findings.push(format!(
            "run {current}: a record line carries no wire bytes or no hash — nothing ties \
             it to the chain"
        ));
        pass.clean = false;
        return;
    };
    let raw_bytes = raw.as_bytes();
    // The body verification reads is parsed from the wire bytes — the one
    // source the hash actually covers.
    let Ok(body) = serde_json::from_slice::<crate::journal::RecordBody>(raw_bytes) else {
        report
            .findings
            .push(format!("run {current}: a record line is malformed"));
        pass.clean = false;
        return;
    };
    // The readable `body` is a courtesy copy, and it is held to the bytes: a
    // file whose display half says something its hashed half does not is the
    // quiet edit — every hash verifies, and the reader was shown a lie.
    let wire: serde_json::Value = serde_json::from_slice(raw_bytes).unwrap_or_default();
    if value.get("body") != Some(&wire) {
        report.findings.push(format!(
            "run {current}: record {}'s readable body does not match its wire bytes — the \
             display copy was edited, and every hash still verifies over the real one",
            body.seq
        ));
        pass.clean = false;
    }
    // Collected for the case-coverage settlement: a stamp is the journal
    // naming a matter, and the case layer must carry every matter it names.
    if let Some(case) = body.case {
        stamped.insert(case);
    }
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

    // The sealing record's own claim, held to the chain it sits in — the same
    // check the live audit makes. `RunSealed.chain_head` is the head the
    // conclusion was drawn over, which is by construction its own record's
    // `prev_hash`; `pass.prev` here is that head, recomputed from the wire
    // bytes of every line before this one, so agreement is evidence about the
    // bytes rather than the file agreeing with itself. A mismatch means the
    // conclusion was composed against a different history than the one it was
    // appended to, which no honest writer produces. What this does NOT cover:
    // a run with no sealing record at all — an open run has made no claim,
    // and its absence of one is a state, not a defect.
    if let crate::journal::RecordKind::RunSealed { chain_head, .. } = &body.kind
        && *chain_head != pass.prev
    {
        report.findings.push(format!(
            "run {current}: the sealing record claims a chain head that is not the head it \
             sits on — the conclusion was drawn over a different history"
        ));
        pass.clean = false;
    }

    let attestation = value
        .get("attestation")
        .and_then(|a| serde_json::from_value::<Option<crate::core::Attestation>>(a.clone()).ok())
        .flatten();
    if let Ok(record) = crate::journal::Record::from_stored_attested(
        raw_bytes.to_vec(),
        pass.prev,
        claimed,
        attestation,
    ) {
        pass.prev = record.hash;
        pass.resealed.push(record);
    } else {
        report.findings.push(format!(
            "run {current}: record {} does not recompute to the hash it carries \
             — it was edited after it was sealed",
            pass.last_seq
        ));
        pass.clean = false;
        // The head walks forward over the bytes actually present, so the
        // leaf comparison at the end of the block speaks about what this
        // file carries rather than about the first mismatch.
        pass.prev = crate::core::Digest::chain(pass.prev, raw_bytes);
    }
}

/// Close out a run block: its terminal hash must be the leaf the log recorded,
/// and its signatures must verify if a key was supplied.
fn finish_run(
    report: &mut VerifyReport,
    pass: Option<RunPass>,
    verifier: Option<&dyn crate::core::Verifier>,
    read_runs: &mut usize,
    empty_blocks: &mut Vec<RunId>,
) {
    let Some(pass) = pass else {
        return;
    };
    let run = pass.run;
    // A block with no records is never sound, and it is never judged here:
    // whether it is an honestly-declared unreadable run (unchecked) or a run
    // emptied after the export was taken (a finding) is written in the
    // trailer, which this pass has not necessarily reached — an intermediate
    // block closes when the next one starts. Judging it now would also raise a
    // false leaf-mismatch for a sealed unreadable run, whose declared leaf is
    // genuine and whose records the writer honestly could not read: `prev` is
    // still `ZERO`, and ZERO not matching the leaf is a fact about the empty
    // walk, not about the history.
    if pass.records == 0 {
        empty_blocks.push(run);
        return;
    }
    *read_runs += 1;
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
    /// Cases rebuilt from the export's case layer.
    pub cases: usize,
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
    cases: Option<&Arc<dyn crate::case::CaseStore>>,
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

    // The frame is the completeness signal, and the restore is the reader most
    // exposed to its absence: a truncated export is a *prefix* in which every
    // line is valid, so replaying one rebuilds a partial history shaped
    // exactly like a whole one. The quietest cut is the worst — a file cut
    // after the last record but before the case layer restores a journal that
    // is byte-perfect and `is_faithful`, with every matter it names missing.
    // Refused before any write lands, so a refused restore leaves nothing to
    // clean up. What this does NOT cover: a file truncated *and* given a
    // forged trailer — that is `verify`'s count settlement, and the right
    // order is restore, then verify.
    if !parsed.complete {
        return Err(StoreError::Backend(
            "the export has no trailer, so it was cut short — every line in it is a valid \
             prefix, and restoring a prefix would rebuild a partial history shaped exactly \
             like a whole one. Re-take the export"
                .to_owned(),
        ));
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

    // The case layer, after the journal. Order matters only for the operator's
    // mental model — the two halves share no constraint — but the journal is
    // the half whose restore can fail on a constraint, and failing before any
    // case row landed leaves the cleaner wreck.
    let mut imported = 0usize;
    let mut not_carried = Vec::new();
    match (cases, parsed.cases.is_empty()) {
        (Some(case_store), false) => {
            for block in &parsed.cases {
                case_store
                    .import_case(&block.case, &block.deadlines, &block.blobs)
                    .await?;
                imported += 1;
            }
            not_carried.push(
                "blob link timestamps — the export carries a case's blob digests without \
                 the instant each link was written, so erasure reachability survives and \
                 the original ordering does not"
                    .to_owned(),
            );
        }
        (None, false) => not_carried.push(format!(
            "the case layer — the export carries {} case(s) and no case store was supplied, \
             so the journal is rebuilt and the matters it names are not",
            parsed.cases.len()
        )),
        (_, true) => {}
    }

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
        cases: imported,
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
    /// Whether the file ended with its trailer. A truncated export is a valid
    /// prefix, and a restore must refuse it — see [`from_jsonl`].
    complete: bool,
    runs: Vec<RestoredRun>,
    cases: Vec<RestoredCase>,
    signed: usize,
}

/// One case block, as a restore replays it.
struct RestoredCase {
    case: crate::core::Case,
    deadlines: Vec<crate::core::Deadline>,
    blobs: Vec<crate::core::Digest>,
}

/// Read an export into the shape a restore replays.
///
/// Deliberately does no *soundness* checking: [`verify`] answers *is this
/// sound* and this answers *what does it say*. Folding them would make a
/// restore refuse the very history an operator is trying to recover, at the
/// moment they most need it — and the right order is restore, then verify the
/// result against its own checkpoint, which [`from_jsonl`] reports.
///
/// One class of line is a hard error rather than a skip, and it is not a
/// soundness question: a record line whose wire bytes are missing or do not
/// parse cannot be *replayed*, only guessed at, and the one available guess —
/// the editable display copy — is exactly the value the wire-bytes rule
/// exists to keep out of the rebuilt history.
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
        complete: false,
        runs: Vec::new(),
        cases: Vec::new(),
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
            Some("agentplane.export.case") => {
                // Malformed blocks are skipped here and found by `verify`,
                // per this function's no-checking rule: a restore that
                // refused the file would refuse the healthy cases in it too.
                let (Ok(case), Some(deadlines), Some(blobs)) = (
                    serde_json::from_value::<crate::core::Case>(
                        value.get("case").cloned().unwrap_or(Value::Null),
                    ),
                    value.get("deadlines").and_then(|d| {
                        serde_json::from_value::<Vec<crate::core::Deadline>>(d.clone()).ok()
                    }),
                    value.get("blobs").and_then(|b| {
                        serde_json::from_value::<Vec<crate::core::Digest>>(b.clone()).ok()
                    }),
                ) else {
                    continue;
                };
                parsed.cases.push(RestoredCase {
                    case,
                    deadlines,
                    blobs,
                });
            }
            Some("agentplane.export.end") => parsed.complete = true,
            // A line carrying a `kind` this build does not recognise is not a
            // record — record lines are the only unkinded lines in the format
            // — so it is skipped per the no-checking rule rather than held to
            // a record's obligations.
            Some(_) => {}
            _ => {
                if value.get("attestation").is_some_and(|a| !a.is_null()) {
                    parsed.signed += 1;
                }
                // The wire bytes are the source of truth, exactly as they are
                // for the verifier: the readable `body` is a courtesy copy,
                // and a restore replaying the copy would rebuild whatever the
                // display half said rather than what the chain covered. There
                // is deliberately **no fallback to that copy**: a record line
                // with no `raw`, or whose `raw` does not parse, is a hard
                // error rather than a skip or a guess — silently substituting
                // the one editable value two mechanisms must agree about would
                // rebuild a history the chain never hashed and let the
                // subsequent verify pass bless it.
                let Some(raw) = value.get("raw").and_then(Value::as_str) else {
                    return Err(std::io::Error::other(
                        "a record line carries no wire bytes (`raw`) — restoring its display \
                         copy instead would rebuild what the readable half says rather than \
                         what the chain hashed, so the file is refused instead of guessed at",
                    ));
                };
                let body = serde_json::from_slice::<crate::journal::RecordBody>(raw.as_bytes())
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "a record line's wire bytes do not parse ({e}) — the record cannot \
                             be replayed as written, and its display copy is not a substitute"
                        ))
                    })?;
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
