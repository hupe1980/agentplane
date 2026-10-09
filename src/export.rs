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
    /// A digest is meaningless without the rule that computed it, and an
    /// export outlives the build that wrote it — so the rule travels with the
    /// digests rather than being whatever the reader happens to implement.
    pub canon: u16,
}

/// The first line of a disclosure package: an export of chosen runs, which
/// says so.
pub const DISCLOSURE_KIND: &str = "agentplane.disclosure";

/// What a disclosure package was asked for: whole cases, single runs, or both.
///
/// A package carries the runs these resolve to, each sealed one with its path
/// against the header's checkpoint, and only the cases those runs belong to.
/// Nothing about the log's other leaves is disclosed, and no reader may take
/// the package for a whole export: its header has its own `kind`, and the
/// run blocks carry `proof`, a member a whole export never has.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub cases: Vec<crate::core::CaseId>,
    pub runs: Vec<RunId>,
}

/// A disclosure package's first line: the export header plus its selection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageHeader {
    /// Always [`DISCLOSURE_KIND`].
    pub kind: String,
    /// [`FORMAT_VERSION`]: a package is a framing of the export format and
    /// moves with it.
    pub version: u32,
    /// The checkpoint every path in the file is against.
    pub checkpoint: Checkpoint,
    pub canon: u16,
    pub selection: Selection,
}

impl PackageHeader {
    /// Read a package's first line, refusing another kind, another version or
    /// an unknown member by name.
    ///
    /// # Errors
    ///
    /// When the line is not a package header this build reads.
    pub fn parse(line: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("not JSON: {e}"))?;
        let kind = value.get("kind").and_then(serde_json::Value::as_str);
        if kind != Some(DISCLOSURE_KIND) {
            return Err(format!(
                "the line is a {kind:?}, not a {DISCLOSURE_KIND} header"
            ));
        }
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        if version != Some(FORMAT_VERSION.into()) {
            return Err(format!(
                "the package is at format version {version:?}, and this build reads \
                 {FORMAT_VERSION}"
            ));
        }
        serde_json::from_value(value).map_err(|e| format!("the package header is malformed: {e}"))
    }
}

/// Why a reader that rebuilds or re-derives over a whole file refuses a
/// package, in one sentence every such reader uses.
const PACKAGE_REFUSED: &str = "the file is a disclosure package — the runs of one matter with \
     their inclusion paths, not the plane's whole log — so nothing can be rebuilt or derived \
     from it as if it were whole; verify it with `agentplane verify`";

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
    pub body: DisplayBody,
    pub prev_hash: &'r crate::core::Digest,
    pub hash: &'r crate::core::Digest,
    /// The plane's workload-key signature over this record's chain hash — who
    /// wrote the record, not a hardware attestation of where. Present only
    /// where the plane was configured to sign. `None` is an ordinary state
    /// and is emitted as such rather than omitted, so a reader can tell
    /// *unsigned* from *a field this export forgot*.
    pub signature: Option<&'r crate::core::KeySignature>,
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

/// A record line's display copy, which says what the hashed bytes say.
///
/// This build's typed view of bytes at the shape it writes, and the bytes' own
/// JSON for a record at an older one; `verify` holds either to the bytes.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum DisplayBody {
    Current(Box<crate::journal::RecordBody>),
    Written(serde_json::Value),
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
        let unparsed =
            |e: serde_json::Error| format!("record {}'s wire bytes do not parse: {e}", r.seq());
        // The record was read through the store's upcaster, so its `body` is at
        // this build's version; bytes at another are an older shape, and only
        // their own JSON says what they say.
        let body = match serde_json::from_slice::<crate::journal::RecordBody>(r.raw()) {
            Ok(body) if body.v == r.body.v => DisplayBody::Current(Box::new(body)),
            _ => DisplayBody::Written(serde_json::from_slice(r.raw()).map_err(unparsed)?),
        };
        Ok(Self {
            seq: r.seq(),
            body,
            prev_hash: &r.prev_hash,
            hash: &r.hash,
            signature: r.signature.as_ref(),
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
    /// In a disclosure package only: the sibling hashes, leaf-upwards, that
    /// prove `seal` at `index` against the header's checkpoint. A whole export
    /// never carries it, because it carries every leaf and rebuilds the root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<crate::core::Digest>>,
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
///
/// `hold` is always written, `null` for a matter nobody ordered preserved. A
/// restore that brought a held matter back without its hold would hand the
/// next retention pass a closed, old, unheld case to erase.
///
/// `erasure` is always written too, `null` for a matter nobody erased. A
/// restore that dropped it would bring back a case whose key is destroyed as
/// an ordinary closed one — reopenable, writable, and a drill finding.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CaseBlock {
    /// Always `"agentplane.export.case"`.
    pub kind: &'static str,
    pub case: crate::core::Case,
    pub deadlines: Vec<crate::core::Deadline>,
    pub blobs: Vec<crate::core::Digest>,
    /// The legal hold on this matter: instant, reason and operator.
    pub hold: Option<crate::core::LegalHold>,
    /// The erasure record on this matter: instant, reason, and whether it
    /// completed.
    pub erasure: Option<crate::case::Erasure>,
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
    /// Every case the case store holds is exported, so a record stamped with a
    /// case this file does not carry is a finding the verifier makes.
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
/// `cases` is the plane's case store, and every case it holds is written: a
/// file whose records name a matter it does not carry is a finding to every
/// reader of the format.
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
    cases: &Arc<dyn crate::case::CaseStore>,
    runs: &[RunId],
    out: W,
) -> Result<Trailer, std::io::Error> {
    write_file(store, cases, runs, None, out)
        .await
        .map(|written| written.trailer)
}

/// What a disclosure package carried, for the act that records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// The checkpoint every path in the file is against.
    pub checkpoint: Checkpoint,
    /// The runs the selection resolved to, in file order.
    pub runs: Vec<RunId>,
    /// The cases whose blocks the file carries.
    pub cases: Vec<crate::core::CaseId>,
    /// Whether any record carried a sealed payload.
    pub sealed: bool,
    pub trailer: Trailer,
}

/// Write a disclosure package: the runs `selection` names, each sealed one
/// with its inclusion path against the header's checkpoint, and only the cases
/// those runs belong to.
///
/// A case contributes the runs [`Case::runs`](crate::core::Case::runs) holds at
/// the moment of the call. The case layer is the selection's cases plus every
/// case a carried record is stamped with, so the coverage rule holds over the
/// package as over a whole export.
///
/// This writes bytes and records nothing: a package that leaves the plane is a
/// disclosure, and [`crate::disclosure::disclose`] is what records it before
/// any byte reaches its destination.
///
/// # Errors
///
/// `NotFound` for a named case or run the plane does not hold — never a
/// fall-back to the whole plane — an empty selection, a failure to write or
/// to prove a sealed run at the header's size, or a run whose conclusion seals
/// and which is still not in the log after the file was written against
/// three successive checkpoints. The file is built in memory and written
/// to `out` whole, so a refusal writes nothing.
pub async fn package_to_jsonl<W: std::io::Write>(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn crate::case::CaseStore>,
    selection: &Selection,
    mut out: W,
) -> Result<Package, std::io::Error> {
    let runs = resolve(store, cases, selection).await?;
    // A run concluded and sealed after the header's checkpoint was taken
    // would travel open with its conclusion, which a reader of a package
    // must take for a stripped leaf. So the file is written again against a
    // later checkpoint until every sealing conclusion it carries is placed.
    let mut attempts = 0;
    let (bytes, written) = loop {
        let mut bytes = Vec::new();
        let written = write_file(store, cases, &runs, Some(selection), &mut bytes).await?;
        attempts += 1;
        match written.unplaced.first() {
            None => break (bytes, written),
            Some(run) if attempts >= PACKAGE_ATTEMPTS => {
                return Err(std::io::Error::other(format!(
                    "run {run} concluded under an outcome that seals and is not in the log — \
                     the seal follows the conclusion, and recovery completes one a crash \
                     interrupted; no package was written, so retry once it is sealed"
                )));
            }
            Some(_) => {}
        }
    };
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(Package {
        checkpoint: written.checkpoint,
        runs,
        cases: written.cases,
        sealed: written.sealed,
        trailer: written.trailer,
    })
}

/// How many checkpoints a package is written against before a sealing
/// conclusion with no leaf is refused rather than raced.
const PACKAGE_ATTEMPTS: usize = 3;

/// The runs a selection names, each once, in the order named: a case's runs
/// first, then the runs named alone.
async fn resolve(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn crate::case::CaseStore>,
    selection: &Selection,
) -> Result<Vec<RunId>, std::io::Error> {
    use std::io::{Error, ErrorKind};
    if selection.cases.is_empty() && selection.runs.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "a disclosure package names at least one case or run",
        ));
    }
    let mut runs: Vec<RunId> = Vec::new();
    for &id in &selection.cases {
        let case = cases
            .case(id)
            .await
            .map_err(|e| as_io(&e))?
            .ok_or_else(|| {
                Error::new(ErrorKind::NotFound, format!("no case {id} on this plane"))
            })?;
        for run in case.runs {
            if !runs.contains(&run) {
                runs.push(run);
            }
        }
    }
    for &run in &selection.runs {
        if store.read(run, 1).await.map_err(|e| as_io(&e))?.is_empty() {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("no run {run} on this plane"),
            ));
        }
        if !runs.contains(&run) {
            runs.push(run);
        }
    }
    Ok(runs)
}

/// What one pass of the writer produced.
struct Written {
    checkpoint: Checkpoint,
    cases: Vec<crate::core::CaseId>,
    sealed: bool,
    trailer: Trailer,
    /// A package's runs that concluded under an outcome that seals and have
    /// no leaf below the header's size.
    unplaced: Vec<RunId>,
}

/// The one writer behind a whole export and a package; `package` is the
/// selection for a package and `None` for a whole export.
#[allow(clippy::too_many_lines)]
async fn write_file<W: std::io::Write>(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn crate::case::CaseStore>,
    runs: &[RunId],
    package: Option<&Selection>,
    mut out: W,
) -> Result<Written, std::io::Error> {
    let checkpoint = store.checkpoint().await.map_err(|e| as_io(&e))?;
    let taken = checkpoint.clone();
    // Held out of the header for the one comparison below: the header owns the
    // checkpoint from here on, and the log size is the half of it every run
    // block is checked against.
    let log_size = checkpoint.size;
    // Read from the build, never from the caller. The rule that computed the
    // digests is a fact about the store's own writes, and a parameter here was
    // a header any embedder could make lie — every caller passed
    // `canon::VERSION` verbatim, which is what a fact looks like when it is
    // asked for as an argument.
    match package {
        None => {
            let header = Header {
                kind: "agentplane.export",
                version: FORMAT_VERSION,
                checkpoint,
                canon: crate::core::canon::VERSION,
            };
            writeln!(out, "{}", to_line(&header)?)?;
        }
        Some(selection) => {
            let header = PackageHeader {
                kind: DISCLOSURE_KIND.to_owned(),
                version: FORMAT_VERSION,
                checkpoint,
                canon: crate::core::canon::VERSION,
                selection: selection.clone(),
            };
            writeln!(out, "{}", to_line(&header)?)?;
        }
    }
    let mut sealed = false;
    let mut stamped: std::collections::BTreeSet<crate::core::CaseId> = package
        .map(|s| s.cases.iter().copied().collect())
        .unwrap_or_default();

    let mut records = 0usize;
    let mut exported = 0usize;
    let mut unreadable = Vec::new();
    let mut unplaced = Vec::new();

    // Asked before the records so each block heads them, and asked at all
    // because the log position is the half of the evidence the records do not
    // carry. A store that cannot answer fails the export: writing every run
    // without its position would describe sealed runs as open, and the file
    // would rebuild an empty tree against a header that commits to a full one
    // — a verdict of tampering where there was only an outage.
    let positions = store.log_positions(runs).await.map_err(|e| as_io(&e))?;
    for (&run, placed) in runs.iter().zip(positions) {
        // A run sealed *after* the header's checkpoint was taken is not in that
        // checkpoint. Stamping its position anyway would make the export
        // disagree with its own first line: the verifier rebuilds a tree one
        // leaf larger than the root it compares against, and reports tampering
        // where there was only time. Such a run is exported as still open —
        // true relative to the moment this export describes — and the next
        // export carries it sealed.
        let placed = placed.filter(|&(index, _)| index < log_size);
        // A package proves each leaf on its own, against the header's size: a
        // path against the live log would fail against the header's root for
        // every run sealed while the file is written.
        let proof = match (package, placed) {
            (Some(_), Some(_)) => store
                .inclusion_proof_at(run, log_size)
                .await
                .map_err(|e| as_io(&e))?
                .map(|inclusion| inclusion.proof),
            _ => None,
        };
        writeln!(
            out,
            "{}",
            to_line(&RunBlock {
                kind: "agentplane.export.run",
                run,
                index: placed.map(|(index, _)| index),
                seal: placed.map(|(_, seal)| seal),
                proof,
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
                        if package.is_some() {
                            if placed.is_none() && crate::audit::has_sealing_conclusion(&found) {
                                unplaced.push(run);
                            }
                            stamped.extend(found.iter().filter_map(|r| r.body.case));
                            sealed |= found.iter().any(|r| carries_sealed(r.raw()));
                        }
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
    // drop the matter whose runs happened not to be asked for. A package is
    // the one file that is a subset on purpose, and says so in its header, so
    // it carries the cases it was asked for and every case its records name.
    let mut written_cases = Vec::new();
    if package.is_some() {
        for id in stamped {
            if let Some(case) = cases.case(id).await.map_err(|e| as_io(&e))? {
                write_case(cases, case, &mut out).await?;
                written_cases.push(id);
            }
        }
    } else {
        let mut after: Option<crate::core::CaseId> = None;
        loop {
            let page = cases.cases(after, CASE_PAGE).await.map_err(|e| as_io(&e))?;
            let Some(last) = page.last() else { break };
            after = Some(last.id);
            let full = page.len() >= CASE_PAGE;
            for case in page {
                written_cases.push(case.id);
                write_case(cases, case, &mut out).await?;
            }
            if !full {
                break;
            }
        }
    }
    let case_count = written_cases.len();

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
    Ok(Written {
        checkpoint: taken,
        cases: written_cases,
        sealed,
        trailer,
        unplaced,
    })
}

/// Whether a record's wire bytes carry a sealed payload anywhere in them.
fn carries_sealed(raw: &[u8]) -> bool {
    fn walk(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(text) => crate::journal::payload::is_sealed_text(text),
            serde_json::Value::Array(items) => items.iter().any(walk),
            serde_json::Value::Object(members) => {
                crate::journal::payload::is_sealed(value) || members.values().any(walk)
            }
            _ => false,
        }
    }
    serde_json::from_slice::<serde_json::Value>(raw).is_ok_and(|value| walk(&value))
}

/// One case block: the case, its deadlines, its blob digests, its hold and
/// its erasure record.
async fn write_case<W: std::io::Write>(
    cases: &Arc<dyn crate::case::CaseStore>,
    case: crate::core::Case,
    out: &mut W,
) -> Result<(), std::io::Error> {
    let deadlines = cases.deadlines(case.id).await.map_err(|e| as_io(&e))?;
    let blobs = cases.blobs_of(case.id).await.map_err(|e| as_io(&e))?;
    let hold = cases.hold(case.id).await.map_err(|e| as_io(&e))?;
    let erasure = cases.erasure(case.id).await.map_err(|e| as_io(&e))?;
    writeln!(
        out,
        "{}",
        to_line(&CaseBlock {
            kind: "agentplane.export.case",
            case,
            deadlines,
            blobs,
            hold,
            erasure,
        })?
    )
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
    /// Why this reader could check nothing past the header, when it could not.
    ///
    /// Set for a `canon` this build does not implement: the rule names the
    /// digest algorithm too, so every hash in the file is one this reader
    /// cannot recompute. Neither a finding nor corruption — another build may
    /// verify the file.
    pub unverifiable: Option<String>,
    /// What the file selected, when it is a disclosure package: the runs of
    /// one matter, each proved by its own path, and nothing about the log's
    /// other leaves. `None` for a whole export.
    pub selection: Option<Selection>,
}

impl VerifyReport {
    /// Whether every check that ran, passed, and the checks could run. See
    /// [`Self::not_checked`] and [`Self::unverifiable`].
    #[must_use]
    pub fn is_sound(&self) -> bool {
        self.findings.is_empty() && self.complete && self.unverifiable.is_none()
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
///   with `expected` — the checkpoint the reader was given by somebody other
///   than whoever wrote this file. This is the one that catches a whole run
///   dropped from the middle of the export: the per-run chains all still
///   verify, and only the tree notices.
///
///   Without `expected` it can only be compared with the file's **own header**,
///   which reads like the same check and is not: an editor who drops a run and
///   rewrites the header's size and root produces a file that agrees with
///   itself perfectly. This crate makes the same argument one level down — a
///   record's `prev_hash` is checked by rehashing the wire bytes, never against
///   the previous line, because "the file agrees with itself" is what a
///   competent editor achieves. So a pass with no `expected` reports the root
///   check under [`VerifyReport::not_checked`]: internal consistency
///   established, deletion not.
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
    anchors: &[crate::journal::Anchor],
) -> Result<VerifyReport, std::io::Error> {
    let upcaster = crate::journal::current_upcaster();
    verify_with(input, verifier, anchors, upcaster.as_ref())
}

/// [`verify`], reading each record through `upcaster` rather than the one this
/// build ships.
///
/// The hash is held to the bytes as written either way; the upcaster decides
/// only which record versions this reader can read, and a version it cannot
/// reach is a build skew, never an edit.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_with<R: std::io::BufRead>(
    input: R,
    verifier: Option<&dyn crate::core::Verifier>,
    anchors: &[crate::journal::Anchor],
    upcaster: &dyn crate::journal::Upcaster,
) -> Result<VerifyReport, std::io::Error> {
    verify_observed(input, verifier, anchors, upcaster, &mut |_| {})
}

/// One run block as the verification pass closed it.
pub(crate) struct ClosedRun<'a> {
    pub(crate) run: RunId,
    /// Whether the block declared a log position and a seal.
    pub(crate) sealed: bool,
    /// The records as the pass recomputed them. Whether they are sound is
    /// [`VerifyReport::sound`] once the pass returns.
    pub(crate) records: &'a [crate::journal::Record],
}

/// [`verify`], handing each run block to `observe` as it closes.
#[allow(clippy::too_many_lines)]
pub(crate) fn verify_observed<R: std::io::BufRead>(
    input: R,
    verifier: Option<&dyn crate::core::Verifier>,
    anchors: &[crate::journal::Anchor],
    upcaster: &dyn crate::journal::Upcaster,
    observe: &mut dyn FnMut(ClosedRun<'_>),
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
        unverifiable: None,
        selection: None,
    };
    unanswerable(&mut report, verifier.is_some());

    let mut header_seen = false;
    // (index, leaf) for every sealed run, so the tree can be rebuilt in log
    // order rather than in the order the export happened to walk.
    let mut leaves: Vec<(u64, crate::core::merkle::LeafHash)> = Vec::new();
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
    // Every run a block names and every position a block claims, so a run
    // carried twice or a position claimed twice is named, whatever the mode.
    let mut blocks_of: std::collections::BTreeSet<RunId> = std::collections::BTreeSet::new();
    let mut positions: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();

    // Only the first non-empty line may be a header: it alone fixes which
    // checkpoint every path is held to and which rules the file is read under.
    let mut first = true;
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let is_first = std::mem::replace(&mut first, false);
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            report
                .findings
                .push("a line is not valid JSON, so the export is unreadable from there on".into());
            break;
        };
        if let Some(kind) = value.get("kind").and_then(Value::as_str) {
            note_unknown_members(kind, report.selection.is_some(), &value, &mut report);
        }
        match Line::of(&value) {
            // A package is read by the same pass, with its own settlement: each
            // leaf is proved by its path, and nothing counts the log.
            Line::Header(kind) => {
                if !is_first {
                    report.findings.push(format!(
                        "a '{kind}' header appears past the first line and was ignored — the \
                         first line alone names the checkpoint and the rules this file is \
                         read under, and a later one would re-choose them for every run \
                         after it"
                    ));
                    continue;
                }
                header_seen = true;
                read_header(&value, &mut report);
                if report.unverifiable.is_some() {
                    return Ok(report);
                }
                if kind == DISCLOSURE_KIND {
                    read_selection(&value, &mut report);
                }
            }
            Line::Case => {
                read_case_block(&value, &mut report, &mut carried, &mut blob_digests);
            }
            Line::Run => {
                run_blocks += 1;
                finish_run(
                    &mut report,
                    pass.take(),
                    verifier,
                    &mut read_runs,
                    &mut empty_blocks,
                    observe,
                );
                pass = open_run_block(&value, &mut leaves, &mut report);
                if let Some(opened) = pass.as_mut() {
                    claim_once(opened, &mut blocks_of, &mut positions, &mut report);
                }
            }
            Line::End => read_trailer(&value, &mut report, &mut claims),
            // A line of a kind this build does not know is read as what the
            // format says an unframed line is — a record — and fails as one.
            Line::Record | Line::Unknown => {
                report.records += 1;
                let Some(pass) = pass.as_mut() else {
                    report.findings.push(
                        "a record appears before any run block, so nothing says which run it \
                         belongs to"
                            .into(),
                    );
                    continue;
                };
                read_record(&value, pass, &mut report, &mut stamped, upcaster);
            }
        }
    }
    finish_run(
        &mut report,
        pass,
        verifier,
        &mut read_runs,
        &mut empty_blocks,
        observe,
    );

    // Open runs are the blocks that contributed no leaf. Computed here because
    // this is the one place that holds both numbers, and passed on rather than
    // recounted.
    let open_runs = run_blocks.saturating_sub(leaves.len());
    settle(&mut report, header_seen, leaves, anchors);
    settle_trailer(
        &mut report,
        &claims,
        run_blocks,
        read_runs,
        open_runs,
        &empty_blocks,
    );
    settle_cases(&mut report, &stamped, &carried, blob_digests);
    Ok(report)
}

/// What one export line is, by its `kind` — the one classification both
/// readers of a file use, so the verifier and the restore cannot disagree about
/// which lines are records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line {
    /// The first line: `agentplane.export` or a package header, by name.
    Header(&'static str),
    Run,
    Case,
    End,
    /// No `kind` member: the format's one unframed line.
    Record,
    /// A `kind` this build does not know, or one that is not a string.
    Unknown,
}

impl Line {
    fn of(value: &serde_json::Value) -> Self {
        let Some(kind) = value.get("kind") else {
            return Self::Record;
        };
        match kind.as_str() {
            Some("agentplane.export") => Self::Header("agentplane.export"),
            Some(DISCLOSURE_KIND) => Self::Header(DISCLOSURE_KIND),
            Some("agentplane.export.run") => Self::Run,
            Some("agentplane.export.case") => Self::Case,
            Some("agentplane.export.end") => Self::End,
            _ => Self::Unknown,
        }
    }
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
    open_runs: usize,
    empty_blocks: &[RunId],
) {
    // Said here because `audit` says it about a live store, and these two
    // answer one question about one history: an open run has no Merkle leaf,
    // so nothing pins its tail and a truncation is undetectable until the run
    // seals. The offline reader is the one an independent auditor holds, so it
    // is the worse of the two to leave silent.
    //
    // Once per file rather than per run. A reader deciding what a clean report
    // is worth needs the count and the reason; a line per run buries both.
    if open_runs > 0 {
        report.not_checked.push(format!(
            "{open_runs} open run(s): a run that has not concluded has no position in the \
             Merkle log, so the root proves nothing about it — its chain and signatures \
             were verified, and records cut from its tail before the export was taken are \
             undetectable from this file"
        ));
    }
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
    if let Err(e) = case_hold(value) {
        report.findings.push(e);
    }
    if let Err(e) = case_erasure(value) {
        report.findings.push(e);
    }
    *blob_digests += value
        .get("blobs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
}

/// What this pass cannot answer, whatever the file turns out to contain.
///
/// The twin of the audit's own missing-evidence list, and it exists for the same
/// reason: a pass that quietly skips a question and then reports clean is the
/// reassuring-but-empty artifact this module is built to avoid. Two kinds sit
/// here — a check this invocation lacked an input for, and state the format
/// never carries at all.
fn unanswerable(report: &mut VerifyReport, verifier_supplied: bool) {
    if !verifier_supplied {
        report.not_checked.push(
            "signatures — no public key was supplied, so this pass cannot say who wrote \
             anything"
                .to_owned(),
        );
    }
    report
        .not_checked
        .extend(UNCARRIED.iter().map(|limit| (*limit).to_owned()));
}

/// Operational state this format never carries, named on every pass.
///
/// A restored plane's runs and cases come back; the rows beside them do not.
/// Said unconditionally rather than where something references them, because
/// these are properties of the *format* — a reader meeting a minimal artifact is
/// the one most likely to assume a clean report means a total restore.
///
/// Cursors and unconsumed decisions degrade safely, which is the argument for
/// leaving them out: a cursor costs repetition against receivers that already
/// deduplicate, and a decision is taken again under the same four-eyes and
/// expiry. The disclosure register is left out for its recipients' sake, and
/// its loss is that a restored plane's erasures name no earlier copy. Stating
/// each argument is what stops it from being a silence.
const UNCARRIED: [&str; 3] = [
    "webhook delivery cursors — this file carries no push registrations, so a restored plane \
     re-delivers from the start of each subscriber's history rather than from where it got \
     to. Receivers deduplicate on the event's own identity, so the cost is repetition rather \
     than loss",
    "worklist decisions no run has consumed — a decision recorded against a task and not yet \
     read back by the run it answers is a store row, not a record, so it does not survive \
     here. The task re-opens and is decided again under the same four-eyes and expiry",
    "the disclosure register — which matters left the plane, and to whom, is an operator \
     row, not a record, so a restored plane names no earlier disclosure in its erasures. \
     Carrying it would tell every recipient of an export who else received what",
];

/// The case layer's own settlement: coverage, and what a file cannot check.
///
/// The coverage rule has a deliberate asymmetry. A record stamped with a case
/// the file does not carry is a **finding** — this plane had a case layer (the
/// stamp proves it) and the export is missing a matter the journal names,
/// whether one case block is missing or all of them. The reverse is not: a
/// case whose runs are absent is the ordinary result of exporting a subset of
/// runs, and every case travels regardless of which runs were asked for.
fn settle_cases(
    report: &mut VerifyReport,
    stamped: &std::collections::BTreeSet<crate::core::CaseId>,
    carried: &std::collections::BTreeSet<crate::core::CaseId>,
    blob_digests: usize,
) {
    for case in stamped.difference(carried) {
        report.findings.push(format!(
            "case {case} is stamped on exported records and missing from the case layer — \
             the journal names a matter this file does not carry"
        ));
    }
    // A package proves the inclusion of what it carries, never completeness:
    // a matter its own header names and its case layer omits is the one
    // omission the file itself can show.
    let selected: Vec<crate::core::CaseId> = report
        .selection
        .as_ref()
        .map(|s| s.cases.clone())
        .unwrap_or_default();
    for case in selected {
        if !carried.contains(&case) {
            report.findings.push(format!(
                "case {case} is named by the package's selection and missing from its case \
                 layer — the package does not carry a matter it says it discloses"
            ));
        }
    }
    if carried.is_empty() {
        return;
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
///
/// A block is placed only when it carries both an integer `index` and a
/// `seal` that parses; one carrying either alone, or a seal that does not
/// parse, claims a position nothing can check, and is a finding rather than
/// an open run.
fn open_run_block(
    value: &serde_json::Value,
    leaves: &mut Vec<(u64, crate::core::merkle::LeafHash)>,
    report: &mut VerifyReport,
) -> Option<RunPass> {
    use crate::core::{Digest, merkle};
    use serde_json::Value;

    let run = value
        .get("run")
        .and_then(Value::as_str)
        .and_then(|s| RunId::parse(s).ok())?;
    let index = value.get("index").and_then(Value::as_u64);
    let declared_seal = value
        .get("seal")
        .and_then(|s| serde_json::from_value::<Digest>(s.clone()).ok());
    let placed = index.zip(declared_seal);
    let claims_place = value.get("index").is_some() || value.get("seal").is_some();
    let malformed = claims_place && placed.is_none();
    if malformed {
        report.findings.push(format!(
            "run {run}: its block claims a log position without both an integer index and a \
             seal that parses, so nothing can place it"
        ));
    }
    if let Some((index, seal)) = placed {
        leaves.push((index, merkle::leaf_hash(&seal)));
    }
    Some(RunPass {
        run,
        declared_seal: placed.map(|(_, seal)| seal),
        sealed: placed.is_some(),
        index,
        proof: value
            .get("proof")
            .and_then(|p| serde_json::from_value::<Vec<Digest>>(p.clone()).ok()),
        prev: Digest::ZERO,
        last_seq: 0,
        records: 0,
        resealed: Vec::new(),
        clean: !malformed,
    })
}

/// Hold a run block to the ones before it: a run is carried once and a log
/// position is claimed by one run. Either repeated leaves the block unsound,
/// and a run carried twice is withdrawn from the sound list its first block
/// earned, since neither block is the run's one history.
fn claim_once(
    pass: &mut RunPass,
    blocks_of: &mut std::collections::BTreeSet<RunId>,
    positions: &mut std::collections::BTreeSet<u64>,
    report: &mut VerifyReport,
) {
    if !blocks_of.insert(pass.run) {
        report.findings.push(format!(
            "run {}: the file carries it in two blocks, so neither is the run's one history",
            pass.run
        ));
        report.sound.retain(|run| *run != pass.run);
        pass.clean = false;
    }
    if pass.sealed
        && let Some(index) = pass.index
        && !positions.insert(index)
    {
        report.findings.push(format!(
            "log index {index} is claimed by two runs — one position in the log holds one leaf"
        ));
        pass.clean = false;
    }
}

/// The verifier's working state for the run block it is inside.
///
/// One struct rather than five parallel locals, because they reset together —
/// a new run block replaces all of them at once, and a field that survived the
/// boundary would carry one run's evidence into another's verdict.
struct RunPass {
    run: RunId,
    declared_seal: Option<crate::core::Digest>,
    /// Whether the block declared both a log position and a seal.
    sealed: bool,
    index: Option<u64>,
    /// A package's path for this leaf against the header's checkpoint.
    proof: Option<Vec<crate::core::Digest>>,
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

/// Hold the export's header to every anchor, and return one it matched.
///
/// Three answers, because the size relation decides which applies: an anchor
/// *above* the file, or of another log, names a history the file cannot be part
/// of; an anchor *at* the file's size either matches it or names a second
/// history of that size; and an anchor *below* it is checked against the
/// file's own first leaves, which the file carries — a mismatch is a finding,
/// and a match anchors the prefix and leaves the rest to the header, which is
/// said.
fn compare_anchors(
    report: &mut VerifyReport,
    header_seen: bool,
    anchors: &[crate::journal::Anchor],
    leaves: &[(u64, crate::core::merkle::LeafHash)],
) -> Option<Checkpoint> {
    let mut matched = None;
    if !header_seen {
        return matched;
    }
    for anchor in anchors {
        let given = &anchor.checkpoint;
        if given.origin != report.checkpoint.origin || given.size > report.checkpoint.size {
            report.findings.push(format!(
                "the export's header names log '{}' at size {} with root {}, and the \
                 checkpoint held by {} names '{}' at size {} with root {} — the file \
                 describes a different history than the one it is being checked against",
                report.checkpoint.origin,
                report.checkpoint.size,
                report.checkpoint.root.to_hex(),
                anchor.obtained_from,
                given.origin,
                given.size,
                given.root.to_hex(),
            ));
        } else if given.size == report.checkpoint.size {
            if given.root == report.checkpoint.root {
                if matched.is_none() {
                    matched = Some(given.clone());
                }
            } else {
                report.findings.push(format!(
                    "the export's header names log '{}' at size {} with root {}, and the \
                     checkpoint held by {} holds that same size with root {} — one tree of \
                     a given size has one root, so these are two histories",
                    report.checkpoint.origin,
                    report.checkpoint.size,
                    report.checkpoint.root.to_hex(),
                    anchor.obtained_from,
                    given.root.to_hex(),
                ));
            }
        } else if prefix_root(leaves, given.size) != Some(given.root) {
            report.findings.push(format!(
                "the checkpoint held by {} commits to the first {} run(s) of log '{}' with \
                 root {}, and this export's first {} run(s) do not rebuild to it — a run \
                 inside that prefix was removed, replaced or moved",
                anchor.obtained_from,
                given.size,
                given.origin,
                given.root.to_hex(),
                given.size,
            ));
        } else {
            report.not_checked.push(format!(
                "the checkpoint held by {} is at size {} and matches this export's first {} \
                 run(s); the {} after it are held only to the file's own header",
                anchor.obtained_from,
                given.size,
                given.size,
                report.checkpoint.size - given.size
            ));
        }
    }
    matched
}

/// The root of the tree of a file's first `size` leaves, when the file carries
/// exactly the positions `0..size` among them.
///
/// An export holds every leaf from position 0, so a checkpoint smaller than
/// the file is a tree the file can rebuild — no consistency proof is needed
/// for a reader who holds the leaves themselves. `leaves` is sorted by
/// position; a missing or duplicated position below `size` answers `None`.
fn prefix_root(
    leaves: &[(u64, crate::core::merkle::LeafHash)],
    size: u64,
) -> Option<crate::core::Digest> {
    let size = usize::try_from(size).ok()?;
    let prefix = leaves.get(..size)?;
    prefix
        .iter()
        .enumerate()
        .all(|(at, (index, _))| u64::try_from(at) == Ok(*index))
        .then(|| {
            crate::core::merkle::root(&prefix.iter().map(|(_, leaf)| *leaf).collect::<Vec<_>>())
        })
}

/// The checks that can only be made once the whole file has been read.
///
/// Separated because they answer a different question from the per-record pass:
/// that one asks *is each record what it says it is*, and every one of these
/// asks *is anything missing* — which no single line can reveal.
fn settle(
    report: &mut VerifyReport,
    header_seen: bool,
    mut leaves: Vec<(u64, crate::core::merkle::LeafHash)>,
    anchors: &[crate::journal::Anchor],
) {
    use crate::core::merkle;

    if anchors.iter().any(|a| !a.witnessed.is_empty()) {
        report.not_checked.push(
            "freshness — the anchors carry witness times and verify does not judge them; \
             `agentplane audit --max-checkpoint-age` does"
                .to_owned(),
        );
    }
    if report.selection.is_some() {
        settle_package(report, header_seen, leaves.len(), anchors);
        return;
    }

    // Which checkpoint the rebuild is held to, and everything below turns on
    // it. The header's own is a claim by whoever wrote the file; an anchor is
    // one the reader was given by somebody else — printed by an earlier audit,
    // cosigned by a witness, pasted into a ticket. Only the second makes the
    // Merkle rebuild evidence about *deletion*; against the header it is
    // evidence that the file is self-consistent, which an editor who dropped a
    // run and rewrote the header also achieves.
    //
    // **Every anchor is consulted, and what cannot be is said.** Three answers,
    // because the size relation decides which one applies: an anchor *above*
    // the file is a log that shrank, an anchor *at* the file's size either
    // matches it or names a different history, and an anchor *below* it is
    // rebuilt from the file's own first leaves. Collapsing any of them is what
    // lets an operator pick whichever observer their export happens to satisfy.
    leaves.sort_by_key(|(index, _)| *index);
    let matched = compare_anchors(report, header_seen, anchors, &leaves);
    let against = if let Some(checkpoint) = matched {
        checkpoint
    } else {
        if anchors.is_empty() {
            report.not_checked.push(
                "deletion — no checkpoint was supplied, so the Merkle root could only be \
                 rebuilt and compared against this file's own header. That proves the \
                 file is internally consistent, which is also what an editor who dropped \
                 a run and rewrote the header achieves. Pass the checkpoint an earlier \
                 audit printed, or one a witness cosigned"
                    .to_owned(),
            );
        }
        report.checkpoint.clone()
    };

    if !header_seen {
        report
            .findings
            .push("the export has no header, so nothing says which log it came from".into());
    }

    // The tree, rebuilt in log order. This is what notices a whole run dropped
    // from the middle: every per-run chain above still verified, because a chain
    // links records within a run and knows nothing about its neighbours.
    let size = u64::try_from(leaves.len()).unwrap_or(u64::MAX);
    if size == against.size {
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
            if rebuilt != against.root {
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
                against.size
            ));
        }
    } else {
        report.findings.push(format!(
            "the export carries {size} sealed run(s) and its checkpoint commits to {} — the \
             difference is runs that were in the log and are not in this file",
            against.size
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

/// A package's settlement: its header against each outside checkpoint, and
/// what the file does not disclose.
///
/// Each leaf was proved by its own path in [`finish_run`], so no tree is
/// rebuilt and no count is held to the checkpoint's size — the leaves a
/// package leaves out are the point of it, not a deletion. An outside
/// checkpoint of the header's size is compared by root; one of another size
/// would need a consistency proof the package does not carry, and is said to
/// be uncompared rather than judged.
fn settle_package(
    report: &mut VerifyReport,
    header_seen: bool,
    disclosed: usize,
    anchors: &[crate::journal::Anchor],
) {
    if !header_seen {
        report
            .findings
            .push("the export has no header, so nothing says which log it came from".into());
    }
    let header = report.checkpoint.clone();
    for anchor in anchors {
        let given = &anchor.checkpoint;
        if given.origin != header.origin {
            report.findings.push(format!(
                "the package's header names log '{}', and the checkpoint held by {} names \
                 '{}' — the file describes a different history than the one it is being \
                 checked against",
                header.origin, anchor.obtained_from, given.origin,
            ));
        } else if given.size != header.size {
            report.not_checked.push(format!(
                "the checkpoint held by {} is at size {} and the package's header at {}; a \
                 package carries no consistency proof, so the two were not compared",
                anchor.obtained_from, given.size, header.size,
            ));
        } else if given.root != header.root {
            report.findings.push(format!(
                "the package's header names log '{}' at size {} with root {}, and the \
                 checkpoint held by {} holds that same size with root {} — one tree of a \
                 given size has one root, so these are two histories",
                header.origin,
                header.size,
                header.root.to_hex(),
                anchor.obtained_from,
                given.root.to_hex(),
            ));
        }
    }
    if anchors.is_empty() {
        report.not_checked.push(
            "the header's checkpoint — no outside checkpoint was supplied, so each path was \
             proved against the file's own header, which whoever wrote the file chose. Pass \
             the checkpoint the plane published or a witness cosigned"
                .to_owned(),
        );
    }
    report.not_checked.push(format!(
        "the rest of the log — this file is a disclosure package: the log holds {} sealed \
         run(s) and the package proves {disclosed} of them; nothing about the others is in \
         the file or was checked",
        header.size
    ));
    if !report.complete {
        report.findings.push(
            "the export has no trailer, so it was cut short — every line in it is still valid, \
             which is why the frame is the signal"
                .to_owned(),
        );
    }
}

/// Why no digest in an export written under `canon` can be recomputed here,
/// when this build does not implement that rule.
///
/// The rule names the digest algorithm as well as the canonical form, so under
/// another one no hash in the file is one this build can check or rebuild.
fn canon_unverifiable(canon: Option<u64>) -> Option<String> {
    (canon != Some(u64::from(crate::core::canon::VERSION))).then(|| {
        format!(
            "unknown canon — the export was written under rule {canon:?} and this build \
             implements {}, so no digest in it can be recomputed here. Not a finding: a \
             build implementing that rule can verify and restore it",
            crate::core::canon::VERSION
        )
    })
}

/// Why this build cannot hold an export to its digests, when its header line
/// names a canon this build does not implement.
///
/// What `verify` reports as `unverifiable` and `restore` refuses before
/// writing, for a caller that must tell that answer apart from damage or an
/// outage before reading the whole file. Checked in `verify`'s order: a line
/// that is not this format's header, or names another format version, answers
/// `None`, and refusing it is the parser's.
#[must_use]
pub fn foreign_canon(header: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(header).ok()?;
    let ours = value.get("kind").and_then(serde_json::Value::as_str) == Some("agentplane.export")
        && value.get("version").and_then(serde_json::Value::as_u64)
            == Some(u64::from(FORMAT_VERSION));
    if !ours {
        return None;
    }
    canon_unverifiable(value.get("canon").and_then(serde_json::Value::as_u64))
}

/// Read a package header's selection; one naming nothing is a finding.
fn read_selection(value: &serde_json::Value, report: &mut VerifyReport) {
    let selection = value
        .get("selection")
        .and_then(|s| serde_json::from_value::<Selection>(s.clone()).ok())
        .filter(|s| !(s.cases.is_empty() && s.runs.is_empty()));
    if selection.is_none() {
        report.findings.push(
            "the package header names no case and no run, so nothing says what it was a \
             disclosure of"
                .to_owned(),
        );
    }
    report.selection = Some(selection.unwrap_or_default());
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
    if let Some(why) = canon_unverifiable(value.get("canon").and_then(serde_json::Value::as_u64)) {
        report.unverifiable = Some(why);
    }
    // The reason travels with the refusal: an origin no witness would accept
    // is refused by the deserializer naming the class, and "unreadable" alone
    // would leave the reader to guess which member it was.
    match value
        .get("checkpoint")
        .map(|c| serde_json::from_value::<Checkpoint>(c.clone()))
    {
        Some(Ok(c)) => report.checkpoint = c,
        Some(Err(e)) => report
            .findings
            .push(format!("the header's checkpoint is unreadable: {e}")),
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
    upcaster: &dyn crate::journal::Upcaster,
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
    // The hash first, then the parse. Bytes that do not hash to their claim
    // were edited, whatever they parse as; only bytes that do can make a parse
    // failure a statement about the reader rather than about the file.
    if crate::core::Digest::chain(pass.prev, raw_bytes) != claimed {
        return edited_record(raw_bytes, pass, report);
    }
    // Then the spelling, before a parse failure is believed: bytes that hash
    // to their claim and that no writer under this canon produces — a space, a
    // member out of order, a member written twice — are a statement about the
    // file, and the last would otherwise fail the parse and read as a skew.
    // Compared as values, so a record from another shape is held to the rule.
    if serde_json::from_slice::<serde_json::Value>(raw_bytes)
        .is_ok_and(|wire| crate::core::canon::value_bytes(&wire) != raw_bytes)
    {
        return uncanonical_record(raw_bytes, pass, report);
    }
    // The body verification reads is read from the wire bytes — the one
    // source the hash actually covers — through the upcaster, which compares
    // the record's version before its shape is believed: a record from another
    // shape is lifted, or refused as a skew, rather than failing a parse into
    // this build's struct and being judged by that.
    let signature = value
        .get("signature")
        .and_then(|a| serde_json::from_value::<Option<crate::core::KeySignature>>(a.clone()).ok())
        .flatten();
    let record = match crate::journal::Record::from_stored_with(
        upcaster,
        raw_bytes.to_vec(),
        pass.prev,
        claimed,
        signature,
    ) {
        Ok(record) => record,
        Err(unread) => return unread_record(raw_bytes, &unread, pass, report),
    };
    let body = &record.body;
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
    // The line's `seq` and `prev_hash` are copies too — of the body's position
    // and of the head before it — and held to them the same way, so the two
    // readers of this format agree that a line saying something its hashed
    // half does not is a finding rather than a field one of them ignores.
    let line_prev = value
        .get("prev_hash")
        .and_then(|h| serde_json::from_value::<crate::core::Digest>(h.clone()).ok());
    let line_seq = value.get("seq").and_then(serde_json::Value::as_u64);
    if line_prev != Some(pass.prev) || line_seq != Some(body.seq) {
        report.findings.push(format!(
            "run {current}: record {}'s line says seq {line_seq:?} after {}, and its wire \
             bytes and the chain say seq {} after {} — the line's copy was edited",
            body.seq,
            line_prev.map_or_else(|| "nothing".to_owned(), crate::core::Digest::to_hex),
            body.seq,
            pass.prev.to_hex()
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
    if let crate::journal::RecordKind::RunConcluded { chain_head, .. } = &body.kind
        && *chain_head != pass.prev
    {
        report.findings.push(format!(
            "run {current}: the sealing record claims a chain head that is not the head it \
             sits on — the conclusion was drawn over a different history"
        ));
        pass.clean = false;
    }

    pass.prev = record.hash;
    pass.resealed.push(record);
}

/// Members of a framing line this build does not know, reported as unchecked.
///
/// **A verdict is only as wide as the claims the reader understood.** A framing
/// line carries claims that are checked — a checkpoint, a leaf, the trailer's
/// accounting — so a member added by a later writer may carry one more, and a
/// reader that passes over it reports *sound* about a file it read part of.
///
/// This is `not_checked` rather than a finding, and the difference is the one
/// the record path draws for the same question. A record's bytes are hashed, so
/// a member nobody knows is refused: the verdict would otherwise be reached over
/// evidence the reader did not see. A framing line is not hashed and carries no
/// evidence of its own, so an unknown member does not falsify anything already
/// checked — it bounds what the check covered, which is what this field is for.
fn note_unknown_members(
    kind: &str,
    package: bool,
    value: &serde_json::Value,
    report: &mut VerifyReport,
) {
    let known: &[&str] = match kind {
        "agentplane.export" => &["kind", "version", "checkpoint", "canon"],
        DISCLOSURE_KIND => &["kind", "version", "checkpoint", "canon", "selection"],
        "agentplane.export.run" if package => &["kind", "run", "index", "seal", "proof"],
        "agentplane.export.run" => &["kind", "run", "index", "seal"],
        "agentplane.export.case" => &["kind", "case", "deadlines", "blobs", "hold"],
        "agentplane.export.end" => &[
            "kind",
            "runs_requested",
            "runs_exported",
            "records",
            "cases",
            "unreadable",
        ],
        // Not a frame: a record line carries no top-level `kind`, and its own
        // members are refused rather than noted, one level down.
        _ => return,
    };
    let Some(object) = value.as_object() else {
        return;
    };
    let unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|member| !known.contains(member))
        .collect();
    if !unknown.is_empty() {
        report.not_checked.push(format!(
            "a {kind} line carries {} this build does not know — whatever they claim was \
             not checked, and a later build wrote this file",
            unknown.join(", ")
        ));
    }
}

/// A record line whose bytes do not hash to the hash it carries.
///
/// Filed before any parse: whatever these bytes parse as, they are not the
/// bytes the chain committed to, so a parse failure here says nothing about
/// the reader's age.
fn edited_record(raw_bytes: &[u8], pass: &mut RunPass, report: &mut VerifyReport) {
    let seq = serde_json::from_slice::<serde_json::Value>(raw_bytes)
        .ok()
        .and_then(|v| v.get("seq").and_then(serde_json::Value::as_u64))
        .unwrap_or(pass.last_seq + 1);
    report.findings.push(format!(
        "run {}: record {seq} does not recompute to the hash it carries — it was edited \
         after it was sealed",
        pass.run
    ));
    pass.clean = false;
    // The head and the sequence walk forward over the bytes actually present,
    // so the leaf comparison at the end of the block speaks about what this
    // file carries rather than about the first mismatch.
    pass.prev = crate::core::Digest::chain(pass.prev, raw_bytes);
    pass.last_seq = seq;
}

/// A record whose bytes hash to their claim and are not canonical, filed as a
/// finding, with the head and sequence walked forward over the bytes present.
fn uncanonical_record(raw_bytes: &[u8], pass: &mut RunPass, report: &mut VerifyReport) {
    let seq = serde_json::from_slice::<serde_json::Value>(raw_bytes)
        .ok()
        .and_then(|v| v.get("seq").and_then(serde_json::Value::as_u64))
        .unwrap_or(pass.last_seq + 1);
    report.findings.push(format!(
        "run {}: record {seq}'s wire bytes are not canonical — they hash to their claim, \
         and no writer under the export's canon produces them",
        pass.run
    ));
    pass.clean = false;
    pass.prev = crate::core::Digest::chain(pass.prev, raw_bytes);
    pass.last_seq = seq;
}

/// A record line this reader cannot read, filed under what that means.
///
/// **A line this reader cannot read is not the same as a line nobody can.**
/// The hash was verified before this is reached, so the bytes are the ones the
/// chain committed to and a failure is a statement about the reader. A record
/// at a version the upcaster cannot reach, or at this build's version in a
/// shape it does not parse, is a build skew; answering *edited* or *malformed*
/// for either would report an export written by another build as a damaged
/// file, record by record, to the one audience that has no other copy. Only
/// bytes that are not a record at all are malformed.
fn unread_record(
    raw_bytes: &[u8],
    unread: &crate::core::StoreError,
    pass: &mut RunPass,
    report: &mut VerifyReport,
) {
    let current = pass.run;
    let at = serde_json::from_slice::<serde_json::Value>(raw_bytes)
        .ok()
        .and_then(|v| v.get("seq").and_then(serde_json::Value::as_u64));
    match unread {
        crate::core::StoreError::UnknownRecordVersion { .. } => {
            report.findings.push(format!(
                "run {current}: record {} is at a version this build does not read, and \
                 its bytes hash as written — this is a build skew rather than an edit: \
                 {unread}",
                at.unwrap_or(pass.last_seq + 1)
            ));
        }
        crate::core::StoreError::UnreadableRecordShape { .. } => {
            report.findings.push(format!(
                "run {current}: a record is at a shape this build does not read — a build \
                 skew rather than a damaged file: {unread}"
            ));
        }
        _ => report
            .findings
            .push(format!("run {current}: a record line is malformed")),
    }
    pass.clean = false;
    // The head and the sequence walk forward over what the file carries, so the
    // records after this one are compared against the history the file actually
    // holds. Without it one unreadable line makes every later record in the
    // block report a broken link and a gap — a cascade of incident-shaped
    // findings from one old reader.
    pass.prev = crate::core::Digest::chain(pass.prev, raw_bytes);
    if let Some(seq) = at {
        pass.last_seq = seq;
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
    observe: &mut dyn FnMut(ClosedRun<'_>),
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
        observe(ClosedRun {
            run,
            sealed: pass.sealed,
            records: &[],
        });
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

    // A package places every sealed run it carries, so a conclusion that
    // seals under a block with no leaf is a leaf stripped from the file.
    if report.selection.is_some()
        && !pass.sealed
        && crate::audit::has_sealing_conclusion(&pass.resealed)
    {
        report.findings.push(format!(
            "run {run}: it concluded under an outcome that seals and its block carries no \
             leaf — a package places every sealed run it carries, so this one's place in the \
             log was removed"
        ));
        ok = false;
    }

    // In a package no tree is rebuilt, so the path is the whole of the
    // evidence that this leaf is in the history the header names.
    if report.selection.is_some()
        && let Some(seal) = pass.declared_seal
        && !leaf_is_proved(seal, pass.index, pass.proof.as_deref(), &report.checkpoint)
    {
        report.findings.push(format!(
            "run {run}: its path does not prove its leaf against the header's checkpoint, so \
             nothing ties this run to the history the package names"
        ));
        ok = false;
    }

    // One implementation of *is this signed history sound*, and it is the
    // crate's own. `require_signature` is true because this is the auditor's
    // posture: an unsigned record inside a signed history is the one an
    // attacker who cannot sign would add.
    if let Some(v) = verifier
        && let Err(e) = crate::journal::Record::verify_signed(
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
    observe(ClosedRun {
        run,
        sealed: pass.sealed,
        records: &pass.resealed,
    });
}

/// Whether `proof` proves `seal` at `index` in the tree `checkpoint` commits to.
fn leaf_is_proved(
    seal: crate::core::Digest,
    index: Option<u64>,
    proof: Option<&[crate::core::Digest]>,
    checkpoint: &Checkpoint,
) -> bool {
    let (Some(index), Some(proof)) = (index, proof) else {
        return false;
    };
    let (Ok(index), Ok(size)) = (usize::try_from(index), usize::try_from(checkpoint.size)) else {
        return false;
    };
    crate::core::merkle::verify_inclusion(
        crate::core::merkle::leaf_hash(&seal),
        index,
        size,
        proof,
        &checkpoint.root,
    )
}

/// What a restore loses beyond the case layer, as sentences a reader can act
/// on.
///
/// Extracted so the restore's control flow is the *writing* and this is the
/// *accounting*. Each entry names one loss: a count of them would tell an
/// operator nothing about which one costs them work, and exactly one of these
/// does.
fn losses(parsed: &Parsed) -> Vec<String> {
    let mut out = Vec::new();
    if parsed.signed > 0 && !parsed.runs.is_empty() {
        out.push(format!(
            "{} record(s) carried a signature that this store did not reproduce — `append` \
             attests as the restoring store's own signer, so authorship is lost unless it \
             holds the original key. Hashes and the Merkle root are unaffected",
            parsed.signed
        ));
    }
    out.push(
        "activity timestamps — `recent_runs` now orders by restore time rather than by when \
         history happened. It is a discovery index for listing, and nothing derives a decision \
         from it"
            .to_owned(),
    );

    // Named whether or not this export happens to hold a waiting run. The
    // alternative — say it only when `awaiting` is non-empty — makes the
    // absence of the sentence mean two different things, and the reader who
    // needs it most is the one restoring an export they did not write.
    out.push(
        "every wait's registration — a timer, a subscription and any worklist row a wait \
         opened live in stores this export does not carry, so a restored run that was \
         waiting has nothing to wake it: no timer fires, no subscription matches, and its \
         lease was released cleanly when it suspended, so recovery does not see it either. \
         Resuming each run in `awaiting` re-arms the wait from the journal"
            .to_owned(),
    );
    out.push(
        "the worklist, unclaimed inbound events, webhook registrations and their delivery \
         cursors, governed memory, and the batch, quota and standing-authority ledgers — \
         none of these layers is in the export. A decision a run already consumed survives \
         because that run journaled it; one nobody had consumed does not"
            .to_owned(),
    );

    out
}

/// Which of the restored runs came back waiting.
///
/// Read with the same function every other surface answers *what does this
/// run's history say* with. A fourth copy of the match would be the copy that
/// disagrees the day a record kind arrives.
async fn awaiting_runs(
    store: &Arc<dyn JournalStore>,
    runs: &[RestoredRun],
) -> Result<Vec<RunId>, StoreError> {
    let mut awaiting = Vec::new();
    for run in runs {
        let records = store.read(run.run, 1).await?;
        if matches!(
            crate::runtime::observed_status(&records),
            Some(crate::runtime::RunStatus::Suspended(_))
        ) {
            awaiting.push(run.run);
        }
    }
    Ok(awaiting)
}

/// Every run the outcome indexes cannot name: the ones still in flight.
///
/// **Selecting what to export is two questions, and this is the second.**
/// `runs_by_outcome` indexes *conclusions*, so a run that has not concluded is
/// in no outcome, and an export driven by
/// [`OUTCOMES_OF_RECORD`](crate::runtime::OUTCOMES_OF_RECORD) alone carries no
/// run that is working, sleeping, awaiting a message or waiting on a person —
/// which is the work a disaster recovery is for. Nothing downstream can notice:
/// the Merkle log commits to **sealed** runs, so a file missing every in-flight
/// run restores to an equal root at an equal size and reports itself faithful.
///
/// **Paged, and bounded by `limit` like every other listing here.** It walks
/// every run by id ([`JournalStore::runs_by_id`]) and keeps the runs whose
/// history has not concluded, reading **one record** per candidate to decide:
/// the head's sequence, then that record. A run whose records cannot be read
/// is not silently dropped; it is returned in `unreadable` for the caller to
/// report, on the same principle as the export's own trailer.
///
/// # Errors
///
/// If the activity index cannot be paged. A single unreadable run is reported
/// rather than raised: one damaged run must not cost an operator the export of
/// every other.
pub async fn runs_in_flight(
    store: &Arc<dyn JournalStore>,
    limit: usize,
) -> Result<InFlight, StoreError> {
    let mut found = InFlight::default();
    // Pages of every run, not of the answer: most runs in a healthy plane have
    // concluded, so the page that yields one in-flight run may have held five
    // hundred that had ended. By id, because an id never moves: a run that
    // writes during the walk stays where the cursor will reach it.
    let mut after: Option<RunId> = None;
    while found.runs.len() < limit {
        let page = store.runs_by_id(after, CASE_PAGE).await?;
        if page.is_empty() {
            break;
        }
        after = page.last().copied();
        for run in page {
            if found.runs.len() == limit {
                found.truncated = true;
                return Ok(found);
            }
            let head = store.head(run).await?;
            if head.seq == 0 {
                continue;
            }
            // The last record alone. `read` is inclusive-from, so this is the
            // cheapest question the store answers about a run's state, and it
            // is the one `observed_status` needs.
            match store.read(run, head.seq).await {
                Ok(last) => {
                    // Working (`None` — the last record is neither a
                    // suspension nor a conclusion) and waiting
                    // (`Suspended`) are both in flight. Everything else has
                    // ended, and the wildcard is the arm that matters: a
                    // conclusion this build cannot interpret is still a
                    // conclusion, which `observed_status` guarantees by
                    // failing an unrecognised outcome closed into
                    // `Quarantined` rather than into `None`.
                    let in_flight = match crate::runtime::observed_status(&last) {
                        None | Some(crate::runtime::RunStatus::Suspended(_)) => true,
                        Some(_) => false,
                    };
                    if in_flight {
                        found.runs.push(run);
                    }
                }
                Err(e) => found.unreadable.push((run, e.to_string())),
            }
        }
    }
    Ok(found)
}

/// What [`runs_in_flight`] found, and what it could not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InFlight {
    /// Runs that had not concluded, by run id.
    pub runs: Vec<RunId>,
    /// The limit was reached, so this is a page rather than the set.
    pub truncated: bool,
    /// Runs the activity index names and whose records would not read.
    pub unreadable: Vec<(RunId, String)>,
}

/// The runs an offline reader of one tenant reads, and what it could not reach.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunsToRead {
    /// The runs, concluded ones by outcome first, then those in flight.
    pub runs: Vec<RunId>,
    /// Each outcome whose listing overflowed `limit`, and `"in-flight runs"`
    /// when that listing did.
    pub reached: Vec<String>,
    /// Runs the activity index names and whose records would not read.
    pub unreadable: Vec<(RunId, String)>,
    /// How many of `runs` are in flight.
    pub in_flight: usize,
}

/// The runs under `outcomes`, at most `limit` per outcome, plus the runs still
/// in flight when `include_in_flight`.
///
/// Each outcome is asked for one more than `limit`, so a full page and an
/// overflowing one are distinguishable and the overflow is named in
/// [`RunsToRead::reached`].
///
/// # Errors
///
/// If an index cannot be paged.
pub async fn runs_to_read(
    store: &Arc<dyn JournalStore>,
    outcomes: &[String],
    include_in_flight: bool,
    limit: usize,
) -> Result<RunsToRead, StoreError> {
    let mut found = RunsToRead::default();
    // Each run once. The outcome index keeps a run's last conclusion, so a run
    // quarantined and then resumed is listed under its outcome *and* in flight;
    // read twice, it is exported as two blocks claiming one run, which the
    // verifier reports as a file stitched from two histories.
    let mut listed = std::collections::HashSet::new();
    for outcome in outcomes {
        let runs = store.runs_by_outcome(outcome, limit + 1).await?;
        if runs.len() > limit {
            found.reached.push(outcome.clone());
        }
        found.runs.extend(
            runs.into_iter()
                .take(limit)
                .filter(|run| listed.insert(*run)),
        );
    }
    if include_in_flight {
        let flight = runs_in_flight(store, limit).await?;
        if flight.truncated {
            found.reached.push("in-flight runs".to_owned());
        }
        let fresh: Vec<RunId> = flight
            .runs
            .into_iter()
            .filter(|run| listed.insert(*run))
            .collect();
        found.in_flight = fresh.len();
        found.runs.extend(fresh);
        found.unreadable = flight.unreadable;
    }
    Ok(found)
}

/// One export file's runs, parsed from each record's `raw`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExportRuns {
    pub(crate) runs: Vec<(RunId, Vec<crate::journal::RecordBody>)>,
    pub(crate) unreadable: Vec<RunId>,
    /// The `agentplane.export.end` line was read.
    pub(crate) trailer: bool,
}

/// Why an export file could not be read.
#[derive(Debug)]
pub(crate) enum ReadError {
    Io(std::io::Error),
    NotAnExport(String),
}

/// Read an export's runs for an offline consumer.
///
/// Parsed from each record's `raw` — the bytes the chain hashed — never from
/// the display copy beside them. Integrity is not checked here; that is
/// [`verify`]'s, so a record that does not parse is reported as unreadable and
/// never named a build skew, which only hash-verified bytes can be.
pub(crate) fn read_runs<R: std::io::BufRead>(input: R) -> Result<ExportRuns, ReadError> {
    use serde_json::Value;
    let mut out = ExportRuns::default();
    let mut header = false;
    for (index, line) in input.lines().enumerate() {
        let line = line.map_err(ReadError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|e| ReadError::NotAnExport(format!("line {} is not JSON: {e}", index + 1)))?;
        match value.get("kind").and_then(Value::as_str) {
            Some("agentplane.export") => {
                let version = value.get("version").and_then(Value::as_u64);
                if Some(u64::from(FORMAT_VERSION)) != version {
                    return Err(ReadError::NotAnExport(format!(
                        "the export is at format version {version:?}, and this build reads \
                         {FORMAT_VERSION}"
                    )));
                }
                header = true;
            }
            Some(DISCLOSURE_KIND) if !header => {
                return Err(ReadError::NotAnExport(PACKAGE_REFUSED.to_owned()));
            }
            _ if !header => {
                return Err(ReadError::NotAnExport(
                    "the first line is not an agentplane export header".into(),
                ));
            }
            Some("agentplane.export.run") => {
                let run = value
                    .get("run")
                    .cloned()
                    .and_then(|r| serde_json::from_value::<RunId>(r).ok())
                    .ok_or_else(|| {
                        ReadError::NotAnExport(format!("line {} names no run", index + 1))
                    })?;
                out.runs.push((run, Vec::new()));
            }
            Some("agentplane.export.end") => {
                out.trailer = true;
                if let Some(list) = value.get("unreadable").and_then(Value::as_array) {
                    out.unreadable.extend(list.iter().filter_map(|u| {
                        u.get("run")
                            .cloned()
                            .and_then(|r| serde_json::from_value::<RunId>(r).ok())
                    }));
                }
            }
            Some(_) => {}
            None => {
                let raw = value.get("raw").and_then(Value::as_str).ok_or_else(|| {
                    ReadError::NotAnExport(format!("line {} carries no wire bytes", index + 1))
                })?;
                let upcaster = crate::journal::current_upcaster();
                let body =
                    crate::journal::RecordBody::read_through(upcaster.as_ref(), raw.as_bytes())
                        .map_err(|e| {
                            // No hash is checked here, so a parse failure is
                            // not evidence that another build wrote the bytes,
                            // and the skew's own wording would claim it was.
                            let why = match e {
                                StoreError::UnreadableRecordShape {
                                    kind,
                                    version,
                                    detail,
                                } => {
                                    format!(
                                        "its bytes name {kind} at v{version} and do not parse \
                                         as that shape ({detail}); this reader checks no hash, \
                                         so whether another build wrote them or they were \
                                         edited is `verify`'s to say"
                                    )
                                }
                                other => other.to_string(),
                            };
                            ReadError::NotAnExport(format!(
                                "line {} holds a record this build does not read: {why}",
                                index + 1
                            ))
                        })?;
                let Some((run, records)) = out.runs.last_mut() else {
                    return Err(ReadError::NotAnExport(format!(
                        "line {} is a record before any run block",
                        index + 1
                    )));
                };
                if body.run != *run {
                    return Err(ReadError::NotAnExport(format!(
                        "line {} belongs to run {}, filed under {run}",
                        index + 1,
                        body.run
                    )));
                }
                records.push(body);
            }
        }
    }
    if !header {
        return Err(ReadError::NotAnExport("the input is empty".into()));
    }
    Ok(out)
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
    /// Runs whose history ends in a wait, and which nothing will now wake.
    ///
    /// **Ids rather than a count, because the operator has to act on each
    /// one.** A wait is journaled but what performs it is not: the timer, the
    /// subscription and the task row live in stores this export does not
    /// carry. A restored suspended run has no timer to fire, no subscription
    /// to match, and released its lease cleanly when it suspended — so the
    /// recovery pass does not see it either. Nothing in the system names it,
    /// which is the state the runtime otherwise repairs on sight.
    ///
    /// Resuming each one repairs it: replay reaches the announced wait, finds
    /// no terminal record, and re-arms from the journal. That needs the
    /// agent's own code, so it is the caller's step and not the restore's.
    pub awaiting: Vec<RunId>,
    /// What did not survive, named rather than counted.
    pub not_carried: Vec<String>,
}

impl RestoreReport {
    /// Whether the rebuilt store commits to exactly the history the export did.
    ///
    /// **The commitment, not the label.** A checkpoint carries a log *identity*
    /// beside its size and root, and a recovery routinely changes that: the
    /// realistic restore is into another tenant of a database somebody else is
    /// already using, which is the topology `for_tenant` exists for. Comparing
    /// the identity made a byte-perfect restore report as a failed one exactly
    /// in the case a disaster puts an operator in — and `agentplane restore`
    /// exits on this predicate.
    ///
    /// A relabelling is not silent for being excluded: it is a sentence in
    /// [`not_carried`](Self::not_carried), beside every other thing the file
    /// could not bring across, and both checkpoints are on the report for a
    /// reader who wants to see the names.
    #[must_use]
    pub fn is_faithful(&self) -> bool {
        self.expected.size == self.rebuilt.size && self.expected.root == self.rebuilt.root
    }
}

/// Rebuild a store from an export, then prove it by its own checkpoint.
///
/// # Why this goes through `append` rather than writing rows
///
/// The obvious implementation inserts records verbatim and rebuilds each index
/// beside them. It is also the one that fails quietly: `append` maintains
/// several derived structures — the case index, the exactly-once index, the
/// outcome index and its ordering counter, the admission index, both halves of
/// the activity index — and a restore that reconstructed all but one of them
/// would produce a store that reads perfectly until somebody queries the one it
/// missed.
///
/// Deliberately not a count. A number here is a claim that has to be re-checked
/// on every edit and is not, so it goes stale silently and reads as coverage —
/// the shape this project catalogues and has been bitten by. Going through
/// `append` is what makes the list not need enumerating: whatever `append`
/// maintains, a restore maintains.
///
/// So this replays the ordinary write path, and every constraint the store
/// enforces is enforced here too. What travels through it is each record's
/// written bytes with its body ([`Append::restored`]): the store indexes the
/// body, lifted through the upcaster if the record is from an older shape, and
/// stores the bytes as written, so a restore across a shape change rebuilds
/// the chain that was exported rather than a re-seal of it. Three properties
/// make each record land at the position its bytes name:
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
/// Every loss is a sentence in [`RestoreReport::not_carried`], because the
/// reader who needs it is holding the report rather than this page. One of
/// them costs work rather than metadata and has its own field:
/// [`RestoreReport::awaiting`] names the runs that came back waiting, and says
/// there why nothing will wake them and what does.
///
/// # Errors
///
/// If the export cannot be read, if the store seals payloads as it writes,
/// or if the store already holds any of its runs — each refused before
/// anything is written: this rebuilds a history, it does not merge one. Also
/// if the store refuses a write, or if a rebuilt record's hash is not the one
/// the file claims; those land mid-restore and leave a partial store that a
/// retry refuses, so discard it and restore into a fresh one.
pub async fn from_jsonl<R: std::io::BufRead>(
    store: &Arc<dyn JournalStore>,
    cases: Option<&Arc<dyn crate::case::CaseStore>>,
    input: R,
) -> Result<RestoreReport, StoreError> {
    let upcaster = crate::journal::current_upcaster();
    from_jsonl_with(store, cases, input, upcaster.as_ref()).await
}

/// [`from_jsonl`], reading each record through `upcaster` rather than the one
/// this build ships.
///
/// A record at a version `upcaster` cannot reach is refused before anything is
/// written.
///
/// # Errors
///
/// As [`from_jsonl`].
pub async fn from_jsonl_with<R: std::io::BufRead>(
    store: &Arc<dyn JournalStore>,
    cases: Option<&Arc<dyn crate::case::CaseStore>>,
    input: R,
    upcaster: &dyn crate::journal::Upcaster,
) -> Result<RestoreReport, StoreError> {
    let parsed = parse(input, upcaster).map_err(|e| StoreError::Backend(e.to_string()))?;
    restore_parsed(store, cases, parsed).await
}

/// An export, restored into a store that lives only as long as the process.
///
/// The source a strict replay reads when it is handed a file rather than a
/// plane: every run the file holds, rebuilt through [`from_jsonl`] and so
/// checked against the file's own checkpoint, with nothing written to disk.
#[cfg(feature = "redb")]
#[derive(Debug)]
pub struct ReplaySource {
    pub store: Arc<crate::store::RedbStore>,
    /// The runs the file holds, in the order it lists them.
    pub runs: Vec<RunId>,
    pub report: RestoreReport,
}

/// Restore an export into memory for replay.
///
/// # Errors
///
/// If the file cannot be read or is refused by [`from_jsonl`], or if the
/// rebuilt store does not commit to the history the file claims.
#[cfg(feature = "redb")]
pub async fn open_for_replay<R: std::io::BufRead>(input: R) -> Result<ReplaySource, StoreError> {
    let upcaster = crate::journal::current_upcaster();
    let parsed = parse(input, upcaster.as_ref()).map_err(|e| StoreError::Backend(e.to_string()))?;
    let runs = parsed.runs.iter().map(|r| r.run).collect();
    let store = Arc::new(crate::store::RedbStore::open_in_memory()?);
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let cases = Arc::clone(&store) as Arc<dyn crate::case::CaseStore>;
    let report = restore_parsed(&journal, Some(&cases), parsed).await?;
    if !report.is_faithful() {
        return Err(StoreError::Backend(format!(
            "the export does not rebuild to its own checkpoint: it claims {} records under \
             root {}, and restoring it produced {} under {}",
            report.expected.size, report.expected.root, report.rebuilt.size, report.rebuilt.root
        )));
    }
    Ok(ReplaySource {
        store,
        runs,
        report,
    })
}

async fn restore_parsed(
    store: &Arc<dyn JournalStore>,
    cases: Option<&Arc<dyn crate::case::CaseStore>>,
    parsed: Parsed,
) -> Result<RestoreReport, StoreError> {
    refuse_before_writing(store, &parsed).await?;

    let mut records = 0usize;
    for run in &parsed.runs {
        let mut claimed = run.hashes.iter();
        // Grouped by epoch, in order. Each group is one `append` carrying that
        // group's own epoch, which is what reproduces the hashed bodies of a run
        // that changed owner mid-flight.
        for batch in run.records.chunk_by(|a, b| a.body.epoch == b.body.epoch) {
            let Some(epoch) = batch.first().map(|r| r.body.epoch) else {
                continue;
            };
            let appends: Vec<Append> = batch.iter().cloned().map(Append::restored).collect();
            records += appends.len();
            for (written, want) in store.append(epoch, appends).await?.iter().zip(&mut claimed) {
                if written.hash != *want {
                    return Err(StoreError::Backend(format!(
                        "run {} seq {} rebuilt to hash {} and the file claims {want} — the \
                         store is not reproducing the history it was handed, so the restore \
                         stopped there",
                        run.run,
                        written.seq(),
                        written.hash
                    )));
                }
            }
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
        let (Some(outcome), Some(epoch)) = (
            run.outcome.as_deref(),
            run.records.last().map(|r| r.body.epoch),
        ) else {
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
                if let Some(hold) = &block.hold {
                    case_store.place_hold(block.case.id, hold).await?;
                }
                if let Some(erasure) = &block.erasure {
                    restore_erasure(case_store.as_ref(), block.case.id, erasure).await?;
                }
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

    not_carried.extend(losses(&parsed));

    let awaiting = awaiting_runs(store, &parsed.runs).await?;

    let rebuilt = store.checkpoint().await?;
    if rebuilt.origin != parsed.checkpoint.origin {
        not_carried.push(format!(
            "the log identity — this history was written by '{}' and is now held by '{}'. \
             A legitimate recovery: a restore is pointed at a store, and one tenant's \
             history put back under another tenant's name is a different log with the \
             same contents. It is named because a checkpoint an auditor holds from \
             before the disaster will report the new log as the wrong one",
            parsed.checkpoint.origin, rebuilt.origin
        ));
    }

    Ok(RestoreReport {
        expected: parsed.checkpoint,
        rebuilt,
        runs: parsed.runs.len(),
        records,
        cases: imported,
        awaiting,
        not_carried,
    })
}

/// Every refusal a restore makes before its first write, so a refused restore
/// leaves nothing to clean up.
async fn refuse_before_writing(
    store: &Arc<dyn JournalStore>,
    parsed: &Parsed,
) -> Result<(), StoreError> {
    // A check `parse` leaves to its caller, because it is not about any one
    // line: a format this build does not read cannot be
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

    if let Some(why) = canon_unverifiable(parsed.canon) {
        return Err(StoreError::Backend(why));
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

    if store.seals() {
        return Err(StoreError::Backend(
            "the target store seals payloads as it writes them, and a restore must write \
             each record exactly as it was recorded — sealed payloads stay sealed under \
             their original keys. Restore into the unwrapped store, then open it with the \
             keyring"
                .to_owned(),
        ));
    }

    refuse_foreign_seals(parsed, store.tenant())?;
    // Every run before the first write: the store refuses a held run's records
    // on its own, but only once the runs ahead of it in the file are written.
    for run in &parsed.runs {
        if store.head(run.run).await?.seq != 0 {
            return Err(StoreError::Backend(format!(
                "this store already holds run {} — a restore rebuilds a history into an \
                 empty store, it does not merge one, so nothing was written",
                run.run
            )));
        }
    }
    Ok(())
}

/// Refuse a file whose sealed payloads or case states name another tenant.
///
/// An envelope's associated data and erasure scope both name the tenant that
/// sealed it, so under another tenant it opens for nobody and `erase_case`
/// there destroys a key that wraps none of it. Moving sealed history between
/// tenants needs a re-seal, which a restore cannot do.
fn refuse_foreign_seals(parsed: &Parsed, tenant: &str) -> Result<(), StoreError> {
    use crate::journal::payload::{self, SealedField};

    // Only an envelope that reads and names another tenant is refused. The
    // marker is a shape a clear payload can also have — an agent's input of
    // `{"$sealed": "x"}` is one — and its bytes are not an envelope at all:
    // refusing it would make an unsealed history unrestorable over a value a
    // caller typed. A genuine envelope always reads, because the key ring
    // wrote it.
    let foreign = |envelope: Option<Vec<u8>>, whose: &dyn std::fmt::Display| match envelope
        .as_deref()
        .and_then(payload::sealed_tenant)
    {
        Some(sealer) if sealer != tenant => Err(StoreError::Backend(format!(
            "{whose} carries a payload sealed for tenant '{sealer}', and this store serves \
                 '{tenant}' — under another tenant it opens for nobody and an erasure \
                 there would not reach it, so the file is refused before anything is written"
        ))),
        _ => Ok(()),
    };
    for run in &parsed.runs {
        for record in &run.records {
            let mut kind = record.body.kind.clone();
            for field in payload::payloads(&mut kind) {
                match field {
                    SealedField::Value(v) if payload::is_sealed(v) => {
                        foreign(payload::unwrap(v), &format!("run {}", run.run))?;
                    }
                    SealedField::Text(t) if payload::is_sealed_text(t) => {
                        foreign(payload::unwrap_text(t), &format!("run {}", run.run))?;
                    }
                    _ => {}
                }
            }
        }
    }
    for block in &parsed.cases {
        if payload::is_sealed(&block.case.state) {
            foreign(
                payload::unwrap(&block.case.state),
                &format!("case {}", block.case.id),
            )?;
        }
    }
    Ok(())
}

/// One run, as an export describes it.
struct RestoredRun {
    run: RunId,
    /// Position in the Merkle log; `None` for a run that was still open.
    index: Option<u64>,
    outcome: Option<String>,
    /// Each record as verified, carrying the bytes the restore writes back.
    records: Vec<crate::journal::Record>,
    /// Each body's hash as the file claims it, which the rebuilt record must
    /// reproduce.
    hashes: Vec<crate::core::Digest>,
    /// The chain head over the records read so far, which the next record's
    /// hash must extend.
    prev: crate::core::Digest,
}

/// One record line, once its bytes are known to be the ones the chain
/// committed to and at a version `upcaster` reads.
///
/// Both are conditions of replay rather than verification. Bytes the claimed
/// hash does not cover would rebuild a history the file never committed to,
/// and a record at a version no upcaster reaches has no body the store can
/// index — either way into a populated store, before the checkpoint comparison
/// could say so.
fn replayable(
    raw: &[u8],
    prev: crate::core::Digest,
    claimed: crate::core::Digest,
    upcaster: &dyn crate::journal::Upcaster,
) -> Result<crate::journal::Record, std::io::Error> {
    // A store keeps these bytes as they stand, so bytes that hash correctly
    // and are not canonical would land a record no writer under this canon
    // produces. Compared as values rather than as this build's record shape,
    // so a record from another shape is held to the same rule.
    if serde_json::from_slice::<serde_json::Value>(raw)
        .is_ok_and(|value| crate::core::canon::value_bytes(&value) != raw)
    {
        return Err(std::io::Error::other(
            "a record's wire bytes are not canonical — no writer under the export's canon \
             produces them, and a store would keep them as they stand, so the file is \
             refused before anything is written",
        ));
    }
    crate::journal::Record::from_stored_with(upcaster, raw.to_vec(), prev, claimed, None).map_err(
        |e| {
            std::io::Error::other(match e {
                StoreError::Corrupt { .. } => format!(
                    "a record's claimed hash does not cover its wire bytes and the chain \
                     before it ({e}) — replaying it would rebuild a history the export never \
                     committed to, so the file is refused before anything is written"
                ),
                StoreError::UnknownRecordVersion { .. } => format!(
                    "a record is at a version this build does not restore ({e}) — no \
                     upcaster reaches it, so the store could not index it as written, and \
                     the file is refused before anything is written"
                ),
                other => format!(
                    "a record line's wire bytes do not parse ({other}) — the record cannot be \
                     replayed as written, and its display copy is not a substitute"
                ),
            })
        },
    )
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
    hold: Option<crate::core::LegalHold>,
    erasure: Option<crate::case::Erasure>,
}

/// Mark a restored case erased as its export says, with the original instant
/// and reason.
///
/// Through the store's own erasure verbs, so a restored marker obeys the rules
/// a live one does: a case under hold or not closed is refused, which a sound
/// export never carries.
async fn restore_erasure(
    cases: &dyn crate::case::CaseStore,
    case: crate::core::CaseId,
    erasure: &crate::case::Erasure,
) -> Result<(), StoreError> {
    match cases
        .begin_erasure(case, erasure.at, &erasure.reason)
        .await?
    {
        crate::case::ErasureStart::Marked(_) => {}
        other => {
            return Err(StoreError::Backend(format!(
                "case {case}: the export says it was erased, and the restored case \
                 refuses the marker ({other:?}) — a case cannot be erased and held, \
                 or erased and open"
            )));
        }
    }
    if erasure.complete {
        cases.complete_erasure(case).await?;
    }
    Ok(())
}

/// A case block's erasure record: `null` for none, an
/// [`Erasure`](crate::case::Erasure) otherwise, and an error when the member is
/// missing or unreadable. Shared by the verifier and the restore.
fn case_erasure(value: &serde_json::Value) -> Result<Option<crate::case::Erasure>, String> {
    let Some(erasure) = value.get("erasure") else {
        return Err(
            "a case block carries no `erasure` member, so whether the matter was erased \
             is unknown"
                .to_owned(),
        );
    };
    serde_json::from_value::<Option<crate::case::Erasure>>(erasure.clone())
        .map_err(|e| format!("a case block's erasure record is malformed: {e}"))
}

/// A case block's hold: `null` for none, a [`LegalHold`](crate::core::LegalHold)
/// otherwise, and an error when the member is missing or unreadable.
///
/// Shared by the verifier and the restore so the two cannot disagree about
/// what a readable hold is.
fn case_hold(value: &serde_json::Value) -> Result<Option<crate::core::LegalHold>, String> {
    let Some(hold) = value.get("hold") else {
        return Err(
            "a case block carries no `hold` member, so whether the matter is under \
                    a legal hold is unknown"
                .to_owned(),
        );
    };
    serde_json::from_value::<Option<crate::core::LegalHold>>(hold.clone())
        .map_err(|e| format!("a case block's legal hold is malformed: {e}"))
}

/// One case block as a restore replays it, or `None` for a malformed block.
///
/// Malformed blocks are skipped and found by `verify`, per [`parse`]'s
/// no-checking rule — except an unreadable hold, which refuses the file.
fn restored_case(value: &serde_json::Value) -> Result<Option<RestoredCase>, std::io::Error> {
    use serde_json::Value;

    // A restore that refused the file would refuse the healthy cases too.
    let (Ok(case), Some(deadlines), Some(blobs)) = (
        serde_json::from_value::<crate::core::Case>(
            value.get("case").cloned().unwrap_or(Value::Null),
        ),
        value
            .get("deadlines")
            .and_then(|d| serde_json::from_value::<Vec<crate::core::Deadline>>(d.clone()).ok()),
        value
            .get("blobs")
            .and_then(|b| serde_json::from_value::<Vec<crate::core::Digest>>(b.clone()).ok()),
    ) else {
        return Ok(None);
    };
    // Refused before anything is written.
    let hold = case_hold(value).map_err(|e| {
        std::io::Error::other(format!(
            "case {}: {e} — restoring the matter without it would let retention \
                         erase it, so the file is refused",
            case.id
        ))
    })?;
    let erasure = case_erasure(value).map_err(|e| {
        std::io::Error::other(format!(
            "case {}: {e} — restoring the matter without it would bring an erased case \
             back as an ordinary one, so the file is refused",
            case.id
        ))
    })?;
    Ok(Some(RestoredCase {
        case,
        deadlines,
        blobs,
        hold,
        erasure,
    }))
}

/// Read an export into the shape a restore replays.
///
/// Checks what replay needs and nothing wider: [`verify`] answers *is this
/// sound* and this answers *what does it say*. Folding them would make a
/// restore refuse the very history an operator is trying to recover, at the
/// moment they most need it — and the right order is restore, then verify the
/// result against its own checkpoint, which [`from_jsonl`] reports.
///
/// What replay needs is every line: a line that is not JSON, of a kind this
/// build does not know, a run block naming no run, or a record outside any
/// block is refused rather than skipped, because skipping it restores a
/// history with that line missing. The run and record counts are held to the
/// trailer's, as [`verify`] holds them. And a record line must be *replayable
/// as written*: its wire bytes must be present and parse — the one available
/// guess otherwise, the editable display copy, is exactly the value the
/// wire-bytes rule exists to keep out of the rebuilt history — and they must be
/// the bytes its hash covers, at the version this build writes; see
/// [`replayable`]. All of it is decided here, before [`from_jsonl`] writes
/// anything.
fn parse<R: std::io::BufRead>(
    input: R,
    upcaster: &dyn crate::journal::Upcaster,
) -> Result<Parsed, std::io::Error> {
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
    // The trailer's counts, held against what was read once the file ends.
    let mut declared: Option<(Option<u64>, Option<u64>)> = None;
    let mut records = 0u64;
    let mut run_blocks = 0u64;
    for (number, line) in input.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            return Err(refused(format!(
                "line {} is not JSON, so whatever it carried would be lost",
                number + 1
            )));
        };
        match Line::of(&value) {
            Line::Header(DISCLOSURE_KIND) => return Err(std::io::Error::other(PACKAGE_REFUSED)),
            Line::Header(_) => {
                parsed.version = value.get("version").and_then(Value::as_u64);
                parsed.canon = value.get("canon").and_then(Value::as_u64);
                if let Some(c) = value.get("checkpoint") {
                    parsed.checkpoint =
                        serde_json::from_value::<Checkpoint>(c.clone()).map_err(|e| {
                            refused(format!("the header's checkpoint is unreadable: {e}"))
                        })?;
                }
            }
            Line::Run => {
                run_blocks += 1;
                let Some(run) = value
                    .get("run")
                    .and_then(Value::as_str)
                    .and_then(|s| RunId::parse(s).ok())
                else {
                    return Err(refused(format!(
                        "line {} is a run block naming no readable run, so the records under \
                         it belong to nothing",
                        number + 1
                    )));
                };
                parsed.runs.push(RestoredRun {
                    run,
                    index: value.get("index").and_then(Value::as_u64),
                    outcome: None,
                    records: Vec::new(),
                    hashes: Vec::new(),
                    prev: crate::core::Digest::ZERO,
                });
            }
            Line::Case => {
                if let Some(case) = restored_case(&value)? {
                    parsed.cases.push(case);
                }
            }
            Line::End => {
                parsed.complete = true;
                declared = Some((
                    value.get("runs_requested").and_then(Value::as_u64),
                    value.get("records").and_then(Value::as_u64),
                ));
            }
            // Record lines are the only unkinded lines in the format, so a
            // `kind` this build does not know is neither a frame it can read
            // nor a record it can replay — and skipping it would restore a
            // history with whatever it carried missing.
            Line::Unknown => {
                return Err(refused(format!(
                    "line {} is of a kind this build does not know ({})",
                    number + 1,
                    value.get("kind").map(Value::to_string).unwrap_or_default()
                )));
            }
            Line::Record => {
                records += 1;
                restore_record(&value, number, &mut parsed, upcaster)?;
            }
        }
    }
    if let Some(counts) = declared {
        held_to_trailer(counts, run_blocks, records)?;
    }
    Ok(parsed)
}

/// A refusal of the whole file, before anything is written.
fn refused(mut what: String) -> std::io::Error {
    what.push_str(
        " — a restore writes back every line or none, so the file is refused \
         before anything is written",
    );
    std::io::Error::other(what)
}

/// One record line, replayed into the run block it follows.
fn restore_record(
    value: &serde_json::Value,
    number: usize,
    parsed: &mut Parsed,
    upcaster: &dyn crate::journal::Upcaster,
) -> Result<(), std::io::Error> {
    use serde_json::Value;

    if value.get("signature").is_some_and(|a| !a.is_null()) {
        parsed.signed += 1;
    }
    // The wire bytes are the source of truth, exactly as they are for the
    // verifier: the readable `body` is a courtesy copy, and a restore
    // replaying the copy would rebuild whatever the display half said rather
    // than what the chain covered. There is deliberately **no fallback to
    // that copy**: a record line with no `raw`, or whose `raw` does not parse,
    // is a hard error rather than a skip or a guess — silently substituting
    // the one editable value two mechanisms must agree about would rebuild a
    // history the chain never hashed and let the subsequent verify pass bless
    // it.
    let Some(raw) = value.get("raw").and_then(Value::as_str) else {
        return Err(std::io::Error::other(
            "a record line carries no wire bytes (`raw`) — restoring its display \
             copy instead would rebuild what the readable half says rather than \
             what the chain hashed, so the file is refused instead of guessed at",
        ));
    };
    let Some(claimed) = value
        .get("hash")
        .and_then(|h| serde_json::from_value::<crate::core::Digest>(h.clone()).ok())
    else {
        return Err(std::io::Error::other(
            "a record line carries no hash — nothing ties its bytes to the chain, \
             so the file is refused instead of replayed",
        ));
    };
    let Some(current) = parsed.runs.last_mut() else {
        return Err(refused(format!(
            "line {} is a record before any run block, so nothing says which run it \
             belongs to",
            number + 1
        )));
    };
    let record = replayable(raw.as_bytes(), current.prev, claimed, upcaster)?;
    current.prev = claimed;
    if let crate::journal::RecordKind::RunConcluded { outcome, .. } = &record.body.kind {
        current.outcome = Some(outcome.clone());
    }
    current.records.push(record);
    current.hashes.push(claimed);
    Ok(())
}

/// The trailer's accounting, held as `verify` holds it: a file whose lines
/// were removed or added after it was taken restores a history the export
/// never described, and every line in it is valid on its own. A file with no
/// trailer is refused by the caller, which names the truncation.
fn held_to_trailer(
    declared: (Option<u64>, Option<u64>),
    run_blocks: u64,
    records: u64,
) -> Result<(), std::io::Error> {
    let (Some(requested), Some(written)) = declared else {
        return Err(refused(
            "the trailer is missing the run and record counts this format always writes, \
             so the file cannot be held to its own accounting"
                .to_owned(),
        ));
    };
    if requested != run_blocks {
        return Err(refused(format!(
            "the trailer says {requested} run(s) were requested and the file carries \
             {run_blocks} run block(s)"
        )));
    }
    if written != records {
        return Err(refused(format!(
            "the trailer says {written} record(s) were written and the file carries {records}"
        )));
    }
    Ok(())
}
