//! A matter leaving the plane: the disclosure act, the register that holds it,
//! and the one function that writes a package only once the act is recorded.
//!
//! # The register's rung
//!
//! A disclosure act is an **unchained operator row**, the same rung as a legal
//! hold or a halt: a mutable row in a tenant-scoped store, on no hash chain.
//! Whoever administers that store can edit or delete a row and nothing detects
//! it. So an erasure that names a disclosure repeats the operator's own row,
//! and an erasure that names none does not show that nothing was disclosed.
//! Every surface that names an act says where the name came from.
//!
//! # Before any byte
//!
//! The act names the digest of the bytes that leave, and it is recorded before
//! any byte reaches the destination. Both hold only because the package is
//! written to a private file beside the destination first: digested as it is
//! written, the act recorded, and only then moved into place. A failure to
//! record removes the file and nothing is delivered — a copy with no act is
//! the silent copy an erasure cannot name.

use std::sync::Arc;

use async_trait::async_trait;

use crate::core::{CaseId, Digest, Operator, RunId, StoreError, Timestamp};
use crate::export::Selection;
use crate::journal::{Checkpoint, JournalStore};

/// One disclosure: what left, to whom, sealed or not, under which checkpoint,
/// the digest of the bytes, and who made it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    /// Minted when the act is recorded.
    pub id: String,
    /// The runs the package carried — the selection as resolved, never the
    /// case alone, because a case's runs grow after the package is written.
    pub runs: Vec<RunId>,
    /// The cases whose blocks the package carried.
    pub cases: Vec<CaseId>,
    /// Who received it, as the operator named them.
    pub recipient: String,
    /// Whether any record travelled with a sealed payload. Decides what an
    /// erasure can say about the copy.
    pub sealed: bool,
    /// The checkpoint every path in the package is against.
    pub checkpoint: Checkpoint,
    /// SHA-256 of the delivered bytes.
    pub package: Digest,
    pub by: Operator,
    pub at: Timestamp,
}

impl Disclosure {
    /// Whether this act carried `case` or any of `runs`.
    #[must_use]
    pub fn covers(&self, cases: &[CaseId], runs: &[RunId]) -> bool {
        self.cases.iter().any(|c| cases.contains(c)) || self.runs.iter().any(|r| runs.contains(r))
    }

    /// The sentence an erasure reports for this copy.
    #[must_use]
    pub fn after_erasure(&self) -> String {
        let reach = if self.sealed {
            "the copy carried sealed payloads, and those sealed under the erased key become \
             unopenable; anything travelling unsealed, and the fields the journal keeps in the \
             clear, stay readable in the copy"
        } else {
            "a plaintext copy this erasure cannot reach"
        };
        format!(
            "disclosed to {} on {} by {} — {reach} (named from the operator's disclosure \
             register, an unchained row)",
            self.recipient,
            self.at,
            self.by.actor()
        )
    }
}

/// Where disclosure acts are kept: one register per tenant, for case-bound
/// and case-less runs alike.
#[async_trait]
pub trait DisclosureRegister: Send + Sync + std::fmt::Debug {
    /// Keep one act.
    ///
    /// # Errors
    ///
    /// If the store is unreachable or refuses the write; the caller then
    /// delivers nothing.
    async fn record(&self, act: &Disclosure) -> Result<(), StoreError>;

    /// Every act that carried any of `cases` or `runs`, oldest first.
    ///
    /// # Errors
    ///
    /// If the store is unreachable.
    async fn disclosures(
        &self,
        cases: &[CaseId],
        runs: &[RunId],
    ) -> Result<Vec<Disclosure>, StoreError>;
}

/// What the caller of [`disclose`] asks for.
#[derive(Debug, Clone)]
pub struct Request {
    pub selection: Selection,
    pub recipient: String,
    pub by: Operator,
    pub at: Timestamp,
}

/// Why nothing was delivered.
#[derive(Debug, thiserror::Error)]
pub enum DiscloseError {
    #[error("the package could not be written: {0}")]
    Write(#[from] std::io::Error),
    #[error("the disclosure could not be recorded, so nothing was delivered: {0}")]
    Unrecorded(StoreError),
}

/// Write a package of `request.selection` to `destination`, recording the act
/// before any byte reaches it.
///
/// The package is written to a private file beside `destination`, digested,
/// synced to disk, the act recorded, and the file then renamed into place. A
/// failure at any step removes the private file and leaves `destination`
/// untouched. A destination that is a directory, or whose parent is not one,
/// is refused before anything is recorded, so the reasons a rename can be
/// foreseen to fail never leave a recorded act undelivered.
///
/// A process killed between staging and rename leaves the private file,
/// `.<name>.dsc_<ulid>.partial` beside `destination`; nothing reads it back
/// and it may be deleted. An act recorded and then not delivered — the rename
/// refused, or a caller's onward copy to a closed pipe — stays recorded: the
/// register names every package that may have left, never only the ones that
/// arrived.
///
/// # Errors
///
/// [`DiscloseError::Write`] for a selection naming nothing this plane holds, a
/// destination that cannot receive a file, or a failure to write; [`DiscloseError::Unrecorded`] when the register refuses.
pub async fn disclose(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn crate::case::CaseStore>,
    register: &dyn DisclosureRegister,
    request: &Request,
    destination: &std::path::Path,
) -> Result<Disclosure, DiscloseError> {
    // An operator row's key, not a journaled observation: nothing replays it.
    #[allow(clippy::disallowed_methods)]
    let id = format!("dsc_{}", ulid::Ulid::generate());
    receivable(destination).map_err(DiscloseError::Write)?;
    let staging = staging_path(destination, &id);
    let result = stage_and_record(store, cases, register, request, &id, &staging).await;
    match result {
        Ok(act) => match std::fs::rename(&staging, destination) {
            Ok(()) => Ok(act),
            Err(e) => {
                let _ = std::fs::remove_file(&staging);
                Err(DiscloseError::Write(e))
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&staging);
            Err(e)
        }
    }
}

async fn stage_and_record(
    store: &Arc<dyn JournalStore>,
    cases: &Arc<dyn crate::case::CaseStore>,
    register: &dyn DisclosureRegister,
    request: &Request,
    id: &str,
    staging: &std::path::Path,
) -> Result<Disclosure, DiscloseError> {
    let file = private_file(staging)?;
    let mut out = Digesting::new(std::io::BufWriter::new(file));
    let package =
        crate::export::package_to_jsonl(store, cases, &request.selection, &mut out).await?;
    let (buffered, package_digest) = out.finish()?;
    buffered
        .into_inner()
        .map_err(std::io::IntoInnerError::into_error)?
        .sync_all()?;
    let act = Disclosure {
        id: id.to_owned(),
        runs: package.runs,
        cases: package.cases,
        recipient: request.recipient.clone(),
        sealed: package.sealed,
        checkpoint: package.checkpoint,
        package: package_digest,
        by: request.by.clone(),
        at: request.at,
    };
    register
        .record(&act)
        .await
        .map_err(DiscloseError::Unrecorded)?;
    Ok(act)
}

/// Whether `destination` can be renamed onto: not a directory, and beside
/// one that exists.
fn receivable(destination: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if destination.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "{} is a directory, not a file a package can be written to",
                destination.display()
            ),
        ));
    }
    let parent = match destination.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => std::path::Path::new("."),
    };
    if !parent.is_dir() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!(
                "{} is not a directory a package can be written into",
                parent.display()
            ),
        ));
    }
    Ok(())
}

/// The private file a package is staged in: beside `destination`, so the
/// final rename stays on one filesystem.
fn staging_path(destination: &std::path::Path, id: &str) -> std::path::PathBuf {
    let name = destination
        .file_name()
        .map_or_else(|| "package".into(), |n| n.to_string_lossy().into_owned());
    destination.with_file_name(format!(".{name}.{id}.partial"))
}

/// Created new, readable by its owner alone.
fn private_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// A writer that digests every byte it passes on.
struct Digesting<W: std::io::Write> {
    inner: W,
    hasher: sha2::Sha256,
}

impl<W: std::io::Write> Digesting<W> {
    fn new(inner: W) -> Self {
        use sha2::Digest as _;
        Self {
            inner,
            hasher: sha2::Sha256::new(),
        }
    }

    fn finish(mut self) -> std::io::Result<(W, Digest)> {
        use sha2::Digest as _;
        self.inner.flush()?;
        let bytes: [u8; 32] = self.hasher.finalize().into();
        Ok((self.inner, Digest::from_bytes(bytes)))
    }
}

impl<W: std::io::Write> std::io::Write for Digesting<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest as _;
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
