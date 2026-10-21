//! The one YAML reader: every manifest, token file and content rule goes
//! through these options.
//!
//! Each setting is a parse-time control on a reviewed document, so they live
//! here once rather than at every call site, where one caller with the
//! defaults would accept what the others refuse.
//!
//! * **YAML 1.2 booleans.** Only `true` and `false`. YAML 1.1 read `no` as
//!   `false`, so a grant written `mutates: no` would be read-only — the
//!   permissive direction — from a word nobody meant as a boolean.
//! * **A key written twice is refused.** First-wins and last-wins both hide a
//!   line a reviewer read.
//! * **Merge keys are refused.** `<<: *base` puts what a block says somewhere
//!   other than its own lines.
//! * **A tag never selects a variant.** An enum is a word or a one-key map, so
//!   the YAML and JSON spellings of one document cannot mean different things.
//! * **Aliases are bounded.** A few hundred bytes of nested aliases can name
//!   hundreds of millions of nodes. A declaration is small; the bound is set
//!   for that, not for data files.
//!
//! `!include` and `${NAME}` interpolation are features of the parser this
//! build does not enable, so a manifest can name neither another file nor the
//! environment.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, Options};

/// Replayed alias events a document may cost, across all of its aliases.
const MAX_REPLAYED_EVENTS: usize = 100_000;

fn options() -> Options {
    let mut options = Options::default();
    options.strict_booleans = true;
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Error;
    options.reject_unsupported_tags = true;
    options.alias_limits.max_total_replayed_events = MAX_REPLAYED_EVENTS;
    options
}

/// Read one document.
///
/// A refusal names the field it is about, then the parser's line and snippet:
/// a reviewer fixing `spec.tools[2].mutates` should not have to count list
/// items to find it.
pub(crate) fn from_str<T: DeserializeOwned>(yaml: &str) -> Result<T, String> {
    let mut path = None;
    serde_saphyr::with_deserializer_from_str_with_options(yaml, options(), |de| {
        serde_path_to_error::deserialize(de).map_err(|e| {
            path = Some(e.path().to_string());
            e.into_inner()
        })
    })
    .map_err(|e| located(path.as_deref(), &e))
}

/// Read a value one of [`documents`] returned into its type, naming the field
/// a refusal is about.
pub(crate) fn from_value<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, String> {
    serde_path_to_error::deserialize(value)
        .map_err(|e| located(Some(&e.path().to_string()), e.inner()))
}

/// Read every non-empty document in a `---`-separated file, in order.
///
/// A refusal names the document it is in, counted from the parser's own
/// document starts rather than from `---` lines, which a block scalar can hold.
pub(crate) fn documents(yaml: &str) -> Result<Vec<serde_json::Value>, String> {
    serde_saphyr::from_multiple_with_options(yaml, options()).map_err(|e| {
        match e.location().map(|at| at.line()) {
            Some(line) => format!("document {}: {e}", document_at(yaml, line)),
            None => e.to_string(),
        }
    })
}

/// Which document (1-based) the given 1-based line falls in.
fn document_at(yaml: &str, line: u64) -> usize {
    let mut ordinal = 0;
    for event in serde_saphyr::granit_parser::Parser::new_from_str(yaml) {
        let Ok((event, span)) = event else { break };
        if u64::try_from(span.start.line()).unwrap_or(u64::MAX) > line {
            break;
        }
        if matches!(event, serde_saphyr::granit_parser::Event::DocumentStart(..)) {
            ordinal += 1;
        }
    }
    ordinal.max(1)
}

/// The field first, when there is one: `.` is the document itself.
fn located(path: Option<&str>, error: &dyn std::fmt::Display) -> String {
    match path {
        Some(path) if path != "." => format!("{path}: {error}"),
        _ => error.to_string(),
    }
}

/// Write one document.
pub(crate) fn to_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_saphyr::to_string(value).map_err(|e| e.to_string())
}
