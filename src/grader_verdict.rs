//! A grader's verdict, bound to the records it was reached from.
//!
//! A sidecar is a file beside an export, never a record: it binds opaque
//! verdict bytes from somebody outside this plane to `(run, last_seq,
//! last_hash, open)`. `last_hash` is the chain hash of the run's record at
//! `last_seq`, so it commits to records `1..=last_seq` of that run and to
//! nothing after them. The declaration, policy bundle and canonicalization
//! rule the run was admitted under are inside that prefix, so the check
//! displays them from the export rather than carrying a second copy.
//!
//! This module binds and checks; it never reads, scores or stores a verdict.
//! A bound sidecar proves which records a verdict names and which key signed
//! it — not what the grader saw, and not that the verdict is right.

use std::collections::BTreeMap;
use std::io::BufRead;

use serde::{Deserialize, Serialize};

use crate::core::{
    DOMAIN_GRADER_VERDICT, Digest, KeySignature, PolicyBundleIdentity, RunId, Signer, Verifier,
    canon, signing_hash,
};
use crate::export::{ClosedRun, VerifyReport, verify_observed};
use crate::journal::{AgentIdentity, Anchor, Record, RecordKind};

/// The sidecar format's version.
pub const FORMAT_VERSION: u16 = 1;

/// The sidecar's `kind` member.
pub const KIND: &str = "agentplane.grader-verdict";

/// One grader verdict and the prefix of one run it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecar {
    /// Always [`KIND`].
    pub kind: String,
    /// Always [`FORMAT_VERSION`].
    pub version: u16,
    /// The run the verdict is about.
    pub run: RunId,
    /// The last record of the bound prefix.
    pub last_seq: u64,
    /// The chain hash of the record at `last_seq`.
    pub last_hash: Digest,
    /// `false` claims the run was sealed with `last_seq` as its last record.
    pub open: bool,
    /// The verdict, as bytes this crate never interprets.
    #[serde(with = "content")]
    pub content: Vec<u8>,
    /// The grader's signature over [`Sidecar::signing_digest`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<KeySignature>,
}

mod content {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::core::b64::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        crate::core::b64::decode(&text).ok_or_else(|| D::Error::custom("content is not base64"))
    }
}

impl Sidecar {
    /// Read a sidecar, refusing another kind, another version or a member
    /// this format does not define.
    ///
    /// # Errors
    ///
    /// A sentence naming what is wrong with the file.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let sidecar: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if sidecar.kind != KIND {
            return Err(format!("kind is '{}', not '{KIND}'", sidecar.kind));
        }
        if sidecar.version != FORMAT_VERSION {
            return Err(format!(
                "version {} is not {FORMAT_VERSION}",
                sidecar.version
            ));
        }
        Ok(sidecar)
    }

    /// What a grader signs: the canonical bytes of the sidecar without its
    /// signature, under [`DOMAIN_GRADER_VERDICT`].
    #[must_use]
    pub fn signing_digest(&self) -> Digest {
        let unsigned = Self {
            signature: None,
            ..self.clone()
        };
        let bytes = canon::to_bytes(&unsigned).expect("a sidecar serialises");
        signing_hash(DOMAIN_GRADER_VERDICT, &Digest::of(&bytes))
    }

    /// Sign as `signer`, replacing any signature.
    pub fn sign(&mut self, signer: &dyn Signer) {
        self.signature = Some(signer.signature_over(&self.signing_digest()));
    }
}

/// Why a binding could not be made.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("the export could not be read: {0}")]
    Unreadable(#[from] std::io::Error),
    #[error("the export carries no run {0}")]
    NoSuchRun(RunId),
    #[error("run {0} does not verify in this export, so a binding to it binds nothing")]
    NotSound(RunId),
    #[error("run {run} has no record at seq {last_seq} in this export")]
    NoSuchRecord { run: RunId, last_seq: u64 },
}

/// The runs a pass saw, by id: whether each block declared a seal, and its
/// records.
type Seen = BTreeMap<RunId, (bool, Vec<Record>)>;

fn observe_runs<R: BufRead>(
    export: R,
    verifier: Option<&dyn Verifier>,
    anchors: &[Anchor],
    wanted: &[RunId],
) -> std::io::Result<(VerifyReport, Seen)> {
    let mut seen = Seen::new();
    let upcaster = crate::journal::current_upcaster();
    let report = verify_observed(
        export,
        verifier,
        anchors,
        upcaster.as_ref(),
        &mut |closed: ClosedRun<'_>| {
            if wanted.contains(&closed.run) {
                seen.insert(closed.run, (closed.sealed, closed.records.to_vec()));
            }
        },
    )?;
    Ok((report, seen))
}

/// Bind `content` to the prefix of `run` ending at `last_seq` (by default its
/// last record present), as an unsigned sidecar.
///
/// # Errors
///
/// A run the export does not carry or that does not verify, or a `last_seq`
/// naming no record present.
pub fn bind<R: BufRead>(
    export: R,
    run: RunId,
    last_seq: Option<u64>,
    content: Vec<u8>,
) -> Result<Sidecar, BindError> {
    let (report, seen) = observe_runs(export, None, &[], &[run])?;
    let Some((sealed, records)) = seen.get(&run) else {
        return Err(BindError::NoSuchRun(run));
    };
    if !report.sound.contains(&run) {
        return Err(BindError::NotSound(run));
    }
    let last = records.last().map_or(0, |r| r.body.seq);
    let last_seq = last_seq.unwrap_or(last);
    let Some(at) = records.iter().find(|r| r.body.seq == last_seq) else {
        return Err(BindError::NoSuchRecord { run, last_seq });
    };
    let open = !(*sealed && last_seq == last);
    Ok(Sidecar {
        kind: KIND.to_owned(),
        version: FORMAT_VERSION,
        run,
        last_seq,
        last_hash: at.hash,
        open,
        content,
        signature: None,
    })
}

/// What one sidecar was found to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The binding re-derives, the run verifies, and a supplied grader key
    /// signed it.
    Bound,
    /// A component does not hold; see [`SidecarReport::component`].
    Refused,
    /// The binding re-derives and the run verifies, but no grader key was
    /// supplied, so who signed it was not checked.
    NotChecked,
}

/// The part of a sidecar a refusal names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Format,
    Run,
    Soundness,
    LastSeq,
    LastHash,
    Open,
    Signature,
}

/// What the run was admitted under, read from the bound prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrefixWarrant {
    pub declaration: Option<AgentIdentity>,
    pub policy_bundle: Option<PolicyBundleIdentity>,
    pub canon: u16,
}

/// One sidecar's verdict, beside the export's own report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SidecarReport {
    /// The run named, when the sidecar could be read.
    pub run: Option<RunId>,
    pub status: Status,
    /// What a refusal names.
    pub component: Option<Component>,
    /// The reason, in words.
    pub reason: String,
    /// The verdict's length; it is never interpreted.
    pub content_bytes: usize,
    /// The admission inside the prefix; `None` when the prefix carries none.
    pub warrant: Option<PrefixWarrant>,
    /// Records the export holds past `last_seq`.
    pub records_past_prefix: u64,
    /// Whether the prefix holds payloads sealed under a key — erased data
    /// the grader could not have read from this export.
    pub sealed_payloads: bool,
}

/// An export's report and each sidecar's, from one pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Checked {
    pub export: VerifyReport,
    pub sidecars: Vec<SidecarReport>,
}

impl Checked {
    /// Whether any sidecar was refused.
    #[must_use]
    pub fn any_refused(&self) -> bool {
        self.sidecars.iter().any(|s| s.status == Status::Refused)
    }
}

/// Verify `export` and check every sidecar against it in the same pass.
///
/// `graders` holds the keys a grader signature may verify under — a trust set
/// separate from the record keys in `verifier`.
///
/// # Errors
///
/// Only for a failure to read the export.
pub fn check<R: BufRead>(
    export: R,
    verifier: Option<&dyn Verifier>,
    anchors: &[Anchor],
    sidecars: &[Vec<u8>],
    graders: Option<&dyn Verifier>,
) -> std::io::Result<Checked> {
    let parsed: Vec<Result<Sidecar, String>> = sidecars.iter().map(|b| Sidecar::parse(b)).collect();
    let wanted: Vec<RunId> = parsed.iter().flatten().map(|s| s.run).collect();
    let (report, seen) = observe_runs(export, verifier, anchors, &wanted)?;
    let sidecars = parsed
        .iter()
        .map(|sidecar| match sidecar {
            Err(e) => SidecarReport {
                run: None,
                status: Status::Refused,
                component: Some(Component::Format),
                reason: format!("not a grader-verdict sidecar: {e}"),
                content_bytes: 0,
                warrant: None,
                records_past_prefix: 0,
                sealed_payloads: false,
            },
            Ok(sidecar) => check_one(sidecar, &report, &seen, graders),
        })
        .collect();
    Ok(Checked {
        export: report,
        sidecars,
    })
}

#[allow(clippy::too_many_lines)]
fn check_one(
    sidecar: &Sidecar,
    report: &VerifyReport,
    seen: &Seen,
    graders: Option<&dyn Verifier>,
) -> SidecarReport {
    let mut out = SidecarReport {
        run: Some(sidecar.run),
        status: Status::Refused,
        component: None,
        reason: String::new(),
        content_bytes: sidecar.content.len(),
        warrant: None,
        records_past_prefix: 0,
        sealed_payloads: false,
    };
    let refuse = |mut out: SidecarReport, component, reason: String| {
        out.component = Some(component);
        out.reason = reason;
        out
    };
    let run = sidecar.run;
    let Some((sealed, records)) = seen.get(&run) else {
        return refuse(
            out,
            Component::Run,
            format!("the export carries no run {run}"),
        );
    };
    if !report.sound.contains(&run) {
        return refuse(
            out,
            Component::Soundness,
            format!("run {run} does not verify in this export, so the binding binds nothing"),
        );
    }
    let Some(at) = records.iter().find(|r| r.body.seq == sidecar.last_seq) else {
        return refuse(
            out,
            Component::LastSeq,
            format!("run {run} has no record at seq {}", sidecar.last_seq),
        );
    };
    if at.hash != sidecar.last_hash {
        return refuse(
            out,
            Component::LastHash,
            format!(
                "the record at seq {} of run {run} is not the one the verdict was bound to",
                sidecar.last_seq
            ),
        );
    }
    let last = records.last().map_or(0, |r| r.body.seq);
    if !sidecar.open && (!*sealed || last != sidecar.last_seq) {
        return refuse(
            out,
            Component::Open,
            format!(
                "the sidecar claims run {run} sealed at seq {}, and the export does not",
                sidecar.last_seq
            ),
        );
    }
    let prefix = || {
        records
            .iter()
            .take_while(|r| r.body.seq <= sidecar.last_seq)
    };
    out.warrant = prefix().find_map(|r| match r.kind() {
        RecordKind::RunAdmitted {
            governed_by,
            policy_bundle,
            canon,
            ..
        } => Some(PrefixWarrant {
            declaration: governed_by.as_deref().cloned(),
            policy_bundle: policy_bundle.as_deref().cloned(),
            canon: *canon,
        }),
        _ => None,
    });
    out.records_past_prefix = last.saturating_sub(sidecar.last_seq);
    out.sealed_payloads = prefix().any(|r| {
        serde_json::to_value(r.kind())
            .as_ref()
            .is_ok_and(holds_sealed)
    });
    let Some(graders) = graders else {
        out.status = Status::NotChecked;
        "the binding holds; no grader key was supplied, so who signed the verdict was \
         not checked"
            .clone_into(&mut out.reason);
        return out;
    };
    let Some(signature) = &sidecar.signature else {
        return refuse(
            out,
            Component::Signature,
            "the sidecar is unsigned and a grader key was supplied".to_owned(),
        );
    };
    if !graders.verify(
        &signature.key_id,
        &sidecar.signing_digest(),
        &signature.signature,
    ) {
        return refuse(
            out,
            Component::Signature,
            format!(
                "the signature does not verify under grader key '{}'",
                signature.key_id
            ),
        );
    }
    out.status = Status::Bound;
    out.reason = format!(
        "binds records 1..={} of run {run} and was signed by grader key '{}' — not what \
         the grader saw, and not whether the verdict is right",
        sidecar.last_seq, signature.key_id
    );
    out
}

fn holds_sealed(value: &serde_json::Value) -> bool {
    crate::journal::payload::is_sealed(value)
        || match value {
            serde_json::Value::Object(map) => map.values().any(holds_sealed),
            serde_json::Value::Array(items) => items.iter().any(holds_sealed),
            _ => false,
        }
}
