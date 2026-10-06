//! What a consulted agent may do, derived from its registered declaration.
//!
//! The section an approval of a consultation carries. A pure function of the
//! callee's manifest, so the digest a reviewer approves covers exactly what
//! the declaration permits, and a redeployed callee is a different digest.

use crate::core::{DeclaredReach, Digest, ReachGrant};
use crate::manifest::Manifest;

/// The reach `manifest` declares, under `digest`.
///
/// One level: a grant naming another agent or a peer (`consults` says which
/// server names are peers) is listed and marked, and its reach is not
/// followed.
pub(crate) fn declared(
    manifest: &Manifest,
    digest: Digest,
    consults: impl Fn(&str) -> bool,
) -> DeclaredReach {
    let grants = manifest
        .spec
        .tools
        .iter()
        .map(|grant| ReachGrant {
            reference: grant.reference.clone(),
            mutates: grant.mutates,
            requires_approval: grant.requires_approval,
            consults: crate::tools::ToolId::parse(&grant.reference)
                .is_some_and(|id| id.server == crate::tools::AGENT_SERVER || consults(&id.server)),
        })
        .collect();
    DeclaredReach {
        agent: manifest.metadata.name.clone(),
        version: manifest.metadata.version.clone(),
        digest,
        grants,
        budgets: serde_json::to_value(&manifest.spec.budgets).expect("declared budgets serialize"),
        max_delegation_depth: manifest.spec.security.max_delegation_depth,
    }
}
