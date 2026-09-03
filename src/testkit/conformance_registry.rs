//! One contract, run against every manifest registry.
//!
//! A registry is not a lookup table with rules bolted on; the rules **are** the
//! registry. The npm and `PyPI` incidents were not parser bugs, they were a name
//! resolving to content nobody reviewed — so a backend that stores and serves
//! correctly and gets *one* of these wrong has removed the only reason to have
//! a registry at all.
//!
//! The properties, in the order they matter:
//!
//! * **a published version is immutable** — re-publishing the same name and
//!   version with different content is refused, not overwritten, because "we
//!   reviewed 1.2.0" must be a statement about an artifact rather than about a
//!   moment;
//! * **identical content is the same publish** — a retried deploy is not an
//!   attack, and making it look like one trains people to force;
//! * **a pin is checked against recomputed content**, not against a stored
//!   digest, or the check confirms only that the registry agrees with itself;
//! * **an unsigned artifact may adopt its first attestation, and never change
//!   publisher** — signing arriving later is ordinary, one identity being
//!   silently replaced by another is not;
//! * **verification recomputes the digest** from the manifest that came back,
//!   so a registry serving altered bytes fails rather than passing on its own
//!   bookkeeping;
//! * **the inventory is enumerable** — *which agents does this organisation
//!   run* is the first question a governance function asks, and a registry that
//!   cannot answer it is one that gets maintained a second time somewhere else.

use crate::core::{Digest, Signer, Verifier};
use crate::manifest::{Manifest, Registry, RegistryError};

use super::conformance::Report;

/// Two manifests that differ, under one name and version.
///
/// The difference is a **budget**, not a comment: a registry comparing
/// something other than the canonical digest would pass a whitespace-only
/// change and fail this one, which is the discrimination under test.
fn manifest(name: &str, version: &str, tokens: u64) -> Manifest {
    Manifest::parse(&format!(
        "
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: {name}, version: '{version}' }}
spec:
  capabilities: {{ provides: [work.do] }}
  budgets: {{ max_tokens: {tokens} }}
"
    ))
    .expect("the battery's own fixtures are well-formed")
}

/// Run the battery against one registry.
///
/// The registry must be empty of the names this uses — `conformance-a` and
/// `conformance-b` — since this publishes under them.
pub async fn check(
    registry: &dyn Registry,
    signer: &dyn Signer,
    other_signer: &dyn Signer,
    verifier: &dyn Verifier,
    report: &mut Report,
) {
    immutability(registry, report).await;
    pinning(registry, report).await;
    publisher(registry, signer, other_signer, verifier, report).await;
    inventory(registry, report).await;
}

/// The refusal that makes a version number mean something.
async fn immutability(registry: &dyn Registry, report: &mut Report) {
    let first = manifest("conformance-a", "1.0.0", 1000);

    report.checked += 1;
    let Ok(digest) = registry.publish(&first).await else {
        report.record(
            "a fresh name and version accepts a publish",
            "publishing into an empty registry failed",
        );
        return;
    };

    report.checked += 1;
    match registry.publish(&first).await {
        Ok(again) if again == digest => {}
        Ok(_) => report.record(
            "identical content is the same publish",
            "re-publishing the same manifest returned a different digest, so a \
             retried deploy is not idempotent",
        ),
        Err(e) => report.record(
            "identical content is the same publish",
            format!(
                "re-publishing identical content was refused with `{e}` — a retried \
                 deploy is not an attack, and making it look like one trains people \
                 to force"
            ),
        ),
    }

    report.checked += 1;
    let changed = manifest("conformance-a", "1.0.0", 2000);
    match registry.publish(&changed).await {
        Err(RegistryError::Immutable {
            existing, offered, ..
        }) => {
            report.checked += 1;
            if existing == offered {
                report.record(
                    "the refusal names both digests",
                    "the refusal reported one digest twice, so 'what changed' \
                     still needs guessing",
                );
            }
        }
        Err(e) => report.record(
            "a published version is immutable",
            format!("re-publishing different content failed as `{e}` rather than as Immutable"),
        ),
        Ok(_) => report.record(
            "a published version is immutable",
            "different content replaced a published version, so 'we reviewed \
             1.0.0' is a statement about a moment rather than about an artifact",
        ),
    }

    report.checked += 1;
    match registry.resolve("conformance-a", "1.0.0").await {
        Ok(m) => {
            if m.spec.budgets.as_ref().and_then(|b| b.max_tokens) != Some(1000) {
                report.record(
                    "a refused publish changes nothing",
                    "the refusal was reported and the content changed anyway",
                );
            }
        }
        Err(e) => report.record("a published manifest resolves", format!("{e}")),
    }

    report.checked += 1;
    match registry.resolve("conformance-a", "9.9.9").await {
        Err(RegistryError::NotFound { .. }) => {}
        Err(e) => report.record(
            "an unpublished version is NotFound",
            format!("resolving an unpublished version failed as `{e}`"),
        ),
        Ok(_) => report.record(
            "an unpublished version is NotFound",
            "a version nobody published resolved to something",
        ),
    }
}

/// The caller declining to need the registry's promise.
async fn pinning(registry: &dyn Registry, report: &mut Report) {
    let published = manifest("conformance-a", "1.0.0", 1000);
    let digest = published.digest().expect("a fixture digests");

    report.checked += 1;
    if let Err(e) = registry
        .resolve_pinned("conformance-a", "1.0.0", digest)
        .await
    {
        report.record(
            "a matching pin resolves",
            format!("the digest this registry returned did not satisfy a pin on it: {e}"),
        );
    }

    report.checked += 1;
    let wrong = Digest::of(b"not this manifest");
    match registry
        .resolve_pinned("conformance-a", "1.0.0", wrong)
        .await
    {
        Err(RegistryError::PinBroken { .. }) => {}
        Err(e) => report.record(
            "a broken pin is refused",
            format!("a mismatched pin failed as `{e}` rather than as PinBroken"),
        ),
        Ok(_) => report.record(
            "a broken pin is refused",
            "content that does not match the pin was returned — the pin is the \
             only form of this control that survives the registry being the \
             compromised party",
        ),
    }
}

/// *Who* published it, which no digest can answer.
async fn publisher(
    registry: &dyn Registry,
    signer: &dyn Signer,
    other_signer: &dyn Signer,
    verifier: &dyn Verifier,
    report: &mut Report,
) {
    report.checked += 1;
    match registry
        .resolve_verified("conformance-a", "1.0.0", verifier)
        .await
    {
        Err(RegistryError::Unsigned { .. }) => {}
        Err(e) => report.record(
            "an unsigned publish is Unsigned, not BadSignature",
            format!(
                "resolving an unsigned manifest failed as `{e}` — the two call for \
                 opposite responses: one is an operational fact, the other says \
                 somebody tampered"
            ),
        ),
        Ok(_) => report.record(
            "a verifying resolve refuses an unsigned publish",
            "a manifest nobody signed passed a verifying resolve",
        ),
    }

    // Signing arriving later is ordinary: the artifact is immutable, and
    // deleting it to attach a signature is not an option.
    report.checked += 1;
    let published = manifest("conformance-a", "1.0.0", 1000);
    if let Err(e) = registry.publish_signed(&published, signer).await {
        report.record(
            "an unsigned artifact adopts its first attestation",
            format!("signing an already-published identical artifact was refused: {e}"),
        );
    }

    report.checked += 1;
    match registry
        .resolve_verified("conformance-a", "1.0.0", verifier)
        .await
    {
        Ok((m, key)) => {
            report.checked += 1;
            if key.is_empty() {
                report.record(
                    "a verified resolve names the key",
                    "'it verified' is not the whole answer — which identity signed \
                     it is what a caller decides to trust",
                );
            }
            if m.metadata.name != "conformance-a" {
                report.record(
                    "a verified resolve returns the manifest asked for",
                    "the verified resolve returned a different manifest",
                );
            }
        }
        Err(e) => report.record(
            "a signed publish verifies",
            format!("a manifest this registry signed did not verify: {e}"),
        ),
    }

    report.checked += 1;
    match registry.publish_signed(&published, other_signer).await {
        Err(RegistryError::PublisherChanged { .. }) => {}
        Err(e) => report.record(
            "a publisher cannot be silently replaced",
            format!("a second signer was refused as `{e}` rather than as PublisherChanged"),
        ),
        Ok(_) => report.record(
            "a publisher cannot be silently replaced",
            "identical content was re-attributed to a different identity, so \
             'who published this' answers whoever wrote last",
        ),
    }
}

/// The question a governance function asks first.
async fn inventory(registry: &dyn Registry, report: &mut Report) {
    let second = manifest("conformance-b", "2.0.0", 500);
    let also = manifest("conformance-b", "2.1.0", 500);
    let _ = registry.publish(&second).await;
    let _ = registry.publish(&also).await;

    report.checked += 1;
    match registry.versions("conformance-b").await {
        Ok(versions) => {
            if !(versions.contains(&"2.0.0".to_owned()) && versions.contains(&"2.1.0".to_owned())) {
                report.record(
                    "every published version of a name is listed",
                    format!("expected both published versions, got {versions:?}"),
                );
            }
            report.checked += 1;
            if versions.contains(&"1.0.0".to_owned()) {
                report.record(
                    "versions are scoped to their name",
                    format!("another name's version appeared under this one: {versions:?}"),
                );
            }
        }
        Err(e) => report.record("versions are listable", format!("{e}")),
    }

    report.checked += 1;
    match registry.names().await {
        Ok(names) => {
            for expected in ["conformance-a", "conformance-b"] {
                if !names.contains(&expected.to_owned()) {
                    report.record(
                        "every published name is listed",
                        format!("'{expected}' is published and does not appear in {names:?}"),
                    );
                }
            }
            report.checked += 1;
            let mut sorted = names.clone();
            sorted.sort();
            sorted.dedup();
            if names != sorted {
                report.record(
                    "names are sorted and unique",
                    format!(
                        "an inventory has one row per agent, in an order somebody can \
                         scan: {names:?}"
                    ),
                );
            }
        }
        Err(e) => report.record("names are listable", format!("{e}")),
    }
}
