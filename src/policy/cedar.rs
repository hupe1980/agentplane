//! Cedar as the authorization engine.
//!
//! # Why Cedar and not a policy service
//!
//! [`PolicyEngine::authorize`](crate::core::PolicyEngine::authorize) is
//! synchronous and returns a decision rather than a `Result`, because a gate
//! that can fail open switches itself off exactly when a system is under stress.
//! That constraint rules out a network call and points at an embedded evaluator,
//! and Cedar is the one that is **total, side-effect free, and formally verified
//! in Lean** — so it can run before every effect without I/O, and
//! `cedar-policy-symcc` can *prove* properties of a policy set rather than test
//! them.
//!
//! The crate still ships no engine by default. This adapter lives behind the
//! `cedar` feature, and the seam stays the contract: an embedder with a
//! different evaluator implements the trait and nothing else changes.
//!
//! # A denial from a rule and a denial from a broken policy are different
//!
//! Cedar is total, which means a policy that *errors* during evaluation — a
//! missing attribute, a type mismatch — does not propagate an error. The request
//! is simply not satisfied, and the decision is `Deny`.
//!
//! That is the right default and a reporting trap. Both outcomes reach an
//! operator as "denied", but one means *the rules say no* and the other means
//! *the rules are broken and nobody noticed*. The second is an incident: every
//! request is being denied for a reason that has nothing to do with policy, and
//! the system looks like it is enforcing something it is not.
//!
//! So evaluation errors are pulled out of Cedar's diagnostics and reported
//! distinctly — in the reason string, and as a dedicated `tracing` event — while
//! still denying. Failing closed and saying why are not in tension.
//!
//! # Entity shape
//!
//! The runtime's vocabulary maps onto Cedar's directly, which is why the trait
//! was given that vocabulary in the first place:
//!
//! | Runtime | Cedar |
//! |---|---|
//! | `request.principal` | `Agent::"…"` |
//! | `request.action` | `Action::"effect:perform"` \| `Action::"run:admit"` |
//! | `request.resource` | `Resource::"…"` — an effect kind or a capability |
//! | `request.context` | the Cedar context record |
//!
//! Entities carry no attributes here. Attributes on a principal (its risk tier,
//! its group) belong to the deployment's identity system, and inventing them in
//! the adapter would mean two sources of truth about who an agent is. Everything
//! a rule needs about *this request* is in the context, including the delegation
//! chain's owner and depth (§11.1).

use std::str::FromStr;

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request};

use crate::core::{Digest, PolicyDecision, PolicyEngine, PolicyRequest};
use crate::runtime::telemetry;

/// A Cedar policy set, compiled once.
///
/// Compiled at construction rather than per request: parsing on every effect
/// would put a parser in the hot path and, worse, would make a malformed policy
/// a *runtime* failure at an arbitrary moment instead of a startup one.
#[derive(Debug)]
pub struct CedarEngine {
    policies: PolicySet,
    entities: Entities,
    digest: Digest,
}

/// Why a policy set could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    #[error("policy set does not parse: {0}")]
    Parse(String),
}

impl CedarEngine {
    /// Compile a policy set from Cedar source.
    ///
    /// # Errors
    ///
    /// If the source does not parse. Failing here — at startup, loudly — is the
    /// point: a policy set that cannot be compiled must never become a plane
    /// that denies everything for reasons nobody can see.
    pub fn new(source: &str) -> Result<Self, CedarError> {
        let policies = PolicySet::from_str(source).map_err(|e| CedarError::Parse(e.to_string()))?;
        let entities = Entities::empty();

        // Over the source text, so the journal records *which rules* governed a
        // run rather than which file was on disk. Two deployments with the same
        // rules produce the same digest; a whitespace change produces a
        // different one, which is the conservative direction — an audit that
        // says "the rules may have changed" is recoverable, one that says they
        // did not when they did is not.
        let mut framed = Vec::with_capacity(source.len() + 24);
        framed.extend_from_slice(b"agentplane.cedar.v1\0");
        framed.extend_from_slice(source.as_bytes());
        let digest = Digest::of(&framed);

        Ok(Self {
            policies,
            entities,
            digest,
        })
    }

    /// Build the Cedar request, or say why the runtime's strings could not be
    /// expressed as entities.
    fn request(r: &PolicyRequest<'_>) -> Result<Request, String> {
        let principal = uid("Agent", r.principal)?;
        let action = uid("Action", r.action)?;
        let resource = uid("Resource", r.resource)?;
        let context = Context::from_json_value(r.context.clone(), None)
            .map_err(|e| format!("context is not a Cedar record: {e}"))?;
        Request::new(principal, action, resource, context, None)
            .map_err(|e| format!("request is not well formed: {e}"))
    }
}

/// `Type::"id"`, with the id quoted so a name containing `.` or `/` survives.
///
/// Effect kinds look like `mcp.tools/call`, which is not a bare Cedar
/// identifier. Quoting is not cosmetic: without it the parse fails and every
/// request involving that effect would be denied for a reason that reads like a
/// policy decision.
fn uid(kind: &str, id: &str) -> Result<EntityUid, String> {
    let escaped = id.replace('\\', "\\\\").replace('"', "\\\"");
    EntityUid::from_str(&format!("{kind}::\"{escaped}\""))
        .map_err(|e| format!("'{id}' is not a usable Cedar entity id: {e}"))
}

impl PolicyEngine for CedarEngine {
    fn authorize(&self, request: &PolicyRequest<'_>) -> PolicyDecision {
        // A request the adapter cannot even express is a denial, and a loud one:
        // it is a bug here or in the caller, not a rule firing.
        let req = match Self::request(request) {
            Ok(r) => r,
            Err(why) => {
                tracing::error!(
                    target: telemetry::POLICY_DENIED,
                    action = %request.action,
                    resource = %request.resource,
                    malformed = true,
                    %why,
                );
                return PolicyDecision::deny(format!(
                    "the authorization request could not be expressed for evaluation \
                     ({why}) — this is a defect, not a rule: every request of this \
                     shape is being denied"
                ));
            }
        };

        let answer = Authorizer::new().is_authorized(&req, &self.policies, &self.entities);

        // Errors first, whatever the decision. Cedar is total: a policy that
        // fails to evaluate simply does not contribute, so a broken rule set
        // yields a clean-looking `Deny`. Reporting that as an ordinary refusal
        // is how a plane spends a week enforcing nothing.
        let errors: Vec<String> = answer
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            tracing::error!(
                target: telemetry::POLICY_DENIED,
                action = %request.action,
                resource = %request.resource,
                policy_error = true,
                detail = %errors.join("; "),
            );
        }

        match answer.decision() {
            cedar_policy::Decision::Allow if errors.is_empty() => PolicyDecision::Permit,
            // Permitted *and* something failed to evaluate. The permit stands —
            // a policy that did evaluate said yes — but the broken rule is
            // reported, because the next thing it fails to evaluate may be a
            // `forbid`.
            cedar_policy::Decision::Allow => PolicyDecision::Permit,
            cedar_policy::Decision::Deny if !errors.is_empty() => PolicyDecision::deny(format!(
                "denied while {} policy error(s) went unevaluated: {} — fix the \
                 policy set; this denial may not mean what it appears to",
                errors.len(),
                errors.join("; ")
            )),
            cedar_policy::Decision::Deny => {
                let determining: Vec<String> = answer
                    .diagnostics()
                    .reason()
                    .map(ToString::to_string)
                    .collect();
                if determining.is_empty() {
                    // Cedar denies by default when nothing permits. Saying so
                    // beats "denied by policy", which sends someone hunting for
                    // a `forbid` that does not exist.
                    PolicyDecision::deny(format!(
                        "no policy permits '{}' on '{}'",
                        request.action, request.resource
                    ))
                } else {
                    PolicyDecision::deny(format!(
                        "'{}' on '{}' refused by {}",
                        request.action,
                        request.resource,
                        determining.join(", ")
                    ))
                }
            }
        }
    }

    fn digest(&self) -> Digest {
        self.digest
    }
}
