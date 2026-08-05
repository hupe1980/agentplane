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
//! A bundle may carry deliberately static Cedar entities and attributes. Live
//! identity and facts about *this request* remain in context, including the
//! delegation chain's owner and depth; copying those into static entities
//! would create a stale second source of truth.
//!
//! # The admission context
//!
//! A `run:admit` request carries the governing declaration under `agent`, which
//! a schema for that action must therefore allow:
//!
//! ```text
//! context.agent.name       the declared name — for reading, never for granting
//! context.agent.version    the declared version
//! context.agent.digest     hex over the manifest's canonical bytes
//! context.agent.publisher  the KeyId that vouched for it, or absent
//! ```
//!
//! Bind rules to `publisher` for a set of agents and to `digest` for one exact
//! revision. Not to `name`: a manifest is a file, and its name is whatever its
//! author typed, so a rule granting authority to a name grants it to anyone who
//! types that name.
//!
//! A schema declaring `run:admit` with `"additionalAttributes": false` and no
//! `agent` attribute will reject every admission. That surfaces as a *defect*
//! rather than an ordinary denial — the adapter says so in the reason, because a
//! request it cannot express is a wiring bug and not a rule firing.

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema, ValidationMode, Validator,
};

use crate::core::{
    Digest, PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest, canon,
};
use crate::runtime::telemetry;

/// Decision semantics pinned into every Cedar bundle identity.
///
/// Cargo cannot expose a dependency's version through `env!`, so this stays
/// deliberately explicit and is guarded against `Cargo.toml` by a test. The
/// adapter revision covers entity mapping, schema-aware context parsing, and
/// the set of Cedar extensions made available by 4.12.
pub const EVALUATOR_SEMANTICS: &str =
    "cedar-policy/4.12.0;agentplane-adapter/2;extensions=all-available";

const ADAPTER_CONFIGURATION: &[u8] =
    b"principal=Agent;action=Action;resource=Resource;context=action-schema";

/// A Cedar policy set, compiled once.
///
/// Compiled at construction rather than per request: parsing on every effect
/// would put a parser in the hot path and, worse, would make a malformed policy
/// a *runtime* failure at an arbitrary moment instead of a startup one.
#[derive(Debug)]
pub struct CedarEngine {
    policies: PolicySet,
    entities: Entities,
    schema: Option<Schema>,
    bundle: PolicyBundleIdentity,
}

/// Why a policy set could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    #[error("policy set does not parse: {0}")]
    Parse(String),
    #[error("Cedar schema does not parse: {0}")]
    Schema(String),
    #[error("policy set does not validate against its schema: {0}")]
    Validation(String),
    #[error("static Cedar entities do not parse against the bundle schema: {0}")]
    Entities(String),
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
        Self::from_bundle(source, None, None)
    }

    /// Compile a complete Cedar policy bundle.
    ///
    /// A declared schema is used to validate the policies at startup, parse
    /// static entities, parse each request context, and construct the request.
    /// Static entities are the facts intentionally frozen into this bundle;
    /// per-call facts remain in [`PolicyRequest::context`].
    ///
    /// # Errors
    ///
    /// If rules/schema/entities do not parse, or the policies do not validate
    /// strictly against the schema. Every failure is a startup refusal.
    pub fn from_bundle(
        source: &str,
        schema_json: Option<&str>,
        entities_json: Option<&str>,
    ) -> Result<Self, CedarError> {
        let policies = PolicySet::from_str(source).map_err(|e| CedarError::Parse(e.to_string()))?;

        let (schema, schema_digest) = match schema_json {
            Some(json) => {
                let value: serde_json::Value =
                    serde_json::from_str(json).map_err(|e| CedarError::Schema(e.to_string()))?;
                let schema = Schema::from_json_value(value.clone())
                    .map_err(|e| CedarError::Schema(e.to_string()))?;
                let validation =
                    Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
                if !validation.validation_passed() {
                    let errors = validation
                        .validation_errors()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(CedarError::Validation(errors));
                }
                (Some(schema), Some(Digest::of(&canon::value_bytes(&value))))
            }
            None => (None, None),
        };

        let (entities, entities_digest) = match entities_json {
            Some(json) => {
                let value: serde_json::Value =
                    serde_json::from_str(json).map_err(|e| CedarError::Entities(e.to_string()))?;
                let entities = Entities::from_json_value(value.clone(), schema.as_ref())
                    .map_err(|e| CedarError::Entities(e.to_string()))?;
                (entities, Some(Digest::of(&canon::value_bytes(&value))))
            }
            None => (Entities::empty(), None),
        };

        let mut bundle =
            PolicyBundleIdentity::new(Digest::of(source.as_bytes()), EVALUATOR_SEMANTICS)
                .with_configuration(Digest::of(ADAPTER_CONFIGURATION));
        if let Some(digest) = schema_digest {
            bundle = bundle.with_schema(digest);
        }
        if let Some(digest) = entities_digest {
            bundle = bundle.with_entities(digest);
        }

        Ok(Self {
            policies,
            entities,
            schema,
            bundle,
        })
    }

    /// Build the Cedar request, or say why the runtime's strings could not be
    /// expressed as entities.
    fn request(&self, r: &PolicyRequest<'_>) -> Result<Request, String> {
        let principal = uid("Agent", r.principal)?;
        let action = uid("Action", r.action)?;
        let resource = uid("Resource", r.resource)?;
        let context = Context::from_json_value(
            r.context.clone(),
            self.schema.as_ref().map(|schema| (schema, &action)),
        )
        .map_err(|e| format!("context is not a Cedar record: {e}"))?;
        Request::new(principal, action, resource, context, self.schema.as_ref())
            .map_err(|e| format!("request is not well formed: {e}"))
    }
}

/// `Type::"id"`, with the id quoted so a name containing `.` or `/` survives.
///
/// Effect kinds look like `tool.call`, which is not a bare Cedar
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
        let req = match self.request(request) {
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

    fn bundle(&self) -> PolicyBundleIdentity {
        self.bundle.clone()
    }
}
