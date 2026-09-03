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
//! # Naming a rule, so a denial can name it back
//!
//! Cedar's diagnostics report positional ids — `policy0`, `policy1`, … — so a
//! forty-rule set produces forty denials that each name a number, which is
//! what [`PolicyDecision::Deny`](crate::core::PolicyDecision::Deny)'s required
//! reason exists to prevent. Cedar treats `@id` as an ordinary annotation and
//! does **not** adopt it as the `PolicyId`; this adapter reads it and prefers
//! it:
//!
//! ```cedar
//! @id("betragsgrenze-5000-eur")
//! forbid (principal, action == Action::"effect:perform", resource)
//! when { context.args.amount_eur > 5000 };
//! ```
//!
//! ```text
//! policy denied 'effect:perform' on 'tool.call': refused by betragsgrenze-5000-eur
//! ```
//!
//! The reason names the **rule and nothing else**: every caller already holds
//! the action and the resource on
//! [`StepError::Denied`](crate::core::StepError::Denied) and the journaled
//! `PolicyDenied` record. Two rules answering to one name are refused at
//! construction ([`CedarError::AmbiguousRuleName`]), including an `@id` that
//! collides with another rule's generated id — a name pointing at the wrong
//! rule is worse than a number pointing at the right one.
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

use serde_json::Value;

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
    "cedar-policy/4.12.0;agentplane-adapter/3;extensions=all-available";

const ADAPTER_CONFIGURATION: &[u8] =
    b"principal=Agent;action=Action;resource=Resource;context=action-schema;rule-name=@id";

/// The annotation this adapter reads as a rule's name.
///
/// Cedar generates `policy0`, `policy1`, … when a policy set is parsed from
/// text, and those ids are what its diagnostics report. A denial naming
/// `policy17` sends an operator to count `forbid` blocks in a file, which is
/// the outcome [`PolicyDecision::Deny`]'s required reason exists to prevent.
///
/// Cedar treats `@id` as an ordinary annotation — it does **not** adopt it as
/// the `PolicyId` — so the adapter reads it explicitly and prefers it over the
/// generated id. Two rules sharing one name are refused at construction: see
/// [`CedarError::AmbiguousRuleName`].
///
/// ```cedar
/// @id("betragsgrenze-5000-eur")
/// forbid (principal, action == Action::"effect:perform", resource)
/// when { context.args.amount_eur > 5000 };
/// ```
pub const RULE_NAME_ANNOTATION: &str = "id";

/// Target of the `tracing` event emitted when null stripping changed the
/// context a rule evaluated — see `without_nulls` (crate-private) for why
/// stripping exists and what it can and cannot change.
///
/// Emitted at `debug`, deliberately: a model call's request profile carries a
/// `null` for every optional knob nobody set, so the common case would make a
/// louder level a firehose. What the event buys an audit is the divergence
/// itself: the effect key canonicalized the arguments *with* their nulls,
/// while policy evaluated them without — two views of one call, and the only
/// record that they differed is this event and the `removed` count on it.
pub const CONTEXT_NULLS_STRIPPED: &str = "agentplane.policy.context_nulls_stripped";

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
    /// Two rules answer to one name, so a denial could not say which fired.
    ///
    /// The whole point of the `@id` annotation is that a reason names one
    /// rule. A name shared by two rules is worse than no name: it reads like
    /// an answer and sends the operator to the wrong `forbid`.
    #[error(
        "two rules answer to the name '{name}' ({first} and {second}) — a denial \
         naming it could not say which fired; give each rule its own @id"
    )]
    AmbiguousRuleName {
        name: String,
        first: String,
        second: String,
    },
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
        check_rule_names(&policies)?;

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
        let mut removed = 0usize;
        let stripped = without_nulls(r.context.clone(), &mut removed);
        if removed > 0 {
            // The one record that the two views diverged: the effect key
            // canonicalized these arguments with their nulls, the rules are
            // about to see them without. Cheap — the count fell out of the
            // pass that stripped them — and per request, so an audit walking
            // a decision back to its arguments knows to compare the two.
            tracing::debug!(
                target: CONTEXT_NULLS_STRIPPED,
                action = %r.action,
                resource = %r.resource,
                removed,
                "null values were stripped from the authorization context \
                 before evaluation; policy saw fewer attributes or array \
                 elements than the effect key canonicalized"
            );
        }
        let context = Context::from_json_value(
            stripped,
            self.schema.as_ref().map(|schema| (schema, &action)),
        )
        .map_err(|e| format!("context is not a Cedar record: {e}"))?;
        Request::new(principal, action, resource, context, self.schema.as_ref())
            .map_err(|e| format!("request is not well formed: {e}"))
    }

    /// What to call a rule in a denial: its `@id`, or Cedar's generated id.
    ///
    /// Cedar's own ids are positional — `policy0`, `policy1` — so a forty-rule
    /// set produces forty reasons that each name a number, and the operator
    /// still has to find which of forty rules that is. The annotation is the
    /// half a wrapper cannot supply, and it is why the reason is required at
    /// all.
    ///
    /// An `@id` with no value parses as `Some("")`, which would name nothing;
    /// that falls back to the generated id rather than producing an empty
    /// reason.
    fn rule_name(&self, id: &cedar_policy::PolicyId) -> String {
        self.policies
            .annotation(id, RULE_NAME_ANNOTATION)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| id.to_string(), ToOwned::to_owned)
    }
}

/// Refuse a policy set in which two rules answer to one name.
///
/// Checked over the *effective* name — the `@id` when there is one, Cedar's
/// generated id otherwise — so it also catches the case an annotation-only
/// check would miss: `@id("policy1")` on the first rule while the second is
/// generated as `policy1`.
///
/// At construction, because that is where every other policy defect in this
/// adapter is caught. A denial that names a rule ambiguously is discovered at
/// 3am by whoever is reading it.
fn check_rule_names(policies: &PolicySet) -> Result<(), CedarError> {
    let mut seen: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for policy in policies.policies() {
        let generated = policy.id().to_string();
        let name = policy
            .annotation(RULE_NAME_ANNOTATION)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| generated.clone(), ToOwned::to_owned);
        if let Some(first) = seen.insert(name.clone(), generated.clone()) {
            return Err(CedarError::AmbiguousRuleName {
                name,
                first,
                second: generated,
            });
        }
    }
    Ok(())
}

/// Cedar has no `null`, so an absent value must be spelled *absent*.
///
/// # Why this belongs in the adapter
///
/// `Context::from_json_value` refuses a document containing a JSON `null`
/// anywhere — not the field, **the whole record** — and the consequence is
/// severe and quiet: the request never reaches a rule, so the answer is a clean
/// `Deny`, and an operator reading "denied" hunts for the rule that said no
/// while nothing was evaluated at all. This adapter reports that as *malformed*
/// rather than as a refusal precisely because the two are different situations.
///
/// It was not hypothetical. Two contexts the runtime sends carried nulls, and
/// between them they denied everything a Cedar plane did:
///
/// * `context.agent.publisher` — `None` for every unpublished manifest, which
///   is most of them, so **every admission** was malformed. Fixed at the source
///   too, since the adapter's own documentation already said *"or absent"*.
/// * `context.args` — the effect's own arguments, which are **arbitrary caller
///   JSON**. A model call's request profile carries `null` for every optional
///   knob nobody set. No amount of fixing at the source closes this one: the
///   runtime cannot promise that data it did not author contains no nulls.
///
/// That second case is why the fix lives here rather than only at the callers.
/// A control implemented once per producer is one the next producer does not
/// have, and the producer here is *the user's own arguments*.
///
/// # What the mapping means
///
/// A null-valued object member becomes an **absent attribute**, which is
/// Cedar's own idiom for optional data — `context.agent has publisher` is how a
/// policy asks, and it now answers correctly instead of failing to parse.
///
/// This cannot weaken a rule. Cedar has no null literal, so no policy can match
/// on one; stripping removes only values that were already unmatchable, and the
/// sole observable change is that `has` answers `false` rather than the request
/// being unevaluable.
///
/// # The one lossy case, stated
///
/// A `null` **inside an array** cannot become an absent attribute — there is no
/// key to omit — so the element is dropped, which shortens the array and shifts
/// what follows it. A policy indexing a fixed position in caller-supplied data
/// is fragile regardless, and the alternative is refusing the request, which
/// would reinstate the outage for data the runtime does not control.
///
/// # The divergence is recorded
///
/// Stripping means policy evaluates a context that is not byte-for-byte the
/// arguments the effect key canonicalized. That is safe by the argument above
/// — nothing removed was matchable — but it is still two views of one call,
/// and an audit reconciling a decision against journaled arguments deserves to
/// know they differ. `removed` counts every dropped value, and the caller
/// emits a [`CONTEXT_NULLS_STRIPPED`] event whenever it is non-zero.
fn without_nulls(value: Value, removed: &mut usize) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(k, v)| {
                    if v.is_null() {
                        *removed += 1;
                        None
                    } else {
                        Some((k, without_nulls(v, removed)))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .filter_map(|v| {
                    if v.is_null() {
                        *removed += 1;
                        None
                    } else {
                        Some(without_nulls(v, removed))
                    }
                })
                .collect(),
        ),
        other => other,
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
                return PolicyDecision::malformed(format!(
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
            // Permitted *and* something failed to evaluate. The permit does
            // **not** stand. Cedar is total: an erroring policy contributes
            // nothing, so the rule that failed may be exactly the `forbid`
            // that would have overridden this permit — the `Allow` can exist
            // *because* the veto broke. Letting it through makes every
            // evaluation error a switch that turns a forbid off, and a gate
            // an attacker disarms by making a rule error (a context attribute
            // an unusual request shape omits, say) is a control that yields
            // exactly under the pressure it exists to hold — a ceiling fails
            // open because its accounting was made unreachable, wearing a
            // permit. So this fails closed, exactly as `Deny` + errors stays
            // a deny — and says it is a defect, because the operator's fix is
            // the policy set, not the request. The error text itself goes to
            // the trace above and to the deny reason the journal keeps; a
            // model probing the gate sees only the uniform refusal, as it
            // does for every policy denial.
            cedar_policy::Decision::Allow => PolicyDecision::malformed(format!(
                "policy evaluation error — refusing because a rule that might \
                 have forbidden this call failed to evaluate: {} — this is a \
                 defect in the policy set, not a rule firing",
                errors.join("; ")
            )),
            cedar_policy::Decision::Deny if !errors.is_empty() => {
                PolicyDecision::malformed(format!(
                    "denied while {} policy error(s) went unevaluated: {} — fix the \
                 policy set; this denial may not mean what it appears to",
                    errors.len(),
                    errors.join("; ")
                ))
            }
            cedar_policy::Decision::Deny => {
                let determining: Vec<String> = answer
                    .diagnostics()
                    .reason()
                    .map(|id| self.rule_name(id))
                    .collect();
                if determining.is_empty() {
                    // Cedar denies by default when nothing permits. Saying so
                    // beats "denied by policy", which sends someone hunting for
                    // a `forbid` that does not exist.
                    PolicyDecision::deny("no policy permits it")
                } else {
                    PolicyDecision::deny(format!("refused by {}", determining.join(", ")))
                }
            }
        }
    }

    /// Evaluate each probe and report the rules that could not be evaluated.
    ///
    /// The trap this catches is Cedar's totality: every rule is evaluated
    /// against every request, so a `when` clause reading an attribute the
    /// request does not carry errors rather than failing to match, and an
    /// unevaluable rule refuses the call because it may be the `forbid` that
    /// would have stopped it. One such rule denies every effect of every run,
    /// from a policy set that parsed and validated cleanly — which is exactly
    /// how a deployment found itself with a plane that refused everything.
    ///
    /// Only unevaluable sets are reported. A set that merely *denies* the
    /// probes is a working default-deny plane, and reporting it would make
    /// this check the reason nobody writes one.
    fn preflight(&self, requests: &[PolicyRequest<'_>]) -> Vec<String> {
        requests
            .iter()
            .filter_map(|request| {
                let decision = self.authorize(request);
                decision.is_malformed().then(|| {
                    format!(
                        "`{}` on `{}`: {}",
                        request.action,
                        request.resource,
                        decision.reason().unwrap_or_default()
                    )
                })
            })
            .collect()
    }

    fn bundle(&self) -> PolicyBundleIdentity {
        self.bundle.clone()
    }
}
