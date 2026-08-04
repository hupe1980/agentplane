//! Effects — the boundary between the deterministic and the real.
//!
//! An [`Effect`] is anything non-deterministic or externally visible: model
//! inference, a tool call, the clock, an RNG draw, a deadline resolution. The
//! runtime performs each **at most once**, journals the result, and reads it
//! back on replay.
//!
//! # Why effects declare a descriptor, not a key
//!
//! An effect key must include the step and ordinal to be unique within a run,
//! and an effect has no business knowing either. Worse, letting an effect choose
//! its own key would let a buggy or hostile one collide with another's and read
//! back someone else's journaled output.
//!
//! So an effect declares *what it does* — [`EffectDescriptor`] — and the runtime
//! derives the key from `(step, ordinal, kind, canonical(args))`. Skills cannot
//! forge or collide keys.

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::core::{
    EffectError, EffectKey, Phase, ProtectedField, Provenance, RetryPolicy, Sensitivity, Spend,
    StepId, Trust, canon,
};

impl EffectKey {
    /// Reconstruct the key the runtime would assign to an effect at a position.
    ///
    /// Exposed for tests and for offline journal tooling that needs to locate an
    /// effect without reimplementing the hash. Not a forgery risk: the runtime
    /// always derives its own key from the effect it is about to perform, and
    /// never accepts one from a caller.
    #[doc(hidden)]
    #[must_use]
    pub fn for_effect(
        step: StepId,
        phase: Phase,
        ordinal: u32,
        attempt: u32,
        d: &EffectDescriptor,
    ) -> Self {
        Self::derive(
            step,
            phase,
            ordinal,
            attempt,
            &d.kind,
            &canon::value_bytes(&d.args),
        )
    }
}

/// What an effect does, in terms the runtime can hash and the journal can show.
///
/// `args` must capture everything that makes this call *different* from another
/// call of the same kind: replay identifies effects by their key, so two calls
/// with identical descriptors at the same position are, by definition, the same
/// call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct EffectDescriptor {
    /// Stable, low-cardinality family — `"clock.now"`, `"mcp.tools/call"`,
    /// `"model.complete"`. Appears in journal listings and traces.
    pub kind: String,
    /// Canonical arguments. Hashed into the key and recorded verbatim.
    pub args: Value,
}

impl EffectDescriptor {
    pub fn new(kind: impl Into<String>, args: Value) -> Self {
        Self {
            kind: kind.into(),
            args,
        }
    }

    /// An effect whose identity is fully determined by its position — the
    /// clock, an RNG draw.
    pub fn nullary(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            args: Value::Null,
        }
    }
}

/// What a reconciliation probe established about a call whose outcome was
/// unknown.
///
/// This is how an undecidable case becomes decidable: instead of assuming the
/// call is safe to repeat, ask the provider what happened. Every serious
/// provider supports it — retrieving a payment intent by id, querying a
/// transfer by reference — and it is strictly better than the alternatives,
/// because it produces an *answer* rather than a bet.
#[derive(Debug)]
pub enum Reconciliation<T> {
    /// It landed, and here is the result, recovered from the provider.
    ///
    /// The effect is complete. Nothing is re-performed, and the recovered
    /// output is journaled as this effect's outcome.
    Landed(T),
    /// It never landed. Performing it now is safe.
    DidNotHappen,
    /// The probe could not tell.
    ///
    /// Not a failure of the probe so much as an honest answer, and it leaves
    /// the run exactly where it was: undecidable, and escalated rather than
    /// guessed at.
    Inconclusive,
}

impl<T> Reconciliation<T> {
    /// The probe's answer in the same vocabulary a failure uses, because it is
    /// the same question.
    #[must_use]
    pub fn disposition(&self) -> crate::core::Disposition {
        use crate::core::Disposition;
        match self {
            Self::Landed(_) => Disposition::Landed,
            Self::DidNotHappen => Disposition::DidNotHappen,
            Self::Inconclusive => Disposition::InDoubt,
        }
    }
}

/// How to recover when a crash leaves an effect's outcome unknown.
///
/// A crash between "request sent" and "response recorded" is undecidable from
/// the journal alone. The runtime refuses to guess, so every effect states its
/// semantics — and the default is the conservative one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum Recovery {
    /// Pure read or idempotent write — safe to re-run.
    Retry,
    /// The provider honors an idempotency key; replay reuses the same one.
    Idempotent { key: String },
    /// The effect can be queried to learn whether it landed.
    Reconcile,
    /// Undecidable. Escalate to a human; never guess.
    ///
    /// The default for anything that mutates external state. In a regulated
    /// domain this is the correct posture, and it is the line between a
    /// durable-execution demo and something you point at an accounting ledger.
    #[default]
    RequiresOperator,
}

/// Anything non-deterministic or externally visible.
///
/// Implemented by *drivers* (clock, RNG, MCP, A2A, model, timer) — never by
/// skill authors, who reach effects through
/// [`StepCtx`](crate::runtime::StepCtx).
#[async_trait]
pub trait Effect: Send + Sync {
    /// What comes back. Must round-trip through JSON: replay reconstructs it
    /// from the journal rather than from the driver.
    type Output: Serialize + DeserializeOwned + Send;

    /// What this effect does. Hashed (with position) into the effect key.
    fn descriptor(&self) -> EffectDescriptor;

    /// Receive the run-scoped provenance for this call.
    ///
    /// Defaulted to a no-op, because most effects send nothing outward that a
    /// callee could check. The ones that do — a tool call, a peer call — store
    /// it and put it on the wire.
    ///
    /// It arrives here rather than at construction because the
    /// [`EffectKey`](crate::core::EffectKey) is part of it, and an effect has no
    /// business knowing its own key: the key includes the effect's *position* in
    /// the run, which only the runtime knows. That is the same reasoning that
    /// turned `Effect::key()` into `Effect::descriptor()`, and it is why this is
    /// a hook rather than a constructor argument.
    fn attach(&mut self, _provenance: &Provenance) {}

    /// Which `OpenTelemetry` `GenAI` operation this effect is, if it is one.
    ///
    /// Returned as the value of `gen_ai.operation.name` — `execute_tool` for a
    /// tool call, `chat` for a completion. Observability tooling keys on that
    /// attribute, so an effect that does not answer here is invisible *as an
    /// agent operation* even though its span is emitted: a trace shows the
    /// agent invocation and nothing about the calls inside it.
    ///
    /// Defaulted to `None`, which is the honest answer for the effects that are
    /// not `GenAI` operations at all — reading the clock, sleeping, writing case
    /// state. Labelling those would make the convention meaningless.
    ///
    /// The conventions are still pre-1.0, which is why the version this targets
    /// is pinned in [`telemetry::SEMCONV_VERSION`] rather than tracked.
    ///
    /// [`telemetry::SEMCONV_VERSION`]: crate::runtime::telemetry::SEMCONV_VERSION
    fn gen_ai_operation(&self) -> Option<&'static str> {
        None
    }

    /// Whether this mutates external state.
    ///
    /// Drives the recovery default and the policy engine's `resource.mutates`
    /// attribute. Defaults to `true`: an effect that forgets to declare itself
    /// is treated as dangerous.
    fn mutates(&self) -> bool {
        true
    }

    /// What to do when the outcome is unknown — after a crash, or after an
    /// [`InDoubt`](crate::core::Disposition::InDoubt) failure. The two are the
    /// same situation reached from different directions.
    fn recovery(&self) -> Recovery {
        if self.mutates() {
            Recovery::RequiresOperator
        } else {
            Recovery::Retry
        }
    }

    /// How many times to repeat this effect when it fails, and how far apart.
    ///
    /// The policy is not the safety control — [`Recovery`] and the failure's
    /// [`Disposition`](crate::core::Disposition) are, and they are consulted
    /// first. Raising `max_attempts` cannot make a mutating in-doubt call
    /// retryable; it only governs failures that are already safe to repeat.
    ///
    /// Defaults to [`RetryPolicy::default`] — three attempts with exponential
    /// backoff. That default is safe for a mutating effect precisely because
    /// the disposition gate stands in front of it.
    fn retry(&self) -> RetryPolicy {
        RetryPolicy::default()
    }

    /// The highest data sensitivity this sink may receive.
    ///
    /// The runtime refuses to pass arguments above this ceiling, which is the
    /// control for the exfiltration path that actually matters: a
    /// legitimate-looking call carrying a secret read three steps earlier.
    fn max_sensitivity(&self) -> Sensitivity {
        Sensitivity::Public
    }

    /// The exact value this effect will send to its sink.
    ///
    /// [`StepCtx::sink`](crate::runtime::StepCtx::sink) compares this value to
    /// the labeled value it checks. Returning `None` means the effect has not
    /// bound its outbound arguments and is therefore refused by `sink`.
    /// Without this binding a caller could present a harmless trusted value to
    /// the gate while the effect sent unrelated attacker-controlled arguments.
    fn sink_arguments(&self) -> Option<&Value> {
        None
    }

    /// Field-specific source and sensitivity rules for a structured sink.
    ///
    /// Declared selectors are enforced for every effect: a read-only URL,
    /// tenant, model, path, or query can still carry authority. A mutating
    /// effect with no protected fields additionally receives the conservative
    /// whole-object taint gate. Once fields are declared, those selectors carry
    /// the stricter trust/source checks while ordinary content may remain
    /// untrusted. This avoids broad whole-value releases merely to preserve a
    /// trusted recipient or amount beside untrusted descriptive text.
    fn protected_fields(&self) -> &[ProtectedField] {
        &[]
    }

    /// The resulting delegation depth when this effect hands authority onward.
    ///
    /// `None` means the effect does not delegate. A peer call returns the depth
    /// of the attenuated chain it will put on the wire, allowing a manifest to
    /// enforce a ceiling at the last boundary before dispatch without teaching
    /// core about any particular peer protocol.
    fn delegation_depth(&self) -> Option<usize> {
        None
    }

    /// How much this effect's *output* may be trusted.
    ///
    /// **Defaults to [`Trust::Untrusted`]**, and the direction of that default is
    /// the point. An effect is how the deterministic zone reaches the outside
    /// world, so its result is the outside world's data — a tool response, a
    /// peer's answer, a model completion. Those are the three most important
    /// untrusted inputs an agent runtime handles, and the whole architecture
    /// rests on them being labelled *at the source* rather than remembered about
    /// later.
    ///
    /// Getting this wrong in the safe direction produces spurious taint, which
    /// is an annoyance that shows up immediately as a refused sink. Getting it
    /// wrong the other way is a prompt injection reaching a mutating tool, which
    /// shows up as a wire transfer. So the effect that forgets to declare
    /// anything gets the conservative answer — the same rule
    /// [`Effect::recovery`] follows.
    ///
    /// Declare [`Trust::Trusted`] only for effects that do not cross a trust
    /// boundary: the runtime's own journaled clock, a seeded RNG, a durable
    /// timer. `tests/guards/layering.rs` requires each one to be named, so a fourth has
    /// to argue for itself.
    fn trust(&self) -> Trust {
        Trust::Untrusted
    }

    /// How sensitive this effect's output is, at minimum.
    ///
    /// The runtime takes the **maximum** of this and whatever the trust level
    /// implies — an untrusted result is already `Internal`. So this can raise
    /// sensitivity and never lower it, which is the only safe direction: an
    /// effect that could declare its output *less* sensitive than its
    /// provenance implies would be a laundering primitive with a polite name.
    ///
    /// Declare it for effects that return things worth protecting: a vault read,
    /// a model completion over customer records, a peer's answer about a named
    /// person. The egress ceiling on the next sink is what then does the work.
    fn output_sensitivity(&self) -> Sensitivity {
        Sensitivity::Public
    }

    /// What this effect consumed.
    ///
    /// Reported *after* the fact because only then is it known, and journaled in
    /// the `EffectDone` record so replay adds up the same figures. Asking a
    /// provider what something cost at replay time would give a moving answer,
    /// and the budget verdict would move with it.
    fn spend(&self, _output: &Self::Output) -> Spend {
        Spend::default()
    }

    /// Do the thing. Called at most once per key per run; never called during
    /// replay.
    async fn perform(&self) -> Result<Self::Output, EffectError>;

    /// Ask the provider whether a call landed.
    ///
    /// Called only when [`recovery`](Self::recovery) is
    /// [`Recovery::Reconcile`] and the outcome is genuinely unknown — after a
    /// crash between "sent" and "recorded", or after an
    /// [`InDoubt`](crate::core::Disposition::InDoubt) failure. The two are the
    /// same situation, and this is the only thing that resolves either without
    /// guessing.
    ///
    /// The probe must identify the call by something stable across attempts —
    /// an idempotency key, a client reference, an order id carried in the
    /// request. A probe that searches by timestamp or by "most recent" is not a
    /// probe; it is a guess with extra steps.
    ///
    /// The result is journaled, so replay reads the verdict back rather than
    /// probing again. The default is [`Inconclusive`](Reconciliation::Inconclusive):
    /// declaring `Reconcile` without implementing this escalates to an operator
    /// rather than silently deciding either way.
    async fn reconcile(&self) -> Result<Reconciliation<Self::Output>, EffectError> {
        Ok(Reconciliation::Inconclusive)
    }
}

/// An [`Effect`] whose output type has been erased to [`Value`].
///
/// # Why erasure, when generics are right everywhere else
///
/// An [`EffectGroup`](crate::runtime::EffectGroup) has to hold the *concrete
/// call that undoes* each member it performed — built from that member's actual
/// output, at the moment it landed — and hold several of them, of different
/// types, in one list. A generic cannot do that.
///
/// The alternative would be to journal the undo call and reconstruct it later
/// from a name-to-constructor registry. That was rejected: a registry is a
/// second place where an effect must be declared, it fails at *recovery* time
/// rather than at compile time when someone forgets, and it makes an undo
/// dispatchable by anyone who can write a name into a record.
///
/// Erasure keeps the undo a value the compiler checked, and — because
/// `Box<dyn AnyEffect>` implements [`Effect`] — it travels the **same**
/// dispatch path as any other effect: journaled, keyed, retried, gated by
/// policy, metered against the budget. Nothing about being an undo makes it
/// privileged.
#[async_trait]
pub trait AnyEffect: Send + Sync {
    fn descriptor(&self) -> EffectDescriptor;
    fn attach_erased(&mut self, provenance: &Provenance);
    fn gen_ai_operation(&self) -> Option<&'static str>;
    fn mutates(&self) -> bool;
    fn recovery(&self) -> Recovery;
    fn retry(&self) -> RetryPolicy;
    fn max_sensitivity(&self) -> Sensitivity;
    fn sink_arguments(&self) -> Option<&Value>;
    fn protected_fields(&self) -> &[ProtectedField];
    fn delegation_depth(&self) -> Option<usize>;
    fn trust(&self) -> Trust;
    fn output_sensitivity(&self) -> Sensitivity;
    fn spend_erased(&self, output: &Value) -> Spend;
    async fn perform_erased(&self) -> Result<Value, EffectError>;
    async fn reconcile_erased(&self) -> Result<Reconciliation<Value>, EffectError>;
}

#[async_trait]
impl<E> AnyEffect for E
where
    E: Effect,
{
    fn descriptor(&self) -> EffectDescriptor {
        Effect::descriptor(self)
    }
    fn attach_erased(&mut self, provenance: &Provenance) {
        Effect::attach(self, provenance);
    }
    fn gen_ai_operation(&self) -> Option<&'static str> {
        Effect::gen_ai_operation(self)
    }
    fn mutates(&self) -> bool {
        Effect::mutates(self)
    }
    fn recovery(&self) -> Recovery {
        Effect::recovery(self)
    }
    fn retry(&self) -> RetryPolicy {
        Effect::retry(self)
    }
    fn max_sensitivity(&self) -> Sensitivity {
        Effect::max_sensitivity(self)
    }
    fn sink_arguments(&self) -> Option<&Value> {
        Effect::sink_arguments(self)
    }
    fn protected_fields(&self) -> &[ProtectedField] {
        Effect::protected_fields(self)
    }
    fn delegation_depth(&self) -> Option<usize> {
        Effect::delegation_depth(self)
    }
    fn trust(&self) -> Trust {
        Effect::trust(self)
    }
    fn output_sensitivity(&self) -> Sensitivity {
        Effect::output_sensitivity(self)
    }
    /// Round-trips the output to ask the typed effect what it cost.
    ///
    /// A type that cannot be deserialized from its own serialization is already
    /// broken for replay — `Effect::Output` requires the round-trip, and the
    /// journal reconstructs every output that way. Charging zero here is the
    /// same answer replay would reach, and the defect surfaces where it belongs.
    fn spend_erased(&self, output: &Value) -> Spend {
        serde_json::from_value::<E::Output>(output.clone())
            .map(|o| Effect::spend(self, &o))
            .unwrap_or_default()
    }
    async fn perform_erased(&self) -> Result<Value, EffectError> {
        let out = Effect::perform(self).await?;
        serde_json::to_value(out).map_err(EffectError::OutputShape)
    }
    async fn reconcile_erased(&self) -> Result<Reconciliation<Value>, EffectError> {
        Ok(match Effect::reconcile(self).await? {
            Reconciliation::Landed(o) => {
                Reconciliation::Landed(serde_json::to_value(o).map_err(EffectError::OutputShape)?)
            }
            Reconciliation::DidNotHappen => Reconciliation::DidNotHappen,
            Reconciliation::Inconclusive => Reconciliation::Inconclusive,
        })
    }
}

/// So an erased effect dispatches exactly like a typed one, with no second
/// code path in the runtime that could drift from the first.
///
/// Written over `dyn AnyEffect + 'e` rather than the `'static` default: the
/// executor re-enters itself through a commission, so this impl has to hold for
/// whatever lifetime the surrounding future is inferred at, and pinning it to
/// `'static` makes that proof fail for every specific one.
#[async_trait]
impl Effect for Box<dyn AnyEffect + '_> {
    type Output = Value;

    fn descriptor(&self) -> EffectDescriptor {
        (**self).descriptor()
    }
    fn attach(&mut self, provenance: &Provenance) {
        (**self).attach_erased(provenance);
    }
    fn gen_ai_operation(&self) -> Option<&'static str> {
        (**self).gen_ai_operation()
    }
    fn mutates(&self) -> bool {
        (**self).mutates()
    }
    fn recovery(&self) -> Recovery {
        (**self).recovery()
    }
    fn retry(&self) -> RetryPolicy {
        (**self).retry()
    }
    fn max_sensitivity(&self) -> Sensitivity {
        (**self).max_sensitivity()
    }
    fn sink_arguments(&self) -> Option<&Value> {
        (**self).sink_arguments()
    }
    fn protected_fields(&self) -> &[ProtectedField] {
        (**self).protected_fields()
    }
    fn delegation_depth(&self) -> Option<usize> {
        (**self).delegation_depth()
    }
    fn trust(&self) -> Trust {
        (**self).trust()
    }
    fn output_sensitivity(&self) -> Sensitivity {
        (**self).output_sensitivity()
    }
    fn spend(&self, output: &Value) -> Spend {
        (**self).spend_erased(output)
    }
    async fn perform(&self) -> Result<Value, EffectError> {
        (**self).perform_erased().await
    }
    async fn reconcile(&self) -> Result<Reconciliation<Value>, EffectError> {
        (**self).reconcile_erased().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn descriptors_with_reordered_args_are_equal_after_canonicalization() {
        let a = EffectDescriptor::new("mcp.tools/call", json!({"b": 2, "a": 1}));
        let b = EffectDescriptor::new("mcp.tools/call", json!({"a": 1, "b": 2}));
        assert_eq!(
            crate::core::canon::value_bytes(&a.args),
            crate::core::canon::value_bytes(&b.args),
            "argument order must not change an effect's identity"
        );
    }

    #[test]
    fn mutating_effects_default_to_operator_recovery() {
        struct Mutating;
        #[async_trait]
        impl Effect for Mutating {
            type Output = ();
            fn descriptor(&self) -> EffectDescriptor {
                EffectDescriptor::nullary("test.mutate")
            }
            async fn perform(&self) -> Result<(), EffectError> {
                Ok(())
            }
        }
        assert!(matches!(
            Effect::recovery(&Mutating),
            Recovery::RequiresOperator
        ));
    }

    #[test]
    fn read_only_effects_default_to_retry() {
        struct ReadOnly;
        #[async_trait]
        impl Effect for ReadOnly {
            type Output = ();
            fn descriptor(&self) -> EffectDescriptor {
                EffectDescriptor::nullary("test.read")
            }
            fn mutates(&self) -> bool {
                false
            }
            async fn perform(&self) -> Result<(), EffectError> {
                Ok(())
            }
        }
        assert!(matches!(Effect::recovery(&ReadOnly), Recovery::Retry));
    }
}
