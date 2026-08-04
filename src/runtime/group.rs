//! Effect groups: several effects that take together, or not at all.
//!
//! # The gap a per-step saga leaves open
//!
//! Compensation is declared per *step*, and [`Skill::compensate`] receives the
//! step's **output**. A step that reserved inventory, authorised a card, and
//! then failed has no output — it failed — so its compensation is handed the
//! absence of one and has to guess what it is undoing. Guessing produces the
//! two worst answers available: undo something that never happened, or leave a
//! charge standing while unwinding everything around it.
//!
//! The missing unit is smaller than a step and larger than an effect. That unit
//! is an **effect group**: a set of effects with a declared footprint, a
//! recorded reversal for each member that can be reversed, and one point at
//! which the whole thing either takes or does not.
//!
//! [`Skill::compensate`]: crate::core::Skill::compensate
//!
//! # A reversal is captured, not reconstructed
//!
//! Each reversible member registers the concrete call that undoes it, built
//! from that member's **actual output at the moment it landed** — the hold id,
//! the authorisation reference. Nothing is reconstructed later from state that
//! may have moved, and nothing is looked up in a registry that may disagree.
//!
//! Reversals dispatch through [`StepCtx::effect`], so an undo is journaled,
//! keyed, retried and metered exactly like the forward call, and a replayed run
//! reads it back rather than performing it twice.
//!
//! They are exempt from one thing, and it is the same exemption a compensating
//! phase already has: the **gate**. A ceiling exists to bound work, not to
//! strand it half-done, and a run that could not afford to release the hold it
//! had already placed would end with exactly the shape the ceiling was meant to
//! prevent. The spend is still billed and journaled, so an overshoot is visible
//! rather than silent.
//!
//! # The frontier is where reversibility ends
//!
//! A group has two regions and one boundary.
//!
//! **Before the frontier**, members are reversible and the group can still be
//! abandoned at no cost to the outside world.
//!
//! **The frontier** is [`EffectGroup::commit`]. It checks the invariants that
//! must hold before anything becomes permanent, and only then releases the
//! deferred members. Invariants are checked *here* rather than earlier because
//! this is the last instant at which failing them is free.
//!
//! **After the frontier** there is no group. A skill that continues with
//! ordinary [`StepCtx::effect`] calls is past the point of no return, and a
//! failure there does not unwind — undoing a committed group would reverse a
//! decision the outside world has already acted on. That is the saga pivot
//! rule, at the granularity where the individual calls live.
//!
//! # Deferral is stronger than compensation
//!
//! A member that runs immediately and is undone on abort leaves a visible
//! trace: the reservation existed, the webhook fired, someone saw it. A member
//! that does not run *at all* until the group is certain leaves none.
//!
//! So [`EffectGroup::deferred`] is where irreversible sends belong — the email,
//! the payment capture, the published event. An aborted group never sends them,
//! which is a stronger statement than sending and apologising. The literature
//! calls this class *gated*; the point is the same, and it is why an
//! irreversible effect inside a group is safer than the same effect outside
//! one.
//!
//! [`StepCtx::effect`]: crate::runtime::StepCtx::effect
//!
//! # The footprint is enforced, not documented
//!
//! A group declares the resources it touches, and every member names the
//! resource it touches. A member naming a resource outside the declared set is
//! refused before it runs. Without that, "this group touches inventory and
//! payments" is a comment, and a frontier over an unknown set of resources is a
//! frontier over nothing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::{AnyEffect, Effect, StepError, Tainted};
use crate::journal::RecordKind;
use crate::runtime::StepCtx;

/// A condition that must hold before a group becomes permanent.
///
/// Evaluated by the caller, because the runtime cannot know what "the hold
/// covers the order" means. What the runtime supplies is the part a caller
/// cannot: the check happens at the frontier, the failing one is named in the
/// journal, and failing it reverses the members rather than returning an error
/// beside a half-applied group.
///
/// The value of naming it — rather than writing `if !ok { return Err(..) }` —
/// is that "which invariant failed" becomes a fact on the record instead of a
/// message someone reworded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invariant {
    /// What must be true, in the words the operator reading the abort will see.
    pub what: String,
    /// Whether it is.
    pub holds: bool,
}

impl Invariant {
    pub fn new(what: impl Into<String>, holds: bool) -> Self {
        Self {
            what: what.into(),
            holds,
        }
    }
}

/// How a group ended.
///
/// Four outcomes rather than two, because "nothing happened" and "we could not
/// establish what happened" are different situations and an operator acts on
/// them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupOutcome {
    /// Every member took. Deferred members ran; reversals were discarded.
    Committed,
    /// No member is standing. Reversible members were reversed, and deferred
    /// members never ran.
    Aborted,
    /// Neither could be established. Some member is in doubt, or a reversal
    /// failed, and unwinding further would compound the damage.
    ///
    /// The run is quarantined. This is the honest answer, and the one a
    /// half-applied group is usually reported as by systems that do not have
    /// this variant.
    Quarantined,
}

impl GroupOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::Quarantined => "quarantined",
        }
    }
}

/// A member that ran and can be taken back.
struct Reversal {
    resource: String,
    kind: String,
    undo: Box<dyn AnyEffect>,
}

/// A member held at the gate until the group commits.
struct Deferred {
    resource: String,
    effect: Box<dyn AnyEffect>,
}

/// The part of a group that outlives the handle.
///
/// Lives on the [`StepCtx`] rather than in [`EffectGroup`] on purpose. A skill
/// that fails with `?` drops the handle without committing or aborting, and
/// `Drop` cannot run an async reversal. So the executor asks the context
/// whether a group is open and settles it — the same way it settles a step.
pub(crate) struct OpenGroup {
    pub(crate) name: String,
    resources: Vec<String>,
    /// In the order they landed. Reversed in the opposite order, because a
    /// later member may depend on an earlier one still being in place.
    reversals: Vec<Reversal>,
    deferred: Vec<Deferred>,
}

impl std::fmt::Debug for OpenGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenGroup")
            .field("name", &self.name)
            .field("resources", &self.resources)
            .field("reversible", &self.reversals.len())
            .field("deferred", &self.deferred.len())
            .finish()
    }
}

/// Several effects that take together, or not at all.
///
/// Obtained from [`StepCtx::group`]. See the [module docs](self) for the shape
/// and why it is that shape.
///
/// ```no_run
/// # use agentplane::core::{Effect, EffectDescriptor, EffectError, StepError};
/// # use agentplane::runtime::{Invariant, StepCtx};
/// # use serde_json::{Value, json};
/// # #[derive(Debug)] struct Reserve { sku: String, qty: u32 }
/// # #[async_trait::async_trait] impl Effect for Reserve {
/// #   type Output = Value;
/// #   fn descriptor(&self) -> EffectDescriptor {
/// #     EffectDescriptor::new("stock.hold", json!({"sku": self.sku, "qty": self.qty})) }
/// #   async fn perform(&self) -> Result<Value, EffectError> { Ok(json!({"hold": "h-1"})) } }
/// # #[derive(Debug)] struct Release { hold: String }
/// # #[async_trait::async_trait] impl Effect for Release {
/// #   type Output = Value;
/// #   fn descriptor(&self) -> EffectDescriptor {
/// #     EffectDescriptor::new("stock.release", json!({"hold": self.hold})) }
/// #   async fn perform(&self) -> Result<Value, EffectError> { Ok(Value::Null) } }
/// # #[derive(Debug)] struct Notify { text: String }
/// # #[async_trait::async_trait] impl Effect for Notify {
/// #   type Output = Value;
/// #   fn descriptor(&self) -> EffectDescriptor {
/// #     EffectDescriptor::new("mail.send", json!({"text": self.text})) }
/// #   async fn perform(&self) -> Result<Value, EffectError> { Ok(Value::Null) } }
/// # async fn example(cx: &mut StepCtx<'_>) -> Result<(), StepError> {
/// let mut g = cx.group("checkout", ["inventory", "notify"]).await?;
///
/// // Runs now. The reversal is built from the id this call actually returned.
/// let hold = g
///     .reversible(
///         "inventory",
///         Reserve { sku: "sku-1".into(), qty: 2 },
///         |out| Release { hold: out["hold"].as_str().unwrap_or_default().to_owned() },
///     )
///     .await?;
///
/// // Does not run yet. An aborted group never sends it at all.
/// g.deferred("notify", Notify { text: "order confirmed".into() })?;
///
/// // The frontier: the last instant at which failing is free.
/// g.commit(&[Invariant::new(
///     "the hold covers the order",
///     hold.peek()["hold"].is_string(),
/// )])
/// .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct EffectGroup<'g, 'c> {
    cx: &'g mut StepCtx<'c>,
}

impl<'g, 'c> EffectGroup<'g, 'c> {
    pub(crate) fn new(cx: &'g mut StepCtx<'c>) -> Self {
        Self { cx }
    }

    /// Perform a member now, recording the call that takes it back.
    ///
    /// `undo` is handed the member's output and returns the concrete reversing
    /// effect. It is called immediately, so the reversal closes over the real
    /// identifiers this call returned rather than over whatever the world looks
    /// like when the abort happens.
    ///
    /// # Errors
    ///
    /// If `resource` is outside the group's declared footprint, or the effect
    /// itself fails. A failure leaves the group open: the executor reverses
    /// what landed.
    pub async fn reversible<E, U, F>(
        &mut self,
        resource: &str,
        effect: E,
        undo: F,
    ) -> Result<Tainted<E::Output>, StepError>
    where
        E: Effect,
        U: AnyEffect + 'static,
        F: FnOnce(&E::Output) -> U,
    {
        self.check_footprint(resource)?;
        let kind = effect.descriptor().kind;
        let out = self.cx.effect(effect).await?;
        let reversal = Reversal {
            resource: resource.to_owned(),
            kind,
            undo: Box::new(undo(out.peek())),
        };
        self.open()?.reversals.push(reversal);
        Ok(out)
    }

    /// Perform a member now that needs no reversal.
    ///
    /// For reads inside a group — the balance you check before charging it. A
    /// read has nothing to take back, and pretending otherwise would put an
    /// empty compensation in the journal beside the real ones.
    ///
    /// # Errors
    ///
    /// If `resource` is outside the declared footprint, or the effect fails.
    pub async fn read<E: Effect>(
        &mut self,
        resource: &str,
        effect: E,
    ) -> Result<Tainted<E::Output>, StepError> {
        self.check_footprint(resource)?;
        if effect.mutates() {
            return Err(StepError::GroupFootprint {
                group: self.open()?.name.clone(),
                detail: format!(
                    "effect '{}' mutates, so it cannot be a group read — declare it \
                     reversible with the call that undoes it, or deferred so an aborted \
                     group never runs it",
                    effect.descriptor().kind
                ),
            });
        }
        self.cx.effect(effect).await
    }

    /// Hold a member at the gate until the group commits.
    ///
    /// It does not run here. It runs at [`commit`](Self::commit), after every
    /// reversible member has landed and every invariant holds — or it never
    /// runs at all.
    ///
    /// This is where an irreversible send belongs. An abort then costs the
    /// outside world nothing, which is strictly better than sending and
    /// compensating.
    ///
    /// # Errors
    ///
    /// If `resource` is outside the group's declared footprint.
    pub fn deferred<E: AnyEffect + 'static>(
        &mut self,
        resource: &str,
        effect: E,
    ) -> Result<(), StepError> {
        self.check_footprint(resource)?;
        let member = Deferred {
            resource: resource.to_owned(),
            effect: Box::new(effect),
        };
        self.open()?.deferred.push(member);
        Ok(())
    }

    /// Cross the frontier: check the invariants, then release the deferred
    /// members.
    ///
    /// The order is the whole point. Invariants are checked while failing them
    /// is still free, and deferred members run only once they hold. Past this
    /// call the group is gone and nothing is reversed.
    ///
    /// Returns the deferred members' outputs in declaration order, labelled
    /// like any other effect output.
    ///
    /// # Errors
    ///
    /// [`StepError::GroupAborted`] when an invariant fails or a deferred member
    /// fails before any other has landed — in both cases every reversible
    /// member has been taken back and nothing is standing.
    /// [`StepError::GroupUnsettled`] when neither outcome could be established;
    /// the run is quarantined.
    pub async fn commit(self, invariants: &[Invariant]) -> Result<Vec<Tainted<Value>>, StepError> {
        if let Some(broken) = invariants.iter().find(|i| !i.holds) {
            let what = broken.what.clone();
            self.cx
                .abort_open_group(&format!("invariant: {what}"))
                .await?;
            return Err(StepError::GroupAborted { what });
        }

        let (name, deferred) = {
            let open = self.cx.open_group_mut().ok_or_else(no_group)?;
            (open.name.clone(), std::mem::take(&mut open.deferred))
        };

        let mut outputs = Vec::with_capacity(deferred.len());
        for member in deferred {
            let kind = AnyEffect::descriptor(&*member.effect).kind;
            let resource = member.resource.clone();
            match self.cx.effect(member.effect).await {
                Ok(v) => outputs.push(v),
                // Nothing else has externalised, so the group can still be
                // taken back whole.
                Err(e) if outputs.is_empty() && !in_doubt(&e) => {
                    let what = format!("deferred member '{kind}' on '{resource}' failed: {e}");
                    self.cx.abort_open_group(&what).await?;
                    return Err(StepError::GroupAborted { what });
                }
                // A member already landed, or this one may have. Reversing now
                // would undo everything except the thing that actually
                // happened, which is the worst of the three answers available.
                Err(e) => {
                    let detail = format!(
                        "deferred member '{kind}' on '{resource}' failed after {} landed: \
                         {e} — reversing now would undo everything except the thing that \
                         actually happened",
                        outputs.len()
                    );
                    self.cx
                        .settle_open_group(GroupOutcome::Quarantined, Some(&detail))
                        .await?;
                    return Err(StepError::GroupUnsettled {
                        group: name,
                        detail,
                    });
                }
            }
        }

        self.cx
            .settle_open_group(GroupOutcome::Committed, None)
            .await?;
        Ok(outputs)
    }

    /// Abandon the group: reverse every member that landed, run none of the
    /// deferred ones.
    ///
    /// # Errors
    ///
    /// [`StepError::GroupUnsettled`] if a reversal failed or a member is in
    /// doubt. The abort is reported as a quarantine rather than a success,
    /// because a partial unwind is not an unwind.
    pub async fn abort(self, why: &str) -> Result<(), StepError> {
        self.cx.abort_open_group(why).await
    }

    /// What this group touches, for a caller that needs to check.
    ///
    /// # Errors
    ///
    /// If the group is no longer open.
    pub fn resources(&self) -> Result<&[String], StepError> {
        Ok(&self.cx.open_group().ok_or_else(no_group)?.resources)
    }

    fn open(&mut self) -> Result<&mut OpenGroup, StepError> {
        self.cx.open_group_mut().ok_or_else(no_group)
    }

    fn check_footprint(&self, resource: &str) -> Result<(), StepError> {
        let open = self.cx.open_group().ok_or_else(no_group)?;
        if open.resources.iter().any(|r| r == resource) {
            return Ok(());
        }
        Err(StepError::GroupFootprint {
            group: open.name.clone(),
            detail: format!(
                "member touches '{resource}', which is not among the declared resources \
                 [{}] — a frontier over an undeclared resource is a frontier over nothing",
                open.resources.join(", ")
            ),
        })
    }
}

fn no_group() -> StepError {
    StepError::GroupUnsettled {
        group: String::new(),
        detail: "the group was already settled".to_owned(),
    }
}

/// Whether a failure leaves the outside world in an unknown state.
///
/// Doubt is the one condition under which nothing may be reversed: undoing a
/// call that may or may not have happened is a coin flip with real money on it.
pub(crate) fn in_doubt(e: &StepError) -> bool {
    match e {
        StepError::Undecidable { .. } => true,
        StepError::Effect(inner) => inner.disposition() == crate::core::Disposition::InDoubt,
        _ => false,
    }
}

impl<'a> StepCtx<'a> {
    /// Open a group over a declared set of resources.
    ///
    /// Every member must name a resource from this set. Declaring the footprint
    /// up front is what makes the frontier mean something: a group that could
    /// touch anything has committed to nothing.
    ///
    /// # Errors
    ///
    /// If a group is already open — groups do not nest, because a nested abort
    /// would have to decide whether it takes the outer group with it, and
    /// either answer is wrong half the time.
    pub async fn group<'g, R, S>(
        &'g mut self,
        name: impl Into<String>,
        resources: R,
    ) -> Result<EffectGroup<'g, 'a>, StepError>
    where
        R: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.into();
        if let Some(open) = self.open_group() {
            return Err(StepError::GroupFootprint {
                group: name,
                detail: format!(
                    "group '{}' is still open — groups do not nest, because a nested abort \
                     would have to decide whether it takes the outer group with it",
                    open.name
                ),
            });
        }
        let resources: Vec<String> = resources.into_iter().map(Into::into).collect();
        if resources.is_empty() {
            return Err(StepError::GroupFootprint {
                group: name,
                detail: "a group must declare the resources it touches; an empty footprint \
                         admits every member and refuses none"
                    .to_owned(),
            });
        }
        self.append(RecordKind::GroupOpened {
            group: name.clone(),
            resources: resources.clone(),
        })
        .await?;
        self.set_open_group(OpenGroup {
            name,
            resources,
            reversals: Vec::new(),
            deferred: Vec::new(),
        });
        Ok(EffectGroup::new(self))
    }

    /// Reverse every landed member, newest first, and settle the group.
    pub(crate) async fn abort_open_group(&mut self, why: &str) -> Result<(), StepError> {
        let Some(open) = self.open_group_mut() else {
            return Err(no_group());
        };
        let name = open.name.clone();
        let reversals = std::mem::take(&mut open.reversals);
        open.deferred.clear();

        let total = reversals.len();
        // Undo is exempt from the gate, exactly as a compensating phase is: a
        // ceiling exists to bound work, not to strand it half-done. The spend
        // is still billed and journaled, so an overshoot is visible rather than
        // silent.
        self.set_reversing(true);
        for (reversed, member) in reversals.into_iter().rev().enumerate() {
            let Reversal {
                resource,
                kind,
                undo,
            } = member;
            if let Err(e) = self.effect(undo).await {
                // Stop. Reversing further members around one that would not
                // come back leaves a shape nobody declared and nobody can read.
                let detail = format!(
                    "reversing '{kind}' on '{resource}' failed after {reversed} of {total}: {e}"
                );
                self.set_reversing(false);
                self.settle_open_group(GroupOutcome::Quarantined, Some(&detail))
                    .await?;
                return Err(StepError::GroupUnsettled {
                    group: name,
                    detail,
                });
            }
        }

        self.set_reversing(false);
        self.settle_open_group(GroupOutcome::Aborted, Some(why))
            .await
    }

    /// Write the group's ending and close it.
    pub(crate) async fn settle_open_group(
        &mut self,
        outcome: GroupOutcome,
        detail: Option<&str>,
    ) -> Result<(), StepError> {
        let Some(open) = self.take_open_group() else {
            return Err(no_group());
        };
        self.append(RecordKind::GroupSettled {
            group: open.name,
            outcome,
            detail: detail.map(ToOwned::to_owned),
        })
        .await
    }
}
