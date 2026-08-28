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

use crate::core::{AnyEffect, Effect, GroupOutcome, StepError, Tainted};
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

/// A member that ran and can be taken back.
struct Reversal {
    resource: String,
    kind: String,
    undo: Box<dyn AnyEffect>,
}

/// A member that commits with the journal, in the journal's own transaction.
pub(crate) struct AtomicMember {
    resource: String,
    inner: std::sync::Arc<dyn crate::journal::AtomicResource>,
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
    atomic: Vec<AtomicMember>,
}

impl std::fmt::Debug for OpenGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenGroup")
            .field("name", &self.name)
            .field("resources", &self.resources)
            .field("reversible", &self.reversals.len())
            .field("deferred", &self.deferred.len())
            .field("atomic", &self.atomic.len())
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
        let out = self.cx.effect_as_member(effect).await?;
        let undo = undo(out.peek());
        // A **quarantine**, not a refusal, and the difference is the whole
        // point: the forward member has already landed, and an undo that
        // cannot be dispatched means the runtime has no way to take it back.
        // Reporting that as an ordinary error would let the abort settle the
        // group as `Aborted` with nothing registered to reverse — the journal
        // saying discharged while the hold still stands.
        if let Some(detail) = Self::check_dispatchable(&undo) {
            let group = self.group_name();
            self.cx
                .settle_open_group(GroupOutcome::Quarantined, Some(&detail))
                .await?;
            return Err(StepError::GroupUnsettled { group, detail });
        }
        let reversal = Reversal {
            resource: resource.to_owned(),
            kind,
            undo: Box::new(undo),
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
        self.cx.effect_as_member(effect).await
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
        // Nothing has run for this member yet, so refusing is free and the
        // group can still be taken back whole.
        if let Some(detail) = Self::check_dispatchable(&effect) {
            return Err(StepError::GroupFootprint {
                group: self.group_name(),
                detail,
            });
        }
        let member = Deferred {
            resource: resource.to_owned(),
            effect: Box::new(effect),
        };
        self.open()?.deferred.push(member);
        Ok(())
    }

    /// Register a member that commits **with the journal**, in one transaction.
    ///
    /// The strongest class available, and it is available only when the resource
    /// lives in the same database as the journal. Nothing is externalised and
    /// later reversed, so no reversal can fail; there is no in-doubt state,
    /// because a transaction either committed or did not; and an abort is a
    /// rollback, which cannot itself fail halfway. Compensation that never has
    /// to run beats compensation that runs correctly.
    ///
    /// It does not run here. It runs inside the transaction that
    /// [`commit`](Self::commit) opens, alongside the records saying it
    /// happened — so a caller cannot see its result before the frontier, which
    /// is the price of it being atomic with the frontier.
    ///
    /// # Errors
    ///
    /// If `resource` is outside the declared footprint, or the journal cannot
    /// offer its transaction. The second is checked **here**, not at commit: a
    /// group that discovered its backend at the frontier would have already
    /// performed every eager member.
    pub fn atomic(
        &mut self,
        resource: &str,
        member: std::sync::Arc<dyn crate::journal::AtomicResource>,
    ) -> Result<(), StepError> {
        self.check_footprint(resource)?;
        if !self.cx.store_is_atomic() {
            return Err(StepError::GroupFootprint {
                group: self.group_name(),
                detail: format!(
                    "'{}' must commit with the journal, and this store has no transaction \
                     a resource can join — an embedded backend has no notion of a foreign \
                     table, so the capability is absent rather than failing",
                    member.descriptor().kind
                ),
            });
        }
        let member = AtomicMember {
            resource: resource.to_owned(),
            inner: member,
        };
        self.open()?.atomic.push(member);
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
    /// [`StepError::GroupAborted`] when an invariant fails, when the atomic
    /// members' transaction does not commit, or when a deferred member fails
    /// before anything externalised — in every case every reversible member has
    /// been taken back and nothing is standing.
    /// [`StepError::GroupUnsettled`] when that claim cannot be made — a
    /// deferred member failed after another landed or after the atomic members
    /// committed, or its outcome is in doubt; the run is quarantined.
    pub async fn commit(self, invariants: &[Invariant]) -> Result<Vec<Tainted<Value>>, StepError> {
        if let Some(broken) = invariants.iter().find(|i| !i.holds) {
            let what = broken.what.clone();
            self.cx
                .abort_open_group(&format!("invariant: {what}"))
                .await?;
            return Err(StepError::GroupAborted { what });
        }

        let (name, deferred, atomic) = {
            let open = self.cx.open_group_mut().ok_or_else(no_group)?;
            (
                open.name.clone(),
                std::mem::take(&mut open.deferred),
                std::mem::take(&mut open.atomic),
            )
        };

        // The database part, before the outside-world part. If the transaction
        // does not commit, nothing in it happened and the group can still be
        // taken back whole; telling anyone about it first would be announcing
        // work that may yet vanish.
        let touched = atomic
            .iter()
            .map(|m| m.resource.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        // Once the transaction below succeeds this is a fact about the outside
        // world: the members' writes are permanent, have no registered reversal,
        // and cannot have one. The deferred loop's cheap abort path is priced on
        // "nothing has externalised", and this is the bit that says whether that
        // price is still available.
        let atomic_committed = !atomic.is_empty();
        if atomic_committed && let Err(e) = self.cx.commit_atomic(&name, atomic).await {
            // A lost acknowledgement is not a refusal. The server either
            // committed or did not, but this client's knowledge of which is
            // gone — so the members' writes may be standing, permanent, with
            // no reversal registered and none possible. Aborting here would
            // settle the journal on *taken back whole* over a write nobody
            // took back; the only honest settlement is quarantine, and an
            // operator reconciles against the database itself.
            if matches!(
                &e,
                StepError::Store(crate::core::StoreError::CommitUnknown { .. })
            ) {
                let detail = format!(
                    "the atomic members on [{touched}] may have committed — the \
                     acknowledgement was lost ({e}); aborting would claim 'taken \
                     back whole' over a write that may stand"
                );
                self.cx
                    .settle_open_group(GroupOutcome::Quarantined, Some(&detail))
                    .await?;
                return Err(StepError::GroupUnsettled {
                    group: name,
                    detail,
                });
            }
            // A transaction the server refused changed nothing, so the eager
            // members can still be reversed. That is the property this class
            // exists for, and it is why the failure path here is the *cheap*
            // one rather than a quarantine.
            let what = format!("the atomic members on [{touched}] did not commit: {e}");
            self.cx.abort_open_group(&what).await?;
            return Err(StepError::GroupAborted { what });
        }

        let mut outputs = Vec::with_capacity(deferred.len());
        for member in deferred {
            let kind = AnyEffect::descriptor(&*member.effect).kind;
            let resource = member.resource.clone();
            match self.cx.effect_as_member(member.effect).await {
                Ok(v) => outputs.push(v),
                // Nothing has externalised — no prior deferred member landed, no
                // atomic member committed, and *this* member provably did not
                // reach the world (`DidNotHappen`) — so the group can still be
                // taken back whole. All three conjuncts are load-bearing. The
                // atomic one: an atomic member's write is permanent the moment
                // its transaction commits, has no registered reversal and cannot
                // have one. The `may_have_externalised` one: a member that fails
                // `Landed` or `InDoubt` did or might have taken effect, so an
                // `Aborted` settlement would be the journal claiming "taken back
                // whole" over a write that stands.
                Err(e) if outputs.is_empty() && !atomic_committed && !may_have_externalised(&e) => {
                    let what = format!("deferred member '{kind}' on '{resource}' failed: {e}");
                    self.cx.abort_open_group(&what).await?;
                    return Err(StepError::GroupAborted { what });
                }
                // A member already landed — deferred, atomic, or possibly this
                // one. Reversing now would undo everything except the thing
                // that actually happened, which is the worst of the three
                // answers available.
                Err(e) => {
                    let landed = if atomic_committed {
                        format!(
                            "{} deferred and the atomic members on [{touched}]",
                            outputs.len()
                        )
                    } else {
                        outputs.len().to_string()
                    };
                    let detail = format!(
                        "deferred member '{kind}' on '{resource}' failed after {landed} \
                         landed: {e} — reversing now would undo everything except the \
                         thing that actually happened",
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

    fn open(&mut self) -> Result<&mut OpenGroup, StepError> {
        self.cx.open_group_mut().ok_or_else(no_group)
    }

    /// Refuse a member that must go through `sink`, at the moment it is
    /// registered.
    ///
    /// `StepCtx::effect` refuses any effect exposing outbound arguments,
    /// because the information-flow check cannot be skipped and a group has no
    /// labelled value to bind on a member's behalf. Left to dispatch, that
    /// refusal surfaces during an **abort** — the run is already failing, and
    /// the diagnostic arrives about the undo rather than about the member that
    /// was wrong. Catching it here costs nothing and names the right thing.
    fn check_dispatchable(effect: &dyn AnyEffect) -> Option<String> {
        effect.sink_arguments().is_some().then(|| {
            format!(
                "'{}' binds the arguments it sends, so it must be dispatched with \
                 StepCtx::sink and cannot be a group member — a group has no labelled \
                 value to bind on its behalf",
                effect.descriptor().kind
            )
        })
    }

    fn group_name(&self) -> String {
        self.cx
            .open_group()
            .map_or_else(String::new, |g| g.name.clone())
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

/// Whether a member's failure leaves open the possibility that the call reached
/// the outside world.
///
/// The cheap abort — settling `Aborted`, the journal's claim of *taken back
/// whole* — is available only when this is **false**: the member provably did
/// not externalise (`DidNotHappen`). Two dispositions forfeit that claim, and
/// for the same reason:
///
/// * `InDoubt` — the call may or may not have happened, and reversing a coin
///   flip is a coin flip with the outside world's money on it;
/// * `Landed` — the call *did* happen, so reversing everything around it would
///   undo everything except the thing that actually took effect. A member that
///   fails `Landed` registered no reversal (an undo is built from an output a
///   failed member has none of), so an `Aborted` settlement would be a lie about
///   a write that stands.
///
/// The `Landed` arm is the load-bearing one: excluding only `InDoubt` here let a
/// deferred member return `Landed` (a provider answering 200 with an unusable
/// body) and still take the cheap abort — the group rule that an abort is
/// available only while nothing has externalised, violated for the one member
/// whose failure carries the strongest evidence that it did.
///
/// `Unrecorded` is the same question asked one layer later: the call returned
/// and the journal refused the terminal record. The store error alone cannot
/// say whether dispatch had happened, which is why `perform_once` classifies
/// at the site that knows — flattened into the catch-all below, a deferred
/// send whose `EffectDone` append fails would take the cheap abort, the
/// journal would claim *taken back whole* over an email already delivered,
/// and the orphaned announcement would be re-performed by the next resume.
pub(crate) fn may_have_externalised(e: &StepError) -> bool {
    match e {
        StepError::Undecidable { .. } => true,
        StepError::Unrecorded { disposition, .. } => {
            *disposition != crate::core::Disposition::DidNotHappen
        }
        StepError::Effect(inner) => inner.disposition() != crate::core::Disposition::DidNotHappen,
        // Anything else is a pre-dispatch refusal (a gate, a budget, a footprint
        // check) — the member never left the process, so the cheap abort stands.
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
        // Exactly one `GroupOpened` per open and pass: like the settlement
        // below, the record is not an effect, so a resumed step re-opening
        // its group at the frontier would otherwise announce the same group
        // twice.
        if let Some(recorded) = self.recorded_groups.get_mut(&name)
            && recorded.opened > 0
        {
            recorded.opened -= 1;
        } else {
            self.append(RecordKind::GroupOpened {
                group: name.clone(),
                resources: resources.clone(),
            })
            .await?;
        }
        self.set_open_group(OpenGroup {
            name,
            resources,
            reversals: Vec::new(),
            deferred: Vec::new(),
            atomic: Vec::new(),
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

        // Undo is exempt from the gate, exactly as a compensating phase is: a
        // ceiling exists to bound work, not to strand it half-done. The spend
        // is still billed and journaled, so an overshoot is visible rather than
        // silent.
        //
        // The exemption is set and cleared **around a single call**, with
        // nothing between the two but one `await`, so no path through the
        // reversal can leave it standing. That matters more than it looks: the
        // flag suppresses the manifest check, policy and the budget, so a
        // reversal that returned early with it still set would leave every
        // later effect in the step ungated — a security hole reached by adding
        // an ordinary `?` to a loop.
        self.set_reversing(true);
        let reversed = self.reverse_each(reversals).await;
        self.set_reversing(false);

        match reversed {
            Ok(()) => {
                self.settle_open_group(GroupOutcome::Aborted, Some(why))
                    .await
            }
            Err(detail) => {
                self.settle_open_group(GroupOutcome::Quarantined, Some(&detail))
                    .await?;
                Err(StepError::GroupUnsettled {
                    group: name,
                    detail,
                })
            }
        }
    }

    /// Take the members back, newest first.
    ///
    /// Returns the reason on failure rather than a `StepError`, so the caller
    /// settles the group exactly once and this function has no reason to reach
    /// for `?`.
    async fn reverse_each(&mut self, reversals: Vec<Reversal>) -> Result<(), String> {
        let total = reversals.len();
        for (done, member) in reversals.into_iter().rev().enumerate() {
            let Reversal {
                resource,
                kind,
                undo,
            } = member;
            if let Err(e) = self.effect_as_member(undo).await {
                // Stop. Reversing further members around one that would not
                // come back leaves a shape nobody declared and nobody can read.
                return Err(format!(
                    "reversing '{kind}' on '{resource}' failed after {done} of {total}: {e}"
                ));
            }
        }
        Ok(())
    }

    /// Write the group's ending and close it.
    ///
    /// Exactly once per group and pass: a settlement is not an effect, so the
    /// cursor cannot dedup it, and a resumed step re-reaching its group's end
    /// at the frontier — cursor exhausted, writes enabled — would otherwise
    /// record the same settlement twice. The recorded counts are read back
    /// from the journal when the step starts, and they are counts because two
    /// *distinct* groups may legitimately share a name within one step —
    /// opened, settled, opened again — so each recorded settlement excuses
    /// exactly one re-settlement.
    pub(crate) async fn settle_open_group(
        &mut self,
        outcome: GroupOutcome,
        detail: Option<&str>,
    ) -> Result<(), StepError> {
        let Some(open) = self.take_open_group() else {
            return Err(no_group());
        };
        if let Some(recorded) = self.recorded_groups.get_mut(&open.name)
            && recorded.settled > 0
        {
            recorded.settled -= 1;
            return Ok(());
        }
        self.append(RecordKind::GroupSettled {
            group: open.name,
            outcome,
            detail: detail.map(ToOwned::to_owned),
        })
        .await
    }
}

// ── Applying the atomic members ─────────────────────────────────────────────

/// The group's atomic members, as one unit of work for the store.
///
/// Holds everything needed to build the records *inside* the transaction,
/// because the records carry the members' outputs and nothing outside the
/// transaction can know those yet.
struct GroupCommit {
    run: crate::core::RunId,
    step: crate::core::StepId,
    phase: crate::core::Phase,
    case: Option<crate::core::CaseId>,
    /// Members with the effect key each was assigned, in declaration order.
    members: Vec<(crate::core::EffectKey, AtomicMember)>,
}

impl GroupCommit {
    fn stamp(&self, kind: RecordKind) -> crate::journal::Append {
        let mut a = crate::journal::Append::new(self.run, kind)
            .step(self.step)
            .phase(self.phase);
        if let Some(c) = self.case {
            a = a.case(c);
        }
        a
    }
}

#[async_trait::async_trait]
impl crate::journal::AtomicWork for GroupCommit {
    async fn run(
        &self,
        tx: &dyn crate::journal::AtomicTx,
    ) -> Result<Vec<crate::journal::Append>, crate::core::EffectError> {
        let mut appends = Vec::with_capacity(self.members.len() * 2 + 1);
        for (key, member) in &self.members {
            let descriptor = member.inner.descriptor();
            // Announced and recorded in the same transaction as the work. The
            // announce/record split exists because an ordinary effect acts
            // *outside* the transaction that records it, leaving a window a
            // crash can land in. Here there is no window — so both records are
            // written, for the operator and for replay, but neither is load
            // bearing for recovery.
            appends.push(
                self.stamp(RecordKind::EffectStarted {
                    descriptor: descriptor.clone(),
                    recovery: crate::core::Recovery::Retry,
                    mutates: true,
                    attempt: 1,
                    backoff_ms: 0,
                    // An atomic member binding outbound arguments is refused at
                    // registration — it would need `sink`, and a group has no
                    // labelled value to bind on its behalf.
                    outbound_label: None,
                })
                .effect(*key),
            );
            let output = member.inner.apply(tx).await?;
            appends.push(
                self.stamp(RecordKind::EffectDone {
                    output,
                    source: None,
                    spend: crate::core::Spend::default(),
                    // An atomic member's result never reaches the caller — it
                    // commits with the frontier, so `commit` returns only the
                    // deferred members' values. Recorded conservatively so the
                    // record is honest about a value nothing labelled.
                    declared: crate::core::DeclaredOutput::untrusted(),
                })
                .effect(*key),
            );
        }
        // Deliberately **not** the group's settlement. The guarantee this class
        // offers is that a member's write and the record that it happened
        // commit together; a group is not finished when its transaction is,
        // because deferred members run afterwards and can still fail. A
        // `GroupSettled { Committed }` inside the transaction would be a claim
        // about work that had not been attempted yet.
        //
        // A crash between the transaction and the settlement therefore leaves
        // an opened group with no settlement beside it. That state is healed
        // rather than hunted: the crashed run lands in a backlog the sweep
        // already drains, and the resume re-walks the members from history and
        // settles. The one state no resume repairs — a *sealed* run holding an
        // unsettled group — is an `audit` finding.
        Ok(appends)
    }
}

impl StepCtx<'_> {
    /// Whether this run's store can lend a resource its transaction.
    pub(crate) fn store_is_atomic(&self) -> bool {
        self.journal().atomic().is_some()
    }

    /// Apply the atomic members and settle the group, in one transaction.
    ///
    /// On replay this performs nothing: the members' records are already in
    /// history, so the cursor is walked and the recorded outputs stand. A
    /// transaction re-applied on replay would be a second real write, which is
    /// the failure the effect protocol exists to prevent — atomicity does not
    /// exempt anything from it.
    pub(crate) async fn commit_atomic(
        &mut self,
        group: &str,
        members: Vec<AtomicMember>,
    ) -> Result<(), StepError> {
        let mut keyed = Vec::with_capacity(members.len());
        for member in members {
            let descriptor = member.inner.descriptor();
            let key = self.next_effect_key(&descriptor);
            if self.replaying() {
                // Consume the recorded pair. The output is discarded rather
                // than returned: an atomic member's result is not handed back
                // to the caller in the first place, because it cannot be seen
                // before the frontier it commits with.
                match self.cursor_next(key)? {
                    Some(crate::journal::EffectReplay::Done { .. }) => continue,
                    // The same rule as the ordinary dispatch loop, through the
                    // same implementation: a gate must not re-decide a dispatch
                    // history already settled, so strict re-raises the verdict,
                    // a resume consumes a policy denial verbatim, and a budget
                    // refusal is re-asked against the ledger now in force — a
                    // re-admitted member falls through and dispatches live
                    // below. Ignoring the record here would consume it and
                    // then run the gate fresh, so a resume could dispatch a
                    // member the recorded run was refused.
                    Some(
                        refusal @ (crate::journal::EffectReplay::Refused { .. }
                        | crate::journal::EffectReplay::Denied { .. }),
                    ) => {
                        self.replayed_refusal(key, refusal).await?;
                    }
                    // An atomic member's records commit with its transaction,
                    // so the only things history can hold under its key are
                    // the pair and a gate refusal. A failure or an orphaned
                    // announcement means the recorded run dispatched this call
                    // through a different protocol class than this build does
                    // — divergence the ordered key comparison cannot see,
                    // because the key matches.
                    Some(other) => {
                        return Err(StepError::GroupUnsettled {
                            group: group.to_owned(),
                            detail: format!(
                                "atomic member '{}' replays {other:?}, which an atomic \
                                 member cannot have written — its records commit with \
                                 its transaction, so the recorded run dispatched this \
                                 call through a different protocol class than this \
                                 build does",
                                descriptor.kind
                            ),
                        });
                    }
                    None if self.is_strict() => {
                        return Err(StepError::ReplayOverrun { actual: key });
                    }
                    None => {}
                }
            }
            // Gated **before** the transaction opens, and one member at a
            // time. An atomic member is a write to a real database chosen by
            // skill code and, in the tool-calling tier, shaped by a model:
            // being wrapped in a transaction makes it reliable, not
            // authorised. Skipping this would leave the one mutating path that
            // *commits* as the only one policy, the manifest and the budget all
            // miss.
            //
            // Before rather than inside, because a refusal must cost nothing:
            // opening a transaction to discover the caller had no right to it
            // would be a rollback where a refusal would do, and the journaled
            // denial would land after work the run was never allowed to start.
            self.gate(key, &descriptor, true, None, None).await?;
            keyed.push((key, member));
        }
        if keyed.is_empty() {
            // Everything was replayed, so the settlement is already recorded
            // too — this group committed once and is not committing again.
            return Ok(());
        }

        let work = GroupCommit {
            run: self.run_id(),
            step: self.step_id(),
            phase: self.phase_of(),
            case: self.bound_case(),
            members: keyed,
        };
        let atomic = self
            .journal()
            .atomic()
            .ok_or_else(|| StepError::GroupFootprint {
                group: group.to_owned(),
                detail: "the store stopped offering a transaction between registration \
                         and commit"
                    .to_owned(),
            })?;
        atomic
            .append_atomic(self.run_id(), self.epoch(), &work)
            .await?;
        Ok(())
    }
}
