//! Budgets — bounded cost, enforced deterministically.
//!
//! # Why spend is journaled
//!
//! A budget decision is control flow: "may this effect run?" changes what the
//! run does. So it has to live in the deterministic zone, and everything it
//! reads has to be reproducible.
//!
//! That rules out asking a provider what something cost at replay time — the
//! answer moves. Instead each effect reports its consumption when it completes,
//! the number goes into the `EffectDone` record, and replay adds up the same
//! figures the original run did. A replayed run therefore reaches the same
//! budget verdict at the same point, which is the only way an exhausted budget
//! can be part of a faithful history rather than an artefact of when you looked.
//!
//! # A metered budget stops *after* the limit, not before it
//!
//! A token or cost limit cannot be a hard ceiling, because an operation's cost
//! is not known until it has run. What is enforced is: *once consumption has
//! reached the limit, no further operation starts.* A run can therefore
//! overshoot by at most one operation's cost.
//!
//! That is stated rather than hidden because the alternative — pretending to a
//! hard cap — is how somebody sizes a limit at exactly their ceiling and is
//! surprised. Where a true ceiling matters, set `max_effects` too: counts *are*
//! known in advance, so that limit is exact.
//!
//! # Why wall-clock limits are opt-in
//!
//! Elapsed time cannot be checked without reading a clock, and a clock read is
//! an effect. A wall-clock budget therefore costs one journaled effect per step
//! boundary. That is cheap but not free, so it is only paid when asked for.

use serde::{Deserialize, Serialize};

/// What one effect consumed.
///
/// Deliberately unit-agnostic: the engine never learns what a token is or which
/// currency `minor_units` is in. It adds them up and compares them to a limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spend {
    /// Model tokens, or any other metered unit the deployment counts.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub tokens: u64,
    /// Money in minor units — cents, pence, whatever the deployment uses.
    ///
    /// Integer rather than float: money that rounds differently on two machines
    /// is money that produces two different budget verdicts.
    ///
    /// **Unsigned, and that is a security property rather than tidiness.** Every
    /// ceiling in this crate — a [`Budget`], a [`TenantQuota`], a
    /// [`StandingAuthority`] — is enforced by comparing an accumulated `Spend`
    /// against a limit. A *negative* amount reverses the accumulation, so a
    /// single one un-spends everything before it and the ceiling stops being
    /// one. That was reachable while this was an `i64`: a €500 standing
    /// authority could be drawn to zero, drawn again for −€400, and then drawn
    /// for a further €400 — €900 against a €500 mandate, with every check
    /// passing. Refusing negatives in each of the three enforcement paths would
    /// have been three places to remember; making the state unrepresentable is
    /// none.
    ///
    /// A refund or a credit is therefore not a `Spend`. It is a new
    /// authorization, which is what leaves both decisions on the record.
    ///
    /// [`TenantQuota`]: crate::quota::TenantQuota
    /// [`StandingAuthority`]: crate::authority::StandingAuthority
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub minor_units: u64,
}

impl Spend {
    /// Whether anything was consumed.
    ///
    /// By-reference because `skip_serializing_if` requires it: a zero spend is
    /// the overwhelmingly common case and costs no bytes and no hash input.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.tokens == 0 && self.minor_units == 0
    }
}

// By-reference because `skip_serializing_if` requires it.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

impl Spend {
    #[must_use]
    pub const fn tokens(n: u64) -> Self {
        Self {
            tokens: n,
            minor_units: 0,
        }
    }

    #[must_use]
    pub const fn money(minor_units: u64) -> Self {
        Self {
            tokens: 0,
            minor_units,
        }
    }

    /// By-reference form, for `skip_serializing_if`.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[must_use]
    pub const fn is_free_ref(v: &Self) -> bool {
        v.is_free()
    }

    #[must_use]
    pub const fn is_free(self) -> bool {
        self.tokens == 0 && self.minor_units == 0
    }

    /// Saturating so a runaway meter cannot wrap into a smaller number and
    /// silently re-open a budget that was already blown.
    #[must_use]
    pub fn plus(self, other: Self) -> Self {
        Self {
            tokens: self.tokens.saturating_add(other.tokens),
            minor_units: self.minor_units.saturating_add(other.minor_units),
        }
    }
}

impl std::ops::AddAssign for Spend {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.plus(rhs);
    }
}

/// What a run is allowed to consume.
///
/// Every limit is optional; `Budget::unlimited()` is a legitimate choice for a
/// run that only touches free, local effects. It is not the default, because
/// "nobody set a limit" and "somebody decided no limit was needed" should not
/// look the same in a config file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Plan nodes this run may execute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_steps: Option<usize>,
    /// Externally visible operations.
    ///
    /// The blunt instrument that stops a loop nobody predicted, independent of
    /// what each operation happens to cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_effects: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_minor_units: Option<u64>,
    /// How many times a run may change its plan.
    ///
    /// A run that replans without bound is a run that has stopped making
    /// progress and started thrashing, and the ceiling is what turns that from
    /// an unbounded spend into a reported fault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replans: Option<u32>,
    /// Wall-clock ceiling.
    ///
    /// Costs one journaled clock read per step boundary when set — see the
    /// module docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wallclock_secs: Option<u64>,
    /// How many times the policy may refuse this run before it is stopped.
    ///
    /// **A run that keeps hitting the policy is probing it.** Refusals carry a
    /// uniform message precisely so a model cannot tell one from another
    /// ([`REFUSED`](crate::core::REFUSED)), but the refused/allowed bit itself
    /// still leaks one bit per attempt, and nothing short of fabricating success
    /// removes that. What bounds the channel is bounding the attempts.
    ///
    /// It is an operational ceiling as much as a security one: a run stuck in a
    /// denial loop has stopped making progress, exactly like one that replans
    /// without bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_denials: Option<u32>,
}

impl Budget {
    /// No limits. An explicit choice, not an absence of one.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_steps: None,
            max_effects: None,
            max_tokens: None,
            max_minor_units: None,
            max_replans: None,
            max_wallclock_secs: None,
            max_denials: None,
        }
    }

    #[must_use]
    pub const fn steps(mut self, n: usize) -> Self {
        self.max_steps = Some(n);
        self
    }

    #[must_use]
    pub const fn effects(mut self, n: usize) -> Self {
        self.max_effects = Some(n);
        self
    }

    #[must_use]
    pub const fn tokens(mut self, n: u64) -> Self {
        self.max_tokens = Some(n);
        self
    }

    #[must_use]
    pub const fn minor_units(mut self, n: u64) -> Self {
        self.max_minor_units = Some(n);
        self
    }

    #[must_use]
    pub const fn replans(mut self, n: u32) -> Self {
        self.max_replans = Some(n);
        self
    }

    /// How many policy refusals this run may accrue.
    #[must_use]
    pub const fn denials(mut self, n: u32) -> Self {
        self.max_denials = Some(n);
        self
    }

    #[must_use]
    pub const fn wallclock_secs(mut self, n: u64) -> Self {
        self.max_wallclock_secs = Some(n);
        self
    }

    #[must_use]
    pub const fn tracks_wallclock(&self) -> bool {
        self.max_wallclock_secs.is_some()
    }
}

/// Running totals for one run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consumed {
    pub steps: usize,
    /// Effects **dispatched**, not effects that succeeded.
    ///
    /// A call that fails still consumed a call — it occupied a connection, hit
    /// a rate limit, and may have cost money on the way to failing. Counting
    /// only successes leaves the one loop a ceiling most needs to stop, a
    /// failing call retried forever, costing nothing on paper.
    pub effects: usize,
    pub spend: Spend,
    pub elapsed_secs: u64,
    /// Policy refusals this run has accrued.
    #[serde(default)]
    pub denials: u32,
}

/// Which limit stopped the run, and where it stood.
///
/// Carries the numbers rather than a message: an operator raising a limit needs
/// to know what it actually reached, and "budget exhausted" does not say.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BudgetExceeded {
    #[error("step budget exhausted: {allowed} step(s) permitted")]
    Steps { allowed: usize },

    #[error("effect budget exhausted: {allowed} operation(s) permitted, {used} performed")]
    Effects { allowed: usize, used: usize },

    #[error("replan budget exhausted: {allowed} replan(s) permitted")]
    Replans { allowed: u32 },

    /// The run was refused by the policy more often than it is allowed to be.
    ///
    /// Not a policy failure — a *probing* ceiling. See
    /// [`Budget::max_denials`].
    #[error("denial budget exhausted: {allowed} refusal(s) permitted")]
    Denials { allowed: u32 },

    /// A refusal read back from the journal.
    ///
    /// Carries the recorded limit rather than the one in force now, because a
    /// run replayed under a larger budget still stopped where it stopped.
    #[error("{limit} (recorded: {used})")]
    Recorded { limit: String, used: String },

    #[error("token budget exhausted: {allowed} permitted, {used} consumed")]
    Tokens { allowed: u64, used: u64 },

    #[error("cost budget exhausted: {allowed} minor units permitted, {used} spent")]
    Money { allowed: u64, used: u64 },

    #[error("time budget exhausted: {allowed}s permitted, {used}s elapsed")]
    Wallclock { allowed: u64, used: u64 },
}

impl BudgetExceeded {
    /// Which limit was hit, for a metric label.
    ///
    /// The variant only — never the rendered message. `Display` here embeds the
    /// allowed and used figures, and a label carrying those is a new time series
    /// per distinct budget, which is how a metrics backend falls over. See
    /// `runtime::metrics`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Steps { .. } => "steps",
            Self::Effects { .. } => "effects",
            Self::Replans { .. } => "replans",
            Self::Denials { .. } => "denials",
            Self::Recorded { .. } => "recorded",
            Self::Tokens { .. } => "tokens",
            Self::Money { .. } => "money",
            Self::Wallclock { .. } => "wallclock",
        }
    }
}

/// Tracks a run's consumption against its budget.
///
/// Lives entirely in the deterministic zone: it reads only numbers that came
/// out of the journal, so a replayed run reaches the same verdict at the same
/// point as the original.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    budget: Budget,
    consumed: Consumed,
    /// What *this pass* dispatched, as opposed to what it read back.
    ///
    /// The budget verdict runs on `consumed`, which bills replayed history
    /// exactly as it was billed live so a resumed run reaches the same
    /// exhaustion at the same point. The tenant's quota ledger must not: a run
    /// that suspends and resumes N times would accrue its prefix N times, and
    /// a strict verification would bill a historical run's whole spend into
    /// the current period on every look. This figure carries only the effects
    /// the current pass actually performed, and it is what settlement accrues.
    live: Spend,
}

impl Ledger {
    #[must_use]
    pub const fn new(budget: Budget) -> Self {
        Self {
            budget,
            consumed: Consumed {
                steps: 0,
                effects: 0,
                spend: Spend {
                    tokens: 0,
                    minor_units: 0,
                },
                elapsed_secs: 0,
                denials: 0,
            },
            live: Spend {
                tokens: 0,
                minor_units: 0,
            },
        }
    }

    #[must_use]
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// What the current pass dispatched, excluding everything read from
    /// history. This is the figure a tenant's period ledger accrues; the run's
    /// own budget verdict uses [`consumed`](Self::consumed), which includes
    /// the replayed prefix.
    #[must_use]
    pub const fn live_spend(&self) -> Spend {
        self.live
    }

    #[must_use]
    pub const fn consumed(&self) -> Consumed {
        self.consumed
    }

    /// Whether elapsed time needs measuring at all.
    #[must_use]
    pub const fn tracks_wallclock(&self) -> bool {
        self.budget.tracks_wallclock()
    }

    /// Record measured elapsed time, from a journaled clock read.
    pub const fn observe_elapsed(&mut self, secs: u64) {
        self.consumed.elapsed_secs = secs;
    }

    /// Check whether another step may start.
    ///
    /// Checked *before* dispatch: a step that would exceed the budget must not
    /// half-run and then be stopped.
    pub fn admit_step(&self) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_steps
            && self.consumed.steps >= max
        {
            return Err(BudgetExceeded::Steps { allowed: max });
        }
        self.check_denials()?;
        self.check_time()
    }

    pub const fn record_step(&mut self) {
        self.consumed.steps += 1;
    }

    /// Check whether another effect may be performed.
    ///
    /// Before dispatch — after is too late, since the point of a budget is to
    /// stop the money leaving. Note the semantics for metered limits: an
    /// operation's cost is unknown until it runs, so this refuses once
    /// consumption has *reached* the limit. A run overshoots by at most one
    /// operation. `max_effects` is exact, because counts are known in advance.
    pub fn admit_effect(&self) -> Result<(), BudgetExceeded> {
        // Checked here as well as at the denial itself, and that is the half
        // that actually binds: a probing loop swallows the error it gets back,
        // so refusing the *next* attempt is what stops the probing rather than
        // merely reporting it.
        self.check_denials()?;
        if let Some(max) = self.budget.max_effects
            && self.consumed.effects >= max
        {
            return Err(BudgetExceeded::Effects {
                allowed: max,
                used: self.consumed.effects,
            });
        }
        if let Some(max) = self.budget.max_tokens
            && self.consumed.spend.tokens >= max
        {
            return Err(BudgetExceeded::Tokens {
                allowed: max,
                used: self.consumed.spend.tokens,
            });
        }
        if let Some(max) = self.budget.max_minor_units
            && self.consumed.spend.minor_units >= max
        {
            return Err(BudgetExceeded::Money {
                allowed: max,
                used: self.consumed.spend.minor_units,
            });
        }
        self.check_time()
    }

    /// Add what an effect consumed. The figure comes from the journal, so this
    /// is identical on replay.
    ///
    /// For an effect the current pass actually dispatched, use
    /// [`record_live_effect`](Self::record_live_effect) — this method is the
    /// replay arm, and what it records is deliberately absent from
    /// [`live_spend`](Self::live_spend).
    pub fn record_effect(&mut self, spend: Spend) {
        self.consumed.effects += 1;
        self.consumed.spend += spend;
    }

    /// Add what a **freshly dispatched** effect consumed.
    ///
    /// Identical to [`record_effect`](Self::record_effect) for the budget
    /// verdict, and additionally counted toward [`live_spend`](Self::live_spend)
    /// — the figure the tenant's period ledger accrues at settlement. Calling
    /// this from a replay path would resurrect the double-billing it exists to
    /// remove.
    pub fn record_live_effect(&mut self, spend: Spend) {
        self.record_effect(spend);
        self.live += spend;
    }

    /// Count a policy refusal, and report if that was one too many.
    ///
    /// Counted *after* the refusal rather than checked before it: the run is not
    /// asking permission to be denied, and a refusal that has already been
    /// journaled has already happened. What the ceiling stops is the *next*
    /// attempt — which is the one that would learn something.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded::Denials`] once the run has been refused more often than
    /// its budget allows.
    pub fn record_denial(&mut self) -> Result<(), BudgetExceeded> {
        self.consumed.denials += 1;
        if let Some(max) = self.budget.max_denials
            && self.consumed.denials > max
        {
            return Err(BudgetExceeded::Denials { allowed: max });
        }
        Ok(())
    }

    /// Whether this run may be put in front of the policy again.
    ///
    /// Checked *before* the policy is consulted, which is the only placement
    /// that works: a refusal is journaled as it happens, so a ceiling applied
    /// afterwards bounds nothing an observer can see. Refusing here means the
    /// attempt produces no new record and no new bit.
    ///
    /// # Errors
    ///
    /// [`BudgetExceeded::Denials`] once the run has spent its refusals.
    pub fn admit_policy_check(&self) -> Result<(), BudgetExceeded> {
        self.check_denials()
    }

    fn check_denials(&self) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_denials
            && self.consumed.denials > max
        {
            return Err(BudgetExceeded::Denials { allowed: max });
        }
        Ok(())
    }

    fn check_time(&self) -> Result<(), BudgetExceeded> {
        if let Some(max) = self.budget.max_wallclock_secs
            && self.consumed.elapsed_secs >= max
        {
            return Err(BudgetExceeded::Wallclock {
                allowed: max,
                used: self.consumed.elapsed_secs,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlimited_budget_admits_everything() {
        let mut l = Ledger::new(Budget::unlimited());
        for _ in 0..1000 {
            l.admit_effect().unwrap();
            l.record_effect(Spend::tokens(10_000));
        }
        l.admit_step().unwrap();
    }

    #[test]
    fn the_step_limit_stops_the_next_step() {
        let mut l = Ledger::new(Budget::default().steps(2));
        l.admit_step().unwrap();
        l.record_step();
        l.admit_step().unwrap();
        l.record_step();
        assert!(matches!(
            l.admit_step().unwrap_err(),
            BudgetExceeded::Steps { allowed: 2 }
        ));
    }

    /// The blunt instrument: a loop nobody predicted is stopped by count, even
    /// when every individual operation is free.
    #[test]
    fn the_effect_limit_stops_a_runaway_loop_of_free_operations() {
        let mut l = Ledger::new(Budget::default().effects(3));
        for _ in 0..3 {
            l.admit_effect().unwrap();
            l.record_effect(Spend::default());
        }
        assert!(matches!(
            l.admit_effect().unwrap_err(),
            BudgetExceeded::Effects {
                allowed: 3,
                used: 3
            }
        ));
    }

    #[test]
    fn the_token_limit_reports_where_it_stood() {
        let mut l = Ledger::new(Budget::default().tokens(100));
        l.admit_effect().unwrap();
        l.record_effect(Spend::tokens(150));
        match l.admit_effect().unwrap_err() {
            BudgetExceeded::Tokens { allowed, used } => {
                assert_eq!(
                    (allowed, used),
                    (100, 150),
                    "raise-the-limit needs the numbers"
                );
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn the_cost_limit_uses_integers() {
        let mut l = Ledger::new(Budget::default().minor_units(500));
        l.admit_effect().unwrap();
        l.record_effect(Spend::money(499));
        l.admit_effect().expect("still under");
        l.record_effect(Spend::money(2));
        assert!(matches!(
            l.admit_effect().unwrap_err(),
            BudgetExceeded::Money {
                allowed: 500,
                used: 501
            }
        ));
    }

    #[test]
    fn elapsed_time_is_only_checked_when_asked_for() {
        let mut unbounded = Ledger::new(Budget::default().steps(10));
        assert!(!unbounded.tracks_wallclock());
        unbounded.observe_elapsed(99_999);
        unbounded.admit_step().expect("no wall-clock limit was set");

        let mut bounded = Ledger::new(Budget::default().wallclock_secs(60));
        assert!(bounded.tracks_wallclock());
        bounded.observe_elapsed(61);
        assert!(matches!(
            bounded.admit_step().unwrap_err(),
            BudgetExceeded::Wallclock {
                allowed: 60,
                used: 61
            }
        ));
    }

    /// A negative amount must not be *representable*, not merely refused.
    ///
    /// Every ceiling in this crate is an accumulate-and-compare, so one negative
    /// figure un-spends everything before it. When `minor_units` was an `i64`
    /// that was reachable and demonstrated: a €500 standing authority drawn to
    /// zero, drawn again for −€400, then drawn for a further €400 — €900 against
    /// a €500 mandate, with the ceiling check passing at every step.
    ///
    /// The fix was the type, so the compiler covers every caller and the three
    /// enforcement paths need no rule of their own. What the compiler does *not*
    /// cover is the deserialization boundary — a journal record, a stored row, a
    /// manifest — and that is what this pins. Flip the field back to a signed
    /// integer and these parse successfully instead of failing, which is the
    /// only externally visible difference the change makes.
    #[test]
    fn a_negative_amount_does_not_deserialize() {
        serde_json::from_str::<Spend>(r#"{"minor_units":-1}"#)
            .expect_err("a negative spend un-spends every ceiling comparing against it");
        serde_json::from_str::<Budget>(r#"{"max_minor_units":-1}"#)
            .expect_err("a negative ceiling is not a ceiling");

        // The positive half, so a refuse-everything change cannot pass: the
        // ordinary forms still parse, and to the value they name.
        assert_eq!(
            serde_json::from_str::<Spend>(r#"{"minor_units":250}"#).expect("an ordinary spend"),
            Spend::money(250)
        );
        assert_eq!(
            serde_json::from_str::<Budget>(r#"{"max_minor_units":250}"#)
                .expect("an ordinary ceiling")
                .max_minor_units,
            Some(250)
        );
    }

    /// A wrapping meter would silently re-open a budget that was already blown.
    #[test]
    fn spend_saturates_rather_than_wrapping() {
        let huge = Spend {
            tokens: u64::MAX,
            minor_units: u64::MAX,
        };
        let sum = huge.plus(Spend::tokens(10)).plus(Spend::money(10));
        assert_eq!(sum.tokens, u64::MAX);
        assert_eq!(sum.minor_units, u64::MAX);
    }

    /// The same journaled figures produce the same verdict — the property that
    /// makes an exhausted budget part of history rather than an artefact.
    #[test]
    fn the_same_figures_produce_the_same_verdict() {
        let replay = |spends: &[Spend]| {
            let mut l = Ledger::new(Budget::default().tokens(100));
            let mut stopped_at = None;
            for (i, s) in spends.iter().enumerate() {
                if l.admit_effect().is_err() {
                    stopped_at = Some(i);
                    break;
                }
                l.record_effect(*s);
            }
            stopped_at
        };
        let spends = [Spend::tokens(40); 5];
        assert_eq!(
            replay(&spends),
            replay(&spends),
            "same figures, same verdict"
        );
        // 0, 40, 80 all admit; at 120 consumption has reached the 100 limit.
        assert_eq!(replay(&spends), Some(3));
    }

    /// A metered budget is overshot by at most one operation, because an
    /// operation's cost is not known until it has run.
    ///
    /// Stated as a test so nobody has to discover it by sizing a limit at their
    /// actual ceiling.
    #[test]
    fn a_metered_budget_overshoots_by_at_most_one_operation() {
        let mut l = Ledger::new(Budget::default().tokens(100));
        l.admit_effect().unwrap();
        l.record_effect(Spend::tokens(99));
        l.admit_effect().expect("99 has not reached 100");
        l.record_effect(Spend::tokens(1_000_000));

        assert!(l.admit_effect().is_err(), "but nothing further starts");
        assert_eq!(l.consumed().spend.tokens, 1_000_099);
    }

    /// An effect *count* limit is exact, because counts are known in advance.
    #[test]
    fn an_effect_count_budget_is_exact() {
        let mut l = Ledger::new(Budget::default().effects(2));
        l.admit_effect().unwrap();
        l.record_effect(Spend::tokens(1));
        l.admit_effect().unwrap();
        l.record_effect(Spend::tokens(1));
        assert!(l.admit_effect().is_err());
        assert_eq!(l.consumed().effects, 2, "never more than asked for");
    }
}

#[cfg(test)]
mod denial_tests {
    use super::*;

    /// The ceiling admits exactly as many refusals as it names.
    #[test]
    fn the_denial_ceiling_admits_what_it_says_and_no_more() {
        let mut ledger = Ledger::new(Budget::unlimited().denials(3));
        for i in 1..=3 {
            assert!(
                ledger.record_denial().is_ok(),
                "refusal {i} is within a ceiling of 3"
            );
        }
        assert!(matches!(
            ledger.record_denial(),
            Err(BudgetExceeded::Denials { allowed: 3 })
        ));
    }

    /// Past the ceiling, nothing further is admitted.
    ///
    /// The half that actually binds: a probing loop swallows the error it gets
    /// back, so what stops the probing is refusing the *next* attempt rather
    /// than reporting the last one.
    #[test]
    fn past_the_ceiling_no_further_effect_is_admitted() {
        let mut ledger = Ledger::new(Budget::unlimited().denials(1));
        assert!(ledger.admit_effect().is_ok());
        let _ = ledger.record_denial();
        assert!(
            ledger.admit_effect().is_ok(),
            "one refusal is within a ceiling of one"
        );
        let _ = ledger.record_denial();
        assert!(
            matches!(
                ledger.admit_effect(),
                Err(BudgetExceeded::Denials { allowed: 1 })
            ),
            "past the ceiling the next attempt must be refused before it is \
             performed, or the loop keeps learning"
        );
        assert!(
            matches!(
                ledger.admit_step(),
                Err(BudgetExceeded::Denials { allowed: 1 })
            ),
            "and the run must not be admitted to a further step"
        );
    }

    /// No ceiling set means no ceiling applied.
    #[test]
    fn an_unset_denial_ceiling_does_not_bind() {
        let mut ledger = Ledger::new(Budget::unlimited());
        for _ in 0..1_000 {
            assert!(ledger.record_denial().is_ok());
        }
        assert!(ledger.admit_effect().is_ok());
    }
}
