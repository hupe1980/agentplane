#![cfg(feature = "redb")]

//! Per-tenant ceilings.
//!
//! Budgets bound one run; these bound a tenant. The failure they answer is the
//! noisy neighbour: a caller that can start runs can start a thousand, each
//! perfectly within its own budget, and the plane's compute and the deployment's
//! model bill are somebody else's problem.
//!
//! Two properties get the most attention because both fail silently. A ceiling
//! must be **durable**, or it doubles the moment a second instance starts — the
//! moment it was needed. And it must be **per tenant**, or one busy tenant
//! throttles everybody, which is a shared ceiling wearing a per-tenant name.

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Spend, Tainted, TenantId};
use agentplane::journal::JournalStore;
use agentplane::quota::{Period, QuotaError, QuotaStore, TenantQuota};
use agentplane::runtime::{RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

/// A skill that does nothing, so a run's shape is the only variable.
#[derive(Debug)]
struct Work;

#[async_trait::async_trait]
impl Skill for Work {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("work").provides("work")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(Tainted::trusted(json!({"ok": true}))))
    }
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).expect("valid")
}

fn plane(store: &RedbStore, name: &str, quota: TenantQuota) -> Arc<Runtime> {
    let scoped = Arc::new(store.clone().for_tenant(tenant(name)));
    Runtime::builder(scoped.clone() as Arc<dyn JournalStore>)
        .tenant(tenant(name))
        .quota(scoped as Arc<dyn QuotaStore>, quota)
        .skill(Work)
        .build()
}

// ── Concurrency ─────────────────────────────────────────────────────────────

/// A tenant at its concurrency ceiling is refused, and told to come back.
///
/// The refusal is deliberately a *distinct* error from a policy denial, because
/// they call for opposite responses: a denial says "you may not" and retrying is
/// pointless, a quota refusal says "not right now" and the caller should return.
/// Collapsing them teaches callers to retry denials, or to give up on
/// back-pressure.
#[tokio::test]
async fn a_tenant_at_its_ceiling_is_refused() {
    let store = RedbStore::open_in_memory().expect("store");
    let scoped = Arc::new(store.for_tenant(tenant("acme")));

    let quotas = Arc::clone(&scoped) as Arc<dyn QuotaStore>;
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("instant");

    let first = agentplane::core::RunId::generate();
    let second = agentplane::core::RunId::generate();

    quotas
        .reserve(first, Some(1), at)
        .await
        .expect("first fits");

    let refused = quotas.reserve(second, Some(1), at).await;
    assert!(
        matches!(refused, Err(QuotaError::TooManyRuns { running: 1, .. })),
        "a second run was admitted past a ceiling of one: {refused:?}"
    );

    // Releasing the first makes room — the ceiling is back-pressure, not a
    // permanent refusal.
    quotas.release(first).await.expect("release");
    quotas
        .reserve(second, Some(1), at)
        .await
        .expect("the slot freed by the first run was not reusable");
}

/// Reserving the same run twice takes one slot, not two.
///
/// A retried admission must not consume a second slot, and must not be refused
/// against a ceiling it is already counted in — otherwise a transient store
/// error during admission permanently costs the tenant capacity.
#[tokio::test]
async fn reserving_the_same_run_twice_takes_one_slot() {
    let store = RedbStore::open_in_memory().expect("store");
    let quotas = Arc::new(store.for_tenant(tenant("acme"))) as Arc<dyn QuotaStore>;
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("instant");
    let run = agentplane::core::RunId::generate();

    quotas.reserve(run, Some(1), at).await.expect("first");
    quotas
        .reserve(run, Some(1), at)
        .await
        .expect("a retried admission was refused against its own slot");
    assert_eq!(
        quotas.running().await.expect("count"),
        1,
        "one run holds two slots, so a retry permanently costs the tenant capacity"
    );
}

/// One tenant's ceiling does not throttle another's.
///
/// The whole point of *per-tenant*. A count taken over the whole table rather
/// than the tenant's range would make one busy tenant throttle everybody, which
/// is a shared ceiling wearing a per-tenant name — and it would look correct in
/// every single-tenant test.
#[tokio::test]
async fn one_tenants_ceiling_does_not_throttle_another() {
    let base = RedbStore::open_in_memory().expect("store");
    let acme = Arc::new(base.clone().for_tenant(tenant("acme"))) as Arc<dyn QuotaStore>;
    let globex = Arc::new(base.for_tenant(tenant("globex"))) as Arc<dyn QuotaStore>;
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("instant");

    // Acme fills its ceiling.
    acme.reserve(agentplane::core::RunId::generate(), Some(1), at)
        .await
        .expect("acme fits");
    assert!(
        acme.reserve(agentplane::core::RunId::generate(), Some(1), at)
            .await
            .is_err(),
        "acme's own ceiling did not hold"
    );

    // Globex is unaffected.
    globex
        .reserve(agentplane::core::RunId::generate(), Some(1), at)
        .await
        .expect("one tenant's runs consumed another tenant's ceiling");
    assert_eq!(globex.running().await.expect("count"), 1);
    assert_eq!(acme.running().await.expect("count"), 1);
}

// ── Spend ───────────────────────────────────────────────────────────────────

/// Spend accrues per period, and a period at its ceiling refuses.
#[tokio::test]
async fn a_tenant_that_has_spent_its_period_is_refused() {
    let store = RedbStore::open_in_memory().expect("store");
    let quotas = Arc::new(store.for_tenant(tenant("acme"))) as Arc<dyn QuotaStore>;
    let quota = TenantQuota {
        max_tokens_per_period: Some(1_000),
        ..TenantQuota::default()
    };

    quotas
        .accrue("2026-08", Spend::tokens(400))
        .await
        .expect("accrue");
    quotas
        .accrue("2026-08", Spend::tokens(600))
        .await
        .expect("accrue again");

    let spent = quotas.spent("2026-08").await.expect("read");
    assert_eq!(
        spent.tokens, 1_000,
        "two accruals were not summed — reading, adding and writing back loses \
         one of two concurrent updates, and the one it loses is spend already \
         incurred"
    );
    assert!(
        agentplane::quota::check_spend("acme", "2026-08", &quota, spent).is_err(),
        "a tenant at exactly its ceiling was allowed to start more work"
    );

    // A different period is a clean slate — the window is a billing period, so
    // this is the behaviour a bill implies.
    let next = quotas.spent("2026-09").await.expect("read");
    assert_eq!(next.tokens, 0);
    assert!(agentplane::quota::check_spend("acme", "2026-09", &quota, next).is_ok());
}

/// A period key is derived from the instant, and orders lexicographically.
#[test]
fn period_keys_sort_in_time_order() {
    let at = |s: i64| agentplane::core::Timestamp::from_unix_timestamp(s).expect("instant");
    // 2026-01-05 and 2026-11-05: the month must be zero-padded or "2026-11"
    // sorts before "2026-2", and a range scan over a tenant's periods reads
    // them out of order.
    let jan = Period::Monthly.key_for(at(1_767_600_000));
    let nov = Period::Monthly.key_for(at(1_794_000_000));
    assert!(
        jan < nov,
        "period keys do not sort in time order: {jan} vs {nov}"
    );
    assert_eq!(jan.len(), nov.len(), "keys must be fixed width to sort");

    let daily = Period::Daily.key_for(at(1_767_600_000));
    assert_eq!(daily.len(), 10, "a daily key is YYYY-MM-DD: {daily}");
}

// ── Through the runtime ─────────────────────────────────────────────────────

/// A run refused on quota leaves nothing behind.
///
/// The check runs before the lease and before any record, so a throttled tenant
/// does not accumulate half-open runs its next request has to step over — and
/// the journal never gains a run that did not happen.
#[tokio::test]
async fn a_refused_run_writes_nothing() {
    let store = RedbStore::open_in_memory().expect("store");
    let rt = plane(
        &store,
        "acme",
        TenantQuota {
            max_concurrent_runs: Some(0),
            ..TenantQuota::default()
        },
    );

    let refused = rt.run("work", Tainted::trusted(json!({}))).await;
    assert!(
        matches!(
            refused,
            Err(agentplane::core::RuntimeError::QuotaExceeded(_))
        ),
        "a run was admitted past a ceiling of zero: {refused:?}"
    );

    let scoped = store.for_tenant(tenant("acme"));
    assert_eq!(
        QuotaStore::running(&scoped).await.expect("count"),
        0,
        "a refused run left a slot held, so the tenant's capacity shrinks every \
         time it is throttled"
    );
}

/// A finished run gives its slot back and reports what it spent.
#[tokio::test]
async fn a_finished_run_frees_its_slot() {
    let store = RedbStore::open_in_memory().expect("store");
    let rt = plane(
        &store,
        "acme",
        TenantQuota {
            max_concurrent_runs: Some(1),
            ..TenantQuota::default()
        },
    );

    for _ in 0..3 {
        let out = rt
            .run("work", Tainted::trusted(json!({})))
            .await
            .expect("run");
        assert_eq!(out.status, RunStatus::Succeeded);
    }

    let scoped = store.for_tenant(tenant("acme"));
    assert_eq!(
        QuotaStore::running(&scoped).await.expect("count"),
        0,
        "finished runs still hold their slots, so a ceiling of one permits one \
         run per process lifetime"
    );
}

/// redb, held to the quota contract.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn redb_satisfies_the_quota_store_contract() {
    let store = RedbStore::open_in_memory().expect("store");
    let scoped = store.for_tenant(tenant("conformance"));

    let mut report = agentplane::testkit::conformance::Report::default();
    agentplane::testkit::conformance_quota::check(&scoped, &mut report).await;
    report.assert_conforms("RedbStore (quota)");
}

/// Replay never consults the quota, so a ceiling cannot rewrite the past.
///
/// A quota is wall-clock, mutable state that lives outside the chain. If replay
/// asked it, then re-reading a run that genuinely happened could produce a
/// *refusal* — because the tenant has since filled its ceiling, or because a
/// slot for that run is no longer held. History would then say something
/// different on the second reading, which is the one thing a journal exists to
/// prevent.
///
/// Checked by exhausting the ceiling after the run and replaying anyway.
#[tokio::test]
async fn replay_does_not_consult_the_quota() {
    use agentplane::runtime::Mode;

    let store = RedbStore::open_in_memory().expect("store");
    let rt = plane(
        &store,
        "acme",
        TenantQuota {
            max_concurrent_runs: Some(1),
            ..TenantQuota::default()
        },
    );

    let out = rt
        .run("work", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);

    // Fill the tenant's ceiling with something else entirely, so any quota
    // question asked during replay would be answered "no".
    let scoped = Arc::new(store.for_tenant(tenant("acme"))) as Arc<dyn QuotaStore>;
    let at = agentplane::core::Timestamp::from_unix_timestamp(1_760_000_000).expect("instant");
    scoped
        .reserve(agentplane::core::RunId::generate(), Some(1), at)
        .await
        .expect("occupy the ceiling");

    let replayed = rt
        .replay(out.run_id, Mode::Strict)
        .await
        .expect("a completed run could not be re-read once its tenant was at its ceiling");
    assert_eq!(
        replayed.status,
        RunStatus::Succeeded,
        "replaying a finished run produced a different outcome because of a \
         ceiling crossed after it ran — history now says something it did not"
    );
}

/// A quota refusal is distinguishable from a policy denial.
///
/// They call for opposite responses. A denial says *you may not*, and retrying
/// is pointless. A ceiling says *not right now*, and the caller should come back
/// when a run finishes. Collapsing them into one error teaches callers either to
/// retry denials forever or to abandon work that would succeed in a second.
#[tokio::test]
async fn a_quota_refusal_is_not_a_policy_denial() {
    use agentplane::core::RuntimeError;

    let store = RedbStore::open_in_memory().expect("store");
    let rt = plane(
        &store,
        "acme",
        TenantQuota {
            max_concurrent_runs: Some(0),
            ..TenantQuota::default()
        },
    );

    match rt.run("work", Tainted::trusted(json!({}))).await {
        Err(RuntimeError::QuotaExceeded(QuotaError::TooManyRuns { running, .. })) => {
            assert_eq!(running, 0, "the refusal must report the count it saw");
        }
        Err(RuntimeError::PolicyDenied(_)) => panic!(
            "a ceiling was reported as a policy denial, so a caller told to \
             stop trying will never come back for capacity that frees in a second"
        ),
        other => panic!("expected a quota refusal, got {other:?}"),
    }
}

/// The emergency stop refuses new work, across instances, and says why.
///
/// Three properties in one test because they are one control:
///
/// * it refuses a tenant with **no ceilings at all** — the halt is checked
///   before the unlimited shortcut, because an unlimited tenant is exactly the
///   one an operator is most likely to need to stop;
/// * the refusal is **its own error**, not a ceiling. A ceiling says *not right
///   now* and invites a retry, which is what somebody pulling this switch is
///   trying to stop;
/// * a **second plane on the same store** refuses too, because the flag is in
///   the store. An in-process switch stops only the instance it was thrown on,
///   which is the in-process-counter failure arriving during an incident.
#[tokio::test]
async fn a_halt_refuses_new_runs_on_every_instance_and_names_the_reason() {
    let store = RedbStore::open_in_memory().expect("store");
    // Deliberately unlimited: a halt is not a ceiling.
    let one = plane(&store, "acme", TenantQuota::default());
    let two = plane(&store, "acme", TenantQuota::default());

    // The positive half, first: nothing is refused before the switch is thrown.
    assert_eq!(
        one.run("work", Tainted::trusted(json!({})))
            .await
            .expect("run")
            .status,
        RunStatus::Succeeded
    );

    one.set_halt(Some("incident 42: ledger reconciliation is wrong"))
        .await
        .expect("halt");

    for (which, rt) in [("the halting instance", &one), ("a second instance", &two)] {
        match rt.run("work", Tainted::trusted(json!({}))).await {
            Err(agentplane::core::RuntimeError::QuotaExceeded(
                agentplane::quota::QuotaError::Halted { tenant, reason },
            )) => {
                assert_eq!(tenant, "acme");
                assert!(
                    reason.contains("incident 42"),
                    "{which}: the refusal must carry the operator's reason, got '{reason}'"
                );
            }
            other => panic!("{which} admitted a run while halted: {other:?}"),
        }
    }

    // Another tenant on the same store is untouched: a halt is per tenant, or
    // an incident in one customer's data stops everybody else's business too.
    let other = plane(&store, "globex", TenantQuota::default());
    assert_eq!(
        other
            .run("work", Tainted::trusted(json!({})))
            .await
            .expect("run")
            .status,
        RunStatus::Succeeded,
        "halting one tenant stopped another"
    );

    one.set_halt(None).await.expect("lift");
    assert_eq!(
        two.run("work", Tainted::trusted(json!({})))
            .await
            .expect("run")
            .status,
        RunStatus::Succeeded,
        "work did not resume on the second instance after the halt was lifted"
    );
}

// ── Accrual across passes ───────────────────────────────────────────────────

/// A metered effect for the accrual tests: real spend, no other behaviour.
#[derive(Debug)]
struct Costs(u64);

#[async_trait::async_trait]
impl agentplane::core::Effect for Costs {
    type Output = Value;
    fn descriptor(&self) -> agentplane::core::EffectDescriptor {
        agentplane::core::EffectDescriptor::new("test.costly", json!(null))
    }
    fn mutates(&self) -> bool {
        false
    }
    fn recovery(&self) -> agentplane::core::Recovery {
        agentplane::core::Recovery::Retry
    }
    fn spend(&self, _out: &Value) -> Spend {
        Spend::tokens(self.0)
    }
    async fn perform(&self) -> Result<Value, agentplane::core::EffectError> {
        Ok(json!({"ok": true}))
    }
}

/// Spends 100 tokens, then sleeps a minute, then finishes.
#[derive(Debug)]
struct SpendThenSleep;

#[async_trait::async_trait]
impl Skill for SpendThenSleep {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("spender").provides("spender")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Costs(100)).await?;
        cx.sleep(std::time::Duration::from_secs(60)).await?;
        Ok(Outcome::done(Tainted::trusted(json!({"ok": true}))))
    }
}

/// The period key settlement writes under, derived the same way it derives it.
///
/// The clock read is the test harness establishing "now", not a step smuggling
/// non-determinism past the journal — the same exemption the sweep tests take.
#[allow(clippy::disallowed_methods)]
fn this_period(quota: &TenantQuota) -> String {
    quota.period.key_for(agentplane::core::Timestamp::now_utc())
}

/// A suspend/resume cycle accrues each token once, not once per pass.
///
/// The run's own budget deliberately re-bills replayed history so a resume
/// exhausts where the original did — but the tenant's period ledger must not,
/// or a run that suspends N times accrues its prefix N times and the ceiling
/// fills with phantom spend. The positive half: the total does arrive — one
/// hundred tokens spent is one hundred accrued, on whichever pass dispatched
/// them.
#[tokio::test]
async fn a_resumed_run_accrues_its_spend_once() {
    use agentplane::case::TimerStore;

    let quota = TenantQuota {
        max_tokens_per_period: Some(1_000_000),
        ..TenantQuota::default()
    };
    let store = RedbStore::open_in_memory().expect("store");
    let scoped = Arc::new(store.clone().for_tenant(tenant("acme")));
    let rt = Runtime::builder(scoped.clone() as Arc<dyn JournalStore>)
        .tenant(tenant("acme"))
        .owner("t")
        .timers(scoped.clone() as Arc<dyn TimerStore>)
        .quota(scoped.clone() as Arc<dyn QuotaStore>, quota)
        .skill(SpendThenSleep)
        .build();

    let out = rt
        .run("spender", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert!(out.status.is_suspended(), "the sleep must suspend the run");

    let period = this_period(&quota);
    let after_suspend = QuotaStore::spent(scoped.as_ref(), &period)
        .await
        .expect("read");
    assert_eq!(
        after_suspend.tokens, 100,
        "the suspending pass dispatched the effect, so it accrues it"
    );

    // Fire the timer far in the future; the resume replays the effect from
    // history and finishes the run.
    #[allow(clippy::disallowed_methods)]
    let later = agentplane::core::Timestamp::now_utc() + std::time::Duration::from_secs(3600);
    assert_eq!(rt.fire_timers(later).await.expect("fire").fired, 1);

    let after_resume = QuotaStore::spent(scoped.as_ref(), &period)
        .await
        .expect("read");
    assert_eq!(
        after_resume.tokens, 100,
        "the resume read the effect back from history and accrued it again — \
         every suspend/resume cycle re-bills the prefix"
    );
}

/// A strict verification accrues nothing and releases nobody's lease.
///
/// Strict is a read: it dispatches nothing, so billing its pass into the
/// current period would charge the tenant once per audit for work done long
/// ago. The positive half is above — the live pass did accrue.
#[tokio::test]
async fn a_strict_pass_accrues_no_spend() {
    use agentplane::runtime::Mode;

    let quota = TenantQuota {
        max_tokens_per_period: Some(1_000_000),
        ..TenantQuota::default()
    };
    let store = RedbStore::open_in_memory().expect("store");
    let scoped = Arc::new(store.clone().for_tenant(tenant("acme")));
    let rt = Runtime::builder(scoped.clone() as Arc<dyn JournalStore>)
        .tenant(tenant("acme"))
        .owner("t")
        .quota(scoped.clone() as Arc<dyn QuotaStore>, quota)
        .skill(SpendsOnce)
        .build();

    let out = rt
        .run("spends-once", Tainted::trusted(json!({})))
        .await
        .expect("run");
    assert_eq!(out.status, RunStatus::Succeeded);

    let period = this_period(&quota);
    let live = QuotaStore::spent(scoped.as_ref(), &period)
        .await
        .expect("read");
    assert_eq!(live.tokens, 100, "the live run accrues its spend");

    for _ in 0..2 {
        rt.replay(out.run_id, Mode::Strict).await.expect("strict");
    }
    let after = QuotaStore::spent(scoped.as_ref(), &period)
        .await
        .expect("read");
    assert_eq!(
        after.tokens, 100,
        "a strict verification billed a historical run's spend into the \
         current period"
    );
}

/// Spends 100 tokens and finishes — the strict test's fixture.
#[derive(Debug)]
struct SpendsOnce;

#[async_trait::async_trait]
impl Skill for SpendsOnce {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("spends-once").provides("spends-once")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        cx.effect(Costs(100)).await?;
        Ok(Outcome::done(Tainted::trusted(json!({"ok": true}))))
    }
}
