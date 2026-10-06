#![cfg(all(feature = "redb", feature = "manifest"))]
#![allow(clippy::disallowed_methods)]

//! A tool's rate ceiling, across runs.
//!
//! Every other ceiling sees one run, or a tenant's runs and money. This one
//! counts calls to one tool across every run of a tenant, in the quota store,
//! and refuses the one past the ceiling before it is announced. Three things
//! carry the weight: a retry or a recovery spends once, a refusal is history
//! that replay reads back rather than re-asks, and a refused run stops where an
//! operator can find it and lift it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use agentplane::core::{ArgSource, PlanIR, PlanNode};
use agentplane::core::{
    BudgetExceeded, Outcome, RetryPolicy, RunId, Skill, SkillDescriptor, SkillError, Spend,
    StoreError, Tainted, TenantId, Timestamp,
};
use agentplane::journal::{JournalStore, RecordKind};
use agentplane::manifest::Manifest;
use agentplane::quota::{
    Halt, HaltScope, Held, QuotaError, QuotaSettlement, QuotaStore, RateCeiling, RateReservation,
    SpendHold, TenantQuota,
};
use agentplane::runtime::{Agent, BuildError, Mode, RunStatus, Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::tools::{ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety};
use serde_json::{Value, json};

const REFUND: &str = "tool://payments/refund";

fn tenant() -> TenantId {
    TenantId::new("acme").expect("valid")
}

/// A payments server that counts what reaches it, and can fail its first
/// calls as unreachable so a retry policy takes a second attempt.
#[derive(Debug, Default)]
struct Payments {
    calls: AtomicUsize,
    lookups: AtomicUsize,
    fail_first: AtomicUsize,
}

#[async_trait::async_trait]
impl ToolClient for Payments {
    async fn call(
        &self,
        tool: &ToolId,
        _arguments: &Value,
        _provenance: Option<&agentplane::core::Provenance>,
    ) -> Result<Value, ToolError> {
        if tool.tool == "lookup" {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            return Ok(json!({ "found": true }));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_first
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(ToolError::Unreachable {
                tool: tool.clone(),
                detail: "injected".to_owned(),
            });
        }
        Ok(json!({ "refunded": true }))
    }

    fn destination(&self, _tool: &ToolId) -> agentplane::tools::Destination {
        agentplane::tools::Destination::Local
    }
}

/// Issues one refund per run, and — asked to — carries on to a lookup when the
/// refund is refused, so a test can see what the refusal cost the run.
#[derive(Debug)]
struct Refunds {
    name: &'static str,
    capability: &'static str,
    carry_on: bool,
}

impl Refunds {
    const fn new() -> Self {
        Self {
            name: "refunds",
            capability: "refund",
            carry_on: false,
        }
    }
}

#[async_trait::async_trait]
impl Skill for Refunds {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new(self.name).provides(self.capability)
    }
    fn compensation(&self) -> agentplane::core::Compensation {
        agentplane::core::Compensation::Compensatable
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let refunded = cx.call_tool(ToolId::new("payments", "refund"), input).await;
        match refunded {
            Err(e) if self.carry_on => {
                let found = cx
                    .call_tool(
                        ToolId::new("payments", "lookup"),
                        Tainted::trusted(json!({})),
                    )
                    .await?;
                Ok(Outcome::done(Tainted::trusted(
                    json!({ "refused": e.to_string(), "found": found.peek() }),
                )))
            }
            Err(e) => Err(e.into()),
            Ok(answer) => Ok(Outcome::done(answer)),
        }
    }
    async fn compensate(
        &self,
        cx: &mut StepCtx<'_>,
        _output: &Tainted<Value>,
    ) -> Result<(), SkillError> {
        cx.call_tool(
            ToolId::new("payments", "refund"),
            Tainted::trusted(json!({ "undo": true })),
        )
        .await?;
        Ok(())
    }
}

/// The step after the refund, which fails so the refund is taken back.
#[derive(Debug)]
struct Fails;

#[async_trait::async_trait]
impl Skill for Fails {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("fails").provides("fails")
    }
    async fn invoke(
        &self,
        _cx: &mut StepCtx<'_>,
        _input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Err(SkillError::Other("after the refund".to_owned()))
    }
}

fn declaration(name: &str, capability: &str, version: &str, rate: &str, budgets: &str) -> Manifest {
    Manifest::parse(&format!(
        "
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: {name}, version: '{version}' }}
spec:
  capabilities: {{ provides: [{capability}] }}
  tools:
    - ref: {REFUND}
      mutates: false
      rate_limit: {rate}
    - ref: tool://payments/lookup
      mutates: false
  budgets: {budgets}
"
    ))
    .expect("a well-formed declaration")
}

fn refunder(rate: &str) -> Manifest {
    declaration("refunder", "refund", "1.0.0", rate, "{}")
}

fn catalog(retry: bool) -> Arc<ToolCatalog> {
    let refund = if retry {
        ToolSafety::read_only().retry(
            RetryPolicy::attempts(3)
                .with_backoff(
                    std::time::Duration::from_millis(1),
                    std::time::Duration::from_millis(1),
                )
                .without_jitter(),
        )
    } else {
        ToolSafety::read_only()
    };
    Arc::new(
        ToolCatalog::new()
            .allow(ToolId::new("payments", "refund"), refund)
            .allow(ToolId::new("payments", "lookup"), ToolSafety::read_only()),
    )
}

fn scoped() -> Arc<RedbStore> {
    Arc::new(
        RedbStore::open_in_memory()
            .expect("store")
            .for_tenant(tenant()),
    )
}

fn plane(
    journal: Arc<dyn JournalStore>,
    quotas: Arc<dyn QuotaStore>,
    payments: &Arc<Payments>,
    manifest: &Manifest,
    skill: Refunds,
    retry: bool,
) -> Arc<Runtime> {
    Runtime::builder(journal)
        .tenant(tenant())
        .quota(quotas, TenantQuota::default())
        .tools(catalog(retry), Arc::clone(payments) as Arc<dyn ToolClient>)
        .agent(Agent::new(manifest).skill(skill))
        .build()
}

async fn refund(rt: &Runtime, n: u32) -> agentplane::runtime::RunOutcome {
    rt.run("refund", Tainted::trusted(json!({ "order": n })))
        .await
        .expect("admitted")
}

async fn count(store: &RedbStore, run: RunId, f: fn(&RecordKind) -> bool) -> usize {
    store
        .read(run, 1)
        .await
        .expect("records")
        .iter()
        .filter(|r| f(r.kind()))
        .count()
}

fn is_refused(k: &RecordKind) -> bool {
    matches!(k, RecordKind::BudgetRefused { .. })
}

fn is_readmitted(k: &RecordKind) -> bool {
    matches!(k, RecordKind::BudgetReadmitted { .. })
}

fn now() -> Timestamp {
    Timestamp::now_utc()
}

/// Fill `grant`'s window under `ceiling` as other runs would have.
async fn fill(store: &dyn QuotaStore, grant: &str, ceiling: RateCeiling) {
    for n in 0..ceiling.count {
        store
            .reserve_rate(&RateReservation {
                grant: grant.to_owned(),
                run: RunId::generate(),
                dispatch: agentplane::core::EffectKey::from_hex(&format!("{n:064x}")).expect("hex"),
                ceilings: vec![ceiling],
                at: now(),
                exempt: false,
            })
            .await
            .expect("the window fills");
    }
}

/// A quota store that forwards everything but the rate counter, which it
/// answers as told instead of asking the store — and counts being asked.
#[derive(Debug)]
struct Doctored {
    inner: Arc<RedbStore>,
    rate: Rate,
    asked: AtomicUsize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rate {
    AdmitsEverything,
    Unreachable,
}

impl Doctored {
    fn new(inner: Arc<RedbStore>, rate: Rate) -> Self {
        Self {
            inner,
            rate,
            asked: AtomicUsize::new(0),
        }
    }

    fn answer(&self) -> Result<(), QuotaError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match self.rate {
            Rate::AdmitsEverything => Ok(()),
            Rate::Unreachable => Err(QuotaError::Unavailable("injected outage".to_owned())),
        }
    }
}

#[async_trait::async_trait]
impl QuotaStore for Doctored {
    fn tenant(&self) -> &str {
        QuotaStore::tenant(self.inner.as_ref())
    }
    async fn reserve(
        &self,
        run: RunId,
        quota: &TenantQuota,
        hold: Option<&SpendHold>,
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        self.inner.reserve(run, quota, hold, at).await
    }
    async fn release(&self, run: RunId) -> Result<(), StoreError> {
        self.inner.release(run).await
    }
    async fn carry(&self, run: RunId, period: &str) -> Result<(), StoreError> {
        self.inner.carry(run, period).await
    }
    async fn reservations(&self, limit: usize) -> Result<Vec<Held>, StoreError> {
        self.inner.reservations(limit).await
    }
    async fn reserved(&self, period: &str) -> Result<Spend, StoreError> {
        self.inner.reserved(period).await
    }
    async fn set_halt(
        &self,
        scope: &HaltScope,
        by: &agentplane::core::Operator,
        at: Timestamp,
        reason: &str,
    ) -> Result<(), StoreError> {
        self.inner.set_halt(scope, by, at, reason).await
    }
    async fn lift_halt(&self, scope: &HaltScope) -> Result<bool, StoreError> {
        self.inner.lift_halt(scope).await
    }
    async fn lift_halt_if(&self, standing: &Halt) -> Result<bool, StoreError> {
        self.inner.lift_halt_if(standing).await
    }
    async fn halts(&self) -> Result<Vec<Halt>, StoreError> {
        self.inner.halts().await
    }
    async fn settle(&self, settlement: &QuotaSettlement) -> Result<(), StoreError> {
        self.inner.settle(settlement).await
    }
    async fn spent(&self, period: &str) -> Result<Spend, StoreError> {
        self.inner.spent(period).await
    }
    async fn running(&self) -> Result<u32, StoreError> {
        self.inner.running().await
    }
    async fn running_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.running_runs(limit).await
    }
    async fn reserve_rate(&self, reservation: &RateReservation) -> Result<(), QuotaError> {
        let _ = reservation;
        self.answer()
    }
    async fn rate_room(
        &self,
        grant: &str,
        ceilings: &[RateCeiling],
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let _ = (grant, ceilings, at);
        self.answer()
    }
}

// ── The declaration binds ───────────────────────────────────────────────────

/// **A ceiling with nowhere to count it is refused at build.**
#[test]
fn a_rate_ceiling_on_a_plane_with_no_quota_store_is_refused_at_build() {
    let store = scoped();
    let err = Runtime::builder(store as Arc<dyn JournalStore>)
        .tenant(tenant())
        .tools(
            catalog(false),
            Arc::new(Payments::default()) as Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&refunder("{ count: 20, window_seconds: 3600 }")).skill(Refunds::new()))
        .try_build()
        .expect_err("a ceiling nothing counts is decoration");
    assert!(
        matches!(&err, BuildError::RateLimitWithoutQuotaStore { agent, grant }
            if agent == "refunder" && grant == REFUND),
        "{err}"
    );
}

/// **The call past the ceiling is refused before it reaches the tool, and the
/// refusal is on the run's record in the operator's words.**
#[tokio::test]
async fn the_call_past_the_ceiling_is_refused_and_journaled() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &refunder("{ count: 2, window_seconds: 3600 }"),
        Refunds::new(),
        false,
    );
    for n in 0..2 {
        let out = refund(&rt, n).await;
        assert!(matches!(out.status, RunStatus::Succeeded), "{out:?}");
    }
    let third = refund(&rt, 2).await;
    match &third.status {
        RunStatus::Exhausted(BudgetExceeded::Rate {
            grant,
            allowed: 2,
            window_seconds: 3_600,
            reached: 2,
        }) if grant == REFUND => {}
        other => panic!("the third refund under two an hour was not refused: {other:?}"),
    }
    assert_eq!(
        payments.calls.load(Ordering::SeqCst),
        2,
        "the refused refund reached the payments server"
    );
    let records = store.read(third.run_id, 1).await.expect("records");
    let refusal = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::BudgetRefused { limit, .. } => Some(limit.clone()),
            _ => None,
        })
        .expect("the refusal is journaled");
    assert!(
        refusal.contains(REFUND) && refusal.contains("2 call(s) per 3600s"),
        "the refusal must name the grant, the ceiling and the window: {refusal}"
    );
}

/// **The tightest ceiling any declaration states binds every agent calling the
/// tool.** The count is per tool, so a looser agent is held to it too.
#[tokio::test]
async fn the_tightest_ceiling_binds_every_agent() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let tight = declaration(
        "tight",
        "refund.tight",
        "1.0.0",
        "{ count: 1, window_seconds: 3600 }",
        "{}",
    );
    let loose = declaration(
        "loose",
        "refund",
        "1.0.0",
        "{ count: 5, window_seconds: 3600 }",
        "{}",
    );
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .tenant(tenant())
        .quota(store.clone() as Arc<dyn QuotaStore>, TenantQuota::default())
        .tools(catalog(false), Arc::clone(&payments) as Arc<dyn ToolClient>)
        .agent(Agent::new(&tight).skill(Refunds {
            name: "tight",
            capability: "refund.tight",
            ..Refunds::new()
        }))
        .agent(Agent::new(&loose).skill(Refunds::new()))
        .build();
    assert!(matches!(refund(&rt, 0).await.status, RunStatus::Succeeded));
    let second = refund(&rt, 1).await;
    assert!(
        matches!(
            second.status,
            RunStatus::Exhausted(BudgetExceeded::Rate { allowed: 1, .. })
        ),
        "the loose agent's second refund was held only to its own ceiling of five: {:?}",
        second.status
    );
}

/// **A new revision of the declaration does not reset the count.** The count
/// is keyed on the tool, not on the revision that declared the ceiling.
#[tokio::test]
async fn a_new_revision_does_not_reset_the_count() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let first = declaration(
        "refunder",
        "refund",
        "1.0.0",
        "{ count: 1, window_seconds: 3600 }",
        "{}",
    );
    let next = declaration(
        "refunder",
        "refund",
        "1.0.1",
        "{ count: 1, window_seconds: 3600 }",
        "{}",
    );
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &first,
        Refunds::new(),
        false,
    );
    assert!(matches!(refund(&rt, 0).await.status, RunStatus::Succeeded));
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &next,
        Refunds::new(),
        false,
    );
    assert!(matches!(
        refund(&rt, 1).await.status,
        RunStatus::Exhausted(BudgetExceeded::Rate { .. })
    ));
}

/// **An unreachable counter refuses.** A ceiling that yields when its store is
/// down is one an attacker removes by taking the store down.
#[tokio::test]
async fn an_unreachable_rate_counter_refuses() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let quotas = Arc::new(Doctored::new(store.clone(), Rate::Unreachable));
    let rt = plane(
        store.clone(),
        quotas,
        &payments,
        &refunder("{ count: 20, window_seconds: 3600 }"),
        Refunds::new(),
        false,
    );
    let out = rt
        .run("refund", Tainted::trusted(json!({ "order": 1 })))
        .await;
    assert!(
        out.as_ref().is_err() || !matches!(out.as_ref().unwrap().status, RunStatus::Succeeded),
        "a refund went out with its rate counter unreachable: {out:?}"
    );
    assert_eq!(
        payments.calls.load(Ordering::SeqCst),
        0,
        "the refund reached the payments server while nothing could count it"
    );
}

/// **A rate refusal costs the run nothing, and is not a policy denial.**
///
/// The run's budget admits one effect. The refund is refused at the rate
/// ceiling, and the lookup that follows must still be admitted: replay bills
/// slots from announcements and a refusal has none, so a live pass that
/// billed the refusal would stop earlier than its own replay. And the run
/// admits no policy denial at all, so a refusal counted as one would stop the
/// lookup too.
#[tokio::test]
async fn a_rate_refusal_does_not_spend_the_run_budget() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let ceiling = RateCeiling {
        count: 1,
        window_seconds: 3_600,
    };
    fill(store.as_ref(), REFUND, ceiling).await;
    let manifest = declaration(
        "refunder",
        "refund",
        "1.0.0",
        "{ count: 1, window_seconds: 3600 }",
        "{ max_effects: 1, max_denials: 0 }",
    );
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &manifest,
        Refunds {
            carry_on: true,
            ..Refunds::new()
        },
        false,
    );
    let out = refund(&rt, 1).await;
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the lookup after a rate refusal was refused, so the refusal spent the run's \
         one effect or counted as a denial: {:?}",
        out.status
    );
    assert_eq!(payments.calls.load(Ordering::SeqCst), 0);
    assert_eq!(payments.lookups.load(Ordering::SeqCst), 1);
}

/// **A peer call is held to its grant's ceiling.** A peer is granted as
/// `tool://<peer>/<capability>`, the same reference a tool is.
#[tokio::test]
async fn a_peer_call_is_held_to_its_grant_s_rate_ceiling() {
    use agentplane::core::{Delegation, Principal, Scope};
    use agentplane::peers::{
        PeerClient, PeerCredential, PeerError, PeerGrant, PeerId, PeerRegistry,
    };
    use agentplane::runtime::RunTerms;

    #[derive(Debug, Default)]
    struct Reviewer(AtomicUsize);
    #[async_trait::async_trait]
    impl PeerClient for Reviewer {
        async fn send(
            &self,
            _peer: &PeerId,
            _capability: &str,
            _payload: &Value,
            _acting_as: &Delegation,
            _credential: Option<&PeerCredential>,
            _provenance: Option<&agentplane::core::Provenance>,
        ) -> Result<Value, PeerError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "reviewed": true }))
        }
    }

    #[derive(Debug)]
    struct AsksReviewer;
    #[async_trait::async_trait]
    impl Skill for AsksReviewer {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("audit.review").provides("audit.review")
        }
        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let answer = cx
                .call_peer(&PeerId::new("reviewer.example"), "audit.check", &input)
                .await?;
            Ok(Outcome::done(answer))
        }
    }

    let manifest = Manifest::parse(
        "
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: auditor, version: '1.0.0' }
spec:
  capabilities: { provides: [audit.review] }
  tools:
    - ref: tool://reviewer.example/audit.check
      rate_limit: { count: 1, window_seconds: 3600 }
  budgets: {}
",
    )
    .expect("a well-formed declaration");
    let store = scoped();
    let reviewer = Arc::new(Reviewer::default());
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .tenant(tenant())
        .quota(store.clone() as Arc<dyn QuotaStore>, TenantQuota::default())
        .peers(
            PeerRegistry::new().allow(
                PeerId::new("reviewer.example"),
                PeerGrant::new(Scope::of(["audit.*"])),
            ),
            Arc::clone(&reviewer) as Arc<dyn PeerClient>,
        )
        .agent(Agent::new(&manifest).skill(AsksReviewer))
        .build();
    let alice = || Delegation::root(Principal::new("user:alice", Scope::of(["audit.*"])));
    let mut statuses = Vec::new();
    for n in 0..2 {
        let out = rt
            .run_under(
                "audit.review",
                Tainted::trusted(json!({ "invoice": n })),
                RunTerms::default().acting_as(alice()),
            )
            .await
            .expect("admitted")
            .outcome()
            .cloned()
            .expect("fresh");
        statuses.push(out.status);
    }
    assert!(matches!(statuses[0], RunStatus::Succeeded), "{statuses:?}");
    assert!(
        matches!(
            statuses[1],
            RunStatus::Exhausted(BudgetExceeded::Rate { .. })
        ),
        "a second peer call went out under a ceiling of one an hour: {statuses:?}"
    );
    assert_eq!(reviewer.0.load(Ordering::SeqCst), 1);
}

/// **An undo is counted, and never refused.** Refusing to undo is how a run
/// ends with a charged card and no order; not counting it would let undos
/// hide from the ceiling the next forward call is judged against.
#[tokio::test]
async fn a_compensation_is_counted_and_never_rate_refused() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    // A mutating refund, so the failed step has something to take back.
    let manifest = Manifest::parse(&format!(
        "
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: refunder, version: '1.0.0' }}
spec:
  capabilities: {{ provides: [refund] }}
  tools:
    - ref: {REFUND}
      rate_limit: {{ count: 1, window_seconds: 3600 }}
  budgets: {{}}
"
    ))
    .expect("a well-formed declaration");
    let rt = Runtime::builder(store.clone() as Arc<dyn JournalStore>)
        .tenant(tenant())
        .quota(store.clone() as Arc<dyn QuotaStore>, TenantQuota::default())
        .tools(
            Arc::new(
                ToolCatalog::new().allow(ToolId::new("payments", "refund"), ToolSafety::default()),
            ),
            Arc::clone(&payments) as Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&manifest).skill(Refunds::new()))
        .skill(Fails)
        .build();
    let plan = PlanIR::new(vec![
        PlanNode::new(0, "refund").arg("input", ArgSource::run_input()),
        PlanNode::new(1, "fails")
            .arg("x", ArgSource::node(agentplane::core::StepId(0)))
            .terminal(),
    ]);
    let out = rt
        .run_plan(plan, Tainted::trusted(json!({ "order": 1 })))
        .await
        .expect("admitted");
    assert!(matches!(out.status, RunStatus::Failed(_)), "{out:?}");
    assert_eq!(
        payments.calls.load(Ordering::SeqCst),
        2,
        "the undo was refused at a window the forward call had filled"
    );
    match store
        .rate_room(
            REFUND,
            &[RateCeiling {
                count: 2,
                window_seconds: 3_600,
            }],
            now(),
        )
        .await
    {
        Err(QuotaError::RateLimited { reached: 2, .. }) => {}
        other => panic!("the undo went uncounted: {other:?}"),
    }
}

// ── A retry and a crash spend once ──────────────────────────────────────────

/// **A retried call reserves once.** Its attempts derive different effect
/// keys; the reservation is keyed on the first.
#[tokio::test]
async fn a_retried_dispatch_reserves_once() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    payments.fail_first.store(1, Ordering::SeqCst);
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &refunder("{ count: 1, window_seconds: 3600 }"),
        Refunds::new(),
        true,
    );
    let out = refund(&rt, 1).await;
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the retry of an admitted refund was refused as a second call: {:?}",
        out.status
    );
    assert_eq!(payments.calls.load(Ordering::SeqCst), 2, "two attempts");
}

/// **A dispatch recovered after its reservation reserves once.** The instance
/// that reserved dies before announcing the call; another resumes the run and
/// finds its own row.
#[tokio::test]
async fn a_dispatch_recovered_after_its_reservation_reserves_once() {
    use agentplane::testkit::faults::{Fault, Faulty, Schedule};

    let store = scoped();
    let payments = Arc::new(Payments::default());
    let manifest = refunder("{ count: 1, window_seconds: 3600 }");
    let faulty: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        store.clone(),
        Schedule::default().on_kind("EffectStarted", Fault::FailedClean),
    ));
    let crashed = plane(
        faulty,
        store.clone(),
        &payments,
        &manifest,
        Refunds::new(),
        false,
    );
    let first = crashed
        .run("refund", Tainted::trusted(json!({ "order": 1 })))
        .await;
    assert_eq!(
        payments.calls.load(Ordering::SeqCst),
        0,
        "the call went out without its announcement: {first:?}"
    );
    let run = match &first {
        Ok(out) => out.run_id,
        Err(_) => store
            .running_runs(10)
            .await
            .expect("slots")
            .first()
            .copied()
            .unwrap_or_else(|| panic!("no run to recover after {first:?}")),
    };

    let recovered = plane(
        store.clone(),
        store.clone(),
        &payments,
        &manifest,
        Refunds::new(),
        false,
    );
    let out = recovered.replay(run, Mode::Resume).await.expect("resumes");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the recovered dispatch was refused against its own reservation: {:?}",
        out.status
    );
    assert_eq!(payments.calls.load(Ordering::SeqCst), 1);
}

/// **Two runs making the same call each count.** An effect key does not name
/// its run, so the reservation must.
#[tokio::test]
async fn two_runs_making_the_same_call_each_count() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &refunder("{ count: 1, window_seconds: 3600 }"),
        Refunds::new(),
        false,
    );
    assert!(matches!(refund(&rt, 7).await.status, RunStatus::Succeeded));
    assert!(
        matches!(
            refund(&rt, 7).await.status,
            RunStatus::Exhausted(BudgetExceeded::Rate { .. })
        ),
        "a second run making the identical call shared the first run's reservation"
    );
    assert_eq!(payments.calls.load(Ordering::SeqCst), 1);
}

// ── Replay reads the verdict ────────────────────────────────────────────────

/// **A strict replay reads a rate refusal back, and never asks the counter.**
/// Replayed against a counter that would admit everything, the run stops where
/// it stopped.
#[tokio::test]
async fn a_strict_replay_reads_a_rate_refusal_back_without_the_counter() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let manifest = refunder("{ count: 1, window_seconds: 3600 }");
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &manifest,
        Refunds::new(),
        false,
    );
    let performed = refund(&rt, 1).await;
    let refused = refund(&rt, 2).await;
    assert!(matches!(refused.status, RunStatus::Exhausted(_)));

    let quotas = Arc::new(Doctored::new(store.clone(), Rate::AdmitsEverything));
    let auditor = plane(
        store.clone(),
        Arc::clone(&quotas) as Arc<dyn QuotaStore>,
        &payments,
        &manifest,
        Refunds::new(),
        false,
    );
    let replayed = auditor
        .replay(refused.run_id, Mode::Strict)
        .await
        .expect("replays");
    assert!(
        matches!(replayed.status, RunStatus::Exhausted(_)),
        "a strict replay of a rate-refused run reached {:?}",
        replayed.status
    );
    let replayed = auditor
        .replay(performed.run_id, Mode::Strict)
        .await
        .expect("replays");
    assert!(matches!(replayed.status, RunStatus::Succeeded));
    assert_eq!(
        quotas.asked.load(Ordering::SeqCst),
        0,
        "a strict replay asked the rate counter"
    );
    assert_eq!(payments.calls.load(Ordering::SeqCst), 1);
}

// ── The operator can see it and lift it ─────────────────────────────────────

/// **A resume inside a full window stays refused without a second record, and
/// one after the window continues beside the refusal.**
#[tokio::test]
async fn a_resume_inside_a_full_window_stays_refused_without_a_second_record() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &refunder("{ count: 1, window_seconds: 2 }"),
        Refunds::new(),
        false,
    );
    assert!(matches!(refund(&rt, 1).await.status, RunStatus::Succeeded));
    let refused = refund(&rt, 2).await;
    let run = refused.run_id;
    assert!(matches!(refused.status, RunStatus::Exhausted(_)));

    let again = rt.replay(run, Mode::Resume).await.expect("resumes");
    assert!(
        matches!(again.status, RunStatus::Exhausted(_)),
        "a resume inside a full window went on: {:?}",
        again.status
    );
    assert_eq!(
        count(&store, run, is_refused).await,
        1,
        "a second refusal was stacked"
    );
    assert_eq!(count(&store, run, is_readmitted).await, 0);

    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    let lifted = rt.replay(run, Mode::Resume).await.expect("resumes");
    assert!(
        matches!(lifted.status, RunStatus::Succeeded),
        "a resume after the window did not continue: {:?}",
        lifted.status
    );
    assert_eq!(
        count(&store, run, is_refused).await,
        1,
        "the refusal stays on the record"
    );
    assert_eq!(count(&store, run, is_readmitted).await, 1);
    assert_eq!(payments.calls.load(Ordering::SeqCst), 2);
}

/// **A rate-stopped run is listed, with a remedy that says to wait.**
#[tokio::test]
async fn a_rate_refused_run_is_listed_with_its_remedy() {
    let store = scoped();
    let payments = Arc::new(Payments::default());
    let rt = plane(
        store.clone(),
        store.clone(),
        &payments,
        &refunder("{ count: 1, window_seconds: 3600 }"),
        Refunds::new(),
        false,
    );
    refund(&rt, 1).await;
    let refused = refund(&rt, 2).await;
    let attention = rt.attention(now(), 50).await.expect("attention");
    let exhausted = attention
        .conditions
        .iter()
        .find(|c| c.kind == "run.exhausted")
        .expect("the rate-stopped run is listed");
    assert!(exhausted.subjects.contains(&refused.run_id.to_string()));
    assert!(
        exhausted.remedy.cli.contains("rate ceiling")
            && exhausted.remedy.http.contains("rate ceiling"),
        "the remedy tells the operator to raise a ceiling nobody can raise at run time: {:?}",
        exhausted.remedy
    );
}

// ── The contract ────────────────────────────────────────────────────────────

/// **One tenant's count does not throttle another's.**
#[tokio::test]
async fn one_tenants_rate_count_does_not_throttle_another() {
    let base = RedbStore::open_in_memory().expect("store");
    let first = base.clone().for_tenant(tenant());
    let other = base.for_tenant(TenantId::new("globex").expect("valid"));
    let mut report = agentplane::testkit::conformance::Report::default();
    agentplane::testkit::conformance_quota::check_rate_tenants(&first, &other, &mut report).await;
    report.assert_conforms("RedbStore (rate tenants)");
}

/// **The battery refuses a counter that admits everything.** A contract a
/// counter with no ceiling passes asserts nothing about ceilings.
#[tokio::test]
async fn the_quota_contract_refuses_a_counter_that_admits_everything() {
    let admits = Doctored::new(scoped(), Rate::AdmitsEverything);
    let mut report = agentplane::testkit::conformance::Report::default();
    agentplane::testkit::conformance_quota::check(&admits, &mut report).await;
    let failed: Vec<&str> = report.violations.iter().map(|v| v.invariant).collect();
    for expected in [
        "a full window refuses",
        "a window boundary does not double the ceiling",
        "two runs making the same call each count",
    ] {
        assert!(
            failed.contains(&expected),
            "the battery passed a counter that admits everything on '{expected}': {failed:?}"
        );
    }
}
