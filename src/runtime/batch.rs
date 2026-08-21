//! Driving a batch: reserve, run, record, repeat.
//!
//! The loop is deliberately boring, because the interesting decisions are all in
//! [`crate::batch`]'s types. What this file has to get right is the *ordering* —
//! an item's run id becomes durable before the run performs anything — and the
//! refusal to stop at the first failure.

use std::sync::Arc;

use crate::batch::{BatchCensus, BatchItem, BatchReport, BatchStatus, ItemOutcome, ItemSource};
use crate::core::{BatchId, PlanIR, RunId, RuntimeError, Spend};

use super::executor::{RunOutcome, RunStatus, Runtime};
use super::{Mode, metrics};

/// How a batch is to be run.
#[derive(Debug)]
pub struct BatchSpec {
    /// The plan every item runs. Frozen once, for the whole batch: a batch whose
    /// plan could change between items would be several acts wearing one name,
    /// and its audit record would say nothing about what actually happened to
    /// item 60,000.
    pub plan: PlanIR,
    pub source: Arc<dyn ItemSource>,
    /// Items fetched per call to the source.
    ///
    /// A paging hint, not a limit on the batch. See [`BatchSpec::page`].
    pub page: usize,
    /// Stop after this many items reach a terminal outcome, if set.
    ///
    /// For operating a very large batch in windows — "settle ten thousand and
    /// let me look". The batch stays `Running`; the next call resumes.
    pub max_items: Option<u64>,
}

impl BatchSpec {
    pub fn new(plan: PlanIR, source: Arc<dyn ItemSource>) -> Self {
        Self {
            plan,
            source,
            page: 256,
            max_items: None,
        }
    }

    /// How many items to fetch from the source at a time.
    #[must_use]
    pub const fn page(mut self, n: usize) -> Self {
        self.page = n;
        self
    }

    /// Process at most this many items before returning.
    #[must_use]
    pub const fn max_items(mut self, n: u64) -> Self {
        self.max_items = Some(n);
        self
    }
}

impl Runtime {
    /// Start a batch, or continue one.
    ///
    /// Passing an existing [`BatchId`] resumes it: processing picks up after the
    /// stored cursor, and any item that was reserved but never finished is
    /// replayed under its original run id rather than started again.
    ///
    /// Returns when the source is exhausted or `max_items` is reached. **A
    /// failing item does not stop the batch** — that is the failure isolation a
    /// batch exists for, and a caller who wants the opposite should be running
    /// one run, not many.
    pub async fn run_batch(
        &self,
        id: BatchId,
        spec: &BatchSpec,
    ) -> Result<BatchReport, RuntimeError> {
        let store = self.batches().ok_or_else(|| {
            RuntimeError::PlanContract(
                "batches need a batch store — build the runtime with `.batches(store)`".into(),
            )
        })?;

        crate::plan::validate(&spec.plan, &self.contract())
            .map_err(|e| RuntimeError::PlanContract(e.to_string()))?;
        store
            .open(id, &spec.plan.digest().to_hex())
            .await
            .map_err(RuntimeError::from_store)?;

        // Resume from where a previous pass got to. If this is lost the batch is
        // slower, not wrong: every item's reservation makes re-processing a
        // replay. See the module docs in `crate::batch`.
        let mut after = store.cursor(id).await.map_err(RuntimeError::from_store)?;
        let mut processed = 0_u64;

        loop {
            if spec.max_items.is_some_and(|m| processed >= m) {
                break;
            }
            let page = store_page(spec, after.as_deref()).await?;
            if page.is_empty() {
                // The source is done. Recorded durably: it is the difference
                // between a finished batch and one that stopped early with
                // every stored item terminal.
                store
                    .mark_exhausted(id)
                    .await
                    .map_err(RuntimeError::from_store)?;
                break;
            }

            for item in page {
                after = Some(item.key.clone());
                let outcome = self.run_item(id, spec, &item).await?;
                if outcome.is_terminal() {
                    processed += 1;
                }
                if spec.max_items.is_some_and(|m| processed >= m) {
                    break;
                }
            }
        }

        self.batch_report(id).await
    }

    /// Reserve, run, record — one item.
    ///
    /// The order is the effect protocol: the run id is durable before anything
    /// is performed, so an interrupted item is findable and replayable rather
    /// than a question nobody can answer.
    async fn run_item(
        &self,
        id: BatchId,
        spec: &BatchSpec,
        item: &BatchItem,
    ) -> Result<ItemOutcome, RuntimeError> {
        let store = self
            .batches()
            .ok_or_else(|| RuntimeError::PlanContract("no batch store".into()))?;

        let reserved = store
            .reserve(id, &item.key, RunId::generate())
            .await
            .map_err(RuntimeError::from_store)?;

        // Already terminal from an earlier pass: nothing to do, and re-running
        // would be the duplicate work the reservation exists to prevent.
        if let Some(done) = reserved.outcome.as_ref().filter(|o| o.is_terminal()) {
            return Ok(done.clone());
        }

        // A reservation with no terminal outcome is either a fresh item or one
        // interrupted mid-flight. Both are addressed by the same call: `replay`
        // resumes an existing journal, and a run that never wrote one is
        // admitted here for the first time.
        let outcome = if reserved.outcome.is_some() || self.has_journal(reserved.run).await? {
            self.replay(reserved.run, Mode::Resume).await
        } else {
            self.admit_plan_as(
                reserved.run,
                spec.plan.clone(),
                crate::core::Tainted::trusted(item.input.clone()),
                // A batch item's at-most-once identity is its reservation, not
                // an admission key: the run id is written to the batch store
                // before the run starts, so a retry replays that journal rather
                // than admitting again. Two mechanisms for one invariant would
                // be two places to disagree.
                super::executor::Terms::default(),
            )
            .await
        };

        let (result, spend) = classify_item(outcome);
        store
            .record(id, &item.key, &result, spend)
            .await
            .map_err(RuntimeError::from_store)?;

        self.meter().count(metrics::BATCH_ITEMS, result.as_str());
        Ok(result)
    }

    /// Whether a run has already written anything.
    async fn has_journal(&self, run: RunId) -> Result<bool, RuntimeError> {
        match self.journal().head(run).await {
            Ok(head) => Ok(head.seq > 0),
            Err(e) => Err(RuntimeError::from_store(e)),
        }
    }

    /// The batch's current tally, without processing anything.
    pub async fn batch_report(&self, id: BatchId) -> Result<BatchReport, RuntimeError> {
        let store = self
            .batches()
            .ok_or_else(|| RuntimeError::PlanContract("batches need a batch store".into()))?;
        // Existence first, from the batch's own row. A census cannot answer
        // it — no such batch and a batch with no items yet both count zero
        // rows — and answering a mistyped id with an empty `Running` report
        // sends an operator watching a batch that will never exist.
        if store
            .plan_digest(id)
            .await
            .map_err(RuntimeError::from_store)?
            .is_none()
        {
            return Err(RuntimeError::from_store(crate::core::StoreError::NotFound(
                format!("batch {id}"),
            )));
        }
        let census = store.census(id).await.map_err(RuntimeError::from_store)?;
        let cursor = store.cursor(id).await.map_err(RuntimeError::from_store)?;
        let exhausted = store
            .is_exhausted(id)
            .await
            .map_err(RuntimeError::from_store)?;
        Ok(BatchReport {
            id,
            status: status_of(&census, exhausted),
            in_flight: census.in_flight + census.suspended,
            spend: census.spend,
            cursor,
        })
    }
}

/// A batch is complete only when nothing is reserved and nothing is waiting.
///
/// An exhausted item is waiting too — paused at a ceiling, resumable the
/// moment somebody raises it — and it holds the cursor for exactly that
/// reason. Reporting `Completed` over one would let `everything_settled()`
/// answer yes while an item's meters are unsettled, which is the "mostly
/// worked read as worked" this type exists to prevent.
///
/// Note there is no path to a status that says "succeeded": see `crate::batch`.
fn status_of(c: &BatchCensus, source_exhausted: bool) -> BatchStatus {
    if !source_exhausted || c.in_flight > 0 || c.suspended > 0 || c.exhausted > 0 {
        return BatchStatus::Running;
    }
    BatchStatus::Completed {
        succeeded: c.succeeded,
        failed: c.failed,
        quarantined: c.quarantined,
    }
}

/// Turn a run's ending into an item's.
///
/// A store or contract error is *the item's* failure, not the batch's: one
/// malformed item must not take down a settlement run for the other 99,999. The
/// detail goes on the item record, and the item's own journal holds the rest.
fn classify_item(outcome: Result<RunOutcome, RuntimeError>) -> (ItemOutcome, Spend) {
    let Ok(out) = outcome else {
        let e = outcome.expect_err("checked");
        return (ItemOutcome::Failed(e.to_string()), Spend::default());
    };
    let spend = out.spend;
    let item = match out.status {
        RunStatus::Succeeded => ItemOutcome::Succeeded,
        RunStatus::Suspended(r) => ItemOutcome::Suspended(r.to_string()),
        RunStatus::Quarantined(why) => ItemOutcome::Quarantined(why),
        // `Replanning` is never observed by a caller — the executor resolves
        // it internally — but if one ever escaped it is an item that did not
        // settle, which is what `Failed` means here.
        RunStatus::Failed(why) | RunStatus::Replanning(why) => ItemOutcome::Failed(why),
        // A pause, not a fault — mirrored from the run's own semantics: the
        // work stands, and raising the ceiling resumes it. Filing it under
        // `Failed` taught operators to re-run items whose work was intact.
        RunStatus::Exhausted(limit) => ItemOutcome::Exhausted(limit.to_string()),
        // An item somebody stopped did not settle, and the batch must not
        // report otherwise — but the reason names the person, so a partial
        // batch can be told apart from one that hit a wall.
        RunStatus::Cancelled { actor, reason } => {
            ItemOutcome::Failed(format!("cancelled by '{actor}': {reason}"))
        }
    };
    (item, spend)
}

/// Fetch the next page, mapping a source failure onto the runtime's errors.
async fn store_page(spec: &BatchSpec, after: Option<&str>) -> Result<Vec<BatchItem>, RuntimeError> {
    spec.source
        .next(after, spec.page)
        .await
        // Surfaced, never swallowed into an empty page: a source failure that
        // read as "no more items" would truncate a settlement run silently,
        // which is the exact failure this crate exists to make loud.
        .map_err(|e| RuntimeError::PlanContract(e.to_string()))
}
