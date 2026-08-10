//! Per-tenant quota accounting on `PostgreSQL`.
//!
//! This is the backend the guarantee is actually about. On a single node a
//! ceiling can be held up by almost anything; the moment two instances admit
//! concurrently, only the database can arbitrate — which is why the reservation
//! below is **one statement**, not a count followed by an insert.

use async_trait::async_trait;

use crate::core::{RunId, Spend, StoreError, Timestamp};
use crate::quota::{QuotaError, QuotaStore};

use super::postgres::{PostgresStore, amount_of, sql_amount};

fn be(e: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn pool_err(e: &impl std::fmt::Display) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[async_trait]
impl QuotaStore for PostgresStore {
    async fn reserve(
        &self,
        run: RunId,
        limit: Option<u32>,
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let mut client = self
            .pool_ref()
            .get()
            .await
            .map_err(|e| QuotaError::Unavailable(pool_err(&e).to_string()))?;
        let tenant = self.tenant_name();
        let run = run.to_string();

        let Some(limit) = limit else {
            // No ceiling: still record the run, so `running()` answers honestly
            // and a ceiling added later starts from the truth. No lock either —
            // there is no decision here for two admissions to disagree about.
            client
                .execute(
                    "INSERT INTO quota_running (tenant, run_id, admitted_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (tenant, run_id) DO NOTHING",
                    &[&tenant, &run, &at.unix_timestamp()],
                )
                .await
                .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
            return Ok(());
        };

        // The count and the insert decide together **under a per-tenant
        // advisory lock**, because nothing weaker serialises them. This
        // statement's earlier form ran without the lock, on a comment claiming
        // the decision happened "inside the row lock the write takes" — and no
        // such lock exists: two INSERTs of *different* rows lock nothing in
        // common, each count subquery reads its own statement snapshot under
        // READ COMMITTED, and two admissions racing for one remaining slot
        // both passed `count < limit` and both landed. A ceiling that admits
        // limit+k exactly under concurrent load is the catalogued
        // yields-under-load shape, on the one control whose whole promise is
        // surviving a second instance.
        //
        // The lock is transaction-scoped and per tenant — admissions for one
        // tenant serialise, which is the semantic the ceiling requires; other
        // tenants' admissions do not wait. The length prefix keeps
        // `("acme", …)` from colliding with a tenant literally named
        // `"acme…"` under concatenation.
        //
        // `ON CONFLICT DO NOTHING` keeps a retried admission idempotent: the
        // run already holds its slot, so re-reserving must neither take a
        // second nor be refused against a ceiling it is already counted in.
        let tx = client
            .transaction()
            .await
            .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("quota-admission:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
        let inserted = tx
            .execute(
                "INSERT INTO quota_running (tenant, run_id, admitted_at)
                 SELECT $1, $2, $3
                  WHERE (SELECT COUNT(*) FROM quota_running WHERE tenant = $1) < $4
                     OR EXISTS (SELECT 1 FROM quota_running
                                 WHERE tenant = $1 AND run_id = $2)
                 ON CONFLICT (tenant, run_id) DO NOTHING",
                &[&tenant, &run, &at.unix_timestamp(), &i64::from(limit)],
            )
            .await
            .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;

        if inserted == 1 {
            tx.commit()
                .await
                .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
            return Ok(());
        }

        // Nothing was written. Either the tenant is at its ceiling, or the run
        // already held a slot and `DO NOTHING` fired — and those are opposite
        // answers, so it is read back rather than assumed. Still inside the
        // transaction, so the counts are the ones the decision was made from.
        let held: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM quota_running WHERE tenant = $1 AND run_id = $2",
                &[&tenant, &run],
            )
            .await
            .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?
            .get(0);
        if held > 0 {
            tx.commit()
                .await
                .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
            return Ok(());
        }

        let running: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM quota_running WHERE tenant = $1",
                &[&tenant],
            )
            .await
            .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?
            .get(0);
        tx.commit()
            .await
            .map_err(|e| QuotaError::Unavailable(be(&e).to_string()))?;
        Err(QuotaError::TooManyRuns {
            tenant,
            running: u32::try_from(running).unwrap_or(u32::MAX),
        })
    }

    async fn set_halt(&self, reason: Option<&str>) -> Result<(), StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        match reason {
            Some(reason) => {
                client
                    .execute(
                        "INSERT INTO quota_halted (tenant, reason) VALUES ($1, $2)
                         ON CONFLICT (tenant) DO UPDATE SET reason = EXCLUDED.reason",
                        &[&self.tenant_name(), &reason],
                    )
                    .await
                    .map_err(|e| be(&e))?;
            }
            None => {
                client
                    .execute(
                        "DELETE FROM quota_halted WHERE tenant = $1",
                        &[&self.tenant_name()],
                    )
                    .await
                    .map_err(|e| be(&e))?;
            }
        }
        Ok(())
    }

    async fn halted(&self) -> Result<Option<String>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT reason FROM quota_halted WHERE tenant = $1",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(row.map(|row| row.get::<_, String>(0)))
    }

    async fn release(&self, run: RunId) -> Result<(), StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "DELETE FROM quota_running WHERE tenant = $1 AND run_id = $2",
                &[&self.tenant_name(), &run.to_string()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn accrue(&self, period: &str, spend: Spend) -> Result<(), StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        // The addition happens in the database, not here. Reading a total,
        // adding to it and writing it back would lose one of two concurrent
        // accruals — and the one it loses is spend a tenant has already
        // incurred, so the ceiling drifts upward under exactly the load that
        // makes it matter.
        client
            .execute(
                "INSERT INTO quota_spent (tenant, period, tokens, minor_units)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant, period) DO UPDATE SET
                   tokens = quota_spent.tokens + EXCLUDED.tokens,
                   minor_units = quota_spent.minor_units + EXCLUDED.minor_units",
                &[
                    &self.tenant_name(),
                    &period.to_owned(),
                    &sql_amount(spend.tokens),
                    &sql_amount(spend.minor_units),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn spent(&self, period: &str) -> Result<Spend, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_opt(
                "SELECT tokens, minor_units FROM quota_spent
                  WHERE tenant = $1 AND period = $2",
                &[&self.tenant_name(), &period.to_owned()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(row.map_or_else(Spend::default, |r| Spend {
            tokens: amount_of(r.get::<_, i64>(0)),
            minor_units: amount_of(r.get::<_, i64>(1)),
        }))
    }

    async fn running(&self) -> Result<u32, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let n: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM quota_running WHERE tenant = $1",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?
            .get(0);
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }
}
