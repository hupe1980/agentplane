//! Per-tenant quota accounting on `PostgreSQL`.
//!
//! This is the backend the guarantee is actually about. On a single node a
//! ceiling can be held up by almost anything; the moment two instances admit
//! concurrently, only the database can arbitrate — which is why the reservation
//! below is **one statement**, not a count followed by an insert.

use async_trait::async_trait;

use crate::core::{RunId, Spend, StoreError, Timestamp};
use crate::quota::{
    Halt, HaltScope, Held, QuotaError, QuotaSettlement, QuotaStore, RateCeiling, RateReservation,
    SpendHold, TenantQuota,
};

use super::postgres::{PostgresStore, amount_of, be, pool_err, sql_amount};

#[async_trait]
impl QuotaStore for PostgresStore {
    fn tenant(&self) -> &str {
        crate::journal::JournalStore::tenant(self)
    }

    #[allow(clippy::too_many_lines)]
    async fn reserve(
        &self,
        run: RunId,
        quota: &TenantQuota,
        hold: Option<&SpendHold>,
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let unavailable = |e: &tokio_postgres::Error| QuotaError::Unavailable(be(e).to_string());
        let mut client = self
            .pool_ref()
            .get()
            .await
            .map_err(|e| QuotaError::Unavailable(pool_err(&e).to_string()))?;
        let tenant = self.tenant_name();
        let run = run.to_string();

        if quota.max_concurrent_runs.is_none() && hold.is_none() {
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
                .map_err(|e| unavailable(&e))?;
            return Ok(());
        }

        // The counts and the inserts decide together **under a per-tenant
        // advisory lock**, because nothing weaker serialises them. Two INSERTs
        // of *different* rows lock nothing in common, and each count reads its
        // own statement snapshot under READ COMMITTED — so without the lock two
        // admissions racing for the last slot, or the last units of a period,
        // both pass and both land: a ceiling that yields under exactly the
        // concurrent load it exists for.
        //
        // The lock is transaction-scoped and per tenant — admissions for one
        // tenant serialise, which is the semantic the ceiling requires; other
        // tenants' admissions do not wait. The length prefix keeps
        // `("acme", …)` from colliding with a tenant literally named
        // `"acme…"` under concatenation.
        let tx = client.transaction().await.map_err(|e| unavailable(&e))?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("quota-admission:{}:{tenant}", tenant.len())],
        )
        .await
        .map_err(|e| unavailable(&e))?;

        // Idempotent per run: a retried admission must neither take a second
        // slot nor be refused against a ceiling it is already counted in.
        let row = tx
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM quota_running WHERE tenant = $1 AND run_id = $2),
                        EXISTS (SELECT 1 FROM quota_reserved WHERE tenant = $1 AND run_id = $2),
                        (SELECT COUNT(*) FROM quota_running WHERE tenant = $1)",
                &[&tenant, &run],
            )
            .await
            .map_err(|e| unavailable(&e))?;
        let (slot_held, hold_held, running): (bool, bool, i64) =
            (row.get(0), row.get(1), row.get(2));

        if !slot_held
            && let Some(limit) = quota.max_concurrent_runs
            && running >= i64::from(limit)
        {
            tx.commit().await.map_err(|e| unavailable(&e))?;
            return Err(QuotaError::TooManyRuns {
                tenant,
                running: u32::try_from(running).unwrap_or(u32::MAX),
            });
        }

        if let Some(hold) = hold.filter(|_| !hold_held) {
            // Settled and held in **one statement**, so both figures come from
            // one snapshot: read apart, a settlement committing between them
            // moves a pass's spend out of the holds after the settled total was
            // read, and the period is undercounted by exactly that pass.
            let figures = tx
                .query_one(
                    "SELECT COALESCE((SELECT tokens FROM quota_spent
                                       WHERE tenant = $1 AND period = $2), 0),
                            COALESCE((SELECT minor_units FROM quota_spent
                                       WHERE tenant = $1 AND period = $2), 0),
                            LEAST(9223372036854775807::numeric, COALESCE((
                                SELECT SUM(tokens) FROM quota_reserved
                                 WHERE tenant = $1 AND period = $2), 0))::bigint,
                            LEAST(9223372036854775807::numeric, COALESCE((
                                SELECT SUM(minor_units) FROM quota_reserved
                                 WHERE tenant = $1 AND period = $2), 0))::bigint",
                    &[&tenant, &hold.period],
                )
                .await
                .map_err(|e| unavailable(&e))?;
            let settled = Spend {
                tokens: amount_of(figures.get(0)),
                minor_units: amount_of(figures.get(1)),
            };
            let outstanding = Spend {
                tokens: amount_of(figures.get(2)),
                minor_units: amount_of(figures.get(3)),
            };
            if let Err(refusal) = crate::quota::check_spend(
                &tenant,
                &hold.period,
                quota,
                settled,
                outstanding,
                hold.amount,
            ) {
                tx.commit().await.map_err(|e| unavailable(&e))?;
                return Err(refusal);
            }
            tx.execute(
                "INSERT INTO quota_reserved (tenant, run_id, period, tokens, minor_units)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &tenant,
                    &run,
                    &hold.period,
                    &sql_amount(hold.amount.tokens),
                    &sql_amount(hold.amount.minor_units),
                ],
            )
            .await
            .map_err(|e| unavailable(&e))?;
        }

        tx.execute(
            "INSERT INTO quota_running (tenant, run_id, admitted_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant, run_id) DO NOTHING",
            &[&tenant, &run, &at.unix_timestamp()],
        )
        .await
        .map_err(|e| unavailable(&e))?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(())
    }

    async fn reserve_rate(&self, reservation: &RateReservation) -> Result<(), QuotaError> {
        let unavailable = |e: &tokio_postgres::Error| QuotaError::Unavailable(be(e).to_string());
        let mut client = self
            .pool_ref()
            .get()
            .await
            .map_err(|e| QuotaError::Unavailable(pool_err(&e).to_string()))?;
        let tenant = self.tenant_name();
        let grant = reservation.grant.as_str();
        let run = reservation.run.to_string();
        let dispatch = reservation.dispatch.to_hex();

        // Serialised per `(tenant, grant)` under a transaction-scoped advisory
        // lock, for the reason admission is: two inserts of different rows
        // lock nothing in common, so without it two instances each count a
        // window with one place left and both land. Seeded apart from the
        // admission lock, and length-prefixed so no tenant and grant pair can
        // spell another's.
        let tx = client.transaction().await.map_err(|e| unavailable(&e))?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 1))",
            &[&format!(
                "quota-rate:{}:{tenant}:{}:{grant}",
                tenant.len(),
                grant.len()
            )],
        )
        .await
        .map_err(|e| unavailable(&e))?;

        let held: bool = tx
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM quota_rate
                                 WHERE tenant = $1 AND grant_ref = $2
                                   AND run_id = $3 AND dispatch = $4)",
                &[&tenant, &grant, &run, &dispatch],
            )
            .await
            .map_err(|e| unavailable(&e))?
            .get(0);
        if held {
            tx.commit().await.map_err(|e| unavailable(&e))?;
            return Ok(());
        }

        let floor = crate::quota::rate_prune_floor(reservation.at, &reservation.ceilings);
        tx.execute(
            "DELETE FROM quota_rate WHERE tenant = $1 AND grant_ref = $2 AND reserved_at <= $3",
            &[&tenant, &grant, &floor],
        )
        .await
        .map_err(|e| unavailable(&e))?;
        let instants: Vec<i64> = tx
            .query(
                "SELECT reserved_at FROM quota_rate WHERE tenant = $1 AND grant_ref = $2",
                &[&tenant, &grant],
            )
            .await
            .map_err(|e| unavailable(&e))?
            .iter()
            .map(|row| row.get(0))
            .collect();
        if !reservation.exempt
            && let Err(refusal) = crate::quota::check_rate(
                &tenant,
                grant,
                &reservation.ceilings,
                &instants,
                reservation.at,
            )
        {
            tx.commit().await.map_err(|e| unavailable(&e))?;
            return Err(refusal);
        }
        tx.execute(
            "INSERT INTO quota_rate (tenant, grant_ref, run_id, dispatch, reserved_at)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &tenant,
                &grant,
                &run,
                &dispatch,
                &reservation.at.unix_timestamp(),
            ],
        )
        .await
        .map_err(|e| unavailable(&e))?;
        tx.commit().await.map_err(|e| unavailable(&e))?;
        Ok(())
    }

    async fn rate_room(
        &self,
        grant: &str,
        ceilings: &[RateCeiling],
        at: Timestamp,
    ) -> Result<(), QuotaError> {
        let unavailable = |e: &tokio_postgres::Error| QuotaError::Unavailable(be(e).to_string());
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|e| QuotaError::Unavailable(pool_err(&e).to_string()))?;
        let tenant = self.tenant_name();
        let instants: Vec<i64> = client
            .query(
                "SELECT reserved_at FROM quota_rate WHERE tenant = $1 AND grant_ref = $2",
                &[&tenant, &grant],
            )
            .await
            .map_err(|e| unavailable(&e))?
            .iter()
            .map(|row| row.get(0))
            .collect();
        crate::quota::check_rate(&tenant, grant, ceilings, &instants, at)
    }

    async fn set_halt(
        &self,
        scope: &HaltScope,
        by: &crate::core::Operator,
        at: crate::core::Timestamp,
        reason: &str,
    ) -> Result<(), StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let scope = scope.key();
        client
            .execute(
                "INSERT INTO quota_halted (tenant, scope, reason, by_actor, by_basis, thrown_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (tenant, scope) DO UPDATE SET
                     reason = EXCLUDED.reason,
                     by_actor = EXCLUDED.by_actor,
                     by_basis = EXCLUDED.by_basis,
                     thrown_at = EXCLUDED.thrown_at",
                &[
                    &self.tenant_name(),
                    &scope,
                    &reason,
                    &by.actor(),
                    &by.basis().as_str(),
                    &at.unix_timestamp(),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn lift_halt(&self, scope: &HaltScope) -> Result<bool, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let removed = client
            .execute(
                "DELETE FROM quota_halted WHERE tenant = $1 AND scope = $2",
                &[&self.tenant_name(), &scope.key()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(removed > 0)
    }

    async fn halts(&self) -> Result<Vec<Halt>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT scope, reason, by_actor, by_basis, thrown_at FROM quota_halted \
                 WHERE tenant = $1 ORDER BY scope",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.into_iter()
            .map(|row| {
                let stored: String = row.get(0);
                // Corruption, not a row to skip: a halt this build cannot read
                // is one it would run straight through, and from the outside
                // that is indistinguishable from a halt that was lifted.
                let scope = HaltScope::parse(&stored).ok_or_else(|| StoreError::Corrupt {
                    seq: 0,
                    detail: format!(
                        "quota_halted holds the scope '{stored}', which this build cannot \
                         read — refusing rather than admitting work an operator stopped"
                    ),
                })?;
                let corrupt = |what: &str| StoreError::Corrupt {
                    seq: 0,
                    detail: format!(
                        "quota_halted holds a halt on '{stored}' whose {what} this build \
                         cannot read — refusing rather than admitting work an operator stopped"
                    ),
                };
                let by = super::decode_operator(
                    &row.get::<_, String>(2),
                    &row.get::<_, String>(3),
                    "quota_halted",
                )?;
                Ok(super::halt_from_row(
                    scope,
                    super::HaltRow {
                        reason: row.get(1),
                        by,
                        at: crate::core::Timestamp::from_unix_timestamp(row.get::<_, i64>(4))
                            .map_err(|_| corrupt("instant"))?,
                    },
                ))
            })
            .collect()
    }

    async fn release(&self, run: RunId) -> Result<(), StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let (tenant, run) = (self.tenant_name(), run.to_string());
        for statement in [
            "DELETE FROM quota_running WHERE tenant = $1 AND run_id = $2",
            "DELETE FROM quota_reserved WHERE tenant = $1 AND run_id = $2",
        ] {
            tx.execute(statement, &[&tenant, &run])
                .await
                .map_err(|e| be(&e))?;
        }
        tx.commit().await.map_err(|e| be(&e))
    }

    async fn carry(&self, run: RunId, period: &str) -> Result<(), StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "UPDATE quota_reserved SET period = $3
                  WHERE tenant = $1 AND run_id = $2 AND period <> $3",
                &[&self.tenant_name(), &run.to_string(), &period.to_owned()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn reservations(&self, limit: usize) -> Result<Vec<Held>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT run_id, period, tokens, minor_units FROM quota_reserved
                  WHERE tenant = $1 ORDER BY run_id ASC LIMIT $2",
                &[
                    &self.tenant_name(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        rows.into_iter()
            .map(|row| {
                let raw: String = row.get(0);
                Ok(Held {
                    run: RunId::parse(&raw).map_err(|e| StoreError::Corrupt {
                        seq: 0,
                        detail: format!("bad run id '{raw}' in the quota hold table: {e}"),
                    })?,
                    period: row.get(1),
                    remaining: Spend {
                        tokens: amount_of(row.get(2)),
                        minor_units: amount_of(row.get(3)),
                    },
                })
            })
            .collect()
    }

    async fn reserved(&self, period: &str) -> Result<Spend, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let row = client
            .query_one(
                "SELECT LEAST(9223372036854775807::numeric, COALESCE(SUM(tokens), 0))::bigint,
                        LEAST(9223372036854775807::numeric, COALESCE(SUM(minor_units), 0))::bigint
                   FROM quota_reserved WHERE tenant = $1 AND period = $2",
                &[&self.tenant_name(), &period.to_owned()],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(Spend {
            tokens: amount_of(row.get(0)),
            minor_units: amount_of(row.get(1)),
        })
    }

    async fn settle(&self, settlement: &QuotaSettlement) -> Result<(), StoreError> {
        let mut client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let tx = client.transaction().await.map_err(|e| be(&e))?;
        let tenant = self.tenant_name();
        let run = settlement.run.to_string();
        let epoch = settlement.epoch.cast_signed();
        let tokens = sql_amount(settlement.spend.tokens);
        let minor_units = sql_amount(settlement.spend.minor_units);

        let inserted = tx
            .execute(
                "INSERT INTO quota_settled
                   (tenant, run_id, epoch, period, tokens, minor_units, release_slot, concludes)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (tenant, run_id, epoch) DO NOTHING",
                &[
                    &tenant,
                    &run,
                    &epoch,
                    &settlement.period,
                    &tokens,
                    &minor_units,
                    &settlement.release_slot,
                    &settlement.concludes,
                ],
            )
            .await
            .map_err(|e| be(&e))?;

        if inserted == 0 {
            let stored = tx
                .query_one(
                    "SELECT period, tokens, minor_units, release_slot, concludes
                       FROM quota_settled
                      WHERE tenant = $1 AND run_id = $2 AND epoch = $3",
                    &[&tenant, &run, &epoch],
                )
                .await
                .map_err(|e| be(&e))?;
            let same = stored.get::<_, Option<String>>(0) == settlement.period
                && stored.get::<_, i64>(1) == tokens
                && stored.get::<_, i64>(2) == minor_units
                && stored.get::<_, bool>(3) == settlement.release_slot
                && stored.get::<_, bool>(4) == settlement.concludes;
            if !same {
                return Err(StoreError::Corrupt {
                    seq: 0,
                    detail: format!(
                        "quota pass {run}/{} was settled twice with different payloads",
                        settlement.epoch
                    ),
                });
            }
            tx.commit().await.map_err(|e| be(&e))?;
            return Ok(());
        }

        if let Some(period) = settlement.period.as_deref() {
            // Cast before addition: BIGINT addition can overflow before LEAST
            // sees it. The numeric intermediate is exact and the stored total
            // saturates at the largest representable non-negative amount.
            tx.execute(
                "INSERT INTO quota_spent (tenant, period, tokens, minor_units)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant, period) DO UPDATE SET
                   tokens = LEAST(9223372036854775807::numeric,
                                  quota_spent.tokens::numeric + EXCLUDED.tokens::numeric)::bigint,
                   minor_units = LEAST(9223372036854775807::numeric,
                                       quota_spent.minor_units::numeric + EXCLUDED.minor_units::numeric)::bigint",
                &[&tenant, &period, &tokens, &minor_units],
            )
            .await
            .map_err(|e| be(&e))?;
        }
        // The pass's spend leaves the run's hold as it enters the settled
        // total, so the period counts it once; the concluding pass gives back
        // what the run never spent.
        if settlement.concludes {
            tx.execute(
                "DELETE FROM quota_reserved WHERE tenant = $1 AND run_id = $2",
                &[&tenant, &run],
            )
            .await
            .map_err(|e| be(&e))?;
        } else {
            tx.execute(
                "UPDATE quota_reserved
                    SET tokens = GREATEST(tokens - $3, 0),
                        minor_units = GREATEST(minor_units - $4, 0)
                  WHERE tenant = $1 AND run_id = $2",
                &[&tenant, &run, &tokens, &minor_units],
            )
            .await
            .map_err(|e| be(&e))?;
        }
        if settlement.release_slot {
            tx.execute(
                "DELETE FROM quota_running WHERE tenant = $1 AND run_id = $2",
                &[&tenant, &run],
            )
            .await
            .map_err(|e| be(&e))?;
        }
        tx.commit().await.map_err(|e| be(&e))?;
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

    async fn running_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT run_id FROM quota_running WHERE tenant = $1 \
                 ORDER BY run_id ASC LIMIT $2",
                &[
                    &self.tenant_name(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.get(0);
            // Damage rather than absence — see the embedded backend for why a
            // skipped row is the worst available answer here.
            out.push(RunId::parse(&raw).map_err(|e| StoreError::Corrupt {
                seq: 0,
                detail: format!("bad run id '{raw}' in the quota slot table: {e}"),
            })?);
        }
        Ok(out)
    }
}
