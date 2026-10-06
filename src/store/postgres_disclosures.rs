//! The disclosure register over Postgres: one table, one row per act.

use async_trait::async_trait;

use crate::core::{CaseId, RunId, StoreError};
use crate::disclosure::{Disclosure, DisclosureRegister};

use super::postgres::{PostgresStore, be, pool_err};

/// One row per act, the act itself as JSON. Mutable by whoever administers the
/// database and on no hash chain — the rung every surface naming an act states.
pub(super) const DISCLOSURE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS disclosures (
    tenant TEXT NOT NULL,
    id     TEXT NOT NULL,
    act    TEXT NOT NULL,
    PRIMARY KEY (tenant, id)
);
";

#[async_trait]
impl DisclosureRegister for PostgresStore {
    async fn record(&self, act: &Disclosure) -> Result<(), StoreError> {
        let encoded = serde_json::to_string(act)?;
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        client
            .execute(
                "INSERT INTO disclosures (tenant, id, act) VALUES ($1, $2, $3)",
                &[&self.tenant_name(), &act.id, &encoded],
            )
            .await
            .map_err(|e| be(&e))?;
        Ok(())
    }

    async fn disclosures(
        &self,
        cases: &[CaseId],
        runs: &[RunId],
    ) -> Result<Vec<Disclosure>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| pool_err(&e))?;
        let rows = client
            .query(
                "SELECT act FROM disclosures WHERE tenant = $1 ORDER BY id",
                &[&self.tenant_name()],
            )
            .await
            .map_err(|e| be(&e))?;
        let mut found = Vec::new();
        for row in rows {
            let act: Disclosure = serde_json::from_str(row.get::<_, &str>(0))?;
            if act.covers(cases, runs) {
                found.push(act);
            }
        }
        Ok(found)
    }
}
