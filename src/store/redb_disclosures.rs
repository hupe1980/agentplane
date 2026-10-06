//! The disclosure register over redb: one table, keyed by tenant and act id.

use async_trait::async_trait;
use redb::{ReadableDatabase, TableDefinition};

use crate::core::{CaseId, RunId, StoreError};
use crate::disclosure::{Disclosure, DisclosureRegister};

use super::redb::{RedbStore, be, begin_write};

/// `(tenant, id)` → the act as JSON. An id leads with a ULID, so key order is
/// the order the acts were recorded in.
const DISCLOSURES: TableDefinition<(&str, &str), &str> = TableDefinition::new("disclosures");

#[async_trait]
impl DisclosureRegister for RedbStore {
    async fn record(&self, act: &Disclosure) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let id = act.id.clone();
        let encoded = serde_json::to_string(act)?;
        self.with_db(move |db| {
            let w = begin_write(db)?;
            w.open_table(DISCLOSURES)
                .map_err(|e| be(&e))?
                .insert((tenant.as_str(), id.as_str()), encoded.as_str())
                .map_err(|e| be(&e))?;
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn disclosures(
        &self,
        cases: &[CaseId],
        runs: &[RunId],
    ) -> Result<Vec<Disclosure>, StoreError> {
        let tenant = self.tenant_name();
        let rows = self
            .with_db(move |db| {
                let r = db.begin_read().map_err(|e| be(&e))?;
                // Absent until the first disclosure.
                let Ok(t) = r.open_table(DISCLOSURES) else {
                    return Ok(Vec::new());
                };
                let mut out = Vec::new();
                for entry in t
                    .range((tenant.as_str(), "")..=(tenant.as_str(), "\u{10ffff}"))
                    .map_err(|e| be(&e))?
                {
                    let (_, value) = entry.map_err(|e| be(&e))?;
                    out.push(value.value().to_owned());
                }
                Ok(out)
            })
            .await?;
        let mut found = Vec::new();
        for raw in rows {
            let act: Disclosure = serde_json::from_str(&raw)?;
            if act.covers(cases, runs) {
                found.push(act);
            }
        }
        Ok(found)
    }
}
