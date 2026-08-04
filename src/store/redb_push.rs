//! Webhook registrations on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, TableDefinition};

use crate::core::{RunId, Secret, StoreError};
use crate::push::{PushConfig, PushStore};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(tenant, task, config_id) -> (url, token, has_token)`.
///
/// The tenant leads for the same reason it leads everything else: a task id is
/// not a capability, and a handle for one tenant must not be able to read
/// another's webhook — which would disclose both a URL and, without the split
/// below, a bearer token for it.
const PUSH: TableDefinition<(&str, &str, &str), (&str, &str, u8)> =
    TableDefinition::new("push_configs");

#[async_trait]
impl PushStore for RedbStore {
    async fn put(&self, config: &PushConfig) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let task = config.task.to_string();
        let id = config.id.clone();
        let url = config.url.clone();
        // Stored, because delivery happens long after the request that
        // registered it — a token held only in memory would leave every
        // notification after a restart unauthenticated at the receiver.
        let (token, has_token) = config
            .token
            .as_ref()
            .map_or_else(|| (String::new(), 0), |s| (s.expose().to_owned(), 1));

        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(PUSH).map_err(|e| be(&e))?;
                t.insert(
                    (tenant.as_str(), task.as_str(), id.as_str()),
                    (url.as_str(), token.as_str(), has_token),
                )
                .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn get(&self, task: RunId, id: &str) -> Result<Option<PushConfig>, StoreError> {
        let tenant = self.tenant_name();
        let task_key = task.to_string();
        let id = id.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(PUSH) else {
                return Ok(None);
            };
            let Some(v) = t
                .get((tenant.as_str(), task_key.as_str(), id.as_str()))
                .map_err(|e| be(&e))?
            else {
                return Ok(None);
            };
            let (url, token, has_token) = v.value();
            Ok(Some(PushConfig {
                id,
                task,
                url: url.to_owned(),
                token: (has_token == 1).then(|| Secret::new(token)),
            }))
        })
        .await
    }

    async fn list(&self, task: RunId) -> Result<Vec<PushConfig>, StoreError> {
        let tenant = self.tenant_name();
        let task_key = task.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(t) = r.open_table(PUSH) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for e in t
                .range(
                    (tenant.as_str(), task_key.as_str(), "")
                        ..=(tenant.as_str(), task_key.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                let (k, v) = e.map_err(|e| be(&e))?;
                let (url, token, has_token) = v.value();
                out.push(PushConfig {
                    id: k.value().2.to_owned(),
                    task,
                    url: url.to_owned(),
                    token: (has_token == 1).then(|| Secret::new(token)),
                });
            }
            Ok(out)
        })
        .await
    }

    async fn delete(&self, task: RunId, id: &str) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let task = task.to_string();
        let id = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(PUSH).map_err(|e| be(&e))?;
                t.remove((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }
}
