//! Webhook registrations on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::{RunId, Secret, Seq, StoreError};
use crate::push::{
    DueBatch, PushAuthentication, PushConfig, PushNamespace, PushRegistration, PushStore,
};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(tenant, task, config_id) -> (url, token, has_token)`.
///
/// The tenant leads for the same reason it leads everything else: a task id is
/// not a capability, and a handle for one tenant must not be able to read
/// another's webhook — which would disclose both a URL and, without the split
/// below, a bearer token for it.
type StoredPush<'a> = (&'a str, &'a str, u8, &'a str, &'a str, u8);

const PUSH: TableDefinition<(&str, &str, &str), StoredPush<'_>> =
    TableDefinition::new("push_configs");

const PUSH_CURSOR: TableDefinition<(&str, &str, &str), &str> =
    TableDefinition::new("push_delivery_cursor");

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Cursor {
    next_seq: Seq,
    attempts: u32,
    next_attempt_at: u64,
    last_error: Option<String>,
    /// Stopped, with the cursor kept. Excluded from both due scans, so a parked
    /// row costs nothing per tick and still names how far its receiver got.
    parked: bool,
}

/// One config row and its cursor into a registration, shared by
/// [`PushStore::due`] and [`PushStore::due_in`] so the two scans cannot decode
/// one table two ways.
fn registration_from(
    task: &str,
    id: &str,
    value: StoredPush<'_>,
    cursor: Cursor,
) -> Result<PushRegistration, StoreError> {
    let (url, token, has_token, auth_scheme, auth_credentials, has_auth) = value;
    let task = RunId::parse(task).map_err(|error| StoreError::Backend(error.to_string()))?;
    Ok(PushRegistration {
        config: PushConfig {
            id: id.to_owned(),
            task,
            url: url.to_owned(),
            token: (has_token == 1).then(|| Secret::new(token)),
            authentication: (has_auth == 1).then(|| PushAuthentication {
                scheme: auth_scheme.to_owned(),
                credentials: Secret::new(auth_credentials),
            }),
        },
        next_seq: cursor.next_seq,
        attempts: cursor.attempts,
        next_attempt_at: cursor.next_attempt_at,
        last_error: cursor.last_error,
    })
}

#[async_trait]
impl PushStore for RedbStore {
    fn tenant(&self) -> &str {
        self.tenant_str()
    }

    async fn put(&self, config: &PushConfig, next_seq: Seq) -> Result<(), StoreError> {
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
        let (auth_scheme, auth_credentials, has_auth) = config.authentication.as_ref().map_or_else(
            || (String::new(), String::new(), 0),
            |auth| (auth.scheme.clone(), auth.credentials.expose().to_owned(), 1),
        );

        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut t = w.open_table(PUSH).map_err(|e| be(&e))?;
                t.insert(
                    (tenant.as_str(), task.as_str(), id.as_str()),
                    (
                        url.as_str(),
                        token.as_str(),
                        has_token,
                        auth_scheme.as_str(),
                        auth_credentials.as_str(),
                        has_auth,
                    ),
                )
                .map_err(|e| be(&e))?;
                let mut cursors = w.open_table(PUSH_CURSOR).map_err(|e| be(&e))?;
                let existing = cursors
                    .get((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|raw| {
                        serde_json::from_str::<Cursor>(raw.value())
                            .map_err(|error| StoreError::Backend(error.to_string()))
                    })
                    .transpose()?;
                let cursor = serde_json::to_string(&Cursor {
                    next_seq: existing.map_or(next_seq, |cursor| cursor.next_seq),
                    attempts: 0,
                    next_attempt_at: 0,
                    last_error: None,
                    parked: false,
                })
                .map_err(|error| StoreError::Backend(error.to_string()))?;
                cursors
                    .insert(
                        (tenant.as_str(), task.as_str(), id.as_str()),
                        cursor.as_str(),
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
            let (url, token, has_token, auth_scheme, auth_credentials, has_auth) = v.value();
            Ok(Some(PushConfig {
                id,
                task,
                url: url.to_owned(),
                token: (has_token == 1).then(|| Secret::new(token)),
                authentication: (has_auth == 1).then(|| PushAuthentication {
                    scheme: auth_scheme.to_owned(),
                    credentials: Secret::new(auth_credentials),
                }),
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
                let (url, token, has_token, auth_scheme, auth_credentials, has_auth) = v.value();
                out.push(PushConfig {
                    id: k.value().2.to_owned(),
                    task,
                    url: url.to_owned(),
                    token: (has_token == 1).then(|| Secret::new(token)),
                    authentication: (has_auth == 1).then(|| PushAuthentication {
                        scheme: auth_scheme.to_owned(),
                        credentials: Secret::new(auth_credentials),
                    }),
                });
            }
            Ok(out)
        })
        .await
    }

    async fn due(&self, at: u64, limit: usize) -> Result<Vec<PushRegistration>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(configs) = r.open_table(PUSH) else {
                return Ok(Vec::new());
            };
            let Ok(cursors) = r.open_table(PUSH_CURSOR) else {
                return Ok(Vec::new());
            };
            // Longest-due first, the same order `due_in` serves and the
            // postgres twin returns. A key-ordered window under persistent
            // saturation is a ranking by name: a lexically late registration
            // that is continuously due would never be served at all.
            let mut due: Vec<(String, String, Cursor)> = Vec::new();
            for entry in cursors
                .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (key, raw) = entry.map_err(|e| be(&e))?;
                let cursor: Cursor = serde_json::from_str(raw.value())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                if cursor.parked || cursor.next_attempt_at > at {
                    continue;
                }
                let (_, task, id) = key.value();
                due.push((task.to_owned(), id.to_owned(), cursor));
            }
            due.sort_by_key(|(_, _, cursor)| cursor.next_attempt_at);
            due.truncate(limit);
            let mut out = Vec::new();
            for (task, id, cursor) in due {
                let Some(value) = configs
                    .get((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                out.push(registration_from(&task, &id, value.value(), cursor)?);
            }
            Ok(out)
        })
        .await
    }

    async fn due_in(
        &self,
        at: u64,
        limit: usize,
        namespace: PushNamespace,
    ) -> Result<DueBatch, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(configs) = r.open_table(PUSH) else {
                return Ok(DueBatch::default());
            };
            let Ok(cursors) = r.open_table(PUSH_CURSOR) else {
                return Ok(DueBatch::default());
            };
            // One pass, skip-and-count: the paging default is correct here and
            // linear in the other namespace's backlog *per window*, re-reading
            // the head on every doubling. This scan walks the cursor table
            // once. Ownership is decided on the id alone — it is in the key —
            // so a foreign row costs a count and never a config read, and the
            // count runs to the end of the table: `unserved` documents itself
            // as a lower bound, and the exact foreign backlog is the most
            // honest lower bound a full scan can give.
            let mut batch = DueBatch::default();
            let mut due: Vec<(String, String, Cursor)> = Vec::new();
            for entry in cursors
                .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (key, raw) = entry.map_err(|e| be(&e))?;
                let cursor: Cursor = serde_json::from_str(raw.value())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                if cursor.parked || cursor.next_attempt_at > at {
                    continue;
                }
                let (_, task, id) = key.value();
                if !namespace.owns_id(id) {
                    batch.unserved = batch.unserved.saturating_add(1);
                    continue;
                }
                due.push((task.to_owned(), id.to_owned(), cursor));
            }
            // Longest-due first, as the postgres twin orders. A key-ordered
            // window is a ranking by name: under persistent saturation a
            // lexically early registration that is continuously due re-enters
            // every window, and a lexically late one is never served at all.
            due.sort_by_key(|(_, _, cursor)| cursor.next_attempt_at);
            due.truncate(limit);
            for (task, id, cursor) in due {
                let Some(value) = configs
                    .get((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                batch
                    .rows
                    .push(registration_from(&task, &id, value.value(), cursor)?);
            }
            Ok(batch)
        })
        .await
    }

    async fn advance(&self, task: RunId, id: &str, next_seq: Seq) -> Result<(), StoreError> {
        update_cursor(self, task, id, move |cursor| {
            cursor.next_seq = cursor.next_seq.max(next_seq);
            cursor.attempts = 0;
            cursor.next_attempt_at = 0;
            cursor.last_error = None;
            cursor.parked = false;
        })
        .await
    }

    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError> {
        let error = error.to_owned();
        update_cursor(self, task, id, move |cursor| {
            cursor.attempts = cursor.attempts.saturating_add(1);
            cursor.next_attempt_at = next_attempt_at;
            cursor.last_error = Some(error);
            cursor.parked = false;
        })
        .await
    }

    async fn park(&self, task: RunId, id: &str, error: &str) -> Result<(), StoreError> {
        let error = error.to_owned();
        update_cursor(self, task, id, move |cursor| {
            cursor.attempts = cursor.attempts.saturating_add(1);
            cursor.last_error = Some(error);
            cursor.parked = true;
        })
        .await
    }

    async fn parked(&self, limit: usize) -> Result<Vec<PushRegistration>, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(configs) = r.open_table(PUSH) else {
                return Ok(Vec::new());
            };
            let Ok(cursors) = r.open_table(PUSH_CURSOR) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for entry in cursors
                .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (key, raw) = entry.map_err(|e| be(&e))?;
                let cursor: Cursor = serde_json::from_str(raw.value())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                if !cursor.parked {
                    continue;
                }
                let (_, task, id) = key.value();
                let Some(value) = configs
                    .get((tenant.as_str(), task, id))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                out.push(registration_from(task, id, value.value(), cursor)?);
            }
            Ok(out)
        })
        .await
    }

    async fn unpark(&self, task: RunId, id: &str, at: u64) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        let task = task.to_string();
        let id = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let found = {
                let mut cursors = w.open_table(PUSH_CURSOR).map_err(|e| be(&e))?;
                let Some(raw) = cursors
                    .get((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                else {
                    return Ok(false);
                };
                let mut cursor: Cursor = serde_json::from_str(raw.value())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                drop(raw);
                if !cursor.parked {
                    return Ok(false);
                }
                cursor.parked = false;
                cursor.attempts = 0;
                cursor.next_attempt_at = at;
                let raw = serde_json::to_string(&cursor)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                cursors
                    .insert((tenant.as_str(), task.as_str(), id.as_str()), raw.as_str())
                    .map_err(|e| be(&e))?;
                true
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(found)
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
                let mut cursors = w.open_table(PUSH_CURSOR).map_err(|e| be(&e))?;
                cursors
                    .remove((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }
}

async fn update_cursor(
    store: &RedbStore,
    task: RunId,
    id: &str,
    update: impl FnOnce(&mut Cursor) + Send + 'static,
) -> Result<(), StoreError> {
    let tenant = store.tenant_name();
    let task = task.to_string();
    let id = id.to_owned();
    store
        .with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut cursors = w.open_table(PUSH_CURSOR).map_err(|e| be(&e))?;
                let Some(raw) = cursors
                    .get((tenant.as_str(), task.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                else {
                    return Ok(());
                };
                let mut cursor: Cursor = serde_json::from_str(raw.value())
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                drop(raw);
                update(&mut cursor);
                let raw = serde_json::to_string(&cursor)
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                cursors
                    .insert((tenant.as_str(), task.as_str(), id.as_str()), raw.as_str())
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
}
