//! `PostgreSQL` webhook registrations and durable journal cursors.

use async_trait::async_trait;

use crate::core::{RunId, Secret, Seq, StoreError};
use crate::push::{PushAuthentication, PushConfig, PushRegistration, PushStore};

use super::postgres::PostgresStore;

fn be(error: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(error.to_string())
}

#[async_trait]
impl PushStore for PostgresStore {
    async fn put(&self, config: &PushConfig, next_seq: Seq) -> Result<(), StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        client
            .execute(
                "INSERT INTO push_delivery
                          (tenant, task_id, config_id, url, token, auth_scheme, auth_credentials,
                            next_seq, attempts, next_attempt_at, last_error)
                      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 0, NULL)
                 ON CONFLICT (tenant, task_id, config_id) DO UPDATE SET
                    url = EXCLUDED.url,
                    token = EXCLUDED.token,
                    auth_scheme = EXCLUDED.auth_scheme,
                    auth_credentials = EXCLUDED.auth_credentials,
                    next_seq = push_delivery.next_seq,
                    attempts = 0,
                    next_attempt_at = 0,
                    last_error = NULL",
                &[
                    &self.tenant_name(),
                    &config.task.to_string(),
                    &config.id,
                    &config.url,
                    &config.token.as_ref().map(Secret::expose),
                    &config
                        .authentication
                        .as_ref()
                        .map(|auth| auth.scheme.as_str()),
                    &config
                        .authentication
                        .as_ref()
                        .map(|auth| auth.credentials.expose()),
                    &next_seq.cast_signed(),
                ],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(())
    }

    async fn get(&self, task: RunId, id: &str) -> Result<Option<PushConfig>, StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let row = client
            .query_opt(
                "SELECT url, token, auth_scheme, auth_credentials FROM push_delivery
                 WHERE tenant = $1 AND task_id = $2 AND config_id = $3",
                &[&self.tenant_name(), &task.to_string(), &id],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(row.map(|row| PushConfig {
            id: id.to_owned(),
            task,
            url: row.get(0),
            token: row.get::<_, Option<String>>(1).map(Secret::new),
            authentication: row
                .get::<_, Option<String>>(2)
                .zip(row.get::<_, Option<String>>(3))
                .map(|(scheme, credentials)| PushAuthentication {
                    scheme,
                    credentials: Secret::new(credentials),
                }),
        }))
    }

    async fn list(&self, task: RunId) -> Result<Vec<PushConfig>, StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let rows = client
            .query(
                "SELECT config_id, url, token, auth_scheme, auth_credentials FROM push_delivery
                 WHERE tenant = $1 AND task_id = $2 ORDER BY config_id",
                &[&self.tenant_name(), &task.to_string()],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(rows
            .into_iter()
            .map(|row| PushConfig {
                id: row.get(0),
                task,
                url: row.get(1),
                token: row.get::<_, Option<String>>(2).map(Secret::new),
                authentication: row
                    .get::<_, Option<String>>(3)
                    .zip(row.get::<_, Option<String>>(4))
                    .map(|(scheme, credentials)| PushAuthentication {
                        scheme,
                        credentials: Secret::new(credentials),
                    }),
            })
            .collect())
    }

    async fn due(&self, at: u64, limit: usize) -> Result<Vec<PushRegistration>, StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let rows = client
            .query(
                "SELECT task_id, config_id, url, token, auth_scheme, auth_credentials,
                    next_seq, attempts, next_attempt_at, last_error
                 FROM push_delivery
                 WHERE tenant = $1 AND next_attempt_at <= $2
                 ORDER BY next_attempt_at, task_id, config_id
                 LIMIT $3",
                &[
                    &self.tenant_name(),
                    &at.cast_signed(),
                    &i64::try_from(limit).unwrap_or(i64::MAX),
                ],
            )
            .await
            .map_err(|error| be(&error))?;
        rows.into_iter()
            .map(|row| {
                let task_id: String = row.get(0);
                Ok(PushRegistration {
                    config: PushConfig {
                        id: row.get(1),
                        task: RunId::parse(&task_id)
                            .map_err(|error| StoreError::Backend(error.to_string()))?,
                        url: row.get(2),
                        token: row.get::<_, Option<String>>(3).map(Secret::new),
                        authentication: row
                            .get::<_, Option<String>>(4)
                            .zip(row.get::<_, Option<String>>(5))
                            .map(|(scheme, credentials)| PushAuthentication {
                                scheme,
                                credentials: Secret::new(credentials),
                            }),
                    },
                    next_seq: row.get::<_, i64>(6).cast_unsigned(),
                    attempts: row.get::<_, i32>(7).cast_unsigned(),
                    next_attempt_at: row.get::<_, i64>(8).cast_unsigned(),
                    last_error: row.get(9),
                })
            })
            .collect()
    }

    async fn advance(&self, task: RunId, id: &str, next_seq: Seq) -> Result<(), StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        client
            .execute(
                "UPDATE push_delivery
                 SET next_seq = GREATEST(next_seq, $4), attempts = 0,
                     next_attempt_at = 0, last_error = NULL
                 WHERE tenant = $1 AND task_id = $2 AND config_id = $3",
                &[
                    &self.tenant_name(),
                    &task.to_string(),
                    &id,
                    &next_seq.cast_signed(),
                ],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(())
    }

    async fn retry(
        &self,
        task: RunId,
        id: &str,
        next_attempt_at: u64,
        error: &str,
    ) -> Result<(), StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|pool_error| StoreError::Backend(pool_error.to_string()))?;
        client
            .execute(
                "UPDATE push_delivery
                 SET attempts = LEAST(attempts + 1, 2147483647),
                     next_attempt_at = $4, last_error = $5
                 WHERE tenant = $1 AND task_id = $2 AND config_id = $3",
                &[
                    &self.tenant_name(),
                    &task.to_string(),
                    &id,
                    &next_attempt_at.cast_signed(),
                    &error,
                ],
            )
            .await
            .map_err(|db_error| be(&db_error))?;
        Ok(())
    }

    async fn delete(&self, task: RunId, id: &str) -> Result<(), StoreError> {
        let client = self
            .pool_ref()
            .get()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        client
            .execute(
                "DELETE FROM push_delivery
                 WHERE tenant = $1 AND task_id = $2 AND config_id = $3",
                &[&self.tenant_name(), &task.to_string(), &id],
            )
            .await
            .map_err(|error| be(&error))?;
        Ok(())
    }
}
