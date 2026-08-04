//! Governed memory on redb.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::core::StoreError;
use crate::memory::{MemoryItem, MemoryStore, Recall};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `(tenant, id, version) -> item JSON`.
///
/// Every version kept, keyed by its own number. Editing in place would make the
/// store unable to answer what the agent believed last week, and unable to undo
/// one write without guessing what it replaced — which is the difference between
/// a memory that can be repaired and one that can only be purged.
const ITEMS: TableDefinition<(&str, &str, u64), &str> = TableDefinition::new("memory_items");

/// `(tenant, subject, purpose, created_at, id) -> version`, current versions only.
///
/// The retrieval path. Subject leads because it is the axis an operator reasons
/// about and the unit an erasure request names; `created_at` is negated so a
/// forward scan reads newest first without reversing an iterator.
const BY_SUBJECT: TableDefinition<(&str, &str, &str, i64, &str), u64> =
    TableDefinition::new("memory_by_subject");

/// `(tenant, id) -> (subject, purpose, created_at, version)`, the current one.
///
/// So superseding a memory can find and remove the index row it replaces without
/// knowing what the previous write said.
const CURRENT: TableDefinition<(&str, &str), (&str, &str, i64, u64)> =
    TableDefinition::new("memory_current");

/// `(tenant, source_id, derived_id) -> ()`, the derivation edges.
///
/// Written when a summary is stored, and read when one is repaired. Without it a
/// poisoned memory can be forgotten while every summary that absorbed it stays
/// readable — the attack outliving its own remedy, which is the failure the
/// whole memory model is shaped to avoid.
const DERIVED: TableDefinition<(&str, &str, &str), ()> = TableDefinition::new("memory_derived");

#[async_trait]
impl MemoryStore for RedbStore {
    async fn remember(&self, item: &MemoryItem) -> Result<u64, StoreError> {
        let tenant = self.tenant_name();
        let id = item.id.clone();
        let subject = item.subject.clone();
        let purpose = item.purpose.clone();
        let created = item.created_at.unix_timestamp();
        let mut item = item.clone();

        self.with_db(move |db| {
            let w = begin_write(db)?;
            let version = {
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;

                // The previous current version, if any: its index row must go,
                // or a recall would return two versions of one memory and the
                // caller would have no way to tell which is believed.
                let previous = current
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (s, p, c, ver) = v.value();
                        (s.to_owned(), p.to_owned(), c, ver)
                    });

                let version = previous.as_ref().map_or(1, |(_, _, _, v)| v + 1);
                item.version = version;

                if let Some((s, p, c, _)) = &previous {
                    by_subject
                        .remove((tenant.as_str(), s.as_str(), p.as_str(), *c, id.as_str()))
                        .map_err(|e| be(&e))?;
                }

                let json =
                    serde_json::to_string(&item).map_err(|e| StoreError::Backend(e.to_string()))?;
                items
                    .insert((tenant.as_str(), id.as_str(), version), json.as_str())
                    .map_err(|e| be(&e))?;
                current
                    .insert(
                        (tenant.as_str(), id.as_str()),
                        (subject.as_str(), purpose.as_str(), created, version),
                    )
                    .map_err(|e| be(&e))?;
                by_subject
                    .insert(
                        (
                            tenant.as_str(),
                            subject.as_str(),
                            purpose.as_str(),
                            // Negated so a forward range reads newest first.
                            -created,
                            id.as_str(),
                        ),
                        version,
                    )
                    .map_err(|e| be(&e))?;

                // One edge per source. Written on every version, so a summary
                // revised to read different sources is findable from the new
                // ones — an edge list built once at first write would answer for
                // a derivation that no longer exists.
                let mut derived = w.open_table(DERIVED).map_err(|e| be(&e))?;
                for source in &item.derived_from {
                    derived
                        .insert((tenant.as_str(), source.id.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                }
                version
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(version)
        })
        .await
    }

    async fn recall(&self, query: &Recall) -> Result<Vec<MemoryItem>, StoreError> {
        let tenant = self.tenant_name();
        let subject = query.subject.clone();
        let purpose = query.purpose.clone();
        let limit = query.limit;

        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(by_subject) = r.open_table(BY_SUBJECT) else {
                return Ok(Vec::new());
            };
            let Ok(items) = r.open_table(ITEMS) else {
                return Ok(Vec::new());
            };

            // Ranged within one tenant and one subject. A purpose narrows the
            // range further rather than filtering afterwards, so a memory kept
            // for support triage is never read into a payments decision by a
            // scan that forgot to check.
            let (from, to) = match &purpose {
                Some(p) => (
                    (tenant.as_str(), subject.as_str(), p.as_str(), i64::MIN, ""),
                    (
                        tenant.as_str(),
                        subject.as_str(),
                        p.as_str(),
                        i64::MAX,
                        MAX_STR,
                    ),
                ),
                None => (
                    (tenant.as_str(), subject.as_str(), "", i64::MIN, ""),
                    (
                        tenant.as_str(),
                        subject.as_str(),
                        MAX_STR,
                        i64::MAX,
                        MAX_STR,
                    ),
                ),
            };

            let mut out = Vec::new();
            for entry in by_subject.range(from..=to).map_err(|e| be(&e))? {
                if out.len() >= limit {
                    break;
                }
                let (k, v) = entry.map_err(|e| be(&e))?;
                let id = k.value().4;
                let Some(raw) = items
                    .get((tenant.as_str(), id, v.value()))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                let item: MemoryItem = serde_json::from_str(raw.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                out.push(item);
            }
            Ok(out)
        })
        .await
    }

    async fn version(&self, id: &str, version: u64) -> Result<Option<MemoryItem>, StoreError> {
        let tenant = self.tenant_name();
        let id = id.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(items) = r.open_table(ITEMS) else {
                return Ok(None);
            };
            let Some(raw) = items
                .get((tenant.as_str(), id.as_str(), version))
                .map_err(|e| be(&e))?
            else {
                return Ok(None);
            };
            serde_json::from_str(raw.value())
                .map(Some)
                .map_err(|e| StoreError::Backend(e.to_string()))
        })
        .await
    }

    async fn derivatives(&self, id: &str) -> Result<Vec<MemoryItem>, StoreError> {
        let tenant = self.tenant_name();
        let source = id.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(edges) = r.open_table(DERIVED) else {
                return Ok(Vec::new());
            };
            let Ok(current) = r.open_table(CURRENT) else {
                return Ok(Vec::new());
            };
            let Ok(items) = r.open_table(ITEMS) else {
                return Ok(Vec::new());
            };

            let mut out = Vec::new();
            for e in edges
                .range(
                    (tenant.as_str(), source.as_str(), "")
                        ..=(tenant.as_str(), source.as_str(), MAX_STR),
                )
                .map_err(|e| be(&e))?
            {
                let (k, _) = e.map_err(|e| be(&e))?;
                let derived_id = k.value().2;

                // Through `current`, so a derivative that has since been
                // forgotten is absent rather than a dangling edge every caller
                // has to filter — and so a repair reads what is believed now
                // rather than a version nobody would act on.
                let Some(v) = current
                    .get((tenant.as_str(), derived_id))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                let version = v.value().3;
                let Some(raw) = items
                    .get((tenant.as_str(), derived_id, version))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                out.push(
                    serde_json::from_str(raw.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?,
                );
            }
            Ok(out)
        })
        .await
    }

    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let id = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;

                if let Some(v) = current
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (s, p, c, ver) = v.value();
                        (s.to_owned(), p.to_owned(), c, ver)
                    })
                {
                    by_subject
                        .remove((
                            tenant.as_str(),
                            v.0.as_str(),
                            v.1.as_str(),
                            v.2,
                            id.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                }
                current
                    .remove((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?;

                // Every version, not only the current one. Forgetting that left
                // history behind would discharge an erasure request while the
                // data it named was still readable by id and version.
                // The edges naming this memory as a *source* go too. Left
                // behind they would make `derivatives` answer for a memory that
                // no longer exists, and a repair walking them would forget
                // summaries of nothing.
                let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let stale: Vec<String> = edges
                    .range(
                        (tenant.as_str(), id.as_str(), "")
                            ..=(tenant.as_str(), id.as_str(), MAX_STR),
                    )
                    .map_err(|e| be(&e))?
                    .map(|e| e.map(|(k, _)| k.value().2.to_owned()).map_err(|e| be(&e)))
                    .collect::<Result<_, _>>()?;
                for derived_id in stale {
                    edges
                        .remove((tenant.as_str(), id.as_str(), derived_id.as_str()))
                        .map_err(|e| be(&e))?;
                }

                let doomed: Vec<u64> = items
                    .range(
                        (tenant.as_str(), id.as_str(), 0)
                            ..=(tenant.as_str(), id.as_str(), u64::MAX),
                    )
                    .map_err(|e| be(&e))?
                    .map(|e| e.map(|(k, _)| k.value().2).map_err(|e| be(&e)))
                    .collect::<Result<_, _>>()?;
                for version in doomed {
                    items
                        .remove((tenant.as_str(), id.as_str(), version))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        let subject = subject.to_owned();

        // The ids first, in a read, then each forgotten through the same path a
        // single forget takes. One implementation of "remove a memory
        // completely" rather than two that can disagree about what completely
        // means.
        let ids = self
            .with_db({
                let tenant = tenant.clone();
                let subject = subject.clone();
                move |db| {
                    let r = db.begin_read().map_err(|e| be(&e))?;
                    let Ok(by_subject) = r.open_table(BY_SUBJECT) else {
                        return Ok(Vec::new());
                    };
                    let mut ids = Vec::new();
                    for entry in by_subject
                        .range(
                            (tenant.as_str(), subject.as_str(), "", i64::MIN, "")
                                ..=(
                                    tenant.as_str(),
                                    subject.as_str(),
                                    MAX_STR,
                                    i64::MAX,
                                    MAX_STR,
                                ),
                        )
                        .map_err(|e| be(&e))?
                    {
                        let (k, _) = entry.map_err(|e| be(&e))?;
                        ids.push(k.value().4.to_owned());
                    }
                    Ok(ids)
                }
            })
            .await?;

        let count = ids.len();
        for id in ids {
            self.forget(&id).await?;
        }
        Ok(count)
    }
}
