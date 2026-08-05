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

/// `(tenant, subject, purpose, created_at, id) -> (version, trust rank)`,
/// current versions only.
///
/// The retrieval path. Subject leads because it is the axis an operator reasons
/// about and the unit an erasure request names; `created_at` is negated so a
/// forward scan reads newest first without reversing an iterator.
///
/// The **trust rank rides in the index value** so a bounded recall can rank by
/// it without reading every item. Recall truncates, and truncating by recency
/// alone is an eviction an attacker steers: anything that can write an untrusted
/// memory — model output and tool output both can, by design — writes `limit` of
/// them and the trusted ones silently lose. Every label stays correct in that
/// scenario, which is what makes it hard to see; the defect is in the ordering,
/// not the labelling.
/// `(tenant, subject, purpose, negated created_at, id)`.
type SubjectKey<'a> = (&'a str, &'a str, &'a str, i64, &'a str);
/// The current version, and how it ranks for trust.
type SubjectEntry = (u64, u8);

const BY_SUBJECT: TableDefinition<SubjectKey, SubjectEntry> =
    TableDefinition::new("memory_by_subject");

/// Lower sorts first. Explicit rather than relying on the enum's own order, so
/// a new level has to be given a rank rather than inheriting one.
const fn trust_rank(trust: crate::core::Trust) -> u8 {
    match trust {
        crate::core::Trust::Trusted => 0,
        crate::core::Trust::Untrusted => 1,
    }
}

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

/// `(tenant, id) -> ()`, identities whose content was erased.
///
/// An id is never recycled. Reuse would make an old journal selection name new
/// content and would make retained derivation edges attach old lineage to an
/// unrelated memory.
const FORGOTTEN: TableDefinition<(&str, &str), ()> = TableDefinition::new("memory_forgotten");

/// `(tenant, id) -> ()`, legal holds that block every erasure path.
const HOLDS: TableDefinition<(&str, &str), ()> = TableDefinition::new("memory_legal_holds");

/// `(tenant, id) -> effective access expiry`, separate from immutable items.
const ACCESS_EXPIRY: TableDefinition<(&str, &str), i64> =
    TableDefinition::new("memory_access_expiry");

#[async_trait]
impl MemoryStore for RedbStore {
    #[allow(clippy::too_many_lines)]
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

                if previous.is_none()
                    && w.open_table(FORGOTTEN)
                        .map_err(|e| be(&e))?
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some()
                {
                    return Err(StoreError::Backend(format!(
                        "memory id '{id}' was forgotten and cannot be reused"
                    )));
                }

                if let Some((previous_subject, previous_purpose, _, _)) = &previous
                    && (previous_subject != &subject || previous_purpose != &purpose)
                {
                    return Err(StoreError::Backend(format!(
                        "memory id '{id}' is scoped to subject '{previous_subject}' and purpose \
                         '{previous_purpose}'; use a new id instead of moving it to subject \
                         '{subject}' and purpose '{purpose}'"
                    )));
                }

                for source in &item.derived_from {
                    let raw = items
                        .get((tenant.as_str(), source.id.as_str(), source.version))
                        .map_err(|e| be(&e))?
                        .map(|raw| raw.value().to_owned())
                        .ok_or_else(|| {
                            StoreError::Backend(format!(
                                "derived memory '{id}' names missing source '{}' version {}",
                                source.id, source.version
                            ))
                        })?;
                    let source_item: MemoryItem = serde_json::from_str(&raw)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    if source_item.selection_digest() != source.digest {
                        return Err(StoreError::Backend(format!(
                            "derived memory '{id}' names a changed source '{}' version {}",
                            source.id, source.version
                        )));
                    }
                    if source_item.subject != subject {
                        return Err(StoreError::Backend(format!(
                            "derived memory '{id}' must stay in source subject '{}' rather than \
                             '{subject}'",
                            source_item.subject
                        )));
                    }
                }

                let version = previous.as_ref().map_or(1, |(_, _, _, v)| v + 1);
                item.version = version;
                item.superseded_at = None;

                if let Some((s, p, c, previous_version)) = &previous {
                    by_subject
                        .remove((tenant.as_str(), s.as_str(), p.as_str(), -*c, id.as_str()))
                        .map_err(|e| be(&e))?;

                    // Supersession is part of the version's durable history,
                    // not only an index decision. Without this write the public
                    // `superseded_at` field is permanently `None`, so an audit
                    // cannot tell when the old belief stopped being current.
                    let previous_json = items
                        .get((tenant.as_str(), id.as_str(), *previous_version))
                        .map_err(|e| be(&e))?
                        .map(|raw| raw.value().to_owned());
                    if let Some(previous_json) = previous_json {
                        let mut superseded: MemoryItem = serde_json::from_str(&previous_json)
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                        superseded.superseded_at = Some(item.created_at);
                        let json = serde_json::to_string(&superseded)
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                        items
                            .insert(
                                (tenant.as_str(), id.as_str(), *previous_version),
                                json.as_str(),
                            )
                            .map_err(|e| be(&e))?;
                    }
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
                        (version, trust_rank(item.trust)),
                    )
                    .map_err(|e| be(&e))?;

                // One edge per source. Written on every version, so a summary
                // revised to read different sources is findable from the new
                // ones. Remove the old incoming edges first: otherwise a source
                // no longer present in the current summary can still erase it,
                // even though the current summary no longer contains it.
                let mut derived = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let stale_sources: Vec<String> = derived
                    .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                    .filter_map(|entry| match entry {
                        Ok((key, _)) if key.value().2 == id => Some(Ok(key.value().1.to_owned())),
                        Ok(_) => None,
                        Err(error) => Some(Err(be(&error))),
                    })
                    .collect::<Result<_, StoreError>>()?;
                for source_id in stale_sources {
                    derived
                        .remove((tenant.as_str(), source_id.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                }
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
        let as_of = query.as_of;

        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(by_subject) = r.open_table(BY_SUBJECT) else {
                return Ok(Vec::new());
            };
            let Ok(items) = r.open_table(ITEMS) else {
                return Ok(Vec::new());
            };
            let access = r.open_table(ACCESS_EXPIRY).ok();

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

            // Two buckets, each bounded by `limit`, filled in one pass — so a
            // trusted memory is never evicted by a newer untrusted one, and the
            // scan still reads at most `2 * limit` items rather than the whole
            // subject. The index range is walked to its end because the rank is
            // in the value: stopping early would be the recency-only truncation
            // this exists to remove.
            let mut trusted: Vec<MemoryItem> = Vec::new();
            let mut untrusted: Vec<MemoryItem> = Vec::new();
            for entry in by_subject.range(from..=to).map_err(|e| be(&e))? {
                if trusted.len() >= limit {
                    break;
                }
                let (k, v) = entry.map_err(|e| be(&e))?;
                let (version, rank) = v.value();
                // A full untrusted bucket cannot improve the answer, and
                // deserializing into it would be work thrown away.
                if rank != 0 && untrusted.len() >= limit {
                    continue;
                }
                let id = k.value().4;
                let Some(raw) = items
                    .get((tenant.as_str(), id, version))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                let item: MemoryItem = serde_json::from_str(raw.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let access_expiry = access
                    .as_ref()
                    .and_then(|table| table.get((tenant.as_str(), id)).ok().flatten())
                    .and_then(|value| {
                        crate::core::Timestamp::from_unix_timestamp(value.value()).ok()
                    });
                let effective = match (item.expires_at, access_expiry) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (left, right) => left.or(right),
                };
                if as_of.is_some_and(|at| effective.is_some_and(|expires| expires <= at)) {
                    continue;
                }
                if rank == 0 {
                    trusted.push(item);
                } else {
                    untrusted.push(item);
                }
            }
            trusted.truncate(limit);
            let room = limit - trusted.len();
            untrusted.truncate(room);
            trusted.append(&mut untrusted);
            Ok(trusted)
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

    #[allow(clippy::too_many_lines)]
    async fn forget_cascading(&self, id: &str) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        let root = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let removed = {
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;
                let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let mut forgotten = w.open_table(FORGOTTEN).map_err(|e| be(&e))?;

                // redb admits one writer, so the graph cannot grow between
                // this traversal and the deletions below.
                let mut queue = vec![root];
                let mut doomed = std::collections::BTreeSet::new();
                while let Some(source) = queue.pop() {
                    if !doomed.insert(source.clone()) {
                        continue;
                    }
                    let children: Vec<String> = edges
                        .range(
                            (tenant.as_str(), source.as_str(), "")
                                ..=(tenant.as_str(), source.as_str(), MAX_STR),
                        )
                        .map_err(|e| be(&e))?
                        .filter_map(|entry| match entry {
                            Ok((key, _)) => {
                                let child = key.value().2.to_owned();
                                match current.get((tenant.as_str(), child.as_str())) {
                                    Ok(Some(_)) => Some(Ok(child)),
                                    Ok(None) => None,
                                    Err(error) => Some(Err(be(&error))),
                                }
                            }
                            Err(error) => Some(Err(be(&error))),
                        })
                        .collect::<Result<_, StoreError>>()?;
                    queue.extend(children);
                }

                let holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
                for memory_id in &doomed {
                    if holds
                        .get((tenant.as_str(), memory_id.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some()
                    {
                        return Err(StoreError::Backend(format!(
                            "memory '{memory_id}' is under legal hold"
                        )));
                    }
                }

                for memory_id in &doomed {
                    let previous = current
                        .get((tenant.as_str(), memory_id.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|value| {
                            let (subject, purpose, created, version) = value.value();
                            (subject.to_owned(), purpose.to_owned(), created, version)
                        });
                    if let Some((subject, purpose, created, _)) = &previous {
                        by_subject
                            .remove((
                                tenant.as_str(),
                                subject.as_str(),
                                purpose.as_str(),
                                -*created,
                                memory_id.as_str(),
                            ))
                            .map_err(|e| be(&e))?;
                    }
                    current
                        .remove((tenant.as_str(), memory_id.as_str()))
                        .map_err(|e| be(&e))?;
                    forgotten
                        .insert((tenant.as_str(), memory_id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    access
                        .remove((tenant.as_str(), memory_id.as_str()))
                        .map_err(|e| be(&e))?;

                    let versions: Vec<u64> = items
                        .range(
                            (tenant.as_str(), memory_id.as_str(), 0)
                                ..=(tenant.as_str(), memory_id.as_str(), u64::MAX),
                        )
                        .map_err(|e| be(&e))?
                        .map(|entry| {
                            entry
                                .map(|(key, _)| key.value().2)
                                .map_err(|error| be(&error))
                        })
                        .collect::<Result<_, _>>()?;
                    for version in versions {
                        items
                            .remove((tenant.as_str(), memory_id.as_str(), version))
                            .map_err(|e| be(&e))?;
                    }
                }

                // Cascading erasure no longer needs repair lineage for any
                // vertex it removed. Delete both incoming and outgoing edges.
                let stale_edges: Vec<(String, String)> = edges
                    .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                    .filter_map(|entry| match entry {
                        Ok((key, _)) => {
                            let (_, source, derived) = key.value();
                            (doomed.contains(source) || doomed.contains(derived))
                                .then(|| Ok((source.to_owned(), derived.to_owned())))
                        }
                        Err(error) => Some(Err(be(&error))),
                    })
                    .collect::<Result<_, StoreError>>()?;
                for (source, derived) in stale_edges {
                    edges
                        .remove((tenant.as_str(), source.as_str(), derived.as_str()))
                        .map_err(|e| be(&e))?;
                }
                doomed.len()
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(removed)
        })
        .await
    }

    async fn forget(&self, id: &str) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let id = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                if w.open_table(HOLDS)
                    .map_err(|e| be(&e))?
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .is_some()
                {
                    return Err(StoreError::Backend(format!(
                        "memory '{id}' is under legal hold"
                    )));
                }
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;

                let previous = current
                    .get((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (s, p, c, ver) = v.value();
                        (s.to_owned(), p.to_owned(), c, ver)
                    });
                if let Some(v) = &previous {
                    by_subject
                        .remove((
                            tenant.as_str(),
                            v.0.as_str(),
                            v.1.as_str(),
                            -v.2,
                            id.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                }
                current
                    .remove((tenant.as_str(), id.as_str()))
                    .map_err(|e| be(&e))?;

                if previous.is_some() {
                    w.open_table(FORGOTTEN)
                        .map_err(|e| be(&e))?
                        .insert((tenant.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                }

                // Every version, not only the current one. Forgetting that left
                // history behind would discharge an erasure request while the
                // data it named was still readable by id and version.
                // Outgoing edges, where this memory is the source, deliberately
                // stay: a correction may later become an erasure request, and
                // losing those edges would make its derived summaries
                // undiscoverable. The tombstone above prevents id reuse from
                // attaching that lineage to unrelated future content.
                let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                // Incoming edges no longer point at a current derivative and
                // are unnecessary for repairing anything upstream.
                let stale_sources: Vec<String> = edges
                    .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                    .filter_map(|entry| match entry {
                        Ok((key, _)) if key.value().2 == id => Some(Ok(key.value().1.to_owned())),
                        Ok(_) => None,
                        Err(error) => Some(Err(be(&error))),
                    })
                    .collect::<Result<_, StoreError>>()?;
                for source_id in stale_sources {
                    edges
                        .remove((tenant.as_str(), source_id.as_str(), id.as_str()))
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

    #[allow(clippy::too_many_lines)]
    async fn forget_subject(&self, subject: &str) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        let subject = subject.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let count = {
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;
                let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let mut forgotten = w.open_table(FORGOTTEN).map_err(|e| be(&e))?;
                let holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                let ids: Vec<String> = by_subject
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
                    .map(|entry| {
                        entry
                            .map(|(key, _)| key.value().4.to_owned())
                            .map_err(|error| be(&error))
                    })
                    .collect::<Result<_, _>>()?;
                for id in &ids {
                    if holds
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some()
                    {
                        return Err(StoreError::Backend(format!(
                            "memory '{id}' is under legal hold"
                        )));
                    }
                }
                for id in &ids {
                    let previous = current
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|value| {
                            let (scope, purpose, created, _) = value.value();
                            (scope.to_owned(), purpose.to_owned(), created)
                        });
                    if let Some((scope, purpose, created)) = previous {
                        by_subject
                            .remove((
                                tenant.as_str(),
                                scope.as_str(),
                                purpose.as_str(),
                                -created,
                                id.as_str(),
                            ))
                            .map_err(|e| be(&e))?;
                    }
                    current
                        .remove((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                    forgotten
                        .insert((tenant.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    let incoming: Vec<String> = edges
                        .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                        .map_err(|e| be(&e))?
                        .filter_map(|entry| match entry {
                            Ok((key, _)) if key.value().2 == id => {
                                Some(Ok(key.value().1.to_owned()))
                            }
                            Ok(_) => None,
                            Err(error) => Some(Err(be(&error))),
                        })
                        .collect::<Result<_, StoreError>>()?;
                    for source in incoming {
                        edges
                            .remove((tenant.as_str(), source.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?;
                    }
                    let versions: Vec<u64> = items
                        .range(
                            (tenant.as_str(), id.as_str(), 0)
                                ..=(tenant.as_str(), id.as_str(), u64::MAX),
                        )
                        .map_err(|e| be(&e))?
                        .map(|entry| {
                            entry
                                .map(|(key, _)| key.value().2)
                                .map_err(|error| be(&error))
                        })
                        .collect::<Result<_, _>>()?;
                    for version in versions {
                        items
                            .remove((tenant.as_str(), id.as_str(), version))
                            .map_err(|e| be(&e))?;
                    }
                }
                ids.len()
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(count)
        })
        .await
    }

    async fn set_legal_hold(&self, id: &str, held: bool) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let id = id.to_owned();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                if held
                    && current
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .is_none()
                {
                    return Err(StoreError::Backend(format!(
                        "cannot hold missing memory '{id}'"
                    )));
                }
                let mut holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                if held {
                    holds
                        .insert((tenant.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                } else {
                    holds
                        .remove((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
    }

    async fn legal_hold(&self, id: &str) -> Result<bool, StoreError> {
        let tenant = self.tenant_name();
        let id = id.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(holds) = r.open_table(HOLDS) else {
                return Ok(false);
            };
            holds
                .get((tenant.as_str(), id.as_str()))
                .map(|value| value.is_some())
                .map_err(|e| be(&e))
        })
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn sweep_expired(&self, at: crate::core::Timestamp) -> Result<usize, StoreError> {
        let tenant = self.tenant_name();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let removed = {
                let mut items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let mut by_subject = w.open_table(BY_SUBJECT).map_err(|e| be(&e))?;
                let mut forgotten = w.open_table(FORGOTTEN).map_err(|e| be(&e))?;
                let mut edges = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                let access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
                let entries: Vec<(String, String, String, i64, u64)> = current
                    .range((tenant.as_str(), "")..=(tenant.as_str(), MAX_STR))
                    .map_err(|e| be(&e))?
                    .map(|entry| {
                        entry
                            .map(|(key, value)| {
                                let (_, id) = key.value();
                                let (subject, purpose, created, version) = value.value();
                                (
                                    id.to_owned(),
                                    subject.to_owned(),
                                    purpose.to_owned(),
                                    created,
                                    version,
                                )
                            })
                            .map_err(|e| be(&e))
                    })
                    .collect::<Result<_, _>>()?;
                let mut expired = Vec::new();
                for (id, subject, purpose, created, version) in entries {
                    if holds
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some()
                    {
                        continue;
                    }
                    let Some(raw) = items
                        .get((tenant.as_str(), id.as_str(), version))
                        .map_err(|e| be(&e))?
                    else {
                        continue;
                    };
                    let item: MemoryItem = serde_json::from_str(raw.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    let access_expiry = access
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .and_then(|value| {
                            crate::core::Timestamp::from_unix_timestamp(value.value()).ok()
                        });
                    let effective = match (item.expires_at, access_expiry) {
                        (Some(left), Some(right)) => Some(left.max(right)),
                        (left, right) => left.or(right),
                    };
                    if effective.is_some_and(|expires| expires <= at) {
                        expired.push((id, subject, purpose, created));
                    }
                }
                for (id, subject, purpose, created) in &expired {
                    by_subject
                        .remove((
                            tenant.as_str(),
                            subject.as_str(),
                            purpose.as_str(),
                            -*created,
                            id.as_str(),
                        ))
                        .map_err(|e| be(&e))?;
                    current
                        .remove((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                    forgotten
                        .insert((tenant.as_str(), id.as_str()), ())
                        .map_err(|e| be(&e))?;
                    let incoming: Vec<String> = edges
                        .range((tenant.as_str(), "", "")..=(tenant.as_str(), MAX_STR, MAX_STR))
                        .map_err(|e| be(&e))?
                        .filter_map(|entry| match entry {
                            Ok((key, _)) if key.value().2 == id => {
                                Some(Ok(key.value().1.to_owned()))
                            }
                            Ok(_) => None,
                            Err(error) => Some(Err(be(&error))),
                        })
                        .collect::<Result<_, StoreError>>()?;
                    for source in incoming {
                        edges
                            .remove((tenant.as_str(), source.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?;
                    }
                    let versions: Vec<u64> = items
                        .range(
                            (tenant.as_str(), id.as_str(), 0)
                                ..=(tenant.as_str(), id.as_str(), u64::MAX),
                        )
                        .map_err(|e| be(&e))?
                        .map(|entry| {
                            entry
                                .map(|(key, _)| key.value().2)
                                .map_err(|error| be(&error))
                        })
                        .collect::<Result<_, _>>()?;
                    for version in versions {
                        items
                            .remove((tenant.as_str(), id.as_str(), version))
                            .map_err(|e| be(&e))?;
                    }
                }
                expired.len()
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(removed)
        })
        .await
    }

    async fn touch(&self, ids: &[String], at: crate::core::Timestamp) -> Result<(), StoreError> {
        let tenant = self.tenant_name();
        let ids = ids.to_vec();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let current = w.open_table(CURRENT).map_err(|e| be(&e))?;
                let items = w.open_table(ITEMS).map_err(|e| be(&e))?;
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
                for id in &ids {
                    let Some(pointer) = current
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                    else {
                        continue;
                    };
                    let version = pointer.value().3;
                    let Some(raw) = items
                        .get((tenant.as_str(), id.as_str(), version))
                        .map_err(|e| be(&e))?
                    else {
                        continue;
                    };
                    let item: MemoryItem = serde_json::from_str(raw.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    let Some(window) = item.access_retention_seconds else {
                        continue;
                    };
                    let window = i64::try_from(window).unwrap_or(i64::MAX);
                    let expiry = at.unix_timestamp().saturating_add(window);
                    let prior = access
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .map_or(i64::MIN, |value| value.value());
                    if expiry > prior {
                        access
                            .insert((tenant.as_str(), id.as_str()), expiry)
                            .map_err(|e| be(&e))?;
                    }
                }
            }
            w.commit().map_err(|e| be(&e))
        })
        .await
    }
}
