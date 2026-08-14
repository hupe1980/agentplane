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

/// `(tenant, source_id, source_version, derived_id, derived_version) -> ()`,
/// the derivation edges — **per version on both ends**.
///
/// Written when a summary is stored, and read when one is repaired. Without it a
/// poisoned memory can be forgotten while every summary that absorbed it stays
/// readable — the attack outliving its own remedy, which is the failure the
/// whole memory model is shaped to avoid.
///
/// Per-version rather than per-id, because supersession does not un-absorb
/// anything: a summary re-derived from other sources still *contains* what its
/// superseded version read, and that version stays readable through
/// `version()`. Id-level edges were replaced on every revision, so a cascade
/// from the original source no longer found the superseded summary that had
/// absorbed it. Keeping every version's edges makes the traversal see the
/// union of what was ever derived, and lets it erase exactly the superseded
/// versions that named a doomed source while sparing a current version that
/// did not.
const DERIVED: TableDefinition<(&str, &str, u64, &str, u64), ()> =
    TableDefinition::new("memory_derived");

/// `(tenant, derived_id, derived_version, source_id, source_version) -> ()`,
/// the same edges keyed from the target side.
///
/// The reverse lookup erasure needs: removing a memory must find the edges
/// *pointing at it* without ranging over every edge the tenant has, which is a
/// scan that grows with the corpus and runs inside every erasure transaction.
/// Written and removed in the same transaction as [`DERIVED`], always — the two
/// tables are one index, not two facts.
const DERIVED_BY_TARGET: TableDefinition<(&str, &str, u64, &str, u64), ()> =
    TableDefinition::new("memory_derived_by_target");

/// One derivation edge, both endpoints versioned, as erasure collects them.
type Edge = (String, u64, String, u64);

/// Every edge touching any version of `id`, in either direction.
///
/// Both tables are ranged by their leading id, so this is proportional to the
/// node's own degree rather than to the tenant's edge count. An edge whose two
/// endpoints are both being erased is collected twice; removal is idempotent,
/// so the duplicate costs a lookup and nothing else.
fn collect_edges_of_id(
    forward: &impl ReadableTable<(&'static str, &'static str, u64, &'static str, u64), ()>,
    reverse: &impl ReadableTable<(&'static str, &'static str, u64, &'static str, u64), ()>,
    tenant: &str,
    id: &str,
    out: &mut Vec<Edge>,
) -> Result<(), StoreError> {
    for entry in forward
        .range((tenant, id, 0, "", 0)..=(tenant, id, u64::MAX, MAX_STR, u64::MAX))
        .map_err(|e| be(&e))?
    {
        let (key, _) = entry.map_err(|e| be(&e))?;
        let (_, source_id, source_version, derived_id, derived_version) = key.value();
        out.push((
            source_id.to_owned(),
            source_version,
            derived_id.to_owned(),
            derived_version,
        ));
    }
    for entry in reverse
        .range((tenant, id, 0, "", 0)..=(tenant, id, u64::MAX, MAX_STR, u64::MAX))
        .map_err(|e| be(&e))?
    {
        let (key, _) = entry.map_err(|e| be(&e))?;
        let (_, derived_id, derived_version, source_id, source_version) = key.value();
        out.push((
            source_id.to_owned(),
            source_version,
            derived_id.to_owned(),
            derived_version,
        ));
    }
    Ok(())
}

/// Every edge touching exactly `(id, version)`, in either direction.
fn collect_edges_of_version(
    forward: &impl ReadableTable<(&'static str, &'static str, u64, &'static str, u64), ()>,
    reverse: &impl ReadableTable<(&'static str, &'static str, u64, &'static str, u64), ()>,
    tenant: &str,
    id: &str,
    version: u64,
    out: &mut Vec<Edge>,
) -> Result<(), StoreError> {
    for entry in forward
        .range((tenant, id, version, "", 0)..=(tenant, id, version, MAX_STR, u64::MAX))
        .map_err(|e| be(&e))?
    {
        let (key, _) = entry.map_err(|e| be(&e))?;
        let (_, source_id, source_version, derived_id, derived_version) = key.value();
        out.push((
            source_id.to_owned(),
            source_version,
            derived_id.to_owned(),
            derived_version,
        ));
    }
    for entry in reverse
        .range((tenant, id, version, "", 0)..=(tenant, id, version, MAX_STR, u64::MAX))
        .map_err(|e| be(&e))?
    {
        let (key, _) = entry.map_err(|e| be(&e))?;
        let (_, derived_id, derived_version, source_id, source_version) = key.value();
        out.push((
            source_id.to_owned(),
            source_version,
            derived_id.to_owned(),
            derived_version,
        ));
    }
    Ok(())
}

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

                // One edge per source, keyed by **this version** on the
                // derived end and the exact version read on the source end.
                // Earlier versions' edges are deliberately left in place: a
                // superseded summary still contains what it absorbed, and it
                // stays readable through `version()`, so its lineage must stay
                // traversable for exactly as long as the version itself
                // exists. Erasure — not supersession — is what removes edges.
                let mut derived = w.open_table(DERIVED).map_err(|e| be(&e))?;
                let mut derived_rev = w.open_table(DERIVED_BY_TARGET).map_err(|e| be(&e))?;
                for source in &item.derived_from {
                    derived
                        .insert(
                            (
                                tenant.as_str(),
                                source.id.as_str(),
                                source.version,
                                id.as_str(),
                                version,
                            ),
                            (),
                        )
                        .map_err(|e| be(&e))?;
                    derived_rev
                        .insert(
                            (
                                tenant.as_str(),
                                id.as_str(),
                                version,
                                source.id.as_str(),
                                source.version,
                            ),
                            (),
                        )
                        .map_err(|e| be(&e))?;
                }
                drop(derived_rev);

                // Sliding retention starts at the write, not at the first
                // touch. Initialized lazily, an item with a window and no
                // fixed expiry was *immortal* until somebody touched it —
                // opt-in garbage that never collects. The write is itself an
                // access, so the window opens here and each journaled touch
                // slides it; a version written without the window drops the
                // row, because retention is a property of what is currently
                // believed.
                drop(derived);
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
                match item.access_retention_seconds {
                    Some(window) => {
                        let expiry =
                            created.saturating_add(i64::try_from(window).unwrap_or(i64::MAX));
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
                    None => {
                        access
                            .remove((tenant.as_str(), id.as_str()))
                            .map_err(|e| be(&e))?;
                    }
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

            // The selection rule, stated once for every backend: most trusted
            // first, then newest, then id — **globally across purposes** when
            // no purpose narrows the range. The index is keyed with the purpose
            // *before* the timestamp (that ordering is what makes a purposeful
            // recall a contiguous range), so a purpose-less scan arrives
            // purpose-lexicographic and has to be re-sorted here; truncating
            // the raw scan order would let whichever purpose sorts first evict
            // newer, equally trusted memories from every other purpose.
            //
            // Trust still leads recency because recall truncates, and
            // truncating by recency alone is an eviction an attacker steers:
            // anything able to write an untrusted memory writes `limit` of
            // them and the trusted ones silently lose. Only the index keys are
            // collected and sorted — item rows are read after the cut, at most
            // until `limit` survivors are found — so the memory cost is one
            // key per current item in the subject, not one item.
            let mut keys: Vec<(u8, i64, String, u64)> = Vec::new();
            for entry in by_subject.range(from..=to).map_err(|e| be(&e))? {
                let (k, v) = entry.map_err(|e| be(&e))?;
                let (version, rank) = v.value();
                let (_, _, _, neg_created, id) = k.value();
                keys.push((rank, neg_created, id.to_owned(), version));
            }
            // `neg_created` is the negated timestamp, so ascending order here
            // is newest-first — the same trick the index itself plays.
            keys.sort_unstable_by(|a, b| {
                (a.0, a.1, a.2.as_str()).cmp(&(b.0, b.1, b.2.as_str()))
            });

            let mut out: Vec<MemoryItem> = Vec::new();
            for (_, _, id, version) in keys {
                if out.len() >= limit {
                    break;
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
                    .as_ref()
                    .and_then(|table| table.get((tenant.as_str(), id.as_str())).ok().flatten())
                    .and_then(|value| {
                        crate::core::Timestamp::from_unix_timestamp(value.value()).ok()
                    });
                // `expires_at` is a hard ceiling: sliding access retention may
                // shorten a life below it, never extend one past it — so the
                // effective expiry is the *earlier* of the two, not the later.
                let effective = match (item.expires_at, access_expiry) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (left, right) => left.or(right),
                };
                if as_of.is_some_and(|at| effective.is_some_and(|expires| expires <= at)) {
                    continue;
                }
                out.push(item);
            }
            Ok(out)
        })
        .await
    }

    async fn subject_ids(&self, subject: &str) -> Result<Vec<String>, StoreError> {
        let tenant = self.tenant_name();
        let subject = subject.to_owned();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let Ok(by_subject) = r.open_table(BY_SUBJECT) else {
                return Ok(Vec::new());
            };
            // The whole subject range, unconditionally: this is the erasure
            // path's enumeration, and a page size here would be a page size on
            // how much of a subject an erasure reaches.
            let mut ids = std::collections::BTreeSet::new();
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
                let (key, _) = entry.map_err(|e| be(&e))?;
                ids.insert(key.value().4.to_owned());
            }
            Ok(ids.into_iter().collect())
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
            let mut seen = std::collections::BTreeSet::new();
            for e in edges
                .range(
                    (tenant.as_str(), source.as_str(), 0, "", 0)
                        ..=(tenant.as_str(), source.as_str(), u64::MAX, MAX_STR, u64::MAX),
                )
                .map_err(|e| be(&e))?
            {
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, _, _, derived_id, derived_version) = k.value();

                // Through `current`, so a derivative that has since been
                // forgotten is absent rather than a dangling edge every caller
                // has to filter — and so a repair reads what is believed now
                // rather than a version nobody would act on. Edges are
                // per-version, so only the edge written by the *current*
                // version counts here: a summary re-derived from other sources
                // is no longer a live derivative of this one, even though its
                // superseded versions keep their lineage for erasure.
                let Some(v) = current
                    .get((tenant.as_str(), derived_id))
                    .map_err(|e| be(&e))?
                else {
                    continue;
                };
                let version = v.value().3;
                if version != derived_version || !seen.insert(derived_id.to_owned()) {
                    continue;
                }
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
                let mut edges_rev = w.open_table(DERIVED_BY_TARGET).map_err(|e| be(&e))?;
                let mut forgotten = w.open_table(FORGOTTEN).map_err(|e| be(&e))?;

                // redb admits one writer, so the graph cannot grow between
                // this traversal and the deletions below.
                //
                // The traversal is **version-granular**. Edges are kept per
                // derivative version, and a doomed source propagates to
                // exactly the derivative versions that read it:
                //
                //   * a derivative whose *current* version absorbed a doomed
                //     node is doomed as a whole id — its content is believed
                //     now, so the id, every version, and everything derived
                //     onward all go;
                //   * a derivative whose only absorbing versions are
                //     **superseded** loses those versions and keeps its
                //     current one — a summary honestly re-derived from clean
                //     sources is not destroyed by its own history, but the
                //     history that named the doomed source stops being
                //     readable through `version()`.
                //
                // Every edge target is enqueued, **including tombstoned
                // ones**: `forget` deliberately keeps a forgotten memory's
                // edges so a later cascade from further upstream can route
                // through the tombstone. A tombstoned node has nothing to
                // remove, but its descendants do.
                let mut id_queue = vec![root];
                let mut version_queue: Vec<(String, u64)> = Vec::new();
                let mut doomed = std::collections::BTreeSet::new();
                let mut doomed_versions: std::collections::BTreeSet<(String, u64)> =
                    std::collections::BTreeSet::new();
                loop {
                    if let Some(source) = id_queue.pop() {
                        if !doomed.insert(source.clone()) {
                            continue;
                        }
                        // Every outgoing edge, from every version of a fully
                        // doomed id.
                        for entry in edges
                            .range(
                                (tenant.as_str(), source.as_str(), 0, "", 0)
                                    ..=(
                                        tenant.as_str(),
                                        source.as_str(),
                                        u64::MAX,
                                        MAX_STR,
                                        u64::MAX,
                                    ),
                            )
                            .map_err(|e| be(&e))?
                        {
                            let (key, _) = entry.map_err(|e| be(&e))?;
                            let (_, _, _, derived_id, derived_version) = key.value();
                            version_queue.push((derived_id.to_owned(), derived_version));
                        }
                    } else if let Some((derived_id, derived_version)) = version_queue.pop() {
                        if doomed.contains(&derived_id) {
                            continue;
                        }
                        let current_version = current
                            .get((tenant.as_str(), derived_id.as_str()))
                            .map_err(|e| be(&e))?
                            .map(|value| value.value().3);
                        if current_version == Some(derived_version) {
                            id_queue.push(derived_id);
                        } else {
                            if !doomed_versions
                                .insert((derived_id.clone(), derived_version))
                            {
                                continue;
                            }
                            // Only this version's own onward lineage: what a
                            // superseded summary was itself read into.
                            for entry in edges
                                .range(
                                    (
                                        tenant.as_str(),
                                        derived_id.as_str(),
                                        derived_version,
                                        "",
                                        0,
                                    )
                                        ..=(
                                            tenant.as_str(),
                                            derived_id.as_str(),
                                            derived_version,
                                            MAX_STR,
                                            u64::MAX,
                                        ),
                                )
                                .map_err(|e| be(&e))?
                            {
                                let (key, _) = entry.map_err(|e| be(&e))?;
                                let (_, _, _, next_id, next_version) = key.value();
                                version_queue.push((next_id.to_owned(), next_version));
                            }
                        }
                    } else {
                        break;
                    }
                }

                let holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
                // A hold blocks every erasure path, version-level included: an
                // id under hold must not lose even a superseded version.
                let held_candidates = doomed
                    .iter()
                    .cloned()
                    .chain(doomed_versions.iter().map(|(id, _)| id.clone()));
                for memory_id in held_candidates {
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

                // Counted per node that actually held state, so a tombstoned
                // intermediate the traversal passed through is not reported as
                // an erasure it did not perform.
                let mut erased = 0usize;
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
                    if previous.is_some() || !versions.is_empty() {
                        erased += 1;
                    }
                    for version in versions {
                        items
                            .remove((tenant.as_str(), memory_id.as_str(), version))
                            .map_err(|e| be(&e))?;
                    }
                }

                // Superseded versions that absorbed a doomed source, on ids
                // that stay alive. Only the version row goes: the id keeps its
                // current entry, its index row, its access window and — no
                // tombstone — its future.
                let mut partly: std::collections::BTreeSet<&str> =
                    std::collections::BTreeSet::new();
                for (memory_id, version) in &doomed_versions {
                    if doomed.contains(memory_id) {
                        continue;
                    }
                    if items
                        .remove((tenant.as_str(), memory_id.as_str(), *version))
                        .map_err(|e| be(&e))?
                        .is_some()
                    {
                        partly.insert(memory_id.as_str());
                    }
                }
                erased += partly.len();

                // Cascading erasure no longer needs repair lineage for any
                // vertex — id or version — it removed. Delete the edges
                // touching them in both directions, through the indexes rather
                // than a tenant-wide scan.
                let mut stale: Vec<(String, u64, String, u64)> = Vec::new();
                for memory_id in &doomed {
                    collect_edges_of_id(&edges, &edges_rev, &tenant, memory_id, &mut stale)?;
                }
                for (memory_id, version) in &doomed_versions {
                    if doomed.contains(memory_id) {
                        continue;
                    }
                    collect_edges_of_version(
                        &edges, &edges_rev, &tenant, memory_id, *version, &mut stale,
                    )?;
                }
                for (source_id, source_version, derived_id, derived_version) in stale {
                    edges
                        .remove((
                            tenant.as_str(),
                            source_id.as_str(),
                            source_version,
                            derived_id.as_str(),
                            derived_version,
                        ))
                        .map_err(|e| be(&e))?;
                    edges_rev
                        .remove((
                            tenant.as_str(),
                            derived_id.as_str(),
                            derived_version,
                            source_id.as_str(),
                            source_version,
                        ))
                        .map_err(|e| be(&e))?;
                }
                erased
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
                // The sliding-retention row goes with the memory it describes.
                // Left behind, it is residue about an erased id — and worse, a
                // future write under a recycled id would inherit a window it
                // never asked for. Every erasure path removes it; this one
                // used to leave it to `forget_cascading` alone.
                w.open_table(ACCESS_EXPIRY)
                    .map_err(|e| be(&e))?
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
                //
                // Edges deliberately stay — **both directions**. Outgoing,
                // because a correction may later become an erasure request and
                // losing them would make this memory's derived summaries
                // undiscoverable. Incoming, because a cascade from further
                // *upstream* routes through this tombstone to reach those same
                // summaries: A → B → C with B forgotten here must still let a
                // later cascade from poisoned A find C, and deleting A → B
                // severed exactly that path. The read path is what keeps a kept
                // edge harmless — `derivatives` skips targets with no current
                // entry — and the tombstone prevents id reuse from attaching
                // this lineage to unrelated future content.
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
                let mut edges_rev = w.open_table(DERIVED_BY_TARGET).map_err(|e| be(&e))?;
                let mut forgotten = w.open_table(FORGOTTEN).map_err(|e| be(&e))?;
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
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
                    // Sliding-retention residue goes with the memory — see
                    // `forget` for why every erasure path removes this row.
                    access
                        .remove((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                    // Incoming edges only, and through the reverse index
                    // rather than a tenant-wide scan: a derivative must stay
                    // in its source's subject, so every source of this id is
                    // in this same erasure and the edge is intra-subject
                    // cleanup, not lineage a later cascade could still need.
                    let incoming: Vec<(String, u64, u64)> = edges_rev
                        .range(
                            (tenant.as_str(), id.as_str(), 0, "", 0)
                                ..=(tenant.as_str(), id.as_str(), u64::MAX, MAX_STR, u64::MAX),
                        )
                        .map_err(|e| be(&e))?
                        .map(|entry| {
                            entry
                                .map(|(key, _)| {
                                    let (_, _, derived_version, source_id, source_version) =
                                        key.value();
                                    (source_id.to_owned(), source_version, derived_version)
                                })
                                .map_err(|error| be(&error))
                        })
                        .collect::<Result<_, StoreError>>()?;
                    for (source_id, source_version, derived_version) in incoming {
                        edges
                            .remove((
                                tenant.as_str(),
                                source_id.as_str(),
                                source_version,
                                id.as_str(),
                                derived_version,
                            ))
                            .map_err(|e| be(&e))?;
                        edges_rev
                            .remove((
                                tenant.as_str(),
                                id.as_str(),
                                derived_version,
                                source_id.as_str(),
                                source_version,
                            ))
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
                let holds = w.open_table(HOLDS).map_err(|e| be(&e))?;
                let mut access = w.open_table(ACCESS_EXPIRY).map_err(|e| be(&e))?;
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
                    // The recall rule, applied to erasure: the ceiling wins,
                    // so a touched-up window never carries an item past its
                    // immutable `expires_at`.
                    let effective = match (item.expires_at, access_expiry) {
                        (Some(left), Some(right)) => Some(left.min(right)),
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
                    // The window row that (possibly) triggered this erasure is
                    // itself removed: an expired id must not keep sliding-
                    // retention residue, exactly as the other erasure paths.
                    access
                        .remove((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?;
                    // Edges deliberately stay — both directions, exactly as
                    // `forget` keeps them. An expired memory becomes a
                    // tombstone, not a hole in the graph: with U → E → D and E
                    // expired here, a later `forget_cascading(U)` must still
                    // route *through* E to reach D, and this sweep once
                    // deleted E's incoming edges — severing exactly that path,
                    // so the poisoned source's summary-of-a-summary outlived
                    // the erasure. The read path keeps a kept edge harmless
                    // (`derivatives` joins on a current item), and the
                    // tombstone prevents id reuse from attaching this lineage
                    // to unrelated future content.
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
