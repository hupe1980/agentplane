//! Case storage on redb.
//!
//! Two constraints carry the correctness here, and on redb both are the *shape*
//! of a key rather than a declaration a migration could drop:
//!
//! * [`CORR_OPEN`] is keyed by `(namespace, value)` and holds only open cases.
//!   "One open case per business key" is therefore inexpressible to violate —
//!   which is what stops two concurrent inbound messages fragmenting a process
//!   across two cases, with its obligations tracked in neither.
//! * [`DEADLINES_DUE`] is keyed by the instant an obligation first needs
//!   attention, so the sweep is a range scan rather than a table scan that
//!   quietly stops finishing on time at a hundred thousand open obligations.
//!
//! Secondary indexes are written in the **same** transaction as the row they
//! describe. redb is atomic across tables, so an index cannot be left
//! describing a row that was never committed.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde_json::Value;

use crate::case::{CaseCensus, CaseStore, Correlation};
use crate::core::{
    Case, CaseId, CaseStatus, CaseVersion, CorrelationKey, Deadline, DeadlineState, Digest, RunId,
    StoreError, Timestamp,
};

use super::redb::{MAX_STR, RedbStore, be, begin_write};

/// `case_id -> (kind, status, state, version, opened_at)`.
const CASES: TableDefinition<&str, (&str, &str, &str, u64, i64)> = TableDefinition::new("cases");

/// `(namespace, value) -> case_id`, open cases only. One open case per key.
const CORR_OPEN: TableDefinition<(&str, &str), &str> = TableDefinition::new("case_corr_open");

/// `(case_id, namespace, value) -> ()`, every key a case ever claimed.
const CORR_ALL: TableDefinition<(&str, &str, &str), ()> = TableDefinition::new("case_corr_all");

/// `(case_id, written_at, digest) -> ()`, the blobs a case produced.
///
/// Keyed by time so erasure walks a case's artifacts in the order they were
/// created, and so the key is unique even when one case stores identical bytes
/// at two different moments — the digest alone would collide, which is correct
/// for storage and wrong for an index that has to enumerate.
const CASE_BLOBS: TableDefinition<(&str, i64, &[u8]), ()> = TableDefinition::new("case_blobs");

/// `(case_id, seq) -> run_id`, in attachment order.
const CASE_RUNS: TableDefinition<(&str, u64), &str> = TableDefinition::new("case_runs");

/// `(case_id, run_id) -> seq`, so attaching twice is idempotent.
const CASE_RUN_SEEN: TableDefinition<(&str, &str), u64> = TableDefinition::new("case_run_seen");

/// `(case_id, name) -> (resolved_at, calendar_digest, warn_at, has_warn, state)`.
/// `(resolved_at, calendar_digest, warn_at, has_warn, state)`.
type DeadlineRow<'a> = (i64, &'a [u8], i64, u8, &'a str);

const DEADLINES: TableDefinition<(&str, &str), DeadlineRow<'static>> =
    TableDefinition::new("case_deadlines");

/// `(trigger_at, case_id, name) -> resolved_at`, pending and warned only.
///
/// Keyed by `min(resolved_at, warn_at)` — the moment the obligation first needs
/// looking at. Keying on `resolved_at` alone would hide a deadline whose warning
/// has passed but whose due date has not, which is exactly the one a warning
/// exists to surface early.
const DEADLINES_DUE: TableDefinition<(i64, &str, &str), i64> =
    TableDefinition::new("case_deadlines_due");

/// `(opened_at, case_id) -> ()`, cases that are not closed.
///
/// Carries the census: the count is the table's length and the oldest is its
/// first entry, so the two cannot disagree about which cases were open.
const CASES_OPEN: TableDefinition<(i64, &str), ()> = TableDefinition::new("cases_open");

/// `(status, -opened_at, case_id) -> ()`. The negated stamp puts newest first
/// under redb's ascending iteration, which is the order the worklist wants.
const CASES_BY_STATUS: TableDefinition<(&str, i64, &str), ()> =
    TableDefinition::new("cases_by_status");

fn ts(t: Timestamp) -> i64 {
    t.unix_timestamp()
}

fn from_ts(v: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_unix_timestamp(v).map_err(|e| StoreError::Corrupt {
        seq: 0,
        detail: format!("unrepresentable timestamp {v}: {e}"),
    })
}

fn status_from(s: &str) -> Result<CaseStatus, StoreError> {
    Ok(match s {
        "open" => CaseStatus::Open,
        "awaiting_external" => CaseStatus::AwaitingExternal,
        "awaiting_human" => CaseStatus::AwaitingHuman,
        "escalated" => CaseStatus::Escalated,
        "closed" => CaseStatus::Closed,
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown case status '{other}'"),
            });
        }
    })
}

fn deadline_state_from(s: &str) -> Result<DeadlineState, StoreError> {
    Ok(match s {
        "pending" => DeadlineState::Pending,
        "warned" => DeadlineState::Warned,
        "breached" => DeadlineState::Breached,
        "met" => DeadlineState::Met,
        "cancelled" => DeadlineState::Cancelled,
        other => {
            return Err(StoreError::Corrupt {
                seq: 0,
                detail: format!("unknown deadline state '{other}'"),
            });
        }
    })
}

/// Whether an obligation is still outstanding, and therefore indexed for the
/// sweep and blocking closure.
fn is_outstanding(state: &str) -> bool {
    matches!(state, "pending" | "warned")
}

/// When an obligation first needs attention.
fn trigger_at(resolved_at: i64, warn_at: Option<i64>) -> i64 {
    warn_at.map_or(resolved_at, |w| w.min(resolved_at))
}

fn parse_case_id(id: &str) -> Result<CaseId, StoreError> {
    CaseId::parse(id).map_err(|e| StoreError::Corrupt {
        seq: 0,
        detail: format!("bad case id '{id}': {e}"),
    })
}

fn build_deadline(case: &str, name: &str, row: DeadlineRow<'_>) -> Result<Deadline, StoreError> {
    let (resolved_at, digest, warn_at, has_warn, state) = row;
    let bytes: [u8; 32] = digest.try_into().map_err(|_| StoreError::Corrupt {
        seq: 0,
        detail: "stored calendar digest is not 32 bytes".into(),
    })?;
    Ok(Deadline {
        case: parse_case_id(case)?,
        name: name.to_owned(),
        resolved_at: from_ts(resolved_at)?,
        calendar_digest: Digest::from_bytes(bytes),
        warn_at: if has_warn == 1 {
            Some(from_ts(warn_at)?)
        } else {
            None
        },
        state: deadline_state_from(state)?,
    })
}

/// Create every case table, so a read on a fresh database is a miss rather than
/// a missing-table error.
///
/// redb creates a table on first *write*, so `case()` reading `CASE_RUNS` for a
/// case with no runs yet would otherwise fail rather than return an empty list.
pub(super) fn create_tables(w: &redb::WriteTransaction) -> Result<(), StoreError> {
    w.open_table(CASES).map_err(|e| be(&e))?;
    w.open_table(CORR_OPEN).map_err(|e| be(&e))?;
    w.open_table(CORR_ALL).map_err(|e| be(&e))?;
    w.open_table(CASE_RUNS).map_err(|e| be(&e))?;
    w.open_table(CASE_BLOBS).map_err(|e| be(&e))?;
    w.open_table(CASE_RUN_SEEN).map_err(|e| be(&e))?;
    w.open_table(DEADLINES).map_err(|e| be(&e))?;
    w.open_table(DEADLINES_DUE).map_err(|e| be(&e))?;
    w.open_table(CASES_OPEN).map_err(|e| be(&e))?;
    w.open_table(CASES_BY_STATUS).map_err(|e| be(&e))?;
    Ok(())
}

#[async_trait]
impl CaseStore for RedbStore {
    async fn correlate(&self, keys: &[CorrelationKey]) -> Result<Option<CaseId>, StoreError> {
        if keys.is_empty() {
            return Ok(None);
        }
        let keys = keys.to_vec();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(CORR_OPEN).map_err(|e| be(&e))?;
            for k in &keys {
                if let Some(v) = t
                    .get((k.namespace.as_str(), k.value.as_str()))
                    .map_err(|e| be(&e))?
                {
                    return parse_case_id(v.value()).map(Some);
                }
            }
            Ok(None)
        })
        .await
    }

    async fn correlate_or_open(
        &self,
        kind: &str,
        keys: &[CorrelationKey],
        at: Timestamp,
    ) -> Result<Correlation, StoreError> {
        let kind = kind.to_owned();
        let keys = keys.to_vec();
        let id = CaseId::generate();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            // Computed inside a scope so every table borrow is released before
            // the commit below; redb takes the transaction by value.
            let outcome = {
                let mut corr_open = w.open_table(CORR_OPEN).map_err(|e| be(&e))?;

                // Looked up inside the write transaction, so a concurrent
                // opener cannot slip between the check and the insert.
                let mut attached = None;
                for k in &keys {
                    if let Some(v) = corr_open
                        .get((k.namespace.as_str(), k.value.as_str()))
                        .map_err(|e| be(&e))?
                    {
                        attached = Some(parse_case_id(v.value())?);
                        break;
                    }
                }

                if let Some(found) = attached {
                    Correlation::Attached(found)
                } else {
                    let case = id.to_string();
                    w.open_table(CASES)
                        .map_err(|e| be(&e))?
                        .insert(
                            case.as_str(),
                            (
                                kind.as_str(),
                                CaseStatus::Open.as_str(),
                                "null",
                                0u64,
                                ts(at),
                            ),
                        )
                        .map_err(|e| be(&e))?;

                    let mut corr_all = w.open_table(CORR_ALL).map_err(|e| be(&e))?;
                    for k in &keys {
                        // The key *is* the constraint: a prior value means
                        // someone claimed it between our read and our write.
                        let prior = corr_open
                            .insert((k.namespace.as_str(), k.value.as_str()), case.as_str())
                            .map_err(|e| be(&e))?;
                        if prior.is_some() {
                            return Err(StoreError::Backend(format!(
                                "correlation key {k} was claimed concurrently — retry"
                            )));
                        }
                        corr_all
                            .insert((case.as_str(), k.namespace.as_str(), k.value.as_str()), ())
                            .map_err(|e| be(&e))?;
                    }

                    w.open_table(CASES_OPEN)
                        .map_err(|e| be(&e))?
                        .insert((ts(at), case.as_str()), ())
                        .map_err(|e| be(&e))?;
                    w.open_table(CASES_BY_STATUS)
                        .map_err(|e| be(&e))?
                        .insert((CaseStatus::Open.as_str(), -ts(at), case.as_str()), ())
                        .map_err(|e| be(&e))?;

                    Correlation::Opened(id)
                }
            };
            w.commit().map_err(|e| be(&e))?;
            Ok(outcome)
        })
        .await
    }

    async fn case(&self, id: CaseId) -> Result<Option<Case>, StoreError> {
        let key = id.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let cases = r.open_table(CASES).map_err(|e| be(&e))?;
            let Some(row) = cases.get(key.as_str()).map_err(|e| be(&e))? else {
                return Ok(None);
            };
            let (kind, status, state, version, opened) = row.value();
            let (kind, status, state) = (kind.to_owned(), status.to_owned(), state.to_owned());
            drop(row);

            let corr = r.open_table(CORR_ALL).map_err(|e| be(&e))?;
            let mut correlation = Vec::new();
            for e in corr
                .range((key.as_str(), "", "")..=(key.as_str(), MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, ns, v) = k.value();
                correlation.push(CorrelationKey::new(ns.to_owned(), v.to_owned()));
            }

            let runs_t = r.open_table(CASE_RUNS).map_err(|e| be(&e))?;
            let mut runs = Vec::new();
            for e in runs_t
                .range((key.as_str(), 0u64)..=(key.as_str(), u64::MAX))
                .map_err(|e| be(&e))?
            {
                let (_, v) = e.map_err(|e| be(&e))?;
                let s = v.value();
                runs.push(RunId::parse(s).map_err(|e| StoreError::Corrupt {
                    seq: 0,
                    detail: format!("bad run id '{s}': {e}"),
                })?);
            }

            Ok(Some(Case {
                id,
                kind,
                status: status_from(&status)?,
                correlation,
                state: serde_json::from_str(&state).unwrap_or(Value::Null),
                version: CaseVersion(version),
                opened_at: from_ts(opened)?,
                runs,
            }))
        })
        .await
    }

    async fn attach_run(&self, case: CaseId, run: RunId) -> Result<(), StoreError> {
        let (c, r) = (case.to_string(), run.to_string());
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut seen = w.open_table(CASE_RUN_SEEN).map_err(|e| be(&e))?;
                if seen
                    .get((c.as_str(), r.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    let mut runs = w.open_table(CASE_RUNS).map_err(|e| be(&e))?;
                    let next = runs
                        .range((c.as_str(), 0u64)..=(c.as_str(), u64::MAX))
                        .map_err(|e| be(&e))?
                        .next_back()
                        .transpose()
                        .map_err(|e| be(&e))?
                        .map_or(1, |(k, _)| k.value().1 + 1);
                    runs.insert((c.as_str(), next), r.as_str())
                        .map_err(|e| be(&e))?;
                    seen.insert((c.as_str(), r.as_str()), next)
                        .map_err(|e| be(&e))?;
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn link_blob(
        &self,
        case: CaseId,
        digest: Digest,
        at: Timestamp,
    ) -> Result<(), StoreError> {
        let key = case.to_string();
        let bytes = digest.as_bytes().to_vec();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                w.open_table(CASE_BLOBS)
                    .map_err(|e| be(&e))?
                    .insert((key.as_str(), ts(at), bytes.as_slice()), ())
                    .map_err(|e| be(&e))?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn blobs_of(&self, case: CaseId) -> Result<Vec<Digest>, StoreError> {
        let key = case.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let t = r.open_table(CASE_BLOBS).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            for e in t
                .range(
                    (key.as_str(), i64::MIN, [].as_slice())
                        ..=(key.as_str(), i64::MAX, [0xffu8; 32].as_slice()),
                )
                .map_err(|e| be(&e))?
            {
                let (k, _) = e.map_err(|e| be(&e))?;
                let raw: [u8; 32] = k.value().2.try_into().map_err(|_| StoreError::Corrupt {
                    seq: 0,
                    detail: "a linked blob digest is not 32 bytes".into(),
                })?;
                // The same bytes stored twice are one artifact; erasing it twice
                // would report a second expiry that never happened.
                if seen.insert(raw) {
                    out.push(Digest::from_bytes(raw));
                }
            }
            Ok(out)
        })
        .await
    }

    async fn put_state(
        &self,
        case: CaseId,
        expected: CaseVersion,
        state: Value,
    ) -> Result<CaseVersion, StoreError> {
        let key = case.to_string();
        let encoded = serde_json::to_string(&state)?;
        let next = expected.next();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            let result = {
                let mut cases = w.open_table(CASES).map_err(|e| be(&e))?;
                let current = cases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                    let (k, s, st, ver, at) = v.value();
                    (k.to_owned(), s.to_owned(), st.to_owned(), ver, at)
                });
                match current {
                    // Read and write inside one transaction, so the check and
                    // the write cannot be separated by another writer — the
                    // predicate the SQL backend put on the UPDATE.
                    Some((kind, status, _, ver, at)) if ver == expected.0 => {
                        cases
                            .insert(
                                key.as_str(),
                                (kind.as_str(), status.as_str(), encoded.as_str(), next.0, at),
                            )
                            .map_err(|e| be(&e))?;
                        Ok(next)
                    }
                    // The caller needs to know which: a missing case reported as
                    // a conflict sends them into a re-read loop against nothing.
                    Some((_, _, _, current, _)) => Err(StoreError::CaseConflict {
                        case: key.clone(),
                        expected: expected.0,
                        current,
                    }),
                    None => Err(StoreError::NotFound(key.clone())),
                }
            };
            let out = result?;
            w.commit().map_err(|e| be(&e))?;
            Ok(out)
        })
        .await
    }

    async fn set_status(&self, case: CaseId, status: CaseStatus) -> Result<(), StoreError> {
        let key = case.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut cases = w.open_table(CASES).map_err(|e| be(&e))?;
                let Some(row) = cases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                    let (k, s, st, ver, at) = v.value();
                    (k.to_owned(), s.to_owned(), st.to_owned(), ver, at)
                }) else {
                    return Err(StoreError::NotFound(key));
                };
                let (kind, was, state, ver, at) = row;
                cases
                    .insert(
                        key.as_str(),
                        (kind.as_str(), status.as_str(), state.as_str(), ver, at),
                    )
                    .map_err(|e| be(&e))?;
                reindex_status(&w, &key, &was, status.as_str(), at)?;
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn close(&self, case: CaseId) -> Result<(), StoreError> {
        let key = case.to_string();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                // A case with an unmet obligation may not be closed — the check
                // that stops a missed regulatory window disappearing behind a
                // tidy "closed" status.
                let outstanding = {
                    let d = w.open_table(DEADLINES).map_err(|e| be(&e))?;
                    let mut n = 0usize;
                    for e in d
                        .range((key.as_str(), "")..=(key.as_str(), MAX_STR))
                        .map_err(|e| be(&e))?
                    {
                        let (_, v) = e.map_err(|e| be(&e))?;
                        if is_outstanding(v.value().4) {
                            n += 1;
                        }
                    }
                    n
                };
                if outstanding > 0 {
                    return Err(StoreError::Backend(format!(
                        "case {case} has {outstanding} open deadline(s); \
                         resolve or cancel them before closing"
                    )));
                }

                let mut cases = w.open_table(CASES).map_err(|e| be(&e))?;
                let Some(row) = cases.get(key.as_str()).map_err(|e| be(&e))?.map(|v| {
                    let (k, s, st, ver, at) = v.value();
                    (k.to_owned(), s.to_owned(), st.to_owned(), ver, at)
                }) else {
                    return Err(StoreError::NotFound(key));
                };
                let (kind, was, state, ver, at) = row;
                cases
                    .insert(
                        key.as_str(),
                        (kind.as_str(), "closed", state.as_str(), ver, at),
                    )
                    .map_err(|e| be(&e))?;
                reindex_status(&w, &key, &was, "closed", at)?;

                // Release the correlation keys so a genuinely new matter about
                // the same entity opens a fresh case rather than reanimating
                // this one.
                let corr_all = w.open_table(CORR_ALL).map_err(|e| be(&e))?;
                let mut owned: Vec<(String, String)> = Vec::new();
                for e in corr_all
                    .range((key.as_str(), "", "")..=(key.as_str(), MAX_STR, MAX_STR))
                    .map_err(|e| be(&e))?
                {
                    let (k, _) = e.map_err(|e| be(&e))?;
                    let (_, ns, v) = k.value();
                    owned.push((ns.to_owned(), v.to_owned()));
                }
                drop(corr_all);
                let mut corr_open = w.open_table(CORR_OPEN).map_err(|e| be(&e))?;
                for (ns, v) in owned {
                    // Only if still ours: a key released and re-claimed by a new
                    // case must not be removed out from under that case.
                    let mine = corr_open
                        .get((ns.as_str(), v.as_str()))
                        .map_err(|e| be(&e))?
                        .is_some_and(|got| got.value() == key);
                    if mine {
                        corr_open
                            .remove((ns.as_str(), v.as_str()))
                            .map_err(|e| be(&e))?;
                    }
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn register_deadline(&self, deadline: &Deadline) -> Result<(), StoreError> {
        let (case, name) = (deadline.case.to_string(), deadline.name.clone());
        let resolved = ts(deadline.resolved_at);
        let warn = deadline.warn_at.map(ts);
        let digest = deadline.calendar_digest.as_bytes().to_vec();
        let state = deadline.state.as_str();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut d = w.open_table(DEADLINES).map_err(|e| be(&e))?;
                // First registration wins, as `ON CONFLICT DO NOTHING` did.
                if d.get((case.as_str(), name.as_str()))
                    .map_err(|e| be(&e))?
                    .is_none()
                {
                    d.insert(
                        (case.as_str(), name.as_str()),
                        (
                            resolved,
                            digest.as_slice(),
                            warn.unwrap_or(0),
                            u8::from(warn.is_some()),
                            state,
                        ),
                    )
                    .map_err(|e| be(&e))?;
                    if is_outstanding(state) {
                        w.open_table(DEADLINES_DUE)
                            .map_err(|e| be(&e))?
                            .insert(
                                (trigger_at(resolved, warn), case.as_str(), name.as_str()),
                                resolved,
                            )
                            .map_err(|e| be(&e))?;
                    }
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn deadlines(&self, case: CaseId) -> Result<Vec<Deadline>, StoreError> {
        let key = case.to_string();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let d = r.open_table(DEADLINES).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            for e in d
                .range((key.as_str(), "")..=(key.as_str(), MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (k, v) = e.map_err(|e| be(&e))?;
                out.push(build_deadline(k.value().0, k.value().1, v.value())?);
            }
            out.sort_by_key(|d| d.resolved_at);
            Ok(out)
        })
        .await
    }

    async fn set_deadline_state(
        &self,
        case: CaseId,
        name: &str,
        state: DeadlineState,
    ) -> Result<(), StoreError> {
        let (key, name) = (case.to_string(), name.to_owned());
        let to = state.as_str();
        self.with_db(move |db| {
            let w = begin_write(db)?;
            {
                let mut d = w.open_table(DEADLINES).map_err(|e| be(&e))?;
                let Some(row) = d
                    .get((key.as_str(), name.as_str()))
                    .map_err(|e| be(&e))?
                    .map(|v| {
                        let (res, dig, warn, has, st) = v.value();
                        (res, dig.to_vec(), warn, has, st.to_owned())
                    })
                else {
                    return Err(StoreError::NotFound(format!("{key}/{name}")));
                };
                let (resolved, digest, warn, has_warn, was) = row;
                d.insert(
                    (key.as_str(), name.as_str()),
                    (resolved, digest.as_slice(), warn, has_warn, to),
                )
                .map_err(|e| be(&e))?;

                // The sweep index tracks outstanding obligations only, and it is
                // updated in the same transaction as the state it reflects.
                let warn_opt = (has_warn == 1).then_some(warn);
                let trigger = trigger_at(resolved, warn_opt);
                let mut due = w.open_table(DEADLINES_DUE).map_err(|e| be(&e))?;
                match (is_outstanding(&was), is_outstanding(to)) {
                    (true, false) => {
                        due.remove((trigger, key.as_str(), name.as_str()))
                            .map_err(|e| be(&e))?;
                    }
                    (false, true) => {
                        due.insert((trigger, key.as_str(), name.as_str()), resolved)
                            .map_err(|e| be(&e))?;
                    }
                    _ => {}
                }
            }
            w.commit().map_err(|e| be(&e))?;
            Ok(())
        })
        .await
    }

    async fn census(&self, now: Timestamp) -> Result<CaseCensus, StoreError> {
        let now_i = ts(now);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let open_t = r.open_table(CASES_OPEN).map_err(|e| be(&e))?;
            // Count and oldest come from one index, so they cannot disagree
            // about which cases were open.
            let open = open_t.len().map_err(|e| be(&e))?;
            let oldest = open_t
                .first()
                .map_err(|e| be(&e))?
                .map(|(k, _)| k.value().0);

            let due_t = r.open_table(DEADLINES_DUE).map_err(|e| be(&e))?;
            let mut due = 0u64;
            for e in due_t
                .range((i64::MIN, "", "")..=(now_i, MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                let (_, resolved) = e.map_err(|e| be(&e))?;
                // The census counts what is *due*, not what has merely warned.
                if resolved.value() <= now_i {
                    due += 1;
                }
            }

            Ok(CaseCensus {
                open,
                oldest_age_secs: oldest.map(|o| {
                    crate::runtime::metrics::age_secs(
                        Timestamp::from_unix_timestamp(o).unwrap_or(now),
                        now,
                    )
                }),
                due,
            })
        })
        .await
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Deadline>, StoreError> {
        let now_i = ts(now);
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            let due_t = r.open_table(DEADLINES_DUE).map_err(|e| be(&e))?;
            let d = r.open_table(DEADLINES).map_err(|e| be(&e))?;
            let mut out = Vec::new();
            // Ascending by trigger instant, so the longest-waiting obligation is
            // taken first when the limit bites.
            for e in due_t
                .range((i64::MIN, "", "")..=(now_i, MAX_STR, MAX_STR))
                .map_err(|e| be(&e))?
            {
                if out.len() >= limit {
                    break;
                }
                let (k, _) = e.map_err(|e| be(&e))?;
                let (_, case, name) = k.value();
                if let Some(row) = d.get((case, name)).map_err(|e| be(&e))? {
                    out.push(build_deadline(case, name, row.value())?);
                }
            }
            out.sort_by_key(|d| d.resolved_at);
            Ok(out)
        })
        .await
    }

    async fn by_status(&self, status: CaseStatus, limit: usize) -> Result<Vec<Case>, StoreError> {
        let s = status.as_str().to_owned();
        let ids = self
            .with_db(move |db| {
                let r = db.begin_read().map_err(|e| be(&e))?;
                let t = r.open_table(CASES_BY_STATUS).map_err(|e| be(&e))?;
                let mut out = Vec::new();
                for e in t
                    .range((s.as_str(), i64::MIN, "")..=(s.as_str(), i64::MAX, MAX_STR))
                    .map_err(|e| be(&e))?
                {
                    if out.len() >= limit {
                        break;
                    }
                    let (k, _) = e.map_err(|e| be(&e))?;
                    out.push(k.value().2.to_owned());
                }
                Ok(out)
            })
            .await?;

        let mut cases = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.case(parse_case_id(&id)?).await? {
                cases.push(c);
            }
        }
        Ok(cases)
    }
}

/// Move a case between the status and open indexes.
///
/// Both are derived from the row being written, and both are updated in that
/// row's transaction — an index that disagreed with its row would make the
/// worklist show work that is not there.
fn reindex_status(
    w: &redb::WriteTransaction,
    case: &str,
    was: &str,
    now: &str,
    opened_at: i64,
) -> Result<(), StoreError> {
    if was == now {
        return Ok(());
    }
    let mut by_status = w.open_table(CASES_BY_STATUS).map_err(|e| be(&e))?;
    by_status
        .remove((was, -opened_at, case))
        .map_err(|e| be(&e))?;
    by_status
        .insert((now, -opened_at, case), ())
        .map_err(|e| be(&e))?;

    let mut open = w.open_table(CASES_OPEN).map_err(|e| be(&e))?;
    match (was == "closed", now == "closed") {
        (false, true) => {
            open.remove((opened_at, case)).map_err(|e| be(&e))?;
        }
        (true, false) => {
            open.insert((opened_at, case), ()).map_err(|e| be(&e))?;
        }
        _ => {}
    }
    Ok(())
}
