//! Standing-authority accounting on redb.
//!
//! Three tables, and the split between them is the design. The **terms** are
//! written once and never rewritten, so what somebody agreed to cannot move
//! under them. The **balance** is the only row a draw touches, so the hot path
//! is one point read and one point write inside a single transaction. The
//! **receipts** make a retry idempotent by naming the effect key that took each
//! draw, which is the same shape the journal uses for exactly-once and works for
//! the same reason: a `SELECT` before an `INSERT` leaves a window, and the
//! window is the whole guarantee when a ceiling is nearly spent.

use async_trait::async_trait;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::authority::{
    AuthorityError, AuthorityId, AuthorityState, AuthorityStore, Drawn, Revocation,
    StandingAuthority,
};
use crate::core::{EffectKey, Spend, StoreError, Timestamp};

use super::redb::{RedbStore, be, begin_write};

/// `(tenant, authority) -> canonical JSON of the issued terms`.
///
/// Immutable after the first write. Stored as its canonical serialization rather
/// than as columns so that "is this the same declaration" is a byte comparison
/// — a field-by-field check has to be extended every time the type gains a
/// field, and the one time somebody forgets, a differing re-issue silently wins.
const TERMS: TableDefinition<(&str, &str), &str> = TableDefinition::new("authority_terms");

/// `(drawn tokens, drawn minor units, draws taken, revoked, revoked at, reason)`.
///
/// `revoked` is an explicit flag and **not** a sentinel timestamp. The obvious
/// encoding — `revoked_at == 0` means live — collides with a real value: the
/// Unix epoch is a representable instant, so an authority revoked at it read
/// back as standing. That is not a hypothetical; it is what the first version of
/// this table did, and the revocation test caught it. A sentinel that overlaps
/// the domain it guards is a bug waiting for the one caller who uses that value.
type BalanceRow<'a> = (u64, u64, u32, bool, i64, &'a str);

/// `(tenant, authority) -> `[`BalanceRow`].
///
/// Revocation lives here rather than in a second table because it is read on
/// every draw, and a missing-row lookup on the hot path buys nothing over a
/// field that is already present.
const BALANCE: TableDefinition<(&str, &str), BalanceRow<'static>> =
    TableDefinition::new("authority_balance");

/// `(drawn tokens, drawn minor units, remaining tokens, remaining minor units,
/// the draw ordinal this receipt was)`.
type ReceiptRow = (u64, u64, u64, u64, u32);

/// `(tenant, authority, dispatch key) -> `[`ReceiptRow`].
///
/// The receipt a repeated draw reads back. Keyed by the **dispatch** identifier
/// because that is what identifies *this* draw across attempts: deduplicating on
/// the amount would collapse two legitimate identical charges into one, and
/// deduplicating on the effect key would not deduplicate a retry at all.
const RECEIPTS: TableDefinition<(&str, &str, &str), ReceiptRow> =
    TableDefinition::new("authority_receipts");

#[async_trait]
impl AuthorityStore for RedbStore {
    fn tenant(&self) -> &str {
        crate::journal::JournalStore::tenant(self)
    }

    async fn issue(&self, authority: &StandingAuthority) -> Result<(), AuthorityError> {
        authority.validate()?;
        let tenant = self.tenant_name();
        let id = authority.id.0.clone();
        // Canonical bytes, so a re-issue that only reordered fields is
        // recognised as identical rather than refused as a conflict.
        let terms = String::from_utf8(
            crate::core::canon::to_bytes(authority)
                .map_err(|e| AuthorityError::Unavailable(e.to_string()))?,
        )
        .map_err(|e| AuthorityError::Unavailable(e.to_string()))?;

        let conflict: Result<(), ()> = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let outcome = {
                    let mut table = w.open_table(TERMS).map_err(|e| be(&e))?;
                    // Read to an owned value before writing: the borrow of the
                    // accessor outlives the `match` arm otherwise.
                    let existing = table
                        .get((tenant.as_str(), id.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|v| v.value().to_owned());
                    match existing {
                        // A retried deploy is not an attack: identical terms
                        // succeed and change nothing.
                        Some(existing) if existing == terms => Ok(()),
                        Some(_) => Err(()),
                        None => {
                            table
                                .insert((tenant.as_str(), id.as_str()), terms.as_str())
                                .map_err(|e| be(&e))?;
                            let mut balance = w.open_table(BALANCE).map_err(|e| be(&e))?;
                            balance
                                .insert(
                                    (tenant.as_str(), id.as_str()),
                                    (0u64, 0u64, 0u32, false, 0i64, ""),
                                )
                                .map_err(|e| be(&e))?;
                            Ok(())
                        }
                    }
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(outcome)
            })
            .await?;

        conflict.map_err(|()| AuthorityError::AlreadyIssued(authority.id.clone()))
    }

    async fn draw(
        &self,
        id: &AuthorityId,
        key: EffectKey,
        amount: Spend,
        at: Timestamp,
    ) -> Result<Drawn, AuthorityError> {
        let tenant = self.tenant_name();
        let name = id.0.clone();
        let key = key.to_hex();
        let now = at.unix_timestamp();

        // The whole decision happens inside one write transaction. redb has a
        // single writer, so this is atomic against every other draw on this
        // store — which is the point: checking the balance in one transaction
        // and spending it in another is a ceiling two callers walk through.
        let outcome: Result<Drawn, AuthorityError> = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let decided = draw_in(&w, &tenant, &name, &key, amount, now);
                // Committed either way: on refusal nothing was written, and
                // aborting would only discard an empty change set.
                w.commit().map_err(|e| be(&e))?;
                Ok(decided)
            })
            .await?;

        outcome
    }

    async fn revoke(
        &self,
        id: &AuthorityId,
        reason: &str,
        at: Timestamp,
    ) -> Result<(), AuthorityError> {
        let tenant = self.tenant_name();
        let name = id.0.clone();
        let reason = reason.to_owned();
        let now = at.unix_timestamp();

        let found: Result<(), ()> = self
            .with_db(move |db| {
                let w = begin_write(db)?;
                let outcome = {
                    let mut balance = w.open_table(BALANCE).map_err(|e| be(&e))?;
                    let row = balance
                        .get((tenant.as_str(), name.as_str()))
                        .map_err(|e| be(&e))?
                        .map(|v| {
                            let (tokens, minor, draws, revoked, _, _) = v.value();
                            (tokens, minor, draws, revoked)
                        });
                    match row {
                        None => Err(()),
                        // Idempotent, and the **first** reason stands: a second
                        // revocation is a retry, and overwriting would lose the
                        // account of why it was withdrawn.
                        Some((_, _, _, true)) => Ok(()),
                        Some((tokens, minor, draws, false)) => {
                            balance
                                .insert(
                                    (tenant.as_str(), name.as_str()),
                                    (tokens, minor, draws, true, now, reason.as_str()),
                                )
                                .map_err(|e| be(&e))?;
                            Ok(())
                        }
                    }
                };
                w.commit().map_err(|e| be(&e))?;
                Ok(outcome)
            })
            .await?;

        found.map_err(|()| AuthorityError::Unknown(id.clone()))
    }

    async fn state(&self, id: &AuthorityId) -> Result<Option<AuthorityState>, StoreError> {
        let tenant = self.tenant_name();
        let name = id.0.clone();
        self.with_db(move |db| {
            let r = db.begin_read().map_err(|e| be(&e))?;
            // Absent tables mean nothing was ever issued, which is a `None`
            // rather than a failure to read.
            let (Ok(terms), Ok(balance)) = (r.open_table(TERMS), r.open_table(BALANCE)) else {
                return Ok(None);
            };
            let Some(raw) = terms
                .get((tenant.as_str(), name.as_str()))
                .map_err(|e| be(&e))?
            else {
                return Ok(None);
            };
            let authority: StandingAuthority = serde_json::from_str(raw.value())
                .map_err(|e| StoreError::Backend(format!("stored authority is unreadable: {e}")))?;
            let (tokens, minor, draws, revoked, revoked_at, reason) = balance
                .get((tenant.as_str(), name.as_str()))
                .map_err(|e| be(&e))?
                .map_or((0, 0, 0, false, 0, String::new()), |v| {
                    let (t, m, d, rv, at, why) = v.value();
                    (t, m, d, rv, at, why.to_owned())
                });
            Ok(Some(AuthorityState {
                authority,
                drawn: Spend {
                    tokens,
                    minor_units: minor,
                },
                draws,
                revoked: revoked.then(|| Revocation {
                    at: Timestamp::from_unix_timestamp(revoked_at).unwrap_or(Timestamp::UNIX_EPOCH),
                    reason,
                }),
            }))
        })
        .await
    }
}

/// The decision, inside the caller's transaction.
///
/// Split out so the ordering of the five refusals is readable in one place. That
/// ordering is deliberate: **revocation and expiry are checked before the
/// balance**, because "you took this back" and "this ran out of time" are
/// answers a caller must not be able to mistake for "ask for less".
fn draw_in(
    w: &redb::WriteTransaction,
    tenant: &str,
    name: &str,
    key: &str,
    amount: Spend,
    now: i64,
) -> Result<Drawn, AuthorityError> {
    let id = || AuthorityId::new(name);

    let mut receipts = w.open_table(RECEIPTS).map_err(|e| be(&e))?;
    // Idempotence first, before any check. A retry of a draw that already landed
    // must return the original receipt even if the authority has since been
    // revoked or exhausted — the draw happened, and reporting it as refused
    // would make a caller compensate something that stands.
    if let Some(prior) = receipts
        .get((tenant, name, key))
        .map_err(|e| be(&e))?
        .map(|v| v.value())
    {
        let (tokens, minor, rem_tokens, rem_minor, draws) = prior;
        return Ok(Drawn {
            authority: id(),
            amount: Spend {
                tokens,
                minor_units: minor,
            },
            remaining: Spend {
                tokens: rem_tokens,
                minor_units: rem_minor,
            },
            draws,
        });
    }

    let terms_table = w.open_table(TERMS).map_err(|e| be(&e))?;
    let Some(raw) = terms_table.get((tenant, name)).map_err(|e| be(&e))? else {
        return Err(AuthorityError::Unknown(id()));
    };
    let authority: StandingAuthority = serde_json::from_str(raw.value())
        .map_err(|e| AuthorityError::Unavailable(format!("stored authority is unreadable: {e}")))?;
    drop(raw);

    let mut balance = w.open_table(BALANCE).map_err(|e| be(&e))?;
    let (drawn_tokens, drawn_minor, draws, revoked, reason) = balance
        .get((tenant, name))
        .map_err(|e| be(&e))?
        .map_or((0, 0, 0, false, String::new()), |v| {
            let (t, m, d, rv, _, why) = v.value();
            (t, m, d, rv, why.to_owned())
        });

    let remaining = crate::authority::permits(
        &authority,
        amount,
        Spend {
            tokens: drawn_tokens,
            minor_units: drawn_minor,
        },
        draws,
        revoked.then_some(reason.as_str()),
        now,
    )?;

    let now_drawn = (
        drawn_tokens.saturating_add(amount.tokens),
        drawn_minor.saturating_add(amount.minor_units),
        draws + 1,
    );
    balance
        .insert(
            (tenant, name),
            (now_drawn.0, now_drawn.1, now_drawn.2, false, 0i64, ""),
        )
        .map_err(|e| be(&e))?;

    let left = Spend {
        tokens: remaining.tokens.saturating_sub(amount.tokens),
        minor_units: remaining.minor_units.saturating_sub(amount.minor_units),
    };
    receipts
        .insert(
            (tenant, name, key),
            (
                amount.tokens,
                amount.minor_units,
                left.tokens,
                left.minor_units,
                now_drawn.2,
            ),
        )
        .map_err(|e| be(&e))?;

    Ok(Drawn {
        authority: id(),
        amount,
        remaining: left,
        draws: now_drawn.2,
    })
}
