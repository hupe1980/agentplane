//! Standing-authority accounting on `PostgreSQL`.
//!
//! This is the backend the guarantee is actually about. On a single node a
//! ceiling can be held up by almost anything, because redb has one writer. The
//! moment two instances draw on the same authority concurrently, only the
//! database can arbitrate — which is why the draw below is **one statement**
//! whose `WHERE` clause carries the whole decision, not a `SELECT` followed by
//! an `UPDATE`.
//!
//! The window between those two is not theoretical. It widens with load, so a
//! ceiling built that way fails hardest exactly when it is doing something —
//! and what it fails *at* is letting two draws through the last of somebody's
//! authorized spend.

use async_trait::async_trait;

use crate::authority::{
    AuthorityError, AuthorityId, AuthorityState, AuthorityStore, Drawn, Revocation,
    StandingAuthority,
};
use crate::core::{EffectKey, Spend, StoreError, Timestamp};

use super::postgres::{PostgresStore, amount_of, sql_amount};

/// Terms, balance and receipts, keyed by tenant throughout.
///
/// The tenant leads every primary key here for the same reason it does
/// everywhere else in this schema: a query that forgets it returns nothing
/// rather than another tenant's authority, and an authority id is a customer's
/// reference rather than a globally unique one — two tenants naming a mandate
/// `mandate-1` is ordinary, not a collision.
pub(super) const AUTHORITY_SCHEMA: &str = "
-- What was authorized. Written once and never updated: a ceiling somebody
-- agreed to must not be editable under them, so a change is a new authority and
-- both stay on the record.
CREATE TABLE IF NOT EXISTS authority_terms (
    tenant      TEXT   NOT NULL,
    authority   TEXT   NOT NULL,
    terms       TEXT   NOT NULL,
    PRIMARY KEY (tenant, authority)
);

-- What has been consumed, and whether it still stands.
--
-- `revoked` is a boolean and not a sentinel timestamp. The obvious encoding —
-- revoked_at = 0 means live — collides with a representable instant, and an
-- authority revoked at the Unix epoch then reads back as standing.
CREATE TABLE IF NOT EXISTS authority_balance (
    tenant      TEXT    NOT NULL,
    authority   TEXT    NOT NULL,
    tokens      BIGINT  NOT NULL DEFAULT 0 CHECK (tokens      >= 0),
    minor_units BIGINT  NOT NULL DEFAULT 0 CHECK (minor_units >= 0),
    draws       BIGINT  NOT NULL DEFAULT 0 CHECK (draws       >= 0),
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at  BIGINT  NOT NULL DEFAULT 0,
    reason      TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (tenant, authority),
    FOREIGN KEY (tenant, authority) REFERENCES authority_terms (tenant, authority)
);

-- One row per draw, keyed by the dispatch identifier that took it.
--
-- This is what makes a retry idempotent, and the primary key is the mechanism
-- rather than a check in code: a second insert under the same key cannot
-- happen, so a double-spend is inexpressible instead of guarded against.
CREATE TABLE IF NOT EXISTS authority_receipt (
    tenant        TEXT   NOT NULL,
    authority     TEXT   NOT NULL,
    dispatch      TEXT   NOT NULL,
    tokens        BIGINT NOT NULL CHECK (tokens       >= 0),
    minor_units   BIGINT NOT NULL CHECK (minor_units  >= 0),
    rem_tokens    BIGINT NOT NULL CHECK (rem_tokens   >= 0),
    rem_minor     BIGINT NOT NULL CHECK (rem_minor    >= 0),
    draw_ordinal  BIGINT NOT NULL CHECK (draw_ordinal >= 0),
    PRIMARY KEY (tenant, authority, dispatch)
);
";

fn be(e: &tokio_postgres::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn unavailable(e: &impl std::fmt::Display) -> AuthorityError {
    AuthorityError::Unavailable(e.to_string())
}

#[async_trait]
impl AuthorityStore for PostgresStore {
    async fn issue(&self, authority: &StandingAuthority) -> Result<(), AuthorityError> {
        authority.validate()?;
        let mut client = self.pool_ref().get().await.map_err(|e| unavailable(&e))?;
        let tenant = self.tenant_name();
        let id = authority.id.0.clone();
        let terms = String::from_utf8(
            crate::core::canon::to_bytes(authority).map_err(|e| unavailable(&e))?,
        )
        .map_err(|e| unavailable(&e))?;

        // One transaction, not three autocommit statements. The terms row and
        // the balance row exist as a pair — `draw` reads them with a `JOIN`-
        // shaped pair of queries and treats a missing balance as the store
        // being unavailable — so a crash between the two inserts used to leave
        // an authority that could never be drawn on *and* never re-issued: the
        // terms row made every retry of `issue` read as an identical re-issue
        // that then skipped the balance insert it still needed. Under a
        // transaction, either both rows land or the retry starts from nothing.
        let tx = client
            .transaction()
            .await
            .map_err(|e| unavailable(&be(&e)))?;

        // `DO NOTHING` then read back, rather than `DO UPDATE`: an identical
        // re-issue must succeed and a differing one must be refused, and only
        // reading what is actually stored can tell those apart.
        tx.execute(
            "INSERT INTO authority_terms (tenant, authority, terms)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant, authority) DO NOTHING",
            &[&tenant, &id, &terms],
        )
        .await
        .map_err(|e| unavailable(&be(&e)))?;

        let stored: String = tx
            .query_one(
                "SELECT terms FROM authority_terms WHERE tenant = $1 AND authority = $2",
                &[&tenant, &id],
            )
            .await
            .map_err(|e| unavailable(&be(&e)))?
            .get(0);

        if stored != terms {
            return Err(AuthorityError::AlreadyIssued(authority.id.clone()));
        }

        tx.execute(
            "INSERT INTO authority_balance (tenant, authority)
             VALUES ($1, $2)
             ON CONFLICT (tenant, authority) DO NOTHING",
            &[&tenant, &id],
        )
        .await
        .map_err(|e| unavailable(&be(&e)))?;
        tx.commit().await.map_err(|e| unavailable(&be(&e)))?;
        Ok(())
    }

    async fn draw(
        &self,
        id: &AuthorityId,
        key: EffectKey,
        amount: Spend,
        at: Timestamp,
    ) -> Result<Drawn, AuthorityError> {
        let mut client = self.pool_ref().get().await.map_err(|e| unavailable(&e))?;
        let tenant = self.tenant_name();
        let name = id.0.clone();
        let dispatch = key.to_hex();

        let tx = client
            .transaction()
            .await
            .map_err(|e| unavailable(&be(&e)))?;

        // Idempotence first, before any refusal is evaluated. A retry of a draw
        // that already landed must return the original receipt even if the
        // authority has since been revoked or exhausted: the draw happened, and
        // reporting it refused would make a caller compensate something that
        // stands.
        if let Some(prior) = receipt(&tx, &tenant, &name, &dispatch, id).await? {
            return Ok(prior);
        }

        let Some(terms) = tx
            .query_opt(
                "SELECT terms FROM authority_terms WHERE tenant = $1 AND authority = $2",
                &[&tenant, &name],
            )
            .await
            .map_err(|e| unavailable(&be(&e)))?
        else {
            return Err(AuthorityError::Unknown(id.clone()));
        };
        let authority: StandingAuthority =
            serde_json::from_str(terms.get::<_, &str>(0)).map_err(|e| {
                AuthorityError::Unavailable(format!("stored authority unreadable: {e}"))
            })?;

        // `FOR UPDATE` is the whole concurrency story. It takes the row lock
        // before the balance is read, so a second instance drawing on the same
        // authority blocks here rather than reading a balance that is about to
        // change. Without it, both would see the same remainder and both would
        // pass a check the other had already invalidated.
        let balance = tx
            .query_one(
                "SELECT tokens, minor_units, draws, revoked, reason
                 FROM authority_balance
                 WHERE tenant = $1 AND authority = $2
                 FOR UPDATE",
                &[&tenant, &name],
            )
            .await
            .map_err(|e| unavailable(&be(&e)))?;

        // Checked again now that the row lock is held. The first check ran
        // before the lock, so two carriers of the *same* dispatch key can both
        // pass it; the loser then reaches this point only after the winner
        // committed, and without this re-read it would be refused `Exhausted`
        // for a draw that stands — or trip the receipt table's primary key.
        // The runtime cannot produce that race (fencing keeps one executor per
        // run, and intent is durable before dispatch), but the trait promises
        // idempotence by key without that qualification, and a promise that
        // depends on the caller's discipline is a check in the wrong place.
        if let Some(prior) = receipt(&tx, &tenant, &name, &dispatch, id).await? {
            return Ok(prior);
        }

        let drawn = Spend {
            tokens: amount_of(balance.get(0)),
            minor_units: amount_of(balance.get(1)),
        };
        let taken: i64 = balance.get(2);
        let revoked: bool = balance.get(3);
        let reason: String = balance.get(4);

        let remaining = crate::authority::permits(
            &authority,
            amount,
            drawn,
            u32::try_from(taken).unwrap_or(u32::MAX),
            revoked.then_some(reason.as_str()),
            at.unix_timestamp(),
        )?;

        let ordinal = taken + 1;
        let left = Spend {
            tokens: remaining.tokens.saturating_sub(amount.tokens),
            minor_units: remaining.minor_units.saturating_sub(amount.minor_units),
        };

        tx.execute(
            "UPDATE authority_balance
             SET tokens = tokens + $3, minor_units = minor_units + $4, draws = $5
             WHERE tenant = $1 AND authority = $2",
            &[
                &tenant,
                &name,
                &sql_amount(amount.tokens),
                &sql_amount(amount.minor_units),
                &ordinal,
            ],
        )
        .await
        .map_err(|e| unavailable(&be(&e)))?;

        tx.execute(
            "INSERT INTO authority_receipt
                 (tenant, authority, dispatch, tokens, minor_units,
                  rem_tokens, rem_minor, draw_ordinal)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &tenant,
                &name,
                &dispatch,
                &sql_amount(amount.tokens),
                &sql_amount(amount.minor_units),
                &sql_amount(left.tokens),
                &sql_amount(left.minor_units),
                &ordinal,
            ],
        )
        .await
        .map_err(|e| unavailable(&be(&e)))?;

        // The receipt and the balance commit together. Either both landed or
        // neither did — a balance advanced without its receipt would make the
        // next retry draw again, which is the double-spend this table exists to
        // make impossible.
        tx.commit().await.map_err(|e| unavailable(&be(&e)))?;

        Ok(Drawn {
            authority: id.clone(),
            amount,
            remaining: left,
            draws: u32::try_from(ordinal).unwrap_or(u32::MAX),
        })
    }

    async fn revoke(
        &self,
        id: &AuthorityId,
        reason: &str,
        at: Timestamp,
    ) -> Result<(), AuthorityError> {
        let client = self.pool_ref().get().await.map_err(|e| unavailable(&e))?;
        let tenant = self.tenant_name();

        // `WHERE NOT revoked` makes this idempotent *and* keeps the first
        // reason, in one statement: a second revocation matches no row and
        // changes nothing, rather than overwriting the account of why the
        // authority was withdrawn in the first place.
        let updated = client
            .execute(
                "UPDATE authority_balance
                 SET revoked = TRUE, revoked_at = $3, reason = $4
                 WHERE tenant = $1 AND authority = $2 AND NOT revoked",
                &[&tenant, &id.0, &at.unix_timestamp(), &reason],
            )
            .await
            .map_err(|e| unavailable(&be(&e)))?;

        if updated == 1 {
            return Ok(());
        }
        // Nothing updated: either already revoked, or no such authority. Only
        // the second is an error, so the two are distinguished by asking.
        let exists = client
            .query_opt(
                "SELECT 1 FROM authority_balance WHERE tenant = $1 AND authority = $2",
                &[&tenant, &id.0],
            )
            .await
            .map_err(|e| unavailable(&be(&e)))?
            .is_some();
        if exists {
            Ok(())
        } else {
            Err(AuthorityError::Unknown(id.clone()))
        }
    }

    async fn state(&self, id: &AuthorityId) -> Result<Option<AuthorityState>, StoreError> {
        let client = self.pool_ref().get().await.map_err(|e| {
            StoreError::Backend(format!("the standing-authority store is unavailable: {e}"))
        })?;
        let tenant = self.tenant_name();

        let Some(row) = client
            .query_opt(
                "SELECT t.terms, b.tokens, b.minor_units, b.draws,
                        b.revoked, b.revoked_at, b.reason
                 FROM authority_terms t
                 JOIN authority_balance b
                   ON b.tenant = t.tenant AND b.authority = t.authority
                 WHERE t.tenant = $1 AND t.authority = $2",
                &[&tenant, &id.0],
            )
            .await
            .map_err(|e| be(&e))?
        else {
            return Ok(None);
        };

        let authority: StandingAuthority = serde_json::from_str(row.get::<_, &str>(0))
            .map_err(|e| StoreError::Backend(format!("stored authority is unreadable: {e}")))?;
        let draws: i64 = row.get(3);
        let revoked: bool = row.get(4);
        let revoked_at: i64 = row.get(5);
        let reason: String = row.get(6);

        Ok(Some(AuthorityState {
            authority,
            drawn: Spend {
                tokens: amount_of(row.get(1)),
                minor_units: amount_of(row.get(2)),
            },
            draws: u32::try_from(draws).unwrap_or(u32::MAX),
            revoked: revoked.then(|| Revocation {
                at: Timestamp::from_unix_timestamp(revoked_at).unwrap_or(Timestamp::UNIX_EPOCH),
                reason,
            }),
        }))
    }
}

/// The receipt a previous attempt at this draw left, if there was one.
///
/// Its own function so the transaction body reads as the decision it makes
/// rather than as row unpacking, and because "has this draw already landed" is
/// the question a reader checks first.
async fn receipt(
    tx: &tokio_postgres::Transaction<'_>,
    tenant: &str,
    name: &str,
    dispatch: &str,
    id: &AuthorityId,
) -> Result<Option<Drawn>, AuthorityError> {
    let Some(row) = tx
        .query_opt(
            "SELECT tokens, minor_units, rem_tokens, rem_minor, draw_ordinal
             FROM authority_receipt
             WHERE tenant = $1 AND authority = $2 AND dispatch = $3",
            &[&tenant, &name, &dispatch],
        )
        .await
        .map_err(|e| unavailable(&be(&e)))?
    else {
        return Ok(None);
    };
    let ordinal: i64 = row.get(4);
    Ok(Some(Drawn {
        authority: id.clone(),
        amount: Spend {
            tokens: amount_of(row.get(0)),
            minor_units: amount_of(row.get(1)),
        },
        remaining: Spend {
            tokens: amount_of(row.get(2)),
            minor_units: amount_of(row.get(3)),
        },
        draws: u32::try_from(ordinal).unwrap_or(u32::MAX),
    }))
}
