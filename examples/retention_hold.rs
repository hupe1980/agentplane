//! A retention pass, and the one thing that stops it.
//!
//! Retention is automatic: a window, applied to every closed case, by the
//! plane. That is what makes a legal hold necessary rather than tidy — the
//! matter somebody has been ordered to preserve looks exactly like every other
//! closed case old enough to go, and nothing in the data distinguishes them.
//!
//! The part worth watching is the third block: the sweep erases one matter,
//! refuses the other, and says *which* and *on whose instruction* — a held case
//! is reported as held rather than as a failure, because a control doing its
//! job must not read as a malfunction.
//!
//! Run with: `cargo run --example retention_hold --features redb,testkit`

use std::sync::Arc;

use agentplane::blob::{BlobStore, MemoryBlobs, ScopedBlobs};
use agentplane::case::CaseStore;
use agentplane::core::{CorrelationKey, LegalHold, Timestamp, erasure_scope};
use agentplane::prelude::*;

/// Wall-clock instants for a fixture, outside any run. Real dates, because a
/// retention window is the one thing here a reader checks against a calendar.
fn at(secs: i64) -> Timestamp {
    Timestamp::from_unix_timestamp(secs).expect("representable")
}

/// 2019-03-04 — when both matters opened. Retention measures from `opened_at`,
/// because the rules it serves are written as *N years from the start of the
/// business matter*.
const OPENED: i64 = 1_551_657_600;
/// 2026-09-10 — when the preservation order arrived.
const ORDERED: i64 = 1_788_998_400;
/// 2019-09-14 — seven years before the pass, so both matters are due.
const CUTOFF: i64 = 1_568_419_200;
/// 2026-09-14 — when the pass ran, stamped on every tombstone.
const SWEPT: i64 = 1_789_344_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(RedbStore::open_in_memory()?);
    let cases: Arc<dyn CaseStore> = store.clone();
    let blobs: Arc<dyn BlobStore> = Arc::new(MemoryBlobs::new());
    let tenant = agentplane::core::TenantId::default();

    // ── 1. Two matters, both closed and both past any window ────────────────
    let mut opened = Vec::new();
    for (key, bytes) in [
        ("DISP-1", &b"evidence in a live dispute"[..]),
        ("INV-7", &b"a routine attachment"[..]),
    ] {
        let case = cases
            .correlate_or_open(
                "matter",
                &[CorrelationKey::new("document", key)],
                at(OPENED),
            )
            .await?
            .case_id();
        // Each matter writes through its own unit-scoped handle, exactly as
        // `StepCtx::store_blob` does: identical bytes in two matters are two
        // objects, so one unit's erasure cannot reach the other's.
        let scoped = ScopedBlobs::new(
            Arc::clone(&blobs),
            erasure_scope(&tenant, &case.to_string()),
        );
        let digest = scoped.put(bytes).await?;
        cases.link_blob(case, digest, at(OPENED)).await?;
        cases.close(case).await?;
        opened.push((key, case, scoped, digest));
    }
    let (held_key, held, held_blobs, held_digest) = &opened[0];
    let (_, _, routine_blobs, routine_digest) = &opened[1];
    println!("1. two closed matters, both older than the window");

    // ── 2. One of them is under a preservation order ────────────────────────
    cases
        .place_hold(
            *held,
            &LegalHold {
                placed_at: at(ORDERED),
                reason: "preservation order 2026-114".to_owned(),
            },
        )
        .await?;
    println!("\n2. a hold is placed on {held_key}");

    // The dry run and the pass agree about what would happen, including about
    // which matter a hold is keeping. A listing that said *this will go* while
    // a hold kept it is how an operator learns to distrust the listing.
    let plan = agentplane::retention::plan(cases.as_ref(), at(CUTOFF)).await?;
    println!("   dry run        → would erase {}", plan.due.len());
    println!("                    preserved   {}", plan.held.len());

    // ── 3. The sweep ────────────────────────────────────────────────────────
    let stores = agentplane::retention::Stores {
        cases: &cases,
        blobs: Some(&blobs),
        #[cfg(feature = "keyring")]
        keys: None,
        tenant: &tenant,
    };
    let report = agentplane::retention::retain(&stores, at(CUTOFF), at(SWEPT), "7 years").await?;
    println!("\n3. the pass");
    println!("   erased         → {}", report.erased);
    println!("   failures       → {:?}", report.failures);
    for line in &report.held {
        println!("   held           → {line}");
    }

    // Nothing was half-done: the hold is read before the first tombstone, so a
    // refused erasure leaves no expired blobs behind.
    println!(
        "   held bytes     → readable: {}",
        held_blobs.get(*held_digest).await.is_ok()
    );
    println!(
        "   swept bytes    → readable: {}",
        routine_blobs.get(*routine_digest).await.is_ok()
    );

    // ── 4. The register answers somebody who does not know the case id ──────
    println!("\n4. what is still being kept, and on whose instruction");
    for (case, hold) in cases.holds(None, 50).await? {
        println!("   {case} — {}", hold.reason);
    }

    // ── 5. A pause, not an exemption ────────────────────────────────────────
    cases.release_hold(*held).await?;
    let after = agentplane::retention::retain(&stores, at(CUTOFF), at(SWEPT), "7 years").await?;
    println!("\n5. the hold is lifted and the same pass runs again");
    println!("   still held     → {}", after.held.len());
    println!(
        "   held bytes     → readable: {}",
        held_blobs.get(*held_digest).await.is_ok()
    );

    println!(
        "\nA hold outranks the calendar, and lifting it puts the matter back \
         under it.\nThe sweep never guessed which was which — somebody said so, \
         and the record says who."
    );
    Ok(())
}
