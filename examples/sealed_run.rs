//! Erasure that reaches every copy — and a history that still proves itself.
//!
//! One `.keyring(..)` seals the journal, the case store, the worklist and the
//! event buffer, plus blob payloads. Erasing the case destroys the wrapping
//! key, so every copy becomes unreadable at once — including backups nobody
//! can reach, because what was destroyed was never in them.
//!
//! The part worth watching is the last line: the hash chain **still verifies**
//! afterwards. The chain commits to the sealed bytes, so an erasure costs the
//! data and not the proof that nothing was altered.
//!
//! Run with: `cargo run --example sealed_run --features redb,testkit,keyring`

use std::sync::Arc;

use agentplane::case::CaseStore;
use agentplane::core::{
    CorrelationKey, Digest, Outcome, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::journal::{JournalStore, Record, RecordKind, payload};
use agentplane::keyring::KeyRing;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use agentplane::testkit::MemoryKeyRing;
use serde_json::{Value, json};

/// Writes a claimant's details into case state — the shape a real intake has.
#[derive(Debug)]
struct Intake;

#[async_trait::async_trait]
impl Skill for Intake {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("intake").provides("claim.intake")
    }

    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let (_, version) = cx.case_state().await?;
        cx.put_case_state(version, input.peek().clone()).await?;
        Ok(Outcome::done(Tainted::trusted(json!({ "recorded": true }))))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw = Arc::new(RedbStore::open_in_memory()?);
    let keys = Arc::new(MemoryKeyRing::default());
    let tenant = agentplane::core::TenantId::default();

    // One call. Stores registered before it are sealed just the same, because
    // the wrapping happens at `build()`.
    let ring: Arc<dyn KeyRing> = keys.clone();
    let rt = Runtime::builder_on(Arc::clone(&raw))
        .keyring(ring)
        .skill(Intake)
        .build();

    let out = rt
        .run_correlated(
            "claim.intake",
            Tainted::trusted(
                json!({ "claimant": "Ada Lovelace", "iban": "GB29 NWBK 6016 1331 9268 19" }),
            ),
            "claim",
            &[CorrelationKey::new("claim", "CLM-42")],
        )
        .await?;
    println!("1. run            → {:?}", out.status);

    let case = raw
        .correlate(&[CorrelationKey::new("claim", "CLM-42")])
        .await?
        .expect("the case exists");

    // ── 2. Readable through the plane, sealed underneath ────────────────────
    let stored = raw.case(case).await?.expect("stored");
    println!(
        "2. in the store   → {} (sealed: {})",
        stored.state,
        payload::is_sealed(&stored.state)
    );
    let records = raw.read(out.run_id, 1).await?;
    let journalled = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted { input, .. } => Some(input.clone()),
            _ => None,
        })
        .expect("the run was admitted");
    println!(
        "   journal input  → {journalled} (sealed: {})",
        payload::is_sealed(&journalled)
    );
    println!(
        "   the name is in the stored bytes: {}",
        String::from_utf8_lossy(records[0].raw()).contains("Lovelace")
    );

    // ── 3. Erase the case ───────────────────────────────────────────────────
    keys.destroy(
        &agentplane::keyring::scope(&tenant, &case.to_string()),
        cx_now(),
        "subject exercised the right to erasure",
    )
    .await?;
    println!("\n3. erased         → the wrapping key is destroyed");

    let after = raw.case(case).await?.expect("still listed");
    println!(
        "   case state     → unreadable: {}",
        payload::is_sealed(&after.state)
    );

    // ── 4. And the history still proves itself ──────────────────────────────
    Record::verify_chain(&records, Digest::ZERO)?;
    println!(
        "\n4. chain verifies → yes, with no key at all — the erasure cost the \
         data, not the proof"
    );
    Ok(())
}

/// The wall clock, for a tombstone's date. Outside a run, so outside the
/// journal's determinism rule.
#[allow(clippy::disallowed_methods)]
fn cx_now() -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::now_utc()
}
