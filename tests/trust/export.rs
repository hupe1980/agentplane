//! Getting the record out, and the two ways an export lies by omission.
//!
//! An auditor who can check a history but cannot obtain it is still dependent
//! on the operator, so the export is part of the same argument the offline
//! audit makes. Which means the interesting tests here are not "the bytes come
//! out" — they are the two states an export can be in while *looking* complete:
//! cut short, and missing a run it could not read.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::core::{Outcome, Skill, SkillDescriptor, SkillError, Tainted};
use agentplane::journal::JournalStore;
use agentplane::runtime::{Runtime, StepCtx};
use agentplane::store::RedbStore;
use serde_json::{Value, json};

#[derive(Debug)]
struct Trivial;

#[async_trait::async_trait]
impl Skill for Trivial {
    fn descriptor(&self) -> SkillDescriptor {
        SkillDescriptor::new("trivial").provides("demo.trivial")
    }
    async fn invoke(
        &self,
        cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        let at = cx.now().await?;
        Ok(Outcome::done(
            input.map(|v| json!({ "saw": v, "at": at.to_string() })),
        ))
    }
}

/// Run once and hand back the store and the run's id.
async fn one_run() -> (Arc<dyn JournalStore>, agentplane::core::RunId) {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let out = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 1 })))
        .await
        .expect("run");
    (store as Arc<dyn JournalStore>, out.run_id)
}

/// A run id as it appears *in the file*.
///
/// `RunId::to_string()` renders `run_01K…` and the JSON form is bare, so a
/// fixture that greps for the display form silently matches nothing — and an
/// assertion that the edit landed is then satisfied by the edit never having
/// been possible. That is the shape where a negative test measures its own
/// fixture, so the one place this could go wrong is written once.
fn as_written(run: agentplane::core::RunId) -> String {
    serde_json::to_value(run)
        .expect("a run id serializes")
        .as_str()
        .expect("as a string")
        .to_owned()
}

fn lines(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is its own JSON value"))
        .collect()
}

/// **An export is self-describing, framed, and re-walkable offline.**
///
/// Everything asserted here is something a reader who does not have this crate
/// would otherwise have to be told, and being told is the dependency the export
/// exists to remove: which log, at what size, under which canonicalization
/// rule, and — for every record — the chain links that let them verify it
/// without asking the operator anything.
#[tokio::test]
async fn an_export_carries_what_a_reader_needs_to_check_it_without_us() {
    let (store, run) = one_run().await;

    let mut out = Vec::new();
    let trailer = agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    let lines = lines(&out);
    assert!(lines.len() > 2, "an export with no records: {lines:#?}");

    let header = &lines[0];
    assert_eq!(header["kind"], "agentplane.export");
    assert_eq!(
        header["version"],
        agentplane::export::FORMAT_VERSION,
        "the format version is what a reader pins; it must not be absent"
    );
    assert_eq!(
        header["canon"],
        agentplane::core::canon::VERSION,
        "a digest without the rule that computed it is unverifiable — a \
         version-less digest would be re-derived under whatever rule the \
         reading build implements"
    );
    assert_eq!(
        header["checkpoint"]["size"], 1,
        "the checkpoint is what ties this export to a commitment: {header}"
    );

    // Records are the lines that are neither the header, a run block, nor the
    // trailer. Run blocks carry the Merkle log position, which the records
    // cannot: a chain links records *within* a run and knows nothing about its
    // neighbours, so without the position a whole missing run is invisible.
    let blocks: Vec<&Value> = lines
        .iter()
        .filter(|l| l["kind"] == "agentplane.export.run")
        .collect();
    assert_eq!(blocks.len(), 1, "one run, one block: {lines:#?}");
    assert!(
        blocks[0]["index"].is_number() && blocks[0]["seal"].is_string(),
        "a sealed run's block carries no log position, so this export cannot be \
         checked against its own checkpoint: {}",
        blocks[0]
    );

    let records: Vec<&Value> = lines.iter().filter(|l| l["kind"].is_null()).collect();
    assert_eq!(trailer.records, records.len());
    for r in &records {
        assert!(r["hash"].is_string(), "a record without its hash: {r}");
        assert!(r["prev_hash"].is_string(), "a record without a link: {r}");
        assert!(r["seq"].is_number(), "a record without its position: {r}");
        assert!(
            r.get("attestation").is_some(),
            "the signature field is absent rather than null, so a reader cannot \
             tell unsigned history from a field this export forgot: {r}"
        );
    }
    // The links actually join up, which is the property the export is for.
    for pair in records.windows(2) {
        assert_eq!(
            pair[0]["hash"], pair[1]["prev_hash"],
            "consecutive records do not chain, so the export cannot be verified \
             offline even though every field is present"
        );
    }

    let end = lines.last().expect("a trailer");
    assert_eq!(end["kind"], "agentplane.export.end");
    assert_eq!(end["runs_requested"], 1);
    assert_eq!(end["runs_exported"], 1);
}

/// **A truncated export is distinguishable from a complete one.**
///
/// This is the failure mode that matters, because it is silent: an export
/// killed by a full disk, a closed pipe or a crash ends mid-file and every line
/// in it is valid JSON. A reader comparing counts has nothing to compare
/// against — they do not have the source. The trailer's *absence* is the
/// signal, which is why it is a framed format rather than a bare stream of
/// records.
#[tokio::test]
async fn an_interrupted_export_is_missing_its_trailer() {
    let (store, run) = one_run().await;

    let mut whole = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut whole)
        .await
        .expect("export");

    // Cut it where a killed process would: mid-file, on a line boundary.
    let all = lines(&whole);
    let cut = all[..all.len() - 1].to_vec();

    assert_eq!(
        all.last().expect("trailer")["kind"],
        "agentplane.export.end",
        "the complete export has no trailer, so its absence proves nothing"
    );
    assert_ne!(
        cut.last().expect("a line")["kind"],
        "agentplane.export.end",
        "a truncated export still ends with a trailer, so a reader cannot tell \
         a prefix from the whole file"
    );
}

/// **A run that cannot be read is named, not dropped.**
///
/// The export continues past a damaged run, because one unreadable run must not
/// withhold every healthy one. That decision is only safe while the omission is
/// reported: an export that skipped a run quietly is shaped exactly like one
/// that had nothing to skip, and the run that fails to read is not a random one.
///
/// The failure is **injected**, and it has to be. Asking for a run that does not
/// exist does not reach this path — both backends answer an unknown run with an
/// empty read rather than an error, which is correct — so a test written that
/// way asserts an accounting identity that holds whether or not the omission is
/// ever recorded. It passed with the reporting deleted, which is precisely the
/// test that cannot fail.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_run_that_cannot_be_read_is_named_in_the_trailer() {
    use agentplane::testkit::faults::{Faulty, Schedule};

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let healthy = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 1 })))
        .await
        .expect("run")
        .run_id;
    let damaged = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 2 })))
        .await
        .expect("run")
        .run_id;

    // One run readable, one not — the state a corrupt page or a lost shard
    // leaves behind.
    let faulty: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        Arc::clone(&store) as Arc<dyn JournalStore>,
        Schedule::healthy().unreadable(damaged),
    ));

    let mut out = Vec::new();
    let trailer = agentplane::export::to_jsonl(&faulty, None, &[healthy, damaged], &mut out)
        .await
        .expect("a damaged run does not fail the whole export");

    assert_eq!(
        trailer.runs_requested, 2,
        "the trailer must say what was asked for, not only what was delivered"
    );
    assert_eq!(
        trailer.runs_exported, 1,
        "the healthy run did not come out, so one damaged run withheld it — \
         which is the opposite of what an export is for"
    );
    assert!(
        trailer.records > 0,
        "no records were exported despite a healthy run being asked for"
    );
    assert_eq!(
        trailer.unreadable.len(),
        1,
        "the unreadable run was skipped without being named, so this export is \
         shaped exactly like a complete one: {trailer:?}"
    );
    assert_eq!(
        trailer.unreadable[0].run, damaged,
        "the trailer names the wrong run as unreadable"
    );
    assert!(
        !trailer.unreadable[0].reason.is_empty(),
        "an unreadable run was named with no reason, so an operator learns that \
         something is missing and not what to do about it"
    );
    assert_eq!(
        trailer.runs_exported + trailer.unreadable.len(),
        trailer.runs_requested,
        "the trailer does not account for every run asked for: {trailer:?}"
    );
}

/// **A faithful export verifies against its own checkpoint, offline.**
///
/// This is the restore drill. Putting bytes back into a store proves bytes
/// moved; it does not prove they are the bytes that were taken, in the order
/// they were taken, with nothing dropped from the middle. That is what this
/// establishes — and it establishes it from the file alone, with no store and
/// no runtime.
#[tokio::test]
async fn a_faithful_export_verifies_from_the_file_alone() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    for n in 0..3 {
        runs.push(
            rt.run("demo.trivial", Tainted::trusted(json!({ "n": n })))
                .await
                .expect("run")
                .run_id,
        );
    }
    let store: Arc<dyn JournalStore> = store;

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &runs, &mut out)
        .await
        .expect("export");

    let report =
        agentplane::export::verify(std::io::Cursor::new(&out), None, None).expect("verify");
    assert!(
        report.is_sound(),
        "a faithful export did not verify: {:#?}",
        report.findings
    );
    assert_eq!(report.sound.len(), 3, "not every run verified: {report:#?}");
    assert_eq!(
        report.checkpoint.size, 3,
        "the export's checkpoint does not cover the runs in it"
    );
    // The honest half: no key was supplied, so authorship is unestablished and
    // the report says so rather than implying it checked.
    assert!(
        report.not_checked.iter().any(|s| s.contains("signature")),
        "a pass with no key claimed to have checked signatures: {report:#?}"
    );
}

/// **A run dropped from the middle is caught only by the tree.**
///
/// The case that justifies carrying Merkle log positions in the export at all.
/// Remove a whole run and every remaining per-run chain still verifies
/// perfectly — each one is internally consistent, because a chain links records
/// *within* a run and knows nothing about its neighbours. Only rebuilding the
/// log notices that a leaf is gone.
///
/// This is the difference between an export that is a transcript and one that
/// is evidence, and it is exactly the deletion an operator handing over a
/// selective copy would perform.
#[tokio::test]
async fn a_run_removed_from_the_middle_is_caught_by_the_rebuilt_root() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    for n in 0..3 {
        runs.push(
            rt.run("demo.trivial", Tainted::trusted(json!({ "n": n })))
                .await
                .expect("run")
                .run_id,
        );
    }
    let store: Arc<dyn JournalStore> = store;

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &runs, &mut out)
        .await
        .expect("export");

    // Excise the middle run's block and every record under it, exactly as a
    // careful editor would — leaving a file in which nothing else is disturbed.
    let text = String::from_utf8(out).expect("utf8");
    let victim = as_written(runs[1]);
    let mut kept = Vec::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.contains("agentplane.export.run") {
            skipping = line.contains(&victim);
        }
        if !skipping {
            kept.push(line);
        }
    }
    let edited = kept.join("\n");
    assert!(
        text.contains(&victim),
        "the fixture searched for a run id the file never contained, so removing \
         it would remove nothing and this test would measure itself"
    );
    assert!(
        !edited.contains(&victim),
        "the fixture did not actually remove the run"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None, None)
        .expect("verify");
    assert!(
        !report.is_sound(),
        "a run was removed from the middle of the export and it verified clean — every \
         surviving chain is internally consistent, so only the rebuilt log can notice"
    );
    // Asserted on the *counts*, not just the class of finding. "A run is
    // missing" and "this export carries no log positions at all" both produce a
    // size mismatch, and a test that accepts either passes against an export
    // that dropped the positions entirely — which is the very thing that makes
    // the deletion invisible.
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("carries 2 sealed run(s)") && f.contains("commits to 3")),
        "the removal was noticed, but not as two runs surviving out of three — \
         so this export may carry no log positions at all: {:#?}",
        report.findings
    );
    // The positive half: the two surviving runs still verified, so this is a
    // finding about the log rather than a file that failed to parse.
    assert_eq!(
        report.sound.len(),
        2,
        "the surviving runs did not verify, so the fixture broke more than it meant to"
    );
}

/// **An edited record does not recompute to the hash it carries.**
///
/// The chain is only evidence if somebody recomputes it. `verify` re-seals
/// every record through the same function the store sealed with, so agreement
/// is a statement about the bytes rather than about the file agreeing with
/// itself.
#[tokio::test]
async fn an_edited_record_fails_to_recompute() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    // Change a journaled payload without touching any hash — the edit an
    // operator with write access to the file would make, applied to **both**
    // copies the line carries: the readable body (`"n":1`) and the wire bytes,
    // where the same characters travel escaped inside the `raw` string
    // (`\"n\":1`). Editing both is the consistent forgery, so the only thing
    // left to catch it is the hash. The run's *input* is in the record; the
    // skill's output is not, which is why this greps for a value the export
    // demonstrably contains rather than one it seemed like it should.
    let original = String::from_utf8(out).expect("utf8");
    let text = original
        .replace("\\\"n\\\":1", "\\\"n\\\":9")
        .replace("\"n\":1", "\"n\":9");
    assert_ne!(
        original, text,
        "the fixture edited nothing, so this test would pass against a verifier \
         that checks no hashes at all"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, None)
        .expect("verify");
    assert!(
        !report.is_sound(),
        "a record was edited and the export still verified"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("does not recompute")),
        "the edit was noticed for the wrong reason: {:#?}",
        report.findings
    );
}

/// **Verification runs over the wire bytes, not over a re-serialization.**
///
/// The chain is over history *as written* — the journal's own wire-bytes rule
/// — and the export carries those bytes in `raw` so an offline verifier can
/// hold the file to them. A verifier that instead re-serialized the parsed
/// `body` would pass this file: the pretty copy still matches the hash once
/// put back through this build's canonicalization, while the bytes actually
/// carried — the ones a restore replays — say something else. Only rehashing
/// `raw` itself catches it.
#[tokio::test]
async fn tampered_wire_bytes_are_caught_even_when_the_readable_body_is_pristine() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    // Edit only the escaped copy inside `raw`, leaving `body` and every hash
    // exactly as written.
    let original = String::from_utf8(out).expect("utf8");
    let text = original.replace("\\\"n\\\":1", "\\\"n\\\":9");
    assert_ne!(
        original, text,
        "the fixture edited nothing, so this test would pass against any verifier"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, None)
        .expect("verify");
    assert!(
        !report.is_sound(),
        "the wire bytes were edited and the export still verified — the \
         verifier is rehashing a re-serialization of the display copy instead \
         of the bytes the chain covers"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("does not recompute") || f.contains("wire bytes")),
        "the edit was noticed for the wrong reason: {:#?}",
        report.findings
    );
}

/// **The display copy is held to the wire bytes.**
///
/// `body` exists for a reader's eyes; the hash covers `raw`. An edit to the
/// display copy alone leaves every hash verifying — which is exactly why it
/// must be its own finding, or an export could show an auditor a history the
/// chain never committed to, one field over from the bytes that prove
/// otherwise.
#[tokio::test]
async fn an_edited_display_body_is_a_finding_though_every_hash_verifies() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    // Edit only the readable copy, leaving `raw` and every hash as written.
    let original = String::from_utf8(out).expect("utf8");
    let text = original.replace("\"n\":1", "\"n\":9");
    assert_ne!(original, text, "the fixture edited nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("wire bytes")),
        "a display body disagreeing with its wire bytes went unnoticed: {:#?}",
        report.findings
    );
    assert!(
        !report.sound.contains(&run),
        "a run whose readable history disagrees with its hashed history was \
         reported sound"
    );
}

/// **A restored store commits to exactly the history the export did.**
///
/// The result is one comparison: equal Merkle roots at equal size. That is a far
/// stronger statement than "the rows loaded" — it means every record, in every
/// run, in the order the log recorded them, rebuilt to the same commitment. A
/// restore that got any of the three wrong produces a different root and says so.
///
/// It also exercises the reason this replays `append` rather than writing rows.
/// `append` maintains several derived indexes, and a restore that rebuilt all
/// but one would leave a store that reads perfectly until somebody queries the
/// one it missed — so the assertions below go back through the *query* surfaces
/// rather than only the checkpoint.
/// The admission key the restored run was admitted under.
const KEY: &str = "urn:test:bus\u{1f}EV-1";

/// Every index `append` derives, queried the way a caller would.
///
/// The checkpoint says nothing about these, which is exactly why a restore that
/// wrote rows directly could pass every hash comparison and still be broken.
async fn assert_derived_indexes_survived(fresh: &Arc<dyn JournalStore>, keyed: RunId) {
    let by_outcome = fresh
        .runs_by_outcome("succeeded", 10)
        .await
        .expect("by outcome");
    assert_eq!(
        by_outcome.len(),
        3,
        "the outcome index did not survive the restore, so the quarantine and \
         success backlogs are empty on a store that looks healthy"
    );

    let recent = fresh.recent_runs(None, 10).await.expect("recent");
    assert_eq!(
        recent.len(),
        3,
        "the discovery index did not survive, so nothing lists over A2A"
    );

    assert_eq!(
        fresh.admitted_as(KEY).await.expect("admission index"),
        Some(keyed),
        "the admission index did not survive the restore, so every emitter's \
         redelivery would start a second run against a store that looks healthy"
    );
}

#[tokio::test]
async fn a_restored_store_rebuilds_the_same_checkpoint() {
    let origin = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&origin) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    // The first carries an admission key, so the index derived from it has
    // something to lose.
    runs.push(
        rt.run_once("demo.trivial", Tainted::trusted(json!({ "n": 0 })), KEY)
            .await
            .expect("run")
            .run_id(),
    );
    for n in 1..3 {
        runs.push(
            rt.run("demo.trivial", Tainted::trusted(json!({ "n": n })))
                .await
                .expect("run")
                .run_id,
        );
    }
    let origin: Arc<dyn JournalStore> = origin;
    let before = origin.checkpoint().await.expect("checkpoint");

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&origin, None, &runs, &mut out)
        .await
        .expect("export");

    // A different store, with nothing in it.
    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let report = agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(&out))
        .await
        .expect("restore");

    assert!(
        report.is_faithful(),
        "the rebuilt store commits to a different history:\n  expected {:?}\n  rebuilt  {:?}",
        report.expected,
        report.rebuilt
    );
    assert_eq!(
        report.rebuilt, before,
        "the restore drifted from the source"
    );
    assert_eq!(report.runs, 3);

    // Nothing here was signed, so the only thing that could not be carried is
    // the activity index — and it is named rather than left to be discovered.
    assert!(
        report
            .not_carried
            .iter()
            .any(|s| s.contains("activity timestamps")),
        "the restore did not say what it could not carry: {report:#?}"
    );

    // The records themselves round-tripped, hash for hash. The checkpoint
    // covers terminal hashes only, so this is the part it does not prove.
    for run in &runs {
        let a = origin.read(*run, 1).await.expect("origin");
        let b = fresh.read(*run, 1).await.expect("restored");
        assert_eq!(a.len(), b.len(), "run {run} lost records");
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.hash, y.hash, "run {run} record {} rehashed", x.seq());
            assert_eq!(x.body, y.body, "run {run} record {} differs", x.seq());
        }
    }

    assert_derived_indexes_survived(&fresh, runs[0]).await;

    // **The strongest statement available**: a plane wired to the restored store
    // replays a run it never executed, in `Strict` mode — consuming every effect
    // from history and performing none. A store whose records merely *looked*
    // right would diverge here, because replay recomputes each effect key from
    // the record it reads and quarantines on the first disagreement.
    let restored_plane = Runtime::builder(Arc::clone(&fresh)).skill(Trivial).build();
    let replayed = restored_plane
        .replay(runs[0], agentplane::runtime::Mode::Strict)
        .await
        .expect("a restored run replays");
    assert!(
        matches!(replayed.status, agentplane::runtime::RunStatus::Succeeded),
        "a run restored from an export did not strict-replay: {:?}",
        replayed.status
    );

    // And the restored history verifies on its own terms.
    let mut again = Vec::new();
    agentplane::export::to_jsonl(&fresh, None, &runs, &mut again)
        .await
        .expect("re-export");
    let verified =
        agentplane::export::verify(std::io::Cursor::new(&again), None, None).expect("verify");
    assert!(
        verified.is_sound(),
        "a restored store exported something that does not verify: {:#?}",
        verified.findings
    );
}

/// **A run that changed hands restores with its epochs intact.**
///
/// `epoch` is a field of the hashed body, so it is not a detail a restore may
/// re-derive. A run that was taken over carries 1 on the records its first owner
/// wrote and 2 on the rest, and a restore that wrote everything under one fresh
/// lease would rehash exactly those records — which is to say, exactly the runs a
/// failover produced. That is the history a disaster recovery is most likely to
/// be carrying, so it is the case that must not be the untested one.
///
/// The epochs are written directly rather than by waiting out a lease: both
/// backends fence only when a lease row exists, so appending without one
/// reproduces precisely the history a takeover leaves, without a second of
/// sleeping. The test is about the restore, not about how the epochs arose.
#[tokio::test]
async fn a_run_that_changed_hands_restores_with_its_epochs() {
    use agentplane::journal::{Append, RecordKind};

    let origin: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let run = agentplane::core::RunId::generate();

    // Two owners, two epochs, one chain — what a mid-flight takeover leaves.
    for (epoch, skill) in [(1u64, "before"), (1, "still-before"), (2, "after")] {
        origin
            .append(
                epoch,
                vec![Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: skill.to_owned(),
                    },
                )],
            )
            .await
            .expect("append");
    }
    // Sealed the way the runtime seals: the conclusion enters the *chain*
    // first, then the store's seal row. `from_jsonl` reads the outcome from
    // that record rather than from store state, deliberately — the record is
    // hash-chained and the seal row is derived.
    let head = origin.head(run).await.expect("head");
    origin
        .append(
            2,
            vec![Append::new(
                run,
                RecordKind::RunSealed {
                    outcome: "succeeded".to_owned(),
                    chain_head: head.hash,
                    reason: None,
                },
            )],
        )
        .await
        .expect("seal record");
    origin.seal(run, 2, "succeeded").await.expect("seal");

    let epochs: Vec<u64> = origin
        .read(run, 1)
        .await
        .expect("read")
        .iter()
        .map(|r| r.body.epoch)
        .collect();
    assert_eq!(
        epochs,
        vec![1, 1, 2, 2],
        "the fixture did not produce a run with two epochs, so this test would \
         pass against a restore that flattens them"
    );

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&origin, None, &[run], &mut out)
        .await
        .expect("export");

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let report = agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(&out))
        .await
        .expect("restore");

    assert!(
        report.is_faithful(),
        "a run that changed hands did not restore to the same commitment:\n  \
         expected {:?}\n  rebuilt  {:?}",
        report.expected,
        report.rebuilt
    );

    let a = origin.read(run, 1).await.expect("origin");
    let b = fresh.read(run, 1).await.expect("restored");
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(
            x.body.epoch,
            y.body.epoch,
            "record {} was restored under epoch {} instead of {}",
            x.seq(),
            y.body.epoch,
            x.body.epoch
        );
        assert_eq!(
            x.hash,
            y.hash,
            "record {} rehashed, because the epoch it was sealed with is inside \
             the bytes that are hashed",
            x.seq()
        );
    }
}

/// **A format this build does not read is named, not guessed at.**
///
/// The header's `version` exists so a reader pins it — and a version only the
/// writer ever consults is a declaration that does nothing. Both readers must
/// react: `verify` says which lines it could interpret, and a restore refuses
/// outright, because `parse` skips what it does not recognise and would
/// otherwise rebuild whatever subset happened to look familiar and call it a
/// history.
#[tokio::test]
async fn an_export_of_a_foreign_format_version_is_named_not_guessed_at() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    let original = String::from_utf8(out).expect("utf8");
    let foreign = original.replace(
        &format!("\"version\":{}", agentplane::export::FORMAT_VERSION),
        "\"version\":999",
    );
    assert_ne!(
        original, foreign,
        "the fixture edited nothing, so this test would pass against a reader \
         that never looks at the version"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(foreign.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("format version")),
        "a future format was verified without saying this build cannot read it: {:#?}",
        report.findings
    );

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused =
        agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(foreign.as_bytes()))
            .await;
    let Err(e) = refused else {
        panic!("a restore rebuilt a format it cannot fully parse");
    };
    assert!(
        e.to_string().contains("format version"),
        "the refusal does not name the version mismatch: {e}"
    );

    // The positive half: the same file under its own version restores.
    let ok =
        agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(original.as_bytes()))
            .await
            .expect("restore");
    assert!(ok.is_faithful(), "the untouched export did not restore");
}

/// **A relabelled run block is caught by its own records.**
///
/// Chain, leaf and Merkle checks all verify the *bytes* — so an export that
/// filed run B's records and B's leaf under run A's id passed every one of
/// them, and `sound` then named a run whose history is somebody else's. The
/// label is what a reader looks a run up by, and the record's own body is the
/// only line that carries the truth to hold it to.
#[tokio::test]
async fn a_relabelled_run_block_is_caught_by_its_own_records() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    let victim = as_written(run);
    let imposter = as_written(agentplane::core::RunId::generate());
    let text = String::from_utf8(out).expect("utf8");
    let relabelled: String = text
        .lines()
        .map(|line| {
            if line.contains("agentplane.export.run") {
                line.replace(&victim, &imposter)
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        relabelled.contains(&imposter),
        "the fixture relabelled nothing, so this test would pass against a \
         verifier that never compares the block to its records"
    );

    let report =
        agentplane::export::verify(std::io::Cursor::new(relabelled.as_bytes()), None, None)
            .expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("belongs to run")),
        "a run block wearing another run's records verified clean: {:#?}",
        report.findings
    );
    assert!(
        report.sound.is_empty(),
        "the imposter id was reported sound over records that are not its \
         history: {:?}",
        report.sound
    );
}

/// **Two run blocks claiming one log position are named, not left as a root
/// mismatch.**
///
/// A checkpoint of size N commits to positions 0..N, so the positions are part
/// of the claim. An export that files two runs at one position describes a
/// different log than the one it names, and before this finding the only
/// symptom was "the root differs" — true, and useless to the auditor asking
/// *which* runs to distrust: a tree rebuilt over duplicated positions compares
/// garbage against the root and reports the wrong defect.
#[tokio::test]
async fn a_duplicated_log_position_is_named_rather_than_left_as_a_root_mismatch() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    for n in 0..2 {
        runs.push(
            rt.run("demo.trivial", Tainted::trusted(json!({ "n": n })))
                .await
                .expect("run")
                .run_id,
        );
    }
    let store: Arc<dyn JournalStore> = store;

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &runs, &mut out)
        .await
        .expect("export");

    // File the second run at the first one's position, exactly as an export
    // stitched together from two histories would.
    let text = String::from_utf8(out).expect("utf8");
    let edited: String = text
        .lines()
        .map(|line| {
            if line.contains("agentplane.export.run") {
                line.replace("\"index\":1", "\"index\":0")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(
        edited, text,
        "the fixture moved nothing, so this test would pass against a verifier \
         that never reads the positions"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("log positions")),
        "two runs claiming one log position were not named: {:#?}",
        report.findings
    );
}

use agentplane::core::{CaseId, Digest, Epoch, Seq, StoreError};
use agentplane::journal::{Append, Cancellation, Checkpoint, Head, Inclusion, Lease, Record};
use std::time::Duration;

use agentplane::core::RunId;

/// Delegates everything, but answers `checkpoint()` from the moment it was
/// wrapped — which is exactly what a caller racing a concurrent seal sees.
#[derive(Debug)]
struct StaleCheckpoint {
    inner: Arc<dyn JournalStore>,
    at: Checkpoint,
}

#[async_trait::async_trait]
impl JournalStore for StaleCheckpoint {
    async fn append(&self, e: Epoch, b: Vec<Append>) -> Result<Vec<Record>, StoreError> {
        self.inner.append(e, b).await
    }
    fn is_shared(&self) -> bool {
        self.inner.is_shared()
    }
    async fn read(&self, run: RunId, from: Seq) -> Result<Vec<Record>, StoreError> {
        self.inner.read(run, from).await
    }
    async fn runs_by_outcome(&self, outcome: &str, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.runs_by_outcome(outcome, limit).await
    }
    async fn admitted_as(&self, key: &str) -> Result<Option<RunId>, StoreError> {
        self.inner.admitted_as(key).await
    }

    async fn forget_admissions(
        &self,
        older_than: agentplane::core::Timestamp,
    ) -> Result<usize, StoreError> {
        self.inner.forget_admissions(older_than).await
    }
    async fn abandoned_runs(&self, limit: usize) -> Result<Vec<RunId>, StoreError> {
        self.inner.abandoned_runs(limit).await
    }
    async fn recent_runs(
        &self,
        after: Option<(u64, RunId)>,
        limit: usize,
    ) -> Result<Vec<(RunId, u64)>, StoreError> {
        self.inner.recent_runs(after, limit).await
    }
    async fn case_history(&self, case: CaseId, limit: usize) -> Result<Vec<Record>, StoreError> {
        self.inner.case_history(case, limit).await
    }
    async fn head(&self, run: RunId) -> Result<Head, StoreError> {
        self.inner.head(run).await
    }
    async fn acquire(&self, run: RunId, o: &str, t: Duration) -> Result<Lease, StoreError> {
        self.inner.acquire(run, o, t).await
    }
    async fn release_lease(&self, run: RunId, e: Epoch) -> Result<(), StoreError> {
        self.inner.release_lease(run, e).await
    }
    async fn renew(&self, run: RunId, o: &str, e: Epoch, t: Duration) -> Result<Lease, StoreError> {
        self.inner.renew(run, o, e, t).await
    }
    async fn seal(&self, run: RunId, e: Epoch, o: &str) -> Result<Digest, StoreError> {
        self.inner.seal(run, e, o).await
    }
    async fn checkpoint(&self) -> Result<Checkpoint, StoreError> {
        Ok(self.at.clone())
    }
    async fn consistency_proof(&self, old: u64) -> Result<Vec<Digest>, StoreError> {
        self.inner.consistency_proof(old).await
    }
    async fn inclusion_proof(&self, run: RunId) -> Result<Option<Inclusion>, StoreError> {
        self.inner.inclusion_proof(run).await
    }
    async fn request_cancel(
        &self,
        run: RunId,
        actor: &str,
        reason: &str,
    ) -> Result<bool, StoreError> {
        self.inner.request_cancel(run, actor, reason).await
    }
    async fn cancellation(&self, run: RunId) -> Result<Option<Cancellation>, StoreError> {
        self.inner.cancellation(run).await
    }
}

/// **A run sealed after the export's checkpoint is exported as still open.**
///
/// `to_jsonl` reads the checkpoint first and each run's log position after, so
/// a run sealed in between carries an index the header's checkpoint does not
/// commit to. Stamping it anyway makes the export disagree with its own first
/// line: the verifier rebuilds a tree one leaf larger than the root it compares
/// against, and reports tampering where there was only time. The export instead
/// describes the log *as of its checkpoint* — the late run's records are all
/// present, and its seal travels in the next export.
#[tokio::test]
async fn a_run_sealed_after_the_checkpoint_exports_as_still_open() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let first = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 1 })))
        .await
        .expect("run")
        .run_id;
    let store: Arc<dyn JournalStore> = store;
    let at = store.checkpoint().await.expect("checkpoint");

    // Sealed after the checkpoint was taken — the race, made deterministic.
    let late = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 2 })))
        .await
        .expect("run")
        .run_id;

    let stale: Arc<dyn JournalStore> = Arc::new(StaleCheckpoint {
        inner: Arc::clone(&store),
        at,
    });
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&stale, None, &[first, late], &mut out)
        .await
        .expect("export");

    let report =
        agentplane::export::verify(std::io::Cursor::new(&out), None, None).expect("verify");
    assert!(
        report.is_sound(),
        "an export racing a concurrent seal reported tampering where there was \
         only time: {:#?}",
        report.findings
    );
    assert_eq!(
        report.sound.len(),
        2,
        "both runs' records are in the file and both chains verify: {report:#?}"
    );
    // The late run is described as the checkpoint knew it: open, no log
    // position — a state, not a gap.
    let blocks: Vec<Value> = lines(&out)
        .into_iter()
        .filter(|l| l["kind"] == "agentplane.export.run")
        .collect();
    let late_block = blocks
        .iter()
        .find(|b| b["run"] == as_written(late))
        .expect("the late run has a block");
    assert!(
        late_block.get("index").is_none(),
        "a run sealed past the checkpoint carries a position its own header \
         does not commit to: {late_block}"
    );
}

/// **An edited record in an open run is not sound.**
///
/// A sealed run's tampering surfaces at the leaf comparison; an open run has no
/// leaf, so per-record findings are the only thing standing between an edit and
/// `sound` — and `sound` promises *chain recomputed exactly*. Without the
/// per-run flag this run produced a finding **and** appeared sound, which is
/// two halves of one report contradicting each other.
#[tokio::test]
async fn an_edited_record_in_an_open_run_is_not_sound() {
    #[derive(Debug)]
    struct Failing;

    #[async_trait::async_trait]
    impl Skill for Failing {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("failing").provides("demo.failing")
        }
        async fn invoke(
            &self,
            _cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            Err(SkillError::Other("on purpose".into()))
        }
    }

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Failing)
        .build();
    let out = rt
        .run("demo.failing", Tainted::trusted(json!({ "n": 1 })))
        .await
        .expect("run");
    assert!(
        matches!(out.status, agentplane::runtime::RunStatus::Failed(_)),
        "the fixture needs an open run, and a failed run stays open for resume"
    );
    let store: Arc<dyn JournalStore> = store;

    let mut bytes = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[out.run_id], &mut bytes)
        .await
        .expect("export");

    // The untouched export lists the open run sound — the positive half, so
    // the assertion below is about the edit rather than about open runs.
    let clean =
        agentplane::export::verify(std::io::Cursor::new(&bytes), None, None).expect("verify");
    assert!(
        clean.sound.contains(&out.run_id),
        "an untouched open run did not verify: {:#?}",
        clean.findings
    );

    let original = String::from_utf8(bytes).expect("utf8");
    // Both copies — the readable body and the escaped wire bytes — so the
    // hash is the only witness left. See `an_edited_record_fails_to_recompute`.
    let edited = original
        .replace("\\\"n\\\":1", "\\\"n\\\":9")
        .replace("\"n\":1", "\"n\":9");
    assert_ne!(original, edited, "the fixture edited nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("does not recompute")),
        "the edit was not noticed at all: {:#?}",
        report.findings
    );
    assert!(
        !report.sound.contains(&out.run_id),
        "a run with an edited record was reported sound — there is no leaf to \
         catch it for an open run, so the per-record findings must"
    );
}

// ── The case layer crosses the boundary ─────────────────────────────────────
//
// A restore of the journal alone rebuilds every index the journal owns and no
// case rows, because case state is not derivable from records. The export
// therefore carries the case layer, the verifier holds the two halves to each
// other — a record stamped with a case the file does not carry is a finding —
// and the restore rebuilds the rows so the matter is queryable again.

/// **The drill.** A matter with an obligation and an artifact round-trips:
/// export, verify, restore into a fresh store, and every read path answers.
#[tokio::test]
async fn the_case_layer_survives_export_and_restore() {
    use agentplane::case::CaseStore;
    use agentplane::core::{CaseStatus, CorrelationKey, DeadlineState, Digest, Timestamp};

    let origin = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&origin) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&origin) as Arc<dyn agentplane::case::CaseStore>)
        .skill(Trivial)
        .build();
    let keys = [CorrelationKey::new("document", "DOC-77")];
    let out = rt
        .run_correlated("demo.trivial", Tainted::trusted(json!(1)), "matter", &keys)
        .await
        .expect("run");
    let case_id = (Arc::clone(&origin) as Arc<dyn CaseStore>)
        .correlate(&keys)
        .await
        .expect("correlate")
        .expect("case exists");
    let at = Timestamp::from_unix_timestamp(1_800_000_000).expect("instant");
    let cases: Arc<dyn CaseStore> = Arc::clone(&origin) as Arc<dyn CaseStore>;
    cases
        .register_deadline(&agentplane::core::Deadline {
            case: case_id,
            name: "respond-by".to_owned(),
            resolved_at: at,
            calendar_digest: Digest::of(b"cal"),
            warn_at: None,
            state: DeadlineState::Pending,
        })
        .await
        .expect("deadline");
    cases
        .link_blob(case_id, Digest::of(b"artifact"), at)
        .await
        .expect("blob link");

    let store: Arc<dyn JournalStore> = origin;
    let mut bytes = Vec::new();
    let trailer = agentplane::export::to_jsonl(&store, Some(&cases), &[out.run_id], &mut bytes)
        .await
        .expect("export");
    assert_eq!(trailer.cases, 1, "the matter travelled");

    // The file alone: sound, and the two halves cover each other.
    let verified =
        agentplane::export::verify(std::io::Cursor::new(&bytes), None, None).expect("verify");
    assert!(
        verified.is_sound(),
        "the export does not verify: {:#?}",
        verified.findings
    );
    assert_eq!(verified.cases, 1);
    assert!(
        verified
            .not_checked
            .iter()
            .any(|n| n.contains("blob bytes")),
        "an offline pass cannot check blob presence and must say so: {:#?}",
        verified.not_checked
    );

    // A fresh plane, rebuilt from the file.
    let fresh = Arc::new(RedbStore::open_in_memory().expect("store"));
    let fresh_journal: Arc<dyn JournalStore> = Arc::clone(&fresh) as Arc<dyn JournalStore>;
    let fresh_cases: Arc<dyn CaseStore> = fresh as Arc<dyn CaseStore>;
    let report = agentplane::export::from_jsonl(
        &fresh_journal,
        Some(&fresh_cases),
        std::io::Cursor::new(&bytes),
    )
    .await
    .expect("restore");
    assert!(report.is_faithful(), "journal roots differ");
    assert_eq!(report.cases, 1);

    // Every read path answers about the restored matter.
    let restored = fresh_cases
        .case(case_id)
        .await
        .expect("read")
        .expect("the case is back");
    assert_eq!(restored.kind, "matter");
    assert_eq!(restored.status, CaseStatus::Open);
    assert_eq!(restored.runs, vec![out.run_id]);
    assert_eq!(
        fresh_cases.correlate(&keys).await.expect("correlate"),
        Some(case_id),
        "the next message about this matter must attach, not open a duplicate"
    );
    let deadlines = fresh_cases.deadlines(case_id).await.expect("deadlines");
    assert_eq!(deadlines.len(), 1);
    assert_eq!(deadlines[0].name, "respond-by");
    assert!(
        fresh_cases
            .blobs_of(case_id)
            .await
            .expect("blobs")
            .contains(&Digest::of(b"artifact")),
        "erasure can no longer find the artifact from the case that names it"
    );
}

/// A matter the journal names, missing from the case layer, is a finding.
///
/// The per-run chains, the leaves and the Merkle root all still verify — the
/// case layer is beside the journal, not inside it — so only the coverage
/// cross-check notices. Without it, dropping every case line produces a file
/// that reads as a complete, sound export of a plane that simply had no cases.
#[tokio::test]
async fn a_dropped_case_layer_is_a_finding_not_a_quiet_file() {
    use agentplane::case::CaseStore;
    use agentplane::core::CorrelationKey;

    let origin = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&origin) as Arc<dyn JournalStore>)
        .cases(Arc::clone(&origin) as Arc<dyn CaseStore>)
        .skill(Trivial)
        .build();
    let out = rt
        .run_correlated(
            "demo.trivial",
            Tainted::trusted(json!(1)),
            "matter",
            &[CorrelationKey::new("document", "DOC-88")],
        )
        .await
        .expect("run");

    let cases: Arc<dyn CaseStore> = Arc::clone(&origin) as Arc<dyn CaseStore>;
    let store: Arc<dyn JournalStore> = origin;
    let mut bytes = Vec::new();
    agentplane::export::to_jsonl(&store, Some(&cases), &[out.run_id], &mut bytes)
        .await
        .expect("export");

    let text = String::from_utf8(bytes).expect("utf8");
    let dropped: String = text
        .lines()
        .filter(|l| !l.contains("agentplane.export.case"))
        .fold(String::new(), |mut s, l| {
            s.push_str(l);
            s.push('\n');
            s
        });
    assert_ne!(text, dropped, "the fixture removed nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(dropped.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("case layer was cut")),
        "a file stripped of its case layer read as complete: {report:#?}"
    );
    assert!(!report.is_sound(), "a stripped export still reported sound");
}

/// An export taken through a sealed journal carries ciphertext, not plaintext.
///
/// `SealedJournal::read` hands records back *opened* — the runtime's own steps
/// must read what they wrote — so an export that copied the opened `body` into
/// the file would quietly undo erasure: destroying the wrapping key no longer
/// reaches the copy somebody exported last month. The export therefore derives
/// its display copy from the wire bytes the chain hashed. Three assertions,
/// each a distinct failure mode: the caller's payload is absent from the file,
/// the verifier raises no false tamper finding over the honest sealed export,
/// and the sealed body still matches its own wire bytes by construction.
#[cfg(feature = "keyring")]
#[tokio::test]
async fn a_sealed_journals_export_carries_no_plaintext() {
    use agentplane::keyring::KeyRing;
    use agentplane::testkit::MemoryKeyRing;

    let secret = "SECRET-PAYLOAD-73";
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let ring = Arc::new(MemoryKeyRing::new());
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .keyring(Arc::clone(&ring) as Arc<dyn KeyRing>)
        .skill(Trivial)
        .build();
    let out = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": secret })))
        .await
        .expect("run");

    // Through the runtime's own handle — the sealed decorator, which is the
    // natural wiring an embedder reaches for and the one that used to leak.
    let mut file = Vec::new();
    agentplane::export::to_jsonl(rt.journal(), None, &[out.run_id], &mut file)
        .await
        .expect("export");
    let text = String::from_utf8(file).expect("utf8");

    assert!(
        !text.contains(secret),
        "the export of a sealed journal carries the caller's plaintext — \
         erasure no longer reaches the exported copy"
    );
    // The positive half: the payload genuinely crossed the run, so its absence
    // above is sealing, not the fixture never writing it.
    let opened = rt
        .journal()
        .read(out.run_id, 1)
        .await
        .expect("read through the ring");
    let opened_text = serde_json::to_string(&opened.iter().map(|r| &r.body).collect::<Vec<_>>())
        .expect("serialize");
    assert!(
        opened_text.contains(secret),
        "the payload never reached the journal — the absence assertion above \
         is measuring the fixture"
    );

    let report = agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report.is_sound(),
        "an honest sealed export raised findings — the display copy and the \
         wire bytes disagree: {:#?}",
        report.findings
    );
}

// ── The trailer's accounting, held to the file ──────────────────────────────
//
// Only the trailer's `cases` count used to be read back; `runs_requested`,
// `runs_exported`, `records` and `unreadable` were written by the exporter
// and consulted by nobody, so a file edited under an intact trailer verified
// clean wherever no chain link or leaf happened to notice. These tests pin
// the settlement that closed that: counts compared, honest unreadability
// routed to `not_checked`, and an empty run block never sound.

/// Build an **open** run by appending records and never sealing — the shape
/// whose tail no Merkle leaf pins, so the trailer's counts are the only
/// witness left when lines go missing.
async fn open_run_export() -> (agentplane::core::RunId, String) {
    use agentplane::journal::RecordKind;

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let run = agentplane::core::RunId::generate();
    for skill in ["first", "second", "third"] {
        store
            .append(
                1,
                vec![Append::new(
                    run,
                    RecordKind::StepStarted {
                        skill: skill.to_owned(),
                    },
                )],
            )
            .await
            .expect("append");
    }
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");
    (run, String::from_utf8(out).expect("utf8"))
}

/// **Deleting an open run's tail record is caught by the trailer's count.**
///
/// The quiet edit this settlement exists for: an open run has no leaf, a
/// chain prefix verifies, and the sequence stays contiguous when only the
/// tail is gone — so before the counts were compared, this file verified
/// clean with a record missing. The trailer is the writer's own tally, and
/// the only line left that knows how long the run was.
#[tokio::test]
async fn a_deleted_tail_record_fails_the_trailer_accounting() {
    let (_, text) = open_run_export().await;

    // The positive half first: the untouched file verifies.
    let clean = agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, None)
        .expect("verify");
    assert!(clean.is_sound(), "{:#?}", clean.findings);

    // Remove the last record line — the tail cut, on a line boundary.
    let lines: Vec<&str> = text.lines().collect();
    let is_record =
        |l: &str| serde_json::from_str::<Value>(l).is_ok_and(|v| v.get("kind").is_none());
    let last_record = lines
        .iter()
        .rposition(|l| is_record(l))
        .expect("the fixture exported records");
    let cut: String = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != last_record)
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(cut, text, "the fixture removed nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(cut.as_bytes()), None, None)
        .expect("verify");
    assert!(
        !report.is_sound(),
        "an open run's tail record was deleted and the export verified clean — \
         no leaf pins an open run, so only the trailer's count can notice"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("record lines were removed")),
        "the deletion was noticed for the wrong reason: {:#?}",
        report.findings
    );
}

/// **A run block with no records is never sound.**
///
/// Empty every record out of a run and, before this, the block sailed
/// through: an open run has no leaf to disagree with, `clean` stayed true
/// over zero checks, and the run landed in `sound` — an export vouching for
/// a history it does not contain. An empty block the trailer does not
/// declare unreadable has no honest producer, because the exporter files an
/// empty or failed read in the trailer instead.
#[tokio::test]
async fn a_run_block_with_no_records_is_never_sound() {
    let (run, text) = open_run_export().await;

    let stripped: String = text
        .lines()
        .filter(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v.get("kind").is_some()))
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(stripped, text, "the fixture removed nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(stripped.as_bytes()), None, None)
        .expect("verify");
    assert!(
        !report.sound.contains(&run),
        "a run block with zero records under it was reported sound — the \
         verifier vouched for records it never saw"
    );
    assert!(!report.is_sound(), "{report:#?}");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("carries no records")),
        "the emptied block was not named: {:#?}",
        report.findings
    );
}

/// **A run the export declares unreadable is unchecked, not tampering.**
///
/// The exporter's honesty must not read as an incident: a run it could not
/// read is named in the trailer, its block carries the log position and
/// nothing else, and the verifier used to meet that shape with "the log's
/// leaf is not this run's terminal hash" — a tamper finding over a run the
/// file explicitly says it does not contain. Honest omission routes to
/// `not_checked`; the tamper finding is reserved for an empty block the
/// trailer does *not* declare, which no honest writer produces.
#[cfg(feature = "testkit")]
#[tokio::test]
async fn a_declared_unreadable_run_is_unchecked_not_a_tamper_finding() {
    use agentplane::testkit::faults::{Faulty, Schedule};

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let healthy = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 1 })))
        .await
        .expect("run")
        .run_id;
    let damaged = rt
        .run("demo.trivial", Tainted::trusted(json!({ "n": 2 })))
        .await
        .expect("run")
        .run_id;

    let faulty: Arc<dyn JournalStore> = Arc::new(Faulty::new(
        Arc::clone(&store) as Arc<dyn JournalStore>,
        Schedule::healthy().unreadable(damaged),
    ));
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&faulty, None, &[healthy, damaged], &mut out)
        .await
        .expect("export");

    let report =
        agentplane::export::verify(std::io::Cursor::new(&out), None, None).expect("verify");
    assert!(
        report.is_sound(),
        "an honestly-declared unreadable run was reported as tampering — an \
         auditor paged over the exporter's own honesty: {:#?}",
        report.findings
    );
    assert!(
        report.sound.contains(&healthy),
        "the healthy run stopped verifying: {report:#?}"
    );
    assert!(
        !report.sound.contains(&damaged),
        "a run whose records are not in the file was vouched for"
    );
    assert!(
        report
            .not_checked
            .iter()
            .any(|n| n.contains(&damaged.to_string()) && n.contains("unreadable")),
        "the unreadable run is not reported as unchecked, so its absence from \
         `sound` is silence rather than a statement: {:#?}",
        report.not_checked
    );
}

/// **A foreign canonicalization rule narrows coverage; it is not a finding.**
///
/// Nothing the offline pass checks depends on the rule: the chain rehash,
/// leaf, root and signature checks hash the wire bytes as written and never
/// re-canonicalize, and the counts and body-vs-wire comparisons have no rule
/// in them at all. What a foreign rule removes is re-deriving digests inside
/// the bodies — which this pass never does. Filing the mismatch as a finding
/// made an honest cross-build export read as tampered; and worse, the old
/// gate implied the *other* checks stopped meaning anything, which they do
/// not — proven here by catching a real edit under the foreign rule.
#[tokio::test]
async fn a_foreign_canon_rule_is_narrowed_coverage_not_a_finding() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");

    // Rewrite only the header's canon field. Record bodies journal the canon
    // version too, so a blanket replace would edit hashed bytes and this test
    // would measure its own corruption.
    let text = String::from_utf8(out).expect("utf8");
    let foreign: String = text
        .lines()
        .map(|line| {
            if serde_json::from_str::<Value>(line)
                .is_ok_and(|v| v.get("kind") == Some(&json!("agentplane.export")))
            {
                line.replace(
                    &format!("\"canon\":{}", agentplane::core::canon::VERSION),
                    "\"canon\":999",
                )
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(foreign, text, "the fixture edited nothing");

    let report = agentplane::export::verify(std::io::Cursor::new(foreign.as_bytes()), None, None)
        .expect("verify");
    assert!(
        report.is_sound(),
        "an honest export written under another canonicalization rule was \
         reported as tampered — unverifiable and wrong are different \
         sentences: {:#?}",
        report.findings
    );
    assert!(
        report
            .not_checked
            .iter()
            .any(|n| n.contains("canonicalization rule")),
        "the narrowed coverage is not stated: {:#?}",
        report.not_checked
    );

    // The checks that do run under a foreign rule still catch a real edit —
    // the half that proves the gate was scoped rather than moved.
    let edited = foreign
        .replace("\\\"n\\\":1", "\\\"n\\\":9")
        .replace("\"n\":1", "\"n\":9");
    assert_ne!(edited, foreign, "the fixture edited nothing");
    let caught = agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None, None)
        .expect("verify");
    assert!(
        caught
            .findings
            .iter()
            .any(|f| f.contains("does not recompute")),
        "under a foreign canon rule the rehash stopped running — the rule \
         gates digest re-derivation, not hashing bytes as written: {:#?}",
        caught.findings
    );
}

/// **A sealing record claiming a foreign head is caught offline.**
///
/// The live audit holds `RunSealed.chain_head` to the chain it sits in; an
/// auditor working from the file alone deserves the same check, because the
/// forgery it catches — a conclusion composed against a different history
/// and appended to this one — leaves every hash, leaf and root verifying:
/// the chain is honest about the bytes, and only the claim inside them lies.
#[tokio::test]
async fn a_sealing_record_claiming_a_foreign_head_is_caught_offline() {
    use agentplane::core::Label;
    use agentplane::journal::RecordKind;

    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let run = agentplane::core::RunId::generate();
    let lease = store
        .acquire(run, "test", Duration::from_secs(60))
        .await
        .expect("lease");
    store
        .append(
            lease.epoch,
            vec![
                Append::new(
                    run,
                    RecordKind::RunAdmitted {
                        capability: "demo".into(),
                        governed_by: None,
                        input_label: Label::trusted(),
                        input: json!({}),
                        policy_bundle: None,
                        canon: agentplane::core::canon::VERSION,
                        idempotency_key: None,
                    },
                ),
                Append::new(
                    run,
                    RecordKind::RunSealed {
                        outcome: "succeeded".into(),
                        // Not the head this conclusion sits on.
                        chain_head: Digest::of(b"some other history"),
                        reason: None,
                    },
                ),
            ],
        )
        .await
        .expect("append");
    store
        .seal(run, lease.epoch, "succeeded")
        .await
        .expect("seal");

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");
    let report =
        agentplane::export::verify(std::io::Cursor::new(&out), None, None).expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("chain head")),
        "a conclusion drawn over a different history verified offline — the \
         live audit catches this and the file reader waved it through: {:#?}",
        report.findings
    );
    assert!(
        !report.sound.contains(&run),
        "the run carrying the lying conclusion was reported sound"
    );

    // The positive half: an honest run raises no such finding.
    let (honest_store, honest_run) = one_run().await;
    let mut honest = Vec::new();
    agentplane::export::to_jsonl(&honest_store, None, &[honest_run], &mut honest)
        .await
        .expect("export");
    let clean =
        agentplane::export::verify(std::io::Cursor::new(&honest), None, None).expect("verify");
    assert!(
        !clean.findings.iter().any(|f| f.contains("chain head")),
        "an honest sealing record was flagged: {:#?}",
        clean.findings
    );
}

// ── The restore refuses what it cannot faithfully replay ────────────────────

/// **A truncated export does not restore.**
///
/// A cut file is a valid prefix — every line parses, every chain joins — and
/// a restore that replayed it would rebuild a partial history shaped exactly
/// like a whole one. The quietest cut is the worst: everything after the last
/// record but before the trailer is the case layer, so the journal restores
/// byte-perfect and every matter it names is silently gone. The frame is the
/// completeness signal, and the restore must demand it.
#[tokio::test]
async fn a_truncated_export_refuses_to_restore() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");
    let text = String::from_utf8(out).expect("utf8");

    let lines: Vec<&str> = text.lines().collect();
    let cut = lines[..lines.len() - 1].join("\n");
    assert!(
        lines
            .last()
            .expect("lines")
            .contains("agentplane.export.end"),
        "the fixture did not cut the trailer, so this test would measure itself"
    );

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused =
        agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(cut.as_bytes())).await;
    let Err(e) = refused else {
        panic!("a truncated export restored as a whole history");
    };
    assert!(
        e.to_string().contains("cut short"),
        "the refusal does not name the truncation: {e}"
    );

    // The positive half: the whole file restores.
    let ok = agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(text.as_bytes()))
        .await
        .expect("restore");
    assert!(ok.is_faithful(), "the untouched export did not restore");
}

/// **A record line without wire bytes does not restore from its display copy.**
///
/// `raw` is the bytes the chain hashed; `body` is a courtesy copy anyone can
/// edit. A restore that quietly fell back to the copy when `raw` was missing
/// rebuilt whatever the readable half said — the exact value the wire-bytes
/// rule exists to keep out of a rebuilt history, substituted silently on the
/// one field two mechanisms must agree about — and the verify pass after the
/// restore would then bless the result, because the rebuilt store re-hashes
/// what it was fed.
#[tokio::test]
async fn a_record_line_without_wire_bytes_refuses_to_restore() {
    let (store, run) = one_run().await;
    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &[run], &mut out)
        .await
        .expect("export");
    let text = String::from_utf8(out).expect("utf8");

    // Strip `raw` from every record line, leaving the display copies intact —
    // the file a fallback-shaped restore would happily rebuild from.
    let mut stripped_any = false;
    let stripped: String = text
        .lines()
        .map(|line| {
            let mut v: Value = serde_json::from_str(line).expect("line json");
            if v.get("kind").is_none()
                && let Some(obj) = v.as_object_mut()
                && obj.remove("raw").is_some()
            {
                stripped_any = true;
                return serde_json::to_string(&v).expect("line json");
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(stripped_any, "the fixture stripped nothing");

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused =
        agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(stripped.as_bytes()))
            .await;
    let Err(e) = refused else {
        panic!("a record with no wire bytes restored from its editable display copy");
    };
    assert!(
        e.to_string().contains("wire bytes"),
        "the refusal does not name the missing wire bytes: {e}"
    );
}

/// **A rebuilt root compared with the file's own header proves nothing.**
///
/// `a_run_removed_from_the_middle_is_caught_by_the_rebuilt_root` removes a run
/// and leaves the header alone, which the rebuild catches. An editor who is
/// paying attention does not leave the header alone. The header carries the
/// size and the root, both in the same file, both under the same editor's
/// hand — so the check that "the tree matches the checkpoint" was, on its own,
/// a check that the file agrees with itself.
///
/// This crate already makes that argument one level down: a record's
/// `prev_hash` is verified by rehashing the wire bytes, explicitly *not* by
/// comparing it with the previous line, because agreement between two lines of
/// one file is what a competent editor achieves. The same sentence is true of
/// the checkpoint, and it was not being applied.
///
/// So the rebuild is held to a checkpoint from **outside** the file, and a
/// pass without one says plainly that deletion went unchecked rather than
/// reporting sound.
#[tokio::test]
async fn an_export_with_a_rewritten_header_needs_an_outside_checkpoint() {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .skill(Trivial)
        .build();
    let mut runs = Vec::new();
    for n in 0..3 {
        runs.push(
            rt.run("demo.trivial", Tainted::trusted(json!({ "n": n })))
                .await
                .expect("run")
                .run_id,
        );
    }
    let store: Arc<dyn JournalStore> = store;
    let genuine = store.checkpoint().await.expect("checkpoint");

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&store, None, &runs, &mut out)
        .await
        .expect("export");
    let text = String::from_utf8(out).expect("utf8");

    // What a careful editor produces: the last run gone, and the header and
    // trailer rewritten to describe the shorter log. This is the file that used
    // to verify clean.
    let edited = deleted_tail(&text, &as_written(runs[2]), &genuine);
    assert_ne!(edited, text, "the fixture edited nothing");

    // Without an outside checkpoint the file is internally perfect, and the
    // report must not call that sound-with-nothing-to-say.
    let blind = agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None, None)
        .expect("verify");
    assert!(
        blind.findings.is_empty(),
        "the edited file is internally consistent by construction; a finding here means \
         the fixture broke something else: {:#?}",
        blind.findings
    );
    assert!(
        blind.not_checked.iter().any(|n| n.starts_with("deletion")),
        "a pass with no outside checkpoint rebuilt the root against the header the same \
         editor wrote, and did not say so: {:#?}",
        blind.not_checked
    );

    // With the checkpoint an auditor was actually given, the deletion is a
    // finding — and it names the discrepancy rather than only the root.
    let checked = agentplane::export::verify(
        std::io::Cursor::new(edited.as_bytes()),
        None,
        Some(&genuine),
    )
    .expect("verify");
    assert!(
        !checked.is_sound(),
        "a run was deleted and the header rewritten to match, and the pass holding the \
         real checkpoint reported sound"
    );
    assert!(
        checked
            .findings
            .iter()
            .any(|f| f.contains("different history than the one it is being checked against")),
        "the mismatch between the header and the checkpoint the auditor holds must be \
         named, or a reader sees only a root that differs and cannot tell which side \
         moved: {:#?}",
        checked.findings
    );
    assert!(
        !checked
            .not_checked
            .iter()
            .any(|n| n.starts_with("deletion")),
        "deletion was reported unchecked even though a checkpoint was supplied"
    );

    // And the honest file, against the real checkpoint, still passes — or this
    // is a verifier that refuses everything.
    let honest =
        agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None, Some(&genuine))
            .expect("verify");
    assert!(
        honest.is_sound(),
        "the unedited export failed against its own genuine checkpoint: {honest:#?}"
    );
}

/// The seal of the run at log position `index`, read out of an export's own
/// run blocks — so the fixture above rebuilds the tree from the file rather
/// than from a second copy of the runtime's arithmetic.
fn store_seal(text: &str, index: u64) -> agentplane::core::Digest {
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("kind").and_then(serde_json::Value::as_str) != Some("agentplane.export.run") {
            continue;
        }
        if v.get("index").and_then(serde_json::Value::as_u64) != Some(index) {
            continue;
        }
        let hex = v
            .get("seal")
            .and_then(serde_json::Value::as_str)
            .expect("a sealed run block carries its seal");
        return agentplane::core::Digest::from_hex(hex).expect("a seal is a digest");
    }
    panic!("no run block at log position {index}");
}

/// Remove the last run block from an export and rewrite the header and trailer
/// to match, leaving a file that is internally perfect in every respect.
///
/// Its own function because the point of the test using it is what the *reader*
/// can conclude, and forty lines of JSON surgery in the middle of that argument
/// obscures it.
fn deleted_tail(text: &str, victim: &str, genuine: &agentplane::journal::Checkpoint) -> String {
    let mut kept: Vec<String> = Vec::new();
    let mut skipping = false;
    for line in text.lines() {
        if line.contains("agentplane.export.run") {
            skipping = line.contains(victim);
        }
        // The trailer ends every block, or the excision swallows the frame and
        // the file reads as truncated rather than as edited — a different
        // finding, and not the one under test.
        if line.contains("agentplane.export.end") {
            skipping = false;
        }
        if !skipping {
            kept.push(line.to_owned());
        }
    }
    assert!(text.contains(victim), "the fixture removed nothing");

    // The trailer counts runs and records, so leaving it alone would raise a
    // count finding instead of the silence this is meant to produce.
    let last = kept.len() - 1;
    let mut trailer: serde_json::Value = serde_json::from_str(&kept[last]).expect("trailer");
    // A record line is the one with no `kind`: header, run, case and trailer
    // lines all name themselves and records do not.
    let is_record = |l: &str| {
        serde_json::from_str::<serde_json::Value>(l)
            .ok()
            .is_some_and(|v| v.get("kind").is_none())
    };
    let dropped = text.lines().filter(|l| is_record(l)).count()
        - kept.iter().filter(|l| is_record(l)).count();
    assert!(dropped > 0, "the fixture removed no records");
    for (field, by) in [
        ("runs_requested", 1usize),
        ("runs_exported", 1),
        ("records", dropped),
    ] {
        if let Some(n) = trailer.get(field).and_then(serde_json::Value::as_u64) {
            trailer[field] = serde_json::json!(n - by as u64);
        }
    }
    kept[last] = serde_json::to_string(&trailer).expect("json");

    // And the header, rewritten to the log the shortened file actually is.
    let truncated = agentplane::journal::Checkpoint {
        origin: genuine.origin.clone(),
        size: 2,
        root: agentplane::core::merkle::root(
            &[0u64, 1]
                .iter()
                .map(|i| agentplane::core::merkle::leaf_hash(&store_seal(text, *i)))
                .collect::<Vec<_>>(),
        ),
    };
    kept[0] = kept[0].replace(
        &serde_json::to_string(genuine).expect("json"),
        &serde_json::to_string(&truncated).expect("json"),
    );
    kept.join("\n")
}
