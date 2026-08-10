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
    let trailer = agentplane::export::to_jsonl(&store, &[run], &mut out)
        .await
        .expect("export");

    let lines = lines(&out);
    assert!(lines.len() > 2, "an export with no records: {lines:#?}");

    let header = &lines[0];
    assert_eq!(header["kind"], "agentplane.export");
    assert_eq!(
        header["version"], 1,
        "the format version is what a reader pins; it must not be absent"
    );
    assert_eq!(
        header["canon"],
        agentplane::core::canon::VERSION,
        "a digest without the rule that computed it is unverifiable, and the \
         rule has already changed once"
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
    agentplane::export::to_jsonl(&store, &[run], &mut whole)
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
    let trailer = agentplane::export::to_jsonl(&faulty, &[healthy, damaged], &mut out)
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
    agentplane::export::to_jsonl(&store, &runs, &mut out)
        .await
        .expect("export");

    let report = agentplane::export::verify(std::io::Cursor::new(&out), None).expect("verify");
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
    agentplane::export::to_jsonl(&store, &runs, &mut out)
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

    let report =
        agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None).expect("verify");
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
    agentplane::export::to_jsonl(&store, &[run], &mut out)
        .await
        .expect("export");

    // Change a journaled payload without touching any hash — the edit an
    // operator with write access to the file would make. The run's *input* is
    // in the record; the skill's output is not, which is why this greps for a
    // value the export demonstrably contains rather than one it seemed like it
    // should.
    let original = String::from_utf8(out).expect("utf8");
    let text = original.replace("\"n\":1", "\"n\":9");
    assert_ne!(
        original, text,
        "the fixture edited nothing, so this test would pass against a verifier \
         that checks no hashes at all"
    );

    let report =
        agentplane::export::verify(std::io::Cursor::new(text.as_bytes()), None).expect("verify");
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

/// **A restored store commits to exactly the history the export did.**
///
/// The result is one comparison: equal Merkle roots at equal size. That is a far
/// stronger statement than "the rows loaded" — it means every record, in every
/// run, in the order the log recorded them, rebuilt to the same commitment. A
/// restore that got any of the three wrong produces a different root and says so.
///
/// It also exercises the reason this replays `append` rather than writing rows.
/// `append` maintains six derived indexes, and a restore that rebuilt five would
/// leave a store that reads perfectly until somebody queries the sixth — so the
/// assertions below go back through the *query* surfaces rather than only the
/// checkpoint.
#[tokio::test]
async fn a_restored_store_rebuilds_the_same_checkpoint() {
    let origin = Arc::new(RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(Arc::clone(&origin) as Arc<dyn JournalStore>)
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
    let origin: Arc<dyn JournalStore> = origin;
    let before = origin.checkpoint().await.expect("checkpoint");

    let mut out = Vec::new();
    agentplane::export::to_jsonl(&origin, &runs, &mut out)
        .await
        .expect("export");

    // A different store, with nothing in it.
    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let report = agentplane::export::from_jsonl(&fresh, std::io::Cursor::new(&out))
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

    // A derived index, queried the way a caller would. The checkpoint says
    // nothing about these, which is exactly why a restore that wrote rows
    // directly could pass everything above and still be broken.
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
    agentplane::export::to_jsonl(&fresh, &runs, &mut again)
        .await
        .expect("re-export");
    let verified = agentplane::export::verify(std::io::Cursor::new(&again), None).expect("verify");
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
    agentplane::export::to_jsonl(&origin, &[run], &mut out)
        .await
        .expect("export");

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let report = agentplane::export::from_jsonl(&fresh, std::io::Cursor::new(&out))
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
    agentplane::export::to_jsonl(&store, &[run], &mut out)
        .await
        .expect("export");

    let original = String::from_utf8(out).expect("utf8");
    let foreign = original.replace("\"version\":1", "\"version\":2");
    assert_ne!(
        original, foreign,
        "the fixture edited nothing, so this test would pass against a reader \
         that never looks at the version"
    );

    let report =
        agentplane::export::verify(std::io::Cursor::new(foreign.as_bytes()), None).expect("verify");
    assert!(
        report.findings.iter().any(|f| f.contains("format version")),
        "a future format was verified without saying this build cannot read it: {:#?}",
        report.findings
    );

    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused =
        agentplane::export::from_jsonl(&fresh, std::io::Cursor::new(foreign.as_bytes())).await;
    let Err(e) = refused else {
        panic!("a restore rebuilt a format it cannot fully parse");
    };
    assert!(
        e.to_string().contains("format version"),
        "the refusal does not name the version mismatch: {e}"
    );

    // The positive half: the same file under its own version restores.
    let ok = agentplane::export::from_jsonl(&fresh, std::io::Cursor::new(original.as_bytes()))
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
    agentplane::export::to_jsonl(&store, &[run], &mut out)
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

    let report = agentplane::export::verify(std::io::Cursor::new(relabelled.as_bytes()), None)
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
    agentplane::export::to_jsonl(&store, &runs, &mut out)
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

    let report =
        agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None).expect("verify");
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
    agentplane::export::to_jsonl(&stale, &[first, late], &mut out)
        .await
        .expect("export");

    let report = agentplane::export::verify(std::io::Cursor::new(&out), None).expect("verify");
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
    agentplane::export::to_jsonl(&store, &[out.run_id], &mut bytes)
        .await
        .expect("export");

    // The untouched export lists the open run sound — the positive half, so
    // the assertion below is about the edit rather than about open runs.
    let clean = agentplane::export::verify(std::io::Cursor::new(&bytes), None).expect("verify");
    assert!(
        clean.sound.contains(&out.run_id),
        "an untouched open run did not verify: {:#?}",
        clean.findings
    );

    let original = String::from_utf8(bytes).expect("utf8");
    let edited = original.replace("\"n\":1", "\"n\":9");
    assert_ne!(original, edited, "the fixture edited nothing");

    let report =
        agentplane::export::verify(std::io::Cursor::new(edited.as_bytes()), None).expect("verify");
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
