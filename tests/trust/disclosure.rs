//! One matter out of the plane: a disclosure package, the readers that take
//! it, the ones that refuse it, and the act that records it.

#![cfg(feature = "redb")]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use agentplane::case::CaseStore;
use agentplane::core::{
    CaseId, CorrelationKey, Outcome, RunId, Skill, SkillDescriptor, SkillError, Tainted,
};
use agentplane::export::{Selection, VerifyReport};
use agentplane::journal::{Anchor, Checkpoint, JournalStore};
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
        _cx: &mut StepCtx<'_>,
        input: Tainted<Value>,
    ) -> Result<Outcome, SkillError> {
        Ok(Outcome::done(input))
    }
}

/// A plane holding two matters and a run that belongs to neither.
pub(crate) struct Plane {
    pub(crate) journal: Arc<dyn JournalStore>,
    pub(crate) cases: Arc<dyn CaseStore>,
    pub(crate) register: Arc<dyn agentplane::disclosure::DisclosureRegister>,
    pub(crate) a: CaseId,
    pub(crate) a_runs: Vec<RunId>,
    pub(crate) b: CaseId,
    pub(crate) loose: RunId,
}

pub(crate) async fn two_matters() -> Plane {
    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let rt = Runtime::builder(Arc::clone(&journal))
        .cases(Arc::clone(&cases))
        .skill(Trivial)
        .build();
    let a_keys = [CorrelationKey::new("document", "DOC-A")];
    let b_keys = [CorrelationKey::new("document", "DOC-B")];
    let mut a_runs = Vec::new();
    for n in 0..2 {
        let out = rt
            .run_correlated(
                "demo.trivial",
                Tainted::trusted(json!(n)),
                "matter",
                &a_keys,
            )
            .await
            .expect("run");
        a_runs.push(out.run_id);
        rt.run_correlated(
            "demo.trivial",
            Tainted::trusted(json!(n)),
            "matter",
            &b_keys,
        )
        .await
        .expect("run");
    }
    let loose = rt
        .run("demo.trivial", Tainted::trusted(json!("loose")))
        .await
        .expect("run")
        .run_id;
    let a = cases
        .correlate(&a_keys)
        .await
        .expect("correlate")
        .expect("case A");
    let b = cases
        .correlate(&b_keys)
        .await
        .expect("correlate")
        .expect("case B");
    Plane {
        journal,
        cases,
        register: store,
        a,
        a_runs,
        b,
        loose,
    }
}

pub(crate) async fn package(plane: &Plane, selection: &Selection) -> Vec<u8> {
    let mut bytes = Vec::new();
    agentplane::export::package_to_jsonl(&plane.journal, &plane.cases, selection, &mut bytes)
        .await
        .expect("package");
    bytes
}

fn of_case(case: CaseId) -> Selection {
    Selection {
        cases: vec![case],
        runs: Vec::new(),
    }
}

fn verified(bytes: &[u8], anchors: &[Anchor]) -> VerifyReport {
    agentplane::export::verify(std::io::Cursor::new(bytes), None, anchors).expect("verify")
}

fn outside(checkpoint: Checkpoint) -> Anchor {
    Anchor {
        checkpoint,
        obtained_from: "the plane's published checkpoint".to_owned(),
        witnessed: Vec::new(),
    }
}

/// `bytes` with each JSON line passed through `edit`.
fn edited(bytes: &[u8], mut edit: impl FnMut(&mut Value)) -> Vec<u8> {
    let mut out = String::new();
    for line in std::str::from_utf8(bytes).expect("utf-8").lines() {
        let mut value: Value = serde_json::from_str(line).expect("a JSON line");
        edit(&mut value);
        out.push_str(&serde_json::to_string(&value).expect("serialise"));
        out.push('\n');
    }
    out.into_bytes()
}

/// The second reader over `bytes` with `args` after the file: its exit status
/// and what it printed.
fn second_reader(bytes: &[u8], args: &[String]) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!(
        "agentplane-disclosure-{}-{}",
        std::process::id(),
        RunId::generate()
    ));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("package.jsonl");
    std::fs::write(&path, bytes).expect("write");
    let out = std::process::Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg("tools/verify_export.py")
        .arg(&path)
        .args(args)
        .output()
        .expect("python3 runs the second reader");
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// **One matter verifies sound, in both readers, against a checkpoint from
/// outside the file — and the file says it is selective.**
#[tokio::test]
async fn one_matter_verifies_sound_against_an_outside_anchor() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let published = plane.journal.checkpoint().await.expect("checkpoint");
    assert_eq!(published.size, 5, "every run of the plane is a leaf");

    let report = verified(&bytes, &[outside(published.clone())]);
    assert!(report.is_sound(), "{report:#?}");
    let mut sound = report.sound.clone();
    sound.sort();
    let mut expected = plane.a_runs.clone();
    expected.sort();
    assert_eq!(sound, expected, "exactly the matter's runs are sound");
    assert_eq!(report.selection, Some(of_case(plane.a)));
    assert!(
        report
            .not_checked
            .iter()
            .any(|n| n.contains("disclosure package") && n.contains("proves 2")),
        "the report must say the rest of the log was not disclosed: {:#?}",
        report.not_checked
    );

    let anchor = format!("{}:{}", published.size, published.root.to_hex());
    let (status, said) = second_reader(&bytes, &[anchor]);
    assert_eq!(status, Some(0), "{said}");
    assert!(said.contains("disclosure package"), "{said}");
}

/// **A leaf the path does not prove is not sound** — the chain, seal and
/// header all agree, and only the path is wrong.
#[tokio::test]
async fn a_package_with_a_damaged_path_is_not_sound() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let mut damaged_run = None;
    let damaged = edited(&bytes, |line| {
        if damaged_run.is_none()
            && let Some(first) = line.get_mut("proof").and_then(|p| p.get_mut(0))
        {
            let mut hex = first.as_str().expect("hex").to_owned();
            let flipped = if hex.ends_with('0') { '1' } else { '0' };
            hex.pop();
            hex.push(flipped);
            *first = Value::String(hex);
            damaged_run = line["run"].as_str().map(str::to_owned);
        }
    });
    let damaged_run = RunId::parse(&damaged_run.expect("a run with a path")).expect("a run id");

    let report = verified(&damaged, &[]);
    assert!(!report.sound.contains(&damaged_run), "{report:#?}");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains(&damaged_run.to_string()) && f.contains("path")),
        "{:#?}",
        report.findings
    );
    let (status, said) = second_reader(&damaged, &[]);
    assert_eq!(status, Some(1), "{said}");
}

/// **A package relabelled as a whole export is judged as one**: the count
/// check fires, and the paths read as members this format does not know.
#[tokio::test]
async fn a_package_relabelled_as_an_export_reports_deletion() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let relabelled = edited(&bytes, |line| {
        if line["kind"] == "agentplane.disclosure" {
            line["kind"] = json!("agentplane.export");
            line.as_object_mut().expect("object").remove("selection");
        }
    });
    let report = verified(&relabelled, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains("sealed run(s) and its checkpoint commits to")),
        "{:#?}",
        report.findings
    );
    assert!(
        report.not_checked.iter().any(|n| n.contains("proof")),
        "{:#?}",
        report.not_checked
    );
    let (status, _) = second_reader(&relabelled, &[]);
    assert_eq!(status, Some(1));
}

/// **Only the matter's own case travels.**
#[tokio::test]
async fn a_package_carries_only_its_runs_cases() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let carried: Vec<String> = std::str::from_utf8(&bytes)
        .expect("utf-8")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["kind"] == "agentplane.export.case")
        .map(|v| v["case"]["id"].as_str().expect("id").to_owned())
        .collect();
    assert_eq!(carried, vec![plane.a.to_string()]);
    assert!(!String::from_utf8_lossy(&bytes).contains(&plane.b.to_string()));
    assert!(!String::from_utf8_lossy(&bytes).contains(&plane.loose.to_string()));

    // A run that belongs to no case carries none, and says so.
    let loose = package(
        &plane,
        &Selection {
            cases: Vec::new(),
            runs: vec![plane.loose],
        },
    )
    .await;
    let report = verified(&loose, &[]);
    assert!(report.is_sound(), "{report:#?}");
    assert_eq!(report.cases, 0);
}

/// **An outside checkpoint of another size is not compared** — the package
/// carries no consistency proof — and the report says so instead of judging.
#[tokio::test]
async fn an_anchor_of_another_size_is_reported_not_compared() {
    let plane = two_matters().await;
    let earlier = plane.journal.checkpoint().await.expect("checkpoint");
    Runtime::builder(Arc::clone(&plane.journal))
        .skill(Trivial)
        .build()
        .run("demo.trivial", Tainted::trusted(json!("later")))
        .await
        .expect("run");
    let bytes = package(&plane, &of_case(plane.a)).await;
    let report = verified(&bytes, &[outside(earlier.clone())]);
    assert!(report.is_sound(), "{report:#?}");
    assert!(
        report
            .not_checked
            .iter()
            .any(|n| n.contains("not compared")),
        "{:#?}",
        report.not_checked
    );
    let (status, said) = second_reader(
        &bytes,
        &[format!("{}:{}", earlier.size, earlier.root.to_hex())],
    );
    assert_eq!(status, Some(0), "{said}");
    assert!(said.contains("not compared"), "{said}");
}

/// **A run of the matter still open is carried unproved**, and the report
/// says the checkpoint does not cover it.
#[tokio::test]
async fn an_open_run_in_a_package_is_carried_unproved() {
    use agentplane::journal::{Append, RecordKind};

    let plane = two_matters().await;
    let open = RunId::generate();
    let lease = plane
        .journal
        .acquire(open, "w", std::time::Duration::from_mins(1))
        .await
        .expect("lease");
    plane
        .journal
        .append(
            lease.epoch,
            vec![
                Append::new(
                    open,
                    RecordKind::Note {
                        text: "still working".into(),
                    },
                )
                .case(plane.a),
            ],
        )
        .await
        .expect("append");
    plane.cases.attach_run(plane.a, open).await.expect("attach");

    let bytes = package(&plane, &of_case(plane.a)).await;
    let block = std::str::from_utf8(&bytes)
        .expect("utf-8")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["run"] == json!(open.to_string()))
        .expect("the open run is carried");
    assert!(block.get("index").is_none() && block.get("proof").is_none());
    let report = verified(&bytes, &[]);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    assert!(
        report.not_checked.iter().any(|n| n.contains("1 open run")),
        "{:#?}",
        report.not_checked
    );
}

/// **An unknown case or run is refused, never widened to the plane.**
#[tokio::test]
async fn a_package_of_an_unknown_matter_is_refused() {
    let plane = two_matters().await;
    for selection in [
        of_case(CaseId::generate()),
        Selection {
            cases: Vec::new(),
            runs: vec![RunId::generate()],
        },
        Selection::default(),
    ] {
        let mut bytes = Vec::new();
        let refused = agentplane::export::package_to_jsonl(
            &plane.journal,
            &plane.cases,
            &selection,
            &mut bytes,
        )
        .await;
        assert!(refused.is_err(), "{selection:?} was answered");
        assert!(
            bytes.is_empty(),
            "nothing is written for a refused selection"
        );
    }
}

/// **Restore and a strict replay from a file refuse a package by name.**
#[tokio::test]
async fn restore_refuses_a_disclosure_package() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let fresh: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    let refused = agentplane::export::from_jsonl(&fresh, None, std::io::Cursor::new(&bytes)).await;
    let err = refused.expect_err("a package is not a whole log");
    assert!(err.to_string().contains("disclosure package"), "{err}");
    assert_eq!(fresh.checkpoint().await.expect("checkpoint").size, 0);
}

#[tokio::test]
async fn a_replay_from_a_package_is_refused() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let err = agentplane::export::open_for_replay(std::io::Cursor::new(&bytes))
        .await
        .expect_err("a package is not a whole log");
    assert!(err.to_string().contains("disclosure package"), "{err}");
}

/// **A grader's verdict binds to a disclosed sealed run, and not to one whose
/// path fails or that the package does not carry.**
#[tokio::test]
async fn a_grader_verdict_binds_to_a_disclosed_run() {
    use agentplane::grader_verdict::BindError;

    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let sealed = plane.a_runs[0];
    let sidecar = agentplane::grader_verdict::bind(
        std::io::Cursor::new(&bytes),
        sealed,
        None,
        b"a verdict".to_vec(),
    )
    .expect("a disclosed sealed run binds");
    let checked = agentplane::grader_verdict::check(
        std::io::Cursor::new(&bytes),
        None,
        &[],
        &[serde_json::to_vec(&sidecar).expect("json")],
        None,
    )
    .expect("the package reads");
    assert!(!checked.any_refused(), "{:#?}", checked.sidecars);

    let mut damaged_once = false;
    let damaged = edited(&bytes, |line| {
        if line["run"] == json!(sealed.to_string())
            && let Some(first) = line.get_mut("proof").and_then(|p| p.get_mut(0))
            && !damaged_once
        {
            *first = json!(agentplane::core::Digest::of(b"not a sibling").to_hex());
            damaged_once = true;
        }
    });
    assert!(damaged_once);
    assert!(matches!(
        agentplane::grader_verdict::bind(
            std::io::Cursor::new(&damaged),
            sealed,
            None,
            b"a verdict".to_vec()
        ),
        Err(BindError::NotSound(_))
    ));
    assert!(matches!(
        agentplane::grader_verdict::bind(
            std::io::Cursor::new(&bytes),
            plane.loose,
            None,
            b"a verdict".to_vec()
        ),
        Err(BindError::NoSuchRun(_))
    ));
}

/// **`policy check` refuses a package by name**: a verdict over a subset is a
/// claim about runs the file does not hold.
#[tokio::test]
async fn policy_check_refuses_a_disclosure_package() {
    use agentplane::policy::check::{Check, CheckError, TenantSource};

    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let refused = Check::new("default", TenantSource::Supplied)
        .rebuild(bytes.as_slice())
        .await;
    assert!(
        matches!(&refused, Err(CheckError::NotAnExport(why)) if why.contains("disclosure package")),
        "{refused:?}"
    );
}

/// **`agentplane grants` refuses a package by name**: an unused grant over a
/// subset is a claim about runs the file does not hold.
#[cfg(feature = "manifest")]
#[tokio::test]
async fn grants_refuses_a_disclosure_package() {
    use agentplane::grants::{Grants, GrantsError};

    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let refused = Grants::new(&[]).run(bytes.as_slice()).await;
    assert!(
        matches!(&refused, Err(GrantsError::NotAnExport(why)) if why.contains("disclosure package")),
        "{refused:?}"
    );
}

// ── The act, and the erasure that names it ──────────────────────────────────

fn operator() -> agentplane::core::Operator {
    agentplane::core::Operator::asserted("dpo@example").expect("an operator")
}

fn instant() -> agentplane::core::Timestamp {
    agentplane::core::Timestamp::from_unix_timestamp(1_800_000_000).expect("an instant")
}

fn request(selection: Selection, to: &str) -> agentplane::disclosure::Request {
    agentplane::disclosure::Request {
        selection,
        recipient: to.to_owned(),
        by: operator(),
        at: instant(),
    }
}

/// A scratch directory of its own, removed when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("agentplane-disclose-{}", RunId::generate()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        Self(dir)
    }
    fn entries(&self) -> Vec<String> {
        std::fs::read_dir(&self.0)
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A register that refuses every write.
#[derive(Debug)]
struct Refusing;

#[async_trait::async_trait]
impl agentplane::disclosure::DisclosureRegister for Refusing {
    async fn record(
        &self,
        _act: &agentplane::disclosure::Disclosure,
    ) -> Result<(), agentplane::core::StoreError> {
        Err(agentplane::core::StoreError::Backend(
            "the register is down".into(),
        ))
    }
    async fn disclosures(
        &self,
        _cases: &[CaseId],
        _runs: &[RunId],
    ) -> Result<Vec<agentplane::disclosure::Disclosure>, agentplane::core::StoreError> {
        Ok(Vec::new())
    }
}

/// **No byte reaches the destination when the act cannot be recorded**, and
/// the staged file is gone.
#[tokio::test]
async fn no_byte_is_emitted_when_the_disclosure_cannot_be_recorded() {
    let plane = two_matters().await;
    let scratch = Scratch::new();
    let destination = scratch.0.join("matter-a.jsonl");
    let refused = agentplane::disclosure::disclose(
        &plane.journal,
        &plane.cases,
        &Refusing,
        &request(of_case(plane.a), "Regulator R"),
        &destination,
    )
    .await;
    assert!(
        matches!(
            refused,
            Err(agentplane::disclosure::DiscloseError::Unrecorded(_))
        ),
        "{refused:?}"
    );
    assert!(scratch.entries().is_empty(), "{:?}", scratch.entries());
}

/// **A recorded disclosure names its bytes**: the act's digest is the digest
/// of the file delivered, and the act is listed by case and by run.
#[tokio::test]
async fn a_disclosure_is_recorded_with_the_digest_of_what_left() {
    let plane = two_matters().await;
    let scratch = Scratch::new();
    let destination = scratch.0.join("matter-a.jsonl");
    let act = agentplane::disclosure::disclose(
        &plane.journal,
        &plane.cases,
        plane.register.as_ref(),
        &request(of_case(plane.a), "Regulator R"),
        &destination,
    )
    .await
    .expect("disclosed");
    let delivered = std::fs::read(&destination).expect("the package was delivered");
    assert_eq!(act.package, agentplane::core::Digest::of(&delivered));
    assert!(
        !act.sealed,
        "an unsealed plane's records travel in the clear"
    );
    assert_eq!(scratch.entries(), vec!["matter-a.jsonl".to_owned()]);

    let by_case = plane
        .register
        .disclosures(&[plane.a], &[])
        .await
        .expect("list");
    let by_run = plane
        .register
        .disclosures(&[], &[plane.a_runs[1]])
        .await
        .expect("list");
    assert_eq!(by_case, vec![act.clone()]);
    assert_eq!(by_run, vec![act]);
    assert_eq!(
        plane
            .register
            .disclosures(&[plane.b], &[plane.loose])
            .await
            .expect("list"),
        []
    );
}

/// **An erasure names the disclosure of what it erased**, as a plaintext copy
/// it cannot reach on an unsealed plane, and says the name is the operator's
/// own row.
#[tokio::test]
async fn an_unsealed_disclosure_is_reported_not_reached() {
    let plane = two_matters().await;
    let scratch = Scratch::new();
    agentplane::disclosure::disclose(
        &plane.journal,
        &plane.cases,
        plane.register.as_ref(),
        &request(of_case(plane.a), "Regulator R"),
        &scratch.0.join("a.jsonl"),
    )
    .await
    .expect("disclosed");
    plane.cases.close(plane.a).await.expect("close");
    let erased = agentplane::blob::erase_case(
        None,
        plane.cases.as_ref(),
        #[cfg(feature = "keyring")]
        None,
        Some(plane.register.as_ref()),
        &agentplane::core::TenantId::default(),
        plane.a,
        instant(),
        "erasure request",
    )
    .await
    .expect("erase");
    assert_eq!(erased.copies.len(), 1, "{:?}", erased.copies);
    let line = &erased.copies[0];
    assert!(line.contains("Regulator R"), "{line}");
    assert!(
        line.contains("a plaintext copy this erasure cannot reach"),
        "{line}"
    );
    assert!(line.contains("operator's disclosure register"), "{line}");
}

/// **A sealed plane's copy is reported as sealed**: its payloads become
/// unopenable when the scope's key goes, and its clear fields stay readable.
#[cfg(feature = "keyring")]
#[tokio::test]
async fn an_erasure_names_the_disclosure_of_what_it_erased() {
    use agentplane::keyring::KeyRing;

    let store = Arc::new(RedbStore::open_in_memory().expect("store"));
    let journal = Arc::clone(&store) as Arc<dyn JournalStore>;
    let cases = Arc::clone(&store) as Arc<dyn CaseStore>;
    let ring = Arc::new(agentplane::testkit::MemoryKeyRing::new());
    let keys = [CorrelationKey::new("document", "DOC-S")];
    Runtime::builder(Arc::clone(&journal))
        .cases(Arc::clone(&cases))
        .keyring(Arc::clone(&ring) as Arc<dyn KeyRing>)
        .skill(Trivial)
        .build()
        .run_correlated(
            "demo.trivial",
            Tainted::trusted(json!({"name": "Ada"})),
            "matter",
            &keys,
        )
        .await
        .expect("run");
    let case = cases
        .correlate(&keys)
        .await
        .expect("correlate")
        .expect("case");

    let scratch = Scratch::new();
    let act = agentplane::disclosure::disclose(
        &journal,
        &cases,
        store.as_ref(),
        &request(of_case(case), "Court C"),
        &scratch.0.join("s.jsonl"),
    )
    .await
    .expect("disclosed");
    assert!(act.sealed, "a sealed plane's records travel sealed");

    cases.close(case).await.expect("close");
    let erased = agentplane::blob::erase_case(
        None,
        cases.as_ref(),
        Some(ring.as_ref() as &dyn KeyRing),
        Some(store.as_ref() as &dyn agentplane::disclosure::DisclosureRegister),
        &agentplane::core::TenantId::default(),
        case,
        instant(),
        "erasure request",
    )
    .await
    .expect("erase");
    assert_eq!(erased.copies.len(), 1, "{:?}", erased.copies);
    assert!(
        erased.copies[0].contains("Court C")
            && erased.copies[0].contains("sealed under the erased key become unopenable")
            && erased.copies[0].contains("operator's disclosure register"),
        "{:?}",
        erased.copies
    );

    // A run that belongs to no case is erased on its own, and names its copy.
    let plane = two_matters().await;
    agentplane::disclosure::disclose(
        &plane.journal,
        &plane.cases,
        plane.register.as_ref(),
        &request(
            Selection {
                cases: Vec::new(),
                runs: vec![plane.loose],
            },
            "Counterparty P",
        ),
        &scratch.0.join("loose.jsonl"),
    )
    .await
    .expect("disclosed");
    let copies = agentplane::blob::erase_run(
        ring.as_ref(),
        Some(plane.register.as_ref()),
        &agentplane::core::TenantId::default(),
        plane.loose,
        instant(),
        "erasure request",
    )
    .await
    .expect("erase");
    assert!(
        copies.len() == 1 && copies[0].contains("Counterparty P"),
        "{copies:?}"
    );
}

/// **A retention pass names the disclosures of the cases it erased.**
#[tokio::test]
async fn a_retention_pass_names_the_disclosures_of_what_it_erased() {
    let plane = two_matters().await;
    let scratch = Scratch::new();
    agentplane::disclosure::disclose(
        &plane.journal,
        &plane.cases,
        plane.register.as_ref(),
        &request(of_case(plane.a), "Regulator R"),
        &scratch.0.join("a.jsonl"),
    )
    .await
    .expect("disclosed");
    plane.cases.close(plane.a).await.expect("close");
    let tenant = agentplane::core::TenantId::default();
    let report = agentplane::retention::retain(
        &agentplane::retention::Stores {
            cases: &plane.cases,
            blobs: None,
            #[cfg(feature = "keyring")]
            keys: None,
            tenant: &tenant,
            disclosures: Some(&plane.register),
        },
        agentplane::core::Timestamp::from_unix_timestamp(4_000_000_000).expect("instant"),
        instant(),
        "retention",
    )
    .await
    .expect("retain");
    assert_eq!(report.erased, 1, "{report:?}");
    assert!(
        report.disclosed.len() == 1
            && report.disclosed[0].contains(&plane.a.to_string())
            && report.disclosed[0].contains("Regulator R"),
        "{:?}",
        report.disclosed
    );
}

/// `bytes` as one JSON value per line.
fn lines_of(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .expect("utf-8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("a JSON line"))
        .collect()
}

/// `lines` written back as JSON Lines.
fn joined(lines: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for line in lines {
        out.push_str(&serde_json::to_string(line).expect("serialise"));
        out.push('\n');
    }
    out.into_bytes()
}

fn has(findings: &[String], needle: &str) -> bool {
    findings.iter().any(|f| f.contains(needle))
}

/// A hex digest with its last nibble changed.
fn flipped(hex: &str) -> String {
    let mut hex = hex.to_owned();
    let last = if hex.ends_with('0') { '1' } else { '0' };
    hex.pop();
    hex.push(last);
    hex
}

/// **A header past the first line is a finding and is ignored** — whether it
/// would turn a whole export with runs removed into a package, or put a
/// genuine checkpoint behind a forged one.
#[tokio::test]
async fn a_later_header_is_a_finding_and_ignored() {
    let plane = two_matters().await;

    // A whole export missing two of the log's runs, with a disclosure header
    // after the first line: still read as a whole export, so the deletion is
    // reported.
    let mut runs = plane.a_runs.clone();
    runs.push(plane.loose);
    let mut whole = Vec::new();
    agentplane::export::to_jsonl(&plane.journal, &plane.cases, &runs, &mut whole)
        .await
        .expect("export");
    let mut lines = lines_of(&whole);
    let mut relabel = lines[0].clone();
    relabel["kind"] = json!("agentplane.disclosure");
    relabel["selection"] = json!({"cases": [plane.a.to_string()], "runs": []});
    lines.insert(1, relabel);
    let attacked = joined(&lines);
    let report = verified(&attacked, &[]);
    assert!(
        has(&report.findings, "past the first line"),
        "{:#?}",
        report.findings
    );
    assert!(
        has(&report.findings, "checkpoint commits to"),
        "{:#?}",
        report.findings
    );
    assert_eq!(report.selection, None, "the later header chose nothing");
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("past the first line"), "{said}");

    // A package behind a forged checkpoint, its genuine header second.
    let bytes = package(&plane, &of_case(plane.a)).await;
    let mut lines = lines_of(&bytes);
    let mut forged = lines[0].clone();
    let root = forged["checkpoint"]["root"]
        .as_str()
        .expect("root")
        .to_owned();
    forged["checkpoint"]["root"] = json!(flipped(&root));
    lines.insert(0, forged);
    let attacked = joined(&lines);
    let report = verified(&attacked, &[]);
    assert!(
        has(&report.findings, "past the first line"),
        "{:#?}",
        report.findings
    );
    assert_ne!(
        report.checkpoint.root.to_hex(),
        root,
        "the first header is the one read"
    );
    assert!(report.sound.is_empty(), "{report:#?}");
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("past the first line"), "{said}");
}

/// **A block with an index and no seal places nothing** — it is a finding,
/// and the conclusion under it is a leaf stripped from the package.
#[tokio::test]
async fn a_block_with_an_index_and_no_seal_is_a_finding() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let mut stripped = None;
    let attacked = edited(&bytes, |line| {
        if stripped.is_none() && line.get("seal").is_some() {
            line.as_object_mut().expect("object").remove("seal");
            stripped = line["run"].as_str().map(str::to_owned);
        }
    });
    let run = stripped.expect("a sealed block");
    let report = verified(&attacked, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains(&run) && f.contains("seal that parses")),
        "{:#?}",
        report.findings
    );
    assert!(
        !report.sound.iter().any(|r| r.to_string() == run),
        "{report:#?}"
    );
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("needs both index and seal"), "{said}");
}

/// **A concluded run whose leaf was removed from a package is a finding** in
/// both readers: a package places every sealed run it carries.
#[tokio::test]
async fn a_concluded_run_without_its_leaf_is_a_finding() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let mut stripped = None;
    let attacked = edited(&bytes, |line| {
        if stripped.is_none() && line.get("seal").is_some() {
            let block = line.as_object_mut().expect("object");
            for member in ["index", "seal", "proof"] {
                block.remove(member);
            }
            stripped = line["run"].as_str().map(str::to_owned);
        }
    });
    let run = stripped.expect("a sealed block");
    let report = verified(&attacked, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains(&run) && f.contains("carries no leaf")),
        "{:#?}",
        report.findings
    );
    assert!(
        !report.sound.iter().any(|r| r.to_string() == run),
        "{report:#?}"
    );
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("carries no leaf"), "{said}");
}

/// **A run carried twice, or a log index claimed twice, is a finding** in
/// both readers, and the repeated run is not listed sound.
#[tokio::test]
async fn a_repeated_run_or_index_is_a_finding() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let lines = lines_of(&bytes);
    let first = lines
        .iter()
        .position(|l| l["kind"] == "agentplane.export.run")
        .expect("a run block");
    let next = lines
        .iter()
        .skip(first + 1)
        .position(|l| l.get("kind").is_some())
        .map(|n| n + first + 1)
        .expect("a line after the block");
    let run = lines[first]["run"].as_str().expect("run").to_owned();

    let mut twice = lines.clone();
    let block: Vec<Value> = lines[first..next].to_vec();
    for (n, line) in block.into_iter().enumerate() {
        twice.insert(next + n, line);
    }
    let attacked = joined(&twice);
    let report = verified(&attacked, &[]);
    assert!(
        has(&report.findings, "two blocks"),
        "{:#?}",
        report.findings
    );
    assert!(
        !report.sound.iter().any(|r| r.to_string() == run),
        "{report:#?}"
    );
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("two blocks"), "{said}");

    let mut seen = None;
    let claimed = edited(&bytes, |line| {
        if let Some(index) = line.get("index").cloned() {
            match &seen {
                None => seen = Some(index),
                Some(first) => line["index"] = first.clone(),
            }
        }
    });
    let report = verified(&claimed, &[]);
    assert!(
        has(&report.findings, "claimed by two runs"),
        "{:#?}",
        report.findings
    );
    let (status, said) = second_reader(&claimed, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("claimed by two runs"), "{said}");
}

/// **A case the selection names and the package omits is a finding** in both
/// readers: a package proves inclusion, and this is the one omission it shows.
#[tokio::test]
async fn a_selected_case_the_package_omits_is_a_finding() {
    let plane = two_matters().await;
    let bytes = package(&plane, &of_case(plane.a)).await;
    let mut lines = lines_of(&bytes);
    lines.retain(|l| l["kind"] != "agentplane.export.case");
    let attacked = joined(&lines);
    let report = verified(&attacked, &[]);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.contains(&plane.a.to_string()) && f.contains("selection")),
        "{:#?}",
        report.findings
    );
    let (status, said) = second_reader(&attacked, &[]);
    assert_eq!(status, Some(1), "{said}");
    assert!(said.contains("selection names case"), "{said}");
}

/// **A destination that cannot receive a file is refused before anything is
/// recorded**: a directory, or a path under a parent that does not exist.
#[tokio::test]
async fn an_unreceivable_destination_is_refused_before_recording() {
    let plane = two_matters().await;
    let scratch = Scratch::new();
    for destination in [scratch.0.clone(), scratch.0.join("absent").join("a.jsonl")] {
        let refused = agentplane::disclosure::disclose(
            &plane.journal,
            &plane.cases,
            plane.register.as_ref(),
            &request(of_case(plane.a), "Regulator R"),
            &destination,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(agentplane::disclosure::DiscloseError::Write(_))
            ),
            "{refused:?}"
        );
    }
    let recorded = plane
        .register
        .disclosures(&[plane.a], &[])
        .await
        .expect("register");
    assert!(recorded.is_empty(), "{recorded:?}");
    assert!(scratch.entries().is_empty(), "{:?}", scratch.entries());
}
