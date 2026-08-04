//! The manifest is a security document, so every check here is about a refusal.
//!
//! A config format that guesses is worse than no config format: the guess is
//! silent, it looks like it worked, and the run that discovers otherwise is the
//! expensive one.

#![cfg(feature = "manifest")]

use agentplane::manifest::{Manifest, ManifestError};

const GOOD: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata:
  name: pattern-compliance-auditor
  version: "2.0.0"
spec:
  security:
    max_sensitivity_egress: internal
    max_delegation_depth: 2
  capabilities:
    provides: [audit.anomaly-detection]
    requires: [data.fetch]
  budgets:
    max_tokens: 120000
    max_minor_units: 250
    max_steps: 25
  tools:
    - ref: "mcp://validator/apply_correction"
      mutates: true
      max_sensitivity: internal
"#;

/// [`GOOD`] again — same declaration, different bytes.
///
/// Keys reordered, flow mappings where the other uses block style, quoting
/// changed. Everything a formatter or a second author might do to a file
/// without changing what it declares — and none of it may change the digest, or
/// "which manifest governed this run" has a different answer after every
/// reformat.
const REFORMATTED: &str = r#"
kind: Agent
apiVersion: agentplane.hupe1980.github.io/v1alpha1
spec:
  budgets: { max_steps: 25, max_tokens: 120000, max_minor_units: 250 }
  tools:
    - max_sensitivity: internal
      mutates: true
      ref: mcp://validator/apply_correction
  capabilities: { requires: ["data.fetch"], provides: ["audit.anomaly-detection"] }
  security:
    max_delegation_depth: 2
    max_sensitivity_egress: "internal"
metadata:
  version: '2.0.0'
  name: "pattern-compliance-auditor"
"#;

#[test]
fn a_complete_manifest_parses() {
    let m = Manifest::parse(GOOD).expect("a valid manifest");
    assert_eq!(m.metadata.name, "pattern-compliance-auditor");
    assert_eq!(
        m.spec.security.max_sensitivity_egress,
        Some(agentplane::core::Sensitivity::Internal)
    );
    assert_eq!(m.budget().max_tokens, Some(120_000));
    assert_eq!(m.spec.tools.len(), 1);
}

/// **A misspelled security field is fatal, not ignored.**
///
/// The single most dangerous thing a config parser can do is accept
/// `max_tokns: 100` and silently mean *no token ceiling*. Nothing about the run
/// looks wrong until the bill arrives, and the manifest — the artifact whose
/// entire job is to make limits reviewable — is what said it was fine.
#[test]
fn a_misspelled_field_is_refused() {
    let typo = GOOD.replace("max_tokens:", "max_tokns:");
    match Manifest::parse(&typo) {
        Err(ManifestError::Syntax(detail)) => assert!(
            detail.contains("max_tokns") || detail.contains("unknown field"),
            "the refusal must name the field: {detail}"
        ),
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(m) => panic!(
            "a typo silently disabled a budget: max_tokens = {:?}",
            m.budget().max_tokens
        ),
    }
}

/// A manifest for something else is refused rather than best-effort parsed.
#[test]
fn a_foreign_document_is_refused() {
    let foreign = GOOD.replace("kind: Agent", "kind: Deployment");
    assert!(matches!(
        Manifest::parse(&foreign),
        Err(ManifestError::WrongDocument { .. })
    ));
}

/// **Silence is not a budget.**
///
/// An agent with no ceiling is exactly the one that runs up a bill nobody
/// authorised. Omitting the section must not be the easy way to get that —
/// `budgets: {}` says it on purpose, and is accepted.
#[test]
fn an_absent_budget_is_refused_but_an_empty_one_is_not() {
    let no_budgets = GOOD
        .lines()
        .filter(|l| !l.trim_start().starts_with("max_") && !l.contains("budgets:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        matches!(Manifest::parse(&no_budgets), Err(ManifestError::Unbounded)),
        "a manifest with no budgets section was accepted"
    );

    let deliberate = GOOD.replace(
        "  budgets:\n    max_tokens: 120000\n    max_minor_units: 250\n    max_steps: 25",
        "  budgets: {}",
    );
    let m = Manifest::parse(&deliberate).expect("`budgets: {}` is a deliberate choice");
    assert_eq!(m.budget().max_tokens, None);
}

/// A tool nobody described still mutates.
///
/// The default has to be the cautious one. A grant written in a hurry, with no
/// `mutates` field, must not become the one the runtime feels free to retry.
#[test]
fn a_tool_grant_defaults_to_mutating() {
    let terse = GOOD.replace(
        "    - ref: \"mcp://validator/apply_correction\"\n      mutates: true\n      max_sensitivity: internal",
        "    - ref: \"mcp://validator/apply_correction\"",
    );
    let m = Manifest::parse(&terse).expect("a terse grant is still a grant");
    assert!(
        m.spec.tools[0].mutates,
        "a tool nobody described was assumed harmless"
    );
}

#[test]
fn protected_tool_fields_are_strict_and_digest_covered() {
    let protected = GOOD.replace(
        "      max_sensitivity: internal",
        "      max_sensitivity: internal\n      protected_fields:\n        - path: /recipient\n          require_trusted: true\n        - path: /amount\n          allowed_sources: [run.input]",
    );
    let manifest = Manifest::parse(&protected).expect("protected fields parse");
    let fields = &manifest.spec.tools[0].protected_fields;
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].path(), "/amount", "rules normalize by path");
    assert_ne!(
        manifest.digest().unwrap(),
        Manifest::parse(GOOD).unwrap().digest().unwrap()
    );

    let reordered = protected.replace(
        "        - path: /recipient\n          require_trusted: true\n        - path: /amount\n          allowed_sources: [run.input]",
        "        - path: /amount\n          allowed_sources: [run.input]\n        - path: /recipient\n          require_trusted: true",
    );
    assert_eq!(
        manifest.digest().unwrap(),
        Manifest::parse(&reordered).unwrap().digest().unwrap(),
        "constraint order is formatting, not authority"
    );

    let typo = protected.replace("require_trusted", "require_trsuted");
    assert!(matches!(
        Manifest::parse(&typo),
        Err(ManifestError::Syntax(_))
    ));

    let contradictory = protected.replace(
        "          require_trusted: true",
        "          require_trusted: true\n          allowed_sources: [model.complete]",
    );
    assert!(matches!(
        Manifest::parse(&contradictory),
        Err(ManifestError::Syntax(_))
    ));

    let duplicate = protected.replace(
        "        - path: /amount\n          allowed_sources: [run.input]",
        "        - path: /recipient\n          require_trusted: true\n        - path: /amount\n          allowed_sources: [run.input]",
    );
    assert!(matches!(
        Manifest::parse(&duplicate),
        Err(ManifestError::Syntax(_))
    ));
}

/// A manifest's ceilings reach the runtime it configures.
///
/// The point of declaring a budget in a reviewable file is that it binds. A
/// manifest whose numbers stopped at the parser would be documentation wearing
/// a config file's clothes.
#[cfg(feature = "redb")]
#[tokio::test]
async fn each_agents_budget_bounds_only_its_own_runs() {
    use agentplane::runtime::{Agent, RunStatus, Runtime};

    // Two agents on one plane, one whose ceiling forbids any effect at all.
    //  rather than : a metered budget always allows the
    // first operation, because its cost is unknown until it has run.
    let generous = Manifest::parse(BOUND).expect("parse");
    let mean = Manifest::parse(
        &BOUND
            .replace("bound-agent", "mean-agent")
            .replace("work.do", "work.cheap")
            .replace("budgets: {}", "budgets: { max_effects: 0 }"),
    )
    .expect("parse");

    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let provider = agentplane::testkit::FakeProvider::new();
    let rt = Runtime::builder(store)
        .agent(Agent::new(&generous).skill(CallsModel {
            provider: std::sync::Arc::clone(&provider),
            model: agentplane::model::ModelId::new("fake", "declared-1"),
            capability: "work.do",
        }))
        .agent(Agent::new(&mean).skill(CallsModel {
            provider: std::sync::Arc::clone(&provider),
            model: agentplane::model::ModelId::new("fake", "declared-1"),
            capability: "work.cheap",
        }))
        .build();

    let rich = rt.run("work.do", serde_json::json!({})).await.expect("run");
    assert!(
        matches!(rich.status, RunStatus::Succeeded),
        "the generous agent's run was bounded by somebody else's ceiling: {:?}",
        rich.status
    );

    let poor = rt
        .run("work.cheap", serde_json::json!({}))
        .await
        .expect("run");
    assert!(
        matches!(poor.status, RunStatus::Exhausted(_)),
        "an agent forbidden any effect ran to completion — its neighbour's ceiling applied \
         instead of its own, which is what a plane-wide budget would do: {:?}",
        poor.status
    );
}

/// A manifest cannot advertise a capability the agent has no skill for.
///
/// **An agent has skills.** A declaration listing one it cannot perform is a
/// card that lies, and the caller who believed it finds out at dispatch, in
/// production, rather than at startup where the mistake was made.
#[test]
#[should_panic(expected = "advertises capabilities none of its skills provide")]
fn a_manifest_may_not_advertise_a_skill_it_lacks() {
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{Agent, Runtime};
    use agentplane::store::RedbStore;
    use std::sync::Arc;

    let m = Manifest::parse(GOOD).expect("parse");
    let store: Arc<dyn JournalStore> = Arc::new(RedbStore::open_in_memory().expect("store"));
    // No skills registered at all, so the advertised capability is unbacked.
    let _ = Runtime::builder(store).agent(Agent::new(&m)).build();
}

/// Two agents may not claim the same capability.
///
/// This is the bug class the multi-agent plane introduces. With one agent per
/// runtime a collision was impossible; now `by_capability` is a plane-wide map,
/// and an unguarded `insert` means the second registration silently wins.
///
/// Silent shadowing would be bad enough. The real damage is *governance*:
/// dispatch resolves a capability to a skill name and the manifest governing it,
/// so the loser's budget, model grants and egress ceiling quietly stop applying
/// to work its declaration still advertises. Nobody is told, and the journal
/// records the winner as though it had always been the only claimant.
#[cfg(feature = "redb")]
#[test]
#[should_panic(expected = "is claimed by two agents")]
fn two_agents_may_not_claim_the_same_capability() {
    use agentplane::runtime::{Agent, Runtime};

    let one = Manifest::parse(BOUND).expect("parse");
    // A different agent, same advertised capability.
    let two = Manifest::parse(&BOUND.replace("bound-agent", "rival-agent")).expect("parse");

    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    // Distinct skill *names*, same advertised capability — otherwise this would
    // trip the duplicate-name guard instead and prove nothing about capability
    // resolution.
    let _ = Runtime::builder(store)
        .agent(Agent::new(&one).skill(Claims("worker-a", "work.do")))
        .agent(Agent::new(&two).skill(Claims("worker-b", "work.do")))
        .build();
}

/// Two skills on one plane may not share a name.
///
/// The other half of the same collision. A skill name is what a capability
/// resolves *to* and what `governed_by` is keyed on, so two skills sharing one
/// makes both lookups arbitrary — and the second silently inherits the first's
/// manifest, which is governance by alphabetical accident.
#[cfg(feature = "redb")]
#[test]
#[should_panic(expected = "are both named")]
fn two_skills_on_one_plane_may_not_share_a_name() {
    use agentplane::runtime::{Agent, Runtime};

    let one = Manifest::parse(BOUND).expect("parse");
    let two = Manifest::parse(
        &BOUND
            .replace("bound-agent", "rival-agent")
            .replace("work.do", "work.other"),
    )
    .expect("parse");

    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    // Distinct capabilities, same skill name — so this cannot trip the
    // duplicate-capability guard instead.
    let _ = Runtime::builder(store)
        .agent(Agent::new(&one).skill(Claims("worker", "work.do")))
        .agent(Agent::new(&two).skill(Claims("worker", "work.other")))
        .build();
}

/// The journal says which declaration governed a run.
///
/// A digest that pins a manifest is worth nothing to an auditor if no run ever
/// records which one it ran under. "Which declaration governed this run" then
/// depends on somebody still having the file and remembering how the plane was
/// wired — exactly the memory the journal exists to replace.
///
/// The digest is the load-bearing field. A name and version identify a file that
/// may have been edited since; only the digest pins what it actually said,
/// including the system prompt, which is inside it.
#[cfg(feature = "redb")]
#[tokio::test]
async fn the_journal_records_which_declaration_governed_a_run() {
    use agentplane::journal::{JournalStore, RecordKind};
    use agentplane::runtime::{Agent, Runtime};

    let m = Manifest::parse(BOUND).expect("parse");
    let store: std::sync::Arc<dyn JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(std::sync::Arc::clone(&store))
        .agent(Agent::new(&m).skill(Claims("worker", "work.do")))
        .build();

    let out = rt.run("work.do", serde_json::json!({})).await.expect("run");
    let records = store.read(out.run_id, 0).await.expect("read");

    let admitted = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::RunAdmitted {
                capability,
                governed_by,
                ..
            } => Some((capability.clone(), governed_by.clone())),
            _ => None,
        })
        .expect("RunAdmitted");

    assert_eq!(
        admitted.0, "work.do",
        "the capability is recorded as itself"
    );
    let id = admitted
        .1
        .expect("a run under a declared agent must name its declaration");
    assert_eq!(id.name, "bound-agent");
    assert_eq!(id.version, "1.0.0");
    assert_eq!(
        id.digest,
        m.digest().expect("digest"),
        "the recorded digest must be the manifest's own, or it pins nothing"
    );
}

/// An ungoverned run says so, rather than looking governed by nobody.
///
/// A skill registered straight onto the plane is a legitimate shape. Recording
/// `None` distinguishes it from a governed run whose identity went missing —
/// two very different answers to an audit question.
#[cfg(feature = "redb")]
#[tokio::test]
async fn a_run_with_no_declaration_records_no_governor() {
    use agentplane::journal::{JournalStore, RecordKind};
    use agentplane::runtime::Runtime;

    let store: std::sync::Arc<dyn JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(std::sync::Arc::clone(&store))
        .skill(Claims("worker", "work.do"))
        .build();

    let out = rt.run("work.do", serde_json::json!({})).await.expect("run");
    let records = store.read(out.run_id, 0).await.expect("read");
    let governed = records.iter().find_map(|r| match r.kind() {
        RecordKind::RunAdmitted { governed_by, .. } => Some(governed_by.clone()),
        _ => None,
    });
    assert_eq!(
        governed,
        Some(None),
        "a plane-registered skill has no declaration, and the record must say so"
    );
}

/// Admission binds an agent by **digest**, never by its self-asserted name.
///
/// A policy needs to say "this agent may not run that capability". The tempting
/// way is to make the agent's `metadata.name` the principal — and it is wrong:
/// a manifest is a file, its name is whatever the author typed, so a rule
/// granting authority to a name grants it to any file claiming that name.
///
/// So the declaration reaches policy as *context*, digest included, and the
/// principal stays what it has always been — an authenticated identity, or the
/// capability when there is none, which claims nothing. The digest is the part
/// that binds: it is content-addressed, and it covers the prompt, the model
/// grants and the ceilings, so an edited agent is a different agent.
#[cfg(feature = "redb")]
#[tokio::test]
async fn admission_policy_sees_the_agent_apart_from_the_capability() {
    use agentplane::core::{PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest};
    use agentplane::runtime::{Agent, Runtime};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Seen(Mutex<Vec<(String, String, Option<String>)>>);

    impl PolicyEngine for Seen {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push((
                r.principal.to_owned(),
                r.resource.to_owned(),
                r.context
                    .get("agent")
                    .and_then(|a| a.get("digest"))
                    .and_then(|d| d.as_str())
                    .map(ToOwned::to_owned),
            ));
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            PolicyBundleIdentity::new(agentplane::core::Digest::of(b"seen"), "test")
        }
    }

    let m = Manifest::parse(BOUND).expect("parse");
    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let engine = std::sync::Arc::new(Seen::default());
    let rt = Runtime::builder(store)
        .policy(std::sync::Arc::clone(&engine) as std::sync::Arc<dyn PolicyEngine>)
        .agent(Agent::new(&m).skill(Claims("worker", "work.do")))
        .build();

    rt.run("work.do", serde_json::json!({})).await.expect("run");

    let seen = engine.0.lock().unwrap().clone();
    let (principal, resource, digest) = seen
        .iter()
        .find(|(_, r, _)| r == "work.do")
        .expect("an admission decision naming the capability as the resource")
        .clone();

    assert_eq!(resource, "work.do", "the resource is what was asked for");
    assert_ne!(
        principal, "bound-agent",
        "the agent's self-asserted name must never be the principal: a rule \
         granting authority to a name grants it to any file claiming that name"
    );
    assert_eq!(
        digest.as_deref(),
        Some(m.digest().expect("digest").to_hex().as_str()),
        "without the digest in context, a rule can only bind to a name — and the \
         digest is what an edited agent changes"
    );

    // The property the digest buys, stated as a test rather than asserted in a
    // comment: editing the agent changes what a rule binds to. A name-based rule
    // would go on permitting this.
    let widened = BOUND.replace("budgets: {}", "budgets: { max_tokens: 999999 }");
    assert_ne!(
        widened, BOUND,
        "the edit matched nothing, so this would compare a manifest to itself"
    );
    let edited = Manifest::parse(&widened).expect("the edited manifest still parses");
    assert_ne!(
        edited.digest().expect("digest"),
        m.digest().expect("digest"),
        "raising a ceiling left the digest unchanged, so a digest-bound rule \
         would keep permitting an agent whose limits were widened"
    );
    assert_eq!(
        edited.metadata.name, m.metadata.name,
        "the name is unchanged by the edit — which is exactly why it must not be \
         the thing a policy binds to"
    );
}

/// A policy binds to a **publisher**, which is the only usable grouping.
///
/// A rule has to name a *set* of agents. Every other candidate fails a
/// deployment: a workload identity is per-instance, so the rule is rewritten on
/// every deploy; a digest names one revision, so every edit is a policy change;
/// and a name, a role, or any group label in the manifest is a string the file's
/// author typed, so granting authority to one grants it to anybody who types it.
///
/// A publisher key is both a group — many agents, many versions — and impossible
/// to claim without holding the key. It reaches the runtime from a verified
/// registry resolution, which returns it *beside* the manifest precisely because
/// a document cannot state who signed it.
#[cfg(feature = "redb")]
#[tokio::test]
async fn a_policy_can_bind_to_the_publisher_that_vouched_for_an_agent() {
    use agentplane::core::{PolicyBundleIdentity, PolicyDecision, PolicyEngine, PolicyRequest};
    use agentplane::runtime::{Agent, Runtime};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Publishers(Mutex<Vec<Option<String>>>);

    impl PolicyEngine for Publishers {
        fn authorize(&self, r: &PolicyRequest<'_>) -> PolicyDecision {
            self.0.lock().unwrap().push(
                r.context
                    .get("agent")
                    .and_then(|a| a.get("publisher"))
                    .and_then(|p| p.as_str())
                    .map(ToOwned::to_owned),
            );
            PolicyDecision::Permit
        }
        fn bundle(&self) -> PolicyBundleIdentity {
            PolicyBundleIdentity::new(agentplane::core::Digest::of(b"pub"), "test")
        }
    }

    let m = Manifest::parse(BOUND).expect("parse");
    let engine = std::sync::Arc::new(Publishers::default());
    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(store)
        .policy(std::sync::Arc::clone(&engine) as std::sync::Arc<dyn PolicyEngine>)
        .agent(
            Agent::new(&m)
                .published_by("release-bot")
                .skill(Claims("worker", "work.do")),
        )
        .build();

    rt.run("work.do", serde_json::json!({})).await.expect("run");
    assert!(
        engine
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.as_deref() == Some("release-bot")),
        "the publisher never reached policy, so a rule has nothing to bind to \
         but a name any file can claim: {:?}",
        engine.0.lock().unwrap()
    );

    // Unvouched-for is recorded as such, not left blank to be read as trusted.
    let engine2 = std::sync::Arc::new(Publishers::default());
    let store2: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt2 = Runtime::builder(store2)
        .policy(std::sync::Arc::clone(&engine2) as std::sync::Arc<dyn PolicyEngine>)
        .agent(Agent::new(&m).skill(Claims("worker", "work.do")))
        .build();
    rt2.run("work.do", serde_json::json!({}))
        .await
        .expect("run");
    assert!(
        engine2.0.lock().unwrap().iter().all(Option::is_none),
        "an agent nobody vouched for reported a publisher"
    );
}

/// A skill that only advertises: a name and the capability it claims.
#[derive(Debug)]
struct Claims(&'static str, &'static str);

#[async_trait::async_trait]
impl agentplane::core::Skill for Claims {
    fn descriptor(&self) -> agentplane::core::SkillDescriptor {
        agentplane::core::SkillDescriptor::new(self.0).provides(self.1)
    }

    async fn invoke(
        &self,
        _cx: &mut agentplane::runtime::StepCtx<'_>,
        input: agentplane::core::Tainted<serde_json::Value>,
    ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
        Ok(agentplane::core::Outcome::done(input))
    }
}

/// The digest identifies the declaration, not the file.
///
/// Reformatting must not change it, or "which manifest governed this run" has a
/// different answer every time somebody runs a formatter. Changing what is
/// *declared* must change it, or the digest pins nothing.
#[test]
fn the_digest_follows_meaning_not_formatting() {
    let a = Manifest::parse(GOOD).expect("parse");
    let reordered = Manifest::parse(REFORMATTED).expect("the reformatted manifest must parse");
    assert_ne!(
        GOOD.trim(),
        REFORMATTED.trim(),
        "the two fixtures are byte-identical, so this test proves nothing"
    );
    assert_eq!(
        a, reordered,
        "the fixtures do not declare the same thing, so the digest comparison \
         below would be testing the wrong property"
    );
    assert_eq!(
        a.digest().unwrap(),
        reordered.digest().unwrap(),
        "formatting changed the identity of the declaration"
    );

    let changed =
        Manifest::parse(&GOOD.replace("max_tokens: 120000", "max_tokens: 999999")).expect("parse");
    assert_ne!(
        a.digest().unwrap(),
        changed.digest().unwrap(),
        "raising a ceiling did not change the manifest's identity"
    );
}

// ── The registry ────────────────────────────────────────────────────────────
//
// A manifest makes a grant reviewable; a registry decides whether the reviewed
// version is the one that runs. Both tests below are about content changing
// under a name that did not.

/// A published version cannot be replaced.
///
/// The property that makes "we reviewed 2.0.0" a statement about an artifact
/// rather than about a Tuesday. Without it, review has a shelf life nobody is
/// told about.
#[tokio::test]
async fn a_published_version_cannot_be_rewritten() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};

    let reg = MemoryRegistry::new();
    let original = Manifest::parse(GOOD).expect("parse");
    reg.publish(&original).await.expect("first publish");

    // Same name, same version, one more tool. This is the supply-chain shape:
    // nothing a version-pinned consumer would notice.
    let widened =
        Manifest::parse(&GOOD.replace("  tools:", "  tools:\n    - ref: \"mcp://shell/exec\"\n"))
            .expect("parse");

    match reg.publish(&widened).await {
        Err(RegistryError::Immutable { name, version, .. }) => {
            assert_eq!(name, "pattern-compliance-auditor");
            assert_eq!(version, "2.0.0");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a published version was silently replaced with a wider grant"),
    }

    // And the original still resolves — a refused publish must not damage what
    // is already there.
    let back = reg
        .resolve("pattern-compliance-auditor", "2.0.0")
        .await
        .expect("resolve");
    assert_eq!(
        back.spec.tools.len(),
        1,
        "the refused publish changed the stored manifest"
    );
}

/// Re-publishing identical content is not an attack.
///
/// A deploy that retries must not have to reason about whether it already ran.
#[tokio::test]
async fn republishing_identical_content_is_the_same_publish() {
    use agentplane::manifest::{MemoryRegistry, Registry};

    let reg = MemoryRegistry::new();
    let m = Manifest::parse(GOOD).expect("parse");
    let first = reg.publish(&m).await.expect("first publish");
    let second = reg
        .publish(&m)
        .await
        .expect("a retried deploy must not be refused");
    assert_eq!(first, second);
}

/// A pin refuses content the caller did not review.
///
/// Immutability is a promise the registry makes about itself. A pin is the
/// caller declining to need that promise — the only form that survives the
/// registry being the compromised party.
#[tokio::test]
async fn a_pinned_resolve_refuses_substituted_content() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};

    let reg = MemoryRegistry::new();
    let reviewed = Manifest::parse(GOOD).expect("parse");
    let pin = reviewed.digest().expect("digest");

    // A *different* manifest under the same coordinates — what a compromised
    // registry serves, and what immutability alone cannot catch because the
    // registry is the one enforcing it.
    let substituted =
        Manifest::parse(&GOOD.replace("max_delegation_depth: 2", "max_delegation_depth: 9"))
            .expect("parse");
    reg.publish(&substituted).await.expect("publish");

    match reg
        .resolve_pinned("pattern-compliance-auditor", "2.0.0", pin)
        .await
    {
        Err(RegistryError::PinBroken {
            expected, actual, ..
        }) => {
            assert_ne!(expected, actual);
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a pinned resolve accepted content the caller never reviewed"),
    }

    // The same pin against the reviewed content resolves — a pin that refused
    // everything would pass this test while being useless.
    let reg2 = MemoryRegistry::new();
    reg2.publish(&reviewed).await.expect("publish");
    reg2.resolve_pinned("pattern-compliance-auditor", "2.0.0", pin)
        .await
        .expect("the reviewed content must resolve under its own pin");
}

/// Versions are listed, not ordered.
#[tokio::test]
async fn versions_are_listed_per_name() {
    use agentplane::manifest::{MemoryRegistry, Registry};

    let reg = MemoryRegistry::new();
    reg.publish(&Manifest::parse(GOOD).expect("parse"))
        .await
        .expect("publish");
    reg.publish(&Manifest::parse(&GOOD.replace("\"2.0.0\"", "\"2.1.0\"")).expect("parse"))
        .await
        .expect("publish");
    reg.publish(
        &Manifest::parse(&GOOD.replace("pattern-compliance-auditor", "other")).expect("parse"),
    )
    .await
    .expect("publish");

    let vs = reg
        .versions("pattern-compliance-auditor")
        .await
        .expect("versions");
    assert_eq!(vs, vec!["2.0.0", "2.1.0"], "versions leaked across names");
}

/// A prompt declared in the manifest is covered by its digest.
///
/// The point of `spec.identity`. A prompt composed in Rust changes in a deploy
/// and nothing connects that change to the runs it affected; declared here, a
/// reworded instruction *is* a new manifest identity, and "which exact prompt
/// produced this decision" survives six months.
#[test]
fn rewording_a_prompt_changes_the_manifest_identity() {
    let with_identity = GOOD.replace(
        "spec:\n",
        "spec:\n  identity:\n    role: \"Automated data invariant auditor\"\n    \
         constraints: \"Isolate structural failures.\"\n",
    );
    let a = Manifest::parse(&with_identity).expect("parse");
    assert_eq!(
        a.spec.identity.as_ref().expect("identity").role,
        "Automated data invariant auditor"
    );

    let reworded = Manifest::parse(&with_identity.replace(
        "Isolate structural failures.",
        "Isolate structural failures. Escalate anything ambiguous.",
    ))
    .expect("parse");

    assert_ne!(
        a.digest().unwrap(),
        reworded.digest().unwrap(),
        "rewording the prompt did not change the manifest's identity, so a \
         prompt change would be invisible to anything pinning the digest"
    );

    // And a manifest with no identity at all is still valid — an embedder may
    // compose its prompt in code, and forcing the field would just produce
    // manifests with a placeholder in it.
    Manifest::parse(GOOD).expect("identity is optional");
}

/// The rendered prompt has a layout, and changing it is a test failure.
///
/// This is the one edit in the crate that could silently change model behaviour
/// for every embedder without changing any manifest or any digest. Pinning the
/// exact bytes is the only thing that makes the digest's promise honest.
#[test]
fn a_rendered_prompt_has_a_pinned_layout() {
    use agentplane::manifest::Identity;

    let full = Identity {
        role: "Automated data invariant auditor".into(),
        constraints: "Isolate structural failures.".into(),
        workload_id: None,
    };
    assert_eq!(
        full.system_prompt(),
        "Automated data invariant auditor\n\nIsolate structural failures.",
        "the prompt template changed — every agent's prompt just changed with it, \
         and no manifest digest moved to record it"
    );

    // No constraints means no trailing blank lines, not an empty paragraph the
    // model has to interpret.
    let bare = Identity {
        role: "  Automated data invariant auditor  ".into(),
        constraints: "   ".into(),
        workload_id: None,
    };
    assert_eq!(bare.system_prompt(), "Automated data invariant auditor");
}

/// A declared identity has to say something.
#[test]
fn a_blank_role_is_refused() {
    let blank = GOOD.replace("spec:\n", "spec:\n  identity:\n    role: \"  \"\n");
    match Manifest::parse(&blank) {
        Err(ManifestError::Empty(field)) => assert_eq!(field, "spec.identity.role"),
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a manifest declared an identity that says nothing"),
    }
}

// ── The output contract ─────────────────────────────────────────────────────

/// A declared result shape is covered by the digest.
///
/// `capabilities.provides` names a capability; this says what comes back.
/// Narrowing a field is a breaking change to every consumer, so it has to be a
/// version bump rather than a deploy nothing records.
#[test]
fn narrowing_the_output_schema_changes_the_manifest_identity() {
    let with_output = GOOD.replace(
        "  tools:",
        "  output:\n    schema:\n      type: object\n      required: [finding]\n  tools:",
    );
    let a = Manifest::parse(&with_output).expect("parse");
    assert!(
        a.output_schema().is_some(),
        "the schema did not survive parsing"
    );

    let narrowed = Manifest::parse(
        &with_output.replace("required: [finding]", "required: [finding, severity]"),
    )
    .expect("parse");

    assert_ne!(
        a.digest().unwrap(),
        narrowed.digest().unwrap(),
        "narrowing the result contract did not change the manifest's identity"
    );
}

/// An output contract that constrains nothing is refused.
///
/// `{}` is a *valid* JSON Schema meaning "anything", so it parses, looks
/// answered in review, and promises nothing. An agent with no machine-readable
/// result omits `output` entirely — the distinction this refusal preserves.
#[test]
fn an_output_schema_that_permits_anything_is_refused() {
    let empty = GOOD.replace("  tools:", "  output:\n    schema: {}\n  tools:");
    match Manifest::parse(&empty) {
        Err(ManifestError::Empty(field)) => assert_eq!(field, "spec.output.schema"),
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("an output contract that constrains nothing was accepted"),
    }

    // And something that is not a schema object at all.
    let wrong = GOOD.replace("  tools:", "  output:\n    schema: \"an object\"\n  tools:");
    assert!(
        matches!(
            Manifest::parse(&wrong),
            Err(ManifestError::NotASchema { .. })
        ),
        "a string was accepted as a JSON Schema"
    );
}

// ── The models ──────────────────────────────────────────────────────────────

/// Swapping a model changes the manifest's identity.
///
/// A model id is a behaviour change, and one made in a deploy has no version,
/// no diff, and nothing connecting it to the runs whose outputs changed.
#[test]
fn swapping_a_model_changes_the_manifest_identity() {
    let with_models = GOOD.replace(
        "  tools:",
        "  models:\n    privileged: { provider: anthropic, model: claude-sonnet-5 }\n  tools:",
    );
    let a = Manifest::parse(&with_models).expect("parse");
    assert_eq!(
        a.spec
            .models
            .as_ref()
            .unwrap()
            .privileged
            .as_ref()
            .unwrap()
            .model,
        "claude-sonnet-5"
    );

    let swapped =
        Manifest::parse(&with_models.replace("claude-sonnet-5", "claude-haiku-4-5-20251001"))
            .expect("parse");
    assert_ne!(
        a.digest().unwrap(),
        swapped.digest().unwrap(),
        "changing the model did not change the manifest's identity"
    );

    // `models: {}` is a declared absence of inference, not a mistake.
    let none = Manifest::parse(&GOOD.replace("  tools:", "  models: {}\n  tools:"))
        .expect("`models: {}` declares a rules-only agent on purpose");
    assert_eq!(
        none.spec.models,
        Some(agentplane::manifest::Models::default()),
        "`models: {{}}` must parse as a declared, empty model set"
    );
}

/// A model reference has to name something.
#[test]
fn a_blank_model_reference_is_refused() {
    let blank = GOOD.replace(
        "  tools:",
        "  models:\n    privileged: { provider: \"  \", model: claude-sonnet-5 }\n  tools:",
    );
    match Manifest::parse(&blank) {
        Err(ManifestError::Empty(field)) => assert_eq!(field, "spec.models.privileged"),
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a model reference with no provider was accepted"),
    }
}

// ── Topology ────────────────────────────────────────────────────────────────
//
// Inter-agent misalignment is the largest single class of multi-agent failure,
// and it is the one class that exists only because somebody chose an
// arrangement. So the arrangement is declared, and the combinations that
// describe nothing are refused.

/// A specialist may not delegate.
///
/// The structural answer to the handoff loop — A hands to B, B to C, C back to
/// A — which is the consistently reported top failure mode of handoff
/// architectures. Most agents in an arrangement have no authority to hand off at
/// all, and an agent that turns out to delegate when nobody expected it to is
/// how a bounded task becomes an unbounded one.
#[test]
fn a_specialist_that_may_delegate_is_refused() {
    let s = GOOD.replace(
        "  security:",
        "  topology: { mode: single, role: specialist }\n  security:",
    );
    // `GOOD` declares max_delegation_depth: 2.
    match Manifest::parse(&s) {
        Err(ManifestError::IncoherentTopology { detail }) => {
            assert!(detail.contains("specialist"), "wrong detail: {detail}");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!(
            "a specialist was allowed to hand off, which is an orchestrator that \
             nobody reviewed as one"
        ),
    }

    // Depth zero is what a specialist means, and must be accepted.
    Manifest::parse(&s.replace("max_delegation_depth: 2", "max_delegation_depth: 0"))
        .expect("a specialist that cannot delegate is the ordinary case");

    // An orchestrator is the role that may.
    Manifest::parse(&GOOD.replace(
        "  security:",
        "  topology: { mode: collaborative, role: orchestrator, reason: distinct-authority }\n  security:",
    ))
    .expect("an orchestrator is precisely the role permitted to delegate");
}

/// A lone agent cannot be an orchestrator.
#[test]
fn single_mode_refuses_a_coordinating_role() {
    for role in ["orchestrator", "router"] {
        let s = GOOD.replace(
            "  security:",
            &format!("  topology: {{ mode: single, role: {role} }}\n  security:"),
        );
        assert!(
            matches!(
                Manifest::parse(&s),
                Err(ManifestError::IncoherentTopology { .. })
            ),
            "mode 'single' accepted role '{role}' — there is nobody to coordinate"
        );
    }
}

/// Collaboration has to say why, and only collaboration may.
#[test]
fn collaboration_requires_a_reason_and_nothing_else_may_carry_one() {
    let no_reason = GOOD.replace(
        "  security:",
        "  topology: { mode: collaborative, role: orchestrator }\n  security:",
    );
    assert!(
        matches!(
            Manifest::parse(&no_reason),
            Err(ManifestError::IncoherentTopology { .. })
        ),
        "collaboration was accepted without a declared justification"
    );

    // A justification for something this agent does not do reads in review as
    // one that was required.
    let stray = GOOD.replace(
        "  security:",
        "  topology: { mode: routed, role: router, reason: distinct-authority }\n  security:",
    );
    assert!(
        matches!(
            Manifest::parse(&stray),
            Err(ManifestError::IncoherentTopology { .. })
        ),
        "a collaboration reason was accepted on a non-collaborative mode"
    );

    // And a routed router, which is the shape most "we run multi-agent"
    // deployments actually have.
    Manifest::parse(&GOOD.replace(
        "  security:",
        "  topology: { mode: routed, role: router }\n  security:",
    ))
    .expect("routing to one agent per trigger is a dispatch table, and legitimate");
}

/// Every topology value has a pinned wire spelling.
#[test]
fn every_topology_value_has_a_pinned_wire_spelling() {
    use agentplane::manifest::{Justification, Role, TopologyMode};

    for (wire, expected) in [
        ("single", TopologyMode::Single),
        ("routed", TopologyMode::Routed),
        ("collaborative", TopologyMode::Collaborative),
    ] {
        let role = if wire == "single" {
            "specialist"
        } else {
            "orchestrator"
        };
        let reason = if wire == "collaborative" {
            ", reason: parallel-disjoint"
        } else {
            ""
        };
        // A specialist may not delegate, and `GOOD` declares depth 2.
        let m = Manifest::parse(
            &GOOD
                .replace("max_delegation_depth: 2", "max_delegation_depth: 0")
                .replace(
                    "  security:",
                    &format!("  topology: {{ mode: {wire}, role: {role}{reason} }}\n  security:"),
                ),
        )
        .replace_err(wire);
        assert_eq!(m.spec.topology.expect("topology").mode, expected);
    }

    for (wire, expected) in [
        ("specialist", Role::Specialist),
        ("orchestrator", Role::Orchestrator),
        ("router", Role::Router),
    ] {
        let m = Manifest::parse(
            &GOOD
                .replace("max_delegation_depth: 2", "max_delegation_depth: 0")
                .replace(
                    "  security:",
                    &format!("  topology: {{ mode: routed, role: {wire} }}\n  security:"),
                ),
        )
        .replace_err(wire);
        assert_eq!(m.spec.topology.expect("topology").role, expected);
    }

    for (wire, expected) in [
        ("parallel-disjoint", Justification::ParallelDisjoint),
        ("distinct-authority", Justification::DistinctAuthority),
    ] {
        let m = Manifest::parse(&GOOD.replace(
            "  security:",
            &format!(
                "  topology: {{ mode: collaborative, role: orchestrator, reason: {wire} }}\n  security:"
            ),
        ))
        .replace_err(wire);
        assert_eq!(m.spec.topology.expect("topology").reason, Some(expected));
    }

    // And a value nobody defined is refused rather than defaulted to the
    // cheapest-looking shape.
    assert!(
        Manifest::parse(&GOOD.replace("  security:", "  topology: { mode: swarm }\n  security:"))
            .is_err(),
        "an undefined topology mode was accepted"
    );
}

/// Panics naming the wire spelling that stopped parsing.
trait ReplaceErr {
    fn replace_err(self, wire: &str) -> Manifest;
}

impl ReplaceErr for Result<Manifest, ManifestError> {
    fn replace_err(self, wire: &str) -> Manifest {
        self.unwrap_or_else(|e| panic!("`{wire}` no longer parses: {e}"))
    }
}

// ── The manifest binds ──────────────────────────────────────────────────────
//
// Everything above proves the *document* refuses bad declarations. These prove
// the declaration refuses bad *behaviour* — which is the difference between a
// security document and a comment. Without them `spec.models` describes what the
// code is supposed to do: a reviewer approves one model, the code calls another,
// and nothing anywhere disagrees.

const BOUND: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: bound-agent, version: "1.0.0" }
spec:
  capabilities:
    provides: [work.do]
  models:
    privileged: { provider: fake, model: declared-1 }
  budgets: {}
"#;

#[derive(Debug)]
struct BoundarySink {
    max_sensitivity: agentplane::core::Sensitivity,
    delegation_depth: Option<usize>,
    arguments: serde_json::Value,
}

#[async_trait::async_trait]
impl agentplane::core::Effect for BoundarySink {
    type Output = serde_json::Value;

    fn descriptor(&self) -> agentplane::core::EffectDescriptor {
        agentplane::core::EffectDescriptor::nullary("test.boundary/sink")
    }

    fn max_sensitivity(&self) -> agentplane::core::Sensitivity {
        self.max_sensitivity
    }

    fn sink_arguments(&self) -> Option<&serde_json::Value> {
        Some(&self.arguments)
    }

    fn delegation_depth(&self) -> Option<usize> {
        self.delegation_depth
    }

    async fn perform(&self) -> Result<serde_json::Value, agentplane::core::EffectError> {
        Ok(serde_json::json!({ "sent": true }))
    }
}

#[derive(Debug)]
struct ProbesBoundary {
    label: agentplane::core::Sensitivity,
    sink: BoundarySink,
}

#[async_trait::async_trait]
impl agentplane::core::Skill for ProbesBoundary {
    fn descriptor(&self) -> agentplane::core::SkillDescriptor {
        agentplane::core::SkillDescriptor::new("boundary-probe").provides("work.do")
    }

    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _input: agentplane::core::Tainted<serde_json::Value>,
    ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
        let args = agentplane::core::Tainted::with_label(
            serde_json::json!({ "record": "customer" }),
            agentplane::core::Label::trusted().with_sensitivity(self.label),
        );
        let out = cx
            .sink(
                BoundarySink {
                    max_sensitivity: self.sink.max_sensitivity,
                    delegation_depth: self.sink.delegation_depth,
                    arguments: args.peek().clone(),
                },
                &args,
            )
            .await?;
        Ok(agentplane::core::Outcome::done(out))
    }
}

async fn run_boundary(
    security: &str,
    label: agentplane::core::Sensitivity,
    delegation_depth: Option<usize>,
) -> agentplane::runtime::RunOutcome {
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{Agent, Runtime};
    use std::sync::Arc;

    let source = BOUND.replace("spec:\n", &format!("spec:\n  security:\n{security}"));
    let manifest = Manifest::parse(&source).expect("parse");
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    Runtime::builder(store)
        .agent(Agent::new(&manifest).skill(ProbesBoundary {
            label,
            sink: BoundarySink {
                max_sensitivity: agentplane::core::Sensitivity::Secret,
                delegation_depth,
                arguments: serde_json::Value::Null,
            },
        }))
        .build()
        .run("work.do", serde_json::json!({}))
        .await
        .expect("run")
}

/// The manifest's egress ceiling is a runtime control, not review-only prose.
#[tokio::test]
async fn the_manifest_egress_ceiling_binds_every_sink() {
    let out = run_boundary(
        "    max_sensitivity_egress: internal\n",
        agentplane::core::Sensitivity::Confidential,
        None,
    )
    .await;
    match out.status {
        agentplane::runtime::RunStatus::Failed(reason) => assert!(
            reason.contains("Confidential") && reason.contains("Internal"),
            "wrong refusal: {reason}"
        ),
        other => panic!("a confidential value crossed an internal manifest ceiling: {other:?}"),
    }
}

/// A delegating effect is refused at the last boundary before dispatch.
#[tokio::test]
async fn the_manifest_delegation_ceiling_binds_every_handoff() {
    let out = run_boundary(
        "    max_delegation_depth: 1\n",
        agentplane::core::Sensitivity::Public,
        Some(2),
    )
    .await;
    match out.status {
        agentplane::runtime::RunStatus::Failed(reason) => assert!(
            reason.contains("delegation depth 2") && reason.contains("ceiling 1"),
            "wrong refusal: {reason}"
        ),
        other => panic!("a depth-two handoff crossed a depth-one manifest ceiling: {other:?}"),
    }
}

/// A skill that calls whichever model it was handed, ignoring the manifest.
#[derive(Debug)]
struct CallsModel {
    provider: std::sync::Arc<agentplane::testkit::FakeProvider>,
    model: agentplane::model::ModelId,
    /// Which capability this skill answers, so two of them can sit on one plane
    /// under different agents.
    capability: &'static str,
}

#[async_trait::async_trait]
impl agentplane::core::Skill for CallsModel {
    fn descriptor(&self) -> agentplane::core::SkillDescriptor {
        agentplane::core::SkillDescriptor::new(self.capability).provides(self.capability)
    }

    async fn invoke(
        &self,
        cx: &mut agentplane::runtime::StepCtx<'_>,
        _input: agentplane::core::Tainted<serde_json::Value>,
    ) -> Result<agentplane::core::Outcome, agentplane::core::SkillError> {
        let prompt = agentplane::core::Tainted::trusted(serde_json::json!({ "q": "hello" }));
        let call = agentplane::model::ModelCall::new(
            std::sync::Arc::clone(&self.provider)
                as std::sync::Arc<dyn agentplane::model::ModelProvider>,
            self.model.clone(),
            prompt.peek().clone(),
        );
        let c = cx.sink(call, &prompt).await?;
        Ok(agentplane::core::Outcome::done(
            c.map(|c| serde_json::json!({ "text": c.text })),
        ))
    }
}

async fn run_with(model: &str) -> agentplane::runtime::RunOutcome {
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{Agent, Runtime};
    use std::sync::Arc;

    let m = Manifest::parse(BOUND).expect("parse");
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let provider = agentplane::testkit::FakeProvider::new();
    let rt = Runtime::builder(store)
        .agent(Agent::new(&m).skill(CallsModel {
            provider,
            model: agentplane::model::ModelId::new("fake", model),
            capability: "work.do",
        }))
        .build();
    rt.run("work.do", serde_json::json!({})).await.expect("run")
}

/// A model the manifest never named is refused before it is called.
///
/// The declaration binds, or it is decoration. A reviewer who approved
/// `declared-1` has to be able to rely on `undeclared-9` not running, and the
/// only thing that can deliver that is the runtime refusing it.
#[tokio::test]
async fn a_model_the_manifest_never_declared_is_refused() {
    let declared = run_with("declared-1").await;
    assert!(
        matches!(declared.status, agentplane::runtime::RunStatus::Succeeded),
        "the declared model must still work: {:?}",
        declared.status
    );

    let smuggled = run_with("undeclared-9").await;
    match &smuggled.status {
        agentplane::runtime::RunStatus::Failed(msg) => {
            assert!(
                msg.contains("undeclared-9") && msg.contains("bound-agent"),
                "the refusal must name what was attempted and whose declaration \
                 refused it: {msg}"
            );
        }
        other => panic!(
            "a model the manifest never declared ran anyway ({other:?}) — the file \
             a reviewer approved and the model that answered are then two \
             independent copies of one decision"
        ),
    }
}

/// The refusal is in the journal, not just in the return value.
///
/// A control that leaves no record is a control an auditor cannot confirm ever
/// ran — and a replay that found no history here would report the *build* as
/// divergent, sending an operator after a code change that does not exist.
#[tokio::test]
async fn a_manifest_refusal_is_journaled() {
    use agentplane::journal::{JournalStore, RecordKind};
    use agentplane::runtime::{Agent, Runtime};
    use std::sync::Arc;

    let m = Manifest::parse(BOUND).expect("parse");
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let provider = agentplane::testkit::FakeProvider::new();
    let rt = Runtime::builder(Arc::clone(&store))
        .agent(Agent::new(&m).skill(CallsModel {
            provider: Arc::clone(&provider),
            model: agentplane::model::ModelId::new("fake", "undeclared-9"),
            capability: "work.do",
        }))
        .build();

    let out = rt.run("work.do", serde_json::json!({})).await.expect("run");
    let records = store.read(out.run_id, 1).await.expect("read");

    let denial = records
        .iter()
        .find_map(|r| match r.kind() {
            RecordKind::PolicyDenied { action, reason, .. } => {
                Some((action.clone(), reason.clone()))
            }
            _ => None,
        })
        .expect("the refusal must be in the journal");

    assert_eq!(
        denial.0,
        agentplane::core::ACTION_DECLARED,
        "a manifest refusal must be distinguishable from a policy denial: the \
         first is the agent doing something its own declaration never mentioned, \
         the second is the deployment's rules saying no"
    );
    assert!(denial.1.contains("undeclared-9"), "got: {}", denial.1);

    // And the model was never actually called.
    assert_eq!(
        provider.calls(),
        0,
        "the effect was refused *after* it reached the provider, which bounds \
         nothing — the point of checking before dispatch is that the call does \
         not happen"
    );
}

#[cfg(feature = "redb")]
#[tokio::test]
async fn protected_tool_fields_must_match_the_live_catalogue() {
    use agentplane::core::{Outcome, ProtectedField, Skill, SkillDescriptor, SkillError, Tainted};
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{RunStatus, Runtime, StepCtx};
    use agentplane::tools::{ToolCall, ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct Client(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl ToolClient for Client {
        async fn call(
            &self,
            _tool: &ToolId,
            _arguments: &Value,
            _provenance: Option<&agentplane::core::Provenance>,
        ) -> Result<Value, ToolError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(json!({ "sent": true }))
        }
    }

    #[derive(Debug)]
    struct CallsTool {
        catalog: ToolCatalog,
        client: Arc<Client>,
    }

    #[async_trait::async_trait]
    impl Skill for CallsTool {
        fn descriptor(&self) -> SkillDescriptor {
            SkillDescriptor::new("worker").provides("work.do")
        }

        async fn invoke(
            &self,
            cx: &mut StepCtx<'_>,
            _input: Tainted<Value>,
        ) -> Result<Outcome, SkillError> {
            let arguments =
                Tainted::trusted(json!({ "recipient": "treasury", "account": "settlement" }));
            let call = ToolCall::prepare(
                &self.catalog,
                Arc::clone(&self.client) as Arc<dyn ToolClient>,
                ToolId::new("ledger", "transfer"),
                arguments.peek().clone(),
            )
            .map_err(|error| SkillError::Other(error.to_string()))?;
            Ok(Outcome::done(cx.sink(call, &arguments).await?))
        }
    }

    let source = BOUND.replace(
        "  budgets: {}",
        "  budgets: {}\n  tools:\n    - ref: mcp://ledger/transfer\n      protected_fields:\n        - path: /recipient\n          require_trusted: true",
    );
    let manifest = Manifest::parse(&source).expect("parse");
    let calls = Arc::new(AtomicUsize::new(0));
    let client = Arc::new(Client(Arc::clone(&calls)));
    let catalog = ToolCatalog::new().allow(
        ToolId::new("ledger", "transfer"),
        ToolSafety::default().protect(ProtectedField::trusted("/account")),
    );
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));

    let outcome = Runtime::builder(store)
        .agent(agentplane::runtime::Agent::new(&manifest).skill(CallsTool { catalog, client }))
        .build()
        .run("work.do", json!({}))
        .await
        .expect("run");

    match outcome.status {
        RunStatus::Failed(reason) => assert!(
            reason.contains("live catalogue disagree about protected fields"),
            "wrong refusal: {reason}"
        ),
        other => panic!("manifest/catalogue disagreement reached the tool: {other:?}"),
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0, "refused before dispatch");
}

// ── The declarative tier ────────────────────────────────────────────────────
//
// The tier where the digest covers the *whole* agent. Everywhere else the
// manifest governs the boundary of code somebody wrote; here there is no code,
// so there is nothing outside the digest to diverge.

const DECLARATIVE: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: summariser, version: "1.0.0" }
spec:
  execution:
    kind: completion
  identity:
    role: "Summarise a support ticket"
    constraints: "One sentence. No speculation."
  capabilities:
    provides: [support.summarise]
  models:
    privileged: { provider: fake, model: sum-1 }
  output:
    schema:
      type: object
      required: [summary]
      properties:
        summary: { type: string }
  budgets:
    max_tokens: 10000
"#;

/// An agent that is only a file runs.
///
/// Not one line of behaviour is written here: the prompt, the model, the result
/// shape and the ceiling all come from the manifest, and the runtime supplies
/// the conduct. That is what makes the digest cover the entire agent rather than
/// only its boundary.
#[tokio::test]
async fn an_agent_defined_only_in_yaml_runs() {
    use agentplane::journal::JournalStore;
    use agentplane::runtime::{RunStatus, Runtime};
    use std::sync::Arc;

    let m = Manifest::parse(DECLARATIVE).expect("parse");
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let provider = agentplane::testkit::FakeProvider::new();

    // The only Rust: which driver answers to the name `fake`. That is deployment
    // wiring — an agent's declaration must not change when its API key does.
    let rt = Runtime::builder(store)
        .provider(
            "fake",
            Arc::clone(&provider) as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(agentplane::runtime::Agent::new(&m))
        .build();

    let out = rt
        .run(
            "support.summarise",
            serde_json::json!({ "ticket": "printer on fire" }),
        )
        .await
        .expect("run");

    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "a declarative agent did not run: {:?}",
        out.status
    );

    // The wire spelling, pinned. `kind` is the one field that selects *code*,
    // so renaming the variant would silently change which behaviour a manifest
    // asks for — and the failure would land in somebody else's deployment.
    assert_eq!(
        m.spec.execution.expect("execution").kind,
        agentplane::manifest::ExecutionKind::Completion
    );

    // The declaration reached the provider — prompt, model and schema.
    let asked = provider.asked();
    let ask = asked.first().expect("the provider was asked");
    assert_eq!(
        ask.prompt["system"].as_str(),
        Some("Summarise a support ticket\n\nOne sentence. No speculation."),
        "the manifest's prompt is not the one that was sent"
    );
    assert_eq!(ask.model, agentplane::model::ModelId::new("fake", "sum-1"));
    assert!(
        ask.schema.is_some(),
        "the declared result shape was not requested"
    );
}

/// A declarative agent may not be run on a driver its file never named.
///
/// Falling back to whatever driver happened to be registered would run the agent
/// on a model its own declaration does not name — the exact substitution this
/// layer exists to refuse, arrived at by convenience instead of by attack.
#[test]
#[should_panic(expected = "no driver is registered for")]
fn a_declarative_agent_refuses_an_unnamed_provider() {
    use agentplane::journal::JournalStore;
    use agentplane::runtime::Runtime;
    use std::sync::Arc;

    let m = Manifest::parse(DECLARATIVE).expect("parse");
    let store: Arc<dyn JournalStore> =
        Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let provider = agentplane::testkit::FakeProvider::new();

    // Registered under a *different* name than the manifest asks for.
    let _ = Runtime::builder(store)
        .provider(
            "anthropic",
            provider as Arc<dyn agentplane::model::ModelProvider>,
        )
        .agent(agentplane::runtime::Agent::new(&m))
        .build();
}

// ── Declared oversight ──────────────────────────────────────────────────────

/// Oversight declared where nothing could apply it is refused.
///
/// The binding rule as a parse error. A hand-written skill chooses its own
/// moment to ask, so `oversight` beside a coded agent would name a control the
/// runtime never performs — and the reviewer who approved the file would believe
/// a human was in the loop.
#[test]
fn oversight_without_a_declarative_agent_is_refused() {
    let coded = DECLARATIVE
        .replace("  execution:\n    kind: completion\n", "")
        .replace(
            "  identity:",
            "  oversight:\n    approval: required\n    deadline: same-day\n  identity:",
        );
    match Manifest::parse(&coded) {
        Err(ManifestError::Unenforceable { field, .. }) => {
            assert_eq!(field, "spec.oversight");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!(
            "oversight was accepted where nothing applies it — the file claims a \
             human is in the loop and no human ever is"
        ),
    }

    // Beside a declarative agent it is accepted, because there it binds.
    let declared = DECLARATIVE.replace(
        "  identity:",
        "  oversight:\n    approval: required\n    deadline: same-day\n  identity:",
    );
    Manifest::parse(&declared).expect("oversight binds for a declarative agent");
}

/// Acting unattended has to be written down.
///
/// The runtime already refuses `OnExpiry::Proceed` without explicit consent. The
/// file demands the same, so the decision is greppable in the document a
/// reviewer reads rather than only in the code they do not.
#[test]
fn proceeding_with_no_human_must_be_stated() {
    let sloppy = DECLARATIVE.replace(
        "  identity:",
        "  oversight:\n    approval: required\n    deadline: same-day\n    on_expiry: proceed\n  identity:",
    );
    assert!(
        matches!(
            Manifest::parse(&sloppy),
            Err(ManifestError::Unenforceable { .. })
        ),
        "an agent was allowed to act unattended on expiry without anybody saying so"
    );

    let deliberate = sloppy.replace(
        "    on_expiry: proceed\n",
        "    on_expiry: proceed\n    allow_unattended: true\n",
    );
    Manifest::parse(&deliberate).expect("stated explicitly, it is a legitimate choice");
}

/// The default when the window closes is to refuse.
#[test]
fn an_unstated_expiry_denies() {
    use agentplane::manifest::Expiry;
    let m = Manifest::parse(&DECLARATIVE.replace(
        "  identity:",
        "  oversight:\n    approval: required\n    deadline: same-day\n  identity:",
    ))
    .expect("parse");
    let o = m.spec.oversight.expect("oversight");
    assert_eq!(
        o.on_expiry,
        Expiry::Deny,
        "an unstated expiry must refuse, not proceed — the safe direction is the \
         one nobody has to remember to choose"
    );
    // The wire spelling, pinned: renaming the variant would silently change the
    // vocabulary of every manifest in the field, and the failure would be a
    // parse error at deploy time in somebody else's repository.
    assert_eq!(o.approval, agentplane::manifest::Approval::Required);
}

// ── Signing: proving *who*, not just *what* ─────────────────────────────────

/// A signature says who published, which no digest can.
///
/// Immutability and pinning both answer *what* was published. Neither answers
/// *who*, and "the registry accepted it" is not an answer when the registry is
/// the thing you are worried about.
#[tokio::test]
async fn a_signed_manifest_names_who_published_it() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};
    use agentplane::testkit::StubSigner;

    let signer = StubSigner::new("release-bot");
    let reg = MemoryRegistry::new();
    let m = Manifest::parse(GOOD).expect("parse");
    reg.publish_signed(&m, &signer).await.expect("publish");

    let (back, key) = reg
        .resolve_verified("pattern-compliance-auditor", "2.0.0", &signer)
        .await
        .expect("a manifest this signer signed must verify under it");
    assert_eq!(back, m);
    assert_eq!(key, "release-bot", "the wrong identity was reported");

    // An unsigned publish is refused by a verifying resolve — and reported
    // distinctly, because "nobody signed this yet" is an operational fact and
    // "this signature is wrong" is an incident.
    let unsigned = MemoryRegistry::new();
    unsigned.publish(&m).await.expect("publish");
    assert!(
        matches!(
            unsigned
                .resolve_verified("pattern-compliance-auditor", "2.0.0", &signer)
                .await,
            Err(RegistryError::Unsigned { .. })
        ),
        "an unsigned manifest passed a resolve that required a signature"
    );
}

/// Signing adoption must not require deleting and republishing an immutable
/// version.
///
/// A deployment may first publish without a signer and enable workload signing
/// later. `publish_signed` returning success while preserving the unsigned row
/// is a false success: the caller believes publication recorded authorship, but
/// the only verifying read still reports `Unsigned`.
#[tokio::test]
async fn signing_an_existing_unsigned_manifest_records_the_publisher() {
    use agentplane::manifest::{MemoryRegistry, Registry};
    use agentplane::testkit::StubSigner;

    let signer = StubSigner::new("release-bot");
    let reg = MemoryRegistry::new();
    let m = Manifest::parse(GOOD).expect("parse");
    let unsigned = reg.publish(&m).await.expect("unsigned publish");
    let signed_digest = reg
        .publish_signed(&m, &signer)
        .await
        .expect("signing the identical immutable artifact must succeed");
    assert_eq!(
        signed_digest, unsigned,
        "signing must not change artifact identity"
    );

    let (back, key) = reg
        .resolve_verified("pattern-compliance-auditor", "2.0.0", &signer)
        .await
        .expect("a successful signed publish must leave a verifiable artifact");
    assert_eq!(back, m);
    assert_eq!(key, "release-bot");
}

/// Publisher evidence is immutable just like the artifact it approves.
#[tokio::test]
async fn republishing_with_another_signer_cannot_reassign_the_publisher() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};
    use agentplane::testkit::StubSigner;

    let original = StubSigner::new("release-bot");
    let replacement = StubSigner::new("compromised-bot");
    let reg = MemoryRegistry::new();
    let m = Manifest::parse(GOOD).expect("parse");
    reg.publish_signed(&m, &original).await.expect("publish");

    match reg.publish_signed(&m, &replacement).await {
        Err(RegistryError::PublisherChanged {
            existing, offered, ..
        }) => {
            assert_eq!(existing, "release-bot");
            assert_eq!(offered, "compromised-bot");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("identical bytes silently changed who published them"),
    }

    let (_, key) = reg
        .resolve_verified("pattern-compliance-auditor", "2.0.0", &original)
        .await
        .expect("the original publisher evidence must survive");
    assert_eq!(key, "release-bot");
}

/// A signature made for one purpose cannot be reused for another.
///
/// `Signer::sign` takes a bare digest, so a manifest signature and a record
/// attestation are structurally identical — same key, same algorithm, same input
/// shape, and nothing in either saying which question it answered. Domain
/// separation is what stops one being presented as the other.
///
/// Checked **through the registry**, not against the helper: a domain-separation
/// function nobody calls separates nothing, and the first version of this test
/// asserted only that the helper's output differs — which a mutation removing
/// the registry's use of it survived.
#[tokio::test]
async fn a_manifest_signature_is_bound_to_being_a_manifest() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};
    use agentplane::testkit::StubSigner;

    /// Accepts exactly one thing: a signature over the manifest's **bare**
    /// digest — which is what a record attestation over the same value would be.
    ///
    /// It ignores the hash it is handed, on purpose. The registry chooses that
    /// input, so a verifier that recomputed from it would agree with whatever
    /// the registry did and prove nothing. Naming the bare digest up front is
    /// what makes this able to disagree.
    #[derive(Debug)]
    struct AcceptsBareDigestSignature {
        signer: StubSigner,
        bare: agentplane::core::Digest,
    }

    impl agentplane::core::Verifier for AcceptsBareDigestSignature {
        fn verify(&self, key_id: &str, _handed: &agentplane::core::Digest, sig: &[u8]) -> bool {
            use agentplane::core::Signer;
            key_id == self.signer.key_id() && sig == self.signer.sign(&self.bare)
        }
    }

    let signer = StubSigner::new("release-bot");
    let reg = MemoryRegistry::new();
    let m = Manifest::parse(GOOD).expect("parse");
    reg.publish_signed(&m, &signer).await.expect("publish");

    // `resolve_verified` hands the verifier the domain-separated hash. A
    // registry that signed the bare digest would produce a signature this
    // verifier accepts over that same input — so acceptance here means the
    // domain is not binding anything.
    let bare = AcceptsBareDigestSignature {
        signer: StubSigner::new("release-bot"),
        bare: m.digest().expect("digest"),
    };
    match reg
        .resolve_verified("pattern-compliance-auditor", "2.0.0", &bare)
        .await
    {
        Err(RegistryError::BadSignature { .. }) => {}
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!(
            "a signature over the bare digest verified as approval of a manifest — \
             a record attestation could then be presented as a publisher's blessing"
        ),
    }

    // And the domain-separated signer still verifies, so this is not a test that
    // passes by refusing everything.
    reg.resolve_verified("pattern-compliance-auditor", "2.0.0", &signer)
        .await
        .expect("the signature that was actually made must still verify");
}

/// Content that does not match its signature is refused.
#[tokio::test]
async fn a_manifest_whose_signature_does_not_check_out_is_refused() {
    use agentplane::manifest::{MemoryRegistry, Registry, RegistryError};
    use agentplane::testkit::StubSigner;

    let publisher = StubSigner::new("release-bot");
    let reg = MemoryRegistry::new();
    reg.publish_signed(&Manifest::parse(GOOD).expect("parse"), &publisher)
        .await
        .expect("publish");

    // A different identity: the signature is real, but not one this verifier
    // will vouch for.
    let stranger = StubSigner::new("someone-else");
    match reg
        .resolve_verified("pattern-compliance-auditor", "2.0.0", &stranger)
        .await
    {
        Err(RegistryError::BadSignature { key_id, .. }) => {
            assert_eq!(key_id, "release-bot");
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a manifest verified under a key that did not sign it"),
    }
}

/// A reviewed tool grant tightens; it never loosens.
///
/// `ToolGrant::mutates` and `ToolGrant::max_sensitivity` are the operator's
/// decision about a tool, and a server's own description of itself is an
/// advertisement. So the grant must be able to say "treat this as mutating" or
/// "this one may not see internal data" and have it *bind* — otherwise a
/// reviewer approves two fields that nothing consults, which is the failure the
/// binding rule exists to prevent.
#[test]
fn a_reviewed_tool_grant_can_only_tighten() {
    let m = Manifest::parse(GOOD).expect("parse");
    let grant = m
        .tool_grant("mcp://validator/apply_correction")
        .expect("the fixture grants this tool");

    assert!(grant.mutates, "the fixture declares a mutating tool");
    assert_eq!(
        grant.max_sensitivity,
        Some(agentplane::core::Sensitivity::Internal),
        "the fixture declares a per-tool ceiling"
    );

    // The two fields the runtime must consult. A grant is looked up by exact
    // reference: a near miss is not a match, because resolving a tool name
    // approximately is how authority leaks to a neighbour.
    assert!(
        m.tool_grant("mcp://validator/apply_correction ").is_none(),
        "a trailing space must not resolve to the granted tool"
    );
    assert!(
        m.tool_grant("mcp://validator/apply").is_none(),
        "a prefix must not resolve to the granted tool"
    );
}

/// A `tool-calling` agent runs the loop, and every call is governed.
///
/// The whole point: the model picks the tool and the arguments, and neither
/// choice is authority. The name is matched against the operator's catalogue
/// byte for byte, the call is dispatched through the ordinary sink so grants and
/// labels apply, and every turn is a journaled effect — so a replay reads the
/// conversation back rather than holding it again.
#[cfg(all(feature = "redb", feature = "testkit"))]
#[tokio::test]
async fn a_tool_calling_agent_loops_until_it_answers() {
    use agentplane::runtime::{Agent, Mode, RunStatus, Runtime};
    use agentplane::tools::{ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Default)]
    struct Ledger(AtomicUsize);

    #[async_trait::async_trait]
    impl ToolClient for Ledger {
        async fn call(
            &self,
            _tool: &ToolId,
            _arguments: &Value,
            _p: Option<&agentplane::core::Provenance>,
        ) -> Result<Value, ToolError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(json!({ "balance": 42 }))
        }
    }

    const YAML: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: teller, version: "1.0.0" }
spec:
  capabilities:
    provides: [ledger.ask]
  models:
    privileged: { provider: fake, model: declared-1 }
  tools:
    - ref: mcp://ledger/read
      mutates: false
      description: Read a ledger account's balance.
      arguments:
        type: object
        properties:
          id: { type: string }
        required: [id]
  execution: { kind: tool-calling, max_turns: 4 }
  budgets: {}
"#;

    let m = Manifest::parse(YAML).expect("parse");
    let provider = agentplane::testkit::FakeProvider::new();
    // Turn 1: the model asks. Turn 2: it answers.
    provider.will_call_tool("toolu_1", "ledger__read", json!({ "id": "AC-1" }));
    provider.will_say("the balance is 42");

    // `read_only` is load-bearing. A model's chosen arguments are untrusted by
    // definition, and a *mutating* tool with no field policy refuses untrusted
    // arguments outright — so a mutating tool reached this way is refused, and
    // the refusal is reported back to the model rather than ending the run. That
    // is the design: the model may choose what to read, never what to change,
    // unless the operator declared which fields it may influence.
    let ledger = std::sync::Arc::new(Ledger::default());
    let catalog = std::sync::Arc::new(ToolCatalog::new().allow(
        ToolId::new("ledger", "read"),
        // Cleared for internal data. A model's output is `Internal`, so a
        // tool the operator cleared only for `Public` refuses the call —
        // the egress ceiling doing its job, and reported back to the model
        // rather than ending the run.
        ToolSafety::read_only().max_sensitivity(agentplane::core::Sensitivity::Internal),
    ));
    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));

    let rt = Runtime::builder(std::sync::Arc::clone(&store))
        .provider(
            "fake",
            std::sync::Arc::clone(&provider)
                as std::sync::Arc<dyn agentplane::model::ModelProvider>,
        )
        .tools(
            std::sync::Arc::clone(&catalog),
            std::sync::Arc::clone(&ledger) as std::sync::Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&m))
        .build();

    let out = rt
        .run("ledger.ask", json!({ "q": "balance?" }))
        .await
        .expect("run");
    assert!(
        matches!(out.status, RunStatus::Succeeded),
        "the loop did not finish: {:?}",
        out.status
    );
    assert_eq!(
        ledger.0.load(Ordering::Relaxed),
        1,
        "the granted tool was not called exactly once"
    );
    assert_eq!(provider.calls(), 2, "two turns: the ask, then the answer");

    // Replay reads the whole conversation back — no model, no tool.
    let replayed = rt.replay(out.run_id, Mode::Strict).await.expect("replay");
    assert!(matches!(replayed.status, RunStatus::Succeeded));
    assert_eq!(
        (provider.calls(), ledger.0.load(Ordering::Relaxed)),
        (2, 1),
        "a replay re-ran the conversation, so every turn was paid for twice and \
         the tool acted on the world again"
    );
    assert_eq!(out.output, replayed.output, "the loop replays exactly");
}

/// An agent that will not converge is stopped, and says so.
///
/// A model that keeps asking for tools would otherwise run until the budget
/// stopped it — and a budget stops it *after* paying for every turn. Worse, the
/// last completion is not an answer: returning it would hand back half-formed
/// reasoning as the result, which is the failure that looks like success.
#[cfg(all(feature = "redb", feature = "testkit"))]
#[tokio::test]
async fn a_tool_calling_agent_stops_when_it_will_not_converge() {
    use agentplane::runtime::{Agent, RunStatus, Runtime};
    use agentplane::tools::{ToolCatalog, ToolClient, ToolError, ToolId, ToolSafety};
    use serde_json::{Value, json};

    #[derive(Debug)]
    struct Always;

    #[async_trait::async_trait]
    impl ToolClient for Always {
        async fn call(
            &self,
            _t: &ToolId,
            _a: &Value,
            _p: Option<&agentplane::core::Provenance>,
        ) -> Result<Value, ToolError> {
            Ok(json!({ "again": true }))
        }
    }

    const YAML: &str = r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: looper, version: "1.0.0" }
spec:
  capabilities:
    provides: [loop.forever]
  models:
    privileged: { provider: fake, model: declared-1 }
  tools:
    - ref: mcp://ledger/read
      mutates: false
      description: Read a ledger account's balance.
  execution: { kind: tool-calling, max_turns: 3 }
  budgets: {}
"#;

    let m = Manifest::parse(YAML).expect("parse");
    let provider = agentplane::testkit::FakeProvider::new();
    // Four asks against a ceiling of three: it never gets to answer.
    for i in 0..4 {
        provider.will_call_tool(format!("toolu_{i}"), "ledger__read", json!({}));
    }

    let store: std::sync::Arc<dyn agentplane::journal::JournalStore> =
        std::sync::Arc::new(agentplane::store::RedbStore::open_in_memory().expect("store"));
    let rt = Runtime::builder(store)
        .provider(
            "fake",
            std::sync::Arc::clone(&provider)
                as std::sync::Arc<dyn agentplane::model::ModelProvider>,
        )
        .tools(
            std::sync::Arc::new(ToolCatalog::new().allow(
                ToolId::new("ledger", "read"),
                ToolSafety::read_only().max_sensitivity(agentplane::core::Sensitivity::Internal),
            )),
            std::sync::Arc::new(Always) as std::sync::Arc<dyn ToolClient>,
        )
        .agent(Agent::new(&m))
        .build();

    let out = rt.run("loop.forever", json!({})).await.expect("run");
    match out.status {
        RunStatus::Failed(why) => assert!(
            why.contains("did not finish") && why.contains('3'),
            "the failure must name the ceiling it hit: {why}"
        ),
        other => panic!(
            "an agent still asking for tools was reported as {other:?}. Its last \
             completion is not an answer, and returning it hands back half-formed \
             reasoning as the result"
        ),
    }
    assert_eq!(
        provider.calls(),
        3,
        "the ceiling must stop the turns, not merely label the outcome"
    );
}

/// `kind:` spells the behaviour the way the manifest does.
///
/// The wire spelling is kebab-case and the Rust name is not, so the rename is
/// load-bearing: a manifest saying `tool-calling` must reach
/// [`ExecutionKind::ToolCalling`] and nothing else. And an unknown kind is
/// refused rather than defaulted — a config whose behaviours are open-ended is
/// one nobody can review, because the reviewer would have to know what the
/// string does.
#[test]
fn an_execution_kind_is_spelled_the_way_the_manifest_spells_it() {
    use agentplane::manifest::ExecutionKind;

    let of = |kind: &str| {
        Manifest::parse(&format!(
            r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: k, version: "1.0.0" }}
spec:
  capabilities: {{ provides: [x.y] }}
  models:
    privileged: {{ provider: fake, model: m }}
  execution: {{ kind: {kind} }}
  budgets: {{}}
"#
        ))
    };

    assert_eq!(
        of("tool-calling")
            .expect("parse")
            .spec
            .execution
            .expect("declared")
            .kind,
        ExecutionKind::ToolCalling,
    );
    assert_eq!(
        of("completion")
            .expect("parse")
            .spec
            .execution
            .expect("declared")
            .kind,
        ExecutionKind::Completion,
    );
    assert!(
        of("toolCalling").is_err(),
        "camelCase is not the wire spelling and must not be accepted"
    );
    assert!(
        of("do-whatever").is_err(),
        "an unknown behaviour must be refused, not defaulted to one this crate \
         happens to implement"
    );

    // The default turn ceiling exists, so a manifest that omits it is still
    // bounded rather than unbounded.
    assert!(
        of("tool-calling")
            .expect("parse")
            .spec
            .execution
            .expect("declared")
            .max_turns
            > 0,
        "an omitted `max_turns` must not mean unbounded"
    );
}

/// A tool-calling agent must be able to describe its tools.
///
/// The model picks from what it is told. A grant with no description gives it a
/// bare name to guess from — and a guessed call is refused at the protected-field
/// check *after* the tokens are paid for, so an undescribed tool is not a smaller
/// feature but a slower refusal.
///
/// The description lives in the manifest rather than in code for the same reason
/// the system prompt does: it is text that steers what an agent reaches for, so
/// it belongs where a reviewer sees it as a diff and the digest covers it.
#[test]
fn a_tool_calling_agent_must_describe_its_tools() {
    let with = |extra: &str| {
        Manifest::parse(&format!(
            r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: {{ name: teller, version: "1.0.0" }}
spec:
  capabilities: {{ provides: [x.y] }}
  models:
    privileged: {{ provider: fake, model: m }}
  tools:
    - ref: mcp://ledger/read
      mutates: false
{extra}
  execution: {{ kind: tool-calling }}
  budgets: {{}}
"#
        ))
    };

    assert!(
        with("      description: Read a balance.").is_ok(),
        "a described tool must be accepted"
    );
    let err = with("").expect_err("an undescribed tool must be refused");
    assert!(
        err.to_string().contains("description"),
        "the refusal must name what is missing: {err}"
    );
    assert!(
        with("      description: '   '").is_err(),
        "whitespace is not a description"
    );

    // The same grant is fine for a skill-backed agent: it knows what it calls,
    // so requiring prose there would be decoration.
    assert!(
        Manifest::parse(
            r#"
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: coded, version: "1.0.0" }
spec:
  capabilities: { provides: [x.y] }
  tools:
    - ref: mcp://ledger/read
      mutates: false
  budgets: {}
"#
        )
        .is_ok(),
        "a skill-backed agent must not be forced to describe tools for a model \
         that will never see them"
    );

    // The description and schema are inside the digest: editing either is a
    // version bump, not an untracked deploy.
    let a = with("      description: Read a balance.").expect("parse");
    let b = with("      description: Read a balance, quickly.").expect("parse");
    assert_ne!(
        a.digest().expect("digest"),
        b.digest().expect("digest"),
        "a reworded tool description left the digest unchanged, so the text that \
         steers which tool a model picks could change with no version and \
         nothing connecting it to the runs it altered"
    );
}

/// The published Agent Card is derived from the declaration, not written beside it.
///
/// A card is what a peer reads before deciding to call at all, so it is the most
/// consequential prose an agent publishes. Deriving it means what an agent
/// *advertises* and what it is *permitted* cannot drift — and since the plane
/// refuses to start when a declared capability has no skill behind it, a derived
/// card cannot advertise work the plane would not dispatch.
#[test]
fn an_agent_card_is_derived_from_the_manifest() {
    use agentplane::peers::AgentCard;

    let m = Manifest::parse(GOOD).expect("parse");
    let card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");

    assert_eq!(card.name, m.metadata.name);
    assert_eq!(card.version, m.metadata.version);
    assert_eq!(
        card.skills.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        m.spec.capabilities.provides,
        "the card's skills must be exactly the declared capabilities — a card \
         advertising anything else is advertising work the plane would refuse \
         to dispatch"
    );
    assert_eq!(
        card.manifest_digest,
        m.digest().expect("digest").to_hex(),
        "the card must name the declaration it came from: two cards with one \
         name and version are otherwise indistinguishable when the document \
         behind them changed"
    );

    // **Nothing unimplemented is advertised, and nothing implemented is
    // hidden.** A card is a promise a caller plans against: an unimplemented
    // transport produces a caller waiting for events nobody will send, and an
    // unadvertised one produces a caller that polls what it could have streamed.
    assert!(
        card.capabilities.streaming,
        "streaming is implemented — `SendStreamingMessage` and `SubscribeToTask` \
         are served from the journal — so the flag must say so"
    );
    // Tracks the build rather than a hardcoded answer: the flag exists to tell
    // a caller what *this* deployment can do, and "we compiled that out" is not
    // a distinction a peer can discover any other way.
    assert_eq!(
        card.capabilities.push_notifications,
        cfg!(feature = "push"),
        "the card's push flag disagrees with whether this build has the \
         machinery — a caller plans against it either way"
    );
    assert!(
        card.capabilities.extended_agent_card,
        "the extended card is implemented, so the flag must say so — a capability \
         is advertised because the thing exists, never the other way round"
    );

    // The URL is deployment wiring, not a property of the agent — the same split
    // as an API key.
    assert_eq!(
        card.supported_interfaces[0].url,
        "https://plane.internal/a2a"
    );
    assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
    assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");

    // The wire form is what a conforming client parses: camelCase, and every
    // required A2A v1.0 field present.
    let wire = serde_json::to_value(&card).expect("serialise");
    for required in [
        "name",
        "description",
        "version",
        "capabilities",
        "supportedInterfaces",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    ] {
        assert!(
            wire.get(required).is_some(),
            "the card omits the required A2A field `{required}`: {wire}"
        );
    }
    assert!(
        wire.get("supported_interfaces").is_none(),
        "snake_case leaked into the wire form, which a conforming client will \
         not read: {wire}"
    );
}

/// The extended card says more, and still not everything.
///
/// A2A's `GetExtendedAgentCard` exists because the public card is read by anyone
/// while some of what a peer legitimately needs — which tools the far side can
/// reach, what it may spend — is not for everyone. It is a **separate type** so
/// that serving the wrong one is a compile error rather than a review miss:
/// both are valid JSON, and the extra fields simply appear on a public endpoint
/// where nobody notices until somebody reads them.
#[test]
fn the_extended_card_discloses_more_but_not_the_model() {
    use agentplane::peers::{AgentCard, ExtendedAgentCard};

    let m = Manifest::parse(GOOD).expect("parse");
    let public = AgentCard::derive(&m, "https://plane/a2a").expect("public");
    let extended = ExtendedAgentCard::derive(&m, "https://plane/a2a").expect("extended");

    assert_eq!(
        extended.public, public,
        "the extended card must contain the public one unchanged, or a peer \
         reading both sees two different agents"
    );
    assert_eq!(
        extended.tools.len(),
        m.spec.tools.len(),
        "an authenticated peer deciding whether to delegate needs to know what \
         the far side can reach"
    );
    assert!(
        extended.tools.iter().any(|t| t.mutates),
        "the fixture grants a mutating tool, and `mutates` is the field a peer \
         most needs: an agent that can only read is a different risk from one \
         that can move money"
    );

    // The capability is advertised because the thing exists — not the other way
    // round.
    assert!(
        public.capabilities.extended_agent_card,
        "the extended card is implemented, so the flag must say so"
    );
    assert!(
        public.capabilities.streaming,
        "the extended card must agree with the public one about streaming"
    );
    assert_eq!(
        public.capabilities.push_notifications,
        cfg!(feature = "push"),
        "the extended card must agree with the build about push notifications"
    );

    // What it still will not say. The model is a fact about a supply chain, and
    // the protected-field rules are a map of where to push.
    let wire = serde_json::to_string(&extended).expect("serialise");
    assert!(
        !wire.contains("claude") && !wire.contains("gpt") && !wire.contains("provider"),
        "the extended card disclosed which model the agent runs on: {wire}"
    );
    assert!(
        !wire.contains("protected") && !wire.contains("require_trusted"),
        "the extended card disclosed the protected-field rules, which is a map \
         of exactly where to push: {wire}"
    );
}

/// The card serializes to the field names A2A 1.0 defines, not to ours.
///
/// A card is the one artifact whose entire job is being parsed by software
/// nobody here wrote, so a field spelled our way is not a style choice — it is
/// unreadable. This test asserts on the *serialized JSON*, because that is what
/// a peer sees; asserting on the Rust struct would pass with any `serde` rename
/// at all, including a wrong one.
///
/// The interface object is where this went wrong once: it carried `transport`
/// and no version, which a conforming client cannot use — `protocolVersion` is
/// required, and `transport` is not a field it reads.
#[test]
fn the_card_uses_the_spec_field_names() {
    use agentplane::peers::AgentCard;

    let m = Manifest::parse(GOOD).expect("parse");
    let card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");
    let json = serde_json::to_value(&card).expect("serialize");

    for field in [
        "name",
        "description",
        "version",
        "capabilities",
        "supportedInterfaces",
        "defaultInputModes",
        "defaultOutputModes",
        "skills",
    ] {
        assert!(
            json.get(field).is_some(),
            "the card is missing `{field}`, which A2A 1.0 requires — a client \
             that validates the card rejects it: {json:#}"
        );
    }

    let iface = &json["supportedInterfaces"][0];
    assert_eq!(
        iface["protocolBinding"], "JSONRPC",
        "the interface must name its binding as `protocolBinding`; spelled any \
         other way a client cannot tell what this URL speaks: {iface:#}"
    );
    assert_eq!(
        iface["protocolVersion"], "1.0",
        "`protocolVersion` is required on every interface, and its absence is \
         what made the previous card unreadable: {iface:#}"
    );
    assert!(
        iface.get("transport").is_none(),
        "`transport` is this crate's old name for the binding and means nothing \
         to a client: {iface:#}"
    );
    assert!(
        iface.get("tenant").is_none(),
        "a card that names a tenant tells callers to send one, and the default \
         tenant is not a routing identifier: {iface:#}"
    );

    // The capabilities block says false for what does not exist, and the flags
    // are spelled the spec's way too.
    let caps = &json["capabilities"];
    assert_eq!(caps["streaming"], true);
    assert_eq!(caps["pushNotifications"], cfg!(feature = "push"));
}

// ── Card signing ────────────────────────────────────────────────────────────

/// A signed card verifies, and any edit to it stops verifying.
///
/// The property a signature exists for. TLS says the bytes came from that host;
/// it says nothing about whether the host is the party whose capabilities the
/// card describes. This does — and only if a changed card fails, which is the
/// half a test can accidentally skip.
#[cfg(feature = "signing")]
#[test]
fn a_signed_card_verifies_and_a_changed_one_does_not() {
    use agentplane::peers::{AgentCard, CardSignatureError, CardSigner, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let signer = Ed25519Signer::new("did:example:publisher", &[7u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:publisher", &signer.verifying_key())
        .expect("a valid key");

    let m = Manifest::parse(GOOD).expect("parse");
    let mut card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");
    assert!(
        card.verify(&verifier as &dyn CardVerifier).is_err(),
        "an unsigned card verified, so the check passes on anything"
    );

    card.sign(&signer as &dyn CardSigner).expect("sign");
    assert_eq!(
        card.verify(&verifier as &dyn CardVerifier)
            .expect("verify")
            .as_str(),
        "did:example:publisher",
        "a card signed by a trusted key did not verify"
    );

    // The signature covers what the card *says*. Change any of it and the
    // signature must stop being about this document.
    let mut tampered = card.clone();
    tampered.skills[0].id = "payments.transfer".to_owned();
    assert!(
        matches!(
            tampered.verify(&verifier as &dyn CardVerifier),
            Err(CardSignatureError::Untrusted)
        ),
        "a card whose advertised capability was rewritten still verified — which \
         is the whole attack: a peer plans against a capability the publisher \
         never claimed"
    );
}

/// A signature made by a key the verifier does not trust is refused.
#[cfg(feature = "signing")]
#[test]
fn a_card_signed_by_a_stranger_is_refused() {
    use agentplane::peers::{AgentCard, CardSigner, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let stranger = Ed25519Signer::new("did:example:stranger", &[9u8; 32]);
    let known = Ed25519Signer::new("did:example:publisher", &[7u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:publisher", &known.verifying_key())
        .expect("a valid key");

    let m = Manifest::parse(GOOD).expect("parse");
    let mut card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");
    card.sign(&stranger as &dyn CardSigner).expect("sign");

    assert!(
        card.verify(&verifier as &dyn CardVerifier).is_err(),
        "a card signed by an unknown key verified"
    );
}

/// Two signatures coexist, so a publisher can rotate keys without a gap.
#[cfg(feature = "signing")]
#[test]
fn a_card_can_carry_two_signatures() {
    use agentplane::peers::{AgentCard, CardSigner, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};

    let old = Ed25519Signer::new("key-2025", &[1u8; 32]);
    let new = Ed25519Signer::new("key-2026", &[2u8; 32]);

    let m = Manifest::parse(GOOD).expect("parse");
    let mut card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");
    card.sign(&old as &dyn CardSigner).expect("sign with old");
    card.sign(&new as &dyn CardSigner).expect("sign with new");
    assert_eq!(card.signatures.len(), 2);

    // A verifier that knows only one of them is satisfied, which is what makes
    // rotation gapless: neither side has to cut over at the same instant.
    for (id, signer) in [("key-2025", &old), ("key-2026", &new)] {
        let v = Ed25519Verifier::new()
            .trust(id, &signer.verifying_key())
            .expect("a valid key");
        assert_eq!(
            card.verify(&v as &dyn CardVerifier)
                .expect("verify")
                .as_str(),
            id,
            "a verifier holding only {id} could not verify a card carrying both"
        );
    }
}

/// The algorithm is read from a constant, never from the card.
///
/// The oldest JWS attack: the document being checked names the algorithm, so an
/// attacker names one the verifier will accept without a key. A card is exactly
/// the attacker-supplied document that was invented for.
#[cfg(feature = "signing")]
#[test]
fn a_card_naming_its_own_algorithm_is_refused() {
    use agentplane::peers::{AgentCard, CardSignature, CardSignatureError, CardVerifier};
    use agentplane::policy::{Ed25519Signer, Ed25519Verifier};
    use base64::Engine as _;

    let signer = Ed25519Signer::new("did:example:publisher", &[7u8; 32]);
    let verifier = Ed25519Verifier::new()
        .trust("did:example:publisher", &signer.verifying_key())
        .expect("a valid key");

    let m = Manifest::parse(GOOD).expect("parse");
    let mut card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    card.signatures.push(CardSignature {
        protected: b64.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "none",
                "kid": "did:example:publisher"
            }))
            .unwrap(),
        ),
        signature: b64.encode([0u8; 64]),
        header: None,
    });

    assert!(
        matches!(
            card.verify(&verifier as &dyn CardVerifier),
            Err(CardSignatureError::WrongAlgorithm(_))
        ),
        "a card that named its own algorithm was accepted — the `alg: none` \
         attack, on the one document an attacker fully controls"
    );
}

/// The signed payload contains no numbers.
///
/// RFC 8785's hardest requirement is ECMAScript number formatting, and a card of
/// strings, booleans, arrays and objects never reaches it. That is why this
/// crate can canonicalize a card correctly without a full JCS implementation —
/// so the constraint is asserted rather than assumed, and the day somebody adds
/// an integer field this fails instead of two implementations disagreeing about
/// a signature.
#[test]
fn a_card_carries_no_numbers_to_canonicalize() {
    use agentplane::peers::AgentCard;

    fn numbers(value: &serde_json::Value, path: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Number(_) => found.push(path.to_owned()),
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    numbers(v, &format!("{path}/{k}"), found);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    numbers(v, &format!("{path}/{i}"), found);
                }
            }
            _ => {}
        }
    }

    let m = Manifest::parse(GOOD).expect("parse");
    let card = AgentCard::derive(&m, "https://plane.internal/a2a").expect("derive");
    let mut found = Vec::new();
    numbers(
        &serde_json::to_value(&card).expect("serialize"),
        "",
        &mut found,
    );
    assert!(
        found.is_empty(),
        "the card now contains numbers at {found:?}. RFC 8785 mandates \
         ECMAScript number formatting, which this crate's canonicalizer does not \
         implement — so a signature over this card may not verify elsewhere. \
         Either format the value as a string or implement JCS numbers."
    );
}

/// An interface is selected by binding **and** version, in card order.
///
/// An agent may publish the same binding at several protocol versions, so
/// matching on the binding alone picks an endpoint speaking a protocol this
/// client does not — and the failure surfaces as a confusing wire error rather
/// than as "we do not speak that".
#[cfg(feature = "a2a")]
#[test]
fn an_interface_is_selected_by_binding_and_version() {
    use agentplane::peers::{AgentCard, CardInterface, JSONRPC};

    let m = Manifest::parse(GOOD).expect("parse");
    let mut card = AgentCard::derive(&m, "https://plane/a2a").expect("derive");

    // An older JSON-RPC interface first, then the current one. Card order is the
    // publisher's preference, so selection must respect it *within* the
    // versions it can actually speak.
    card.supported_interfaces.insert(
        0,
        CardInterface {
            url: "https://plane/a2a/v0".to_owned(),
            protocol_binding: JSONRPC.to_owned(),
            protocol_version: "0.3".to_owned(),
            tenant: None,
        },
    );

    let chosen = card
        .select_interface(JSONRPC, "1.0")
        .expect("no 1.0 interface was found");
    assert_eq!(
        chosen.url, "https://plane/a2a",
        "selection took the first entry regardless of version, so the client \
         would speak 1.0 at a 0.3 endpoint"
    );

    // And a binding this crate does not speak is not selected at all.
    assert!(
        card.select_interface("GRPC", "1.0").is_none(),
        "a gRPC interface was selected by a JSON-RPC client"
    );
}
