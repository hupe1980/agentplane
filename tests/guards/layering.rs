//! Architectural guards.
//!
//! These check properties that no amount of code review reliably catches,
//! because they are about what is *absent*.

use agentplane::core::Tainted;
use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn core_sources() -> Vec<(String, String)> {
    // `walk` recurses, so a future `src/core/<subdir>` cannot smuggle in an I/O
    // dependency the flat `read_dir` this replaced would never have looked at.
    walk("src/core")
        .into_iter()
        .map(|path| {
            let content = read(&path);
            (path, content)
        })
        .collect()
}

/// `core` must stay free of I/O.
///
/// Keeping the type layer dependency-free is what lets the whole runtime be
/// swapped under a simulator, keeps the surface reviewable, and makes an
/// eventual crate split mechanical rather than archaeological. Lose it once and
/// no later refactor gets it back cheaply.
#[test]
fn core_has_no_io_dependencies() {
    const FORBIDDEN: &[&str] = &[
        "redb",
        "tokio::",
        "reqwest",
        "std::fs",
        "std::net",
        "std::process",
    ];

    let sources = core_sources();
    // The same shape-3 trap as above: an empty `src/core` would satisfy every
    // prohibition below by having nothing to prohibit.
    assert!(
        sources.len() > 10,
        "only {} core sources were found, so this guard is reading the wrong \
         directory rather than passing",
        sources.len()
    );

    for (name, src) in sources {
        // Strip the doc/comment lines: prose may legitimately mention a backend.
        let code: String = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
            })
            .collect::<Vec<_>>()
            .join("\n");

        for needle in FORBIDDEN {
            assert!(
                !code.contains(needle),
                "{name} references `{needle}` — core must have no I/O"
            );
        }
    }
}

/// The determinism gate must stay armed.
///
/// If these lints are ever removed, ambient clock and RNG reads silently become
/// legal again and replay breaks in a way that presents as a mysterious runtime
/// bug months later.
#[test]
fn the_determinism_lints_are_configured() {
    let cfg = read("clippy.toml");
    for m in [
        "SystemTime::now",
        "Instant::now",
        "OffsetDateTime::now_utc",
        "rand::random",
        "ulid::Ulid::new",
    ] {
        assert!(cfg.contains(m), "clippy.toml no longer denies `{m}`");
    }
}

/// Canonical JSON depends on `serde_json` sorting object keys, which stops being
/// true the moment anything enables `preserve_order`.
///
/// Every hash in the system — record hashes, effect keys, chain links — would
/// start depending on insertion order, and replay would fail across processes
/// for no visible reason.
#[test]
fn every_hash_goes_through_the_canonical_writer() {
    let manifest = read("Cargo.toml");
    let feature_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("serde_json"))
        .expect("serde_json is declared");
    assert!(
        !feature_line.contains("preserve_order"),
        "this crate must not ask for preserve_order itself"
    );

    // What this guard used to check — that `indexmap` is absent from the
    // lockfile, proving nothing enabled `preserve_order` transitively — stopped
    // being the right question when the `cedar` feature landed. `cedar-policy`
    // enables it, cargo unifies features across the whole graph, and there is no
    // way to refuse on a dependency's behalf.
    //
    // The invariant was therefore moved out of the dependency graph and into
    // `core::canon`, which now sorts object keys itself. What remains checkable
    // here is the thing that would quietly undo that: hashing bytes produced by
    // `serde_json` directly instead of by the canonical writer. With
    // `preserve_order` on — which it now is — such a call takes insertion order
    // into a hash, and two runs performing the same effect derive different
    // keys. Exactly-once fails, and it fails silently.
    let mut scanned = 0usize;
    for file in walk("src") {
        if file.ends_with("canon.rs") {
            continue; // the canonical writer is allowed to serialize
        }
        let src = code_only(&read(&file));
        scanned += 1;
        {
            let call = "serde_json::to_vec";
            assert!(
                !src.contains(call),
                "{file} calls `{call}`. Bytes for hashing must come from \
                 `core::canon`, which sorts object keys — `serde_json` does not, \
                 because `preserve_order` is enabled transitively by cedar."
            );
        }
    }

    // Shape 3: a checker that read nothing passes for the wrong reason. This
    // one walks a tree, and a tree that comes back empty — a moved directory, a
    // renamed extension — turns a crate-wide prohibition into a no-op that
    // still reports success.
    assert!(
        scanned > 20,
        "only {scanned} sources were scanned for non-canonical hashing, so this \
         guard is reading the wrong tree rather than passing"
    );
}

/// `unsafe` is forbidden, not merely discouraged.
#[test]
fn unsafe_code_is_forbidden() {
    assert!(
        read("Cargo.toml").contains("unsafe_code = \"forbid\""),
        "the crate must forbid unsafe code"
    );
}

/// Which test checks each spec invariant against the implementation:
/// `(spec, invariant, test)`.
const CLAIMS: &[(&str, &str, &str)] = &[
    (
        "EffectGroup",
        "DeferredOnlyPastTheFrontier",
        "a_deferred_member_runs_last_and_only_on_commit",
    ),
    (
        "EffectGroup",
        "NoSilentCommit",
        "a_group_left_open_is_reversed_rather_than_committed",
    ),
    (
        "EffectGroup",
        "ReversalFollowsLanding",
        "a_deferred_member_runs_last_and_only_on_commit",
    ),
    (
        "EffectGroup",
        "ReversalIsBackwards",
        "reversals_run_in_the_opposite_order_to_the_members",
    ),
    (
        "EffectGroup",
        "ReversedAtMostOnce",
        "a_reversal_is_journaled_and_is_not_repeated_on_replay",
    ),
    (
        "EffectGroup",
        "NoUnwindUnderDoubt",
        "a_group_in_doubt_is_quarantined_rather_than_reversed",
    ),
    (
        "EffectGroup",
        "NoUnwindPastAnExternalisedDeferred",
        "a_gated_member_that_fails_after_another_landed_does_not_unwind",
    ),
    (
        "EffectGroup",
        "TransactionPrecedesTheGate",
        "an_atomic_member_commits_with_the_journal",
    ),
    (
        "EffectGroup",
        "AbortIsComplete",
        "an_aborted_group_never_runs_its_deferred_member",
    ),
    (
        "EffectGroup",
        "CommitIsComplete",
        "a_deferred_member_runs_last_and_only_on_commit",
    ),
    (
        "Delegation",
        "ScopeNeverWidens",
        "a_delegate_cannot_widen_its_delegator_s_authority",
    ),
    (
        "Delegation",
        "NoLinkExceedsTheOwner",
        "a_chain_narrows_at_every_hop",
    ),
    (
        "Delegation",
        "DepthIsBounded",
        "a_chain_may_not_run_deeper_than_the_cap",
    ),
    (
        "Delegation",
        "RehydratedChainsAreWellFormed",
        "a_rehydrated_chain_is_rechecked_for_widening",
    ),
    (
        "Authorization",
        "NothingForbiddenIsPerformed",
        "a_denied_effect_is_refused_before_it_is_performed",
    ),
    (
        "Authorization",
        "ReplayNeverConsultsPolicy",
        "strict_replay_never_asks_the_policy_engine",
    ),
    (
        "Authorization",
        "DenialIsDurable",
        "a_denial_is_journaled_like_a_budget_refusal",
    ),
    (
        "Authorization",
        "ReplayPerformsNothing",
        "a_recorded_denial_replays_even_if_the_policy_would_now_permit",
    ),
    (
        "Authorization",
        "NoRedundantPermitRecords",
        "a_permit_writes_no_record_of_its_own",
    ),
    (
        "EffectProtocol",
        "ExactlyOnce",
        "replay_does_not_re_perform_effects",
    ),
    (
        "EffectProtocol",
        "DurableIntentPrecedesAction",
        "an_orphaned_mutating_effect_is_quarantined_not_retried",
    ),
    (
        "EffectProtocol",
        "NoOutcomeWithoutAnnouncement",
        "the_store_refuses_a_duplicate_effect_start",
    ),
    (
        "EffectProtocol",
        "SuccessMeansComplete",
        "a_failing_skill_does_not_succeed",
    ),
    (
        "RetrySafety",
        "ExactlyOnce",
        "a_timeout_on_a_mutating_effect_is_never_retried",
    ),
    (
        "RetrySafety",
        "DurableIntentPrecedesAction",
        "every_attempt_is_journaled_with_its_number_and_disposition",
    ),
    (
        "RetrySafety",
        "SuccessMeansComplete",
        "attempts_are_exhausted_and_the_error_says_so",
    ),
    (
        "RetrySafety",
        "NoSuccessOnUnresolvedDoubt",
        "raising_max_attempts_does_not_make_an_in_doubt_call_retryable",
    ),
    (
        "RetrySafety",
        "NoQuarantineWithoutAsking",
        "a_probe_that_finds_it_never_landed_permits_a_retry",
    ),
    (
        "Saga",
        "CompensationFollowsCompletion",
        "a_failing_step_unwinds_the_completed_ones_in_reverse",
    ),
    (
        "Saga",
        "UnwindIsReverse",
        "a_failing_step_unwinds_the_completed_ones_in_reverse",
    ),
    (
        "Saga",
        "CompensatedAtMostOnce",
        "replay_reproduces_an_unwind_without_repeating_it",
    ),
    ("Saga", "PivotHolds", "a_pivot_stops_the_unwind"),
    (
        "Saga",
        "NoUnwindUnderDoubt",
        "a_quarantined_run_is_never_unwound",
    ),
    (
        "Saga",
        "UndeclaredIsNeverUndone",
        "an_undeclared_step_that_changed_something_escalates",
    ),
    (
        "Saga",
        "UnwindIsComplete",
        "a_succeeding_sibling_is_compensated_when_its_neighbour_fails",
    ),
    (
        "Fencing",
        "EpochsNeverRegress",
        "a_fenced_writer_cannot_append",
    ),
    (
        "Fencing",
        "SingleCurrentOwner",
        "a_live_lease_blocks_takeover_and_says_so_precisely",
    ),
    (
        "Fencing",
        "NoWriteAboveCurrentEpoch",
        "a_fenced_writer_cannot_append",
    ),
];

/// `TypeOK` is a well-formedness check on the model itself, not a claim about
/// the runtime, so it is deliberately unmapped.
const NOT_A_BEHAVIOURAL_CLAIM: &[&str] = &["TypeOK"];

/// Every behavioural invariant in the TLA+ specs must have a test checking the
/// same property against the code.
///
/// The specs check the design and the tests check the implementation, and
/// nothing otherwise notices when the two drift apart. The dangerous direction
/// is a spec gaining an invariant that the Rust side never checks: the model
/// then verifies a protocol the runtime does not implement, and the green TLA+
/// job reads as assurance about code it says nothing about.
///
/// Checked in both directions — a renamed invariant or a renamed test fails
/// here rather than silently unhooking a layer of the assurance ladder.
#[test]
fn every_spec_invariant_is_claimed_by_a_test() {
    // Every test file, not a hand-listed subset. A list has to be remembered,
    // and the moment it is not, a spec invariant can be "claimed" by a test in
    // a file the guard never reads — or a new harness drops out of scope
    // unnoticed. Same failure shape as the ambient-clock escape count.
    let tests: String = walk("tests").iter().map(|f| read(f)).collect();

    for (spec, invariant, test) in CLAIMS {
        let source = read(&format!("spec/{spec}.tla"));
        assert!(
            source.contains(&format!("\n{invariant} ==")),
            "spec/{spec}.tla no longer defines `{invariant}` — the spec was \
             renamed out from under this mapping, so the model and the code are \
             no longer known to be checking the same thing"
        );
        assert!(
            tests.contains(&format!("fn {test}(")),
            "`{test}` is gone, so nothing checks `{invariant}` against the code"
        );
    }

    // The direction that actually matters: a spec conjunct with no counterpart.
    // Discovered, not listed: a spec added without an entry here would verify
    // invariants that nothing checks against the code, which is exactly the
    // direction this guard exists to catch.
    let specs: Vec<String> = walk_ext("spec", "tla")
        .into_iter()
        .map(|f| {
            f.rsplit('/')
                .next()
                .unwrap_or_default()
                .trim_end_matches(".tla")
                .to_owned()
        })
        .collect();
    assert!(
        specs.len() >= 5,
        "only {} specs were discovered — this guard is reading the wrong path",
        specs.len()
    );
    for spec in &specs {
        let source = read(&format!("spec/{spec}.tla"));
        let safety = source
            .split_once("\nSafety ==")
            .expect("every spec states a top-level Safety conjunction")
            .1;
        for line in safety.lines().skip(1) {
            let Some(conjunct) = line.trim().strip_prefix("/\\ ") else {
                break; // end of the conjunction
            };
            let conjunct = conjunct.trim();
            if NOT_A_BEHAVIOURAL_CLAIM.contains(&conjunct) {
                continue;
            }
            assert!(
                CLAIMS.iter().any(|(s, i, _)| *s == spec && *i == conjunct),
                "spec/{spec}.tla verifies `{conjunct}`, but no test checks it \
                 against the implementation. Either map it to a test above, or \
                 the model is proving something the runtime does not do."
            );
        }
    }
}

/// Every event P7 promises must actually be emitted by something.
///
/// A telemetry constant nobody emits is the dashboard equivalent of a dead API:
/// the panel exists and is always empty, and an operator reads that as "this
/// never happens" rather than "nothing reports it". The runtime's whole claim is
/// that silent failure is made loud, so an unemitted event is not a cosmetic
/// gap.
///
/// Checked against the source rather than by running: several of these fire only
/// on failures that are awkward to provoke together, and a guard that is easy to
/// keep passing is a guard that stays.
#[test]
fn every_promised_telemetry_event_is_emitted() {
    let src: String = ["ctx.rs", "executor.rs", "sweeper.rs"]
        .iter()
        .map(|f| read(&format!("src/runtime/{f}")))
        .collect();

    // Map each event's value back to the constant that declares it, rather than
    // guessing the identifier from the string — the two need not correspond, and
    // a guard that assumes they do fails for the wrong reason.
    let vocab = read("src/runtime/telemetry.rs");
    for name in agentplane::runtime::telemetry::LOUD_EVENTS {
        let decl = vocab
            .lines()
            .find(|l| l.contains(&format!("= \"{name}\";")))
            .unwrap_or_else(|| panic!("`{name}` has no `pub const` in telemetry.rs"));
        let ident = decl
            .split_whitespace()
            .nth(2)
            .and_then(|t| t.strip_suffix(':'))
            .unwrap_or_else(|| panic!("cannot read the constant name from: {decl}"));

        assert!(
            src.contains(&format!("telemetry::{ident}")),
            "`{name}` is promised in `telemetry::LOUD_EVENTS` but nothing emits \
             `telemetry::{ident}` — the panel would always be empty"
        );
    }
}

/// The determinism gate must not have been loosened for telemetry.
///
/// Instrumentation is observation, not state: a span may not read a clock, mint
/// an id, or otherwise reach for the ambient world the deterministic zone is
/// forbidden. If adding tracing had required an `#[allow]`, that would be the
/// signal that a span was doing more than observing.
#[test]
fn telemetry_did_not_loosen_the_determinism_gate() {
    // Three, and each is named here so a fourth has to argue for itself:
    //
    //   effects.rs  — the `Clock` effect, whose whole job is to read the clock
    //                 and journal the result.
    //   executor.rs — `now_for_admission`, for the case row's `opened_at` stamp,
    //                 which never enters the journal.
    //   ctx.rs      — `subscription_clock`, store metadata like a lease.
    //
    // Instrumentation must observe, not reach: a span may not read a clock or
    // mint an id. If adding one had needed a fourth escape, that would be the
    // signal a span was doing more than watching.
    const KNOWN_ESCAPES: usize = 3;

    // Every file in `runtime/`, not a hand-listed subset. A fixed list is a
    // guard that stops guarding the moment someone adds a module — which is
    // exactly when a new escape would arrive, since a new module is where new
    // work goes. `metrics.rs` was added under this rule and needed none.
    let runtime: String = walk("src/runtime").iter().map(|f| read(f)).collect();
    let allows = runtime.matches("allow(clippy::disallowed_methods)").count();
    assert_eq!(
        allows, KNOWN_ESCAPES,
        "the runtime has {allows} ambient-clock escapes, not {KNOWN_ESCAPES} — \
         each one needs naming above before it is allowed to exist"
    );
}

/// Spans must be attached to futures, never entered around them.
///
/// `Span::enter` returns a guard bound to the *thread*. Held across an `.await`
/// it stays entered while the future is suspended, so whatever the executor runs
/// next is attributed to it. With sequential dispatch that is invisible — only
/// one step is ever in flight. With concurrent siblings it silently reparents
/// their work, and it did: a step span came out nested under another step's.
///
/// `Instrument` binds the span to the future instead, which is the only form
/// that survives a suspension. This bans the guard outright in async code rather
/// than trusting review to spot the difference.
#[test]
fn spans_are_instrumented_onto_futures_not_entered() {
    // The whole of `src/runtime`, like the sibling clock guard — a fixed file
    // list is exactly the shape that lets a `.enter()` land in `declarative.rs`,
    // `group.rs` or `batch.rs` (all async runtime code) unnoticed.
    let files = walk("src/runtime");
    assert!(
        files.len() >= 8,
        "expected to scan the runtime module; found {} files",
        files.len()
    );
    for file in files {
        let src = read(&file);
        assert!(
            !src.contains(".enter()"),
            "{file} enters a span guard. In async code that guard outlives the \
             await and captures unrelated work — use `.instrument(span)` so the \
             span belongs to the future"
        );
    }
}

/// No public enum variant may exist that nothing constructs.
///
/// This runtime has produced the same bug five times: a variant, a recovery
/// mode, an error, a record kind declared and never built. Each read as a
/// capability the system had, and each was a promise to the caller that nothing
/// kept — `Recovery::Reconcile` escalated instead of probing,
/// `RuntimeError::CompensationFailed` was never constructed, `RecordKind::
/// RunSealed` was never written. An API that reads as though a capability exists
/// is worse than one that admits it does not, because callers plan around it.
///
/// So the sweep runs on every build instead of when somebody remembers.
///
/// Two exemptions, both principled:
///
/// * `#[from]` variants are constructed implicitly by `?`.
/// * A variant meant for *library users* to construct counts if a **test**
///   constructs it. That is the point: user-facing API earns its place by being
///   exercised, not by being declared.
#[test]
fn no_public_enum_variant_is_dead() {
    let sources: Vec<(String, String)> = walk("src")
        .into_iter()
        .map(|p| (p.clone(), read(&p)))
        .collect();
    // Comments are stripped first, and that is not tidiness. This guard's own
    // doc comment names `RuntimeError::CompensationFailed` as an example of the
    // bug — which made the guard blind to exactly that variant when it was
    // reintroduced. Prose about a variant is not a use of it.
    let everything: String = sources
        .iter()
        .map(|(_, s)| s.clone())
        .chain(walk("tests").into_iter().map(|p| read(&p)))
        .map(|s| code_only(&s))
        .collect::<Vec<_>>()
        .join("\n");

    // Match arms are stripped too, and for the same reason comments are:
    // *destructuring* a variant is not *constructing* one. A variant that only
    // ever appears on the left of a `=>` is reachable from nowhere — the code
    // that mentions it is the code refusing it — which is precisely the dead
    // declaration this guard exists to find. It hid `Outcome::Delegate`, a
    // public variant whose only mention was the arm that turned it into a
    // failure, so no caller could ever use it successfully.
    let constructed = strip_match_patterns(&everything);

    let mut dead = Vec::new();
    for (path, text) in &sources {
        for (name, body) in enums(text) {
            for variant in variants(&body) {
                let v = &variant.name;
                let referenced = constructed.contains(&format!("{name}::{v}"))
                    || constructed.contains(&format!("Self::{v}"));
                if !variant.from && !referenced {
                    dead.push(format!("{path}: {name}::{v}"));
                }
            }
        }
    }

    assert!(
        dead.is_empty(),
        "these variants are declared and never constructed — delete them, or \
         exercise them from a test if they are for callers:\n  {}",
        dead.join("\n  ")
    );
}

/// Drop everything to the left of a `=>`, which is where patterns live.
///
/// Deliberately a heuristic rather than a parser: it can only ever make the
/// guard *stricter*, because it removes text rather than adding it. A variant
/// that survives this is one somebody actually builds.
fn strip_match_patterns(src: &str) -> String {
    // Two shapes, and the second one is why this guard once passed a variant
    // nobody constructed. A `match` arm is easy: everything left of `=>` is a
    // pattern. A `matches!(x, A | B | C)` is not — every name in it is a
    // pattern too, and none of them is a construction, but nothing about the
    // line says so.
    //
    // A `SweptAction` variant survived here for exactly that reason: it was
    // mentioned only inside a `matches!` in a predicate that nothing called,
    // and the guard read it as used. Dropping the whole macro call is coarse —
    // a construction genuinely inside one is now invisible — and that is the
    // safe direction: this guard's failure mode must be a false *alarm*, not a
    // false pass.
    let without_matches = strip_matches_macro(src);
    without_matches
        .lines()
        .map(|l| l.split_once("=>").map_or(l, |(_, rhs)| rhs))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Drop the **pattern** argument of every `matches!(expr, PATTERNS)`.
///
/// The first argument is an expression and may legitimately construct
/// something; everything after the first top-level comma is a pattern and
/// constructs nothing. Dropping the whole call was the first attempt and it was
/// too coarse — seven variants that *are* constructed became false alarms, and
/// a guard that cries wolf seven times is a guard people delete.
///
/// Parentheses are balanced rather than scanning to the next `)`, because
/// patterns routinely contain their own: `Some(x)`, `Fenced { .. }`.
fn strip_matches_macro(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut rest = src;
    while let Some(at) = rest.find("matches!(") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "matches!(".len()..];

        let mut depth = 1usize;
        let mut first_comma = None;
        let mut end = after.len();
        for (i, c) in after.char_indices() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                ',' if depth == 1 && first_comma.is_none() => first_comma = Some(i),
                _ => {}
            }
        }
        // Keep the scrutinee, drop the patterns.
        out.push_str(&after[..first_comma.unwrap_or(end)]);
        rest = after.get(end + 1..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

/// Drop comment lines, so prose mentioning a name is not mistaken for using it.
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("/*") && !t.starts_with('*')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn walk(dir: &str) -> Vec<String> {
    walk_ext(dir, "rs")
}

/// Every file under `dir` with this extension, repo-relative.
fn walk_ext(dir: &str, ext: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == ext) {
                out.push(
                    p.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                        .unwrap_or(&p)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    out
}

/// `(name, body)` for every `pub enum` in a source file.
fn enums(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("pub enum ") {
        let after = &rest[i + "pub enum ".len()..];
        let Some(brace) = after.find('{') else { break };
        let name: String = after[..brace]
            .trim()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // Enum bodies here are never nested, so the first `\n}` closes them.
        if let Some(end) = after[brace..].find("\n}") {
            out.push((name, after[brace..brace + end].to_owned()));
            rest = &after[brace + end..];
        } else {
            break;
        }
    }
    out
}

struct Variant {
    name: String,
    from: bool,
}

fn variants(body: &str) -> Vec<Variant> {
    let mut out = Vec::new();
    let mut pending_from = false;
    for line in body.lines() {
        let t = line.trim();
        if t.contains("#[from]") {
            pending_from = true;
        }
        // A variant starts at four-space indent with a capital letter.
        let is_variant = line.starts_with("    ")
            && !line.starts_with("     ")
            && t.chars().next().is_some_and(char::is_uppercase);
        if is_variant {
            let name: String = t.chars().take_while(|c| c.is_alphanumeric()).collect();
            if !name.is_empty() {
                out.push(Variant {
                    name,
                    from: pending_from,
                });
            }
            pending_from = false;
        }
    }
    out
}

/// Feature axes, and how a test betrays that it exercises one.
///
/// Keys are matched against a test's file prefix plus its own body, because
/// fixtures — the skills and effects that make a feature happen — live at file
/// scope and the test bodies below them are short.
const AXES: &[(&str, &[&str])] = &[
    ("retry", &["RetryPolicy", "Recovery::Retry"]),
    ("reconcile", &["Reconciliation", "fn reconcile"]),
    ("saga", &["Compensation::", "fn compensate"]),
    ("timers", &["cx.sleep", "fire_timers", "TimerStore"]),
    ("waits", &["await_event", "AwaitSpec"]),
    ("concurrency", &["multi_thread"]),
    ("replan", &["Outcome::Replan", "Replanner"]),
    ("budget", &["Budget::"]),
    ("group", &["cx.group", "EffectGroup"]),
];

/// Pairs that share no machinery, with the reason each is exempt.
///
/// An entry here is a claim that the two cannot interfere. It is not a to-do
/// list — if a pair turns out to share a mechanism, it belongs in a test, not
/// here.
const INDEPENDENT: &[(&str, &str, &str)] = &[
    (
        "budget",
        "reconcile",
        "a probe is a driver call the ledger never sees; billing happens on the \
         effect it resolves",
    ),
    ("budget", "waits", "as above: waiting spends no operations"),
    (
        "concurrency",
        "reconcile",
        "a probe is scoped to one effect in one step; siblings share no probe \
         state",
    ),
    (
        "reconcile",
        "replan",
        "a probe resolves one effect's outcome; it cannot change the plan",
    ),
    (
        "reconcile",
        "saga",
        "compensating effects reconcile through the same path forward ones do, \
         which `retry x reconcile` already covers",
    ),
    (
        "reconcile",
        "timers",
        "a timer performs nothing external, so there is no outcome to be in \
         doubt about",
    ),
    (
        "reconcile",
        "waits",
        "as above: a wait's result arrives by delivery, not by a call that can \
         time out",
    ),
    (
        "replan",
        "waits",
        "as above — a waiting step has not returned an outcome to act on",
    ),
    (
        "timers",
        "waits",
        "both suspend through one path, and `one_step_may_sleep_retry_and_sleep_again` \
         exercises repeated suspension within a step",
    ),
];

/// Every pair of features that can interact must be exercised together.
///
/// The bug this exists for: replanning shipped with its own gates tested and
/// broke the saga — a successor reusing a completed step's id made the unwind
/// compensate work that never ran, which is exactly what the `Saga` spec's
/// `CompensationFollowsCompletion` forbids. The spec was right and the code
/// stopped satisfying it, and nothing noticed, because the model↔code guard maps
/// each invariant to *one* test and no test combined a replan with an unwind.
///
/// A guard that an invariant is checked somewhere is not a guard that it is
/// checked everywhere it now applies. Adding a feature silently widens where it
/// applies, so the widening is what gets checked here.
#[test]
fn every_interacting_feature_pair_is_exercised() {
    let mut covered: Vec<(String, String)> = Vec::new();

    for path in walk("tests") {
        // This file is excluded, and that is not housekeeping. It contains every
        // detection key below as a string literal, so scanning it makes the
        // guard believe one test exercises all eight axes and every pair is
        // covered. The dead-variant check learned the same lesson from its own
        // doc comment: a guard that reads itself is reading its description as
        // evidence.
        if path.ends_with("layering.rs") {
            continue;
        }
        let src = code_only(&read(&path));
        let marks: Vec<usize> = src.match_indices("#[tokio::test").map(|(i, _)| i).collect();
        let prefix = marks.first().map_or(src.as_str(), |&i| &src[..i]);

        for (i, &start) in marks.iter().enumerate() {
            let end = marks.get(i + 1).copied().unwrap_or(src.len());
            let unit = format!("{prefix}{}", &src[start..end]);
            let present: Vec<&str> = AXES
                .iter()
                .filter(|(_, keys)| keys.iter().any(|k| unit.contains(k)))
                .map(|(name, _)| *name)
                .collect();
            for a in &present {
                for b in &present {
                    if a < b {
                        covered.push(((*a).to_owned(), (*b).to_owned()));
                    }
                }
            }
        }
    }

    let exempt = |a: &str, b: &str| {
        INDEPENDENT
            .iter()
            .any(|(x, y, _)| (*x == a && *y == b) || (*x == b && *y == a))
    };

    let mut missing = Vec::new();
    for (i, (a, _)) in AXES.iter().enumerate() {
        for (b, _) in &AXES[i + 1..] {
            let seen = covered
                .iter()
                .any(|(x, y)| (x == a && y == b) || (x == b && y == a));
            if !seen && !exempt(a, b) {
                missing.push(format!("{a} x {b}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these feature pairs can interact and nothing exercises them together. \
         Add a test to tests/interactions.rs, or add the pair to `INDEPENDENT` \
         with the reason it cannot interfere:\n  {}",
        missing.join("\n  ")
    );
}

/// Every feature a test file gates itself on must exist.
///
/// A `#![cfg(feature = "…")]` at the top of an integration test is a silent
/// switch: if the feature is misspelled, or renamed, or removed, the file
/// compiles to *zero tests* and the suite reports success with a whole harness
/// missing. Nothing warns — an unsatisfied `cfg` is not an error, and a test
/// binary with no tests is a passing test binary.
///
/// This matters more the more valuable the file is. `tests/simulation.rs` and
/// `tests/faults.rs` are the crash and fault layers; both are gated, and both
/// would vanish without trace from a typo.
#[test]
fn every_feature_a_test_gates_itself_on_exists() {
    let manifest = std::fs::read_to_string("Cargo.toml").expect("Cargo.toml");
    let declared: Vec<String> = manifest
        .lines()
        .skip_while(|l| l.trim() != "[features]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter_map(|l| l.split('=').next())
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty() && !n.starts_with('#'))
        .collect();
    assert!(
        declared.contains(&"redb".to_string()),
        "the feature table was not parsed — this guard is inert: {declared:?}"
    );

    let mut gated = 0;
    // Recursive, because the suite is one cargo target with the files as
    // modules under `tests/suite/`. The non-recursive version found the
    // directory, skipped it, and read zero gated files — caught only by the
    // `gated >= 2` assertion below, which is shape 10 doing its job.
    for path in walk("tests") {
        let src = read(&path);
        // Only the crate-level gate: an inner `#[cfg]` disables one item, which
        // is visible in the test list. A crate-level one disables everything.
        let Some(line) = src.lines().find(|l| l.starts_with("#![cfg(")) else {
            continue;
        };
        gated += 1;

        for name in line.split("feature = \"").skip(1) {
            let name = name.split('"').next().unwrap_or_default();
            assert!(
                declared.contains(&name.to_string()),
                "{path}: gated on feature '{name}', which is not in [features]. \
                 The whole file compiles to zero tests and the suite still \
                 passes. Declared: {declared:?}"
            );
        }
    }
    assert!(
        gated >= 2,
        "no gated test files were found, so this guard read nothing — it has \
         been blinded by a path or parsing change"
    );
}

/// Every declared metric is emitted by something.
///
/// The metrics twin of `every_promised_telemetry_event_is_emitted`, and the
/// failure it prevents is worse. An event nobody emits leaves a dashboard panel
/// empty, which at least looks wrong. A *counter* nobody emits reads as a hard
/// zero — indistinguishable from "this genuinely never happens" — so an operator
/// concludes the system is healthy on the strength of a number that was never
/// wired up.
///
/// Gauges are exempt from the call-site search: they are emitted through
/// `Census::emit`, which iterates rather than naming each one, so the check for
/// those is `tests/metrics.rs::a_sweep_emits_every_gauge` asserting on what a
/// subscriber received.
#[test]
fn every_declared_metric_is_emitted() {
    let catalogue = read("src/runtime/metrics.rs");
    let emitters: String = walk("src/runtime")
        .iter()
        .filter(|f| !f.ends_with("metrics.rs"))
        .map(|f| code_only(&read(f)))
        .collect();

    // Constant names, taken from the `CATALOGUE` array so the guard cannot
    // drift from the list it is checking.
    let list = catalogue
        .split("pub const CATALOGUE")
        .nth(1)
        .expect("CATALOGUE not found — this guard is reading the wrong shape");
    // Anchored on `= &[` — the first `[` in the declaration belongs to the
    // slice type `&[Instrument]`, not to the array.
    let body = list
        .split_once("= &[")
        .and_then(|(_, r)| r.split_once(']'))
        .expect("CATALOGUE array")
        .0;

    let gauges: Vec<&str> = catalogue
        .split("pub const ")
        .skip(1)
        .filter(|blk| blk.contains("Kind::Gauge"))
        .filter_map(|blk| blk.split(':').next())
        .map(str::trim)
        .collect();

    let mut checked = 0;
    for name in body.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        if gauges.contains(&name) {
            continue;
        }
        checked += 1;
        assert!(
            emitters.contains(&format!("metrics::{name}")),
            "metric {name} is declared but nothing emits it. A counter with no \
             emitter reports zero, which an operator reads as 'this never \
             happens' rather than 'nothing reports it'."
        );
    }
    assert!(
        checked >= 10,
        "only {checked} counters were checked — the guard is reading the \
         catalogue wrong and is now inert"
    );
}

/// Every metric carries a description an operator could act on.
///
/// A metric name is not self-explanatory to the person reading a dashboard at
/// 3am — `agentplane.effects` counts *attempts*, so a retry counts twice, and
/// nobody would guess that from the name. The catalogue is the only place that
/// can say so, and a field nothing checks is a field that quietly becomes empty.
///
/// This also keeps `Instrument::description` load-bearing rather than declared,
/// which is the same rule `no_public_enum_variant_is_dead` applies to variants.
#[test]
fn every_metric_explains_itself() {
    let src = read("src/runtime/metrics.rs");
    let mut checked = 0;
    for block in src.split("pub const ").skip(1) {
        // Only `NAME: Instrument = Instrument { .. }` declarations. Splitting on
        // the first colon also catches method bodies that happen to follow a
        // `pub const`, which is how this guard first read `as_str` as a metric.
        let Some((name, body)) = block.split_once(": Instrument = Instrument {") else {
            continue;
        };
        checked += 1;
        let desc = body
            .split("description:")
            .nth(1)
            .unwrap_or("")
            .split("};")
            .next()
            .unwrap_or("");
        let text: String = desc.chars().filter(|c| c.is_alphabetic()).collect();
        assert!(
            text.len() > 25,
            "metric {} has no usable description. A name alone does not tell an \
             operator what the number means — and the ones that need saying are \
             exactly the ones nobody would guess.",
            name.trim()
        );
    }
    assert!(
        checked >= 15,
        "only {checked} instruments were read — this guard has been blinded by a \
         formatting change and is now inert"
    );
}

/// Every effect that declares itself trusted is named here.
///
/// `Effect::trust` defaults to untrusted because an effect is how the
/// deterministic zone reaches the outside world, and what comes back is the
/// outside world's data. Declaring `Trusted` opts an effect out of the taint
/// gate, the egress ceiling, and the refusal to replan on untrusted data — all
/// at once, and silently.
///
/// So a trusted effect is an escape, in exactly the sense the ambient-clock
/// escapes are, and a fourth one has to argue for itself here before it can
/// exist. Getting this wrong is not a compile error and not a test failure; it
/// is a prompt injection reaching a mutating tool.
#[test]
fn every_trusted_effect_is_named() {
    // Nine, and each is the runtime's own machinery rather than the world's:
    //
    //   Clock           — the journaled instant, written by the runtime.
    //   Recorded        — a value the runtime recorded for itself; adds no trust.
    //   ResolveDeadline — a Calendar the operator configured, not a peer.
    //   ReadCaseState   — the plane's own storage. Note the distinction the
    //                     label is making: the *store* is not a trust boundary
    //                     the way a tool or a peer is, but the bytes in it may
    //                     well have arrived untrusted, and `case_state()` hands
    //                     them back labeled rather than passing this through.
    //   WriteCaseState  — same store, and its output is a version number the
    //                     runtime itself assigned.
    //   RecallMemory    — the same distinction as ReadCaseState, and the one
    //                     most worth stating: this effect's *output* is a
    //                     selection — ids, versions, digests the runtime
    //                     computed — and never the remembered content. The
    //                     content is labelled from each item's declared
    //                     provenance by `cx.recall`, which is the whole defence
    //                     against a poisoned memory promoting itself.
    //   SetCaseStatus   — the runtime writing a status it chose, to a store it
    //                     owns. Its output is `()`: there is no value to
    //                     mislabel, and the argument for trust is that there is
    //                     nothing to trust.
    //   TransitionDeadline — the same write, and its output *is* read back from
    //                     the store, which is the one that deserves a sentence.
    //                     Unlike case state, which is an opaque `Value` anybody
    //                     may have written, this is a four-variant enum the
    //                     runtime itself defines and only the runtime writes;
    //                     the worst a second writer can do is a wrong-but-valid
    //                     variant, and it reaches nothing but the `from` field
    //                     of a record.
    //   OpenTask        — the runtime opening a worklist row whose id it
    //                     derived from its own effect key, and that id is the
    //                     effect's whole output. The *justification* the row
    //                     carries is untrusted model content by construction and
    //                     is not what this labels — see `effects::OpenTask` on
    //                     why a worklist is deliberately not a sink.
    const KNOWN_TRUSTED: usize = 9;

    // Anchored on the *declaration*, not on the token. `Trust::Trusted` also
    // appears in the doc comment that explains the rule and in the match arm
    // that applies a label — counting those would make the guard fail for
    // explaining itself, which is the same trap `no_public_enum_variant_is_dead`
    // fell into.
    let src: String = walk("src").iter().map(|f| code_only(&read(f))).collect();
    let declared = src
        .split("fn trust(")
        .skip(1)
        .filter(|body| {
            body.split("}\n")
                .next()
                .unwrap_or_default()
                .contains("Trust::Trusted")
        })
        .count();
    assert_eq!(
        declared, KNOWN_TRUSTED,
        "the crate declares {declared} trusted effects, not {KNOWN_TRUSTED}. \
         Each one opts out of the taint gate, the egress ceiling, and the \
         replan refusal at once — name it above before it exists."
    );
}

/// Every test the mutation table names actually exists.
///
/// `tools/mutants.py` breaks a guarantee on purpose and requires the *named*
/// test to fail. A name that matches nothing degrades silently: the mutation is
/// caught by some other test, the row reports WEAK, and it looks like a missing
/// test rather than a typo — which is exactly what happened when this table was
/// written, five times in one sitting.
///
/// Checking it here costs milliseconds. Discovering it from the sweep costs a
/// full rebuild per row.
#[test]
fn every_test_the_mutation_table_names_exists() {
    let table = read("tools/mutants.py");
    // Both trees: a mutation may legitimately name a unit test living beside
    // the code it checks — `canon`'s ordering guard is one — and scanning only
    // `tests/` reported that as a missing test.
    let tests: String = walk("tests")
        .iter()
        .chain(walk("src").iter())
        .map(|f| read(f))
        .collect();

    // The second string literal in each tuple is the test name; take every
    // bare-word literal and keep those that look like test identifiers, then
    // require each to be a real function.
    let mut checked = 0;
    for line in table.lines().map(str::trim) {
        let Some(name) = line.strip_prefix('"').and_then(|r| r.strip_suffix("\",")) else {
            continue;
        };
        // Test names here are snake_case identifiers and nothing else is.
        if name.contains(' ') || name.contains('/') || name.contains("::") || !name.contains('_') {
            continue;
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        checked += 1;
        assert!(
            tests.contains(&format!("fn {name}(")),
            "tools/mutants.py names `{name}` as the test that must fail, and no \
             such test exists. The mutation would be caught by something else \
             and reported as a weak guarantee rather than as this typo."
        );
    }
    assert!(
        checked >= 15,
        "only {checked} test names were read from the mutation table — this \
         guard has been blinded by a formatting change"
    );
}

/// Secrets cannot be written, printed, or journaled.
///
/// A bearer token in the journal is the worst kind of leak this crate can
/// produce: the log is append-only and hash-chained, so the secret cannot be
/// redacted later — the record's hash covers it and the chain would break. It
/// can only be discovered.
///
/// Three things stop it, and two of them are structural rather than a habit:
///
///   * no `Serialize`, so it cannot be written by accident;
///   * a hand-written `Debug` that redacts, so it cannot reach a log line or a
///     span attribute;
///   * `tests/peers.rs` scans a real run's journal for the secret.
///
/// This guard holds the first two. Deriving `Serialize` on a credential is a
/// one-word change that no compiler and no other test would object to.
#[test]
fn a_credential_cannot_be_serialized_or_printed() {
    let src = read("src/peers/mod.rs");
    let decl = src
        .split("pub struct PeerCredential")
        .next()
        .and_then(|before| before.rsplit("#[derive(").next())
        .unwrap_or_default();
    let derives = decl.split(')').next().unwrap_or_default();

    for forbidden in ["Serialize", "Deserialize"] {
        assert!(
            !derives.contains(forbidden),
            "PeerCredential derives {forbidden}. A credential that can be \
             serialized is one that reaches the journal, and a journal entry \
             cannot be redacted — the chain covers it."
        );
    }
    assert!(
        !derives.contains("Debug"),
        "PeerCredential derives Debug. The hand-written impl redacts the secret; \
         a derived one prints it into every log line and span that touches it."
    );
    assert!(
        code_only(&src).contains("impl Debug for PeerCredential"),
        "the redacting Debug impl is gone — without it the type either prints \
         its secret or stops satisfying the trait bounds the seam needs"
    );
}

/// Every future the runtime hands a caller must be `Send`.
///
/// A control plane runs runs on a multi-threaded executor: `tokio::spawn`,
/// `JoinSet`, a batch driver fanning out. All of them require `Send`, and none
/// of this crate's own tests need it — a single-threaded `#[tokio::test]` awaits
/// futures in place and never notices.
///
/// So the whole surface was non-`Send` and no test said so. One field did it:
/// `stamp: &dyn Fn(Append) -> Append` inside the executor. A bare `dyn Fn` trait
/// object is neither `Send` nor `Sync`, that infects every future holding it,
/// and the symptom surfaces at the *embedder's* spawn site as a page of trait
/// error naming a private type they cannot see. It was found by writing an HTTP
/// handler, which is to say: by accident.
///
/// This is a compile-time assertion. It is never called and does not need to be
/// — if a future stops being `Send`, this file stops compiling, which is exactly
/// where the report belongs.
#[allow(dead_code)]
fn every_runtime_future_survives_a_spawn(
    rt: &agentplane::Runtime,
    run: agentplane::RunId,
    event: &agentplane::core::InboundEvent,
    task: agentplane::core::TaskId,
    decision: &agentplane::core::Decision,
    now: agentplane::core::Timestamp,
) {
    fn spawnable<F: std::future::Future + Send>(_f: F) {}

    spawnable(rt.run("target", Tainted::trusted(serde_json::Value::Null)));
    spawnable(rt.replay(run, agentplane::runtime::Mode::Strict));
    spawnable(rt.deliver(event));
    spawnable(rt.decide_task(task, decision, &[]));
    spawnable(rt.sweep(now, std::time::Duration::from_secs(1)));
    spawnable(rt.fire_timers(now));
    spawnable(rt.census(now));
}

/// A closure held in the runtime must be `Send + Sync`, at the field.
///
/// The compile-time guard above catches the consequence; this catches the cause,
/// at the line that causes it. The two are worth having separately because the
/// consequence is reported a long way from the field — and because a future
/// author adding a second `dyn Fn` field will read this message rather than
/// re-derive the reasoning from a trait error.
#[test]
fn a_closure_the_runtime_holds_is_send_and_sync() {
    for file in walk("src/runtime") {
        let src = code_only(&read(&file));
        for (i, line) in src.lines().enumerate() {
            let Some(at) = line.find("dyn Fn") else {
                continue;
            };
            let tail = &line[at..];
            assert!(
                tail.contains("+ Send + Sync") || tail.contains("+ Sync + Send"),
                "{file}:{} holds a bare `dyn Fn`. A trait object is neither \
                 `Send` nor `Sync` unless it says so, and one such field makes \
                 every future that touches it unspawnable:\n  {}",
                i + 1,
                line.trim()
            );
        }
    }
}

/// A task id cannot be built from an effect key alone.
///
/// An [`EffectKey`] is unique *within a run* — the journal enforces
/// `(run, effect_key)` and needs nothing more. The worklist is a table shared by
/// every run, and two runs of one plan reach the same step, at the same ordinal,
/// with the same descriptor, and derive the same key. `TaskStore::open` is
/// idempotent by id, so the second run's task was silently not created: one
/// proposal appeared carrying the *first* run's amount, and the second run
/// waited for an answer nobody would ever be shown.
///
/// `tests/tasks.rs` catches the behaviour. This catches the shape, because the
/// fix is that the collision is now **unrepresentable**: the field is private,
/// so `TaskId::derive(run, key)` is the only way to build one, and a future
/// author cannot reintroduce the bug by writing the obvious thing.
#[test]
fn a_task_id_cannot_be_built_from_an_effect_key_alone() {
    let src = read("src/core/task.rs");
    assert!(
        !src.contains("pub struct TaskId(pub"),
        "TaskId's field is public again. An effect key is unique within a run; \
         a task id lives in a table shared by every run, and one built directly \
         from a key collides across runs of the same plan"
    );
    assert!(
        code_only(&src).contains("pub fn derive(run: RunId, effect: EffectKey)"),
        "TaskId::derive is gone — the run has to be in the hash, or two runs of \
         one plan share one decision"
    );
}

/// A secret is held in a type that wipes itself.
///
/// The redacting `Debug` and the absent `Serialize` on `PeerCredential` stop a
/// secret being *written* somewhere. Neither stops it *staying* in freed heap
/// after the value drops — where a core dump, a swap file, or a heap-reading
/// exploit finds it — and `String` makes that worse by leaving reallocated
/// copies the eventual drop can no longer reach.
///
/// So every long-lived secret in this crate is a `core::Secret`, and this checks
/// it structurally: `key: String` in a provider driver is a one-word change that
/// no compiler and no other test would object to.
#[test]
fn every_held_secret_is_wiped_when_it_drops() {
    let holders = [
        ("src/peers/mod.rs", "PeerCredential"),
        ("src/model/anthropic.rs", "Anthropic"),
        ("src/model/openai.rs", "OpenAi"),
    ];

    let mut checked = 0;
    for (file, ty) in holders {
        let src = code_only(&read(file));
        let decl = src
            .split(&format!("pub struct {ty} {{"))
            .nth(1)
            .unwrap_or_else(|| panic!("{file} no longer declares {ty}"));
        let body = decl.split('}').next().unwrap_or_default();
        checked += 1;

        for field in ["key", "secret", "token", "password"] {
            let bare = format!("{field}: String");
            assert!(
                !body.contains(&bare),
                "{ty} in {file} holds `{bare}`. A `String` secret is still in \
                 freed heap after it drops, and its reallocations leave copies \
                 nothing can reach — use `core::Secret`"
            );
        }
    }
    assert_eq!(checked, 3, "this guard read fewer types than it names");
}

/// `Secret` itself must not become serializable or printable.
#[test]
fn a_secret_cannot_be_serialized_or_printed() {
    let src = read("src/core/secret.rs");
    let derives = src
        .split("pub struct Secret")
        .next()
        .and_then(|before| before.rsplit("#[derive(").next())
        .unwrap_or_default()
        .split(')')
        .next()
        .unwrap_or_default();

    for forbidden in ["Serialize", "Deserialize", "Debug"] {
        assert!(
            !derives.contains(forbidden),
            "Secret derives {forbidden}. Deriving it puts the value into every \
             log line, span, and record that touches the type"
        );
    }
    assert!(
        code_only(&src).contains("impl fmt::Debug for Secret"),
        "the redacting Debug is gone — without it Secret either prints its \
         value or stops satisfying the bounds its holders need"
    );
}

/// Every mutation still anchors in the code it claims to break.
///
/// `every_test_the_mutation_table_names_exists` checks the *test* half of each
/// row. This checks the other half, and the two fail in opposite ways: a missing
/// test is loud, whereas an anchor that has drifted is silent. The guarantee is
/// simply unverified from then on, which is indistinguishable from verified
/// until somebody runs the sweep.
///
/// Refactoring the code a mutation points at is routine — rewriting the two
/// model drivers to stream broke seven rows at once, and one more had been
/// pointing at a struct field that does not exist, so it had never compiled and
/// had therefore never tested anything. Text-only, so it costs milliseconds
/// here instead of a full rebuild per row.
#[test]
fn every_mutation_still_anchors_in_the_code() {
    let out = std::process::Command::new("python3")
        .args(["tools/mutants.py", "--check"])
        .output()
        .expect("run tools/mutants.py");
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        report.contains("0 broken"),
        "a mutation no longer matches the code it names, so the guarantee it \
         pins is unverified and looks verified:\n{report}"
    );
}

/// Only the sealed accessor may read the raw blob store.
///
/// `StepCtx::blobs_scoped` decides whether payload bytes are encrypted. Any
/// other path reaching `self.blobs` directly writes them in the clear, so a
/// deployment with a key ring gets one route that seals and one that does not —
/// and erasing a case silently misses whatever took the second. The governed
/// media path did exactly that, and nothing failed: the bytes were written, the
/// run succeeded, and the erasure was quietly partial.
///
/// A count rather than a name, because the next bypass will not be called
/// `fetch_media`.
#[test]
fn only_the_sealed_accessor_reads_the_raw_blob_store() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime/ctx.rs"),
    )
    .expect("the context module");
    assert!(
        src.contains("fn blobs_scoped"),
        "the sealed accessor is gone or renamed — this guard now proves nothing"
    );

    let direct = src.matches("self.blobs.clone()").count();
    assert_eq!(
        direct, 1,
        "the raw blob store is read {direct} times; exactly one — inside \
         `blobs_scoped` — may. Every other caller must go through it, or a \
         sealed deployment has a write path that stores payload bytes in the \
         clear and an erasure that cannot reach them"
    );
}

/// Every declared route appears in the unauthenticated-request test.
///
/// That test is the one saying "no credentials, no answer — on every route", and
/// it is a **hand-written list**: it enumerates requests rather than asking the
/// router what it serves. So a route added to the router and forgotten here is
/// silently unguarded, and the claim keeps reading as though it were checked.
///
/// This closes that by comparing the two: each route's literal path segments
/// must appear in the test's source. It is a coarse match on purpose — the test
/// substitutes real ids for `{run}` and builds some paths with `format!`, so
/// matching whole paths would fail for reasons that are not defects.
#[test]
fn every_api_route_is_covered_by_the_unauthenticated_test() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let router = std::fs::read_to_string(root.join("src/api/mod.rs")).expect("the api module");
    let guard = std::fs::read_to_string(root.join("tests/wire/api.rs")).expect("the api tests");

    let start = guard
        .find("async fn an_unauthenticated_request_is_refused_everywhere")
        .expect("the unauthenticated-request test is gone, so this guard is inert");
    let body = &guard[start..];

    let paths: Vec<&str> = router
        .match_indices(".route(\"")
        .filter_map(|(i, _)| {
            let rest = &router[i + ".route(\"".len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .collect();
    assert!(
        paths.len() > 5,
        "found only {} routes; the extraction broke and this guard now proves \
         nothing",
        paths.len()
    );

    // Matched on the route's **shape**, not on its segments appearing
    // somewhere. Segment matching passed `/runs` the moment `/runs/{run}`
    // existed, because "runs" was already in the file — so a genuinely new
    // route was silently unguarded and the guard said otherwise. That is the
    // failure this guard exists to prevent, committed by the guard.
    //
    // The shape replaces every `{param}` with a wildcard and requires a request
    // in the test whose path has the same literal segments in the same
    // positions. Still tolerant of real ids and `format!`, still intolerant of
    // a route nobody asked for.
    let requested: Vec<Vec<String>> = body
        .match_indices('"')
        .filter_map(|(i, _)| {
            let rest = &body[i + 1..];
            rest.find('"').map(|end| &rest[..end])
        })
        .filter(|s| s.starts_with('/'))
        .map(|s| {
            s.split('?')
                .next()
                .unwrap_or(s)
                .split('/')
                .filter(|seg| !seg.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .collect();

    let mut uncovered = Vec::new();
    for path in &paths {
        let want: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let covered = requested.iter().any(|got| {
            got.len() == want.len()
                && want.iter().zip(got).all(|(w, g)| {
                    // A `{param}` matches whatever the test substituted for it;
                    // a literal segment must be that literal.
                    w.starts_with('{') || w == g
                })
        });
        if !covered {
            uncovered.push(*path);
        }
    }
    assert!(
        uncovered.is_empty(),
        "these routes are served but absent from the unauthenticated-request \
         test, so nothing checks that they refuse a caller with no \
         credentials:\n  {}",
        uncovered.join("\n  ")
    );
}

/// A journaled record names only `core` vocabulary.
///
/// The journal is the durable contract. Every type inside a `RecordKind` is a
/// word that history is written in, so it belongs in `core` beside
/// `Compensation`, `Disposition` and `Recovery` — the layer with no I/O and
/// nothing above it.
///
/// A field reaching *upward* into `runtime`, `store` or a transport is the
/// inversion this catches: it makes the durable format depend on an executor
/// that may be reorganised, and it hides a domain word in a module where
/// nobody looks for the journal's vocabulary. `GroupOutcome` was written in
/// `runtime` for exactly one release and read perfectly naturally there.
#[test]
fn every_journaled_record_field_names_core_vocabulary() {
    let src = std::fs::read_to_string("src/journal/record.rs").expect("record.rs");
    let start = src.find("pub enum RecordKind").expect("RecordKind");
    let end = src[start..].find("\nimpl RecordKind").expect("end of enum") + start;
    let body = &src[start..end];

    let mut checked = 0usize;
    for (n, line) in body.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with("#[") {
            continue;
        }
        for hit in code.match_indices("crate::") {
            checked += 1;
            let rest = &code[hit.0 + "crate::".len()..];
            let module: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            assert_eq!(
                module,
                "core",
                "RecordKind names `crate::{module}` at record.rs line {} — a journaled \
                 field must come from `core`, or the durable format depends on a layer \
                 above it:\n  {code}",
                n + 1
            );
        }
    }

    assert!(
        checked > 3,
        "the guard found only {checked} qualified paths in RecordKind, so it is \
         probably reading the wrong span rather than passing"
    );
}
