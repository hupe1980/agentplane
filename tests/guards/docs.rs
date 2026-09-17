//! Guards over the *published* documentation.
//!
//! Everything else in `tests/guards` checks the code against itself. This file
//! checks the code against what the site tells the world about it, which is a
//! different failure and a worse one: a wrong claim on a documentation site is
//! read by people deciding whether to trust the project, and nothing in a
//! normal test run touches it.
//!
//! It is here rather than in a shell script because a doc claim that drifts is
//! caught in the same `cargo test` an ordinary change already runs, and a check
//! nobody runs is not a check.

use std::path::Path;

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every module the crate exposes appears in the documented layout.
///
/// This drifted by **five modules** — `blob`, `manifest`, `peers`, `policy` and
/// `tools` were all public and none was listed — which is the failure mode a
/// hand-maintained map has: adding a module is a deliberate act, remembering a
/// diagram in another file is not. A reader consulting that section would have
/// concluded the crate has no blob storage.
///
/// The check runs in the direction that matters. A module missing from the
/// layout is a reader misled about what exists; a *stale* entry naming a module
/// that is gone is caught by the second half.
#[test]
fn the_documented_module_layout_lists_every_module() {
    let lib = read("src/lib.rs");
    let doc = read("site/content/docs/architecture.md");

    let layout = doc
        .split("## Module layout")
        .nth(1)
        .expect("the architecture page has a 'Module layout' section")
        .split("```")
        .nth(1)
        .expect("that section contains a code block");

    let declared: Vec<String> = lib
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub mod "))
        .filter_map(|l| l.split(&[';', ' '][..]).next())
        .map(str::to_owned)
        .collect();

    assert!(
        declared.len() > 10,
        "the `pub mod` scan found only {declared:?} — lib.rs moved and this guard is now inert"
    );

    let missing: Vec<&String> = declared
        .iter()
        .filter(|m| {
            // A module is listed as `name/` (a directory) or bare (a single
            // file), so match the name followed by either.
            !layout.contains(&format!("{m}/")) && !layout.contains(&format!("  {m} "))
        })
        .collect();

    assert!(
        missing.is_empty(),
        "these modules are public but absent from the documented layout in \
         site/content/docs/architecture.md: {missing:?} — a reader consulting \
         that map would conclude they do not exist"
    );
}

/// The layout does not name modules that are gone.
///
/// The other direction, and the one that turns a map into a lie rather than an
/// omission: a reader looking for a documented module and finding nothing
/// concludes the docs are stale about *everything*.
#[test]
fn the_documented_module_layout_names_nothing_that_is_gone() {
    let doc = read("site/content/docs/architecture.md");
    let layout = doc
        .split("## Module layout")
        .nth(1)
        .expect("the architecture page has a 'Module layout' section")
        .split("```")
        .nth(1)
        .expect("that section contains a code block");

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut named = 0;
    for line in layout.lines() {
        let Some(entry) = line.split_whitespace().next() else {
            continue;
        };
        let Some(name) = entry.strip_suffix('/') else {
            continue;
        };
        if name == "src" || name.is_empty() {
            continue;
        }
        named += 1;
        assert!(
            root.join(name).is_dir(),
            "the documented layout names `{name}/`, which does not exist in src/"
        );
    }
    assert!(
        named > 10,
        "only {named} directories were parsed out of the layout block — its \
         format changed and this guard is now inert"
    );
}

/// The feature table lists every optional feature.
///
/// A feature that exists and is undocumented is a capability nobody switches
/// on; a documented feature that does not exist is a build error the reader
/// blames on themselves.
#[test]
fn the_documented_feature_table_matches_cargo_toml() {
    let manifest = read("Cargo.toml");
    let doc = read("site/content/docs/getting-started.md");

    let features = manifest
        .split("\n[features]")
        .nth(1)
        .expect("Cargo.toml has a [features] section")
        .split("\n[")
        .next()
        .expect("the section ends");

    let names: Vec<&str> = features
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, _)| k.trim())
        // `default` is not something a user enables, and the internal
        // `dep:`-style aliases are not user-facing either.
        .filter(|k| !k.is_empty() && *k != "default" && !k.starts_with('#'))
        .collect();

    assert!(
        names.len() > 5,
        "the [features] scan found only {names:?} — Cargo.toml moved and this guard is now inert"
    );

    let undocumented: Vec<&&str> = names
        .iter()
        .filter(|f| !doc.contains(&format!("| `{f}`")))
        .collect();

    assert!(
        undocumented.is_empty(),
        "these Cargo features are not in the feature table on \
         site/content/docs/getting-started.md: {undocumented:?}"
    );

    // The reverse direction, which this guard's own doc comment always
    // promised and the test did not check: a table row for a feature that no
    // longer exists reads as a capability, and the reader who enables it gets
    // a build error they blame on themselves. Rows are `| `name` |` lines in
    // the feature table.
    let phantom: Vec<&str> = doc
        .lines()
        .filter_map(|l| {
            let row = l.strip_prefix("| `")?;
            let (name, _) = row.split_once('`')?;
            Some(name)
        })
        .filter(|row| !row.contains(' ') && !names.contains(row))
        .collect();
    assert!(
        phantom.is_empty(),
        "the feature table on site/content/docs/getting-started.md documents \
         features Cargo.toml does not define: {phantom:?}"
    );
}

/// **The release workflow names the package whose version it checks.**
///
/// `cargo metadata --no-deps` returns a *list*, and `.packages[0].version` is
/// only unambiguous while that list has one entry. A tag check that compares the
/// wrong package's version to the right tag passes and says nothing, and
/// crates.io is immutable — so the selection is by name, and held here rather
/// than remembered.
#[test]
fn the_release_workflow_selects_the_published_package_by_name() {
    let release = read(".github/workflows/release.yml");
    // Comments stripped first. The prohibition below is on what the workflow
    // *runs*, and the first version of this guard failed on the sentence
    // explaining why — a checker that reads a file's prose as its behaviour is
    // the same mistake in the other direction.
    let script: String = release
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        script.contains("cargo metadata"),
        "the release workflow no longer reads cargo metadata — this guard is inert"
    );
    assert!(
        !script.contains(".packages[0]"),
        "the release workflow picks a package by index. `--no-deps` lists every \
         workspace member, so index 0 is whichever one cargo emits first — and \
         this workspace has a test-only member at version 0.0.0. Select by \
         `.name == \"agentplane\"`"
    );
    assert!(
        script.contains(r#"select(.name == "agentplane")"#),
        "the release workflow must select the published package by name"
    );
}

/// **Nothing a release ships pulls `testkit` in.**
///
/// `testkit` carries fault injection, a signer that mints its own attestations,
/// and the exception that lets a peer be reached over plaintext — each of them
/// documented, at its definition, as a thing that cannot exist in a production
/// build. That claim was false for a year: `cli` listed `testkit`, so the
/// published binary and the container image carried all three. The one thing
/// `cli` actually needed was `provider: fake`, which is now `fake-model`.
///
/// A comment cannot hold this, because the failure is silent in both
/// directions: adding `testkit` to a shipped feature compiles, tests pass, and
/// nothing about the artifact says what is in it. So the closure is computed
/// here, over every feature a user can enable, and only `testkit` may reach
/// `testkit`.
#[test]
fn no_shipped_feature_enables_testkit() {
    let manifest = read("Cargo.toml");
    let table = manifest
        .split("\n[features]")
        .nth(1)
        .expect("Cargo.toml has a [features] section")
        .split("\n[")
        .next()
        .expect("the section ends");

    let mut graph: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for line in table.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let enables = rest
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|e| e.trim().trim_matches('"'))
            // `dep:` entries are dependencies, not features of this crate.
            .filter(|e| !e.is_empty() && !e.contains(':'))
            .collect();
        graph.insert(name, enables);
    }

    assert!(
        graph.contains_key("testkit") && graph.len() > 5,
        "the [features] scan found {graph:?} — Cargo.toml moved and this guard is now inert"
    );

    // What `f` ends up enabling, following the table to a fixed point.
    let closure = |f: &str| {
        let mut seen = std::collections::BTreeSet::new();
        let mut todo = vec![f];
        while let Some(next) = todo.pop() {
            for e in graph.get(next).into_iter().flatten() {
                if seen.insert(*e) {
                    todo.push(e);
                }
            }
        }
        seen
    };

    let leaks: Vec<&str> = graph
        .keys()
        .copied()
        .filter(|f| *f != "testkit" && closure(f).contains("testkit"))
        .collect();

    assert!(
        leaks.is_empty(),
        "these features enable `testkit`, so a build that asks for them ships fault \
         injection, a self-minting signer and the plaintext-loopback exception — each \
         of which is documented as impossible in a production build: {leaks:?}. If one \
         of them needs a piece of `testkit`, that piece is not a test double and \
         belongs beside the real thing, the way `fake-model` does."
    );

    // The other half: `cli` still has to be able to run `provider: fake`, which
    // is the need that put `testkit` there in the first place. Without this, the
    // guard above is satisfied by deleting the capability rather than by
    // separating it, and every getting-started page stops working.
    //
    // It checks the feature *graph*, and that is not the whole claim: the
    // binary's provider dispatch stayed `cfg(testkit)` through the split, so the
    // graph was right and `agentplane run` still answered "no driver for
    // provider 'fake'". `tools/cli-smoke.sh` is what caught it, because the
    // binary is never exercised by `cargo test` — it only compiles. Two checks,
    // and neither substitutes for the other.
    assert!(
        closure("cli").contains("fake-model"),
        "`cli` no longer enables `fake-model`, so `agentplane run` cannot construct the \
         `provider: fake` that the getting-started guide, first-agent and every \
         examples/*.yaml name"
    );
}

/// Every `cargo run --example …` command in the README actually runs.
///
/// The examples' `required-features` live in Cargo.toml, and a README line
/// that omits one fails with an error the reader blames on themselves — which
/// happened: a quickstart command drifted when an example gained a feature.
///
/// The default feature set counts as present, because `--features` adds to it.
///
/// What this does not check: that the example does what the comment beside it
/// says, or commands on the site (the site embeds and runs its own snippets).
#[test]
fn every_readme_example_command_names_the_features_it_needs() {
    let manifest = read("Cargo.toml");
    let readme = read("README.md");

    // `[[example]]` blocks: name plus required-features.
    let mut required: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for block in manifest.split("[[example]]").skip(1) {
        let name = block
            .lines()
            .find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == "name"))
            .map(|(_, v)| v.trim().trim_matches('"').to_owned());
        let features = block
            .lines()
            .find_map(|l| {
                l.split_once('=')
                    .filter(|(k, _)| k.trim() == "required-features")
            })
            .map(|(_, v)| {
                v.trim()
                    .trim_matches(['[', ']'])
                    .split(',')
                    .map(|f| f.trim().trim_matches('"').to_owned())
                    .filter(|f| !f.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(name) = name {
            required.insert(name, features);
        }
    }
    assert!(
        required.len() > 10,
        "the [[example]] scan found only {required:?} — Cargo.toml moved and \
         this guard is now inert"
    );

    let default_features = ["redb"];
    let mut commands = 0usize;
    let mut broken = Vec::new();
    for line in readme.lines() {
        let Some(rest) = line.trim().strip_prefix("cargo run --example ") else {
            continue;
        };
        commands += 1;
        let mut words = rest.split_whitespace();
        let example = words.next().unwrap_or_default();
        let listed: Vec<&str> = match words.next() {
            Some("--features") => words.next().unwrap_or_default().split(',').collect(),
            _ => Vec::new(),
        };
        let Some(needs) = required.get(example) else {
            broken.push(format!("`{example}` is not an example Cargo.toml declares"));
            continue;
        };
        for need in needs {
            if !default_features.contains(&need.as_str()) && !listed.contains(&need.as_str()) {
                broken.push(format!(
                    "`cargo run --example {example}` needs feature `{need}` \
                     and the README command does not pass it"
                ));
            }
        }
    }
    assert!(
        commands > 5,
        "the README scan found only {commands} `cargo run --example` commands \
         — the quickstart moved and this guard is now inert"
    );
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// Every file an example or module embeds is actually in the published tarball.
///
/// `include_str!` resolves at compile time against the *source tree*, so a
/// missing entry in Cargo.toml's `include` list is invisible locally and breaks
/// only when somebody builds the packaged crate. `cargo package --list` does not
/// catch it either — it lists what is there, and says nothing about what the
/// code needs.
///
/// This bit for real: `examples/manifest_run.rs` embeds `examples/agent.yaml`
/// while `include` listed only `/examples/*.rs`, so the crate on crates.io would
/// not have compiled. A publish is immutable, so that is a mistake you cannot
/// take back — only yank, with the broken contents still served.
#[test]
fn every_embedded_file_is_packaged() {
    let manifest = read("Cargo.toml");
    let include = manifest
        .split("\ninclude = [")
        .nth(1)
        .expect("Cargo.toml has an `include` list")
        .split(']')
        .next()
        .expect("the list ends");

    let globs: Vec<String> = include
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"'))
        .filter_map(|l| l.split('"').next())
        .map(|g| g.trim_start_matches('/').to_owned())
        .collect();

    assert!(
        globs.len() > 3,
        "the `include` scan found only {globs:?} — Cargo.toml moved and this guard is now inert"
    );

    // `/a/**/*.rs` and `/a/*.yaml` are the only shapes this crate uses; an
    // unrecognised one is reported rather than silently treated as matching.
    let matches = |path: &str| {
        globs.iter().any(|g| {
            g.strip_suffix(".rs")
                .or_else(|| g.strip_suffix(".yaml"))
                .map_or(g == path, |_| {
                    let (dir, ext) = g.rsplit_once('/').expect("a glob has a directory");
                    let ext = ext.trim_start_matches('*');
                    let dir = dir.trim_end_matches("/**");
                    path.starts_with(&format!("{dir}/")) && path.ends_with(ext)
                })
        })
    };

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for dir in ["examples", "src"] {
        for entry in walk(&root.join(dir)) {
            let text = std::fs::read_to_string(&entry).expect("read source");
            for marker in ["include_str!(\"", "include_bytes!(\""] {
                for chunk in text.split(marker).skip(1) {
                    let rel = chunk.split('"').next().expect("a quoted path");
                    let embedded = entry
                        .parent()
                        .expect("a file has a parent")
                        .join(rel)
                        .canonicalize()
                        .unwrap_or_else(|e| {
                            panic!(
                                "{}: embeds {rel}, which does not exist: {e}",
                                entry.display()
                            )
                        });
                    let packaged = embedded
                        .strip_prefix(root.canonicalize().expect("canonicalize root"))
                        .expect("embedded files live in the crate")
                        .to_string_lossy()
                        .replace('\\', "/");
                    checked += 1;
                    assert!(
                        matches(&packaged),
                        "{} embeds `{packaged}`, which no `include` entry in Cargo.toml \
                         covers — the packaged crate would not compile, and a publish \
                         cannot be taken back",
                        entry.display()
                    );
                }
            }
        }
    }

    assert!(
        checked > 0,
        "no `include_str!` was found at all — this guard is now inert"
    );
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "rs" || x == "md") {
            out.push(p);
        }
    }
    out
}

/// Documents whose section numbers a reader *can* resolve.
///
/// A published specification's section is not the leak this guard is about:
/// `the A2A specification §5.5` names its document and does not get renumbered
/// underneath a reader without a version. The exemption is a named list rather
/// than "anything with a citation", because the failure mode being prevented is
/// a bare `§11.1` that reads as though the reader ought to know which document
/// it means.
const NAMED_EXTERNAL: &[&str] = &["RFC", "C2SP", "A2A", "MCP", "CloudEvents"];

/// The internal design documents, by file name.
///
/// The name alone is the needle, so both a bare sibling reference and a
/// `concepts/`-prefixed path are caught. The folder name is deliberately *not*
/// on this list: the published site serves `/docs/concepts/`, and a needle that
/// coarse fails on the README link to it. `README.md` and `CHANGELOG.md` are
/// absent for the same reason in reverse — those ship.
const INTERNAL_DOCUMENTS: &[&str] = &[
    "OVERVIEW.md",
    "INVARIANTS.md",
    "EXECUTION.md",
    "STATE.md",
    "AUTHORITY.md",
    "INTEGRITY.md",
    "INTEROP.md",
    "OPERATIONS.md",
    "ASSURANCE.md",
    "LANDSCAPE.md",
    "DECISIONS.md",
    "REFERENCES.md",
    "ROADMAP.md",
    "SHAPES.md",
];

/// The internal folder itself, which no future document can escape.
///
/// The list above is a closed enumeration and a new design document falsifies
/// it — which happened. This catches the containing path instead, so a
/// reference to anything in it is flagged whether or not the filename was ever
/// added here. It also catches the half the filename list cannot see at all: a
/// line naming the *folder*, or a tool that operates on it, points readers at
/// something their checkout does not have just as surely as a dead link does.
const INTERNAL_FOLDER: &str = "concepts/";

/// Whether a line names one of the internal design documents.
///
/// The sibling detector below catches a bare `§11.1`. This catches the other
/// half of the same leak: naming or linking a document under `concepts/`, which
/// is not in the release tarball and is not on the site, so every such
/// reference is a dead link for the only people who read these pages. It is
/// easy to write while editing, because the file is open in the author's editor
/// and resolves fine there — which is precisely why a guard rather than a
/// habit.
fn names_internal_document(line: &str) -> bool {
    if INTERNAL_DOCUMENTS.iter().any(|doc| line.contains(doc)) {
        return true;
    }
    // The folder, minus the one spelling that is *not* it: `docs/concepts/` and
    // `concepts.md` are the published page of that name, which every reader can
    // follow. Checked by what precedes the match rather than by a denylist of
    // URLs, because a new link shape would slip past a denylist.
    line.match_indices(INTERNAL_FOLDER).any(|(at, _)| {
        let before = &line[..at];
        !before.ends_with("docs/") && !before.ends_with('.')
    })
}

/// Whether a line cites a section of a document the reader does not have.
///
/// A named specification before the section is a citation a reader can follow;
/// a bare one is a pointer into an internal document.
///
/// The internal document numbers two things, and for a while this saw only one:
/// sections are `§9.1` and invariants are `§I1`, so a reference to an invariant
/// went straight past a detector that required a digit after the sign. It slipped
/// a fresh leak into shipped rustdoc while the guard reported clean — the shape
/// this project keeps a second check for, arriving in the check itself.
fn cites_internal_section(line: &str) -> bool {
    let Some(at) = line.find('§') else {
        return false;
    };
    let before = &line[..at];
    if NAMED_EXTERNAL.iter().any(|doc| before.contains(doc)) {
        return false;
    }
    let mut after = line[at..].chars().skip(1);
    match after.next() {
        Some(c) if c.is_ascii_digit() => true,
        // `§I1`, an invariant rather than a section: the sign, `I`, a digit.
        Some('I') => after.next().is_some_and(|c| c.is_ascii_digit()),
        _ => false,
    }
}
/// The two detectors recognise what they exist to find, and nothing else.
///
/// Split from the scan below because they answer different questions: this one
/// asks whether the detectors work, and that one asks whether any artifact a
/// reader can see trips them. A detector that recognised nothing would make the
/// scan pass over every leak in the repository.
#[test]
fn the_internal_reference_detectors_recognise_what_they_are_for() {
    assert!(
        !cites_internal_section("/// the A2A specification §5.5 requires camelCase"),
        "a named external specification's section is resolvable and must not be flagged"
    );
    assert!(
        cites_internal_section("//! The sensitivity lattice (§12) controls what may leave"),
        "the detector does not recognise the very thing it exists to find"
    );
    assert!(
        cites_internal_section("/// Three is the shape §11.1 describes"),
        "the detector misses a subsection reference"
    );
    assert!(
        cites_internal_section("/// a nondeterministic read — §I1's exact prohibition"),
        "the detector misses an *invariant* reference, which is how a leak got \
         into shipped rustdoc while this guard reported clean"
    );
    assert!(
        !cites_internal_section("/// the § sign used as ordinary punctuation"),
        "the detector fires on a sign that cites nothing"
    );
    assert!(
        !cites_internal_section("/// RFC 4648 §4, the encoding the note format specifies."),
        "the detector flags an external specification, which is a citation a \
         reader *can* follow"
    );
    assert!(
        !cites_internal_section("/// an ordinary line with no citation at all"),
        "the detector fires on a line containing no section reference"
    );
    assert!(
        names_internal_document("see https://github.com/x/y/blob/main/concepts/AUTHORITY.md"),
        "the detector does not recognise a link to an internal document"
    );
    assert!(
        names_internal_document("/// the reasoning is in AUTHORITY.md"),
        "the detector does not recognise an internal document by its bare name"
    );
    assert!(
        !names_internal_document("/// the reasoning is stated at the mechanism"),
        "the detector fires on a line naming no document"
    );
    assert!(
        !names_internal_document("/// the release notes are in CHANGELOG.md"),
        "the detector flags a document that ships"
    );
    assert!(
        names_internal_document("| `just x` | after editing `concepts/` |"),
        "the detector misses the internal folder named on its own, which is how \
         a reference to it reached a public page while every filename was absent"
    );
    assert!(
        names_internal_document("see concepts/SOMETHING-NEW.md for the reasoning"),
        "a design document added later must be caught by the folder, because the \
         filename list is a closed enumeration and adding one falsifies it"
    );
    assert!(
        !names_internal_document(
            "[Concepts](https://hupe1980.github.io/agentplane/docs/concepts/)"
        ),
        "the published page of that name is a link every reader can follow"
    );
    assert!(
        !names_internal_document("see @/docs/concepts.md for the ideas"),
        "the site's own page must not be mistaken for the internal folder"
    );
}

/// Shipped source must not cite sections of the internal design document.
///
/// The packaging guard checks that the internal document is not in the release
/// tarball. A bare `§11.1` slips straight past that while being the same leak:
/// this crate's
/// rustdoc goes to docs.rs, where a reader has no document to resolve that
/// number against. It is also the reference most likely to be *wrong* — the
/// design document gets renumbered, and nothing recompiles a comment. Seventeen
/// of these had accumulated, and several pointed at sections that had since
/// become something else entirely or no longer existed at all.
///
/// The detectors are exercised on known inputs by the sibling test above, and
/// that is not a convenience: on a clean tree a working detector and a disabled
/// one both report nothing, so without it deleting the rule would leave a green
/// test guarding an empty set.
#[test]
fn nothing_a_reader_sees_cites_an_internal_section_number() {
    // `src` is what reaches docs.rs, but the repository is public and an
    // evaluator reads `tests` and `examples` to see what the crate can do. A
    // pointer into a document they do not have is the same dead reference
    // wherever it sits, so all three are scanned. Markdown is covered too: the
    // site and the README are the first thing anyone reads.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples", "site/content"] {
        files.extend(walk(&root.join(dir)));
    }
    files.push(root.join("README.md"));
    files.push(root.join("CONTRIBUTING.md"));
    // Ships *inside the crate tarball*, so a dead reference here travels
    // further than one on the site and was the file this scan did not read.
    files.push(root.join("CHANGELOG.md"));
    assert!(
        files.len() > 60,
        "the scan found only {} files — this guard is now inert",
        files.len()
    );

    let mut offenders = Vec::new();
    for path in &files {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        // This file defines the detector, so it necessarily contains examples
        // of what it detects. Excluding it by name rather than by pattern: a
        // pattern that skipped "lines that look like fixtures" would also skip
        // a real leak that happened to look like one.
        if path.file_name().is_some_and(|n| n == "docs.rs") {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            if cites_internal_section(line) || names_internal_document(line) {
                offenders.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(root).unwrap_or(path).display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "an artifact a reader can see points into the internal design document — \
         by section number, which they cannot resolve and which goes stale \
         silently when the document is renumbered, or by name, which is a dead \
         link because that file ships nowhere. State the reasoning instead:\n{}",
        offenders.join("\n")
    );
}

/// Every manifest published anywhere is one the crate's own parser accepts.
///
/// A manifest in a document is a snippet a reader copies, and nothing in the
/// toolchain reads it: doc tests compile Rust under `src/`, never the YAML in a
/// markdown page. So an example could contradict a validation rule the same
/// repository enforces, and did — the architecture page's flagship agent
/// declared `role: specialist` beside `max_delegation_depth: 2`, a pair
/// [`Manifest::validate`](agentplane::manifest::Manifest::validate) refuses.
///
/// A reader following the page got a parse error from the first command.
///
/// The parser is the authority here, deliberately: a guard that re-implemented
/// the rules would be a second copy of them, agreeing everywhere except the
/// boundary that matters.
#[test]
#[cfg(feature = "manifest")]
fn every_documented_manifest_parses() {
    use agentplane::manifest::{API_VERSION, Manifest};

    let mut checked = 0usize;
    let mut pages = 0usize;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = vec![root.join("README.md")];
    let mut stack = vec![root.join("site/content")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("the site content tree is readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }

    for file in &files {
        pages += 1;
        let text = std::fs::read_to_string(file).expect("a readable page");
        // Fenced blocks, in order; every other segment is inside a fence.
        for (index, block) in text.split("```").enumerate() {
            if index % 2 == 0 {
                continue;
            }
            let body = block.split_once('\n').map_or("", |(_, rest)| rest);
            if !body.contains(API_VERSION) {
                continue;
            }
            checked += 1;
            // `parse_all`, not `parse`: a published block may be a whole
            // room (documents separated by `---`), and each document is held
            // to the same validation a single manifest is.
            if let Err(error) = Manifest::parse_all(body).map(|_| ()) {
                panic!(
                    "the manifest published in {} is refused by this crate's own \
                     parser, so a reader copying it gets an error rather than an \
                     agent: {error}\n---\n{body}",
                    file.strip_prefix(root).unwrap_or(file).display()
                );
            }
        }
    }

    // A walk that read nothing satisfies every assertion above by having
    // nothing to assert on, which is the silent failure this project keeps a
    // second check for.
    assert!(
        pages > 5,
        "the documentation walk found only {pages} pages — the site moved and \
         this guard is now inert"
    );
    assert!(
        checked > 0,
        "no published manifest was found to check across {pages} pages — either \
         the examples were removed or the fence scan stopped matching them"
    );
}

/// Every recipe's `just --list` line is a summary, not a sentence fragment.
///
/// `just` shows the **last** comment line above a recipe and nothing else, so a
/// rationale paragraph ending in a subordinate clause is published as the
/// recipe's description. Two thirds of them had read like *"than for the
/// reader."* and *"warm."* — and `just --list` is the first thing anyone runs.
///
/// The rule is the shape that makes it true: a summary is separated from the
/// rationale above it by a bare `#`, or is the only comment line. It is a
/// property of the file rather than of the prose, which is what makes it
/// checkable at all.
#[test]
fn every_recipe_publishes_a_summary_rather_than_a_fragment() {
    let recipe = read("justfile");
    let lines: Vec<&str> = recipe.lines().collect();
    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        // A recipe header: a name at column zero ending in `:`, which
        // distinguishes it from an assignment (`NAME := "..."`).
        let Some((head, _)) = line.split_once(':') else {
            continue;
        };
        if line.starts_with([' ', '\t', '#']) || head.is_empty() || line.contains(":=") {
            continue;
        }
        let name = head.split_whitespace().next().unwrap_or_default();
        if !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            continue;
        }
        let Some(previous) = index.checked_sub(1).map(|i| lines[i]) else {
            continue;
        };
        if !previous.starts_with('#') {
            // Undocumented is a different finding, and `just --list` says so
            // for itself by printing no description at all.
            continue;
        }
        checked += 1;
        let before_summary = index.checked_sub(2).map(|i| lines[i]).unwrap_or_default();
        if before_summary.starts_with('#') && before_summary.trim() != "#" {
            bad.push(format!(
                "{name}: `just --list` publishes `{}`",
                previous.trim()
            ));
        }
    }

    assert!(
        checked > 20,
        "only {checked} documented recipes were found — the justfile moved and \
         this guard is now inert"
    );
    assert!(
        bad.is_empty(),
        "these recipes publish the tail of a paragraph as their description — \
         put a one-line summary last, separated by a bare `#`:\n  {}",
        bad.join("\n  ")
    );
}

/// Every schema this repository publishes can actually be asked for.
///
/// Constrained decoding accepts a **subset** of JSON Schema, and the `OpenAI`
/// driver refuses anything outside it before sending — so a declared
/// `output.schema` missing `additionalProperties: false`, or an array with no
/// `items`, is an agent that parses, passes every test against `FakeProvider`,
/// and fails at its first real model call. Four shipped manifests were in that
/// state, including two a reader is pointed at by name.
///
/// A tool's `arguments` fails differently and more quietly: the drivers drop to
/// non-strict rather than refusing, so the schema becomes a suggestion the
/// model may ignore — which is the thing this crate says a schema is not.
///
/// The checker is the authority, as the parser is next door: re-deriving the
/// subset here would be a second copy of it, agreeing everywhere except the
/// boundary that matters.
#[test]
#[cfg(all(feature = "manifest", feature = "providers"))]
fn every_published_schema_survives_constrained_decoding() {
    use agentplane::manifest::{API_VERSION, Manifest};
    use agentplane::model::strict_schema_problem;

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources: Vec<(String, String)> = Vec::new();

    for entry in std::fs::read_dir(root.join("examples")).expect("examples are readable") {
        let path = entry.expect("a readable directory entry").path();
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") => {
                sources.push((
                    name,
                    std::fs::read_to_string(&path).expect("a readable file"),
                ));
            }
            // An example that embeds its manifest as a raw string is as
            // published as one that ships a file beside it, and is more likely
            // to be the thing a reader copies.
            Some("rs") => {
                let text = std::fs::read_to_string(&path).expect("a readable file");
                for (index, block) in text.split("r#\"").enumerate() {
                    if index == 0 {
                        continue;
                    }
                    let Some((body, _)) = block.split_once("\"#") else {
                        continue;
                    };
                    sources.push((name.clone(), body.to_owned()));
                }
            }
            _ => {}
        }
    }

    let mut files: Vec<std::path::PathBuf> = vec![root.join("README.md")];
    let mut stack = vec![root.join("site/content")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("the site content tree is readable") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a readable page");
        for (index, block) in text.split("```").enumerate() {
            if index % 2 == 0 {
                continue;
            }
            let body = block.split_once('\n').map_or("", |(_, rest)| rest);
            if body.contains(API_VERSION) {
                let name = file
                    .strip_prefix(root)
                    .unwrap_or(file)
                    .display()
                    .to_string();
                sources.push((name, body.to_owned()));
            }
        }
    }

    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for (name, text) in &sources {
        let Ok(manifests) = Manifest::parse_all(text) else {
            // Unparseable is the neighbouring guard's finding, not this one's.
            continue;
        };
        for manifest in manifests {
            let agent = manifest.metadata.name.clone();
            let mut schemas: Vec<(String, &serde_json::Value)> = Vec::new();
            if let Some(output) = manifest.output_schema() {
                schemas.push(("spec.output.schema".to_owned(), output));
            }
            for grant in &manifest.spec.tools {
                if let Some(arguments) = grant.arguments.as_ref() {
                    schemas.push((format!("{} arguments", grant.reference), arguments));
                }
            }
            for (where_, schema) in schemas {
                checked += 1;
                if let Some(problem) = strict_schema_problem(schema) {
                    bad.push(format!("{name} [{agent}] {where_}: {problem}"));
                }
            }
        }
    }

    assert!(
        checked > 8,
        "only {checked} schemas were found — the walk stopped matching and this \
         guard is now inert"
    );
    assert!(
        bad.is_empty(),
        "a published schema cannot be asked for under constrained decoding, so \
         the agent declaring it fails at its first real model call:\n  {}",
        bad.join("\n  ")
    );
}

/// Every example is actually run by the recipe that claims to run them all.
///
/// `just examples` is the only thing that executes example code, so an example
/// missing from it compiles forever and never runs — which is worse than not
/// having it, because the README points readers at something nothing checks.
///
/// `memory_run` had been in that state.
///
/// The `_live` examples are exempt by name and by design: they spend money
/// against a real provider, and a credential being available is not a decision
/// to use it. `_bench` is exempt for a different reason — it is a *measurement*
/// rather than a demonstration, it runs for twenty seconds, and CI time is a
/// real cost. Both exemptions are by suffix so adding one is a rename somebody
/// has to mean, rather than a name quietly missing from a list.
#[test]
fn every_example_is_run_by_the_examples_recipe() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let recipe = read("justfile");
    let block = recipe
        .split("\nexamples:")
        .nth(1)
        .expect("the justfile has an `examples` recipe")
        .split("\n\n")
        .next()
        .expect("the recipe ends at a blank line");

    let mut on_disk: Vec<String> = std::fs::read_dir(root.join("examples"))
        .expect("the examples directory is readable")
        .filter_map(Result::ok)
        .filter_map(|e| {
            let p = e.path();
            (p.extension()? == "rs")
                .then(|| p.file_stem()?.to_str().map(str::to_owned))
                .flatten()
        })
        .filter(|name| !name.ends_with("_live") && !name.ends_with("_bench"))
        .collect();
    on_disk.sort();

    assert!(
        on_disk.len() > 8,
        "only {on_disk:?} were found — the examples directory moved and this \
         guard is now inert"
    );

    // The recipe names each example as a bare word in the loop it runs, so a
    // word-boundary match rather than a substring one: `model_run` must not be
    // satisfied by `batch_run` sharing a suffix, nor `plan_graph` by a comment
    // that mentions it.
    let named: Vec<&str> = block
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .collect();

    let missing: Vec<&String> = on_disk
        .iter()
        .filter(|name| !named.contains(&name.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "these examples are never executed by `just examples`, so nothing \
         notices when they stop working: {missing:?}"
    );

    // And the other direction, which the substring form could not ask: a name
    // in the loop with no file behind it makes the recipe fail with
    // `no such file or directory` on a path nobody recognises, at the end of a
    // run that already took a minute.
    let phantom: Vec<&str> = block
        .lines()
        .skip_while(|l| !l.contains("for ex in"))
        .take_while(|l| !l.contains("done"))
        .flat_map(|l| l.split_whitespace())
        .filter(|w| {
            w.chars().all(|c| c.is_alphanumeric() || c == '_')
                && w.contains('_')
                && *w != "for"
                && *w != "ex"
                && *w != "in"
        })
        .filter(|w| !on_disk.iter().any(|d| d == w))
        .collect();

    assert!(
        phantom.is_empty(),
        "`just examples` runs names with no file in examples/: {phantom:?}"
    );
}

/// No rustdoc block carries two of the same top-level section.
///
/// The shape this catches is a doc comment that has silently absorbed the one
/// below it, which happens when a new method is inserted *between* an existing
/// doc block and the function it belonged to. Nothing in the toolchain says a
/// word: the block is valid rustdoc, the orphaned function compiles, and the
/// only symptom is that one published page describes the wrong operation while
/// another describes nothing.
///
/// It happened here. `StepCtx::draw` was inserted above `StepCtx::recall`'s doc
/// comment, so `draw` — the method that spends a customer's standing
/// authorization — was published under "Recall what this agent remembers about a
/// subject", with two `# Errors` sections, one of them about a missing memory
/// store. `recall` was published with no documentation at all.
///
/// A duplicated `# Errors` (or `# Panics`, or `# Examples`) is the mechanical
/// fingerprint of that merge, because each is a section a single item has at
/// most one of. Cheaper and far more precise than `missing_docs`, which fires
/// 1124 times on this crate — mostly on builder methods whose names already say
/// everything, where a doc comment would restate the code rather than explain
/// it.
///
/// **That fingerprint alone missed twenty-three of these**, because most merged
/// blocks contain no `#` section at all. `RuntimeBuilder::signing_as` and
/// `lease_ttl` were both published under `owner`'s summary while `owner` had no
/// documentation; `EffectError::spend` was published under `disposition`'s, and
/// `disposition` — the accessor that decides `DidNotHappen`/`InDoubt`/`Landed` —
/// had none. So a second fingerprint runs beside the first, taken from those
/// twenty-three: **an absorbed summary is a one-sentence line that closes a
/// paragraph and follows another complete sentence.** A merge splices the next
/// item's summary directly onto the previous block's final paragraph, with no
/// blank `///` between, and a summary is always followed by the blank line
/// rustdoc needs before a body.
///
/// The rule that keeps it exact, and the reason seven blocks were reflowed when
/// it landed: **a sentence that closes a paragraph and follows another complete
/// sentence starts its own paragraph.** That is a formatting convention this
/// codebase already follows for punchlines, and holding to it is what makes the
/// second fingerprint report nothing on a clean tree.
///
/// What it therefore does **not** catch, stated because a checker that hides its
/// reach is worse than one that admits it: a merge whose absorbed summary wraps
/// onto two lines, one that lands mid-paragraph rather than before a blank, and
/// a doc block attached to the wrong item where nothing was absorbed at all.
///
/// Only the compiler resolves that last one.
///
/// **And a fourth escape, found by three real instances after this guard was
/// green**: an absorbed doc that was a *one-liner* lands as the block's final
/// line — there is no body below it, so no blank `///` follows and the loop
/// bound `1..len-1` never reaches it. `audit`'s whole doc block sat on
/// `releases_in`, `run_correlated`'s explanation sat on `run_in_case`, and the
/// `skills` field's summary sat on `per_agent` — all final lines. Extending the
/// detector there was measured and declined: the same predicate over final
/// lines fires on 31 legitimate closing punchlines against 3 defects, and a
/// guard that cries ten-to-one trains the reader it exists to protect. The
/// sweep that found them is the review prompt instead: when auditing, run the
/// final-line variant by hand and read the hits.
#[test]
fn no_doc_comment_has_absorbed_the_one_below_it() {
    const SECTIONS: [&str; 4] = ["# Errors", "# Panics", "# Examples", "# Safety"];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    let mut merged: Vec<String> = Vec::new();

    // `tests/` and `examples/` as well as `src/`, because the guard's own file
    // carried two of these and the scan walked straight past them. A pointer at
    // the wrong item is the same defect wherever it sits, and the repository is
    // public.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![root.join("src"), root.join("tests"), root.join("examples")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("the tree is readable")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }

    for file in &files {
        let text = std::fs::read_to_string(file).expect("readable");
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string();

        // One block is a maximal run of consecutive `///` lines. `//!` is
        // excluded: a module header legitimately has several sections and is
        // not attached to an item.
        let mut block: Vec<&str> = Vec::new();
        let mut start = 0usize;
        for (i, line) in text.lines().chain(std::iter::once("")).enumerate() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix("///") {
                if block.is_empty() {
                    start = i + 1;
                }
                block.push(rest.trim());
                continue;
            }
            if !block.is_empty() {
                checked += 1;
                for section in SECTIONS {
                    let n = block.iter().filter(|&&l| l == section).count();
                    if n > 1 {
                        merged.push(format!(
                            "{rel}:{start} has {n} `{section}` sections — this block \
                             has absorbed the doc comment of the item below it"
                        ));
                    }
                }
                for k in 1..block.len().saturating_sub(1) {
                    if absorbed_summary(block[k - 1], block[k], block[k + 1]) {
                        merged.push(format!(
                            "{rel}:{} reads as the summary of a *different* item — \
                             `{}` closes a paragraph directly after another complete \
                             sentence, which is what an absorbed doc comment looks \
                             like. If it belongs to the item below, move it there; if \
                             it is a punchline for the paragraph above, join it to \
                             that paragraph. Do **not** separate it with a blank \
                             `///` line to quieten this: that is the shape the \
                             no-summary check below exists to catch, and moving a \
                             defect between two detectors is not fixing it",
                            start + k,
                            block[k]
                        ));
                    }
                }
                // The other half, and the one the typographic check above
                // cannot reach. An absorbed doc block leaves a footprint at the
                // item *below* it: that item is left with only its `# Errors`
                // or `# Panics` section and no summary, which rustdoc renders
                // as an empty description. Checking for that is sound where the
                // paragraph shape is a heuristic — there is no legitimate
                // reason for a documented item to open on a section header —
                // and it catches the absorption whether or not a blank line
                // separates the two halves. The netguard SSRF gate was absorbed
                // into the error enum below it with a blank line between, which
                // is precisely the case `absorbed_summary` returns false for.
                if let Some(first) = block.iter().find(|l| !l.is_empty())
                    && SECTIONS.iter().any(|s| first.starts_with(s))
                {
                    merged.push(format!(
                        "{rel}:{start} opens on `{first}` and has no summary — \
                         rustdoc renders this item with an empty description. \
                         Either its summary was absorbed by the doc comment \
                         above it, or it never had one; both want the same fix"
                    ));
                }
                block.clear();
            }
        }
    }

    assert!(
        checked > 1_000,
        "only {checked} doc blocks were scanned — the `///` scan stopped \
         matching and this guard is now inert"
    );
    assert!(merged.is_empty(), "{}", merged.join("\n"));
}

/// Whether `cur` reads as a summary line absorbed from the item below.
///
/// Three conditions, all taken from the twenty-three real instances: the line
/// closes a paragraph (`next` is blank), it follows a line that also ends a
/// sentence (so it is not ordinary wrapped prose continuing a thought), and it
/// is a single sentence (a summary is one sentence; a body paragraph is not).
///
/// List items are exempt: a bulleted line legitimately ends a sentence directly
/// after another bulleted line, and `Scope`'s capability list is the case that
/// proved it.
fn absorbed_summary(prev: &str, cur: &str, next: &str) -> bool {
    let is_list = |l: &str| l.starts_with('*') || l.starts_with('-');
    if !next.is_empty() || is_list(cur) || is_list(prev) {
        return false;
    }
    if !prev.ends_with('.') || !cur.ends_with('.') {
        return false;
    }
    // Two sentences on one line is a paragraph, not a summary.
    !cur.match_indices(". ")
        .any(|(i, _)| cur[i + 2..].chars().next().is_some_and(char::is_uppercase))
}

/// The second fingerprint fires on the defect that motivated it, and not on the
/// prose next door.
///
/// A guard's first act must be to fail on the specific defect it was written
/// for. On a clean tree a working detector and a disabled one both report
/// nothing, so without this the rule could be deleted and leave a green test.
#[test]
fn the_absorbed_summary_detector_recognises_what_it_is_for() {
    assert!(
        absorbed_summary(
            "one, such as a pod name. An agent's *name* is several.",
            "How long this plane's run leases last.",
            ""
        ),
        "the detector misses the shape that published `lease_ttl` under `owner`'s summary"
    );
    assert!(
        absorbed_summary(
            "part of the prefix invalidates every later signature, not just its own.",
            "The largest a single journal record may be.",
            ""
        ),
        "the detector misses the shape that published `MAX_RECORD_BYTES` under \
         `seal_signed`'s summary"
    );
    assert!(
        !absorbed_summary(
            "crate's to declare and a guard that flagged them would be turned",
            "off, which is why the allowlist exists.",
            ""
        ),
        "the detector fires on ordinary wrapped prose, whose previous line does \
         not end a sentence"
    );
    assert!(
        !absorbed_summary(
            "* `\"billing.reconcile\"` — exactly that capability.",
            "* `\"billing.*\"` — that prefix and everything under it.",
            ""
        ),
        "the detector fires on a bulleted list, where consecutive sentence-final \
         lines are the normal shape"
    );
    assert!(
        !absorbed_summary(
            "the sealed block travels to third-party tool servers and peers.",
            "So the three are separated. They are argued about no longer.",
            ""
        ),
        "the detector fires on a two-sentence paragraph, which is not a summary"
    );
    assert!(
        !absorbed_summary(
            "the sealed block travels to third-party tool servers and peers.",
            "So the three are separated rather than argued about.",
            "and the reasoning is worth keeping."
        ),
        "the detector fires on a line that does not close its paragraph"
    );
}

/// Every published YAML block is well-formed YAML, whole manifest or fragment.
///
/// `every_documented_manifest_parses` above checks blocks containing
/// `apiVersion`, which is the right check for a complete agent and covers none
/// of the **fragments** — a `spec:` excerpt showing one section, which is most
/// of what the cookbook and manifest reference publish. A fragment is what a
/// reader copies *into* a manifest they already have, so a broken one fails in
/// their editor rather than in ours.
///
/// One was broken: the cookbook's protected-fields excerpt had
/// `protected_fields:` indented past the sibling keys of its own list item, and
/// the item keys under it indented past `path`. Both are YAML errors, and
/// nothing read the block because it named no `apiVersion`.
///
/// Parsed as plain YAML rather than as a `Manifest`, because a fragment is by
/// definition not a whole document — the question is whether the *shape* the
/// page shows is syntactically real, not whether an excerpt is a complete
/// agent.
#[test]
// `serde_yaml_ng` is the `manifest` feature's parser, and gating on the
// feature rather than vendoring a second YAML crate keeps the guard reading
// these blocks with the same parser that will read them for real.
#[cfg(feature = "manifest")]
fn every_published_yaml_fragment_is_well_formed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files: Vec<std::path::PathBuf> = vec![root.join("README.md")];
    let mut stack = vec![root.join("site/content")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }

    let mut checked = 0usize;
    let mut broken: Vec<String> = Vec::new();

    for file in &files {
        let text = std::fs::read_to_string(file).expect("readable");
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string();
        for (index, block) in text.split("```").enumerate() {
            // Odd segments are inside a fence; the first line is its language.
            if index % 2 == 0 {
                continue;
            }
            let Some((lang, body)) = block.split_once('\n') else {
                continue;
            };
            if lang.trim() != "yaml" {
                continue;
            }
            checked += 1;
            // A fragment is indented under a parent this excerpt does not show,
            // so the common leading indentation is stripped before parsing —
            // otherwise every excerpt fails for a reason that is not a defect.
            let indent = body
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.len() - l.trim_start().len())
                .min()
                .unwrap_or(0);
            let dedented: String = body
                .lines()
                .map(|l| if l.len() >= indent { &l[indent..] } else { l })
                .collect::<Vec<_>>()
                .join("\n");
            if let Err(error) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&dedented) {
                broken.push(format!("{rel}: {error}\n---\n{dedented}"));
            }
        }
    }

    assert!(
        checked > 10,
        "only {checked} yaml fences were found — the fence scan stopped matching \
         and this guard is now inert"
    );
    assert!(
        broken.is_empty(),
        "a reader copying these gets a parse error:\n{}",
        broken.join("\n\n")
    );
}

/// Every public method on `StepCtx`, gathered across the runtime module.
///
/// Scoped to the `impl StepCtx` blocks, and read from every file rather than
/// one: `ctx.rs` also holds `Mode` and the commission effect, whose methods
/// must not make the caller permissive — and `group.rs` carries
/// `StepCtx::group`, so reading `ctx.rs` alone reported the four pages that
/// document it as wrong. A guard's own first run is where that gets found.
fn step_ctx_methods(root: &Path) -> std::collections::BTreeSet<String> {
    let mut real = std::collections::BTreeSet::new();
    for file in walk(&root.join("src/runtime")) {
        if file.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&file).expect("a readable module");
        let mut in_step_ctx = false;
        for line in source.lines() {
            if line.starts_with("impl") {
                in_step_ctx = line.contains("StepCtx");
            }
            if !in_step_ctx {
                continue;
            }
            let Some(rest) = line.trim_start().strip_prefix("pub ") else {
                continue;
            };
            let rest = rest.strip_prefix("async ").unwrap_or(rest);
            let rest = rest.strip_prefix("const ").unwrap_or(rest);
            if let Some(name) = rest.strip_prefix("fn ") {
                let name: String = name
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    real.insert(name);
                }
            }
        }
    }
    real
}

/// Every `cx.method(...)` a page publishes names a method that exists.
///
/// The defect this catches shipped: the concepts page's `StepCtx` table — the
/// surface a newcomer programs against — listed `random()`, `write_case_state()`
/// and `read_blob`, none of which are on the type. The real names are `rng()`,
/// `put_case_state()` and `blobs()`. A reader copying any of the three gets a
/// compile error, and nothing in the toolchain looked: doc tests compile
/// rustdoc under `src/`, never the markdown, and the one harness that does
/// build a published snippet only builds the *first* example a reader meets.
///
/// Deliberately one-directional. It refuses a documented name that does not
/// exist; it does not demand that every method be documented, because a page
/// choosing what to teach is editorial and a guard that forced completeness
/// would be answered by a table nobody reads.
///
/// One hazard comes with it: **prose describing this guard is scanned by it.**
/// The status page's own row for this check cited two invented names as
/// examples and failed the build. Describe the check without writing the
/// literal call forms — the alternative is exempting a page, which would let
/// real drift hide on whichever page carries the exemption.
#[test]
fn every_documented_step_ctx_method_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let real = step_ctx_methods(root);
    assert!(
        real.len() > 20,
        "only {} StepCtx methods were found — the impl blocks moved and this \
         guard is now inert",
        real.len()
    );

    let mut pages = 0usize;
    let mut cited = 0usize;
    let mut bad: Vec<String> = Vec::new();
    let mut files: Vec<std::path::PathBuf> = vec![root.join("README.md")];
    files.extend(walk(&root.join("site/content")));
    for file in &files {
        if file.extension().is_none_or(|e| e != "md") {
            continue;
        }
        pages += 1;
        let text = std::fs::read_to_string(file).expect("a readable page");
        for (n, line) in text.lines().enumerate() {
            // Both spellings a page uses: `cx.recall(` in a snippet and
            // `StepCtx::recall` in prose.
            for (marker, offset) in [("cx.", 3usize), ("StepCtx::", 9)] {
                let mut from = 0usize;
                while let Some(at) = line[from..].find(marker) {
                    let start = from + at + offset;
                    let name: String = line[start..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    from = start.max(from + at + 1);
                    if name.is_empty() {
                        continue;
                    }
                    // A call or a rustdoc-style reference, not a field access
                    // in prose like `cx.step` — only names followed by `(`
                    // or closing a doc link are claims about the API.
                    let after = line[start + name.len()..].chars().next();
                    if !matches!(after, Some('(' | ')' | '`') | None) {
                        continue;
                    }
                    cited += 1;
                    if !real.contains(&name) {
                        bad.push(format!(
                            "{}:{}: `{marker}{name}` is not a StepCtx method",
                            file.strip_prefix(root).unwrap_or(file).display(),
                            n + 1
                        ));
                    }
                }
            }
        }
    }

    // The table under `{#step-context}` is the one place a method is published
    // *bare* — ``random()`` rather than ``cx.random(`` — and it is the page a
    // newcomer programs against, so the markers above walk straight past the
    // defect this guard exists for. Its own first version did exactly that:
    // it passed with `random()` reinstated. Scanned separately rather than by
    // loosening the markers, because a bare ``foo()`` anywhere else in the
    // prose is as likely to be someone else's API as this one's.
    let concepts = read("site/content/docs/concepts.md");
    let table = concepts
        .split_once("{#step-context}")
        .map(|(_, rest)| rest.split("\n## ").next().unwrap_or(rest))
        .expect("the concepts page still carries the StepCtx section");
    let mut table_cited = 0usize;
    for row in table.lines().filter(|l| l.starts_with('|')) {
        for cell in row.split('`') {
            let name: String = cell
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || !cell[name.len()..].starts_with('(') {
                continue;
            }
            table_cited += 1;
            if !real.contains(&name) {
                bad.push(format!(
                    "site/content/docs/concepts.md: the StepCtx table lists \
                     `{name}()`, which is not a method on the type"
                ));
            }
        }
    }

    assert!(
        pages > 5 && cited > 20 && table_cited > 10,
        "the walk found {pages} pages, {cited} citations and {table_cited} \
         table rows — the site moved and this guard is now inert"
    );
    assert!(
        bad.is_empty(),
        "a page publishes a StepCtx method that does not exist, so a reader \
         copying it gets a compile error:\n  {}",
        bad.join("\n  ")
    );
}

/// Every field the manifest reference tabulates is a field the parser knows.
///
/// The YAML-block guards above run published *examples* through the real
/// parser, so a stale field inside a fenced block fails loudly. A stale field
/// in a **table** fails nowhere: the reference's field-by-field tables are
/// prose to every tool in the toolchain, and `deny_unknown_fields` means a
/// reader who copies a renamed one gets a hard parse failure rather than a
/// warning. That is the same shape as the `StepCtx` table next door, which
/// shipped three method names that did not exist.
///
/// One-directional, for the same reason: it refuses a documented field that
/// is gone, and does not demand that every field be tabulated.
#[test]
fn every_tabulated_manifest_field_exists() {
    // The whole module, not only `mod.rs`: the declaration's types are spread
    // across files — `triage.rs` holds the rule and condition shapes — and a
    // scan of one file reports every field in the others as documented-but-
    // nonexistent, which is a guard failing for its own reason.
    let source: String =
        walk(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/manifest"))
            .iter()
            .map(|f| std::fs::read_to_string(f).expect("read a manifest module file"))
            .collect::<Vec<_>>()
            .join("\n");

    let mut real: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        // Struct fields as serde sees them: the declared name, plus any
        // `rename` that changes what the YAML actually says.
        if line.starts_with("    pub ")
            && let Some(rest) = trimmed.strip_prefix("pub ")
            && let Some((name, _)) = rest.split_once(':')
            && name
                .chars()
                .all(|c| c.is_lowercase() || c.is_numeric() || c == '_')
        {
            real.insert(name.to_owned());
        }
        if let Some(at) = trimmed.find("rename = \"") {
            let rest = &trimmed[at + 10..];
            if let Some((name, _)) = rest.split_once('"') {
                real.insert(name.to_owned());
            }
        }
    }
    assert!(
        real.len() > 40,
        "only {} manifest fields were found — the module moved and this guard \
         is now inert",
        real.len()
    );

    let page = read("site/content/docs/manifest.md");
    let mut checked = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for (n, line) in page.lines().enumerate() {
        // A field row: the first cell is a single backticked identifier. A
        // dotted path (`spec.tools[].ref`) is checked on its last segment,
        // which is the part the parser names.
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((cell, _)) = rest.split_once('`') else {
            continue;
        };
        if !cell
            .chars()
            .all(|c| c.is_lowercase() || c.is_numeric() || "_.[]".contains(c))
        {
            continue;
        }
        let leaf = cell
            .rsplit('.')
            .next()
            .unwrap_or(cell)
            .trim_end_matches("[]");
        checked += 1;
        if !real.contains(leaf) {
            bad.push(format!(
                "manifest.md:{}: `{cell}` is not a manifest field",
                n + 1
            ));
        }
    }

    assert!(
        checked > 20,
        "only {checked} field rows were found — the reference's tables changed \
         shape and this guard is now inert"
    );
    assert!(
        bad.is_empty(),
        "the manifest reference tabulates a field the parser does not know, so \
         a reader copying it gets a `deny_unknown_fields` failure:\n  {}\n  \
         (checked against {} fields in src/manifest/mod.rs)",
        bad.join("\n  "),
        real.len()
    );
}

/// **The TLS trust anchor is the one this crate says it is.**
///
/// `reqwest`'s feature list carried `webpki-roots` for a while, which reads as
/// *this build pins Mozilla's root bundle* and did nothing of the kind. reqwest
/// 0.13 has no such feature: it declares `webpki-roots` as an **optional
/// dependency** and never writes `dep:webpki-roots` in its own `[features]`, so
/// Cargo synthesises an implicit feature of that name. Enabling it resolves,
/// compiles, and links the whole bundle in — while the actual verifier stays
/// `rustls-platform-verifier`, reading the operating system's store.
///
/// That is the worst shape a dead declaration can take. It is not merely unused:
/// it is a security-relevant belief, and an operator reading the manifest would
/// conclude their trust anchors are pinned and independent of the host when they
/// are neither.
///
/// Checked against the **lock file**, because that is what says which crates a
/// build actually contains — the manifest says what was asked for, and the
/// entire failure here was the gap between the two. Both directions are
/// asserted, so a change that swapped the verifier out is caught as loudly as
/// one that brought the bundle back.
#[test]
fn the_tls_trust_anchor_is_the_platform_verifier_and_not_a_pinned_bundle() {
    let lock = read("Cargo.lock");
    assert!(
        lock.contains("name = \"rustls-platform-verifier\""),
        "the TLS verifier is gone from the lock file: this crate's trust anchor is \
         the operating system's store, deliberately, because the operator already \
         administers a CA policy and a runtime that ignored it would break every \
         corporate inspection proxy while claiming to be safer"
    );
    assert!(
        !lock.contains("name = \"webpki-roots\""),
        "`webpki-roots` is back in the tree. reqwest has no feature of that name — \
         Cargo synthesises one from its optional dependency — so asking for it \
         links Mozilla's whole root bundle into every build and changes the trust \
         anchor not at all. If pinned roots are genuinely wanted, that is \
         `rustls-no-provider` plus an explicit `ClientConfig`, and it is a \
         decision to make on purpose rather than a word in a feature list"
    );
}

/// A published error message is the one the runtime produces.
///
/// The README and the getting-started page both quote the plane's answer to a
/// misspelled capability, because it is the first failure a newcomer meets and
/// the sentence is doing teaching work. Quoting it makes the message a fact
/// maintained in three places, and it drifted in exactly the way §10.6 shape 18
/// predicts: admission moved to `Tainted<Value>`, the `run_trusted` /
/// `run_tainted` pair was deleted for being worse than one door, and both pages
/// went on telling readers that *`run_trusted` takes a capability*. A reader
/// grepping for that method finds nothing at all.
///
/// Nothing in the toolchain could have caught it. Doc tests compile rustdoc
/// under `src/`, never markdown; the `StepCtx` guard reads methods off
/// `impl StepCtx`, and this is a `Runtime` method quoted inside a plain-text
/// block. So this asserts the published lines against the message the code
/// **actually formats**, which is a known answer rather than a second copy —
/// rewording the error fails here instead of in a reader's editor.
#[test]
fn the_published_no_provider_message_is_the_one_the_runtime_writes() {
    let error = agentplane::core::RuntimeError::NoProvider {
        target: "demo.greeet".to_owned(),
        available: vec!["demo.greet".to_owned()],
    };
    let produced = error.to_string();
    assert!(
        produced.contains("demo.greeet") && produced.contains("takes a capability"),
        "this guard is anchored on a message that has changed shape: {produced}"
    );

    // The pages wrap the sentence to fit a code block, so compare on words.
    let normalise = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
    let produced = normalise(&produced);

    for page in ["README.md", "site/content/docs/getting-started.md"] {
        let text = normalise(&read(page));
        assert!(
            text.contains(&produced),
            "{page} publishes an error message the runtime does not write.\n\
             The runtime says:\n  {produced}\n\
             Search the page for `no skill provides capability` and make it match."
        );
    }
}

/// Names two pages describe as **deliberately absent**.
///
/// An unconfigured seam is no control, spelled as absence — so the pages name
/// `Egress::allow_all` in order to say it is not there. Exempting those pages
/// would let real drift hide behind whichever page carried the exemption, so
/// the guard asserts the *absence* instead: adding one of these fails, which is
/// correct, because two documents would then be wrong the other way.
const ABSENT_BY_DESIGN: &[(&str, &str)] = &[
    ("Egress", "allow_all"),
    // Names the **upgrading** page cites because they were removed or renamed.
    // That page is a historical record: its job is to say *this used to be X*,
    // so the old spelling appearing there is correct and the guard asserts the
    // absence rather than exempting the page. Re-adding one of these would make
    // an upgrade note wrong in the other direction, which is why this list
    // fails on resurrection instead of on mention.
    ("McpTaskSnapshot", "ttl_ms"),
    ("PlanNode", "with_quorum"),
    ("Spend", "is_zero"),
    ("Runtime", "halted"),
    ("QuotaStore", "accrue"),
    ("PushSweepReport", "abandoned"),
    ("KeyRing", "rewrap"),
];

/// Types this crate does not own.
///
/// Named rather than pattern-matched: an "anything not in `src/`" rule would
/// silently grow to cover the crate's own types the moment one was renamed.
const FOREIGN_TYPES: &[&str] = &[
    "Span",
    "Duration",
    "Value",
    "String",
    "Vec",
    "Arc",
    "Some",
    "None",
    "Ok",
    "Err",
    "Path",
    "PathBuf",
    "HashMap",
    "BTreeMap",
    "Option",
    "Result",
    "Box",
    "Mutex",
    "RwLock",
    "Instant",
    "SystemTime",
    "OffsetDateTime",
    "Regex",
    "Url",
    "Client",
    "Router",
    "Uuid",
    "Ulid",
    "Cow",
    "Self",
    "Default",
    "From",
    "Into",
    "Iterator",
    "Cedar",
    "Utc",
    "NaiveDate",
];

/// Every public function name this crate declares, inherent or on a trait.
///
/// Name-based on purpose, and the trade decides what the guard can find: it
/// catches an **invented** name and not a real name attached to the wrong type,
/// which needs the compiler. Trait methods carry no `pub` and are collected
/// separately — a public trait's methods are as callable as any inherent one,
/// and `SemanticRetriever::profile` is a documented name that only exists that
/// way.
fn declared_function_names(root: &Path) -> std::collections::BTreeSet<String> {
    fn name_after(prefix: &str, line: &str) -> Option<String> {
        let rest = line.strip_prefix(prefix)?;
        let rest = rest.strip_prefix("async ").unwrap_or(rest);
        let rest = rest.strip_prefix("const ").unwrap_or(rest);
        let rest = rest.strip_prefix("unsafe ").unwrap_or(rest);
        let name: String = rest
            .strip_prefix("fn ")?
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }

    let mut declared = std::collections::BTreeSet::new();
    for file in walk(&root.join("src")) {
        if file.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        for line in std::fs::read_to_string(&file)
            .expect("a readable module")
            .lines()
        {
            let line = line.trim_start();
            if let Some(name) = name_after("pub ", line).or_else(|| name_after("", line)) {
                declared.insert(name);
            }
            // Public fields, consts and enum variants. A page cites
            // `Justification::summary` and `AuditReport::warrants` the same way
            // it cites a method, and a scan that knew only about `fn` would
            // report both as invented the moment the parenthesis rule below
            // stopped hiding them.
            if let Some(rest) = line.strip_prefix("pub ") {
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !field.is_empty() && rest[field.len()..].starts_with(':') {
                    declared.insert(field);
                }
                let konst: String = rest
                    .strip_prefix("const ")
                    .unwrap_or("")
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !konst.is_empty() {
                    declared.insert(konst);
                }
            }
            // An enum variant, wherever the crate names one by path.
            if let Some((_, after)) = line.split_once("::") {
                let variant: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if variant.chars().next().is_some_and(char::is_uppercase) {
                    declared.insert(variant);
                }
            }
        }
    }
    // Names a `derive` or a std trait supplies, which no `fn` line declares.
    for supplied in [
        "default",
        "from",
        "into",
        "try_from",
        "try_into",
        "clone",
        "fmt",
        "eq",
        "cmp",
        "hash",
        "next",
        "deref",
        "drop",
        "to_string",
        "to_owned",
        "as_ref",
        "from_str",
    ] {
        declared.insert(supplied.to_owned());
    }
    declared
}

/// Every `Type::associated_fn` a page publishes exists on that type.
///
/// The `StepCtx` guard covers the surface a newcomer programs against, and it
/// covers **only** `StepCtx` — so a constructor on any other public type could
/// be invented in prose and nothing would look. One was: the concepts page
/// taught obligations with `DeadlineSpec::working_days(1)`, which does not
/// exist and never has. The type has three constructors and none of them is
/// that, so the first line of the deadline example a reader copies did not
/// compile — and the comment above it said *five working days* while the call
/// said one, which is the tell that nobody had run it.
///
/// The check is name-based rather than type-resolved, and the trade is stated
/// because it decides what this can and cannot find. It collects every
/// `pub fn`/`pub const fn` name declared anywhere in `src/` and refuses a
/// documented `Type::name` whose `name` is not among them. So it catches an
/// **invented** name, and it does not catch a real name attached to the wrong
/// type — resolving that needs the compiler, which for markdown means building
/// every snippet, which the doc-example harness does for the ones that carry
/// their own imports.
///
/// Std and dependency paths are skipped by an allowlist rather than by
/// guessing, because `Duration::from_secs` and `Value::String` are not this
/// crate's to declare and a guard that flagged them would be turned off.
#[test]
fn every_documented_associated_function_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let declared = declared_function_names(root);
    assert!(
        declared.len() > 200,
        "only {} public functions were found — the scan is now inert",
        declared.len()
    );

    for (ty, name) in ABSENT_BY_DESIGN {
        assert!(
            !declared.contains(*name),
            "`{ty}::{name}` now exists, and two pages tell readers it deliberately \
             does not. Fix the pages, then remove this row"
        );
    }

    let mut pages: Vec<std::path::PathBuf> = walk(&root.join("site/content/docs"))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    pages.push(root.join("README.md"));
    assert!(
        pages.len() > 5,
        "only {} pages were scanned — the site layout moved",
        pages.len()
    );

    let mut missing: Vec<String> = Vec::new();
    for page in &pages {
        let text = std::fs::read_to_string(page).expect("a readable page");
        let rel = page.strip_prefix(root).unwrap_or(page).display();
        for (number, line) in text.lines().enumerate() {
            let bytes: Vec<char> = line.chars().collect();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == ':' && i + 1 < bytes.len() && bytes[i + 1] == ':' {
                    // Walk back over the type name and forward over the member.
                    let start = bytes[..i]
                        .iter()
                        .rposition(|c| !(c.is_alphanumeric() || *c == '_'))
                        .map_or(0, |p| p + 1);
                    let ty: String = bytes[start..i].iter().collect();
                    let mut j = i + 2;
                    while j < bytes.len() && (bytes[j].is_alphanumeric() || bytes[j] == '_') {
                        j += 1;
                    }
                    let member: String = bytes[i + 2..j].iter().collect();
                    let is_type = ty.chars().next().is_some_and(char::is_uppercase);
                    let is_fn = member.chars().next().is_some_and(char::is_lowercase);
                    // **No parenthesis requirement.** It used to be one, and it
                    // was the blind spot: these pages cite a member as
                    // `BlobStore::expire` far more often than as a call, so the
                    // rule checked the minority spelling and let an invented
                    // name through in the majority one.
                    if is_type
                        && is_fn
                        && !FOREIGN_TYPES.contains(&ty.as_str())
                        && !ABSENT_BY_DESIGN.contains(&(ty.as_str(), member.as_str()))
                        && !declared.contains(&member)
                    {
                        missing.push(format!("{rel}:{}: {ty}::{member}", number + 1));
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these pages call associated functions this crate does not declare — a \
         reader copying the line gets a compile error, and nothing else in the \
         toolchain reads markdown:\n{}",
        missing.join("\n")
    );
}

/// **The figures the landing page offers as proof are the tree's own.**
///
/// The section is headed *"Why you should believe any of it"*, and it was the
/// one part of this site nothing checked: it read 6 / 18 / 106 against a tree
/// holding 7 / 26 / 644 — the code-mutation count off by six times. A claim
/// about falsifiability that nothing falsifies is the shape this project
/// catalogues, arriving on the page that exists to argue against it.
///
/// Counted from the artifacts rather than restated, so adding a spec or a
/// mutation moves the page or fails the build.
#[test]
fn the_landing_pages_proof_figures_are_the_real_ones() {
    let page = read("site/templates/index.html");

    // `<div><dt>N</dt><dd>label…` — the figure and enough of the label to say
    // which claim a mismatch is about.
    let stated = |needle: &str| -> u64 {
        let at = page
            .find(needle)
            .unwrap_or_else(|| panic!("the landing page no longer claims '{needle}'"));
        let before = &page[..at];
        let open = before
            .rfind("<dt>")
            .unwrap_or_else(|| panic!("no <dt> precedes '{needle}'"));
        let close = before[open..]
            .find("</dt>")
            .unwrap_or_else(|| panic!("unterminated <dt> before '{needle}'"));
        before[open + 4..open + close]
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("the figure before '{needle}' is not a number: {e}"))
    };

    let tla = std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("spec"))
        .expect("read spec/")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "tla"))
        .count() as u64;

    // One table entry per line, `    "Name": (` — the same shape both tables use
    // and the same one `mutants.py --check` walks.
    // Bounded to the mutation table itself. The file also holds the map from
    // each invariant to the rows that pin it, whose entries are the same shape
    // — and counting those as mutations overstated the figure by fourteen on
    // the one page arguing the project does not overstate.
    let rows = |table: &str| -> u64 {
        let text = read(table);
        let text = text
            .split_once("= {\n")
            .map_or(text.as_str(), |(_, rest)| rest);
        let text = text.split_once("\n}\n").map_or(text, |(first, _)| first);
        text.lines()
            .filter(|l| {
                let t = l.trim_start();
                l.starts_with("    \"")
                    && t.ends_with("\": (")
                    && t.trim_start_matches('"')
                        .chars()
                        .next()
                        .is_some_and(char::is_alphanumeric)
            })
            .count() as u64
    };

    for (claim, stated, actual) in [
        ("TLA+ specifications", stated("TLA+ specifications"), tla),
        (
            "deliberately broken specs",
            stated("deliberately broken specs"),
            rows("spec/mutations.py"),
        ),
        (
            "code mutations",
            stated("code mutations"),
            rows("tools/mutants.py"),
        ),
    ] {
        assert_eq!(
            stated, actual,
            "the landing page offers '{claim}' as evidence and says {stated}, \
             but this tree holds {actual} — the page arguing that every \
             guarantee is falsifiable is itself out of date"
        );
    }

    // The one figure that is a property rather than a count.
    assert_eq!(stated("unsafe blocks"), 0);
    assert!(
        read("Cargo.toml").contains("unsafe_code = \"forbid\""),
        "the page claims `forbid(unsafe_code)` and the manifest does not set it"
    );
}

/// **Every specification the tree holds is named where the README lists them.**
///
/// The list read "effect protocol, retry safety, sagas, fencing, authorization,
/// delegation" while `spec/` held a seventh, `EffectGroup` — the one covering
/// the transactional tier, which is the hardest thing here to believe without
/// a proof and therefore the one worth naming. A hand-maintained list of files
/// drifts in exactly this direction: adding the spec is deliberate, remembering
/// the sentence is not.
#[test]
fn the_readme_names_every_specification_the_tree_holds() {
    let readme = read("README.md").to_lowercase();
    for entry in std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("spec"))
        .expect("read spec/")
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "tla") {
            continue;
        }
        let stem = path
            .file_stem()
            .expect("a named spec")
            .to_string_lossy()
            .to_string();
        // `EffectGroup` → ["effect", "group"], each of which must appear — the
        // README writes them as prose ("effect groups", "sagas"), so the check
        // is on the words rather than on the file name.
        let words: Vec<String> = stem.chars().fold(Vec::<String>::new(), |mut acc, c| {
            if c.is_uppercase() || acc.is_empty() {
                acc.push(String::new());
            }
            acc.last_mut()
                .expect("just pushed")
                .push(c.to_ascii_lowercase());
            acc
        });
        for word in &words {
            assert!(
                readme.contains(word.as_str()),
                "spec/{stem}.tla is model-checked on every push and the README's \
                 list of specifications never says '{word}' — a reader deciding \
                 whether to trust this project is shown a shorter list than the \
                 one CI runs"
            );
        }
    }
}

/// **Every event the runtime promises is named on the operations page.**
///
/// The table is headed *"Every failure P7 exists to surface has its own event
/// target"*, and it listed ten of the fourteen in `telemetry::LOUD_EVENTS`. The
/// four it omitted were `run.unreproducible`, `run.recovered`, `run.replanned`
/// and `policy.denied` — an integrity finding, a takeover, a plan change and
/// every policy refusal.
///
/// A table headed *every* is an alerting checklist. An operator builds their
/// dashboard from it once and never returns, so a short list is not a smaller
/// table — it is four signals nobody is watching, and the page says they are
/// all there.
#[test]
fn the_operations_page_names_every_event_the_runtime_promises() {
    let page = read("site/content/docs/operations.md");
    let telemetry = read("src/runtime/telemetry.rs");

    // The constants named by `LOUD_EVENTS`, resolved to their string values.
    let list = telemetry
        .split("pub const LOUD_EVENTS")
        .nth(1)
        .expect("telemetry declares LOUD_EVENTS")
        .split("];")
        .next()
        .expect("LOUD_EVENTS is terminated");

    let mut checked = 0;
    for ident in list
        .lines()
        .map(|l| l.trim().trim_end_matches(','))
        .filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
    {
        let decl = format!("pub const {ident}: &str = \"");
        let target = telemetry
            .split(&decl)
            .nth(1)
            .unwrap_or_else(|| panic!("LOUD_EVENTS names {ident}, which is not declared"))
            .split('"')
            .next()
            .expect("a terminated string");
        assert!(
            page.contains(&format!("`{target}`")),
            "the runtime promises the event `{target}` and the operations page's \
             table of *every* event does not name it — an operator building \
             alerts from that table is not watching it"
        );
        checked += 1;
    }
    assert!(
        checked >= 14,
        "only {checked} events were checked; the LOUD_EVENTS parse found too few \
         to be reading the real list"
    );
}

/// **Every documentation page is linked from the README.**
///
/// The README's table is how most readers reach the site at all, and a page
/// absent from it is a page nobody arrives at — which is the same outcome as
/// not having written it. Splitting one long page into six made the risk
/// concrete: the table named the page that was split and none of the pages it
/// became.
///
/// Checked in the direction that matters. A README link to a page that does not
/// exist is caught by the site build; a page the README never mentions is
/// caught by nothing else.
#[test]
fn the_readme_links_every_documentation_page() {
    let readme = read("README.md");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("site/content/docs");
    for entry in std::fs::read_dir(&root)
        .expect("read site/content/docs")
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "md") {
            continue;
        }
        let stem = path
            .file_stem()
            .expect("a named page")
            .to_string_lossy()
            .to_string();
        if stem == "_index" {
            continue;
        }
        assert!(
            readme.contains(&format!("/docs/{stem}/")),
            "site/content/docs/{stem}.md is published and the README's table of \
             documentation never links it — a page no reader is routed to"
        );
    }
}

/// **Every published page belongs to a navigation group somebody declared.**
///
/// The sidebar and the documentation hub are built by walking
/// `config.extra.doc_groups` and printing the pages that name each one. A page
/// whose `extra.group` is missing, or is a group not on that list, is rendered
/// by neither — it stays published, indexed and reachable by URL, and vanishes
/// from every route a reader actually takes.
///
/// That is the failure mode of *any* grouped navigation, and it is silent: the
/// page builds, the link checker is happy, and the only symptom is nobody
/// arriving.
#[test]
fn every_documentation_page_is_in_the_navigation() {
    let config = read("site/config.toml");
    let groups: Vec<String> = config
        .lines()
        .find_map(|l| l.strip_prefix("doc_groups = ["))
        .expect("site/config.toml declares doc_groups")
        .trim_end_matches(']')
        .split(',')
        .map(|g| g.trim().trim_matches('"').to_owned())
        .collect();
    assert!(groups.len() > 2, "got {groups:?}");

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("site/content/docs");
    let mut pages = 0usize;
    for path in std::fs::read_dir(&root)
        .expect("read site/content/docs")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
    {
        let stem = path.file_stem().expect("a named page").to_string_lossy();
        if stem == "_index" {
            continue;
        }
        pages += 1;
        let text = std::fs::read_to_string(&path).expect("a page");
        let declared = text
            .lines()
            .find_map(|l| l.strip_prefix("group = "))
            .map(|g| g.trim().trim_matches('"').to_owned());
        let Some(group) = declared else {
            panic!(
                "site/content/docs/{stem}.md declares no `extra.group`, so it appears in \
                 neither the sidebar nor the documentation hub — published and unreachable \
                 by every route a reader takes"
            );
        };
        assert!(
            groups.contains(&group),
            "site/content/docs/{stem}.md is in group '{group}', which \
             `config.extra.doc_groups` does not list ({groups:?}) — the page renders in \
             no navigation at all"
        );
    }
    assert!(pages > 10, "found only {pages} pages — wrong tree");
}

/// **Every recipe the pipeline invokes is one the local gate runs.**
///
/// `CONTRIBUTING.md` promises that `just ci` is what CI runs, "so a check
/// cannot drift between your machine and the pipeline". That promise has been
/// false twice, and both times the symptom was a green local gate and a red
/// pipeline: once for `site-check`, once for the per-seam test jobs, where a
/// list built under a `#[cfg]` left an unused `mut` visible only to the one
/// feature combination `just ci` never compiled.
///
/// The failure is structural rather than careless. A workflow gains a job by
/// editing YAML; the local gate gains a step by editing a justfile; nothing
/// holds the two together, and the drift is invisible until a push.
///
/// Exemptions are named here with a reason, because a recipe that needs a
/// container must not make the local gate depend on a daemon — but the *set* of
/// such recipes is a decision, not a default.
#[test]
fn every_recipe_ci_runs_is_in_the_local_gate() {
    /// Recipes the pipeline runs that `just ci` deliberately does not.
    const OWN_JOB: &[(&str, &str)] = &[
        ("ci", "the gate itself"),
        ("ci-full", "the gate plus the two slow layers"),
        (
            "mutants",
            "its own job: it rebuilds the library once per mutation",
        ),
        (
            "specs",
            "its own job: TLA+ model checking, minutes per spec",
        ),
        ("test-postgres", "needs a PostgreSQL container"),
        ("test-vault", "needs a Vault container"),
    ];

    let justfile = read("justfile");
    let gate: Vec<&str> = justfile
        .lines()
        .find_map(|l| l.strip_prefix("ci: "))
        .expect("the justfile declares a `ci` recipe")
        .split_whitespace()
        .collect();
    assert!(gate.len() > 5, "got {gate:?}");

    // Everything `ci` reaches, including one level of composition — `seams`
    // exists precisely to name four recipes at once.
    let mut reached: Vec<String> = gate.iter().map(|s| (*s).to_owned()).collect();
    for step in &gate {
        if let Some(deps) = justfile
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{step}: ")))
        {
            reached.extend(deps.split_whitespace().map(ToOwned::to_owned));
        }
    }

    let workflows = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut missing = Vec::new();
    let mut invoked = 0usize;
    for entry in std::fs::read_dir(&workflows)
        .expect("read .github/workflows")
        .filter_map(Result::ok)
    {
        let file = entry.file_name().to_string_lossy().to_string();
        let yaml = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in yaml.lines() {
            let Some(rest) = line.split("just ").nth(1) else {
                continue;
            };
            let stem: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            if stem.is_empty() {
                continue;
            }
            // `just test-${{ matrix.seam }}` is five recipes, and taking the
            // literal prefix as one name checks none of them — which is how the
            // first version of this test passed while the seams were missing
            // from the gate. The matrix is expanded from its own declaration.
            for recipe in expand_matrix(&yaml, &stem, rest) {
                invoked += 1;
                if !reached.contains(&recipe) && !OWN_JOB.iter().any(|(name, _)| *name == recipe) {
                    missing.push(format!("{file}: just {recipe}"));
                }
            }
        }
    }
    assert!(
        invoked > 6,
        "found only {invoked} recipe invocations across the workflows — the matrix \
         is not being expanded, and a guard that checks nothing passes"
    );
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "the pipeline runs these and `just ci` does not, so they fail after a push \
         rather than before one — add them to the gate, or to this test's exemption \
         list with the reason they cannot be:\n  {}",
        missing.join("\n  ")
    );
}

/// A workflow step that runs a tool directly is held to the gate too.
///
/// The half above reads `just <recipe>` lines, so a step that invokes a tool
/// itself is invisible to it — and that is the shape the divergence took: the
/// Pages workflow ran `zola check` while the local recipe ran `zola check
/// --skip-external-links`, so the gate deliberately skipped the one check that
/// failed. A control that inspects one spelling of a CI step leaves the other
/// spelling unguarded, which is worse than no control, because the survey
/// sentence reads as complete.
///
/// Verification workflows only. `release.yml` publishes rather than checks, and
/// its steps cannot have a local equivalent by construction.
#[test]
fn every_command_ci_runs_itself_is_one_the_gate_runs() {
    /// Steps that legitimately have no local twin, with the reason.
    const NOT_LOCAL: &[(&str, &str)] = &[(
        "cargo check --all-features",
        "the MSRV job, which pins a toolchain the local gate does not install",
    )];

    // Whole commands, never substrings. `contains` would let the weaker
    // `zola check --skip-external-links` satisfy a CI step running `zola
    // check` — the exact divergence this exists to catch, admitted by the
    // matching rule rather than by the justfile.
    let justfile = read("justfile");
    let recipe_commands: Vec<String> = justfile
        .lines()
        .filter(|l| l.starts_with(char::is_whitespace))
        .flat_map(|l| l.split("&&"))
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty())
        .collect();

    let workflows = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut missing = Vec::new();
    let mut checked = 0usize;

    for entry in std::fs::read_dir(&workflows)
        .expect("read .github/workflows")
        .filter_map(Result::ok)
    {
        let file = entry.file_name().to_string_lossy().to_string();
        if file.starts_with("release") {
            continue;
        }
        let yaml = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in yaml.lines() {
            let Some(command) = line.trim().strip_prefix("- run: ") else {
                continue;
            };
            let command = command.trim();
            if command.contains("just ") {
                continue; // the other half of this pair reads those
            }
            checked += 1;
            // Every command the step chains, so `a && b` is two claims.
            for part in command.split("&&").map(str::trim) {
                if part.is_empty()
                    || NOT_LOCAL.iter().any(|(exempt, _)| *exempt == part)
                    || recipe_commands.iter().any(|c| c == part)
                {
                    continue;
                }
                missing.push(format!("{file}: {part}"));
            }
        }
    }

    assert!(
        checked > 0,
        "no raw run step was found at all — the guard is reading nothing rather \
         than passing"
    );
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "the pipeline runs these itself and no recipe does, so they fail after a \
         push rather than before one — give them a recipe the gate reaches, or \
         name them in this test's exemption list:\n  {}",
        missing.join("\n  ")
    );
}

/// One workflow invocation, as the set of recipes it actually runs.
///
/// A plain name is itself. `test-${{ matrix.seam }}` is one recipe per entry in
/// the job's `seam:` list, read from the same file rather than restated here —
/// a list in two places is the drift this whole test exists to catch.
fn expand_matrix(yaml: &str, stem: &str, rest: &str) -> Vec<String> {
    let Some(var) = rest
        .split("matrix.")
        .nth(1)
        .map(|v| {
            v.chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect::<String>()
        })
        .filter(|v| !v.is_empty())
    else {
        return vec![stem.to_owned()];
    };
    let Some(values) = yaml
        .lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{var}: [")))
        .and_then(|l| l.split(']').next())
    else {
        panic!("a workflow expands `matrix.{var}` and no `{var}: [...]` declares it");
    };
    values
        .split(',')
        .map(|v| format!("{stem}{}", v.trim()))
        .collect()
}

/// **A heading with an emoji in it names its own anchor.**
///
/// Zola slugifies an emoji to its Unicode name, so `## 🎲 Disposition` becomes
/// `#5-game-die-disposition` and `## 📤 Emit an event` becomes
/// `#outbox-tray-emit-an-event`. Three consequences, and the third is what
/// makes this a guard rather than a preference:
///
/// * The URL a reader copies out of the address bar reads as broken.
/// * A search engine shows anchor links as jump-to targets, so the nonsense is
///   what a result page displays.
/// * **It is not stable.** The id changes if the emoji changes, if the emoji is
///   dropped, or if Zola's table is updated — and three hand-written links in
///   this repository already pointed at anchors that had moved out from under
///   them, which is how this was found.
///
/// The fix is one the author sees while writing: give the heading an explicit
/// `{#id}`. The emoji stays; only the anchor stops being derived from it.
#[test]
fn every_emoji_heading_names_its_own_anchor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("site/content");
    let mut derived = Vec::new();
    let mut checked = 0usize;

    for path in walk_markdown(&root) {
        let text = std::fs::read_to_string(&path).expect("a page");
        for (n, line) in text.lines().enumerate() {
            let Some(rest) = line.strip_prefix("##") else {
                continue;
            };
            checked += 1;
            // Anything outside the Basic Multilingual Plane, plus the ranges
            // that carry the symbols and dingbats a heading actually uses.
            let has_emoji = rest.chars().any(|c| {
                matches!(c, '\u{2190}'..='\u{27bf}' | '\u{2b00}'..='\u{2bff}' | '\u{fe0f}')
                    || c as u32 >= 0x1_f000
            });
            if has_emoji && !line.contains("{#") {
                derived.push(format!("{}:{}  {}", path.display(), n + 1, line.trim()));
            }
        }
    }

    assert!(
        checked > 100,
        "found only {checked} headings — the guard is reading the wrong tree \
         rather than passing"
    );
    assert!(
        derived.is_empty(),
        "these headings let Zola name their anchor from an emoji, which produces \
         an unguessable id that changes when the emoji does:\n  {}",
        derived.join("\n  ")
    );
}

/// Every markdown page under a directory, recursively.
fn walk_markdown(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_markdown(&path));
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
    out
}

/// **The changelog uses the vocabulary it says it uses, and ships nothing it
/// does not carry.**
///
/// `CHANGELOG.md` is in the crate's `include` list, so it travels to crates.io
/// and docs.rs. Two things drifted there because nothing looked:
///
/// It accumulated **seven** ad-hoc entry categories beside the standard ones —
/// `Audited`, `Audit notes`, `Audited clean`, `Assurance`, `Testing`,
/// `Research`, `Known` — four of which were one idea under four names, in a
/// project whose worst-named defect is a rule with two spellings.
///
/// And it cited internal design documents by section (`CONCEPT §6.3`, `§9.1`)
/// nineteen times. Those files are deliberately not packaged, so a reader on
/// docs.rs followed a reference to something they were never sent. The docs
/// guard that forbids internal section numbers everywhere else exempts this
/// file, which is precisely why they survived here and nowhere else.
#[test]
fn the_changelog_ships_only_what_the_reader_receives() {
    // The four standard categories this file uses, plus the two it documents.
    const ALLOWED: &[&str] = &[
        "Added",
        "Changed",
        "Deprecated",
        "Removed",
        "Fixed",
        "Security",
        "Assurance",
        "Known",
    ];

    let log = read("CHANGELOG.md");
    for line in log.lines().filter(|l| l.starts_with("### ")) {
        let category = line[4..].split(" — ").next().unwrap_or("").trim();
        assert!(
            ALLOWED.contains(&category),
            "CHANGELOG.md uses the category '{category}', which the preamble does \
             not declare — an eighth spelling is how one idea ends up under four \
             names"
        );
    }

    // An internal section reference, as distinct from a cited external one:
    // `RFC 9110 §11.1` names a document the reader can fetch; a bare `§9.1`
    // names one this crate does not ship.
    for (n, line) in log.lines().enumerate() {
        assert!(
            !line.contains("CONCEPT"),
            "CHANGELOG.md:{} cites an internal design document, and this file \
             ships inside the crate: {line}",
            n + 1
        );
        if let Some(at) = line.find('§') {
            let cited_source = line[..at].contains("RFC") || line[..at].contains("specification");
            assert!(
                cited_source,
                "CHANGELOG.md:{} cites a section of a document the reader was not \
                 sent: {line}",
                n + 1
            );
        }
    }

    assert!(
        !log.contains("arxiv.org"),
        "CHANGELOG.md cites a paper. Research is how a design got decided, not \
         what a release changed — and the preamble says so."
    );
}

/// The record vocabulary, read out of the enum that defines it.
///
/// Two guards need this list and they must not each parse it: a second parser
/// that reads a slightly different span agrees with the first until the day the
/// enum moves, and then one of them reports on a vocabulary nobody has.
fn record_kinds() -> Vec<String> {
    let source = read("src/journal/record.rs");
    let start = source
        .find("pub enum RecordKind {")
        .expect("the RecordKind enum");
    let end = source[start..].find("\n}\n").expect("end of enum") + start;
    let kinds: Vec<String> = source[start..end]
        .lines()
        .filter_map(|line| {
            let code = line.strip_prefix("    ")?;
            let ident: String = code
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!ident.is_empty() && ident.starts_with(char::is_uppercase)).then_some(ident)
        })
        .collect();
    assert!(
        kinds.len() > 20,
        "found {kinds:?} — the guard is reading the wrong span rather than passing"
    );
    kinds
}

/// The published format specification names every record kind that exists.
///
/// The one document an outside implementation reads. A kind missing from it is
/// a record a second implementation will meet and have no rule for — and the
/// failure is silent on this side, because every test here is written against
/// the vocabulary this build already has.
///
/// The constants are checked in the same pass: a specification that states the
/// wrong domain string, prefix byte or ceiling is worse than one that omits
/// them, because a reader implements what it says and gets signatures that
/// verify against nothing.
#[test]
fn the_format_specification_is_in_step_with_the_code() {
    let spec = read("site/content/docs/format.md");

    let kinds = record_kinds();
    for kind in &kinds {
        assert!(
            spec.contains(&format!("`{kind}`")),
            "`{kind}` is a record kind and the published format specification never \
             names it — a second implementation meets a record it has no rule for"
        );
    }

    // Values a reader implements verbatim. Each is quoted from the code it
    // must agree with, so a change to either side fails here rather than in
    // somebody else's verifier.
    for (what, needle) in [
        (
            "the record signing domain",
            agentplane::core::DOMAIN_RECORD.to_owned(),
        ),
        (
            "the record size ceiling",
            format!(
                "{} MiB",
                agentplane::journal::Record::MAX_RECORD_BYTES / (1 << 20)
            ),
        ),
        (
            "the canonicalization version",
            format!("`canon` version **{}**", agentplane::core::canon::VERSION),
        ),
        (
            "the export format version",
            format!("\"version\":{}", agentplane::export::FORMAT_VERSION),
        ),
    ] {
        assert!(
            spec.contains(&needle),
            "the format specification does not state {what} as the code has it ({needle:?})"
        );
    }
}

/// Every published count of the record vocabulary is the count the tree holds.
///
/// The guard above checks *which* kinds a page names. This one checks *how
/// many*, and the two rot separately: adding a kind is a deliberate edit to the
/// enum, the corpus and the specification's list, while the sentence on three
/// other pages saying how many vectors a second implementation re-derives is
/// nobody's edit. It was wrong by two for a release — a guard that checks
/// membership passing while the sentence the list is published under is false.
///
/// Two phrasings are held, and they are the two that state a *derived total*:
/// `N record vectors` is the golden corpus, and `There are N record kinds` is
/// the vocabulary. A page counting a handful of new kinds (`Two record kinds
/// arrived with it`) is a different claim and is deliberately not matched. What
/// this does not cover is a fourth phrasing invented later; the answer to that
/// is to add it here, not to widen the match until ordinary prose trips it.
#[test]
fn every_published_record_count_is_the_one_the_tree_holds() {
    let kinds = record_kinds();
    let corpus = read("tests/golden/records.jsonl");
    let vectors = corpus.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        vectors,
        kinds.len(),
        "the golden corpus holds {vectors} vectors for {} record kinds — the          published counts are checked against the corpus, so the two must agree          before either can be published",
        kinds.len()
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut pages: Vec<std::path::PathBuf> = walk(&root.join("site/content/docs"))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .collect();
    pages.push(root.join("README.md"));
    assert!(
        pages.len() > 5,
        "only {} pages were scanned — the site layout moved",
        pages.len()
    );

    let mut found = 0usize;
    for page in &pages {
        let text = read(page.strip_prefix(root).unwrap_or(page).to_str().unwrap());
        for (claim, suffix, expected) in [
            ("", " record vectors", vectors),
            ("There are ", " record kinds", kinds.len()),
        ] {
            for (idx, _) in text.match_indices(suffix) {
                let head = &text[..idx];
                let digits: String = head
                    .chars()
                    .rev()
                    .take_while(char::is_ascii_digit)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if digits.is_empty() {
                    continue;
                }
                let before = &head[..head.len() - digits.len()];
                if !claim.is_empty() && !before.ends_with(claim) {
                    continue;
                }
                let stated: usize = digits.parse().expect("a run of ASCII digits");
                assert_eq!(
                    stated,
                    expected,
                    "{}: the page says {stated}{suffix} and the tree holds {expected}",
                    page.display()
                );
                found += 1;
            }
        }
    }
    assert!(
        found >= 3,
        "found {found} published counts — this guard read nothing and passed, \
         which is the shape it exists to catch"
    );
}

/// The second implementation is in the gate, and independent of the first.
///
/// Two properties, and the second is what makes it evidence. A verifier
/// nothing runs is a file; and a verifier that consults this crate's source to
/// decide what a rule means has stopped being a second reader of the
/// specification and become a paraphrase of the implementation — at which
/// point it agrees with the first one by construction and catches nothing.
#[test]
fn the_second_implementation_is_run_and_stays_independent() {
    let verifier = read("tools/verify_export.py");
    let justfile = read("justfile");

    let chain = justfile
        .lines()
        .find(|line| line.starts_with("ci:"))
        .expect("the ci recipe");
    assert!(
        chain.contains("verify-golden"),
        "`verify-golden` is not in the local gate's chain, so the only reader of the \
         format specification that is not this crate runs nowhere"
    );

    for check in ["--canon-check", "--self-test"] {
        assert!(
            justfile.contains(check),
            "the gate never passes {check}, so part of what the second implementation \
             proves is not being asked for: `--canon-check` is the half that *produces* \
             bytes rather than accepting them, and `--self-test` is the half that proves \
             this reader can still fail"
        );
    }

    // Independence, mechanically: the whole point is that it derives the format
    // from the published prose. A path into `src/` would make it a paraphrase.
    for borrowed in ["src/", "agentplane::", "cargo ", "target/"] {
        assert!(
            !verifier.contains(borrowed),
            "tools/verify_export.py mentions {borrowed:?} — a verifier that reads this \
             crate is not a second implementation of the specification, it is a copy \
             of the first one"
        );
    }
}

/// **The changelog's newest entry is this version, and a released version is
/// not still "unreleased".**
///
/// Two ways this drifts, and both happened. A section headed `unreleased` stays
/// headed that way after the tag is cut, so the next round's entries land in a
/// version somebody already depends on — the one document written for a reader
/// who has pinned a version, describing changes that are not in it. And
/// `Cargo.toml` moves without the changelog gaining a section, or the reverse,
/// so the top of the file names a version that was never published.
///
/// The tag is the authority on *released*: it is what a reader can check out.
/// Skipped rather than failed where git cannot answer — a packaged crate has no
/// repository, and a red suite for a missing tool teaches people to ignore red
/// suites.
#[test]
fn the_changelog_top_entry_is_this_version_and_released_ones_are_dated() {
    let log = read("CHANGELOG.md");
    let version = env!("CARGO_PKG_VERSION");

    let headings: Vec<&str> = log.lines().filter(|l| l.starts_with("## [")).collect();
    assert!(
        headings.len() > 5,
        "only {} version headings were found — the changelog's format changed and \
         this guard is now inert",
        headings.len()
    );

    // **One section per kind per release.** Keep a Changelog's sections are a
    // reader's index: two `### Security` blocks under one version means the
    // entries a deployment must act on are split across a page, and the second
    // block is the one nobody scrolls to. Easy to introduce by adding a section
    // that already exists further down, and invisible in review.
    let mut version_starts: Vec<usize> =
        log.match_indices("\n## [").map(|(at, _)| at + 1).collect();
    version_starts.push(log.len());
    for pair in version_starts.windows(2) {
        let section = &log[pair[0]..pair[1]];
        let name = section.lines().next().unwrap_or_default();
        let mut kinds: Vec<&str> = section
            .lines()
            .filter_map(|l| l.strip_prefix("### "))
            .collect();
        let total = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            kinds.len(),
            total,
            "{name} repeats a section heading — a reader's index for that release \
             is split, and the half nobody scrolls to is the half they miss"
        );
    }

    let top = headings[0];
    assert!(
        top.contains(&format!("[{version}]")),
        "the changelog's newest entry is {top:?} but this crate is {version} — \
         either the bump did not reach the changelog or the changelog names a \
         version that was never published"
    );

    let Ok(tags) = std::process::Command::new("git")
        .args(["tag", "--list"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
    else {
        return; // No git: nothing to check released-ness against.
    };
    if !tags.status.success() {
        return;
    }
    let tags = String::from_utf8_lossy(&tags.stdout);
    let tagged: Vec<&str> = tags.lines().map(str::trim).collect();

    assert!(
        !tagged.iter().any(|t| *t == format!("v{version}")),
        "v{version} is tagged, so it is released, and `Cargo.toml` still says \
         {version} — the next change would be written into a version somebody \
         already depends on. Bump first."
    );
    for heading in &headings {
        if !heading.contains("unreleased") {
            continue;
        }
        let named = heading
            .split_once('[')
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(v, _)| v)
            .unwrap_or_default();
        assert!(
            !tagged.iter().any(|t| *t == format!("v{named}")),
            "the changelog calls {named} unreleased and v{named} is tagged — a \
             reader who pinned it is being told about changes it does not contain"
        );
    }
}

/// **A documented `agentplane` command line actually parses.**
///
/// The recovery drill is the block an operator copies during an incident, and a
/// flag that does not exist fails there rather than in review. Every command in
/// it had drifted — a positional documented as `--file`, `--anchor` for what is
/// spelled `--checkpoint`, an `--out` that was never a flag — while the same
/// page spelled `export` correctly two hundred lines earlier.
///
/// Read out of the source rather than by running the binary, for the reason
/// the route walk is: a test that shells out is a test that is skipped wherever
/// the binary is not built.
///
/// `upgrading.md` is exempt. Showing the old spelling beside the new one is
/// that page's whole content.
/// One `clap::Args` struct's long flags, including the renamed ones and **the
/// ones it flattens**.
///
/// A `#[command(flatten)]` field contributes the flags of the struct it names
/// and no flag of its own, which is what clap does. Modelling it as a flag named
/// after the field would report every page documenting `--store` as wrong the
/// day a shared `StoreRef` replaced nine hand-written copies of it — and the
/// cheapest way to silence that is to delete the flatten, which fixes nothing.
///
/// Lives beside the test rather than inside it because the recursion needs a
/// name, and because the test was over its line budget with it nested.
fn flags_of(cli: &str, ty: &str, depth: usize) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    // Args structs do not nest deeply; the bound means a cycle in the source
    // cannot hang the suite.
    if depth > 4 {
        return out;
    }
    let Some(at) = cli.find(&format!("struct {ty} {{")) else {
        return out;
    };
    let body = &cli[at..];
    let end = body.find("\n}").map_or(body.len(), |e| e + 2);
    let body = &body[..end];
    let mut renamed = None;
    let mut flattening = false;
    for line in body.lines().map(str::trim) {
        if line.starts_with("#[command(flatten)]") {
            flattening = true;
            continue;
        }
        if line.starts_with("#[arg(") {
            renamed = line
                .split("long = \"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .map(str::to_owned);
            if line.contains("long") {
                continue;
            }
        }
        if let Some((field, rest)) = line.split_once(':')
            && !field.starts_with("//")
            && !field.starts_with('#')
            && field.chars().all(|c| c.is_alphanumeric() || c == '_')
            && !field.is_empty()
        {
            if flattening {
                flattening = false;
                out.extend(flags_of(
                    cli,
                    rest.trim().trim_end_matches(',').trim(),
                    depth + 1,
                ));
                continue;
            }
            let name = renamed.take().unwrap_or_else(|| kebab_field(field));
            out.insert(format!("--{name}"));
        }
    }
    out.insert("--help".to_owned());
    out
}

#[test]
fn every_documented_command_line_uses_flags_the_cli_has() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cli = std::fs::read_to_string(root.join("src/bin/agentplane.rs")).expect("the cli");

    // `Verb::Retain(RetainArgs)` → which struct carries a verb's flags.
    let mut verb_args: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for line in cli.lines().map(str::trim) {
        if let Some((name, rest)) = line.split_once('(') {
            let name = name.trim();
            let ty = rest
                .trim_end_matches("),")
                .replace("Box<", "")
                .replace('>', "");
            if !name.is_empty()
                && name.chars().next().is_some_and(char::is_uppercase)
                && name.chars().all(char::is_alphanumeric)
                && ty.ends_with("Args")
            {
                verb_args.insert(kebab(name), ty);
            }
        }
    }
    assert!(
        verb_args.len() > 8,
        "only {} verbs were parsed out of the CLI — its shape moved and this \
         guard is now inert",
        verb_args.len()
    );

    let mut pages: Vec<std::path::PathBuf> = walk(&root.join("site/content/docs"))
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "md") && !p.ends_with("upgrading.md"))
        .collect();
    pages.push(root.join("README.md"));

    let mut missing = Vec::new();
    for page in &pages {
        let text = std::fs::read_to_string(page).expect("a readable page");
        // Shell continuations, so a multi-line invocation is read whole.
        let joined = text.replace("\\\n", " ");
        let rel = page.strip_prefix(root).unwrap_or(page).display();
        for (number, line) in joined.lines().enumerate() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("agentplane ") else {
                continue;
            };
            let Some(verb) = rest.split_whitespace().next() else {
                continue;
            };
            let Some(ty) = verb_args.get(verb) else {
                continue; // prose, or a verb that takes no flags
            };
            let have = flags_of(&cli, ty, 0);
            // Inline `# …` annotations are documentation, not arguments.
            let args: String = rest.split('`').step_by(2).collect::<Vec<_>>().join(" ");
            for word in args.split_whitespace() {
                let word = word.trim_end_matches(['\\', ',']);
                if word.starts_with("--") && !have.contains(word) {
                    missing.push(format!("{rel}:{}: `agentplane {verb} {word}`", number + 1));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these pages document a flag the CLI does not have — an operator copying \
         the line gets a parse error, and the block they copy under pressure is \
         the recovery drill:\n  {}",
        missing.join("\n  ")
    );
}

/// `Run` → `run`, for a verb name.
fn kebab(variant: &str) -> String {
    let mut out = String::new();
    for (i, c) in variant.char_indices() {
        if c.is_uppercase() && i > 0 {
            out.push('-');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// `older_than_days` → `older-than-days`, clap's default long-flag spelling.
fn kebab_field(field: &str) -> String {
    field.replace('_', "-")
}
