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
    if before.contains("RFC") || before.contains("C2SP") {
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
/// The detector is exercised on known inputs **before** it is run over the
/// tree. Without that this test cannot fail for the right reason: on a clean
/// tree a working detector and a disabled one both report nothing, so deleting
/// the rule would leave a green test guarding an empty set.
#[test]
fn nothing_a_reader_sees_cites_an_internal_section_number() {
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
            if cites_internal_section(line) {
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
        "an artifact a reader can see cites internal design-document sections, \
         which they cannot resolve and which go stale silently when the document \
         is renumbered — state the reasoning instead:\n{}",
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

/// Every example is actually run by the recipe that claims to run them all.
///
/// `just examples` is the only thing that executes example code, so an example
/// missing from it compiles forever and never runs — which is worse than not
/// having it, because the README points readers at something nothing checks.
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

    let missing: Vec<&String> = on_disk
        .iter()
        .filter(|name| !block.contains(&format!("--example {name}")))
        .collect();

    assert!(
        missing.is_empty(),
        "these examples are never executed by `just examples`, so nothing \
         notices when they stop working: {missing:?}"
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
#[test]
fn no_doc_comment_has_absorbed_the_one_below_it() {
    const SECTIONS: [&str; 4] = ["# Errors", "# Panics", "# Examples", "# Safety"];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0usize;
    let mut merged: Vec<String> = Vec::new();

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src is readable").flatten() {
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
                    let n = block.iter().filter(|l| **l == section).count();
                    if n > 1 {
                        merged.push(format!(
                            "{rel}:{start} has {n} `{section}` sections — this block \
                             has absorbed the doc comment of the item below it"
                        ));
                    }
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
    let source = read("src/manifest/mod.rs");

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
