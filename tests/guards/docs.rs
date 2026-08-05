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
            if let Err(error) = Manifest::parse(body) {
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
