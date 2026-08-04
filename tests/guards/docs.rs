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
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// Whether a line cites a section of a document the reader does not have.
///
/// A named specification before the section is a citation a reader can follow;
/// a bare one is a pointer into an internal document.
fn cites_internal_section(line: &str) -> bool {
    let Some(at) = line.find('§') else {
        return false;
    };
    let before = &line[..at];
    if before.contains("RFC") || before.contains("C2SP") {
        return false;
    }
    line[at..]
        .chars()
        .nth(1)
        .is_some_and(|c| c.is_ascii_digit())
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
fn shipped_source_cites_no_internal_section_numbers() {
    assert!(
        cites_internal_section("//! The sensitivity lattice (§12) controls what may leave"),
        "the detector does not recognise the very thing it exists to find"
    );
    assert!(
        cites_internal_section("/// Three is the shape §11.1 describes"),
        "the detector misses a subsection reference"
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

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = walk(&root);
    assert!(
        files.len() > 20,
        "the source scan found only {} files — this guard is now inert",
        files.len()
    );

    let mut offenders = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).expect("a source file this crate owns");
        for (n, line) in text.lines().enumerate() {
            if cites_internal_section(line) {
                offenders.push(format!(
                    "{}:{}: {}",
                    path.strip_prefix(&root).unwrap_or(path).display(),
                    n + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "shipped source cites internal design-document sections, which a docs.rs \
         reader cannot resolve and which go stale silently when the document is \
         renumbered — state the reasoning instead:\n{}",
        offenders.join("\n")
    );
}
