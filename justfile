# Every check this project runs, in one place.
#
# CI calls these recipes rather than repeating their flags, so a command cannot
# drift between what a contributor runs locally and what the pipeline runs. When
# they differ, the pipeline is right and the contributor finds out late — which
# is the failure this file exists to prevent.
#
#   just            list everything
#   just ci         what CI runs, in one pass
#   just anchors    milliseconds; run this constantly
#   just mutants    minutes; the assurance gate, not an inner-loop check

_default:
    @just --list --unsorted

# ── The inner loop ──────────────────────────────────────────────────────────

# format everything
fmt:
    cargo fmt --all

# `--all-targets`: a lint that only runs over the library is a lint the tests
# and examples are exempt from, and those are where fixtures rot.

# fmt + clippy across all three feature configurations
lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features
    cargo clippy --all-targets
    cargo clippy --no-default-features

# the full suite, all features
test:
    cargo test --all-features

# Text-only, so it costs milliseconds — and it catches the silent half of the
# mutation harness: a refactor that moves the anchored code leaves the
# guarantee unverified while still looking verified.

# every mutation still anchors in the code it names (milliseconds)
anchors:
    python3 tools/mutants.py --check

# ── Feature configurations ──────────────────────────────────────────────────
#
# Not redundant with `test`. `--all-features` enables `cedar`, which
# transitively enables `serde_json/preserve_order` — so the default build and
# the full build exercise genuinely different canonicalization paths, and
# running only one leaves the other unproven.

# the default feature set (a different canonicalization path)
test-default:
    cargo test

# `test`, not `check`: a `check` here once passed while
# `cargo test --no-default-features` was broken, because the integration tests
# and examples were not gated. A gate nobody exercises is not a gate.

# the crate with no backend — an embedder bringing their own store
test-minimal:
    cargo test --no-default-features

# ── Targeted suites, matching the CI jobs ───────────────────────────────────
#
# Each runs one seam with *only* its own features on — the configuration an
# embedder who wants that seam and nothing else will actually build. It proves
# the seam does not quietly depend on some other feature being present.

# the store contract, against a real Postgres container
test-postgres:
    cargo test --features postgres,testkit --test guards postgres::

# real MCP round trips against an in-process server
test-mcp:
    cargo test --features mcp,redb,testkit --test wire mcp::

# the operator surface, with only its own features on
test-http:
    cargo test --features http,redb --test wire api::

# signed journals, including a wholesale rewrite
test-attestation:
    cargo test --features signing,redb --test trust attestation::

# A2A and model-driver failure mappings
test-drivers:
    cargo test --features a2a,providers,http,redb,testkit --test wire drivers::

# run every example end to end
examples:
    cargo run --example durable_pipeline
    cargo run --example clearing_case
    cargo run --example plan_graph
    cargo run --example model_run --features redb,testkit

# build the rustdoc a reader would land on
docs:
    cargo doc --no-deps --all-features

# the crate still builds on the declared minimum Rust
msrv:
    cargo +1.94.0 check --all-features

# ── The assurance gate ──────────────────────────────────────────────────────

# Rebuilds once per mutation, so this is a gate rather than an inner-loop
# check — use `just anchors` while working.

# break each guarantee on purpose; its named test must fail (minutes)
mutants:
    tools/verify-mutants.sh

# Finds code with no test at all, which the hand-written table cannot: it names
# the test that must fail, so it only covers guarantees somebody wrote down.
# Scope it to a file — the whole crate is a wall-clock day.

# auto-generated mutants over one file: just mutants-auto src/model/sse.rs
mutants-auto file:
    cargo mutants --all-features -f {{file}} -j 4

# TLA+ model check, plus the spec mutants
specs:
    ./spec/verify.sh

# ── Release ─────────────────────────────────────────────────────────────────

# Run it before tagging: a crates.io publish is immutable, so a file that
# should not be in the tarball cannot be withdrawn afterwards — only yanked,
# with the contents still served.

# list the publish tarball and refuse if the internal design doc is in it
package:
    cargo package --list
    @echo
    @cargo package --list | grep -qx 'CONCEPT.md' \
        && (echo "REFUSED: CONCEPT.md is in the tarball" && exit 1) \
        || echo "ok: the internal design document is not in the tarball"

# a full verification build from the tarball, uploading nothing
publish-dry:
    cargo publish --dry-run

# ── What CI runs ────────────────────────────────────────────────────────────

# `mutants` and `specs` are their own CI jobs because they rebuild repeatedly;
# run them before a release, not on every save.

# everything CI runs, minus the two slow layers
ci: lint anchors test test-default test-minimal examples docs package

# everything, including the slow layers — what a release must pass
ci-full: ci specs mutants
