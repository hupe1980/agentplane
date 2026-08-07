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
# `-D warnings` here, not only in CI. The pipeline sets it globally, so without
# it locally `just ci` passes on a tree the pipeline rejects — which is exactly
# the drift this file exists to prevent, and it happened: fifteen lints and a
# feature-combination error reached CI green from here.
#
# `--all-features` cannot see a lint that only fires when a feature is OFF, so
# the seam configurations below are not redundant with the first line.
lint:
    cargo fmt --all -- --check
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features
    RUSTFLAGS="-D warnings" cargo clippy --all-targets
    RUSTFLAGS="-D warnings" cargo clippy --no-default-features
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --features postgres,testkit

# Every optional feature, compiled on its own.
#
# `--all-features` cannot see this and neither can a curated combination: a
# feature that uses a module it never declared builds perfectly as long as
# something else in the set happens to enable that module. `a2a-server` did
# exactly that with `push` — it had never once been compiled alone.
#
# Cheap because the dependency graph is shared: after the first, each is a
# handful of crates.
features:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in $(python3 -c "
    import pathlib
    c = pathlib.Path('Cargo.toml').read_text()
    b = c[c.index('[features]'):c.index('[dependencies]')]
    print(' '.join(
        l.split('=')[0].strip()
        for l in b.splitlines()
        if '=' in l and not l.strip().startswith('#') and l.split('=')[0].strip() != 'default'
    ))"); do
        printf '  %s\n' "$f"
        cargo check --quiet --no-default-features --features "$f"
    done

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

# the key-ring contract, against a real Vault container
#
# The in-process ring cannot get a status code wrong and the adapter cannot get
# a HashMap wrong, so one passing says nothing about the other. This found three
# real defects the unit tests could not: Vault reports a destroyed key as a 400
# with a message, not a 404.
test-vault:
    cargo test --features keyring-vault,testkit --test guards vault:: -- --test-threads=1

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

# Tests that call a real provider and therefore cost money.
#
# Never part of `ci`, and gated twice: this recipe supplies AGENTPLANE_LIVE=1,
# and the keys come from .env (gitignored). An exported OPENAI_API_KEY alone
# does nothing — a credential being available is not a decision to spend it.
#
# Each provider's battery skips on its own key, so one key runs one battery and
# the rest say so loudly. The Gemini one carries the load here: a thought
# signature is minted and validated by Google, so a canned server accepts
# whatever a fixture tells it to and proves nothing about whether Gemini takes
# the signature back.
test-live:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -f .env ]; then
        echo "no .env — put OPENAI_API_KEY and/or GEMINI_API_KEY in it, or export them and set AGENTPLANE_LIVE=1" >&2
        exit 1
    fi
    set -a; . ./.env; set +a
    AGENTPLANE_LIVE=1 cargo test --features providers,redb,testkit --test live -- --nocapture --test-threads=1

# standing authority: cross-run ceilings, idempotent draws, revocation
test-authority:
    cargo test --features redb,testkit --test guards authority::

# memory: provenance labelling, journaled recall, versioning and forgetting
test-memory:
    cargo test --features redb,testkit --test guards memory::

# webhook grants, SSRF guards, and what a notification may contain
test-push:
    cargo test --features push,media,redb,testkit --test guards push::

# the official A2A conformance kit against this server — the outside authority
#
# Every other A2A test drives this server with this crate's own client, which
# proves symmetry, not conformance. Network-gated (clones and installs the
# kit); needs `uv`. Two kit MUSTs are excluded with evidence — see the script.
test-a2a-tck:
    bash tools/a2a_tck.sh

# being called: the public card, the 1.0 methods, and a client/server round trip
test-a2a-server:
    cargo test --features a2a-server,a2a,signing,redb,testkit --test wire a2a_server::

# run every example end to end
examples:
    cargo run --example hello_skill
    cargo run --example durable_pipeline
    cargo run --example clearing_case
    cargo run --example plan_graph
    cargo run --example governed_transfer
    cargo run --example saga_checkout
    cargo run --example effect_group
    cargo run --example tool_loop --features redb,testkit,manifest
    cargo run --example planned_run --features redb,testkit,manifest
    cargo run --example sealed_run --features redb,testkit,keyring
    cargo run --example model_run --features redb,testkit
    cargo run --example media_run --features redb,testkit,media
    cargo run --example memory_run
    cargo run --example manifest_run --features redb,testkit,manifest
    cargo run --example mcp_tools --features redb,testkit,manifest,mcp
    cargo run --example blog_room --features redb,testkit,manifest
    cargo run --example a2a_peer --features redb,a2a-server,manifest
    cargo run --example standing_authority --features redb,testkit
    cargo run --example streaming_run --features redb,testkit

# the binary is never exercised by `cargo test` — it only compiles
cli-smoke:
    tools/cli-smoke.sh

# build the rustdoc a reader would land on
#
# `-D warnings` because a broken intra-doc link is invisible otherwise: two
# references to `TursoStore` survived the move to redb — one of them in the
# crate-level docs, which is the first thing a reader sees — and nothing in the
# gate said a word. Clippy does not check doc links; only rustdoc does.
docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# the crate still builds on the declared minimum Rust
msrv:
    cargo +1.94.1 check --all-features

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

# regenerate the social card from its SVG source (needs librsvg)
og:
    rsvg-convert -w 1200 -h 630 site/assets/og.svg -o site/static/og.png

# build the first example a reader copies, exactly as they would
doc-examples:
    tools/check-doc-examples.sh

# build the docs site into site/public
site:
    cd site && zola build

# every `agentplane = "X.Y"` on the site resolves on crates.io (needs network)
#
# `check-doc-examples.sh` holds those lines to `Cargo.toml`, which is the half
# that cannot fail alone — one commit moves both. This is the other half, and it
# is the one a reader actually meets: `release.yml` fires on a tag while
# `pages.yml` fires on any `site/**` push, so nothing orders publishing the
# crate before publishing the page that tells people to depend on it. Not in
# `ci`, which must work offline and on a branch whose version is unpublished by
# definition; it runs in the Pages workflow, before the site is deployed.
published:
    ./tools/check-published.sh

# serve the docs site locally with live reload
site-serve:
    cd site && zola serve

# TLA+ model check, plus the spec mutants
specs:
    ./spec/verify.sh

# ── Release ─────────────────────────────────────────────────────────────────

# Run it before tagging: a crates.io publish is immutable, so a file that
# should not be in the tarball cannot be withdrawn afterwards — only yanked,
# with the contents still served.

# list the publish tarball and refuse if the internal design doc is in it
#
# `--allow-dirty` because this runs in `ci`, and `cargo package` otherwise
# refuses any tree with uncommitted work — which is every tree a developer is
# actually working in. Without it the recipe fails for a reason that has nothing
# to do with what it checks, and the check silently never runs: three CI passes
# went by with this step erroring on a dirty tree and the tarball unexamined.
#
# Listing uncommitted files is exactly right here. The question this asks is
# "would the *current* contents ship", and the current contents are what a
# release is cut from.
package:
    cargo package --list --allow-dirty
    @echo
    @cargo package --list --allow-dirty | grep -qx 'CONCEPT.md' \
        && (echo "REFUSED: CONCEPT.md is in the tarball" && exit 1) \
        || echo "ok: the internal design document is not in the tarball"

# a full verification build from the tarball, uploading nothing
publish-dry:
    cargo publish --dry-run

# no dependency in the tree has a known advisory against it
#
# This crate forbids `unsafe`, models its protocol in TLA+ and mutation-tests its
# own guarantees — and none of that reaches the 480-odd crates it links. The gap
# was not hypothetical: the AWS SDK's default `rustls` feature is
# `legacy-rustls-ring`, which pinned `rustls-webpki` 0.101 and three live
# advisories against certificate validation into every `bedrock` build. Nothing
# in the pipeline could see it, because nothing in the pipeline was looking.
#
# In `ci` rather than `ci-full`: an advisory published this morning is a fact
# about today's tree, and finding out at release time is finding out late.
audit:
    cargo audit --deny warnings

# ── What CI runs ────────────────────────────────────────────────────────────

# `mutants` and `specs` are their own CI jobs because they rebuild repeatedly;
# run them before a release, not on every save.

# everything CI runs, minus the two slow layers
ci: lint features anchors audit test test-default test-minimal examples cli-smoke doc-examples docs package

# everything, including the slow layers — what a release must pass
ci-full: ci specs mutants
