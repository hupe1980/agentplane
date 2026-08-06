#!/usr/bin/env bash
#
# Build the examples a newcomer copies first.
#
# `cargo test --doc` covers rustdoc inside `src/`. It does not touch the
# markdown under `site/content/docs/`, so the getting-started snippets — the
# very first code anyone runs — were unverified. A copy-pasted example that does
# not compile is the worst first impression a crate can make, and it is exactly
# the kind of rot that sets in silently after an API change.
#
# Only the *complete* blocks are checked: fragments that illustrate one call
# have no imports and are not meant to stand alone. The rule is the file's, not
# a guess — a block qualifies when it carries its own `use` lines.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/agentplane-doc-examples"
rm -rf "$WORK"; mkdir -p "$WORK/src"

# Every version this crate names of itself agrees with `Cargo.toml`.
#
# This harness supplies its own manifest — it has to, since it builds against a
# path dependency — so it proves the *code* compiles while saying nothing about
# the dependency line the page tells a reader to write. That gap is not
# theoretical: the two blocks on the getting-started page said `0.2` while the
# crate was at `0.3`, so the very first thing a newcomer copied resolved to a
# release without the API the same page went on to demonstrate.
#
# The MSRV is checked the same way and for a stronger reason: it is a fact
# maintained in five places — `Cargo.toml`, the `msrv` recipe, the CI toolchain
# pin, and two lines of README — and the pipeline pins an *exact* toolchain, so
# a `rust-version` bump that misses `ci.yml` fails the msrv job rather than
# quietly disagreeing.
#
# Crate versions compare major.minor only: a patch bump is not something prose
# should have to chase, and a caret requirement does not care. The MSRV compares
# exactly, because a patch is precisely what an MSRV can turn on.
python3 - "$ROOT" <<'PY'
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
# Read `[package]` by hand rather than with `tomllib`: that is 3.11+, and this
# repository's own virtualenv is 3.9. The justfile parses Cargo.toml the same
# way for the same reason.
manifest = (root / "Cargo.toml").read_text()
package = manifest[manifest.index("[package]") : manifest.index("\n[", manifest.index("[package]") + 1)]
crate = re.search(r'^version\s*=\s*"([^"]+)"', package, re.M).group(1)
msrv = re.search(r'^rust-version\s*=\s*"([^"]+)"', package, re.M).group(1)
want = ".".join(crate.split(".")[:2])

# `agentplane = "0.3"` and `agentplane = { version = "0.3", ... }`, both of
# which appear, and both of which a reader copies verbatim.
pattern = re.compile(r'agentplane\s*=\s*(?:\{[^}]*?version\s*=\s*)?"([0-9]+\.[0-9]+)[^"]*"')

bad = []
for page in sorted((root / "site/content").rglob("*.md")) + [root / "README.md"]:
    for n, line in enumerate(page.read_text().splitlines(), 1):
        for found in pattern.findall(line):
            if found != want:
                bad.append(f"{page.relative_to(root)}:{n}: says {found}, crate is {want}")

# Wherever a Rust version is pinned or advertised, it is this one. Each pattern
# is anchored to its own file so a stray version number elsewhere — a dependency
# requirement, a changelog line — is not mistaken for an MSRV claim.
for rel, pat, what in [
    ("justfile", r'cargo \+([0-9][0-9.]*) check', "the msrv recipe"),
    (".github/workflows/ci.yml", r'rust-toolchain@([0-9][0-9.]*)', "the CI toolchain pin"),
    ("README.md", r'rustc-([0-9][0-9.]*)%2B', "the MSRV badge"),
    ("README.md", r'Rust \*\*([0-9][0-9.]*)\+\*\*', "the prose MSRV"),
]:
    path = root / rel
    for n, line in enumerate(path.read_text().splitlines(), 1):
        for found in re.findall(pat, line):
            if found != msrv:
                bad.append(f"{rel}:{n}: {what} says {found}, rust-version is {msrv}")

if bad:
    print("REFUSED: a documented version has drifted from Cargo.toml")
    print("\n".join("  " + b for b in bad))
    raise SystemExit(1)
print(f"ok: every documented agentplane version says {want}, every MSRV says {msrv}")
PY

cat > "$WORK/Cargo.toml" <<EOF
[package]
name = "doc-examples"
version = "0.0.0"
edition = "2024"

[dependencies]
agentplane = { path = "$ROOT", features = ["redb", "testkit"] }
serde_json = "1"
async-trait = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
EOF

python3 - "$ROOT" "$WORK" <<'PY'
import pathlib, re, sys
root, work = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
gs = (root / "site/content/docs/getting-started.md").read_text()
blocks = re.findall(r"```rust\n(.*?)```", gs, flags=re.S)

skill = next(b for b in blocks if "impl Skill" in b)
wiring = next(b for b in blocks if "Runtime::builder" in b)

uses = "\n".join(l for l in wiring.splitlines() if l.startswith("use "))
body = "\n".join("    " + l for l in wiring.splitlines() if not l.startswith("use "))

(work / "src/main.rs").write_text(f"""{skill}

{uses}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
{body}
    Ok(())
}}
""")
print("assembled the getting-started skill + wiring")
PY

cd "$WORK"
cargo run --quiet
echo "ok: the first example a reader copies compiles and runs"
