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
