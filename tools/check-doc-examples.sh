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
# Which blocks are checked, stated as what the code below actually does rather
# than as a rule it does not implement. This comment used to claim "a block
# qualifies when it carries its own `use` lines", and nothing enforced that: the
# assembler picked exactly two blocks by searching for `impl Skill` and
# `Runtime::builder`. The tool-call block carries `use` lines, was therefore
# believed covered, and was not — it shipped for a while with `ToolCall::prepare(..)?`
# in a function returning `SkillError`, which does not compile. A checker whose
# comment overstates its own reach is worse than a narrower one, because it is
# the reason nobody looks again.
#
# Three blocks are checked, each named by a marker unique to it:
#
#   * the skill        (`impl Skill`)      — self-contained
#   * the wiring       (`Runtime::builder`) — self-contained
#   * the tool call    (`ToolCall::prepare`) — a *fragment*, compiled inside a
#     function that supplies its three free names. That coupling is deliberate
#     and narrow: the harness states the contract in one place, and a page that
#     renames one of them fails here rather than in a reader's editor.
#
# Anything else on the page is prose-adjacent illustration and is not compiled.
# Adding a block does not silently add coverage — say so here, or it has none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/agentplane-doc-examples"
rm -rf "$WORK"; mkdir -p "$WORK/src"

# The MSRV agrees everywhere it is written down.
#
# It is a fact maintained in five places — `Cargo.toml`, the `msrv` recipe, the
# CI toolchain pin, and two lines of README — and the pipeline pins an *exact*
# toolchain, so a `rust-version` bump that misses `ci.yml` fails the msrv job
# rather than quietly disagreeing. Compared exactly, because a patch release is
# precisely what an MSRV can turn on.
#
# There is deliberately **no crate-version check here any more**, and its
# removal is the point rather than a gap. It compared the site's
# `agentplane = "X.Y"` lines against `Cargo.toml`, which conflates two different
# facts: `Cargo.toml` holds the version being *developed*, while a reader should
# depend on the latest version *published*. Those legitimately differ for as
# long as a release takes — so the check forced the docs to state something
# false the moment the version was bumped, and a second guard was then added to
# catch the falsehood the first one required. Two guards policing a duplicated
# fact.
#
# The fact is gone instead: the pages say `cargo add agentplane`, which asks the
# registry and cannot be stale. Nothing to compare, nothing to drift.
python3 - "$ROOT" <<'PY'
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
# Read `[package]` by hand rather than with `tomllib`: that is 3.11+, and this
# repository's own virtualenv is 3.9. The justfile parses Cargo.toml the same
# way for the same reason.
manifest = (root / "Cargo.toml").read_text()
package = manifest[manifest.index("[package]") : manifest.index("\n[", manifest.index("[package]") + 1)]
msrv = re.search(r'^rust-version\s*=\s*"([^"]+)"', package, re.M).group(1)

bad = []

# No page may reintroduce a hand-written version. `cargo add` is the whole
# remedy, and one `agentplane = "0.7"` slipping back in is how the drift starts
# again — silently, because a version that happens to be current today reads as
# correct.
pattern = re.compile(r'agentplane\s*=\s*(?:\{[^}]*?version\s*=\s*)?"[0-9]+\.[0-9]+')
for page in sorted((root / "site/content").rglob("*.md")) + [root / "README.md"]:
    for n, line in enumerate(page.read_text().splitlines(), 1):
        if pattern.search(line):
            bad.append(
                f"{page.relative_to(root)}:{n}: writes a crate version by hand; "
                f"use `cargo add agentplane` so it cannot go stale"
            )

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
    print("REFUSED:")
    print("\n".join("  " + b for b in bad))
    raise SystemExit(1)
print(f"ok: no page pins a crate version by hand, every MSRV says {msrv}")
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

def one(marker):
    """The single block carrying `marker`, or a loud failure.

    `next(...)` would silently take the first of several, which is how a page
    that grows a second `Runtime::builder` block starts checking the wrong one.
    """
    found = [b for b in blocks if marker in b]
    if len(found) != 1:
        sys.exit(
            f"REFUSED: expected exactly one getting-started block containing "
            f"{marker!r}, found {len(found)}. Update this harness rather than "
            f"letting it check whichever one comes first."
        )
    return found[0]

skill = one("impl Skill")
wiring = one("Runtime::builder")
tool_call = one("ToolCall::prepare")


def split_uses(block):
    uses = "\n".join(l for l in block.splitlines() if l.startswith("use "))
    body = "\n".join(l for l in block.splitlines() if not l.startswith("use "))
    return uses, body


wiring_uses, wiring_body = split_uses(wiring)
tool_uses, tool_body = split_uses(tool_call)

# The fragment's three free names are supplied as parameters so the block itself
# is compiled **verbatim**. Rewriting it to fit would check a different program
# from the one the page publishes, which is the failure mode a snippet harness
# exists to prevent.
#
# The fragment lives in its own module so its `use` lines are compiled as the
# page writes them without colliding with the skill block's — two snippets on
# one page legitimately import the same name, and rewriting either to avoid that
# would check a program the page does not publish.
tool_fn = "\n".join("        " + l for l in tool_body.splitlines())
tool_mod_uses = "\n".join("    " + l for l in tool_uses.splitlines())
main_fn = "\n".join("    " + l for l in wiring_body.splitlines())

(work / "src/main.rs").write_text(f"""{skill}

{wiring_uses}

/// The tool-call fragment, verbatim, with the three names the page leaves to the reader.
#[allow(dead_code, unused_variables, unused_imports)]
mod governed_tool_call {{
{tool_mod_uses}
    use serde_json::json;

    pub async fn call(
        cx: &mut agentplane::runtime::StepCtx<'_>,
        client: std::sync::Arc<dyn agentplane::tools::ToolClient>,
        model_written_memo: agentplane::core::Tainted<serde_json::Value>,
    ) -> Result<(), agentplane::core::SkillError> {{
{tool_fn}
        let _ = result;
        Ok(())
    }}
}}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
{main_fn}
    Ok(())
}}
""")
print("assembled the getting-started skill + wiring + tool call")
PY

cd "$WORK"
cargo run --quiet
echo "ok: the first example a reader copies compiles and runs"
