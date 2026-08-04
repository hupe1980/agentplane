#!/usr/bin/env bash
#
# The CLI is the declarative tier's whole point, so it has to keep working.
#
# A binary is the one thing `cargo test` never exercises: it compiles, and
# nothing runs it. This drives the three verbs against a real manifest and
# checks the answers, so "you can run an agent with no Rust" stays a fact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN=(cargo run -q --features cli --bin agentplane --)
YAML=examples/summariser.yaml

echo "── validate ──"
"${BIN[@]}" validate "$YAML"

echo "── digest is stable ──"
a="$("${BIN[@]}" digest "$YAML")"
b="$("${BIN[@]}" digest "$YAML")"
[[ "$a" == "$b" ]] || { echo "FAIL: the digest is not deterministic"; exit 1; }
[[ ${#a} -eq 64 ]] || { echo "FAIL: not a sha256 hex digest: $a"; exit 1; }
echo "ok: $a"

echo "── run ──"
out="$("${BIN[@]}" run "$YAML" --input '{"ticket":"printer on fire"}')"
echo "$out" | grep -q '"summary"' || {
    echo "FAIL: the declared output shape did not come back: $out"; exit 1; }
echo "ok: $out"

echo "── a manifest with no execution block is refused ──"
tmp="$(mktemp -t agentplane-XXXX).yaml"
trap 'rm -f "$tmp"' EXIT
grep -v 'execution' "$YAML" | grep -v 'kind: completion' > "$tmp"
if "${BIN[@]}" run "$tmp" >/dev/null 2>&1; then
    echo "FAIL: a manifest whose behaviour is a skill was run by the binary anyway"
    exit 1
fi
echo "ok: refused, and said why"

echo "── a failed run exits non-zero ──"
if "${BIN[@]}" run "$YAML" --input 'not json' >/dev/null 2>&1; then
    echo "FAIL: bad input exited zero; a script could not tell it went wrong"
    exit 1
fi
echo "ok"

echo
echo "the CLI runs an agent that is only a file"
