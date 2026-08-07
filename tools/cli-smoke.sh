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

echo "── a room in one file: three agents, three digests, one run ──"
ROOM=examples/room.yaml
lines="$("${BIN[@]}" digest "$ROOM" | wc -l | tr -d ' ')"
[[ "$lines" == "3" ]] || { echo "FAIL: a room of three printed $lines digests"; exit 1; }
# No --capability: the desk is the room's one orchestrator, so the entry is
# unambiguous and declared rather than guessed.
"${BIN[@]}" run "$ROOM" --input '{"topic":"durable execution"}' >/dev/null
echo "ok: the room ran, starting at its declared orchestrator"

echo "── an ambiguous entry is refused, not guessed ──"
if out="$("${BIN[@]}" run "$ROOM" --capability nothing.here 2>&1 >/dev/null)"; then
    echo "FAIL: an unknown capability ran something"; exit 1
fi
echo "$out" | grep -q 'blog.desk' || {
    echo "FAIL: the refusal did not list the candidates: $out"; exit 1; }
echo "ok: refused, listing what the file provides"

echo "── a failed run exits non-zero ──"
if "${BIN[@]}" run "$YAML" --input 'not json' >/dev/null 2>&1; then
    echo "FAIL: bad input exited zero; a script could not tell it went wrong"
    exit 1
fi
echo "ok"

echo "── the default journal needs no writable filesystem ──"
# `agentplane run` journals in memory unless `--store` says otherwise, and
# "in memory" has to mean it. It did not: the ephemeral store created a file
# under TMPDIR and unlinked it, which behaves like memory right up until there
# is nowhere to put it. The container image runs read-only with no writable
# temp directory, so the *first documented command* failed there with
# `Read-only file system (os error 30)` — naming neither the journal nor the
# directory it wanted.
#
# Pointing TMPDIR at something that cannot exist is the cheap version of that
# environment. The old implementation fails this line; that is what makes it a
# check rather than a restatement.
if ! TMPDIR=/nonexistent/agentplane-must-not-need-this \
     "${BIN[@]}" run "$YAML" --input '{"ticket":"printer on fire"}' >/dev/null 2>&1; then
    echo "FAIL: the default in-memory journal reached for a temp directory"
    exit 1
fi
echo "ok: an in-memory journal is in memory"

echo "── a build that cannot serve says which flag it needs ──"
# `serve` needs `a2a-server` and `cedar`, which `cli` does not pull in. Meeting
# it with "unknown command" would tell a reader the feature does not exist when
# it does and is one flag away, so the refusal names the flag. Asserted here
# because this smoke test runs the *slim* feature set, which is exactly the
# build a reader hits it in.
if out="$("${BIN[@]}" serve "$YAML" 2>&1 >/dev/null)"; then
    echo "FAIL: a build without a2a-server served something"; exit 1
fi
echo "$out" | grep -q 'a2a-server' || {
    echo "FAIL: the refusal does not name the missing feature: $out"; exit 1; }
echo "ok: refused, naming the feature to rebuild with"

echo "── --mcp in a build without the transport names the feature ──"
# `cli` does not pull in `mcp-stdio`, so this smoke test runs the exact build a
# reader meets the flag in. Ignoring the flag would be worse than refusing it:
# the plane would then fail to build for a *different* reason — no tool
# catalogue — and send them looking at their manifest for a mistake in their
# build.
if out="$("${BIN[@]}" run "$YAML" --mcp 'tickets=true' 2>&1 >/dev/null)"; then
    echo "FAIL: a build without mcp-stdio accepted --mcp"; exit 1
fi
echo "$out" | grep -q 'mcp-stdio' || {
    echo "FAIL: the refusal does not name the missing feature: $out"; exit 1; }
echo "ok: refused, naming the feature to rebuild with"

echo "── a declarative tool loop, with tools from an MCP server ──"
# The last declarative tier: `tool-calling` needs a catalogue, the catalogue is
# derived from the manifest, and the transport is named on the command line.
# Run with `mcp-stdio` because that is the build the feature exists in — and on
# the host rather than in the container, because a distroless image has no
# interpreter to run a scripted MCP server with.
MCPBIN=(cargo run -q --features cli,mcp-stdio --bin agentplane --)
out="$("${MCPBIN[@]}" run "$ROOT/examples/tool-calling.yaml" \
        --input '{"ticket":"T-1"}' \
        --mcp "tickets=python3 $ROOT/examples/mcp-server.py" 2>&1)" || {
    echo "FAIL: the tool loop did not run: $out"; exit 1; }
grep -q 'Succeeded' <<<"$out" || { echo "FAIL: the tool loop did not succeed: $out"; exit 1; }
echo "ok: started the server, derived the catalogue, completed the run"

echo "── a grant whose server nobody wired refuses the build ──"
# The wiring is load-bearing, not decorative: naming the wrong server must fail
# at build rather than offering the model a tool that fails when chosen.
if out="$("${MCPBIN[@]}" run "$ROOT/examples/tool-calling.yaml" --input '{}' \
            --mcp "wrongname=python3 $ROOT/examples/mcp-server.py" 2>&1 >/dev/null)"; then
    echo "FAIL: a grant with no transport built anyway"; exit 1
fi
echo "$out" | grep -q 'no transport is wired' || {
    echo "FAIL: the refusal does not name the missing transport: $out"; exit 1; }
echo "ok: refused at build, naming the server nobody wired"

echo "── a flag belonging to another verb does not parse ──"
# The defect the parser rewrite removed: one flag table for every verb meant
# `run` silently accepted `--push-host`, `--url`, `--tokens` and friends and did
# nothing with them. One of those is a security control, which makes it shape 1
# at the command line — a declaration that does nothing.
for bad in --push-host --url --operator-addr --tokens; do
    if "${BIN[@]}" run "$YAML" --input '{}' "$bad" x >/dev/null 2>&1; then
        echo "FAIL: \`run\` accepted the serve-only flag $bad"; exit 1
    fi
done
if "${BIN[@]}" validate "$YAML" --input '{}' >/dev/null 2>&1; then
    echo "FAIL: \`validate\` accepted a run-only flag"; exit 1
fi
echo "ok: each verb takes only its own flags"

echo "── --strict without --replay does not parse ──"
# It used to be accepted and ignored, so a reader asking for a *verification*
# replay got an ordinary one and no hint of the difference.
if "${BIN[@]}" run "$YAML" --input '{}' --strict >/dev/null 2>&1; then
    echo "FAIL: --strict was accepted without --replay"; exit 1
fi
echo "ok: --strict requires --replay"

echo "── the two input flags are mutually exclusive ──"
if "${BIN[@]}" run "$YAML" --input '{}' --input-file /dev/null >/dev/null 2>&1; then
    echo "FAIL: --input and --input-file were both accepted"; exit 1
fi
echo "ok: refused, rather than one silently winning"

echo
echo "the CLI runs an agent that is only a file"
