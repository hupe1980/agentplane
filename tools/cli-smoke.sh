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

# A review rule the runtime deliberately never enforces: `metadata.annotations`
# is never read, which is what makes it safe to carry, and is why nothing can
# notice an agent shipped without an owner. The check belongs in CI, so it has
# to actually fail there.
echo "── a required annotation is a build failure, not a convention ──"
if "${BIN[@]}" validate "$YAML" --require-annotation example.com/nobody >/dev/null 2>&1; then
    echo "FAIL: a missing required annotation exited zero"; exit 1
fi
"${BIN[@]}" validate "$YAML" >/dev/null || {
    echo "FAIL: the same manifest must still pass with nothing required"; exit 1; }
echo "ok: a missing required annotation fails, and requiring none still passes"

echo "── schema names its published home ──"
schema="$("${BIN[@]}" schema)"
echo "$schema" | grep -q '"\$id": "https://hupe1980.github.io/agentplane/agent.schema.json"' || {
    echo "FAIL: the schema does not carry its published \$id"; exit 1; }
echo "ok: schema"

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

# **What a first run prints is part of the product.** Metrics carry their own
# `tracing` target so a subscriber can filter them out, and a one-shot verb has
# nobody collecting them — two metric events per run bury the two lines the run
# is about, on the first command the guide tells a reader to type. `RUST_LOG`
# still reaches them, which is the half that keeps this a default rather than a
# removal.
echo "── a one-shot run prints its answer, not a metric stream ──"
noise="$("${BIN[@]}" run "$YAML" --input '{"ticket":"printer on fire"}' 2>&1 >/dev/null \
    | grep -c 'agentplane.metric' || true)"
[ "$noise" = "0" ] || {
    echo "FAIL: $noise metric events on a one-shot run — the guide shows three lines"
    exit 1; }
asked="$(RUST_LOG=agentplane=info "${BIN[@]}" run "$YAML" --input '{"ticket":"x"}' 2>&1 >/dev/null \
    | grep -c 'agentplane.metric' || true)"
[ "$asked" != "0" ] || {
    echo "FAIL: RUST_LOG cannot reach the metric stream, so this is a removal"
    exit 1; }
echo "ok: quiet by default, reachable on request"

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
tdir="$(mktemp -d -t agentplane-tools-XXXX)"
out="$("${MCPBIN[@]}" run "$ROOT/examples/tool-calling.yaml" \
        --input '{"ticket":"T-1"}' --store "$tdir/t.redb" \
        --mcp "tickets=python3 $ROOT/examples/mcp-server.py" 2>&1)" || {
    echo "FAIL: the tool loop did not run: $out"; exit 1; }
grep -q 'Succeeded' <<<"$out" || { echo "FAIL: the tool loop did not succeed: $out"; exit 1; }
# Success alone is not evidence the server was reached: a loop whose model never
# asks for a tool succeeds too. The server's answer is in the journal only if
# the call went out and came back.
"${MCPBIN[@]}" export --store "$tdir/t.redb" 2>/dev/null | grep -q 'printer on fire' || {
    echo "FAIL: the run succeeded and the MCP server's answer is not in its journal"; exit 1; }
rm -rf "$tdir"
echo "ok: started the server, derived the catalogue, called the tool, completed the run"

echo "── a tool loop with no transport names the flag that wires one ──"
# The library's refusal names the Rust call that fixes it; a YAML author holds
# this binary, so the refusal they see names the flag.
if out="$("${BIN[@]}" run "$ROOT/examples/tool-calling.yaml" --input '{}' 2>&1 >/dev/null)"; then
    echo "FAIL: a tool loop with no transport ran"; exit 1
fi
grep -q -- '--mcp tickets=' <<<"$out" || {
    echo "FAIL: the refusal does not name --mcp: $out"; exit 1; }
if grep -q 'RuntimeBuilder' <<<"$out"; then
    echo "FAIL: the refusal tells a YAML author to write Rust: $out"; exit 1
fi
echo "ok: refused, naming --mcp"

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

echo "── the journal verbs work on a store this process did not write ──"
# The point of these two verbs is that an auditor holds a database file and
# nothing else — no source tree, no Rust toolchain, no manifest. So the smoke
# test uses only the store, exactly as they would.
jdir="$(mktemp -d -t agentplane-journal-XXXX)"
trap 'rm -rf "$jdir"' EXIT
"${BIN[@]}" run "$YAML" --input '{"text":"hello"}' --store "$jdir/j.redb" >/dev/null 2>&1 || {
    echo "FAIL: could not produce a journal to read"; exit 1; }

out="$("${BIN[@]}" export --store "$jdir/j.redb" 2>/dev/null)"
head -1 <<<"$out" | grep -q '"kind":"agentplane.export"' || {
    echo "FAIL: the export has no header, so a reader must be told how to read it"; exit 1; }
tail -1 <<<"$out" | grep -q '"kind":"agentplane.export.end"' || {
    echo "FAIL: the export has no trailer, so a truncated one looks complete"; exit 1; }
# Every line is its own JSON value: that is the whole reason for JSON Lines, and
# a single malformed line breaks every streaming reader downstream.
while IFS= read -r line; do
    printf '%s' "$line" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null || {
        echo "FAIL: an export line is not valid JSON: $line"; exit 1; }
done <<<"$out"
echo "ok: the export is framed, and every line parses on its own"

# ── the tenant is part of naming a store, not decoration ──
#
# Every key in both backends leads with the tenant, so naming the wrong one is a
# *miss* rather than an error: the verb answers about a plane nobody runs and
# exits zero. An export of the wrong tenant is empty, well-formed and looks
# exactly like an export of a quiet one — which is the artifact an auditor is
# handed. Asserted here because no unit test holds a whole binary to it.
runs_in() {
    "${BIN[@]}" export --store "$jdir/j.redb" ${2:+--tenant "$2"} 2>/dev/null \
        | python3 -c 'import json,sys
for line in sys.stdin:
    d = json.loads(line)
    if d.get("kind") == "agentplane.export.end":
        print(d["runs_exported"])'
}
[ "$(runs_in _ )" != "0" ] || {
    echo "FAIL: the default tenant exported nothing, so this check proves nothing"; exit 1; }
[ "$(runs_in _ somebody-else)" = "0" ] || {
    echo "FAIL: an export named another tenant and still found this one's runs"; exit 1; }
echo "ok: an export is scoped to the tenant it was asked for"

echo "── a connection string in a build without the backend names the feature ──"
# `cli` does not pull in `postgres`, so this smoke test runs the exact build a
# reader meets the flag in. "No such file or directory" would send them to look
# at their path for a mistake that is in their feature list.
if out="$("${BIN[@]}" halt list --store 'postgres://localhost/nope' 2>&1 >/dev/null)"; then
    echo "FAIL: a build without postgres opened a connection string"; exit 1
fi
grep -q 'postgres' <<<"$out" || {
    echo "FAIL: the refusal does not name the missing feature: $out"; exit 1; }
echo "ok: refused, naming the feature to rebuild with"

# Stderr is captured rather than discarded: these three are the verbs an
# operator reaches for during an incident, and a smoke failure that says only
# `exited non-zero` sends whoever reads it back to reproduce by hand.
"${BIN[@]}" audit --store "$jdir/j.redb" >"$jdir/report.json" 2>"$jdir/audit.err" || {
    echo "FAIL: the audit exited non-zero on healthy history:"
    sed 's/^/    /' "$jdir/audit.err"; exit 1; }
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$jdir/report.json" || {
    echo "FAIL: the audit report is not machine-readable"; exit 1; }
grep -q 'not_checked' "$jdir/report.json" || {
    echo "FAIL: the audit does not report what it could not check"; exit 1; }
grep -q 'no public key was supplied' "$jdir/report.json" || {
    echo "FAIL: an audit given no key claimed to have checked signatures"; exit 1; }
echo "ok: the audit reports what it could not check as loudly as what it did"

echo "── the restore drill runs on the export alone ──"
# `verify` takes a file and nothing else: no store, no manifest, no toolchain.
# That is the point — it is the verb somebody handed a copy can run.
"${BIN[@]}" export --store "$jdir/j.redb" >"$jdir/history.jsonl" 2>/dev/null
"${BIN[@]}" verify "$jdir/history.jsonl" >"$jdir/verify.json" 2>"$jdir/verify.err" || {
    echo "FAIL: a faithful export did not verify:"
    sed 's/^/    /' "$jdir/verify.err"; exit 1; }
grep -q '"findings": \[\]' "$jdir/verify.json" || {
    echo "FAIL: a faithful export produced findings"; exit 1; }
grep -q 'no public key was supplied' "$jdir/verify.json" || {
    echo "FAIL: a pass with no key claimed to have checked signatures"; exit 1; }
echo "ok: verified, and honest about what it could not check"

# The negative half, pointed at something that would otherwise *succeed*: the
# same file with one payload byte changed. A verifier that checks no hashes
# passes this, which is what makes it a test of the control rather than of the
# fixture.
sed 's/"capability":"/"capability":"x/' "$jdir/history.jsonl" >"$jdir/tampered.jsonl"
if ! cmp -s "$jdir/history.jsonl" "$jdir/tampered.jsonl"; then
    if "${BIN[@]}" verify "$jdir/tampered.jsonl" >/dev/null 2>&1; then
        echo "FAIL: an edited export verified clean"; exit 1
    fi
    echo "ok: an edited record does not recompute to the hash it carries"
else
    echo "FAIL: the tamper fixture changed nothing"; exit 1
fi

# Truncation: every line still valid, only the frame missing.
head -3 "$jdir/history.jsonl" >"$jdir/cut.jsonl"
if "${BIN[@]}" verify "$jdir/cut.jsonl" >/dev/null 2>&1; then
    echo "FAIL: a truncated export verified clean"; exit 1
fi
echo "ok: a truncated export is refused on its missing frame"

echo "── a store rebuilds from an export, and proves it ──"
"${BIN[@]}" restore "$jdir/history.jsonl" --store "$jdir/restored.redb" >"$jdir/restore.json" 2>"$jdir/restore.err" || {
    echo "FAIL: restoring an export exited non-zero:"
    sed 's/^/    /' "$jdir/restore.err"; exit 1; }
# The result is the comparison, not the loading: equal roots at equal size.
python3 - "$jdir/restore.json" <<'PY' || { echo "FAIL: the rebuilt store commits to a different history"; exit 1; }
import json,sys
r = json.load(open(sys.argv[1]))
assert r["expected"] == r["rebuilt"], (r["expected"], r["rebuilt"])
assert r["records"] > 0
PY
echo "ok: the rebuilt store reports the same checkpoint"

# And it is a working store, not just matching bytes: exporting it again
# produces something that verifies on its own terms.
"${BIN[@]}" export --store "$jdir/restored.redb" >"$jdir/again.jsonl" 2>/dev/null
"${BIN[@]}" verify "$jdir/again.jsonl" >/dev/null 2>&1 || {
    echo "FAIL: a restored store exported something that does not verify"; exit 1; }
echo "ok: and what it exports verifies"

echo "── policy check re-derives an export's verdicts, and says what it could not ──"
# The slim build names the feature rather than letting the parser say the verb
# does not exist.
if out="$("${BIN[@]}" policy check --bundle "$jdir" --from "$jdir/history.jsonl" 2>&1 >/dev/null)"; then
    echo "FAIL: a build without cedar checked policy"; exit 1
fi
grep -q 'cedar' <<<"$out" || {
    echo "FAIL: the refusal does not name the missing feature: $out"; exit 1; }
POLBIN=(cargo run -q --features cli,cedar --bin agentplane --)
mkdir -p "$jdir/policy"
printf 'permit(principal, action, resource);\n' >"$jdir/policy/policy.cedar"
# `run` wires no engine, so no gate ran and there is no verdict to re-derive.
# That is a partial answer, never a clean one.
status=0
"${POLBIN[@]}" policy check --bundle "$jdir/policy" --from "$jdir/history.jsonl" --json \
    >"$jdir/policy.json" 2>"$jdir/policy.err" || status=$?
[ "$status" = "5" ] || {
    echo "FAIL: an export with nothing to re-derive exited $status, not 5:"
    sed 's/^/    /' "$jdir/policy.err"; exit 1; }
python3 - "$jdir/policy.json" <<'PY' || { echo "FAIL: the report does not say what it could not judge"; exit 1; }
import json,sys
r = json.load(open(sys.argv[1]))
assert r["runs"] and all(run["mode"] == "ungoverned" for run in r["runs"]), r["runs"]
assert r["tenant"]["source"] == "default", r["tenant"]
assert "refused admission" in r["outside_export"], r["outside_export"]
PY
# A rules file the loader would not read is refused, not read around.
printf 'forbid(principal, action, resource);\n' >"$jdir/policy/extra.cedar"
status=0
"${POLBIN[@]}" policy check --bundle "$jdir/policy" --from "$jdir/history.jsonl" \
    >/dev/null 2>&1 || status=$?
[ "$status" = "2" ] || {
    echo "FAIL: a bundle with a stray rules file exited $status, not 2"; exit 1; }
rm "$jdir/policy/extra.cedar"
status=0
"${POLBIN[@]}" policy check --bundle "$jdir/policy" --from "$jdir/policy/policy.cedar" \
    >/dev/null 2>&1 || status=$?
[ "$status" = "2" ] || {
    echo "FAIL: a file that is not an export exited $status, not 2"; exit 1; }
echo "ok: ungoverned history is partial, and a bundle or file it cannot read is refused"

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
# `--key` and `--prior` are audit/verify evidence; an export neither checks
# signatures nor compares checkpoints, so accepting them would be the same
# defect — a security-sounding flag, silently ignored.
for bad in --key --prior; do
    if "${BIN[@]}" export --store "$jdir/j.redb" "$bad" x >/dev/null 2>&1; then
        echo "FAIL: \`export\` accepted the audit-only flag $bad"; exit 1
    fi
done
# And a malformed key is refused with the shape named, not half-parsed.
if "${BIN[@]}" verify "$jdir/history.jsonl" --key not-a-pair >/dev/null 2>&1; then
    echo "FAIL: \`verify\` accepted a --key with no <key-id>=<hex> shape"; exit 1
fi
echo "ok: the audit verbs' evidence flags belong to the audit verbs"
echo "ok: each verb takes only its own flags"

echo "── --strict belongs to replay, not run ──"
# It used to be accepted and ignored, so a reader asking for a *verification*
# replay got an ordinary one and no hint of the difference.
if "${BIN[@]}" run "$YAML" --input '{}' --strict >/dev/null 2>&1; then
    echo "FAIL: \`run\` accepted --strict, which only \`replay\` performs"; exit 1
fi
echo "ok: --strict is a replay flag"

echo "── the two input flags are mutually exclusive ──"
if "${BIN[@]}" run "$YAML" --input '{}' --input-file /dev/null >/dev/null 2>&1; then
    echo "FAIL: --input and --input-file were both accepted"; exit 1
fi
echo "ok: refused, rather than one silently winning"

echo "── admission-key retirement names its own window ──"
# The window has no default on purpose: retiring a key reopens the door it
# closed, so a default would be this crate picking somebody else's retry
# horizon. A verb that silently chose one would be the more dangerous shape.
if "${BIN[@]}" forget-admissions --store "$jdir/j.redb" >/dev/null 2>&1; then
    echo "FAIL: \`forget-admissions\` ran without --older-than-days"; exit 1
fi
out="$("${BIN[@]}" forget-admissions --store "$jdir/j.redb" --older-than-days 30)"
grep -q '"retired"' <<<"$out" || {
    echo "FAIL: the retention pass said nothing, so a growing index looks like a \
quiet one: $out"; exit 1; }
echo "ok: retirement requires a window and reports what it retired"

echo "── every remedy verb names itself, and each refuses a nameless actor ──"
# The half a unit test cannot reach: the guard holds the *lists* together, and
# this holds the parser to them. An operator act a terminal records is
# `asserted`, so the name beside it is the whole of its evidence — a verb that
# took it as optional would write an act attributed to nobody.
for verb in reconcile quarantine tasks decide acknowledge cancel; do
    "${BIN[@]}" "$verb" --help >/dev/null 2>&1 || {
        echo "FAIL: \`$verb\` is named in an \`attention\` remedy and does not exist"; exit 1; }
done
echo "ok: every remedy verb exists"

if "${BIN[@]}" cancel some-run --store "$jdir/j.redb" --reason x >/dev/null 2>&1; then
    echo "FAIL: \`cancel\` recorded an act with nobody named on it"; exit 1
fi
if "${BIN[@]}" decide some-task --store "$jdir/j.redb" --actor a --reason x >/dev/null 2>&1; then
    echo "FAIL: \`decide\` accepted a decision with no verdict"; exit 1
fi
if "${BIN[@]}" quarantine some-run --store "$jdir/j.redb" --actor a --reason x \
        --decision sideways >/dev/null 2>&1; then
    echo "FAIL: \`quarantine\` accepted a decision it cannot make"; exit 1
fi
if "${BIN[@]}" reconcile some-run --store "$jdir/j.redb" --actor a --note n \
        --effect 00 --outcome did-not-happen --output '{}' >/dev/null 2>&1; then
    echo "FAIL: \`reconcile\` accepted a result for an effect that did not happen"; exit 1
fi
echo "ok: each refuses the argument it cannot honestly record"

echo "── a manifest with oversight runs, waits for a person, and finishes ──"
# `run` opens a case for every run, so a declared approval can open its task.
# Without one, the first oversight step failed with "this run has no case" and
# no manifest with `spec.oversight` could run from a terminal at all.
odir="$(mktemp -d -t agentplane-oversight-XXXX)"
APPROVAL="$ROOT/examples/approval.yaml"
set +e
"${BIN[@]}" run "$APPROVAL" --input '{"ticket":"T-1"}' --store "$odir/o.redb" \
    >"$odir/run.out" 2>"$odir/run.err"
code=$?
set -e
[ "$code" = "3" ] || {
    echo "FAIL: a run waiting for a person exited $code, not 3:"; sed 's/^/    /' "$odir/run.err"; exit 1; }
grep -q 'is waiting for a person to decide task_' "$odir/run.err" || {
    echo "FAIL: a suspended run did not say what it waits for:"; sed 's/^/    /' "$odir/run.err"; exit 1; }
grep -q 'agentplane decide task_' "$odir/run.err" || {
    echo "FAIL: a suspended run did not print the command that answers it"; exit 1; }
if grep -q 'Suspended(' "$odir/run.err"; then
    echo "FAIL: a suspended run printed its Debug form"; exit 1
fi
run_id="$(grep -o 'run_[0-9A-Z]*' "$odir/run.err" | head -1)"
task="$("${BIN[@]}" tasks --store "$odir/o.redb" | python3 -c 'import json,sys
t = json.load(sys.stdin)["tasks"]
assert len(t) == 1, t
print(t[0]["task"])')"
"${BIN[@]}" tasks --store "$odir/o.redb" --show "$task" | grep -q '"proposed_action"' || {
    echo "FAIL: tasks --show did not show what is being approved"; exit 1; }
"${BIN[@]}" decide "$task" approve --reason "checked" --actor ada --store "$odir/o.redb" \
    >/dev/null 2>"$odir/decide.err" || {
    echo "FAIL: deciding from a terminal failed:"; sed 's/^/    /' "$odir/decide.err"; exit 1; }
[ "$("${BIN[@]}" tasks --store "$odir/o.redb" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["tasks"]))')" = "0" ] || {
    echo "FAIL: a decided task is still on the worklist"; exit 1; }
out="$("${BIN[@]}" replay "$run_id" --manifest "$APPROVAL" --store "$odir/o.redb" 2>&1)" || {
    echo "FAIL: the approved run did not finish: $out"; exit 1; }
grep -q 'Succeeded' <<<"$out" || { echo "FAIL: the approved run did not succeed: $out"; exit 1; }
rm -rf "$odir"
echo "ok: suspended, listed, decided, resumed, succeeded"

echo "── a strict replay of a waiting run verifies the wait ──"
# A run that recorded a suspension and replays to the same suspension is the
# record reproduced — `0`, not the `3` a resume that stops to wait exits.
wdir="$(mktemp -d -t agentplane-wait-XXXX)"
set +e
"${BIN[@]}" run "$APPROVAL" --input '{"ticket":"T-2"}' --store "$wdir/w.redb" \
    >/dev/null 2>"$wdir/run.err"
set -e
wait_run="$(grep -o 'run_[0-9A-Z]*' "$wdir/run.err" | head -1)"
"${BIN[@]}" tasks --store "$wdir/w.redb" | grep -q '"escaped"' || {
    echo "FAIL: the worklist does not say whether it escaped anything"; exit 1; }
"${BIN[@]}" replay "$wait_run" --manifest "$APPROVAL" --strict --store "$wdir/w.redb" \
    >/dev/null 2>"$wdir/replay.err" || {
    echo "FAIL: a strict replay of a faithfully waiting run did not exit 0:"
    sed 's/^/    /' "$wdir/replay.err"; exit 1; }
grep -q 'verified' "$wdir/replay.err" || {
    echo "FAIL: no verdict:"; sed 's/^/    /' "$wdir/replay.err"; exit 1; }
rm -rf "$wdir"
echo "ok: a reproduced wait is verified"

echo "── a strict replay under an edited manifest names the edit, and calls nobody ──"
rdir="$(mktemp -d -t agentplane-verify-XXXX)"
"${BIN[@]}" run "$YAML" --input '{"ticket":"T-3"}' --store "$rdir/r.redb" \
    >/dev/null 2>"$rdir/run.err"
vrun="$(grep -o 'run_[0-9A-Z]*' "$rdir/run.err" | head -1)"
sed 's/One sentence\./Two sentences./' "$YAML" >"$rdir/edited.yaml"
# The same edit, now naming a real provider — with its credential unset, so a
# strict path that built live drivers would refuse before replaying anything.
sed 's/provider: fake/provider: anthropic/' "$rdir/edited.yaml" >"$rdir/anthropic.yaml"
sed 's/support\.summarise/support.digest/' "$YAML" >"$rdir/renamed.yaml"
cmp -s "$YAML" "$rdir/edited.yaml" && { echo "FAIL: the fixture edit changed nothing"; exit 1; }

"${BIN[@]}" replay "$vrun" --manifest "$YAML" --strict --store "$rdir/r.redb" \
    >/dev/null 2>"$rdir/same.err" || {
    echo "FAIL: a strict replay under the recording manifest did not verify:"
    sed 's/^/    /' "$rdir/same.err"; exit 1; }
grep -q '(same digest)' "$rdir/same.err" || {
    echo "FAIL: a verified replay did not name its revision:"; sed 's/^/    /' "$rdir/same.err"; exit 1; }

set +e
env -u ANTHROPIC_API_KEY "${BIN[@]}" replay "$vrun" --manifest "$rdir/anthropic.yaml" \
    --strict --store "$rdir/r.redb" >/dev/null 2>"$rdir/edit.err"
code=$?
set -e
[ "$code" = "1" ] || {
    echo "FAIL: a diverging strict replay exited $code, not 1:"; sed 's/^/    /' "$rdir/edit.err"; exit 1; }
grep -q 'first divergence: step s0' "$rdir/edit.err" && grep -q '(different digest)' "$rdir/edit.err" || {
    echo "FAIL: the divergence named no step or no second digest:"; sed 's/^/    /' "$rdir/edit.err"; exit 1; }
if grep -q 'ANTHROPIC_API_KEY' "$rdir/edit.err"; then
    echo "FAIL: a strict replay asked for a provider credential"; exit 1
fi

set +e
"${BIN[@]}" replay "$vrun" --manifest "$rdir/renamed.yaml" --strict --store "$rdir/r.redb" \
    >/dev/null 2>"$rdir/gone.err"
code=$?
set -e
[ "$code" = "5" ] && grep -q 'cannot replay: entry point removed' "$rdir/gone.err" || {
    echo "FAIL: a replay the plane cannot make exited $code, or was not named:"
    sed 's/^/    /' "$rdir/gone.err"; exit 1; }

if "${BIN[@]}" replay "$vrun" --manifest "$YAML" --strict --store "$rdir/r.redb" \
        --mcp tickets=true >/dev/null 2>&1; then
    echo "FAIL: --strict accepted --mcp, which could only start a server"; exit 1
fi

edir="$(mktemp -d -t agentplane-corpus-XXXX)"
"${BIN[@]}" export --store "$rdir/r.redb" >"$edir/runs.jsonl" 2>/dev/null
set +e
env -u ANTHROPIC_API_KEY "${BIN[@]}" replay --manifest "$rdir/anthropic.yaml" --strict \
    --from "$edir/runs.jsonl" >/dev/null 2>"$rdir/export.err"
code=$?
set -e
[ "$code" = "1" ] && grep -q "run $vrun — diverged" "$rdir/export.err" || {
    echo "FAIL: a corpus replay from an export exited $code:"; sed 's/^/    /' "$rdir/export.err"; exit 1; }
[ "$(ls "$edir")" = "runs.jsonl" ] || {
    echo "FAIL: replaying an export wrote a store beside it: $(ls "$edir")"; exit 1; }
rm -rf "$rdir" "$edir"
echo "ok: verified 0, diverged 1 with both digests, cannot replay 5, from an export, no credential"

echo "── init writes a manifest that validates ──"
idir="$(mktemp -d -t agentplane-init-XXXX)"
"${BIN[@]}" init "$idir/agent.yaml" >/dev/null 2>&1 || { echo "FAIL: init failed"; exit 1; }
"${BIN[@]}" validate "$idir/agent.yaml" >/dev/null || {
    echo "FAIL: the starter manifest does not validate"; exit 1; }
grep -q 'yaml-language-server: \$schema=' "$idir/agent.yaml" || {
    echo "FAIL: the starter carries no schema modeline"; exit 1; }
grep -q 'budgets:' "$idir/agent.yaml" || { echo "FAIL: the starter states no budget"; exit 1; }
"${BIN[@]}" init "$idir/tools.yaml" --tools --name desk >/dev/null 2>&1
"${BIN[@]}" validate "$idir/tools.yaml" >/dev/null || {
    echo "FAIL: the tool-calling starter does not validate"; exit 1; }
if "${BIN[@]}" init "$idir/agent.yaml" >/dev/null 2>&1; then
    echo "FAIL: init overwrote an existing file"; exit 1
fi
rm -rf "$idir"
echo "ok: both starters validate, and neither overwrites a file"

echo "── the listings are subcommands of the verbs they list ──"
"${BIN[@]}" halt list --store "$jdir/j.redb" --json | grep -q '"halts"' || {
    echo "FAIL: halt list --json did not list"; exit 1; }
"${BIN[@]}" halt list --store "$jdir/j.redb" | grep -q 'no halts standing' || {
    echo "FAIL: halt list did not answer in text"; exit 1; }
"${BIN[@]}" hold list --store "$jdir/j.redb" | grep -q '"holds"' || {
    echo "FAIL: hold list did not list"; exit 1; }
"${BIN[@]}" retention plan --store "$jdir/j.redb" --older-than-days 30 | grep -q '"would_erase"' || {
    echo "FAIL: retention plan did not say what a pass would erase"; exit 1; }
if "${BIN[@]}" hold --store "$jdir/j.redb" >/dev/null 2>&1; then
    echo "FAIL: hold with no --case did something"; exit 1
fi
echo "ok: halt list, hold list, retention plan"

echo "── a peer is reached, on somebody's behalf ──"
# A peer call needs a chain. Without --acting-as the call was refused inside the
# run, reported to the model as a tool failure, and the run exited zero with the
# peer never asked — so the flag is required, and a stub peer must see the call.
PEERBIN=(cargo run -q --features cli,a2a,testkit --bin agentplane --)
pdir="$(mktemp -d -t agentplane-peer-XXXX)"
cat >"$pdir/desk.yaml" <<'YAML'
apiVersion: agentplane.hupe1980.github.io/v1alpha1
kind: Agent
metadata: { name: desk, version: "1.0.0" }
spec:
  execution: { kind: tool-calling, max_turns: 3 }
  identity: { role: "Ask the reviewer to check an invoice", constraints: "One sentence." }
  topology: { mode: collaborative, role: orchestrator, reason: distinct-authority }
  security: { max_delegation_depth: 1, max_sensitivity_egress: internal }
  model: { provider: fake, model: m-1 }
  tools:
    - ref: tool://reviewer/audit.check
      mutates: false
      max_sensitivity: internal
      description: Ask the reviewer to check an invoice.
      arguments:
        type: object
        additionalProperties: false
        required: [invoice]
        properties: { invoice: { type: string } }
  budgets: { max_tokens: 1000 }
YAML
cat >"$pdir/peer.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class Peer(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with open(sys.argv[1], "a") as f:
            f.write(json.dumps(body) + "\n")
        raw = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": {"message": {
            "role": "ROLE_AGENT", "messageId": "reply-1",
            "parts": [{"data": {"verdict": "ok"}, "mediaType": "application/json"}]}}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self, *_):
        pass
server = HTTPServer(("127.0.0.1", 0), Peer)
print(server.server_address[1], flush=True)
server.serve_forever()
PY
python3 "$pdir/peer.py" "$pdir/asked.log" >"$pdir/port" &
peer_pid=$!
for _ in $(seq 50); do [ -s "$pdir/port" ] && break; sleep 0.1; done
port="$(cat "$pdir/port")"
if "${PEERBIN[@]}" run "$pdir/desk.yaml" --input '{"invoice":"INV-9"}' \
        --peer "reviewer=http://127.0.0.1:$port/" >/dev/null 2>&1; then
    kill "$peer_pid"; echo "FAIL: --peer ran with no chain to call it under"; exit 1
fi
"${PEERBIN[@]}" run "$pdir/desk.yaml" --input '{"invoice":"INV-9"}' \
    --peer "reviewer=http://127.0.0.1:$port/" --acting-as alice >/dev/null 2>"$pdir/run.err" || {
    kill "$peer_pid"; echo "FAIL: the peer run failed:"; sed 's/^/    /' "$pdir/run.err"; exit 1; }
kill "$peer_pid"
grep -q '"SendMessage"' "$pdir/asked.log" 2>/dev/null || {
    echo "FAIL: the run succeeded and the peer was never asked"; exit 1; }
rm -rf "$pdir"
echo "ok: refused without a chain; with one, the peer saw the request"

echo "── one table of exit statuses ──"
# A scheduler reads the status and nothing else: a finding, a refused command,
# an outage and a partial answer each have their own number, and `--help` says
# which is which.
status() { set +e; "$@" >/dev/null 2>&1; echo $?; set -e; }
"${BIN[@]}" --help | grep -q '5  partial' || { echo "FAIL: --help prints no exit table"; exit 1; }
"${BIN[@]}" --version | grep -q '^features: .*cli' || {
    echo "FAIL: --version does not name the compiled features"; exit 1; }
[ "$(status "${BIN[@]}" validate "$YAML" --require-annotation example.com/nobody)" = "1" ] || {
    echo "FAIL: a missing annotation is not a finding (1)"; exit 1; }
[ "$(status "${BIN[@]}" quarantine some-run --store "$jdir/j.redb" --actor a --reason x --decision sideways)" = "2" ] || {
    echo "FAIL: a refused argument is not a usage error (2)"; exit 1; }
[ "$(status "${BIN[@]}" halt --lift --store "$jdir/j.redb")" = "1" ] || {
    echo "FAIL: a lift that found nothing standing exited as a success"; exit 1; }
[ "$(status "${BIN[@]}" export --store /nonexistent/agentplane/j.redb)" = "4" ] || {
    echo "FAIL: a store that cannot be opened is not an operational error (4)"; exit 1; }
set +e
"${BIN[@]}" export --store "$jdir/j.redb" --limit 0 >"$jdir/partial.jsonl" 2>/dev/null
code=$?
set -e
[ "$code" = "5" ] || { echo "FAIL: a truncated export exited $code, not 5"; exit 1; }
[ ! -s "$jdir/partial.jsonl" ] || { echo "FAIL: a refused partial export wrote a file"; exit 1; }
[ "$(status "${BIN[@]}" export --store "$jdir/j.redb" --limit 0 --allow-partial)" = "5" ] || {
    echo "FAIL: an allowed partial export does not say it is partial"; exit 1; }
set +e
"${BIN[@]}" audit --store "$jdir/j.redb" --limit 0 >"$jdir/partial.json" 2>/dev/null
code=$?
set -e
[ "$code" = "5" ] || { echo "FAIL: an audit over a truncated list exited $code, not 5"; exit 1; }
python3 -c 'import json,sys; t = json.load(open(sys.argv[1]))["truncated"]; assert t["reached"], t' \
    "$jdir/partial.json" || { echo "FAIL: the audit report does not say it was truncated"; exit 1; }
echo "ok: finding 1, usage 2, operational 4, partial 5 — and a partial export is refused"

echo
echo "the CLI runs an agent that is only a file"
