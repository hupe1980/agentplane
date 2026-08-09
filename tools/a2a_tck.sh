#!/usr/bin/env bash
#
# Run the official A2A conformance kit against this crate's server.
#
# Every other A2A test in this repository drives this server with this crate's
# own client, or with requests written from this crate's reading of the spec.
# That proves symmetry, not conformance — a client and server written from the
# same misreading agree everywhere, including where both are wrong. This script
# is the outside authority: the protocol project's own pytest suite
# (https://github.com/a2aproject/a2a-tck), spoken at a live socket.
#
# Its first run earned its keep: the JSON-RPC endpoint 404ed the
# trailing-slash URL every httpx-based client produces, contextId was absent
# from tasks, protocol errors carried no ErrorInfo, a wrong Content-Type was
# answered as a parse error, and the extended card failed the spec's schema.
# None of those was reachable by an in-repo test, because every in-repo client
# shared the server's reading.
#
# Network-gated like `test-live`: it clones and installs somebody else's
# repository. Kept out of `ci` for that reason, and cached under .tck-cache so
# a re-run costs nothing but the tests. Prefers host `uv` over a container
# because the kit publishes no image — a docker build would run the same
# pip-over-network with an extra layer of indirection.
#
# Usage:  tools/a2a_tck.sh [extra pytest args]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${ROOT}/.tck-cache"
TCK_REPO="https://github.com/a2aproject/a2a-tck.git"
ADDR="${A2A_TCK_ADDR:-127.0.0.1:9999}"

# Rows excluded with the evidence rather than silently. Two classes.
#
# (1) Two rows contradict themselves: each *titles* a required error
# (ContentTypeNotSupportedError; "agent rejects unacceptable contextId") while
# setting no `expected_error`, so its validator demands success for a request
# its own description says MUST fail. This server returns the error the titles
# require.
#
# (2) Six rows are blocked by a defect in the kit's own JSON-RPC client, and
# the evidence is the specification the kit ships in the same repository.
# `specification.md` §5.5 states that all JSON serializations of the A2A data
# model **MUST** use camelCase field names, "not the snake_case convention used
# in Protocol Buffer definitions" — and §9.4.4's own worked example sends
# `{"contextId": ..., "pageSize": ...}`. `tck/transport/jsonrpc_client.py`
# sends `context_id`, `page_size`, `include_artifacts` and `task_id`.
#
# This server refuses those, which is why the rows fail. Accepting them would
# be accepting a spelling the specification forbids — the same reason the
# version header and the method names are exact here.
#
# Worth knowing what the exclusion cost and what it bought, because the pass
# count went *down*: the five CORE-LIST rows previously **passed vacuously**.
# The server used to ignore an unrecognised parameter, so a request whose
# `contextId` filter was spelled `context_id` had no filter at all and answered
# with every task the caller could see — shaped exactly like the scoped list the
# row asked for, so the row could not fail. Refusing unknown parameters is what
# turned five silent passes into five honest failures against a kit bug.
#
# All eight are worth an upstream issue; a kit release that fixes the client
# makes six of these lines deletable and should raise the floor by five.
DESELECT=(
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-SEND-003-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-MULTI-002a-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-001-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-002-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-003-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-004-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-005-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_push_notifications.py::TestPushNotificationCrud::test_create_push_config[jsonrpc]"
)

command -v uv >/dev/null || { echo "uv is required (https://docs.astral.sh/uv/)"; exit 2; }

# ── The kit ─────────────────────────────────────────────────────────────────
mkdir -p "$CACHE"
if [[ ! -d "${CACHE}/a2a-tck/.git" ]]; then
    git clone --depth 1 "$TCK_REPO" "${CACHE}/a2a-tck"
fi
cd "${CACHE}/a2a-tck"
if [[ ! -d .venv ]]; then
    uv venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
uv pip install -q -e .

# ── The server under test ───────────────────────────────────────────────────
cd "$ROOT"
cargo build --example a2a_tck_live --features redb,a2a-server,manifest,testkit
A2A_TCK_ADDR="$ADDR" ./target/debug/examples/a2a_tck_live &
SUT_PID=$!
trap 'kill "$SUT_PID" 2>/dev/null || true' EXIT

# The kit fetches the card in a session-scoped fixture, so a server that is
# not up yet fails every test in one incomprehensible cascade.
for _ in $(seq 1 50); do
    curl -fsS "http://${ADDR}/.well-known/agent-card.json" >/dev/null 2>&1 && break
    sleep 0.2
done
curl -fsS "http://${ADDR}/.well-known/agent-card.json" >/dev/null \
    || { echo "the fixture never came up on ${ADDR}"; exit 2; }

# ── The verdict ─────────────────────────────────────────────────────────────
# pytest directly rather than run_tck.py, so the exclusions above apply and
# the exit code is the verdict. `-m must` is the release bar: MUSTs are hard
# failures; SHOULD/MAY are reported by the kit's own tooling when wanted.
#
# `-rs` because the exit code alone is not the verdict it looks like: a MUST row
# the kit *skips* is counted neither passed nor failed, so it reads exactly like
# one that passed. This bit — STREAM-SUB-002 ("stream closes at terminal state")
# skipped on the kit's own client timeout for a release, while the server was in
# fact correct: reproduced by hand, the subscription emits the terminal
# TASK_STATE_COMPLETED and closes in about two seconds. The row was neither
# passing nor failing, and nothing said so. This is the same standard
# `mutants.py --verify` already applies to itself — distinguish *survived* from
# *never ran* — applied to the conformance kit.
cd "${CACHE}/a2a-tck"
set +e
./.venv/bin/python3 -m pytest tests/compatibility/ \
    --sut-host "http://${ADDR}" --transport jsonrpc -m must -rs -q \
    "${DESELECT[@]}" "$@" 2>&1 | tee "${CACHE}/last-run.txt"
STATUS=${PIPESTATUS[0]}
set -e
[[ $STATUS -eq 0 ]] || exit "$STATUS"

# A floor, not an exact count: the kit gains rows between releases and a new
# *passing* row must not be a failure here. A row that stops passing must be.
PASSED=$(sed -n 's/^\([0-9]\{1,\}\) passed.*/\1/p' "${CACHE}/last-run.txt" | tail -1)
# 77 until push was wired and unknown parameters started being refused. Both
# moved it, in opposite directions and for opposite reasons, so the composition
# matters more than the number: +4 real push rows (including all three
# *delivery* rows — that the agent POSTs, carries its auth, and sends a
# StreamResponse), −3 rows that could only pass while push was absent, and −5
# CORE-LIST rows that had been passing over a filter the server silently
# dropped. Lowering a floor is normally the wrong move; here the rows it lets go
# were never checking anything, and the comment beside DESELECT says which.
EXPECTED_MIN=73
if [[ -z "$PASSED" ]]; then
    echo "REFUSED: could not read a pass count from the kit's output — a run that" >&2
    echo "         asserted nothing reports no failures and reads like success" >&2
    exit 1
fi
if (( PASSED < EXPECTED_MIN )); then
    echo "REFUSED: ${PASSED} MUST rows passed, down from ${EXPECTED_MIN}." >&2
    echo "         A row that stopped passing skips silently — read the SKIPPED" >&2
    echo "         lines above and find which one, rather than lowering this." >&2
    exit 1
fi
echo "ok: ${PASSED} MUST-level rows passed (floor ${EXPECTED_MIN}); skips listed above"
echo "    Skipped rows are not passing rows. The standing ones are: the two"
echo "    unconfigured transports, the errors only an agent *without* streaming"
echo "    or push could raise, the five push rows the kit's snake_case client"
echo "    cannot get past CreateTaskPushNotificationConfig (see DESELECT), and"
echo "    STREAM-SUB-002's client-side timeout, checked by hand and correct on"
echo "    the server. Push itself is wired now: the three PUSH-DELIVER rows run"
echo "    against a real webhook receiver."
