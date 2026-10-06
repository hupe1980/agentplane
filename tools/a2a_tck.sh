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
# (3) Five rows need a fresh task left waiting for input, and the kit cannot
# make one twice: `tck_id` mints one message id per session, so every such
# task is sent as the same `messageId`. The specification the kit ships lets an
# agent read that as a retransmit — §"Send Message operations MAY be
# idempotent. Agents may utilize the messageId to detect duplicate messages" —
# and this one does, so after the first multi-turn row continues the shared
# task to completion, each later row is handed that completed task and skips.
#
# Each is worth an upstream issue. A kit release that fixes the client, or
# mints a message id per task, makes its lines deletable — and the rows they
# free raise the floor.
DESELECT=(
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-SEND-003-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-MULTI-002a-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-001-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-002-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-003-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-004-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-LIST-005-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_push_notifications.py::TestPushNotificationCrud::test_create_push_config[jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_task_history.py::TestHistoryLengthLimit::test_get_task_history_does_not_exceed_limit[jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_task_lifecycle.py::TestCancelTask::test_cancel_task_returns_updated_state[jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_task_lifecycle.py::TestMultiTurn::test_infer_context_from_task[jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_task_lifecycle.py::TestSubscribeLifecycle::test_subscribe_terminates_at_terminal_state[jsonrpc]"
    --deselect "tests/compatibility/jsonrpc/test_sse_streaming.py::TestSseSubscribeToTask::test_subscribe_first_event_is_task[jsonrpc]"
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
# one that passed. The skip lines are how one is noticed — the standard
# `mutants.py --verify` applies to itself, *survived* versus *never ran*.
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
# What this kit revision measures with the rows above deselected. A deselected
# row is excluded with its evidence; it is never counted as passing.
EXPECTED_MIN=70
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
echo "    cannot get past CreateTaskPushNotificationConfig (see DESELECT)."
echo "    Push itself is wired: the three PUSH-DELIVER rows run against a real"
echo "    webhook receiver."
