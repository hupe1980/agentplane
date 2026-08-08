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

# Two of the kit's MUST rows contradict themselves, and are excluded with the
# evidence rather than silently: each *titles* a required error
# (ContentTypeNotSupportedError; "agent rejects unacceptable contextId") while
# setting no `expected_error`, so its validator demands success for a request
# its own description says MUST fail. This server returns the error the titles
# require. Worth an upstream issue; a kit release that fixes them makes these
# two lines deletable.
DESELECT=(
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-SEND-003-jsonrpc]"
    --deselect "tests/compatibility/core_operations/test_requirements.py::test_must_requirement[CORE-MULTI-002a-jsonrpc]"
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
cargo build --example a2a_tck_live --features redb,a2a-server,manifest
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
EXPECTED_MIN=77
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
echo "    unconfigured transports, the errors only a non-streaming agent can"
echo "    raise, the ten push rows (this fixture wires no --push-host, and"
echo "    PushSender refuses a non-public webhook host by design, so the kit"
echo "    cannot reach them from localhost), and STREAM-SUB-002's client-side"
echo "    timeout, checked by hand and correct on the server."
