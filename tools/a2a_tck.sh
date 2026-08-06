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
cd "${CACHE}/a2a-tck"
./.venv/bin/python3 -m pytest tests/compatibility/ \
    --sut-host "http://${ADDR}" --transport jsonrpc -m must -q \
    "${DESELECT[@]}" "$@"
