#!/usr/bin/env bash
#
# Drive the generated Python client against a running plane.
#
# The wire suite validates every answer against the published document, but
# in-process, with a test authenticator. This is the shipped binary on a real
# socket with the shipped token authenticator and policy, called through the
# client a generator built from the document alone — so a document that does
# not describe what ships fails here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "── build the binary that serves ──"
cargo build -q --features cli,a2a-server,cedar --bin agentplane
BIN="$ROOT/target/debug/agentplane"

work="$(mktemp -d -t agentplane-client-XXXX)"
pid=""
cleanup() {
    [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

token() { python3 -c 'import secrets; print(secrets.token_hex(32))'; }
PEER_TOKEN="$(token)"
OPS_TOKEN="$(token)"
APP_TOKEN="$(token)"
sed -e "s/replace-me:peer-a:openssl-rand-hex-32/$PEER_TOKEN/" \
    -e "s/replace-me:ops-alice:openssl-rand-hex-32/$OPS_TOKEN/" \
    -e "s/replace-me:app-1:openssl-rand-hex-32/$APP_TOKEN/" \
    examples/serve-tokens.yaml >"$work/tokens.yaml"

# Ports are reserved by binding and closing, so another process can take one
# before serve binds it. A serve that could not bind is retried on fresh ports;
# any other exit, or a socket that never answers, fails.
free_ports() {
    python3 -c '
import socket
socks = [socket.socket() for _ in range(2)]
for s in socks: s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))
for s in socks: s.close()'
}

up=""
for attempt in 1 2 3; do
    read -r A2A_PORT OPS_PORT < <(free_ports)
    echo "── serve, with an operator socket on $OPS_PORT ──"
    rm -f "$work/plane.redb"
    "$BIN" serve examples/served.yaml \
        --addr "127.0.0.1:$A2A_PORT" --url "http://127.0.0.1:$A2A_PORT/a2a" \
        --policy examples/serve-policy.cedar --tokens "$work/tokens.yaml" \
        --operator-addr "127.0.0.1:$OPS_PORT" --store "$work/plane.redb" \
        >"$work/serve.log" 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        if python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', $OPS_PORT), 0.2)" 2>/dev/null; then
            up=yes
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    [ -n "$up" ] && break
    if ! kill -0 "$pid" 2>/dev/null && grep -q 'could not bind' "$work/serve.log"; then
        wait "$pid" 2>/dev/null || true
        pid=""
        echo "   a port was taken before serve bound it; retrying ($attempt)"
        continue
    fi
    if kill -0 "$pid" 2>/dev/null; then
        echo "FAIL: serve never came up on 127.0.0.1:$OPS_PORT"
    else
        echo "FAIL: serve exited at startup"
    fi
    cat "$work/serve.log"
    exit 1
done
[ -n "$up" ] || { echo "FAIL: serve never came up: every port tried was taken"; cat "$work/serve.log"; exit 1; }

echo "── an incident, through the generated client ──"
if ! OPS_URL="http://127.0.0.1:$OPS_PORT" OPS_TOKEN="$OPS_TOKEN" PEER_TOKEN="$PEER_TOKEN" \
    PYTHONPATH="$ROOT/clients/python" python3 - <<'EOF'
import json
import os
import pathlib

from agentplane_operator import Client, OperatorError

document = json.loads(pathlib.Path("site/static/openapi.json").read_text())
schemas = document["components"]["schemas"]


def resolve(schema):
    while "$ref" in schema:
        schema = schemas[schema["$ref"].rsplit("/", 1)[1]]
    return schema


KINDS = {"number": (int, float), "object": dict, "array": list, "string": str, "boolean": bool, "integer": int, "null": type(None)}


def shaped(value, schema, where):
    """The documented `type` and `required` members, recursively; not a full validator."""
    schema = resolve(schema)
    types = schema.get("type")
    if types is not None:
        types = types if isinstance(types, list) else [types]
        if not any(isinstance(value, KINDS[t]) and not (t == "integer" and isinstance(value, bool)) for t in types):
            raise AssertionError(f"{where}: {value!r} is not {types}")
    if isinstance(value, dict):
        missing = [m for m in schema.get("required", []) if m not in value]
        assert not missing, f"{where}: missing {missing}"
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(schema.get("properties", {}))
            assert not extra, f"{where}: undocumented {sorted(extra)}"
        for name, member in schema.get("properties", {}).items():
            if name in value:
                shaped(value[name], member, f"{where}.{name}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            shaped(item, schema["items"], f"{where}[{i}]")


def answer(path, method, status, value):
    response = document["paths"][path][method]["responses"][str(status)]
    shaped(value, response["content"]["application/json"]["schema"], f"{method.upper()} {path} {status}")


def refused(call, status, path, method):
    try:
        call()
    except OperatorError as error:
        assert error.status == status, f"{method.upper()} {path}: {error.status} {error.error}"
        assert str(status) in document["paths"][path][method]["responses"], f"{status} undocumented"
        assert error.error.strip(), "a refusal with no sentence"
        return error
    raise AssertionError(f"{method.upper()} {path} answered where {status} was documented")


url = os.environ["OPS_URL"]
plane = Client(url, token=os.environ["OPS_TOKEN"])

runs = plane.list_runs()
answer("/runs", "get", 200, runs)
print("ok: list_runs", runs["outcome"], len(runs["runs"]))

halt = plane.place_halt({"scope": "tenant", "reason": "client smoke"})
answer("/halts", "post", 200, halt)
assert halt["halted"] is True and halt["by"] == "ops-alice", halt

halts = plane.list_halts()
answer("/halts", "get", 200, halts)
assert [h["scope"] for h in halts["halts"]] == ["tenant"], halts

lifted = plane.lift_halt({"scope": "tenant"})
answer("/halts/lift", "post", 200, lifted)
assert lifted["was_standing"] is True, lifted
assert plane.list_halts()["halts"] == []
print("ok: a halt thrown, listed and lifted")

refused(lambda: Client(url).list_runs(), 401, "/runs", "get")
print("ok: no token is 401")
refused(lambda: Client(url, token=os.environ["PEER_TOKEN"]).list_halts(), 403, "/halts", "get")
print("ok: a peer token on an operator route is 403")
error = refused(
    lambda: plane.place_halt({"scope": "tenant", "reason": "x", "actor": "somebody-else"}),
    422,
    "/halts",
    "post",
)
assert "actor" in error.error, error.error
print("ok: an unknown member is 422 with the documented error:", error.error[:80])
EOF
then
    echo "FAIL: the generated client and the running plane disagree"
    cat "$work/serve.log"
    exit 1
fi
echo "ok: the generated client drove a running plane"
