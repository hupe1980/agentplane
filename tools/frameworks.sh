#!/usr/bin/env bash
#
# Walk every framework quickstart through the plane `init --serve` writes, and
# render the Helm chart's accept and refuse cases.
#
# What it proves: the published commands work from the `:full` image; each
# quickstart's lock is what its requirements resolve to, and installs only with
# every hash matching; each framework's own client reaches a governed call,
# read back from the operator listener as a succeeded run admitted by the
# caller the quickstart used (`framework-1` over MCP, `peer-1` over A2A); every
# port is bound to loopback, no token is in the plane's environment and no
# secret on its command line; and the chart renders the plane's security
# posture and refuses what it must.
#
# Outside `just ci`, like `docker-smoke` and `test-a2a-tck`: it needs Docker,
# `uv`, the network (PyPI, the Postgres image) and `helm` — or Docker to run it.
# It holds no credential: CI runs it in a job with read-only contents and no
# registry login, before anything is tagged or signed.
#
#   IMAGE=ghcr.io/…@sha256:…  test that image instead of building one
#   FEATURES=…                the features to build with (default: the justfile's)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/agentplane"
FW="$ROOT/examples/frameworks"
tmp_lock="$(mktemp -t agentplane-lock-XXXX)"
trap 'rm -f "$tmp_lock"' EXIT

# ── The chart ───────────────────────────────────────────────────────────────
if command -v helm >/dev/null 2>&1; then
  helm() { command helm "$@"; }
else
  helm() { docker run --rm -v "$ROOT:$ROOT:ro" -w "$ROOT" alpine/helm:3.18.4 "$@"; }
fi
# The chart's inputs are the files `init --serve` writes; these are their sources.
files=(--set-file "manifest=$ROOT/examples/served-starter.yaml"
       --set-file "policy=$ROOT/examples/serve-policy.cedar")
required=("${files[@]}" --set tokens.existingSecret=agentplane-tokens
          --set storeSecret.existingSecret=agentplane-store)

echo "==> helm lint"
helm lint "$CHART" "${required[@]}" >/dev/null

echo "==> the chart renders the plane's posture"
rendered="$(helm template plane "$CHART" "${required[@]}")"
expect() { grep -qE -- "$1" <<<"$rendered" || { echo "REFUSED: the chart does not render $2"; exit 1; }; }
expect 'runAsNonRoot: true' "a non-root pod"
expect 'readOnlyRootFilesystem: true' "a read-only root filesystem"
expect 'allowPrivilegeEscalation: false' "a pod that cannot escalate"
expect 'secretName: agentplane-tokens' "the token file from the named Secret"
expect 'path: /.well-known/agent-card.json' "readiness on the Agent Card"
expect 'name: AGENTPLANE_STORE' "the store from the named Secret"
grep -q -- '--store=' <<<"$rendered" && { echo "REFUSED: a Secret-held store renders into the pod's args"; exit 1; }
grep -q 'sessionAffinity' <<<"$rendered" && { echo "REFUSED: one replica renders session affinity"; exit 1; }
grep -q 'sessionAffinity: ClientIP' <<<"$(helm template plane "$CHART" "${required[@]}" --set replicas=2)" ||
  { echo "REFUSED: two replicas render no MCP session affinity"; exit 1; }
# The operator port belongs to its own ClusterIP Service and to no other.
python3 - "$rendered" <<'PY' || exit 1
import sys
docs = [d for d in sys.argv[1].split("\n---") if "\nkind: Service\n" in "\n" + d + "\n"]
operator = [d for d in docs if "-operator\n" in d]
public = [d for d in docs if d not in operator]
if len(docs) != 2 or len(operator) != 1:
    sys.exit(f"REFUSED: the chart renders {len(docs)} Services, {len(operator)} for the operator")
if "type: ClusterIP" not in operator[0] or "port: 9090" not in operator[0]:
    sys.exit("REFUSED: the operator Service is not ClusterIP on 9090")
if "9090" in public[0]:
    sys.exit("REFUSED: the public Service exposes the operator port")
PY
grace="$(grep -oE 'terminationGracePeriodSeconds: [0-9]+' <<<"$rendered" | grep -oE '[0-9]+$')"
drain="$(grep -oE -- '--drain-secs=[0-9]+' <<<"$rendered" | grep -oE '[0-9]+$')"
[ "$grace" -gt "$drain" ] || { echo "REFUSED: grace ${grace}s does not exceed the ${drain}s drain"; exit 1; }
# A sentinel planted where a careless template would render a credential from:
# it must reach no rendered object, and the ConfigMap holds the two files only.
sentinel="sentinel-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
planted="$(helm template plane "$CHART" "${required[@]}" --set "tokens.token=$sentinel" \
  --set "storeSecret.store=postgres://agentplane:$sentinel@postgres/agentplane")"
grep -qF -- "$sentinel" <<<"$planted" && { echo "REFUSED: the chart renders a value planted beside the token Secret"; exit 1; }
python3 - "$rendered" <<'PY' || exit 1
import sys
maps = [d for d in sys.argv[1].split("\n---") if "\nkind: ConfigMap\n" in "\n" + d + "\n"]
if len(maps) != 1:
    sys.exit(f"REFUSED: the chart renders {len(maps)} ConfigMaps")
data = maps[0].split("\ndata:\n", 1)[1]
keys = sorted(l.split(":")[0].strip() for l in data.splitlines() if l.startswith("  ") and not l.startswith("    "))
if keys != ["agent.yaml", "policy.cedar"]:
    sys.exit(f"REFUSED: the ConfigMap carries {keys}")
PY

refuses() {
  local why="$1" message="$2"; shift 2
  local out
  if out="$(helm template plane "$CHART" "$@" 2>&1)"; then
    echo "REFUSED: the chart rendered $why"; exit 1
  fi
  grep -q -- "$message" <<<"$out" || { echo "REFUSED: rendering $why failed for another reason: $out"; exit 1; }
}
echo "==> the chart refuses a shared redb plane, a missing input, and a password in args"
refuses "two replicas on redb" "Postgres" "${files[@]}" --set tokens.existingSecret=t --set store=/data/plane.redb --set replicas=2
refuses "no token Secret" "tokens.existingSecret" "${files[@]}" --set storeSecret.existingSecret=s
refuses "no store" "a store is required" "${files[@]}" --set tokens.existingSecret=t
refuses "two stores" "name two stores" "${required[@]}" --set store=/data/plane.redb
refuses "a password in store" "store holds a password" "${files[@]}" --set tokens.existingSecret=t --set 'store=postgres://agentplane:pw@postgres/agentplane'
refuses "no manifest" "manifest is required" --set-file "policy=$ROOT/examples/serve-policy.cedar" --set tokens.existingSecret=t --set storeSecret.existingSecret=s
refuses "no policy" "policy is required" --set-file "manifest=$ROOT/examples/served-starter.yaml" --set tokens.existingSecret=t --set storeSecret.existingSecret=s

# ── The locks ───────────────────────────────────────────────────────────────
# Each lock is what its requirements resolve to: re-resolved with the lock as
# the preference, so an unchanged requirements.txt reproduces it byte for byte.
for dir in "$FW"/*/; do
  name="$(basename "$dir")"
  echo "==> $name: requirements.lock matches requirements.txt"
  cp "$dir/requirements.lock" "$tmp_lock"
  (cd "$dir" && uv pip compile --quiet --universal --python-version 3.12 --generate-hashes \
     requirements.txt -o "$tmp_lock" >/dev/null)
  sed 1,2d "$tmp_lock" | diff -u <(sed 1,2d "$dir/requirements.lock") - ||
    { echo "REFUSED: $name/requirements.lock is not what requirements.txt resolves to; regenerate it (header line 2)"; exit 1; }
done

# ── The plane ───────────────────────────────────────────────────────────────
if [ -z "${IMAGE:-}" ]; then
  IMAGE=agentplane:full
  echo "==> building $IMAGE"
  docker build --build-arg "FEATURES=${FEATURES:?FEATURES or IMAGE must be set}" -t "$IMAGE" "$ROOT"
fi

work="$(mktemp -d -t agentplane-frameworks-XXXX)"
project="agentplane-frameworks-$$"
compose=(docker compose -p "$project" -f "$work/plane/compose.yaml" -f "$work/image.yaml")
cleanup() {
  status=$?
  rm -f "$tmp_lock"
  if [ "$status" != 0 ] && [ -f "$work/plane/compose.yaml" ]; then
    "${compose[@]}" logs --no-color plane 2>/dev/null | tail -n 80 || true
  fi
  [ -f "$work/plane/compose.yaml" ] && "${compose[@]}" down -v >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

echo "==> init --serve, as the published command runs it"
docker run --rm --user "$(id -u):$(id -g)" -v "$work:/work" "$IMAGE" init --serve plane >/dev/null
# The written file names the release image; this run tests $IMAGE.
printf 'services:\n  plane:\n    image: %s\n' "$IMAGE" >"$work/image.yaml"

echo "==> docker compose up --wait"
"${compose[@]}" up --wait --quiet-pull

token() { awk -v who="$1" '
  /token:/ { gsub(/[" ]/, "", $0); sub(/^-?token:/, "", $0); t = $0 }
  /actor:/ { if ($2 == who) print t }' "$work/plane/tokens.yaml"; }
FRAMEWORK_TOKEN="$(token framework-1)"
PEER_TOKEN="$(token peer-1)"
OPS_TOKEN="$(token ops-1)"
[ "$FRAMEWORK_TOKEN" = "$(cat "$work/plane/framework.token")" ] ||
  { echo "REFUSED: framework.token is not the framework caller's token"; exit 1; }
[ -n "${GITHUB_ACTIONS:-}" ] && for t in "$FRAMEWORK_TOKEN" "$PEER_TOKEN" "$OPS_TOKEN"; do echo "::add-mask::$t"; done

for _ in $(seq 1 60); do
  curl -sf -o /dev/null http://127.0.0.1:8080/.well-known/agent-card.json && break
  sleep 1
done

echo "==> every port is on loopback, no token is in the environment, no secret on a command line"
cid="$("${compose[@]}" ps -q plane)"
bound="$(docker inspect --format '{{range $p, $b := .HostConfig.PortBindings}}{{$p}}={{range $b}}{{.HostIp}} {{end}};{{end}}' "$cid")"
for port in 8080 8081 9090; do
  grep -qE "(^|;)$port/tcp=127\.0\.0\.1 ;" <<<"$bound" || { echo "REFUSED: port $port is bound as $bound"; exit 1; }
done
env_dump="$(docker inspect --format '{{range .Config.Env}}{{.}} {{end}}' "$cid")"
for t in "$FRAMEWORK_TOKEN" "$PEER_TOKEN" "$OPS_TOKEN"; do
  grep -qF -- "$t" <<<"$env_dump" && { echo "REFUSED: a token is in the plane's environment"; exit 1; }
done
PASSWORD="$(cat "$work/plane/postgres.password")"
[ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$PASSWORD"
for c in "$cid" "$("${compose[@]}" ps -q postgres)"; do
  args="$(docker inspect --format '{{.Path}} {{join .Args " "}} {{json .Config.Cmd}}' "$c")"
  grep -qF -- "$PASSWORD" <<<"$args" && { echo "REFUSED: the Postgres password is on a command line"; exit 1; }
done
"${compose[@]}" exec -T postgres sh -c 'psql -h "$(hostname -i)" -U agentplane -d agentplane -w -c "select 1"' >/dev/null 2>&1 &&
  { echo "REFUSED: Postgres accepts a connection over the network with no password"; exit 1; }

ops() { curl -sf "http://127.0.0.1:9090$1" -H "authorization: Bearer $OPS_TOKEN"; }
succeeded() { ops '/runs?outcome=succeeded' | python3 -c 'import json, sys; print("\n".join(json.load(sys.stdin)["runs"]))'; }

# Each quickstart, then the runs it added, each read back for who admitted it.
for dir in "$FW"/*/; do
  name="$(basename "$dir")"
  expected=(framework-1)
  peer=""
  if grep -q AGENTPLANE_PEER_TOKEN "$dir/quickstart.py"; then
    expected+=(peer-1)
    peer="$PEER_TOKEN"
  fi
  before="$(succeeded | sort)"
  echo "==> $name"
  # Installed from the lock with every hash checked, then run with no model
  # configured: the keyless path the published block takes.
  uv venv --quiet --python 3.12 "$work/venv-$name"
  uv pip install --quiet --python "$work/venv-$name/bin/python" --require-hashes \
    -r "$dir/requirements.lock" || { echo "REFUSED: $name's lock does not install with its hashes"; exit 1; }
  (cd "$dir" && env -u QUICKSTART_MODEL AGENTPLANE_TOKEN="$FRAMEWORK_TOKEN" AGENTPLANE_PEER_TOKEN="$peer" \
     PYDANTIC_AI_NO_BANNER=1 "$work/venv-$name/bin/python" quickstart.py \
     >"$work/$name.out" 2>&1) || { cat "$work/$name.out"; echo "REFUSED: $name exited non-zero"; exit 1; }
  added="$(comm -13 <(echo "$before") <(succeeded | sort))"
  for actor in "${expected[@]}"; do
    found=""
    for run in $added; do
      ops "/runs/$run/history" | grep -q "\"admitted_by\":\"$actor\"" && found="$run" && break
    done
    [ -n "$found" ] || { cat "$work/$name.out"; echo "REFUSED: $name produced no succeeded run admitted by $actor"; exit 1; }
    echo "    $found succeeded, admitted by $actor"
  done
done

echo "ok: the chart renders and refuses; init --serve and compose bring up the plane;"
echo "    every quickstart reached a governed call through its framework's own client"
