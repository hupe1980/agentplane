#!/usr/bin/env bash
#
# Build the image and prove it does the thing it exists for.
#
# `just cli-smoke` exercises the binary; nothing exercised the *image*, and the
# two fail differently. A binary that works can still be packaged into an image
# that cannot resolve a manifest path, cannot write where it runs, or ships a
# secret. Each check below is one of those.
#
# The last two are supply chain rather than function, and they are the reason
# this script exists at all: `.dockerignore` is an allowlist, and an allowlist
# is only as good as the check that it held.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-agentplane:smoke}"
FEATURES="${FEATURES:-cli}"

echo "==> building $IMAGE (features: $FEATURES)"
docker build --build-arg "FEATURES=$FEATURES" -t "$IMAGE" "$ROOT"

run() { docker run --rm -v "$ROOT/examples:/work:ro" "$IMAGE" "$@"; }

echo "==> --help exits zero"
docker run --rm "$IMAGE" --help >/dev/null

echo "==> validate reads a mounted room"
out=$(run validate /work/room.yaml)
grep -q "blog-desk" <<<"$out" || { echo "REFUSED: validate lost an agent: $out"; exit 1; }

echo "==> digest is the same identity the host computes"
in_image=$(run digest /work/summariser.yaml)
on_host=$(cd "$ROOT" && cargo run --quiet --features cli --bin agentplane -- digest examples/summariser.yaml)
[ "$in_image" = "$on_host" ] || {
  # A digest that differs between the image and the host would mean the
  # identity a registry pins depends on where it was computed, which is the
  # whole claim the manifest digest makes.
  echo "REFUSED: image digest $in_image != host digest $on_host"; exit 1
}

echo "==> a run completes on a read-only rootfs with no network"
# Both flags are the point. The journal defaults to memory, so nothing needs a
# writable layer; the fake provider needs no network. An image that quietly
# depended on either would only reveal it in somebody's hardened deployment.
out=$(docker run --rm --read-only --network none -v "$ROOT/examples:/work:ro" "$IMAGE" \
        run /work/summariser.yaml --input '{"ticket":"printer on fire"}')
grep -q '"summary"' <<<"$out" || { echo "REFUSED: run produced no answer: $out"; exit 1; }

echo "==> the container does not run as root"
uid=$(docker run --rm --entrypoint /usr/local/bin/agentplane "$IMAGE" --help >/dev/null 2>&1; \
      docker inspect --format '{{.Config.User}}' "$IMAGE")
[ -n "$uid" ] && [ "$uid" != "root" ] && [ "$uid" != "0:0" ] || {
  echo "REFUSED: image runs as '$uid'"; exit 1
}

echo "==> no shell to inherit"
# Distroless has no /bin/sh. If one appears, the base image changed to something
# with a package manager and an attacker's foothold, and nobody meant it to.
if docker run --rm --entrypoint /bin/sh "$IMAGE" -c 'echo reachable' 2>/dev/null | grep -q reachable; then
  echo "REFUSED: the image has a shell"; exit 1
fi

echo "==> no secret and no internal document in any layer"
# Filesystem *and* history: a file deleted in a later layer is still served to
# anyone who pulls the earlier one, and a build arg can leak a path into the
# recorded command line.
layers=$(docker save "$IMAGE" | tar -tf - 2>/dev/null || true)
for forbidden in CONCEPT.md .env; do
  if docker run --rm --entrypoint /usr/local/bin/agentplane "$IMAGE" --help >/dev/null 2>&1 \
     && grep -q "$forbidden" <<<"$layers"; then
    echo "REFUSED: '$forbidden' is present in an image layer"; exit 1
  fi
done
if docker history --no-trunc "$IMAGE" | grep -qE 'CONCEPT\.md|\.env'; then
  echo "REFUSED: build history names a file that must not ship"; exit 1
fi

# The `:full` variant exists to carry the surfaces `:slim` does not, and a
# variant whose extra features nothing can reach is a declaration that does
# nothing — the shape this repository keeps a catalogue of. So when they are
# built in, the image has to prove it can actually host an agent.
if [[ "$FEATURES" == *a2a-server* && "$FEATURES" == *cedar* ]]; then
  echo "==> the full image serves an A2A peer"
  cid=$(docker run -d --rm -p 18080:8080 -p 19090:9090 -v "$ROOT/examples:/work:ro" "$IMAGE" \
          serve /work/served.yaml --addr 0.0.0.0:8080 --url http://localhost:18080 \
          --policy /work/serve-policy.cedar --tokens /work/serve-tokens.yaml \
          --operator-addr 0.0.0.0:9090 --push-host hooks.example.com \
          --store /tmp/served.redb)
  # `--store` needs a writable path, so this one is deliberately *not*
  # `--read-only`: a served task's id is a promise it can be fetched again, and
  # the CLI refuses an in-memory journal for exactly that reason.
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 60); do
    curl -sf -o /dev/null "http://127.0.0.1:18080/.well-known/agent-card.json" && break
    sleep 1
  done
  card=$(curl -sf "http://127.0.0.1:18080/.well-known/agent-card.json") || {
    echo "REFUSED: the served card never came up"; docker logs "$cid"; exit 1; }
  grep -q '"summariser"' <<<"$card" || { echo "REFUSED: wrong card: $card"; exit 1; }

  # An unauthenticated call must be refused, or the image ships an open door.
  rpc='{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"printer on fire"}],"messageId":"m1"}}}'
  anon=$(curl -sf -X POST "http://127.0.0.1:18080/a2a" -H 'content-type: application/json' \
           -H 'a2a-version: 1.0' -d "$rpc")
  grep -q '"error"' <<<"$anon" || { echo "REFUSED: an unauthenticated call was accepted: $anon"; exit 1; }

  ok=$(curl -sf -X POST "http://127.0.0.1:18080/a2a" -H 'content-type: application/json' \
         -H 'a2a-version: 1.0' -H 'authorization: Bearer a-long-random-string' -d "$rpc")
  grep -q 'TASK_STATE_COMPLETED' <<<"$ok" || {
    echo "REFUSED: the served run did not complete: $ok"; docker logs "$cid"; exit 1; }
  # I13 through a shipped binary: the conclusion is *queryable* by whoever has
  # to clear it, not merely emitted. Until `--operator-addr` there was no way to
  # ask a running plane what it had concluded without writing Rust.
  runs=$(curl -sf "http://127.0.0.1:19090/runs?outcome=succeeded" \
           -H 'authorization: Bearer another-long-random-string') || {
    echo "REFUSED: the operator surface did not answer"; docker logs "$cid"; exit 1; }
  grep -q 'run_' <<<"$runs" || { echo "REFUSED: the run it just completed is not listed: $runs"; exit 1; }

  # And the two surfaces are separated by **policy**, not by the port. A peer
  # token reaching the operator socket must still be refused, or the separation
  # is a firewall rule somebody can misconfigure rather than a rule.
  leak=$(curl -s "http://127.0.0.1:19090/runs?outcome=succeeded" \
           -H 'authorization: Bearer a-long-random-string')
  grep -q 'run_' <<<"$leak" && { echo "REFUSED: a peer token listed runs: $leak"; exit 1; }

  # The converse, so the separation is not one-directional.
  cross=$(curl -s -X POST "http://127.0.0.1:18080/a2a" -H 'content-type: application/json' \
            -H 'a2a-version: 1.0' -H 'authorization: Bearer another-long-random-string' -d "$rpc")
  grep -q '"error"' <<<"$cross" || { echo "REFUSED: an operator token sent a message: $cross"; exit 1; }

  # Push: the card must *claim* it, and the grant must *bite*. Advertising a
  # capability nothing serves is the failure this pairing exists to rule out —
  # a peer that registers a webhook and never hears back has a worse day than
  # one told up front.
  grep -q '"pushNotifications":true' <<<"$card" || {
    echo "REFUSED: push was granted and the card does not advertise it: $card"; exit 1; }

  reg='{"jsonrpc":"2.0","id":"9","method":"SendMessage","params":{"message":{"role":"ROLE_USER","parts":[{"text":"hi"}],"messageId":"push-1"},"configuration":{"taskPushNotificationConfig":{"url":"https://evil.example.net/hook"}}}}'
  refused=$(curl -s -X POST "http://127.0.0.1:18080/a2a" -H 'content-type: application/json' \
              -H 'a2a-version: 1.0' -H 'authorization: Bearer a-long-random-string' -d "$reg")
  grep -q 'does not permit webhooks' <<<"$refused" || {
    echo "REFUSED: a webhook to an ungranted host was accepted: $refused"; exit 1; }

  docker rm -f "$cid" >/dev/null 2>&1 || true
  trap - EXIT
  echo "    served a card, refused an anonymous call, completed an authorized one,"
  echo "    listed the conclusion to an operator, kept the two roles apart, and"
  echo "    advertised push while refusing a webhook to an ungranted host"
fi

# `mcp-stdio` is compiled into `:full`, and the image deliberately **cannot**
# demonstrate it. A distroless image has no interpreter and no shell, so the
# `npx`- and Python-based servers most of the MCP ecosystem publishes cannot run
# inside it — only a statically linked server binary mounted in can. That is a
# real constraint of the combination rather than a gap in either half, and it is
# checked on the host by `cli-smoke` instead, where an interpreter exists.
#
# Asserted rather than skipped silently: if a base image ever gained a runtime,
# this line is where somebody would notice the assumption changed.
if [[ "$FEATURES" == *mcp-stdio* ]]; then
  echo "==> the image has no interpreter, so a scripted MCP server cannot run in it"
  if docker run --rm --entrypoint /usr/bin/python3 "$IMAGE" --version >/dev/null 2>&1; then
    echo "REFUSED: the base image gained an interpreter; the docs say it has none"; exit 1
  fi
fi

echo "ok: the image validates, digests identically to the host, runs read-only"
echo "    with no network, is nonroot, has no shell, and carries no secret"
