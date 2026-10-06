#!/usr/bin/env bash
# Re-shoot the dev page pictures the getting-started guide shows: one run of
# `examples/room.yaml` on the deterministic fake model, its timeline and its
# conversation, in the light and the dark theme, written to `site/static/`.
#
# Run it after changing the page; the pictures are otherwise a copy of the UI
# that nothing keeps current. The browser is $CHROMIUM, else the first
# Chromium or Chrome found.
set -euo pipefail
cd "$(dirname "$0")/.."

browser="${CHROMIUM:-}"
if [[ -z "$browser" ]]; then
    for candidate in chromium chromium-browser google-chrome google-chrome-stable \
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
        "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
        if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
            browser="$candidate"
            break
        fi
    done
fi
[[ -n "$browser" ]] || { echo "dev-page-screenshot: no Chromium found; set CHROMIUM" >&2; exit 1; }

cargo build --quiet --features dev --bin agentplane
work="$(mktemp -d)"
pid=""
cleanup() {
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

target/debug/agentplane dev examples/room.yaml --scratch "$work/store" \
    >"$work/url" 2>"$work/log" &
pid=$!
for _ in $(seq 1 300); do
    [[ -s "$work/url" ]] && break
    sleep 0.1
done
url="$(head -n 1 "$work/url")"
[[ -n "$url" ]] || { echo "dev-page-screenshot: agentplane dev printed no URL" >&2; cat "$work/log" >&2; exit 1; }
origin="${url%%/#*}"
token="${url##*#t=}"

run="$(curl --silent --show-error --fail \
    -H "Host: ${origin#http://}" -H "Origin: $origin" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data '{"input": {"topic": "durable execution"}}' \
    "$origin/dev/runs" | python3 -c 'import json, sys; print(json.load(sys.stdin)["run"])')"

python3 tools/dev-page-screenshot.py "$browser" "$url&run=$run" "$work/profile" site/static
