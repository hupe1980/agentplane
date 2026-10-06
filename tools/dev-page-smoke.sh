#!/usr/bin/env bash
# Load the `agentplane dev` page in headless Chromium over a journal holding
# hostile records, and assert every one of them reached the document as text.
#
# The source guard over the page script checks which sinks it names; this is
# the check on the claim itself: a real browser, the real content security
# policy with Trusted Types required, and records written to be executed —
# `<img onerror>`, `</script>`, a bidi override, ESC and OSC-52 sequences and
# a `javascript:` URL. It passes only if each appears as text, the bidi
# override only escaped, no element was made from any of them, and the page
# counted zero policy violations. It then switches the timeline between two
# runs and passes only if the run shown holds its own records, each once.
#
# The browser is $CHROMIUM, else the first Chromium or Chrome found. None
# found is a failure, not a skip: a smoke that passes by not running is the
# result this exists to rule out.
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
if [[ -z "$browser" ]]; then
    echo "dev-page-smoke: no Chromium found; set CHROMIUM=<path to a Chromium or Chrome binary>" >&2
    exit 1
fi

cargo build --quiet --features dev --bin agentplane
work="$(mktemp -d)"
pid=""
cleanup() {
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT

target/debug/agentplane dev examples/approval.yaml --scratch "$work/store" \
    >"$work/url" 2>"$work/log" &
pid=$!
for _ in $(seq 1 100); do
    [[ -s "$work/url" ]] && break
    sleep 0.1
done
url="$(head -n 1 "$work/url")"
if [[ -z "$url" ]]; then
    echo "dev-page-smoke: agentplane dev printed no URL" >&2
    cat "$work/log" >&2
    exit 1
fi
origin="${url%%/#*}"
token="${url##*#t=}"
authority="${origin#http://}"

body="$(python3 -c 'import json; print(json.dumps({"input": {"ticket": "<img src=x onerror=\"document.title=1\"></script><script>document.title=2</script> \u202egnp.exe \x1b[31mred\x1b[0m \x1b]52;c;ZXZpbA==\x07 javascript:alert(1)"}}))')"
run="$(curl --silent --show-error --fail \
    -H "Host: $authority" -H "Origin: $origin" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data "$body" \
    "$origin/dev/runs" | python3 -c 'import json, sys; print(json.load(sys.stdin)["run"])')"

second="$(curl --silent --show-error --fail \
    -H "Host: $authority" -H "Origin: $origin" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    --data '{"input": {"ticket": "second-run-marker"}}' \
    "$origin/dev/runs" | python3 -c 'import json, sys; print(json.load(sys.stdin)["run"])')"

python3 tools/dev-page-smoke.py "$browser" "$url&run=$run" "$run" "$work/profile" "$second"
