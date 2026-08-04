#!/usr/bin/env bash
#
# Model-check the specs, then check the checker.
#
# Two passes, and the second is the one that matters:
#
#   1. Each spec must verify.
#   2. Each spec's MUTANT must fail.
#
# A spec nobody has run is documentation. A spec whose mutants also pass is
# worse — it is decoration that looks like evidence. Both of these specs did
# exactly that at first: the effect protocol modelled "act" and "record" as one
# atomic step, so the state it exists to rule out was unreachable and its
# central invariant was true by construction. It verified. It proved nothing.
#
# The mutations live in mutations.py, one per plausible real-world bug.
#
# Usage:  spec/verify.sh            (uses Docker; no local Java needed)
#         TLA_JAR=/path/to.jar spec/verify.sh --local
set -euo pipefail

SPEC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${SPEC_DIR}/../.tla-cache"
IMAGE="eclipse-temurin:21-jdk"
TLA_URL="https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"

RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; OFF=$'\033[0m'
pass() { printf '  %sPASS%s  %s\n' "$GREEN" "$OFF" "$1"; }
fail() { printf '  %sFAIL%s  %s\n' "$RED" "$OFF" "$1"; }
note() { printf '        %s%s%s\n' "$DIM" "$1" "$OFF"; }

USE_DOCKER=1
[[ "${1:-}" == "--local" ]] && USE_DOCKER=0

# Run TLC over a directory, returning its output. TLC exits non-zero on a
# violation, which is a PASS for a mutant — so callers inspect the output, not
# the status.
run_tlc() {
    local dir="$1" cfg="$2" spec="$3"
    if (( USE_DOCKER )); then
        docker run --rm \
            -v "${dir}:/spec" -v "${CACHE_DIR}:/cache" -w /spec "$IMAGE" \
            java -XX:+UseParallelGC -cp /cache/tla2tools.jar tlc2.TLC \
                 -nowarning -config "$cfg" "$spec" 2>&1
    else
        ( cd "$dir" && java -XX:+UseParallelGC -cp "${TLA_JAR:?set TLA_JAR}" \
              tlc2.TLC -nowarning -config "$cfg" "$spec" 2>&1 )
    fi
}

prepare() {
    mkdir -p "$CACHE_DIR"
    if [[ ! -f "${CACHE_DIR}/tla2tools.jar" ]]; then
        printf '%sfetching tla2tools.jar%s\n' "$DIM" "$OFF"
        if (( USE_DOCKER )); then
            docker run --rm -v "${CACHE_DIR}:/cache" "$IMAGE" \
                curl -sSLo /cache/tla2tools.jar "$TLA_URL"
        else
            curl -sSLo "${CACHE_DIR}/tla2tools.jar" "$TLA_URL"
        fi
    fi
}

failures=0

# ── Pass 1: the specs must verify ───────────────────────────────────────────
check_spec() {
    local name="$1" out states
    out="$(run_tlc "$SPEC_DIR" "${name}.cfg" "${name}.tla")" || true
    if grep -q "Model checking completed. No error has been found." <<<"$out"; then
        states="$(grep -oE '[0-9]+ distinct states found' <<<"$out" | head -1)"
        pass "${name} verifies (${states:-state count unavailable})"
    else
        fail "${name} did not verify"
        sed 's/^/        /' <<<"$out" | tail -25
        failures=$((failures + 1))
    fi
}

# ── Pass 2: each mutant must be caught ──────────────────────────────────────
check_mutant() {
    local mutant="$1" invariant="$2" description="$3" dir out tripped

    # Under /tmp, not the system default: on macOS `mktemp -d` lands in
    # /var/folders, which Docker Desktop does not share. The container then sees
    # an empty directory and every mutant "survives" for want of a spec.
    dir="$(mktemp -d /tmp/agentplane-mutant.XXXXXX)"
    trap 'rm -rf "$dir"' RETURN

    # A mutation that no longer matches its spec is silently testing nothing, so
    # mutations.py treats that as an error rather than a no-op.
    if ! python3 "${SPEC_DIR}/mutations.py" "$mutant" "$dir"; then
        fail "could not build mutant ${mutant}"
        failures=$((failures + 1))
        return
    fi

    # The generated config checks ONLY the targeted invariant, so a violation
    # here is evidence about that invariant specifically — not merely that the
    # mutant broke something somewhere.
    out="$(run_tlc "$dir" "${mutant}.cfg" "${mutant}.tla")" || true
    tripped="$(grep -oE 'Invariant [A-Za-z]+ is violated' <<<"$out" | head -1)"
    if [[ "$tripped" == "Invariant ${invariant} is violated" ]]; then
        pass "${description}"
        note "caught by ${invariant}"
    elif [[ -n "$tripped" ]]; then
        fail "${description}"
        printf '        expected %s to catch this; %s did\n' "$invariant" "$tripped"
        failures=$((failures + 1))
    else
        fail "mutant SURVIVED: ${description}"
        printf '        %s holds with this bug present, so it proves nothing\n' "$invariant"
        sed 's/^/        /' <<<"$out" | tail -8
        failures=$((failures + 1))
    fi
}

prepare

printf '\n%sspecs%s\n' "$DIM" "$OFF"
check_spec EffectProtocol
check_spec RetrySafety
check_spec Saga
check_spec EffectGroup
check_spec Fencing
check_spec Authorization
check_spec Delegation

printf '\n%smutants — each must be caught%s\n' "$DIM" "$OFF"
while IFS=$'\t' read -r mutant _spec invariant description; do
    check_mutant "$mutant" "$invariant" "$description"
done < <(python3 "${SPEC_DIR}/mutations.py" --list)

printf '\n'
if (( failures )); then
    printf '%s%d check(s) failed%s\n' "$RED" "$failures" "$OFF"
    exit 1
fi
printf '%sall specs verify and every mutant is caught%s\n' "$GREEN" "$OFF"
