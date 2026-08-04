#!/usr/bin/env bash
#
# Break each guarantee on purpose; check that its named test notices.
#
# The specs are already checked this way (`spec/verify.sh`). This does the same
# for the implementation, because a guarantee that no test can falsify is
# indistinguishable from one that was never built — and this project has shipped
# exactly that: the refusal to replan on untrusted data was real, tested, and
# could not have failed, because the fixtures laundered the taint before it
# reached the check.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; OFF=$'\033[0m'
failed=0
current=""

# This script deliberately breaks the source, so the state it leaves behind when
# something goes wrong matters more than the happy path. Three separate hazards,
# each of which bit during development:
#
#   1. A run that dies between apply and revert leaves a mutation in the tree.
#      The trap below handles Ctrl-C and a cancelled CI job.
#
#   2. A trap cannot survive SIGKILL, a crash, or a power cut. So the tree is
#      also restored at STARTUP — recovery must not depend on the dying process
#      getting a chance to act.
#
#   3. Two concurrent runs mutate the same files under each other. That produced
#      a genuinely confusing hour: scans disagreed with grep, failures moved
#      between runs, and a clean-looking tree failed tests. The lock makes it
#      impossible rather than merely unwise.
# A mutation removes a guarantee, and dead code is the expected side effect —
# an unused variable where a check used to read one, an unused import where a
# constructor used to be called. Under `-D warnings` (which CI sets globally)
# those become compile errors, and this harness reports a perfectly valid
# mutation as "did not compile" — i.e. as an error in the *table* rather than a
# caught guarantee.
#
# So the sweep compiles without warnings-as-errors. Lint strictness is `just
# lint`'s job, on unmutated source, where a warning means something.
export RUSTFLAGS="${RUSTFLAGS_MUTANTS:-}"

LOCK="${TMPDIR:-/tmp}/agentplane-mutants.lock"

restore_strays() {
    while IFS= read -r backup; do
        [[ -n "$backup" ]] || continue
        printf '  %sNOTE%s  restoring %s left by an earlier run\n' \
            "$YELLOW" "$OFF" "${backup%.orig}"
        mv -f "$backup" "${backup%.orig}"
        touch "${backup%.orig}"
    done < <(find src -name '*.rs.orig' 2>/dev/null)
}

# Which cargo target holds a test, so a mutation can be checked by running that
# one binary instead of all of them.
#
# Falls back to the whole suite rather than guessing: a wrong target would run
# zero tests and report the mutation as uncaught, which is the loud-looking
# failure that wastes the most time. `tests/guards/layering.rs` already guarantees every
# name in the table exists somewhere, so a miss here means a unit test in `src`.
binary_for() {
    local test="$1"
    # The integration tests are grouped into a handful of targets — `tests/
    # <group>/main.rs` with the files as modules — so the target is the *group
    # directory* holding the file, not a stem derived from the file itself.
    local hit
    hit="$(grep -rl "fn ${test}(" tests 2>/dev/null | head -1)"
    if [[ -n "$hit" ]]; then
        local group="${hit#tests/}"
        printf -- '--test %s' "${group%%/*}"
        return
    fi
    if grep -rq "fn ${test}(" src 2>/dev/null; then
        printf -- '--lib'
        return
    fi
    printf -- '--no-fail-fast'
}

cleanup() {
    if [[ -n "$current" ]]; then
        python3 tools/mutants.py "$current" --revert || true
        current=""
    fi
    restore_strays
    # `rm -rf`, not `rmdir`: the lock holds the owner's pid, so a directory
    # remove would fail and leak the lock on every clean exit — turning the
    # stale-lock recovery above into the only way the tool ever starts again.
    rm -rf "$LOCK" 2>/dev/null || true
}

# `mkdir` is the atomic test-and-set every POSIX shell has.
#
# The owner's PID goes inside it, and that is not decoration. A trap cannot
# survive SIGKILL — the same reason the tree is restored at startup — so a sweep
# that is killed outright leaves this directory behind. Without the PID there is
# nothing to distinguish "a sweep is running" from "a sweep died three days ago",
# and every later run refuses forever until somebody deletes it by hand. That is
# a worse failure than the race it prevents, because it looks like the guard
# working.
if ! mkdir "$LOCK" 2>/dev/null; then
    owner="$(cat "$LOCK/pid" 2>/dev/null || true)"
    if [[ -n "$owner" ]] && kill -0 "$owner" 2>/dev/null; then
        printf '%sanother mutation sweep is running (pid %s)%s\n' "$RED" "$owner" "$OFF" >&2
        printf '%stwo sweeps rewrite the same files under each other; refusing to start%s\n' \
            "$DIM" "$OFF" >&2
        exit 2
    fi
    printf '%sNOTE%s  clearing a lock left by pid %s, which is gone\n' \
        "$YELLOW" "$OFF" "${owner:-unknown}" >&2
    rm -rf "$LOCK"
    if ! mkdir "$LOCK" 2>/dev/null; then
        printf '%scould not take the lock (%s)%s\n' "$RED" "$LOCK" "$OFF" >&2
        exit 2
    fi
fi
printf '%s' "$$" > "$LOCK/pid"

trap cleanup EXIT INT TERM

# Anything left by a run that never got to clean up.
restore_strays

printf '\n%smutants — each must be caught by its named test%s\n' "$DIM" "$OFF"

while IFS=$'\t' read -r name file test desc; do
    current="$name"
    if ! python3 tools/mutants.py "$name" --apply; then
        current=""
        printf '  %sERROR%s %s\n' "$RED" "$OFF" "$desc"
        failed=1
        continue
    fi

    # Two-speed, because the slow path is only needed to tell WEAK from FAIL.
    #
    # A mutation changes one source file, so the library rebuilds and *every*
    # test binary relinks and re-runs — around 570 tests to learn one bit. But
    # the classification below only consults the whole suite when the named test
    # did **not** fail, which is the rare and interesting case. So: run the one
    # binary that holds the named test first, and fall back to the full sweep
    # only when that comes back clean.
    #
    # The full run is never skipped where it matters. PASS is the only verdict
    # the fast path may produce, and it is the verdict that needs no knowledge of
    # any other test.
    # `- should panic` is optional in the pattern because cargo prints it for a
    # `#[should_panic]` test — `test foo - should panic ... FAILED`. Without it
    # the classifier cannot see those failing at all, and reports every mutation
    # whose named test is a `should_panic` as a guarantee nothing can falsify.
    # That is the worst possible direction for this harness to be wrong in: it
    # would send somebody hunting for a missing test that exists and works.
    #
    # No `--exact`: a unit test's real name is module-qualified
    # (`core::merkle::tests::foo`), so an exact filter on the leaf name matches
    # nothing and reports `0 passed` — which the classifier below would read as
    # "nothing failed", i.e. a guarantee with no test. Substring filtering is
    # what makes one name work for both trees.
    target="$(binary_for "$test")"
    out="$(cargo test --all-features $target "$test" 2>&1)"
    if ! grep -qE "^test .*${test}( - should panic)? \.\.\. FAILED" <<<"$out"; then
        out="$(cargo test --all-features --no-fail-fast 2>&1)"
    fi
    python3 tools/mutants.py "$name" --revert
    current=""

    # Order matters. A *failing test* makes cargo print `error: test failed, to
    # rerun pass ...`, so a naive `^error:` check reads every successful
    # mutation as a compile failure — which is exactly what the first run of
    # this script did, reporting all twenty as broken.
    if grep -qE "^test .*${test}( - should panic)? \.\.\. FAILED" <<<"$out"; then
        printf '  %sPASS%s  %s\n        %scaught by %s%s\n' \
            "$GREEN" "$OFF" "$desc" "$DIM" "$test" "$OFF"
    elif grep -qE "^error\[|could not compile" <<<"$out"; then
        # A mutation that does not compile tests nothing: it has to *remove the
        # guarantee*, not break the file.
        printf '  %sERROR%s %s\n        %sdid not compile%s\n' \
            "$RED" "$OFF" "$desc" "$DIM" "$OFF"
        failed=1
    elif grep -q "test result: FAILED" <<<"$out"; then
        other="$(grep -oE "^test [a-z_:]+ \.\.\. FAILED" <<<"$out" | head -3 | sed 's/^test //;s/ \.\.\..*//' | paste -sd, -)"
        printf '  %sWEAK%s  %s\n        %s%s did not fail; caught only by: %s%s\n' \
            "$YELLOW" "$OFF" "$desc" "$DIM" "$test" "$other" "$OFF"
        failed=1
    else
        printf '  %sFAIL%s  %s\n        %snothing failed — this guarantee has no test that can falsify it%s\n' \
            "$RED" "$OFF" "$desc" "$DIM" "$OFF"
        failed=1
    fi
done < <(python3 tools/mutants.py --list)

if [[ $failed -eq 0 ]]; then
    printf '\n%severy guarantee is falsifiable, and by the test written for it%s\n' "$GREEN" "$OFF"
else
    printf '\n%ssome guarantees are not pinned by the test that names them%s\n' "$RED" "$OFF"
fi
exit $failed
