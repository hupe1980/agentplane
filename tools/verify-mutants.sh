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
    # One classifier, not two. `mutants.py --verify` owns *did this guarantee
    # hold* — it applies, runs the named test, falls back to the full suite only
    # when that test held, restores on every path, and distinguishes killed from
    # weak from survived. This script owns the sweep: the lock, the strays, the
    # progress and the summary.
    #
    # They were briefly two implementations of one rule, which is exactly the
    # shape this codebase rejects: they can disagree about the same mutation,
    # and the one that rots is the one nobody runs alone.
    verdict="$(python3 tools/mutants.py "$name" --verify 2>&1)"
    status=$?
    current=""

    case $status in
        0) printf '  %sPASS%s  %s\n        %s%s%s\n' \
               "$GREEN" "$OFF" "$desc" "$DIM" "${verdict#*: }" "$OFF" ;;
        1) printf '  %sFAIL%s  %s\n        %s%s%s\n' \
               "$RED" "$OFF" "$desc" "$DIM" "${verdict#*: }" "$OFF"
           failed=1 ;;
        *) printf '  %sERROR%s %s\n        %s%s%s\n' \
               "$RED" "$OFF" "$desc" "$DIM" "$(head -1 <<<"${verdict#*: }")" "$OFF"
           failed=1 ;;
    esac
done < <(python3 tools/mutants.py --list)

if [[ $failed -eq 0 ]]; then
    printf '\n%severy guarantee is falsifiable, and by the test written for it%s\n' "$GREEN" "$OFF"
else
    printf '\n%ssome guarantees are not pinned by the test that names them%s\n' "$RED" "$OFF"
fi
exit $failed
