#!/usr/bin/env bash
#
# Every version the *site* names of itself is a version crates.io can resolve.
#
# `check-doc-examples.sh` already holds the site's `agentplane = "X.Y"` lines to
# `Cargo.toml`. That is one half of the question and it is the half that cannot
# fail alone: both facts live in this repository, so a version bump updates them
# together and the check passes at the exact moment the claim becomes false.
#
# The claim is about the *registry*. A reader copies `agentplane = "0.5"` into a
# fresh project and cargo asks crates.io, which knows nothing about this working
# tree. Bumping `Cargo.toml` to 0.5.0 and deploying the site before publishing
# leaves every documented dependency line resolving to nothing:
#
#     error: failed to select a version for the requirement `agentplane = "^0.5"`
#     candidate versions found which didn't match: 0.4.0
#
# That is the same failure `check-doc-examples.sh`'s own comment describes ("the
# very first thing a newcomer copied resolved to a release without the API the
# same page went on to demonstrate"), and the existing guard structurally cannot
# see it: it compares the two facts that always agree, because a version bump
# touches both in one commit.
#
# Nothing orders the two publications either. `release.yml` fires on a tag;
# `pages.yml` fires on any push touching `site/**`. A version bump that lands on
# main before the tag is cut therefore deploys a site telling readers to depend
# on a release that does not exist yet, for as long as the gap lasts. The window
# is real even when nobody is currently inside it.
#
# So this runs where the claim is actually published: the Pages workflow, before
# the site is deployed. It is deliberately *not* in `just ci`, which must work
# offline and on a branch whose version is unpublished by definition. The
# release order it enforces is: publish the crate, then deploy the site.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The sparse index is a plain HTTP file per crate, one JSON object per line.
# No API token, no rate-limited API endpoint, no `cargo` invocation that would
# need a manifest — three fewer things to be flaky in a docs job.
INDEX="https://index.crates.io/ag/en/agentplane"

if ! PUBLISHED="$(curl -fsSL --retry 3 --max-time 30 "$INDEX")"; then
    echo "SKIPPED: the crates.io index is unreachable — not failing the build over it" >&2
    exit 0
fi

python3 - "$ROOT" <<PY
import json, pathlib, re, sys

root = pathlib.Path(sys.argv[1])
published = []
for line in """$PUBLISHED""".splitlines():
    line = line.strip()
    if not line:
        continue
    entry = json.loads(line)
    if not entry.get("yanked"):
        published.append(entry["vers"])

# A caret requirement "X.Y" is satisfied by any published X.Y.Z. Compare on that
# pair, because a patch bump is not something prose should have to chase.
satisfiable = {tuple(v.split(".")[:2]) for v in published}

# Every way the site writes the dependency line, in one expression, so a new
# spelling is caught rather than silently unchecked.
pattern = re.compile(r'agentplane\s*=\s*(?:"([0-9]+\.[0-9]+)"|\{[^}]*version\s*=\s*"([0-9]+\.[0-9]+)")')

claims = {}
for page in sorted((root / "site" / "content").rglob("*.md")):
    for n, line in enumerate(page.read_text().splitlines(), 1):
        for m in pattern.finditer(line):
            claims.setdefault(m.group(1) or m.group(2), []).append(
                f"{page.relative_to(root)}:{n}"
            )

if not claims:
    sys.exit(
        "REFUSED: no 'agentplane = \"X.Y\"' line was found on the site. A walk that "
        "finds nothing satisfies every prohibition by having nothing to prohibit."
    )

broken = {v: where for v, where in claims.items() if tuple(v.split(".")) not in satisfiable}
if broken:
    print("REFUSED: the site tells readers to depend on a version crates.io cannot resolve.")
    print(f"published (not yanked): {', '.join(published) or '<none>'}")
    for version, where in sorted(broken.items()):
        print(f"  agentplane = \"{version}\" — {', '.join(where)}")
    print()
    print("Publish the crate first, then deploy the site. A reader copying one of")
    print("those lines today gets 'failed to select a version', which is the worst")
    print("first impression this project can make.")
    sys.exit(1)

for version, where in sorted(claims.items()):
    print(f"ok: agentplane = \"{version}\" resolves ({len(where)} site reference(s))")
PY
