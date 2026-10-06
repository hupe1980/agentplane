#!/usr/bin/env python3
"""Hold the design constitution to the rules its own README states.

`concepts/` is untracked and never ships, so no test in `tests/` can read it,
and `cargo doc` never sees it. This is the maintainer's equivalent of `zola
check`, run as `just _concepts-check`. A missing `concepts/` is a fault, since a
check that passes by finding nothing is the shape this project treats as a
defect; `--allow-missing` is for a checkout that deliberately has none.

This docstring is the one home of the rules; `concepts/README.md` points here.

1. **Section numbers are global and stable**, so every `§N.M` resolves to a
   heading in the folder. Another specification's section must be named —
   `ACS §8.2` — because the syntax is otherwise identical.
2. **Every cross-file link resolves**, file and anchor. An anchor pointing at a
   renamed heading lands the reader somewhere plausible, which is worse than
   dangling.
3. **Open work lives in ROADMAP.md only.** Every other document describes
   current state.
4. **A code reference resolves to code.** `Type::member` and `module::item` in
   backticks name something `src/` defines. Scoped to names this crate has, so
   another specification's vocabulary is skipped without an exemption list.
5. **A deferred format cost is named where it will be paid.** The freeze item
   (`### Perform the freeze`) collects, in both directions: every decision in
   DECISIONS.md marked *pre-freeze record change*, by its bolded subject; and
   every live specification that says it moves a durable format (*pre-freeze
   record change*, or *before the freeze as a hard cut*), by its folder name in
   a `` - `NNN-slug` `` bullet. A listed folder must be a live specification. A
   cost recorded only where it was deferred is priced by nobody at the act that
   pays it ([§10.5](SHAPES.md#105-shapes-of-mistake) shape 59).
6. **A published deferral is owned by the roadmap.** Each entry under
   `### Deferred` in `site/content/docs/status.md` is claimed by a
   `**Published as deferred:**` line with the entry's own words — on an item, or
   on prose that says why nothing here can start it — and each claim names a
   published entry (shape 60).
7. **Every open item is specified, and every specification is open.** Each
   `###` item carries one `**Specified as:**` naming a folder directly under
   `specs/`, each such folder is named by exactly one item, and a discharged
   one lives in `specs/archive/`. Rules 1 and 4 read the specifications too.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "concepts"
SPECS = ROOT.parent / "specs"
SPEC_DIR = re.compile(r"^\d{3}-[a-z0-9-]+$")

# Reference to somebody else's specification, which this folder's numbering
# says nothing about. Anything else is a claim about a heading here.
FOREIGN = re.compile(r"\b(ACS|ACP|RFC(?:\s+\d+)?|MCP|A2A|OCSF)\s+§")

# Phrases that mean "not done" outside the one document allowed to say so.
UNFINISHED = re.compile(
    r"\bTODO\b|\bTBD\b|\bFIXME\b|\bnot yet implemented\b|\bwe should\b|\bstill to do\b",
    re.I,
)


def slug(heading: str) -> str:
    """GitHub's anchor for a heading, near enough for this folder's needs.

    Punctuation is *removed* rather than replaced, which is why an em-dash
    surrounded by spaces yields two hyphens — the spaces survive it.
    """
    explicit = re.search(r"\{#([^}]+)\}", heading)
    if explicit:
        return explicit.group(1)
    s = heading.strip().lower()
    s = re.sub(r"[^a-z0-9 \-]", "", s)
    return s.replace(" ", "-")


def anchors(text: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r"^#{1,6}\s+(.+?)\s*$", text, re.M):
        head = m.group(1)
        explicit = re.search(r"\{#([^}]+)\}", head)
        if explicit:
            out.add(explicit.group(1))
            head = head[: explicit.start()]
        out.add(slug(head))
    return out


def main() -> int:
    if not ROOT.is_dir():
        if "--allow-missing" in sys.argv[1:]:
            print(f"no {ROOT} — nothing to check (--allow-missing)")
            return 0
        print(f"no {ROOT}: a check that finds nothing has checked nothing; pass --allow-missing where that is intended")
        return 1
    docs = {p.name: p.read_text() for p in sorted(ROOT.glob("*.md"))}
    if not docs:
        print(f"{ROOT} holds no documents")
        return 1

    specs: dict[str, str] = {}
    if SPECS.is_dir():
        for d in sorted(SPECS.iterdir()):
            if d.is_dir() and SPEC_DIR.match(d.name) and (d / "spec.md").is_file():
                specs[f"specs/{d.name}/spec.md"] = (d / "spec.md").read_text()

    defined: set[str] = set()
    for text in docs.values():
        for m in re.finditer(r"^#{1,4}\s+(\d+(?:\.\d+)*)[.\s]", text, re.M):
            defined.add(m.group(1))

    faults: list[str] = []

    # 1. Section references.
    for name, text in {**docs, **specs}.items():
        for m in re.finditer(r"§(\d+(?:\.\d+)*)", text):
            before = text[max(0, m.start() - 12) : m.start()]
            if FOREIGN.search(before + "§"):
                continue
            if m.group(1) not in defined:
                faults.append(
                    f"{name}: §{m.group(1)} resolves to no heading. If it is another "
                    f"specification's section, name it — `ACS §{m.group(1)}`"
                )

    # 2. Cross-file links.
    by_doc = {name: anchors(text) for name, text in docs.items()}
    for name, text in docs.items():
        for m in re.finditer(r"\[[^\]]*\]\(([A-Z][A-Za-z]*\.md)(#[^)]+)?\)", text):
            target, frag = m.group(1), m.group(2)
            if target not in docs:
                faults.append(f"{name}: links to {target}, which is not in this folder")
            elif frag and frag[1:] not in by_doc[target]:
                faults.append(
                    f"{name}: {target}{frag} — no such anchor. A link that lands "
                    f"somewhere plausible is worse than one that dangles"
                )

    # 3. Unfinished work outside the roadmap.
    for name, text in docs.items():
        if name == "ROADMAP.md":
            continue
        for m in UNFINISHED.finditer(text):
            line = text[: m.start()].count("\n") + 1
            faults.append(
                f"{name}:{line}: {m.group(0)!r} — open work belongs in ROADMAP.md, "
                f"and every other document describes current state"
            )

    # 4. Code references.
    #
    # The surface is every name a reader could reach: functions, consts, and
    # public struct fields. Fields matter as much as methods — `Justification::
    # summary` and `AuditReport::warrants` are both cited in this folder and
    # both are fields, so a check that only knew about `fn` would report two
    # faults on a clean tree and be turned off within the week.
    surface: set[str] = set()
    for rs in sorted((ROOT.parent / "src").rglob("*.rs")):
        body = rs.read_text()
        surface.update(re.findall(r"\bfn\s+([a-z_][A-Za-z0-9_]*)", body))
        surface.update(re.findall(r"\b(?:const|static)\s+([A-Z][A-Z0-9_]*)", body))
        surface.update(re.findall(r"^\s*pub\s+([a-z_][A-Za-z0-9_]*)\s*:", body, re.M))
        surface.update(re.findall(r"\b(?:struct|enum|trait|type)\s+([A-Z][A-Za-z0-9]*)", body))
        # Enum variants and associated types, picked up wherever the crate names
        # one by path. Parsing `enum` bodies would mean matching braces; this
        # gets the same names because a variant nothing in the crate ever names
        # is not a surface a design document should be citing either.
        surface.update(re.findall(r"::([A-Z][A-Za-z0-9]*)", body))

    # Module paths are the half the type rule cannot see. `netguard::intake`,
    # `journal::payload` and `core::canon` are cited here as often as types are,
    # and a lowercase first segment does not match the pattern below — so a
    # module renamed or a helper moved leaves the citation reading as current.
    # Scoped to first segments this crate actually has a module for, which makes
    # somebody else's lowercase vocabulary skip without an exemption list.
    modules = {p.stem for p in (ROOT.parent / "src").rglob("*.rs")}
    modules |= {d.name for d in (ROOT.parent / "src").iterdir() if d.is_dir()}
    for name, text in {**docs, **specs}.items():
        for m in re.finditer(r"`([a-z_][a-z0-9_]*)::([a-z_][A-Za-z0-9_]*)`", text):
            module, item = m.group(1), m.group(2)
            if module not in modules or item in surface or item in modules:
                continue
            line = text[: m.start()].count("\n") + 1
            faults.append(
                f"{name}:{line}: `{module}::{item}` names a module this crate has "
                f"and an item it does not"
            )

    for name, text in {**docs, **specs}.items():
        for m in re.finditer(r"`([A-Z][A-Za-z0-9]*)::([A-Za-z_][A-Za-z0-9_]*)`", text):
            ty, member = m.group(1), m.group(2)
            # A type this crate does not define is somebody else's vocabulary —
            # `AcsParams.required`, a protocol's own record names — and this
            # folder cites those deliberately.
            if ty not in surface:
                continue
            if member not in surface:
                line = text[: m.start()].count("\n") + 1
                faults.append(
                    f"{name}:{line}: `{ty}::{member}` resolves to nothing in src/. "
                    f"A design document describing a surface that no longer exists "
                    f"is worse than a dangling link: the reader has no reason to doubt it"
                )

    # 5. Deferred format costs, named where they will be paid.
    #
    # The subject is the decision's own bolded lead, so the two lists are held
    # together by the sentence a reader searches for rather than by a tag only
    # this script understands — which is `concepts/README.md`'s citation rule
    # ("quote the decision's claim, or name it") made checkable for the one
    # class where forgetting is expensive.
    decisions = docs.get("DECISIONS.md", "")
    deferred: set[str] = set()
    for m in re.finditer(r"^- (.+?)(?=\n- |\n#|\Z)", decisions, re.M | re.S):
        body = m.group(1)
        if "pre-freeze record change" not in body.replace("*", ""):
            continue
        lead = re.match(r"\*\*(.+?)\*\*", body, re.S)
        if not lead:
            faults.append(
                "DECISIONS.md: a pre-freeze record change with no bolded subject "
                "— the freeze item has nothing to quote"
            )
            continue
        deferred.add(" ".join(lead.group(1).split()).rstrip("."))

    freeze = re.search(
        r"^### Perform the freeze$(.*?)(?=^#{1,3} )", docs.get("ROADMAP.md", ""), re.M | re.S
    )
    if deferred and not freeze:
        faults.append(
            "ROADMAP.md: no `### Perform the freeze` item, and DECISIONS.md defers "
            "a record change to it"
        )
    elif freeze:
        listed = {
            " ".join(m.group(1).split()).rstrip(".")
            for m in re.finditer(r"^- \*\*(.+?)\*\*", freeze.group(1), re.M | re.S)
        }
        for subject in sorted(deferred - listed):
            faults.append(
                f"DECISIONS.md: {subject!r} is a pre-freeze record change and the "
                f"freeze item does not name it. A cost recorded only where it was "
                f"deferred is priced by nobody at the act that pays it"
            )
        for subject in sorted(listed - deferred):
            faults.append(
                f"ROADMAP.md: the freeze item names {subject!r}, and no decision "
                f"carries it as a pre-freeze record change any more"
            )

    # 5b. Open specifications that would move a durable format.
    #
    # An open item carries no decision for the join above to read, so its
    # specification is what says it moves a record — and the freeze item names
    # it by folder. The negated forms ("no …", "not a pre-freeze record change")
    # are a spec saying the opposite and are skipped.
    if freeze:
        own = re.search(r"^\*\*Specified as:\*\*\s+`([^`]+)`", freeze.group(1), re.M)
        own_spec = own.group(1) if own else None
        named = set(re.findall(r"^- `(\d{3}-[a-z0-9-]+)`", freeze.group(1), re.M))
        marks = re.compile(
            r"(?<!\bno )(?<!\bnot a )pre-freeze record change|before the freeze as a hard cut", re.I
        )
        moving = set()
        for path, text in specs.items():
            folder = path.split("/")[1]
            if folder == own_spec:
                continue
            if marks.search(" ".join(text.replace("*", "").split())):
                moving.add(folder)
        live_folders = {path.split("/")[1] for path in specs}
        for folder in sorted(moving - named):
            faults.append(
                f"specs/{folder}: says it moves a durable format and the freeze item "
                f"does not name it. List it as a `- `{folder}`` bullet under what the act costs"
            )
        for folder in sorted(named - live_folders):
            faults.append(
                f"ROADMAP.md: the freeze item names {folder!r} as a cost, and it is not a "
                f"live specification — discharged or archived costs leave the list"
            )

    # 6. Published deferrals, owned by an item.
    #
    # The site is tracked and this folder is not, which is why the join lives
    # here and not in `tests/guards/docs.rs`: a test cannot read the roadmap.
    status = ROOT.parent / "site" / "content" / "docs" / "status.md"
    if status.is_file():
        section = re.search(r"^### Deferred$(.*?)(?=^## )", status.read_text(), re.M | re.S)
        published: set[str] = set()
        if section:
            for entry in re.finditer(r"^\*\*(.+?)\*\*", section.group(1), re.M | re.S):
                lead = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", entry.group(1))
                published.add(" ".join(lead.split()).rstrip(".").strip(" —-"))
        claimed = {
            " ".join(m.group(1).split()).rstrip(".")
            for m in re.finditer(
                r"^\*\*Published as deferred:\*\*\s+(.+?)$",
                docs.get("ROADMAP.md", ""),
                re.M,
            )
        }
        for subject in sorted(published - claimed):
            faults.append(
                f"status.md defers {subject!r} and the roadmap does not claim it. A "
                f"gap named to an adopter and to nobody here is a promise with no "
                f"work behind it"
            )
        for subject in sorted(claimed - published):
            faults.append(
                f"ROADMAP.md claims {subject!r} as published-deferred, and the "
                f"status page does not defer it under that name"
            )

    # 7. Open items and their specifications, one to one.
    #
    # Both directions, and the absence of the folder is a fault rather than a
    # skip: an item naming a specification is a claim, and a check that passes
    # because the subject is missing is the shape this project treats as a
    # defect.
    roadmap = docs.get("ROADMAP.md", "")
    live = {name.split("/")[1] for name in specs}
    owners: dict[str, list[str]] = {}
    items = re.findall(r"^### (.+?)\n(.*?)(?=^#{2,3} |\Z)", roadmap, re.M | re.S)
    for heading, body in items:
        named = re.findall(r"^\*\*Specified as:\*\*\s+`([^`]+)`", body, re.M)
        if len(named) != 1:
            faults.append(
                f"ROADMAP.md: {heading!r} names {len(named)} specifications — every "
                f"open item carries exactly one `**Specified as:**` line"
            )
            continue
        owners.setdefault(named[0], []).append(heading)
        if named[0] not in live:
            where = (
                "is archived — a discharged specification's item is deleted, not kept"
                if (SPECS / "archive" / named[0]).is_dir()
                else "does not exist"
            )
            faults.append(f"ROADMAP.md: {heading!r} is specified as {named[0]!r}, which {where}")
    for spec, headings in sorted(owners.items()):
        if len(headings) > 1:
            faults.append(f"ROADMAP.md: {spec!r} is claimed by {len(headings)} items: {headings}")
    for spec in sorted(live - owners.keys()):
        faults.append(
            f"specs/{spec}: no roadmap item names it. Open work outside the roadmap is "
            f"a second backlog; a discharged one moves to specs/archive/"
        )

    checked = sum(len(re.findall(r"\]\([A-Z][A-Za-z]*\.md", t)) for t in docs.values())
    print(
        f"{len(docs)} documents, {len(specs)} specifications, {len(defined)} sections, "
        f"{checked} cross-file links, {len(surface)} names on the crate surface"
    )
    for fault in faults:
        print(f"  {fault}")
    print(f"{len(faults)} fault(s)")
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
