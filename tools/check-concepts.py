#!/usr/bin/env python3
"""Hold the design constitution to the rules its own README states.

`concepts/` is untracked and never ships, so no test in `tests/` can read it —
which is exactly why its cross-references rot silently while every
reader-visible page is guarded. This is the maintainer's equivalent of
`zola check`, and it is a `just` recipe rather than a `ci` stage for one honest
reason: a clean checkout does not have the folder, and a check that passes by
finding nothing is the shape this project treats as a defect.

Three rules, all of them stated in `concepts/README.md`:

1. **Section numbers are global and stable**, so every `§N.M` resolves to a
   heading somewhere in the folder. A reference to another *specification's*
   sections must name it — `ACS §8.2` — because the syntax is otherwise
   identical and `§8.2` already means something here.
2. **Every cross-file link resolves**, file and anchor. An anchor that points at
   a renamed heading is worse than a dangling one: it lands the reader
   somewhere plausible.
3. **Open work lives in ROADMAP.md only.** Every other document describes
   current state.
4. **A code reference resolves to code.** `Type::member` in backticks names
   something this crate actually exposes. The constitution cites the code
   constantly and nothing else can check it: `tests/` cannot read an untracked
   folder, and `cargo doc` never sees these files. A renamed method leaves the
   design document quietly describing a surface that no longer exists, which is
   worse here than a dangling link — the reader has no reason to doubt it.
6. **A published deferral is owned by the roadmap.** `site/content/docs/status.md`
   tells an adopter what this project is waiting on, "so a reader can tell
   whether their own need would move it". An entry there the roadmap does not
   claim is a promise made outside the building with no work behind it — and it
   happened: symbolic policy analysis was published as deferred and appeared
   nowhere in this folder ([§10.5](SHAPES.md#105-shapes-of-mistake) shape 60).
   Whatever claims it carries `**Published as deferred:**` with the entry's own
   words, and both directions are checked. An *item* is the usual claimant and
   not the only honest one: a wait that is prose rather than work — because
   nothing here can start it — owns its deferral the same way, by naming it and
   saying what would settle it.
5. **A deferred cost is named where it will be paid.** A decision that parks a
   durable-format change until the format freeze marks itself a *pre-freeze
   record change*, and the freeze act is the one place that list is worth
   reading — because the act is what converts "cheapest moment" into "upcaster
   and a version bump, forever". Recorded only at the decision, each is
   findable and the act is still priced by nobody
   ([§10.5](SHAPES.md#105-shapes-of-mistake) shape 59). Both directions are
   checked: a marked decision the freeze item does not name, and a cost the
   freeze item names that no decision carries any more.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "concepts"

# Reference to somebody else's specification, which this folder's numbering
# says nothing about. Anything else is a claim about a heading here.
FOREIGN = re.compile(r"\b(ACS|ACP|RFC|MCP|A2A|OCSF)\s+§")

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
        print(f"no {ROOT} — nothing to check")
        return 0
    docs = {p.name: p.read_text() for p in sorted(ROOT.glob("*.md"))}
    if not docs:
        print(f"{ROOT} holds no documents")
        return 1

    defined: set[str] = set()
    for text in docs.values():
        for m in re.finditer(r"^#{1,4}\s+(\d+(?:\.\d+)*)[.\s]", text, re.M):
            defined.add(m.group(1))

    faults: list[str] = []

    # 1. Section references.
    for name, text in docs.items():
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
    for name, text in docs.items():
        for m in re.finditer(r"`([a-z_][a-z0-9_]*)::([a-z_][A-Za-z0-9_]*)`", text):
            module, item = m.group(1), m.group(2)
            if module not in modules or item in surface or item in modules:
                continue
            line = text[: m.start()].count("\n") + 1
            faults.append(
                f"{name}:{line}: `{module}::{item}` names a module this crate has "
                f"and an item it does not"
            )

    for name, text in docs.items():
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

    checked = sum(len(re.findall(r"\]\([A-Z][A-Za-z]*\.md", t)) for t in docs.values())
    print(
        f"{len(docs)} documents, {len(defined)} sections, {checked} cross-file links, "
        f"{len(surface)} names on the crate surface"
    )
    for fault in faults:
        print(f"  {fault}")
    print(f"{len(faults)} fault(s)")
    return 1 if faults else 0


if __name__ == "__main__":
    sys.exit(main())
