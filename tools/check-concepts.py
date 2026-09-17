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
