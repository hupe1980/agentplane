#!/usr/bin/env python3
"""An independent verifier for an agentplane export.

Written from the published record-format specification and nothing else — none
of this crate's Rust was read while implementing it, which is the whole point. The corpus in
`tests/golden/` is this project's build checking itself; that catches drift and
cannot catch a shared misunderstanding. A second implementation is the only
thing that can, and it is only evidence while it stays independent: if this
file ever starts consulting the Rust to decide what a rule means, the rule
belongs in the specification instead.

    python3 tools/verify_export.py tests/golden/export.jsonl
    python3 tools/verify_export.py export.jsonl 42:<root-hex> [checkpoint.json …]

Each argument after the file is a checkpoint from outside it — `SIZE:ROOT`,
`ORIGIN:SIZE:ROOT`, or a JSON file holding `{"origin", "size", "root"}` — and
the file is held to every one. A cosigned note is not read here: this reader
checks no signatures of any kind, and says so in its output.

Exit 0 when the file verifies, 1 when it does not, 2 when the file could not be
read at all. Findings are printed one per line.

Standard library only, deliberately: an auditor should be able to run this on a
machine with nothing installed.
"""

from __future__ import annotations

import hashlib
import json
import sys

# ── Section 1: versioning ──────────────────────────────────────────────────
# "A reader that cannot interpret one refuses; it never guesses."
EXPORT_VERSION = 1
CANON_VERSION = 1

HEADER_KIND = "agentplane.export"
RUN_KIND = "agentplane.export.run"
CASE_KIND = "agentplane.export.case"
TRAILER_KIND = "agentplane.export.end"
FRAMING = {HEADER_KIND, RUN_KIND, CASE_KIND, TRAILER_KIND}

# The members each framing line is specified to carry. A later writer may add
# one; this reader passes over it and says so, because a verdict is only as wide
# as the claims the reader understood. Not a refusal: a framing line is not
# hashed and carries no evidence of its own, so an added member falsifies
# nothing already checked — it bounds what "sound" covered. A record line is the
# other answer, and for the reason its members are covered by a hash.
FRAMING_MEMBERS = {
    HEADER_KIND: {"kind", "version", "checkpoint", "canon"},
    RUN_KIND: {"kind", "run", "index", "seal"},
    CASE_KIND: {"kind", "case", "deadlines", "blobs", "hold"},
    TRAILER_KIND: {
        "kind",
        "runs_requested",
        "runs_exported",
        "records",
        "cases",
        "unreadable",
    },
}

ZERO = bytes(32)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ── Section 7: the Merkle log, RFC 6962 ────────────────────────────────────

def leaf_hash(digest: bytes) -> bytes:
    return sha256(b"\x00" + digest)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def empty_root() -> bytes:
    return sha256(b"")


def split_point(n: int) -> int:
    """Largest power of two strictly less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return empty_root()
    if len(leaves) == 1:
        return leaves[0]
    k = split_point(len(leaves))
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


# ── The verifier ───────────────────────────────────────────────────────────

class Report:
    def __init__(self) -> None:
        self.findings: list[str] = []
        self.records = 0
        self.runs = 0
        self.cases = 0
        self.unverifiable = False
        self.unchecked: list[str] = []

    def note(self, text: str) -> None:
        self.findings.append(text)


def unhex(value: object, what: str, report: Report) -> bytes | None:
    if not isinstance(value, str) or len(value) != 64:
        report.note(f"{what} is not a 64-character hex digest: {value!r}")
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        report.note(f"{what} is not hex: {value!r}")
        return None


class Anchor:
    """A checkpoint from outside the file: an origin (optional), a size, a root."""

    def __init__(self, size: int, root: bytes, origin: str | None = None) -> None:
        self.size = size
        self.root = root
        self.origin = origin

    def __str__(self) -> str:
        where = f"'{self.origin}' " if self.origin is not None else ""
        return f"{where}size {self.size} root {self.root.hex()}"


# A basis names what established an operator's name; see the format's case
# block. A hold with an empty reason or actor preserves a matter nobody can
# account for.
BASES = {"authenticated", "asserted", "connected"}


def hold_problem(block: dict) -> str | None:
    """Why a case block's `hold` member is unreadable, or None when it is sound.

    The member is required and may be `null`. A restore that dropped a hold
    would let retention erase the matter, so a reader treats a missing or
    malformed one as a finding rather than as "not held".
    """
    if "hold" not in block:
        return "the case block carries no hold member"
    hold = block["hold"]
    if hold is None:
        return None
    if not isinstance(hold, dict) or set(hold) != {"placed_at", "reason", "by"}:
        return "the legal hold is malformed: it needs exactly placed_at, reason and by"
    if not isinstance(hold["placed_at"], str) or not isinstance(hold["reason"], str):
        return "the legal hold is malformed: placed_at and reason are strings"
    by = hold["by"]
    if (
        not isinstance(by, dict)
        or set(by) != {"actor", "basis"}
        or not isinstance(by["actor"], str)
        or not by["actor"].strip()
        or by["basis"] not in BASES
    ):
        return "the legal hold is malformed: by needs a non-empty actor and a known basis"
    return None


def verify(lines: list[str], anchors: list[Anchor] | None = None) -> Report:
    report = Report()
    anchors = anchors or []
    # Section 10, step 4: this reader implements no signature scheme, so every
    # verdict it gives is about integrity and never about authorship.
    report.unchecked.append(
        "signatures — this reader checks no record signature and no cosignature, so "
        "nothing here says who wrote the file"
    )

    open_runs = 0
    parsed: list[dict] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            report.note(f"line {number} is not JSON: {error}")
            return report
        if not isinstance(value, dict):
            report.note(f"line {number} is not a JSON object")
            return report
        known = FRAMING_MEMBERS.get(value.get("kind"))
        if known is not None:
            unknown = sorted(set(value) - known)
            if unknown:
                report.unchecked.append(
                    f"a {value['kind']} line carries {', '.join(unknown)} this reader "
                    "does not know — whatever they claim was not checked, and a later "
                    "writer produced this file"
                )
        parsed.append(value)

    if not parsed:
        report.note("the file is empty")
        return report

    # ── step 1: the header ────────────────────────────────────────────────
    header = parsed[0]
    if header.get("kind") != HEADER_KIND:
        report.note(f"the first line is not a {HEADER_KIND} header")
        return report
    if header.get("version") != EXPORT_VERSION:
        report.note(
            f"export version {header.get('version')!r} is not one this reader "
            f"implements ({EXPORT_VERSION})"
        )
        return report
    if header.get("canon") != CANON_VERSION:
        report.note(
            f"canon {header.get('canon')!r} is not the rule this reader "
            f"implements ({CANON_VERSION}) — every digest below is UNVERIFIABLE "
            "rather than wrong"
        )
        report.unverifiable = True
        return report

    checkpoint = header.get("checkpoint")
    if not isinstance(checkpoint, dict):
        report.note("the header carries no checkpoint")
        return report
    claimed_root = unhex(checkpoint.get("root"), "the checkpoint root", report)
    log_size = checkpoint.get("size")
    if not isinstance(log_size, int):
        report.note("the checkpoint has no integer size")
        return report
    if log_size == 0 and claimed_root is not None and claimed_root != empty_root():
        report.note("a size-0 checkpoint claims a root the empty log cannot have")

    # ── the body of the file ──────────────────────────────────────────────
    current_run: str | None = None
    prev_hash = ZERO
    last_seq: int | None = None
    terminal: dict[str, bytes] = {}
    placed: dict[int, tuple[str, bytes]] = {}
    stamped: set[str] = set()
    carried: set[str] = set()
    trailer: dict | None = None
    # [run, records under its block], one entry per run block in file order.
    blocks: list[list] = []
    origin = checkpoint.get("origin")

    for value in parsed[1:]:
        kind = value.get("kind")

        if kind == RUN_KIND:
            current_run = value.get("run")
            prev_hash = ZERO
            last_seq = None
            report.runs += 1
            blocks.append([str(current_run), 0])
            index, seal = value.get("index"), value.get("seal")
            if index is None and seal is None:
                # An open run: not in the log, and that is a state rather than
                # a gap. It is counted, because the root proves nothing about
                # it and a reader deciding what a clean report is worth has to
                # be told how much of the file that covers.
                open_runs += 1
                continue
            if not isinstance(index, int) or seal is None:
                report.note(f"run {current_run}: a placed run needs both index and seal")
                continue
            digest = unhex(seal, f"run {current_run}'s seal", report)
            if digest is None:
                continue
            if index in placed:
                report.note(f"log index {index} is claimed by two runs")
            placed[index] = (str(current_run), digest)
            continue

        if kind == CASE_KIND:
            report.cases += 1
            case = value.get("case")
            identifier = case.get("id") if isinstance(case, dict) else None
            if identifier is None:
                report.note("a case block carries no identifier")
            else:
                carried.add(str(identifier))
            problem = hold_problem(value)
            if problem is not None:
                report.note(f"case {identifier}: {problem}")
            continue

        if kind == TRAILER_KIND:
            trailer = value
            continue

        if kind in FRAMING:
            report.note(f"unexpected framing line {kind!r}")
            continue

        # ── step 2 and 3: a record line ───────────────────────────────────
        report.records += 1
        if blocks:
            blocks[-1][1] += 1
        raw = value.get("raw")
        if not isinstance(raw, str):
            report.note(f"run {current_run}: a record line carries no wire bytes")
            continue
        raw_bytes = raw.encode("utf-8")

        claimed = unhex(value.get("hash"), f"run {current_run}: a record hash", report)
        stored_prev = unhex(
            value.get("prev_hash"), f"run {current_run}: a record prev_hash", report
        )
        if claimed is None or stored_prev is None:
            continue

        if stored_prev != prev_hash:
            report.note(
                f"run {current_run}: record {value.get('seq')} does not link to its "
                "predecessor"
            )
        recomputed = sha256(stored_prev + raw_bytes)
        if recomputed != claimed:
            report.note(
                f"run {current_run}: record {value.get('seq')} was altered after it "
                f"was written (stored {claimed.hex()}, recomputed {recomputed.hex()})"
            )
        head_before = prev_hash
        prev_hash = claimed

        try:
            wire = json.loads(raw)
        except json.JSONDecodeError as error:
            report.note(f"run {current_run}: a record's wire bytes do not parse: {error}")
            continue
        if value.get("body") != wire:
            report.note(
                f"run {current_run}: record {value.get('seq')}'s readable body does "
                "not match its wire bytes"
            )

        seq = wire.get("seq")
        if not isinstance(seq, int):
            report.note(f"run {current_run}: a record has no integer seq")
        else:
            if last_seq is not None and seq != last_seq + 1:
                report.note(
                    f"run {current_run}: seq jumps from {last_seq} to {seq} — the "
                    "record between them is missing"
                )
            last_seq = seq
        if wire.get("run") != current_run:
            report.note(
                f"run {current_run}: a record's own body names run {wire.get('run')!r}"
            )
        # Step 3: a conclusion names the head it was drawn over, which is the
        # head it sits on.
        if wire.get("kind") == "RunConcluded" and wire.get("chain_head") != head_before.hex():
            report.note(
                f"run {current_run}: the sealing record's chain_head is not the head it "
                "sits on — the conclusion was drawn over a different history"
            )
        if "case" in wire:
            stamped.add(str(wire["case"]))
        if current_run is not None:
            terminal[current_run] = claimed

    # ── step 5: the log ───────────────────────────────────────────────────
    for index, (run, seal) in sorted(placed.items()):
        if run in terminal and terminal[run] != seal:
            report.note(
                f"run {run}: the log leaf is not this run's terminal chain hash"
            )

    positions = sorted(placed)
    against = claimed_root
    if positions != list(range(len(positions))):
        # Not a root mismatch: a tree over duplicated or out-of-range positions
        # compares garbage and reports the wrong defect.
        report.note(
            f"the run blocks' log positions {positions} are not contiguous from 0 — "
            "a position is duplicated or missing, so this file describes a different "
            "log than the one it names"
        )
    elif len(positions) != log_size:
        report.note(
            f"this export carries {len(positions)} sealed run(s) and its checkpoint "
            f"commits to {log_size} — the chains verify and the set cannot be checked"
        )
    elif positions and against is not None:
        leaves = [leaf_hash(placed[i][1]) for i in positions]
        if merkle_root(leaves) != against:
            report.note(
                "the Merkle root rebuilt from this export does not match the "
                "checkpoint it claims to be a copy of"
            )

    # A run with no position in the log has an unpinned tail: the root proves
    # nothing about it, so records cut from it before the export was taken are
    # undetectable from this file. Once, with the count and the reason — a
    # coverage line on every report is one a reader learns to skip.
    if open_runs:
        report.unchecked.append(
            f"{open_runs} open run(s) — a run that has not concluded has no position "
            "in the Merkle log, so its chain was verified and records cut from its "
            "tail before the export was taken are undetectable from this file"
        )

    # ── step 6: the root, against a checkpoint from somewhere else ────────
    if not anchors:
        report.unchecked.append(
            "deletion — no external checkpoint was supplied, so the root could only "
            "be rebuilt and compared against this file's own header. That proves the "
            "file is internally consistent, which is also what an editor who dropped "
            "a run and rewrote the header achieves"
        )
    for anchor in anchors:
        if (anchor.origin is not None and anchor.origin != origin) or anchor.size > log_size:
            report.note(
                f"the checkpoint {anchor} names a history this file (log '{origin}' at "
                f"size {log_size}) cannot be part of"
            )
        elif anchor.size == log_size:
            if claimed_root is not None and anchor.root != claimed_root:
                report.note(
                    f"this file's header names a different root than the checkpoint "
                    f"{anchor} — one tree of a given size has one root, so the file "
                    "describes a different history"
                )
        elif positions[: anchor.size] != list(range(anchor.size)) or merkle_root(
            [leaf_hash(placed[i][1]) for i in range(anchor.size)]
        ) != anchor.root:
            # The file carries every leaf from position 0, so a smaller
            # checkpoint is a tree it can rebuild: its own first `size` leaves.
            report.note(
                f"the checkpoint {anchor} commits to this log's first {anchor.size} "
                f"run(s), and this file's first {anchor.size} do not rebuild to it — "
                "a run inside that prefix was removed, replaced or moved"
            )
        else:
            report.unchecked.append(
                f"the checkpoint {anchor} matches this file's first {anchor.size} "
                f"run(s); the {log_size - anchor.size} after it are held only to the "
                "file's own header"
            )

    # ── step 7: cross-layer ───────────────────────────────────────────────
    for case in sorted(stamped - carried):
        report.note(f"a record names case {case}, which this file does not carry")

    # ── step 8: the trailer ───────────────────────────────────────────────
    if trailer is None:
        report.note("no trailer: this file is a prefix, not a whole export")
    else:
        unreadable = trailer.get("unreadable") or []
        declared = {str(entry.get("run")) for entry in unreadable if isinstance(entry, dict)}
        # Complete as an artifact, incomplete as a history: unchecked, not
        # tampered with — the writer said so at export time.
        for entry in unreadable:
            report.unchecked.append(
                f"run {entry.get('run')}: the export declares it unreadable "
                f"({entry.get('reason')}), so nothing about it was verified"
            )
        # A block with no records is honest only when the trailer names its
        # run. Sealed or not: an emptied sealed block has no terminal hash to
        # hold against its seal, so this is the only rule that sees it.
        for run, count in blocks:
            if count == 0 and run not in declared:
                report.note(
                    f"run {run}: its block carries no records and the trailer does not "
                    "declare it unreadable — its records were removed"
                )
        exported = sum(1 for _, count in blocks if count > 0)
        if trailer.get("runs_requested") != len(blocks):
            report.note(
                f"the trailer claims {trailer.get('runs_requested')} run(s) requested "
                f"and the file holds {len(blocks)} run block(s)"
            )
        if trailer.get("runs_exported") != exported:
            report.note(
                f"the trailer claims {trailer.get('runs_exported')} run(s) exported and "
                f"the file holds records for {exported}"
            )
        if trailer.get("records") != report.records:
            report.note(
                f"the trailer claims {trailer.get('records')} records and the file "
                f"holds {report.records}"
            )
        if trailer.get("cases") != report.cases:
            report.note(
                f"the trailer claims {trailer.get('cases')} cases and the file holds "
                f"{report.cases}"
            )

    return report


# ── Section 3: canonical JSON, implemented rather than checked ─────────────
#
# This is the half that produces rather than consumes. Re-canonicalizing a
# record's parsed value and getting its wire bytes back proves an independent
# reader of the specification derives the *same bytes* — which is the claim a
# corpus of this project's own output cannot make about itself.

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def canonical_string(text: str) -> str:
    out = ['"']
    for char in text:
        point = ord(char)
        if point in _ESCAPES:
            out.append(_ESCAPES[point])
        elif point < 0x20:
            out.append(f"\\u{point:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def canonical_number(value: int | float) -> str:
    if isinstance(value, bool):  # bool is an int in Python; JSON says otherwise
        raise TypeError("a bool is not a number")
    if isinstance(value, int):
        # The one departure from JCS: integers stay exact rather than passing
        # through an IEEE-754 double, so two values above 2**53 keep two byte
        # strings.
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{value!r} has no JSON form")
    if value == 0:
        return "0"
    # ECMAScript's number-to-string at radix 10: shortest round-tripping
    # digits, positional inside [1e-6, 1e21), exponential with an explicit
    # sign outside it.
    if abs(value) >= 1e-6 and abs(value) < 1e21:
        text = repr(value)
        if text.endswith(".0"):
            text = text[:-2]
        if "e" in text:  # Python reaches for exponents earlier than ECMAScript
            text = f"{value:.17f}".rstrip("0").rstrip(".")
        return text
    mantissa, exponent = repr(value).split("e")
    if mantissa.endswith(".0"):
        mantissa = mantissa[:-2]
    sign = "+" if not exponent.startswith("-") else "-"
    return f"{mantissa}e{sign}{exponent.lstrip('+-').lstrip('0') or '0'}"


def canonical(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return canonical_string(value)
    if isinstance(value, (int, float)):
        return canonical_number(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785: sorted by UTF-16 code unit of the member name, not by UTF-8
        # byte. The two agree throughout the Basic Multilingual Plane, so this
        # sort key is what an ASCII-only corpus cannot tell apart.
        members = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(f"{canonical_string(k)}:{canonical(v)}" for k, v in members)
            + "}"
        )
    raise TypeError(f"{type(value).__name__} has no canonical form")


# RFC 8785's own number vectors, including the four boundaries a naive
# implementation gets wrong: where positional notation gives way to
# exponential in each direction, the smallest subnormal, and negative zero.
_RFC_8785_NUMBERS: list[tuple[float, str]] = [
    (0.0, "0"),
    (-0.0, "0"),
    (4.5, "4.5"),
    (0.002, "0.002"),
    (1e-6, "0.000001"),
    (1e-7, "1e-7"),
    (1e20, "100000000000000000000"),
    (1e21, "1e+21"),
    (1e30, "1e+30"),
    (1e-27, "1e-27"),
    (9007199254740992.0, "9007199254740992"),
    (333333333.33333329, "333333333.3333333"),
    (9.999999999999997e22, "9.999999999999997e+22"),
    (5e-324, "5e-324"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
    (-4.5, "-4.5"),
    (-1e30, "-1e+30"),
]


def canon_check(path: str) -> int:
    """Re-derive every record vector from its parsed value.

    Non-circular: the input is the *meaning* of each record, and this produces
    the bytes and the chain digest from the specification's rules. A
    disagreement is the two implementations understanding the format
    differently, which is the one thing a single-implementation corpus cannot
    detect.
    """
    failures = 0
    checked = 0
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            vector = json.loads(line)
            raw, claimed = vector["raw"], vector["hash"]
            rebuilt = canonical(json.loads(raw))
            checked += 1
            if rebuilt != raw:
                failures += 1
                print(f"line {number} ({vector['kind']}): canonical bytes differ")
                print(f"  theirs {raw}")
                print(f"  ours   {rebuilt}")
                continue
            digest = sha256(ZERO + rebuilt.encode("utf-8")).hex()
            if digest != claimed:
                failures += 1
                print(
                    f"line {number} ({vector['kind']}): chain digest differs — "
                    f"theirs {claimed}, ours {digest}"
                )
    print(f"{checked - failures}/{checked} record vectors re-derived independently")
    if failures:
        return 1

    # The number rules have no corpus coverage: no record vector carries a
    # double, so `canonical_number`'s float path is exercised by nothing above.
    # RFC 8785 publishes its own vectors, and both implementations are held to
    # them rather than to each other.
    for value, expected in _RFC_8785_NUMBERS:
        got = canonical_number(value)
        if got != expected:
            print(f"RFC 8785 formats {value!r} as {expected!r}; this reader wrote {got!r}")
            failures += 1
    if failures:
        return 1
    print(f"ok   {len(_RFC_8785_NUMBERS)} RFC 8785 number vectors")

    # And the same discipline the export self-test applies: a differential
    # check that agrees with everything is a check that has stopped running.
    # The perturbation is the defect this file exists to have caught — a vector
    # written in struct-declaration order rather than canonical order.
    with open(path, encoding="utf-8") as handle:
        first = json.loads(next(line for line in handle if line.strip()))
    body = json.loads(first["raw"])
    unsorted = json.dumps(
        dict(reversed(list(body.items()))), separators=(",", ":"), ensure_ascii=False
    )
    if canonical(json.loads(unsorted)) == unsorted and len(body) > 1:
        print("the canonicalizer accepted member order it did not choose")
        return 1
    print("ok   a vector in declaration order is not canonical")
    return 0


# ── Proving this verifier bites ────────────────────────────────────────────
# A second implementation that reports "0 findings" for everything agrees with
# the first one perfectly and is worth nothing. `--self-test` takes a file that
# verifies, damages it, and asserts each damage is reported — so the gate checks
# that this reader can still fail, not only that it passed. It also checks the
# other direction: a file that is *not* damaged but carries something this
# reader does not understand has to bound its own verdict rather than pass.

def _damaged(lines: list[dict]) -> list[tuple[str, list[dict], str]]:
    import copy

    cases: list[tuple[str, list[dict], str]] = []

    def record_indexes() -> list[int]:
        return [i for i, l in enumerate(lines) if "kind" not in l]

    first_record = record_indexes()[0]

    edited = copy.deepcopy(lines)
    edited[first_record]["body"]["kind"] = "Swept"
    cases.append(("an edited readable body", edited, "does not match its wire bytes"))

    tampered = copy.deepcopy(lines)
    raw = tampered[first_record]["raw"]
    tampered[first_record]["raw"] = raw.replace('"v":1', '"v":9', 1)
    cases.append(("a flipped wire byte", tampered, "was altered after it was written"))

    dropped = copy.deepcopy(lines)
    del dropped[record_indexes()[1]]
    cases.append(("a record removed from the middle", dropped, "does not link to its predecessor"))

    relabelled = copy.deepcopy(lines)
    for line in relabelled:
        if line.get("kind") == RUN_KIND and "seal" in line:
            line["seal"] = "00" * 32
    cases.append(("a rewritten log leaf", relabelled, "not this run's terminal chain hash"))

    uncased = [l for l in copy.deepcopy(lines) if l.get("kind") != CASE_KIND]
    cases.append(("the case layer dropped", uncased, "which this file does not carry"))

    unheld = copy.deepcopy(lines)
    for line in unheld:
        if line.get("kind") == CASE_KIND:
            del line["hold"]
    cases.append(("a case block without its hold", unheld, "carries no hold member"))

    cases.append(("a file cut short", copy.deepcopy(lines)[:-1], "this file is a prefix"))

    # A sealed run emptied of every record, with the trailer's counts adjusted
    # to match: no terminal hash is left to hold against the seal, so only the
    # empty-block rule sees it.
    emptied = [l for l in copy.deepcopy(lines) if "kind" in l]
    emptied[-1]["records"] = 0
    emptied[-1]["runs_exported"] = 0
    cases.append(("a sealed run emptied, counts adjusted", emptied, "carries no records"))

    miscounted = copy.deepcopy(lines)
    miscounted[-1]["runs_requested"] += 1
    cases.append(("a run block count the trailer disowns", miscounted, "run block(s)"))

    # A conclusion re-drawn over another head, and every hash, seal and root
    # after it rebuilt — so the chain, leaf and root all verify and only the
    # sealing record's own claim is wrong.
    redrawn = copy.deepcopy(lines)
    at = next(i for i, l in enumerate(redrawn) if "kind" not in l and '"RunConcluded"' in l["raw"])
    wire = json.loads(redrawn[at]["raw"])
    wire["chain_head"] = "00" * 32
    raw = canonical(wire)
    head = sha256(bytes.fromhex(redrawn[at]["prev_hash"]) + raw.encode("utf-8"))
    redrawn[at].update(raw=raw, body=wire, hash=head.hex())
    block = max(i for i in range(at) if redrawn[i].get("kind") == RUN_KIND)
    redrawn[block]["seal"] = head.hex()
    seals = sorted(
        (l["index"], bytes.fromhex(l["seal"]))
        for l in redrawn
        if l.get("kind") == RUN_KIND and "seal" in l
    )
    redrawn[0]["checkpoint"]["root"] = merkle_root([leaf_hash(s) for _, s in seals]).hex()
    cases.append(("a conclusion drawn over another head", redrawn, "chain_head is not the head"))

    return cases


def _anchored(lines: list[dict]) -> list[tuple[str, Anchor, str]]:
    """Checkpoints from outside the file that the unedited file must fail."""
    header = lines[0]["checkpoint"]
    return [
        (
            "a prefix anchor the file does not rebuild",
            Anchor(0, sha256(b"another history"), header["origin"]),
            "do not rebuild to it",
        ),
        (
            "an anchor at the file's size with another root",
            Anchor(header["size"], sha256(b"another history"), header["origin"]),
            "different root",
        ),
        (
            "an anchor from another log",
            Anchor(header["size"], bytes.fromhex(header["root"]), "another.example/log"),
            "cannot be part of",
        ),
    ]


def _bounded(lines: list[dict]) -> list[tuple[str, list[dict], str]]:
    """Files that are sound and carry something this reader cannot account for.

    Each must verify with no findings and say what it passed over. A reader that
    reports these as damage is wrong in the expensive direction, and one that
    reports them not at all has described a file it read part of.
    """
    import copy

    ahead = copy.deepcopy(lines)
    for line in ahead:
        if line.get("kind") == HEADER_KIND:
            line["attestation_bundle"] = {"alg": "ml-dsa-65"}
    return [("a framing member from a later writer", ahead, "attestation_bundle")]


def self_test(lines: list[str]) -> int:
    clean = verify(lines)
    if clean.findings:
        print("the reference file does not verify, so nothing below means anything:")
        for finding in clean.findings:
            print(f"  {finding}")
        return 1

    parsed = [json.loads(line) for line in lines if line.strip()]
    failures = 0
    for name, damaged, expected in _damaged(parsed):
        report = verify([json.dumps(line) for line in damaged])
        if any(expected in finding for finding in report.findings):
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: nothing reported {expected!r}; got {report.findings}")
            failures += 1
    for name, ahead, expected in _bounded(parsed):
        report = verify([json.dumps(line) for line in ahead])
        if report.findings:
            print(f"MISS {name}: reported as damage; got {report.findings}")
            failures += 1
        elif any(expected in note for note in report.unchecked):
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: nothing said it passed over {expected!r}")
            failures += 1
    for name, anchor, expected in _anchored(parsed):
        report = verify(lines, [anchor])
        if any(expected in finding for finding in report.findings):
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: nothing reported {expected!r}; got {report.findings}")
            failures += 1

    # The other direction for anchors: the file's own checkpoint, and the empty
    # prefix of it, are histories the file is part of. The prefix match must
    # say how far it reaches.
    header = parsed[0]["checkpoint"]
    whole = verify(lines, [Anchor(header["size"], bytes.fromhex(header["root"]), header["origin"])])
    prefix = verify(lines, [Anchor(0, empty_root(), header["origin"])])
    if whole.findings or prefix.findings:
        print(f"MISS an anchor the file matches: reported {whole.findings + prefix.findings}")
        failures += 1
    elif not any("held only to the file's own header" in n for n in prefix.unchecked):
        print("MISS a prefix anchor: nothing said the rest is held only to the header")
        failures += 1
    else:
        print("ok   an anchor the file matches, whole and as a prefix")

    print(f"{failures} case(s) not reported" if failures else "every case reported")
    return 1 if failures else 0


def parse_anchor(spec: str) -> Anchor | str:
    """A checkpoint argument, or the reason it is not one.

    A bare root is refused: a root without its size names no tree, and reading
    it as the file's own size would hold the file to a claim nobody made.
    """
    import os

    if os.path.isfile(spec):
        try:
            with open(spec, encoding="utf-8") as handle:
                value = json.load(handle)
            origin, size, root = value.get("origin"), value["size"], value["root"]
        except (OSError, ValueError, KeyError, AttributeError) as error:
            return f"{spec}: not a checkpoint file ({error})"
    else:
        parts = spec.rsplit(":", 2)
        if len(parts) == 2:
            origin, (size, root) = None, parts
        elif len(parts) == 3:
            origin, size, root = parts
        else:
            return f"{spec!r}: a checkpoint is SIZE:ROOT or ORIGIN:SIZE:ROOT — a bare root names no tree"
    try:
        size = int(size)
        digest = bytes.fromhex(root)
    except (TypeError, ValueError):
        return f"{spec!r}: the size is not an integer or the root is not hex"
    if size < 0 or len(digest) != 32:
        return f"{spec!r}: a size is non-negative and a root is 32 bytes"
    return Anchor(size, digest, origin)


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[2] == "--canon-check":
        try:
            return canon_check(argv[1])
        except OSError as error:
            print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
            return 2
    if len(argv) == 3 and argv[2] == "--self-test":
        try:
            with open(argv[1], encoding="utf-8") as handle:
                return self_test(handle.readlines())
        except OSError as error:
            print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
            return 2
    if len(argv) < 2 or argv[1].startswith("-"):
        print(
            f"usage: {argv[0]} <export.jsonl> [SIZE:ROOT | ORIGIN:SIZE:ROOT | checkpoint.json]…\n"
            f"       {argv[0]} <export.jsonl> --self-test\n"
            f"       {argv[0]} <records.jsonl> --canon-check",
            file=sys.stderr,
        )
        print(
            "  each checkpoint is one from outside the file — one an earlier audit\n"
            "  printed, or one a witness cosigned. Without one, deletion is unchecked.",
            file=sys.stderr,
        )
        return 2
    anchors = []
    for spec in argv[2:]:
        anchor = parse_anchor(spec)
        if isinstance(anchor, str):
            print(anchor, file=sys.stderr)
            return 2
        anchors.append(anchor)
    try:
        with open(argv[1], encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as error:
        print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
        return 2

    report = verify(lines, anchors)
    for finding in report.findings:
        print(f"finding: {finding}")
    for unchecked in report.unchecked:
        print(f"not checked: {unchecked}")
    print(
        f"{report.runs} runs, {report.records} records, {report.cases} cases, "
        f"{len(report.findings)} findings"
    )
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
