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
    python3 tools/verify_export.py export.jsonl --key KEY_ID=<64 hex> …
    python3 tools/verify_export.py export.jsonl checkpoint.note --witness-key NAME=<base64> \
        --max-checkpoint-age 86400
    python3 tools/verify_export.py export.jsonl --grader-verdict v.json --grader-key ID=<hex>

Each argument after the file is a checkpoint from outside it — `SIZE:ROOT`,
`ORIGIN:SIZE:ROOT`, a JSON file holding `{"origin", "size", "root"}`, or a
cosigned `signed-note` file — and the file is held to every one. The auditor
supplies three disjoint sets of trusted Ed25519 public keys: `--key` for record
signatures (with any, an unsigned record is a finding), `--witness-key` for
the cosignatures on a note anchor, `--grader-key` for a grader verdict's
signature. `--max-checkpoint-age SECS` judges each witness key's latest
verified time against this machine's clock (`--now RFC3339` replaces the clock).
What a run did not check — a signature without its key, an anchor nobody
cosigned, freshness without a maximum age — is named in its output.

Exit 0 when the file verifies, 1 when it does not, 2 when the command line is
malformed, 4 when a file could not be read at all, 6 when it is under a `canon`
this reader does not implement and so cannot be verified here — the statuses
`agentplane verify` uses for the same answers. Findings are printed one per line.

Standard library only, deliberately: an auditor should be able to run this on a
machine with nothing installed.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import sys

# ── Section 1: versioning ──────────────────────────────────────────────────
# "A reader that cannot interpret one refuses; it never guesses."
EXPORT_VERSION = 1
CANON_VERSION = 1

HEADER_KIND = "agentplane.export"
PACKAGE_KIND = "agentplane.disclosure"
RUN_KIND = "agentplane.export.run"
CASE_KIND = "agentplane.export.case"
TRAILER_KIND = "agentplane.export.end"
FRAMING = {HEADER_KIND, PACKAGE_KIND, RUN_KIND, CASE_KIND, TRAILER_KIND}

# The conclusions that seal a run into the log (the specification's sealing
# outcomes). A package places every sealed run it carries, so a run whose last
# conclusion is one of these and whose block carries no leaf had it removed.
SEALED_OUTCOMES = {"succeeded", "cancelled", "abandoned", "swept", "broke-glass", "halt-lifted", "hold-released", "observed"}

# The members each framing line is specified to carry. A later writer may add
# one; this reader passes over it and says so, because a verdict is only as wide
# as the claims the reader understood. Not a refusal: a framing line is not
# hashed and carries no evidence of its own, so an added member falsifies
# nothing already checked — it bounds what "sound" covered. A record line is the
# other answer, and for the reason its members are covered by a hash.
FRAMING_MEMBERS = {
    HEADER_KIND: {"kind", "version", "checkpoint", "canon"},
    PACKAGE_KIND: {"kind", "version", "checkpoint", "canon", "selection"},
    RUN_KIND: {"kind", "run", "index", "seal"},
    CASE_KIND: {"kind", "case", "deadlines", "blobs", "hold", "erasure"},
    TRAILER_KIND: {
        "kind",
        "runs_requested",
        "runs_exported",
        "records",
        "cases",
        "unreadable",
    },
}

# The record vocabulary (the specification's Vocabulary section) and the one
# record version this reader implements. A record of a kind or at a version
# outside them is one this reader cannot interpret: it says so rather than
# passing over it, which is what the Rust reader does through its upcaster.
RECORD_VERSION = 1
RECORD_KINDS = frozenset(
    {
        "RunAdmitted", "QuotaPassStarted", "PlanFrozen", "StepStarted", "StepFinished",
        "Note", "EffectStarted", "EffectDone", "EffectFailed", "EffectReconciled",
        "StepCompensated", "QuarantineDecided", "GroupOpened", "GroupSettled",
        "BudgetRefused", "BudgetReadmitted", "AuthorityWithheld", "AuthorityRestored",
        "IdentityBound", "DataSubjectBound", "PolicyDenied", "RunSuspended",
        "CaseBound", "DeadlineRegistered", "DeadlineTransition", "Released",
        "RunCancelled", "RunConcluded", "BreakGlass", "HaltLifted", "HoldReleased",
        "Swept", "Observed",
    }
)

# A checkpoint origin, by C2SP tlog-cosignature: non-empty UTF-8 of at most 255
# bytes, with no Unicode space, no '+' and no control character below U+0020.
MAX_ORIGIN_BYTES = 255

ZERO = bytes(32)


def origin_refusal(origin: object) -> str | None:
    """Why `origin` cannot name a log, or None — the rule the Rust reader's
    `Checkpoint::validate_origin` states, in its words."""
    if not isinstance(origin, str):
        return f"checkpoint origin: {origin!r} is not a string"
    if not origin:
        return "checkpoint origin: is empty, so it names no log"
    size = len(origin.encode("utf-8"))
    if size > MAX_ORIGIN_BYTES:
        return f"checkpoint origin: is {size} bytes, and a witness accepts at most {MAX_ORIGIN_BYTES}"
    for c in origin:
        if c in UNICODE_WHITESPACE or c == "+" or ord(c) < 0x20:
            return f"checkpoint origin: contains {c!r}, which tlog-cosignature forbids in an origin"
    return None


def is_integer(value: object) -> bool:
    """A JSON integer: Python's bool is an int, and JSON's `true` is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def _finite(text: str) -> float:
    value = float(text)
    if value in (float("inf"), float("-inf")):
        raise ValueError(f"{text} is out of range for a double")
    return value


def loads(text: str) -> object:
    """JSON as RFC 8259 and the Rust reader define it: no NaN or Infinity, and
    no number past the largest double — both of which Python's `json` accepts."""
    return json.loads(text, parse_constant=_no_constant, parse_float=_finite)


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


def path_proves(leaf: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """Whether `path` (siblings, leaf-upwards) proves `leaf` at `index` in the
    tree of `size` leaves whose root is `root` — the inclusion check of
    RFC 9162 §2.1.3.2, over this format's leaf and node hashes."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ── Sections 6 and 7: Ed25519 verification, RFC 8032 §5.1 ─────────────────
# Written from the normative prose of RFC 8032 §5.1 (5.1.2 encoding, 5.1.3
# decoding, 5.1.4 point addition, 5.1.7 verification), not from the
# illustrative code in its §6. Verification only: this reader never signs and
# never makes a key. Strict where the RFC leaves room: S must be below L, the
# public key must be a canonical encoding, the equation is the cofactorless
# one, and the recomputed R is compared as an encoding with the signature's R
# bytes — so a non-canonical R never verifies. Not constant-time; it handles
# only public data.

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = (-121665 * pow(121666, ED_P - 2, ED_P)) % ED_P
# sqrt(-1) mod p, used by the decoding's second square-root case.
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)


def _ed_inv(x: int) -> int:
    return pow(x, ED_P - 2, ED_P)


# A point is (X, Y, Z, T) in extended homogeneous coordinates (§5.1.4):
# x = X/Z, y = Y/Z, x*y = T/Z.
ED_IDENTITY = (0, 1, 1, 0)


def _ed_add(p1: tuple, p2: tuple) -> tuple:
    """Point addition, §5.1.4; complete, so it also doubles."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = t1 * 2 * ED_D * t2 % ED_P
    d = z1 * 2 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def _ed_neg(point: tuple) -> tuple:
    x, y, z, t = point
    return ((-x) % ED_P, y, z, (-t) % ED_P)


def _ed_mul(scalar: int, point: tuple) -> tuple:
    """[scalar]point by double-and-add."""
    result = ED_IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_encode(point: tuple) -> bytes:
    """§5.1.2: y little-endian in 32 bytes, the top bit holding x's low bit."""
    x, y, z, _ = point
    zi = _ed_inv(z)
    x, y = x * zi % ED_P, y * zi % ED_P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(encoded: bytes) -> tuple | None:
    """§5.1.3, refusing every non-canonical encoding: y ≥ p, and x = 0 with
    the sign bit set. None for anything that is not a point."""
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= ED_P:
        return None
    u = (y * y - 1) % ED_P
    v = (ED_D * y * y + 1) % ED_P
    x = u * pow(v, 3, ED_P) * pow(u * pow(v, 7, ED_P), (ED_P - 5) // 8, ED_P) % ED_P
    vxx = v * x * x % ED_P
    if vxx == (-u) % ED_P:
        x = x * ED_SQRT_M1 % ED_P
    elif vxx != u:
        return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = ED_P - x
    return (x, y, 1, x * y % ED_P)


# The base point B of §5.1: y = 4/5, x even.
ED_BASE = _ed_decode((4 * _ed_inv(5) % ED_P).to_bytes(32, "little"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """§5.1.7, cofactorless: [S]B = R + [k]A, checked as encodings.

    False — never an exception — for a key that is not 32 bytes, a signature
    that is not 64, S ≥ L, a key that is not a canonical point encoding, and a
    signature that does not verify."""
    if not isinstance(public, bytes) or not isinstance(signature, bytes):
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    r_bytes, s = signature[:32], int.from_bytes(signature[32:], "little")
    if s >= ED_L:
        return False
    a = _ed_decode(public)
    if a is None:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % ED_L
    check = _ed_add(_ed_mul(s, ED_BASE), _ed_neg(_ed_mul(k, a)))
    return _ed_encode(check) == r_bytes


# ── The verifier ───────────────────────────────────────────────────────────

class Report:
    def __init__(self) -> None:
        self.findings: list[str] = []
        self.records = 0
        self.runs = 0
        self.cases = 0
        self.unverifiable: str | None = None
        self.unchecked: list[str] = []
        # Record signatures that verified under a supplied key.
        self.signatures = 0
        # What each note anchor's cosignatures established.
        self.anchors: list[str] = []
        # Freshness findings: about the witnesses, not the file, so a sidecar's
        # binding is not judged by them.
        self.stale: list[str] = []
        # Per run block: whether it declared a seal, and its record hashes by seq.
        self.blocks: dict[str, dict] = {}

    def note(self, text: str) -> None:
        self.findings.append(text)


# A signature travels as lowercase hex, exactly 128 characters; a key on the
# command line as 64 hex characters of either case, as `agentplane` takes it.
SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}")
KEY_HEX = re.compile(r"[0-9a-fA-F]{64}")


def signature_bytes(encoded: object) -> bytes | None:
    """A signature's 64 bytes from its hex, or None for any other spelling —
    whitespace, a separator, upper case or a wrong length included."""
    if not isinstance(encoded, str) or not SIGNATURE_HEX.fullmatch(encoded):
        return None
    return bytes.fromhex(encoded)


def b64_canonical(text: str) -> bytes | None:
    """RFC 4648 base64 in its one canonical spelling, or None: the standard
    alphabet, padded, and with zero trailing bits — so two spellings never
    decode to one value."""
    try:
        decoded = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    if base64.b64encode(decoded).decode("ascii") != text:
        return None
    return decoded


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
    """A checkpoint from outside the file: an origin (optional), a size, a root.

    An anchor read from a signed note also carries the note's body and its
    signature lines; `cosigned` is filled with each supplied witness key whose
    line verified, and its signed time, and nothing else.
    """

    def __init__(self, size: int, root: bytes, origin: str | None = None) -> None:
        self.size = size
        self.root = root
        self.origin = origin
        self.source: str | None = None
        self.body: bytes | None = None
        # (name, key id ‖ payload) per signature line, as the note carries them.
        self.lines: list[tuple[str, bytes]] = []
        # (name, time) per line that verified under a supplied witness key.
        self.cosigned: list[tuple[str, int]] = []

    def __str__(self) -> str:
        where = f"'{self.origin}' " if self.origin is not None else ""
        return f"{where}size {self.size} root {self.root.hex()}"


# A basis names what established an operator's name; see the format's case
# block. A hold with an empty reason or actor preserves a matter nobody can
# account for.
BASES = {"authenticated", "asserted", "connected"}


RFC3339 = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))"
)


def is_rfc3339(text: str) -> bool:
    """Whether `text` is an RFC 3339 date-time naming a real instant."""
    match = RFC3339.fullmatch(text)
    if match is None:
        return False
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    if match.group(9) is not None and (int(match.group(9)) > 23 or int(match.group(10)) > 59):
        return False
    try:
        datetime.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return False
    return True


def same(a: object, b: object) -> bool:
    """JSON equality that tells `1`, `1.0` and `true` apart, as the wire does."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def erasure_problem(block: dict) -> str | None:
    """Why a case block's `erasure` member is unreadable, or None when it is sound.

    The member is required and may be `null`. A restore that dropped it would
    bring an erased matter back as an ordinary closed one, so a missing or
    malformed record is a finding rather than "not erased".
    """
    if "erasure" not in block:
        return "the case block carries no erasure member"
    erasure = block["erasure"]
    if erasure is None:
        return None
    if not isinstance(erasure, dict) or set(erasure) != {"at", "reason", "complete"}:
        return "the erasure record is malformed: it needs exactly at, reason and complete"
    if not isinstance(erasure["at"], str) or not is_rfc3339(erasure["at"]):
        return "the erasure record is malformed: at is not an RFC 3339 instant"
    if not isinstance(erasure["reason"], str) or not isinstance(erasure["complete"], bool):
        return "the erasure record is malformed: reason is a string and complete a boolean"
    if block.get("hold") is not None:
        return "the case is both erased and held, which no plane writes"
    return None


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
    if not is_rfc3339(hold["placed_at"]):
        return "the legal hold is malformed: placed_at is not an RFC 3339 instant"
    by = hold["by"]
    if (
        not isinstance(by, dict)
        or set(by) != {"actor", "basis"}
        or not isinstance(by["actor"], str)
        or not by["actor"].strip()
        or not isinstance(by["basis"], str)
        or by["basis"] not in BASES
    ):
        return "the legal hold is malformed: by needs a non-empty actor and a known basis"
    return None


# ── Section 6: record signatures ───────────────────────────────────────────
RECORD_DOMAIN = b"io.github.hupe1980.agentplane/record/v1"


def record_signing_input(chain_hash: bytes) -> bytes:
    """What a record's Ed25519 signature covers: SHA-256(domain ‖ 0x00 ‖ hash)."""
    return sha256(RECORD_DOMAIN + b"\x00" + chain_hash)


def check_record_signature(
    line: dict, claimed: bytes, run: object, keys: dict[str, bytes], report: Report
) -> None:
    """One record line's signature under the key its `key_id` names. Called
    only when the auditor supplied keys, so unsigned is a finding here."""
    where = f"run {run}: record {line.get('seq')}'s signature"
    signed = line.get("signature")
    if signed is None:
        report.note(f"{where} is absent, inside a verification that required one")
        return
    if not isinstance(signed, dict) or set(signed) != {"key_id", "signature"}:
        report.note(f"{where} is not a {{key_id, signature}} object: {signed!r}")
        return
    key_id, encoded = signed["key_id"], signed["signature"]
    signature = signature_bytes(encoded)
    if signature is None:
        report.note(f"{where} by {key_id!r} is not 128 lowercase hex characters")
        return
    public = keys.get(key_id) if isinstance(key_id, str) else None
    if public is None:
        report.note(f"{where} is under key {key_id!r}, which was not supplied")
        return
    if not ed25519_verify(public, record_signing_input(claimed), signature):
        report.note(f"{where} by {key_id!r} does not verify")
        return
    report.signatures += 1


# ── Section 7: cosignatures and freshness ──────────────────────────────────
# A witness's cosignature over a checkpoint note, per the Cosignature section.
COSIGNER_KEY_TYPE = 0x04
COSIGNATURE_PAYLOAD = 72
LARGEST_TIMESTAMP = 2**63 - 1


def cosigner_key_id(name: str, public: bytes) -> bytes:
    """SHA-256(name ‖ 0x0A ‖ 0x04 ‖ public key), first four bytes."""
    return sha256(name.encode("utf-8") + b"\n" + bytes([COSIGNER_KEY_TYPE]) + public)[:4]


def cosignature_message(timestamp: int, body: bytes) -> bytes:
    """What a cosignature signs: the header, the time line, then the note body."""
    return b"cosignature/v1\ntime " + str(timestamp).encode("ascii") + b"\n" + body


# A witness key as the reader holds it: by name *and* key id, as the Rust
# reader matches a line, so two keys published under one name are two keys.
Witnesses = dict[tuple[str, bytes], bytes]


def witness_entry(name: str, public: bytes) -> tuple[tuple[str, bytes], bytes]:
    return (name, cosigner_key_id(name, public)), public


def cosignature_time(name: str, decoded: bytes, body: bytes, witnesses: Witnesses) -> int | str:
    """The signed time of one note line when it is a cosignature by a supplied
    witness key: its name and key id both match that key, its payload is one,
    its timestamp is neither 0 nor above 2^63−1, and the signature verifies.
    Otherwise the reason it is not one."""
    public = witnesses.get((name, decoded[:4]))
    if public is None:
        return f"{name}: no supplied --witness-key has this name and key id"
    if len(decoded) != 4 + COSIGNATURE_PAYLOAD:
        return f"{name}: the payload is {len(decoded) - 4} bytes, not {COSIGNATURE_PAYLOAD}"
    timestamp = int.from_bytes(decoded[4:12], "big")
    if timestamp == 0:
        return f"{name}: the timestamp is 0, which a cosignature must not carry"
    if timestamp > LARGEST_TIMESTAMP:
        return f"{name}: the timestamp {timestamp} is above 2^63-1"
    if not ed25519_verify(public, cosignature_message(timestamp, body), decoded[12:]):
        return f"{name}: the signature does not verify"
    return timestamp


def utc(timestamp: int) -> str:
    """A verified time as UTC, or as plain seconds when it is past what a
    calendar date can spell — a far-future time is still a signed one."""
    try:
        moment = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"{timestamp} seconds after the epoch"
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def check_cosignatures(
    anchors: list[Anchor], witnesses: Witnesses, report: Report
) -> None:
    """Fill each note anchor's `cosigned`, and say per anchor what it is."""
    notes = [anchor for anchor in anchors if anchor.body is not None]
    if not notes:
        if anchors:
            report.unchecked.append(
                "cosignatures — no anchor was a cosigned note, so every anchor is a "
                "checkpoint whoever supplied it could have produced"
            )
        return
    if not witnesses:
        report.unchecked.append(
            f"cosignatures — no --witness-key was given, so who cosigned the "
            f"{len(notes)} note anchor(s) is not checked, and each is a checkpoint "
            "whoever supplied it could have produced"
        )
        return
    for anchor in notes:
        reasons = []
        for name, decoded in anchor.lines:
            timestamp = cosignature_time(name, decoded, anchor.body, witnesses)
            if isinstance(timestamp, str):
                reasons.append(timestamp)
            else:
                anchor.cosigned.append((name, timestamp))
        if anchor.cosigned:
            for name, timestamp in anchor.cosigned:
                report.anchors.append(
                    f"the checkpoint {anchor.source} is cosigned by {name} at {utc(timestamp)}"
                )
        else:
            report.anchors.append(
                f"the checkpoint {anchor.source} is not cosigned — none of its "
                f"{len(anchor.lines)} signature line(s) verifies under a supplied "
                f"--witness-key ({'; '.join(reasons)}), so it is a checkpoint whoever "
                "supplied it could have produced"
            )


def judge_freshness(
    anchors: list[Anchor], max_age: int | None, now: int, report: Report
) -> None:
    """Per witness key, its latest verified time against `now`. Keys are never
    compared with each other, and a time whose cosignature did not verify is an
    unauthenticated number, so it is never judged."""
    latest: dict[str, tuple[int, str | None]] = {}
    for anchor in anchors:
        for name, timestamp in anchor.cosigned:
            if name not in latest or timestamp > latest[name][0]:
                latest[name] = (timestamp, anchor.source)
    if max_age is None:
        if latest:
            report.unchecked.append(
                "freshness — the anchors carry verified witness times and no "
                "--max-checkpoint-age was given, so how long each witness has gone "
                "without seeing this log was not judged"
            )
        return
    if not latest:
        report.unchecked.append(
            "freshness — a maximum age was given and no anchor carries a verified "
            "witness time, so there is no signed time to judge"
        )
        return
    unsigned = [str(a.source or a) for a in anchors if not a.cosigned]
    if unsigned:
        report.unchecked.append(
            f"freshness — {', '.join(unsigned)} carry no verified witness time and "
            "were not judged"
        )
    for name, (timestamp, source) in sorted(latest.items()):
        age, ahead = now - timestamp, timestamp - now
        if ahead > max_age:
            report.stale.append(
                f"witness {name}'s latest verified time {utc(timestamp)} (the checkpoint "
                f"{source}) is {ahead} s ahead of this reader's clock, more than the "
                f"maximum of {max_age} s"
            )
        elif age > max_age:
            report.stale.append(
                f"witness {name} is stale: its latest verified time {utc(timestamp)} (the "
                f"checkpoint {source}) is {age} s old, more than the maximum of "
                f"{max_age} s — a suffix removed since then is not detectable"
            )


def verify(
    lines: list[str],
    anchors: list[Anchor] | None = None,
    keys: dict[str, bytes] | None = None,
    witnesses: Witnesses | None = None,
    max_age: int | None = None,
    now: int | None = None,
) -> Report:
    report = Report()
    anchors = anchors or []
    keys = keys or {}
    # Section 10, step 4: a verifier that does not check signatures says so.
    if not keys:
        report.unchecked.append(
            "record signatures — no --key was given, so who signed the records is not "
            "checked"
        )
    check_cosignatures(anchors, witnesses or {}, report)
    judge_freshness(
        anchors,
        max_age,
        int(datetime.datetime.now(datetime.timezone.utc).timestamp()) if now is None else now,
        report,
    )

    open_runs = 0
    package = False
    parsed: list[dict] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = loads(line)
        except ValueError as error:
            report.note(f"line {number} is not JSON: {error}")
            return report
        if not isinstance(value, dict):
            report.note(f"line {number} is not a JSON object")
            return report
        try:
            json.dumps(value, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            report.note(f"line {number} is not JSON: it escapes a lone surrogate")
            return report
        if not isinstance(value.get("kind", ""), str):
            report.note(f"line {number} carries a kind that is not a string")
            return report
        if not parsed and value.get("kind") == PACKAGE_KIND:
            package = True
        known = FRAMING_MEMBERS.get(value.get("kind"))
        if package and value.get("kind") == RUN_KIND:
            known = FRAMING_MEMBERS[RUN_KIND] | {"proof"}
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
    if header.get("kind") not in (HEADER_KIND, PACKAGE_KIND):
        report.note(f"the first line is not a {HEADER_KIND} or {PACKAGE_KIND} header")
        return report
    if not same(header.get("version"), EXPORT_VERSION):
        report.note(
            f"export version {header.get('version')!r} is not one this reader "
            f"implements ({EXPORT_VERSION})"
        )
        return report
    if not same(header.get("canon"), CANON_VERSION):
        # Not a finding: the rule names the digest algorithm, so nothing below
        # can be recomputed here and nothing below is known to be wrong.
        report.unverifiable = (
            f"unknown canon — {header.get('canon')!r} is not the rule this reader "
            f"implements ({CANON_VERSION}), so no digest in the file can be recomputed"
        )
        return report

    checkpoint = header.get("checkpoint")
    if not isinstance(checkpoint, dict):
        report.note("the header carries no checkpoint")
        return report
    refusal = origin_refusal(checkpoint.get("origin"))
    if refusal is not None:
        report.note(f"the header's checkpoint is unreadable: {refusal}")
        return report
    claimed_root = unhex(checkpoint.get("root"), "the checkpoint root", report)
    log_size = checkpoint.get("size")
    if not is_integer(log_size) or log_size < 0:
        report.note("the checkpoint has no integer size")
        return report
    if log_size == 0 and claimed_root is not None and claimed_root != empty_root():
        report.note("a size-0 checkpoint claims a root the empty log cannot have")
    selected_cases: list = []
    if package:
        selection = header.get("selection")
        if (
            not isinstance(selection, dict)
            or set(selection) != {"cases", "runs"}
            or not all(isinstance(selection[k], list) for k in ("cases", "runs"))
            or not (selection["cases"] or selection["runs"])
        ):
            report.note("the package header names no case and no run")
        else:
            selected_cases = selection["cases"]

    # ── the body of the file ──────────────────────────────────────────────
    current_run: str | None = None
    prev_hash = ZERO
    last_seq: int | None = None
    terminal: dict[str, bytes] = {}
    placed: dict[int, tuple[str, bytes]] = {}
    # A package's path per run, as hex strings; checked in step 5.
    paths: dict[str, object] = {}
    stamped: set[str] = set()
    carried: set[str] = set()
    # Each run's last conclusion outcome, for the package's placement rule.
    concluded: dict[str, object] = {}
    trailer: dict | None = None
    # [run, records under its block], one entry per run block in file order.
    blocks: list[list] = []
    origin = checkpoint.get("origin")

    for value in parsed[1:]:
        kind = value.get("kind")

        if kind == RUN_KIND:
            current_run = value.get("run")
            if not isinstance(current_run, str):
                report.note(f"a run block names no run: {current_run!r}")
                current_run = repr(current_run)
            prev_hash = ZERO
            last_seq = None
            report.runs += 1
            if str(current_run) in report.blocks:
                report.note(
                    f"run {current_run}: the file carries it in two blocks, so neither "
                    "is the run's one history"
                )
            blocks.append([str(current_run), 0])
            index, seal = value.get("index"), value.get("seal")
            report.blocks[str(current_run)] = {
                "sealed": index is not None and seal is not None,
                "hashes": {},
            }
            if index is None and seal is None:
                # An open run: not in the log, and that is a state rather than
                # a gap. It is counted, because the root proves nothing about
                # it and a reader deciding what a clean report is worth has to
                # be told how much of the file that covers.
                open_runs += 1
                continue
            if not is_integer(index) or seal is None:
                report.note(f"run {current_run}: a placed run needs both index and seal")
                report.blocks[str(current_run)]["sealed"] = False
                continue
            digest = unhex(seal, f"run {current_run}'s seal", report)
            if digest is None:
                report.blocks[str(current_run)]["sealed"] = False
                continue
            if index in placed:
                report.note(f"log index {index} is claimed by two runs")
            placed[index] = (str(current_run), digest)
            paths[str(current_run)] = value.get("proof")
            continue

        if kind == CASE_KIND:
            report.cases += 1
            case = value.get("case")
            identifier = case.get("id") if isinstance(case, dict) else None
            if identifier is None:
                report.note("a case block carries no identifier")
            else:
                carried.add(str(identifier))
            for problem in (hold_problem(value), erasure_problem(value)):
                if problem is not None:
                    report.note(f"case {identifier}: {problem}")
            continue

        if kind == TRAILER_KIND:
            trailer = value
            continue

        if kind in (HEADER_KIND, PACKAGE_KIND):
            # The first line alone names the checkpoint and the rules: a later
            # header would re-choose them for every run after it.
            report.note(f"a {kind!r} header appears past the first line and was ignored")
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
        if keys:
            check_record_signature(value, claimed, current_run, keys, report)

        try:
            wire = loads(raw)
        except ValueError as error:
            report.note(f"run {current_run}: a record's wire bytes do not parse: {error}")
            continue
        if not isinstance(wire, dict):
            report.note(f"run {current_run}: a record's wire bytes are not a JSON object")
            continue
        # The format's `raw` is canonical bytes: bytes that hash to their claim
        # and that no writer under this canon produces are a finding, and the
        # reference reader refuses to restore them.
        if canonical(wire) != raw:
            report.note(
                f"run {current_run}: record {wire.get('seq')}'s wire bytes are not canonical"
            )
        if not same(value.get("body"), wire):
            report.note(
                f"run {current_run}: record {value.get('seq')}'s readable body does "
                "not match its wire bytes"
            )

        # The record's own vocabulary, before anything is read from it as a
        # record: a version or kind this reader does not implement is a skew
        # it reports, never a shape it reads as the current one.
        if not same(wire.get("v"), RECORD_VERSION):
            report.note(
                f"run {current_run}: record {wire.get('seq')} is at version "
                f"{wire.get('v')!r} and this reader reads {RECORD_VERSION} — a build skew "
                "rather than an edit"
            )
        elif not isinstance(wire.get("kind"), str) or wire["kind"] not in RECORD_KINDS:
            report.note(
                f"run {current_run}: record {wire.get('seq')} is of kind "
                f"{wire.get('kind')!r}, which is not in the record vocabulary"
            )

        seq = wire.get("seq")
        # The line's own `seq` is a copy of the body's, as its `prev_hash` is of
        # the head before it: held to the hashed bytes, so the two readers
        # agree that a line saying something its body does not is a finding.
        if not same(value.get("seq"), seq):
            report.note(
                f"run {current_run}: a record line says seq {value.get('seq')!r} and its "
                f"wire bytes say {seq!r}"
            )
        if not is_integer(seq):
            report.note(f"run {current_run}: a record has no integer seq")
        else:
            if last_seq is None and seq != 1:
                report.note(f"run {current_run}: its first record is seq {seq}, not 1")
            if last_seq is not None and seq != last_seq + 1:
                report.note(
                    f"run {current_run}: seq jumps from {last_seq} to {seq} — the "
                    "record between them is missing"
                )
            last_seq = seq
            if str(current_run) in report.blocks:
                report.blocks[str(current_run)]["hashes"][seq] = claimed.hex()
        if wire.get("run") != current_run:
            report.note(
                f"run {current_run}: a record's own body names run {wire.get('run')!r}"
            )
        # Step 3: a conclusion names the head it was drawn over, which is the
        # head it sits on.
        if wire.get("kind") == "RunConcluded" and current_run is not None:
            concluded[str(current_run)] = wire.get("outcome")
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
    if package:
        # A package's leaves are not the log: each is proved by its own path
        # against the header, and the undisclosed ones are not a deletion.
        for index, (run, seal) in sorted(placed.items()):
            path = paths.get(run)
            hashes = (
                [unhex(h, f"run {run}'s path", report) for h in path]
                if isinstance(path, list)
                else None
            )
            if (
                hashes is None
                or any(h is None for h in hashes)
                or claimed_root is None
                or not path_proves(leaf_hash(seal), index, log_size, hashes, claimed_root)
            ):
                report.note(
                    f"run {run}: its path does not prove its leaf against the header's "
                    "checkpoint"
                )
        leafed = {run for run, _ in placed.values()}
        for run, outcome in concluded.items():
            if outcome in SEALED_OUTCOMES and run not in leafed:
                report.note(
                    f"run {run}: it concluded under an outcome that seals and its block "
                    "carries no leaf — a package places every sealed run it carries"
                )
        report.unchecked.append(
            f"the rest of the log — this file is a disclosure package: the log holds "
            f"{log_size} sealed run(s) and the package proves {len(placed)} of them; "
            "nothing about the others is in the file or was checked"
        )
    elif positions != list(range(len(positions))):
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
    if package:
        if not anchors:
            report.unchecked.append(
                "the header's checkpoint — no external checkpoint was supplied, so each "
                "path was proved against the file's own header"
            )
        for anchor in anchors:
            if anchor.origin is not None and anchor.origin != origin:
                report.note(
                    f"the checkpoint {anchor} names a log other than this package's "
                    f"'{origin}'"
                )
            elif anchor.size != log_size:
                report.unchecked.append(
                    f"the checkpoint {anchor} is not at the package's size {log_size}; a "
                    "package carries no consistency proof, so the two were not compared"
                )
            elif claimed_root is not None and anchor.root != claimed_root:
                report.note(
                    f"this package's header names a different root than the checkpoint "
                    f"{anchor} — one tree of a given size has one root"
                )
        anchors = []
    elif not anchors:
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
    # A package proves inclusion, never completeness; a matter its own header
    # names and its case layer omits is the one omission the file can show.
    for case in sorted(set(map(str, selected_cases)) - carried):
        report.note(f"the package's selection names case {case}, which it does not carry")

    # ── step 8: the trailer ───────────────────────────────────────────────
    if trailer is None:
        report.note("no trailer: this file is a prefix, not a whole export")
    else:
        unreadable = trailer.get("unreadable") or []
        if not isinstance(unreadable, list) or not all(isinstance(e, dict) for e in unreadable):
            report.note("the trailer's unreadable list is not a list of runs and reasons")
            unreadable = []
        declared = {str(entry.get("run")) for entry in unreadable}
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
        if not same(trailer.get("runs_requested"), len(blocks)):
            report.note(
                f"the trailer claims {trailer.get('runs_requested')} run(s) requested "
                f"and the file holds {len(blocks)} run block(s)"
            )
        if not same(trailer.get("runs_exported"), exported):
            report.note(
                f"the trailer claims {trailer.get('runs_exported')} run(s) exported and "
                f"the file holds records for {exported}"
            )
        if not same(trailer.get("records"), report.records):
            report.note(
                f"the trailer claims {trailer.get('records')} records and the file "
                f"holds {report.records}"
            )
        if not same(trailer.get("cases"), report.cases):
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
    # ECMAScript's Number::toString at radix 10, from the shortest digits that
    # round-trip — which `repr` gives — placed by ECMAScript's rule rather than
    # Python's: positional for a decimal exponent n in (-6, 21], exponential
    # with an explicit sign outside it. Python switches to exponents at 1e16
    # and 1e-4, so its spelling cannot be reused, only its digits.
    digits, n = _shortest_digits(value)
    k = len(digits)
    sign = "-" if value < 0 else ""
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * -n + digits
    exponent = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{sign}{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"


def _shortest_digits(value: float) -> tuple[str, int]:
    """The shortest round-tripping decimal digits of |value|, without leading
    or trailing zeros, and n such that |value| = 0.digits × 10**n."""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = whole + fraction
    n = len(whole) + (int(exponent) if exponent else 0)
    significant = digits.lstrip("0")
    n -= len(digits) - len(significant)
    return significant.rstrip("0"), n


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
    # Where Python's own spelling turns exponential and ECMAScript's does not:
    # below 1e-4 and from 1e16.
    (1.2345678901234568e-05, "0.000012345678901234568"),
    (1.2345678901234568e20, "123456789012345680000"),
    (1e16, "10000000000000000"),
    (-5e-05, "-0.00005"),
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

    unerased = copy.deepcopy(lines)
    for line in unerased:
        if line.get("kind") == CASE_KIND:
            del line["erasure"]
    cases.append(("a case block without its erasure record", unerased, "carries no erasure member"))

    misdated = copy.deepcopy(lines)
    for line in misdated:
        if line.get("kind") == CASE_KIND:
            line["erasure"] = {"at": "last tuesday", "reason": "art-17", "complete": True}
    cases.append(("an erasure at no instant", misdated, "at is not an RFC 3339 instant"))

    cases.append(("a file cut short", copy.deepcopy(lines)[:-1], "this file is a prefix"))

    surrogate = copy.deepcopy(lines)
    surrogate[first_record]["body"]["note"] = "\ud800"
    cases.append(("a lone surrogate", surrogate, "lone surrogate"))

    retyped = copy.deepcopy(lines)
    retyped[first_record]["body"]["seq"] = float(retyped[first_record]["body"]["seq"])
    cases.append(("a body integer retyped as a float", retyped, "does not match its wire bytes"))

    # The file's last record, re-hashed so its own link holds: one with a
    # successor would also break the next link, which is not what this asks.
    respelled = copy.deepcopy(lines)
    last = record_indexes()[-1]
    raw = respelled[last]["raw"]
    spelled = raw.replace(",", ", ", 1)
    respelled[last]["raw"] = spelled
    respelled[last]["hash"] = sha256(
        bytes.fromhex(respelled[last]["prev_hash"]) + spelled.encode("utf-8")
    ).hex()
    cases.append(("a record spelled non-canonically", respelled, "not canonical"))

    renumbered = copy.deepcopy(lines)
    for i in record_indexes():
        wire = json.loads(renumbered[i]["raw"])
        wire["seq"] += 1
        renumbered[i]["raw"] = canonical(wire)
        renumbered[i]["body"] = wire
    cases.append(("a run whose first seq is not 1", renumbered, "not 1"))

    undated = copy.deepcopy(lines)
    for line in undated:
        if line.get("kind") == CASE_KIND and line.get("hold"):
            line["hold"]["placed_at"] = "last tuesday"
    cases.append(("a hold placed at no instant", undated, "not an RFC 3339 instant"))

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


# One bad origin of each class tlog-cosignature names, and the class a reader
# must say it refused.
BAD_ORIGINS = [
    ("an empty origin", "", "is empty"),
    ("an origin past 255 bytes", "a" * 256, "is 256 bytes"),
    ("an origin with a space", "agentplane/acme corp", "contains ' '"),
    ("an origin with U+00A0", "agentplane/acme\u00a0corp", "contains '\\xa0'"),
    ("an origin with U+3000", "agentplane/acme\u3000corp", "contains '\\u3000'"),
    ("an origin with a plus", "agentplane/a+b", "contains '+'"),
    ("an origin with a newline", "agentplane\nforged", "contains '\\n'"),
    ("an origin with a tab", "agentplane\tlog", "contains '\\t'"),
    ("an origin with a control character", "agentplane\x01", "contains '\\x01'"),
]


def _origin_cases(lines: list[dict]) -> int:
    """Each bad origin, refused in the header, in a note, in a JSON checkpoint
    file and in an ORIGIN:SIZE:ROOT anchor; and the bound and a multi-byte
    character accepted. The number of cases not answered as expected."""
    import copy
    import tempfile

    failures = 0
    header = lines[0]["checkpoint"]
    root_b64 = base64.b64encode(bytes.fromhex(header["root"])).decode("ascii")
    for name, origin, expected in BAD_ORIGINS:
        damaged = copy.deepcopy(lines)
        damaged[0]["checkpoint"]["origin"] = origin
        report = verify([json.dumps(line) for line in damaged])
        refusals = {
            "the header": any("origin" in f and expected in f for f in report.findings),
            # A newline or a control character breaks the note's own structure
            # first, so a note is held to being refused, not to naming why.
            "a note": isinstance(
                parse_note("note", f"{origin}\n{header['size']}\n{root_b64}\n\n— w AAAAAAA=\n"), str
            ),
            "an anchor": expected in str(parse_anchor(f"{origin}:{header['size']}:{header['root']}")),
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"origin": origin, "size": header["size"], "root": header["root"]}, f)
        try:
            refusals["a JSON checkpoint"] = expected in str(parse_anchor(f.name))
        finally:
            os.unlink(f.name)
        missed = [where for where, refused in refusals.items() if not refused]
        if missed:
            print(f"MISS {name}: not refused naming {expected!r} in {', '.join(missed)}")
            failures += 1
        else:
            print(f"ok   {name}, refused in the header, a note and both anchor forms")
    for name, origin in [("an origin of exactly 255 bytes", "é" * 127 + "a"), ("a conforming origin", "example.com/log42")]:
        if origin_refusal(origin) is not None or not isinstance(
            parse_anchor(f"{origin}:{header['size']}:{header['root']}"), Anchor
        ):
            print(f"MISS {name}: refused")
            failures += 1
        else:
            print(f"ok   {name} is accepted")
    return failures


def _strict_json_cases(lines: list[dict]) -> int:
    """Bytes Python's json reads and the format does not: each is a finding,
    never a traceback. The number of cases not answered as expected."""
    import copy

    failures = 0
    first = next(i for i, l in enumerate(lines) if "kind" not in l)

    def relinked(raw: str) -> list[dict]:
        out = copy.deepcopy(lines)
        out[first]["raw"] = raw
        out[first]["hash"] = sha256(bytes.fromhex(out[first]["prev_hash"]) + raw.encode()).hex()
        return out

    wire = json.loads(lines[first]["raw"])
    cases = [
        ("a NaN in a record's wire bytes", relinked(lines[first]["raw"][:-1] + ',"x":NaN}'), "do not parse"),
        ("an Infinity in a record's wire bytes", relinked(lines[first]["raw"][:-1] + ',"x":Infinity}'), "do not parse"),
        ("a number past the largest double", relinked(lines[first]["raw"][:-1] + ',"x":1e400}'), "do not parse"),
        ("a record whose wire bytes are an array", relinked("[1,2]"), "not a JSON object"),
        ("a record of a kind outside the vocabulary", relinked(canonical(dict(wire, kind="Teleported"))), "not in the record vocabulary"),
    ]
    boolean_size = copy.deepcopy(lines)
    boolean_size[0]["checkpoint"]["size"] = True
    cases.append(("a checkpoint size of true", boolean_size, "no integer size"))
    boolean_version = copy.deepcopy(lines)
    boolean_version[0]["version"] = True
    cases.append(("an export version of true", boolean_version, "export version"))
    # `false` is the index Python's bool would read as 0, the one position a
    # contiguity check cannot tell from the integer.
    boolean_index = copy.deepcopy(lines)
    for line in boolean_index:
        if line.get("kind") == RUN_KIND and is_integer(line.get("index")) and line["index"] == 0:
            line["index"] = False
    cases.append(("a log index of false", boolean_index, "needs both index and seal"))
    reseq = copy.deepcopy(lines)
    reseq[first]["seq"] = reseq[first]["seq"] + 7
    cases.append(("a line seq its body does not say", reseq, "wire bytes say"))
    for name, damaged, expected in cases:
        try:
            report = verify([json.dumps(line) for line in damaged])
        except Exception as error:  # noqa: BLE001 — a traceback is the defect
            print(f"MISS {name}: raised {error!r}")
            failures += 1
            continue
        if any(expected in f for f in report.findings):
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: nothing reported {expected!r}; got {report.findings}")
            failures += 1
    return failures


def _older_shape(lines: list[dict]) -> list[dict]:
    """The reference file as a build one record shape older wrote it: each
    `StepStarted` at version 0 with `skill` named `name`, and every hash, seal
    and root re-derived. Hashes cover the bytes as written, so it must verify."""
    import copy

    older = copy.deepcopy(lines)
    prev, block = ZERO, None
    for line in older:
        if line.get("kind") == RUN_KIND:
            prev, block = ZERO, line
            continue
        if "kind" in line:
            continue
        wire = json.loads(line["raw"])
        if wire.get("kind") == "StepStarted":
            wire["name"] = wire.pop("skill")
            wire["v"] = 0
        if wire.get("kind") == "RunConcluded":
            wire["chain_head"] = prev.hex()
        raw = canonical(wire)
        digest = sha256(prev + raw.encode())
        line.update(body=wire, prev_hash=prev.hex(), hash=digest.hex(), raw=raw)
        prev = digest
        if block is not None and "seal" in block:
            block["seal"] = digest.hex()
    seals = sorted(
        (l["index"], bytes.fromhex(l["seal"])) for l in older if l.get("kind") == RUN_KIND and "seal" in l
    )
    older[0]["checkpoint"]["root"] = merkle_root([leaf_hash(s) for _, s in seals]).hex()
    return older


# RFC 8032 §7.1, the five Ed25519 vectors: (name, public key, message, signature),
# copied as published.
RFC8032_VECTORS = [
    (
        "TEST 1",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "TEST 2",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
    (
        "TEST 3",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    ),
    (
        "TEST 1024",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        (
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
            "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
            "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
            "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
            "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
            "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
            "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
            "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
            "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
            "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
            "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
            "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
            "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
            "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
            "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
            "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
            "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
            "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
            "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
            "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
            "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
            "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
            "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
            "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
            "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
            "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
            "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
            "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
            "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
            "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
            "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
            "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
        ),
        (
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
            "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        ),
    ),
    (
        "TEST SHA(abc)",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
        (
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
            "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        ),
    ),
]


def _flip(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def _ed25519_cases() -> int:
    """The verifier against RFC 8032 §7.1, then the strictness rules; the
    number of cases not answered as expected."""
    import time

    failures = 0

    def expect(name: str, got: bool, want: bool) -> None:
        nonlocal failures
        if got is want:
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: verified {got}, expected {want}")
            failures += 1

    for name, public, message, signature in RFC8032_VECTORS:
        a, m, s = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
        expect(f"Ed25519 {name} verifies", ed25519_verify(a, m, s), True)
        expect(f"Ed25519 {name}, one signature bit flipped", ed25519_verify(a, m, _flip(s, 300)), False)
        expect(f"Ed25519 {name}, one key bit flipped", ed25519_verify(_flip(a, 9), m, s), False)
        flipped = _flip(m, 3) if m else b"\x01"
        expect(f"Ed25519 {name}, one message bit flipped", ed25519_verify(a, flipped, s), False)

    _, public, message, signature = RFC8032_VECTORS[0]
    a, m, s = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    s_plus_l = s[:32] + (int.from_bytes(s[32:], "little") + ED_L).to_bytes(32, "little")
    expect("Ed25519 S + L (a non-canonical S)", ed25519_verify(a, m, s_plus_l), False)
    # y = p is a second spelling of y = 0, which is a point; only the encoding
    # is non-canonical.
    expect("Ed25519 an R with y = p", ed25519_verify(a, m, ED_P.to_bytes(32, "little") + s[32:]), False)
    expect("Ed25519 a key with y = p", ed25519_verify(ED_P.to_bytes(32, "little"), m, s), False)
    # Each strictness rule against a signature that verifies but for that rule:
    # with s = 0 and the identity as key, [S]B − [k]A is the identity, whose
    # canonical encoding is 01 00…; a second spelling of a point is refused
    # only by the rule under test.
    identity = (1).to_bytes(32, "little")
    zero_s = bytes(32)
    expect("Ed25519 the identity key with the identity R verifies", ed25519_verify(identity, m, identity + zero_s), True)
    noncanonical = (ED_P + 1).to_bytes(32, "little")
    expect("Ed25519 a key spelled y = p + 1", ed25519_verify(noncanonical, m, identity + zero_s), False)
    negative_zero = ((1 << 255) | 1).to_bytes(32, "little")
    expect("Ed25519 a key with x = 0 and the sign bit set", ed25519_verify(negative_zero, m, identity + zero_s), False)
    expect("Ed25519 an R spelled y = p + 1", ed25519_verify(identity, m, noncanonical + zero_s), False)
    expect("Ed25519 a 31-byte key", ed25519_verify(a[:31], m, s), False)
    expect("Ed25519 a 63-byte signature", ed25519_verify(a, m, s[:63]), False)
    expect("Ed25519 a 65-byte signature", ed25519_verify(a, m, s + b"\x00"), False)

    rounds = 20
    started = time.perf_counter()
    for _ in range(rounds):
        ed25519_verify(a, m, s)
    elapsed = (time.perf_counter() - started) / rounds
    print(f"     Ed25519: {1 / elapsed:.0f} verifications per second ({elapsed * 1000:.1f} ms each)")
    return failures


def _signed_cases(directory: str) -> int:
    """Record signatures over the signed reference export beside the unsigned
    one, under the keys published with it: clean, then damaged one way per
    rule. Only damage made without signing — this reader never signs."""
    import copy

    try:
        with open(os.path.join(directory, "export.signed.jsonl"), encoding="utf-8") as handle:
            signed = handle.readlines()
        with open(os.path.join(directory, "keys.txt"), encoding="utf-8") as handle:
            flags = handle.read().split()
    except OSError as error:
        print(f"MISS the signed reference artifacts: {error}")
        return 1
    keys = {}
    for flag, value in zip(flags[::2], flags[1::2]):
        if flag == "--key":
            key = parse_key(value)
            if isinstance(key, str):
                print(f"MISS the published record key: {key}")
                return 1
            keys[key[0]] = key[1]

    failures = 0
    clean = verify(signed, keys=keys)
    records = sum(1 for line in signed if '"raw"' in line)
    if clean.findings or clean.signatures != records or records == 0:
        print(f"MISS the signed reference export: {clean.signatures} of {records} "
              f"signatures verified; {clean.findings}")
        return 1
    print(f"ok   the signed reference export: {clean.signatures} record signatures verified")
    if not any("record signatures" in n for n in verify(signed).unchecked):
        print("MISS no --key: nothing said record signatures were not checked")
        failures += 1

    parsed = [json.loads(line) for line in signed if line.strip()]
    at = {line["seq"]: i for i, line in enumerate(parsed) if "raw" in line}
    run = json.loads(parsed[at[2]]["raw"])["run"]

    def damaged(seq: int, change) -> list[dict]:
        lines = copy.deepcopy(parsed)
        change(lines[at[seq]], lines)
        return lines

    def flip(line: dict, _lines: list[dict]) -> None:
        raw = bytearray(bytes.fromhex(line["signature"]["signature"]))
        raw[10] ^= 1
        line["signature"]["signature"] = raw.hex()

    def swap(line: dict, lines: list[dict]) -> None:
        other = lines[at[2]]
        line["signature"], other["signature"] = other["signature"], line["signature"]

    def strip(line: dict, _lines: list[dict]) -> None:
        line["signature"] = None

    def rename(line: dict, _lines: list[dict]) -> None:
        line["signature"]["key_id"] = "golden-nobody"

    def plus_l(line: dict, _lines: list[dict]) -> None:
        raw = bytes.fromhex(line["signature"]["signature"])
        s = int.from_bytes(raw[32:], "little") + ED_L
        line["signature"]["signature"] = (raw[:32] + s.to_bytes(32, "little")).hex()

    for name, seq, change in [
        ("a record signature with one byte flipped", 2, flip),
        ("two records' signatures swapped", 1, swap),
        ("a record signature set to null under a key", 2, strip),
        ("a record signature under a key id nobody supplied", 2, rename),
        ("a record signature with S + L in place of S", 2, plus_l),
    ]:
        report = verify([json.dumps(line) for line in damaged(seq, change)], keys=keys)
        named = f"run {run}: record {seq}'s signature"
        if any(named in finding for finding in report.findings):
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: nothing named {named!r}; got {report.findings}")
            failures += 1
    failures += _cosigned_cases(directory, signed, flags)
    failures += _graded_cases(directory, clean, flags)
    return failures


def _flag_values(flags: list[str], wanted: str) -> list[str]:
    return [value for flag, value in zip(flags[::2], flags[1::2]) if flag == wanted]


# Cosignature lines the published golden witness key signed over the reference
# note body at time 0 and at time 2^63 — times the format refuses — so the
# self-test can show each time rule refusing a signature that otherwise verifies.
BOUND_AT_ZERO = "3mBVAwAAAAAAAAAACbeOg0Ihk7uDP6nWr3x0Fq4xPbKigtF45xaQvqh+9w2/Mgbvt2BWrzesrDKLorzMHAWFQwowQpx14aJKVw7BCQ=="
BOUND_PAST_LARGEST = "3mBVA4AAAAAAAAAA8tBzxb5/ug+c9kN9QsJorbfTj2TOYnJFbqoh50LsB8kJb96oRSTqS1nVJkuGBnU646+6p0VDIS0m70VibqBBDA=="


def _cosigned_cases(directory: str, signed: list[str], flags: list[str]) -> int:
    """Cosignatures and freshness over the cosigned reference note, under the
    witness key published with it: clean, then each way a line stops being a
    cosignature, then the age rule against a fixed clock."""
    path = os.path.join(directory, "checkpoint.cosigned.note")
    try:
        with open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
    except OSError as error:
        print(f"MISS the cosigned reference note: {error}")
        return 1
    witnesses = {}
    for value in _flag_values(flags, "--witness-key"):
        key = parse_witness_key(value)
        if isinstance(key, str):
            print(f"MISS the published witness key: {key}")
            return 1
        witnesses.update([witness_entry(*key)])

    def checked(note: str, **extra) -> Report | str:
        anchor = parse_note(path, note)
        if isinstance(anchor, str):
            return anchor
        return verify(signed, [anchor], witnesses=witnesses, **extra)

    failures = 0
    report = checked(text)
    if isinstance(report, str) or report.findings or not any(
        "is cosigned by" in line for line in report.anchors
    ):
        print(f"MISS the cosigned reference note: {report}")
        return 1
    print("ok   the cosigned reference note names its witness")
    reference = parse_note(path, text)
    body, (name, clean) = reference.body.decode("utf-8")[:-1], reference.lines[0]
    at = int.from_bytes(clean[4:12], "big")

    def note(body: str, name: str, decoded: bytes) -> str:
        return f"{body}\n\n— {name} {base64.b64encode(decoded).decode('ascii')}\n"

    def changed(index: slice, value: bytes) -> bytes:
        decoded = bytearray(clean)
        decoded[index] = value
        return bytes(decoded)

    for case, damaged in [
        ("a cosignature byte flipped", note(body, name, changed(slice(22, 23), bytes([clean[22] ^ 1])))),
        ("the payload's timestamp edited", note(body, name, changed(slice(11, 12), bytes([clean[11] ^ 1])))),
        ("a note body line edited", note(body.replace("agentplane\n", "agentplanf\n", 1), name, clean)),
        ("the key id changed with the name kept", note(body, name, changed(slice(0, 1), bytes([clean[0] ^ 1])))),
        ("the name changed with the key id kept", note(body, name[:-1] + "z", clean)),
        ("a cosignature payload of 71 bytes", note(body, name, clean[:-1])),
        ("a zero cosignature timestamp", note(body, name, changed(slice(4, 12), bytes(8)))),
    ]:
        report = checked(damaged)
        if not isinstance(report, str) and any("is not cosigned" in a for a in report.anchors) and not any(
            "is cosigned by" in a for a in report.anchors
        ):
            print(f"ok   {case}")
        else:
            print(f"MISS {case}: the line was honoured; got {report if isinstance(report, str) else report.anchors}")
            failures += 1

    # Lines the published witness key genuinely signed, over the reference body,
    # at the two times the format refuses: each verifies but for its time rule.
    signed_body = (body + "\n").encode("utf-8")
    for case, encoded, expected in [
        ("a signed cosignature at time 0", BOUND_AT_ZERO, "the timestamp is 0"),
        ("a signed cosignature at time 2^63", BOUND_PAST_LARGEST, "above 2^63-1"),
    ]:
        refusal = cosignature_time(name, base64.b64decode(encoded), signed_body, witnesses)
        if isinstance(refusal, str) and expected in refusal:
            print(f"ok   {case}")
        else:
            print(f"MISS {case}: got {refusal!r}, expected {expected!r}")
            failures += 1

    for case, now, expected in [
        ("a witness older than the maximum age", at + 120, "s old"),
        ("a witness ahead of the reader's clock", at - 120, "s ahead"),
    ]:
        report = checked(text, max_age=60, now=now)
        if not isinstance(report, str) and any(name in s and expected in s for s in report.stale):
            print(f"ok   {case}")
        else:
            print(f"MISS {case}: nothing reported {expected!r}")
            failures += 1
    report = checked(text, max_age=60, now=at + 30)
    if isinstance(report, str) or report.stale:
        print(f"MISS a witness within the maximum age: {report if isinstance(report, str) else report.stale}")
        failures += 1
    else:
        print("ok   a witness within the maximum age")
    unverified = note(body, name, changed(slice(22, 23), bytes([clean[22] ^ 1])))
    report = checked(unverified, max_age=60, now=at + 120)
    if not isinstance(report, str) and not report.stale and any(
        "no anchor carries a verified" in n for n in report.unchecked
    ):
        print("ok   a time whose cosignature does not verify is not judged")
    else:
        print("MISS a time whose cosignature does not verify was judged")
        failures += 1
    return failures


def _graded_cases(directory: str, clean: Report, flags: list[str]) -> int:
    """Grader-verdict signatures over the signed reference sidecar, under the
    grader key published with it: clean, then damage made without signing."""
    try:
        with open(os.path.join(directory, "export.grader-verdict.json"), encoding="utf-8") as handle:
            sidecar = json.load(handle)
    except (OSError, ValueError) as error:
        print(f"MISS the signed reference sidecar: {error}")
        return 1
    graders = {}
    for value in _flag_values(flags, "--grader-key"):
        key = parse_key(value)
        if isinstance(key, str):
            print(f"MISS the published grader key: {key}")
            return 1
        graders[key[0]] = key[1]

    failures = 0
    component, reason = check_sidecar(json.dumps(sidecar), clean, graders)
    if component is None and "signed by grader key" in reason:
        print("ok   the signed reference sidecar holds under its grader key")
    else:
        print(f"MISS the signed reference sidecar: {component!r} ({reason})")
        failures += 1
    component, reason = check_sidecar(json.dumps(sidecar), clean)
    if component is None and "not checked" in reason:
        print("ok   no --grader-key: the sidecar's signature is said to be not checked")
    else:
        print(f"MISS no --grader-key: {component!r} ({reason})")
        failures += 1
    unsigned = {k: v for k, v in sidecar.items() if k != "signature"}
    for case, damaged in [
        ("a signed sidecar's content swapped", dict(sidecar, content="ZmFpbA==")),
        ("a sidecar's signature removed under a grader key", unsigned),
    ]:
        component, reason = check_sidecar(json.dumps(damaged), clean, graders)
        if component == "signature":
            print(f"ok   {case}")
        else:
            print(f"MISS {case}: expected 'signature', got {component!r} ({reason})")
            failures += 1
    return failures


def self_test(lines: list[str], directory: str = ".") -> int:
    import copy

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
    # This reader implements one record version, as the Rust reader does with no
    # upcaster: a record at another is a skew it names, never an edit and never
    # a shape it reads as the current one.
    older = verify([json.dumps(line) for line in _older_shape(parsed)])
    skews = [f for f in older.findings if "build skew rather than an edit" in f]
    if not skews or any("altered" in f for f in older.findings):
        print(f"MISS a record at an older shape: reported {older.findings}")
        failures += 1
    else:
        print("ok   a record at an older shape is a skew, not an edit")
    foreign = copy.deepcopy(parsed)
    foreign[0]["canon"] = 999
    report = verify([json.dumps(line) for line in foreign])
    if report.findings or report.unverifiable is None:
        print(f"MISS an unknown canon: {report.findings or 'nothing said it was unverifiable'}")
        failures += 1
    else:
        print("ok   an unknown canon is unverifiable, not damage")
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

    # Grader-verdict sidecars, built over the reference file's first run.
    run, block = next(iter(clean.blocks.items()))
    hashes = block["hashes"]
    first, last = min(hashes), max(hashes)
    base = {
        "kind": SIDECAR_KIND,
        "version": SIDECAR_VERSION,
        "run": run,
        "last_seq": first,
        "last_hash": hashes[first],
        "open": True,
        "content": "cGFzcw==",
    }
    sealed = dict(base, last_seq=last, last_hash=hashes[last], open=not block["sealed"])
    for name, sidecar, expected in [
        ("a sidecar over a prefix", base, None),
        ("a sidecar over the whole run", sealed, None),
        ("a sidecar over an edited prefix", dict(base, last_hash="00" * 32), "last_hash"),
        ("a sidecar past the last record", dict(base, last_seq=last + 1), "last_seq"),
        ("a prefix claimed sealed", dict(base, open=False), "open"),
        ("a sidecar naming no run here", dict(base, run="run_00000000000000000000000000"), "run"),
        ("a sidecar with an unknown member", dict(base, grade="A"), "format"),
        ("a sidecar whose content is not base64", dict(base, content="!"), "format"),
    ]:
        component, reason = check_sidecar(json.dumps(sidecar), clean)
        if component == expected:
            print(f"ok   {name}")
        else:
            print(f"MISS {name}: expected {expected!r}, got {component!r} ({reason})")
            failures += 1
    broken = copy.deepcopy(parsed)
    for line in broken:
        if line.get("kind") not in FRAMING and line.get("raw") and json.loads(line["raw"]).get("run") == run:
            line["hash"] = "00" * 32
            break
    component, _ = check_sidecar(json.dumps(base), verify([json.dumps(line) for line in broken]))
    if component == "soundness":
        print("ok   a sidecar over a run that does not verify")
    else:
        print(f"MISS a sidecar over a run that does not verify: got {component!r}")
        failures += 1

    failures += _origin_cases(parsed)
    failures += _strict_json_cases(parsed)
    failures += _ed25519_cases()
    failures += _signed_cases(directory)

    print(f"{failures} case(s) not reported" if failures else "every case reported")
    return 1 if failures else 0


# ── Grader-verdict sidecars ────────────────────────────────────────────────
SIDECAR_KIND = "agentplane.grader-verdict"
SIDECAR_VERSION = 1
SIDECAR_MEMBERS = {"kind", "version", "run", "last_seq", "last_hash", "open", "content", "signature"}


GRADER_DOMAIN = b"io.github.hupe1980.agentplane/grader-verdict/v1"


def sidecar_signing_input(sidecar: dict) -> bytes:
    """SHA-256(domain ‖ 0x00 ‖ SHA-256(canonical(sidecar without signature)))."""
    unsigned = {k: v for k, v in sidecar.items() if k != "signature"}
    return sha256(GRADER_DOMAIN + b"\x00" + sha256(canonical(unsigned).encode("utf-8")))


def check_sidecar(
    raw: str, report: Report, graders: dict[str, bytes] | None = None
) -> tuple[str | None, str]:
    """`(component, reason)`: the part of the sidecar that does not hold, or
    `(None, what it binds)`. With grader keys, an unsigned sidecar or one whose
    signature does not verify under the key its `key_id` names is refused
    naming `signature`; without, the signature is said not to be checked."""
    try:
        sidecar = json.loads(raw)
    except json.JSONDecodeError as error:
        return "format", f"not JSON: {error}"
    if not isinstance(sidecar, dict):
        return "format", "not a JSON object"
    unknown = sorted(set(sidecar) - SIDECAR_MEMBERS)
    if unknown:
        return "format", f"carries {', '.join(unknown)}, which the format does not define"
    if sidecar.get("kind") != SIDECAR_KIND:
        return "format", f"kind is {sidecar.get('kind')!r}, not {SIDECAR_KIND!r}"
    if not same(sidecar.get("version"), SIDECAR_VERSION):
        return "format", f"version {sidecar.get('version')!r} is not {SIDECAR_VERSION}"
    run, last_seq, last_hash, still_open = (
        sidecar.get("run"),
        sidecar.get("last_seq"),
        sidecar.get("last_hash"),
        sidecar.get("open"),
    )
    content = sidecar.get("content")
    if (
        not isinstance(run, str)
        or type(last_seq) is not int
        or not isinstance(last_hash, str)
        or type(still_open) is not bool
        or not isinstance(content, str)
    ):
        return "format", "run, last_seq, last_hash, open or content has the wrong type"
    try:
        decoded = base64.b64decode(content, validate=True)
    except ValueError:
        return "format", "content is not base64"
    if base64.b64encode(decoded).decode("ascii") != content:
        return "format", "content is not canonical base64"
    if "signature" in sidecar and not isinstance(sidecar["signature"], dict):
        return "format", "signature is not an object"

    block = report.blocks.get(run)
    if block is None:
        return "run", f"the export carries no run {run}"
    # A finding about this run, or one about the file as a whole, means the
    # prefix is not known to be what was written.
    if any(f"run {run}" in finding or not finding.startswith("run ") for finding in report.findings):
        return "soundness", f"run {run} does not verify in this export, so the binding binds nothing"
    hashes = block["hashes"]
    if last_seq not in hashes:
        return "last_seq", f"run {run} has no record at seq {last_seq}"
    if hashes[last_seq] != last_hash.lower():
        return "last_hash", f"the record at seq {last_seq} of run {run} is not the one the verdict was bound to"
    last = max(hashes) if hashes else 0
    if not still_open and not (block["sealed"] and last == last_seq):
        return "open", f"the sidecar claims run {run} sealed at seq {last_seq}, and the export does not"
    binds = f"binds records 1..={last_seq} of run {run} ({last - last_seq} record(s) past it)"
    if not graders:
        return None, (
            f"{binds}; no --grader-key was given, so who signed the verdict is not checked"
        )
    signed = sidecar.get("signature")
    if signed is None:
        return "signature", "the sidecar is unsigned and a grader key was supplied"
    key_id, encoded = signed.get("key_id"), signed.get("signature")
    signature = signature_bytes(encoded) or b""
    public = graders.get(key_id) if isinstance(key_id, str) else None
    if public is None:
        return "signature", f"the signature is under grader key {key_id!r}, which was not supplied"
    if not ed25519_verify(public, sidecar_signing_input(sidecar), signature):
        return "signature", f"the signature does not verify under grader key {key_id!r}"
    return None, (
        f"{binds}, signed by grader key {key_id!r} — not what the grader saw, and not "
        "whether the verdict is right"
    )


def parse_anchor(spec: str) -> Anchor | str:
    """A checkpoint argument, or the reason it is not one.

    A bare root is refused: a root without its size names no tree, and reading
    it as the file's own size would hold the file to a claim nobody made.
    """
    if os.path.isfile(spec):
        try:
            with open(spec, encoding="utf-8", newline="") as handle:
                text = handle.read()
        except (OSError, ValueError) as error:
            return f"{spec}: not a checkpoint file ({error})"
        if not text.lstrip().startswith("{"):
            return parse_note(spec, text)
        try:
            value = loads(text)
            origin, size, root = value.get("origin"), value["size"], value["root"]
        except (ValueError, KeyError, AttributeError) as error:
            return f"{spec}: not a checkpoint file ({error})"
        if not is_integer(size) or not isinstance(root, str):
            return f"{spec}: not a checkpoint file (the size is not an integer or the root not a string)"
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
    if origin is not None:
        refusal = origin_refusal(origin)
        if refusal is not None:
            return f"{spec!r}: {refusal}"
    anchor = Anchor(size, digest, origin)
    anchor.source = spec
    return anchor


SIZE_LINE = re.compile(r"0|[1-9][0-9]*")


# What `signed-note` and the Rust reader refuse in a body and in a key name:
# a control character other than a body's newlines, and — in a name — any
# whitespace or an em dash, which the signature line uses as structure. The
# whitespace set is Unicode's White_Space property, which Rust's
# `char::is_whitespace` tests; Python's `str.isspace` is a different set.
EM_DASH = "\u2014"
UNICODE_WHITESPACE = frozenset(
    "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)


def _is_control(c: str) -> bool:
    """Unicode general category Cc, which Rust's `char::is_control` tests."""
    return ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F


def note_text_refusal(text: str) -> str | None:
    """Why a note body is not one, or None: empty, no trailing newline, a blank
    line inside it, or a control character other than newline."""
    if not text:
        return "the body is empty"
    if not text.endswith("\n"):
        return "the body does not end in a newline"
    if "\n\n" in text.rstrip("\n"):
        return "the body contains a blank line"
    for c in text:
        if c != "\n" and _is_control(c):
            return f"the body contains the control character {ord(c):#04x}"
    return None


def note_name_refusal(name: str) -> str | None:
    """Why a key name is not one, or None: empty, or carrying whitespace, a
    control character, an em dash or a '+' (which signed-note forbids)."""
    if not name:
        return "a key name is empty"
    for c in name:
        if c in UNICODE_WHITESPACE or _is_control(c) or c == EM_DASH or c == "+":
            return f"a key name contains {c!r}"
    return None


def parse_note(spec: str, text: str) -> Anchor | str:
    """A cosigned checkpoint: the checkpoint note body, one blank line, then one
    `— NAME BASE64` line per signature (the Checkpoint and Cosignature sections)."""
    body, blank, signatures = text.partition("\n\n")
    if not blank or not signatures.endswith("\n"):
        return f"{spec}: not a signed note — a body, a blank line, then signature lines"
    body += "\n"
    refusal = note_text_refusal(body)
    if refusal is not None:
        return f"{spec}: not a signed note — {refusal}"
    head = body.split("\n")
    if len(head) < 4 or not head[0] or not SIZE_LINE.fullmatch(head[1]):
        return f"{spec}: the note body is not origin, canonical decimal size, root"
    refusal = origin_refusal(head[0])
    if refusal is not None:
        return f"{spec}: {refusal}"
    root = b64_canonical(head[2]) or b""
    if len(root) != 32:
        return f"{spec}: the note's root is not 32 bytes of canonical base64"
    anchor = Anchor(int(head[1]), root, head[0])
    anchor.source = spec
    anchor.body = body.encode("utf-8")
    for line in signatures[:-1].split("\n"):
        name, _, encoded = line.removeprefix(EM_DASH + " ").partition(" ")
        decoded = b64_canonical(encoded) or b""
        if not line.startswith(EM_DASH + " ") or len(decoded) < 5:
            return f"{spec}: {line!r} is not a signature line"
        refusal = note_name_refusal(name)
        if refusal is not None:
            return f"{spec}: {line!r} is not a signature line — {refusal}"
        anchor.lines.append((name, decoded))
    return anchor


def key_refusal(public: bytes) -> str | None:
    """Why 32 bytes are not an Ed25519 public key this reader trusts, or None:
    not the canonical encoding of a curve point, or a point of small order — a
    weak key, under which a signature can verify without anyone's secret."""
    point = _ed_decode(public)
    if point is None:
        return "not the canonical encoding of an Ed25519 curve point"
    x, y, z, _ = _ed_mul(8, point)
    if x == 0 and y == z:
        return "a small-order (weak) Ed25519 key, which proves no signer"
    return None


def parse_witness_key(spec: str | None) -> tuple[str, bytes] | str:
    """`NAME=BASE64` — a witness name and its 32-byte Ed25519 public key."""
    if spec is None or "=" not in spec:
        return f"--witness-key takes NAME=<base64 Ed25519 public key>, got {spec!r}"
    name, encoded = spec.split("=", 1)
    public = b64_canonical(encoded)
    if public is None:
        return f"--witness-key {name}: not canonical base64"
    if not name or len(public) != 32:
        return f"--witness-key {name}: an Ed25519 public key is 32 bytes, this is {len(public)}"
    refusal = key_refusal(public)
    if refusal is not None:
        return f"--witness-key {name}: {refusal}"
    return name, public


def parse_key(spec: str | None) -> tuple[str, bytes] | str:
    """`KEY_ID=HEX` — a key id and a 32-byte Ed25519 public key — or why not.
    The id ends at the first `=`, as `agentplane` reads it."""
    if spec is None or "=" not in spec:
        return f"--key takes KEY_ID=<64 hex characters>, got {spec!r}"
    key_id, encoded = spec.split("=", 1)
    if not key_id or not KEY_HEX.fullmatch(encoded):
        return f"--key {key_id}: an Ed25519 public key is 64 hex characters"
    public = bytes.fromhex(encoded)
    refusal = key_refusal(public)
    if refusal is not None:
        return f"--key {key_id}: {refusal}"
    return key_id, public


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[2] == "--canon-check":
        try:
            return canon_check(argv[1])
        except OSError as error:
            print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
            return 4
    if len(argv) == 3 and argv[2] == "--self-test":
        try:
            with open(argv[1], encoding="utf-8") as handle:
                return self_test(handle.readlines(), os.path.dirname(argv[1]) or ".")
        except OSError as error:
            print(f"cannot read {argv[1]}: {error}", file=sys.stderr)
            return 4
    if len(argv) < 2 or argv[1].startswith("-"):
        print(
            f"usage: {argv[0]} <export.jsonl> [SIZE:ROOT | ORIGIN:SIZE:ROOT | checkpoint.json]… "
            f"[--grader-verdict FILE]… [--key KEY_ID=HEX]…\n"
            f"       {argv[0]} <export.jsonl> --self-test\n"
            f"       {argv[0]} <records.jsonl> --canon-check",
            file=sys.stderr,
        )
        print(
            "  each checkpoint is one from outside the file — one an earlier audit\n"
            "  printed, or one a witness cosigned. Without one, deletion is unchecked.\n"
            "  each --key is a record-signing Ed25519 public key, as 64 hex characters,\n"
            "  under the key id its records name. Without one, signatures are unchecked.",
            file=sys.stderr,
        )
        return 2
    anchors = []
    sidecars: list[str] = []
    keys: dict[str, bytes] = {}
    witnesses: Witnesses = {}
    graders: dict[str, bytes] = {}
    max_age: int | None = None
    now: int | None = None
    specs = iter(argv[2:])
    for spec in specs:
        if spec in ("--key", "--grader-key"):
            key = parse_key(next(specs, None))
            if isinstance(key, str):
                print(key.replace("--key", spec), file=sys.stderr)
                return 2
            (keys if spec == "--key" else graders)[key[0]] = key[1]
            continue
        if spec == "--witness-key":
            witness = parse_witness_key(next(specs, None))
            if isinstance(witness, str):
                print(witness, file=sys.stderr)
                return 2
            witnesses.update([witness_entry(*witness)])
            continue
        if spec == "--max-checkpoint-age":
            value = next(specs, None)
            if value is None or not SIZE_LINE.fullmatch(value):
                print(f"--max-checkpoint-age takes whole seconds, got {value!r}", file=sys.stderr)
                return 2
            max_age = int(value)
            continue
        if spec == "--now":
            value = next(specs, None)
            if value is None or not is_rfc3339(value):
                print(f"--now takes an RFC 3339 instant, got {value!r}", file=sys.stderr)
                return 2
            now = int(datetime.datetime.fromisoformat(value.upper().replace("Z", "+00:00")).timestamp())
            continue
        if spec == "--grader-verdict":
            path = next(specs, None)
            if path is None:
                print("--grader-verdict needs a file", file=sys.stderr)
                return 2
            sidecars.append(path)
            continue
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
        return 4

    if graders and not sidecars:
        print("--grader-key was given with no --grader-verdict to use it against", file=sys.stderr)
        return 2
    if witnesses and not any(anchor.body is not None for anchor in anchors):
        print("--witness-key was given with no signed-note anchor to use it against", file=sys.stderr)
        return 2

    report = verify(lines, anchors, keys, witnesses, max_age, now)
    for finding in report.findings + report.stale:
        print(f"finding: {finding}")
    if report.unverifiable is not None and not report.findings:
        print(f"unverifiable: {report.unverifiable}")
        return 6
    refused = 0
    for path in sidecars:
        try:
            with open(path, encoding="utf-8") as handle:
                raw = handle.read()
        except OSError as error:
            print(f"cannot read {path}: {error}", file=sys.stderr)
            return 4
        component, reason = check_sidecar(raw, report, graders)
        if component is None:
            print(f"grader verdict {path}: holds — {reason}")
        else:
            refused += 1
            print(f"grader verdict {path}: refused ({component}) — {reason}")
    if keys:
        print(f"{report.signatures} record signatures verified")
    for line in report.anchors:
        print(f"anchor: {line}")
    for unchecked in report.unchecked:
        print(f"not checked: {unchecked}")
    print(
        f"{report.runs} runs, {report.records} records, {report.cases} cases, "
        f"{len(report.findings) + len(report.stale)} findings"
    )
    return 1 if report.findings or report.stale or refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
