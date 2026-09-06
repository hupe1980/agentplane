+++
title = "Record format"
description = "The normative wire specification for agentplane's journal records, hash chain, Merkle log and export file — enough to verify a history without this crate."
weight = 14

[extra]
group = "Trust"
+++

This is the specification an independent implementation reads. Everything here
is what a verifier must reproduce **byte for byte** to check a history it did
not write; everything not here is implementation freedom.

[Audit](@/docs/assurance.md) rests on the party under examination not being the
only party able to examine, and an auditor who has to read someone's Rust to
check their evidence has not escaped that dependency.

**Scope.** Verification is *payload-agnostic*. A verifier recomputes digests
over bytes and never interprets what a record says, so this document specifies
the envelope, the chain, the log and the file completely, and treats record
payloads as opaque JSON. The payload vocabulary is [listed below](#vocabulary)
and pinned by machine-readable vectors.

## 1. Versioning {#versioning}

Four version numbers, each answering a different question. A reader that cannot
interpret one **refuses**; it never guesses, and it never treats an
unrecognised value as the current one.

| Number | Where it appears | What it governs |
|---|---|---|
| `canon` | `RunAdmitted.canon`, export header | The canonical-JSON rule the run's derived digests were computed under |
| `v` | every record body | The record body's own shape |
| export `version` | export header | The export file's framing |
| envelope byte 0 | every sealed payload | The sealed-envelope layout |

All four are **1** in this specification.

They are deliberately independent. A run written under another `canon` is
*unverifiable by this reader*, which is a different finding from *this run
diverged* — an audit must report unknown scope as prominently as corruption and
never as corruption.

## 2. Primitives {#primitives}

- **Digest** — SHA-256. Thirty-two bytes, written in JSON as 64 lowercase hex
  characters.
- **RunId**, **CaseId** — [ULID](https://github.com/ulid/spec), written in
  Crockford base32, 26 characters. A `CaseId` is written `case_` + the ULID
  where it appears as a case identifier and bare inside a record body's `case`
  field.
- **Seq**, **Epoch** — unsigned 64-bit integers.
- **Timestamp** — RFC 3339 with an offset, as a JSON string.
- **Bytes in JSON** — base64, RFC 4648 standard alphabet, **padded**, and
  canonical: padding must be present and correct, and the bits below the last
  whole byte must be zero. A decoder that accepts a second spelling of one
  value accepts two artifacts that both verify and are not the same bytes.

## 3. Canonical JSON {#canonical-json}

`canon` version **1** is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
(JCS) with one stated departure.

1. **Object members are sorted by UTF-16 code unit** of the member name. Not by
   UTF-8 byte: the two agree throughout the Basic Multilingual Plane and
   disagree above it, so an ASCII-only test suite cannot tell them apart.
2. **No insignificant whitespace.** No space after `:` or `,`, none at either
   end.
3. **Strings** are escaped as RFC 8785 requires: `"` and `\` backslash-escaped,
   the C0 controls that have short escapes written as `\b \t \n \f \r`, every
   other code point below `U+0020` as `\u00XX` with lowercase hex, and
   everything else emitted as itself in UTF-8.
4. **Doubles** are formatted by ECMAScript's number-to-string algorithm at
   radix 10 — shortest
   round-tripping digits, positional notation for magnitudes in
   `[1e-6, 1e21)`, exponential with an explicit sign outside it. So `100.0`
   is `100` and `1e30` is `1e+30`.
5. **The departure: integers stay exact.** JCS treats every number as an IEEE-754
   double, under which two distinct 64-bit integers above 2⁵³ share one
   representation — and a canonicalizer that gives two different values one byte
   string gives two different effects one key. Inside ±2⁵³ the two rules agree,
   so nothing interoperable is lost; outside it,
   [I-JSON](https://www.rfc-editor.org/rfc/rfc7493) draws the same line.

Sorting is recursive: nested objects are canonicalized by the same rule.

```
canon(  {"b":1,"a":{"d":2,"c":3}}  )  =  {"a":{"c":3,"d":2},"b":1}
```

## 4. The record body {#record-body}

A record body is a JSON object. Seven envelope members, then the payload
members of exactly one kind, **flattened into the same object**.

| Member | Type | Presence |
|---|---|---|
| `seq` | integer | always |
| `run` | ULID string | always |
| `case` | ULID string | omitted when absent |
| `step` | integer | omitted when absent |
| `phase` | `"forward"` or `"compensating"` | omitted when `forward` |
| `epoch` | integer | always |
| `v` | integer | always |
| `effect_key` | digest hex | omitted when absent |
| `kind` | one of the [vocabulary](#vocabulary) | always |

`phase` is omitted rather than written when it is `forward`, so the
overwhelmingly common record costs no bytes and no hash input.

**Unknown members are refused, in both directions.** A body carrying a member
this reader does not know — at the top level or inside the payload — is an
error, not a member to skip. That is the opposite of what a *message* format
does, and deliberately: a record is **evidence**. Its members are the inputs to
an authorization, retry or recovery verdict, so dropping one is reaching a
conclusion over evidence the reader did not see. The same argument forbids
reading a missing `v` as "the current shape".

**A record body is at most 1 MiB** of canonical bytes. A writer refuses a
larger one rather than truncating it; bytes that do not fit belong in a blob
store addressed by digest.

## 5. The hash chain {#hash-chain}

Let `raw` be the canonical bytes of the record body and `prev` the previous
record's `hash`. Then

```
hash = SHA-256( prev ‖ raw )
```

with `prev` the 32 raw bytes of the digest — not its hex form — and `raw` the
canonical UTF-8 JSON. The first record of a run uses `prev = ` **32 zero
bytes**.

Because `prev` is fixed-width, the concatenation is unambiguous and needs no
length prefix.

**Verification never re-serializes.** A verifier hashes the bytes it was given
and compares; it does not parse the body and canonicalize it again. This is the
load-bearing rule of the whole format: if the chain were taken over a
re-serialization, then the first time a reader's canonicalizer differed from
the writer's — a version, a library, a locale — every historical hash would
move, and tamper evidence would be destroyed by an upgrade. Reading a record at
a newer shape is a *view*; the chain is over history as written.

## 6. Attestation {#attestation}

A record may carry a signature. It sits **beside** the hash, never inside the
body — a signature inside the body would make the hash cover the signature that
covers the hash.

```
signing input = SHA-256( domain ‖ 0x00 ‖ hash )
domain        = "io.github.hupe1980.agentplane/record/v1"
```

`hash` is the 32 raw bytes from [the chain](#hash-chain). The `0x00` separates the domain from the
payload; the domain string contains no NUL, so the split is unambiguous.

The signature is Ed25519 over that input. It travels as

```json
{"key_id": "...", "signature": "<hex>"}
```

`key_id` names the key, **not the algorithm**: a self-described algorithm is a
downgrade attack waiting to be written, so a verifier resolves the algorithm
from its own trust configuration.

Because the hash chains, one signature transitively commits to every record
before it: rewriting any part of the prefix invalidates every later signature,
not only its own.

Two sibling domains exist and must not be confused with this one — they are
signed by the same key:
`…/manifest/v1` and `…/provenance/v1`.

## 7. The Merkle log {#merkle-log}

A per-run chain leaves one gap: **deleting an entire run leaves every remaining
run verifying perfectly.** What closes it is committing to the *set* of runs.

Leaves are the terminal chain hashes of sealed runs, in seal order. Hashing is
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), unchanged:

```
leaf(d)        = SHA-256( 0x00 ‖ d )
node(l, r)     = SHA-256( 0x01 ‖ l ‖ r )
root([])       = SHA-256( "" )
root([x])      = x
root(xs)       = node( root(xs[..k]), root(xs[k..]) )    k = largest power of two < |xs|
```

The prefix bytes are not decoration: without them a leaf can be made to collide
with an interior node, and an attacker who controls leaf content can present a
subtree as a leaf.

The split is at the largest power of two below the length, **not at the
midpoint**. That is what keeps a tree's left subtree stable as the log grows,
which is what consistency proofs between two checkpoints rely on.

The empty root is `SHA-256("")` and not thirty-two zero bytes, because zeroes
are also what an uninitialised buffer, a default-constructed struct and a
truncated read produce.

### Checkpoint {#checkpoint}

```json
{"origin": "...", "size": 1234, "root": "<hex>"}
```

A checkpoint claiming `size` 0 beside any root other than the empty root
describes a log that cannot exist and must be refused. A witness has no prior
memory to check a first submission against, so one incoherent size-0
submission would poison an origin permanently.

Its text form is the C2SP
[`tlog-checkpoint`](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md)
note body — origin, decimal size, base64 root, each on its own line, with a
trailing newline:

```
example.com/agentplane
1234
irNutGGI+kpEEwQrBb3xjEEWKohYs7xnm603736/WBQ=
```

The size is a canonical decimal number: no sign, no leading zero, no
surrounding space, because each of those is a second spelling of one log.

## 8. Sealed payloads {#sealed-payloads}

Where a key ring is configured, a payload is replaced in the record **before**
it is hashed, so the chain commits to ciphertext and destroying the wrapping
key reaches every copy at once — including one somebody exported last month.

A sealed JSON payload is the object `{"$sealed": "<base64 envelope>"}`; a sealed
string field is `"$sealed:<base64 envelope>"`.

The envelope is binary:

```
byte  0      format version (1)
bytes 1..5   wrapped-key length, u32 big-endian
bytes 5..5+n wrapped key, canonical JSON
next 24      XChaCha20-Poly1305 nonce
rest         ciphertext ‖ Poly1305 tag
```

The version leads, so no offset is trusted before the layout is known. A reader
that cannot interpret the version reports a **build skew**, not tampering:
those two reach different people.

Sealed bytes are rotation-immutable. The chain commits to the envelope, which
carries the wrapped key inline, so re-wrapping is not expressible — the erasure
scope is the rotation unit.

## 9. The export file {#export-file}

JSON Lines, UTF-8, one object per line, in this order:

1. exactly one **header**
2. for each run: one **run block**, then that run's **record lines** in `seq` order
3. zero or more **case blocks**
4. exactly one **trailer**

**Framing lines carry a `kind` member; record lines do not.** That is the
dispatch rule, and it is the only one: a line whose top-level `kind` is one of
the four framing names is that kind of frame, and a line with no top-level
`kind` is a record belonging to the run block above it. A record's *own* kind
is inside its body, one level down, and must not be mistaken for the frame's.

### Header {#header}

```json
{"kind":"agentplane.export","version":1,
 "checkpoint":{"origin":"…","size":1,"root":"<hex>"},"canon":1}
```

| Member | Type |
|---|---|
| `kind` | `"agentplane.export"` |
| `version` | the export format's version, `1` |
| `checkpoint` | `origin`, `size`, `root` — see [checkpoint](#checkpoint) |
| `canon` | the canonicalization rule the digests were computed under |

### Run block {#run-block}

```json
{"kind":"agentplane.export.run","run":"<ulid>","index":0,"seal":"<hex>"}
```

| Member | Type | Presence |
|---|---|---|
| `kind` | `"agentplane.export.run"` | always |
| `run` | ULID string | always |
| `index` | integer, the position in the Merkle log | omitted for an open run |
| `seal` | digest hex, the run's terminal chain hash | omitted for an open run |

`index` and `seal` are present together or not at all. Their absence means the
run is not in the log, which is a state and not a gap.

**A run sealed after the header's checkpoint was taken is exported as open.**
The writer omits its position rather than stamping one the checkpoint does not
commit to, because a verifier that rebuilt a tree one leaf larger than the root
it compares against would report tampering where there was only time. The next
export carries it sealed.

### Record line {#record-line}

```json
{"seq":2,"body":{…},"prev_hash":"<hex>","hash":"<hex>","attestation":null,"raw":"…"}
```

| Member | Type | Presence |
|---|---|---|
| `seq` | integer | always |
| `body` | the parsed [record body](#record-body) | always |
| `prev_hash` | digest hex | always |
| `hash` | digest hex | always |
| `attestation` | `{"key_id": "…", "signature": "<hex>"}` or `null` | always present, `null` when unsigned |
| `raw` | string | always |

`attestation` is written as an explicit `null` rather than omitted, so a reader
tells *unsigned* from *a field this export forgot*.

`raw` is **the exact bytes the hash covers**, carried as a JSON string —
canonical record bytes are UTF-8 JSON, so they escape and recover byte for
byte. It is the member that makes the file checkable: a verifier that
re-serialized the parsed `body` would be holding the file to its own
canonicalizer rather than to the bytes the store sealed. `body` is a courtesy
copy for a reader's eyes, and a verifier holds the two to each other rather
than trusting either alone.

### Case block {#case-block}

```json
{"kind":"agentplane.export.case",
 "case":{"id":"<ulid>","kind":"…","status":"open","correlation":[…],
         "state":{…},"version":0,"opened_at":"<rfc3339>","runs":["<ulid>"]},
 "deadlines":[…],"blobs":["<hex>"]}
```

| Member | Type |
|---|---|
| `kind` | `"agentplane.export.case"` |
| `case` | the case: `id`, `kind`, `status`, `correlation`, `state`, `version`, `opened_at`, `runs` |
| `deadlines` | the case's obligations, each with `case`, `name`, `resolved_at`, `calendar_digest`, `state` and optionally `warn_at` and `acknowledged` |
| `blobs` | digest hex strings |

`case.id` is the bare ULID — the same spelling a record body's `case` member
carries, which is what makes the cross-layer check a string comparison.

`state` travels **as stored**: sealed on a sealed plane. Exporting plaintext
would quietly undo erasure.

The case layer is mandatory rather than an optional extension — a reader that
tolerated its absence could not tell *this plane has no cases* from *the case
layer was dropped from this file*, and the second is the finding that matters.
A plane with no case store exports zero case blocks and says `"cases":0` in the
trailer.

Blob **bytes** are never in the file. Presence and integrity of bytes are a
question about a live store, which an offline file honestly reports as
unchecked.

### Trailer {#trailer}

```json
{"kind":"agentplane.export.end","runs_requested":1,"runs_exported":1,
 "records":3,"cases":1,"unreadable":[]}
```

| Member | Type |
|---|---|
| `kind` | `"agentplane.export.end"` |
| `runs_requested` | integer |
| `runs_exported` | integer |
| `records` | integer |
| `cases` | integer |
| `unreadable` | array of `{"run": "<ulid>", "reason": "…"}` |

`unreadable` **names** the runs the export could not read rather than counting
them, because the run that fails to read is not a random one.

**The trailer's absence is the signal that matters.** An export cut short by a
crash, a full disk or a killed pipe ends without one, so a reader tells a
prefix from a whole file without comparing counts against a source it does not
have.

## 10. Verifying an export {#verifying}

An implementation that does the following has verified the file.

1. **Header.** Refuse an unknown `version`. Record `canon`; if it is not a rule
   this reader implements, every digest below is *unverifiable* rather than
   *wrong*, and the report must say which. A `size` of 0 beside any root other
   than the empty root is a checkpoint describing a log that cannot exist.
2. **Per record.** Recompute `SHA-256(prev_hash ‖ raw)` and compare with
   `hash`. Then parse `raw` and compare the result with `body` — the two must
   agree, or the file's readable half is saying something its hashed half does
   not.
3. **Per run.** `prev_hash` of the first record is 32 zero bytes; every later
   record's `prev_hash` is its predecessor's `hash`; `seq` is contiguous and
   ascending; and every record's own `body.run` is the run its block claims.
   That last one is not redundant: without it an export could file run B's
   records and B's leaf under A's id, and chain, seal and root would all verify
   B's bytes. Only the *label* lied, and the label is what a reader looks a run
   up by.
4. **Signatures**, where present: verify as [attestation](#attestation)
   describes, against a key set the verifier holds. A record with no
   attestation is unsigned, which is a state; a *strict* verification refuses
   it, and stripping signatures must not be a way to pass.
5. **The log.** For each sealed run, `seal` must equal the run's terminal
   `hash`. Then leaf-hash every `seal` in `index` order and compute the root as
   [the log](#merkle-log) describes.

   Three ways the set can fail to be checkable, and they are different
   findings:

   - The positions are not the contiguous `0..size` the checkpoint commits to —
     one is duplicated, missing, or at or beyond `size`. That file describes a
     different log than the one it names. Do not compute a root over it: a tree
     built on duplicated positions compares garbage and reports the wrong
     defect.
   - The file carries fewer runs than `size`. A partial export's chains all
     verify and its *set* cannot be checked; say so, rather than reporting
     either a pass or a root mismatch.
   - The positions are contiguous and complete: compute the root and compare.

6. **The root, against a checkpoint from somewhere else.** This is the step
   that decides what the comparison in 5 is worth, and it is the one most
   easily skipped.

   Comparing the rebuilt root with the checkpoint in the file's **own header**
   proves the file is internally consistent — which is also exactly what an
   editor who dropped a run and rewrote the header achieves. The rebuild only
   becomes evidence about **deletion** when the checkpoint came from outside
   the file: one an earlier audit printed, one a witness cosigned, one from a
   ticket. A verifier given no such checkpoint has not checked for deletion and
   must report that it did not, rather than reporting a pass.

7. **Cross-layer.** A record naming a `case` the file does not carry is a
   finding.
8. **The trailer.** No trailer means a prefix. A non-empty `unreadable` means
   the export is complete *as an artifact* and incomplete *as a history*, and
   the two must not be reported the same way. The counts are a cheap
   cross-check on the frame.

## 11. Conformance vectors {#vectors}

Two machine-readable corpora ship in the repository:

| File | What it pins |
|---|---|
| `tests/golden/records.jsonl` | One canonical record per kind, with its chain digest under `prev = 0` |
| `tests/golden/export.jsonl` | A complete sealed export that every build must still verify offline |

Both are produced by the functions the runtime writes through, and regenerated
deliberately with `AGENTPLANE_BLESS_GOLDEN=1 cargo test --test trust format::` —
a typed command, because a shape change is a hard cut rather than a diff.

They are this build checking itself, which catches drift and cannot catch a
shared misunderstanding. `tools/verify_export.py` is the second reader: it
implements this document, reads none of the crate's Rust, verifies the export
and **re-derives** every record vector from its parsed value. `just
verify-golden` runs it.

## Vocabulary {#vocabulary}

Twenty-seven record kinds. A verifier does not interpret them; a reader that
does must refuse one it has never heard of, for the reason
[the record body](#record-body) gives.

`RunAdmitted`, `QuotaPassStarted`, `PlanFrozen`, `StepStarted`, `StepFinished`,
`Note`, `EffectStarted`, `EffectDone`, `EffectFailed`, `EffectReconciled`,
`StepCompensated`, `QuarantineDecided`, `GroupOpened`, `GroupSettled`,
`BudgetRefused`, `BudgetReadmitted`, `IdentityBound`, `PolicyDenied`,
`RunSuspended`, `CaseBound`, `DeadlineRegistered`, `DeadlineTransition`,
`Released`, `RunCancelled`, `RunConcluded`, `BreakGlass`, `Swept`.

Each kind's member set is pinned by `tests/golden/records.jsonl`, one line per
kind. That file is the normative statement of the payloads: prose listing them
here would be the same facts in two places, and the copy that drifts is always
the second one.

## What this format does not promise {#not-promised}

**Store row encodings carry no version and are not specified.** The journal is
the record and the stores are indexes derived from it; a store is rebuilt by
[`restore`](@/docs/operations.md), which reads this format and proves the
result by equal Merkle roots at equal size. That is a weaker promise on
purpose, and it is written down here rather than left to be inferred from
silence.
