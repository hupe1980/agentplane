+++
title = "Erasure and keys"
description = "Cryptographic erasure that reaches backups, envelope encryption, key rotation and revocation, and the tenancy boundary."
weight = 9
+++

An erasure obligation is discharged by making data unreadable **everywhere**,
not by deleting the copy you can reach. This page is how that is done here, and
what the boundary actually is.

For the trust model those keys sit inside, see [security](@/docs/security.md).

---

## What lands where, and what can be erased

Decide this before personal data reaches a run. The journal is append-only and
hash-chained: a record cannot be deleted without breaking the chain, so nothing
that enters it is ever *removed*. What decides whether it can be **erased** is
whether a key ring is configured — without one the bytes are permanent for the
life of the store, and with one they are ciphertext whose key `erase_case`
destroys.

The **Erasable** column below is therefore two answers, and the difference is
one builder call:

| Data | Where it lands | Erasable without `.keyring(..)` | with it |
|---|---|---|---|
| Run input | journal — `RunAdmitted.input` | **no**, verbatim | sealed, per-case scope |
| **Model prompts** | journal — inside `EffectStarted.descriptor.args`, because the prompt is part of effect identity | **no**, verbatim | sealed, per-case scope |
| **Tool call arguments** | journal — same field, same reason | **no**, verbatim | sealed, per-case scope |
| Effect outputs — completions, tool results | journal — `EffectDone.output`, and a reconciliation probe's `EffectReconciled.output`, which is the same data | **no**, verbatim | sealed, per-case scope |
| Failure messages, notes, frozen plans | journal — `EffectFailed.error` (the message only), `Note.text`, `PlanFrozen.plan`, which embeds the trusted input the plan was compiled from | **no**, verbatim | sealed, per-case scope |
| Case state writes, status changes, deadline transitions | journal (the effect) **and** the case store | **no** in the journal; the case store's copy is overwritten, not erased | sealed in both, one scope |
| Inbound event payloads — a counterparty's message body | journal (the awaited effect's output) **and** the event store | **no** | sealed in both; the buffer's copy is its own unit, keyed `(source, id)` |
| Human task proposals — `Justification.proposed_action`, the exact thing a reviewer is shown | journal (the task effect) **and** the task store | **no** | sealed in both; the task's `summary` stays readable so a queue stays usable |
| Memory item content | `MemoryStore` | **yes** — `forget`, `forget_cascading`, expiry sweep | unreadable everywhere with an explicit `EncryptedMemoryStore` wrap — **not** covered by `.keyring(..)`, see below |
| Blob bytes — `cx.store_blob`, fetched media | blob store | **yes** — expiry leaves a tombstone, in the live store only | unreadable everywhere, backups included |
| Correlation keys, deadline names, task summaries, statuses | case / task store | no, and deliberately — they are what the store is asked questions *about* | unchanged: still readable |
| Admission keys — a message's `source`/`id` | journal — `RunAdmitted.idempotency_key` — **and** the `run_admission` index | no, and deliberately: the index is looked up by a value the caller holds in the clear, and sealing it would leave a store that cannot refuse a redelivery | unchanged: still readable |
| Blob digest and classification | journal | no, and it does not need to be — a digest is not the bytes | unchanged |

Read the first column as the floor and the second as what one call buys. Both
are honest positions: a deployment that would rather **refuse** the data than
seal it declares `max_sensitivity_journaled` and never reaches this table.

**Without a key ring the rule is: keep erasable personal data out of the
chain.** Put the bytes in a blob and let the journal commit to the digest:

```rust
let digest = cx.store_blob(document_bytes).await?;  // erasable, linked to the case
// The chain records the digest and the classification, never the bytes.
```

**`cx.store_blob` is the only way a value reaches a blob, and it is
size-independent.** There is **no size-triggered spill**: the 1 MiB
`Record::MAX_RECORD_BYTES` ceiling *refuses* a record and names the limit, it
does not blob for you. Anything under it is journaled inline whatever it holds.

That is deliberate. A size-triggered spill would make erasability depend on how
long a value happened to be — the same field permanent for one customer and
erasable for another. So **references are the intended shape**, not a
workaround: journal a digest or an identifier, and fetch details through an
authorised tool call.

Prompts are the hard case, because the prompt *is* effect identity — replay
reconstructs a run by re-deriving the same key, so a prompt cannot be redacted
after the fact without making the run unreplayable. A prompt built from a
customer record puts that record in the chain permanently. Pass a reference or
a digest and materialize the bytes at dispatch, as governed media already does,
or treat the run as retained data with a retention period on the whole store.

**Declare the ceiling and the runtime enforces it.** `spec.security.max_sensitivity_journaled`
refuses, at dispatch, any argument more sensitive than a deployment is willing
to make permanent — so the mistake is a refusal naming the blob pattern rather
than a discovery at the first erasure request:

```yaml
spec:
  security:
    max_sensitivity_egress:    secret     # what may leave
    max_sensitivity_journaled: internal   # what may be written down forever
```

Absent means unbounded, which is what every deployment had before the field
existed.

**A plane of hand-written skills declares the same ceiling in code**, since it
runs under no manifest:

```rust
Runtime::builder(store)
    .max_sensitivity_journaled(Sensitivity::Internal)
    .skill(Triage)
    .build()
```

Where both are present the **stricter** binds, the same rule a reviewed tool
grant follows: a declaration may only tighten what the deployment allows. It is
an enforcement point rather than a warning — a build-time lint that let the run
proceed would be the advisory control this format refuses everywhere else.

**Or seal the journal itself.** `SealedJournal::wrap(store, keys, tenant)` seals the
payload fields — run input, effect arguments (prompts, tool calls), effect and
reconciliation outputs, failure messages, notes and frozen plans; the caller's
data, never the runtime's routing — under the same per-case scope `erase_case`
already destroys, so a single erasure reaches blobs and journal alike. The
envelope's associated data binds the tenant and the record's identity, so
ciphertext moved to another record fails to authenticate rather than opening
as somebody else's payload:

```rust
Runtime::builder_on(store)
    .keyring(keys)   // seals all of them, and blob payloads
    .build()
```

Run it: `cargo run --example sealed_run --features redb,testkit,keyring`
writes a claimant's details, shows them sealed in the store, erases the case,
and verifies the chain afterwards.

One call, one guarantee. The wrapping happens at `build()`, so the order you
write the builder in cannot lose it — registering a store *after* the key ring
seals it just the same. An operator `Outbox`'s store is swept up too: it keeps
the destinations' webhook bearer tokens — credentials like any caller's — so
`SealedPush` wraps it in the same pass. The decorators (`SealedJournal`,
`SealedCases`, `SealedTasks`, `SealedEvents`, `SealedPush`) are public for
embedders wiring stores by hand, but a plane should not need five correct
decisions where one will do: a control that can be forgotten five times is one
where forgetting looks exactly like remembering.

**Governed memory is the one store this call leaves alone, and the exclusion
is forced rather than an oversight.** `EncryptedMemoryStore` serialises subject
erasure against writes and legal-hold changes with a **process-local** mutex,
so it holds its contract on a single-writer deployment and nowhere else.
Wrapping it automatically would hand that adapter to an active-active
`PostgreSQL` plane, where the mutex coordinates nothing and the hold race it
exists to prevent is the result — a control that is worse than absent, because
it reads as present. Its erasure unit differs too: `tenant/memory/<subject>`
outlives every case, so `erase_case` was never the act that reaches it. Wrap it
where you can see the deployment:

```rust
let memories = EncryptedMemoryStore::new(inner, Arc::clone(&keys), tenant.clone());
Runtime::builder(store).memory(Arc::new(memories)).keyring(keys).build()
```

### Erasing on more than one instance

Destroying a subject's wrapping key is not one operation. It reads the subject's
items, checks every legal hold, tombstones, and then asks a KMS to destroy the
scope — and **between the hold check and the destroy**, a write on another
instance can add an item, or an operator can place a hold on one. Either makes
the erasure wrong in a way nothing detects: the new item is sealed under a scope
that is about to stop existing, and the held item is destroyed anyway.

`EncryptedMemoryStore` closed that window with a process-local mutex, which is
correct on a single writer and silently nothing on an active-active plane. The
lock is a seam, and the default is honest about being local:

```rust
// Single node: the default. `is_distributed()` answers false.
let memories = EncryptedMemoryStore::new(inner, keys.clone(), tenant.clone());

// Active-active: a session advisory lock in the database the plane shares.
let memories = EncryptedMemoryStore::new(inner, keys.clone(), tenant.clone())
    .coordinated_by(Arc::new(store.erasure_coordinator()));
```

**Why a session advisory lock and not a row.** A row taken with `SELECT … FOR
UPDATE` needs its transaction held open for the whole erasure, and the erasure's
own writes go through the store's other connections — so the row lock would be
held by a transaction that cannot see the work it protects. A *session* lock is
held by the connection, and `PostgreSQL` releases it when the session ends. That
last property is the one that chose it: an instance that dies mid-erasure
releases by dying, where a lease with a TTL must choose between stranding the
subject and handing it over while the first instance's KMS call may still be in
flight.

**The lease is not an RAII guard**, deliberately. Releasing a distributed lock is
async and fallible and `Drop` is neither, so a guard would have to block a
runtime thread or swallow the failure — and swallowing *that* failure strands the
subject for every other instance. Use `under_lock`, which releases on the success
and the failure path.

The scope is per **tenant**, not per subject: `forget`, `forget_cascading` and
`set_legal_hold` are addressed by item id and `sweep_expired` spans every
subject, so choosing a subject-scoped lock would need a read that races the very
thing the lock protects.

**The pairing is refused at `build`.** Both facts are in hand there: the journal
store says whether two instances can write it (`JournalStore::is_shared`), and
the memory store says whether its lifecycle lock spans them
(`MemoryStore::erasure_is_distributed`). A shared store beside a process-local
lock is `BuildError::ErasureCoordinatorNotShared`, naming the fix.

`is_shared` has **no default**, deliberately. A default of `false` would let an
embedder's shared backend answer *single-writer* by saying nothing, and a control
that fails open when an implementer forgets is a property the runtime relies on
rather than checks. `erasure_is_distributed` *does* default — to `None`, meaning
"no lifecycle lock because there is no cryptographic erasure here", which is the
honest answer for an ordinary store and leaves the check inapplicable rather than
satisfied.

Two properties make it worth having rather than merely present. Only the
*payload* is sealed: `seq`, `run`, `case`, `effect_key` and the record's own
variant stay in the clear, so exactly-once, the case scan, the outcome index
and the chain keep working with no key at all. And the chain commits to the
**ciphertext**, so an auditor holding no keys still verifies the history of a
run whose payloads have been erased — hashing the plaintext would have tied
the tamper evidence to the key and destroyed both together.

**Events are the one thing not erased by the case, and that is forced.** An
event is buffered *before* any subscription matches it, and one nobody claims
becomes a **dead letter** — which by definition matched no case at all, and is
kept indefinitely so an operator can find the wrong correlation key. There is
no case to erase it with. So the event is its own unit, scoped by the
`(source, id)` pair the buffer already deduplicates on, which is the finest
granularity a request about one message could ask for:

```rust
keys.destroy(&scope(&tenant, "event/bank.example/MSG-7"), at, reason).await?;
```

Its *delivered* copy is a separate matter and already covered: claiming an
event journals the payload under the awaiting effect, sealed under that run's
case like every other journal payload.

**The composed claim is tested, not merely asserted.** *One erasure reaches
every copy* is a sentence about three mechanisms sharing one scope, and
composition is where that kind of claim breaks — each decorator can be correct
alone while sealing under a scope `erase_case` never destroys, which would
report a successful erasure over readable data. A test wires all of it
together, erases the case once, and asserts blobs, journal payloads and case
state are all unreadable afterwards while the hash chain still verifies. A
mutation that gives the case store a *different* scope is caught by that test
and by nothing else.

Correlation keys, deadline names, task summaries and statuses stay readable
everywhere by design — they are what the stores are asked questions *about*.
A deployment that considers its business keys personal data must choose keys
that are not. A deployment
whose obligation covers them either erases the case — which destroys the scope
key and takes the journal copies with it — or keeps the data out, which is what
`max_sensitivity_journaled` refuses at the boundary.

---

## Retention on a window, and what it cannot reach

`erase_case` and `erase_run` erase one unit. Retention is the same act on a
clock: a window, applied to every closed case, by the plane.

```rust
let report = plane.retain(cutoff, now, "retention: 7 years from opening").await?;
```

```sh
agentplane retain --store ./journal.redb \
  --older-than-days 2555 --reason "retention: 7 years from opening" --dry-run
```

The verb **lists**; it does not erase. The shipped binary wires no blob store
and no key ring — a redb file is a journal and a case layer — so nothing in it
can make a byte unreadable, and a verb that walked the cases and printed
`erased: 0` beside a clean exit code would be a control that reads as having
run. It answers the half it can, through the same selection rule the pass uses
(`retention::plan`, so a listing and an erasure cannot disagree about which
cases), and refuses to run without `--dry-run`. The pass itself is
`Runtime::retain`, from a plane built with the stores that can act.

**A pass erases closed cases only, and the window is measured from `opened_at`.** A
case still open is a matter still running, and erasing the data underneath a
live run turns a retention pass into an outage. `opened_at` is the anchor
because retention rules are written as *N years from the start of the business
matter* — and it is the only instant a case records, which is a fact this verb
states rather than works around.

`--older-than-days` has **no default**, for the reason `forget-admissions` has
none: a retention period is a legal and business decision, and a crate that
picked one would be choosing somebody else's. `--reason` is required and lands
on every tombstone and key destruction, so a later read says *expired, on this
date, for this reason* rather than *missing* — which is the distinction the
recovery drill's three-way verdict is built on.

### `not_erasable` is the half that matters

Every pass returns a coverage list beside its count, for the same reason
`DrillReport` carries `not_checked`:

```json
{
  "scanned": 1204, "erased": 318, "blobs_expired": 892, "failures": [],
  "not_erasable": [
    "no key ring is wired: blob tombstones cover the live store only, and journal payloads — run input, prompts, tool arguments, effect outputs — stay verbatim and permanent…",
    "journal records are append-only: the chain, the routing fields and the fact each run happened remain — by design…",
    "a run that belongs to no case is not reached by a case walk; erase one with `blob::erase_run`"
  ]
}
```

A number with no coverage statement beside it is exactly how a deployment comes
to believe an erasure obligation is discharged while the chain still holds the
payload verbatim. **Without a key ring, retention tombstones blobs in the live
store and nothing else.** Without a blob store the pass still runs — the unit
is the key, and a plane that seals its journal and stores no blobs is an
ordinary shape — and the tombstones it could not write are named. With one, the case's key scope is destroyed and the
erasure reaches every replica and every backup at once — because what was
destroyed was never in them.

### Admission keys are their own window

`agentplane forget-admissions --older-than-days N` retires the idempotency index,
and it is a different decision from the one above: **retiring a key reopens the
door it closed.** The window must exceed how long your emitter keeps retrying a
delivery it has not seen a 2xx for, or a redelivery arriving after retirement
admits a second run — the failure the key exists to prevent, delivered on a
timer.

There is no default, deliberately. Other durable runtimes bound this for you —
Restate expires an idempotency key a day after the invocation completes,
Temporal's dedup window is its namespace retention — and both are choosing a
retry horizon on your behalf. Pick yours from the emitter, not from the index's
size:

```sh
# A webhook source that retries for 72 hours; a week is comfortably clear of it.
agentplane forget-admissions --store ./journal.redb --older-than-days 7
```

Absent a call, keys are kept forever. That is the safe default — the one that
cannot silently admit a duplicate — and the size of the index is a fact your
database monitoring already reports.

## Erasure that reaches the backups

Dropping a payload's bytes leaves the hash chain intact, because the chain only
ever committed to a digest. That is the right shape and it is not sufficient: it
erases the bytes *in the live store*. Every backup taken before the request,
every replica, every snapshot nobody remembers still holds them.

Chasing those copies does not work. Backups are offline, offsite and frequently
immutable by design — that is what makes them survive the incident they exist
for — so a retention story requiring rewritten backups puts two guarantees in
direct conflict, and whichever loses, loses silently.

So payload bytes are sealed under a **data key**, and the data key is wrapped by
a key this crate never holds. Erasure destroys the data key, and every copy of
the ciphertext becomes unreadable at the same instant — including the ones nobody
can reach, because what was destroyed was never in them. A test restores a backup
taken *before* the erasure into a fresh store and asserts it stays unreadable;
that is the property deletion cannot provide.

Two operations fall out of one structure, which is the argument for it:

| | |
|---|---|
| **Erasure** | destroy a scope's wrapping key — every payload ever sealed under that scope is unreadable, everywhere |
| **Revocation** | the same act for a different reason; the blast radius a compromised key should have is exactly the scope it wrapped |

### Rotation: sealed bytes never change

Envelope encryption is usually sold on a third operation — rotate the wrapping
key, re-wrap the data keys, leave bulk data alone. agentplane does not offer it,
and the omission is a decision rather than missing work.

An envelope carries its wrapped data key inline, and the journal's hash chain
commits to the envelope bytes. That is what lets an auditor holding no keys
verify a run whose payloads have been erased — and it is exactly what makes
re-wrapping impossible: rewriting a journal payload's envelope rewrites a record
the chain covers, so it breaks the chain it sits inside. Re-wrapping the *other*
stores would not help either, because a scope's journal payloads and its case
state share one wrapping key: the scope stays pinned to the oldest version any of
its journal envelopes names.

So the rule is stated instead: **sealed payload bytes never change, and the
erasure scope is the rotation unit.** A scope is already narrow — one case, one
run, one memory subject — so a compromised wrapping key exposes that unit and
nothing else, which is the blast radius rotation is bought for in the first
place. Adding a key version is safe and needs nothing from agentplane; envelopes
sealed before a rotation keep opening.

**This is the model AWS KMS already assumes.** KMS rotates a key's backing
material on a schedule, keeps *every* previous version in perpetuity, and picks
the right one from the ciphertext on decrypt — you cannot select a version, and
you cannot delete one. The only way to remove old key material is to delete the
whole KMS key, which is precisely erasure. So on KMS, rotation is automatic and
transparent, and nothing below can arise.

**Vault's transit engine is the one to be careful with,** because it offers a
lever KMS does not: `min_decryption_version` refuses to decrypt ciphertext below
a floor. Since envelopes pin their key version for life, raising that floor past
a live envelope makes un-erased history unreadable — an erasure nobody
requested, that no retention record explains and no obligation discharges. (This
is what `rewrap` exists for in Vault's own model, and the reason it cannot serve
that purpose here is the chain, above.)

agentplane cannot stop an operator moving that floor, so it makes moving it too
far legible. `KeyError::Retired` is its own answer, distinct from a completed
erasure and from a plain refusal, and it names the version the floor has to
readmit:

```text
the wrapping key version 'vault:v1' for scope 'acme/case-8f2…' has been retired
by policy — this is not an erasure and not a loss: the sealed bytes are intact
and become readable again if the key service's minimum decryption version is
lowered to admit 'vault:v1'
```

`agentplane drill` reports such a case as a finding that names the remedy, rather
than as *neither opens nor was its key destroyed* — the sentence that would send
somebody hunting for tampering while a reversible setting is the whole cause.

### An envelope says which construction it is

Rotation-immutability has a consequence for the *format*, not just for the keys:
an envelope is read by builds written long after it, for as long as it is
retained. A mixed-version fleet mid-deploy, a rollback, and a restore from a
backup taken by a newer plane are all ordinary operations that hand one build
another build's bytes.

So an envelope leads with the construction it was written to:

```text
[u8 version][u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
```

The version is read **before any offset is trusted**, which is the whole point —
a parser that reads a length first has already committed to a layout it may have
no rule for. It is one number, exposed as `keyring::ENVELOPE_FORMAT_VERSION`,
and it names the entire construction: layout, nonce width and AEAD together.
Changing the cipher changes what the bytes mean, so a second AEAD is a second
version rather than a second field — and a reader that picked between suites by
trying them would be a decryption oracle, not a parser.

A version this build does not read is `KeyError::UnknownFormat`, beside
`Retired` and for the same reason:

```text
this sealed envelope is format version 2 and this build reads 1 — the bytes are
intact and not erased; they open under a build that reads version 2
```

Without the byte, that envelope would have reached the AEAD with its fields read
from the wrong offsets and come back as *the sealed payload did not
authenticate* — an incident sentence for a build skew whose remedy is which
binary is running.

The rule binds readers too. A component that cannot identify what it is holding
says so rather than staying silent: `drill`'s probe answers *nothing to check*
only for state that was never sealed. State marked sealed whose envelope will not
parse, whose version is unknown, or whose erasure scope names a **different
case** is a finding — the last most of all, because erasing that case destroys a
key which does not reach those bytes, so the data would survive the deletion
request.

The version stays `1` until the durable-format freeze, and an envelope at any
other version is refused rather than lifted. Pre-alpha shape changes are hard
cuts, and here more sharply than anywhere else in the crate: sealed bytes cannot
be rewritten into a new shape, so a deployment holding sealed data from an
earlier release keeps it readable by staying on that release.

Four rules hold the semantics together, each removing a way an erasure could be
quietly incomplete:

- A scope yields **one** data key. Two keys in one erasure unit means destroying
  one leaves the other half readable.
- An erased scope **does not come back**. Re-minting would let a late write land
  in a unit already reported as erased.
- Erasure is **idempotent**, and the first tombstone stands — a retry must not
  rewrite when or why the data went, because that record is the evidence.
- An erased read reports **expired**, never missing and never corrupt. Those
  three send an operator to three different places, and only one is an incident.

A blob stays *identified* by the digest of its **plaintext**, so every digest
already written to a journal keeps meaning what it meant, and the digest is the
envelope's associated data — ciphertext moved to another address fails to
authenticate rather than opening as somebody else's payload. The **storage
address** underneath is derived from the erasure scope *and* that digest
(`blob::unit_address`), and the distinction carries an erasure guarantee of
its own: identical bytes in two cases are one digest but **two objects**, so
one case's tombstones cannot destroy another case's copy of the same document
— and neither can its key destruction, because each case's copy is sealed
under its own scope. Deduplication ends at the erasure-unit boundary on
purpose; a copy shared across two units would be one that one unit's erasure
either destroys wrongly or provably fails to reach.

The erasure unit is the **case**, on both sides, because the case is already the
retention unit — bytes are linked to their case when they are written, and a
second differently-shaped unit for keys would let the two disagree about what an
erasure covered. `cx.blobs()` is where a skill gets a store already sealed to its
case; a store held from the builder writes in the clear, and the two would
disagree about what erasing the case erased. A **blob** write on a run under a
key ring that belongs to no case is refused rather than quietly unsealed. The
run's *journal* payloads are a different matter: a record bound to no case seals
under `tenant/<run>` — still an erasure unit somebody can name — and
`blob::erase_run` is the verb that destroys it, the counterpart of `erase_case`
for the unit that call can never reach.

Governed media is payload too, and takes the same route — scoped to its case, or to a named external retention policy when another lifecycle controller owns those bytes. A guard holds the raw store to **exactly one reader**, because a second write path reaching it directly is the shape of hole worth naming: everything works, the bytes are written, the run succeeds, and the erasure is quietly partial.

`erase_case` writes every tombstone first and destroys the key last. The order
matters in one direction only: a crash between them leaves bytes that are still
readable, which running the erasure again fixes. The reverse would leave
unreadable bytes with no tombstone, so a later read reports *corrupt* and someone
is paged for an integrity fault that is really a completed erasure.

Each payload gets its **own** data key, wrapped under the scope's key and stored
*inside the envelope* alongside the ciphertext:

```text
[u32 len][wrapped data key][24-byte nonce][ciphertext ‖ tag]
```

That shape is not a convenience — it is what a key-management service actually
does. Vault's `transit/datakey` and KMS's `GenerateDataKey` both mint a fresh key
per call and wrap it under a *named* key, so a design expecting a stable
per-scope key cannot be implemented against either. The erasure unit is therefore
the **wrapping key**: destroying a scope's wrapping key makes every data key ever
wrapped under it unopenable at once, however many payloads there were.

It is also what makes **restore** work. A backup holds the ciphertext and its
wrapped key — everything needed to bring the bytes back and nothing needed to
read them, because the wrapping key never left the service. Restoring into a
fresh store, a new region, or a different operator's hands yields ciphertext and
a key nobody can open.

The `KeyRing` seam is where a deployment points at the thing that already holds
its keys. `VaultTransit` speaks HashiCorp Vault's transit engine over its HTTP
API — four calls, no SDK — so the wrapping key is created inside Vault and never
leaves it, and erasure becomes something this crate asks for and cannot undo.
A single key-ring conformance battery is run against both the in-process ring
and a real Vault, because the two fail in different places: one cannot get a
status code wrong, the other cannot get a `HashMap` wrong. That is not a
formality — running it against Vault found three defects, all the same root
cause: **Vault reports a destroyed key as a 400 with a message, not a 404**, so
a completed erasure was arriving as an ordinary refusal and a caller could not
tell it from a permission problem.

One operational detail matters enough to state: **a transit key cannot be deleted
unless it was configured to allow it**, so an erasure against a default key fails
loudly here rather than reporting a success that did not happen.

`MemoryKeyRing` lives in `testkit` and is unreachable without it: it holds the
wrapping keys beside the data they protect, so the feature gate is the guarantee
rather than a warning in a doc comment.

## Tenancy

`RuntimeBuilder::tenant` names the tenant a plane runs as, and the name is a
validated type rather than a string: it refuses `/` and `:`, because a tenant
called `acme/prod` would otherwise produce the same key scope as tenant `acme`
with unit `prod`, and the two would be indistinguishable afterwards.

The tenant is a **key component**, never a filter. That distinction is the whole
of it: a filter is a predicate somebody has to remember to write, and the query
that forgets it returns another tenant's rows. A key component means the same
mistake returns nothing. Every test here hands the attacker a *valid* identifier
belonging to the other tenant, because that is the realistic leak — not a
guessed id, but a real one arriving through a path that never checked whose it
was.

What is bound:

- **data keys** are scoped `tenant/unit`, so one tenant's erasure cannot reach
  another's bytes — even when both use the same case name, which is exactly
  where a missing prefix collides;
- the **policy request** carries the tenant, at admission and at every effect;
- the **redb** journal, seal log, cases, events, timers, tasks and batches are
  tenant-keyed via `RedbStore::for_tenant`, which prefixes every key. The tenant
  leads every time-ordered index, so a sweep or a worklist *ranges over* its own
  rather than filtering another's out, and counts are ranged rather than taken
  from the table — a whole-table count reports every tenant's backlog as this
  one's;
- **`PostgreSQL`** carries `tenant` as the leading column of every primary key,
  unique index and foreign key, via `PostgresStore::for_tenant`. This is the
  backend that exists for several plane instances sharing one store, so it is
  the one where a forgotten predicate is both most likely and worst. It is
  checked against a real Postgres, and the check is adversarial in all three
  places that matter: a valid run id from another tenant, a correlation key two
  tenants both use, and an event whose kind and keys match another tenant's
  waiting run.

Two correlation paths deserve naming, because both look like collisions and are
not. A **correlation key is a business value** — `document`/`DOC-1` means
something different to every tenant, and two of them using it is ordinary. Left
global, one tenant's run would join another's case and the two would share a
history, a deadline set and an erasure unit. Worse, one tenant's message would
resume another tenant's waiting run, handing it a payload nobody sent it. Both
indexes lead with the tenant.

**Blob paths** lead with the tenant too, and the reason is erasure rather than
reading. Blobs are content-addressed, so two tenants writing identical bytes — a
standard form, an empty document, a common attachment — land on one object when
the path has no tenant in it. Expiring it to discharge one tenant's request then
destroys the other tenant's data *and reports both requests satisfied*: the
request nobody made is marked done, and the data that should have survived is
gone. Encryption does not fix that half; only the path does. The same argument
holds at the unit erasure actually names: the **erasure unit** leads the
storage address too (`blob::unit_address`), so one matter's erasure cannot
destroy another matter's copy of the same bytes.

**The plane and its stores must agree, and `try_build` checks.** The tenant
scopes the plane's data keys; each store handle is scoped separately, so the two
are set in different places and can differ. When a key ring is wired that
difference is invisible: `build()` seals case, event, task, memory and outbox
state under the *plane's* tenant while the store writes its rows under its own,
both scopes are real, every run works — and an erasure destroys exactly the key
it was asked for without reaching the rows, then reports success. That is the
one failure a deletion guarantee may not have, so it is a startup refusal:
`JournalStore`, `BlobStore`, `CaseStore`, `EventStore`, `TaskStore`,
`MemoryStore` and `PushStore` each answer a `tenant()` question, and a
disagreement fails the build naming the store and both tenants. A store that
does not override the accessor answers `default` — right for a single-tenant
deployment, and refused against a named plane, which is the safe direction.

**Serving** is tenant-aware: `Planes` maps an authenticated caller's tenant to
that tenant's plane. Three details carry the weight.

The tenant comes from the **credential**, exactly as `actor` and `roles` do. It
is the field that decides which store answers, so a body-supplied one would be a
cross-tenant read with an authentication step in front of it.

The gate returns the plane **with** the caller, and the surface holds a registry
rather than a runtime. A handler therefore cannot reach a store without having
resolved whose it is, and every lookup on that registry names a *caller* rather
than a tenant — so the accidental cross-tenant read is unspellable rather than
guarded against. The deliberate one is `Planes::cross`, which records the
crossing in the crossed tenant's own journal before serving anything.

An unregistered tenant is **refused, never defaulted**. A fallback would turn an
unknown tenant into somebody else's data, and it would look like working
software. Each plane also answers under its own policy engine, so one tenant's
rules cannot decide another's requests.

On A2A the tenant is checked twice: against the card's routing identifier and
against the credential. Those are different questions — what the request asked
for, and what the caller holds — and a peer with a valid credential for one
tenant naming another is precisely the case where they disagree.

**Quotas** are per tenant too, and durable for the same reason the keys are: an
in-process ceiling vanishes the moment a second instance starts, and it fails
*open*. Concurrent runs and spend per billing period are both bounded, refused at
admission, and never consulted on replay — a ceiling crossed since a run happened
must not turn its history into a refusal. See
[operations](@/docs/operations.md).
