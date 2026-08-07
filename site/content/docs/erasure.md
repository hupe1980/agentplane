+++
title = "Erasure and keys"
description = "Cryptographic erasure that reaches backups, envelope encryption, key rotation and revocation, and the tenancy boundary."
weight = 7
+++

An erasure obligation is discharged by making data unreadable **everywhere**,
not by deleting the copy you can reach. This page is how that is done here, and
what the boundary actually is.

For the trust model those keys sit inside, see [security](@/docs/security.md).

---

## What lands where, and what can be erased

Decide this before personal data reaches a run. The journal is append-only and
hash-chained: a record cannot be deleted without breaking the chain, and
**journal rows are not encrypted**, so cryptographic erasure does not reach
them either. Whatever enters the chain is permanent for the life of the store.

| Data | Where it lands | Erasable |
|---|---|---|
| Run input | journal — `RunAdmitted.input`, verbatim | **no** |
| **Model prompts** | journal — inside `EffectStarted.descriptor.args`, verbatim, because the prompt is part of effect identity | **no** |
| **Tool call arguments** | journal — same field, same reason | **no** |
| Effect outputs — completions, tool results | journal — `EffectDone.output`, verbatim | **no** |
| Case state writes, status changes, deadline transitions | journal (the effect) **and** the case store | sealed in both, under the same per-case scope |
| Inbound event payloads — a counterparty's message body | journal (the awaited effect's output) **and** the event store | sealed in the journal; **plaintext in the event store** |
| Human task proposals — `Justification.proposed_action`, the exact thing a reviewer is shown | journal (the task effect) **and** the task store | sealed in both; the task's `summary` stays readable so a queue stays usable |
| Memory item content | `MemoryStore` | **yes** — `forget`, `forget_cascading`, expiry sweep; and unreadable everywhere with `EncryptedMemoryStore` |
| Blob bytes — `cx.store_blob`, fetched media | blob store | **yes** — expiry leaves a tombstone; and unreadable everywhere with `EncryptedBlobs` |
| Blob digest and classification | journal | no, and it does not need to be — a digest is not the bytes |

**The rule this forces: keep erasable personal data out of the chain.** Put the
bytes in a blob and let the journal commit to the digest:

```rust
let digest = cx.store_blob(document_bytes).await?;  // erasable, linked to the case
// The chain records the digest and the classification, never the bytes.
```

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

**Or seal the journal itself.** `SealedJournal::wrap(store, keys)` seals the
payload fields — run input, effect arguments (prompts, tool calls) and effect
outputs — under the same per-case scope `erase_case` already destroys, so a
single erasure reaches blobs and journal alike:

```rust
let store = SealedJournal::wrap(store, keys);
let cases = SealedCases::wrap(cases, keys, tenant);   // the case store's own copy
let tasks = SealedTasks::wrap(tasks, keys, tenant);  // the worklist's copy
```

Two properties make it worth having rather than merely present. Only the
*payload* is sealed: `seq`, `run`, `case`, `effect_key` and the record's own
variant stay in the clear, so exactly-once, the case scan, the outcome index
and the chain keep working with no key at all. And the chain commits to the
**ciphertext**, so an auditor holding no keys still verifies the history of a
run whose payloads have been erased — hashing the plaintext would have tied
the tamper evidence to the key and destroyed both together.

What stays plaintext is **event payloads** in the event store. That one is not
an oversight but an open question: an event is buffered *before* any
subscription matches it, so at write time it belongs to no case — and the
erasure unit everything else here uses is the case. Sealing events under the
tenant instead would give at-rest protection while leaving `erase_case` unable
to reach them, which is exactly the two-mechanisms-disagreeing shape the rest
of this page avoids. Until that is settled, an event payload is journaled
(sealed) and buffered (plaintext until claimed).

Correlation keys, deadline names, task summaries and statuses stay readable
everywhere by design — they are what the stores are asked questions *about*.
A deployment that considers its business keys personal data must choose keys
that are not. A deployment
whose obligation covers them either erases the case — which destroys the scope
key and takes the journal copies with it — or keeps the data out, which is what
`max_sensitivity_journaled` refuses at the boundary.

---

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

Three operations fall out of one structure, which is the argument for it:

| | |
|---|---|
| **Erasure** | destroy a data key — its scope's bytes are gone, everywhere |
| **Rotation** | re-wrap data keys under a new wrapping key; bulk data is never rewritten, so rotating is cheap enough to do on a schedule rather than in a plan |
| **Revocation** | destroy a wrapping key — everything wrapped under it is unreadable, which is the blast radius a compromised key should have |

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

A blob stays addressed by the digest of its **plaintext**, so every digest
already written to a journal keeps meaning what it meant, and the digest is the
envelope's associated data — ciphertext moved to another address fails to
authenticate rather than opening as somebody else's payload.

The erasure unit is the **case**, on both sides, because the case is already the
retention unit — bytes are linked to their case when they are written, and a
second differently-shaped unit for keys would let the two disagree about what an
erasure covered. `cx.blobs()` is where a skill gets a store already sealed to its
case; a store held from the builder writes in the clear, and the two would
disagree about what erasing the case erased. A run under a key ring that belongs
to no case is refused rather than quietly unsealed.

Governed media is payload too, and takes the same route — scoped to its case, or to a named external retention policy when another lifecycle controller owns those bytes. Its own write path previously reached the raw store, which is the shape of hole worth naming: everything worked, the bytes were written, the run succeeded, and the erasure was quietly partial. A guard now holds the raw store to exactly one reader.

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
gone. Encryption does not fix that half; only the path does.

**Serving** is tenant-aware: `Planes` maps an authenticated caller's tenant to
that tenant's plane. Three details carry the weight.

The tenant comes from the **credential**, exactly as `actor` and `roles` do. It
is the field that decides which store answers, so a body-supplied one would be a
cross-tenant read with an authentication step in front of it.

The gate returns the plane **with** the caller, and the surface holds a registry
rather than a runtime. A handler therefore cannot reach a store without having
resolved whose it is — the cross-tenant read is unspellable, not guarded
against.

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
