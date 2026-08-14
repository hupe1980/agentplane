+++
title = "Operations"
description = "Deploying, high availability, retention, observability, and a runbook for every state a run can get stuck in."
weight = 8
+++

Running this for real: topologies, the store contract, the background sweep,
and what it reports about itself.

---

## Ownership and fencing

Plane instances are stateless. Each run has at most one owner, held as a lease
with an **epoch**.

Every append carries the writer's epoch, and the store compares it *inside the
same transaction that writes*. There is no window between "am I still the
owner?" and the write for a paused instance to slip through, because there is no
gap to slip into.

Two failure modes, deliberately distinct because they need opposite responses:

| Error | Meaning | Response |
|---|---|---|
| `LeaseHeld` | Someone else owns it and is alive | Wait |
| `Fenced` | Your epoch is stale; you were taken over | **Drop the run.** Never retry |

Failover is not a special code path — it is the crash-recovery path. Lease
expires, another instance claims at `epoch + 1`, resumes via replay. That is the
payoff of building on replay: HA costs one lease table and an epoch column.

The claim is **initiated by the sweep**, and that sentence used to be missing
its subject. Fencing makes takeover safe and replay makes it correct, but for a
release neither made it *happen*: every resume had an event-shaped driver — an
inbound message, a fired timer, an operator — so a run crashed mid-step with
none of those pending had no driver at all, appeared in no backlog (it
concluded nothing, and its wake was already consumed), and waited forever while
looking exactly like work in progress. The sweep's recovery pass closes that:
an expired lease that still names an owner is precisely "an instance died
holding this run", because every clean exit — sealed, failed, suspended —
releases. See [the sweeper](#the-sweeper).

### A live run renews; only a dead owner's lease expires

Expiry answers *is this owner dead?* Without renewal it also answers a question
nobody asked — a healthy run that outlives its TTL looks exactly like a crashed
one, and agent runs routinely outlive a lease because one model call can. The
run would be taken over and the original fenced mid-flight, having already done
real work.

So the runtime renews while a run executes, at a third of the TTL, and stops the
moment execution returns. Set the TTL with `RuntimeBuilder::lease_ttl`: it bounds
how long a **crashed** owner strands its runs, not how long a run may take.

Anything under two seconds is refused at build. Both stores keep expiry in whole
seconds and lapse on `expires_at <= now`, so a one-second lease is expired for
part of every second it exists and no renewal frequency saves it — a plane
configured that way would lose runs under load and nowhere else.

### The owner string identifies a *process*, not an agent

This is the one piece of the mechanism you can defeat by accident. A lease is
renewed **without bumping the epoch** when the claimant is the same owner —
that is what lets a live instance keep its own run. So two instances sharing an
owner string each read the other's lease as their own, renew it, and both write
under one epoch. Fencing is gone, and nothing reports an error.

`Runtime::owner_id()` therefore defaults to a value that is unique per process
and per runtime instance. Override it with a real instance identity — a pod name
— never with the agent's name:

```rust
Runtime::builder(store).owner(std::env::var("POD_NAME")?).build()
```

Several instances of one agent are the normal way to run one, so the agent's
name is exactly the wrong choice. The agent is named by its manifest; the
process is named here, and the two are different questions.

The owner lives in the lease table and never in the chain, so changing it has no
bearing on replay.

### Releasing frees the lease without forgetting the epoch

A graceful shutdown hands the lease back so the next instance need not wait out
the TTL. What it must **not** do is delete the row: the epoch lives there, and
without it `append` has nothing to fence against while the next `acquire` starts
again at 1 — so a writer already fenced at 2 outranks the new owner and the
mechanism inverts. Releasing marks the row expired instead, and the next
takeover advances the epoch as any takeover does.

That last part is worth stating because the intuition runs the other way:
releasing says the owner *intends* to stop, not that it already has. An
un-awaited task or a crash between release and exit leaves an append in flight,
and only a bump stops it. Takeover is immediate either way, which was the point
of releasing.

## Two backends, one contract

`JournalStore` states three guarantees and requires them atomically: fencing,
exactly-once, chaining. They are storage invariants deliberately — application
logic can be bypassed by the next caller, a constraint cannot.

A second backend is where that stops being true, and the mechanism is worth being
precise about. The new store is written from the same prose as the first. It
encodes two guarantees exactly and something *nearly* like the third. Nothing
catches it, because the suite that proves the runtime correct runs against the
embedded store, and the new one gets whatever tests its author wrote — which are the
tests for the parts they were already thinking about. The invariant they misread
is by construction the one with no test.

So the contract is written once, in `testkit::conformance`, and every backend is
run against the same battery. It ships rather than living in `tests/` because an
embedder bringing their own store needs it for the same reason.

Two design choices in the battery:

* **It reports every violation, not the first.** Bringing up a backend is
  iterative, and stopping at the first failure hides whether the second is a
  separate bug or a consequence.
* **It fails if it checked nothing.** A battery that silently runs zero checks
  reports success, which is the worst outcome available to it.

Writing it immediately caught a misreading in the battery itself: a *live* lease
is correctly not stealable — `LeaseHeld`, deliberately distinct from `Fenced`,
because the two call for opposite responses. A fenced writer must drop the run; a
writer refused a live lease is not stale and should wait. That distinction is now
one of the checks.

### The case layer

Five more stores, each settling one race:

| Store | The race |
|---|---|
| cases | two messages, one new matter; and two runs, one case state |
| events | one message, two waiters |
| timers | one wake-up, two sweeps |
| tasks | one decision, two reviewers |
| batches | one item, two reservations |

Each has a battery in `testkit::conformance_case`, run against both backends. The
container tag is pinned in the test rather than inherited: the
`testcontainers-modules` default is `postgres:11-alpine`, which has been end of
life since November 2023, so the default would certify this backend against a
release nobody should be running.
Postgres settles several more cleanly than the embedded store: `UPDATE … RETURNING` collapses
a read-then-write into one statement, so there is no window to reason about
because there is no second statement.

#### A paged read is part of the contract

`JournalStore::recent_runs(after, limit)` is the discovery index behind A2A task
listing, and the battery checks three things a paged read gets silently wrong:
the order is `(updated_at, run)` descending and **total**, the limit is
honoured, and paging through it in twos reassembles the whole index exactly —
no run served twice, none skipped.

The tie-break on run id is contract rather than detail. Both backends keep
whole-second timestamps, so runs written back to back share one; without a
tie-break the store may order them differently between two calls, and a cursor
landing inside the tie drops or duplicates whichever moved. From a single page
both look like a healthy listing.

This method used to return *everything*, and had no battery entry — the two
facts belong together. A signature with no page boundary has no boundary to get
wrong, so there was nothing to check, and the one caller paid for it by reading
every run's complete journal on every request.

#### A sequential test cannot detect a race

Sequential checks prove the *result* is right, not that it is right for the right
reason — a `SELECT` then `INSERT` returns the correct answer every time it is
called one at a time.

So correlation also has a racing check, and it races **hard**: two concurrent
callers serialise often enough that dropping the constraint which arbitrates
correlation goes undetected. Eight racers across four keys catches it on every
run, and mutation-testing the battery is what proves the check can fail.

* **A race test that does not reliably race reports green** — an untested
  guarantee wearing a test's clothing.
* **A race check corroborates, it does not prove.** Passing means no interleaving
  found a violation; the constraint in the store is what makes absence real.

A store that serialises internally — redb admits one writer at a time — passes
trivially and correctly, having no race to lose. That is not a reason to skip it:
the check exists for the backend where the race is real.

The lesson was paid for once. The PostgreSQL run ceiling shipped with a comment
claiming its count-and-insert serialised "inside the row lock the write takes" —
no such lock exists for inserts of different rows, and racing it put eight runs
through a ceiling of four while every sequential test stayed green. So the
guards suite now **races every store-side concurrency claim against a real
PostgreSQL**: quota admission (sixteen racers, four slots), authority draws
(sixteen racers, a mandate affording three), task claims (sixteen reviewers,
one holder), timer sweeps (two sweepers partitioning twelve due wake-ups), case
correlation and case-state writes. A claim about concurrency that has only been
read is a claim; raced, it is evidence.

### Postgres

Three traps, each a plausible way to be nearly right:

* **Exactly-once is a partial unique index.** A `SELECT` then `INSERT` has a
  window with two writers, and closing that window is the entire point.
* **Fencing reads the lease `FOR UPDATE` inside the appending transaction.**
  Checking the epoch first and appending second re-opens the gap a paused
  instance wakes up into.
* **`seq` comes from the run's own chain**, never a sequence. Postgres sequences
  are non-transactional and leave gaps; a gap is indistinguishable from a deleted
  record during verification.

Each was confirmed falsifiable by weakening the store and checking the battery
named the right invariant — including one mutation that moved the writes outside
the transaction, which the atomicity check caught with "a rejected batch left 1
record(s) behind".

## What an effect costs

The first question a runtime built on *"the journal is the plan of record"*
invites, and one this project could not answer until it had a way to produce a
number. `just perf` produces it; these figures are from an Apple-silicon laptop
and are quoted with the command precisely because they are hardware-specific:

```
2000 effects, redb in memory
  live      161.8ms      12363 effects/sec   0.08 ms/effect
  replay     11.7ms     171282 effects/sec   14x faster than live

2000 effects, redb on disk
  live       17.5s         115 effects/sec   8.73 ms/effect
  replay     16.3ms     122809 effects/sec   1072x faster than live
```

### Read the gap, not the numbers

**Two fsyncs per effect.** An effect crosses the protocol twice — `EffectStarted`
before dispatch, its terminal record after — and both are durable commits at
`Durability::Immediate`, because I2 says the announcement must survive the
process *before* anything reaches the world. The ~9 ms is that guarantee's
price, not an inefficiency waiting to be tuned away. Batching the two would
break the only thing standing between a crash and an unrecorded payment.

**Against what an effect normally is, this is noise.** A model call is seconds; a
tool call is tens of milliseconds. At 9 ms, journaling is well under 1 % of a
real agent's wall clock, and the whole design is priced for effects that reach
the world.

**It stops being noise when effects are cheap and many.** `cx.now()`, a case
read, a memory recall — a plan doing hundreds of those pays 9 ms each. If a
step is looping over cheap effects, that loop is the cost.

**On redb it is a plane-wide ceiling, not a per-run one.** redb has a single
writer, which is exactly what makes its exactly-once key and its fencing free of
races — and it means ~115 effects/sec is the *whole plane's* durable write
budget on this hardware, not one run's. A single-node plane running agents that
call models will never notice. A plane running many concurrent runs of cheap
effects will, and that is the signal to move to `PostgreSQL`, which is also the
answer for more than one instance.

**Replay is not the same cost, by a wide margin.** It performs nothing and reads
history back — 1000× faster on disk. That matters more than it looks: a
divergence check, a crash recovery and an offline audit all pay the read price,
so the expensive half is the half that only happens once.

`PostgreSQL` is deliberately **not** measured here. It is a different machine, a
different fsync, and usually a network hop; quoting a number produced on a
laptop's container would be worse than quoting none.

## The sweeper

Until something runs on a clock, a deadline is a number in a table and an
unclaimed event is a row nobody reads. That is the failure this runtime is built
against — not a crash, but a silence.

One tick, five findings — four of them loud, and the first one routine healing
that still means an instance died:

| Finding | What happens |
|---|---|
| An instance died holding a run | The run is taken over at `epoch + 1` and resumed |
| An obligation is approaching | `DeadlineTransition` → `Warned` |
| An obligation passed unmet | `DeadlineTransition` → `Breached`; the **case** is escalated |
| A task's window closed | The declared `on_expiry` is applied |
| An event nobody claimed aged out | Dead-lettered with a reason |

`now` is passed in rather than read, so the caller controls the clock. That keeps
the sweeper testable at all, and lets a simulation drive a year of obligations
through in milliseconds.

Every field of `SweepReport` is a number worth alerting on. `is_quiet()` is the
useful predicate: a healthy plane sweeps silently, so a non-silent sweep means
something happened.

### The recovery pass: who resumes a crashed run

The candidate set is exact, not heuristic. Every clean exit hands its lease
back — sealed, failed, *suspended* — so `JournalStore::abandoned_runs` answers
one precise question: which leases expired while still naming an owner. That is
the set of runs somebody was executing when their process stopped, and the
sweep resumes each one: takeover bumps the epoch, the store fences the dead
owner's next append, and replay reads completed effects back rather than
redoing them.

Three details are worth knowing at 3 a.m.:

- **`runs_recovered` above zero means an instance died**, even though the runs
  themselves are fine. The healing is routine; the dying is not. A steady
  recovery rate with allegedly healthy instances is a contradiction — go look
  at why leases are lapsing (GC stalls and CPU starvation produce exactly
  this).
- **`recovery_failures` is one stuck run, not many.** The run stays listed and
  is retried every tick, so a persistent count is the same run failing
  repeatedly — and nothing else will unstick it. The reason is in the log line
  of the failing tick. This is the one recovery number `needs_attention()`
  fires on.
- **The batch is small (32) on purpose.** Recovering a run replays its journal
  and then executes live from the frontier — which may dispatch a model call —
  so a mass failure drains over several ticks with `saturated.recovery` up
  rather than holding one tick hostage. The flag means *at least* a batch was
  waiting, never that the batch was all there was.

Each takeover is written into the sweep's own sealed run as `run_recovered`,
because a takeover fences the previous owner and *who fenced whom, and why*
must be answerable from the journal rather than inferred from an epoch gap.

One state recovers to nothing, deliberately: a lease over an **empty** journal
means admission acquired and died before its first append landed. No run
exists — the atomic admission batch never committed, so nothing was declared,
authorized or performed — and clearing the lease is the whole recovery.

What the pass does **not** cover, stated rather than implied: a crash inside
the one store-commit between an event's claim and the lease acquisition that
resumes it. That window is one transaction wide; its symptom is later events
for the same correlation dead-lettering, which the sweep already reports.

### A finding has to be findable

Every conclusion this runtime reaches is queryable by whoever must clear it:
escalated cases by status, overdue tasks by role, breached obligations by the
sweep, dead-lettered events by their own list.

That sentence was written once while it was not yet true of two of its own
items, which is worth saying because the failure it describes is precisely a
claim nobody re-reads. A quarantine
means the recorded history can no longer be trusted, or a mutation is in a state
nobody can establish — and it produced a run status, an `error!` event and a
counter. None of those can be asked for, and a run started with `spawn` or over
A2A's `return_immediately` returns *before* the status exists, so the log line
was the only trace.

```sh
curl -H "$AUTH" 'https://plane/runs?outcome=quarantined'
```

Concluded runs are indexed by how they ended. The index is **derived** from
the `RunSealed` record inside `append`, in the same transaction, so it can be
rebuilt from the chain and is never an authority. **The last conclusion
wins**: a failed run moves to `succeeded` when a resume concludes it again,
so the failed backlog drains. Failure does not seal — a failed or exhausted
run stays open and resumable; only succeeded, quarantined and cancelled
freeze the journal and enter the Merkle log.

The list comes back **newest first**, and `truncated` says whether there is
more. That ordering is part of the store contract rather than a detail of the
index, because the obvious alternative reintroduces the exact failure this
endpoint exists to remove: a bounded query in ascending order is a page that
stops changing, so a plane whose backlog already exceeds one page returns the
same runs forever and the quarantine that just happened is the one that never
appears. Emitted, indexed, queryable — and still not delivered.

**Escalated cases were the second exception**, and it survived the fix above by
being asserted in a comment on it. An escalation is the sweeper saying an
obligation was missed and somebody was told; "told" meant a status written onto
the case, and the only way to read it back needed the case id — so the answer
was available to everyone except the person who had to ask.

```sh
curl -H "$AUTH" 'https://plane/cases?status=escalated'
```

Same discipline as the run listing: newest first, `truncated` says whether there
is more, and `status` defaults to the one somebody is looking for. An
unrecognised status is a `400` rather than a quiet fallback — answering *what is
escalated* with a list of healthy cases reads as an empty backlog, which is the
most reassuring possible way to be wrong.

A third gap sat behind both, in the enumeration rather than the routes.
`api:run.list` — the verb guarding the quarantine listing — was **missing from
the exported action vocabulary**, so a deployment that wrote its rules by
enumerating it never granted that verb, and a default-deny engine refused the
backlog to everybody. The test that should have caught it compared the
vocabulary against the routes its own walk exercised, and that walk did not call
`/runs` either: two omissions that cancelled, agreeing forever. Enumerate the
vocabulary when writing rules, and grant `api:run.list` and `api:case.list`
explicitly — they are the two read verbs an on-call person needs and the two an
allowlist built from route names alone will miss.

The general rule is worth stating because it is easy to satisfy accidentally and
easy to lose: a control that notices and does not deliver is closer to none than
to half, because it also manufactures the belief that somebody was told.

### Taking the record away

Two verbs read a journal and nothing else — no manifest, no source tree, no Rust
toolchain — because that is what an auditor or a departing tenant holds:

```sh
agentplane export --store ./journal.redb > history.jsonl
agentplane audit  --store ./journal.redb > report.json
agentplane verify history.jsonl            # check a copy, offline
agentplane restore history.jsonl --store ./rebuilt.redb
```

`export` writes JSON Lines: a header naming the log, its checkpoint and the
canonicalization rule the digests were computed under; one line per record
carrying `prev_hash` and `hash`, so the chain re-walks from the file alone;
**one line per case** — the case layer is beside the journal, not derivable
from it, so a file without it rebuilds a journal whose records name matters
that no longer exist; and a trailer. The trailer's **absence** is the signal —
a file cut short by a full disk or a killed pipe ends without one, and every
line in it is still valid JSON, so counting is no help to a reader who does not
have the source. Runs that could not be read are named in the trailer rather
than quietly missing, and the trailer's case count is what catches the case
layer stripped whole.

Case state travels **as stored**: on a sealed plane that is ciphertext, because
an export of plaintext would quietly undo erasure — the key destroyed tomorrow
would no longer reach the copy taken today. Two questions stay live rather than
offline, and `verify` reports them as unchecked instead of passed: whether the
blob bytes behind the exported digests are present, and whether sealed state's
keys still unwrap.

`audit` prints the report as JSON and exits non-zero on findings — but **not** on
`not_checked`, which is a separate list and the one worth reading. An audit given
no public key and no earlier checkpoint still walks every chain, and says in that
list that it could establish neither authorship nor deletion. Supply them to
narrow it:

```sh
agentplane audit --store ./journal.redb \
  --key plane-1=<64 hex chars> \        # the signer's Ed25519 public key
  --prior last-report.json              # the `current` field of an earlier report
```

`--key` is the authorship check, repeatable per trusted signer; add
`--require-signatures` to make an unsigned record a failure rather than a note —
off by default, because history written before signing was configured is
legitimately unsigned. `--prior` is the deletion check: the report's own
`current` field, saved from an earlier pass, and a log that shrank or forked
since then is a finding. The loop is deliberate — each audit prints the
checkpoint the next one checks against.

Both verbs default to every sealed outcome. `--outcome` narrows, `--limit`
bounds, and reaching the limit prints a warning on **stderr** — so it survives
`> out.jsonl` and an operator piping the export somewhere still learns the view
was partial.

Auditing open runs (`--outcome failed`, say) is not an alarm: an open run has
no Merkle leaf, so it is checked on chain and signatures and the report says in
`not_checked` that nothing pins its tail until it seals. The finding is the
opposite case — a run whose own records carry a *sealing* conclusion, in a log
that holds no leaf for it. That is history the log no longer commits to.

`verify` is the drill, and it takes the file alone. It re-seals every record
through the same function the store sealed with — so agreement is evidence about
the bytes, not the file agreeing with itself — checks sequences are contiguous,
holds every record to the run block it sits under (a relabelled block passes
chain, leaf and Merkle checks, because those verify the bytes and only the label
lied), then rebuilds the Merkle log from the positions each run block carries
and compares the root against the checkpoint in the header. With `--key` it
also verifies signatures, strictly: inside a signed history, an unsigned record
is the one an attacker who cannot sign would add.

That last check is the one worth understanding. Delete a whole run from an
export and every remaining chain still verifies perfectly: a chain links records
*within* a run and knows nothing about its neighbours. Only the rebuilt tree
notices the missing leaf. It is also the reason each run block carries its log
position at all — without it an export is a transcript rather than evidence.

Exit codes: findings fail, `not_checked` does not. A pass with no public key has
established less rather than failed, and the report says which.

`restore` rebuilds a journal from an export and proves it by one comparison:
**equal Merkle roots at equal size**. That is a far stronger statement than "the
rows loaded" — it means every record, in every run, in the order the log
recorded them, rebuilt to the same commitment. A run restored this way
strict-replays on a plane that never executed it.

It rebuilds the case layer beside the journal: every matter is queryable again
— `case`, correlation, the status worklist, the deadline sweep, the blob links
erasure walks — and the conformance battery holds the import to every one of
those read paths on both backends, because an import that rebuilds five
indexes out of six reads perfectly until somebody queries the sixth. A store
that already holds a case refuses it: a restore rebuilds a case layer, it does
not merge one.

It replays the ordinary `append` path rather than writing rows, and that is the
safety argument: `append` maintains six derived indexes — case, exactly-once,
outcome and its ordering counter, and both halves of the discovery index — and a
restore that rebuilt five of them would produce a store that reads perfectly
until somebody queries the sixth.

Two details make that reproduce the original bytes rather than similar ones.
Runs are **sealed in log-index order**, because that order *is* the Merkle log —
seal them in file order and the same leaves give a different root. And `epoch` is
**carried, not re-derived**: it is inside the hashed body, so a run that ever
changed hands would rehash under a single fresh lease, and those are exactly the
runs a failover produced. Both backends fence only when a lease row exists, so
restoring into a store with no leases writes each record under its own epoch.

What does not survive is named in the report rather than left to be discovered.
**Signatures**: `append` attests as the restoring store's signer, so a history
signed by a key this store does not hold comes back unsigned — hashes and the
root are unaffected, since a signature is taken over the chain hash and stored
beside it, but authorship is gone. Configure the same signer if you are restoring
your own log. **Activity timestamps**: the discovery index is rebuilt at restore
time, so `recent_runs` orders by when history was restored. It is documented as
ordering and cursor stability only, and nothing derives a decision from it.

What is exported is what the chain committed to. With a key ring configured that
is ciphertext, deliberately: an export of plaintext would put a copy beyond the
reach of key destruction and undo the erasure the key ring exists for.

### Break-glass

Reaching another tenant's data is the one exception to isolation, so it is
recorded in **that tenant's** journal — actor, roles, and a reason that cannot
be blank — before anything is served:

```rust
let plane = planes.cross(&caller, &target, "INC-42: stuck settlement").await?;
```

`Planes::cross` hands back the plane only once the crossing is on that tenant's
record. That ordering is the control, and making it a door rather than a step is
what makes it one: a break-glass that serves first and records best-effort works
exactly as well when its own evidence is lost, which is the state an incident is
most likely to produce.

The whole `Caller` goes in rather than its actor, roles and tenant separately,
because those are one fact — who authenticated. Passed apart, a handler can
record one operator's name against another's crossing, and the record is written,
signed, and wrong.

The ordinary lookup, `Planes::get`, takes the same `Caller` and serves **its**
tenant. That is what leaves `cross` as the way to reach another one: a signature
taking a bare tenant id cannot tell *mine* from *somebody else's*, so it serves
both and the difference lives in whether the handler remembered which to pass.
The narrow claim worth making is that no path reaches another tenant's plane by
accident, because none can name one — not that a cross-tenant read is
impossible, since an embedder writing its own `Authenticator` decides what a
credential means and can mint a `Caller` for any tenant. That seam is where a
deployment defines identity; it is a deliberate act rather than a forgotten step.

This used to be two calls — `record_break_glass`, then reach for the plane —
and nothing enforced the order. `record_break_glass` remains for an embedder
recording a crossing they made some other way; `cross` is what an admin surface
should use.

Same-tenant crossings are refused, because recording routine access as
break-glass buries the real ones. A tenant this process does not serve is
refused rather than defaulted, exactly as the ordinary gate refuses one.

The crossing seals like any other run, so it enters the Merkle log, verifies
offline, and lists with the rest:

```sh
curl -H "$AUTH" 'https://plane/runs?outcome=broke-glass'
```

Who may pull it is your policy engine's decision, not this crate's.

### One matter, one scan

*Show me everything about this matter* is the question a regulated deployment
asks, and there are two ways to answer it. Listing the case's runs and reading
each is a join whose cost grows with the case's life — and it **misses** every
record written by a run the case does not own.

A sweep is exactly that run. One tick may escalate several cases and belongs to
none of them, so a per-run walk never reaches the record explaining why a case
was escalated — which is the only reason for writing it down.

So the journal carries the case on the record and indexes it:

```rust
let history = store.case_history(case, 200).await?;
```

One range scan, tenant-first like every other key here, so a query that forgets
the predicate returns nothing rather than another customer's matter. Both
backends are held to it by the same conformance battery, which checks the two
halves separately — that the scan finds this matter's records, *and* that it
returns no other's. Either alone passes for the wrong reason: a scan returning
nothing satisfies the second, and one returning everything satisfies the first.

`GET /cases/{id}` includes it, with `history_truncated` when the bound bit,
because a shortened list is shaped exactly like a complete one.

### The sweep writes its own history

The sweeper makes the plane's most consequential *automated* decisions: it
breaches an obligation, escalates a case, expires a person's task. Nothing asked
it to — that is the point of it — so there is no run whose history explains why
the state changed.

Without a record, *why is this case escalated* is answerable only from the
resulting state, and state cannot distinguish **the sweep breached this at
02:00** from **somebody set it**. No human was present to remember which.

So a tick that decides anything writes its decisions into a **sealed run of its
own**: `Swept { subject, action, detail }`, one per action, with a typed action
rather than a message. It inherits the chain, the per-record signature and the
Merkle inclusion every other run has, so the external audit tool checks it
without being taught what a sweep is.

```rust
let report = plane.sweep(now, grace).await?;
if let Some(run) = report.record {
    // Exactly what this tick decided, verifiable like any other run.
    let entries = store.read(run, 1).await?;
}
```

**A quiet tick writes nothing.** A healthy plane sweeps constantly, and a Merkle
log filling with evidence of inactivity is where the somethings hide.

Two things are deliberately *not* in it, and both are worth knowing. Dead-lettered
events are counted rather than named, because the event store reports how many
aged out and not which — they stay in the report and the emitted event, and
there is deliberately no `SweptAction` for them, because a variant nobody
constructs reads as a capability. And a sweep run is not a *plan*: it is sealed
with the outcome `swept` rather than a run status, because a tick that breached
forty obligations is not a plan that completed.

### A capped tick says it was capped

Each sweep takes a bounded batch — 128 timers, 512 obligations, 512 expired
tasks — so one tick is bounded. A sweeper still working through a backlog is a
sweeper not noticing the *next* obligation, which is the failure the whole
mechanism exists against.

The hazard is that a bounded query returns a list shaped exactly like a complete
one. A tick that handled its cap and a tick that handled everything produce the
same counters, and they are the two states most worth telling apart: the first
means the backlog is growing while the report looks ordinary.

So `SweepReport::saturated` names which sweeps came back full, and
`needs_attention()` is true when any did. A saturated tick means *at least* the
cap was waiting — never that the cap was all there was.

```rust
let report = plane.sweep(now, grace).await?;
if report.saturated.deadlines {
    // More obligations were outstanding than one tick will take.
    // Sweep more often, or find out why they are accumulating.
}
```

## Metrics

### The runtime does not measure durations

Ambient clocks are lint-denied with three named escapes, each for a value that
gets journaled or is store metadata. A fourth escape *for instrumentation* would
end the rule, because timing is the most plausible-sounding reason anyone reaches
for a clock. And a replayed run would re-measure durations belonging to calls it
never made, so "effect latency by driver" would average network time with journal
reads — the failure `agentplane.effect.replayed` exists to prevent, arriving
through the metrics door.

Durations are therefore derived from spans, by the collector. The spans carry the
mode and the replay flag, so a collector can compute latency *and* exclude
replays, which an in-crate histogram could not.

### Counters are emitted; gauges are observed

"Open cases" cannot be an increment-on-open, decrement-on-close counter. A crash
between the state change and the emission loses a decrement permanently, and the
dashboard slowly invents open cases that do not exist — *plausibly*, which is
worse than obviously.

So gauges come from a census query against the store, and the sweeper emits them:
it already runs periodically and already takes its `now` as a parameter, so no
clock is read. The census is also the only consumer of a case's `opened_at`, and
the reason that column exists — a count cannot distinguish ten cases open for an
hour from ten open for a month.

A gauge must never be read from a `limit`-bounded query. That is why `census`
exists rather than `by_status(..).len()`: a paged count rises, flattens at the
page size, and looks like a plateau exactly when it has become a backlog.

### Two rules, both guarded

**A dimension is a variant, never a rendered message.** `Display` on a budget
error embeds the allowed and used figures; a label carrying those is one time
series per distinct budget, which is how a metrics backend falls over. Every
dimension comes from an `as_str()` accessor.

**The catalogue is not a wish list.** A declared-but-unemitted event leaves an
empty panel, which at least looks wrong. A declared-but-unemitted *counter* reads
as a hard zero — indistinguishable from "this never happens" — so an operator
concludes the system is healthy from a number nobody wired up.
`tests/guards/layering.rs` fails the build if a catalogue entry has no emitter.

## Observability

`tracing` spans and events, so the runtime is usable by any subscriber — OTel,
JSON logs, a test recorder — without the crate choosing an exporter.

```
agentplane.run                     gen_ai.operation.name = invoke_agent
└── agentplane.step                agentplane.step.id, .capability, .phase
    └── agentplane.effect          .kind, .attempt, .mutates, .replayed
                                   gen_ai.operation.name = execute_tool | chat
```

Spans follow the **OpenTelemetry GenAI semantic conventions** where they apply:
a tool call is `execute_tool`, a completion is `chat`. Each effect *declares* its
own operation rather than having one inferred from its name, so a new effect
type cannot pick up a label by accident.

Effects that are not GenAI operations — reading the clock, arming a timer,
writing case state — carry no such attribute at all. That is deliberate:
labelling them would make the attribute useless to the tooling that keys on it,
which is the whole reason to emit it.

The conventions are still pre-1.0, so the revision targeted is pinned in
`telemetry::SEMCONV_VERSION` rather than tracked. An upstream change becomes a
deliberate migration instead of a silent shift in what your dashboards mean.

Three further decisions worth knowing:

- **One span per effect *attempt*.** A retried call shows as several spans rather
  than one long one, which is what makes "how often does this driver need a
  second try" answerable.
- **Replay is marked on every span.** A replayed run re-executes its skills and
  emits spans again. An effect served from the journal is reported as an event
  with `replayed = true`, never as an effect span — otherwise "effect latency by
  driver" averages real calls with journal reads.
- **Spans attach to futures, never to threads.** `Span::enter` returns a guard
  bound to the current thread; held across an `.await` it stays entered while the
  future is suspended, so whatever runs next is attributed to it. With concurrent
  siblings that silently reparents their work. `Instrument` is the only form that
  survives a suspension, and `tests/guards/layering.rs` bans the guard in async code.
- **The vocabulary lives in `runtime::telemetry`.** A span name typed inline at
  twelve call sites is twelve chances to drift, and telemetry drift is invisible:
  the dashboard stops matching and nobody is told.

Every failure P7 exists to surface has its own event target:

| Event | Fires when |
|---|---|
| `agentplane.run.nondeterminism_detected` | Replay recomputed a different effect key |
| `agentplane.run.quarantined` | A run was set aside for a human |
| `agentplane.effect.undecidable` | An outcome could not be determined and guessing was forbidden |
| `agentplane.effect.reconciled` | A probe was asked whether a call landed |
| `agentplane.budget.refused` | A limit refused an operation |
| `agentplane.saga.compensated` | A completed step was undone |
| `agentplane.saga.compensation_failed` | A compensation failed, leaving the run partly unwound |
| `agentplane.event.dead_lettered` | An event aged out with nobody waiting — a correlation bug |
| `agentplane.deadline.breached` | An obligation passed unmet |
| `agentplane.timer.fired` | A sleeping run's instant arrived |

`tests/guards/layering.rs` fails the build if any of those has no emitter, and
`tests/process/telemetry.rs` asserts on what a subscriber actually received rather than
on what the source contains — an instrumentation test that greps is checking the
author's intent, not the runtime's behaviour.

## The operator surface

Feature `http`, off by default. A library embedded in someone else's process
should not open a port unless asked.

### Identity comes from the request, never from its body

This is the whole design, and everything else in the module follows from it.

Four-eyes is enforced in `TaskStore::claim`, which takes an actor and a set of
roles. In-process both come from the embedder's own code, which is trusted. Over
HTTP they would come from whoever is on the socket — and a reviewer who can name
themselves can name the person who proposed the action. That is not a bypass of
the control; it *is* the control, inverted.

Discipline does not hold that. So the wire type has no field to hold it:

```rust
pub struct DecisionRequest {   // no `actor`. no `roles`.
    pub approved: bool,
    pub reason: String,
    pub amendment: Value,
}
```

The handler builds the `Decision` from the authenticated `Caller`, because there
is no other source available to it. A later maintainer cannot be talked into
reading the body's actor, since there is nothing to read.

`deny_unknown_fields` is the other half. Without it, a body carrying
`"actor": "alice"` is accepted and silently ignored — the integrator who wrote it
believes they decided as Alice, the journal says Bob, and the disagreement
surfaces at an audit months later. A `422` says so at the first call instead.

### Two gates, and the surface will not start without the second

Authentication says *who*; it does not say *what they may do*. An operator
surface that stops there hands every authenticated caller the whole plane. So
every route runs `gate()`, which authenticates, resolves the caller's tenant to
a plane, and then authorizes through **that plane's** `PolicyEngine` under an
`api:` action — and `Api::new` returns an error if any registered plane has
none, or if none was registered at all.

That refusal is deliberate. In-process an absent engine is a choice; on a socket
it is a hole, and a permissive default is one nobody discovers until the port is
reachable. `DenyAll` exists for wiring the surface up before the rules are
written. One ungoverned tenant among governed ones is the one an attacker looks
for, which is why the check is over every plane rather than the first.

### Checking a driver against the real thing

`just test-live` exercises the OpenAI and Gemini drivers against the actual
APIs, loading keys from `.env`. Each provider's battery skips on its own key, so
one key runs one battery and the rest say so. It is gated twice — `AGENTPLANE_LIVE=1` **and** the key — and is
never part of `just ci`: a developer with `OPENAI_API_KEY` exported would
otherwise be billed for running the test suite, and would find out at the end of
the month.

Worth having because a stubbed provider cannot have the defects a real one finds.
It accepts any request shape and returns whatever it is told to, so a driver that
sends a malformed body, or mis-reads a response, passes every offline test. Both
bugs these found were of exactly that kind: a tool declaration in the wrong shape
for the API being called, and a tool call read as an empty answer.

### Putting a tenant on your metrics

Off by default, and the default is the interesting part. A tenant name is
frequently a customer name, and a metrics backend is usually the least protected
system in a deployment: sampled into third-party services, on a dashboard nobody
signs into, retained past every other record. A deployment that has not decided
where its metrics go has not decided that customer names may travel there.

```rust
.metric_tenant(TenantLabel::Name)
```

**Cardinality is bounded by configuration, not by data.** The label is *this
plane's* tenant, so the number of streams is the number of planes you wired.
There is no request that can grow it — a tenant read from a request would be
exactly the unbounded label that makes a metrics backend fall over.

There is deliberately **no pseudonymous option**. Hashing the name here would
cover one of the many places a tenant already appears — store keys, blob paths,
the policy request, the checkpoint origin published to witnesses, and the
`tenant` field on an Agent Card served unauthenticated at a well-known path. A
control that covers one exit and not the other nine is worse than none, because
it invites the belief that the name is contained.

If customer names must not leak, **do not put them in the tenant id**.
`TenantId::new("t-9f3a")` covers every one of those places at once, costs no
code, and cannot fall out of step with a surface added later.

### Per-tenant ceilings

Budgets bound one run. They do not bound a tenant: a caller that can start runs
can start a thousand, each perfectly within its own ceiling, and the compute and
the model bill are somebody else's problem. `RuntimeBuilder::quota` sets a
tenant's limits and points at the store that accounts them.

```rust
.quota(store.clone() as Arc<dyn QuotaStore>, TenantQuota {
    max_concurrent_runs: Some(50),
    max_tokens_per_period: Some(20_000_000),
    period: Period::Monthly,
    ..Default::default()
})
```

**The accounting is durable, and that is the whole point.** An in-process
counter is a ceiling that vanishes the moment a second instance starts — and it
fails *open*, silently doubling when somebody scales out, which is exactly when
it was needed. The reservation is one transaction that counts and inserts, so
two instances racing for the last slot serialise and one loses.

What each ceiling bounds, stated precisely, because a limit believed to bound
something it does not is worse than none:

**Concurrency** bounds runs *executing*. A slot is taken at admission and given
back when the instance finishes with the run — including when it **suspends**, since
a suspended run costs a row and not a thread, and holding its slot would mean a
tenant waiting on a hundred approvals could start nothing. It follows that a
resume is not gated: that work was admitted already, and refusing it would
strand a run waiting on something that has now happened.

**Spend** bounds a period and is checked at admission, against what has been
*accrued* — and a run accrues when it finishes. A run already executing when the
ceiling is crossed therefore runs to completion, so the overshoot is at most the
concurrency ceiling times the per-run budget.

Both of those are yours to set, and the second one has a default worth knowing:
`RuntimeBuilder` starts at `Budget::unlimited()`. A deployment that sets a tenant
ceiling and no per-run budget has bounded *nothing* — the product has an
unbounded factor in it. A declarative agent cannot make that mistake, because a
manifest without `budgets` fails validation rather than defaulting; a Rust
deployment has to decide the same thing deliberately.

A refusal is `RuntimeError::QuotaExceeded`, deliberately not a policy denial: a
denial means *you may not* and retrying is pointless; a ceiling means *not right
now*. Over A2A it comes back as `-32004` rather than an internal error, so a
peer backs off instead of retrying a "fault" immediately.

Two failure choices worth knowing. An unreachable quota store **refuses** rather
than admits — a ceiling that yields when its accounting is down is one an
attacker removes by taking the accounting down. And concurrency is tracked as a
*set of runs*, not a counter, so a process that dies mid-run strands a slot an
operator can name and release, rather than a number nobody can audit.

### One surface, many tenants

`Api::new` takes `Planes`, a registry keyed by tenant, so one process can serve
several — a single-tenant deployment passes its runtime and reads as before.
Which plane answers comes from the caller's tenant, which the `Authenticator`
derives from the credential exactly as it derives `actor` and `roles`.

The gate hands each route its resolved plane, and `Api` holds no runtime of its
own, so a handler cannot read a store without having established whose it is. A
caller whose tenant has no plane is refused rather than served by a default: a
fallback would turn an unregistered tenant into somebody else's data while
looking like working software.

The gate runs *before* the path is parsed, so a denied caller cannot learn
whether a run id exists by comparing a `400` against a `404`.

### What the endpoints are for

| Route | The question it answers |
|---|---|
| `GET /runs?outcome=…` | What ended this way and has not been cleared? Newest first; defaults to `quarantined` |
| `GET /runs/{run}` | What is this run doing, and **why is it not finishing**? |
| `GET /tasks` | What is waiting for me? |
| `GET /tasks/{task}` | What is this proposal, and may I decide it? |
| `POST /tasks/{task}/claim` | This one is mine — don't let a colleague duplicate it |
| `POST /tasks/{task}/release` | It isn't mine after all; give it back |
| `POST /tasks/{task}/decide` | Approve or reject, as myself |
| `GET /cases?status=…` | What is escalated and has not been cleared? Newest first; defaults to `escalated` |
| `GET /cases/{case}` | What has happened on this matter, and by when must it end? |
| `POST /runs/{run}/cancel` | Stop it — `202`, because the run stops at its next boundary |
| `POST /events` | This message arrived; wake whoever wanted it |

Two details carry more weight than the plumbing:

**A suspended run says what it is waiting for.** "Suspended" tells an operator a
run is stuck; it does not tell them whether to approve something, chase a
counterparty, or page somebody. The `SuspendReason` is on the record, so it costs
nothing to answer properly.

That status is read from the run's **last** record, not from whether a
suspension appears anywhere in its history. Every run that has ever waited for a
human has a `RunSuspended` in it, forever — scanning would report every completed
approval flow as permanently stuck, which is worse than reporting nothing.

**The worklist says when it was cut off.** The response is an object, not a
bare array, because an array cannot express it: a queue of 140 items paged at
100 returns 100 and reads exactly like a queue of 100. The flag comes from
asking the store for one more than the page and dropping it — inferring it from
`len() == limit` would cry wolf on every queue of exactly `limit`.

**Each worklist item says whether *this* caller may decide it.** A reviewer
barred by four-eyes still sees the task — hiding it leaves them wondering where
it went — and is told on the item rather than by a refusal after they have read
the case and made up their mind. The flag calls `Task::may_decide`, the same
predicate the store enforces, rather than re-implementing it: a second copy of an
authorization rule drifts, and the copy that drifts is the one people read.

### No authenticator is shipped

Same reasoning as the policy engine and the tracing exporter. `Authenticator` is
handed the whole header map, because a deployment may authenticate by bearer
token, mutual TLS, or a signed header from a gateway, and a parser baked in here
would be wrong for one and load-bearing for the other.

### Claiming is what stops duplicated work

`decide` alone makes the queue first-past-the-post at *decision* time: two
reviewers read the same case in parallel and one of them discovers, at the moment
they submit, that the work was wasted. `claim` reserves; `release` gives it back,
and it is `release` that makes `claim` safe to use — without it, a reviewer who
claims something they then cannot decide has parked it until somebody edits the
database, so the queue learns not to claim and the reservation stops meaning
anything.

Claiming is not advisory. `TaskStore::claim` runs four-eyes and role eligibility
in the same transaction that reserves, so an ineligible reviewer is refused
*before* they read the case rather than after they have made up their mind.

#### Eligibility outranks availability

Writing the handler forced a question the in-process API never had to answer:
what status code does a refused claim get? `403` and `409` ask different things
of the reader — *this will never be yours* versus *try again, or ask Bob* — and
that made the store's ordering visible. Both backends checked availability first,
so a barred reviewer asking for a held task was told "held by Bob". They wait for
Bob to release it, ask again, and are refused for a reason nobody has yet
mentioned; and meanwhile they have learnt who is reviewing what, from a queue
they have no standing in.

The order is now part of the `TaskStore` contract, and the conformance battery
holds both backends to it:

```
NotFound → Excluded → WrongRole → NotPending → AlreadyClaimed
```

The permanent refusal wins over the transient one, because the transient one
hides it.

The same battery run then caught a second defect, in Postgres only: `release`
had the right `WHERE` clause and **discarded the row count**, so a release by
somebody who did not hold the task returned `Ok(())`. The caller is told the task
is free; the holder still has it. That is the exact failure mode the shared
contract exists to catch — a second backend gets whatever tests its author
remembered to write, and those are the ones they were already thinking about.
Releasing now reports `ClaimError::NotHeld`, which is deliberately not
`NotFound`: "the id is wrong" and "it is not yours" call for different responses.

### The second thing building it found

Two runs of one plan shared one human task.

`TaskId` was derived from the awaiting effect's key. An `EffectKey` is unique
*within a run* — the journal enforces `(run, effect_key)` and needs nothing more
— but the worklist is a table shared by every run, and two runs of one plan reach
the same step, at the same ordinal, with the same descriptor, and derive the same
key. `TaskStore::open` is idempotent by id, so the second run's task was silently
**not created**. One proposal appeared, carrying the first run's amount; an
operator decided it; the second run went on waiting for an answer nobody would
ever be shown. Two €900 refunds became one €100 approval, and nothing anywhere
reported a problem.

It surfaced while writing a test that needed three tasks in one queue and could
only produce one.

The rule it encodes: **an effect key is unique within its run; anything that
escapes into a shared namespace has to mix the run back in.** `TaskId::derive`
now hashes both, and the field is private, so the collision is unrepresentable
rather than merely fixed. The `("task", …)` correlation key inherits the fix,
since it is derived from the id.

Worth noting *why* no test caught it: every task test ran one run. A one-run
fixture cannot express a two-run collision, and the shape was shared by all of
them — the same failure named in the retrospective as "one test shape hiding a
class of bug".

### What building it found

Writing the first handler failed to compile, and the reason was not in the
handler: `Runtime`'s futures were not `Send`. One field did it — a bare
`&dyn Fn(Append) -> Append` in the executor, which is neither `Send` nor `Sync`
unless it says so, and which infected every future that touched it.

Nothing in the crate had noticed, because nothing needed to: a single-threaded
`#[tokio::test]` awaits futures in place. An embedder calling `tokio::spawn`
would have hit it immediately, as a page of trait error naming a private type
they cannot see. `tests/guards/layering.rs` now holds it at both ends — a compile-time
assertion that every public runtime future is `Send`, and a scan that fails any
bare `dyn Fn` field in `src/runtime/`.

## 🗄️ Retention and erasure

A full-fidelity journal is simultaneously an asset and a GDPR liability, and
**this is currently your problem to solve, not the runtime's.**

What exists today:

- **The journal keeps everything, indefinitely.** It is append-only and
  hash-chained: nothing in it can be edited or removed without invalidating
  every record after it. That is the property Article 12 wants and precisely the
  property an erasure request does not.
- **A record over 1 MiB is refused** rather than written, so bulk content is
  pushed out of the chain by construction. Bytes that big belong in the
  content-addressed blob store, with only the digest journaled — see
  [the cookbook](@/docs/cookbook.md). Deleting a blob is then a filesystem or bucket
  operation, and the chain still verifies afterwards because it only ever
  committed to the digest.

- **Blob bytes can be erased, and the erasure is recorded.** `BlobStore::expire`
  drops the content and leaves a tombstone. A reader afterwards gets `Expired`
  with the date and the reason — not `NotFound` — because "retention did its job"
  and "data is missing and nobody knows why" are different answers and only one
  of them is an incident. Expiring twice keeps the first tombstone, so a retry
  cannot rewrite when the data went.

**On scheduling, and why there is no TTL here.** Every object store this runs on
already expires objects far better than a sweeper could — S3 lifecycle rules,
GCS object lifecycle, Azure blob lifecycle — and they run without your process
being alive. Reimplementing that would be a worse copy of a solved problem.

The catch is worth knowing before you rely on it: **a lifecycle rule deletes,
it does not tombstone.** A blob removed that way reads as `NotFound`, and the
distinction between "retention did its job" and "data is missing and nobody
knows why" is gone. So use lifecycle rules for bulk age-based expiry where that
distinction does not matter, and call `expire` explicitly for erasure requests,
where being able to say *when and why* is the entire point.

**The erasure unit is the case**, which is the only unit anybody actually names —
nobody asks to forget a digest. Write bytes through `cx.store_blob`, which
records the link at the one moment it is knowable (a digest cannot be reversed to
find its case), and answer a request with one call:

```rust
let n = agentplane::blob::erase_case(
    blobs.as_ref(), cases.as_ref(), case, now, "art-17 request",
).await?;
```

Every blob that case produced is tombstoned with the same reason. Other cases
are untouched — including ones that stored *identical bytes*, which land on the
same digest by construction, so the link is what scopes the erasure rather than
the content.

**What still cannot be erased** is anything written into a journal *record*. The
chain is append-only by design; keep personal data out of records rather than
expecting erasure to reach it. The 1 MiB refusal pushes bulk content out by
construction, but a short string still fits. Personal data that
reached a journal *record* rather than a blob also cannot be removed: the chain
is append-only, which is the point. Keep it out of records — the 1 MiB refusal
pushes bulk content out by construction, but a short string still fits.
[Regulation](@/docs/regulation.md) says the same in the obligations' own terms.

## 🚑 Runbook

| Symptom | Where to look |
|---|---|
| A run is `Quarantined` | It holds an effect whose outcome is unknown, or replay diverged. The record names the step. It will not be unwound automatically, and that is deliberate — reversing everything *except* the thing nobody can account for is worse than stopping |
| A run seems stuck | It is almost certainly suspended on an event, a timer, or a human. `GET /runs/{id}` reports *why* rather than only *that* |
| An event was dead-lettered | Nothing was waiting for it, and the grace window elapsed. The reason is on the record — usually a correlation key that does not match what the run subscribed to |
| Budget exhausted | A ceiling doing its job, not a fault. The status carries the limit **and** where consumption actually reached, so it says what to raise it to |
| `LeaseHeld` vs `Fenced` | Opposite responses. `LeaseHeld` means another instance is alive and you should wait; `Fenced` means this writer is stale and must drop the run, never retry |
