+++
title = "Testing agents"
description = "A fake provider, deterministic fault injection, a store conformance battery, and the assertion that proves replay actually replayed."
weight = 7

[extra]
group = "Build"
+++

Most agent frameworks are hard to test for one reason: the interesting behaviour
is downstream of a model, and a model is neither cheap nor deterministic. So
tests either call one for real — slow, costly, flaky — or mock it so thoroughly
that they stop testing the runtime.

This crate is testable for a structural reason rather than a tooling one. Every
nondeterministic thing is an **effect**, effects are journaled, and replay reads
them back. That means a test can drive a whole agent with no key, no network and
no clock, and still exercise the real path — because there is only one path.

Everything here is behind the `testkit` feature, which is off by default and
should never be in a production build.

```sh
cargo add --dev agentplane --features redb,testkit,manifest
cargo add --dev tokio --features macros,rt-multi-thread
```

## The golden run

`FakeProvider` answers model calls from a script. It is deterministic by
construction, **never reports a call as free**, and refuses to answer as a real
provider — so a journal it produced can never be mistaken for a genuine one.

Three things to know:

**`FakeProvider::new()` returns `Arc<Self>` already.** Wrapping it again gives
`Arc<Arc<FakeProvider>>`, whose error reads as though the type does not
implement `ModelProvider`. Pass `Arc::clone(&provider) as Arc<dyn ModelProvider>`.

**`will_say` sets the completion's *text*.** Against an agent declaring
`output.schema`, the fake parses that text and validates it, answering
`Unusable` for prose — the same as a real driver. Give `will_say` the JSON
document, or use `will_answer` with `structured` set.

**It makes the refusals a real driver makes before sending**, so an agent that
could not be asked for fails here rather than on its first real call — including
a schema outside [the subset constrained decoding accepts](@/docs/manifest.md#spec-output).
`provider.without_constrained_decoding()` opts out for a deployment on a provider
that genuinely accepts more.

```rust,ignore
use agentplane::testkit::FakeProvider;
use agentplane::runtime::{Mode, RunStatus, Runtime};

#[tokio::test]
async fn the_agent_answers_and_replays_without_asking_again() {
    let provider = FakeProvider::new();
    provider.will_call_tool("call_1", "ledger__read", json!({ "account": "AC-1" }));
    provider.will_say("AC-1 holds 42.");

    let store = Arc::new(RedbStore::open_in_memory()?);
    let rt = Runtime::builder(Arc::clone(&store) as Arc<dyn JournalStore>)
        .provider("fake", Arc::clone(&provider) as Arc<dyn ModelProvider>)
        .agent(Agent::new(&manifest))
        .toolbox(ToolBox::new().with::<ReadBalance>())
        .build();

    let out = rt.run("ledger.ask", Tainted::trusted(json!({ "question": "what is in AC-1?" }))).await?;
    assert_eq!(out.status, RunStatus::Succeeded);

    // The claim worth testing, and the one most runtimes cannot make.
    let before = provider.calls();
    let replayed = rt.replay(out.run_id, Mode::Strict).await?;
    assert_eq!(replayed.output, out.output);
    assert_eq!(provider.calls(), before, "strict replay asked the model again");
}
```

That last assertion is the whole point. It is not "the output is stable"; it is
**the model was not consulted** and the answer still came out identical.

### Asserting what the model was actually shown

`provider.asked()` returns an `Ask` per call, which carries the assembled prompt,
the schema, and — the field that matters most — the exact tool surface offered
that turn, plus what this turn was told about the last turn's tool calls.

```rust,ignore
let asked = provider.asked();

// The prompt is assembled from the manifest, so this pins the declaration.
assert_eq!(asked[0].prompt["system"], expected_system_prompt);

// The model was offered exactly the manifest's grants, with the schema derived
// from the Rust argument type — not a permissive `{ type: object }`.
let read = asked[0].tools.iter().find(|t| t.name == "ledger__read").unwrap();
assert_eq!(read.parameters["properties"]["account"]["type"], "string");

// What the *next* turn was told about a refusal. This is the only place a
// refusal reaches a model, and asserting it here is different from asserting
// that the refusal formatter is uniform: one proves the function, the other
// proves the runtime uses it.
assert_eq!(asked[1].exchanges[0].output, "the request was not permitted");
```

The `exchanges` field exists because of a real defect. A tool-calling loop was
handing the model the *precise* policy denial — an oracle a prober could map the
authorization vocabulary with — and every test passed, because they all called
the uniform-refusal formatter directly and asserted it was uniform. Nothing
asserted what the next turn was told.

## Deterministic fault injection

`Faulty` wraps any `JournalStore` and fails on a **schedule**, which is a seed
rather than a probability. A failing schedule is therefore a number that
reproduces forever.

```rust,ignore
use agentplane::testkit::{Fault, Faulty, Schedule};

let store = Faulty::new(inner, Schedule::default().at(7, Fault::CommittedThenLost));
```

Three faults, and the middle one is why the module exists:

| | |
|---|---|
| `FailedClean` | the call failed and nothing was written — the benign case, present so a test can tell *handled it* from *never saw one* |
| `CommittedThenLost` | the write **committed** and the caller got an error |
| `Fenced` | the call failed after another instance took the lease |

`CommittedThenLost` is unreachable by the usual technique of truncating a journal
at every prefix, because **a truncation is always clean**. It cannot produce the
state where a write committed and the writer never found out: connection lost
after commit, the process killed between `COMMIT` and the syscall returning, a
proxy timing out a request the database went on to apply. That is the store-level
twin of an in-doubt effect, and a runtime that responds by retrying the append
puts two records at one position in history.

## The assertion that proves replay replayed

Exactly-once is enforced **twice** here on purpose: replay reads a completed
effect back from the journal instead of performing it, and beneath that the store
holds a unique index rejecting a second `EffectStarted` for one key.

That redundancy is good engineering and poison for tests. Delete the entire
replay read-back and the world *still* contains no duplicate — the
re-announcement is rejected one layer down. Every outcome-shaped assertion still
passes: the world has one entry, the chain still verifies, the run "failed" in a
way a permissive test accepts.

```rust,ignore
use agentplane::testkit::assert_replay_was_not_backstopped;

let outcome = rt.replay(run_id, Mode::Resume).await;
assert_replay_was_not_backstopped("crash at record 7", &outcome);
```

The general rule, which is not specific to this crate: **a property enforced at
more than one layer cannot be tested by observing the outcome**, because the
outer layer masks every inner failure. The test has to assert *which layer held*.

## Holding your own store to the contract

If you implement `JournalStore` — for a database this crate does not ship —
`check_journal_store` is the same battery both built-in backends pass, including
a racing check no sequential test can replace.

```rust,ignore
use agentplane::testkit::check_journal_store;

let report = check_journal_store(|| my_store()).await;
assert!(report.violations.is_empty(), "{report:#?}");
```

There are matching batteries for the case layer, the quota store, the registry,
the push store, the key ring, **blob storage**, **the calendar** and **the
policy engine**. They exist as shipped code rather than as this crate's private
tests for one reason: rebuilding a conformance suite per project is how each one
ends up checking a slightly different, slightly weaker thing.

**Run them against the handle you actually hold, not the one underneath it.** A
decorator is a store in its own right — wire a key ring and the runtime is given
`SealedCases`, not your case store — and it re-implements the whole trait by
forwarding. Forwarding is where a contract goes wrong, and none of it is visible
from above, because the wrapper answers the same signatures.

The blob battery has two entry points, and the split is worth knowing before
you write a store:

```rust
use agentplane::testkit::conformance::Report;
use agentplane::testkit::conformance_blob;

let mut report = Report::default();
conformance_blob::check(&store, "mine", &mut report).await;
// …and this one only if something may seal *onto* your store:
conformance_blob::check_backing(&store, "mine", &mut report).await;
report.assert_conforms("MyBlobs");
```

`put_at` and `get_raw` are the **envelope pair** — bytes deliberately stored at
an address they do not hash to, read back without the verification that would
reject them. They belong to a backing store; a sealing decorator refuses both
on purpose, because exposing them through it is an unsealed side door. So a
store that refuses the pair is not incomplete, and a battery demanding it of
everything would fail the one implementation whose refusal is the guarantee.

The calendar battery matters for the same reason in sharper form: a real
deadline forces you to replace that seam — working days in a named timezone
with a holiday table do not belong in a domain-agnostic engine — and the instant
your replacement returns is binding and unreviewable from above. It checks that
resolution is pure, that a rule the calendar does not implement is refused
rather than approximated, that the digest identifies the ruleset, and that a
count at the edge of its type is an error rather than an abort. The hostile
counts are **derived** from the specs you declare supported, so you cannot hand
the battery the inputs your code already handles.

The **policy battery** checks the three things `PolicyEngine` asks for that no
signature can express — total, pure, no I/O — plus the two that make a journaled
verdict re-derivable:

```rust
use agentplane::testkit::conformance::Report;
use agentplane::testkit::conformance_policy;

let mut report = Report::default();
conformance_policy::check(&my_engine, &mut report);
report.assert_conforms("MyEngine");
```

It answers every request shape the runtime issues plus hostile ones — empty
fields, a context that is not an object, rule-language metacharacters — and
requires the same answer twice, the same answer regardless of what was evaluated
before it, a refusal that names a rule rather than an empty string, a bundle
identity that does not move between calls, and a `digest` that is the bundle's.
What it cannot tell you is whether your rules are **right**: an engine that
permits everything passes every check in it.


The blob rule that is least obvious — an expired address stays expired — is
argued where its reader is, on [erasure](@/docs/erasure.md#an-expired-address-stays-expired).

## Holding your own authenticator to the contract

The **authenticator battery** is the one for a seam this crate ships no
implementation of, because it cannot: establishing who is calling is your
identity provider's job, and the surface believes whatever `authenticate`
returns.

```rust
use agentplane::testkit::conformance::Report;
use agentplane::testkit::{conformance_auth, conformance_auth::Requests};

let mut report = Report::default();
let requests = Requests {
    accepted: Some((bearer("a-token-you-issue"), "alice@example.com".into())),
    rejected: vec![("expired", bearer(&expired)), ("wrong audience", bearer(&other))],
};
conformance_auth::check(&my_auth, &requests, &mut report).await;
report.assert_conforms("MyAuth");
```

You supply the requests because only you know what a credential looks like —
the trait takes a whole `HeaderMap` so a bearer token, a mutual-TLS header and a
gateway assertion are all expressible. It checks that an empty request is
`Missing` rather than an anonymous caller, that your own examples of bad
credentials come back `Rejected`, and that the accepted one names the actor you
say it should.

The rule worth knowing before you write one: **`Rejected` and `Missing` are
different answers**. `Missing` means *there was nothing here I can use* — no
header, or a scheme this server does not speak. A credential you looked at and
refused is `Rejected`, whatever was wrong with it. Answering `Missing` for it
tells whoever is probing that the token was at least the right shape, which is
the one thing a refusal is not supposed to say. Neither variant carries a
reason, and that is deliberate: expired, unknown signer and wrong audience are
one sentence to a caller.

## Testing a policy against the *real* context

A Cedar policy is only as good as the attributes it reads, and a policy tested
against a context the test invented is a policy tested against itself. This bit
for real: a taint gate in this repository keyed on `context.args_trust`, which
the runtime has never sent. Cedar is **total**, so a `when` clause reading a
missing attribute does not raise — the rule is simply unsatisfied, the `forbid`
never matched, and the gate failed **open** while every assertion passed.

So drive policy tests through a run, or build the context from what
[the security model](@/docs/security.md#the-authorization-context) documents —
never from what the rule happens to need.

## What is deliberately not here

**No mock runtime.** There is one execution path, and a test that took a
different one would be testing something else. `FakeProvider` replaces the
*provider*, which is a real seam; nothing replaces the executor.

**No time mocking.** The clock is already an effect. `cx.now()` returns a
journaled instant, so a test asserts on the recorded value rather than freezing a
global.

**No snapshot assertions over the journal.** Records carry ULIDs and hashes, so a
golden file would need scrubbing, and a scrubbed snapshot stops detecting the
things worth detecting. Assert on the effect *sequence* and on what the world saw.
