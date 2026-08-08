+++
title = "Upgrading"
description = "What breaks between pre-alpha releases, why, and the shortest correct fix for each."
weight = 11
+++

Pre-alpha means hard cuts rather than deprecation cycles, and a manifest or a
call site that stops working is the intended way to find out. What this page owes
you is the *reason* and the shortest correct fix — a refusal you have to reverse
engineer costs an afternoon, which is one afternoon more than the change saved.

Every entry here is a **parse-time or build-time** refusal. None of them changes
what a running agent does silently, which is the property that makes a hard cut
acceptable at this stage.

---

## Admission takes a label, not a bare value

`Runtime::run` and its siblings took a `serde_json::Value` and admitted it as
**`Trusted`**. That is right for a literal an operator wrote and silently wrong
for a plane whose runs are started by inbound events.

```rust
// before
rt.run("claim.assess", json!({ "id": "CLM-9" })).await?;

// after — the operator's own literal, vouched for
rt.run("claim.assess", Tainted::trusted(json!({ "id": "CLM-9" }))).await?;

// after — a payload that arrived from outside, kept honest
rt.run("claim.assess", inbound).await?;
```

**Why it is worth your call sites.** A deployment whose runs came from inbound
events passed counterparty data straight in, and three controls went quiet at
once: `require_trusted` protected fields were satisfied by attacker-chosen
values, the egress ceiling had nothing untrusted to join with, and the journal
recorded no contact with outside data. Nothing failed and its suite stayed green.

The renames that came with it, because the old names were a trap of their own:

| before | after |
|---|---|
| `run(target, Value)` | `run(target, Tainted<Value>)` |
| `run_tainted(..)` | *gone* — `run` is the tainted door |
| `run_in_case(target, .., kind, keys)` — **correlated** | `run_correlated(..)` |
| `run_tainted_in_case(target, .., CaseId)` | `run_in_case(..)` — *this exact case* |
| `run_tainted_correlated(..)` | `run_correlated(..)` |
| `run_plan(plan, Value)` | `run_plan(plan, Tainted<Value>)` |
| `run_plan_in_case(..)` | `run_plan_correlated(..)` |
| `spawn_tainted_in_case` / `spawn_tainted_correlated` | `spawn_in_case` / `spawn_correlated` |

Eleven doors became eight. A `run_trusted`/`run_tainted` pair was tried first and
rejected: it doubles every shape, puts `run_trusted_in_case` one word from
`run_tainted_in_case`, and still lets `run_trusted(cap, payload)` compile over
data nobody vouched for. A label is a **value** — it can be computed, threaded
through an adapter, or derived from where a message arrived, and a method name
can do none of that.

---

## `models.quarantined` must be selectable

A manifest declaring a quarantined model on `execution.kind: completion` or
`tool-calling`, with no `memory_formation`, is now **refused at parse**:

```text
spec.models.quarantined: ... the second role reads as dual-model isolation
while one model does all the work
```

This breaks manifests written against earlier guidance, at parse, with no
warning phase — so it is worth being blunt about what it caught: a deployment
with 28 manifests all declaring the role, and an operator guide claiming
dual-model isolation, had **nothing selecting the quarantined model**. Every call
went to the privileged one. The file read as a control and was decoration.

Exactly two things point a model at untrusted-derived content on their own, so
exactly three fixes exist:

1. **Drop the role.** Correct whenever the agent is a completion or a tool loop
   and you were not relying on isolation. This is the right answer for most.
2. **Declare `memory_formation`.** Extraction then runs on the quarantined
   model — the reviewer's designated model writes the durable memory while the
   answer stays on the privileged one.
3. **Move to `execution.kind: planned`.** `parse` steps run on the quarantined
   model under a fixed extraction-only instruction, which is the dual-model
   pattern in full.

**What `planned` costs**, so the third option is a decision and not a leap: the
planner sees only **trusted** input — untrusted input is refused, because the
planner reads the input to write the plan — control flow is fixed before
anything hostile is read, and step outputs travel as references rather than
through a model's context. That is the point, and it is also the constraint: an
agent that must react to what a tool *said* wants the loop, not a plan.

A coded skill is exempt: it chooses its own models, so the declaration is a
reviewed allowlist rather than something a tier selects from.

Also refused: `privileged` and `quarantined` naming the same provider and model.
Two roles, one model behind both, is isolation spelled as if it were on.

---

## A tool loop with nothing to reach refuses the build

A manifest declaring `execution.kind: tool-calling` on a plane with no tool
catalogue used to assemble cleanly and then fail **identically on every run**.
Both facts are known at `build`, so it is a `BuildError` now, naming the agent,
its grants, and both fixes — `toolbox(..)` (derived from the declaration) or
`.tools(catalog, client)` (stated by hand).

This is worth knowing because of the shape it catches: a service whose tests
wired a stub catalogue and whose production wiring passed `None` had green tests
and 166 grants across 14 servers that could never have been called. Tests cannot
see that arrangement; the builder can.

Agents whose grants are **all** `tool://agent/…` are exempt and need no
catalogue — those dispatch through `commission`.

---

## `--features postgres` now delivers Postgres

`store` was declared under the `redb` feature while holding *both* backends, so
`--no-default-features --features postgres` compiled, pulled `tokio-postgres` in,
and exposed **no store module at all**. If you worked around it by also enabling
`redb`, you no longer need to.

---

## Checking your own upgrade

```sh
agentplane validate <manifest>...   # every parse refusal, before deploying
cargo check --all-targets           # every admission call site
```

`validate` reads a room as happily as a single agent, and names *which* document
broke — two thirds of a room must not deploy.
