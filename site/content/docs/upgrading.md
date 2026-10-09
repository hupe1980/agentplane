+++
title = "Upgrading"
description = "What a hard cut means before the format freeze, and the procedure for moving a plane from one agentplane build to the next."
weight = 20

[extra]
group = "Operate"
+++

Pre-alpha means hard cuts, with no deprecation cycle. What breaks in each
release is listed in the
[changelog](https://github.com/hupe1980/agentplane/blob/main/CHANGELOG.md), where
every breaking entry is marked **BREAKING** and says what to do about it. This
page is the procedure that applies to all of them.

## What a hard cut means {#hard-cuts}

Until the [format freeze](@/docs/status.md#format-freeze):

| | Across a cut |
|---|---|
| **A build reads its own formats** | A store, an export and a record are read as this build writes them. What does not parse that way is refused, not converted |
| **A store is not migrated** | There is no migration tooling. A store is recreated and rebuilt from an export |
| **There is no downgrade** | Nothing is built or tested for reading a newer build's store or export with an older build, so there is no rollback across a cut. Keep the old export and the old binary until the new plane is verified |
| **A refusal is how you find out** | A manifest fails to parse, a call site fails to compile, a store fails to open, a restore refuses the file |

A restore refuses a record whose bytes do not parse at the version the new build
writes. It does not rebuild part of a history. When a release moves the record
format, the old export does not cross the cut. It stays the record of the old
history, readable by the build that wrote it and checkable offline by
`agentplane verify` of that build.

## Moving a plane to a new build {#procedure}

The export is the long-term artifact and the store is disposable. Moving a
plane is taking one and rebuilding the other.

**1. Drain the old build.** Stop admission and let running steps finish, so no
effect is left announced with no terminal record. `agentplane serve` drains on
`SIGTERM`, bounded by `--drain-secs` — see
[stopping an instance](@/docs/operations.md#stopping-an-instance). An embedder
calls `Runtime::drain(grace)` and reads `DrainReport::unfinished`. To keep work
from starting on a shared store while the copy is taken, halt the tenant — a
`postgres://` store needs a binary built with `postgres`, or the `:full` image
([which verb needs which feature](@/docs/operations.md#cli-features)):

```sh
agentplane halt --store "$DATABASE_URL" --tenant acme \
  --reason "upgrade" --actor "alice@example.com"
```

**2. Export on the old build.**

```sh
agentplane export --store ./journal.redb --tenant acme > plane.jsonl
agentplane verify plane.jsonl
```

`redb` admits one writer process, so on the embedded store the plane is stopped
before the export. An export includes runs still in flight and says so on
stderr; the checkpoint covers sealed runs only. An export that reaches `--limit`
is refused and exits `5` — raise the limit rather than reaching for
`--allow-partial`, because a restore from a partial export is a partial plane.

**3. Recreate the store.** A new redb file, or a fresh database or tenant on
PostgreSQL. `restore` refuses a store that already holds any of the runs, and
refuses a sealed export under a tenant other than the one that sealed it: the
ciphertext names its tenant, so it would open for nobody there.

**4. Restore on the new build.**

```sh
agentplane restore plane.jsonl --store ./restored.redb --tenant acme
```

It exits non-zero unless the rebuilt store commits to the same root at the same
size. The report lists what the file does not carry in `not_carried`, and the
runs that came back waiting in `awaiting`.

**5. Verify, then open the gates.**

```sh
agentplane audit  --store ./restored.redb --tenant acme
agentplane drill  --store ./restored.redb --tenant acme
agentplane waiting --store ./restored.redb --tenant acme
```

Resume every run `waiting` lists before accepting traffic, under the manifest
it was admitted under:

```sh
agentplane replay <run> --store ./restored.redb --tenant acme --manifest agent.yaml
```

A resume is what re-arms its timers, subscriptions and tasks, and a message
delivered before that dead-letters. Timers, subscriptions, leases, delivery cursors, blob bytes
and key material are not in an export — what re-establishes each is in
[what an operator re-establishes](@/docs/operations.md#recovery-by-hand). Nor
are the standing-authority, quota and batch ledgers: a recreated store holds no
standing authority until it is issued again, so re-issue it before accepting
traffic. Lift the halt when the plane is serving:

```sh
agentplane halt --store "$DATABASE_URL" --tenant acme --lift --actor ops-carol
```

## When the format moves {#format-moves}

The changelog's **BREAKING** entries say whether a release moves the record
format, the export format or the effect-key derivation. When one does, steps 3
and 4 start the new build on an **empty** store rather than restoring:

- Finish or cancel every run on the old build first — `agentplane waiting` and
  `agentplane attention` list what is still open. A resume on the new build
  computes different effect keys for the recorded history and quarantines the
  run instead of continuing it.
- Keep the old export and the old binary. They are the record of that history,
  and `agentplane verify` of that build checks the file offline.

## Readers before writers {#readers-first}

Every reader — each store, `verify` and `restore` — reads a record through the
build's upcaster. A record at an older version is lifted to the shape the build
reads, and its bytes and hash stay as written; a version no upcaster reaches is
a version skew (`StoreError::UnknownRecordVersion`), never damage. Before the
[format freeze](@/docs/status.md#format-freeze) a shape change is a hard cut
instead, above. A shape that moves with a version bump deploys in this order:

1. **Readers first.** Every instance, and every `verify` an auditor runs, moves
   to the build that reads the new version before any instance writes it.
2. **The rollback window closes at the first write of a bumped kind.** Until
   the new build writes a record of a kind whose version moved, the store
   holds only records at versions the old build reads — a restore keeps them
   byte for byte, and a kind whose version did not move is written as the old
   build would. The first record of a bumped kind is at the new version, which
   the old build refuses as a skew. From then on a rollback is a restore of
   the last export taken before it.

`two_builds_rehearse_the_upgrade_and_the_rollback_window` holds this sequence in
the tree, over an export one record shape older than the build writes.

## What a build refuses at startup {#startup}

Beyond the store, a new build checks the deployment around it and refuses
rather than degrading. Each of these is a current rule, and each is a reason a
plane that ran on the old build does not start:

| What | The rule | What to do |
|---|---|---|
| **Token files** (`serve --tokens FILE`, `AGENTPLANE_TOKENS_FILE`) | Every token is at least 32 bytes and is none of the values printed in this project's examples | Generate each with `openssl rand -hex 32` |
| **Vault transit keys** (`keyring-vault`) | The key for a scope is named `ap-` and the hex SHA-256 of the scope — `VaultTransit::key_name` — and no other name is read | Provision the keys under those names. Vault's transit `backup` and `restore/<name>` carry existing key material to a new name, which keeps sealed payloads readable |
| **The policy bundle** (`serve --policy`) | A file or a directory, loaded as `agentplane policy check` loads it. A served surface refuses a set that cannot evaluate every request shape it will ask, including a caller that presents no chain; a plane with no engine refuses every `release`. A principal is `Subject::"…"` or `Capability::"…"` — there is no `Agent::` — and a schema's `appliesTo` lists both ([the authorization context](@/docs/security.md#the-authorization-context)) | Run `agentplane policy check --bundle <bundle> --from plane.jsonl` — a `cedar` build — against the old export, and `--candidate` for the bundle you are moving to |
| **Tenant ids** (`--tenant`, `TenantId::new`) | At most 64 characters, with no `/`, `:`, control character, whitespace or `+` — a tenant id is part of the checkpoint origin | Choose a conforming id |
| **Manifests** | Parsed by this build's schema — for example a money ceiling needs `pricing` on every model role; a field nothing reads is refused, such as `approvers` on triage-only oversight or `max_turns` on a `completion` agent | `agentplane validate`, below |
| **Scripts that drive the CLI** | A verb or flag this build does not have is a usage error, exit `2`; statuses follow [one table](@/docs/operations.md#exit-statuses) | Check each against `agentplane <verb> --help`, and alert on `1`, `4`, `5` and `6` as the different pages they are |

## Checking your own upgrade {#checking}

```sh
agentplane validate <manifest>...   # every parse refusal, before deploying
cargo check --all-targets           # every call site the new API refuses
```

`validate` reads a room as readily as a single agent and names which document
broke.
