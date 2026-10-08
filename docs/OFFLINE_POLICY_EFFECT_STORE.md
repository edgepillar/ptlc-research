# Isolated local policy and synthetic-effect store

Status: **An offline SQLite construction is selected for qualification only.
It is not an authenticated current-authority service or a physical-entry gate.**

This follows the [source/use model](POLICY_SOURCE_USE_MODEL.md) at parent commit
`a12642986372d73750636a45357ee785451076a6`. The model leaves durability and
serialization as premises. This candidate tests one native implementation of
local policy ordering, retained synthetic allocations and original-operation
reconciliation. See [executed validation](STAGE41_VALIDATION.md).

## Requirements, selected construction and evidence

| Boundary | Requirement | Selected candidate | Verified behavior or open gate |
| --- | --- | --- | --- |
| Source authority | Independently provisioned roles and current authenticated policy | Explicit synthetic labels and an offline administrator premise | No administrator, source or read authentication; no external current-state oracle |
| Policy and charge ordering | One declared authority serializes updates and original scoped operations | One local SQLite database with `BEGIN IMMEDIATE` | Separate native writers serialize or receive an unknown outcome; no automatic retry |
| Protected use | Declare the exact effect and revocation cutoff | Commit a synthetic row in that same database, after checking the complete current local checkpoint | Native before/after-commit process cuts are tested; physical worker entry is outside this construction |
| Retention | Preserve charges, original request identity and results | Bounded policy, operation, effect and event tables | Reopen preserves records; coherent database restore and copies still repeat effects |
| Recovery | Reconcile the original operation after reply loss | Exact request lookup and replay return retained history | No refund, replacement ID, current-source certificate or recovery permission |

The implementation is [qualification/policy_effect_store.py](../qualification/policy_effect_store.py).
It imports the existing pure governor-profile decoder, not a verifier, journal,
application runner, network client or private signer. Source identity, source
incarnation, authority and resource labels are independently supplied synthetic
64-character lowercase hex values. Equality of those labels authenticates
nothing. Owned parent storage, an honest administrator and honest SQLite/VFS
behavior are external premises. A leaf-symlink check does not prove filesystem
ownership or prevent a hostile path replacement.

## Complete local policy and retained operations

The candidate retains the existing canonical 14-field
[governor profile](LOCAL_GOVERNOR_PROFILE.md). The unchanged
[unsigned fixture](../qualification/fixtures/governor_contract.json) has SHA-256
`d287a4e3edc20e3b303a168d3babecdc2142f2bd13e0b329df37f4726837c0b9`.
Owner, scope, caps, intent version and all other profile fields are bound as exact
bytes. Authority and resource cannot change within this selected namespace.
Policy changes require the selected old revision and advance it even if the
profile bytes are identical. Local owner rotation and cap changes preserve all
earlier charges. Reducing a cap below consumption prevents new allocations; it
does not invalidate historical charges or refund them.

An original request consists of an operation ID, expected policy revision,
complete profile bytes and an opaque proposal digest. A repeated exact request
returns its original record; changing any binding under the same operation ID
refuses. No proposal semantics, target count or credential signatures are
decoded. `max_attempt_limit` bounds synthetic allocations, while the other caps
are retained comparison fields. This is not enforcement of an actual worker's
resource budget. A format-valid zero owner can be installed by the local
administrator and receive synthetic effects; the negative control demonstrates
the absence of authentication.

Two different operation IDs can charge and apply the same proposal twice under
a cap of two. Scoped idempotency is not business-intent uniqueness. The selected
bounds are 32 policy revisions, 64 operations/effects and 256 audit events.
Exhaustion refuses further mutations without deleting or resetting records.
There is no migration, pruning, namespace reset, root rotation or source recovery
API. These bounds qualify a finite construction, not a scalable service.

## Selected transaction and synthetic-effect cutoff

Each command opens an explicit `BEGIN IMMEDIATE` transaction, validates the
selected schema, native settings and complete event history, applies its action,
validates again and explicitly commits. Only one database is involved; no
external callback performs protected work. The candidate requires rollback
journal `DELETE`, selects `synchronous=EXTRA` (3), enables foreign keys and checks
these settings again inside each command. WAL and foreign schemas refuse.
Creation uses exclusive file creation and never clobbers an existing database;
opening a missing database does not create a replacement source.

SQLite documents that [an immediate transaction starts a writer before its
queries and can fail when another writer holds it](https://www.sqlite.org/lang_transaction.html).
The Python connection uses `isolation_level=None` for
[explicit transaction control](https://docs.python.org/3/library/sqlite3.html),
with a zero busy timeout. DDL statements execute individually; no implicit
`executescript` commit is relied upon. These mutable documentation pages were
reviewed on 2026-10-05. They are design references, not independently reproduced
provenance for the installed library.

Allocation and synthetic effect are separate transactions. Allocation records a
charge only under the current active local policy. Before a new effect, the
candidate rechecks that exact revision and complete profile. It then inserts
the fixed synthetic row, records the effect event and updates the original
operation atomically. A revocation or policy change committed between allocation
and effect refuses the pending effect and retains the charge. Even an equal
profile reissued at a later revision refuses the old pending request. An effect
committed before revocation remains historical; replay returns that same record
without applying another effect or granting new permission.

`live`, `unavailable`, `ambiguous` and `compromise-detected` are locally selected
administrator labels, not observed network or compromise states. Non-live modes
refuse allocation, effects and original lookup; a diagnostic local view remains
possible. Returning to live retains charges and policy revision. An unchanged
pending original request can then resume its synthetic effect. No cached remote
read or forged Stage 39 response is accepted as a permission input.

## Unknown outcomes and native controls

Lock contention, SQLite errors and loss of a conclusive command reply produce
`StoreOutcomeUnknown`. A refusal occurring after a successful commit is also
unknown, never an absent allocation. If rollback cannot be confirmed, the handle
closes before another command. Structural and local-policy refusals roll back
without repair. No command automatically refunds, changes an ID or retries work.
An unknown reply must be reconciled against the original request; an unavailable
lookup does not turn uncertainty into absence.

Connections belong to their creating process and thread. Inherited, foreign,
closed and recursive access refuse before SQL. Separate-process actors use their
own connections. The [native tests](../tests/test_policy_effect_store.py) pause
[synthetic actors](../tests/policy_effect_store_actor.py) at writes and immediately
before/after commit, then send actual POSIX `SIGKILL`. They cover allocation,
effect and policy transactions, writer races and inherited connections. A small
actor cache with spilling enabled exercises the native rollback-journal path;
it does not promise a particular write or flush at every pause.

Ordinary tests additionally inject in-process exceptions and inconclusive
rollback responses. Those are synthetic fault controls, not native full-disk or
I/O-error qualification. Process death does not simulate OS crash, power loss,
storage-controller failure or dishonest flush/locking behavior. SQLite's
[atomic-commit description](https://www.sqlite.org/atomiccommit.html) states its
storage and locking assumptions. Its
[EXTRA setting](https://www.sqlite.org/pragma.html#pragma_synchronous) adds a
directory sync in DELETE mode; observing that setting is not hardware durability
proof. No independent SQLite/VFS build reproduction or power-failure test is
performed in this stage. Native controls are POSIX-only; Windows remains
unqualified by these tests.

## Required unsafe restore and copy controls

Actual file-copy tests restore a coherent earlier database while retaining the
same labels and apparently current local profile. The same original request can
then apply its synthetic effect again. Two coherent copies likewise have
independent counters and can each consume their own cap under the same labels.
Schema and audit consistency checks do not distinguish either case from valid
history. Changing only one retained label or corrupting a partial event history
refuses, but detecting incoherent tampering does not establish nonrollbackable
lineage. Authentication alone would not repair this boundary.

The same database deliberately contains both effect and operation record.
Restoring it rewinds both. Once an effect exists elsewhere, SQLite cannot atomically
cover it merely because a local record was committed. Connecting this helper to
a subprocess launch, signing operation or remote dispatcher would require a
separately selected fencing and reconciliation mechanism at that actual effect.

## Commands and next gates

```sh
python3 -B -m unittest discover -s tests -p test_policy_effect_store.py -v
python3 -B -m qualification.policy_effect_store
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
```

The module command probes a native temporary-file database and prints only a
numeric SQLite version, selected mode/settings and explicit
`authentication: false` / `physical_entry: false` boundaries. It supplies no
credential or environment log. Runtime versions are observations, not immutable
upstream source pins. No third-party implementation is copied or vendored; see
[notices](../THIRD_PARTY_NOTICES.md).

Before any current-authority adapter, select and independently assess actual
source/root provisioning, authenticated current reads and updates, ownership,
nonrollbackable lineage and authorized compromise/recovery transitions. Before
protecting work outside this database, select physical dispatch/entry fencing
and unknown-outcome recovery for that exact effect. Preserve complete-request
scope checks and decide business-intent uniqueness separately. Neither fixed
review subject nor unfilled report changes; this later delta needs its own
assessment. Offline qualification is **GO**. Source integration, core port,
activation, deployment, private signing and funded recovery remain **NO-GO**.

## Stage 42 isolated root statement

The [source root role candidate](SOURCE_ROOT_ROLE_QUALIFICATION.md) qualifies
complete historical declaration signatures under independently selected bytes.
Five distinct key encodings do not prove independent control; valid old statements
and restored/copy selections still replay. No source service, administrator
authentication, SQLite or physical-use connection is added. See the [Stage 42
validation](STAGE42_VALIDATION.md) for execution evidence and failures.
Both fixed independent assessments remain unfilled; source integration, core port,
private signing and funded execution remain NO-GO.

## Controlled contention and reply ambiguity

The [Stage 100 controls](POLICY_EFFECT_CONTENTION.md) preserve this source and
its original native regressions, including the strict distinct-request assertion.
Explicit readers and before/after-commit reply-loss hooks distinguish native
refusal phases from actual retained rows. Two exit codes of 20 can accompany
zero or one charge; they do not determine a refund or permission to retry.
The initial Stage 99 CI occurrence remains UNRESOLVED. No production retry,
replacement operation, private signer or new source-authority claim is added.
