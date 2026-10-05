# Owned local original-read snapshot qualification

This later experiment targets parent
`ce8813ae27a571c7a525f6bbbb7a673dd1a23069`. It returns the existing
[original-read grammar](ORIGINAL_OPERATION_READ_CONTRACT.md) from actual retained
rows of the unchanged [offline policy/effect store](OFFLINE_POLICY_EFFECT_STORE.md).
The [historical signature construction](ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md)
remains separate. Nothing signs a local sample or authenticates a source service.

## Requirements, selected construction and verified boundary

| Layer | Statement |
| --- | --- |
| Protocol requirement | A lookup must select the complete original id, revision, historical profile and proposal, its source/incarnation, policy position, record position and challenge. A conflicting original must never be reported absent. |
| Selected local construction | One owned `BEGIN IMMEDIATE` transaction validates complete retained history, compares both independently prepared checkpoints and reads the original. The same local transaction discipline serializes managed policy, mode, allocation and synthetic-effect mutations. |
| Historical provenance in this experiment | The original profile must equal the retained local policy row at its original revision, including for an absent original. This is local consistency, with no historical issuance, root/owner signature or external provenance witness. |
| Verified behavior | Directed tests sample real absent/pending/completed/unavailable records, preserve old originals after policy changes, refuse stale heads and collisions, and expose coherent substitution, restore/copy and delayed-delivery counterexamples. Native actors qualify the local writer/death boundary. |
| Unresolved operational requirement | Authenticate the selected current source and both heads, historical profile and original lineage; authorize private lookups; retain records durably outside a rollback domain; select recovery and protected-use rules; obtain independent assessment. None is implemented here. |

The [implementation](../qualification/original_read_snapshot.py) uses the exact
existing store, independently selected root declaration and selected original-read
query. Its source labels and complete current profile must match the local store.
The query's complete root must also match the independently supplied root. Root
selection, storage ownership and honest SQLite/VFS behavior are explicit premises.
No source-root signature or curve check runs in this local experiment.

`local_checkpoints(store, root)` samples both heads in one owned transaction.
This is a diagnostic for preparing a synthetic test query. A later
`sample_original(store, root, query)` uses a different transaction and must refuse
an intervening managed change. A caller cannot replace either selected checkpoint
with a value returned by a peer during that read. There is no trusted latest-head
service, authenticated clock, freshness token, consumed-challenge set or retry.

## Exact local checkpoint choices

The policy checkpoint keeps the Stage 45
[local policy-state formula](LOCAL_SOURCE_READ_ORDERING.md) unchanged: revision
and `SHA256(STATE_DOMAIN || canonical(material))`, where the material includes
the complete selected root, local revision, exact profile bytes, active flag and
source mode. A mode round trip can reproduce this policy checkpoint.

The separate record checkpoint has the existing three-field retention shape:
`retention_rule`, `event_sequence`, `record_lineage_digest_hex`. The sequence is
the count of the completely validated, contiguous retained local events.
The selected digest is:

```text
SHA256("PTLC/offline-local-original-record-lineage/v1" || NUL || canonical(material))
```

Canonical JSON is ASCII with sorted keys, compact separators and no trailing
bytes. The material has exactly these seven top-level fields:

| Field | Complete local material and order |
| --- | --- |
| `root_declaration` | Complete independently selected root declaration. |
| `retention_rule` | `retained-all-originals-in-incarnation-v1`. |
| `source` | `revision`, exact `profile_hex`, boolean `active`, `mode`. The root contains the retained source labels. |
| `policies` | All rows ordered by revision: `revision`, `profile_hex`, boolean `active`, `event_sequence`. |
| `operations` | All rows ordered by operation id: complete five-field `original_operation`, `charge_sequence`, nullable `effect_sequence`. |
| `effects` | All rows ordered by operation id: `operation_id_hex`, `event_sequence`, `payload`. The only valid payload is `synthetic-effect`. |
| `events` | All rows ordered by sequence: `event_sequence`, `kind`, `revision`, nullable `operation_id_hex`, `detail`. |

The digest includes every retained original, not just the queried id. Exact root,
historical profile, proposal, charge/effect positions, policy and mode history are
included. Local filenames, database page layout, process/thread ids and physical
host details are excluded. This is a bounded local consistency commitment, not a
Merkle inclusion proof, external history, cryptographic provenance or nonrollback
witness. It is not a new public signature schema or a standardized source digest.

The store's existing bounds remain: revisions 0 through 32, at most 256 events,
64 operations and 64 synthetic effects. The read grammar's larger safe-integer
range is not an implemented store capacity. Retention is complete only within
this finite selected experiment; no deletion, expiry, pruning or migration path
is authorized by these tests.

## Observation and refusal rules

Before any observation, complete local history must validate; both selected heads
must match; the original profile must equal its retained policy row; and a stored
id must match the complete revision/profile/proposal. A conflict refuses even
when the local source is unavailable. Ambiguous and known-compromised modes
refuse. Invalid/incomplete retention never becomes absence or a cached reply.

| Observation | Actual local selection |
| --- | --- |
| `absent` | No row exists for that id; the selected historical profile still matches a retained policy row. Both heads and current head policy are included; no original record is claimed. |
| `pending` | An exactly matching original has a retained charge and no synthetic effect. Both heads, current head policy and complete old original are included. |
| `completed` | An exactly matching original has an earlier charge and later retained synthetic effect. Completion describes that local row, not a chain receipt, physical entry or application success. |
| `unavailable` | The selected local mode is unavailable. All four state fields are null. No absence, original outcome, current policy or record position is asserted by the claim. |

Revocation, changed owner/epoch/scope pins and reduced current caps do not remove
old originals or change their historical profile. A pending original remains
pending and its charge is retained. Reading it cannot reenable its effect or
start a new operation. Reading a completed record does not execute it again.
Old absence likewise grants no new enrollment, recovery, refund or fresh id.

The returned object is exactly the existing unsigned `OriginalReadClaim`.
Its parser matches framing only. There are no added permission booleans,
capabilities, owner/issuer signatures, receipt fields or application adapters.

## Local ordering and explicit unsafe controls

Complete history validation, both checkpoint comparisons and original lookup are
inside the same owned transaction. The selected read point is the completed
snapshot under the lock, before commit. A successful return follows commit;
source state can change after commit and before delivery. Every mutation and
synthetic effect still uses its own existing transaction and current-policy rule.

The [tests](../tests/test_original_read_snapshot.py) and
[native actor](../tests/original_read_snapshot_actor.py) cover:

- Real original observations; complete historical profile retention and local
  provenance; reduced caps with multiple retained charges; exact-id collisions;
  selected root/source/head mismatches; unavailable and compromise refusal.
- Policy-independent charge/effect changes, mode history returning to the same
  policy head, other retained originals and deterministic full-row commitments.
- Native exclusion of policy, mode, allocation and effect writers while the
  snapshot transaction is held; pending-to-completed and revocation changes after
  commit before return; `SIGKILL` at snapshot, pre-commit and post-commit cuts.
- Lost replies, cancellation and failures without any allocation, refund,
  recovery, effect or local state mutation.
- Coherent original/proposal and old-profile substitution: newly selected local
  heads can accept changed consistent rows without an independent witness.
- Coherent database restore and clones repeating old heads, reads, charges and
  synthetic effects. An ideal nonrewound audit list only exposes the repetition;
  it is not a lineage service or an implemented protection.
- An old returned statement driving a blind ideal actuator after revocation.
  The actuator is a counterexample, not a physical device or use fence.

Native tests use bounded POSIX process cuts on the supported Linux/macOS matrix.
They establish the stated runtime/process behavior, not power-loss durability,
hardware storage honesty, hostile VFS safety or another platform's semantics.
All returned statements remain unsigned and forgeable outside the selected local
transaction premise. A hash of consistent local history cannot detect coherent
replacement or restore when the independent selection is also replaced.

## Acceptance gate and next work

Offline qualification is **GO**. Authenticated source integration, application
signing/recovery/admission, core port, deployment, activation, physical entry,
wallet use, broadcasts and real funds remain **NO-GO**.

Before any operational source adapter, independently select root/response key
custody, authenticated current policy and record heads, original and historical
profile provenance, caller lookup authorization/privacy and retention duration.
Specify a nonrollback original ledger, administrator command deduplication,
authorized incarnation transitions, outage/unknown-outcome behavior and an actual
protected-use cutoff. Qualify a concrete candidate offline before connecting it.

This delta is outside both fixed independent-review subjects. Their immutable
inventories and unfilled reports remain unchanged. See
[Stage 48 execution evidence](STAGE48_VALIDATION.md). Earlier schemas, signature
workers/fixtures, store/journal logic, dependencies and CI workflow are unchanged.
