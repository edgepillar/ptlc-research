# Native release evidence requirements

This is an offline research requirement candidate, not a selected application
cleanup contract. The existing store and isolated selected guard do not implement
these requirements. Independent assessment is absent; application/core remain
**NO-GO**. No observation grants permission to retry an original operation,
allocate another charge, replace a payment, recover a session or perform an effect.

## Distinct evidence boundaries

| Observation | What the selected control establishes | What remains unproved |
| --- | --- | --- |
| Callback returned | The callback returned to its caller | Forwarding, native completion, ownership or release |
| Native connection close returned | The selected connection API returned | Destruction of every subordinate resource or release of every lock |
| Closed connection rejects SELECT | That connection API refuses the selected query | Native deallocation, lock release or authenticated resource identity |
| Cursor close returned before connection close | The selected cursor API returned | An exhaustive inventory of statements, BLOB handles or backup objects |
| Owned Python cursor reference was released | A weak reference becomes empty in the selected CPython profile | General garbage-collection timing, memory erasure or global resource disposal |
| Another connection enters BEGIN EXCLUSIVE | That connection obtains its selected transaction lock at this checkpoint | Permanent availability, global lock absence, custody or physical durability |
| Original operation readback remains exact | The selected local and reopened original rows remain unchanged | Authority to replay, replace, refund or authorize another operation |

None of these observations can substitute for all the others. A resource-release
claim needs an explicit resource inventory, an owner and a stated native driver
profile. Callback reports and Python object lifetime are not authenticated native
identity or lineage. Checkpoint path/stat/byte comparisons are not atomic path
continuity or race resistance.

## Source-pinned explanation

At CPython commit
[`2abcf904b8dac8c999d2b3aac76681abb333798a`](https://github.com/python/cpython/commit/2abcf904b8dac8c999d2b3aac76681abb333798a),
[`connection_close`](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/connection.c#L427)
clears the connection's stored database pointer before calling `sqlite3_close_v2`.
The public close implementation clears its statement cache first. The
[`cursor close implementation`](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/cursor.c#L1279)
checks connection availability before resetting and clearing a cursor's statement.
The [`statement destructor`](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/statement.c#L102)
finalizes the native statement. These source paths explain why a cursor retained
across connection close needs a separate lifetime observation.

SQLite's pinned implementations at
[`8ed5e7365e6f12f427910188bbf6b254daad2ef6`](https://github.com/sqlite/sqlite/blob/8ed5e7365e6f12f427910188bbf6b254daad2ef6/src/main.c#L1235)
and
[`ccd445d76a9362c63add000354fac84ba9022176`](https://github.com/sqlite/sqlite/blob/ccd445d76a9362c63add000354fac84ba9022176/src/main.c#L1240)
distinguish connection invalidation from final cleanup when native statements or
backups remain. The corresponding pinned
[3.50.4 header](https://github.com/sqlite/sqlite/blob/8ed5e7365e6f12f427910188bbf6b254daad2ef6/src/sqlite.h.in#L319)
and [3.53.1 header](https://github.com/sqlite/sqlite/blob/ccd445d76a9362c63add000354fac84ba9022176/src/sqlite.h.in#L322)
describe deferred disposal for `sqlite3_close_v2`, including subordinate BLOB and
backup resources. The [upstream API explanation](https://www.sqlite.org/c3ref/close.html)
is supplementary documentation, not an immutable runtime identity pin.

Source inspection and the measured local interpreter version are separate facts.
No build attestation ties these inspected sources to the loaded SQLite library or
to every hosted interpreter. The local controls use CPython 3.12.14 and report
SQLite 3.53.1; matching version strings do not establish matching builds. Hosted
Python/SQLite profiles need fresh observations. No private pointer layout,
native destructor instrumentation, source rebuild or global resource inventory
is used.

CPython's [license](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/LICENSE)
and both SQLite licenses
([3.50.4](https://github.com/sqlite/sqlite/blob/8ed5e7365e6f12f427910188bbf6b254daad2ef6/LICENSE.md),
[3.53.1](https://github.com/sqlite/sqlite/blob/ccd445d76a9362c63add000354fac84ba9022176/LICENSE.md))
were reviewed. This document paraphrases and attributes source behavior; it
copies no third-party implementation. The original tests use the standard
library and synthetic values. The project license remains unchanged.

## Owner-side candidate requirements

1. Define which trusted component owns the connection and all subordinate
   statements, BLOB handles, backups and other retained references. Inventory
   completeness and source-to-loaded-build identity require independent evidence.
2. State a disposal order for the admitted native profile. Finalize or close
   owned subordinate handles before connection close where required. API return,
   invalidation and selected lock availability must remain separately recorded.
3. Preserve the exact original operation and its accounting independently of
   cleanup. Uncertain release does not erase a charge or authorize another effect.
4. Define how an unknown outcome is retained and escalated without automatic
   retry, replacement or recovery. Exception priority and cancellation behavior
   are separate unresolved application policy choices.
5. Keep explicit test-fixture reference release separate from selected cleanup.
   Do not infer a portable disposal guarantee from CPython reference counting or
   a single successful lock probe.
6. Require independent assessment before admitting application behavior. Natural
   I/O faults, arbitrary interruption, signals, process termination, thread/fork
   behavior, retained BLOB/backup objects, malicious drivers, restore resistance,
   custody and physical durability remain unqualified.

## Selected implementation evidence

Two [native controls](../tests/test_selected_native_release.py) vary cursor close
order while retaining a partially consumed reader in DELETE journal mode, with
zero timeout and no statement cache. Both initially reject a peer's
`BEGIN EXCLUSIVE` with exact `SQLITE_BUSY`. Both later reject owner SELECT with
exact `ProgrammingError` after connection close returns.

Keeping the cursor across connection close also rejects cursor close and retains
the peer's busy result. Closing the cursor first permits the peer transaction,
even while its Python object is retained. Releasing the owned cursor reference
then permits the peer in both controls. The weak reference is empty afterward in
this selected profile; no general garbage-collection or erasure claim follows.

These observations are consistent with the pinned source explanation, not direct
native-pointer destruction measurements. Complete original readback, probe
contents, bytes, checkpoint stat identity, file mode and directory entries are
checked separately before and after fixture reference release and peer close.
See the [Stage 120 validation snapshot](STAGE120_VALIDATION.md) for qualification
counts and remaining acceptance gates. No store, guard, actor, worker,
cryptography or CI workflow changes implement these candidate requirements.

## Scoped resource inventory

The [native resource inventory](NATIVE_RESOURCE_INVENTORY.md) inspects the unchanged
store and actor creator/consumer/disposal paths before selecting a construction.
It distinguishes Python's prepared-statement cache from SQLite's page cache.
One selected control with a one-entry statement cache retains two independent
same-SQL readers. A cache entry count does not establish a live-handle bound or
complete ownership. Wrapper aliases and inline cursor consumption require an
explicit cooperative ownership/disposal design; no registry or application
cleanup policy is selected by that inventory.
