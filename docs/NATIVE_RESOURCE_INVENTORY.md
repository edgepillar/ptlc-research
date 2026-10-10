# Native subordinate resource and cache inventory

This is a scoped offline source inventory and a requirement candidate. It does
not certify complete native ownership, select application cleanup behavior or
repair the existing store. Independent assessment is absent; application/core
remain **NO-GO**. Original charges and effects retain their existing accounting.

## Inspected repository scope

Repository claims below are pinned to the accepted research commit
[`07081224b430d39ac358942057f4ef0bb8ed999f`](https://github.com/edgepillar/ptlc-research/commit/07081224b430d39ac358942057f4ef0bb8ed999f).
These five sources remain unchanged in this stage. This inventory covers their
selected paths, not every test fixture, interpreter extension or native object.

| Selected source and resource | Creator and consumer | Retention and disposal boundary |
| --- | --- | --- |
| [Store connection and provisioning descriptor](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/qualification/policy_effect_store.py#L123) | Constructor creates a file descriptor when provisioning, closes it, then opens one stdlib SQLite connection | `_db` retains the connection. The constructor selects URI read/write, zero timeout, `isolation_level=None` and `detect_types=0`; it omits `cached_statements` |
| [Store inline readers](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/qualification/policy_effect_store.py#L217) | `_source`, `_validate`, `_event`, `_record`, `local_view` and allocation call `execute` and inline `fetchone` or `fetchall` | No explicit cursor registry or per-cursor close order exists. Returned public records contain values, not cursor handles. Inline consumption is not an independently verified native resource inventory |
| [Store transaction and disposal](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/qualification/policy_effect_store.py#L176) | `_transaction` selects BEGIN IMMEDIATE, validation, commit and rollback; `_dispose` attempts rollback followed by connection close | `_closed` is a Python state flag. `_dispose` does not enumerate subordinate handles. Earlier secondary-exception masking and skipped-close boundaries remain unchanged |
| [Original actor](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/tests/policy_effect_store_actor.py#L24) | Opens the store, selects page-cache/spill settings, optionally replaces `_db` with an observation wrapper, then performs a synthetic command | Its finally branch calls `store.close` if `_closed` is false. The wrapper also retains the connection; no native ownership attestation follows |
| [Execute observation wrapper](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/tests/policy_effect_native_observation.py#L27) | Stores the original connection, forwards `execute` and returns its cursor unchanged | Keeps bounded error labels/codes; it neither registers returned cursors nor establishes exclusive disposal ownership. `close` forwards to the connection |
| [Contention actor and wrapper](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/tests/policy_effect_contention_actor.py#L28) | Opens the same store, selects page-cache/spill settings and keeps a connection alias in its wrapper | Store context exit invokes the existing close path. Wrapper `close` forwards but discards its return. Native errors and transaction flags are diagnostics |
| [Rollback actor authorizer](https://github.com/edgepillar/ptlc-research/blob/07081224b430d39ac358942057f4ef0bb8ed999f/tests/policy_effect_rollback_actor.py#L15) | Registers an allowlisted native authorizer on the opened store, then delegates to the original actor | Registration introduces a callback lifetime boundary, not a subordinate-handle inventory or release certificate |

The five inspected sources contain no selected `blobopen`, `backup`, custom
connection factory or row-factory path. This is a bounded source-search result,
not a claim that such objects cannot exist elsewhere or be introduced through an
alias. The store's private `_db` field and wrappers are accessible to qualification
fixtures; Python naming does not provide an ownership or isolation boundary.
The separate `runtime_report` temporary connection is closed by `contextlib.closing`;
its reported version/settings do not identify the store's loaded native objects.

## Two different cache settings

Python's `cached_statements` configures the connection's prepared-statement cache.
At CPython commit
[`2abcf904b8dac8c999d2b3aac76681abb333798a`](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/connection.c#L153),
the inspected cache constructor uses an LRU wrapper and the connection constructor
declares a default of 128. This is a fact about that source pin, not a portable
default or proof of every local/hosted loaded build. The store omits this option;
Stage 120 explicitly selects zero; the new separate control explicitly selects one.

The actor's `PRAGMA cache_size` concerns SQLite's page cache. At SQLite commit
[`ccd445d76a9362c63add000354fac84ba9022176`](https://github.com/sqlite/sqlite/blob/ccd445d76a9362c63add000354fac84ba9022176/src/pragma.c#L882),
that path records a schema page-cache setting and calls the B-tree cache-size
setter. `cache_size=1` and `cache_spill=ON` in the actor do not select a one-entry
Python prepared-statement cache. These are different controls; neither supplies
an exhaustive list or hard bound of all live subordinate resources.

## Cache capacity and live readers

The pinned CPython [cursor path](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/cursor.c#L844)
looks up a cached statement and creates another statement if that statement is
already busy. Its [cursor cleanup](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/Modules/_sqlite/cursor.c#L156)
resets and clears a retained statement; the connection's cursor list uses weak
references. This explains a source-level reason why a cache entry limit is not
an ownership inventory or a bound on all simultaneously active statements.
The inspected default, LRU behavior, busy fallback and weak references are source
facts. The new test does not introspect a native statement pointer or assert
which cached statement a loaded interpreter used.

One [selected native control](../tests/test_selected_statement_cache.py) uses a
separate connection with `cached_statements=1`, zero timeout, DELETE journal mode,
synchronous EXTRA and foreign keys. Two distinct cursor objects execute the
same SQL and retain partially consumed readers over three synthetic integer rows.
The first advances independently; after it closes, the second still returns its
next row and the peer remains busy. Both readers are created before cursor close.

| Checkpoint | Selected observation |
| --- | --- |
| Both same-SQL cursors are live; `in_transaction` is false | Peer BEGIN EXCLUSIVE reports exact SQLITE_BUSY |
| First cursor close returned; second cursor remains usable | Peer still reports exact SQLITE_BUSY |
| Connection close returned; owner SELECT and second cursor close are refused | Both refusals are exact ProgrammingError; peer stays busy |
| Second cursor reference explicitly released; closed first cursor still retained | Second weak reference is empty in the selected CPython profile; peer enters and rolls back without writing |
| Closed first cursor reference explicitly released | First weak reference is empty; peer again enters and rolls back |

The control records one owner connection close, one successful cursor close, one
later refused cursor close, three busy peer attempts, two successful peer
transactions and two explicit fixture reference releases. Fixture cleanup closes
the peer once and performs no further owner close. Complete local/reopened original
readback and both files' bytes, mode, checkpoint device/inode and directory entries
remain exact at five checkpoints. Original charge/event sequence is 1, with one
exact original and zero effects. Neither file is mutated by a successful peer probe.

## Requirements before choosing a construction

- Specify a cooperative owner that retains all handles it creates, the disposal
  responsibility of each wrapper/alias and the order for closing subordinate
  handles while the connection API is usable. Registration and retirement must
  be defined across successful return, error and cancellation paths.
- Treat a cache entry count, page-cache setting, transaction flag, closed flag
  or wrapper callback as a different observation from ownership completeness.
  Cache eviction and reference release need separate source/profile assumptions.
- Keep exact original-operation accounting independent of resource disposal.
  An unknown outcome grants no automatic retry, refund, replacement or new effect.
- State an admitted driver/build profile and assess ownership independently.
  This inventory selects no registry, trusted release Boolean or application
  exception/cancellation policy. The existing guard is not wired into the store.

Source-to-loaded-build identity remains **NOT VERIFIED**. Weak-reference timing is
limited to the selected CPython profile. Exhaustive native inventory, BLOB/backup
objects, callbacks/cycles, cache eviction, natural I/O faults, arbitrary interruption,
thread/fork behavior, process death, malicious drivers, restore resistance, custody
and physical durability remain unresolved. Selected lock probes do not demonstrate
permanent availability, native pointer destruction, race resistance or secure erasure.

The pinned [CPython license](https://github.com/python/cpython/blob/2abcf904b8dac8c999d2b3aac76681abb333798a/LICENSE)
and [SQLite license](https://github.com/sqlite/sqlite/blob/ccd445d76a9362c63add000354fac84ba9022176/LICENSE.md)
were reviewed and retained. This document paraphrases and attributes behavior;
no third-party implementation is copied. The project license remains unchanged.
See [native release requirements](NATIVE_RELEASE_REQUIREMENTS.md) and the
[Stage 121 validation snapshot](STAGE121_VALIDATION.md) for distinct evidence gates.
