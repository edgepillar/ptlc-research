# Test-only witness creation and interruption lifecycle

## Requirement, construction and boundary

A failed or cancelled local witness command must not produce a positive result
or leave a reusable failed handle. This experiment qualifies selected creation,
opening, inspection and retention transitions in the existing
[test-only owned store](../tests/original_witness_store.py). It selects no
application storage, canonical source, recovery service or durability backend.
Its parent is `32e7a436b16b35e62fdd5b204afd093624d49845`,
[draft PR 50](https://github.com/edgepillar/ptlc-research/pull/50).

The narrow helper change marks constructor ownership as busy, closes the new
file descriptor in a `finally` block, adds nine qualification-only creation
cuts, sanitizes unexpected ordinary constructor exceptions and refuses known
nonregular or direct symlink paths before SQLite. Existing compare-and-retain
transactions, schema, bounds, bindings, grammars and public fixtures are
unchanged. The cuts are test hooks, never application callbacks.

## Selected creation state machine

| Selected cuts | State after ordinary failure, interruption or killed actor |
| --- | --- |
| `create-file-opened`, `create-file-closed`, `create-connected` | A created file can remain without a committed schema. Reopening refuses; no automatic initialization, repair or deletion occurs. |
| `create-locked`, `create-binding-table`, `create-witness-table`, `create-bound`, `create-before-commit` | The schema/binding transaction has not committed. Native rollback, including hot-journal recovery, must not finish the partial schema. The remaining file refuses normal opening. |
| `create-after-commit` | The complete independently selected binding and empty witness table are committed. Explicit reopening can observe an empty store; this supplies no historical knowledge or authentication. |

Unexpected ordinary constructor exceptions return sanitized
`WitnessOutcomeUnknown` and close the handle. `KeyboardInterrupt` and
`SystemExit` propagate after cleanup. No failed handle can be used to inspect,
retain, close again or enter a context. These are selected cleanup observations;
close failures, drive failure and every possible instruction cut are not
qualified.

The constructor does not invoke the verifier. Creation serializes both DDL
statements and the complete binding insert under `BEGIN IMMEDIATE`. An existing
empty, partial, mismatched or non-database file is not treated as a fresh file.
An independently wrong complete Root, proposal or historical profile refuses
without erasing the correctly opened owner's completed witness.

The [native child actor](../tests/original_witness_lifecycle_actor.py) uses a
one-page cache with spilling enabled and is killed at each of the nine cuts.
SQLite may alter file bytes during native rollback recovery; this is separate
from application repair. Two live-child cases exercise an uncommitted created
file and an already-held creation writer lock. All actor responses, deadlines
and cleanup are bounded. No power-loss or hostile-filesystem guarantee follows.

## Cancellation and inherited ownership

Cancellation at five retention cuts before commit preserves the pending
witness; cancellation after commit preserves completion while returning no
result. Opening and inspection cancellation at their lock, before-commit and
after-commit cuts dispose the connection without erasing completed history.
Cancellation before or after one verifier response does not retry the worker
or replace the pending witness. The actual qualifier also interrupts after
both successful public mathematical responses, still before retention commit.

A real forked child attempts four commands on the inherited handle: close,
context entry, inspect and retain. A database trap and verifier trap establish
refusal before either is used. The inherited connection is deliberately kept
alive until `os._exit`; the test must not finalize or operate SQLite in the
child. The parent's witness remains usable and unchanged. This does not make
inherited native connections safe application objects.

The [normal 20-method suite](../tests/test_original_witness_lifecycle.py) uses
explicit forged verifier flags. The
[23-case actual-worker qualifier](../scripts/qualify_original_witness_lifecycle.py)
replays those methods with the unchanged selected measured public executable
and adds three mathematical/outcome controls. It adds no signing or private
material. Actual worker identity is an execution premise, not authenticated
binary provenance or a sandbox.

## Path, copy and outcome limits

The directory, pathname, SQLite/VFS, process and verifier remain trusted owned
premises. A known directory, FIFO or direct dangling symlink refuses before
SQLite; these checks do not prevent ancestor changes, aliases, replacement
races or malicious storage. No open-file replacement defense is implemented.

After a completed store is closed, deleting its file and creating a new store
at the same pathname loses all completed knowledge. The new empty store can
retain an incompatible signed first future while the saved old copy still
contains completion. A pathname, local version and successful initialization
are not independent nonrollback ownership.

One actual-worker control separately loses the original source's effect reply
after its commit, then interrupts witness retention after its own commit.
The offline observer sees one source charge/effect and a retained historical
completion. Neither result resolves the caller's original unknown outcome or
authorizes retry, refund, allocation or protected use. Native local command
uncertainty, signed historical observation and authoritative original recovery
remain distinct.

## Decision

**GO** for the bounded offline lifecycle experiment and review.
**NO-GO** for application witness integration or core/product use. Authenticated
Root/issuance/original provenance, current/canonical selection, independent
source and consumer nonrollback ownership, minimal disclosure and lookup
authorization, signer custody, administrative incarnation/deduplication,
authoritative unknown recovery, protected-use ordering and independent
security/privacy assessment remain open. See
[execution and preservation evidence](STAGE56_VALIDATION.md).
