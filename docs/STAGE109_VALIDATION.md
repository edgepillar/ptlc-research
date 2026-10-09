# Stage 109 original actor constructor interruptions

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

The selected immutable parent is `f60f37a5408d6646a8eb69d0bdb5d8f927198252`,
tree `d7e19e1f1f09c8943985673ae23909a8d83ee4b3`. The original actor, store,
observer, classifiers, strict tests and all 325 preceding sources remain byte
exact. One new source adds fourteen disjoint in-process methods. No external
source code is copied. This changes selected offline qualification, with no
application, core, cleanup or allocation retry change.

Each control separately seeds one original charge, sequence 1, with zero
effects before selecting a constructor boundary. The actor constructs its
store before entering its exception and terminal-cleanup guard. Forwarding
test hooks execute the actual original constructor, SQLite connection,
transaction calls and native close. Selected connection-factory cancellation
and existing open-transaction cuts are explicit synthetic interruptions.
Missing-path open and authorizer denials produce actual native SQLite errors.
Selected post-close faults occur only after actual native close succeeds.

| Selected constructor boundary | Outward result and exact context | Constructor disposal / native close calls |
| --- | --- | --- |
| Selected cancellation before native connect | Exact cancellation, no context | 1 / 0 |
| Native missing-path open | New unknown; native CANTOPEN context suppressed | 1 / 0 |
| Native setup PRAGMA denial | New unknown; native AUTH context suppressed | 1 / 1 |
| Original source-label refusal | Exact refusal, no context; open rollback | 1 / 1 |
| Native open BEGIN denial | Exact transaction unknown; native AUTH context suppressed | 1 / 1 |
| Selected open-before-commit cancellation | Exact cancellation; open rollback | 1 / 1 |
| Selected open-after-commit cancellation | Exact cancellation; open commit is not an allocation | 1 / 1 |
| Open cancellation with one native rollback denial | Exact cancellation; second rollback during disposal | 2 / 2 |
| Open cancellation with two native rollback denials | Exact cancellation; native close releases the transaction | 2 / 2 |
| Native setup denial plus selected post-close cancellation | Exact terminal; native AUTH directly as context; no unknown conversion | 1 / 1 |
| Open cancellation plus selected post-close EIO | Exact terminal; exact primary cancellation as context | 1 / 1 |
| Native BEGIN denial plus selected post-close cancellation | Exact terminal; transaction unknown and its suppressed native AUTH context | 1 / 1 |
| Open cancellation plus synthetic SQLite-class post-close fault | Post-close fault swallowed; exact primary cancellation survives | 1 / 1 |
| Healthy original constructor and actor allocation lookup | Function return 0; original record and empty native report | 1 / 1 |

Thirteen interrupted controls assert no constructor return, no allocation,
no actor public close and empty actor output. They verify native closure when a
connection exists. Three non-SQLite post-close faults interrupt the private
closed-flag update: the retained partial object has a false flag while its
native handle is confirmed closed. That object is retained only by the harness;
construction did not return a usable actor store. The selected SQLite-class
fault is synthetic and swallowed after actual close, not a natural native-close
failure. Cleanup hooks close the native handle without replaying the selection.

Every control separately verifies the original local and reopened state:
one raw operation, one retained original, charge sequence 1, no effect sequence,
one charged operation, zero synthetic effects and event sequence 1. No original
is replaced or duplicated. An open transaction's successful commit does not
mean another operation was allocated. The healthy baseline delivers the exact
original record and empty native observation report and closes the handle.

Forwarded transaction calls and native authorizer callbacks are counted
separately. The healthy baseline records four explicit BEGIN/COMMIT calls and
two native callbacks. A callback is not evidence of completed execution, and
neither counter is inferred from the other. Interrupted constructors precede
observer installation, so locally retained native exception objects do not
establish an installed actor report. Exception identity, explicit cause and
context suppression are checked separately from output. Retained suppressed
context does not establish a rendered diagnostic. Process status remains
unavailable for these in-process controls; function return 0 is separate.

The first focused run executed fourteen methods: thirteen passed and one new
healthy-baseline assertion failed in 0.071 s (runner 0.321 s). It incorrectly
expected four authorizer callbacks where two were observed. The failed source,
log and result are preserved. Separate forwarding-call instrumentation corrected
the assertion; the corrected focused run passes fourteen methods in 0.313 s
(runner 0.837 s), required OpenSSL, no skips or ResourceWarnings. There is one
focused correction run. Complete final-source regression is recorded below; source preservation
and artifact hygiene remain separate gates.

The [scope note](POLICY_EFFECT_CONTENTION.md#original-actor-constructor-interruptions)
keeps these selections separate from natural SQLite close failures,
operating-system signals, child exit status, arbitrary fault combinations,
authenticated remote receipt, restored copies and physical durability. No
observation authorizes replacement, retry, refund, nonce allocation, signing or
a physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete run on the frozen final sources passes 2159 exact unique methods
in 1200.33 s (runner 1200.884 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2145 preceding IDs are retained and
fourteen disjoint IDs are added. All 325 preceding sources remain exact; one
new test source gives 326 frozen sources. Two documentation modifications and
two additions give 553 files, with 549 of 551 preceding files exact. The initial
focused assertion failure and one corrected focused run remain separately
recorded. There is no final-source full-regression retry or preparatory failure.
Full Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted execution
and independent assessment remain separate. Earlier failed logs and original
archives remain preserved without source or evidence cleanup.
