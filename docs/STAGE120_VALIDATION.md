# Stage 120: closed APIs and native lock release

This is an offline native counterexample qualification and an owner-side
requirement candidate. Existing store, selected cleanup guard, actor, worker,
cryptography and CI workflow remain unchanged. Independent assessment is absent;
application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/7f510a8e0f78bcbe357e29da785bcedc098f3061).
Its [independent main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/38003081749)
pass eight jobs. The prior Stage 119 no-op controls separate callback return from
actual native calls. This stage tests a different boundary: a real connection
close and API invalidation need not imply immediate native lock release.

## Requirement, construction and observation

[Native release requirements](NATIVE_RELEASE_REQUIREMENTS.md) distinguish
callback completion, connection API invalidation, subordinate handle lifetime,
selected lock availability and exact original-operation retention. The document
attributes inspected CPython and SQLite behavior to immutable commits, reviews
their licenses and copies no third-party implementation. It selects no trusted
release contract, recovery policy or application cleanup construction.

Two original controls derive only from the common policy-store fixture. They do
not inherit another test class or multiply a fault matrix. Each creates a
separate native probe database with three synthetic integer rows, zero timeout,
no statement cache, DELETE journal mode, synchronous EXTRA and foreign keys.
One partially consumed ordered SELECT retains a cursor. A separate peer attempts
BEGIN EXCLUSIVE; successful attempts immediately roll back without writing.

| Selected checkpoint | Cursor retained across connection close | Cursor closed before connection close |
| --- | --- | --- |
| Reader is live | Peer reports exact SQLITE_BUSY | Peer reports exact SQLITE_BUSY |
| Connection close returned; owner SELECT reports exact ProgrammingError | Cursor close also reports exact ProgrammingError; peer stays busy | Cursor close returned earlier; peer enters and rolls back |
| Owned cursor reference explicitly released | Weak reference is empty; peer enters and rolls back | Weak reference is empty; peer enters and rolls back |

Each performs one owner connection close and one explicit fixture reference
release. Busy/successful peer observations are respectively 2/1 and 1/2. The
cursor-first control keeps its closed Python cursor object alive until reference
release, separating object lifetime from lock availability. The retained-reader
control measures closed-connection cursor refusal before reference release.
Exception class, SQLite code/name where available, absent context/cause and no
suppression are checked separately. No exception text is treated as authority.

## Original and native readback

Complete local and reopened original readback occurs after selected connection
close, after fixture cursor reference release and after fixture peer close in
both controls. Each retains one exact original, charge/event sequence 1 and zero
synthetic effects. The original database bytes remain exact. Probe bytes, mode
0600, checkpoint stat identity and directory entries remain exact at these
checkpoints; probe rows remain the three original values. Checkpoint comparisons
prove neither atomic path continuity nor race resistance.

Fixture cleanup is explicitly separate from native owner close and original
operation accounting. It performs no further owner close, closes the peer once
and remains registered for failure cleanup. No observed state grants permission
to allocate, refund, retry, replace, recover or perform a protected effect.

## Validation and unresolved gates

A private two-case native probe passes before the public tests are constructed.
One focused run passes two explicit methods in 0.022 s (runner 0.25 s), with
ResourceWarning treated as an error, no skips or failures. No focused source
correction or later test-source change occurs at this initial snapshot. The local
profile reports CPython 3.12.14 and SQLite 3.53.1. Source-build/runtime identity
is **NOT VERIFIED**; source-consistent explanation is distinct from observation.

All 2292 prior method IDs must remain, with two disjoint additions for 2294. All
336 prior sources must remain exact, with one new test source for 337. The
selected guard remains byte-exact. Complete final-source regression,
artifact/privacy checks and fresh hosted checks remain pending at this initial
snapshot. Full Rust/Go/Linux/Apple profiles are not rerun locally.

The first private source-freeze helper exits before writing a publication state:
it incorrectly applies the historical Stage 118 publication-helper failure
counter to Stage 119. Its original source, output and result remain private and
exact. A separate corrected helper checks the historical counter against Stage
118 and the zero current counter against Stage 119. This correction changes no
public test source and performs no focused test or full-regression retry. Its
actual result is a separate acceptance gate.

A separate private result reader runs prematurely while that corrected helper is
still executing and observes FileNotFoundError. Its original stdin source and
exact tool-output copy remain private. The complete regression starts before the
corrected helper result becomes available; the corrected helper subsequently
passes. Exact source pins are checked again before accepting regression. No
test source changes, cancellation, focused retry or regression retry follow.

The first private local finalizer also exits before recording local qualification:
a later loop variable shadows its digest function. Its original helper source,
output and result remain exact. A separate derived helper corrects the variable
name. No public test source correction or full-regression retry is performed;
the corrected finalizer is checked separately before publication.

Unresolved gates include exhaustive subordinate resource ownership, admitted
driver identity, application exception priority/cancellation policy, interruption,
natural I/O faults, signals, process termination, BLOB/backup objects, fork/thread
behavior, malicious native drivers, custody, restore resistance and physical
durability. No private native-pointer instrumentation or independent worker/
native-profile assessment is added. A peer's selected successful lock acquisition
is not permanent availability or global native resource destruction.

Original failed local/hosted evidence remains preserved, including the Stage 117
initial 12-method failure and its previously unestablished before-rollback
checkpoints, the Stage 118 publication-helper failure and separate correction,
and Stage 119's two read-only inspection misses. The original failed main CI
archive remains exact with original child cause **UNRESOLVED**. None is rewritten
as success or as a failure of this new qualification. No deployment, activation,
wallet access, signing, broadcast, real funds or application/core integration is
authorized by these controls.

One complete frozen-source local run passes all 2294 exact unique methods in 977.692 s
(runner 978.147 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2292 prior IDs remain; 2 disjoint IDs are added. One focused run
passes 2 methods with no source correction or later test-source
change. All 336 prior sources and 572 prior files remain exact. One
new test source brings the inventory to 337. There are 576 files
and 1152 index/worktree artifact versions. No final-source regression
retry occurs. Full Rust/Go/Linux/Apple profiles are not rerun locally.
Fresh hosted checks and independent assessment remain separate gates.
The original Stage 117 failed focus and Stage 118 helper failure remain preserved;
their separate corrections are not failures or retries of this qualification.
Earlier failed private observations and the original failed main
archive stay exact; the original hosted child cause is UNRESOLVED.
