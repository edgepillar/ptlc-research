# Stage 110 constructor preconnection refusals

FINAL-SOURCE LOCAL REGRESSION PASSES; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.

The immutable parent is `cbf1b9e799071cddf65057e14a380f90ac900e87`, tree
`9f653a2481843a28873bd074dbc08957b58531db`. All 326 preceding sources,
including the original actor, store, observer and strict tests, remain byte
exact. One new source adds twelve disjoint methods. No external code is copied.
This selects existing offline guards; it changes no application, core, allocation,
cleanup or retry behavior.

Each control independently seeds one original charge, sequence 1, with no
effect. A forwarding wrapper retains the partial object and exact outward
exception while executing the real original constructor. Native file open and
SQLite connect are guarded against entry; path construction is forwarded to
the real pathlib implementation. Actual synthetic symlinks exercise native
path inspection. No SQLite failure, terminal close fault or process signal is
selected in these controls.

| Selected input | Entry | Fields before refusal | Context |
| --- | --- | --- | --- |
| Uppercase source label | Original actor | Absent | None |
| Numeric incarnation label | Original actor | Absent | None |
| Empty path string | Original actor | Absent | None |
| Path string with 4097 characters | Original actor | Absent | None |
| Symlink to existing source | Original actor | Initialized, no database | None |
| Dangling symlink | Original actor | Initialized, no database | None |
| Inexact label object with hostile attribute hook | Direct constructor | Absent | None |
| Foreign path object with hostile filesystem hook | Direct constructor | Absent | None |
| String subclass with hostile length hook | Direct constructor | Absent | None |
| Bytearray initial profile | Direct constructor | Absent | None |
| Noncanonical complete profile bytes | Direct constructor | Absent | Suppressed decode ValueError |
| Profile with different authority namespace | Direct constructor | Absent | None |

All twelve refuse before the constructor's protected disposal guard, with
one constructor call, zero disposal/public-close/allocation calls and zero
native file-open/SQLite-connect calls. Ten have no owner, labels, busy, closed
or database fields. Two symlink cases have fields, false busy/closed flags and
a None database. No constructor returns a usable store; test-only partial
objects do not establish a live handle. Foreign hooks are never executed.
The exact outward StoreRefused object is retained, with no explicit cause.
Suppressed context does not prove a delivered diagnostic.

Only the six actor cases assert empty actor output and no observer installation.
They classify output separately with unavailable process status. Direct cases
do not qualify actor provisioning or acceptance of arbitrary path objects.
Before any readback, every case checks unchanged original database bytes and
directory entries. Existing/dangling symlinks are preserved and the missing
target stays absent. Independent local and reopened readback agree: one raw
operation, one complete retained original, charge sequence 1, no effect
sequence, one charged operation, zero effects and event sequence 1.

The first focused run executes twelve methods in 0.049 s (runner 0.207 s):
eleven pass and one new symlink expectation fails because it compares a
resolved alias with an unresolved temporary-directory path. Its original
source/log/result are preserved. Resolving both paths corrects only the new
test assertion. One corrected run passes twelve methods in 0.049 s (runner
0.172 s), required OpenSSL, no skips or ResourceWarnings. Complete final-source regression is recorded below; source preservation
and artifact hygiene remain separate gates.

The [scope note](POLICY_EFFECT_CONTENTION.md#constructor-preconnection-refusals)
excludes symlink races, native path errors, signals, child status, arbitrary
input coverage, authenticated delivery, restored copies and physical durability.
No observation authorizes replacement, retry, refund, nonce allocation,
signing or a physical effect.

Stage 99's original failure cause remains UNRESOLVED. SC01-SC12 remain OPEN;
physical F1-F4/future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy ownership and a nonrollback anchor remain UNSELECTED /
NOT IMPLEMENTED. Independent assessment is absent. Application/core remain
NO-GO; this is offline synthetic research.

One complete frozen-source run passes 2171 exact unique methods in
986.292 s (runner 986.751 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2159 preceding IDs and 326 sources
remain exact; twelve disjoint methods in one new source give 327 frozen sources.
Two documentation modifications and two additions give 555 files, with 551 of
553 preceding files exact. The initial focused assertion failure and one
corrected focused run remain separately recorded. There is no final-source
full-regression or hosted-workflow retry, nor a preparatory failure at this
snapshot. Full Rust/Go/Linux/Apple profiles were not rerun locally; fresh hosted
execution and independent assessment remain separate. Prior failed sources,
logs and original archives remain preserved without cleanup.
