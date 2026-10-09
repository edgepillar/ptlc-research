# Stage 115: retained reservation BEGIN interruptions

This is offline synthetic qualification. Protocol requirements, construction
choices and observed implementation behavior remain separate. Independent
assessment is absent; application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/d76bb476ccc8cba9310d941b708a7931356e3a52).
Its [separate main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/37954720000)
pass all eight jobs. That result qualifies the preceding research snapshot;
fresh candidate regression and hosted checks remain separate gates.

## Selected boundaries

Twelve methods select three primary interruption kinds, two BEGIN boundaries
and direct or original actor constructor entry. The kinds are
sqlite3.OperationalError, OSError and KeyboardInterrupt. Before-BEGIN selection
raises before forwarding SQL; after-BEGIN selection first forwards one
successful native BEGIN IMMEDIATE and then raises the chosen primary.
These selections do not establish natural native BEGIN failures or arbitrary
interruption inside SQLite.

Each case retains a previously charged original and a separately reserved empty
file. Successful native exclusive creation and descriptor close precede a
selected URI EIO. That same reservation is carried into the explicit followup
without cleanup, replacement or reconstruction. Native connect and required
PRAGMAs are forwarded. The followup uses no provisioning profile, and schema
validation is never reached.

## Focused observations

One focused final-test-source run on the accepted base passes all twelve methods
in 0.081 seconds (runner 0.25 seconds), with ResourceWarning treated as an error,
no skips or failures. The candidate test source is unchanged from the preserved
private preparation. Earlier focused observations on the preceding base are
not substituted for this execution.

Eight SQLite/OSError selections yield the exact StoreOutcomeUnknown class with
the chosen primary as context, no explicit cause and suppressed context.
Four cancellation selections rethrow the exact primary KeyboardInterrupt.
Chosen primaries have no context or cause and do not suppress context.
Constructor disposal receives the outward outcome unchanged.

Every selected followup invokes the rollback helper twice: transaction exception
handling and constructor disposal. Those calls are counted separately from
successful native SQL ROLLBACK. Six before-BEGIN cases execute no native BEGIN
or SQL rollback; six after-BEGIN cases execute one successful native BEGIN and
one successful SQL rollback.

Each selected followup connects once, disposes once and successfully closes the
native connection once. Private closed state is true and busy state is false;
database object, owner and labels remain exact. A separate native SELECT probe
raises ProgrammingError after close. Fixture cleanup owns no native handle and
performs no additional native close. The constructor never returns, allocates
or invokes public close. Actor observer installation is not reached, and actor
stdout is empty; child diagnostic delivery is not exercised.

Original bytes, reservation bytes, directory entries, mode 0600 and checkpoint
stat identity are checked before complete local and reopened original readback.
One original and charge/event sequence 1 remain, with zero synthetic effects.
Checkpoint identity does not establish atomic path continuity or race resistance.
Owner and label checks establish selected local state, not protocol authority.

## Remaining gates and limits

All preceding 2208 method IDs must remain, with twelve disjoint additions for
2220 total. The new test adds one source for 331; all preceding 330 sources
must stay exact. Complete final-source regression, artifact checks and fresh
hosted checks remain pending at this initial snapshot.

The preceding private measurement failure, its original source and diagnostic,
the separately corrected measurement and earlier focused run remain preserved.
The prior main workflow failure and its original full archive also remain
preserved; the original hosted child cause stays **UNRESOLVED**. No failed
source, log or archive is removed or reclassified as success.

No store, actor, worker, admission, cryptography or CI workflow behavior changes.
Rollback/close compound failures, natural I/O faults, descriptor/symlink races,
arbitrary paths, signals, child delivery, authenticated diagnostics, restores,
physical durability and current-policy authority remain unqualified. No result
authorizes another payment attempt, replacement, automatic recovery, signing,
broadcast, deployment or physical effect. Application/core remain **NO-GO**.

One complete frozen-source local run passes all 2220 exact unique methods in 961.556 s
(runner 962.018 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2208 preceding IDs remain; twelve disjoint IDs are added. One focused
run passes twelve methods on the accepted main base, with no later test-source
change. All 330 prior sources and 561 prior files remain exact. There are 564
current files and 1128 index/worktree artifact versions. No final-source
regression retry occurs. Full Rust/Go/Linux/Apple profiles are not rerun
locally. Fresh hosted checks and independent assessment remain separate gates.
Earlier failed measurements and the original failed main archive remain
preserved; the original hosted child cause stays UNRESOLVED.
