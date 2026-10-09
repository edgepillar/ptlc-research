# Stage 119: returned callbacks and native release

This is an offline counterexample qualification. The existing store, selected
cleanup guard, actor, worker, cryptography and CI workflow remain unchanged.
Independent assessment is absent; application/core remain **NO-GO**.

The base is [the accepted research main commit](https://github.com/edgepillar/ptlc-research/commit/0b473b509ba91713a9e6913e820bc69afc26daaa).
Its [independent main-push checks](https://github.com/edgepillar/ptlc-research/actions/runs/37995177015)
pass eight jobs. The unchanged
[selected guard](https://github.com/edgepillar/ptlc-research/blob/0b473b509ba91713a9e6913e820bc69afc26daaa/qualification/selected_cleanup.py)
reports callback return or escape separately from actual native release. Its
first-exception policy is experimental and is not an application policy choice.

## Requirement, construction and observation

The candidate requirement is to avoid interpreting callback completion as
trusted native release. No new cleanup construction is selected here. Four
materially distinct controls compare callback outcomes with separately measured
native SQL rollback, native close, handle availability and fixture release.

| Selected callbacks | Callback report | Native state before fixture cleanup |
| --- | --- | --- |
| Both return without forwarding native calls | Both returned | Owned, available and active; journal retained |
| Rollback forwards; close returns without forwarding | Both returned | Owned and available, inactive; no journal |
| Rollback escapes before forwarding; close returns without forwarding | Rollback escaped, close returned | Owned, available and active; journal retained |
| Both forward their selected native calls | Both returned | Native handle closed; no fixture release required |

All four invoke one rollback callback and one close callback. The first two and
the fourth share the same returned/returned report despite distinct native
outcomes. Nonforwarding callbacks return synthetic claims; those values are
discarded and are absent from report repr. The status is an observation of a
callback, not authority to retry, allocate, recover or perform a protected effect.

The selected original OSError propagates as the exact same object in all four,
with absent context/cause and no suppression. The selected rollback OSError is
retained separately with the original primary as context. Callback-active
exception observations retain the original primary. Stdout and stderr remain
empty; synthetic diagnostic and return-claim markers are absent from report
repr. These observations do not establish general redaction or secure erasure.

## Native and original readback

Each control retains an empty reservation after successful exclusive creation
and descriptor close followed by a selected initial URI EIO. The same file is
opened with native SQLite, DELETE journal mode, synchronous EXTRA and foreign
keys. One successful BEGIN IMMEDIATE precedes the selected original failure.

Callback entry and forwarded native calls are counted separately. The three
nonforwarding close controls retain an owned handle that accepts SELECT 1 before
fixture cleanup. Two retain an active transaction and journal; the forwarded
rollback control is inactive. Only the separate fixture close releases those
three handles. The forwarding comparison performs one native SQL rollback and
one native close; a SELECT already refuses before fixture cleanup, which performs
no further close. Final closed SELECT readback checks the exact ProgrammingError
class, absent context/cause and no suppression. This is native behavior in the
selected controls, not authenticated ownership or an unconditional release rule.

Original bytes, empty reservation bytes, mode 0600 and checkpoint stat identity
remain exact before and after fixture cleanup. Journal presence and directory
entries are observed separately, including removal after explicit fixture close.
Complete local and reopened original readback is measured both before and after
fixture cleanup in all four: one retained original, charge/event sequence 1 and
zero synthetic effects. Checkpoint identity proves neither atomic path continuity
nor race resistance; fixture cleanup is neither guard cleanup nor recovery.

## Validation and unresolved gates

Four explicit methods pass in 0.028 seconds (runner 0.175 seconds), with
ResourceWarning treated as an error and no skips or failures. No focused source
correction or later test-source change occurs at this initial snapshot. The
selected guard remains byte-exact. All 2288 prior IDs must remain, with four
disjoint additions for 2292; all 335 prior sources must remain exact, with one
new test source for 336. Complete final-source regression, artifact/privacy
checks and fresh hosted checks remain pending at this initial snapshot. Full
Rust/Go/Linux/Apple profiles are not rerun locally.

The earlier unsafe store cleanup behavior remains measured and unchanged.
Application exception priority, cancellation behavior, reliable native-release
evidence and integration requirements remain unresolved. These selected no-op
counterexamples do not qualify malicious/recursive callbacks, guard reset or
cloning, arbitrary interruption, natural I/O faults, signals, process termination,
fork/thread behavior, authenticated ownership, restore resistance, custody or
physical durability. No new independent native-profile or worker-identity
assessment is performed.

Original failed focused, private helper, measurement, permission and read-only
API evidence and the original failed main CI archive remain preserved. The
Stage 118 publication-helper failure and its separate correction remain distinct
from this new source qualification. The original hosted child cause stays
**UNRESOLVED**. No result authorizes signing, broadcast, deployment, a new
payment attempt, replacement, automatic recovery or physical entry.

Two read-only source-inspection commands fail during preparation: one filename
lookup and one shell glob expansion. Their original command sources and output
remain private and separate from the qualification. Inventory-based readback
succeeds; no public source correction, test retry or workflow rerun follows.

One complete frozen-source local run passes all 2292 exact unique methods in 952.797 s
(runner 953.254 s), required OpenSSL, no skips, failures or ResourceWarnings.
All 2288 prior IDs remain; 4 disjoint IDs are added. One focused run
passes 4 methods with no source correction or later test-source
change. All 335 prior sources and 570 prior files remain exact. One
new test source brings the inventory to 336. There are 573 files
and 1146 index/worktree artifact versions. No final-source regression
retry occurs. Full Rust/Go/Linux/Apple profiles are not rerun locally.
Fresh hosted checks and independent assessment remain separate gates.
The original Stage 117 failed focus and Stage 118 helper failure remain preserved;
their separate corrections are not failures or retries of this qualification.
Earlier failed private observations and the original failed main
archive stay exact; the original hosted child cause is UNRESOLVED.
