# Stage 101 control-frame refusal validation

Status: **FIXED CONTROL-FRAME FOCUS AND COMPLETE LOCAL REGRESSION PASS;
FRESH HOSTED QUALIFICATION PENDING AT THIS LOCAL SNAPSHOT.** Application/core remain NO-GO.

## Subject and change

The immutable parent is `0eb96fe71c897cd9e20ad811494a8d298a73baa7`, tree
`f97379a795b93a525d9bd8fa7014bde34ee70163`. This stage deliberately revises
the separate observed helper and its test harness. It does not claim those two
preceding files remain byte exact. The original store, original actor, original
tests and required `[0,20]` / one-retained-original assertions stay unchanged.
Workflows, dependencies, fixtures, review packets and custody proposals stay
unchanged. No third-party implementation is copied.

The [experiment note](POLICY_EFFECT_CONTENTION.md#fixed-control-frame-refusal)
corrects the broader Stage 100 framing claim. A bounded byte read accepts only
the fixed LF-terminated frame. A retained flag prevents a transactional cut's
framing exception from qualifying as an unknown store result after the store
has performed its own unchanged rollback or commit handling. The README's
complete-suite minimum is aligned to Python 3.11; older recorded scopes remain
historical evidence.

## Failing regression and focused result

Four new invalid-frame methods first ran against the unchanged parent helper.
Initial-frame cases passed; the six inputs at each of three transactional cuts
failed the required helper-exit assertion: 18 subtest failures in three methods,
four methods executed in 3.125 s (runner 3.362 s). Complete source and log remain
retained. This red run did not execute the separate open-pipe read-bound method
and did not reach row assertions in the failing subcases.

After the helper fix, all 13 contention methods passed in 5.325 s (runner
5.447 s): the eight preceding methods plus five disjoint additions. The added
methods assert 28 child executions in separate databases. Twenty-one cases
retain zero charges; seven postcommit cases retain one. None applies an effect.
Exact original lookup, raw counts, complete local view and reopen are inspected
after bounded child termination. One method proves refusal of an invalid
four-byte frame while input is still open and has no newline, at all four cuts.
This is not a guarantee that shorter partial frames cannot wait for input.

The selected local runtime is Python 3.12.14 / SQLite 3.53.1. There were no
focused skips, errors or ResourceWarning lines after the fix. The successful
focus does not resolve the historical Stage 99 cause, which remains UNRESOLVED.

## Remaining acceptance scope

The first complete local suite passes all 2083 exact unique methods in
1011.548 s (runner 1012.141 s), with required OpenSSL and no
skips, failures or ResourceWarning lines. All 2078 preceding method IDs remain
with five disjoint additions. All 316 current non-document sources are frozen;
314 remain byte exact and the two deliberate revisions are explicit. Of 534
preceding files, 530 remain exact and four are modified; one new document gives
535 files. Artifact checks pass 1070 index/worktree versions and 1902 resolved
relative links. Both historical author packets, four fixed inventories, three
UNFILLED reports and the license remain exact. One read-only lookup missed an
already removed Rust compiler-intermediate directory. Only rebuildable Go
compiler cache was removed to recover space, preserving source and original
log/archive pins. No qualification failure or retry resulted from that cleanup.
The complete suite was run once; the red focused failure was retained.
Fresh exact-head Linux/macOS Python 3.11/3.13 and the existing Rust/Go/Linux/Apple
profiles are separate hosted scopes. Full native profiles have not been rerun
locally in this stage. Independent assessment is absent. SC01-SC12 remain OPEN;
physical F1-F4 and future A01-A12 remain NOT EXECUTED. Signer, custody,
current-policy owner and nonrollback anchor remain UNSELECTED / NOT IMPLEMENTED.
No wallet, funds, broadcast, deployed contract, node activation, hardware/cloud
custody, main merge, release or reviewer contact occurs.
