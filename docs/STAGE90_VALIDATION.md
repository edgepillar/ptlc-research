# Stage 90 validation snapshot

Status: local macOS and portable qualification passed. New hosted qualification
is pending. Application and core progression remain **NO-GO**. The parent is
`b86af7abcf575ad900fa5bf7fb5b85788d181126`.

The [selected synthetic native handoff](NATIVE_PARTIAL_JOURNAL_HANDOFF.md) orders
journal consumption before the existing native partial-signing primitive, with
fixed public test keys and seeds only. No real signer, entropy, durable custody
or independent nonrollback construction is selected. Its peer assertion is not
an authenticated admission grant. Managed completion is a later boundary.

## Local qualification

- First targeted nonce-lifecycle run: twelve methods passed, seven retained and
  five new, in 3.041 s including runner/build time. The
  [Rust tests](../qualification/tests/nonce_lifecycle.rs) and
  [Python actor](../tests/native_partial_journal_actor.py) select 32 owners and
  producer admissions in 24 child runs across four role/leg scopes: 24 valid
  synthetic native partials, four wrong-key backend refusals and four before-
  backend refusals. This defines 28 signing backend entries. Only the exact
  existing public partial fixture crosses the pipe.
- Actual native result loss is selected before delivery: the computed public
  partial is discarded, the reopened journal becomes `OUTCOME_UNKNOWN`, and the
  original native owner is spent. This is not SIGKILL, native process death or
  power-loss evidence. Eight separate copied-history/restore subcases reconstruct
  deterministic native owners and repeat the same nonce/partial while each
  original owner refuses local reuse. No changed-message key extraction or live
  opaque secret cloning is executed.
- Complete local Rust run: 177 unique methods passed, retaining all 172 prior IDs
  and adding exactly five, in 15.188 s including runner/build
  time. Zero failed or ignored tests and no compiler warning lines. Formatting
  passed. All preceding owner/function/test bodies remain exact after the
  two-line file header update; new helpers and methods are appended.
- Completed full offline Python run: all 2035 unchanged unique IDs passed in
  1277.536 s; runner 1277.997 s,
  with required OpenSSL. Zero skips, failures or ResourceWarning lines. All 35
  sealed and twelve measured-adapter method bodies retain exact source bytes.
  The preceding 44 SIGKILL schedules and eight synthetic-callback copy/restore
  subcases remain a separate retained scope.
- Actual public exchange: all twenty preceding methods passed in
  13.829 s; runner 13.913 s,
  with the cached selected worker. Five Linux sealed schedules explicitly refuse
  the unsupported Apple host and the ELF observer separately refuses Mach-O.
  These are refusals, not skips or actual local Linux/ELF qualification.
- Artifact hygiene: 992 index/worktree versions across 496 tracked files and
  1717 resolved relative file links. Of 493 preceding files, 488 are
  byte exact, four documents are append-only and one native test file retains its
  prior body after the header update; three new files are added. All 296 other
  preceding non-document files are exact and all 298 current non-document files
  are frozen. Journal and primitive implementation, fixtures, dependencies,
  preceding Python tests/actors and workflow remain unchanged.
- Go and complete Linux/Apple worker profiles were not rerun locally for this
  test-only slice. Separate exact-head hosted qualification remains pending in
  this pre-publication snapshot; those results must be assessed separately.

## Run and independent review accounting

Two read-only guessed path lookups missed: a workflow filename before
implementation and a private preflight-proof filename after local qualification.
The actual discovered filenames were then read. One private preflight summary
retained the preceding-stage numeric label despite guards bound to this candidate;
the label was corrected before final preflight and original evidence is retained.
No failed qualification invocation or test execution, source/build repair,
interrupted full run, hidden fallback, targeted/full-suite rerun or failed private
verifier preparation assertion occurred.
Original logs and results remain retained. The case inventory is source-defined;
execution evidence is the five exact successful native methods, not an inventory
count by itself.

Four fixed independent inventories, the earlier author handoff inventory and
three unfilled reports remain byte exact. No reviewer contact or review request
is made. Source-to-worker and reproducibility remain **NOT VERIFIED**; private
consumed inputs, producer origin and loaded runtime remain **NOT AUTHENTICATED**;
independent privacy remains **NOT ASSESSED**. No artifact release, wallet, funds,
chain, broadcast, deployment, activation, merge or core action is qualified.
