# Stage 89 validation snapshot

Status: local macOS and portable qualification passed. New hosted qualification
is pending. Application and core progression remain **NO-GO**. The parent is
`242a75cbc0152b5047d13aa4f77a8a83f7026764`.

The [partial-signing cut map](PARTIAL_SIGNER_FAILURE_CUTS.md) separates local
reservation, consumed admission, ephemeral secret ownership, output retention
and exact replay. No real signer, entropy or nonrollback construction is selected.
Managed adaptor completion is a later, distinct boundary. The false witness-
exposure flag does not establish nonce safety.

## Local qualification

- Final targeted run: all three new unique methods passed in
  5.796 s; runner 5.865 s. The
  [test](../tests/test_partial_journal_boundary.py) and
  [child actor](../tests/partial_journal_actor.py) cover 44 actual SIGKILL
  schedules, eleven per role/leg scope, including both consumption and output
  commit occurrences. Eight separate copied-history/restore subcases each permit
  exactly two synthetic callbacks across histories while retaining one-use refusal
  inside each history. Callbacks return fixed public bytes, with no nonce
  generation, private signing, adaptor completion or key extraction. These are
  expected negative controls. SIGKILL does not qualify power-loss durability.
- Completed full offline Python run: 2035 unique IDs passed, retaining all 2032 prior
  IDs and adding exactly three, with required OpenSSL in
  1252.926 s; runner 1253.324 s. Zero
  skips, failures or ResourceWarning lines. All 35 sealed and twelve measured
  adapter method bodies retain exact source bytes.
- Actual public exchange run: all twenty preceding methods passed in
  12.980 s; runner 13.049 s,
  using the cached selected worker. Five Linux sealed schedules explicitly refuse
  the unsupported Apple host; the ELF observer separately refuses the Mach-O
  worker. These are refusals, not skips or actual local Linux/ELF qualification.
- Artifact hygiene: 986 index/worktree versions across 493 tracked files. All
  1700 relative file links resolve. Of 489 preceding files, 485 retain exact
  bytes and four documents are append-only; four files are added. All 295
  preceding non-document files are unchanged, including workflow, implementation,
  native actors, fixtures and dependencies. All 297 current non-document files
  remain frozen through qualification.
- Full Rust, Go and Linux/Apple worker profiles are not rerun locally for this
  test-only slice. Their byte-exact sources get separate exact-head hosted checks;
  those results are still pending in this pre-publication snapshot.

## Honest run and review accounting

One read-only guessed process-test path lookup missed before edits; file discovery
located the actual source. One native qualification invocation used the wrong
command-line option and exited before any tests. The original log/result is
retained; the corrected option then ran the complete twenty-method exchange suite.
One private publication-verifier preparation assertion stopped on a preceding-
stage document filename. Only that helper was corrected and parsed before hosted
inspection; its original error is retained.

The initial targeted run passed three methods in 5.808 s,
but source review found that an assertion inside a forbidden callback could be
wrapped as the expected journal exception. One new test assertion was corrected
to count callback invocations outside that wrapper. The first full run was
explicitly interrupted with SIGINT before this correction; its original log and
exit -2 are retained. The corrected targeted suite was rerun once and the full
regression was restarted once. No test failure, production source/build repair
or hidden native fallback occurred. The initial targeted pass is not substituted
for final-source qualification.

A separate author-side in-memory control for one synthetic Zenon/Alice operation
deliberately invoked the producer despite a spent record. The earlier assertion
trap was hidden by the exception wrapper; the corrected external counter detected
the bad invocation. The unmodified journal still refused it. This expected
negative control changes no repository source and executes no cryptography.

Four fixed inventories, the earlier author handoff inventory and three unfilled
independent reports retain exact bytes. No reviewer contact or review request is
made. Source-to-worker and reproducibility remain **NOT VERIFIED**; private
consumed inputs, producer origin and loaded runtime remain **NOT AUTHENTICATED**;
independent privacy remains **NOT ASSESSED**. No artifact release, wallet, funds,
chain, broadcast, deployment, activation, merge or core action is qualified.
