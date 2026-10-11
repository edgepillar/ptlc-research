# Account context validation record

Status: additive Stage 0 research. Application and core remain **NO-GO**.
The selected public account verifier entry points use explicit synthetic ledger
views, actual memory stores and actual VM recipient patch handoffs. Complete
node admission, authenticated observations and signed journal composition are
not performed.

## Preserved failures and corrected attempts

- The first harness attempt selected an unsupported native command label. The
  preserved authorization/VM rerun completed, but the new overlay did not run;
  that attempt is `FAILED_OR_INCOMPLETE` and is not accepted.
- The second attempt entered the unchanged source context path for a funding
  original with a missing predecessor and empty global account frontier. It
  stopped on a source panic. The original native streams and failed test identity
  remain preserved. No source patch or fabricated frontier was supplied.
- A test-only wrapper subsequently records those exact empty-frontier controls
  as `SOURCE_PANIC`, separately from normal refusal errors. All other control
  outcomes must still match their independently selected expectations. Passing
  an expected-panic test is not source admission or a live-node finding.
- The third bootstrap completed the native controls but its Python projection
  incorrectly required a nonempty dump for a genuinely empty memory store.
  That projection failure is preserved and is not accepted. The corrected
  projection retains the exact empty bytes and their SHA256, without inventing
  history or changing the existing dump/parser helpers. A directed regression
  requires this empty-state behavior explicitly.
- The first directed Python run passed 35 controls and failed one duplicate-field
  fixture assertion: its mutation targeted an unescaped string inside an escaped
  Go event envelope and therefore did not modify the input. The corrected test
  injects a duplicate inside the decoded output before reencoding the event.
  No source or production parser behavior changed. The original failed stream
  and exact failed test source remain preserved separately.
- Subsequent failed runs, if any, must remain preserved separately; corrected
  qualification must require fresh source execution and complete exact output.

## Required checks

Complete Python 3.12.14 regression passed 2,737 tests with required OpenSSL,
zero skips and zero ResourceWarnings. All 36 new controls and 275 preserved
directed controls passed; all 311 exact identities occur in the complete stream.
All 460 selected code/fixture/CI/test hashes and 724 preserved baseline files
remained unchanged. Both locked Rust subjects passed 194 tests, with fresh
examples and both format checks. Standalone Go suites passed 58 top-level tests
with normal vet. All preserved source and public recovery comparisons passed.
The new qualifier required 185 fresh preserved authorization/VM tests plus
85 new tests and all 84 exact context records; actual VM recipient patches and
twelve source roles were retained. Eight expected source-panic controls are
explicit non-admission observations. All twenty native steps and complete
offline core module-content checks passed. Index/worktree artifact checks cover
1,468 versions of 734 files; whitespace checks pass. Publication metadata,
exact destination and hosted acceptance remain separate subsequent checks.

Fresh exact-head PR checks and whole original CI archive inspection precede
normal history-preserving main integration. Push-triggered main checks are a
separate gate. The final hosted evidence belongs to the PR acceptance record;
this document does not claim future hosted success.

No new worker, application signer, transaction builder, observation authority,
recovery journal interface or core modification is introduced. All independent
construction, source/runtime, canonicality, finality and restore requirements
remain unfilled. Prior failed evidence and original CI archives remain unchanged.
