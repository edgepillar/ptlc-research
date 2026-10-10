# NoM observation conformance validation scope

Additive subject on preserved baseline
`b64bc44719c602e5f23f5a3eb32317b1b0d3ccce`. Application/core remain **NO-GO**;
independent construction/runtime/authority assessment, signed originals,
canonicality/finality and journal admission remain unfilled.

## Selected local source and directed comparisons

The unchanged exact PR #138 source
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced` matched 16 stateful method cases,
14 selected verifier-helper cases and four VM finalization/header cases.
All 34 subtests plus three parents and three package passes were required.
The source remained clean at the same commit/tree before/after; selected file,
fixture, overlay, driver and tool hashes were compared during each run.

Stateful methods used the source account-storage wrapper over disposable memory
with supplied time/chain context. Create stored the computed send hash and complete
terms. The old synthetic witness was rejected for that created id. Valid witness
cases were explicitly seeded old entries, separate from created funding.
Verifier helpers used supplied ledger/confirmation/receive state; VM finalization
used frontier/momentum/patch stubs. None ran full account admission, dispatcher,
balance accounting, canonical inclusion or a funded swap.

The 23 directed Python tests passed across 48 structural controls and event-claim
evidence parsing. Matching forgery and self-selected fork controls still matched
without authentication or recovery authorization. Missing histories stayed
incomplete. Known-height acknowledgement hash mismatches were refused and compared
separately with the source verifier helper. The earlier 44 wire subtests plus
their parent still passed, with their corpus and node pin preserved.

Locked native suites passed 177 primary Rust tests and 14 separate synthetic
handoff tests, examples and both formatting checks. Standalone Go modules passed
47 legacy, eight Bitcoin and three PR #138 top-level tests. Actual public NoM
recovery, declared module-content checks and separate full core module-content
verification passed offline. Normative node module files and the selected expanded
acquisition checksum profile remained unchanged.

## Full regression and hosted acceptance

The final complete Python 3.12.14 regression ran 2,403 tests with required
OpenSSL, zero skips and zero ResourceWarnings. All 403 selected code, fixture,
CI and test files retained their hashes across the run. Final staged/index/worktree
artifact checks covered 1,308 versions of 654 tracked files; whitespace checks
passed.

Fresh PR workflow and separate published-main workflow remain acceptance gates.
Final hosted results and original console-archive integrity are recorded separately
in the PR integration record. Private hosted command streams are ephemeral and
not in console archives; their durable custody remains unqualified.

Overlay vet is explicitly unperformed. The selected Go tool, build cache,
environment and host remain trusted. Successful event parsing, matching digests,
source execution and regression are not runtime attestations or independent
protocol/authority assessment.

## Preserved intermediate failures and interruption

The first directed Python run failed because no explicit JSON depth bound existed.
The first native attempt failed compilation because the synthetic timestamp field
needed a pointer. The next attempt used raw memory storage without the source
account-storage missing-key wrapper, causing incorrect absence checks and a
panic on an unknown entry. The corrected attempt used the source wrapper and
passed; original command/output/outcome records remain private and unchanged.

An intermediate complete-suite attempt was deliberately interrupted before
changing its source subject to add known-height acknowledgement hash bindings.
It exited on SIGINT with no complete summary and is not a passed regression.
The corrected full run is a separate subject/result. Historical failures and both
initial dependency-acquisition failures remain retained; their causes are not
reinterpreted from this iteration's successes.

Final staged whitespace validation rejected an extra blank line at the end of
one directed test file. Its normalization changed no compiled test code, protocol,
fixture or driver. The final-byte complete regression is a separate retained
result from the earlier completed run.

No existing journal policy, retained original, worker review subject or locked
cryptographic construction was changed. Source comparisons and unsigned structural
claims authorize no transaction replacement, signing, broadcast, activation,
wallet access or funds.
