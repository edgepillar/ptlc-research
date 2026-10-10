# NoM wire conformance validation scope

This record describes the additive subject on preserved research baseline
`62935a639276927eac0f0eb900dd2a454f048f6f`. Application/core remain **NO-GO**;
independent construction, worker/runtime, signer/custody and chain-observation
requirements remain unfilled.

## Selected differential and directed controls

The exact clean PR #138 source pin
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced` matched:

- 12 canonical ABI vectors across four methods, including both public NoM leg
  completions, signed-int64 boundaries, a 33-byte point and wire-only invalid
  admission inputs.
- Seven send admission/normalization controls. Four accepted aliases normalized
  to different bytes and changed the account hash; three failed send admission.
- 22 account hash vectors, with 306-byte preimages, every selected input changed,
  uint64/uint256 maxima, empty data and ordered descendant claims.
- Three explicit helper-only counterexamples: excluded metadata hash equivalence,
  an advertised child hash retained across changed payload, and a negative amount
  sharing a positive amount's direct hash.

All **44 selected subtests plus their parent** passed in the local actual-core
overlay. The source remained clean at the same head/tree before and after.
This executes core helpers and send syntax, not the full account transaction
verifier, VM/stateful payout, network observer or private signing.

The 21 directed Python tests passed. They cover strict canonical re-encoding,
hash/ABI context and bounds, malformed/aliased inputs, exact manifest hashes,
preserved old subjects, incomplete/duplicate/failed/skipped test-result claims
and changed fixture refusal. Event-parser inputs are explicitly synthetic claims,
not independent execution or runtime attestations.

## Complete regression and publication gates

Measured final local acceptance: **2,380 Python tests passed**, with required
independent OpenSSL, zero skips and zero ResourceWarnings. The locked Rust suites
passed 191 tests; the three standalone Go modules passed 58 top-level tests.
Examples, both Rust formatting checks, actual public NoM recovery, declared
module-content verification and the fresh unchanged-node wire differential passed.
The separate full core acquisition cache passed content verification. Both index
and worktree artifact/privacy-pattern checks passed on 1,284 candidate versions.
The first complete Python run also passed; its earlier acquisition-profile
subject is retained separately from the final complete regression.

Required acceptance includes complete Python regression with independent OpenSSL,
both locked Rust suites and formatting/examples, all three offline Go modules,
module-content checks, actual public NoM worker recovery, the exact core wire
differential, artifact/index/worktree checks and manual English/privacy/metadata
review. Results are recorded separately from directed qualification.

The new native command label adds only this selected differential. Existing
native stream bounds, cleanup behavior and deadlines remain unchanged. The
previous NoM worker's 620-file frozen source subject and its 72 copied inputs,
legacy locks and all previous assessment templates are preserved.

A fresh PR workflow and subsequent push-triggered main workflow require exact
head verification and complete original console archives. They are separate
acceptance gates; this document does not label pending hosted work as passed.
The final PR integration record holds the measured publication results.

Original failed historical evidence remains retained, including the unexplained
Python 3.9 native failure. Earlier failure causes are not inferred from these
successful source comparisons. Overlay vet remains explicitly unperformed.
Hosted raw private command streams are ephemeral and absent from the archived
console output; durable custody remains unqualified.

The first additional offline core-module check failed because the shared cache
lacked part of the declared graph. Separate full-graph acquisition returned zero
but added checksum rows to copied `go.sum`, failing an initial unchanged-copy
expectation. Both original failures and acquisition streams remain private and
retained. The corrected profile pins the expanded acquisition checksum digest,
checks its contents in a separate cache and preserves the exact node's module
files. It does not relabel the initial failed checks as passed.
