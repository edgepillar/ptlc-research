# Composed NoM VM path validation

Research baseline: `07df9a96e0ac9caf71dfa0ad7d40f001207baaa8`.
Application/core remain **NO-GO**. See [scope and remaining gates](NOM_VM_PATH.md).

The directed Python run passed 20 evidence/parser tests with zero skips and
ResourceWarnings. The directed unchanged-core run passed 58 tests including
parents: 32 VM controls and 24 verifier controls over both preserved funding
legs. It emitted 32 complete public block/accounting records, independently
rehashed them in Python and carried actual VM receive patches into the selected
source verifier. That verifier refused both actual post-receive markers. Both
raw VM replay controls credited twice when admission was intentionally bypassed.
This is an admission-boundary counterexample, not a consensus exploit claim.

Two initial qualifier attempts failed and remain retained privately. The first
attempt was refused before native launch because it used labels outside the
frozen command custodian's selected set. The second passed all 33 VM tests but
the collector tried to decode a fragmented long Go output line as one complete
JSON record. The collector now reassembles bounded output under exact test
identity. The first Python parser run also failed its test-switch control:
unselected continuation output could be ignored. Interleaved record subjects
are now refused. The subsequent complete directed runs passed. No earlier
failed run or historical CI archive is relabeled as success.

The complete local Python 3.12.14 suite passed 2,595 tests with required
OpenSSL, zero skips and zero ResourceWarnings, including the 20 new controls and
149 preserved retention/authority/opening/created controls. All 438 selected
code/fixture/CI/test hashes stayed unchanged through regression, and all 689
preserved base files remain unchanged. Both locked Rust suites passed 194 tests;
examples and both format checks passed. Standalone Go suites passed 58 top-level
tests. Prior source momentum/wire/observation/created comparisons passed
51/45/37/71 tests including parents, and the composed path passed 58. Both public
recovery qualifiers and complete offline core module-content checks passed with
normative source/module files unchanged. Staged artifact checks cover 1,402
versions of 701 files; whitespace checks pass. Generic unsigned UTC commit
metadata and the exact publication destination are reviewed separately.

Complete local regression, original hosted PR archives and exact-head acceptance
are separate requirements before main integration. Main integration must preserve
history; push-triggered main checks and complete original archive verification
are a further gate. Green PR CI is not a main result or runtime admission proof.

There is no full account admission, supervisor/plasma qualification, outer
account signing, authenticated source/state proof, canonicality/finality,
nonrollback current/restore mechanism, atomic recovery entry, live chain
observation or independent security assessment. The two legs use independent
synthetic ledger/spork/frontier selections. Real memory-store balance changes
and selected receipt guards narrow a previous gap but do not qualify a complete
swap protocol. Separate source patch hashes are not account-hash inputs or
authenticated state proofs. Tool/cache/runtime/host remain trusted. Overlay vet
is unperformed. Hosted private command streams/patches remain ephemeral unless
separately retained; original console archives contain summaries only. No
deployment, activation, wallet access, broadcast or real funds are performed.
