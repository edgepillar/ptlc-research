# NoM momentum conformance validation

Status: offline research; application/core **NO-GO**. This subject preserves the
recovery journal, original construction and old wire/observation inputs.
Independent construction, authority, runtime authentication, canonicality,
finality and durable reorg custody remain unfilled.

## Selected corpus and execution

- 24 raw momentum/content/header hash vectors.
- 32 branch/inclusion controls, including matching unauthenticated claims.
- 8 conservative reorg retention/recheck plans without storage or state mutation.
- 26 actual source controls with explicit synthetic context/account stubs.
- 23 directed Python tests; actual Go execution is a separate gate.

The new Go overlay must report 50 subtests plus its parent and one package pass.
No full chain admission, changes execution, dynamic content pricing, producer
election or live funding is performed. Source comparisons are static helper
qualification; public headers are opaque claims, not a composed account flow.

The generator is deterministic and uses no signer. Source/version claims pin
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; the separate acquisition checksum
profile is preserved, with normative node module inputs unchanged.

```sh
python3 -B scripts/generate_nom_momentum.py
python3 -B -m unittest tests.test_nom_momentum tests.test_nom_momentum_core_evidence -v
python3 -B scripts/qualify_nom_momentum_core.py --checkout CORE_CHECKOUT --go SELECTED_GO
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
git diff --check
git diff --cached --check
```

Run the locked offline Rust suites/examples/format checks, standalone Go suites,
preserved source differentials and public-worker recovery separately. Select a
complete local core module cache with network disabled. The selected compiler,
environment, cache and host remain trusted. Overlay vet is not performed.

## Acceptance record

The complete local Python 3.12.14 regression ran 2,426 tests with required
OpenSSL, zero skips and zero ResourceWarnings. All 411 selected code, fixture,
CI and test files retained their hashes across the run. Both locked Rust suites
passed 191 tests, examples and format checks; the standalone Go suites passed
58 top-level tests. Actual momentum/wire/observation source comparisons passed
51/45/37 selected tests including parents, and public-worker recovery passed.
The separate complete core module-content check ran with network disabled;
normative module files and the expanded acquisition checksum profile were unchanged.

Final staged/index/worktree artifact checks covered 1,328 versions of 664 files;
worktree and staged whitespace checks passed. An initial directed evidence test
had an incorrect preserved-file count assertion; its failed stream was retained,
the assertion corrected and the complete final-byte regression ran separately.
A manifest preparation attempt used a missing source filename; no core execution
or mutation occurred in that attempt. Its diagnostic summary is retained privately.
Fresh hosted PR and separate push-triggered main CI, exact published head/tree,
history preservation and complete original console archives are separate
acceptance gates. Native private streams on a hosted runner are ephemeral and
are not made durable by preserving its console archive. Failed/intermediate
evidence must be retained and never relabelled as a successful final run.
