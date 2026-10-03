# Stage 3 validation: public nonce rounds

Historical milestone: [Stage 4 validation](STAGE4_VALIDATION.md) records the later artifact exchange and journal v3 results. [Stage 5 validation](STAGE5_VALIDATION.md) records current completion and journal v4 results. The counts and storage version below describe Stage 3.

Scope: local offline qualification, following the historical [Stage 2 report](STAGE2_VALIDATION.md). All examples use public synthetic inputs. No wallet, real key material, RPC, network transport, node activation, broadcast, funds, public repository, or publication action was involved. Source documentation was inspected separately; verification commands used already populated offline dependency caches.

## Executed results

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode Python suite | 108 passed, 0 failed, 0 skipped | Local Python 3.9.6; real process tests on macOS |
| Pinned Rust tests | 24 passed, 0 failed, 0 ignored | 13 primitive, 4 Bitcoin transaction, 7 new nonce-owner tests; Rust 1.90.0, locked offline dependencies |
| Core-verifier Go module | Passed all 4 top-level tests | Historical PR verifier dependency, not the VM or a node |
| Bitcoin Go module | Passed all 8 top-level tests | Independent transaction/script checks, not mempool or live-chain acceptance |
| Rust/Go formatting | Passed | Existing formatters; no new dependencies |
| Artifact hygiene | Passed | Limited filename/content and staged/disk scan; no anonymity proof |

The Python total consists of 29 Stage 0 tests, 16 static transcript tests, 14 nonce-exchange tests, 36 journal tests, 9 process/recovery tests, and 4 public interoperability tests. Existing required OpenSSL verification also passed. The GitHub workflow already discovers the new tests; hosted CI was not run. The existing native Linux/macOS Python matrix remains a definition, not executed cross-platform evidence.

## Public transcript cases

The new factories reject changed roles, rounds, chain bindings, swapped/reflected openings, identical participant nonces, malformed encodings, zero-coordinate components, unknown fields and tampered reconstructed commitments. Mutating original or returned data cannot alter an existing snapshot. Static-context golden digests remain unchanged.

Two actual library-generated public nonce pairs are recorded in `qualification/fixtures/nonce_rounds.json`. Python and Rust independently build identical canonical static-binding, opening and revealed-round hashes for those vectors. Both partial roles and the designated completion refer to the same round while retaining distinct operation digests. These are matching finite examples, not a general cross-language parser conformance proof.

Python's curve encoding boundary is deliberately shallow: a prefix-valid nonzero coordinate can still be invalid on the curve. Backend tests parse the real fixture points and reject malformed 65/67-byte lengths, invalid prefixes, infinity/zero components, and an out-of-range coordinate. Aggregate nonces have a different library type that can represent infinity; individual-point rejection is not generalized into an aggregate API claim.

## Journal v2 and actual process death

The journal fixes each leg's static mode or exact nonce-round digest at first reservation. Tests cover Alice/Bob divergence, partial/completion divergence, static/dynamic mixing in both directions, produce/replay mismatches, retirement, reopening, and no retry under another round. Persisted public nonce hashes reject identical full encodings across visible legs or sessions. The same round can support its distinct authorized role/purpose scopes.

Reload checks reject missing round pins, mismatched operation pins and duplicate public nonce hashes even in syntactically valid snapshots with recomputed test checkpoints. A valid synthetic v1 database/checkpoint pair is quarantined without modification. No migration is attempted.

The process suite runs the following matrix twice: once with the historical static context, once with an actual fixture-derived nonce round. Each case waits for the child to reach a bounded checkpoint, sends real `SIGKILL`, reaps the child, checks a synchronized public callback-count marker and reopens the journal.

| Kill checkpoint | Callback count | Recovery |
| --- | --- | --- |
| Before consumption database commit | 0 | Reservation retired; no exposure marked |
| After database commit, before checkpoint update | 0 | Quarantined due to mismatched heads |
| After checkpoint replacement | 0 | Outcome unknown; possible exposure retained |
| After checkpoint synchronization | 0 | Outcome unknown; possible exposure retained |
| After durable consumption | 0 | Outcome unknown; possible exposure retained |
| After callback, before output commit | 1 | Outcome unknown; no recomputation |
| After output commit | 1 | Exact output replay; no second callback |

For every recovered dynamic case, the Zenon round digest remains pinned. Existing lock-before-load, persistent-lock ownership, actual fork-child rejection, foreign-thread close refusal, one-sided restore quarantine and payload-tamper cases also pass. Restoring both matching database and checkpoint remains accepted by design and is explicitly tested as a limitation. `SIGKILL` after checkpoint replacement does not simulate loss of power before a directory flush.

Six additional journal scopes record Alice/Bob partials and designated completions for both legs, then reopen and replay the exact fixture bytes. Their callbacks only return preexisting public bytes. They do not invoke the Rust owner, provide authenticated protocol sequencing, or demonstrate durable signing.

## Ephemeral Rust and independent Go checks

The new test-only owner keeps an actual pinned `SecNonce` and full `KeyAggContext` in memory. Consuming `Generated` to seal a round prevents that local object from being rebound. A ready owner takes its nonce before checking a signing request or calling the backend. Tests cover a successful one-use result, changed requests, injected pre-backend failure, backend wrong-key rejection, an unwinding panic, malformed peer nonce refusal, and actual foreign-thread refusal. Failure paths leave no second signing opportunity through that owner.

Contextual derivation changes the observed nonce when the tested round, binding, message, adaptor point or key context changes. Reconstructing the same deterministic inputs repeats the nonce. The latter is an explicit counterexample to treating this wrapper or context hash as fresh entropy or restored-copy protection. PID checks are source-inspected only; there is no Rust fork test or secure-erasure test.

The Rust fixture path asserts declared signer keys and adaptor point against the session terms, uses the actual Taproot tweak and Bitcoin claim digest, checks both participants' partials and aggregate pre-signatures, completes both final signatures, verifies them, and checks extraction against the committed point. The Zenon message remains the exact source-derived SHA3-256 digest.

The separately pinned legacy Go verifier accepts both new signatures and rejects message/signature mutations. It also parses all eight nonce points and checks four distinct full public nonce encodings. The Bitcoin Go test replaces the old fixture's claim witness with the new 64-byte signature, confirms unchanged txid and changed wtxid, recomputes the actual sighash, and executes the script engine successfully. Mutated signature and output reject. No new adaptor implementation, transaction serialization algorithm or curve arithmetic was written.

## Intermediate failures and review

The first Rust compile failed with `E0308`: the Taproot tweak helper requires a 32-byte array reference, while the test passed a byte vector. Converting the decoded root to `[u8; 32]` fixed the test-side type error. The next targeted run passed all 7 new tests. A temporary local fixture writer was then replaced by an immutable expected-fixture assertion; normal tests never rewrite it.

Review requested explicit equality checks between the synthetic signer keys/adaptor point and declared terms. Those checks were added before the final 24-test Rust run and formatting check, both of which passed. Python's new targeted tests and the combined 108-test run passed without intermediate assertion failures. Both Go modules passed their first Stage 3 compile/run. No test failure remains unresolved.

Parallel read-only review examined transcript reconstruction, journal pins/reload checks, public nonce history and the ephemeral owner. No remaining actionable finding was reported within this scope. That review is not an independent human cryptographic audit or protocol proof. Historical Stage 2 findings remain documented in their original report.

## Remaining boundaries

- No authenticated peer exchange or durable commitment-before-reveal transport ordering.
- No verified-artifact state machine enforcing Bob's pre-signature retention before release.
- No Python-to-Rust signing bridge, durable secret nonce owner or process-death test of such a bridge.
- No production entropy, secret storage, zeroization, hardware counter or independent witness.
- No global nonce freshness, related/partial nonce reuse detection, or cloned/restored-copy protection.
- No authenticated chain state, timing/finality evidence, fee policy, regtest/devnet settlement or upstream core port.

The [design](NONCE_ROUNDS.md) records the next integration requirements. Passing this stage supports further offline development; it does not authorize or establish production use.
