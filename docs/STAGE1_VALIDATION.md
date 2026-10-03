# Stage 1 offline qualification record

Date: 2026-10-03. All values are public synthetic inputs. No wallet, RPC, node, broadcast, live funds, public commit or publication is involved. Dependencies and toolchains were acquired separately from offline test execution.

This preserves the Stage 1 checkpoint. Subsequent public-session/journal work and current combined results are recorded in [STAGE2_VALIDATION.md](STAGE2_VALIDATION.md).

## Primitive and core-verifier results

| Suite | Result | Evidence boundary |
| --- | --- | --- |
| Python regressions and finite model | 29 passed, zero failures/skips | Ten historical scalar-disclosure checks, seven artifact-hygiene checks, twelve finite-model checks. |
| Rust adaptor primitives | 13 passed, zero failures/ignored | Two pinned candidates, 32 generated adaptor cases each, all 19 official public BIP340 vectors, untweaked two-party linkage, four regenerated public completed-signature vectors. |
| Rust Bitcoin transactions | Four passed, zero failures/ignored | Actual synthetic Taproot claim/refund bytes and commitments; 32 aggregate claim cases spanning all four internal/output parity pairs. Combined Rust total: 17. |
| Go core-verifier compatibility | Three top-level tests passed, zero failures/skips | Four Rust-completed signatures, 24 negative controls, 19 official vectors with the old verifier's documented message-length restriction, and source-derived Zenon digest binding. |
| Go Bitcoin script verification | Seven top-level tests and 15 named subtests passed, zero failures/skips | Independent serialization, tree/tweak/control-block, sighashes, actual script execution, mutation rejection and separate synthetic locktime-finality boundaries. |

The Rust final-verification entry points use two arithmetic backends: `musig2` and the direct verifier share `libsecp256k1`; `schnorr_fun` supplies a separate Rust path. Go uses the pinned `btcec/v2 v2.3.2` verifier version from PTLC PR #13, with its separate Go arithmetic. This is implementation diversity for final verification, not independent human cryptographic review of the adaptor construction. The isolated Go dependency graph is not identical to the full node graph.

Both Rust candidates produce the expected results for all 19 official BIP340 vectors, including variable-length messages. The old Go verifier matches the first 15 fixed-32-byte cases and rejects all four newer variable-length positive cases. The tests explicitly expect this restriction; passing them must not be reported as full current BIP340 conformance. Zenon's proposed contract supplies a 32-byte digest.

For synthetic entry bytes `00..1f` and destination bytes `00..13`, the proposed contract's message is:

```text
SHA3-256(id32 || destination20)
e357d6597d0149f0adb2ab0f0d7dff932412e2f55fd9b94bb9301c8ccf9df974
```

Python, OpenSSL and the pinned Go hash implementation independently reproduced this digest. The aggregate Zenon signature verifies against it; changed entry/destination bytes and Keccak hashing reject. This checks a synthetic message rule and signature, not account-block serialization, admission, VM execution or actual transfer.

The `musig2` nonce regression demonstrates that repeating a key/message/seed tuple under a changed adaptor point repeats the pre-nonce. It does not implement secret recovery or a safe nonce manager. Wrong-witness tests demonstrate that an extraction API can return a scalar from an invalid completion: final verification and comparison against the committed adaptor point remain necessary. Malformed final-signature lengths in the Rust harness are rejected by its common length boundary; the Go tests additionally exercise the pinned parser's width checks.

## Bitcoin transaction qualification

The original two-leg linkage test retains a synthetic Bitcoin message. A separate test now constructs real serialized transactions for CANDIDATE-01 using rust-bitcoin 0.32.7: a two-party adaptor-completed Taproot key-path claim and an Alice-only CLTV script-path refund. These are conflicting alternatives spending the same fictional output, not two transactions that can both settle. The public fixture contains no private signing inputs.

The aggregate context includes the exact refund leaf's Taproot tweak, and its output key/parity must agree with rust-bitcoin. Both partial signatures and the aggregate pre-signature are checked before adaptation. A 32-case Rust loop exercises signing, adaptation, final verification and extraction across all four internal/output-key parity pairs. Refund signing uses only Alice's separate leaf key. The fixed exported example has odd output parity.

The independent Go module pins btcd v0.25.0. It reconstructs the fixed example's tree/tweak/control block, recomputes both DEFAULT sighashes, checks canonical serialized bytes and executes both spend witnesses. It does not independently reconstruct the MuSig coefficient/aggregate internal-key calculation. Mutations of amounts, destination, previous-output key, annex, explicit zero sighash suffix, refund script and control parity reject. Invalid CLTV locktime/domain/sequence cases specifically return `ErrUnsatisfiedLockTime`, rather than counting an unrelated signature failure as a successful boundary check.

The script engine has no median-time-past input. A separate pure finality-helper test with synthetic context rejects the refund before and exactly at its locktime and accepts it after that value. Neither result establishes actual chain time, UTXO existence, full transaction/block validity, mempool/package admission or inclusion. The test timestamp and fixed fee are not production recommendations. Full cross-chain session binding and durable exchange remain unimplemented.

## Finite schedule model

The selected graph is [CANDIDATE-01](TRANSACTION_GRAPH.md): Alice owns the witness and funds BTC first; Bob funds a shorter-lived ZNN lock; Alice's ZNN claim exposes the witness, allowing Bob's BTC claim. The model represents validated funding and verified cryptographic artifacts as explicit idealized prerequisites. It does not implement them.

| Honest participant | Reachable states | Enumerated transitions | Result |
| --- | --- | --- | --- |
| Alice | 5,738 | 13,810 | No principal-loss state within the modeled schedules. |
| Bob | 3,482 | 5,825 | No principal-loss state within the modeled schedules. |

Default ticks: Zenon expiry 6; Bitcoin refund eligibility 10; inclusion delay at most 1; observation delay at most 1; one Zenon-claim rollback within 1 tick; horizon 12. The derived honest reveal cutoff is tick 2. These are abstract model parameters, not recommended real-chain timeouts. The exact Bitcoin median-time-past boundary must be translated before integration.

All four weakened policies generate replayable counterexamples: trusting observed rather than validated funding, omitting Bob's extraction-material retention, allowing late Alice disclosure, and removing Bob's bounded response. A rollback does not reset prior secret exposure. Bitcoin claim remains eligible after refund opens and competes with refund until the output is spent.

Coverage excludes funding rollback, Bitcoin-spend rollback, unbounded censorship, independent chain clocks/stalls, transaction fees/resources, real cryptography, crashes and concurrent signing. Due-time rules restrict the explored scheduler to the declared honest response/inclusion bounds. Honest abstention is possible, so absence of a principal-loss state does not prove universal completion or liveness.

```sh
python3 scripts/model_swap.py
python3 scripts/model_swap.py --honest alice --policy late-reveal
```

The first command exits 0 for the bounded default search. The weakened-policy example intentionally exits 1 and prints a counterexample. An incomplete search raises a failure instead of reporting safety.

## Reproduction and toolchains

Local execution used macOS arm64, Python 3.9.6, OpenSSL 3.6.3, Rust/Cargo 1.90.0 and Go 1.23.12. Rust and Go were installed in the ignored research cache, without changing global toolchain configuration or Git identity. Official toolchain archive hashes were checked before installation. Compiler caches, acquired upstream code and build logs are ignored and are not publication artifacts.

```sh
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
cargo test --locked --offline --manifest-path qualification/Cargo.toml
cargo fmt --manifest-path qualification/Cargo.toml -- --check
go -C qualification-go test -mod=readonly -count=1 -v ./...
go -C qualification-bitcoin-go test -mod=readonly -count=1 -v ./...
python3 scripts/check_artifacts.py
```

For Go offline execution, set `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off` after downloading dependencies. `Cargo.lock` and the Go module checksum file record dependency resolution. Go tests were run uncached with `-count=1`. No full upstream library suite is claimed.

The workflow defines Python, Rust and Go jobs with pinned actions/toolchain versions and separate dependency acquisition. Hosted CI has not run. Local macOS results do not establish Linux results. Historical toolchain/dependency versions used for compatibility are not production deployment recommendations.

## Intermediate issues and review

- The first Rust offline compile failed with `E0283` in a test-side generic scalar assertion. An explicit marker type fixed it; no candidate implementation was changed. Subsequent complete runs passed.
- The public interoperability fixture was generated in a targeted development run. Normal tests now regenerate expected values in memory and compare against the checked-in fixture; they do not rewrite it.
- Peer review clarified the Rust malformed-length boundary and strengthened wrong-witness extraction assertions. The final primitive suite passed after both changes.
- The Go compatibility harness passed on its first test run. Peer review confirmed the pinned direct versions, SHA3 rule and legacy message-length limit; it also identified the isolated transitive-graph distinction recorded above.
- The Bitcoin Rust tests passed their first compile/run. Peer review identified that an initial parity loop checked only key derivation; it was expanded to complete, verify and extract signatures for each context before the final 17-test run. The immutable transaction fixture assertion replaced a temporary development exporter.
- The Bitcoin Go module first passed a compile-only run with zero tests, then passed all seven test groups on its first fixture-dependent run. No intermediate failure occurred in that module. Its tests distinguish exact CLTV errors from signature failure and script success from transaction finality.
- The schedule model passed targeted and combined checks. A separate graph review found no actionable discrepancy within the stated abstraction. These agent reviews do not constitute independent human security audits.
- [Stage 0's earlier fixture/checker issues](VALIDATION.md) remain recorded rather than hidden by the final passing state.

## Limits and continuing implementation

These checks establish a reproducible offline research baseline. They do not implement durable nonces, protected storage, multi-process ownership, counterparty transport, real-chain observation, fee management, regtest/devnet execution or a current-node PTLC port. No backend has been selected for production use, and no activation decision follows from a passing test.

The final parent-level locked/offline Rust run passed all 17 tests, and both Go modules passed uncached readonly runs after the transaction fixture was finalized. The 29-test Python suite passed with required OpenSSL verification. Rust/Go formatting, workflow YAML syntax and local Markdown links passed. The final artifact check covered 36 candidate file versions; no unresolved test failure or skipped verifier remains in the executed suites.

All repository content is English. Public exported fixtures omit signing scalars, seeds and adaptor witnesses; test code uses deliberately public synthetic scalar inputs. Mechanical hygiene checks cover a limited set of accidental disclosures and inspect both index blobs and working files. They do not prove anonymity or replace review of any future publication destination and metadata. No remote or commit was created; files remain local and uncommitted.
