# Stage 2 offline session qualification record

Historical milestone: current nonce-round and journal v2 results are in [STAGE3_VALIDATION.md](STAGE3_VALIDATION.md). The counts and storage behavior below describe Stage 2.

Date: 2026-10-03. Local platform: macOS arm64, Python 3.9.6, SQLite 3.54.0. All state and outputs are public synthetic test data. The new session/journal code is not connected to a wallet, cryptographic secret-nonce object, signing backend, node or RPC. Existing synthetic primitive tests ran separately. No transaction broadcast, commit or publication occurred.

## Final executed results

| Suite | Result | Covered scope |
| --- | --- | --- |
| Public transcript | 16 passed | Versioned stages, canonical context hashes, input/type/size bounds, immutable copies, role/purpose/terms substitution, source-fixture alignment, exact Zenon message rule. |
| Journal | 27 passed | Durable ordering, replay, scope sealing, stage continuity, exposure monotonicity, exceptions, ownership, corrupt/missing state and checkpoint divergence. |
| Process/concurrency integration | Eight passed | Real SIGKILL at seven boundaries, competing processes, forked handles, foreign-thread close, one-sided rollback, valid SQLite tampering and the explicit full-rollback detection limit. |
| Complete Python suite | 80 passed, zero failures/skips | The 51 new session checks plus the 29 historical crypto, artifact and finite-model tests. OpenSSL independent verification was required. |
| Existing Rust qualification | 17 passed, zero failures/ignored | Locked offline primitive and Taproot checks; formatting passed. No Rust source or dependency change in Stage 2. |
| Existing Go qualification | Both modules passed uncached readonly offline runs | Three core-verifier and seven Bitcoin-verifier top-level tests; no Go source or dependency change in Stage 2. |

The final full Python run follows both review fixes described below. Earlier green runs are not substituted for this final result. Rust/Go results remain bounded by [Stage 1](STAGE1_VALIDATION.md); the journal does not invoke those signing functions.

## Process-death matrix

Each case creates a fresh synthetic journal, records a reservation and starts a child producer. A hook reports that it reached the exact checkpoint, then blocks. The parent sends SIGKILL and waits for actual process exit before reopening. A separately flushed public invocation marker distinguishes whether the callback ran. Every child is reaped and its temporary directory removed by test cleanup.

| Killed checkpoint | Callback calls | Reopen result | Possible exposure |
| --- | --- | --- | --- |
| Before consumption DB commit | 0 | Reservation becomes `RETIRED`; scope remains sealed. | False |
| After consumption DB commit, before checkpoint update | 0 | `Quarantined`; mismatched heads are not healed. | State not accepted |
| After checkpoint replacement | 0 | `OUTCOME_UNKNOWN`; no producer retry. | True |
| After checkpoint commit | 0 | `OUTCOME_UNKNOWN`; no producer retry. | True |
| After consumption, before callback | 0 | `OUTCOME_UNKNOWN`; no producer retry. | True |
| After callback, before output persistence | 1 | `OUTCOME_UNKNOWN`; computed bytes are not assumed recoverable. | True |
| After output persistence, before return | 1 | `OUTPUT_RECORDED`; exact bytes replay without invoking the callback. | True |

This observes process-death behavior on the local filesystem. A successful reopen after replacement does not prove that an unsynchronized directory entry would survive power loss. The implementation uses SQLite FULL synchronization with DELETE journaling, a flushed checkpoint file and a directory sync; their behavior still depends on the storage stack.

Other process tests establish that a contending owner fails before a SQLite connection/state load, a persistent lock inode survives close/process death, a later owner sees the committed exposure/output, an inherited fork handle cannot operate or unlock its parent, and a foreign thread cannot close the active owner's journal during consumption.

## Context and snapshot boundaries

The public fixture is aligned with the prior qualified Bitcoin transaction and Zenon completed-signature examples. Additional compressed public keys and adaptor point were derived through the already pinned library in a temporary ignored helper. Network/genesis identifiers, participant identifiers, policy and Zenon economic fields are explicitly fictional. No new dependency was installed for Stage 2.

The transcript checks compressed-point shape, not curve validity or key ownership. It binds supplied Bitcoin IDs/digests without recomputing them. Its canonical context digest is separate from the consensus messages. It recomputes only the source-defined SHA3-256 entry/destination message. Validation establishes neither authentication, actual funding, pre-signature validity nor reveal authorization.

Database-only and checkpoint-only restores fail closed. Changing a valid SQLite payload without its matching digest/checkpoint also fails. Separate tests restore both matching old copies and demonstrate that local history detection cannot distinguish that snapshot from the earlier state. This is an intentional counterexample to a stronger anti-rollback claim, not a fixed production capability.

The checkpoint is logically outside the journal directory, not a trusted hardware counter or independent remote witness. Secret-nonce freshness, restored replicas, hostile hosts and arbitrary external filesystem writers remain outside the guarantee.

## Intermediate findings and corrections

1. The first transcript run passed 14 tests. Input representation limits, the source-confirmed signed 64-bit Zenon expiry bound and per-leg encoded-key separation brought the focused suite to 16 passing tests. No transcript compile/test failure occurred.
2. The initial seven process tests passed. Adversarial review then reproduced a foreign-thread close race: a second thread could release the lock during consumption persistence, and the owner still invoked the producer. A new root regression failed with `OwnershipError` after that unsafe invocation. The fix binds all use/close to the opening PID and exact thread, spans persistence with a write guard, enables the producer guard before consumption, and checks ownership immediately before the callback. The eight-case process suite passed afterward.
3. A 78-test combined Python run passed after the ownership fix. Further review then demonstrated that distinct operation purposes could use different actual Bitcoin or Zenon bindings under the same terms. This was a context-continuity bug in the prototype, not demonstrated cryptographic theft. Session-wide Bitcoin and Zenon stage pins are now committed with the first applicable reservation and checked for later reserve/produce/replay operations. Two new focused regressions reject valid alternative funding and entry contexts, including after reopen. The final combined suite passed 80 tests.
4. Injected SQLite/checkpoint persistence exceptions, actual checkpoint fsync failure, producer exceptions and process deaths are expected negative scenarios. They end in retirement, unknown output or quarantine as asserted; they are not omitted from the successful final run.

Agent peer review found no remaining actionable blocker within this public-metadata scope. It is not independent human cryptographic review. No unresolved failing test or skipped independent verifier remains in the executed local suites.

## Reproduction and CI boundary

From the repository root, with the previously acquired Rust/Go dependency caches:

```sh
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
cargo test --locked --offline --manifest-path qualification/Cargo.toml
cargo fmt --manifest-path qualification/Cargo.toml -- --check
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-go test -mod=readonly -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-bitcoin-go test -mod=readonly -count=1 ./...
python3 scripts/check_artifacts.py
```

The Python workflow now defines native Linux/macOS jobs for Python 3.11 and 3.13, including process tests and required OpenSSL verification. The macOS job explicitly selects the image's Homebrew OpenSSL executable. Hosted jobs have not run; defining this matrix is not Linux, CI or cross-platform durability evidence. Windows journal support is not implemented.

All repository artifacts are English and use public synthetic values. Test journals, control files and process markers live in temporary directories; no private environment logs or state snapshots are checked in. Files remain local and uncommitted. Mechanical artifact checks do not prove anonymity or replace review before any future publication.

## Remaining implementation work

The package is a public transcript and one-use synthetic output journal. It cannot authenticate a peer, verify chain observations, authorize revealing artifacts from real timing evidence, own a backend's secret nonce object, protect against a matching full snapshot rollback, or recover a cryptographic output that was never durably recorded. Implementing the complete interactive exchange and signer boundary remains the next substantive milestone; node integration and production use remain separate.
