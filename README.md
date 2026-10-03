# Zenon PTLC Swap Research

An offline foundation for investigating a bilateral Bitcoin-to-Zenon atomic swap.

Independent research, not an official Zenon implementation or activation proposal.

**Status: Stage 5 offline Alice/Bob completion lifecycle. There is no usable swap client or production signing implementation in this repository.** CANDIDATE-01 fixes a graph for modeling and finite qualification; its complete construction and implementation remain subject to review.

The repository includes a historical scalar-disclosure regression, pinned BIP340 adaptor experiments, real synthetic Taproot claim/refund transactions checked by an independent Go script engine, and an exhaustive finite schedule model. All experiments use public synthetic inputs and contact neither chain. Dependency acquisition is a separate network step.

The `offline_session` package adds staged public transcript commitments, role-bound public nonce rounds, and a SQLite/checkpoint journal for one-use synthetic operations, exact output replay and explicit unknown outcomes. It stores no secret nonces and has no real signing backend. Process-death, concurrent-owner and rollback-boundary tests exercise its public metadata lifecycle. A separate Rust test-only nonce owner exercises the pinned library using public synthetic seeds; it is not connected to the Python journal.

The managed Bob exchange now verifies and durably retains both legs' public artifacts before making the complete Zenon pre-signature available through its release API. A separate Rust executable performs public MuSig2 verification; it has no signing capability. This local order does not establish peer authentication, chain acceptance, time margins or delivery.

Alice now validates that release against her own retained partial and consumes completion ownership before a synthetic producer runs. Bob durably retains her candidate completion, then uses a second Rust executable to verify the Zenon signature, extract and check the witness, and complete the Bitcoin signature. The recovered scalar is never returned. Actual private signing and chain submission remain absent.

## Repository boundaries

| Component | Responsibility |
| --- | --- |
| This repository | Protocol specification, offline experiments, and later reference-client session and recovery logic |
| A coordinated `go-zenon` contribution | PTLC contract behavior, RPC, encoding policy, activation, and contract tests |
| The selected SDK | Typed contract calls and wire representations |

The core contract proposal is [go-zenon PR #13](https://github.com/zenon-network/go-zenon/pull/13). Its signature verifier is a building block, not a complete atomic-swap protocol. Existing HTLC support is the comparison baseline for deciding whether PTLC's incremental benefits justify the additional work.

## Read first

1. [Scope and milestones](docs/SCOPE.md)
2. [Draft protocol requirements](docs/PROTOCOL.md)
3. [Threat model](docs/THREAT_MODEL.md)
4. [Cryptography candidates and selection gates](docs/CRYPTOGRAPHY.md)
5. [Pinned evidence and verification limits](docs/EVIDENCE.md)
6. [Local validation and intermediate issues](docs/VALIDATION.md)
7. [Selected offline transaction graph](docs/TRANSACTION_GRAPH.md)
8. [Stage 1 results and limits](docs/STAGE1_VALIDATION.md)
9. [Core integration boundary and acceptance backlog](docs/CORE_INTEGRATION.md)
10. [Offline session and journal design](docs/SESSION_JOURNAL.md)
11. [Stage 2 validation and intermediate findings](docs/STAGE2_VALIDATION.md)
12. [Public nonce rounds and ephemeral ownership](docs/NONCE_ROUNDS.md)
13. [Stage 3 validation and limits](docs/STAGE3_VALIDATION.md)
14. [Managed public artifact exchange](docs/ARTIFACT_EXCHANGE.md)
15. [Stage 4 validation and intermediate findings](docs/STAGE4_VALIDATION.md)
16. [Alice completion and Bob public recovery](docs/COMPLETION_LIFECYCLE.md)
17. [Stage 5 validation and intermediate findings](docs/STAGE5_VALIDATION.md)

## Run the offline checks

Requirements: Python 3.9 or later with SQLite, a POSIX host supporting advisory file locks, Git, and OpenSSL with Ed25519 verification support. Session tests target local Linux/macOS filesystems; only the platforms actually executed in the validation report are established. No Python packages, node software, credentials, or network access are required by the tests. OpenSSL is an independent test verifier, not a selected application dependency. Artifact-checker tests use temporary Git repositories without configuring an identity or making commits.

```sh
REQUIRE_OPENSSL=1 python3 -m unittest discover -s tests -v
python3 scripts/check_artifacts.py
python3 scripts/model_swap.py --help
```

The required mode must fail if independent OpenSSL verification cannot run. Any optional run that skips that verifier is incomplete evidence. The CI definition uses required mode; preparing that definition does not establish that hosted CI has run.

The test-only Ed25519 arithmetic is deliberately separate from the BIP340/secp256k1 qualification harness. Demonstrating a flaw in the historical Ed25519 demo does not validate a BIP340 replacement.

The [Rust harness](qualification/README.md) pins two adaptor candidates and rust-bitcoin with a dependency lockfile. The [core-verifier Go harness](qualification-go/README.md) checks public completed signatures using the exact BIP340 dependency version in PR #13. The separate [Bitcoin Go harness](qualification-bitcoin-go/README.md) checks transaction bytes, Taproot commitments, sighashes and script execution. After populating their dependency caches, run from the repository root:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-go test -mod=readonly -count=1 -v ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-bitcoin-go test -mod=readonly -count=1 -v ./...
```

The core-verifier harness is compatibility evidence for a historical verifier version; it is not a node or contract test. Toolchain versions, test results, model bounds and unresolved integration work are recorded in the Stage 1 report.

To run the separate Python-to-Rust public-verifier integration after fetching the locked dependencies:

```sh
cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples
python3 -B scripts/qualify_exchange.py --verifier qualification/target/debug/examples/verify_exchange
python3 -B scripts/qualify_completion.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
```

Use the corresponding executable paths if `CARGO_TARGET_DIR` is set. These checks use temporary public journals, fixture artifacts and explicitly selected local executables. Ordinary Python tests use clearly labeled fake callbacks for sequencing and do not require Rust. Journal storage v4 quarantines older v1-v3 state without migration; incoming Bob releases now require v2 packets with both partials.

## Next milestone

Define authenticated peer transport, observation selection/reconciliation and actual funding/time authorization. An invalid but structurally matched completion candidate currently pins Bob's session without a replacement path. Connect a reviewed private signing worker only after resolving fresh entropy, secret memory, restored-copy protection, and its journal boundary. Restoring both matching database/checkpoint copies can still permit another synthetic Alice producer call. Independent construction review and authenticated chain observations remain prerequisites for a current-node PTLC port and two-party regtest/devnet work.

All checked-in content is English and contains no user identity or private operational data. The artifact checker detects a limited set of accidental disclosures; source, metadata, and destination still require review before publication.

## License and participation

Original project contributions are available under the [MIT License](LICENSE).
Identified third-party fixtures and external dependencies retain their own terms;
see [third-party notices](THIRD_PARTY_NOTICES.md) for sources and attribution.
The crate's `publish = false` setting remains in place: this repository is a
research snapshot, not a published production cryptography package.

See [contribution guidance](CONTRIBUTING.md) for review priorities and validation
requirements, and the [security policy](SECURITY.md) for limitations and reporting.
