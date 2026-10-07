# Stage 4: managed Bob-side public artifact exchange

Status: offline reference sequencing with public synthetic inputs. This implements the local retention-before-release requirement from [CANDIDATE-01](TRANSACTION_GRAPH.md). It has no signer, participant authentication, peer transport, funding observation, time authorization, wallet or broadcaster. A completed state-machine transition is not authorization to use funds.

This document describes the retention/release component introduced in Stage 4. Current storage is v7, and releases use v2 packets containing both ordered partials. [Stage 5](COMPLETION_LIFECYCLE.md) extends this flow with Alice completion and Bob public recovery; the earlier validation report remains historical. Managed Bob start requires the explicit [Stage 8 recovery allowance](RECOVERY_ADMISSION.md); initial artifact verification does not consume it.

## Local transition contract

The pure reducer is `offline_session.exchange`; `Journal` supplies exclusive ownership, persistence and the release boundary. Each managed session belongs to the Bob role and starts with a fully reconstructed nonce-bound Bitcoin partial-signature context. It cannot start after any generic operation reservation, and generic reserve/produce/replay calls are rejected once it starts.

| Stored stage | Accepted next action | Required public evidence |
| --- | --- | --- |
| `BITCOIN_BOUND` | `retain_exchange_bitcoin` | Both ordered Bitcoin partials and their exact verified aggregate pre-signature |
| `BITCOIN_RETAINED` | `bind_exchange_zenon` | Bob's nonce-bound Zenon context with the same Bitcoin predecessor |
| `ZENON_BOUND` | `retain_exchange_alice_partial` | Alice's valid partial for that exact Zenon round |
| `ALICE_PARTIAL_RETAINED` | `retain_exchange_zenon` | Both valid Zenon partials, with Alice's bytes unchanged, and their exact verified aggregate pre-signature |
| `ZENON_RETAINED` | `release_exchange_zenon` | Complete retained contexts, bundles and bound verification results |
| `RELEASE_RECORDED` | `replay_exchange_release` | Exact previously stored release bytes |

Within this retention/release component, other transition orders reject before invoking the verifier. Stage 5 additionally permits Bitcoin completion after `RELEASE_RECORDED`, as described in the completion lifecycle. Contexts require the Bob partial role/purpose and a public nonce round; legacy static contexts cannot enter this flow. The existing terms, Bitcoin/Zenon binding pins, per-leg round pins and cross-scope duplicate-public-nonce checks still apply. Distinct encoded per-leg keys and nonces are required by the existing candidate.

Before binding Zenon, Bob must already have a verified Bitcoin bundle. Before accepting Bob's last Zenon contribution as a complete bundle, the state must already contain Alice's verified partial, and that exact partial must occur in the bundle. Before release, both complete bundles and both full dynamic contexts are durably stored. No method generates either participant's partial; artifacts are supplied public inputs.

## What verification establishes

`verification_request` derives the cryptographic request from the fully reconstructed application context and the supplied artifact. It includes the ordered signer keys, aggregate key, Bitcoin tweak root when applicable, exact 32-byte message, adaptor point, both public nonces and the partials/pre-signature. Caller-provided cryptographic fields cannot override those derived inputs.

`qualification/examples/verify_exchange.rs` is a public-only executable using the already pinned `musig2` dependency. It parses real curve points and scalar encodings, reconstructs the ordered `KeyAggContext`, applies the selected Taproot tweak, and compares the resulting aggregate x-only key. It verifies Alice's partial or both ordered partials. For a complete bundle it also recomputes the aggregate pre-signature, requires exact byte equality with the supplied one, and verifies that pre-signature against the message, aggregate key and adaptor point.

The Rust executable receives the application context digest as an opaque value. Python is responsible for its full reconstruction. The verifier receives the Bitcoin message and root as supplied commitments; it does not rebuild a transaction, refund script, Merkle tree, funding output or chain history. The separate Bitcoin qualification harness checks the shared synthetic transaction example. Neither check establishes accepted funding or a safe release deadline.

Requests use schema `ptlc-artifact-verification-v1` and compact sorted-key ASCII JSON, with at most one trailing LF and a maximum wire size of 32,768 bytes. Unknown/duplicate fields, reordered or noncanonical JSON, non-ASCII input, wrong types, malformed widths and trailing data reject. The successful response is bound to:

```text
SHA256("PTLC/artifact-verification/v1\0" || canonical_request)
```

It contains only schema `ptlc-artifact-verification-result-v1`, that request digest and literal `true`. No request fields or verifier details are echoed on rejection. The executable does not sign, generate nonces, read a wallet, access files or contact a network. Existing dependency licenses and pins are recorded in [the Rust harness](../qualification/README.md); this stage adds no dependency.

## Trusted verifier boundary

The reducer accepts a trusted local verifier callable. It passes a defensive request copy and requires an exact successful response schema, literal boolean and matching request digest. Wrong, stale, malformed or exceptional results leave accepted state unchanged. The stored receipt is the expected request hash; it is not a signed attestation or a peer credential.

`SubprocessVerifier` invokes an explicitly selected existing local executable without a shell. It bounds the request, discards stderr, and accepts only the exact canonical response with a 4,096-byte output limit. [Stage 7 transport](PUBLIC_WORKERS.md) enforces that output allowance while concurrently writing stdin and reading stdout through nonblocking pipes, with one transfer/exit deadline and no output spool file. Cleanup attempts to terminate the owned process group on failure before reaping the direct worker. The executable remains trusted; this is not an operating-system sandbox or an aggregate rate limit.

Normal Python tests deliberately use a fake verifier to isolate sequencing and persistence. A test explicitly shows that such a callback can accept invalid cryptography: satisfying the response shape alone proves nothing. The separate integration script executes the real Rust verifier. A compromised executable, arbitrary caller code or host can bypass these application assumptions. No authenticity claim attaches to a receipt merely because it has the correct JSON format.

## Durable retention, release and replay

The journal holds its process/thread ownership and mutation guard while a verifier runs, while the reducer validates its next state, and through database/checkpoint persistence. A callback cannot reenter a mutation, reserve another operation or close the journal during this sequence. Failed artifact-retention verification commits no state. Stage 5 completion deliberately persists Alice consumption or Bob's candidate observation before its separate completion verifier runs.

Storage schema/domain v3 introduced managed exchange state; v4 extended it with retained completion observations and outputs, and v5 adds the superseded-observation archive. On reopening, the reducer validates the full stage/artifact order, reconstructs contexts, recomputes receipt-to-request bindings, and checks the release bytes and flags. The journal independently matches those contexts to stored session/leg/round/nonce pins. It does not rerun an external verifier on load. This relies on previously trusted verification and the existing local checkpoint/storage assumptions, not resistance to a hostile process that can rewrite both files.

The current `ptlc-bob-zenon-release-v2` envelope is canonical public JSON containing sender role Bob, recipient role Alice, Bob's full Zenon dynamic context, both ordered partials and the exact retained complete Zenon pre-signature. Roles are labels, not authenticated identities. Both ordered partials also remain in Bob's stored bundle for reconstruction. The local application retains both chain contexts, key/tweak/nonce inputs, adaptor point and encoded pre-signature, including the library's parity/extraction representation.

`release_exchange_zenon` records those exact output bytes and `release_may_have_escaped = true`, commits both database and checkpoint, and only then returns the bytes. There is no network send. A second release call rejects; explicit replay returns the exact saved bytes without rerunning the external cryptographic verifier or producing a new signature/artifact. Replay still validates stored structure, reconstructs context/request hashes and compares the expected canonical envelope. When no output is durably recorded, replay reports `OutcomeUnknown`. An interruption between database and checkpoint commits quarantines the journal.

The release marker is separate from `possible_exposure`. Bob releasing a pre-signature does not by itself reveal the adaptor witness; the exposure marker concerns witness-bearing completion and, in Stage 5, retained Bob completion observations. Neither flag proves peer delivery or chain inclusion. Both remain monotonic within their qualified flow and storage assumptions.

These guarantees apply to the managed journal API. The pure reducer has no persistence, and the trusted caller already possesses the supplied public artifacts. It could transmit them directly or read a defensive snapshot and bypass the release API. This module cannot constrain malicious caller side effects. The complete application must own all outbound routes before retention order can be a system-wide guarantee.

Storage versions 1-5 are quarantined without migration or automatic reset. As before, restoring both matching database and checkpoint copies is undetectable; there is no hardware counter or remote witness. This stage does not supply a durable secret nonce owner or a crash-tested journal-to-signer boundary.

## Reproduction and next work

After the existing dependency cache has been populated:

```sh
cargo build --locked --offline --manifest-path qualification/Cargo.toml --example verify_exchange
python3 -B scripts/qualify_exchange.py --verifier qualification/target/debug/examples/verify_exchange
```

Adjust the executable path when selecting a custom Cargo target directory. The integration uses temporary local journals and unchanged public fixtures; it performs no signing or network activity. [STAGE4_VALIDATION.md](STAGE4_VALIDATION.md) records both fake-verifier process tests and actual-verifier integration separately.

[Stage 5](COMPLETION_LIFECYCLE.md) implements Alice's validated inbound flow and the public completion/extraction lifecycle. Remaining work includes authenticated transport, authenticated observation selection, actual chain/timing authorization and a reviewed secret-worker boundary. Fresh entropy, secure memory, copied/restored-state protection and independent cryptographic/protocol assessment remain unresolved before any node integration.

Stage 80 adds [actual public verifier receipt and persistence controls](EXCHANGE_VERIFIER_TRUST_BOUNDARY.md), with [validation scope](STAGE80_VALIDATION.md). The existing exchange adapter trusts its selected local program. A real synthetic positive receipt can pass exact byte binding while mathematical verification refuses, and ordinary journal reopen preserves structural state without rerunning equations. This selects no production change, authenticated producer, private consumed-input proof, nonce custody, guarded-profile migration or application/core progression.

Stage 81 adds one [actual program selection continuity control](EXCHANGE_PROGRAM_SELECTION.md) to the existing exchange qualifier. The same legacy adapter observes native execution, missing-entry refusal, same-path synthetic replacement and restored native execution. Test-only file measurements do not become production authentication. See [validation](STAGE81_VALIDATION.md); application and core progression remain **NO-GO**.


## Explicit measured public verifier selection

A separate optional [measured exchange verifier](MEASURED_EXCHANGE_VERIFIER.md)
requires a caller-provisioned entry-file SHA256 and repeats the bounded comparison
before every call. The legacy adapter and existing consumers remain exact.
Same-path replacement refuses before launch, but a matching pin for a deliberately
selected synthetic actor still permits forged claims. Matching bytes authenticate
neither source nor execution; atomic launch and application policy remain open.
See the [Stage 82 validation](STAGE82_VALIDATION.md).


Stage 83 adds two [measured public verifier execution-boundary controls](EXCHANGE_EXECUTION_BOUNDARY.md) to the existing actual exchange qualifier. A deterministic cut after a real entry read and a replaced dependency behind an unchanged entry both permit synthetic positives while independent native equations refuse. No atomic launch or complete runtime authentication construction is selected. See [validation](STAGE83_VALIDATION.md); application and core progression remain **NO-GO**.


Stage 84 adds a separate opt-in [sealed Linux public verifier](SEALED_PUBLIC_VERIFIER.md) and [validation scope](STAGE84_VALIDATION.md). Each call seals and measures a fresh public ELF snapshot, then executes the same inherited descriptor through the existing bounded runner. Existing consumers and guarded profiles retain exact bytes. The selected entry continuity does not authenticate the pin, source, loader, dependencies or environment. Application and core progression remain **NO-GO**.
