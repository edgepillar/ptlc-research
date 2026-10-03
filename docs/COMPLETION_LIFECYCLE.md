# Stage 5: Alice completion and Bob public recovery

Status: offline lifecycle qualification with synthetic fixtures. Alice's producer returns an existing public test signature; no private signing backend is attached. Bob's executable performs actual verification, witness extraction and Bitcoin signature adaptation using public inputs. It does not accept signing keys, generate secret nonces, return the extracted scalar, broadcast transactions or observe either chain.

## Alice's inbound boundary

Alice starts in a fresh managed journal session with her exact nonce-bound Zenon partial context and her own already computed public partial. That partial is verified with the artifact verifier before retention. This entry point does not manage her earlier Bitcoin partial generation, funding transaction or secret witness. The current local lifecycle deliberately starts after those public signing inputs exist.

Bob's release format is now `ptlc-bob-zenon-release-v2`: it contains his complete dynamic context, both ordered partial signatures and the aggregate pre-signature. Alice requires canonical bounded JSON, exact sender/recipient labels, the same chain binding and nonce round as her own context, and an unchanged Alice partial. The artifact verifier then verifies both partials and their exact aggregation, rather than accepting an unrelated valid pre-signature under the same key/message. Version 1 packets are rejected; role labels do not authenticate a peer.

| Alice stage | Transition | Durable result |
| --- | --- | --- |
| `ALICE_PARTIAL_RETAINED` | Accept verified Bob v2 release | `PRESIGNATURE_RETAINED` with exact release packet and request-bound receipt |
| `PRESIGNATURE_RETAINED` | Start one synthetic completion | `COMPLETION_CONSUMED` and possible exposure before the producer runs |
| `COMPLETION_CONSUMED` | Verify the producer's final signature | `COMPLETION_RECORDED` with exact output packet before return |
| `COMPLETION_CONSUMED` | Restart without a committed output | `OUTCOME_UNKNOWN`; producer cannot run again |
| `COMPLETION_RECORDED` | Explicit replay | Exact saved packet; no producer or external verifier invocation |

Producer exceptions, invalid signature length, rejected cryptographic output, callback interruption and uncertain persistence never reenable a consumed producer. Possible exposure remains true even if the returned signature is invalid, because the trusted callback may already have computed or exposed something. A callback must not transmit or use nonce state through another route; the journal cannot undo arbitrary callback side effects.

The producer returns exactly 64 public signature bytes. After successful verification, the output is a canonical `ptlc-alice-zenon-completion-v1` envelope with Alice/Bob role labels, the exact Alice Zenon-complete context and that signature. It is a public artifact, not a serialized Zenon account block or submission result. The durable marker describes possible exposure, not peer delivery, inclusion or finality.

## Verify, extract, then adapt

The new `complete_exchange` executable reuses the existing ordered-key/tweak/partial/bundle verifier. Its required sequence is:

1. Verify the retained complete Zenon bundle and parse the final signature.
2. Verify the final signature under the exact Zenon key and message.
3. Extract against the retained Zenon pre-signature. Require a nonzero scalar and an exact match to the committed adaptor point.
4. For Bitcoin recovery, verify the retained Bitcoin bundle and require the same adaptor point across both legs.
5. Adapt the Bitcoin pre-signature with the extracted witness, verify the resulting final Bitcoin signature under the retained output key/message, and return only that signature.

Extraction returning a value is never sufficient. Tests include an invalid completion for which the library can return an extracted scalar, an unrelated valid final signature under the same key/message, and independently valid bundles with different adaptor points. These must reject.

The CLI request schema is `ptlc-completion-request-v1` with a kind, nested verified-bundle request(s), and the Zenon signature. `verify-zenon-completion` has no Bitcoin bundle and returns no Bitcoin signature. `recover-bitcoin` has both bundles and returns the final Bitcoin signature. Canonical sorted ASCII JSON, exact fields, duplicate rejection and a 65,536-byte input bound apply. Results use schema `ptlc-completion-result-v1` and bind:

```text
SHA256("PTLC/completion/v1\0" || canonical_request)
```

The response contains only schema, request digest, literal validity and the expected empty-or-final Bitcoin signature field. The extracted scalar stays inside the process and is never serialized by this interface. This is not evidence of memory zeroization or protection from a compromised host. The scalar is derivable from the retained pre-signature and public final signature by design.

Application context hashes are opaque to Rust. Python reconstructs all contexts and derives the nested requests. Bitcoin message/root commitments remain supplied values; the executable does not reconstruct funding transactions or authenticate chain state. The integration's computed Bitcoin signature must exactly match the existing fixture already checked by the separate Go verifier and Bitcoin script engine.

## Bob's retained observation and recovery

Bob may process Alice's completion only after his release has been recorded. The packet must name Alice/Bob, use the expected completion schema and exactly match the Zenon binding/round already retained by Bob. Before calling the public recovery executable, the journal durably stores this exact candidate packet and marks possible exposure.

Candidate retention is a structural match, **not a claim of cryptographic validity**. A request-bound completion receipt and Bitcoin output appear only after the executable succeeds. If it fails or the process stops, the candidate remains available. Calling `complete_exchange_bitcoin` without a packet retries the retained input; a different packet cannot replace it. This retries a public-input computation and does not regenerate or reuse a secret signing nonce.

This conservative pinning has an availability cost: a structurally correct but invalid candidate remains pinned and prevents replacement by a later valid packet. There is no reset API. The caller must select observations under a future authenticated/reconciliation policy before this becomes a network-facing feature. Tests demonstrate the refusal rather than hiding it as automatic recovery.

On success Bob commits the completed Bitcoin packet, bound verification receipt and retained Zenon observation before returning output. State becomes `BTC_COMPLETION_RECORDED`. The packet includes the exact Bitcoin-complete context and final signature, not a broadcast result. Further completion calls reject; replay returns the exact stored output while still performing local structural/hash checks. Bob can also replay his original Zenon release. Neither replay calls an external cryptographic worker.

## Ownership and storage

Storage schema/domain v4 supports mutually exclusive generic, managed Bob and managed Alice modes. A session cannot mix these paths to bypass consumption or artifact ordering. Context, binding, round and public nonce pins are reconstructed on reload. Alice exposure matches her consumed/unknown/recorded stage; Bob exposure matches retained observation presence. Observation/reorg metadata cannot clear either marker.

All producer/verifier/recoverer calls remain under process/thread ownership and mutation guards. Returning bytes follows database plus checkpoint persistence. Mismatched storage heads quarantine the journal. Versions 1-3 are quarantined without modification or automatic migration.

Restoring **both** matching old storage copies remains undetectable. A new test restores Alice's pre-consumption snapshot after a completed run and demonstrates that the synthetic producer can run again. These local records therefore do not establish backup/clone-safe secret ownership. The ephemeral Rust nonce owner from Stage 3 is still separate, and the new Alice callback is not its integration.

## Reproduction and next integration boundary

With the existing locked dependencies cached:

```sh
cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples
python3 -B scripts/qualify_completion.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
```

Adjust paths for a custom Cargo target directory. The test uses separate temporary Alice/Bob journals and actual Rust executables for verification/recovery. Alice's only producer copies the checked-in synthetic signature. The ordinary Python suite uses explicitly fake verification callbacks to isolate state behavior; those results are not cryptographic evidence.

This connects public artifacts through a local two-role lifecycle. Remaining work includes authenticated transport and observation selection, actual funding/time authorization, invalid-candidate reconciliation, full transaction/block construction, secret worker ownership and independent construction review. No regtest/devnet settlement or production readiness follows from this milestone. See [STAGE5_VALIDATION.md](STAGE5_VALIDATION.md) for executed checks and intermediate failures.
