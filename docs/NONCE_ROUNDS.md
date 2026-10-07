# Stage 3: public nonce rounds and ephemeral ownership

Status: offline qualification with deliberately public synthetic inputs. The Python package has no cryptographic signer, secret nonce store, peer transport or chain connection. The Rust owner exists only in an integration-test file and is not callable by the Python journal. Neither component is a usable swap client.

This document describes the Stage 3 nonce layer. [Stage 4](ARTIFACT_EXCHANGE.md) adds a managed Bob artifact flow and a public-verification bridge; current journal storage is v6, including [Stage 5 completion](COMPLETION_LIFECYCLE.md) and [Stage 6 reconciliation](OBSERVATION_RECONCILIATION.md). The ephemeral signing owner remains separate. The next-integration list below records the original Stage 3 backlog; Bob's local retention/release order has since been implemented within Stage 4's narrower scope.

## Public commitment and opening format

The application transcript binds a fixed two-party nonce collection to one already validated Bitcoin or Zenon binding. The ordered roles remain Alice then Bob. A nonce is the selected library's 66-byte `PubNonce` encoding: two compressed non-infinity points. Python checks length, lowercase hexadecimal, compressed prefixes, and rejects all-zero coordinates; actual curve parsing belongs to the selected backend.

| Factory | Input | Result |
| --- | --- | --- |
| `nonce_commitment` | Binding, 32-byte round ID, role, public nonce | Role-bound opening hash |
| `commit_nonce_round` | Binding, round ID, Alice and Bob opening hashes | Immutable `nonce-commitments` snapshot |
| `reveal_nonce_round` | Frozen pair, Alice and Bob public nonces | Reconstructed and checked `nonce-round` snapshot |
| `signing_context` | Binding, role, purpose, optional `nonce_round` | Exact role/purpose commitment with round digest and full round |
| `validate_nonce_round` | Round object | Revalidated session, binding digest, round ID and round digest |

Every commitment uses canonical sorted-key ASCII JSON and:

```text
SHA256("PTLC/offline-transcript/v1\0" || stage || "\0" || canonical_payload)
```

An opening payload includes schema, stage `nonce-opening`, session ID, leg, exact chain-binding digest, round ID, role and full public nonce. The commitment pair includes the complete chain binding and both role hashes. The revealed round includes that complete pair, its digest, and both public nonces. The signing context includes the round and its digest alongside the exact chain binding, role and purpose. Validators rebuild all stages; caller-supplied digest fields are never accepted as authority.

Equal role hashes, equal Alice/Bob nonce bytes, malformed shapes, reflected or swapped openings, mismatched roles/rounds/bindings, and unknown fields reject. Recomputing hashes for a different valid round produces a different signing context. The journal also pins one round for each leg, so a completion cannot silently switch away from its partial-signature round.

These factories describe a collection of matching supplied values. They do **not** establish that Alice and Bob authenticated each other, committed before seeing the other opening, received any packet, or durably stored extraction material. A caller can compute all public values locally. The hash layer is an application binding for this candidate; it is not a new MuSig security proof, a requirement imposed by BIP327, or a standardized interoperable swap wire protocol.

## Journal v2 binding and duplicate history

The first operation for a leg fixes its nonce-bound round or legacy static mode. Subsequent operations for both roles and all purposes must use that exact mode and round. Static contexts are retained solely for existing qualification and cannot be mixed into a nonce-bound leg. Session-wide funding and Zenon-entry pins from Stage 2 remain mandatory.

For a dynamic round the journal records ordered Alice/Bob hashes:

```text
SHA256("ptlc-offline-public-nonce-v1\0" || full_public_nonce_bytes)
```

This domain deliberately excludes session, leg and role so identical full encodings already seen in another visible round scope reject. The same pinned round may support its separate Alice partial, Bob partial and designated completion operations. Each role/purpose scope remains one-use. On reload, stored operation round digests, round pins, nonce hashes and implied leg sets are checked for consistency in addition to checkpoint verification.

This detects only identical complete public nonce encodings in this journal's retained state. It does not detect partial component reuse, related nonces, nonce reuse hidden in another journal, cloned secret state, or restoration of both matching database/checkpoint copies. It is not a proof of fresh entropy. No secret nonce or witness is stored. Storage v1 is quarantined without migration; there is no automatic reset to bypass existing operation state.

## Test-only Rust nonce owner

`qualification/tests/nonce_lifecycle.rs` exercises the pinned `musig2` APIs. A `Generated` owner holds one library nonce and exact key aggregation context, message, adaptor point, binding digest, round ID and role. The derivation extra input binds the application context; it does not replace fresh entropy. Test seeds are fixed, publicly known and unsuitable for funds.

`Generated::seal(self, ...)` consumes the generated owner, parses both public nonces through the backend, and checks its own nonce position. A refusal drops that owner. A successful seal returns `Ready`, which retains the full immutable round and exact `KeyAggContext`, including signer order and Taproot tweak. It does not accept a caller-supplied aggregate x-coordinate as a substitute.

`Ready::sign_once` checks process/thread ownership, then takes the `Option<SecNonce>` before request comparison or backend work. A context mismatch, injected failure, backend rejection, or unwinding panic leaves the local owner spent. A successful result is checked with the participant's actual public nonce and exact aggregate context. Calling it again cannot recompute a partial signature. The wrapper exposes no secret serialization, `Clone` or secret `Debug` interface. This is source-level encapsulation within a test module, not hardened custody.

The [pinned nonce source](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/nonces.rs) exposes cloning and serialization on `SecNonce`; the inspected type has no zeroizing destructor. Moving it into the [pinned partial-signing API](https://github.com/conduition/musig2/blob/5a09b1197b1b5c621a5a9abc60fa95fa84a1da30/src/signing.rs) therefore does not itself prevent all copies. The test wrapper avoids these facilities but cannot prevent memory snapshots, reconstructed deterministic inputs or another implementation from bypassing it. A regression explicitly reconstructs the same inputs and obtains the same public nonce.

Foreign-thread refusal is executed. The Rust PID check is inspected but has no fork test. Neither ephemeral type is durably persisted, connected to SQLite, protected from power loss, or tested for secure erasure. The separate Python fork/process tests apply to the public journal only.

## Shared fixture and verification boundaries

[`nonce_rounds.json`](../qualification/fixtures/nonce_rounds.json) contains two public rounds. The Bitcoin example uses the existing actual Taproot output key/tweak and claim sighash; the Zenon example uses the existing contract-message digest and distinct signer keys. The Rust test asserts signer keys, aggregate keys and adaptor point against session terms, regenerates both public nonce sets and partial signatures, verifies the pre-signatures, completes and verifies both signatures, and checks extracted witness commitments. Tests compare the full public fixture without rewriting it.

Python independently rebuilds static and nonce-round canonical hashes and requires exact agreement with the Rust fixture. It also exercises six journal scopes and exact replay using the fixture's public bytes. Its callback **loads no signer and computes no partial signature**. Separate Go checks parse public nonce points, verify final signatures under the historical core dependency, and place the new Bitcoin signature in the actual claim witness for script execution. Shared bytes connect these finite checks, not the runtime components.

## Next integration requirements

1. Authenticate peer identity and bind transport messages to agreed roles and sessions. Implement a durable artifact-exchange state machine with size limits and explicit cancellation/reconciliation behavior.
2. Enforce verified artifact order, including Bob retaining the full verified Zenon pre-signature and extraction context before releasing his last contribution. The current journal does not authorize signing based on received partials or retained pre-signatures.
3. Define a fresh-entropy and secret-memory policy and a backend-specific worker interface. Qualify the actual journal-to-worker consumption/output boundary under process death; no component may silently regenerate a nonce after uncertainty.
4. Resolve restored-copy/clone protection and authenticated chain observations and timing. Independently assess the exact adaptor construction and application protocol before node integration.

The executed evidence and intermediate failure are recorded in [STAGE3_VALIDATION.md](STAGE3_VALIDATION.md).

## Stage 71: durable invocation remains a separate gate

The [finite nonce invocation comparison](NONCE_INVOCATION_MODEL.md) demonstrates
why locally consumed copied journals and rejection of stale results do not
prevent repeated work with the same underlying nonce. It also exposes a split
check/burn race and restored-authority bypass. Its shared atomic durable consume
reference premise is unimplemented and introduces no secret nonce, new worker
or bridge to the test-only Rust owner above. Exact symbolic output replay is
separate from actual signature bytes. Fresh entropy, secure memory, copied-state
protection and independent cryptographic review remain unresolved.

## Stage 72: copied permission after consumption

The [post-consumption grant comparison](NONCE_GRANT_COPY_MODEL.md) covers the
already granted worker and cached-permission cut deliberately excluded from
Stage 71. A copy can retain permission after a shared durable burn or effect
mark, producing repeated work despite result fencing and receipt deduplication.
The conditional reference assumes a nonexportable custody boundary through the
effect. No private state, real signer bridge or physical atomicity is implemented.
The Rust test owner's source encapsulation and public journal qualification
retain their existing scopes. Entropy, secure memory, restored-copy protection
and independent construction review remain unresolved. See [validation](STAGE72_VALIDATION.md).

## Stage 73: existing context and explicit public arguments

The [public partial intent](PUBLIC_NONCE_INTENT.md) retains the existing complete
context, including its revealed round, and explicitly projects the public
parameters described by it. Ordered nonces remain Alice/Bob even for Bob's
partial; Bitcoin's declared Taproot tweak stays separate from Zenon's untweaked
aggregation. No curve/key arithmetic, new nonce, signer, current authority or
private consumption boundary is added. Public bytes and declared keys are not
actual consumed-input evidence. Exact replay can pass repeatedly without
one-use or freshness. The journal and test-only Rust owner retain their separate
scopes. See [validation](STAGE73_VALIDATION.md); application/core remain NO-GO.

## Stage 74: individual nonce inputs in public verification

The [fixed intent conformance](PUBLIC_NONCE_INTENT_CONFORMANCE.md) parses both
components of each public nonce and verifies existing partials with the indexed
signer and individual nonce. Swapping Alice/Bob full nonces leaves their
aggregate sum unchanged but rejects each original partial. No nonce generation,
private signer, consumption registry, entropy or custody mechanism is added.
The public grammar and separate test-only owner retain their prior scopes.
See [validation](STAGE74_VALIDATION.md); application/core remain NO-GO.
