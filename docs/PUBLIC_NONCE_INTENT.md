# Public nonce invocation intent

Status: a public-only input projection and exact byte comparison. This is
repository research for `CANDIDATE-01`, not a standardized signing wire protocol,
private signer interface or nonce-consumption authority. Application and core
progression remain **NO-GO**.

## Existing objects and the selected addition

The preceding source, `1e1f4bb8bcaac684bcbc7577fd31276c8e0aa9d0`, already has
canonical staged [transcripts](../offline_session/transcript.py), revealed
[nonce rounds](NONCE_ROUNDS.md) and role/purpose signing contexts. These objects
bind the complete supplied session, chain binding and public nonce round. The
separate test-only [Rust owner](../qualification/tests/nonce_lifecycle.rs)
constructs an actual key aggregation context and consumes its local nonce
before backend work. The public journal and Rust test owner remain separate.

A new descriptive digest would duplicate that transcript without establishing
which arguments a real backend consumes. The selected addition instead retains
the full existing signing context and makes its declared public partial-signing
inputs explicit. It reuses the existing validators and introduces no new hash,
worker, cryptographic arithmetic, fixture or private journal bridge.

## Selected grammar

[`nonce_intent.py`](../offline_session/nonce_intent.py) supports only
`bitcoin-claim-partial` and `zenon-claim-partial` contexts with a complete revealed
nonce round. Alice and Bob retain their existing allowed roles. Legacy static
qualification contexts and signature completion are refused by this factory.
Completion is a separate operation with different private-material and artifact
requirements; it is not reinterpreted as a nonce-dependent partial invocation.

The top-level object has exactly `schema`, `signing_context` and `public_inputs`.
The schema is `ptlc-public-nonce-intent-v1`. `signing_context` is the complete
validated existing object, including its binding, terms, public round and
preceding digests. It is not replaced by an opaque digest or a peer-selected
summary. The public projection contains exactly:

| Field | Derived supplied value |
| --- | --- |
| `operation` | Fixed `musig2-adaptor-partial` declaration |
| `key_aggregation` | Ordered Alice/Bob SEC1 keys, tweak declaration, declared base and signing x-only keys |
| `signer_index` | Alice zero or Bob one in the existing ordered lists |
| `message_hex` | Supplied Bitcoin claim sighash or the validated Zenon binding message |
| `adaptor_point_sec1_hex` | Adaptor encoding in the agreed session terms |
| `public_nonces_hex` | Full Alice/Bob public nonce encodings in that order, independent of caller role |

`key_aggregation` has exactly `ordered_signer_keys_sec1_hex`, `tweak`,
`declared_base_key_xonly_hex` and `declared_signing_key_xonly_hex`. Bitcoin uses
`{"kind":"taproot-xonly","merkle_root_hex":...}` with the supplied tapleaf hash,
internal key and output key. Zenon uses `{"kind":"none"}` and the supplied
aggregate key as both declared keys. The factory computes neither aggregation
nor tweak. These declarations must be checked against an actual backend context
in any future independently reviewed bridge.

`public_inputs(context)` returns a fresh dictionary; mutating it changes no
retained context. `encode_intent(context)` returns sorted, compact ASCII JSON
bytes with no trailing newline, capped at 128000 bytes. The existing transcript
validator rebuilds every staged commitment before projection. There is no
factory accepting a peer dictionary as the local expectation.

`require_exact_intent(context, wire)` first requires a plain `bytes` object of
2 through 128000 bytes. It then compares against the factory encoding of the
independently selected complete context. It parses no peer wire. Duplicate
keys, escaped aliases, whitespace, numeric aliases, unknown/missing fields and
trailing bytes all differ from the expected encoding and refuse. No untrusted
JSON depth traversal is needed. Success returns `None`; refusals use one fixed
message without echoing supplied values. Cancellation propagates without retry.

## What exact agreement does and does not establish

This comparison binds the complete selected public object and its projection.
The caller still selects the local context. A caller can select another
self-consistent synthetic context, and repeated checks of the same bytes can
all pass. There is no registry, consume step, attempt identifier, grant,
freshness check, independent participant approval, producer authentication or
current-policy observation. Adding any such claim to the wire is refused.
Returning `None` is not a credential for another component.

The existing transcript checks encoding shapes and supplied consistency. Its
Bitcoin sighash and aggregate/output key declarations are not recomputed here.
Curve membership, signer-key ownership, key aggregation and tweak arithmetic
remain backend responsibilities. The existing Zenon message rule is validated
by the transcript, not replaced by another computation in this module. The
checked-in public fixtures supply regression values; agreement with them is not
a new cryptographic assessment or measured backend invocation.

Public nonce equality across independently selected rounds is not prohibited
by this stateless factory. Its tests explicitly preserve that limitation.
The [public journal](SESSION_JOURNAL.md) retains its separate visible-history
checks. Neither layer detects every secret copy, related nonce component or
restored matching state.

The [pre-consumption model](NONCE_INVOCATION_MODEL.md) still uses symbolic complete
binding labels. The [post-consumption model](NONCE_GRANT_COPY_MODEL.md) still
fixes one binding and separately demonstrates copied granted-work permissions.
This grammar supplies no actual consumed-input evidence and meets neither
model's unimplemented shared/nonrollback custody premise. The models are not
rewritten to treat matching public bytes as permission to perform work.

## Before a real private bridge

The protocol requirement is to bind the actual complete backend input at the
irreversible nonce-use boundary. A future construction must independently
establish its source/producer, prove how actual keys, tweak context, aggregate
nonce, message and adaptor are obtained from the selected public inputs, and
qualify what the backend really consumes. Private key and nonce material must
not be added to this public grammar. A descriptive operation string or matching
artifact digest is not execution evidence.

The construction must separately protect every usable secret-nonce copy before
and after consumption, bind the actual effect to nonexportable authority, retain
the original output before delivery and specify uncertainty without permitting
another nonce-dependent computation. Fresh entropy, secure memory, physical
failure, current authority and independent cryptographic review remain open.
No backend, custody service, protected-use adapter, recovery or deployment is
selected by this input factory.

All four immutable source inventories, historical native profiles, existing
implementations/fixtures/workflow and three unfilled assessment reports remain
preserved. No independent review is claimed or requested. See
[Stage 73 validation](STAGE73_VALIDATION.md).

## Stage 74: a separate fixed-corpus conformance check

The [test-only conformance](PUBLIC_NONCE_INTENT_CONFORMANCE.md) binds four fixed
complete factory outputs to the existing public backend's ordered aggregation,
selected Taproot tweak, point parsing and verification of existing partial
fixtures. It adds no exported application or signer interface. This factory
continues to perform transcript/shape validation and exact byte comparison.
The Rust helper checks only projected public inputs and deliberately does not
replace full-context validation. Neither successful layer establishes actual
private signer consumption, participant authentication, freshness or custody.
See [Stage 74 validation](STAGE74_VALIDATION.md); application/core remain NO-GO.
