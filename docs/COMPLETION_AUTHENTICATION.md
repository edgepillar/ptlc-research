# Offline completion-envelope qualification

Stage 9 qualifies a signature envelope for exact Alice-to-Bob completion bytes
relative to locally selected terms and authentication-key pins. It does not
enroll peers, implement transport, or require authentication at journal entry
points. Its output is opaque authenticated bytes; completion validation must
still run before treating those bytes as a valid claim.

## Requirements and selected experiment

The protocol needs authenticated participants and agreement on the exact
session and message purpose. Opaque participant IDs and transcript hashes alone
do not provide authentication. Pin bootstrap, storage, compromise recovery,
rotation, restart continuity and authorization remain unresolved requirements.

This experiment uses a separate BIP340 key for each participant. It reuses the
locked `bitcoin` 0.32.7 `secp256k1` verifier and SHA-256; no dependencies were
added. This qualification choice does not approve a production identity or
signing system. [BIP340 at the pinned revision](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki)
defines the underlying signature and key encodings. This envelope and its
domain are local experimental framing, not a Bitcoin or Zenon standard.

`authentication.context` requires validated local terms and two independently
supplied x-only public-key pins. Never obtain those pins by copying them from
the incoming envelope. A message signed by an attacker-selected key establishes
no relationship with the intended peer. The pins must differ. The Python
factory also rejects overlap with the x-coordinates of both legs' signer keys,
Bitcoin internal/output/refund keys, the Zenon aggregate key and the adaptor
point. Compressed-key parity cannot bypass this comparison. Generic destination
scripts are not parsed for keys; encoded inequality does not prove independent
generation or absence of related keys. Rust parses both pins as actual curve
points; Python's encoding check alone is insufficient for that claim.

## Exact signed bytes

The context contains exactly eleven string fields:

| Field | Value |
| --- | --- |
| `schema` | `ptlc-completion-auth-context-v1` |
| `algorithm` | `BIP340-SHA256` |
| `purpose` | `zenon-completion` |
| `sender`, `recipient` | `alice`, `bob` |
| `session_id`, `terms_digest_hex` | Local terms commitment's session and digest |
| `alice_id_hex`, `bob_id_hex` | Distinct opaque IDs from those terms |
| `alice_auth_key_hex`, `bob_auth_key_hex` | Distinct locally supplied 32-byte pins |

Canonical JSON is ASCII with sorted keys, compact separators, exact field names
and lowercase hex. No integers or optional fields exist in the context. The
32-byte BIP340 message is:

```text
SHA256(
  "PTLC/completion-auth/signature/v1" || 0x00 ||
  canonical_json(context) || 0x00 ||
  uint32_big_endian(len(payload_bytes)) || payload_bytes
)
```

The envelope has exactly `schema`, `context`, `payload_hex`, `signature_hex`;
its schema is `ptlc-completion-auth-envelope-v1`. Payload length is 1 through
32,000 bytes; the authentication signature is exactly 64 bytes. The envelope
must be canonical JSON without a trailing newline, at most 65,536 bytes. Its
context must equal the independently reconstructed local context before any
worker runs. Duplicate keys, escaped aliases, extra fields and noncanonical
whitespace reject. Payload bytes are never normalized.

## Public verifier boundary

The worker request has the same fields with schema
`ptlc-completion-auth-request-v1`. The executable accepts canonical JSON plus
an optional single final LF, bounded to 65,536 total bytes. It verifies Alice's
signature over the message above. The request supplies all trust inputs; the
executable alone cannot establish pin provenance or recompute terms from a
chain or journal.

Success returns only `schema: ptlc-completion-auth-result-v1`, literal
`valid: true`, and `request_digest_hex`: SHA256 of
`"PTLC/completion-auth/request/v1" || 0x00 || canonical_json(request)`.
It never echoes a payload. The Python adapter uses the existing bounded public
worker and requires the exact canonical result, optionally with one LF.
`authenticate` checks the full request binding and returns its own retained
immutable bytes. Fake callbacks test sequencing only; a trusted callback can
lie. Interrupts and process-exit exceptions propagate; ordinary verifier
failures sanitize to `AuthenticationError`.

The executable has no signing interface. Synthetic signatures are generated
only in Rust test code from public test scalars. No private authentication
store, entropy source, secret-memory claim or signer lifecycle is implemented.

## Admissibility, replay and remaining gates

The helper is stateless: verifying an identical envelope again succeeds. There
is no counter, nonce, timestamp, expiry or freshness claim. Two different
messages can both authenticate. Authentication does not select the correct
observation, prevent an authorized malicious peer from exhausting recovery,
or prove the enclosed Zenon signature valid.

The integration harness composes authentication followed by Bob's existing
recovery API. Authentication failure leaves that harness's journal and allowance
untouched. A valid authentication over an invalid Zenon completion succeeds at
the envelope layer and fails actual recovery, consuming its admitted attempt.
Another test deliberately calls the journal without authentication and succeeds.
Consequently Stage 9 does not enforce authenticated admission.

Journal v6 and its schemas are unchanged. No pin is durably stored there. The
helper's verification calls are outside Bob's recovery allowance; repeated
requests, sessions and restored copies remain separate resource-policy issues.
Per-worker bounds are not aggregate denial-of-service protection. The envelope
provides no confidentiality, peer anonymity, delivery evidence or chain trust;
reusing public authentication keys can link sessions.

Before integration, define and review trusted pin establishment and durable
binding, rotation/compromise semantics, all inbound artifact types, replay and
reconciliation policy, verification admission and safe exhaustion behavior.
Private signing, clone protection, authenticated chain observations and funded
timing policy remain separate gates. A core port and live swap remain no-go.
