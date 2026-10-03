# Constructing a candidate from a public signature

Stage 12 adds `completion.bob_candidate_from_signature(state, signature)`.
It constructs an unverified completion candidate from exactly 64 public
signature bytes and a retained Bob exchange snapshot. It does not observe a
chain, authenticate a source, authorize recovery, or verify the signature.

## Construction contract

```python
snapshot = bob.get_exchange(session_id)
candidate = completion.bob_candidate_from_signature(snapshot, signature_bytes)
```

The signature must be an exact `bytes` value of length 64. Byte subclasses,
mutable buffers, hexadecimal strings and other sizes reject. The snapshot must
pass the existing full exchange structure/causal checks and be in
`RELEASE_RECORDED`. Earlier stages, completed sessions, Alice states and corrupt
stored contexts reject. Ordinary errors become a sanitized `CompletionError`;
explicit cancellation exceptions are not swallowed.

The helper copies the validated snapshot and reconstructs the complete packet
using its retained Zenon signing context. No remote session, role, purpose,
binding, nonce round, source label, inclusion claim or provenance argument is
accepted. It emits the existing canonical `ptlc-alice-zenon-completion-v1`
packet with the original Alice/Bob role labels and the supplied signature.
The existing bounded request builder checks structural compatibility before
return. Packet schemas, journal v7, fixture bytes and dependencies are unchanged.

This packet is locally constructed. `sender_role: alice` describes the existing
format and completion context; it is not evidence that Alice sent or
authenticated a message. An auxiliary authentication envelope is unnecessary
for construction. Locally configured authentication pins neither authorize
the source nor cause the helper to verify it.

## Validation is not provenance or cryptography

The exchange validator checks structural/causal consistency and reconstructed
request hashes. Those hashes are not signatures or an external trust anchor.
The caller must supply its retained local state; passing a coherently rewritten
snapshot does not become trustworthy because the helper accepts it.

Taking a journal snapshot uses the existing owner checks. The pure helper
does not acquire a lock or prove the snapshot is still current. A snapshot and
later recovery are separate operations. Existing recovery stage, context and
exact-observation comparison checks still apply when the caller submits a
candidate.

Any correctly sized signature, including one that is mathematically invalid,
can produce a structurally valid candidate. Actual recovery must still verify
the signature, both retained bundles, the extraction point and the resulting
Bitcoin signature. A signature valid for another key/message is not valid for
this retained context. Changing only an application session label is not, by
itself, evidence that the chain-level signature will fail cryptographic checks.

## Explicit recovery and reconciliation

Construction invokes no callback or worker and writes no observation, receipt,
sequence, archive, exposure marker or recovery counter. Its output is not an
admission token. It can return a candidate even if the session's recovery
allowance is exhausted; later recovery still raises `RecoveryExhausted`.

A structurally valid but cryptographically invalid retained observation does
not prevent constructing a different candidate. Construction deliberately does
not apply the ordinary-recovery equality rule, so it remains useful for
[explicit reconciliation](OBSERVATION_RECONCILIATION.md). It cannot replace the
stored observation itself.

The caller separately chooses whether to invoke ordinary recovery or
reconciliation. Ordinary recovery pins the original candidate and consumes an
allowance before the worker. A different retained candidate still rejects
ordinary recovery. Reconciliation still requires the exact original-packet
digest and remaining allowance; only positive verification commits the
replacement, archive and output. Stale comparison, failure, interruption and
exhaustion retain their existing behavior. No allowance is reset or refunded.

Pure construction records no witness exposure. A false stored marker therefore
does not establish secrecy, and rejection does not authorize signing again.
Source authorization, observation retention and the policy for selecting one
candidate remain separate unresolved decisions.

## Evidence boundary

Synthetic tests compare the constructed packet with the existing exact fixture,
check defensive input handling, and inspect unchanged journal bytes/state
before and after construction. Separate integration tests use the actual
public Rust verifier to recover the expected Bitcoin result and reject invalid
or foreign-context signature bytes. Fake callbacks in unit tests establish
sequencing behavior only. See [Stage 12 validation](STAGE12_VALIDATION.md).

This is an input adapter for offline qualification. It adds no transport,
authenticated observation source, chain identity, funded timing policy,
private signing, restored-copy protection or safe exhaustion policy. Live
swaps and a core port remain no-go.
