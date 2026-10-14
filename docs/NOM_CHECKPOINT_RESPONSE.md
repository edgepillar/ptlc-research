# Selected NoM checkpoint response signatures

This additive offline construction binds a root grant and a candidate/outage
response to the [minimum-bound discovery protocol](NOM_CHECKPOINT_DISCOVERY.md).
It qualifies public signature mathematics under selected reference keys. It
implements no provisioned service, authenticated current read, nonrollback
storage or work entry. Every comparison stays **HOLD**, recovery **NONE**,
application/core **NO-GO**.

Baseline:
[`2bf22c4abcf253807b46d04138ae1f50759a60ab`](https://github.com/edgepillar/ptlc-research/tree/2bf22c4abcf253807b46d04138ae1f50759a60ab).
All 201 earlier measured inputs remain unchanged. Neither the exact reference
query nor unsigned discovery is modified or silently promoted to authentication.

## Requirements and the selected reference role

Operational authority must be provisioned independently of incoming replies and
coherently restorable consumer state. A service must retain complete UNKNOWN
charges and original operations across outage, restart and key transition. Valid
mathematics under a packet-selected root cannot meet that requirement. A signed
response must also identify the instant at which the service evaluated the read
against serialized current retention state. A challenge and a counter above a
minimum cannot establish that instant or rule out a withheld later head.

`select_response_authority` retains an actual complete independently selected
discovery read, a root public-key encoding and a positive authority epoch. The
existing service policy fixes the response key through `checkpoint_key_hex`;
the peer cannot supply a replacement key. The root encoding must differ from
that response key and every historical source/custody role in the known minimum.
It must also differ from those roles in the candidate's actual complete history.
These encoding checks establish no separate organizations or custody domains.

The declaration binds its exact schema and purpose, selected algorithm,
authority epoch, root key, complete service policy, policy digest, stable work
scope and `independent-reprovisioning` transition label. An epoch is neither a
checkpoint sequence nor a new allowance. The grant is stable across challenges
and changes of the known minimum within the same service/work scope. Each caller
must still independently select its actual complete minimum and root/epoch.
This profile implements no root retirement, key migration or service bootstrap.

The disclosed synthetic response encoding was already used as a reference service
key and appears in an old enrollment fixture. That old role and its signature
permission are not reused. A new root grant and distinct message domains supply
the selected checkpoint-response role. The root is a fifth encoding relative to
the three historical source/custody roles and selected response key. Real
provisioning remains an unfilled gate.

## Public message construction

The selected construction uses the key/signature widths and verification
algorithm in the pinned
[BIP340 specification](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki).
The project supplies its own canonical framing and SHA-256 message domains:

| Signature or binding | Exact public payload | Domain before NUL |
| --- | --- | --- |
| Root grant | Complete selected declaration | `ptlc-nom-checkpoint-response-authority-message-v1` |
| Response | Complete declaration, discovery query digest and prior complete discovery-message digest | `ptlc-nom-checkpoint-response-signed-message-v1` |
| Native result | Entire request, including both signature encodings | `ptlc-nom-checkpoint-response-request-v1` |

Each digest is `SHA256(domain || NUL || canonical_ASCII_JSON(payload))`. The
response payload additionally fixes its own schema and
`checkpoint-candidate-or-outage-math-only` purpose. It reuses the old discovery
preimage as a commitment, not an old signature permission. That preimage binds
the complete query, reply, known prefix, source views and opening commitments.
Actual complete contexts must already be retained; a digest cannot construct them.

The peer envelope contains only the complete declaration and two public
signatures. Its declaration must exactly match the independently selected one.
The public native request also carries the two independently computed discovery
digests. The native worker checks packet shape, service policy/digest, two distinct
curve keys and both signatures. It cannot establish where those digest fields
came from, provision the packet root or reopen actual custody. Those remain
separate Python/caller premises and independent application gates.

Requests/envelopes are bounded at 8 KiB, require exact fields, lowercase fixed-width
hex and positive integers at most `2^53 - 1`, and retain the twelve-level JSON
limit. The earlier query/reply bounds remain 32 KiB and sixteen complete reference
checkpoints. Python peer envelopes accept no trailing LF; native stdin permits
one. Duplicate fields, noncanonical bytes, numeric aliases and extra fields refuse.

## Verification and immutable comparison

`response_signature_request` validates actual discovery inputs and complete
openings before invoking a math verifier. Missing custody, divergent lineage,
changed service/role and cached positive openings supplied with outage refuse.
The comparison first preserves the larger complete local/candidate UNKNOWN list.
The verifier receives a defensive public request copy. Expected request digest
and message digests are fixed before the call; argument mutation and incomplete,
numeric or differently bound result flags refuse. One successful verifier
assertion leaves every work, retry, bootstrap and replacement permission false.

The Python module performs no curve arithmetic, signing, file/process/network
entry or service mutation. Its callback can lie: an echo callback reports positive
flags for a zero response signature, while the actual native worker refuses that
exact request. The callback and measured executable/runtime are trust premises.
Remeasurement is neither atomic launch attestation nor a sandbox. `signature_verifier_calls`
counts a callback, not a native process; actual native exits are measured separately.

Rust uses the existing locked Bitcoin/libsecp256k1 dependency. Go independently
checks the same public fixtures using the existing locked btcec dependency. No
dependency version or core source changes. Signing exists only in a native test
generator with deliberately disclosed fixed scalar tags 111/112 for roots and 83
for the response key. There is no application signer or private-key input. No
specification text, code or vectors are copied; the project's existing MIT framing
and synthetic fixture conventions are reused.

## Successful unsafe controls and remaining gates

A newly signed response to a fresh challenge can still return the old minimum.
Two signed siblings above the same old minimum can both verify at the same counter.
A fresh equivalent selection of the coherently restored old complete context can
reuse its exact prior public signature result. This last control is a reference
selection comparison, not a physical storage restore. A packet-selected alternative
root verifies mathematically but cannot replace the caller's selected root. A signed
outage proves no absence. The forged callback control exposes the separate runtime
trust boundary. Every result remains HOLD/NONE and establishes no unique latest head.

Independent root/service/key provisioning, current serialized read evaluation,
external nonrollback retention, shared atomic transitions, actual original-operation
entry, independent assessment and physical power-loss qualification remain unfilled.
Deployment, node activation, wallet access, application signing, transaction
construction, broadcast and real funds are absent. See the
[qualification boundary](NOM_CHECKPOINT_RESPONSE_VALIDATION.md).
