# Reference swap protocol requirements

Status: **DRAFT - requirements, not an executable client.** [CANDIDATE-01](TRANSACTION_GRAPH.md) now fixes roles, funding order, Bitcoin spend/refund graph and reveal direction for offline modeling. The backend, complete transaction/signing implementation and independent protocol review remain unresolved. These requirements alone do not establish safety.

Scope and component ownership are defined in [SCOPE.md](SCOPE.md). Cryptographic candidates and selection decisions belong in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md); evidence limits belong in [EVIDENCE.md](EVIDENCE.md).

## 1. Objects that must not be conflated

- `T = tG` is an adaptor point and its swap-specific secret scalar. It is not a wallet's long-term signing key.
- A signing public key `P` authorizes a particular spend. It may differ between the two chains and from `T`; aggregation, if used, requires its own selected protocol.
- A pre-signature is a protocol-specific artifact. Its verification, completion, and extraction rules must come from the selected construction, not from the existence of ordinary BIP340 verification.
- A completed signature can reveal `t` to a party holding the relevant extraction material before any transaction confirms. A failed or later-reorganized transaction does not erase that knowledge.

Both legs must be demonstrably coupled to the same intended adaptor secret despite signing different messages and possibly using different keys. Parties must verify all public inputs and pre-signatures before they reach any graph-specific point where funding or secret disclosure becomes irreversible.

## 2. Pinned Zenon contract behavior

The following describes [PR #13 implementation at `8ed1ca1`](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/implementation/ptlc.go), not an activated network feature:

| Operation | Relevant behavior |
| --- | --- |
| `Create` | Accepts a supported point type and a 32-byte lock, a nonzero amount, and a future expiration. The send-block hash becomes the contract ID; the sender is the refund owner. No destination is fixed in the Create parameters. |
| `Unlock` | Verifies an ordinary signature under `PointLock` over `H(id || caller address)`, then deletes the entry and constructs a transfer to that address. |
| `ProxyUnlock` | Uses `H(id || destination address)`; the submitting account can differ from the destination. The signature must authorize that destination. |
| `Reclaim` | Only the original sender can reclaim, at or after expiration; success deletes the entry and constructs the refund transfer. |
| Expiration | Uses the frontier momentum timestamp during contract execution. At equality, Create and Unlock reject while Reclaim is eligible. Sending a request before the deadline does not prove timely contract execution. |

The contract does not construct adaptor signatures, validate an adaptor transcript, or extract `t`. Creation checks type and length but does not establish that a point encoding is usable. BIP340 point parsing occurs at unlock. The unknown stored-point-type branch needs explicit fail-closed handling before activation; ordinary Create already rejects unsupported types.

Existing [expiry tests](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/tests/ptlc_test.go#L418-L541) and [post-spend rejection tests](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/tests/ptlc_test.go#L698-L846) must be preserved. A successful third-party ProxyUnlock and explicit rejected-unlock state/transfer assertions remain useful extensions. This document does not report those tests as executed.

The client must reproduce the selected core message encoding exactly. Client transcript domain separation does not authorize changing the contract's signed message format. Any proposed core-format change is a separate consensus-visible decision.

## 3. Immutable session commitments

Before funding or exchanging an artifact that permits secret extraction, the selected protocol must establish and independently verify an authenticated transcript containing:

| Commitment | Required verification |
| --- | --- |
| Session identity | Fresh session ID; protocol/version and construction identifiers; participant roles; chain/network identities and applicable genesis/checkpoint identity. Avoid confusing a reset devnet or another session with the intended chain. |
| Economic terms | Exact integer amounts, Bitcoin output value, Zenon token standard, expiry terms, expected costs, and destination/refund addresses. Never use display-rounded values as acceptance criteria. |
| Signing conditions | Public keys, adaptor point, accepted encodings, any aggregate-key coefficients, Taproot tweaks, nonce commitments, signed messages, and signature hash modes as required by the chosen construction. |
| Bitcoin funding | Exact outpoint, amount, script/output key, spending paths, refund conditions, and required confirmation policy, verified from the intended chain. |
| Zenon funding | Exact send-block/contract ID, stored amount, token, point type/key, expiration and refund owner; the intended claim destination must also match the signed message. A broadcast funding request alone is insufficient. |
| Recovery artifacts | Required refund transactions, scripts, key material, signing shares, or other recovery data established at the graph-specific time that makes funding safe. |

The order in which these commitments become available is specified by the candidate graph. In particular, the Zenon signature message depends on a concrete funding ID: CANDIDATE-01 waits for the actual entry before its Zenon signing exchange. This table is not a claim that every artifact can simply be exchanged before funding.

Counterparty messages, node responses, and local database records are inputs to verification, not substitutes for it. A claim-ready decision must re-check the actual observed funding conditions and remaining execution margin, not only an earlier quotation or transcript.

## 4. State and irreversible knowledge

Keep at least four separate dimensions of state:

| Dimension | Examples | Transition rule |
| --- | --- | --- |
| Protocol phase | Negotiation, verified artifacts, funding, claim/refund monitoring, settled, recovery required | Allowed transitions depend on the selected graph and role. Phase names alone do not authorize an operation. |
| Chain observations | Unknown, broadcast observed, included, confirmation threshold reached, replaced, reorganized, spent | Observations can be invalidated or revised. Record block identity and evidence, not only a Boolean confirmation flag. |
| Secret exposure | No exposure known; disclosure authorized/possibly made; secret locally extracted | Once disclosure is possible, never revert the session to a secret-hidden state because of a reorg, failed RPC, rejected spend, or rollback. Persist exposure intent before releasing a revealing artifact. |
| Signing state | Unallocated, reserved, consumed, output durably recorded, outcome uncertain | A consumed nonce never becomes available again. Recovery must preserve this property across sessions, processes and restored storage. |

Secret possession and secret exposure are separate facts. A participant that originally generates `t` knows it before disclosure. A counterparty may know it even when local delivery confirmation is unavailable. Persist this uncertainty conservatively.

A timeout or connection failure after submission yields an **unknown outcome**, not permission to sign again or construct a conflicting replacement. Recovery first reconciles exact artifact bytes, transaction/block IDs, signatures, contract state, and chain history. A byte-identical retransmission is a distinct operation that may be allowed only by an explicit, idempotent policy; it is not a new signing session.

## 5. Durable signing and process ownership

The chosen library's nonce rules remain authoritative. The application additionally requires:

1. Obtain exclusive ownership before loading mutable session or signing state, and retain it through validation, signing-state updates and durable persistence. Atomic file replacement alone does not prevent stale writers.
2. Bind reserved randomness and nonce state to the precise key, participant role, protocol, session and message set. Do not reconstruct or silently repurpose it for another attempt.
3. Durably mark a nonce consumed **before** executing a signing operation that can release a nonce-dependent response. If a crash leaves consumption uncertain, discard the nonce. A lost response is not a reason to reuse it.
4. Persist any safe-to-replay output and secret-exposure intent before transmission. Recovery must distinguish output replay from secret-dependent computation. Do not place private scalars or secret nonces in logs or public fixture files.
5. Treat process crashes, concurrent launches, stale locks, filesystem failures, and restoration of older snapshots as explicit cases. PID-only ownership and restoring an old "unused" flag are insufficient. The selected storage/ownership mechanism must either prevent stale-state signing or fail closed.

A preliminary [public-state journal](SESSION_JOURNAL.md) now qualifies SQLite/checkpoint ordering, exclusive process/thread ownership and synthetic producer failures. It never stores a library secret nonce. Complete cryptographic nonce ownership, restored-copy protection and production platform durability remain unresolved; the bounded process tests are not a full signer crash-safety claim.

[Stage 3 nonce rounds](NONCE_ROUNDS.md) bind both public nonces, roles, round ID and exact chain context to each operation. Journal v2 seals each leg's round and rejects duplicate full public nonce encodings across visible round scopes. A separate Rust test owner consumes an ephemeral nonce on any signing attempt before request checks and backend calls. These are separate qualifications: no durable signing bridge or authenticated exchange ordering is implemented.

[Stage 4 managed exchange](ARTIFACT_EXCHANGE.md) uses journal v3 to retain Bob's verified Bitcoin bundle, bind the Zenon context, retain Alice's verified partial and the matching complete verified Zenon bundle, and persist exact release bytes before returning them. This is public artifact verification and local ordering. The verifier does not sign; chain/timing authorization and authenticated delivery remain external requirements.

[Stage 5 completion](COMPLETION_LIFECYCLE.md) uses journal v4 for Alice inbound bundle verification, durable synthetic-producer consumption and exact final output replay. Bob stores the exact Zenon observation before actual final-signature verification, witness extraction and Bitcoin adaptation; only that same public input may be retried after an incomplete recovery. Alice private signing, full funding/transaction handling and authenticated observation selection remain unimplemented. Joint restoration of both old storage copies defeats the local consumption history and is explicitly tested.

[Stage 6 reconciliation](OBSERVATION_RECONCILIATION.md) adds a distinct Bob-only path for a different positively verified observation. An exact original-packet digest prevents stale selection; the final stored snapshot retains both the completed replacement and the superseded original. Public computation can be retried after pre-commit interruption if the caller resupplies the replacement. This does not reset any signing ownership or authenticate the observation.

[Stage 8 admission](RECOVERY_ADMISSION.md) now requires remaining local allowance for Bob recovery retries. Each structurally eligible attempt is charged durably before the worker, including failed or interrupted computation. Reconciliation preserves the old candidate on failure while advancing this separate allowance. Exhaustion is a local stopping condition, not a safe funded-swap recovery policy or a cryptographic verdict.

## 6. Timing, refund, and fee policy

The selected graph must identify which leg is funded first, which claim exposes the secret, and which deadline leaves the other party time to claim. It must justify the deadline difference using explicit assumptions for confirmation/reorg policy, detection delay, signing and recovery latency, inclusion delay, clock semantics and resource availability. No arbitrary timeout value is approved here.

Bitcoin locktime rules and Zenon's momentum timestamp are different clocks. A stalled chain, censorship, an offline participant, or a reorg beyond the assumed bound can defeat the timing argument. A local node helps validate data; it does not guarantee inclusion or finality. Each risk bound must be stated without calling a chosen confirmation count absolute finality.

Every funded leg needs a recovery path the rightful party can execute without fresh counterparty cooperation when the specified conditions hold. That path may require data or signatures obtained before funding. A written refund path is insufficient if it lacks spend authority, fee capacity, or timely access to the network.

Claim/refund overlap and near-expiry disclosure require explicit analysis. A revealed secret may survive an unsuccessful claim while the original owner later refunds. The design must identify the last safe disclosure point and what remains recoverable after it; it must not claim that refund automatically restores both parties to their starting balances.

Bitcoin fee changes must be planned against the actual transaction graph, signature hash modes and adaptor transcript. A replacement can change the message, ID or spend dependency. RBF/CPFP availability and pinning exposure must be evaluated for the selected graph; neither is assumed. Any newly signed transaction requires a policy-approved transition and fresh nonce state. Zenon also needs sufficient execution resources, including the applicable Plasma/PoW behavior and admission/inclusion margin, for claim and reclaim attempts.

## 7. Decisions required before executable protocol work

- Select the cryptographic construction and implementation, including complete pre-signature verification and extraction rules.
- Implement and assess CANDIDATE-01's exact Bitcoin messages, signature hash modes, transaction dependencies and fee/resource policy.
- Verify the candidate's roles, funding order, reveal direction and artifact-exchange order in the complete implementation. The opposite trade direction remains unqualified.
- Define chain-validation, confirmation/reorg, timing, execution-resource and availability assumptions; derive concrete deadline and abort rules.
- Select durable session/nonce storage and ownership, including behavior under restored snapshots and unknown outcomes.
- Obtain an independent review of the resulting safety argument before treating a happy-path regtest/devnet demonstration as a usable protocol.

Later acceptance scenarios must include normal settlement, unilateral abort/refund, invalid artifacts, substituted funding, one-leg funding, delayed inclusion, claim/refund races, fee pressure, restart at each irreversible step, concurrent processes, reorgs, and secret disclosure without successful on-chain execution. Expected outcomes must account separately for principal, fees, lock duration and residual recovery work.

## Nonce invocation acceptance clarification

[Stage 71](NONCE_INVOCATION_MODEL.md) makes an existing requirement testable in a
finite symbolic comparison: the same secret nonce must not authorize another
nonce-dependent computation merely because the prior result was lost, refused
or fenced by a newer epoch. Consumption must cover every usable copy before
work. Independent local journals and locks do not cover a restored secret copy;
a separate availability read and later durable burn can race. Rejecting an old
output cannot reverse the computation.

A candidate bridge must state its shared authority, atomic consumption cut,
complete backend input binding, ambiguity behavior and exact retained-output
replay policy. It must qualify those real cuts separately from the public
journal and ephemeral test owner. No nonrollback authority, fresh-entropy
policy, secret-memory mechanism or signer interface is selected here. The
reference model assumes these consumption premises and is not their
implementation or an adaptor-protocol security proof.

## Post-consumption grant acceptance clarification

[Stage 72](NONCE_GRANT_COPY_MODEL.md) separately examines the permission created
by a durable consume step. A candidate private bridge must cover copied grants,
passed checks, exported permits and suspended worker state through the actual
nonce-dependent effect. A unique grant or spent authority word is insufficient
when a copy already holds permission. Result deduplication and epoch refusal
cannot undo repeated computation.

The model's reference couples the final check and effect in one indivisible
symbolic transition, with no exported permission in between. That is an
unimplemented premise requiring independent custody and physical-failure
qualification. It selects no hardware, service, signer interface, private retry
or production mechanism. The requirement remains separate from this comparison
and from any future cryptographic construction or implementation assessment.

## Public invocation intent acceptance clarification

[Stage 73](PUBLIC_NONCE_INTENT.md) supplies a public-only partial-input grammar,
retaining the full existing context instead of treating another descriptive
digest as authority. Exact input agreement remains distinct from authorization
to consume a nonce and evidence of what an actual backend consumed. A future
private bridge must independently qualify its real key aggregation and tweak,
message, adaptor, public nonce association and irreversible effect boundary.
The public schema contains no private key, nonce, consume grant or recovery
credential. A successful comparison implements neither model's custody premise
and supplies no production or core progression permission.
