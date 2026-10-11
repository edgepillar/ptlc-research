# NoM observation requirements before original recovery

Status: source-pinned requirements, **not an implemented observer**. The current
two-journal qualifier still admits synthetic allowlist observations. Application
and core remain **NO-GO**. This document selects no RPC provider, proof protocol,
finality policy, signer, funded confirmation margin or network operation.

## Pinned source facts and their limits

This mapping references PR #138 at
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; it does not claim activation.

- [Create execution](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/embedded/implementation/ptlc.go)
  stores the Create send hash as the entry identifier, the sender as `timeLocked`,
  and the send token/amount with the decoded expiry, point type/key and destination.
  Unlock and reclaim are separate stateful execution paths; both remove the entry.
- [Account verification](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/verifier/account_block.go)
  separately checks hash, account signature/producer, previous account context,
  acknowledged momentum and descendants. For contract receives, the acknowledged
  height equals the original send's confirming height, and child acknowledgements
  must match their parent.
- [VM context selection](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/supervisor.go)
  uses the acknowledged momentum store for contract execution. Therefore the
  contract's frontier timestamp is not interchangeable with a newly queried
  latest-node timestamp. The observer must establish the correct confirming
  context, not infer it from wall time or reply labels.
- [Account headers](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/common/types/account_header.go)
  identify address, height and hash. A header field copied into a peer reply
  is not an authenticated inclusion proof.
- [Momentum hashing](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/nom/momentum.go)
  includes previous momentum, height, timestamp, content and changes commitments;
  its version-dependent Dynamic Plasma fields require the appropriate layout.
  A recomputed digest alone supplies neither canonicality nor finality.

These are static source interpretations. The new [wire corpus](NOM_WIRE_CONFORMANCE.md)
executes ABI/hash helper and send-syntax controls only. It does not execute this
full observation chain, authenticate momentum producers or demonstrate payout.

The later [observation claim corpus](NOM_OBSERVATION_CONFORMANCE.md) exercises
selected structures and source methods/finalization with explicit synthetic
contexts. Its fields and execution-status bytes are unauthenticated claims.
It does not execute full account admission, prove canonical inclusion, run a
funded swap or connect observations to recovery. Required independent mechanisms
in the table below remain unimplemented.

## Required evidence chain

| Claim | Bindings required before admitting it | Current gate |
|---|---|---|
| Target network | Immutable node/binary profile, chain identifier, genesis and active spork state, with a separately established authority | UNSELECTED / UNIMPLEMENTED |
| Funding send | Exact original hash inputs and retained signed wire, account authorization, Create destination/ABI, token and integer amount | UNIMPLEMENTED |
| Live funding entry | Successful Create execution, exact send-derived entry id, funder, expiry, point type/key, fixed recipient, token and amount at an authenticated snapshot | UNIMPLEMENTED |
| Original unlock observed | Exact retained ABI witness, entry id, caller or proxy recipient semantics, outer account authorization and send-confirming momentum context | UNIMPLEMENTED |
| Successful unlock | Contract receive tied to the exact original send, canonical execution context and successful state transition; distinguish reclaim or failed execution | UNIMPLEMENTED |
| Contract payout | Recomputed child hash, verified parent/child/account linkage, contract sender, exact fixed recipient, token, amount and acknowledged momentum | UNIMPLEMENTED |
| Recipient receipt | Recipient account receive referencing the verified contract payout, canonical inclusion and the selected spendability/finality rule | UNIMPLEMENTED |
| Reorg reconciliation | Exact old/new momentum lineage and displaced evidence, retained original bytes and disclosure state, explicit trusted reconciliation | LOCAL CLAIM RETENTION ONLY; AUTHORITY/RESTORE UNQUALIFIED |

The BIP340 funding key authorizes the inner contract witness. The outer account
key and signature authorize the account transaction. Role labels, a valid inner
signature or an equal account hash cannot replace either layer or establish the
sender's control. Fixed destination, token/amount and complete session terms must
be independently matched; the inner unlock digest does not bind every funding
field. The existing synthetic entry identifiers and addresses supply no actual
funding/account proof.

## Refusal and unknown-outcome policy requirements

- Peer claims and unauthenticated RPC replies remain source claims. Mathematical
  validity, inclusion, canonicality, successful execution, payout, receipt and
  spendability require separate verdicts and retained evidence.
- Missing entries or empty histories cannot distinguish unlock, reclaim, a fork,
  a provider omission or a lagging source. Absence cannot erase positive evidence
  or authorize another original transaction.
- Retain exact selected originals before any disclosure/publication attempt and
  preserve unknown outcomes across timeout, lost acknowledgement and restart.
  Never normalize, re-sign or replace retained bytes automatically.
- A changed child payload under an unchanged advertised hash is insufficient
  payout evidence. Verify the child and its linkage, not just the parent digest.
- Expiry/refund decisions must use the correct source-defined execution context
  plus the independently reviewed confirmation policy. A synthetic minimum gap
  or a fresh latest timestamp does not qualify a funded safety margin.
- Reorg must retain displaced evidence and possible disclosure, reopen affected
  outcomes explicitly and recheck funding. It must not silently restore an older
  journal, replenish charged work or select a replacement original.

## Next offline implementation order

1. The additive observation corpus now selects exact funding/send/receive/payout
   bindings and negative controls for forks, wrong recipients, malformed children,
   false entry absence and incorrect confirming context. Its bounded comparison
   stays separate from authentication and the existing journal.
2. Record unchanged-core method, verifier-helper and VM-finalization comparisons
   separately. Existing public signatures belong to old synthetic ids: actual
   Create stores the computed send hash, which changes the witness context.
   Seeded-entry success does not qualify that created funding record. Full VM
   dispatcher, balances, account admission, activation and canonical inclusion
   remain independent requirements.
   The additive [send-derived witness corpus](NOM_CREATED_FUNDING.md) now compares
   actual Create and valid witnesses for both computed ids in isolated storage/time
   contexts. Its payout skeletons and synthetic two-journal recovery remain separate
   from finalized account evidence and core-to-journal admission. Execution uses
   the acknowledged frontier context; later receive inclusion time is not a
   replacement for that timestamp. Independent live-entry proof remains unfilled.
   The additive [composed VM path](NOM_VM_PATH.md) now covers actual memory-store
   balances, embedded dispatch/lifecycle, finalized payment descendants and
   recipient credit. A separate selected verifier consumes its actual blocks and
   pre/post receive patches. Ledger lookup, confirmation context, spork selection
   and frontier adoption remain synthetic. Raw receipt replay demonstrates why
   VM credit alone is not an admission guard. Full admission, context authority,
   canonical inclusion and atomic recovery entry remain independent requirements.
3. Select and independently assess observation authority, pin provisioning,
   canonicality/finality and durable evidence policy before connecting a verifier
   to recovery. A declared provider, binary hash or callback is not that assessment.
   The [momentum claim corpus](NOM_MOMENTUM_CONFORMANCE.md) adds bounded hash,
   header membership, lineage and conservative reorg plans without selecting
   authority, finality, durable storage or recovery admission.
   The separate [public-evidence backend](NOM_EVIDENCE_RETENTION.md) retains
   original/candidate claims and possible disclosure across controlled process
   restart. Coherent old restore remains unsafe; a local receipt supplies no
   trusted reconciliation or journal admission.
   The separate [authority/freshness/restore contract](NOM_AUTHORITY_CONTRACT.md)
   now frames these independent selections and eleven evidence obligations. Its
   complete replies remain unauthenticated, and its finite atomic-entry comparison
   assumes an ideal external current world and nonrollback ledger/fence. No source
   service, authenticated proof verification, restore protection or recovery
   admission is implemented.
   The separate [public-opening comparison](NOM_EVIDENCE_OPENINGS.md) expands three
   commitments into both funding hash-input records, exact synthetic originals
   and raw momentum bytes. It distinguishes structural mismatches and leaves
   eight proof profiles, source authority and recovery admission unfilled.
4. Qualify signing custody, exact signed transaction storage, account-chain/Plasma
   behavior and restore protection separately. Controlled network composition
   remains outside Stage 0 authorization.
