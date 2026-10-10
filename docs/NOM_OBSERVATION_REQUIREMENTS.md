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
| Reorg reconciliation | Exact old/new momentum lineage and displaced evidence, retained original bytes and disclosure state, explicit trusted reconciliation | UNIMPLEMENTED |

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

1. Create source-derived observation fixtures with exact funding/send/receive/
   payout bindings and negative controls for forks, wrong recipients, malformed
   children, false entry absence and incorrect confirming context. Keep fixture
   claim parsing separate from authentication and from the existing journal.
2. Compare the structural rules with the unchanged pinned node using independently
   written offline overlays. Record skipped stateful checks honestly; a helper
   match cannot fill a VM or consensus requirement.
3. Select and independently assess observation authority, pin provisioning,
   canonicality/finality and durable evidence policy before connecting a verifier
   to recovery. A declared provider, binary hash or callback is not that assessment.
4. Qualify signing custody, exact signed transaction storage, account-chain/Plasma
   behavior and restore protection separately. Controlled network composition
   remains outside Stage 0 authorization.
