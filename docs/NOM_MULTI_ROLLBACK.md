# Two actual public momentum rollback steps

Profile: `zenon-pr138-multi-rollback-v1`.
Research baseline: `518a8a6c3d6ee08f69f23c75ecc1cd54e4cfa6cb`.
Selected unchanged GPL core: `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`.
The independently written source overlays in this MIT workspace are applied
virtually to that separately acquired core. No GPL implementation is copied.
Source and license hashes are retained in the additive manifest.

## Selected construction

Preserve the complete initial synthetic M1 root, all original funding, contract
parent, child, inner witness and old receipt bytes from the previous profiles.
Apply the exact parent through the actual Supervisor, then admit it through the
normal public account pool. The actual selector supplies its original child
and parent headers for M2. Generate and exactly apply M2 through the Supervisor,
then add it through the public memory momentum pool with the caller lock held.

Generate, exactly apply and normally insert an empty M3 successor at the next
height and timestamp. Its VM delta is empty; the memory manager independently
appends only its momentum frontier writes. This empty content is an explicit
selected construction. It does not test production fullness or infer an order
among different accounts. Insert M3 before generating any pending controls,
so the second insertion does not rebuild their patches.

After M3, separately generate, exactly apply and normally admit a public receipt
and a later suffix acknowledging M2. They are new controls, never replacements
for the preserved old receipt. Admit an unrelated public send acknowledging M1.
The old M1-acknowledged receipt is refused before M3 insertion, with its exact
wire unchanged and zero signatures. Only disclosed public `0x41`, `0x61` and
`0x64` seeds sign these separate controls and selected momenta.

Call actual public `RollbackTo(M1)` once. It prefetches each current momentum
before its own actual memory pop and passes the resulting original detailed
momentum to the registered listeners. The driver never supplies delete content.
Observe the stable view before the real account-pool callback and the complete
stable and pending view after it.

| Actual removed momentum | Prefetched top-level accounts | Stable view at both delete observers | Pending result after actual pool callback |
| --- | --- | --- | --- |
| Empty M3 | Empty | Complete M2 | Original M2-acknowledged receipt and suffix retained; unrelated original retained |
| Original M2 | Original child, then parent | Complete M1 | Dependent receipt and suffix removed; unrelated original retained |

All eight insertion/deletion observations preserve the actual callback order.
The independent Python model encodes the complete global, stable account,
mailbox, header, confirmation, pending-wire and pool state at every selected
checkpoint. It separately constructs both momentum deltas, manager patches,
hashes and protobuf wires. It checks exact intermediate pending aliases and
their original patches; neither pop adds frontier writes to a retained patch.
The final root alone is insufficient evidence for this profile.

## Refusal and no-op controls

Missing insertion/rollback lockers, wrong existing target height/hash and the
old receipt are refused with complete unchanged checkpoint digests. A rollback
to the exact current M3 frontier succeeds with zero callbacks, zero signatures
and an identical complete logical checkpoint. The existing wrong-height
control names seeded M0 with the M1 hash; no missing-target panic is exercised.
Logical state comparison does not claim unchanged internal map allocation.

The source qualifier freshly reruns all 319 prior source outcomes, then all
eight new outcomes including parents. It retains all three complete source
snapshots before executing the new native command, its exact selected input,
and original private streams. Strict bounded source framing and unique JSON
fields are required before selecting the fixture. Failed or incomplete runs
have no fixture fallback. Hosted private streams can be ephemeral; public
console archive integrity is a separate evidence boundary.

## Unfilled requirements

Both an orphaned send and stale acknowledgement can remove the dependent
manager on the M2 pop; this profile does not isolate a unique eviction cause.
The selected producer acceptance response does not authenticate an elected
producer. M1 is synthetic state, not an authenticated chain. PTLC selection in
the account cache coexists with an actually empty spork store; Dynamic Plasma
is inactive. No node initialization or activation occurs.

Persistent managers, interrupted/failed multi-pop execution, atomicity,
authenticated ancestry, finality, original custody, journal composition,
restore fencing, production scheduling and independent security assessment
remain unfilled. Separate qualification is required before connecting any
source observation to the fixed-receiver recovery flow. Application/core remain
**NO-GO**, and recovery action remains **NONE**. No deployment, wallet access,
application signing, broadcast or real funds are authorized or performed.
