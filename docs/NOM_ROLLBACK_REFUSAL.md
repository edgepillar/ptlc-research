# Selected refusal during public momentum rollback

Profile: `zenon-pr138-rollback-refusal-v1`.
Research baseline: `4c2986bde70c83c9e5a8e9dfd18c91161c9481a7`.
Selected unchanged GPL core: `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`.
Own MIT test overlays run virtually against the separately obtained unchanged
core. Source and license hashes bind the selected implementation. No GPL
implementation is copied into this research workspace.

## Requirements and selected construction

A failed rollback must not be reported as reaching its requested target. The
caller must preserve original operations and evidence, distinguish successful
mutation from an attempted operation, and avoid automatic replacement or retry.
This profile qualifies two selected memory observations. It does not establish
a secure swap construction or grant application recovery permission.

Repeat the original M1 seed, exact contract parent/child admission, actual M2
generation and application, normal public insertion, and empty M3 insertion.
After M3, admit separately labeled public receipt, suffix and unrelated controls.
All original funding, witness, old receipt and previous source profiles remain
unchanged. Only disclosed public `0x41`, `0x61` and `0x64` test seeds sign these
synthetic controls; original exact application and refusals sign zero times.

An own test wrapper embeds the actual unchanged memory manager. It overrides
only `Pop`: a selected call returns a disclosed error **before delegation**;
every successful call delegates to the actual manager. The wrapper is passed to
the real public momentum pool. The Supervisor, stable snapshots, account pool,
public rollback implementation and actual listener order remain unchanged.
This does not simulate failure inside an already mutating `Pop` or a persistent
storage operation. It is a fault construction, not a production fault report.

| Selected refusal | Actual successful pops | Actual source return | Observed complete frontier | Delete observations |
| --- | --- | --- | --- | --- |
| Before first delegation | 0 | Original selected error, same identity | M3, unchanged full logical checkpoint | 0 |
| Before second delegation | 1, removing empty M3 | Actual typed `ErrCanonicalStateUncertain` | M2; M1 target not reached | 2, before and after the actual account-pool callback |

Both cases retain the exact three original pending wires, aliases and patches.
The second case also retains the complete first-pop checkpoint. Stable account,
global, mailbox, header and confirmation bytes are independently projected.
The before-pool observer reads only complete stable state. The after-pool
observer reads complete stable and pending state. A failed pop emits no delete
callback; its prefetch is not directly instrumented. Prefetch-before-pop for
that attempt is a pinned source order claim, not a separate runtime observation.

The native driver measures error identity, `errors.As`, both typed error fields
and `errors.Is` behavior. The uncertain error unwraps its `Cause`, rather than
its selected `RollbackErr`. Matching error text alone cannot establish those
properties. The independent checker binds exact target, observed frontier,
pop attempts, successful delegations, callbacks and full checkpoint digests.
Each selected failed rollback is called once, with zero new signatures. No
retry completes the second pop, and no operation is reconstructed or replaced.

Five preliminary refusal controls and one exact-frontier no-op are repeated in
each independently initialized case. Wrong-height controls name existing M0,
not a missing-target height. The qualifier freshly reruns all 327 prior source
outcomes, then 15 new outcomes including parents. It retains all four complete
overlay snapshots, exact selected input and original streams before execution.
Strict framing, unique JSON fields, typed measurements and bounded records
precede corpus selection. Incomplete native evidence has no fixture fallback.

## Remaining requirements

Persistent manager failures, process interruption, cache restore fencing,
uncertain-state application journal composition, authenticated ancestry,
elected producer authentication, finality, original custody and independent
security assessment remain unfilled. A source error type is not an authenticated
chain observation. M1 is synthetic; producer acceptance is selected input. The
actual spork store is empty, with Dynamic Plasma inactive. No node initialization
or activation occurs. Virtual-overlay vet remains unavailable under the selected
Go version; ordinary standalone Go vet is a separate check.

The next qualification must preserve the original operation when an uncertain
source result is supplied to an offline recovery boundary, without treating a
partially rolled frontier as final or automatically retrying it. That requires
its own composition and restore gates. Application/core remain **NO-GO** and
recovery action remains **NONE**. No deployment, wallet access, application
signing, broadcast or real funds are performed.
