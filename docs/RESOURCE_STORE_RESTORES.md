# Explicit v4 observation-store restore boundaries

Status: **Stage 28 offline restore qualification, not restore protection.**
Application code, formats, resource policy, mathematical records, journal and
cryptography are unchanged. All copying is test-only: snapshots are captured
after source close and installed only at unowned destination paths, with no
live store files overwritten. No recovery, migration, repair,
trusted enrollment or production restore procedure is added.

The source parent is [`421cdabb21473c0a4746faafd6c53b27d4c60aaf`](https://github.com/edgepillar/ptlc-research/tree/421cdabb21473c0a4746faafd6c53b27d4c60aaf).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37203390291)
establishes prior execution, not execution of these new experiments. The
[separate observation subject](OBSERVATION_REVIEW.md) remains pinned to its
189-file source through Stage 26. This later test/qualifier delta lies outside
that subject, and neither unfilled independent report is extended or completed.

## Requirement, construction and evidence

| Desired requirement or limit | Unchanged selected construction | Stage 28 experiment |
| --- | --- | --- |
| Detect a database/checkpoint mismatch without resetting history | Exact v4 pair commitments, configuration checks and quarantine | Combine old database/current checkpoint and current database/old checkpoint after a normal result; require refusal and unchanged pair bytes |
| Preserve explicit resource selection after copying | Required v4 profile in both files; mode/profile preflight before SQLite | Wrong CPU, address-space or ordinary v3 selection refuses without SQLite access or rewrite; matching policy accepts the consistent old pair |
| Avoid replenishment by coherent old pairs | No external monotonic anchor or authenticated latest-head authority is implemented | Restore an old empty pair after exhaustion; require another selected call despite identical store, verifier, pool and requested-resource profiles |
| Retain later normal and unknown history across coherent rewind | Consistency validates one supplied local history, not its freshness | Restore an earlier normal pair after a charged recheck; require the earlier charge/history and remaining allowance to return |
| Preserve knowledge of conflict across rewind | Both contradictory claims are retained within one accepted history; no externally anchored latest history exists | Synthetic verified/rejected claims conflict and survive healthy reopen; a matching earlier pair erases that later conflict |
| Recover pending without replay or refund in a supplied history | Pending attempts recover to charged unknown before the owner is returned | Restore the same pending pair after recovery; recovery can publish again, but no worker repeats and the original charge remains |
| Treat identity/profile labels as authoritative enrollment | Public labels and mathematical profiles do not bind one physical history | Copy an empty pair to separately owned paths with the same physical pool and configuration; both histories admit their own bounded work |

The first two rows qualify consistency and selection. The remaining rows expose
unresolved freshness, clone and enrollment limits or preserve only the stated
pending-recovery boundary. Tests reproduce these distinctions; they add no
defense and select no funded availability policy.

## Exact experiments

Seven [discovery tests](../tests/test_observation_resource_store_restore.py)
use real SQLite, checkpoint bytes, POSIX locks and physical pool descriptors.
Only Linux host selection is simulated; limited verdict callbacks are explicit
synthetic oracles. They establish neither Linux enforcement nor mathematical
validity. The contradictory-normal case is deliberately synthetic: it is not
evidence that the actual Rust verifier rejects and verifies identical inputs.
Both recorded outcomes are read back from SQLite before rewind. The summary
reports a conflicting target instead of counting it as an unambiguous positive
or negative; no normal claim is selected while conflict remains.

Concrete allowance counterexamples include two selected calls under a
one-attempt history after empty-pair rewind, and three calls under a two-attempt
history after restoring a pre-recheck normal pair. Each supplied history still
enforces its own configured limit. An unchanged healthy reopen alone neither
refunds an attempt nor rewrites files. These results distinguish local history
bounds from cumulative work across restored or copied histories.

The copied-pair case uses the same actual pool object and physical slot files.
The pool can still serialize participating calls; it does not deduplicate
identical public store IDs or provide shared cumulative allowance. One discovery
case holds both separately owned stores open while issuing sequential synthetic
calls; the original store remains exhausted and byte-identical. This is no
claim of simultaneous actual computation or physical-pool capacity bypass.
Matching-profile pools at different physical files retain their separately
documented [capacity boundary](SHARED_WORKER_ADMISSION.md).

Copies contain only the complete closed database and checkpoint, retain private
file permissions and leave owner locks/configuration to the unchanged store.
No backup service, live file replacement, lock revocation, partial physical
copy, sync failure, hot-journal backup or power loss is qualified. Test helpers
are not exported as an application restore API. Rejection tests never repair
the input pair; accepted old pairs are deliberately consistent counterexamples.

## Actual Linux verdict gate

The existing [v4 qualifier](../scripts/qualify_observation_resource_store.py)
adds four top-level methods, raising its count from 13 to 17:

1. Exhaust a one-attempt history with an actual verified result, restore its
   earlier empty pair without changed profiles, and require another actual
   verified result. Unknown or simulated normal does not satisfy this gate.
2. Retain an actual positive, then require an actual positive recheck before
   synthetic publication loss. Healthy recovery charges unknown and preserves
   the earlier normal. Restore the earlier normal pair and require another
   actual verified recheck. The injected interruption is not a native fault.
3. Copy an empty pair to separate paths with the same physical pool and policy.
   Require actual limited positives in both histories, while the original
   remains exhausted and unchanged. Calls are sequential; no concurrent
   computation or aggregate-resource containment is claimed.
4. After an actual positive, require both single-sided old-pair combinations
   to quarantine without rewrite. Offline fixture copying of the current full
   pair permits healthy readback of that same retained normal.

Every selected actual call uses the limited route; ordinary-work fallback is
forbidden. Every case's cleanup checks the source journal's state, sequence,
database and checkpoint bytes against the pre-experiment values. Observation
copies grant no source-journal recovery authority or allowance reset.

This qualifier requires a supported unprivileged Linux host. It is not run
locally on macOS, and configured CI is not execution evidence. All nine actual
worker groups remain selected, with 68 total top-level cases expected. Completed
exact-head logs must establish their execution and record skips/failures honestly.
See [Stage 28 validation](STAGE28_VALIDATION.md).

## Progression decision

**Go:** independently assess both fixed subjects and this explicitly separate
qualification delta; define and review the required freshness/enrollment and
recovery authority before connecting retained claims to funded recovery.
External head authority, monotonic state, duplicate enrollment, backup/copy
semantics and availability under exhaustion require explicit constructions and
host/storage assumptions. A profile hash or local file-pair check selects none.

**No-go:** infer anti-rollback/clone defense, global quota, source authority,
physical durability or funded availability from v4 policy continuity. Private
signing, trusted chain source integration, core port, activation and transaction
broadcast remain excluded. Independent construction/backend review, secret nonce
ownership, native storage/power failure, aggregate budgets and timely valid
witness handling remain unresolved.

The separate [Stage 29 authority comparison](OBSERVATION_AUTHORITY_MODEL.md)
now tests finite design alternatives for those freshness/enrollment obligations.
Read checks and external charge alone have distinct counterexamples. Ideal
non-rollbackable state and unique dispatch are conditional premises, with no
application integration or restore defense added to this v4 store.
