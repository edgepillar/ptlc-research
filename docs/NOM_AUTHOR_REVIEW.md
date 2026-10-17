# NoM author review and continued offline development

Status: **AUTHOR TECHNICAL REVIEW, NOT INDEPENDENT ASSESSMENT.** Application and
core remain **NO-GO**. No report template, service gate, signer, chain authority
or operational permission is filled by this review.

## Assessment scope and independence

The reviewed baseline is
[`bcd673bb51526dff8ae3bb91c3272247a013b2b6`](https://github.com/edgepillar/ptlc-research/tree/bcd673bb51526dff8ae3bb91c3272247a013b2b6).
The concrete source finding below concerns
[`offline_session/nom_recovery.py`](../offline_session/nom_recovery.py), whose
SHA-256 is `a187362adee99b5d32002807a2232e14413c46a233efba922e9d2fa32b4f8a2a`.
The implementation, public-worker adapter and worker were examined together
with the fixed-recipient, account-authorization and bilateral graph evidence.
This is a targeted review, not a claim that every baseline file, dependency,
runtime or cryptographic assumption has been independently examined.

The development process can reproduce failures, inspect actual source, compare
separate mathematical implementations and qualify declared offline behavior.
Those activities are useful technical review. Repeating them in the same
development process does not supply an independent reviewer or an independent
security assessment. Cross-implementation agreement is not independent review
of the swap's economics, trust model, custody or failure assumptions.

Independent assessment is an application/release gate, **not a blanket ban on
offline candidate implementation**. Continue reproducible, bounded candidate
work and fix demonstrated defects while retaining explicit limitations. Keep
the [frozen delta subject](NOM_RECOVERY_DELTA_REVIEW.md) and every unfilled report
unchanged; a later reviewer must separately assess subsequent source changes.

## Reproduced finding: the approved observation can change before append

The historical `NomRecovery.record_observation` validates the caller's mutable
dictionary, gives a copy to the observer, and then reads the caller's dictionary
again after that callback returns. A callback holding another reference to the
caller input can approve a valid long-leg funding observation and change the
caller input into a valid short-leg funding observation. The historical writer
then records short funding even though its observer examined long funding.

This was reproduced with the actual file journal and an explicit fixture
cryptographic verifier: the observer examined `long`, the retained observation
was `short`, and the safety assertion failed with actual test exit 1 and complete
output. The failed original remains retained. This establishes an offline
reference API defect; it does not demonstrate a core, wallet or live-chain
exploit, and it does not establish the truth of either funding claim.

The recovery entry also reaches the public signature verifier before consuming
its observation proof. Freezing only inside `record_observation` would leave a
caller alias exposed during that earlier callback. Both handoffs are covered by
the additive fix.

## Selected fix and historical controls

Use [`SnapshotNomRecovery`](../offline_session/nom_recovery_snapshot.py) for new
offline observation/recovery candidates. It retains a canonical byte snapshot
of the selected **synthetic observation**, gives a separate copy to the
observer, requires exact `True` and an unchanged returned argument, and appends
the selected snapshot. Recovery freezes the proof before calling any public
signature verifier. Existing context validation, durable append, original-only
replay and recovery allowance remain inherited.

This canonicalization is not a signed account-block decoder or normalization
rule. Exact signed transaction bytes must never be replaced by a re-encoding of
their decoded fields. The observer is still trusted: the snapshot does not
authenticate it, contain its code, prove its internal behavior, or provide an
atomic read against arbitrary concurrent mutation.

The historical writer remains unchanged because older subjects and evidence
pin its exact bytes. It retains this known defect and should not be selected
for new observation handoffs. The additive entry is not a migration. Opening
an old log does not recheck observations or retrospectively authorize them.
The tests retain both the unsafe historical alias counterexample and the fact
that even a rejecting observer is not invoked to authenticate historical replay.
No old result is relabeled as evidence for the new entry.

The new qualifier also refuses Python optimization before fixture, evidence or
worker access. Its scenario includes calls inside assertions; allowing those
assertions to disappear would skip required actions. A separate subprocess
control checks both direct entry points with optimization actually enabled,
without opening a journal, creating qualification scratch or starting a worker.

Fourteen new actual-journal controls cover caller and callback mutation,
refusal and exception preservation, exact-True admission, bounded canonical
output, idempotence, reopen, the earlier public-verifier handoff, original short
custody, one recovery across reopen, insufficient send acknowledgement, context
refusal and the two historical limitations. Fixture verifiers in these unit
tests are explicitly not mathematical or chain evidence. The focused family
also reruns the existing recovery, interruption and frozen-subject tests.

The separate
[`public-worker qualifier`](../scripts/qualify_nom_recovery_snapshot.py) requires
an explicitly selected executable, its expected SHA-256 and an empty private
evidence directory. It exercises two actual journals, both caller-alias controls,
callback mutation refusal, original-only replay, one public adaptor recovery
and two invalid completion refusals. It captures original requests, replies,
errors and actual exits using the existing single-thread qualification transport.
The observer remains a disclosed synthetic allowlist. An executable hash does
not authenticate its source, loader or dependencies; that selection needs its
separate source/build qualification. Hosted private worker streams are ephemeral
unless separately retained; a console summary is not their archive.

## Local author-review checkpoint

The initial focused journal family passed 80 tests, including the 14 new
controls, with complete output and no skips or ResourceWarnings. This is fixture
oracle and actual file-journal evidence, not a public cryptographic execution.
The author-run historical counterexample remains an expected-red exit-1 failure.
A later, separate optimization-profile test passed with both entries exercised
in an actual optimized subprocess. That test created no journal, qualification
scratch or public worker. It does not make the earlier 80-test source selection
current again; the final source still requires a complete fresh regression.

The subsequent fresh-worker build was stopped by a storage ownership boundary
after the compiler created hard-linked output. Its outer process exit was -9,
with incomplete capture; this build is **NOT QUALIFIED**. Subsequent storage
admission and object ownership refusals occurred before a public-worker scenario
ran. A separately approved repair replaced two generated compiler aliases with
independent copies, preserving all 503 paths, contents and original failure
records. No failed run was reclassified, output cleaned or unrelated store
repaired. The first repair implementation stopped before any copy because a
metadata API was unavailable; its original receipt remains separate.

The new actual-journal scenario then completed with the historical public worker
whose SHA-256 is
`59034c6b0e1ab2419030dfac3dc8f59d6c93fbd0a616fc261c62f989cf890ed8`.
Its earlier before-spawn selection binds 153 still-unchanged source inputs.
Seventeen actual calls have complete original request/reply/error/exit records:
15 returned zero and the two invalid completions returned the expected exit 2.
One public recovery entered and returned across reopen, both caller-alias
controls retained the verified snapshot, and callback argument mutation refused
without an append. All three journal originals remain retained separately.
This uses an existing measured worker, not the failed fresh build; source/build
and loader authentication remain separate, unfilled requirements.

The containing task subsequently failed before its focused test launch because
the generated fixture project label exceeded the manager grammar. Its overall
FAILURE remains unchanged; only its complete native component is eligible for
separate, exact-source reconciliation. This admission refusal is not a failed
native scenario or a passing complete task. No native scenario is rerun to hide
that original outcome.

Final-source complete regression and fresh hosted PR/main results are subsequent
acceptance gates, recorded separately with publication. They are not claims made
by this author-review checkpoint. No independent report is filled and no main
integration is implied by this document.

## Remaining technical obligations

| Surface | Current evidence and limit | Next disposition |
| --- | --- | --- |
| Fixed-recipient construction | Both public pre-signatures, distinct keys/messages and one compressed adaptor point are checked; public completion verification precedes extraction and long adaptation. | Obtain an external review of nonce ownership, role/key separation, disclosure order, timeout margins, reorg and availability assumptions. Same-process source review does not close this gate. |
| Complete transaction authorization | Public source corpora distinguish inner BIP340 validity from outer account signatures, account context, Plasma and admission. | Preserve exact public signed originals and their node identifiers separately from byte digests. No signature or identifier alone supplies complete admission. |
| Original-byte custody | The reference log retains exact synthetic envelopes and unknown outcome before disclosure. | Implement and qualify a separate offline real-byte custody candidate. Never turn a completion, result receipt or normalized object into a replacement original. |
| Observation authority | Complete packet and source comparisons remain distinct from independently selected canonicality and finality. | Specify the source trust and evidence selection before admitting any real recovery. A callback, fresh signature or matching hash is insufficient. |
| Runtime and persistence | Qualified public mathematics, selected executions and local journals are component observations. | Preserve build/loader limits, interrupted work, missing output and coherent restore/copy controls. Local fsync, SQLite equality and green CI are not power-loss or nonrollback authority. |

## Development order and release gates

1. Land the observation snapshot entry after focused tests, complete offline
   regression, artifact checks and exact-head hosted qualification. Accept the
   later push/main run separately. Preserve historical manifests and failed
   evidence.
2. Select a small **offline public-byte custody** candidate using existing actual
   account-block corpus inputs. Bind the exact raw signed bytes, their SHA-256,
   the selected node hash, chain context and immutable swap terms. Account for
   raw protobuf aliases and metadata excluded by the node hash. Do not add a
   signer, new key material, broadcast, replacement original or automatic retry.
3. Exercise that candidate against the pinned current dev verifier/VM evidence
   and actual journals with lost replies, retained UNKNOWN work, reopen and
   exact-byte reconciliation. Keep source admission, canonical chain observation
   and local retention as separate conclusions.
4. Request an external, narrowly scoped written review when a reviewer is
   available: identify an immutable source/tree, construction assumptions,
   selected worker/dependencies, actual counterexamples and raw evidence. A
   protocol/cryptography reviewer and a custody/runtime reviewer can assess
   separate scopes. Neither role is filled by this author report.
5. Allow application progress only after those external findings and the
   independent signer, observation, custody and operational requirements have
   explicit dispositions. The seven service gates remain unfilled. Deployment,
   node activation, wallet access, application signing, controlled network
   composition, transaction broadcast and real funds remain outside Stage 0.

This order permits concrete offline development while keeping missing external
assurance visible. It does not create an exception to the application/core
NO-GO or weaken any previous frozen assessment subject.
