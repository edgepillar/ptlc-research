# Candidate native comparison at 821bdd2

This M1 D6 work item supplies a frozen selection, source preparation, two-stage
runner and original-evidence readers. It does not record a completed native
attempt. The client behavior selection remains `77ba9c7`; candidate native
compatibility, independent assessment and application/core acceptance remain
**UNFILLED**, **UNFILLED** and **NO-GO**, respectively.

The [source tracking corpus](NOM_DEV_821BDD2.md) pins the 523 upstream files to
[`821bdd25eabacbf8a07b6310986f38713f27b4e3`](https://github.com/zenon-network/go-zenon/tree/821bdd25eabacbf8a07b6310986f38713f27b4e3).
Its complete inventory, archive digest and GPL version 3 license remain separate
from the project's original reference programs. Upstream source is acquired
separately; no upstream test implementation is vendored here. The additional
test identities below refer to those pinned upstream implementations.

## Frozen selection

[`compatibility/nom_dev_821bdd2_plan_v1.json`](../compatibility/nom_dev_821bdd2_plan_v1.json)
records the complete command selection, source subjects, counts and exclusions.
The runner requires an exact canonical JSON match before launching a compiler.
A changed source, omitted profile, boolean in place of a numeric count or
historical-cache selection does not match the plan.

| Stage | Selected work | Required inputs and accounting |
| --- | --- | --- |
| Baseline | All 31 reference profiles, the previous three upstream groups, and the two added groups below | 523 upstream files plus the unchanged 25 project producers: 548 files; 36 profiles and 40 commands, including version, cold build, definition-package regression and module verification |
| Fee originals | The separate 14-case fee boundary and its module verification | Append exactly the unchanged fee producer: 549 files; one profile and two commands; the same two public synthetic originals, input/expected hashes and reference fixture labels |
| Complete planned attempt | Both stages, in sequence | One fresh compiler workspace, one physical source view, 37 profiles and 42 commands; 782 named finite parent/child outcomes, with the additional definition-package regression accounted for separately |

The reference labels remain pinned to `661b5ef`; they identify fixture
constructions, not the source being compiled. Their original streams are passed
unchanged to existing reference comparisons. A candidate native result must bind
the actual `821bdd2` source snapshots and actual command exits separately. No
earlier `77ba9c7` or reference run can be relabeled as candidate execution.

The two additional groups are:

- `upstream-per-entity`: all 11 parents in the pinned
  [`per_entity_iteration_test.go`](https://github.com/zenon-network/go-zenon/blob/821bdd25eabacbf8a07b6310986f38713f27b4e3/vm/embedded/definition/per_entity_iteration_test.go).
  They cover valid sub-range selection, revoked stake filtering, totals, empty
  entities and actual shared address/hash prefixes.
- `upstream-final-tally`: all seven parents and eight named method children in
  the pinned
  [`accelerator_final_tally_test.go`](https://github.com/zenon-network/go-zenon/blob/821bdd25eabacbf8a07b6310986f38713f27b4e3/vm/embedded/implementation/accelerator_final_tally_test.go).
  They separate Dynamic Plasma pre/post-spork tally behavior, passing/failing
  expired projects, open project votes, phase votes and the two voting methods.

The added groups do **not** cover malformed rows, mismatched storage keys and
values, iterator failures or the exact accelerator voting deadline. Their late
fixtures use a timestamp one second past expiry; their open-window fixtures do
not establish equality-boundary behavior. The final-tally context reports PTLC
spork enforcement as false. These exclusions cannot be inferred from successful
normal-row or shared-prefix cases, nor from unrelated reference timing tests.

## One admitted workspace

The caller must admit new owned storage, pin the compiler and offline dependency
inputs, enforce the 10 GiB free-space floor plus the allocation/reservations, and
retain original output. Existing historical directories are never adopted.
The runner keeps the existing 2 GiB native reservation and offline environment:
local toolchain selection, read-only module resolution, no VCS transport and
one fresh module/build/temp cache. A refusal does not authorize another cache,
cleanup, a lower reservation or a policy change.

| Entry point | Purpose |
| --- | --- |
| [`prepare_nom_821bdd2.py`](../scripts/prepare_nom_821bdd2.py) | Check the exact retained archive and every selected blob before writing one new source view; add only the 25 unchanged reference producers |
| [`qualify_nom_821bdd2_bundle.py`](../scripts/qualify_nom_821bdd2_bundle.py) | Run the baseline, freeze its original results/streams/receipts, append the fee producer and execute the separate fee stage in the same live invocation |
| [`check_nom_821bdd2_bundle.py`](../scripts/check_nom_821bdd2_bundle.py) | Check actual receipts, source snapshots, finite values, privacy and exact original file selection; allow honest incomplete retention without treating it as acceptance |

Every test command retains `-count=1` and default vet. Compiled objects may be
reused inside this one invocation; completed test results are not substituted.
The first stage's original identities, bytes, modes and modification times must
remain unchanged after the fee stage. Failed or interrupted output remains at
its original path. No automatic retry, replacement, re-signing, broadcast or
cache adoption is supplied.

This design avoids another complete source extraction and cold workspace for
the fee stage. It makes no measured runtime, storage-saving, OS quota, compiler
authentication or independent execution-origin claim. Those require actual
source-bound evidence. The local controls use synthetic streams/processes and
mocked compiler stages; their success cannot close native compatibility.

## Isolated hosted comparison

The separate [candidate workflow](../.github/workflows/nom-821bdd2-native.yml)
selects the full 37-profile, 42-command comparison on Linux. It uses the same
trusted-base scope policy as the existing workflow. A selected public-client
change explicitly skips candidate execution; missing or unknown scope does not
select that fast path. The final selection gate distinguishes an executed job
from nonexecution. It does not accept the original artifact values itself.

The job admits a new hosted workspace with the 10 GiB floor and 4 GiB initial
allocation allowance, downloads the pinned Go archive and exact upstream ZIP,
and acquires dependencies into a separate bootstrap module cache. The native
runner retains its 2 GiB reservation and uses one fresh compiler workspace for
both source stages. No historical local cache or completed native result is
adopted. This admission is not an OS filesystem quota or a measured saving.

Only the exact privacy-checked original file list is uploaded, including honest
incomplete attempts. Compiler caches and private argument receipts are excluded.
An absent or refused artifact remains missing evidence. Actual source-bound
receipts, finite values, hosted originals, PR acceptance, normal main integration
and the main push's own acceptance remain separate requirements. A Linux result
does not establish Darwin behavior, compiler authentication or application safety.

The native runner and evidence checker each obtain the baseline from one freshly
validated frozen plan. They do not repeat the same plan construction within that
entry point. Validation across calls is not cached, and exact scalar types,
array order, original-source snapshots and refusal behavior remain required.

## Acceptance still required

Keep local controls, actual native comparison, PR CI acceptance, normal main
integration and the main push's own acceptance as separate records. The existing
workflow's `77ba9c7` native subject is unchanged by these candidate tools. Green
CI using that subject cannot qualify `821bdd2`.

A future accepted native result may close only this declared finite selection.
The excluded shared-state boundaries, authenticated observation, signing and
nonce custody, recovery reconciliation and independent protocol assessment keep
their separate requirements. No node, wallet, deployment, activation or real
funds action is authorized.
