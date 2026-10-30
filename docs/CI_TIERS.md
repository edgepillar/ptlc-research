# Selected CI tiers

Status: **full-tier baseline accepted; selected hosted fast-path success and
timing require their own qualification**. Application/core remain **NO-GO** and independent
assessment is **UNFILLED**.

The delivery roadmap calls for focused public-client feedback and a complete
baseline tier. This change adds an explicit selector and acceptance job around
the existing native and four-profile workflow. Its first adoption changes CI
code, so it must run the full tier. A later eligible PR is needed to measure the
hosted fast path; a target of approximately 15 minutes is not a measured result.

The recorded full-tier baseline is
[`7186cab21ecb09427fa63f68f1502de948d5787a`](https://github.com/edgepillar/ptlc-research/tree/7186cab21ecb09427fa63f68f1502de948d5787a).
[PR run 41004598656/1](https://github.com/edgepillar/ptlc-research/actions/runs/41004598656/attempts/1)
and its separate [main push run 41014539081/1](https://github.com/edgepillar/ptlc-research/actions/runs/41014539081/attempts/1)
were each accepted from their own metadata, nine artifact families and complete
console. Each selected all 14 runtime jobs, including four 4,619-case Python
profiles and the original native results. The fast job was unexecuted in both.
The [selected-path procedure](PUBLIC_CLIENT_FAST_QUALIFICATION.md) declares the
next work item's original-data and measurement gates before its eligible run.

## Source selection

Every main push selects `full`. A PR can select `public-client` only when its
trusted main base already contains exactly the policy used by its head, the
complete bounded Git diff is available, and base ancestry is established.
The workflow executes the base policy in isolated Python. Missing objects,
unknown context, an unavailable base policy, incomplete diffs and changed policy
select `full`. Selector failure also leaves the native jobs eligible for full
execution; the final acceptance job still fails if scope selection failed.

The source policy names existing public-client Python, checker and corresponding
test/fixture files. It also permits README/STATUS and Markdown reading material
under `docs/`. New executable/fixture paths, deletions, renames, links, mode
changes, ambiguous names, shared codecs, dependencies, locks, instructions,
workflow and CI controller changes require `full`. Path selection establishes
verification scope; it is not a protocol, code-review or release approval.

## Actual execution and acceptance

The full tier expands to 17 actual jobs, including 14 runtime jobs. A skipped
matrix definition must not be counted as executed matrix members: GitHub
[evaluates job conditions before matrix expansion](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
The fast tier needs its own exact job metadata and explicit nonexecution checks;
do not assume that its actual API inventory is the full tier's expanded graph.
The table describes selected workload and required outcomes:

| Selection | Scope control | Public-client job | Full-tier runtime workload | Final acceptance |
| --- | --- | --- | --- | --- |
| `full` | Successful | Not executed | All 14 must succeed | Successful |
| `public-client` | Successful, source range established | Must succeed | All 14 not executed | Successful |
| Unknown or failed selector | Not accepted | Not selected | Full fallback eligible | Failed |

The existing 14-job native recipe is preserved byte-for-byte after removing the
declared selection guards and three new jobs. Main never acquires fast-tier
qualification from a previous PR. Its own full run and original evidence remain
required for main acceptance. A skipped job supplies no runtime evidence.

The fast job runs the complete selected Python client/scope tests, the small
package's actual public Rust library/process tests, Rust formatting and complete
index/worktree privacy checks. Cargo uses the existing locked three-dependency
package. Dependency fetch, source selection and compiler setup are distinct from
the offline test run. No unrelated Go job, complete Python baseline, signer,
observer or operational recovery is executed by this tier.

`run_public_client_ci.py` uses the existing four-command supervisor sequentially.
The caller provides a new private workspace, eight empty original stream files,
Cargo cache/target and temporary fixtures. Original bytes, actual exits,
completeness, exact case names, source before/after and declared scope accompany
the transcript. `read_public_client_ci.py` independently consumes those bytes
and requires the caller's exact run/source context; it executes no native work.
It shares the producer's case-acceptance function and supplies no independent
implementation or assessment.
Hosted metadata, job selection and run/attempt acceptance are separate checks.

The initial hosted job admits 1 GiB above the 10 GiB free-space floor. Its owned
workspace has a 512 MiB sampled limit and bounded command/stream budgets. These
are not an OS quota, a hardware-failure guarantee or cleanup permission. Local
qualification must use the existing owned-storage lifecycle. Failures and
missing originals remain failed/unknown and are not repaired into passing data.
The selected Rust context uses two build workers with incremental output and
debug information disabled. This changes build storage, not assertion policy.
Compiler setup and dependency transport are outside the offline execution
measurement and require their own actual hosted step outcomes.

The pinned dependency checkout contains a
[README link](https://github.com/LLFourn/secp256kfun/blob/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce/README.md)
to `secp256kfun/README.md`. The workspace sampler permits that exact cache path
and relative target, requires its target and parent to be regular file/directory
entries owned on the workspace device, and charges the link without traversing
it. The target is charged separately by the ordinary walk. Other cache aliases,
changed targets and link chains remain refused. This is workspace accounting,
not dependency authentication or permission to adopt existing cache files.

The first selected hosted attempt,
[40999048053/1](https://github.com/edgepillar/ptlc-research/actions/runs/40999048053/attempts/1),
failed before its initial producer record. Its original console contains a
generic workspace refusal and does not identify the rejected entry. The prior
sampler also rejects the pinned README link; a local counterexample tests that
defect separately. It does not establish the original hosted refusal's exact
cause. The failed attempt remains failed, its originals are retained, and a new
revision requires fresh qualification. A sampler change selects the full tier.

The selected public checks grant no funding, signing, disclosure, replacement,
activation, broadcast or funds authority. Full native CI does not close those
operational or independent-review gates either.
