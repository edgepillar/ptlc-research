# Separate observation-layer review brief

Status: **Preparation only. Independent assessment is NOT ASSESSED.** This
package requests a written assessment of the observation, ownership, physical
pool and resource work through Stage 26. It contacts or assigns no reviewer and
selects no production backend, source, enrollment or funded recovery policy.

## Two distinct subjects

| Item | Observation subject | Original construction subject |
| --- | --- | --- |
| Source commit | [`f81e376e96e339647bb065739b4461235f865d2c`](https://github.com/edgepillar/ptlc-research/tree/f81e376e96e339647bb065739b4461235f865d2c) | [`e592633e4c630cfe3f4669876f6f63b80d2e33d6`](https://github.com/edgepillar/ptlc-research/tree/e592633e4c630cfe3f4669876f6f63b80d2e33d6) |
| Git tree | `aef1822a1ffa242d7987aa3a8ecfd2081a610be1` | `eea8afd941b1edfcbbb361d2429dfb5883887d3f` |
| Complete tracked inventory | [189 regular files](../review/observation-subject.json) | [119 regular files](../review/subject.json) |
| Manifest SHA256 | `2f463071bc4f96ba1adaa8e8eb206d47e51845170ca2efe0f2b58182559afd6f` | `df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295` |
| Assessment record | [Separate unfilled report](OBSERVATION_REVIEW_REPORT_TEMPLATE.md) | [Original unfilled report](REVIEW_REPORT_TEMPLATE.md) |

The new inventory covers the entire selected Git tree: 70 added, 10 changed and
109 unchanged baseline files, with no removed files. It records path, mode,
blob ID, byte size, SHA256 and baseline status. The old manifest is unchanged.
`offline_session/public_worker.py` is the only changed baseline application
module; the other nine changed baseline files are guidance or workflow.

This packaging, its checker and tests are outside the selected 189-file source,
avoiding a circular inventory. The original source remains the subject of the
[construction brief](INDEPENDENT_REVIEW.md). Neither a dependency marked
unchanged nor its inclusion in either inventory implies that it was reviewed.
Build outputs, downloaded libraries and runtime state are excluded. Acquire
external source and audit material at the immutable references in the
[evidence inventory](EVIDENCE.md) and [notices](../THIRD_PARTY_NOTICES.md), check
licenses and record unavailable material separately. A dependency lockfile does
not attest registry bytes or an upstream Git checkout.

The later [Stage 29 authority model](OBSERVATION_AUTHORITY_MODEL.md) is outside
both fixed subjects. Its finite external-state/dispatch premises supply no
implemented service, enrollment or restore defense. Assess that exact delta
separately; neither manifest nor unfilled report is extended or completed.

The later [Stage 30 candidate authority contract](OBSERVATION_AUTHORITY_CONTRACT.md)
is likewise outside both subjects. Its pure scope/request/reply checks leave
enrollment, authentication, current-head evidence, target-set ownership and
durable single-use dispatch unimplemented. Existing entry points do not consume
its replayable public claims. Assess this exact codec and pure parsing
dependencies separately without altering either manifest or unfilled report.

The later [Stage 31 canonical enrollment model](OBSERVATION_ENROLLMENT_MODEL.md)
compares mutable quota keys, source-only knowledge, owner facts, cached absence,
atomic uniqueness and registry rewind. Its resource equivalence and owner facts
are premises, and its charges execute no worker or native persistence. This
delta also needs separate assessment; neither fixed manifest nor unfilled report
is extended, and no enrollment backend is selected.

The later [Stage 32 retained-resource and unsigned intent contract](RETAINED_RESOURCE_INTENT.md)
also requires separate exact delta assessment. A selected public commitment
tuple and unsigned owner binding authenticate no source, economic equivalence,
governor role or registry. Matching intent replays, and old expectations do not
prove freshness. Neither manifest or unfilled report is extended; no existing
entry point, actual verifier or enrollment backend is changed.

## Requested assessment surfaces

Relative links locate files in this checkout. Assess their exact source versions
at the observation commit above. The table is a review request, not an assertion
of complete runtime, fixture or cryptographic dependency closure. Reviewers must
identify additional dependencies and explicitly dispose of unexamined surfaces.

| Surface | Selected files and design | Obligation |
| --- | --- | --- |
| Exact observation and verdict partition | [Codec](../offline_session/observation_evidence.py), [adapter](../offline_session/observation_verifier.py), [public verifier](../qualification/examples/verify_observation.rs), [contract](OBSERVATION_EVIDENCE_CONTRACT.md) | Bind exact public request, retained context and selected profile; distinguish normal positive/negative from unknown work; establish trust assumptions separately from hashes |
| Attempt and claim history | [Records](../offline_session/observation_records.py), [record design](OBSERVATION_RECORDS.md) | Preserve prior normal claims, charged unknown attempts, conflict and replay behavior; expose quota replenishment by coherent restore |
| Owned persistence | [Store](../offline_session/observation_store.py), [owner design](OBSERVATION_STORE.md) | Acquire both lifetime locks before load; validate selection before SQLite; persist pending before worker and result before return; quarantine torn pairs without repair |
| Cooperative worker lifetime | [Pipe runner](../offline_session/public_worker.py), [guard](../offline_session/worker_guard.py), [lease design](OBSERVATION_LEASES.md) | Preserve inherited lock references, close-only semantics, exclusive reaping and parent monitoring under process death; separate cooperative exclusion from arbitrary containment |
| Physical capacity | [Pool](../offline_session/worker_pool.py), [admission design](SHARED_WORKER_ADMISSION.md) | Obtain a slot before charge; saturation is uncharged; live guard/worker retain the slot; equal-profile pools at separate physical files admit independent work |
| Requested process limits | [Policy](../offline_session/worker_resources.py), [launcher](../offline_session/resource_launcher.py), [resources](WORKER_RESOURCE_LIMITS.md), [durable v4](DURABLE_RESOURCE_POLICY.md) | Explicit supported Linux selection, inherited-limit preservation, setup/readback and same-process exec; pre-SQLite mode/profile refusal; no fallback after admitted unknown |
| Parsing and cryptographic dependencies | [Transcript](../offline_session/transcript.py), [exchange](../offline_session/exchange.py), [completion](../offline_session/completion.py), [inert package](../offline_session/__init__.py), [Rust harness](../qualification/README.md) | Examine reused parsers, predicates and error paths, dynamic guard/launcher paths, actual public executables and locked libraries; unchanged source is still a dependency |
| Qualification and source-journal boundary | [Observation qualifier](../scripts/qualify_observation.py), [record qualifier](../scripts/qualify_observation_records.py), [store qualifier](../scripts/qualify_observation_store.py), [resource qualifier](../scripts/qualify_worker_resources.py), [v4 qualifier](../scripts/qualify_observation_resource_store.py), [CI](../.github/workflows/offline-tests.yml) | Include qualifier journal setup and completion/authentication dependencies; separate synthetic callbacks from actual Rust verdicts and native-host probes; verify source-journal preservation without granting recovery authority |

The complete inventory includes all context, fixtures, licenses, lockfiles,
models, tests and historical reports, not just these requested targets. A static
Python import walk is insufficient to establish dynamic execution closure.

For each obligation, record three separate statements: desired requirement,
selected construction and executed evidence. In particular:

- Claims and producer hashes authenticate neither a source nor truth. A normal
  verdict requires an explicitly selected trusted local public verifier; process
  failures remain unknown. Requested profile equality attests no actual host or
  effective cap. Virtual address space is not RSS.
- Unknown work stays charged and cannot erase an earlier normal. Contradictory
  normal claims remain explicit. Restore of a matching earlier history can
  replenish quota; local consistency is not an external monotonic anchor.
- Cooperative holders retain two owner references and a physical pool slot.
  Closing the caller's references cannot revoke a live holder. A storage failure
  releases caller capacity while the poisoned live store retains both owner
  locks until close. Another healthy reopen does not replay work or add attempts.
- SQLite commit and checkpoint publication are separate. An old checkpoint with
  a committed database quarantines; a consistent pair may retain a normal after
  reported failure. Complete-pair validation precedes pending recovery. Neither
  v3 nor v4 silently migrates, rotates or falls back across policy/mode changes.
- Observation history has no source-journal mutation, recovery authorization or
  allowance-reset authority. Actual positive/negative and covered fault cases
  preserve source-journal state, sequence and both file bytes. This is a tested
  boundary, not authorization for funded recovery.

## Reproduce source identity offline

The expected commit must be supplied by the operator. Do not select it from a
received manifest, branch label or archive. The following acquisition step uses
the network; it is separate from all checker execution:

```sh
git fetch --no-tags --depth=1 origin f81e376e96e339647bb065739b4461235f865d2c e592633e4c630cfe3f4669876f6f63b80d2e33d6
```

Then, from a checkout containing this packaging with both manifests indexed:

```sh
python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c
```

The [checker](../scripts/check_observation_subject.py) recomputes both complete
inventories from local objects. It protects the original manifest at the selected
source, in the working tree and in the index, then checks the new working and
indexed manifest against exact canonical bytes. It rejects omissions, duplicate
keys/paths, extensions, altered metadata and noncanonical encoding. The broader
working/index source files are not asserted to equal the frozen source.

Git is invoked with `--no-lazy-fetch` and `--no-replace-objects`: missing promisor
objects must fail without fetching, and replacement refs cannot substitute the
source. These flag semantics are documented in the [Git manual](https://git-scm.com/docs/git).
A Git version supporting both flags is required; unsupported Git fails with no
fallback. Ambient Git overrides and installed global/system configuration are
excluded. The local Git executable, object store, filesystem and operator's pin
selection remain trusted. This is no hostile-parser sandbox or provenance proof.

An optional plain source archive can be checked without extracting any file:

```sh
mkdir -p .research-cache/review
git --no-lazy-fetch --no-replace-objects archive --format=tar --output=.research-cache/review/observation-source.tar f81e376e96e339647bb065739b4461235f865d2c
python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c --archive .research-cache/review/observation-source.tar
```

The checker accepts only a bounded uncompressed regular tar, exact complete
source bytes and Git executable classes. It rejects unsafe paths, special files,
links, duplicate/extra/missing members, sparse members and members appended after
end markers. Ordinary tar write-permission bits may differ from Git modes.
Archive bytes, compression, publication and release provenance are not attested.
Limits are 1 MiB per manifest, 2 MiB per source blob, 16 MiB total source and
16 MiB per plain archive, with at most 4,096 source files. These are explicit
input limits, not comprehensive hostile-host resource control.

To compare regeneration without overwriting either protected manifest:

```sh
python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c --emit > .research-cache/review/regenerated-observation-subject.json
cmp review/observation-subject.json .research-cache/review/regenerated-observation-subject.json
```

## Executed evidence and open obligations

The selected source has [seven successful exact-head hosted jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37199301500):
609 Python tests in each Linux/macOS 3.11/3.13 job with required OpenSSL and no
skips, 55 Rust tests, 13 Go top-level tests and nine actual-worker qualifier
groups with 64 cases, including all 13 v4 resource-store cases. Local required
discovery ran 609 tests without skips. These results execute the selected source,
not this later packaging. [Stage 26 validation](STAGE26_VALIDATION.md) preserves
the initial incomplete 20-minute CI attempt; six successful jobs there do not
establish seven-job success. [Stage 27 validation](STAGE27_VALIDATION.md) records
packaging execution separately.

Controlled SQLite/EIO/ENOSPC exceptions surround real operations but are synthetic.
After-operation faults require a real return, not partial physical writes.
Native writer file-size refusal requires kernel EFBIG; it tests neither native
disk exhaustion nor physical fsync failure. Linux result-side faults require an
actual positive or verified actor marker before injection. SIGKILL preserves
the running host and supplies no power-loss evidence. A blank report, finite
model, fixture, hash match or green CI is not an independent assessment.

**Go:** assess the exact observation subject, dependencies and explicit trust
boundaries using the separate report. Record findings, excluded surfaces and
unresolved obligations, including independent construction/backend review,
fresh entropy/private nonce ownership and secret memory, paired restore/clone
defense, source/verifier provisioning, authenticated peers, funding/time
authorization, native EIO/ENOSPC/partial-write/sync/power failure, enrollment,
aggregate budgets, parent/guard/preflight resources, fairness, privilege and
arbitrary descendants. Timely valid witness handling under exhaustion remains
unresolved.

**No-go:** private signing, trusted chain observation, funded swap recovery,
transaction broadcast, a core PTLC port or activation. Preparing this subject
does not resolve any of those gates or extend the original subject's assessment.

[Stage 28's v4 restore qualification](RESOURCE_STORE_RESTORES.md) adds later
test/qualifier evidence outside this fixed source: coherent pair rewind, copied
history, single-sided quarantine and repeat pending recovery. It changes no
application behavior or frozen manifest. Both unfilled assessments remain
pending; review this later qualification delta explicitly instead of silently
extending the 189-file subject. See [validation](STAGE28_VALIDATION.md).

[Stage 33 public enrollment signatures](PUBLIC_ENROLLMENT_SIGNATURES.md) are a later
verifier/framing delta outside this immutable subject and the original 119-file
subject. Actual public checks supply no governor-role or source authority, registry,
quota allocation, freshness, non-rollbackable lineage or unique dispatch. The
reused bounded runner adds no aggregate enrollment work policy. Neither manifest
nor unfilled report changes; assess this delta and its [validation](STAGE33_VALIDATION.md)
separately before any backend or integration.

[Stage 34 independent enrollment checks](INDEPENDENT_ENROLLMENT_SIGNATURES.md)
are later qualification outside this immutable source and the original subject.
Separate Go mathematics and framing checks change no application behavior and
supply no governor/source authority, freshness, enrollment uniqueness or quota.
Both fixed manifests and unfilled reports remain unchanged; this delta requires
separate assessment. See [validation](STAGE34_VALIDATION.md).

[Stage 35 local governor profiles](LOCAL_GOVERNOR_PROFILE.md) are later pure
proposal rules outside this immutable source and the original subject. Role
provenance, current policy/source authority and allocation remain external;
matching wrong/stale rules or broader caps can still succeed with the unchanged
signed intent. Assess independent selection, exact framing and optional
composition separately. Both fixed manifests and unfilled reports remain
unchanged; see [validation](STAGE35_VALIDATION.md) for executed evidence limits.

[Stage 36 governor authority comparison](GOVERNOR_AUTHORITY_MODEL.md) is a later
standalone model outside this immutable source and the original subject. Its
trusted root, assignment/intent signature facts and current oracle implement no
credential or freshness mechanism. Cached-check and old-anchor admissions are
counterexamples; conditional current checking provides no idempotency or worker
entry. Hypothetical complete profile binding changes no existing message. Neither
fixed manifest or unfilled report changes; assess this model separately. See
[validation](STAGE36_VALIDATION.md) for complete finite counts and evidence limits.

[Stage 37 unsigned assignment and v2 intent](GOVERNOR_ASSIGNMENT_CONTRACT.md)
is later framing outside both fixed subjects. It binds complete selected profile
content and issuer, while old v1 messages/signatures remain unchanged. It supplies
no role provisioning, actual credential verification, current-state source,
registry, quota or worker entry. The unsigned vector and passing encoding tests
are no construction assessment or independent cryptographic evidence. Both fixed
inventories and unfilled reports remain unchanged; this later delta needs its
own review. See [validation](STAGE37_VALIDATION.md) for the corrected first run.

[Stage 38 public issuer/owner qualification](GOVERNOR_SIGNATURE_QUALIFICATION.md)
is later verification outside both fixed subjects. Two actual signature facts
under selected keys establish no trusted provisioning, current authority, decoded
scope/source truth, registry or quota. The actual exhausted-journal control adds
no recovery allowance. New cross-language vectors do not fill either assessment;
both inventories, manifests and unfilled reports remain unchanged. Assess this
exact delta and any later use-time integration separately. See
[validation](STAGE38_VALIDATION.md), including the first Go setup failure.

[Stage 39 checkpoint-bound current-authority framing](CURRENT_AUTHORITY_EVIDENCE.md)
is outside both fixed subjects. It includes decoded scope/resource expectations
and both public signature statements, but parses only forgeable read labels.
Trusted provisioning, authenticated current evidence, non-rollbackable source
history and atomic actual-use ordering remain unresolved. Real exhausted-journal
checks establish only unchanged allowance and recovery refusal. Both inventories,
manifests and unfilled reports remain unchanged; independently assess this exact
later delta and any future source integration. See [validation](STAGE39_VALIDATION.md).

[Stage 40 policy-source/use comparison](POLICY_SOURCE_USE_MODEL.md) is outside
both fixed subjects. Ideal durable records and current policy do not establish
real source authentication, nonrewinding history, dispatch or physical entry.
Commit/entry cutoff differences and directed source-restore failures need their
own independent assessment. Selected shuffle completion is no full graph or
security proof. Both inventories, manifests and unfilled reports remain unchanged;
see [validation](STAGE40_VALIDATION.md).

The [Stage 41 local policy/effect store](OFFLINE_POLICY_EFFECT_STORE.md) is a
later isolated delta and leaves the observation subject and report unchanged.
Native process cuts test a synthetic row in one database, without source
credentials or worker admission. Coherent copies/restore still replay effects.
This construction, its runtime assumptions and any future external-effect gate
need a separate independent assessment. See [validation](STAGE41_VALIDATION.md).
