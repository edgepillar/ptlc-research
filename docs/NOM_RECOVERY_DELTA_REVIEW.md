# Separate NoM recovery and retention delta review

Status: **Preparation only. Independent assessment is NOT ASSESSED.** This
package contacts no reviewer and records no approval. Application/core remain
**NO-GO** and recovery action **NONE**. All AS-1 through AS-7 service gates remain
**UNFILLED**. No signer, authenticated chain observer, service or deployment is
selected by this package.

## Exact source and preserved earlier subjects

| Item | Selected value |
| --- | --- |
| Complete source commit | [`a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7`](https://github.com/edgepillar/ptlc-research/tree/a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7) |
| Git tree | `9d3811a5dbdfccdd8f4b4cf642b36f979292d39d` |
| Complete inventory | [969 tracked regular files](../review/nom-recovery-delta-subject.json), 32,689,521 source bytes |
| Canonical inventory SHA-256 | `d08cd8c85c04a0f4bbb8568ef3f87b5302f597686d520b2e208d99b993deb372` |
| Earlier NoM subject | `c560f5dc504818252703fdeaecc2ff96a3f86059`, tree `9a5f312218678cc9d3f8713f7f3d5cda4de6e451`, 620 files |
| Earlier NoM inventory SHA-256 | `59d9b134d4be55f3dc98797529aff86d121fdce3d0e2ddce8dfd7b9c171cf179` |
| Delta from that subject | 349 added, 9 changed, 611 unchanged, no removed paths |
| Separate assessment record | [Unfilled delta report](NOM_RECOVERY_DELTA_REVIEW_REPORT_TEMPLATE.md) |

The inventory records path, regular-file mode, Git blob ID, byte count and
SHA-256 for every selected file. Its status fields compare complete records,
including executable mode, with the earlier NoM inventory. Documentation,
fixtures, tests, workflows, dependency records, licenses and non-build files are
included. An unchanged row identifies unchanged bytes and mode; it supplies no
earlier assessment, dependency attestation or permission.

The [source reader](../scripts/check_nom_recovery_delta_subject.py) reconstructs
the earlier NoM inventory from its immutable Git objects before comparing it.
Six older review inventories/handoff files and three earlier report templates
must match that baseline in the selected source, working tree and index. The
later NoM inventory and separate unfilled NoM report are also pinned and
preserved there. These eleven protected inputs remain unchanged. This new
inventory does not amend an older subject or fill an older report.

This reader, its tests, this brief, the new manifest and new report are packaging
**outside** the selected 969-file source. A reviewer must independently select
their immutable packaging commit/tree, record the reader's digest and assess
that delta separately. The reader cannot certify itself or establish reviewer
independence. Broader working-tree and index contents are not asserted to equal
the source snapshot; the selected manifest and eleven protected artifacts are
checked separately.

## Changed files and requested assessment

The nine changed paths are `.github/workflows/offline-tests.yml`, `README.md`,
`docs/NOM_FIXED_RECOVERY.md`, `offline_session/nom_verifier.py`,
`offline_session/public_worker.py`, `scripts/check_cargo_resolution.py`,
`scripts/check_worker_build.py`, `scripts/qualify_nom_recovery.py` and
`tests/native_nonce_boundary_actor.py`. Review these actual deltas as well as
the 349 additions. The fixed source contains earlier Bitcoin/observation work
as context; this NoM request transfers no assessment to those separate subjects.

Links below locate files. Read their versions at the exact selected commit,
including the frozen NoM implementation retained from the earlier subject.
The complete inventory, rather than this reading map, defines file coverage.

| Surface | Selected entries | Required assessment and remaining boundary |
| --- | --- | --- |
| Fixed-recipient construction | [Recovery](../offline_session/nom_recovery.py), [Rust public worker](../qualification/examples/verify_nom_swap.rs), [fixed recovery contract](NOM_FIXED_RECOVERY.md) | Re-derive both messages, the common compressed adaptor point, key/role separation, extraction and disclosure order. Verify the terms commitment covers fields omitted by the selected core message. Finite public arithmetic does not assess atomicity, economics or real timeout margins. |
| Worker and build deltas | [NoM adapter](../offline_session/nom_verifier.py), [pipe runner](../offline_session/public_worker.py), [build checks](../scripts/check_worker_build.py), [Cargo comparison](../scripts/check_cargo_resolution.py), [worker profile](NOM_WORKER_QUALIFICATION.md) | Assess empty versus inherited environment, exact request/result binding, executable measurements, dependency/build claims and loader trust. A positive script or matching build metadata is not runtime authentication. |
| Original-only recovery | [Recovery qualifier](../scripts/qualify_nom_recovery.py), [strict open](../offline_session/nom_strict_open.py), [journal hold](../offline_session/nom_journal_hold.py), [retention](../offline_session/nom_retention.py) | Verify UNKNOWN is durable before disclosure/work, original bytes and charges survive uncertainty, and missing custody or torn history refuses without reconstruction. Reopen, lookup and send acknowledgement must grant no replacement, retry or new original. |
| Core and wire correspondence | [PR #138 profile](../offline_session/pr138.py), [wire](../offline_session/nom_wire.py), [created funding](NOM_CREATED_FUNDING.md), [VM path](NOM_VM_PATH.md), [recovery cuts](NOM_RECOVERY_CUTS.md) | Check exact source pins and the distinction between synthetic identifiers, Create-derived identifiers, actual ABI/hash inputs and isolated VM observations. Signed account-block originals, account admission, Plasma and atomic journal integration remain unimplemented. |
| Observation and complete openings | [Observation](../offline_session/nom_observation.py), [momentum](../offline_session/nom_momentum.py), [base openings](../offline_session/nom_evidence_openings.py), [VM openings](../offline_session/nom_vm_openings.py), [account history](../offline_session/nom_account_history.py) | Distinguish supplied bytes and reproduced source behavior from independently selected canonicality, finality and reorg evidence. No callback, matching hash or complete packet supplies an authenticated chain observer. |
| Authority, custody and continuity | [Authority contract](../offline_session/nom_authority_contract.py), [capsule](../offline_session/nom_capsule.py), [continuity](../offline_session/nom_capsule_continuity.py), [query](../offline_session/nom_capsule_query.py), [checkpoint](../offline_session/nom_source_checkpoint.py) | Assess complete actual custody, source selection, retained minimum, scope and continuity. Public descriptors cannot restore missing originals or independently provision an authority. |
| Lookup and delivery ordering | [Protocol](../offline_session/nom_checkpoint_protocol.py), [discovery](../offline_session/nom_checkpoint_discovery.py), [response](../offline_session/nom_checkpoint_response.py), [read order](../offline_session/nom_checkpoint_read_ordering.py) | Keep signature mathematics, authentication roles, evaluation position and currentness at delivery separate. Discovery, a fresh challenge or a signed old head cannot establish current independent authority. |
| Lifecycle and durable local records | [Lifecycle](../offline_session/nom_anchor_lifecycle.py), [transition journal](../offline_session/nom_anchor_transition_journal.py), [uncertainty](../offline_session/nom_uncertainty.py), [partial custody](../offline_session/nom_partial_custody.py) | Preserve possible publications, UNKNOWN charges and terminal history. Examine coherent restore, independently writable copies, lost replies and exhaustion as counterexamples rather than closure of an external retention gate. |
| Native SQLite comparison | [Material](../qualification/nom_anchor_sqlite_material.py), [schema](../qualification/nom_anchor_sqlite_schema.sql), [capture](../qualification/nom_anchor_sqlite_capture.py), [comparison](../qualification/nom_anchor_sqlite_comparison.py), [reader](../qualification/nom_anchor_sqlite_review.py), [profile](NOM_ANCHOR_SQLITE_COMPARISON.md) | Check complete bytes, actual command/failure evidence and pre-reopen images. SQL equality consumes an already validated transition; it is not an independent protocol verifier. Process death, DELETE/EXTRA and green CI do not prove physical durability or prevent rollback/copies. |
| Operational service proposal | [Candidate](NOM_ANCHOR_SERVICE_CANDIDATE.md), [seven acceptance gates](NOM_ANCHOR_SERVICE_ACCEPTANCE.md) | Assess the single-administrator trust hypothesis and failures it cannot tolerate. No operational authority, provisioning, authentication message, service transport or original-operation adapter has been selected. Every service gate remains unfilled. |
| Qualification and publication | [Workflow](../.github/workflows/offline-tests.yml), [artifact checker](../scripts/check_artifacts.py), [local SQLite report](NOM_ANCHOR_SQLITE_COMPARISON_VALIDATION.md) | Separate fixture oracles, actual native work, source/runtime identity, original downloaded artifacts, exact-head PR checks and later push/main checks. Preserve failed and incomplete evidence; never infer a pass from a wrapper exit alone. |

For each conclusion, record examined files and dependencies, assumptions,
counterexamples, actual commands and evidence, and excluded or unavailable
surfaces. An absence of findings does not fill an unexamined obligation.

## Inputs not supplied by this inventory

Downloaded third-party source, Cargo archives/checkouts, installed runtimes,
tool support, SDKs, compiler/loader libraries, compiled executables, actual
native graphs and CI console archives are not bundled. Lockfiles identify
claims; they do not authenticate those external bytes or the compiled closure.
Acquire required material in a separately admitted storage lifecycle, verify
the immutable selections and check [notices](../THIRD_PARTY_NOTICES.md).
Record missing or unexamined material explicitly.

The source contains public synthetic test constants. It contains no selected
private signer or secret-custody backend. Review must not promote reference
arithmetic or public fixtures into application cryptography. External upstream
contributions and later dev comparisons need their own exact source/evidence
pins; this inventory does not make an older passing run current after a change.

The selected source's validation documents are historical scope statements.
Fresh hosted results and original artifacts remain separate evidence, including
the PR and subsequent main attempt described in [research PR #168](https://github.com/edgepillar/ptlc-research/pull/168).
No inventory result is a hosted-CI acceptance, independent-machine result,
physical power-loss qualification or independent written assessment.

## Offline identity reproduction

Independently select both the source commit and manifest digest before trusting
received files. Obtain the source and earlier NoM Git objects separately if
absent. Select a packaging checkout with its manifest already indexed, then run:

```sh
python3 -B scripts/check_nom_recovery_delta_subject.py \
  --expect-commit a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7 \
  --expect-manifest-sha256 d08cd8c85c04a0f4bbb8568ef3f87b5302f597686d520b2e208d99b993deb372
```

The new reader selects an 8 MiB blob limit and 40 MiB complete-source limit to
include the actual 7,100,321-byte fixture and 32,689,521-byte snapshot. The older
readers retain their unchanged 2 MiB/16 MiB limits. A 1 MiB manifest/tree-listing
bound and 4,096-file bound remain finite. Oversize declarations, nonregular files,
case aliases, unsafe paths, missing objects, non-ASCII source, changed earlier
artifacts, omitted rows and canonical/digest/index substitutions refuse.
Every selected blob is checked against its Git blob ID and SHA-256.

The reused local Git reader disables lazy fetching, replacement objects and
ambient Git overrides/global/system configuration. The local Git executable,
object store, repository configuration, host, filesystem and independently
chosen pins remain trusted. Bounds are application checks, not a hostile-parser
sandbox or an OS memory quota. This reader has no extraction, build, cleanup,
network, signer, service or recovery API. Its disclosure scan is limited and
does not guarantee anonymity or absence of secrets.

Run source-reader controls separately from protocol and native qualification:

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -p 'test_nom*subject.py' -v
REQUIRE_OPENSSL=1 python3 -B -W error::ResourceWarning -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
```

The [separate report](NOM_RECOVERY_DELTA_REVIEW_REPORT_TEMPLATE.md) remains empty
until an independent assessment identifies its exact scope and evidence.
Findings, exclusions and the still-unfilled signer, observer, original-operation
and service obligations require explicit disposition before application use.
Deployment, node activation, wallet access, application signing, transaction
broadcast, controlled network composition and real funds remain outside Stage 0.
