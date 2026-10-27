# Current NoM source and recovery review handoff

Status: **PREPARATION ONLY; NOT INDEPENDENTLY ASSESSED.** Application and core
remain **NO-GO**, recovery action is **NONE**, and AS-1 through AS-7 remain
**UNFILLED**. This packet selects no signer, chain authority, service, operational
adapter, deployment or funds. No reviewer has been contacted or assigned.

## Exact subject

| Item | Selected value |
| --- | --- |
| Repository | [ptlc-research](https://github.com/edgepillar/ptlc-research) |
| Subject commit | [`e61aa17418cc96d82c21ebfdb651c339363230fd`](https://github.com/edgepillar/ptlc-research/tree/e61aa17418cc96d82c21ebfdb651c339363230fd) |
| Git tree | `4f6b172c1c95d5aa4268906e70819d110330d4b1` |
| Complete source | 1,256 regular tracked files; 37,755,618 source bytes |
| Inventory | [Current source inventory](../review/nom-current-review-subject.json) |
| Canonical inventory SHA-256 | `88e7c60d517fb80b603ee92d5b5c81c96f1ddba196d9d8da6a2f9a2185a7ae09` |
| Inventory bytes | 375,283 |
| Earlier delta subject | `a98dfe7b2fbfc8f8c2b378b34a524e1c1cdff8e7`, tree `9d3811a5dbdfccdd8f4b4cf642b36f979292d39d` |
| Delta from that 969-file subject | 287 added, 20 changed, 949 unchanged, no removed paths |
| Assessment | [Separate unfilled report](NOM_CURRENT_REVIEW_REPORT_TEMPLATE.md) |

The complete inventory uses the existing bounded NoM source reader and its
unchanged schema. Each row identifies path, mode, Git blob, byte count and
SHA-256. Its `nom_worker_status` compares against the preserved 620-file worker
subject; it does not describe the later 969-file delta. The counts above and
the following changed-file list describe that separate comparison.

All thirteen earlier review inventories and report inputs remain unchanged.
This packet does not amend the [969-file brief](NOM_RECOVERY_DELTA_REVIEW.md),
the earlier worker/construction subjects, their evidence or their unfilled
reports. Unchanged files have no inherited assessment merely because their
bytes match. The packet and its eventual packaging revision are outside the
selected 1,256-file subject and need their own explicit source selection.

## Twenty changed paths

Read these actual changes against the earlier subject as well as all 287 added
files. The complete inventory defines coverage; this list is a reading aid.

- `.github/workflows/offline-tests.yml`
- `AGENTS.md`
- `CONTRIBUTING.md`
- `README.md`
- `compatibility/nom_anchor_lifecycle_manifest.json`
- `compatibility/nom_anchor_sqlite_manifest.json`
- `compatibility/nom_anchor_transition_journal_manifest.json`
- `compatibility/nom_capsule_continuity_manifest.json`
- `compatibility/nom_capsule_query_manifest.json`
- `compatibility/nom_checkpoint_discovery_manifest.json`
- `compatibility/nom_checkpoint_protocol_manifest.json`
- `compatibility/nom_checkpoint_read_ordering_manifest.json`
- `compatibility/nom_checkpoint_response_manifest.json`
- `compatibility/nom_source_checkpoint_manifest.json`
- `offline_session/nom_capsule_continuity.py`
- `offline_session/nom_capsule_query.py`
- `offline_session/nom_checkpoint_discovery.py`
- `scripts/check_observation_subject.py`
- `scripts/check_witness_subject.py`
- `tests/test_observation_review_subject.py`

## Required assessment

| Surface | Review question and evidence boundary |
| --- | --- |
| Fixed-recipient construction | Re-derive messages, funding identifiers, terms commitments, key/role separation, adaptor linkage, disclosure/extraction order and timeout assumptions from the exact source. Assess both success and adversarial schedules. Public mathematical agreement does not establish economic or protocol safety. |
| Historical and snapshot recovery entries | The [author review](NOM_AUTHOR_REVIEW.md) identifies the historical mutable-observation callback defect. Assess the additive snapshot entry and both callback boundaries. Historical replay does not authenticate old observations; synthetic observation canonicalization must not replace raw signed bytes. |
| Exact signed-byte custody | Assess original bytes, SHA-256 versus node hash, outer signature, account/context bindings, raw protobuf aliases, excluded metadata and exact replay. A matching node hash or valid signature supplies no original-byte custody, funding, admission or chain authority. |
| Current source and fee boundary | The [current comparison](NOM_DEV_661B5EF.md) selects go-zenon `661b5ef404487cd41685654bf87530f10adebbe4`. The [fee corpus](NOM_FEE_ORIGINAL_BOUNDARY.md) separates six fee, four hash and four outer-signature refusals. These account-send failures do not execute receive, payout, recipient credit or swap recovery. |
| Authorization and a distinct proxy design | The existing direct originals declare less fused Plasma than the selected argument-priced requirement. Changing that signed allowance changes their hash and invalidates existing authorization. Direct fixed-recipient Unlock constrains the sender; a separate ProxyUnlock payer needs independently selected outer authorization, funding, custody and timing. No replacement original, proxy signer or journal upgrade is selected. |
| Source truth and observation | Assess canonicality, finality, reorg handling, exact checkpoints, evaluation position and delivery freshness independently of public mathematical validity. No callback, source label, fresh challenge, signature or complete packet supplies a trusted current chain observer. |
| Retention and uncertain outcomes | Assess original custody, UNKNOWN-before-disclosure/work ordering, interrupted and missing output, lost acknowledgments, exhaustion and reopen. Coherent restore and independently writable copies remain counterexamples; lookup cannot authorize another original, retry or replenishment. |
| Worker, dependencies and storage | Assess actual selected executables, loader/dependency provenance, environment boundaries and the complete implementation delta. Native SQLite equality, fsync, selected process death, source hashes and successful CI do not establish physical durability, nonrollback authority or signing custody. |
| AS-1 through AS-7 | Assess the [service requirements](NOM_ANCHOR_SERVICE_ACCEPTANCE.md) independently: provisioning, enrollment/retirement continuity, shared durable transitions, authenticated current evaluation, external nonrollback retention, original-operation entry and independent qualification. No mechanism or gate is selected by this packet. |

A protocol/cryptography reviewer and a custody/runtime reviewer may examine
separate scopes. Each assessment must identify examined files, dependencies,
assumptions, counterexamples, original evidence, exclusions and unresolved
requirements. Same-process author review and cross-verifier agreement do not
supply reviewer independence. Absence of a finding is not coverage of an
unexamined obligation.

## Execution evidence and exclusions

The publication of this subject is [PR #208](https://github.com/edgepillar/ptlc-research/pull/208).
Its source-bound local regression, hosted PR results, original-content acceptance
and later main push are distinct evidence gates. Source inventory generation
does not qualify any of those gates. Select actual run IDs and attempts, retain
their original archives, and distinguish failed or incomplete attempts even if a
later observation succeeds.

The fourteen fee cases have separate local native component evidence using the
exact checked-in producer and declared values. The selected hosted current-core
job still executes its existing 31-profile subject. This packet does not add
hosted native execution of the separate fourteen-case profile.

External core source, dependencies, installed toolchains, compiler/SDK/loader
closures, compiled workers and original CI archives are not bundled by a source
inventory. Acquire and assess their exact selections separately, respecting
their [licenses and attribution](../THIRD_PARTY_NOTICES.md). A lockfile or checksum
does not authenticate a build or its runtime dependencies.

## Reproduce source identity

Independently select the source commit and inventory digest before reading the
packet. Obtain all required immutable Git objects separately if absent. The
existing reader has no source acquisition, extraction, build, signing, service
or recovery operation. Its unchanged limits are 8 MiB per blob, 40 MiB total,
1 MiB per manifest and 4,096 files; this subject fits those limits.

The existing default CLI still targets the historical 969-file inventory. For
this separate file, call the unchanged generic comparison explicitly:

```sh
python3 -B - <<'PY'
from pathlib import Path
from scripts.check_nom_recovery_delta_subject import Pins, verify_manifest
from scripts.check_observation_subject import _index

root = Path.cwd()
name = "review/nom-current-review-subject.json"
raw = (root / name).read_bytes()
subject = verify_manifest(
    root, Pins("e61aa17418cc96d82c21ebfdb651c339363230fd"), raw,
    "88e7c60d517fb80b603ee92d5b5c81c96f1ddba196d9d8da6a2f9a2185a7ae09")
if _index(root, name) != raw:
    raise SystemExit("REFUSED: selected current inventory differs from index")
print("PASS: {} files; source identity only; NOT ASSESSED".format(subject["file_count"]))
PY
```

The local Git executable, object store, repository configuration, host and
independently selected pins remain trusted. The disclosure scan is limited;
it is not a guarantee of anonymity or absence of sensitive data. Matching bytes
supply source identity, not provenance or a security verdict. This packet grants
no application, signing, network, deployment, activation or funds permission.
