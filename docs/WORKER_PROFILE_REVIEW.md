# Immutable worker-profile acceptance packet

Status: **PREPARATION ONLY / NOT ASSESSED**. This packet records no independent
findings and contacts no reviewer. Application and core progression remain
**NO-GO**. Existing construction, observation and witness reports remain unfilled.

## Exact source and separate packaging

| Item | Selected subject |
| --- | --- |
| Repository | [ptlc-research](https://github.com/edgepillar/ptlc-research) |
| Source commit | [`a80d14f1bc223e7d20901837fe84804fc7c1bce5`](https://github.com/edgepillar/ptlc-research/tree/a80d14f1bc223e7d20901837fe84804fc7c1bce5) |
| Git tree | `667260aee79ef353442feb9a9077731d0a76f88c` |
| Complete inventory | [423 tracked regular files](../review/worker-subject.json) |
| Manifest SHA256 | `f140380fe8c2a11387316c5b8ed7269cdce239f89592ded26588decf1c42c75e` |
| Earlier subjects | [Construction: 119 files](../review/subject.json), [observation: 189 files](../review/observation-subject.json), [witness: 360 files](../review/witness-subject.json) |
| Preserved assessment records | [Construction](REVIEW_REPORT_TEMPLATE.md), [observation](OBSERVATION_REVIEW_REPORT_TEMPLATE.md), [witness](WITNESS_REVIEW_REPORT_TEMPLATE.md): all UNFILLED |

The inventory covers every tracked regular file at the selected source commit,
including all profiles, tests, fixtures, dependency locks, notices, history and
workflow. It does not assert that each file was examined. It compares complete
rows against the fixed witness inventory without enlarging any earlier subject
or transferring approval. The manifest pins all three earlier inventories and
unfilled reports in immutable source, current checkout and index.

The new manifest, [checker](../scripts/check_worker_review_subject.py),
[controls](../tests/test_worker_review_subject.py), this brief, validation and
workflow insertion are later packaging, outside the subject. Assess their exact
revision separately. The checker reuses the existing bounded local Git, JSON
and plain-archive primitives; a checker cannot certify its own correctness.
Externally select the source commit and manifest digest before receiving the
packet. Refuse mutable refs, missing objects, substituted rows, altered preserved
reports or a different canonical encoding. No lazy network fetch or native build
is performed by the checker. Archive inspection extracts no files.

Installed tools, downloaded dependency source, compiled artifacts, private
locations/carriers, runtime state and execution logs are excluded. Hashes identify
selected bytes; they are not an authenticated producer, distribution or source
trust anchor. The source checker is a separate trusted tool on a trusted host.
Its regular-file checks do not provide hostile-filesystem exclusion, an atomic
multi-file snapshot, nonrollback state or future executable-use binding.

## Separately selected profiles and readers

Read each linked path at the exact subject commit. Later checkout versions are
not implicitly covered. Preserve historical profiles rather than relabeling a
later result as their evidence. No new native experiment is selected here.

| Surface | Fixed source entry | Bounded behavior to assess | Limit that must remain explicit |
| --- | --- | --- | --- |
| Build records and native companion | [Contract](OFFLINE_WORKER_BUILD_RECORDS.md), [record parser](../scripts/check_worker_build.py), [driver](../scripts/qualify_worker_build.py) | Independent logical baseline, bounded metadata/build operations, selected source/content/resolution and three native-file byte comparisons | Forged matching claims can pass; installed support chain and complete compilation units are not determined |
| Complete artifact comparison | [Contract](OFFLINE_ARTIFACT_PREFIXES.md), [scanner](../scripts/check_artifact_prefixes.py) | Two complete retained streams, four explicitly selected role prefixes, full measurements and MATCH/DIFFER | Absence covers only selected bytes; matching arbitrary copies supplies no provenance or privacy guarantee |
| Target-only Rust remapping | [Construction](OFFLINE_RUST_PATH_REMAPPING.md), [driver](../scripts/qualify_worker_remapping.py) | Four explicit ordered rules, literal transport, both-pair preflight, selected environment/cwd restoration and pre/post gates | Host build scripts and support inputs are outside target-only coverage; consumed arguments are not authenticated |
| Retained section localization | [Contract](OFFLINE_WORKER_SECTION_LOCALIZATION.md), [driver](../scripts/qualify_worker_sections.py), [parser](../scripts/check_worker_sections.py) | Canonical caller-selected carrier and same complete measurements; fixed region booleans | Carrier agreement authenticates no historical execution; parsing supplies no object or source identity |
| Retained symbol references | [Contract](OFFLINE_WORKER_SYMBOL_REFERENCES.md), [driver](../scripts/qualify_worker_symbols.py), [parser](../scripts/check_worker_symbols.py) | Bounded ELF/Mach-O grammar, raw versus declared referenced names, eight fixed classes and relation agreement | Numeric symbol types, suffix references and name matches prove no existence, ownership or producer attribution |
| Retained debug names | [Contract](OFFLINE_WORKER_DEBUG_NAMES.md), [driver](../scripts/qualify_worker_debug_names.py), [parser](../scripts/check_worker_debug_names.py) | Terminated pools, exact source-STAB types, ten fixed classes and shared-stream implications | Termination or source-name classification is not source truth; debug metadata is not independently authenticated |
| Separate C debug-prefix profile | [Construction](OFFLINE_C_DEBUG_REMAPPING.md), [driver](../scripts/qualify_worker_c_debug.py) | Four C rules plus unchanged Rust rules, selected C namespace restoration, two fresh builds and four observations | CFLAGS affect more than debug prefixes; historical pairs are not isolated causal controls; other producers remain unassessed |
| Retained C-pair symbols | [Contract](OFFLINE_C_WORKER_SYMBOLS.md), [driver](../scripts/qualify_worker_c_symbols.py) | One exact private C carrier and two additional retained streams, actual complete measurements and cross-reader agreement | No build, historical input remeasurement or public mathematics is performed by this companion |
| Separate Apple object-prefix profile | [Construction](OFFLINE_MACHO_OBJECT_PREFIX.md), [driver](../scripts/qualify_worker_macho_prefix.py) | Native Apple-only gate, one explicit literal linker prefix, unchanged C/Rust rules, two fresh builds and four observations | Prefix need not cover all roles; installed linker and argument consumption are not authenticated; no Linux substitute is selected |

All complete-stream measurements, fixed booleans and MATCH/DIFFER are selected
observations. Equal/different bytes and present/absent matches are permitted;
do not require absence or equality as the acceptance condition. Keep native
input measurement, private carrier reads, artifact acquisitions, parsing in
memory and public-worker launches separate. Command counts do not enumerate
support processes or establish isolation. Explicit synthetic negative controls
are distinct from actual local/hosted native qualifications.

## Evidence and independent reproduction

The [Stage 69 validation](STAGE69_VALIDATION.md) describes its local Apple pair
and separates earlier work. [Draft PR 64](https://github.com/edgepillar/ptlc-research/pull/64)
and [its hosted run](https://github.com/edgepillar/ptlc-research/actions/runs/37525800480)
record completed candidate execution: four Python jobs, Rust, two Go jobs and a
separate Apple job. A green badge alone is insufficient: establish the immutable
checkout actually executed, its complete tree and ordered base/head parents,
then inspect every expected method, terminal result and complete artifact
measurement. The displayed merge commit may differ from the executed checkout.

The old Linux qualification remains 25 actual-worker groups / 294 cases and
16 observation acquisitions. The separate Apple profile contributes two public
mathematics groups / 28 cases and four observations. These are different native
runs; do not combine them into a single same-runtime total. The builder does
not launch the public verifier; those 14 historical math cases per selected
worker are independently invoked by the caller. A math pass proves no private
nonce lifecycle, source provenance, privacy, current authority or future use.

Acquire external source and dependency bytes separately using the immutable pins
and license records in [build inputs](OFFLINE_BUILD_INPUTS.md),
[content comparison](OFFLINE_DEPENDENCY_CONTENTS.md),
[resolution](OFFLINE_CARGO_RESOLUTION.md) and [third-party notices](../THIRD_PARTY_NOTICES.md).
Record unavailable or unexamined material. Source references and selected tool
hashes do not identify the installed compiler/linker/support distribution.
No third-party code or prose is copied by this packaging.

Independent execution may require a separately authorized private acquisition
and native scope. Do not publish selections, arguments, raw private names,
streams, carriers, offsets, reference counts, metadata or compiled artifacts.
Public fixed role/class booleans and complete artifact measurements are limited
evidence, not an artifact-release assessment.

## Written acceptance obligations

An independent assessment must identify its own public nonidentifying attribution,
independence/conflicts, immutable examined source and packaging revisions,
method, executed checks and omitted material. No reviewer identity or finding is
supplied here; the three existing records remain untouched. Preparing this packet
neither requests review nor substitutes internal tests for independence.

| Gate | Required written evidence | Current disposition |
| --- | --- | --- |
| Exact source and packaging | Independently selected commit/digest, complete inventory and explicit later checker/workflow delta | Source packaging only; NOT ASSESSED independently |
| Construction and grammar | All selected inputs, type/bound/preflight refusals, cancellation and restoration; malformed and forged agreement counterexamples | NOT ASSESSED independently |
| Native producer and support chain | Identify actually executed native tools and consumed arguments; examine dependencies, generated/support inputs and process effects | NOT AUTHENTICATED / NOT DETERMINED |
| Source-to-worker and reproduction | Independent acquisition, output binding and stated reproducibility method; no reliance on same-run self-selected claims | NOT VERIFIED |
| Privacy and release | Separately authorized full identifying-material assessment of complete artifacts and disclosure policy | NOT ASSESSED; artifacts remain private |
| Runtime, storage and future use | Explicit host/ancestor/transport trust, replacement/snapshot limits, nonrollback and subsequent launch boundary | Unresolved; no protected-use authority |
| Exact protocol and secret custody | Construction review, fresh entropy, durable nonce ownership, restored-copy defense and actual signer/journal boundary | Unresolved; test-only public mathematics |
| Application and consensus progression | Separately justified implementation and upstream-coordinated core scope after all applicable gates | NO-GO |

For each finding distinguish the protocol requirement, selected construction,
trusted premise, verified behavior, reproducible synthetic evidence, severity,
disposition and remaining obligation. No absence of findings or missing material
implies acceptance. An assessment of these build profiles cannot approve the
whole swap protocol or fill unrelated reports.

No private signer, source service, wallet, chain observer, Bitcoin construction,
authoritative recovery, protected-use adapter, core port, deployment, activation,
transaction broadcast or funded operation is added or authorized by this packet.
