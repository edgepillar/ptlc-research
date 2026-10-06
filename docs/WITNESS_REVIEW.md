# Separate immutable witness review brief

Status: **Preparation only. Independent assessment is NOT ASSESSED.** No reviewer
has been contacted or assigned by this package. Application integration, core
port and funded execution remain **NO-GO**.

## Fixed source and separate packaging

| Item | Witness subject |
| --- | --- |
| Source commit | [`bd4b4b523fb3453e2af191eb01973985d6431d66`](https://github.com/edgepillar/ptlc-research/tree/bd4b4b523fb3453e2af191eb01973985d6431d66) |
| Git tree | `1efd5f984cefa203eb581c073c5d6d2ac4334a4a` |
| Complete tracked source | [360 regular files](../review/witness-subject.json), 8,915,480 source bytes |
| Manifest SHA256 | `0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f` |
| Assessment record | [Separate unfilled witness report](WITNESS_REVIEW_REPORT_TEMPLATE.md) |

The [119-file construction subject](../review/subject.json), the [189-file
observation subject](../review/observation-subject.json) and both earlier unfilled
reports retain their exact bytes. This third inventory neither extends their
subjects nor records findings in their reports. Each new row pins path, Git
mode, Git blob ID, byte count, SHA256 and status relative to the observation
subject. All context, source, fixtures, tests, models, historical evidence,
workflow controls, dependency records and licenses in the selected tree are
included. Inventory completeness does not mean every file has been examined.

The new manifest, checker, tests, brief, report template and validation document
are packaging added after the fixed subject commit. They are outside its 360
files and require their own exact-delta assessment. The checker reuses unchanged
bounded Git, JSON and archive primitives in
[check_observation_subject.py](../scripts/check_observation_subject.py), which
is inside the fixed source. A checker cannot certify its own correctness.

Downloaded third-party source, registry bytes, installed runtimes, compiled
executables, private cache, runtime state and hosted logs are excluded. Lockfiles
and public fixture contents are included; they attest neither external bytes nor
their availability. The reviewer must acquire and identify required external
material separately, check attribution and licenses using
[notices](../THIRD_PARTY_NOTICES.md) and [evidence](EVIDENCE.md), and report any
missing, unavailable or unexamined dependency. A static Python import walk is
not a complete execution or cryptographic dependency inventory.

## Requested assessment and acceptance gates

Review the exact source versions at the commit above. The paths below locate
the selected targets; their current checkout versions may differ. Findings must
separate protocol requirements, selected test-only constructions, assumptions,
executed evidence and unresolved obligations.

| Surface | Selected source and entry | Required disposition |
| --- | --- | --- |
| Complete retained original and opening | [Opening](../tests/original_snapshot_opening.py), [sampler](../qualification/original_read_snapshot.py), [opening cases](../tests/test_original_snapshot_opening.py) | Derive original tuple, policy and record heads from complete bounded history; reject partial, conflicting and malformed openings; distinguish original identity from an unsigned selection |
| Prefix and mathematical response composition | [Prefix](../tests/original_snapshot_prefix.py), [composition](../tests/original_snapshot_prefix_response.py), [actual qualifier](../scripts/qualify_original_snapshot_prefix_response.py) | Frame both complete packets before either verifier; preserve earlier records and policy history; authenticate neither callback flags nor the selected source by arithmetic alone |
| Public worker and cryptographic dependencies | [Response adapter](../qualification/original_read_response_verifier.py), [Rust worker](../qualification/examples/verify_original_read_response.rs), [root worker](../qualification/examples/verify_source_root.rs), [Cargo](../qualification/Cargo.lock), [Go comparison](../qualification-bitcoin-go/go.sum) | Assess complete tagged statements, canonical wire, two signature results, selected executable measurement and result binding; identify the worker's bitcoin::secp256k1 dependency separately from the adaptor harness and its schnorr_fun dependency |
| Owned witness transaction | [Store](../tests/original_witness_store.py), [store experiment](ORIGINAL_WITNESS_STORE_EXPERIMENT.md), [actual qualifier](../scripts/qualify_original_witness_store.py) | Validate independently selected complete binding under the same transaction as load, prefix comparison, write and commit; inspect without authority; explain copy, restoration and pathname recreation limits |
| Creation and interrupted lifetime | [Lifecycle cases](../tests/test_original_witness_lifecycle.py), [native actor](../tests/original_witness_lifecycle_actor.py), [actual qualifier](../scripts/qualify_original_witness_lifecycle.py), [lifecycle experiment](ORIGINAL_WITNESS_LIFECYCLE_EXPERIMENT.md) | Assess descriptor cleanup, busy reentrance, actual fork ownership, inherited native finalization, opening and retention cancellation, hot-journal recovery and before/after-commit uncertainty under the stated native/VFS premises |
| Source outcome and protected-use ordering | [Source store](../qualification/policy_effect_store.py), [consumer model](../scripts/model_original_consumer_retention.py), [provenance model](../scripts/model_original_read_provenance.py) | Separate source and consumer rollback domains, retained history and current canonical truth; show where source unknown effects remain unknown and where protected entry requires additional atomic ordering |
| Disclosure, roles and operational authority | [Current evidence](CURRENT_AUTHORITY_EVIDENCE.md), [scope](SCOPE.md), [source roles](SOURCE_ROOT_ROLE_QUALIFICATION.md) | Resolve authenticated Root/issuance/original provenance, current/canonical selection, independent nonrollback ownership, signer custody, minimal disclosure, authorized lookup, administrator incarnation/deduplication and authoritative original recovery before application use |
| Qualification and publication evidence | [Stage 56 local scope](STAGE56_VALIDATION.md), [workflow](../.github/workflows/offline-tests.yml), [artifact checker](../scripts/check_artifacts.py) | Reproduce exact source and executable selections; distinguish synthetic callbacks, actual mathematics, native platform evidence, hosted checkout and independent assessment; keep both prior fixed inventories/reports unchanged |

The witness helper is test-only and is not consumed by an application entry
point. A normal unsigned retained description grants no freshness, canonicality,
recovery, lookup or protected-use permission. A coherent source and consumer
restore can repeat a synthetic effect; deleting and recreating a pathname can
forget completed knowledge. Local consistency and signatures do not supply an
external monotonic anchor. Native hot-journal rollback is distinct from
application repair, and cancellation of a witness command does not reconcile an
unknown original source outcome. Passing more cases cannot close these gates.

## Reproduce source identity offline

Select the commit and manifest digest independently of received files, branch
names and archives. Obtain the packaging at an independently selected immutable
revision, record that revision, and assess its delta separately. If source
objects are absent, acquire them in a separate network step:

```sh
git fetch --no-tags --depth=1 origin bd4b4b523fb3453e2af191eb01973985d6431d66 f81e376e96e339647bb065739b4461235f865d2c e592633e4c630cfe3f4669876f6f63b80d2e33d6
```

Then use a checkout containing this packaging with the three manifests and two
prior report templates indexed:

```sh
python3 -B scripts/check_witness_subject.py --expect-commit bd4b4b523fb3453e2af191eb01973985d6431d66 --expect-manifest-sha256 0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f
```

The [checker](../scripts/check_witness_subject.py) requires both independently
selected pins. It reconstructs the complete source and both earlier inventories
from immutable local Git objects. Both prior manifests and both prior reports
must match the fixed source, working tree and index. The new manifest must match
the selected digest, canonical expected bytes and index. Broader working source
and index contents are not asserted to equal the review snapshot.

The reused primitives reject unsafe/nonregular source paths, unavailable blobs,
duplicate keys, missing/extra/duplicate records, metadata/type substitutions and
noncanonical bytes. Git replacement refs and lazy fetching are disabled; ambient
Git overrides and global/system configuration are excluded. The local Git
executable, object store, filesystem and operator selection remain trusted.
Unsupported Git fails without fallback. This is neither a hostile-parser
sandbox, external provenance attestation nor reviewer independence proof.

A complete plain source tar may additionally be checked without extraction:

```sh
mkdir -p .research-cache/review
git --no-lazy-fetch --no-replace-objects archive --format=tar --output=.research-cache/review/witness-source.tar bd4b4b523fb3453e2af191eb01973985d6431d66
python3 -B scripts/check_witness_subject.py --expect-commit bd4b4b523fb3453e2af191eb01973985d6431d66 --expect-manifest-sha256 0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f --archive .research-cache/review/witness-source.tar
```

Limits inherited unchanged from the observation checker are 1 MiB per manifest,
2 MiB per source blob, 16 MiB total source, 16 MiB per plain tar and 4,096 source
files. Archives must contain exactly the selected file bytes and executable
classes. Unsafe paths, special files, links, sparse files, duplicate/extra/missing
members and appended members are rejected. Archive serialization and release
provenance are not attested. These bounds select this snapshot, not an
application storage or resource policy.

Run the packaging controls independently from witness protocol qualification:

```sh
python3 -B -m unittest discover -s tests -p test_witness_review_subject.py -v
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
```

Use the pinned workflow for the public Rust/Go qualification and record exact
toolchain, dependency and executable identities separately. A manifest passes
source identity only; neither local tests nor hosted checks fill the
[witness report](WITNESS_REVIEW_REPORT_TEMPLATE.md). Application progression
requires an independent written assessment, disposition of findings and missing
surfaces, and explicit closure of the unresolved operational gates above.
