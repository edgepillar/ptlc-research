# Independent review brief

Status: **Preparation only. No independent construction or implementation
assessment has been completed through this package.** No reviewer has been
contacted or assigned by creating it. The target is a written assessment of
CANDIDATE-01 and its offline evidence before private signing or chain work.

## Exact subject

| Item | Value |
| --- | --- |
| Repository | [ptlc-research](https://github.com/edgepillar/ptlc-research) |
| Subject commit | [`e592633e4c630cfe3f4669876f6f63b80d2e33d6`](https://github.com/edgepillar/ptlc-research/tree/e592633e4c630cfe3f4669876f6f63b80d2e33d6) |
| Subject Git tree | `eea8afd941b1edfcbbb361d2429dfb5883887d3f` |
| Inventory | [119 tracked regular files](../review/subject.json) |
| Manifest SHA256 | `df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295` |
| Assessment record | [Unfilled report template](REVIEW_REPORT_TEMPLATE.md) |

The manifest is generated from the subject's Git objects, not a working tree,
index, build directory or dependency cache. It records path, Git mode/blob ID,
size and SHA256 for every tracked regular file, including fixtures, dependency
locks, notices and the CI definition. It excludes untracked runtime data,
compiled executables and downloaded dependency source. Its commit does not
include this Stage 13 packaging, avoiding a circular inventory.

External contract and library source bodies are not bundled or attested by this
manifest. Acquire the immutable references recorded in the evidence inventory
and third-party notices separately, verify their identity, and record any source
or audit material that could not be obtained. Lockfiles do not establish that a
registry archive is byte-identical to an upstream Git checkout.

Hashes identify bytes. They are not signed provenance, a security certificate,
an external trust anchor or evidence against hostile implementation/storage.
Establish the intended subject independently before relying on this inventory.
Changing reviewed implementation or assumptions requires an explicit new
subject and delta assessment; do not silently treat a later branch tip as the
reviewed commit.

[Stage 27's separate observation brief](OBSERVATION_REVIEW.md) now prepares a
distinct complete 189-file subject through Stage 26 and an
[unfilled observation report](OBSERVATION_REVIEW_REPORT_TEMPLATE.md). It preserves
this original 119-file manifest and assessment scope. Neither report is a
completed independent assessment, and unchanged dependencies are not implicitly
reviewed. Read the separate brief for the later ownership/pool/resource targets.

[Stage 28 restore qualification](RESOURCE_STORE_RESTORES.md) adds test-only v4
rewind and copied-history evidence outside both fixed subjects. It implements no
restore/enrollment authority or defense, and neither manifest or unfilled report
is changed. Its execution and exclusions require a separate explicit assessment.

[Stage 29's authority comparison](OBSERVATION_AUTHORITY_MODEL.md) is also outside
both subjects. Its finite conditional results assume canonical enrollment,
non-rollbackable external state and unique dispatch. No real authority, backend,
wire protocol or restore defense is supplied; model assessment and any future
implementation assessment are separate obligations. Neither report is filled.

[Stage 30's candidate authority contract](OBSERVATION_AUTHORITY_CONTRACT.md) is a
later pure codec outside both fixed subjects. Matching scope/request bytes and
declared reply transitions prove no authenticated authority, enrollment, latest
head, durable state or one-use dispatch. Assess its exact delta and reused pure
parsers separately; it changes neither manifest nor unfilled report and does not
connect existing journal/store entry points or a signer.

[Stage 31's canonical enrollment comparison](OBSERVATION_ENROLLMENT_MODEL.md)
also lies outside both subjects. It assumes environmental resource equivalence
and owner facts, then contrasts cached absence with atomic uniqueness and registry
rewind. Charges are abstract reservations; no authenticated mapping, backend,
durability or unique worker entry is implemented. Assess this exact model and
later mechanisms separately; neither manifest nor unfilled report is changed.

[Stage 32's candidate content key and unsigned intent](RETAINED_RESOURCE_INTENT.md)
also lies outside both subjects. Its exact seven-commitment class is an encoding
choice, not source/economic equivalence authority. Independent public-key input
and full-scope/role/purpose binding implement no curve/signature check, owner
role, registry or freshness. Matching unsigned bytes replay. Assess this exact
contract and later verifier/backend deltas separately; neither fixed manifest
nor unfilled report changes.

## Reading and implementation map

Links below locate files in this repository. For the material assessment, read
their versions at the exact subject commit above; the manifest covers that
snapshot. Stage 13 changes documentation and adds inventory, with no execution
or cryptographic changes.

| Review surface | Requirements and limits | Implementation and evidence |
| --- | --- | --- |
| Construction and principal safety | [Protocol](PROTOCOL.md), [graph](TRANSACTION_GRAPH.md), [threat model](THREAT_MODEL.md), [cryptographic candidates](CRYPTOGRAPHY.md) | [Adaptor qualification](../qualification/tests/adaptor_qualification.rs), [schedule model](../scripts/model_swap.py) |
| Bitcoin message, tweak and refund | [CANDIDATE-01](TRANSACTION_GRAPH.md) | [Rust transactions](../qualification/tests/bitcoin_transaction.rs), [separate Go script checks](../qualification-bitcoin-go/verifier_test.go), [public transaction fixture](../qualification/fixtures/bitcoin_transactions.json) |
| Transcript and nonce context | [Session journal](SESSION_JOURNAL.md), [nonce rounds](NONCE_ROUNDS.md) | [Transcript](../offline_session/transcript.py), [ephemeral test owner](../qualification/tests/nonce_lifecycle.rs), [nonce fixture](../qualification/fixtures/nonce_rounds.json) |
| Artifact retention and release | [Artifact exchange](ARTIFACT_EXCHANGE.md) | [Exchange state](../offline_session/exchange.py), [actual public verifier](../qualification/examples/verify_exchange.rs), [verifier cases](../qualification/tests/artifact_verifier.rs) |
| Completion and replacement | [Completion](COMPLETION_LIFECYCLE.md), [reconciliation](OBSERVATION_RECONCILIATION.md), [public candidates](PUBLIC_SIGNATURE_CANDIDATES.md) | [Completion formatting](../offline_session/completion.py), [actual recovery](../qualification/examples/complete_exchange.rs), [recovery cases](../qualification/tests/completion_verifier.rs) |
| Authentication and admission | [Envelope](COMPLETION_AUTHENTICATION.md), [pins](DURABLE_AUTHENTICATION_PINS.md), [allowance](RECOVERY_ADMISSION.md), [bounded model](RECOVERY_ADMISSION_MODEL.md) | [Envelope verifier](../qualification/examples/verify_authentication.rs), [journal](../offline_session/journal.py), [admission model](../scripts/model_recovery_admission.py) |
| Worker and host boundary | [Public workers](PUBLIC_WORKERS.md), [security policy](../SECURITY.md) | [Pipe runner](../offline_session/public_worker.py), [worker regressions](../tests/test_public_worker.py), [crash cases](../tests/test_completion_crash.py) |
| Sources and redistribution | [Evidence inventory](EVIDENCE.md), [third-party notices](../THIRD_PARTY_NOTICES.md) | [Rust lock](../qualification/Cargo.lock), [core-verifier lock](../qualification-go/go.sum), [Bitcoin lock](../qualification-bitcoin-go/go.sum) |

The detailed stage reports retain intermediate findings and evidence limits.
The current subject's [Stage 12 report](STAGE12_VALIDATION.md) is the latest
implementation report; [Stage 13](STAGE13_VALIDATION.md) validates packaging.

[Stage 14 selected trace correspondence](RECOVERY_MODEL_CORRESPONDENCE.md) adds
qualification evidence outside this immutable subject. It leaves the frozen
manifest unchanged and does not extend a pending or completed assessment to
later code without an explicit delta review.

[Stage 15 public reserve experiments](RECOVERY_RESERVE_MODEL.md) also sit outside
this frozen subject. They compare policy assumptions only; their conditional
finite path evidence selects no journal implementation or funded guarantee.
The fixed source inventory remains unchanged, and any review of this later
wrapper requires a separately identified delta.

[Stage 16 exact-observation experiments](PUBLIC_OBSERVATION_MODEL.md) further
separate per-ID authority from inner validity and normal rejection from worker
interruption. This later delta also remains outside the frozen subject; its
ideal-filter comparison implements no observation trust source or funded policy.

[Stage 17's exact evidence codec](OBSERVATION_EVIDENCE_CONTRACT.md) is another
later delta. Its claims remain untrusted without an independently selected and
qualified producer. The frozen source identity and manifest are preserved; this
later code requires separate review before any verdict cache or admission policy
is connected.

[Stage 18's local observation producer](OBSERVATION_VERIFIER.md) further adds a
fixed request domain, explicit normal verdicts and caller-provisioned executable
measurement. Its reuse of earlier pure error paths, local profile, provisioning,
host assumptions and absence of durable evidence/resource policy require their
own delta assessment. The frozen subject and manifest remain unchanged.

[Stage 19's pure record contract](OBSERVATION_RECORDS.md) adds bounded attempt
and claim history with revision replay and explicit conflicts. The selected
format and managed transitions remain outside this subject, and supply no disk
ownership, durable commit, rollback protection or producer authentication. Their
delta review and a future owned-backend assessment must be identified separately.

[Stage 20's separate disk owner](OBSERVATION_STORE.md) adds local process/thread
ownership and SQLite/checkpoint ordering around the unchanged record/producer
surfaces. Its crash recovery, trusted storage/configuration, entry provisioning,
orphan computation and restore boundaries need their own exact delta assessment.
It changes neither the frozen source manifest nor recovery admission, and does
not supply external review, process containment or funded availability evidence.

[Stage 21's guard/lease delta](OBSERVATION_LEASES.md) changed the disk
owner to version 2 and carries two locked descriptions into a selected
cooperative nonforking worker. Parent monitoring, inherited-lock close versus
unlock behavior, exclusive child reaping, guard loss, trusted runtime and old-v1
quarantine need their own exact delta assessment. Arbitrary containment, global
resources and matching-pair rollback remain unresolved. The frozen subject and
unfilled assessment report remain unchanged; these tests are not an external
review.

[Stage 22's shared-admission delta](SHARED_WORKER_ADMISSION.md) now requires a
fixed explicit pool and storage version 3. Review slot acquisition before pending
commit, third-descriptor inheritance and close-only lifetime, configuration/slot
identity, partial initialization quarantine, nonblocking saturation, charged
failure/cancellation and old-v1/v2 rejection separately. Native cross-store and
guard-loss tests qualify physical-pool concurrency; deliberate matching-profile
clone counterexamples exclude trusted enrollment or host-wide control. CPU/memory
and cumulative-rate policy, fairness, hostile-worker containment and restored-copy
defense remain unimplemented. The 119-file subject and unfilled report are unchanged;
this delta's tests do not supply independent assessment or funded availability.

[Stage 23's separate resource delta](WORKER_RESOURCE_LIMITS.md) adds explicit
Linux CPU/address-space caps installed and read back before same-process exec.
Assess inherited-limit preservation, partial-setup refusal, descriptor survival,
privilege/runtime assumptions, CPU signal and mapping probes, unsupported hosts
and unknown-versus-negative partition separately. Store v3 still selects ordinary
admitted work, so resource-policy persistence/continuity and later integration
are not assessed by this experiment. The frozen subject is unchanged. No RSS,
aggregate budget, sandbox, external assessment or funded guarantee follows.

[Stage 24's v4 resource-selection delta](DURABLE_RESOURCE_POLICY.md) separately
binds requested limits in SQLite/checkpoint storage and rejects cross-mode/policy
open before SQLite/recovery. Assess explicit provisioning, canonical versioned
commitments, preflight versus complete-pair validation, charged unknown and
no-fallback routing, synthetic host cases versus native Linux evidence, and all
real v4 storage/recovery crash cuts. Mathematical records, journal and the frozen
subject remain unchanged. Tests and requested-profile consistency provide no
independent assessment, effective-cap attestation or clone defense.

[Stage 25's test-only v4 cut delta](RESOURCE_STORE_CRASH_CUTS.md) adds nineteen
named owner-death cuts, real hot-journal cross-policy/mode refusal and actual
limited-Rust result/recheck death followed by interrupted recovery. Assess
fixture pressure versus default cache behavior, forbidden-connect observability,
charge/normal retention, torn-pair quarantine, no replay and actual-verdict
markers. macOS explicitly simulates only host selection in synthetic-worker
cuts. Runtime, cryptographic sources, journal and frozen review subject remain
unchanged. Power loss, storage faults and external assessment are still separate.

[Stage 26's test-only storage-fault delta](RESOURCE_STORE_FAULTS.md) adds
before/after real operations with synthetic reported failures, secondary
rollback/cleanup errors and poisoned-owner/slot behavior. Assess actual commit
completion versus pre-commit failure, consistent versus divergent pairs, retained
charge and old normal evidence, no replay and exact actual-positive gates. A
separate disposable-writer file limit requires native EFBIG; it does not qualify
native EIO, disk exhaustion or physical sync failure. These later observation,
ownership, pool and resource changes need their own pinned assessment subject;
the original 119-file manifest and source remain unchanged. Preparing or testing
that subject supplies no independent assessment.

## Claims and open obligations

| Bounded evidence at the subject | Obligation still open |
| --- | --- |
| Synthetic adaptor outputs and final signatures are cross-checked through distinct harnesses. | A complete argument for the exact aggregate adaptor construction, including adversarial inputs and selected backend review. |
| Public nonce commitments and an ephemeral Rust owner have local regression coverage. | Fresh entropy, secret lifecycle and durable ownership across private signing, crashes, separate sessions and restored copies. |
| Bob's managed API retains verified extraction material before release. | Authenticated peer order, actual funding/time authorization and caller behavior outside that API. |
| Actual public recovery verifies Zenon completion, checks extraction against the retained point and produces Bitcoin completion. | Trusted public-observation selection, timely inclusion and autonomously executable claim/refund under adversarial scheduling. |
| Candidate formatting is pure; replacement needs positive verification and the retained-input comparison. | Provenance and authorization of observations; role labels or receipt hashes cannot supply them. |
| Optional pins persist locally; exact envelopes can be verified against supplied pins. | Trustworthy enrollment, rotation, freshness and an admission policy that preserves public-witness recovery. |
| Recovery attempts have a durable finite allowance; configured finite models finish or report incompleteness. | Funded availability under exhaustion, withholding, interruption and aggregate resource pressure. |
| Owned journals detect some inconsistent restores and preserve covered process-death ordering. | Paired-restore/clone protection, power-loss durability, hostile-host integrity and the actual journal-to-signer boundary. |

## Questions requiring a written assessment

1. **Exact construction.** Evaluate two-party key aggregation, rogue-key
   defenses, partial verification, adaptor extraction, parity and Taproot tweak
   handling for both legs together. Ordinary BIP327 conformance does not itself
   review an adaptor extension. Record the selected backend, exact reviewed
   dependency revision and evidence for its adaptor-specific assumptions; the
   current backend selection and exact independent audit coverage are pending.
2. **Nonce and key ownership.** Establish per-leg key/nonce separation, fresh
   randomness and one-use secret ownership before releasing any response.
   Determine the required signer/journal transaction boundary and clone defense.
   Public fixture seeds, duplicate full public-nonce checks and the ephemeral
   owner do not implement those properties.
3. **Funding and disclosure order.** Check every CANDIDATE-01 transition,
   including withheld artifacts, substituted funding, late counter-funding and
   public signature disclosure before accepted chain inclusion. Bob must retain
   all usable extraction material before release. Knowledge of the witness is
   irreversible even when an observed spend is rejected, expires or is reorged.
4. **Signed messages versus application labels.** Identify which amounts,
   destinations, funding IDs/outpoints, keys and expiry conditions are bound by
   chain messages, and which session/role labels are only application context.
   A raw signature contains no proof of those local labels or its transmitter.
   Changing a label alone need not invalidate unchanged key/message inputs.
5. **Clocks, refunds and fees.** Assess the graph's separate Bitcoin MTP and
   Zenon timestamp assumptions, earliest/latest expiry bounds and claim/refund
   races. Bitcoin refund eligibility does not expire its claim. The signed
   fixed-fee Bitcoin claim has no qualified autonomous fee-bump path: changing
   its signed output requires a new aggregate signing session; fresh
   counterparty cooperation is not guaranteed, and CPFP is not qualified.
   Explicitly state stalls, censorship, reorg and inclusion-delay assumptions.
6. **Observation authorization and availability.** Keep local authorization,
   envelope authentication, inner validity, source evidence and chain inclusion
   distinct. Alice can publish a valid Zenon completion while withholding an
   auxiliary envelope. Invalid authenticated candidates and interrupted work
   can spend the allowance; a later valid candidate can remain unrecoverable.
   Decide how authorized public recovery and denial-of-service controls can
   coexist before any funded policy is selected.
7. **Storage and trusted components.** Assess comparison-guarded replacement,
   exact replay, exposure ordering, process ownership and worker failure
   boundaries. Restoring matching database/checkpoint copies can reenable the
   synthetic Alice producer, replenish Bob's allowance or erase a later pin
   choice. Receipts are local records. The worker and host remain trusted; pipe
   limits and process-group cleanup are not a sandbox or secret signer isolation.

Each question needs an argument, assumptions and any counterexample, not just
a passing test name. Separate protocol flaws, implementation flaws, explicit
assumptions and missing integration evidence. A finding about an omitted signer
must not be reported as an exploit of implemented private signing.

## Reproduce source identity

Use a clone with the subject object present and the Stage 13 manifest available.
Run from the repository root. This standard-library check compares the complete
Git inventory before checking every blob. It also verifies a local source archive
when one exists, without extracting it.

```sh
python3 -B - <<'PY'
import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

SUBJECT = 'e592633e4c630cfe3f4669876f6f63b80d2e33d6'
TREE = 'eea8afd941b1edfcbbb361d2429dfb5883887d3f'
def git(*args):
    return subprocess.check_output(['git', *args])
def safe_path(path):
    return (isinstance(path, str) and not path.startswith('/')
            and '\\' not in path
            and all(part and part not in ('.', '..') for part in path.split('/'))
            and all(32 <= ord(char) < 127 for char in path))

manifest = json.loads(Path('review/subject.json').read_text(encoding='ascii'))
assert manifest['schema'] == 'ptlc-review-subject-v1'
assert manifest['repository'] == 'https://github.com/edgepillar/ptlc-research'
assert manifest['commit'] == SUBJECT and manifest['tree'] == TREE
assert git('rev-parse', SUBJECT + '^{tree}').decode().strip() == TREE
actual = {}
for record in git('ls-tree', '-r', '-z', SUBJECT).split(b'\0'):
    if not record:
        continue
    metadata, raw_path = record.split(b'\t', 1)
    mode, kind, oid = metadata.decode('ascii').split(' ')
    path = raw_path.decode('ascii')
    assert safe_path(path) and kind == 'blob' and mode in ('100644', '100755')
    assert path not in actual
    actual[path] = (mode, oid)
entries = manifest['files']
assert len(entries) == manifest['file_count'] == len(actual) == 119
paths = [entry['path'] for entry in entries]
assert paths == sorted(actual) and len(set(paths)) == len(paths)
expected = {}
for entry in entries:
    path = entry['path']
    assert safe_path(path)
    assert (entry['mode'], entry['git_blob']) == actual[path]
    payload = git('cat-file', 'blob', entry['git_blob'])
    assert len(payload) == entry['bytes']
    assert hashlib.sha256(payload).hexdigest() == entry['sha256']
    expected[path] = entry
print('Git subject verified: 119 regular files')

archive_path = Path('.research-cache/review-source.tar')
if archive_path.exists():
    seen = set()
    with tarfile.open(archive_path, 'r:') as archive:
        for member in archive.getmembers():
            path = member.name.rstrip('/') if member.isdir() else member.name
            assert safe_path(path)
            if member.isdir():
                assert any(name.startswith(path + '/') for name in expected)
                continue
            assert member.isfile() and path in expected and path not in seen
            entry = expected[path]
            assert member.size == entry['bytes']
            with archive.extractfile(member) as source:
                payload = source.read(entry['bytes'] + 1)
            assert len(payload) == entry['bytes']
            assert hashlib.sha256(payload).hexdigest() == entry['sha256']
            assert bool(member.mode & 0o111) == (entry['mode'] == '100755')
            seen.add(path)
    assert seen == set(expected)
    print('Source archive verified: 119 regular files')
else:
    print('Source archive check skipped: archive not present')
PY
```

To create the optional local archive, run the following first. It contains the
subject's source, licenses and notices, with no downloaded dependency source,
compiled binary or runtime journal. Git archive permissions can differ from
checkout write bits; verification compares Git modes against Git and executable
class against the archive, rather than assuming identical archive permissions.

```sh
mkdir -p .research-cache
git archive --format=tar --output=.research-cache/review-source.tar e592633e4c630cfe3f4669876f6f63b80d2e33d6
```

## Reproduce bounded behavior

Use a separate checkout of the exact subject for execution. Follow the subject's
[offline commands](../README.md#run-the-offline-checks): required OpenSSL Python
discovery, locked Rust tests, both read-only Go modules, all three actual Rust
subprocess integrations and the models at explicitly recorded bounds. Report
each command, toolchain, result and skip separately. Dependency acquisition is
a separate network step; manifests and locks pin it, but are not vendored source
or complete dependency-review evidence.

The subject's [hosted run](https://github.com/edgepillar/ptlc-research/actions/runs/37161466574)
was rechecked as completed with all seven jobs successful for the exact subject.
This CI run covers Python on Ubuntu/macOS with 3.11/3.13, Rust qualification,
two Go modules and actual public subprocess integrations. The Stage 12 local
report records 313 required-mode Python cases and 22 separate actual subprocess
cases. These are regression/conformance results, not an independent assessment.
No node, chain funding, secret signing or broadcast should be introduced to
reproduce this offline evidence.

## Required assessment and progression decision

Complete the report template with exact reviewed revision and manifest digest,
review scope, independence/conflict relationship in non-identifying terms,
assumptions, reproduced checks, unreviewed surfaces and findings. Each finding
needs a trigger, impact, synthetic reproduction or argument, remediation and
status. Record material changes after the subject and their review disposition.
No private identity, contact details or environment logs are needed in the
repository report.

**Current decision: continue offline research; private signing, funded chain
integration and a current-node PTLC port remain no-go.** A scoped independent
assessment is necessary but not sufficient. Material safety findings must be
resolved and assessed; nonce/clone ownership, observation/admission availability,
funding/time authorization and regtest/devnet acceptance gates remain separate.
Any later core contribution needs refreshed upstream coordination. A review
report or green CI does not authorize node activation or real-fund use.

[Stage 33 public enrollment signatures](PUBLIC_ENROLLMENT_SIGNATURES.md) are another
explicit delta outside both fixed subjects. Actual signature checks and exact local
expectation/result binding establish no owner-role assignment, authenticated source,
freshness, allocation or registry idempotency. Assess the new verifier, framing,
reused measurement/transport and actual qualifier separately. Neither manifest nor
unfilled report changes; [validation](STAGE33_VALIDATION.md) distinguishes executed
workers from fake callbacks and records the initial qualifier startup failure.

[Stage 34 independent enrollment checks](INDEPENDENT_ENROLLMENT_SIGNATURES.md)
are a test/documentation delta outside both fixed subjects. Separate Go hash
reconstruction and signature arithmetic qualify unchanged synthetic fixtures,
not hostile-input application parsing or governor/source trust. Valid alternate
keys/sources, replay and reused IDs remain positives. Neither manifest nor
unfilled report changes; assess this delta separately. See
[validation](STAGE34_VALIDATION.md) for local and hosted evidence boundaries.

[Stage 35 local governor profiles](LOCAL_GOVERNOR_PROFILE.md) are a pure helper
and actual-worker qualification delta outside both fixed subjects. Explicit
selected rules and exact matching authenticate no role provenance, current
policy or source. The profile digest is absent from the unchanged signed intent;
malicious/stale selection, broader-cap matches and replay remain positives.
Assess framing, independent selection and composition boundaries separately.
Neither fixed manifest or unfilled report changes; [validation](STAGE35_VALIDATION.md)
separates unit oracles, actual signatures and hosted execution.

[Stage 36 governor authority comparison](GOVERNOR_AUTHORITY_MODEL.md) is a later
finite model outside both fixed subjects. Root/assignment/signature facts, semantic
resource identity and non-rollbackable current evidence are assumptions. Bound
credentials remain replayable after policy/key change or revocation; cached checks
and coherent local anchors add distinct counterexamples. Even the ideal use-time
gate permits repeated packet admission. This selects no provisioning, certificate,
new intent or runtime policy. Neither fixed manifest/report changes; assess this
exact delta separately. See [validation](STAGE36_VALIDATION.md).

[Stage 37 assignment/intent framing](GOVERNOR_ASSIGNMENT_CONTRACT.md) is another
later unsigned codec delta outside this fixed subject. Its complete profile and
issuer binding supply no issued credential, actual signature or current authority.
Old v1 signatures remain separate; stale local expectations still parse. The new
synthetic unsigned vector is not independent cross-language evidence. Assess
this exact construction and any later verifiers/integration separately. The
119-file subject, manifest and unfilled report remain unchanged; see
[validation](STAGE37_VALIDATION.md), including the corrected first affected run.

[Stage 38 public issuer/owner qualification](GOVERNOR_SIGNATURE_QUALIFICATION.md)
is another later delta outside this fixed subject. Actual Rust/Go signature facts
and bounded-worker evidence are no issuer provisioning, current-authority source,
construction review or admission permission. Assess the exact domains, complete
profile binding, expected-input boundary and stale/forged-positive controls
separately. Both fixed manifests and unfilled reports remain unchanged; see
[validation](STAGE38_VALIDATION.md), including the first Go cache setup failure.

[Stage 39 current-authority requirements and read claims](CURRENT_AUTHORITY_EVIDENCE.md)
are a later delta outside this fixed subject. Exact source/query/checkpoint/claim
matching supplies no authenticated current evidence, source provisioning or use
permission. Assess its complete decoded request, source trust model and retained
stale/restore/replay/outage controls separately; then assess the actual source and
protected-use ordering if selected. The 119-file subject, both manifests and
unfilled reports remain unchanged. See [validation](STAGE39_VALIDATION.md).

[Stage 40 source/use ordering](POLICY_SOURCE_USE_MODEL.md) is another later finite
model outside this subject. It compares conditional commit and entry cutoffs with
ideal current policy and durable scoped records. The source-ledger restore
counterexample remains separate from selected schedule counts. Assess its trust,
revocation, unknown-outcome, idempotency and physical-entry boundaries separately;
it supplies no source implementation or worker fence. Both manifests and unfilled
reports remain unchanged. See [validation](STAGE40_VALIDATION.md).

The [Stage 41 isolated SQLite delta](OFFLINE_POLICY_EFFECT_STORE.md) is outside
this fixed baseline. Native writer/process controls qualify local ordering for a
synthetic database row only. Administrator/source authentication, external
lineage, physical entry and recovery remain unimplemented. Preserve actual
restore/copy counterexamples and assess this later construction separately; do
not fill this report from local or hosted regression success. See
[validation](STAGE41_VALIDATION.md).

## Stage 42 isolated root statement

The [source root role candidate](SOURCE_ROOT_ROLE_QUALIFICATION.md) qualifies
complete historical declaration signatures under independently selected bytes.
Five distinct key encodings do not prove independent control; valid old statements
and restored/copy selections still replay. No source service, administrator
authentication, SQLite or physical-use connection is added. See the [Stage 42
validation](STAGE42_VALIDATION.md) for execution evidence and failures.
Both fixed independent assessments remain unfilled; source integration, core port,
private signing and funded execution remain NO-GO.

## Stage 43 isolated administrator commands

The [administrator command candidate](SOURCE_ADMIN_COMMAND_QUALIFICATION.md) permits
only strict cap reduction and profile-preserving revocation under an independently
selected rule. Historical signatures do not read current revisions or apply a
command to any source/store. Replay and coherent restoration still succeed.
See [validation](STAGE43_VALIDATION.md); source integration and production use remain NO-GO.

## Stage 44 isolated source response signatures

The [response signature candidate](SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md)
binds the complete root, checkpoint query, response role and observation claim.
It checks four historical signatures without a current-policy lookup. Old or
coherently restored selections still replay; a new challenge can be signed over
old active state. See [validation](STAGE44_VALIDATION.md). Source integration,
core port and production use remain NO-GO; independent assessments stay unfilled.

## Stage 45 local source read ordering

The [local read delta](LOCAL_SOURCE_READ_ORDERING.md) is outside both fixed source
subjects. It samples complete policy/query bytes and original records under an
owned SQLite transaction, with native read-return and process-death controls.
Restore/copy, unsigned original association, operational authentication and
physical-entry limits remain explicit. Eleven older test-only connections now
close after their transaction context. See [validation](STAGE45_VALIDATION.md);
this is not an independent assessment or closure of either report.

## Stage 46 original-operation read framing

The [separate original-read grammar](ORIGINAL_OPERATION_READ_CONTRACT.md) is
outside both fixed subjects. It binds complete original identity and distinct
policy/record positions; all four observation forms remain unsigned and forgeable.
The four synchronous local-store controls preserve restore/copy and read-age
limits without adding a source or recovery adapter. See
[validation](STAGE46_VALIDATION.md). Neither report is filled or closed, and this
later delta requires its own independent assessment.

## Stage 47 historical original-read response signatures

The [isolated historical response qualification](ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md)
is another later delta outside both fixed subjects. Two signature checks, exact
original binding and cross-language public math do not prove historical profile
provenance, caller lookup authority, current source truth, nonrollback retention
or physical entry. Preserve signed-old-state, self-selected collision, forged
callback and actual local restore/clone controls. Assess this exact construction
and any later source integration separately. Both fixed inventories and unfilled
reports stay unchanged; see [validation](STAGE47_VALIDATION.md).

## Stage 48 owned original-read snapshot

The [historical local snapshot delta](ORIGINAL_READ_SNAPSHOT_QUALIFICATION.md) is
outside both fixed subjects. It reads actual retained original and policy rows
under the existing owned-store transaction discipline and selects a deterministic
full local record commitment. Retained row equality has no authenticated historical
issuance or external nonrollback lineage. Preserve native ordering/death controls
and coherent substitution, restore/copy, outage/lost-return and delayed-use
counterexamples when independently assessing this delta and any later integration.
Neither fixed inventory nor report is changed or closed. See
[execution evidence](STAGE48_VALIDATION.md); operational integration remains NO-GO.

## Stage 49 test-only actual-snapshot signature binding

The [sample-to-message delta](ORIGINAL_READ_SNAPSHOT_SIGNATURE_BINDING.md) is
outside both fixed review subjects. It connects actual synthetic retained rows
to the unchanged public historical message checks through test-only fixtures.
Preserve the six validly signed counterclaims, zero-signature callback forgery,
restored/cloned effect repetition and post-commit delivery/use controls. This
byte-level binding supplies no authenticated source, historical issuance,
nonrollback retention, private lookup permission or operational signer custody.
Assess any later source/recovery integration separately. Fixed inventories and
unfilled reports remain unchanged; see [execution evidence](STAGE49_VALIDATION.md).

## Stage 50 original-read provenance and delivery comparison

The [finite provenance/delivery model](ORIGINAL_READ_PROVENANCE_MODEL.md) is
another delta outside both fixed subjects. Independently assess the provenance
of complete expectations and the actual current-use boundary. Preserve the six
signed counterclaims, callback forgery, delayed revocation, fresh-challenge
restore and unknown-outcome controls. The model's external truth and nonrollback
entry audit are ideal premises without implemented providers. Selected schedule
completion is not full-graph coverage or a security proof. Both inventories and
unfilled reports remain unchanged; see [validation](STAGE50_VALIDATION.md).

## Stage 51 test-only complete retained opening

The [complete synthetic opening](ORIGINAL_SNAPSHOT_OPENING.md) is a separate delta
outside both fixed subjects. Independently assess its event/row consistency,
claim derivation, selected head provenance and disclosure assumptions. Preserve
signed false-state/collision controls, temporal cap reduction, old historical
profiles, post-revocation replay and coherent restore/truncation controls.
Complete synthetic disclosure does not select an application privacy protocol;
current-head authority and nonrollback retention remain external gates. Both
fixed inventories and unfilled reports remain unchanged; see
[validation](STAGE51_VALIDATION.md).

## Stage 52 test-only retained-prefix comparison

The [two-opening experiment](ORIGINAL_SNAPSHOT_PREFIX.md) is another separate
delta outside both fixed subjects. Independently assess complete event/policy
prefixes, immutable original/charge/effect bindings, selection provenance and
consumer-witness retention. Preserve coherent truncation, nonqueried-row
rewrites, competing futures, stale extensions and source/consumer restore
counterexamples. Full synthetic disclosure does not select a private lookup
protocol, and root/incarnation transitions remain out of scope. Both inventories
and unfilled reports stay unchanged; see [validation](STAGE52_VALIDATION.md).

## Stage 53 test-only signed retained histories

The [response/prefix composition](ORIGINAL_SNAPSHOT_PREFIX_RESPONSE.md) is a
separate delta outside both fixed subjects. Independently assess derived complete
expectations, both-packet preflight, selected worker/callback premises, fork and
stale-history controls, disclosure and nonrollback consumer knowledge. Preserve
the actual signed competing-future and source/consumer restore counterexamples.
Framing callback controls are not signature mathematics, and actual mathematics
does not select a current authoritative future. Both inventories and unfilled
reports stay unchanged; see [validation](STAGE53_VALIDATION.md).

## Stage 54 bounded consumer retention

The [consumer model](ORIGINAL_CONSUMER_RETENTION_MODEL.md) is a separate delta
outside both fixed subjects. Assess the 81 opening-pair abstraction, independent
query/claim binding, finite stream coverage, cap-incomplete results, separate
consumer knowledge, copied-state restore and ideal external witness premises.
Preserve competing-future and repeated synthetic-effect counterexamples. A
complete bounded comparison or valid historical signature does not establish
canonical/current authority, durable witness ownership or protected entry.
Both inventories and unfilled reports stay unchanged; see
[validation](STAGE54_VALIDATION.md).

## Stage 55 witness transaction experiment

The [test-only owned witness experiment](ORIGINAL_WITNESS_STORE_EXPERIMENT.md)
and [validation](STAGE55_VALIDATION.md) are outside both fixed review subjects.
Both report templates remain unfilled. Transaction serialization, historical
mathematics and process-death tests are engineering evidence only; independent
security/privacy assessment and nonrollback/canonical ownership gates remain
open before application integration.

## Witness creation and interruption experiment

The [test-only lifecycle experiment](ORIGINAL_WITNESS_LIFECYCLE_EXPERIMENT.md)
and [Stage 56 validation](STAGE56_VALIDATION.md) are outside both fixed subjects.
The constructor delta and native inherited-connection premise need review;
selected process-death and mathematical controls are engineering evidence.
Both report templates remain unfilled. Source provenance, canonical selection,
nonrollback ownership and independent security/privacy assessment remain open.
