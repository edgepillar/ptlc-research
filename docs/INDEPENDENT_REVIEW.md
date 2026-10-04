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
