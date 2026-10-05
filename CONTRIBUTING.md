# Contributing

This is an experimental offline PTLC research workspace. Read the [scope](docs/SCOPE.md), [threat model](docs/THREAT_MODEL.md), [implementation validation](docs/STAGE12_VALIDATION.md), [packaging validation](docs/STAGE13_VALIDATION.md), [correspondence validation](docs/STAGE14_VALIDATION.md), [reserve-model validation](docs/STAGE15_VALIDATION.md), [observation-model validation](docs/STAGE16_VALIDATION.md), [evidence-contract validation](docs/STAGE17_VALIDATION.md), [local-verifier validation](docs/STAGE18_VALIDATION.md), [record-contract validation](docs/STAGE19_VALIDATION.md), [disk-owner validation](docs/STAGE20_VALIDATION.md), [worker-lease validation](docs/STAGE21_VALIDATION.md), [shared-admission validation](docs/STAGE22_VALIDATION.md), [resource validation](docs/STAGE23_VALIDATION.md), [resource-continuity validation](docs/STAGE24_VALIDATION.md), [v4 crash-cut validation](docs/STAGE25_VALIDATION.md) and [storage-fault validation](docs/STAGE26_VALIDATION.md) before proposing changes. There is no usable swap client or production signing backend.

Contributions should be focused and reproducible: protocol analysis, adversarial cases, synthetic fixtures, offline qualification, recovery behavior and documentation. Explain the concrete problem, the resulting behavior and the evidence supporting the change. Keep protocol requirements, selected constructions and verified implementation behavior distinct; identify assumptions and unresolved decisions.

For an independent assessment, use the [exact subject and obligations](docs/INDEPENDENT_REVIEW.md) and [unfilled report template](docs/REVIEW_REPORT_TEMPLATE.md). Identify the reviewed revision, assumptions, findings and excluded surfaces. The package is preparation, not a completed assessment; later changes require an explicit delta review.

Stage 27 also prepares a [separate observation subject](docs/OBSERVATION_REVIEW.md),
[unfilled report](docs/OBSERVATION_REVIEW_REPORT_TEMPLATE.md) and
[packaging validation](docs/STAGE27_VALIDATION.md). Its 189-file inventory preserves
the original 119-file subject. Establish the intended pin independently, acquire
the required exact objects separately, and run the offline inventory checker
alongside discovery. Neither subject's assessment is completed by its packaging.

Stage 28 adds [v4 restore counterexamples](docs/RESOURCE_STORE_RESTORES.md) and
[separate validation](docs/STAGE28_VALIDATION.md). These later tests and actual
qualifier methods lie outside both fixed subjects, leave application behavior
unchanged and implement no restore or freshness authority. Identify their exact
qualification revision separately before using them in an assessment.

Stage 29 adds a [finite authority comparison](docs/OBSERVATION_AUTHORITY_MODEL.md)
and [separate validation](docs/STAGE29_VALIDATION.md). Keep trusted external
state, canonical enrollment and unique dispatch as explicit model premises;
none is an implemented service or restore defense. Assess this later delta
separately and do not extend either fixed manifest or unfilled report.

Stage 30 adds a [candidate authority message contract](docs/OBSERVATION_AUTHORITY_CONTRACT.md)
and [separate validation](docs/STAGE30_VALIDATION.md). Scope/request matching and
declared reply transitions are pure byte checks; matching replies remain forgeable
and replayable. Preserve external enrollment/head provenance, target-set ownership,
idempotency and durable unique dispatch as missing mechanisms. Run the affected
contract suite and full offline/artifact checks; assess this delta separately
without changing either fixed subject or connecting existing entry points.

Stage 31 adds a [canonical enrollment comparison](docs/OBSERVATION_ENROLLMENT_MODEL.md)
and [separate validation](docs/STAGE31_VALIDATION.md). Resource equivalence and
owner authorization are environmental facts; cached absence is not atomic
uniqueness, and a coherent registry restore can replenish quota. Keep abstract
charges separate from worker entry, credential verification and durability.
Assess this exact model delta without changing either fixed subject or using
the model as application admission.

Stage 32 adds a [candidate retained-resource and unsigned intent contract](docs/RETAINED_RESOURCE_INTENT.md)
and [separate validation](docs/STAGE32_VALIDATION.md). Seven-commitment equality
is one selected content class, not authenticated economic/source equivalence.
An independent public-key selection and message digest supply no owner role,
signature check, freshness, allocation or idempotency. Matching unsigned bytes
replay. Assess the exact class/framing and every later verifier/backend separately;
preserve both fixed subjects and existing entry-point boundaries.

- Use English and public synthetic values only. Exclude personal identity, private conversations, local absolute paths, hostnames, credentials, wallet material and private environment logs from files, examples and reports.
- Pin external source claims to immutable commits where possible. Check licenses before reusing material and preserve required attribution.
- Keep reference arithmetic and synthetic signing helpers out of application cryptography. Passing tests do not establish that the swap construction is secure.
- Keep Bitcoin transactions, session recovery and chain observation separate from node consensus changes. A core contribution requires current upstream coordination and its own review.
- Changes involving secret signing, nonce ownership, restored copies, authenticated peers or chain integration must state their safety argument and missing review or validation. Offline results do not authorize deployment or real funds.

Use the [reproduction commands](README.md#run-the-offline-checks). Run the offline suite and artifact checks after relevant edits, plus the affected Rust, Go or subprocess integration checks. Report the commands, outcomes, failures and skipped checks without private environment data. Distinguish local results from hosted CI, process termination from power loss, and code review from independent cryptographic review.

For potential vulnerabilities, follow [SECURITY.md](SECURITY.md). Review the exact file set, commit metadata and destination before publication; do not implicitly use an installed Git identity. Artifact scans are a limited check, not proof that a contribution contains no sensitive information.

Stage 33 adds a [separate public enrollment signature layer](docs/PUBLIC_ENROLLMENT_SIGNATURES.md)
and [validation](docs/STAGE33_VALIDATION.md). Preserve the unchanged Stage 32
message and independent expected inputs; signature validity is no governor role,
source trust or permission. Real worker evidence, fake callback sequencing and
hosted execution must remain separate. This delta lies outside both fixed review
subjects; neither unfilled assessment or existing runtime entry point changes.

Stage 34 adds [independent Go enrollment checks](docs/INDEPENDENT_ENROLLMENT_SIGNATURES.md)
and [validation](docs/STAGE34_VALIDATION.md) over unchanged public fixtures. Keep
raw signature mathematics, exact application framing and governor/source policy
separate. Cross-verifier agreement is not an independent security assessment,
registry or production dependency selection. Both fixed subjects/reports and all
application behavior remain unchanged; assess the test/documentation delta.

Stage 35 adds an [explicit local governor profile](docs/LOCAL_GOVERNOR_PROFILE.md)
and [validation](docs/STAGE35_VALIDATION.md). Select local rules independently of
peer data; matching is no role assignment, policy certificate, fresh allowance
or signature check. Preserve positive malicious/stale selection and broader-cap
controls: the profile digest is not committed by the unchanged signed intent.
Keep fixture-derived rule helpers confined to synthetic qualification. Run both
the affected unit suite and separate actual-worker qualifier, then required full
offline/artifact checks; distinguish real math from fake callback sequencing.
Assess this delta outside both unchanged fixed subjects and unfilled reports.

Stage 36 adds a [finite governor authority comparison](docs/GOVERNOR_AUTHORITY_MODEL.md)
and [validation](docs/STAGE36_VALIDATION.md). Keep root trust, complete assignment,
signature validity and non-rollbackable current evidence as independent premises.
The stronger profile binding is hypothetical; do not modify the existing v1
intent or promote a model decision into runtime admission. Replay witnesses at
their recorded use instant and preserve cached-current/restore counterexamples
and repeated-packet boundaries. A capped search is incomplete. Run the affected
model and seven complete CLI searches, then full offline/artifact checks. Neither
fixed subject or unfilled report changes; assess this later delta separately.

For [Stage 37 assignment/intent changes](docs/GOVERNOR_ASSIGNMENT_CONTRACT.md),
keep five-field issuer and nine-field owner framing unsigned until the exact
construction and independent public verifiers are qualified. Bind every embedded
profile field, including caps, without equating an opaque pin with its own hash.
Preserve v1 schemas and fixtures; never reinterpret their signatures as v2.
Keep issuer provisioning, current-state evidence, atomic use and registry lineage
separate. Report the first fixture-selection failure and corrected run in
[validation](docs/STAGE37_VALIDATION.md); keep independent assessments unfilled.

For [Stage 38 public signature work](docs/GOVERNOR_SIGNATURE_QUALIFICATION.md),
preserve both exact message domains and complete independent expectations. Check
issuer assignment and owner v2 signatures separately; bind every request field,
including both signature variants, to the four-field result. Keep math, trusted
issuer provisioning, decoded scope compliance and current use-time authority
distinct. Signing stays test-only in qualification, using synthetic public tags;
no private signer or admission integration belongs in this delta. Run the offline
suite, locked Rust/Go checks and actual-worker qualifier; retain setup failures
and stale/forged-positive controls in [validation](docs/STAGE38_VALIDATION.md).

For [Stage 39 current-authority framing](docs/CURRENT_AUTHORITY_EVIDENCE.md),
preserve independent source/root/incarnation and checkpoint selection and full
decoded scope/cap matching. A parsed read is a forgeable claim, even with a new
challenge and valid credential signatures. Preserve stale, coherent-restore,
replay, outage and exhausted-journal controls. Select and independently assess
the actual source authentication, current-read semantics, protected-use instant
and atomic lineage/dispatch mechanism before introducing an adapter or runtime
gate. Run the affected suite and full offline/artifact checks; unchanged crypto
and actual-worker checks remain separate evidence. Keep both fixed manifests
and reports unchanged and assess this later delta separately. See
[validation](docs/STAGE39_VALIDATION.md).

For [Stage 40 source/use comparison](docs/POLICY_SOURCE_USE_MODEL.md), keep current
policy, durable scoped operation records and abstract entry as ideal premises.
Compare commit and entry cutoffs without selecting a production revocation rule.
Preserve lost-reply/original-operation reconciliation, source outage, cap lineage,
client restore and unsafe source-ledger restore controls. Selected shuffle counts
exclude those directed fault cases and the full action graph. Run the affected
suite, eight CLI comparisons and full offline/artifact checks. The new CI step
belongs in the existing Python jobs; keep pinned actions and other suites intact.
Neither fixed subject/report changes; assess this later delta independently. See
[validation](docs/STAGE40_VALIDATION.md).

For [Stage 41 isolated SQLite work](docs/OFFLINE_POLICY_EFFECT_STORE.md), retain
the complete original request, charges and selected synthetic-effect cutoff.
Run both ordinary and native affected controls, the safe runtime probe and the
full offline/artifact checks. Keep actual POSIX process death distinct from
synthetic exceptions and OS/power failure. Preserve coherent restore/copy and
different-ID/same-proposal counterexamples. Do not connect this local helper to
existing admission or describe synthetic row commit as physical worker entry.
Authentication, external lineage and recovery require separate construction and
independent assessment. See [validation](docs/STAGE41_VALIDATION.md).

## Stage 42 isolated root statement

The [source root role candidate](docs/SOURCE_ROOT_ROLE_QUALIFICATION.md) qualifies
complete historical declaration signatures under independently selected bytes.
Five distinct key encodings do not prove independent control; valid old statements
and restored/copy selections still replay. No source service, administrator
authentication, SQLite or physical-use connection is added. See the [Stage 42
validation](docs/STAGE42_VALIDATION.md) for execution evidence and failures.
Both fixed independent assessments remain unfilled; source integration, core port,
private signing and funded execution remain NO-GO.

## Stage 43 isolated administrator commands

The [administrator command candidate](docs/SOURCE_ADMIN_COMMAND_QUALIFICATION.md) permits
only strict cap reduction and profile-preserving revocation under an independently
selected rule. Historical signatures do not read current revisions or apply a
command to any source/store. Replay and coherent restoration still succeed.
See [validation](docs/STAGE43_VALIDATION.md); source integration and production use remain NO-GO.
