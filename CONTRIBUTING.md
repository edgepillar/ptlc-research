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
