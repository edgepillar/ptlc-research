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

- Use English and public synthetic values only. Exclude personal identity, private conversations, local absolute paths, hostnames, credentials, wallet material and private environment logs from files, examples and reports.
- Pin external source claims to immutable commits where possible. Check licenses before reusing material and preserve required attribution.
- Keep reference arithmetic and synthetic signing helpers out of application cryptography. Passing tests do not establish that the swap construction is secure.
- Keep Bitcoin transactions, session recovery and chain observation separate from node consensus changes. A core contribution requires current upstream coordination and its own review.
- Changes involving secret signing, nonce ownership, restored copies, authenticated peers or chain integration must state their safety argument and missing review or validation. Offline results do not authorize deployment or real funds.

Use the [reproduction commands](README.md#run-the-offline-checks). Run the offline suite and artifact checks after relevant edits, plus the affected Rust, Go or subprocess integration checks. Report the commands, outcomes, failures and skipped checks without private environment data. Distinguish local results from hosted CI, process termination from power loss, and code review from independent cryptographic review.

For potential vulnerabilities, follow [SECURITY.md](SECURITY.md). Review the exact file set, commit metadata and destination before publication; do not implicitly use an installed Git identity. Artifact scans are a limited check, not proof that a contribution contains no sensitive information.
