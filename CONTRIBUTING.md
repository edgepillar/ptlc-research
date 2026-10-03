# Contributing

This is an experimental offline PTLC research workspace. Read the [scope](docs/SCOPE.md), [threat model](docs/THREAT_MODEL.md) and [current validation report](docs/STAGE11_VALIDATION.md) before proposing changes. There is no usable swap client or production signing backend.

Contributions should be focused and reproducible: protocol analysis, adversarial cases, synthetic fixtures, offline qualification, recovery behavior and documentation. Explain the concrete problem, the resulting behavior and the evidence supporting the change. Keep protocol requirements, selected constructions and verified implementation behavior distinct; identify assumptions and unresolved decisions.

- Use English and public synthetic values only. Exclude personal identity, private conversations, local absolute paths, hostnames, credentials, wallet material and private environment logs from files, examples and reports.
- Pin external source claims to immutable commits where possible. Check licenses before reusing material and preserve required attribution.
- Keep reference arithmetic and synthetic signing helpers out of application cryptography. Passing tests do not establish that the swap construction is secure.
- Keep Bitcoin transactions, session recovery and chain observation separate from node consensus changes. A core contribution requires current upstream coordination and its own review.
- Changes involving secret signing, nonce ownership, restored copies, authenticated peers or chain integration must state their safety argument and missing review or validation. Offline results do not authorize deployment or real funds.

Use the [reproduction commands](README.md#run-the-offline-checks). Run the offline suite and artifact checks after relevant edits, plus the affected Rust, Go or subprocess integration checks. Report the commands, outcomes, failures and skipped checks without private environment data. Distinguish local results from hosted CI, process termination from power loss, and code review from independent cryptographic review.

For potential vulnerabilities, follow [SECURITY.md](SECURITY.md). Review the exact file set, commit metadata and destination before publication; do not implicitly use an installed Git identity. Artifact scans are a limited check, not proof that a contribution contains no sensitive information.
