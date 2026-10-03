# Security

This repository contains experimental offline PTLC research and synthetic qualification code. It has no production signing backend, wallet integration or supported live settlement path. Do not use its fixtures, fixed scalars, nonce inputs or reference arithmetic with real funds.

The [threat model](docs/THREAT_MODEL.md) and [Stage 8 validation report](docs/STAGE8_VALIDATION.md) describe the current evidence and known limits. In particular:

- Alice's completion producer returns a public fixture; it does not manage private signing material.
- Restoring both matching journal and checkpoint copies can reenable a synthetic producer. Local consistency checks do not provide clone or rollback protection.
- Authenticated peer transport and observation selection remain unresolved. Explicit local reconciliation requires a positively verified replacement and retains the original candidate; it does not provide peer authentication or prevent repeated-verification denial of service.
- Public verification and adaptation do not establish funding, chain identity, safe timing, transaction acceptance or settlement.
- Public worker pipe output and transfer/exit time are bounded per invocation. The executable and host remain trusted; process-group cleanup is best effort and does not contain arbitrary resource use or escaped descendants.
- A durable allowance bounds only Bob recovery admissions within one owned journal session. It does not authenticate peers or prevent new-session/restore bypass; exhaustion can prevent a later valid recovery.
- Local tests and review are not an independent cryptographic audit or production security guarantee.

## Reporting a concern

Use GitHub private vulnerability reporting through the repository's Security tab **when that feature is enabled**. This document does not claim that private reporting has been configured. If it is unavailable, a public issue may request a private reporting channel without including sensitive details or an exploit that affects live systems.

A useful report identifies the affected commit, expected and observed behavior, and a minimal offline reproduction using synthetic inputs. Include a proposed fix or relevant public source references when available. Do not submit credentials, private keys, seed phrases, wallet files, real signing nonces, personal identifiers, private conversations or unredacted environment logs. Do not test against live funds or third-party systems to demonstrate a finding.
