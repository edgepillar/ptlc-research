# Security

This repository contains experimental offline PTLC research and synthetic qualification code. It has no production signing backend, wallet integration or supported live settlement path. Do not use its fixtures, fixed scalars, nonce inputs or reference arithmetic with real funds.

The [threat model](docs/THREAT_MODEL.md) and [Stage 5 validation report](docs/STAGE5_VALIDATION.md) describe the current evidence and known limits. In particular:

- Alice's completion producer returns a public fixture; it does not manage private signing material.
- Restoring both matching journal and checkpoint copies can reenable a synthetic producer. Local consistency checks do not provide clone or rollback protection.
- Authenticated peer transport, observation selection and invalid-candidate reconciliation are unresolved. An invalid but structurally matched candidate can block Bob's session.
- Public verification and adaptation do not establish funding, chain identity, safe timing, transaction acceptance or settlement.
- Local tests and review are not an independent cryptographic audit or production security guarantee.

## Reporting a concern

Use GitHub private vulnerability reporting through the repository's Security tab **when that feature is enabled**. This document does not claim that private reporting has been configured. If it is unavailable, a public issue may request a private reporting channel without including sensitive details or an exploit that affects live systems.

A useful report identifies the affected commit, expected and observed behavior, and a minimal offline reproduction using synthetic inputs. Include a proposed fix or relevant public source references when available. Do not submit credentials, private keys, seed phrases, wallet files, real signing nonces, personal identifiers, private conversations or unredacted environment logs. Do not test against live funds or third-party systems to demonstrate a finding.
