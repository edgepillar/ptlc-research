# Core integration boundary and acceptance backlog

Status: source-pinned preparation only. No core patch, maintainer message, activation or node execution is part of this record.

The separate qualification repository is the appropriate home for transaction construction, aggregate/adaptor signing, counterparty messages, observation and recovery. The node verifies an ordinary completed signature and enforces the contract state transition. Do not add a Bitcoin client, swap session database, adaptor library or secret-extraction service to the core node to implement this candidate.

## Baseline and ownership

At the 2026-10-03 refresh, [PR #13](https://github.com/zenon-network/go-zenon/pull/13) remained open and Draft at `8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18`, targeting `master`. Its stored base was `58eaa81439a39197dd9080230580fb8b47bcd323`, not the inspected current master tip. The open-PR title search found #13 for PTLC; title matching alone does not establish complete overlap or ownership.

Before a port, refresh target refs and inspect the candidate target-file changes in other active PRs, issues and maintainer discussion. Decide with maintainers whether work updates the existing proposal or follows it in a separate PR. An old draft is neither abandonment evidence nor permission to replace its author's work. This document is a local implementation backlog, not a submitted proposal.

## Narrow contract requirements from CANDIDATE-01

| Requirement | Pinned proposal behavior | Acceptance work for a port |
| --- | --- | --- |
| Signature key | BIP340 `PointLock` is a 32-byte x-only signing key. It is distinct from the adaptor point. | Accept the correctly aggregated Zenon signing key; reject malformed/unsupported input at the documented boundary. Choose Create-time parsing policy explicitly. |
| Message binding | SHA3-256 of the 32-byte entry ID followed by the 20-byte destination. | Preserve exact bytes and test changed entry/destination, malformed signatures and valid aggregate-completed signatures. A client session domain must not be inserted into this consensus message. |
| Funding ID | Create send-block hash identifies the entry. | Verify actual accepted ID and state; do not assume a quoted or pending ID establishes a deposit. |
| Success state transition | Unlock/ProxyUnlock delete the entry and create a transfer to the signed destination. | Assert transfer amount/token/destination and deletion exactly once; rejected calls must leave state and transfers unchanged. |
| Hard expiry | Unlock rejects at equality; Reclaim accepts at or after expiry for the original sender. | Preserve existing equality tests, boundary neighbors and execution-time semantics. Submission before expiry is insufficient. |
| Independent refund | Original sender can reclaim without the recipient's signature or witness. | Verify owner-only authority and correct refund transfer after counterparty abandonment. |
| Proxy submission | Destination is signed independently of the submitting account. | Demonstrate a successful third-party ProxyUnlock and reject destination substitution. |
| Unexpected stored type | The pinned branch does not explicitly reject the final unsupported-type path before deletion. Normal Create rejects unsupported types. | Add fail-closed stored-type handling plus malformed-state tests, without describing normal Create as a demonstrated exploit. |

The [existing expiry and repeat-spend tests](https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/tests/ptlc_test.go) are starting evidence to preserve. They are not missing work and have not been executed by this repository. The [isolated verifier harness](../qualification-go/README.md) checks signatures using the same direct verifier version, not the VM or complete node dependency graph.

## Activation and compatibility are separate work

The inspected [dev registration](https://github.com/zenon-network/go-zenon/blob/44c0baf1106a76407ac4becf204306f499ae28f9/vm/embedded/embedded.go) composes feature variants. A historical patch cannot simply overwrite this structure. A proposed port needs explicit tests for inactive PTLC behavior, activation boundaries and coexistence with other contract changes. Preserve historical processing semantics when receives execute later than their sends; derive the correct authorization context from the current node's rules rather than a client wall clock.

Do not combine a compatibility port with an implicit verifier upgrade or signed-message redesign. The pinned Go verifier accepts only 32-byte messages; the contract supplies that width. If maintainers choose a different verifier, identify changed acceptance behavior and supply adversarial vectors before deployment.

RPC and SDK work must agree on IDs, point types, exact byte lengths, token/amount serialization, expiry and errors. The reference client's query result must still be validated against the selected node/network and observed chain state. A well-typed response is not evidence of correct funding or finality.

## What is ready and what remains

Ready for review: source-pinned contract requirements, public BIP340 completed-signature vectors, synthetic message-binding checks, a candidate funding/refund graph and a bounded adversarial schedule model.

Before runnable integration: complete the selected transaction/crypto qualification, obtain independent assessment of the aggregate-adaptor exchange, implement durable nonce and extraction-material ownership, and execute source-pinned contract tests on the agreed target. The eventual two-party regtest/devnet exercise must cover aborts and recovery as well as completion. No part of this backlog supplies a production activation decision.
