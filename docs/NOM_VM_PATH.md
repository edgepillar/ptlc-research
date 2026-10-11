# Composed NoM VM path and receipt guards

Research baseline: `07df9a96e0ac9caf71dfa0ad7d40f001207baaa8`.
Profile: `zenon-pr138-composed-vm-path-v1`. Application/core remain **NO-GO**.

## Source and subject

Execution references the unchanged PR #138 source at
[`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced),
tree `b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. The separately obtained source
is GPL-3.0; these independently written overlays and synthetic selections are
MIT. No implementation is copied. The [manifest](../compatibility/nom_vm_path_manifest.json)
pins 42 source/license files, five selected inputs and 28 preserved research
inputs. Upstream changes require a separate comparison; this is not an assertion
that PR #138 is merged, released or active.

The two complete [funding records](../compatibility/fixtures/nom_created_funding_v1.json)
and existing public toy witnesses remain unchanged. There is no new signer,
arithmetic replacement, private producer or core modification. Each leg runs
independently. The two balance exercises are not a joint atomic-swap proof.

## Executed and selected components

| Component | Evidence boundary |
| --- | --- |
| Account balances, storage, received marker | Actual in-memory account stores |
| Account VM context save/reset/done | Actual source lifecycle |
| Create/Unlock/ProxyUnlock/Reclaim | Actual dispatcher and method execution |
| Funding and generated child send | Actual `applySend`, including balance debit |
| Embedded receive and descendants | Actual `generateEmbeddedReceive` and finalization |
| Recipient credit | Actual `applyReceive` and received marker |
| Recipient frontier adoption | Test helper writes the generated frontier; no supervisor admission |
| Ledger lookup, timestamp, confirmation height | Explicit caller-selected synthetic stubs |
| Spork gate | Explicit stub; no activation evidence |
| Parent/child acknowledged context, recipient from-hash guard | Selected real verifier functions only |
| Signatures, plasma, full verifier/supervisor, canonical inclusion | Not performed |

No node, wallet, network observer, activation, application signing, transaction
broadcast, deployment or real funds are used. The compiler, cache, runtime and
host are trusted. Overlay vet remains unperformed because the synthetic test
paths are unavailable to Go 1.23 vet; actual test compilation is mandatory.

## Controls and emitted evidence

The [corpus](../compatibility/fixtures/nom_vm_path_v1.json) selects 16 VM controls
per leg: direct and both proxy successes; invalid, old and cross-leg witnesses;
wrong caller and proxy destination; exact-expiry unlock followed by reclaim;
early reclaim followed by unlock; two deleted-entry replay paths; failed Create
with refund; insufficient funder balance; rollback after insufficient contract
balance; and intentional raw recipient replay. The contract-balance control
injects a corrupted input state and requires its restoration. It is not an
admitted-state or conservation proof. The raw-replay case intentionally bypasses
admission and credits twice. Ordinary successful paths preserve the selected
initial budget after the final recipient receives the payout.

The VM emits complete 17-field hash inputs, source account hashes, separate patch
hash claims, send/parent/descendant/recipient roles, final balances, entry presence
and exact method errors. Python independently recomputes every emitted account
hash and checks complete role coverage, original funding identity, asset,
recipient, receipt source and ancestry. Long `go test -json` output is bounded
and reassembled by exact test identity; truncated, interleaved, duplicate,
foreign, failed or skipped evidence is refused. Self-consistent test output
still does not authenticate its producer or ledger.

For each direct-success leg, the verifier imports the actual VM pre/post receive
patch dumps in a separate process. Twelve controls per leg compare generated
hashes, parent/child context, confirmation height, missing/unconfirmed payout,
actual received marker, wrong recipient on either side of the source's
enforcement height, and wrong acknowledged hashes. The imported post-receive
marker makes `fromHash` return `ErrABFromBlockAlreadyReceived`. The raw credit
path alone does not supply this guard. The source helper allows a receiver
mismatch before its enforcement height and refuses it at that height; this
selected helper behavior is neither a full admission result nor current network
activation evidence.

The source account hash does not include `ChangesHash`. The separate source
patch-hash claim is not an authenticated state proof. Original command streams
and actual patch handoffs are retained privately locally. Hosted private streams
and patches may be ephemeral; the retained console ZIP contains summary claims,
not their underlying custody. No chain authority or private data is published.

## Qualification and next gates

Run `scripts/qualify_nom_vm_path.py --checkout <clean-pinned-source> --go <selected-go>`
after separately obtaining and checking offline dependencies. It requires all
33 VM and 25 verifier tests, including parents, all 32 source records, unchanged
input/tool bytes and unchanged source. The existing source CI job adds this
comparison without removing any earlier comparison. Python parser tests need no
native binary and provide no positive source-execution evidence.

1. Keep full account admission, plasma/signature checks and supervisor context
   authentication separate from this selected call path. Define the exact
   evidence required for the generated payout and recipient receipt before any
   recovery admission. No test frontier is an authenticated execution frontier.
2. Complete independently assessed source/proof provisioning, acknowledged
   execution context, canonicality/finality and current/restore protection. See
   [authority contract](NOM_AUTHORITY_CONTRACT.md) and [typed evidence openings](NOM_EVIDENCE_OPENINGS.md).
   Matching public bytes and a received marker do not fill these requirements.
3. Compose admitted, retained original evidence with recovery/journal entry only
   after those selections are satisfied. Receipt replay refusal in a separate
   verifier process is not atomic journal entry, duplicate execution prevention
   across restored copies or a live recovery guarantee.

Application/core remain **NO-GO**. Core consensus work stays narrow and
coordinated upstream; observation, recovery and Bitcoin construction remain in
the separate research/client workspace. Independent construction and observation
assessments remain unfilled.
