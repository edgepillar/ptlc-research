# NoM observation claims and selected source conformance

Status: additive **offline research**, not an authenticated chain observer or
account transaction implementation. Application/core remain **NO-GO**. Independent
construction/runtime/authority assessment, signer custody, canonicality, finality
and recovery integration are unfilled. The existing NoM journal is unchanged.

## Pinned and preserved subjects

This subject extends `b64bc44719c602e5f23f5a3eb32317b1b0d3ccce` and references
PR #138 at `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, tree
`b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. Its GPL node implementation is obtained
separately and not copied. Independently written fixtures and overlay tests are
MIT. The manifest pins selected source/license/module files, all fixture/overlay
bytes and seven preserved recovery/wire inputs. Existing terms, completions,
wire corpus, locks and historical review subjects are not revised.

## The selected structural profile

`offline_session.nom_observation` performs no I/O and issues no capability.
`inspect_claim` compares one explicitly supplied term set and view claim against
six advertised records: funding send, funding contract receive, original unlock
send, payout child, unlock contract receive and recipient receive. Each selected
block's hash is recomputed independently; the parent alone does not verify a
child payload. The profile also compares:

- Create-derived entry id, funder, token, positive integer amount, expiry,
  selected BIP340 point key and fixed recipient.
- Canonical Create/Unlock ABI. Aliased originals are refused, never normalized.
- Original send, contract receive and payout/recipient linkage, ordered contract
  child-before-parent heights/hashes and matching acknowledged momentum claims.
- Confirming context rather than a latest wall clock, source success-status
  bytes, receipt-after-payout confirmation claims and explicit missing records.

The profile selects direct `Unlock`, two different user addresses, exactly one
payout, adjacent recipient account blocks and unmined hash inputs. These are
conservative research selections, not universal node admission rules. Other
account activity, ProxyUnlock claim composition, complete signatures/protobuf,
momentum hashing/inclusion, account history and Plasma policy are not implemented.
ProxyUnlock method execution is compared separately below.

Wire parsing is limited to 32 KiB and 16 JSON nesting levels; duplicate keys,
non-finite JSON and non-ASCII wire are refused. Existing ABI byte/descendant bounds
remain research limits. Dict entry points inspect fixed fields, not arbitrary
remote objects. This is neither a network service nor denial-of-service assessment.

Every result retains separate `NOT_PERFORMED`/`UNFILLED` signature, source,
VM, canonicality and finality gates and `recovery_action: NONE`. Matching forged
claims and a self-selected matching fork deliberately return `MATCH`. A selected
view claim does not become authoritative by matching. Missing entries/history
remain `INCOMPLETE`; absence cannot distinguish unlock, reclaim, fork or omission.
Invalid supplied hashes are refused even when other records are missing.

## The witness boundary is intentionally visible

The structural baseline computes a new Create hash, uses it as the entry id and
links all six unsigned records to it. Its witness is the existing public synthetic
long-leg signature, which was prepared for a **different** old entry id.
Structural `MATCH` does not check or validate that witness. The actual source
method comparison rejects it for the created record.

Successful BIP340 witness cases explicitly seed the old fixture entry directly
through the source storage codec. They exercise fixed destinations, caller/proxy
semantics and deletion/payout skeletons; they are not success for a Create-funded
swap. No new signer, account signature, secret input or signing backend is added.
This distinction must remain when later real-original work selects its message
and disclosure construction.

## Three independent source overlays

`scripts/qualify_nom_observation_core.py` adds MIT tests only through a Go overlay
on a clean exact node pin; it changes no existing core file. Three packages run:

| Selected source execution | Cases | Limits |
|---|---:|---|
| PTLC ReceiveBlock methods | 16 | Source account-storage wrapper on disposable memory, explicitly supplied time/chain; no dispatcher, balances or consensus |
| Account verifier helpers | 14 | Explicit ledger/confirmation/receive stubs; no full verifier or account authorization |
| VM finalization and header helper | 4 | Explicit frontier/momentum/patch stubs; no applyBlock, rollback accounting, producer or inclusion |

The method cases compare actual Create entry fields/id, expiry boundaries,
funder-only reclaim, invalid old witness on a created id, seeded valid/invalid
unlock, fixed-recipient ProxyUnlock and entry absence. The verifier cases compare
account hashes, confirming context, child acknowledgements, send confirmations,
recipient linkage, repeated receipt and receive-amount refusal. Source
`fromHash` rejects a mismatched receiver at `ReceiverMismatchEnforcementHeight`
but accepts that mismatch below the boundary in this isolated helper. That
historical helper control is not full admission or a current-network vulnerability.
The research profile always requires the selected recipient.

VM finalization compares independently generated funding and unlock receive
hashes, child-before-parent linkage and eight-byte status values: success `1`,
failure `2`. A copied status field or account header is still only a claim.
Stateful method success and finalization are separate synthetic executions; their
combination does not execute an authenticated funded ledger flow.

The driver requires all 34 selected subtests plus three parents and all three
package passes. A zero exit, incomplete output, missing/duplicate/unselected
result, failure or skip is incomplete evidence. Parser tests use explicit event
claims, not substitute native execution. Core source, selected inputs and Go
executable hashes are compared before/after; dependency content qualification is
separate. The tool, compiler cache, environment and host remain trusted.

Original command/stdout/stderr files and outcome records remain private and
bounded. Hosted private streams are ephemeral and not in console archives; their
durable custody is unqualified. Overlay vet is explicitly unperformed because
the synthetic paths are unavailable to the selected Go 1.23 vet. No runtime
attestation, application isolation or native build reproducibility is claimed.

## Verification and next gates

The fixture contains 48 structural controls: matching claims, missing records,
wrong terms/recipients, malformed child commitments, altered account linkage,
wrong confirming context, fork labels, failed status and expiry/receipt ordering.
Run directed Python tests and the actual-core driver separately; then the complete
offline suites and artifact checks. The new hosted step shares only the already
pinned core acquisition; old job definitions and old source comparisons remain.
Fresh PR and separate published-main CI with original archives are acceptance
gates, recorded in the final integration record.

Before journal admission, select and independently assess an observation authority,
network/genesis/spork profile, canonicality/finality, durable evidence and reorg
policy. Qualify exact signed originals and signing custody separately. Keep
possible disclosure and old evidence across unknown outcomes and reorg; do not
normalize, re-sign, replace or replenish work automatically. Stage 0 authorizes
no deployed contract, wallet operation, node activation, broadcast or funds.
