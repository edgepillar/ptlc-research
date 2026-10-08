# Custody entry, continuity and original-output composition

Status: **AUTHOR FINITE MODEL. NO REAL CONSTRUCTION SELECTED.** Every SC01-SC12
requirement remains **OPEN**. Physical custody, effect ownership and reanchoring
are **UNSELECTED / NOT IMPLEMENTED**; application/core remain **NO-GO**.

The [model](../scripts/model_custody_entry.py) composes recipient admission,
durable nonce burn, actual nonce-dependent work, continuity loss and separately
authorized exact-original delivery. It adds a finite experiment after the
[mechanism comparison](CUSTODY_MECHANISM_FEASIBILITY.md), without selecting its
platforms or converting its four physical failure obligations into executed
hardware experiments. All values are public symbols; no keys, entropy,
attestation, encryption, signing or real output bytes exist in this model.

## Requirements, premises and measured behavior

The [requirements](SIGNER_CUSTODY_REQUIREMENTS.md) and
[CUSTODY-01 proposal](CUSTODY_CANDIDATE_01.md) require current authority at actual
entry, spent uncertainty and authorized original-output reconciliation. This
model tests their composition under explicit premises; it neither implements
those premises nor proves that they are physically realizable.

The external world contains the current policy epoch, continuity state, burn,
consumption, spent uncertainty, irreversible work/delivery histories and an
exact retained-original token. A copied worker contains its released image
label and local consumption view. A snapshot/restoration never rewinds the
external world. One approved image can label both workers in the experiment;
that assumed copy transition is no evidence of a vendor memory-export feature.

The reference policy makes current-policy checking, verified nonrewinding
continuity and shared consumption indivisible with the **actual effect**,
covering every usable copy. There is no separately exportable permission or
authorized worker state between the final check and the effect. This is an
**unimplemented environmental premise**, not Python atomicity, a lock, a journal,
an attestation challenge, key-delivery policy or a measured custody boundary.

Original-output retention occurs after an effect. Its token identifies exactly
one prior invocation; it is not a signature, hash or proof of authenticated bytes.
The reference separately checks current policy and continuity on **each delivery
and replay**. Replaying the token never invokes work. This assumed immutable
retention is another boundary for a future assessed construction.

## Five explicit comparisons

| Policy | Actual-work rule | Original-delivery rule | Finite negative control |
| --- | --- | --- | --- |
| `recipient-only` | Initial image admission; copied work can execute without current authority or shared consumption | Exact retained token, without current authority | Repeated nonce work, stale policy, lost continuity and work after spent uncertainty |
| `cached-current` | Current authority at burn, then cached permission; shared nonrewinding consumption and uncertainty are still assumed | Exact retained token, without current authority | Revocation or continuity loss between burn and effect; unauthorized delivery |
| `local-consumption` | Ideal current authority at effect, but consumption belongs to each copied local history | Exact retained token with ideal current authority | Repeated same-nonce work and work after another history became unknown/spent |
| `work-only` | Combined ideal current authority, shared consumption and spent-uncertainty refusal at effect | Exact retained token, without current authority | Delivery after revocation or without verified continuity |
| `continuous-authority` | Combined indivisible effect premise across every usable copy | Exact retained token with current authority on every replay | No finding in the exhausted finite graph, conditional on all premises |

All five enforce the selected finite phase ordering and retain at most one
original. Weak policies are deliberate author controls, not vulnerability
findings about an upstream implementation. In particular, deduplicating retained
results cannot undo already repeated nonce-dependent effects.

## Interruption and authority cuts

- After burn but before entry, policy revocation refuses both ready copies under
  the reference. The burn remains spent; no new nonce or replacement grant exists.
- A worker loss after burn and before any original retention marks the operation
  unknown/spent. The reference refuses copied ready work even when its external
  effect audit happens to contain no computation. That audit fact supplies no
  authorized retry path.
- Loss after an effect but before retention preserves consumed status and the
  work audit. A lost output cannot be retained, recomputed or delivered. A still
  surviving **original** output may be retained/reconciled without new work;
  this is no reconstruction or fresh signing.
- A retained original survives worker loss. Delivery and exact replay still fail
  closed during revocation or unverifiable continuity. Authority recovery can
  enable exact delivery without restoring work permission.
- `lose-continuity` abstracts unavailable or conflicting authority. `reanchor`
  assumes a correctly verified return to the current nonrewinding history; it
  changes only continuity and preserves policy, burns, consumption and originals.
  It cannot reverse revocation, spent uncertainty or an earlier effect. No reset,
  failover protocol or real reanchoring mechanism is implemented.

## Exhaustion and limits

The graph has two workers, one approved image label, one nonce/bound epoch,
one revocation, one ready-worker snapshot/restoration, one continuity loss and
one ideal reanchor. It permits at most two work events, one original token and
two deliveries. Breadth-first search records a shortest trace for each finding.
An early state cap reports **INCOMPLETE**, including when a counterexample was
already found; it never reports conditional completion from a partial search.

The [35 regressions](../tests/test_custody_entry_model.py) replay finding traces,
exercise cuts on both sides of work/retention/delivery, discriminate the removed
premises, check exact symbolic types and reject private CLI arguments without
echoing them. Historical nonce-invocation, post-burn grant-copy and governor
models remain byte exact and have separate subjects. This composition does not
supersede their context-binding, issuance or signature-authority experiments.

Run the combined reference with `python3 -B scripts/model_custody_entry.py
--policy continuous-authority`. Exit 0 means conditional finite completion;
exit 1 means an intentional comparison counterexample; exit 2 means incomplete
search or rejected arguments. The default compares all policies and returns 1.

## Preserved scope and source boundary

The preceding source is `a1c5e23d1f8a0c2bdc246b2c38c9c1448cc1e61d`, tree
`2dd9af6b2a8fd534871211115d754717bf6b037f` (519 files). The mechanism record
SHA256 remains `a598a108a47c36e73a09df6cf1c0afb79f74d957adcc3c5e1b00142728dab715`;
the candidate record remains
`8225498b35e4873c3a433b7126c4cbb144036d4ed4e70764782225c98bb2d2d2`.
This original model copies no upstream implementation or dataset and adds no
dependency, workflow, primitive, journal or private API.

The exact four Alice/Bob Bitcoin/Zenon partial operations, per-party custody and
keys, common adaptor and construction exclusions remain in CUSTODY-01. This
single-operation symbolic model supplies no partial-signature mathematics,
cross-chain refund/liveness guarantee, new complete independent subject or
review. Both historical author packets, four fixed inventories and three
UNFILLED reports stay exact. Source-to-worker/reproducibility remain NOT VERIFIED;
private inputs, producer and runtime remain NOT AUTHENTICATED; privacy remains
NOT ASSESSED. See [validation](STAGE97_VALIDATION.md).
