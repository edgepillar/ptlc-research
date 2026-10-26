# Current-source comparison at 5a2593

Status: the twenty-one-profile combined comparison has complete local native
evidence and accepted original hosted evidence at research commit
[`86f471f33b89069fffec404798e565b41a467681`](https://github.com/edgepillar/ptlc-research/commit/86f471f33b89069fffec404798e565b41a467681).
The separate [main push run](https://github.com/edgepillar/ptlc-research/actions/runs/40217785860)
completed successfully. This finite comparison covers 556 reference outcomes
and 25 actual Go commands; it does not qualify a later upstream source.
Application and core remain **NO-GO**; recovery admission remains unfilled.

The [ac16bfd selection](NOM_DEV_AC16BFD.md) retains this historical corpus and
adds separate runtime obligations. The comparison design and required evidence
below describe this pinned 5a2593 subject, not current-source authority.

The immutable input is go-zenon
[`5a2593ab0d5d56ab15ad7ae7a910323a1565969f`](https://github.com/zenon-network/go-zenon/tree/5a2593ab0d5d56ab15ad7ae7a910323a1565969f),
Git tree `43c8eeaee196a9206da7669b0250a000fba9b776`.
The [inventory](../compatibility/nom_dev_5a2593_source_v1.json) binds all
500 files by byte count, SHA-256, Git blob and logical mode. Its SHA-256 is
`c0ee6bd48163848ab77cb46eddb4f8691c6aa23e1af81863a46f237172559c51`.

Against the earlier [5cb selection](NOM_DEV_5CB.md), 18 files are added,
28 change and 454 remain identical. No file is removed. `LICENSE`, `go.mod`
and `go.sum` remain identical. The upstream GPL version 3 source stays a
separately acquired input; no node implementation is vendored or relicensed.
Every historical source inventory, producer and recovery-journal pin is retained.

The target includes [reclaim locks](https://github.com/zenon-network/go-zenon/pull/216)
and the subsequently merged
[cache lifecycle change](https://github.com/zenon-network/go-zenon/pull/217),
[transport shutdown change](https://github.com/zenon-network/go-zenon/pull/214)
and [liquidity regression tests](https://github.com/zenon-network/go-zenon/pull/218).
All PTLC file blob identities equal the reviewed
`b436efe5fe9a3663851b15ea44cbcf2235f5bf73` milestone. These are source facts,
not execution, activation or deployment evidence.

## Source boundary

`qualification.nom_dev_5a2593_source.inputs()` checks the complete inventory,
Git tree, declared delta and unchanged dependency/license inputs.
`compare_upstream()` checks a bare physical upstream tree, refusing changed,
missing or extra contents, unexpected directories and aliases. It launches
no program and establishes neither producer identity nor compiler execution.
Its bare-tree check is separate from installing project test producers.

All four legacy source-label descendants have explicit byte inverses to their
historical producers. The keyless descendant changes its input core guard to
the same immutable commit selected by the input fixture; its result already
projects that guarded input field. The historical producer and original signed
fixture bytes remain unchanged. A source-consistency regression checks this
binding separately from manufactured output-reader controls. Complete native
execution is still required; label consistency supplies no admission authority.

## Required comparison work

1. Select explicit descendants of the historical 20 producers. Retain each
   original and prove any source-specific producer edit by an exact inverse.
   Compare the historical 479 outcomes without silently replacing expectations
   with newly observed output. Record any changed semantics separately.
2. Add independently calculated reclaim-message/ABI expectations and actual-core
   controls for admission, expiry, ownership, signature refusal, entry/lock
   storage and cleanup, and the selected VM failure/rollback path. A scalar
   unlock witness is not a reclaim signature. Existing upstream vectors and
   serial race-order tests must be identified before proposing missing tests.
3. Build and run the selected producers in one owned source/compiler workspace.
   The unchanged 20-producer baseline would have 500+20 files; additional
   reclaim producers require an explicit new inventory and outcome count.
   Preserve complete original streams, actual exits and failures. A parser
   control or an old 5cb execution cannot satisfy this target.
4. Recheck observer requirements for dropped subscription events, missing
   rollback notifications, cache-stop uncertainty and coherent entry/lock
   snapshots. Transport shutdown joins do not prove a universal bounded stop,
   RPC draining, canonical inclusion or transaction cancellation.

## Additive reclaim candidate

The [selection](../compatibility/nom_dev_5a2593_reclaim_manifest.json) adds one
independently written MIT probe to the twenty selected legacy producers. The
combined source view has 500 upstream files and 21 project producers. The new
probe depends on the selected MIT VM-path probe's explicit memory ledger and
spork adapters; it cannot be installed as an unqualified standalone overlay.
Historical inventories, fixtures, manifests and readers remain unchanged.

The [public input](../compatibility/fixtures/nom_dev_5a2593_reclaim_inputs_v1.json)
declares 76 cases: 18 message projections, 18 send-validation cases and 40
selected VM paths. The separate
[expectations](../compatibility/fixtures/nom_dev_5a2593_reclaim_values_v1.json)
are calculated with Python SHA3-256, explicit ABI words and the existing public
account-block hash codec. They are not captured Go output. The Go probe receives
only the input selection, not the expectation file.

Message cases cover all three claim point types with both reclaim signature
types, field widths, extreme unsigned chain identifiers and amounts, domain
separation and intentional entry-id independence. Send cases cover both new
selectors, offsets and trailing-data normalization, malformed input, unsupported
reclaim types, invalid destinations and amount/signature-width refusals. These
include encoding-only terms that are not admissible entries.

The VM candidate calls the unchanged funding send, embedded dispatch and
`generateEmbeddedReceive` paths over explicit memory accounts. It declares
creation and cleanup for both reclaim types and all three claim types, expiry,
caller/key/domain/term refusals, the absence of an unsigned fallback, and a
same-terms second entry under the same reclaim key. The latter is documented
node behavior, not permission to reuse a reclaim key in a swap.

The two selected payout-failure modes deliberately lower the synthetic contract
balance by one unit. The method can then consume the entry and reclaim lock,
while the downstream payout cannot be applied. The expectation requires the
VM rollback to restore both exact storage values and the prior contract balance,
with a failure receive and no payout. These declarations require actual native
execution before they establish selected implementation behavior.

The probe creates signatures only from intentionally known public test seeds
and small synthetic scalars. Scalar unlocks and unsigned legacy reclaims report
no signed message. These are not application keys, entropy, adaptor-signature
construction or independent cryptographic assessment. The records do not supply
complete signed-account custody, outer admission, real sequencer scheduling,
chain insertion, recipient credit, canonicality, finality, a durable journal or
a recovery action. An absent entry, successful inner signature or self-consistent
receive hash supplies none of that authority.

`qualification.nom_dev_5a2593_reclaim` retains the existing strict event framing
in a private namespace and separately counts all 77 parent/subtest outcomes.
Its source checker requires the complete 521-file combined view. Manufactured
parser controls cannot authenticate execution origin, an actual exit or stream
capture. Full regression, the combined native attempt and original hosted
acceptance remain separate pending gates.

## Joint reproduction and retention candidate

The [joint selection](../compatibility/nom_dev_5a2593_manifest.json) retains the
twenty historical command recipes and adds the reclaim command last. Its
[reader](../qualification/nom_dev_5a2593.py) requires all 42 original profile
streams and separately compares the legacy 479 and reclaim 77 outcomes. Partial
profile sets cannot satisfy the joint scope. The new producer receives only its
public input file. Its independently calculated value file is never passed to Go.

The source preparer, native runner, bounded command capture and explicit
retention checker have separate current-source descendants in `scripts/`.
The selection records each frozen historical program, complete allowed edits
and the exact inverse to its original bytes. Only source selection, schema
labels and additive profile counts change. Historical programs, report schemas,
source inventories and native results remain intact and keep their old scope.

The candidate prepares 500 upstream files plus 21 project probes once. It uses
one new compiler cache and module workspace for a cold compile, 21 selected
commands, the upstream definition tests and module verification: 25 commands in
total. Default vet and `-count=1` remain enabled. There is no automatic native
retry or reuse of historical test results as current-source execution.

Retention compares the exact current arguments and all original stream hashes.
Private argument receipts, caches and generated handoff paths stay outside the
explicit public file selection. Failed or incomplete attempts require separate
retention and cannot fill a completed comparison. Synthetic Python command
controls test transport and failure records only; they establish no Go execution,
compiler provenance, chain acceptance or hosted CI result.

Reclaim locks remain a separate optional construction. Their terms-bound
message and disclosure consequences require review before selection for a
swap; they do not automatically change the fixed-recipient NoM reference
protocol. Source equality, passing regressions and public synthetic signatures
cannot fill independent construction, authority, finality, signing-custody or
restore-protection requirements.
