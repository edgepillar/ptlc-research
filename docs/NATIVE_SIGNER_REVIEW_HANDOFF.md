# Native signer and nonce review subject

Status: **AUTHOR PREPARATION ONLY / NOT INDEPENDENTLY ASSESSED**. This separate
packet includes the later public-synthetic native owner/journal tests. A real
signer, fresh entropy, durable nonce custody and independent nonrollback authority
remain **UNSELECTED**. Application/core progression remains **NO-GO**.

## Independently selected source and complete delta

| Item | Selected value |
| --- | --- |
| Repository | [ptlc-research](https://github.com/edgepillar/ptlc-research) |
| Immutable source | [`bc9e972dbf30bdd6be1d0264a6a518b23ebc1434`](https://github.com/edgepillar/ptlc-research/tree/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434) |
| Source Git tree | `6b922ecec1daf3fc8904ca3bc0ff64c3af780943` |
| Complete source inventory | [508 tracked regular files](../review/native-signer-subject.json), with Git blob, mode, length and SHA256 per path |
| Inventory SHA256 | `0c217d04cc936c2e9b6c55efdeb83964c8337e4052b3748979870f9a7c27e545` |
| Earlier author subject | [`134bf4f33d0152174a4ee06f0cde2bc54d5adff1`](https://github.com/edgepillar/ptlc-research/tree/134bf4f33d0152174a4ee06f0cde2bc54d5adff1); 486 files; tree `1a43d54c57c47fc7ffc393f2c9e9407656556ea0` |
| Complete comparison | 481 unchanged files, 22 additions, five modifications, no deletions; every changed path and before/after fingerprint is in the new inventory |
| Earlier author inventory | [Unchanged 486-file packet](../review/signer-nonce-handoff.json), SHA256 `0d7b0482f4f7717caef58201822f6d97321f2839e03e3a74f0a98cd5fdf38f84` |
| Fixed independent subjects | [Construction](../review/subject.json), [observation](../review/observation-subject.json), [witness](../review/witness-subject.json), [worker profiles](../review/worker-subject.json): unchanged |
| Assessment records | [Construction](REVIEW_REPORT_TEMPLATE.md), [observation](OBSERVATION_REVIEW_REPORT_TEMPLATE.md), [witness](WITNESS_REVIEW_REPORT_TEMPLATE.md): all UNFILLED |

The earlier [author handoff](SIGNER_NONCE_REVIEW_HANDOFF.md) remains an exact
historical subject through Stage 87. It must not be silently relabeled as review
of later native integration. This separate subject includes the accepted source
through Stage 92 and its existing workflow, locks, tests, fixtures and notices.
Stage 93 packaging is outside that immutable tree. Any assessment must identify
the examined source and packaging revisions, exact covered paths and omissions.
Inventory inclusion does not imply examination or transfer any prior approval.

Independently select the expected source commit and manifest digest before
receipt. With a separately trusted tool, compare every inventory row with the
complete selected Git tree, mode and blob bytes; refuse missing objects, omitted,
duplicated or substituted paths, changed lengths, modes or encoding. Independently
reconstruct the complete comparison against the earlier selected tree. Neither a
received manifest nor this document may select its own expected truth. This is
author metadata, without a new trusted executable checker.

Downloaded dependencies, installed tools, compiled artifacts, execution logs,
private inputs, carriers and runtime state are excluded. Git and SHA256 pins
identify selected bytes; they authenticate no producer, distribution origin or
loaded runtime. Original metadata remains under the [root MIT license](../LICENSE);
[existing attribution](../THIRD_PARTY_NOTICES.md) remains exact. This packaging
copies no external implementation or dataset.

## Requirements, selected constructions and measured behavior

All source links below select the immutable commit above. The case totals are
source-defined scopes per complete matrix execution, not summed observations
across repeated local and hosted runs.

| Area | Requirement | Selected test construction and author evidence | Remaining gap |
| --- | --- | --- | --- |
| Durable admission and output | Consumption must precede secret work; unknown outcomes must refuse reuse; recorded output must replay exact bytes | [Stage 89 fixture callback cuts](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/tests/test_partial_journal_boundary.py) cover 44 killed process schedules and eight copied/restored-history subcases | Fixed fixture callbacks perform no native signing and cannot qualify private nonce ownership |
| Native partial/journal integration | Exercise the actual signing boundary and journal together, while separating invocation, computation, delivery, retention and replay | [Stage 90 native tests](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/qualification-native-partial/tests/native_partial_journal.rs) and [Python actor](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/tests/native_partial_journal_actor.py) cover 32 owner/admission attempts in 24 child runs: 28 backend entries, 24 valid public partials, 20 recorded outputs and 12 unknown outcomes after reopen | Synthetic public keys/seeds, deterministic reconstructed owners and trusted test peers supply no real signer, entropy, authenticated grant or durable custody |
| Actual native owner death | Separate owner process death from a surviving journal and possible released output | [Stage 91 native matrix](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/qualification-native-partial/tests/native_owner_sigkill.rs) and [coordinator](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/tests/native_owner_sigkill_actor.py) kill/reap twenty native children at five selected cuts across both roles and legs; twelve partials complete, eight are delivered/recorded, eight consumed admissions reopen unknown and four reserved admissions reopen retired | Coordinator/parent death, machine power loss, interruption inside the primitive, private execution and restored-copy safety are not qualified |
| Nonce removal and backend entry | Keep local consumption distinct from backend computation and physical secret erasure | [Stage 92 instrumented owner](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/qualification-native-partial/tests/native_nonce_boundary.rs) and [coordinator](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/tests/native_nonce_boundary_actor.py) run twelve children: eight acknowledged SIGKILL pauses with zero backend entries, plus four normal paths with both acknowledgements and four exact valid public partials retained/replayed | The removed nonce remains on the live stack; an empty Option proves no erasure or exclusive custody. Both pauses are outside the cryptographic primitive |
| Copies and coherent restore | An independent authority must prevent repeated nonce authorization across copied/restored histories, under explicit outage and compromise assumptions | [Native copy/restore controls](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/qualification-native-partial/tests/native_partial_journal.rs) reconstruct deterministic owners against two simultaneously open copied journals or a restored matching pair; each original owner refuses local reuse while another history repeats the same nonce and partial | No changed-message key-extraction attack or opaque live-owner clone is executed. Local history/refusal and copied-history safety remain separate; independent nonrollback authority is unselected |
| Exact cryptography and protocol | Assess the exact two-party adaptor extension, dependencies, parity/tweak, key order, disclosure material and competing cross-chain spends | [Review obligations](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/docs/INDEPENDENT_REVIEW.md) and [transaction graph](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/docs/TRANSACTION_GRAPH.md) remain unchanged | Ordinary signature verification and finite public vectors are no independent assessment of the swap construction, custody, refund races, reorgs or live observation |
| Provenance and privacy | Authenticate producer, source correspondence, loaded runtime and actual private consumed inputs; assess disclosure independently | [Authority evidence](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/docs/CURRENT_AUTHORITY_EVIDENCE.md) retains the narrower caller pins, public entry and declaration observations | Source-to-worker/reproducibility remain NOT VERIFIED; private inputs, producer and runtime remain NOT AUTHENTICATED; privacy remains NOT ASSESSED |

The Stage 92 ordinary helper separately exercises four inline positive partials
and eight before-backend refusal controls. Those inline controls are not additional
native child launches. Its copied owner still constructs unused counterpart and
expected owners; no exclusive secret custody is inferred. The unchanged root
qualification crate and the separate `publish = false` native test crate share
pinned dependency selections; neither is an application signer API.

The earlier deterministic-context and paired-restore counterexamples remain in
[nonce lifecycle tests](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/qualification/tests/nonce_lifecycle.rs)
and [completion journal tests](https://github.com/edgepillar/ptlc-research/blob/bc9e972dbf30bdd6be1d0264a6a518b23ebc1434/tests/test_completion_journal.py).
The later native copy/restore cases strengthen the measured public-synthetic
counterexample without selecting a remedy. Preserve all of them after any later
entropy, context, journal or custody change. A green crash matrix cannot close
the independent signer or restore gate.

The complete delta also retains the historical Python job timeout increase
from 30 to 45 minutes and the two separate native test/formatting workflow
commands. Stage 93 changes none of those policies, sources, assertions, fixtures
or locks. The construction documents retain their historical failed-run and
layout-correction disclosures; this packet does not erase or reinterpret them.

## Exact-source author qualification

The [accepted main transfer](https://github.com/edgepillar/ptlc-research/pull/88)
and its [main-push run](https://github.com/edgepillar/ptlc-research/actions/runs/37748921812)
record eight successful jobs on attempt one. All eight actually executed the
selected commit/tree directly, separately from earlier pull-request merge
checkouts. Four Python matrices each passed the same 2035 unique methods without
skips or ResourceWarning lines. Rust passed 183 unique tests across two crates
(172 original, eleven separate native); Go passed 55 top-level tests. Linux
worker qualification retained 25 groups/312 cases; a separate native Apple
profile passed two groups/28 cases after two fresh builds. Their distinct runtime
scopes must remain separate.

The main log guard initially refused aggregate-only log framing, then timestamp
parsing under the local interpreter. Both private parser corrections re-inspected
the same original complete archive. No source/test assertion changed, failed
qualification test or hosted retry occurred. The completed main record discloses
those guard errors separately from two read-only status-query errors. This packet
introduces no new main execution claim. Stage 93 has its own
[local validation snapshot](STAGE93_VALIDATION.md) and later exact-head hosted
qualification; packaging does not inherit assessment from the main CI result.

## Review order and explicit decisions

1. Assess the exact two-party adaptor extension and dependency revisions for
   both legs, including adversarial signing/extraction, key order, tweak and parity.
2. Before implementing a real signer, specify fresh entropy, nonce ownership,
   reserve/burn protocol, authenticated admission, uncertain release and recovery.
   The public-synthetic test owner is not a selected private construction.
3. Select and assess independent nonrollback authority with explicit restore,
   copied-owner, availability and compromise assumptions. Preserve the current
   repeated-nonce/partial counterexamples as unmet requirements.
4. For that later selected implementation, qualify the real private owner and
   journal together under the specified failure cuts. Scope surviving coordinator,
   parent death, backend interruption and machine power loss separately.
5. Independently assess producer trust, exact source/packaging, loaded runtime,
   private consumed inputs, distribution and disclosure. A manifest, public event,
   prefix scan or backend equation cannot authenticate these facts.
6. Assess cross-chain material retention before exposure, clocks, observation,
   competing refunds/claims, fees and reorganization. Keep Bitcoin construction,
   session recovery and chain observation outside the narrow core contribution.

An actual assessment must state nonidentifying attribution, independence and
conflicts, examined revisions, covered paths, methods, executed checks, omissions,
findings and conditions. The three reports remain UNFILLED; no reviewer is
contacted or review requested by this packet. No wallet, funds, broadcast, live
chain, deployment, activation, release, merge or core consensus permission follows.
Offline research preparation may continue; application/core progression is NO-GO.
