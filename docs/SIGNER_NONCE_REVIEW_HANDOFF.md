# Immutable signer and nonce review handoff

Status: **AUTHOR PREPARATION ONLY / NOT INDEPENDENTLY ASSESSED**. No signer,
durable nonce-custody or nonrollback authority construction is selected here.
Application and core progression remain **NO-GO**. This packet supplies review
questions and source coordinates; it contains no reviewer findings or outreach.

## Exact source and later packaging

| Item | Selected value |
| --- | --- |
| Repository | [ptlc-research](https://github.com/edgepillar/ptlc-research) |
| Source commit | [`134bf4f33d0152174a4ee06f0cde2bc54d5adff1`](https://github.com/edgepillar/ptlc-research/tree/134bf4f33d0152174a4ee06f0cde2bc54d5adff1) |
| Source Git tree | `1a43d54c57c47fc7ffc393f2c9e9407656556ea0` |
| Complete source inventory | [486 tracked regular files](../review/signer-nonce-handoff.json), with Git blob, mode, length and SHA256 per path |
| Inventory SHA256 | `0d7b0482f4f7717caef58201822f6d97321f2839e03e3a74f0a98cd5fdf38f84` |
| Fixed earlier inventories | [Construction](../review/subject.json), [observation](../review/observation-subject.json), [witness](../review/witness-subject.json), [worker profiles](../review/worker-subject.json): unchanged |
| Independent assessment records | [Construction](REVIEW_REPORT_TEMPLATE.md), [observation](OBSERVATION_REVIEW_REPORT_TEMPLATE.md), [witness](WITNESS_REVIEW_REPORT_TEMPLATE.md): all UNFILLED |

The new inventory covers the complete immutable source, including notices,
dependency locks, fixtures, tests and workflow. Inclusion does not mean that a
file was examined. It does not extend an earlier fixed subject or transfer
approval. This document, the new inventory, validation, appended links and the
Python job timeout change are later packaging, outside the selected source.
An assessment must identify both examined source and packaging revisions.

The inventory is author metadata, not a trusted executable checker. Independently
select its expected commit and digest before receipt; compare its complete rows
with the selected Git tree and blob bytes using a separately trusted tool.
Refuse missing objects, omitted or substituted rows, different modes or altered
encoding. A received manifest must not select its own expected truth. No new
public checker or cryptographic primitive is supplied by this packet.

Downloaded dependencies, installed tools, compiled artifacts, execution logs,
private inputs, carriers and runtime state are excluded. Git and SHA256 pins
identify selected bytes; they authenticate no producer or distribution origin.
Original project metadata remains under the [project license](../LICENSE).
[Existing third-party attribution](../THIRD_PARTY_NOTICES.md) remains intact;
no external implementation or dataset is copied by this packaging.

## Requirements, source facts and evidence limits

Read every source link at the selected immutable commit. A later checkout or
passing test does not implicitly enlarge the inspected construction.

| Review area | Requirement to settle | Existing construction and source fact | Verified boundary and unresolved decision |
| --- | --- | --- | --- |
| Exact adaptor construction | Identify both two-party signing legs, backend revisions, key order, Taproot tweak/parity, messages, adaptor encoding and extraction context; assess adversarial behavior | [Review obligations](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/INDEPENDENT_REVIEW.md) distinguish the selected extension from ordinary signature verification | Local and hosted mathematical regressions cover selected cases. They are no security assessment of the exact extension. Construction/dependency review remains open |
| Freshness and secret ownership | Specify fresh entropy, one-use secret custody and the ownership boundary across cancellation, crash, process copies and restore | [Nonce requirements](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/NONCE_ROUNDS.md) and [test-only Rust owner](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/qualification/tests/nonce_lifecycle.rs#L170-L194) use public synthetic derivation tags | The owner exists in an integration-test file. Deterministic context binding supplies neither fresh entropy nor durable/nonexportable custody. No production signer is selected |
| Signer and journal ordering | Define reserve, burn, uncertain outcome, partial-signature release and recovery as one actual secret-ownership protocol | [Completion journal](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/offline_session/completion.py) and [fixture callback tests](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/tests/test_completion_journal.py) are separate from the Rust owner | Persistence and callback ordering are tested, but the callback does not exercise the actual private signing owner. Their combination is not implemented or qualified |
| Restored copies | Identify independent nonrollback authority and its availability, crash and compromise assumptions; show how copied or coherently restored state cannot authorize another secret use | [Grant/copy model](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/NONCE_GRANT_COPY_MODEL.md) keeps modeled external premises separate | A local anchor alongside a database is not independent current authority. Paired restore can repeat a synthetic producer callback; real signer copy protection remains unproved |
| Entry, producer and runtime | Define the trust anchor for source-to-worker correspondence, private consumed inputs, distribution and complete loaded runtime | [Sealed public entry](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/SEALED_PUBLIC_VERIFIER.md) and [bounded ELF declarations](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/WORKER_ELF_DECLARATIONS.md) retain selected narrower boundaries | Matching a caller pin and observing declared metadata do not authenticate producer, interpreter, dependencies or private signing execution. Source-to-worker, reproducibility and independent privacy remain open |
| Cross-chain disclosure and refund | Specify extraction material retained before disclosure, observation/inclusion assumptions, competing spends, clock margins, fee policy and recovery after possible exposure | [CANDIDATE-01 graph](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/docs/TRANSACTION_GRAPH.md), [Rust transaction tests](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/qualification/tests/bitcoin_transaction.rs), [separate Go verification](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/qualification-bitcoin-go/verifier_test.go) exercise finite synthetic cases | No executable swap client, authenticated live observation, autonomous fee management or funded atomicity is qualified. Bitcoin construction, recovery and observation remain outside the core contribution |

Two explicit counterexamples must survive review and later integration:

1. [`contextual_derivation_is_not_freshness_or_restored_copy_protection`](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/qualification/tests/nonce_lifecycle.rs#L474-L499)
   repeats the public nonce when all synthetic derivation inputs repeat. Changed
   context can change the public output without supplying fresh entropy. After
   the owner check, `sign_once` takes its in-memory nonce before context/backend
   work; that test-only ordering is not durable ownership across restored copies.
2. [`test_restoring_both_alice_copies_can_repeat_production_and_is_not_detected`](https://github.com/edgepillar/ptlc-research/blob/134bf4f33d0152174a4ee06f0cde2bc54d5adff1/tests/test_completion_journal.py#L439-L455)
   restores the database and its anchor together and invokes a synthetic producer
   twice. It returns fixed public fixture bytes; it does not perform real private
   signing, demonstrate secret nonce reuse or establish key extraction.

Do not silently discard either case after introducing another context hash,
local persistence format or a green regression result.

## Qualification evidence available for this source

[Draft PR 82](https://github.com/edgepillar/ptlc-research/pull/82) and
[its completed hosted run](https://github.com/edgepillar/ptlc-research/actions/runs/37698261400)
record author qualification for the selected source. Four hosted Python matrices
passed all 2032 unique methods without skips or ResourceWarning lines; Rust
passed 172 tests and Go passed 55 top-level tests. The Linux worker job retained
25 groups/312 cases, including twenty actual exchange methods and one actual
ELF declaration observation. A separate Apple profile passed two groups/28 cases
after two fresh builds. These native scopes are separate; their totals do not
describe a single same-runtime execution.

One first-attempt Ubuntu/Python 3.13 job reached the 30-minute job limit after
the full suite reported 2032 tests OK. Its downstream checks were skipped and
were not qualified. Seven original successful job histories and one successful
job-only retry form the accepted cohort; it is not eight fresh second-attempt
executions. Complete logs and each immutable executed checkout/tree/ordered
base-head parents were inspected separately from the displayed merge revision.
The new packaging raises only this Python matrix job limit to 45 minutes, while
retaining its commands, action pins and required checks.

Locally, the selected source passed the 2032-method Python suite and twenty
exchange methods. Five Linux sealed schedules explicitly refused the unsupported
Apple host and the ELF observation refused a Mach-O worker; these are refusals,
not skips or local Linux qualification. The [Stage 87 snapshot](STAGE87_VALIDATION.md)
is its earlier pre-publication local record and still states hosted checks pending;
the completed PR body records the later hosted result. Stage 88 packaging gets
its own [validation record](STAGE88_VALIDATION.md) and exact-head hosted checks.

All these results are author regression evidence. No independent assessment,
runtime authentication, private signing or live-chain proof follows.

## Written questions and acceptance order

An independent assessment must state its nonidentifying public attribution,
independence/conflicts, exact examined revisions, method, executed checks,
omitted material, findings and conditions. Leave the three unfilled records
unchanged until an actual assessment supplies these facts. Reviewer contact and
review requests are separate actions; this packet initiates neither.

1. **Construction gate:** can the exact two-party adaptor extension, dependency
   selection, tweak/parity and both signing/extraction contexts be assessed?
   Ordinary BIP340 verification or a generic backend audit cannot fill this gate.
2. **Signer design gate:** what component owns actual secret nonces, supplies
   entropy, commits irreversible consumption and limits release after an unknown
   outcome? Specify the signer/journal boundary and every failure cut before
   selecting an implementation. No construction is chosen in this packet.
3. **Restore gate:** what authority survives coherent local restore and copied
   owners, and under what outage/compromise assumptions? A model premise must
   remain labeled until a concrete independently assessed mechanism supplies it.
4. **Integration gate:** for a later selected implementation, exercise the real
   private owner and journal together under crash, cancellation, uncertain
   release and restart; preserve the existing counterexamples. Public fixture
   callbacks cannot qualify this gate.
5. **Provenance and privacy gate:** assess exact source/packaging, producer trust,
   loaded runtime, private consumed inputs and disclosure limits independently.
   Entry continuity, declared metadata and selected-prefix absence do not fill it.
6. **Protocol gate:** assess adversarial cross-chain disclosure, material
   retention, clocks, refund/claim races, fee limits, reorganization and delayed
   observation/inclusion for the exact candidate. Separate client/chain work from
   a narrow coordinated core proposal.

Research preparation may continue within the offline boundary. Application/core
progression remains **NO-GO** until the applicable independent gates are met.
This packet authorizes no wallet, funds, transaction broadcast, deployment,
activation, release, merge or core consensus change.
