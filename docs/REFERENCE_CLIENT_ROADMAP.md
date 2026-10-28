# Reference-client delivery roadmap

Status: **offline development plan; no application/core approval**.
This roadmap advances a small NoM reference client while preserving existing
qualification and failure evidence. It selects no production signer, live
observer, operational anchor service, node activation or funds.

The [status record](../STATUS.md) identifies accepted source-bound evidence.
The [protocol candidate](NOM_REFERENCE_CLIENT_PROTOCOL.md) separates protocol
requirements, proposed decisions and the initial executable offline slice.

## Delivery rules

- Every change names the milestone acceptance condition it advances or the
  concrete defect it fixes, its evidence and its bounded verification scope.
- Stop a work item when its declared acceptance condition is met. Unrelated
  qualification belongs to another scoped item.
- Keep requirements, selected constructions, local results, hosted acceptance and
  independent assessment distinct. A completed local item is useful progress
  without being an operational release gate.
- Retain exact source pins, original bytes, failures and UNKNOWN outcomes. New
  source or code is not qualified by an older run with a matching label.
- Preserve English-only public content, privacy, commit attribution and the
  existing identity guards. Keep Bitcoin/session/observation work outside core.
- Real signing, node execution, spork activation, wallet use, broadcast and funds
  require a separately scoped authorization and the relevant acceptance gates.

## M0: delivery entry point and scope

Deliver a concise README, one status record and this roadmap. Preserve the full
earlier reading index and all code, tests, inventories and reports. Resolve the
competing Stage status summaries through a current entry point; historical
records keep their explicit subjects and dates.

Acceptance:

- Readers can identify the target, active milestone, accepted baseline and open
  operational boundaries without following the complete Stage history.
- Every retained historical subject remains identifiable and its existing links
  work. A source-preservation comparison proves the full old README is retained.
- Documentation passes link and artifact/privacy checks. Relevant executable
  changes have separately recorded test scope and results.

No branch cleanup, test removal or blanket archive migration is part of M0.
Before removing a later research cluster, map active imports, fixtures, manifests
and review dependencies. Record its immutable source and restoration condition.
Merged branches and old output are not deletion authority.

## M1: explicit NoM protocol and offline client boundary

Consolidate the existing fixed-recipient CANDIDATE-02 graph and source findings
into one small protocol candidate. Specify each message and actor, staged
funding commitments, exact signed-byte custody, disclosure order, time/fee
policy, uncertain outcomes and assumptions. Keep eight decision topics explicit:

| Decision | Required scope |
| --- | --- |
| D1: observation trust | Selected node/genesis/source, canonicality and evaluation position, confirmation policy and reorg limits; no source-service gate is silently declared passed |
| D2: adaptor signing | Exact library revision/API, keys, context/nonce binding and restore behavior; deterministic signing is a proposal requiring review, not a custody proof |
| D3: fee and envelope policy | Preserve exact originals in the initial slice; any replacement requires separately reviewed authorization, account-chain and ambiguous-outcome semantics |
| D4: execution authority | Offline public inputs now; any isolated local-devnet execution is a later explicitly scoped action |
| D5: implementation and licensing | Initial offline reference tools do not select a production language/backend; assess exact distributed dependencies and notices before release |
| D6: upstream tracking | Change-impact closure and separate tracked/qualified pins, rather than equality of direct PTLC files alone |
| D7: Bitcoin graph | Preserve historical MuSig2 work; a tapscript alternative requires a separate graph, transaction and cryptographic review |
| D8: work control | Milestone-linked work, bounded checks, explicit stop conditions and separate external approval boundaries |

The initial executable slice reads bounded public JSON and supplies
`inspect-terms`, `encode-call` and `hash-account-block`. Post-funding terms are
claims. Parsing, encoding and hash agreement do not establish funding, chain
truth, signing permission or recovery permission. There is no signer, file store
or network transport in this slice.

Acceptance:

- Implemented offline commands have explicit public input/output contracts,
  refusal behavior and meaningful positive and negative regression checks.
- Existing wire/hash and fee/receive findings are mapped to protocol rules with
  immutable source references; unresolved choices remain visible.
- Signing-sensitive D2/D3 questions are prepared for early independent review
  before an implementation relies on them. Documentation does not self-approve
  these constructions.

## M2: minimal client and conditional local-devnet composition

First implement bounded offline client transitions, public encoding and exact
replay rules against the selected protocol. Then prepare a separate local-devnet
plan covering source/build/dependencies, genesis, accounts, sporks, resource
bounds, ownership and complete evidence. This plan is not execution permission.

Before connecting a signer or node, select and assess its actual construction
and assumptions. A later authorized local-only experiment uses isolated test
accounts and no real funds. Keep trusted-node assumptions explicit and maintain
raw original bytes separately from parsed observations and client summaries.

The current offline slices keep their acceptance scopes separate:

| Slice | Component condition | Guarantee excluded |
| --- | --- | --- |
| M2a: declared funding | Separate economic agreement from ordered, exact Create hash/entry projections | No successful Create, authenticated agreement or current entry proof |
| M2b: public presignature | Derive one bound leg's request locally; separately check its selected public curve relation with bounded input and explicit refusals | No signing/nonce safety, context authentication, disclosure or funding permission |
| Later composition | Connect independently scoped signer, observer and persistence under an assessed protocol | No local-devnet or operational acceptance follows from M2a/M2b component results |

M2b must work after the long binding without inventing a short entry. A separate
small package and the qualification tests use the same checker source. A result
digest binds input bytes only; the caller's context digest remains unauthenticated.
Exact source, package/build context and actual checks accompany every result.

Acceptance for that later composition:

- An explicitly selected local network and exact client source execute both
  funding and claim legs, including necessary contract and recipient receives.
- Actual admitted blocks, confirmation/evaluation context and both parties'
  balances demonstrate the declared result. CLI output alone is insufficient.
- A clean independently prepared environment reproduces the selected procedure.
- Signer, observer, persistence and network evidence are each scoped. A single
  successful exchange grants no production, core or general custody approval.

## M3: adversarial and recovery scenario matrix

Qualify the actual selected client, rather than growing unrelated verification
infrastructure. The matrix covers success, absent short funding, no claim,
disclosure cutoff, invalid pre-signature/context, insufficient Plasma, process
death, restored state, delayed recipient recovery, proxy behavior if selected,
reorg/canonicality and fee-rule changes.

Acceptance:

- Each applicable scenario has an expected safety/refusal result, actual selected
  implementation/source, complete retained evidence and a reproducible command.
- Missing outputs, possible disclosure and ambiguous broadcast stay UNKNOWN;
  no automatic nonce reuse, fee rewrite or transaction replacement is inferred.
- Restore tests assess the selected context and key-use rules; byte-identical
  deterministic output alone does not establish general restore safety.
- Mock-only or unavailable reorg/proxy cases are labeled separately. They do not
  count as real-devnet scenario passes. Coverage exclusions remain explicit.
- Scheduled repetition is considered only after the harness and its resource
  limits are accepted, and requires a separate scheduling request.

## M4: independent scoped assessment

Prepare a compact reading entry point, exact source/dependency inventory,
protocol/decision records, implementation map, selected matrix evidence and
specific questions. Existing frozen packets remain historical inputs; none is
silently relabeled as an assessment of later client source.

Seek distinct protocol/cryptography and client/recovery scopes. Early assessment
of signing-sensitive decisions can precede the full matrix. Reviewer outreach,
public issues and funding proposals require separate explicit authorization.

Acceptance:

- Written assessments identify exact subject, examined dependencies/evidence,
  independence limits, assumptions, exclusions and findings.
- Critical and high findings in the selected scope have assessed dispositions.
  Remaining risks and unreviewed obligations are explicit.
- Later changes receive impact analysis and an appropriately scoped delta review;
  a small code diff does not automatically justify reviewing only changed lines.

Independent review is necessary for later adoption but is not by itself an
activation, deployment or funds permission.

## M5: separate Bitcoin regtest extension

After the NoM construction and client are qualified for their selected scope,
select one Bitcoin graph in a separate specification. Preserve CANDIDATE-01;
any NUMS/tapscript alternative is a new construction, not a drop-in backend
change. Reuse the existing transaction fixture and independent script-engine
experience without treating them as node or mempool evidence.

Acceptance:

- Exact funding, claim and unilateral refund transactions pass selected Bitcoin
  Core regtest and NoM devnet scenarios with source-bound original evidence.
- Tests distinguish consensus/script acceptance, UTXO existence, mempool/package
  policy, inclusion, confirmation and client observation.
- Timing binds Bitcoin median-time-past and the selected NoM evaluation time;
  fee/CPFP, delayed relay and competing claim/refund assumptions are exercised.
- The full construction delta and applicable matrix receive scoped independent
  assessment. Testnet, mainnet, production wallets and real funds remain later
  separately authorized decisions.

## Proportionate CI and upstream tracking

A fast PR tier may target approximately 15 minutes for privacy/artifact checks,
active parsing/state tests and selected primitive checks. Measure the target
before claiming it. Relevant source, dependency, codec, fee, receive or recovery
changes trigger the corresponding native/component qualification. Keep a full
baseline tier with complete selected OS/Python profiles, native jobs and original
evidence acceptance available for significant changes and release decisions.
The fast tier never reports unexecuted full/native work as passed.

Track PTLC source plus its shared verifier/VM, sequencer/pool, momentum/time,
ABI/RPC, Plasma/spork, serialization and dependency/toolchain closure. Unchanged
direct PTLC files do not prove unchanged behavior through shared entry points.
Unknown shared-path impact requires analysis rather than an automatic pin update.
Keep a latest tracked candidate separate from the last qualified source; new
revisions require the selected evidence before their status changes.

Language and process boundaries do not settle licensing by themselves. Before
vendoring or binary distribution, inspect the actual package/target selection,
copied code, linkage/distribution arrangement and required notices. The project
MIT license applies to original contributions; third-party terms remain as
recorded in [the notices](../THIRD_PARTY_NOTICES.md).
