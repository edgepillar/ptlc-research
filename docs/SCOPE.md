# Scope and delivery boundaries

Status: **Stage 45 - local source read ordering qualification. CANDIDATE-01 has primitive, transaction, session and schedule evidence, with no executable swap client or production signing backend.**

The intended later deliverable is a reference application for one bilateral Bitcoin regtest <-> Zenon devnet swap. Current work establishes an inspectable specification, source inventory, synthetic primitive tests and bounded schedule evidence before connecting nodes. It is not a production wallet, a deployed contract, or an activation proposal.

## Stage 0 deliverables

- Record the exact upstream contract behavior and distinguish existing tests from missing evidence.
- Compare a compatible HTLC baseline with a prospective BIP340/secp256k1 adaptor design. Document what additional benefit justifies the cryptographic and integration work.
- Specify the safety properties, unresolved protocol choices, failure model, and later validation requirements.
- Keep any offline algebra or regression demonstrations separate from cryptographic implementations intended to hold funds. A passing demonstration does not establish protocol security.

Stages 0 through 42 exclude node integration, wallet access, live RPC interaction, real funds, production key material, upstream node changes, and feature activation. Source inspection and local fixture checks cannot establish successful cross-chain settlement.

## Stage 1 deliverables

- Fix one candidate graph and roles in [TRANSACTION_GRAPH.md](TRANSACTION_GRAPH.md), including independently executable refunds and artifact exchange order.
- Qualify two pinned adaptor primitive implementations and untweaked two-party linkage using synthetic inputs. Cross-check completed signatures through separate arithmetic implementations and the pinned Go contract verifier dependency.
- Qualify a real synthetic Taproot key-path claim and independent CLTV refund, including exact serialization, tweak, sighash, and separate Go script execution.
- Enumerate finite schedules under explicit bounds and produce counterexamples when safety guards are removed.
- Record all executed checks, intermediate failures and unimplemented boundaries in [STAGE1_VALIDATION.md](STAGE1_VALIDATION.md). This is no substitute for transaction construction, durable signing or real-node integration.

## Ownership boundaries

Stage 2 adds bounded versioned transcript commitments, session-wide funding/entry bindings, exclusive public-state ownership and a one-use synthetic producer journal. Its [design](SESSION_JOURNAL.md) and [validation](STAGE2_VALIDATION.md) explicitly separate public metadata from real cryptographic nonce handling. A separately stored checkpoint detects one-sided restore; restoring both matching copies remains undetectable.

Stage 3 adds [public nonce-round commitments](NONCE_ROUNDS.md), journal v2 round pins and local duplicate-public-nonce history, plus a separate ephemeral Rust test owner. Shared public fixtures connect the Python hashes, actual pinned MuSig2 signing, legacy Go BIP340 verification, and Bitcoin script execution. The Python callback only replays checked-in public bytes; no signing backend is attached. [Stage 3 validation](STAGE3_VALIDATION.md) records the evidence boundary.

Stage 4 implements the [managed Bob artifact flow](ARTIFACT_EXCHANGE.md) in journal v3. It verifies public partials/bundles, retains the complete Zenon extraction context, commits release intent, and returns exact replayable bytes. The Rust subprocess is a public verifier, not a signing worker. Its integration and process-death checks are recorded in [Stage 4 validation](STAGE4_VALIDATION.md). Peer authentication, actual chain/timing policy and secret signing remain absent.

Stage 5 adds [Alice completion and Bob public recovery](COMPLETION_LIFECYCLE.md) in journal v4. Alice validates the complete inbound bundle, consumes her synthetic producer before invocation, and persists exact completion output. Bob retains the observed public signature before actual verification, witness extraction and Bitcoin adaptation. Alice still returns a fixture signature; no private signing backend is attached. [Stage 5 validation](STAGE5_VALIDATION.md) records public cryptographic integration, process-death tests and the remaining paired-restore and observation-selection limits.

Stage 6 adds [explicit completion observation reconciliation](OBSERVATION_RECONCILIATION.md) in journal v5. A different candidate requires an exact retained-input guard and positive public cryptographic recovery before the completed replacement and original archive are persisted. This local recovery path does not authenticate observations or change Alice ownership. [Stage 6 validation](STAGE6_VALIDATION.md) records the evidence.

Stage 7 replaces temporary-file stdout spooling with [bounded public worker transport](PUBLIC_WORKERS.md), shared by the artifact and completion adapters. It adds concurrent pipe transfer, immediate overflow rejection, a transfer/exit deadline and bounded cleanup attempts without changing storage or cryptographic inputs. [Stage 7 validation](STAGE7_VALIDATION.md) separates synthetic process tests from actual Rust integration. Peer admission and aggregate resource policy remain unresolved.

Stage 8 adds a [durable Bob recovery allowance](RECOVERY_ADMISSION.md) in journal v6, shared by ordinary completion and explicit reconciliation. The caller chooses a finite immutable limit; each eligible attempt is charged before the worker, with no crash/failure refund. This changes reconciliation's storage behavior on failure, while preserving its candidate and archive rules. [Stage 8 validation](STAGE8_VALIDATION.md) records the evidence. Alice and initial artifact verification are outside this allowance; it is not authenticated admission or funded-swap availability policy.

Stage 9 adds a [public completion-envelope qualifier](COMPLETION_AUTHENTICATION.md) using the pinned BIP340 backend and separate locally supplied authentication keys. Exact bytes, roles, purpose, terms and both pins are signed. The [validation report](STAGE9_VALIDATION.md) distinguishes authenticated bytes from valid completion and explicitly demonstrates replay and direct journal bypass. At that milestone, pin enrollment, durable binding, freshness, transport and authenticated journal enforcement remained unimplemented.

Stage 10 adds [durable local authentication pins](DURABLE_AUTHENTICATION_PINS.md) in journal v7. The optional pair and the choice of no pins are frozen at Bob start; a guarded helper reconstructs verification context from stored terms and pins after reopen. Verification writes no observation, exposure flag, receipt or allowance counter. Raw recovery remains independently callable. [Stage 10 validation](STAGE10_VALIDATION.md) records crash, ownership and actual verifier evidence; trusted pin establishment, authenticated admission and public-witness observation authorization remain unresolved.

Stage 11 adds a separate [bounded recovery-admission model](RECOVERY_ADMISSION_MODEL.md) with idealized authentication/validity and explicit external local authorization. It separates candidate/history integrity from availability and produces replayable counterexamples for envelope withholding, finite-allowance exhaustion and authentication/validity confusion. [Stage 11 validation](STAGE11_VALIDATION.md) reports configured exploration bounds, complete versus truncated searches, and the unchanged journal/cryptography boundary. It selects no safe funded admission policy.

Stage 12 adds [pure candidate construction from a public signature](PUBLIC_SIGNATURE_CANDIDATES.md). The helper derives the existing packet entirely from a retained Bob context and 64 signature bytes, without writing state, verifying signatures, or granting source/admission authority. [Stage 12 validation](STAGE12_VALIDATION.md) covers exact fixture reconstruction, unchanged storage and actual recovery/rejection. Journal v7 and ordinary/CAS recovery rules remain unchanged.

Stage 13 prepares an [independent review brief](INDEPENDENT_REVIEW.md), a complete Git-object inventory of the exact Stage 12 source subject and an unfilled report template. [Stage 13 validation](STAGE13_VALIDATION.md) records packaging and regression checks. No independent assessment, production backend choice, reviewer outreach or execution change is implied by this preparation.

Stage 14 adds [selected model/journal correspondence](RECOVERY_MODEL_CORRESPONDENCE.md). Baseline exhaustion traces and concrete positive/negative cases are replayed against real public journals, with a separate actual-worker qualifier in existing CI. [Stage 14 validation](STAGE14_VALIDATION.md) separates fake-oracle checks, actual qualification and intermediate bridge errors. No journal/model policy, source authority or private signing is implemented by this evidence.

Stage 15 compares shared and reserved budgets in a separate [public recovery reserve model](RECOVERY_RESERVE_MODEL.md). Protected attempts can survive general peer exhaustion under ideal authorization, yet interrupted public work can drain them. [Stage 15 validation](STAGE15_VALIDATION.md) records complete bounded searches, explicit environment assumptions and independent resource checks. No reserve, failure bound or funded availability guarantee is implemented in the journal.

Stage 16 weakens that fixed-valid-public premise in a separate [exact-observation model](PUBLIC_OBSERVATION_MODEL.md). Each public identity has independent local authority, and normal invalid rejection can spend the reserve even without interruptions. [Stage 16 validation](STAGE16_VALIDATION.md) records complete comparisons, independent authority/resource checks and projection of the valid subset to the unchanged earlier model. No observation source, new journal policy or funded guarantee is implemented.

Stage 17 adds a pure [observation-evidence contract and codec](OBSERVATION_EVIDENCE_CONTRACT.md). Exact candidates, both retained legs, a Zenon-only predicate request and the separately selected verifier profile determine a bound claim. [Stage 17 validation](STAGE17_VALIDATION.md) covers cross-target/profile rejection, malformed claims and unchanged exhausted journals. Parsed outcomes remain claims; no trusted producer, source, negative cache or admission policy is selected.

Stage 18 adds a separate [local public verdict producer and adapter](OBSERVATION_VERIFIER.md). A complete shape guard precedes reuse of the unchanged pure predicate; normal mathematical negatives are distinct from unavailable requests or workers. The adapter requires an explicit entry-file hash and emits bound unknowns on worker/result failure. [Stage 18 validation](STAGE18_VALIDATION.md) uses synthetic process actors and actual local executables. Host/provisioning trust, source authority and aggregate resources remain external; no cache or journal policy is connected.

Stage 19 adds a pure [bounded observation-record contract](OBSERVATION_RECORDS.md). Pending and finished attempts retain their charges; normal claims survive unknown work and conflicts remain explicit. Exact local targets/profiles, complete event replay and finite quotas are checked without I/O or worker invocation. [Stage 19 validation](STAGE19_VALIDATION.md) separates fixture claims from actual-verdict exercises and exposes old-value quota restoration. Owned persistence, storage identity, aggregate resources and recovery admission remain unimplemented.

Stage 20 adds [separately owned local disk records](OBSERVATION_STORE.md). Lifetime process/thread locks precede load and span pending commit, selected work, result commit and return. Reopen commits unfinished publication as unknown without refund or worker replay; mismatched database/checkpoint pairs quarantine. [Stage 20 validation](STAGE20_VALIDATION.md) covers native owner death, inherited handles, wrong configuration and one-sided/paired restores, plus actual worker restart/result-loss cases. Orphan computation, paired rollback, hostile host integrity, aggregate resources and source authority remain open. The session/recovery journal and frozen review subject are unchanged.

Stage 21 adds [worker-held ownership leases](OBSERVATION_LEASES.md) and a parent-watching guard for the selected cooperative nonforking observation worker. Owner death triggers direct-child cleanup; guard death can leave work alive but its lock references block reopen until exit. Store v2 quarantines consistent old v1 pairs without migration or recovery. [Stage 21 validation](STAGE21_VALIDATION.md) covers native death during input/output/wait, guard loss, deadline/cancellation and old-format rejection, separately from actual mathematical qualification. Arbitrary containment, aggregate resources, paired rollback and independent delta review remain open; no recovery or core policy is connected.

Stage 22 adds [explicit shared worker admission](SHARED_WORKER_ADMISSION.md). Cooperating stores selecting the same physical pool acquire one of its fixed slots before pending persistence; saturation makes no attempt or worker call. The guard and selected worker retain that third reference until exit, including after guard loss. Store v3 binds the pool profile and rejects old v1/v2 pairs without migration. [Stage 22 validation](STAGE22_VALIDATION.md) covers cross-store saturation/retry, capacity after owner/guard death and cancellation, plus actual selected verification. Matching profiles in separate physical pools remain a deliberate bypass counterexample. CPU/memory accounting, cumulative rate, fairness, trusted enrollment, clone/restore protection and independent delta review remain open.

Stage 23 adds a separate [explicit CPU/address-space experiment](WORKER_RESOURCE_LIMITS.md) for one unprivileged selected Linux process. A child-only installer lowers both caps, disables core dumps and verifies readback before exec with three inherited references. Unsupported hosts and incomplete setup select no entry and never fall back. [Stage 23 validation](STAGE23_VALIDATION.md) separates local macOS refusal from hosted Linux enforcement and actual Rust verdicts. The owned store remains v3 with ordinary admitted work; durable resource-policy selection is a separate gate. No RSS, aggregate budget, rate/fairness, capability isolation or funded policy is supplied.

| Component | Responsibility | Boundary for this repository |
| --- | --- | --- |
| Reference application | Session transcript, counterparty validation, chain observations, signing orchestration, durable recovery, and user-visible outcomes | Specify these now; implement only after the construction and transaction graph are selected. |
| `go-zenon` core / PTLC PR #13 | Consensus-visible contract admission, signature verification, expiry, transfers, RPC representation, and activation | Treat pinned source as evidence. Do not silently patch or redefine its rules from the client. A contribution requires fresh upstream state and overlap/ownership coordination. |
| Zenon SDK | Encoding calls, decoding responses, transaction construction and signing interfaces | Specify the required interface. Do not treat experimental fork support as integration into a maintained shared SDK. |
| Cryptographic library | Correct key handling, adaptor construction, verification, extraction, randomness, and nonce rules | Select and evaluate separately in [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md). Do not import a demonstration because it completes a happy path. |
| Bitcoin node and transaction policy | Consensus and script validation; mempool admission and relay policy | A later regtest harness must distinguish these from client assumptions. Regtest cannot establish production fee-market behavior. |

## Initial product boundary

The design target is two participants, one agreed asset pair, one swap at a time per session, and one explicitly selected Bitcoin spend/refund graph. CANDIDATE-01 uses BIP340 over secp256k1 with two-party aggregate adaptor signing, a Taproot key-path claim and a unilateral CLTV refund leaf. This is an offline design choice, not approval of a particular backend or complete protocol.

The baseline asset is BTC against ZNN. Supporting QSR or other Zenon token standards, both trade directions, concurrent sessions, or additional spend structures requires explicit coverage; a generic token field is not that evidence. Concurrency safety remains mandatory even if the interface exposes only one session: a second process or restored copy must not reuse signing state.

Order books, routing, Lightning integration, lending, wrapped-BTC issuance, Portal accounting, and general cross-chain state verification are outside this reference application's initial boundary. A bilateral swap does not create a redeemable BTC-backed asset on Zenon.

## HTLC comparison before committing to PTLC

The current upstream master includes an HTLC contract. The existence of atomic swaps is therefore not a unique justification for adding PTLC. The baseline comparison must examine compatible hash/preimage rules, expiry and refund behavior, supported assets, privacy leakage, client complexity, and recovery costs. It must not assume that source availability demonstrates a working BTC <-> ZNN HTLC product.

A PTLC candidate must identify a concrete benefit, such as removing a shared on-chain hash linkage under a specified observer model or enabling a required signature protocol. Amounts, timing, endpoints, and the explicit Zenon contract remain observable. General claims of anonymity or lower cost require additional evidence.

## Source baseline

The following references were checked on **2026-10-03**. Branch state must be refreshed before implementation or coordination; these identifiers are evidence pins, not promises about current upstream state.

| Source | Pinned reference | Established fact |
| --- | --- | --- |
| [PTLC PR #13](https://github.com/zenon-network/go-zenon/pull/13) | `8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18` | Open draft at inspection; contract and tests exist. The two PR commits are dated 2023-05-22. |
| [Current master spork list](https://github.com/zenon-network/go-zenon/blob/667a69d9e9a418edf7580b08492ba5dcb9efd63a/common/types/spork.go) | `667a69d9e9a418edf7580b08492ba5dcb9efd63a` | HTLC is listed; PTLC is not. This is a source-level observation, not a live-chain activation query. |
| [Current dev contract registration](https://github.com/zenon-network/go-zenon/blob/44c0baf1106a76407ac4becf204306f499ae28f9/vm/embedded/embedded.go) | `44c0baf1106a76407ac4becf204306f499ae28f9` | Composed feature variants include HTLC and Dynamic Plasma; PTLC is absent. |

The PR's stored base SHA is not necessarily the current target-branch tip. See [EVIDENCE.md](EVIDENCE.md) for the evidence inventory and limitations.

## Exit criteria and next work

Stage 0 is reviewable when the source facts, cryptographic candidates, threat model, and unresolved decisions are documented and internally consistent. It does not have to resolve the construction to truthfully complete the research package.

Starting a runnable swap requires a separate decision resolving the cryptographic construction and the full transaction/message graph, with an independent assessment of the safety argument. The acceptance checklist in [PROTOCOL.md](PROTOCOL.md) must then become specific to that graph. A local proof of concept may expose additional blockers.

The Stage 13 brief defines a concrete subject and assessment obligations for that independent work. Its inventory is source identity evidence, not a signed attestation or security verdict. External review remains pending; material findings and changes after the assessed revision need explicit disposition before progression.

A later core port must preserve pre-activation historical behavior and compose PTLC with other activated features. Existing expiry and replay tests must be retained and extended; their presence must not be reported as absent. Any core contribution needs coordination with current maintainers and overlapping work before changes are proposed.

No result from this repository authorizes production activation. A later activation decision requires its own reviewed core commit, protocol implementation, operational assumptions, and network evidence.

## Stage 24 explicit resource continuity

The separate Linux v4 observation entry persists the requested CPU/address-space
profile beside the existing pool profile. It rejects missing/unsupported policy
before creation and cross-mode/policy reopen before SQLite access, then checks
the complete pair before pending recovery. Ordinary v3 behavior and pure math
records remain separate. Limited work still uses three cooperative references;
interruption is charged unknown with no ordinary-work fallback. Stage 24 leaves
the full v4 cut matrix to a separate gate. Aggregate budgets, enrollment,
independent review and funded availability remain open. See
[design](DURABLE_RESOURCE_POLICY.md) and [validation](STAGE24_VALIDATION.md).

## Stage 25 explicit v4 process-death qualification

The separate [cut matrix](RESOURCE_STORE_CRASH_CUTS.md) covers nineteen initial,
admission/result and recovery boundaries, real hot-journal refusal before
SQLite access, repeated interrupted recovery and retained old normal evidence.
Processes, SIGKILL and SQLite are real; Python discovery uses synthetic verdicts
and macOS explicitly simulates only v4 host selection. The actual Linux qualifier
requires limited Rust verification before publisher death. Source journal bytes
and all runtime/cryptographic behavior remain unchanged. See
[validation](STAGE25_VALIDATION.md) for execution boundaries and initial fixture
failures. Controlled write/sync/replace faults, power loss, clone defense,
independent review and funded availability remain separate gates.

## Stage 26 explicit v4 storage-failure qualification

The separate [fault design](RESOURCE_STORE_FAULTS.md) qualifies before/after
SQLite, write, flush, fsync and replacement failures, secondary rollback/cleanup
errors, poisoned handles, charge retention and caller-slot release. The exact
application persistence method still runs; injected errors and discovery verdicts
are synthetic. Separate disposable-writer cases require actual kernel file-size
refusal; Linux result-side qualification requires an actual Rust positive first.
Consistent reopen recovers charged unknown without replay, while divergent pairs
quarantine. Formats, runtime, journal, cryptography and frozen subject are
unchanged. See [validation](STAGE26_VALIDATION.md) for execution boundaries.
Native I/O errors, physical sync failure, power loss, clone defense, independent
assessment and funded availability remain separate obligations.

## Stage 27 separate observation subject

The [observation brief](OBSERVATION_REVIEW.md) pins a complete 189-file snapshot
through Stage 26 while preserving the original 119-file construction subject.
An offline checker recomputes exact Git inventories, protects both working and
indexed manifests and optionally checks a bounded plain source archive without
extraction. It performs no object acquisition, backend execution or chain work.
The [separate report](OBSERVATION_REVIEW_REPORT_TEMPLATE.md) is unfilled. Source
identity and packaging regressions are not independent assessment, authenticated
provenance or a progression decision. See [validation](STAGE27_VALIDATION.md).
Runtime, mathematical records, cryptography, storage formats and dependencies
are unchanged; all prior native storage, restore, resource and source gates remain.

## Stage 28 explicit v4 restore boundaries

The [restore experiments](RESOURCE_STORE_RESTORES.md) qualify mismatched-pair
refusal, coherent old-pair quota/claim rewind, copied histories with the same
physical pool and pending recovery without replay or refund. Discovery uses real
files/locks with synthetic host selection and verdicts; separate Linux methods
require actual limited Rust positives and preserve source-journal state/bytes.
This adds test evidence only, with no application restore API, format change or
monotonic/enrollment authority. Both fixed review subjects remain unchanged;
the later qualification needs its own explicit assessment. See
[validation](STAGE28_VALIDATION.md). Restore/clone defense, source authority,
native storage, aggregate budgets and funded availability remain unresolved.

## Stage 29 finite observation-authority comparison

The [authority model](OBSERVATION_AUTHORITY_MODEL.md) compares local restore,
cached head checks, charged copyable receipts, ideal unique dispatch and
external authority rollback. Default exploration covers two copies, allowance
one and two worker entries, with exact counterexample traces and explicit
incomplete-search reporting. A separate allowance-two trace shows result fencing
without terminating prior work. External state, scope enrollment and dispatch
are ideal premises, not an implemented service or protocol. Application,
qualifiers, formats, dependencies and both fixed subjects are unchanged. See
[validation](STAGE29_VALIDATION.md). Native storage, trusted source, backend
review, secret ownership, aggregate resources and funded availability remain open.

## Stage 30 candidate authority contract

The [pure bounded codec](OBSERVATION_AUTHORITY_CONTRACT.md) fixes public scope,
full expected-head, exact target and operation bindings for assessing a future
authority construction. Candidate signatures and local paths cannot refresh the
same selected scope. New labels or changed contexts still require externally
authenticated canonical enrollment; no quota owner, target set, latest-head
source, idempotency table or dispatcher exists here. Matching replies are
forgeable and replayable claims, not entry permission. Existing journal/store,
worker/resource paths, formats, models, qualifiers, dependencies and fixed
subjects are unchanged. See [validation](STAGE30_VALIDATION.md). Backend selection,
private signing, core port, chain integration and real funds remain no-go.

## Stage 31 finite canonical enrollment comparison

The [separate model](OBSERVATION_ENROLLMENT_MODEL.md) compares scope/caller keys,
canonical source knowledge, independently authorized owner facts, cached missing
checks, atomic uniqueness and registry rewind. It fixes two protected classes,
five single-field proposals per class and finite enrollment/charge/loss bounds.
Conditional atomic ownership preserves one shared allowance per class; source
or authorization claims alone do not implement its premises, and registry rewind
refills quota. Charges are abstract events with no worker entry, authentication,
native transaction, target set or funded policy. Existing runtime/codec, formats,
models, qualifiers, dependencies and both fixed subjects are unchanged. See
[validation](STAGE31_VALIDATION.md). Define actual canonical resource/owner
provenance and non-rollbackable lineage before selecting an enrollment backend.

## Stage 32 candidate content key and unsigned owner intent

The [pure contract](RETAINED_RESOURCE_INTENT.md) selects equality of seven paired
source commitments, excludes all nine external scope selections from that key,
and binds the full scope, independent owner public-key selection and request ID
in unsigned role/purpose-separated bytes. Preparing intent rechecks the supplied
retained snapshot; parsing a retained expectation proves no current-source
freshness. Matching unsigned bytes replay, and key formatting validates no
curve point, ownership or governor role. Changed source remains representable
without economic equivalence or new allowance authority. Existing codecs,
runtime, formats, models, qualifiers, workflows, dependencies and both fixed
subjects remain unchanged. See [validation](STAGE32_VALIDATION.md). Source and
owner provisioning, actual public verification, registry lineage and unique
dispatch must be selected and assessed before integration; funds remain no-go.

## Stage 33 public enrollment signature qualification

The [separate signature layer](PUBLIC_ENROLLMENT_SIGNATURES.md) preserves the
Stage 32 message and verifies it with the unchanged locked BIP340 backend.
Independent exact intent matching precedes the public worker; an explicit entry
hash is repeatedly measured and results bind the complete signature request.
Actual valid/rejected checks preserve an exhausted reopened source journal.
The same unsigned intent is returned, with no governor authority, source trust,
freshness, registration, allowance or permission. Correctly signed alternate
keys/sources remain valid standalone facts and refuse relative to the local
expectation. Legacy bounded transport supplies no enrollment rate/pool policy.
See [validation](STAGE33_VALIDATION.md). Both fixed subjects and reports remain
unchanged. Role/bootstrap, economic-source equivalence, non-rollbackable atomic
uniqueness, idempotency, trusted dispatch, signer and funded gates remain unresolved.

## Stage 34 independent public enrollment signature checks

The [test-only Go cross-check](INDEPENDENT_ENROLLMENT_SIGNATURES.md) independently
reconstructs message/resource/scope/request hashes and verifies the unchanged
public fixture through the existing locked BIP340 module. Invalid bindings,
encodings and mutations reject; valid self-selected source/key signatures and
reused request IDs remain positives without authority or freshness. Exact
application parsing remains separate from raw intent mathematics. This adds no
signer, application verifier, registry, dependency or workflow. See
[validation](STAGE34_VALIDATION.md). Both review subjects and unfilled reports
remain unchanged; this qualification delta needs separate assessment.

## Stage 35 explicit local governor-role profiles

The [pure local profile](LOCAL_GOVERNOR_PROFILE.md) makes key, retained resource,
namespace/epoch, four profile pins and separate proposal caps explicit. Exact
parsing refuses replacement of independently selected bytes; matching checks
the full role constraints and returns the same unsigned intent. Valid alternate
signatures cannot override a different selected key, scope or cap. Selecting
untrusted rules instead, stale profile replay, new IDs and broader local caps
remain positives without role provenance, current policy or allowance. The
unchanged signed intent does not commit this profile digest. Existing journal,
observation and enrollment signature paths do not require the optional helper.
See [validation](STAGE35_VALIDATION.md). Models, workers, packets, dependencies,
fixtures and both fixed subjects/reports remain unchanged; the new pure helper
and qualifier need separate assessment. Bootstrap, policy binding, revocation,
source authority, registry lineage and unique dispatch remain unresolved.

## Stage 36 finite governor authority comparison

The [standalone model](GOVERNOR_AUTHORITY_MODEL.md) separates independently trusted
root/assignment facts, complete hypothetical profile binding and current authority
at abstract use. Cached positives survive policy change, key rotation and
revocation; restoring a coherent old local view can bypass a use-time check.
Conditional atomic-current safety requires ideal inputs and a non-rollbackable
current oracle. Both callers can still admit the same proposal. No provisioning,
certificate format, v2 intent, crypto verification, registry, quota or worker
entry is implemented. Existing code, packets, public workers, models, journals,
dependencies and workflow remain unchanged. See [validation](STAGE36_VALIDATION.md).
Both fixed subjects/reports remain unchanged and this later model needs separate
assessment. Select trusted issuer provisioning and current-policy/use evidence
before any backend; source, lineage, dispatch, signer and funded gates remain open.

## Stage 37 unsigned assignment and complete profile binding

The [pure assignment/intent contract](GOVERNOR_ASSIGNMENT_CONTRACT.md) selects
five-field unsigned issuer bytes containing the full 14-field local profile and
nine-field unsigned v2 owner bytes that commit the assignment. Broader caps and
another issuer change the new message, preserving the old v1 scope/message.
Exact expected-object parsing supplies no issued credential, current authority,
registry, replay defense or quota. [Validation](STAGE37_VALIDATION.md) includes
the corrected first affected run and a real exhausted-journal preservation check.
The old codecs/messages, signature fixture, workers, journals, dependencies and
workflow are unchanged. Actual signature construction, provisioning, current
state at use and both independent assessments remain gates. Current-node core
work, private signing, deployment and funded recovery remain excluded.

## Stage 38 public issuer and v2 owner signatures

The [separate public verifier](GOVERNOR_SIGNATURE_QUALIFICATION.md) checks issuer
BIP340 signatures over the complete assignment and owner signatures over the
separate v2 message. Exact independently prepared expectations precede work;
the four-field result binds both signatures and the entire request. Rust vector
reproduction, independent Go checks and an actual bounded-worker qualifier are
separate from trusted selection and construction review. No private signing,
current-state oracle, registry or application admission is connected.

Valid old authority still verifies under a retained old expectation. A signed
opaque scope hash is no decoded scope/cap/source evidence; a forged selected
verifier result is no mathematical fact. Real exhausted journals retain their
charged allowance and recovery behavior. Both fixed subjects and unfilled
reports remain unchanged. See [validation](STAGE38_VALIDATION.md), including the
first Go setup failure. Trusted issuer provisioning, current authority at actual
use, non-rollbackable lineage, source equivalence and independent review remain
gates. Current-node core work, private signing and funded activity remain NO-GO.

## Stage 39 current-authority requirements and read claims

[The source/use requirements and pure read contract](CURRENT_AUTHORITY_EVIDENCE.md)
separate issuer provisioning, source identity/incarnation, exact policy checkpoint
and actual-use ordering. The query includes both public signature statements and
the complete independently decoded scope/resource. Exact active, revoked, absent
and unavailable responses remain forgeable labels; revision/checkpoint equality,
new challenges and coherent local copies establish no current truth or permission.
Source authentication, current-read semantics, root recovery, protected-use cutoff
and atomic policy/lineage/dispatch are unresolved mechanisms. No source adapter,
signer, journal or admission path is connected. Both fixed subjects and unfilled
reports remain unchanged; this later delta needs separate independent assessment.
[Validation](STAGE39_VALIDATION.md) records directed stale/restore/replay/outage and
real exhausted-journal controls. Offline qualification is GO; current-authority
integration, core work, activation, deployment and funded activity remain NO-GO.

## Stage 40 policy source and protected-use ordering

The [standalone finite model](POLICY_SOURCE_USE_MODEL.md) compares current-policy
commit/charge records and a later abstract entry under two candidate cutoffs.
Original-operation reconciliation, retained charges, source failures, coherent
client restore and unsafe source-ledger restore have separate directed controls.
It selects no production source, protected-use definition, revocation rule or
actual worker fence. One CLI comparison step is added to existing Python CI jobs;
existing runtime code, crypto, workers, journals, dependencies and pinned actions
remain unchanged. Both fixed subjects/reports remain unchanged and this later
delta needs separate assessment. [Validation](STAGE40_VALIDATION.md) distinguishes
selected schedules from the full action graph and hosted execution. Offline
comparison is GO; source integration, core work and funded activity remain NO-GO.

[Stage 41](OFFLINE_POLICY_EFFECT_STORE.md) selects a bounded local SQLite
construction for policy revisions, scoped original operations and synthetic row
effects. It adds no source/read/admin authentication, real target-cap enforcement,
current-authority adapter, physical-entry fence or nonrollbackable source
recovery. Native POSIX cuts and separate writers are executed controls; coherent
restore/copy failure boundaries remain required. Offline qualification is GO;
source integration, core activation, private signing and funds remain NO-GO. See
[validation](STAGE41_VALIDATION.md).

## Stage 42 isolated root statement

The [source root role candidate](SOURCE_ROOT_ROLE_QUALIFICATION.md) qualifies
complete historical declaration signatures under independently selected bytes.
Five distinct key encodings do not prove independent control; valid old statements
and restored/copy selections still replay. No source service, administrator
authentication, SQLite or physical-use connection is added. See the [Stage 42
validation](STAGE42_VALIDATION.md) for execution evidence and failures.
Both fixed independent assessments remain unfilled; source integration, core port,
private signing and funded execution remain NO-GO.

## Stage 43 isolated administrator commands

The [administrator command candidate](SOURCE_ADMIN_COMMAND_QUALIFICATION.md) permits
only strict cap reduction and profile-preserving revocation under an independently
selected rule. Historical signatures do not read current revisions or apply a
command to any source/store. Replay and coherent restoration still succeed.
See [validation](STAGE43_VALIDATION.md); source integration and production use remain NO-GO.

## Stage 44 isolated source response signatures

The [response signature candidate](SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md)
binds the complete root, checkpoint query, response role and observation claim.
It checks four historical signatures without a current-policy lookup. Old or
coherently restored selections still replay; a new challenge can be signed over
old active state. See [validation](STAGE44_VALIDATION.md). Source integration,
core port and production use remain NO-GO; independent assessments stay unfilled.

## Stage 45 local source read ordering

The [owned local snapshot experiment](LOCAL_SOURCE_READ_ORDERING.md) samples the
complete policy/query under an existing SQLite transaction, without signing or
authenticating a source response. Original-operation association is unsigned;
charges and synthetic effect commits remain separate. Native read-return races,
process death and coherent source restore/copy controls qualify that local
boundary. No application admission or physical-entry fence is added. Eleven
inherited test-only SQLite contexts close without suppressing warnings. See
[validation](STAGE45_VALIDATION.md). Both independent assessments stay unfilled.

## Stage 46 original-operation read framing

The [original-read contract](ORIGINAL_OPERATION_READ_CONTRACT.md) selects exact
unsigned framing for one source incarnation, complete original request and
independent policy/record positions. It keeps historical original and current
head profiles separate, with explicit absence/pending/completed/unavailable
meanings. No signature worker, source adapter, lookup authorization, automatic
unknown-outcome recovery or protected-use gate is connected. Coherent source
restore/copy still repeats synthetic effects. See [validation](STAGE46_VALIDATION.md).
Both fixed independent assessments stay unfilled; production use remains NO-GO.
