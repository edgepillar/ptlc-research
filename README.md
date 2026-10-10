# Zenon PTLC Swap Research

An offline foundation for investigating a bilateral Bitcoin-to-Zenon atomic swap.

Independent research, not an official Zenon implementation or activation proposal.

**Status: Stage 46 original-operation read contract qualification. There is no usable swap client or production signing implementation in this repository.** CANDIDATE-01 fixes a graph for modeling and finite qualification; its complete construction and implementation remain subject to review.

The repository includes a historical scalar-disclosure regression, pinned BIP340 adaptor experiments, real synthetic Taproot claim/refund transactions checked by an independent Go script engine, and an exhaustive finite schedule model. All experiments use public synthetic inputs and contact neither chain. Dependency acquisition is a separate network step.

The `offline_session` package adds staged public transcript commitments, role-bound public nonce rounds, and a SQLite/checkpoint journal for one-use synthetic operations, exact output replay and explicit unknown outcomes. It stores no secret nonces and has no real signing backend. Process-death, concurrent-owner and rollback-boundary tests exercise its public metadata lifecycle. A separate Rust test-only nonce owner exercises the pinned library using public synthetic seeds; it is not connected to the Python journal.

The managed Bob exchange now verifies and durably retains both legs' public artifacts before making the complete Zenon pre-signature available through its release API. A separate Rust executable performs public MuSig2 verification; it has no signing capability. This local order does not establish peer authentication, chain acceptance, time margins or delivery.

Alice now validates that release against her own retained partial and consumes completion ownership before a synthetic producer runs. Bob durably retains her candidate completion, then uses a second Rust executable to verify the Zenon signature, extract and check the witness, and complete the Bitcoin signature. The recovered scalar is never returned. Actual private signing and chain submission remain absent. An explicit reconciliation path can complete a different positively verified observation while preserving the original candidate; it never resets Alice or treats a failed worker as proof of invalidity.

Both public executables use a shared bounded pipe runner. It rejects stdout overflow during transfer, applies one transfer/exit deadline and attempts safe cleanup of the owned process group on failure. It creates no output spool file. The executable remains trusted; this is neither a sandbox nor protection against repeated verification requests.

Bob's two journal recovery APIs now share an explicit finite allowance persisted before each admitted recovery. Failures and crashes do not refund it; exact replay is free. This local policy does not authenticate peers or bound other verification calls, new sessions or restored copies. Exhaustion can prevent a later valid recovery and is not a funded-swap availability policy.

A separate public BIP340 verifier now qualifies Alice's completion envelope against locally selected session terms and dedicated authentication-key pins. It binds the exact payload and returns no signing material. Authentication does not prove the enclosed completion valid, provide freshness or establish pin provenance. Journal entry points remain callable without it; authenticated admission is not enforced.

Optional authentication pins can now be frozen when Bob's exchange starts. A journal-scoped helper rebuilds the envelope context from those stored pins and terms after reopen. Verification itself writes nothing and consumes no recovery allowance. Both configured pins and the choice of no pins are immutable under the local continuity checks. Restored matching pre-start files can still erase that choice; enrollment and rollback protection remain external.

A separate finite recovery-admission model explores policy choices before they are connected to the journal. It separates candidate/history integrity from recovery availability, with explicit local authorization as an external input. Counterexamples cover a withheld authentication envelope, exhausted recovery allowance and treating authentication as inner-signature validity. This model selects no funded-swap admission policy and changes no journal or cryptographic behavior.

A pure helper now constructs an unverified completion candidate from a 64-byte public signature and Bob's retained context. It accepts no remote context or provenance claims, writes nothing, and leaves ordinary recovery and comparison-guarded reconciliation unchanged. Its role labels are packet-format metadata, not evidence of an authenticated Alice message. Actual verification and caller authorization remain separate.

An independent review brief now freezes the Stage 12 implementation subject, inventories all 119 source files and separates verified behavior from unresolved construction, ownership and availability obligations. The accompanying assessment template is unfilled. Preparing this package does not complete an independent review or select a production backend.

A separate observation-layer brief now pins all 189 source files through Stage 26, with an offline complete-inventory checker and its own unfilled report. It identifies ownership, pool, resource and storage-failure obligations without altering the original 119-file subject. Both independent assessments remain pending.

V4 restore experiments now distinguish mismatched-pair quarantine from coherent
old-pair acceptance. Restoring an earlier complete history can replenish quota
or erase later claims; same-profile copies can consume independent allowances
even with the same physical pool. These are explicit counterexamples, not a
restore defense or application restore API. The fixed review subjects are unchanged.

A separate finite authority model now compares local history, cached freshness
checks, externally charged receipts, ideal unique dispatch and authority rollback.
Atomic charge alone does not stop copied receipts from starting multiple modeled
workers. The strongest result assumes non-rollbackable external state and a
trusted dispatcher; neither is implemented. History fencing does not contain
old running work, and lost receipts can exhaust quota before any entry.

A new pure bounded authority codec now binds candidate-independent scope,
external enrollment/epoch/profile selections, exact evidence target and full
expected head to reserve, dispatch, publish and unknown-resolution requests.
Reply parsing checks declared transitions but accepts forged matching claims
and replay; it authenticates no authority and returns no worker capability.
Canonical enrollment, target-set ownership, current-head evidence, idempotency
and durable unique dispatch remain unimplemented. Existing entry points and
storage behavior are unchanged; the codec is not connected to them.

A separate enrollment model now compares full scope keys, caller resource
claims, canonical source knowledge, owner authorization with cached absence
checks, atomic ownership and coherent registry rewind. Label/profile/epoch
changes can split quota; canonical knowledge alone permits unauthorized work,
and cached missing checks can create duplicate records. Conditional atomic
ownership requires independently trusted source/owner facts and a registry that
cannot rewind. No enrollment mechanism, backend or worker integration is added.

A pure candidate resource contract now groups the seven retained public source
commitments independently of authority/enrollment labels, epoch, profiles and
limits. An unsigned enrollment intent binds that content key, full requested
scope and an independently selected public owner key to a separate role/purpose
and message domain. Exact expected bytes reject changed selections but matching
unsigned values replay. This pure codec implements no curve/signature verification, owner role, economic
resource mapping, registry count or runtime admission.

A separate public enrollment signature worker now checks that exact intent using
the unchanged locked BIP340 backend. Its adapter matches independently prepared
inputs before work, repeatedly measures an explicit executable pin, and accepts
only a bounded result bound to the complete signature request. Valid signatures
over self-selected sources/keys still establish no governor role; old expected
intents replay without freshness. Actual checks preserve reopened source journals
and exhausted allowance. No registry, quota allocation, signer or runtime admission
is connected; source/role trust, aggregate work and non-rollbackable lineage remain
external gates.

A separate pure governor-role profile now makes independent local key, resource,
namespace/epoch, profile pins and proposal caps explicit. Exact profile parsing
refuses peer replacement; matching still returns the same unsigned intent.
Wrong or stale locally selected rules can match, and broader local caps change
the profile digest without changing the old signed message. This is no role
certificate, policy-version binding, registration or allocation. Existing entry
points do not enforce it; bootstrap, revocation and trusted selection remain open.

A separate finite governor model now compares peer selection, an initial key pin,
scoped role assignment, complete profile binding, cached current checks, an ideal
atomic current check and coherent local anchor restore. Correct static signatures
and binding can remain valid after update, rotation or revocation. Conditional
use-time authorization requires independently trusted current state that cannot
rewind. All policies still permit repeated packet admission. The model issues no
credential, changes no signed message and implements no enrollment or dispatch.

Selected admission-model traces now replay against real temporary journals, with comparisons inside the admitted callback and after reopen. Python discovery uses explicit fixture oracles; a separate qualifier uses the actual public Rust executables. Exhaustion remains reproducible, with no reset, new authorization policy or signing change. External model facts are kept separate from journal fields.

A separate reserve experiment compares equal aggregate budgets under shared and protected public lanes. Reserving attempts prevents general peer work from spending them under ideal public authorization, but public-worker interruptions can still exhaust them. Conditional path evidence requires an explicit environment restriction, not an implemented worker guarantee. The journal retains its shared allowance.

A further observation experiment permits independently authorized valid and invalid public candidates. It separates normal mathematical rejection from interruption and reproduces reserve exhaustion with zero worker failures, cancellations or crashes. The older positive cases require an ideal pre-admission validity filter; exact local authority alone supplies no such filter. These remain separate models with no journal observation policy.

A pure observation-evidence codec now binds exact candidate bytes, both retained legs, a Zenon-only verification request and an externally selected verifier profile. It parses explicit positive, negative or unresolved claims without making them true or authoritative. Legacy completion failure cannot establish a normal negative. The codec itself selects no producer, source mechanism, cache or journal enforcement.

A separate public-only observation worker now emits explicit normal verdicts after a complete request-shape check and reuses the existing pure cryptographic predicate. Its adapter requires a caller-provisioned executable hash and binds results to the exact target/profile; process or result failure becomes unknown. The selected local host and verifier remain trusted. Real verdicts preserve reopened journals and exhausted budgets; no evidence cache, source policy or journal admission is connected.

A pure bounded record contract now separates pending/finished attempts from retained normal claims, replays complete transition ordering and preserves contradictory decisions explicitly. Unknown work remains charged and cannot erase a prior normal claim. The format freezes one profile and finite attempt/target limits through its managed operations; a restored old value can replenish quota. No disk owner, durable cache or recovery admission is implemented by these bytes.

A separate owned SQLite/checkpoint store now retains those records across local restarts. It acquires lifetime process/thread ownership before loading, commits pending work before the selected public worker starts, and commits the exact result before returning it. Reopen recovers unfinished publication as charged unknown without replaying work; divergent pairs quarantine. A parent-watching guard and the selected cooperative nonforking worker retain the two lock references, preventing reopen while prior work holds them even if the guard dies. Matching old pair restores can replenish quota; arbitrary containment, source authority and journal admission remain separate gates.

Owned observations now require an explicitly selected finite worker pool. Stores sharing the same physical slots cannot start more admitted invocations than its fixed capacity; saturation writes nothing and charges no attempt. The guard and selected worker retain a third slot reference, including after guard death. Store v3 binds the pool profile and quarantines old v1/v2 pairs without migration. Matching profiles in different physical pools still admit independent work. CPU/memory accounting, cumulative rate, fairness, trusted pool enrollment and clone/restore protection remain unresolved.

A separate opt-in Linux experiment now lowers explicit per-process CPU and virtual address-space caps before exec, checks exact readback and disables core dumps. Missing policy, unsupported host or incomplete setup runs no selected entry and never falls back. Both ownership references and the shared slot survive exec. macOS rejects this profile; it supplies no portable RSS guarantee. The ordinary v3 store still selects admitted work. A separate explicit v4 entry now binds the requested resource profile in SQLite/checkpoint storage, rejects mode or policy mismatch before SQLite opens, and dispatches only limited work. Aggregate budgets, fairness, capability isolation and independent assessment remain separate gates.

The v4 store now has a separate nineteen-cut SIGKILL matrix for initial creation,
admission/result publication and pending recovery. Real SQLite hot journals
reject cross-mode/resource choices before connect, without changing either file
or the sidecar. Python discovery uses synthetic verdicts; macOS also simulates
only host selection. A separate Linux qualifier requires actual limited Rust
verification before result/recheck loss and tests interrupted recovery. This
changes qualification only and supplies no power-loss or funded-swap guarantee.

Controlled storage faults now distinguish actual rollback, committed database
change with an old checkpoint, and a consistent pair after replacement. Failed
live handles retain store ownership and reject reads/retries while releasing the
caller slot; matched reopen preserves charge and earlier normal evidence without
replay. API failures are synthetic. Separate disposable-writer cases require
actual kernel file-size refusal, including an actual Rust positive before the
Linux result-side fault. Native I/O errors, power loss and independent assessment
remain open; application behavior and the frozen review subject are unchanged.

## Repository boundaries

| Component | Responsibility |
| --- | --- |
| This repository | Protocol specification, offline experiments, and later reference-client session and recovery logic |
| A coordinated `go-zenon` contribution | PTLC contract behavior, RPC, encoding policy, activation, and contract tests |
| The selected SDK | Typed contract calls and wire representations |

The core contract proposal is [go-zenon PR #13](https://github.com/zenon-network/go-zenon/pull/13). Its signature verifier is a building block, not a complete atomic-swap protocol. Existing HTLC support is the comparison baseline for deciding whether PTLC's incremental benefits justify the additional work.

## Read first

1. [Scope and milestones](docs/SCOPE.md)
2. [Draft protocol requirements](docs/PROTOCOL.md)
3. [Threat model](docs/THREAT_MODEL.md)
4. [Cryptography candidates and selection gates](docs/CRYPTOGRAPHY.md)
5. [Pinned evidence and verification limits](docs/EVIDENCE.md)
6. [Local validation and intermediate issues](docs/VALIDATION.md)
7. [Selected offline transaction graph](docs/TRANSACTION_GRAPH.md)
8. [Stage 1 results and limits](docs/STAGE1_VALIDATION.md)
9. [Core integration boundary and acceptance backlog](docs/CORE_INTEGRATION.md)
10. [Offline session and journal design](docs/SESSION_JOURNAL.md)
11. [Stage 2 validation and intermediate findings](docs/STAGE2_VALIDATION.md)
12. [Public nonce rounds and ephemeral ownership](docs/NONCE_ROUNDS.md)
13. [Stage 3 validation and limits](docs/STAGE3_VALIDATION.md)
14. [Managed public artifact exchange](docs/ARTIFACT_EXCHANGE.md)
15. [Stage 4 validation and intermediate findings](docs/STAGE4_VALIDATION.md)
16. [Alice completion and Bob public recovery](docs/COMPLETION_LIFECYCLE.md)
17. [Stage 5 validation and intermediate findings](docs/STAGE5_VALIDATION.md)
18. [Explicit completion observation reconciliation](docs/OBSERVATION_RECONCILIATION.md)
19. [Stage 6 validation and remaining gates](docs/STAGE6_VALIDATION.md)
20. [Bounded public worker transport](docs/PUBLIC_WORKERS.md)
21. [Stage 7 validation and remaining gates](docs/STAGE7_VALIDATION.md)
22. [Durable Bob recovery admission](docs/RECOVERY_ADMISSION.md)
23. [Stage 8 validation and remaining gates](docs/STAGE8_VALIDATION.md)
24. [Offline completion-envelope authentication](docs/COMPLETION_AUTHENTICATION.md)
25. [Stage 9 validation and remaining gates](docs/STAGE9_VALIDATION.md)
26. [Durable local authentication pins](docs/DURABLE_AUTHENTICATION_PINS.md)
27. [Stage 10 validation and remaining gates](docs/STAGE10_VALIDATION.md)
28. [Bounded recovery admission and observation model](docs/RECOVERY_ADMISSION_MODEL.md)
29. [Stage 11 validation and remaining gates](docs/STAGE11_VALIDATION.md)
30. [Public signature candidate construction](docs/PUBLIC_SIGNATURE_CANDIDATES.md)
31. [Stage 12 validation and remaining gates](docs/STAGE12_VALIDATION.md)
32. [Independent review brief and exact subject](docs/INDEPENDENT_REVIEW.md)
33. [Unfilled assessment report template](docs/REVIEW_REPORT_TEMPLATE.md)
34. [Stage 13 packaging validation and remaining gates](docs/STAGE13_VALIDATION.md)
35. [Selected model/journal correspondence](docs/RECOVERY_MODEL_CORRESPONDENCE.md)
36. [Stage 14 validation and remaining gates](docs/STAGE14_VALIDATION.md)
37. [Offline public recovery reserve experiment](docs/RECOVERY_RESERVE_MODEL.md)
38. [Stage 15 validation and remaining gates](docs/STAGE15_VALIDATION.md)
39. [Exact public authority and inner-validity experiment](docs/PUBLIC_OBSERVATION_MODEL.md)
40. [Stage 16 validation and remaining gates](docs/STAGE16_VALIDATION.md)
41. [Exact observation evidence contract](docs/OBSERVATION_EVIDENCE_CONTRACT.md)
42. [Stage 17 validation and remaining gates](docs/STAGE17_VALIDATION.md)
43. [Explicit local observation verifier and trust boundary](docs/OBSERVATION_VERIFIER.md)
44. [Stage 18 validation and remaining gates](docs/STAGE18_VALIDATION.md)
45. [Bounded observation attempts and claim records](docs/OBSERVATION_RECORDS.md)
46. [Stage 19 validation and remaining gates](docs/STAGE19_VALIDATION.md)
47. [Separately owned offline observation records](docs/OBSERVATION_STORE.md)
48. [Stage 20 validation and remaining gates](docs/STAGE20_VALIDATION.md)
49. [Owned observation worker leases and guard](docs/OBSERVATION_LEASES.md)
50. [Stage 21 validation and remaining gates](docs/STAGE21_VALIDATION.md)
51. [Shared admission for owned observation workers](docs/SHARED_WORKER_ADMISSION.md)
52. [Stage 22 validation and remaining gates](docs/STAGE22_VALIDATION.md)
53. [Explicit resources for one admitted public worker](docs/WORKER_RESOURCE_LIMITS.md)
54. [Stage 23 validation and remaining gates](docs/STAGE23_VALIDATION.md)
55. [Durable explicit worker resource selection](docs/DURABLE_RESOURCE_POLICY.md)
56. [Stage 24 validation and remaining gates](docs/STAGE24_VALIDATION.md)
57. [Explicit resource-store process-death cuts](docs/RESOURCE_STORE_CRASH_CUTS.md)
58. [Stage 25 validation and remaining gates](docs/STAGE25_VALIDATION.md)
59. [Explicit resource-store storage failures](docs/RESOURCE_STORE_FAULTS.md)
60. [Stage 26 validation and remaining gates](docs/STAGE26_VALIDATION.md)
61. [Separate pinned observation-layer review brief](docs/OBSERVATION_REVIEW.md)
62. [Unfilled observation-layer assessment report](docs/OBSERVATION_REVIEW_REPORT_TEMPLATE.md)
63. [Stage 27 packaging validation and remaining gates](docs/STAGE27_VALIDATION.md)
64. [Explicit v4 restore and copied-history boundaries](docs/RESOURCE_STORE_RESTORES.md)
65. [Stage 28 validation and remaining gates](docs/STAGE28_VALIDATION.md)
66. [Observation freshness and dispatch authority comparison](docs/OBSERVATION_AUTHORITY_MODEL.md)
67. [Stage 29 validation and remaining gates](docs/STAGE29_VALIDATION.md)
68. [Candidate observation authority scope and message contract](docs/OBSERVATION_AUTHORITY_CONTRACT.md)
69. [Stage 30 validation and remaining gates](docs/STAGE30_VALIDATION.md)
70. [Canonical observation enrollment and quota ownership comparison](docs/OBSERVATION_ENROLLMENT_MODEL.md)
71. [Stage 31 validation and remaining gates](docs/STAGE31_VALIDATION.md)
72. [Candidate retained-resource key and unsigned enrollment intent](docs/RETAINED_RESOURCE_INTENT.md)
73. [Stage 32 validation and remaining gates](docs/STAGE32_VALIDATION.md)
74. [Public enrollment signatures and authority limits](docs/PUBLIC_ENROLLMENT_SIGNATURES.md)
75. [Stage 33 validation and remaining gates](docs/STAGE33_VALIDATION.md)
76. [Independent Go enrollment signature checks](docs/INDEPENDENT_ENROLLMENT_SIGNATURES.md)
77. [Stage 34 validation and remaining gates](docs/STAGE34_VALIDATION.md)
78. [Explicit local governor-role profiles and bootstrap limits](docs/LOCAL_GOVERNOR_PROFILE.md)
79. [Stage 35 validation and remaining gates](docs/STAGE35_VALIDATION.md)
80. [Finite governor provenance and current-policy comparison](docs/GOVERNOR_AUTHORITY_MODEL.md)
81. [Stage 36 validation and remaining gates](docs/STAGE36_VALIDATION.md)
82. [Unsigned governor assignment and v2 intent bindings](docs/GOVERNOR_ASSIGNMENT_CONTRACT.md)
83. [Stage 37 validation and remaining gates](docs/STAGE37_VALIDATION.md)
84. [Public issuer and v2 owner signature qualification](docs/GOVERNOR_SIGNATURE_QUALIFICATION.md)
85. [Stage 38 validation and remaining gates](docs/STAGE38_VALIDATION.md)

## Run the offline checks

Requirements: Python 3.11 or later with SQLite, a POSIX host supporting advisory file locks, Git supporting `--no-lazy-fetch` and `--no-replace-objects`, and OpenSSL with Ed25519 verification support. The complete suite includes probes requiring numeric SQLite error APIs; older Python validation snapshots cover their recorded scopes only. Acquire the two pinned source objects in the [review reproduction instructions](docs/OBSERVATION_REVIEW.md#reproduce-source-identity-offline) before discovery in a shallow checkout. Session tests target local Linux/macOS filesystems; only the platforms actually executed in the validation report are established. No Python packages, node software, credentials, or network access are required by the tests after acquisition. OpenSSL is an independent test verifier, not a selected application dependency. Artifact-checker tests use temporary Git repositories without configuring an identity or making commits; review-inventory tests write synthetic commit objects with explicit fixture metadata and no installed identity or hooks.

```sh
REQUIRE_OPENSSL=1 python3 -m unittest discover -s tests -v
python3 scripts/check_artifacts.py
python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c
python3 scripts/model_swap.py --help
python3 scripts/model_recovery_admission.py --help
python3 scripts/model_recovery_reserve.py --help
python3 scripts/model_public_observation.py --help
python3 scripts/model_observation_authority.py --help
```

The required mode must fail if independent OpenSSL verification cannot run. Any optional run that skips that verifier is incomplete evidence. The CI definition uses required mode; preparing that definition does not establish that hosted CI has run.

The test-only Ed25519 arithmetic is deliberately separate from the BIP340/secp256k1 qualification harness. Demonstrating a flaw in the historical Ed25519 demo does not validate a BIP340 replacement.

The [Rust harness](qualification/README.md) pins two adaptor candidates and rust-bitcoin with a dependency lockfile. The [core-verifier Go harness](qualification-go/README.md) checks public completed signatures using the exact BIP340 dependency version in PR #13. The separate [Bitcoin Go harness](qualification-bitcoin-go/README.md) checks transaction bytes, Taproot commitments, sighashes and script execution. After populating their dependency caches, run from the repository root:

```sh
cargo test --locked --offline --manifest-path qualification/Cargo.toml
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-go test -mod=readonly -count=1 -v ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go -C qualification-bitcoin-go test -mod=readonly -count=1 -v ./...
```

The core-verifier harness is compatibility evidence for a historical verifier version; it is not a node or contract test. Toolchain versions, test results, model bounds and unresolved integration work are recorded in the Stage 1 report.

To run the separate Python-to-Rust public-verifier integration after fetching the locked dependencies:

```sh
cargo build --locked --offline --manifest-path qualification/Cargo.toml --examples
python3 -B scripts/qualify_exchange.py --verifier qualification/target/debug/examples/verify_exchange
python3 -B scripts/qualify_completion.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_authentication.py --authentication qualification/target/debug/examples/verify_authentication --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_enrollment_signature.py --enrollment qualification/target/debug/examples/verify_enrollment --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_governor_profile.py --enrollment qualification/target/debug/examples/verify_enrollment --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_governor_signature.py --governor qualification/target/debug/examples/verify_governor --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_recovery_model.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
python3 -B scripts/qualify_observation.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange --observation qualification/target/debug/examples/verify_observation
python3 -B scripts/qualify_observation_records.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange --observation qualification/target/debug/examples/verify_observation
python3 -B scripts/qualify_observation_store.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange --observation qualification/target/debug/examples/verify_observation
python3 -B scripts/qualify_worker_resources.py --verifier qualification/target/debug/examples/verify_exchange --observation qualification/target/debug/examples/verify_observation
python3 -B scripts/qualify_observation_resource_store.py --verifier qualification/target/debug/examples/verify_exchange --observation qualification/target/debug/examples/verify_observation
```

Use the corresponding executable paths if `CARGO_TARGET_DIR` is set. These checks use temporary public journals, fixture artifacts and explicitly selected local executables. Ordinary Python tests use clearly labeled fake callbacks for sequencing and do not require Rust. Journal storage v7 quarantines older v1-v6 state without migration; incoming Bob releases require v2 packets with both partials. Starting managed Bob exchange requires an explicit `recovery_limit` from 1 through 64. Optional `authentication_pins` are copied at that start and cannot be added, changed or removed later; omitting them is also a frozen choice.

Both resource qualifiers require an unprivileged supported Linux host. On macOS,
the resource platform cases assert explicit refusal and do not execute Linux
enforcement probes. Local refusal and configured CI supply no Linux execution
evidence; completed exact-head hosted results must be reported separately.

## Next milestone

Obtain scoped independent assessments of the original construction subject in the [review brief](docs/INDEPENDENT_REVIEW.md) and the separate exact subject in the [observation brief](docs/OBSERVATION_REVIEW.md). Record assumptions, findings, examined dependencies and excluded surfaces in their distinct unfilled reports. Both assessments are pending; later changes need an explicit delta assessment. This package prepares that work without introducing private signing, node access or reviewer outreach.

Use the bounded admission model's counterexamples to define an explicit public-observation authorization and exhaustion/recovery policy before enforcing an envelope requirement or adding transport. The baseline model's finite shared allowance still permits recovery blockage; no safe funded policy has been selected. Durable local pin selection is available; trustworthy pin establishment remains external. Preserve a separately reviewed authorization path for public-witness recovery: Alice may reveal the Zenon signature while withholding an auxiliary authentication envelope. Observation selection, evidence retention, pin provisioning/rotation and aggregate verification-rate control remain unresolved. Connect a reviewed private signing worker only after resolving fresh entropy, secret memory, restored-copy protection, and its journal boundary. Restoring both matching database/checkpoint copies can still permit another synthetic Alice producer call or replenish Bob's allowance. Independent construction review, authenticated chain observations and funding/time authorization remain prerequisites for a current-node PTLC port and two-party regtest/devnet work.

The [reserve comparison](docs/RECOVERY_RESERVE_MODEL.md) narrows that policy decision: protected attempts alone do not guarantee recovery. Any reliance on bounded public interruptions or eventual worker availability needs a separately specified, implementable and reviewed mechanism before changing the journal or funding a swap.

The [public-observation comparison](docs/PUBLIC_OBSERVATION_MODEL.md) further separates observation authority from inner validity. Specify exact evidence, context bindings, trust assumptions, mathematical verification and aggregate resource handling before treating any source or local authorization as a recovery guarantee.

The [observation-evidence contract](docs/OBSERVATION_EVIDENCE_CONTRACT.md) makes the exact target and outcome vocabulary concrete. The [local producer](docs/OBSERVATION_VERIFIER.md) adds explicit normal verdicts under a caller-provisioned executable pin and trusted host. Review that error partition and provisioning separately, then specify durable attempt/evidence ordering and aggregate resource policy before connecting a negative cache or admission decision. Legacy errors, received claims, matching hashes and profile labels supply no such trust.

The [record contract](docs/OBSERVATION_RECORDS.md) defines bounded attempt/claim transitions. The [separate local disk backend](docs/OBSERVATION_STORE.md) qualifies record ownership and pending-before-worker/result-before-return persistence, including process death, inherited handles and inconsistent restores. [Worker-held leases](docs/OBSERVATION_LEASES.md) add cooperative lifetime exclusion and owner monitoring; [shared admission](docs/SHARED_WORKER_ADMISSION.md) limits simultaneous work only among participants selecting the same physical pool. Assess this exact producer/storage/guard/pool delta, then specify CPU/memory and rate policy, fairness, trusted enrollment, arbitrary worker containment, source authority and external restore handling before connecting recovery policy. Pure canonical records, matching pool profiles, file hashes and fixture results supply no independent truth, power-loss or anti-clone proof.

All checked-in content is English and contains no user identity or private operational data. The artifact checker detects a limited set of accidental disclosures; source, metadata, and destination still require review before publication.

The [resource experiment](docs/WORKER_RESOURCE_LIMITS.md) supplies explicit Linux
per-process maxima. [Durable v4 selection](docs/DURABLE_RESOURCE_POLICY.md) now
binds the requested profile and rejects cross-mode/policy reopen before SQLite
access. The [v4 process-death matrix](docs/RESOURCE_STORE_CRASH_CUTS.md) and
[storage-fault qualification](docs/RESOURCE_STORE_FAULTS.md) now make those
boundaries separately reviewable. The [separate pinned subject](docs/OBSERVATION_REVIEW.md)
now prepares assessment of the observation, ownership, pool and resource deltas,
preserving the original subject and unresolved native storage, restore and source
obligations. Its complete inventory and checker supply source identity only.
The [v4 restore experiments](docs/RESOURCE_STORE_RESTORES.md) separately qualify
coherent rewind and copied-history limits without adding protection. This later
qualification delta lies outside both fixed subjects and needs explicit assessment.
The [authority comparison](docs/OBSERVATION_AUTHORITY_MODEL.md) turns that
restore boundary into explicit enrollment, freshness, receipt and dispatch
requirements. Its finite ideal premises select no backend, impose no application
authority and guarantee no funded recovery or physical worker containment.
The [candidate authority contract](docs/OBSERVATION_AUTHORITY_CONTRACT.md) makes
scope, full-head expectations, operation phases and reply-claim bindings concrete
without implementing those ideal premises. Review canonical enrollment,
authenticated latest-head evidence, scoped idempotency and durable one-use entry
before selecting a backend or using a parsed reply for any admission decision.
The [enrollment comparison](docs/OBSERVATION_ENROLLMENT_MODEL.md) separates those
first premises: independently trusted resource equivalence and owner facts,
atomic uniqueness, exact duplicate lookup and non-rollbackable charge lineage.
Define and assess their actual mechanisms before using any scope digest as a
quota key. Its charges are abstract reservations, not worker entries or proof
of a funded recovery policy.
Virtual address space is not RSS, and per-process caps supply no cumulative rate,
fairness, capability isolation or funded availability proof.

Assess the [candidate retained-resource class](docs/RETAINED_RESOURCE_INTENT.md)
and [public enrollment signature verifier](docs/PUBLIC_ENROLLMENT_SIGNATURES.md)
separately. Define authenticated economic/source equivalence, independently trusted
governor pins, role/namespace identity and first-registration policy before allocation.
Matching unsigned bytes, valid signatures and sender authentication supply no
enrollment role. Atomic uniqueness, non-rollbackable
charged lineage, scoped idempotency and unique dispatch remain later gates.

The [independent Go checks](docs/INDEPENDENT_ENROLLMENT_SIGNATURES.md) reconstruct
the unchanged public enrollment messages and verify their mathematics with a
separate implementation. Cross-verifier agreement supplies no independent
security assessment or governor/source trust. Define and assess bootstrap/role
policy and canonical source authority before selecting an enrollment backend.

The [explicit local governor profile](docs/LOCAL_GOVERNOR_PROFILE.md) supplies
proposal matching, with independently chosen rules as an external trust premise.
Select and assess governor provisioning/role provenance, binding to the current
policy and rotation/revocation before selecting an enrollment backend. Profile
equality and the old valid signature do not implement these mechanisms; replay,
coherent profile restore, first-registration capture and namespace quota splits
remain outside this helper. Keep later uniqueness and charged lineage separate.

Use the [governor model](docs/GOVERNOR_AUTHORITY_MODEL.md) to specify independently
authenticated provisioning, complete role/scope/policy evidence and the exact
authorization instant before selecting another credential or wire format. Define
current-state evidence and outage, compromise, rotation/revocation and coherent
restore behavior. The model's root and current oracle are assumptions; its
strongest finite gate is neither a backend nor a one-use dispatcher. Preserve
the unchanged v1 intent while separately qualifying any future profile binding.

## License and participation

Original project contributions are available under the [MIT License](LICENSE).
Identified third-party fixtures and external dependencies retain their own terms;
see [third-party notices](THIRD_PARTY_NOTICES.md) for sources and attribution.
The crate's `publish = false` setting remains in place: this repository is a
research snapshot, not a published production cryptography package.

See [contribution guidance](CONTRIBUTING.md) for review priorities and validation
requirements, and the [security policy](SECURITY.md) for limitations and reporting.

The [Stage 37 unsigned assignment contract](docs/GOVERNOR_ASSIGNMENT_CONTRACT.md)
binds an independently selected issuer and complete governor profile into
separate candidate bytes. A new nine-field unsigned v2 intent commits the full
assignment digest, so broader local caps change its message under the same old
scope and owner. This introduces no credential signature, current-state source,
migration, registry or worker admission. The old v1 messages and public signature
fixture remain unchanged. [Validation](docs/STAGE37_VALIDATION.md) reports the
corrected first test run and executed unsigned-framing evidence.

[Stage 38 public verification](docs/GOVERNOR_SIGNATURE_QUALIFICATION.md) now
checks the issuer assignment and owner v2 message separately through the locked
Rust library, with independent Go checks and an actual bounded-worker qualifier.
Both signatures bind the complete request/result, but establish no trusted issuer
provisioning, current authority or permission. A raw valid signature pair cannot
decode an opaque scope hash or enforce its caps; complete independently prepared
expectations check these before work. Stale selections, replay and a malicious
selected verifier remain explicit counterexamples. No existing admission path
requires this helper. [Validation](docs/STAGE38_VALIDATION.md) records the first
Go cache-selection setup failure and executed evidence. Current-state/use ordering
and separate independent review remain gates before any runtime integration.

[Stage 39 current-authority requirements](docs/CURRENT_AUTHORITY_EVIDENCE.md)
separate independently provisioned source/root identity, policy checkpoints and
current-use ordering. A new pure query binds those selected inputs to both public
signatures and the complete decoded scope/resource. Its active, revoked, absent
and unavailable replies are forgeable read claims; matching them establishes no
current authority or permission. Coherent old-context restore and request replay
remain possible. No source backend, authenticator, clock, storage or admission
integration is selected. [Validation](docs/STAGE39_VALIDATION.md) reports directed
counterexamples and required offline checks. Define and independently assess the
actual source and protected-use instant before implementing a source adapter.

[Stage 40 policy-source/use comparison](docs/POLICY_SOURCE_USE_MODEL.md) separates
current policy reads, durable operation charging, lost-reply reconciliation and
abstract entry. Commit and entry cutoffs give different revocation behavior;
both are conditional candidates. Current policy alone does not prevent repeat
charge/entry after source-ledger restore, and different operation IDs need not
mean distinct business intent. The pure model adds no source backend, dispatch,
worker fence or application gate. Run its directed tests and eight selected CLI
comparisons using the documented commands; they do not explore the full action
graph. [Validation](docs/STAGE40_VALIDATION.md) separates local and hosted checks.
Offline comparison remains GO; current-authority integration and funded/core
activity remain NO-GO.

[Stage 41 isolated SQLite qualification](docs/OFFLINE_POLICY_EFFECT_STORE.md)
selects one local ordering construction: policy, retained allocations and a
synthetic effect share one database. Strict revision/profile checks precede the
effect commit; native process deaths and writer contention test that boundary.
The effect is a database row, with no authentication or physical-entry gate.
Coherent database restore and copies remain successful unsafe controls. Existing
runners and cryptographic admission are unchanged. [Validation](docs/STAGE41_VALIDATION.md)
separates native evidence, synthetic fault controls and open integration gates.

## Stage 42 isolated root statement

The [source root role candidate](docs/SOURCE_ROOT_ROLE_QUALIFICATION.md) qualifies
complete historical declaration signatures under independently selected bytes.
Five distinct key encodings do not prove independent control; valid old statements
and restored/copy selections still replay. No source service, administrator
authentication, SQLite or physical-use connection is added. See the [Stage 42
validation](docs/STAGE42_VALIDATION.md) for execution evidence and failures.
Both fixed independent assessments remain unfilled; source integration, core port,
private signing and funded execution remain NO-GO.

## Stage 43 isolated administrator commands

The [administrator command candidate](docs/SOURCE_ADMIN_COMMAND_QUALIFICATION.md) permits
only strict cap reduction and profile-preserving revocation under an independently
selected rule. Historical signatures do not read current revisions or apply a
command to any source/store. Replay and coherent restoration still succeed.
See [validation](docs/STAGE43_VALIDATION.md); source integration and production use remain NO-GO.

## Stage 44 isolated source response signatures

The [response signature candidate](docs/SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md)
binds the complete root, checkpoint query, response role and observation claim.
It checks four historical signatures without a current-policy lookup. Old or
coherently restored selections still replay; a new challenge can be signed over
old active state. See [validation](docs/STAGE44_VALIDATION.md). Source integration,
core port and production use remain NO-GO; independent assessments stay unfilled.

## Stage 45 local source read ordering

The [local snapshot experiment](docs/LOCAL_SOURCE_READ_ORDERING.md) serializes an
unsigned complete policy read with owned SQLite mutations and preserves original
operation charges. The response can age before return; coherent database restore
and copies still repeat reads and synthetic effects. Original-operation
association is unsigned and physical entry remains unimplemented. Eleven older
test-only SQLite contexts now close after commit/rollback. See
[validation](docs/STAGE45_VALIDATION.md); authenticated source integration, core
port and production use remain NO-GO.

## Stage 46 original-operation read framing

The [separate original-read contract](docs/ORIGINAL_OPERATION_READ_CONTRACT.md)
binds the complete original id/revision/profile/proposal, source/root, independently
selected policy and record positions, and challenge. Historical original profile
and current policy remain distinct; absent/pending/completed/unavailable claims
are explicit. This is unsigned framing with no source adapter, signature worker,
recovery permission or physical-use gate. Coherent copies/restores and freshly
challenged old state still match. See [validation](docs/STAGE46_VALIDATION.md);
authenticated source integration, core port and production use remain NO-GO.

## Stage 47 isolated original-read response signatures

The [historical original-response candidate](docs/ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md)
binds complete original identity, historical profile and both selected policy/record
positions under a new tagged response domain. Locked Rust and separate Go public
checks verify two historical signatures; old schemas and workers stay unchanged.
Fresh challenges, self-selected collisions and coherent source copies/restores
still expose unsafe limits. No source service, signer, lookup permission or recovery
adapter is connected. See [validation](docs/STAGE47_VALIDATION.md); source integration,
core port and production use remain NO-GO.

## Stage 48 owned local original-read snapshot

The [historical local snapshot experiment](docs/ORIGINAL_READ_SNAPSHOT_QUALIFICATION.md)
returns the existing complete original-read grammar from actual retained SQLite
rows. Both selected heads and the old profile's retained policy row are checked
in one owned transaction. Native ordering/death controls preserve original
charges; coherent replacement, restore/copy and delayed returns remain explicit
unsafe boundaries. No signer, authenticated source or recovery adapter is connected.
See [validation](docs/STAGE48_VALIDATION.md); source integration, core port and
production use remain NO-GO.

## Stage 49 test-only signature binding of owned snapshots

The [sample-to-message qualification](docs/ORIGINAL_READ_SNAPSHOT_SIGNATURE_BINDING.md)
recreates ten actual local-store scenarios and binds their exact bytes to the
existing historical signature grammar. A separate Rust test generates public
synthetic signatures; Python and Go reuse existing public checks. Six validly
signed counterclaims still expose false state, conflicting originals and stale
heads. No application signer or source service is introduced. See
[validation](docs/STAGE49_VALIDATION.md); source integration, recovery, core port
and production use remain NO-GO.

## Stage 50 original-read provenance and delivery model

The [isolated finite model](docs/ORIGINAL_READ_PROVENANCE_MODEL.md) compares peer
selection, query binding and complete owned-snapshot binding against six signed
counterclaims. Separate delivery and abstract entry events expose stale reads,
source restore and repeated entry. Ideal current facts and nonrollback entry
history are external premises, with no implemented adapter or recovery permission.
See [validation](docs/STAGE50_VALIDATION.md); source integration, core port and
production use remain NO-GO.

## Stage 51 test-only complete retained opening

The [synthetic opening experiment](docs/ORIGINAL_SNAPSHOT_OPENING.md) derives an
unsigned original-read claim from complete retained rows that must open both
independently selected diagnostic heads. It separates claim consistency from
authenticated current heads and nonrollback retention. Full-row disclosure is
test-only, with no application source, signer, lookup or recovery integration.
See [validation](docs/STAGE51_VALIDATION.md); operational use remains NO-GO.

## Stage 52 test-only retained-prefix comparison

The [synthetic prefix experiment](docs/ORIGINAL_SNAPSHOT_PREFIX.md) compares two
complete openings against their independently selected diagnostic heads and
requires the earlier events, policies, complete originals and charges to remain
retained. Coherent truncation and rewritten prior rows refuse relative to a
retained witness; competing futures, stale extensions and restored witnesses
remain explicit limits. No application witness store, source, signer, lookup or
recovery adapter is added. See [validation](docs/STAGE52_VALIDATION.md);
operational use remains NO-GO.

## Stage 53 test-only signed retained histories

The [public-response composition](docs/ORIGINAL_SNAPSHOT_PREFIX_RESPONSE.md)
derives both complete historical expectations before invoking the existing
public signature checker. Two actual signed fork futures can both extend one
pending witness; stale and restored histories still expose currentness and
consumer-retention limits. No application source, witness store, signer, lookup,
recovery or use adapter is added. See [validation](docs/STAGE53_VALIDATION.md);
operational use remains NO-GO.

## Stage 54 bounded consumer retention

The [two-consumer model](docs/ORIGINAL_CONSUMER_RETENTION_MODEL.md) separates
retaining a historical prefix from selecting a common canonical future. It
compares delayed fork deliveries, old challenged absence, source restore and
consumer restore against an explicitly ideal nonrollback witness. No application
retention backend or authority protocol is selected. See
[validation](docs/STAGE54_VALIDATION.md); operational use remains NO-GO.

## Test-only owned witness transaction

The [owned witness experiment](docs/ORIGINAL_WITNESS_STORE_EXPERIMENT.md) compares
and retains complete signed histories under one bounded SQLite writer
transaction. Native contention/death and copied-state counterexamples are
qualified separately from historical signature mathematics. It selects no
application storage or nonrollback/canonical authority. See
[Stage 55 validation](docs/STAGE55_VALIDATION.md).

## Test-only witness creation and interruption

The [lifecycle experiment](docs/ORIGINAL_WITNESS_LIFECYCLE_EXPERIMENT.md) qualifies
selected creation, inherited ownership and cancellation cuts in the isolated
witness helper. Partial creation refuses automatic repair; post-commit
cancellation can leave history persisted without a command result. Recreated
paths and coherent copies still lose retained knowledge. See
[Stage 56 validation](docs/STAGE56_VALIDATION.md); application integration and
independent source/nonrollback gates remain open.

## Stage 57 separate witness review package

The [witness review brief](docs/WITNESS_REVIEW.md) fixes the complete accepted
360-file source without extending the earlier 119/189-file subjects. The new
[report template](docs/WITNESS_REVIEW_REPORT_TEMPLATE.md) remains unfilled.
Source identity and hosted qualification are distinct from independent
assessment. See [validation](docs/STAGE57_VALIDATION.md); application and core
progression remain NO-GO.

## Offline dependency and worker input evidence

The [input evidence entry](docs/OFFLINE_BUILD_INPUTS.md) separately checks fixed
source records, selected cached registry archives and caller-selected native
bytes. Installed dependency trees and source-to-binary provenance remain open;
all three assessment reports are unfilled. See
[Stage 58 validation](docs/STAGE58_VALIDATION.md). Application/core NO-GO remains.

## Selected installed dependency contents

The [content comparison](docs/OFFLINE_DEPENDENCY_CONTENTS.md) adds complete selected
registry/Git tree comparison and declared Go content hashing against fixed source
records. Cache metadata cannot choose replacement expectations. This measures
content agreement; build provenance and independent review remain open. See
[Stage 59 validation](docs/STAGE59_VALIDATION.md). Application/core remains NO-GO.

## Selected Cargo resolution records

The [resolution comparison](docs/OFFLINE_CARGO_RESOLUTION.md) binds a bounded
workspace metadata claim to fixed lock identities, measured source locations and
a separately selected project baseline. Package IDs remain opaque; private
metadata is discarded. The prepared source copy and native metadata query are
separate operations. A matching claim is not authenticated resolution, exact
worker compilation or source-to-binary provenance. See
[Stage 60 validation](docs/STAGE60_VALIDATION.md); all assessments remain unfilled
and application/core remains NO-GO.

## Selected worker build artifact claims

The [build-record comparison](docs/OFFLINE_WORKER_BUILD_RECORDS.md) binds the
selected example's bounded Cargo claims to fixed source declarations and
explicitly selected executable bytes. Its read-only checker is separate from
the explicit fresh native build and public-math qualification. Forgeable records
and omitted dependency artifacts do not establish generator authentication,
complete compilation units or independent source-to-worker provenance. See
[Stage 61 validation](docs/STAGE61_VALIDATION.md); all assessments remain unfilled
and application/core remains NO-GO.

## Selected private-prefix and artifact-byte observations

The [artifact comparison](docs/OFFLINE_ARTIFACT_PREFIXES.md) reads two explicitly
pinned files and reports whole-stream byte agreement plus presence of four
privately selected exact byte prefixes per file. It emits only fixed logical
roles and artifact measurements. Neither equal bytes nor absent selected
prefixes proves provenance, reproducibility or complete privacy; both artifacts
remain private. See [Stage 62 validation](docs/STAGE62_VALIDATION.md); all
assessments remain unfilled and application/core remains NO-GO.

## Separate target-only Rust path remapping experiment

The [selected remapping profile](docs/OFFLINE_RUST_PATH_REMAPPING.md) builds two
fresh fixed-source workers with four explicit directory rules, then compares
complete bytes and private-prefix presence. Its extra Rust flags cover target
compilation; host build-script/proc-macro compilation and C/linker/support inputs
remain incompletely assessed. Both binaries remain private under every result.
See [Stage 63 validation](docs/STAGE63_VALIDATION.md); all assessments remain
unfilled and application/core remains NO-GO.

## Bounded worker section localization

The [selected read-only construction](docs/OFFLINE_WORKER_SECTION_LOCALIZATION.md)
adds fixed raw section-group observations for retained private outputs. See
[Stage 64 validation](docs/STAGE64_VALIDATION.md). No producer attribution,
privacy qualification, new compiler flags or application/core permission is
supplied; all earlier constructions and unfilled assessments remain intact.

## Bounded worker symbol-name references

The [selected reference reader](docs/OFFLINE_WORKER_SYMBOL_REFERENCES.md) adds
fixed name-reference classes after raw section localization. See
[Stage 65 validation](docs/STAGE65_VALIDATION.md). Declared name indices/types
supply no producer or source identity; all outputs remain private and all three
independent assessments remain unfilled. Application/core remains NO-GO.

## Bounded worker debug-pool and source-STAB names

The [selected debug-name reader](docs/OFFLINE_WORKER_DEBUG_NAMES.md) refines
private observations with terminated ELF string-pool entries and declared Mach-O
source-STAB references. See [Stage 66 validation](docs/STAGE66_VALIDATION.md).
No DWARF reference or source/producer identity is authenticated. Artifacts remain
private; independent assessments remain unfilled and application/core stays NO-GO.

## Separate C debug-prefix research profile

The [selected C profile](docs/OFFLINE_C_DEBUG_REMAPPING.md) adds two fresh private
builds alongside the preserved target-only Rust experiment. See
[Stage 67 validation](docs/STAGE67_VALIDATION.md). Complete measurements and fixed
classes authenticate no producer or privacy improvement. All three assessments
remain unfilled; artifacts stay private and application/core remains NO-GO.

Stage 68 adds [retained C-worker symbols](docs/OFFLINE_C_WORKER_SYMBOLS.md) and
[its validation scope](docs/STAGE68_VALIDATION.md). One private canonical C carrier
is checked before two retained streams. Existing symbol/debug/section grammars
run in memory; no new native build or worker is selected. Complete carrier and
declared-type agreement authenticate no producer or historical execution.
Artifacts remain private; application/core progression remains NO-GO.


## Stage 69: separate Mach-O object-prefix qualification

See [selected construction](docs/OFFLINE_MACHO_OBJECT_PREFIX.md) and [validation scope](docs/STAGE69_VALIDATION.md). One explicit linker prefix supplements the unchanged Rust/C rules in two fresh Apple builds. The preceding seven hosted jobs remain intact; an additional native Apple job qualifies the separate profile and public mathematics. All observations and inputs remain private; no absence, equality, producer identity or artifact release is required or proven. All three independent reports remain unfilled. Application and core progression remain NO-GO.


## Stage 70: immutable worker-profile review packet

The [acceptance packet](docs/WORKER_PROFILE_REVIEW.md) pins all 423 tracked files at the exact Stage 69 source, preserves three earlier inventories and unfilled reports, and separates historical profiles from later packaging. The new checker inventories source only; it authenticates no producer, consumed argument, private artifact or future use. Independent review and privacy remain NOT ASSESSED; application and core remain NO-GO. See [validation](docs/STAGE70_VALIDATION.md).

## Nonce invocation acceptance gap

[Stage 71](docs/NONCE_INVOCATION_MODEL.md) adds a source-only finite comparison
of consumption before nonce-dependent work. Copied local journals, result-only
fencing, split check/burn and restored authority produce replayable
counterexamples. The reference policy assumes a shared atomic durable consume
authority outside copied state; it implements no custody mechanism or signer.
[Validation](docs/STAGE71_VALIDATION.md) keeps application/core NO-GO and the
three independent reports unfilled.

## Post-consumption grant copy gap

[Stage 72](docs/NONCE_GRANT_COPY_MODEL.md) separately copies an already issued
worker or cached permission. Unique durable issuance and deduplicated result
receipts still permit repeated nonce work in the selected controls. Conditional
no-counterexample exploration assumes an unimplemented nonexportable boundary
through the actual effect. No private signer or custody mechanism is added.
See [validation](docs/STAGE72_VALIDATION.md); application/core remain NO-GO.

## Public partial-invocation input projection

[Stage 73](docs/PUBLIC_NONCE_INTENT.md) retains the complete existing dynamic
signing context and makes its declared public backend inputs explicit. It adds
no new digest, private signer or consumption permission. Exact byte comparison
checks the selected public object; it authenticates no producer, actual backend
input, current authority or nonce custody. See [validation](docs/STAGE73_VALIDATION.md);
application/core remain NO-GO and independent reports remain unfilled.

## Public input backend conformance

[Stage 74](docs/PUBLIC_NONCE_INTENT_CONFORMANCE.md) binds four fixed complete
factory packets to test-only backend key aggregation, Taproot tweaking, point
parsing and verification of existing public partial fixtures. Swapping valid
full nonces preserves their sum but rejects individual partials. No signer,
private bridge, freshness, consumed-signer-input evidence or authentication is
added. See [validation](docs/STAGE74_VALIDATION.md); application/core remain NO-GO.

### Public nonce component and infinity boundaries

[Public edge conformance](docs/PUBLIC_NONCE_EDGE_CONFORMANCE.md) checks shared
components, aggregate cancellation and in-field noncurve encodings against
complete transcript shape and the existing pinned backend. These public-only
controls select no signing interface or new aggregate rejection policy.
See [Stage 75 validation](docs/STAGE75_VALIDATION.md). Application and core
progression remain NO-GO.


Public partial and adaptor boundaries are documented in [public adaptor edge conformance](docs/PUBLIC_ADAPTOR_EDGE_CONFORMANCE.md) with the [Stage 76 validation scope](docs/STAGE76_VALIDATION.md). Aggregate validity alone does not validate each supplied share; application and core progression remain NO-GO.

Public partial collection cardinality is selected for separate conformance.
The new controls retain two original roles while testing one, three and four
supplied scalars. See the [construction and role boundaries](docs/PUBLIC_PARTIAL_COLLECTION_CONFORMANCE.md)
and [Stage 77 validation scope](docs/STAGE77_VALIDATION.md).

Stage 78 adds [existing public collection consumer conformance](docs/PUBLIC_COLLECTION_CONSUMER_CONFORMANCE.md) and its [validation scope](docs/STAGE78_VALIDATION.md). Aggregate-valid wrong-count and wrong-role collections are passed through the preserved consumers; no consumer or application interface changes.

Stage 79 extends the existing actual subprocess qualifier with four [durable public collection controls](docs/EXCHANGE_COLLECTION_CONFORMANCE.md) and a separate [validation scope](docs/STAGE79_VALIDATION.md). Equal-total count and role refusals preserve the selected session and head through ordinary reopen; original public artifacts remain usable. No production interface or private custody is added.

Stage 80 adds [actual verifier receipt trust-boundary controls](docs/EXCHANGE_VERIFIER_TRUST_BOUNDARY.md) and a separate [validation scope](docs/STAGE80_VALIDATION.md). A synthetic executable can return canonical positive receipts for public inputs the native verifier refuses; structural journal reopen preserves those receipts without rerunning mathematics. These negative controls keep program trust and persistence separate from cryptographic validity. Application and core progression remain NO-GO.

Stage 81 adds one [actual program selection continuity control](docs/EXCHANGE_PROGRAM_SELECTION.md) to the existing exchange qualifier. The same legacy adapter observes native execution, missing-entry refusal, same-path synthetic replacement and restored native execution. Test-only file measurements do not become production authentication. See [validation](docs/STAGE81_VALIDATION.md); application and core progression remain **NO-GO**.


## Explicit measured public verifier selection

A separate optional [measured exchange verifier](docs/MEASURED_EXCHANGE_VERIFIER.md)
requires a caller-provisioned entry-file SHA256 and repeats the bounded comparison
before every call. The legacy adapter and existing consumers remain exact.
Same-path replacement refuses before launch, but a matching pin for a deliberately
selected synthetic actor still permits forged claims. Matching bytes authenticate
neither source nor execution; atomic launch and application policy remain open.
See the [Stage 82 validation](docs/STAGE82_VALIDATION.md).


Stage 83 adds two [measured public verifier execution-boundary controls](docs/EXCHANGE_EXECUTION_BOUNDARY.md) to the existing actual exchange qualifier. A deterministic cut after a real entry read and a replaced dependency behind an unchanged entry both permit synthetic positives while independent native equations refuse. No atomic launch or complete runtime authentication construction is selected. See [validation](docs/STAGE83_VALIDATION.md); application and core progression remain **NO-GO**.


Stage 84 adds a separate opt-in [sealed Linux public verifier](docs/SEALED_PUBLIC_VERIFIER.md) and [validation scope](docs/STAGE84_VALIDATION.md). Each call seals and measures a fresh public ELF snapshot, then executes the same inherited descriptor through the existing bounded runner. Existing consumers and guarded profiles retain exact bytes. The selected entry continuity does not authenticate the pin, source, loader, dependencies or environment. Application and core progression remain **NO-GO**.


Stage 85 narrows the optional adapter with an [original acceptance cutoff and standard-descriptor policy](docs/SEALED_VERIFIER_ACCEPTANCE.md), plus [validation scope](docs/STAGE85_VALIDATION.md). Correct late receipts refuse at the selected checks; snapshots below three refuse before transport. Existing consumers and native equations remain exact. Blocking syscalls, late worker launch, caller delivery time and complete runtime authentication remain outside the qualified boundary. Application and core progression remain **NO-GO**.


## Submitted-wire receipt expectation

The optional sealed public verifier now retains one expectation derived from
the exact bounded request bytes submitted before snapshot acquisition. Later
same-process caller mutation cannot replace that expectation. See the
[construction and limits](docs/SEALED_VERIFIER_SUBMITTED_WIRE.md) and
[Stage 86 validation](docs/STAGE86_VALIDATION.md). This is research qualification;
application and core progression remain **NO-GO**.

## Stage 87: separate bounded ELF declarations

The optional [ELF metadata observer](docs/WORKER_ELF_DECLARATIONS.md) reads one
caller-pinned entry without opening its declared interpreter or resolving dynamic
strings. Fixed declaration observations do not authenticate runtime closure or
source correspondence. Accepted adapters and consumers retain exact bytes.
See the separate [validation snapshot](docs/STAGE87_VALIDATION.md). Application
and core progression remain **NO-GO**.

## Stage 88: signer and nonce review handoff

An [author-prepared review packet](docs/SIGNER_NONCE_REVIEW_HANDOFF.md) pins all
486 files of the accepted immutable source and separates nonce freshness,
signer/journal integration, paired restore, runtime provenance and cross-chain
disclosure/refund gates. It selects no signer or custody construction and leaves
all independent reports unfilled. The Python CI job limit increases to 45 minutes
after a documented timeout; commands remain intact. See
[validation](docs/STAGE88_VALIDATION.md). Application and core remain **NO-GO**.

## Stage 89: partial-signing journal cuts and copy limits

The [partial-signing failure map](docs/PARTIAL_SIGNER_FAILURE_CUTS.md) separates
consumed admission, secret work, retained output and exact replay. Three new
fixture-only methods cover 44 SIGKILL schedules across both roles and legs, plus
eight copy/restore counterexamples. Distinct live histories can each produce the
same synthetic output, and coherent restore can erase a prior reservation. No
private signer is integrated. See [validation](docs/STAGE89_VALIDATION.md);
application and core remain **NO-GO**.

## Stage 90: native partial math with public test inputs

A [test-only Rust/Python handoff](docs/NATIVE_PARTIAL_JOURNAL_HANDOFF.md) uses the
source-pinned copy of the ephemeral test owner in a separate `publish = false`
crate to produce actual pinned native partial signatures only
for fixed public synthetic keys and seeds. Five native tests separate admission,
backend entry, result loss, retention and replay. Copied/restored histories and
reconstructed deterministic owners still repeat the same nonce and partial.
See [validation](docs/STAGE90_VALIDATION.md). A real signer and durable custody
remain unselected; application and core remain **NO-GO**.

## Native owner process-death qualification

The [selected Stage 91 construction](docs/NATIVE_OWNER_PROCESS_DEATH.md) separates
actual SIGKILL of a public-synthetic native test owner from a surviving journal
coordinator. Five cuts across four role/leg scopes cover twenty native children
per matrix execution. Computed but undelivered outputs reopen unknown; already
delivered public partials can remain recorded after the owner's death. This
selects no real signer, durable custody or nonrollback authority. See the
[local validation snapshot](docs/STAGE91_VALIDATION.md); hosted and independent
qualification must be assessed separately. Application/core progression remains
NO-GO.

## Acknowledged native nonce boundaries

The [separate Stage 92 construction](docs/NATIVE_NONCE_BOUNDARY_CUTS.md) pauses a
public-synthetic test call after local nonce removal and before backend entry.
Eight selected native SIGKILL subcases retain unknown consumed admissions; four
normal-path children compare exact public partials and recorded replay. Option
removal is not secure erasure, and no pause is inside the signing primitive.
See [local validation](docs/STAGE92_VALIDATION.md). Real signer/custody and
independent nonrollback authority remain unselected; application/core remain NO-GO.


## Complete native signer review subject

A [separate Stage 93 author packet](docs/NATIVE_SIGNER_REVIEW_HANDOFF.md) pins all
508 files of the accepted immutable main source and its complete delta from the
earlier 486-file handoff. It includes the public-synthetic native partial/journal,
actual owner-death and acknowledged nonce-boundary tests without replacing any
fixed subject or filling an assessment. Real signer, entropy, custody and
independent nonrollback authority remain unselected. See
[validation](docs/STAGE93_VALIDATION.md); application/core remain NO-GO.

## Signer custody requirements before implementation

The [Stage 94 requirements matrix](docs/SIGNER_CUSTODY_REQUIREMENTS.md) defines
twelve open acceptance predicates, a complete secret/permission copy inventory,
spent unknown-outcome rules and candidate evidence needed before selecting a real
construction. Local, external-authority, remote and device custody remain
hypothetical and unselected. No private signing API or independent assessment
is introduced. See [validation](docs/STAGE94_VALIDATION.md); application/core
remain NO-GO.

## A concrete custody proposal, with unresolved premises

The [Stage 95 CUSTODY-01 proposal](docs/CUSTODY_CANDIDATE_01.md) fixes separate
party-owned custody domains, exact partial-input mapping, entry-cutoff policy,
spent uncertainty and rejection conditions. Its [static decision record](design/custody-candidate-01.json)
keeps all twelve requirements OPEN and every real mechanism UNSELECTED.
The pinned library's copyable nonce API is source evidence, not a protected
custody boundary or new vulnerability claim. No private implementation is added.
See [validation](docs/STAGE95_VALIDATION.md); application/core remain NO-GO.

## Custody mechanism prerequisites

The [Stage 96 comparison](docs/CUSTODY_MECHANISM_FEASIBILITY.md) examines pinned
NSM source and mutable official Nitro Enclaves/KMS documentation as one case.
Attestation, key delivery and encrypted restoration alone do not supply the
proposed nonce admission/continuity protocol. The [comparison record](design/custody-mechanism-feasibility.json)
keeps every mechanism UNSELECTED / NOT IMPLEMENTED and all twelve gates OPEN.
No platform or private implementation is selected. See
[validation](docs/STAGE96_VALIDATION.md); application/core remain NO-GO.

## Finite custody entry and original-output composition

The [Stage 97 model](docs/CUSTODY_ENTRY_MODEL.md) separates recipient admission,
current policy at actual work, copied local consumption, spent uncertainty and
separately authorized exact-original replay. Four intentional controls expose
missing premises; the combined reference exhausts a finite graph conditionally.
Physical custody and reanchoring remain UNSELECTED / NOT IMPLEMENTED and all
twelve gates OPEN. See [validation](docs/STAGE97_VALIDATION.md); application/core
remain NO-GO.

### Custody authority interface proposal

The [authority ordering proposal](docs/CUSTODY_AUTHORITY_INTERFACE.md) separates
remote revocation submission, an accepted admission fence and committed policy.
It specifies effect/release intervals, spent uncertainty and complete-history
reanchoring, without an implemented authority, selected platform or transferable
permit. All custody gates remain OPEN. See the
[descriptive record](design/custody-authority-interface.json) and
[local validation](docs/STAGE98_VALIDATION.md).

### Public native custody intervals

The [bounded suspension experiment](docs/NATIVE_CUSTODY_INTERVALS.md) applies real
SIGSTOP/SIGCONT and observed SIGKILL/reaping to four public party/leg scopes. An
early synthetic commit still permits actual later computation; pending completion
or observed termination gives two narrower orderings. Policy labels are local
assumptions, with no private custody or all-copy fencing claim. See the separate
[local snapshot](docs/STAGE99_VALIDATION.md); application/core remain NO-GO.

### Controlled SQLite contention and reply ambiguity

[Eight new Python methods](tests/test_policy_effect_contention.py) distinguish
native BEGIN/write/COMMIT refusals, explicit reply loss and retained original
rows in nine fixed synthetic scenarios. `[20,20]` can accompany either zero or
one charge; it does not identify the historical CI failure's outcome. The
Stage 100 snapshot kept the store, actors, tests and strict safety assertions unchanged.
The additional numeric-error profile requires Python 3.11 or later. See the
[scope and open cause](docs/POLICY_EFFECT_CONTENTION.md) and
[local snapshot](docs/STAGE100_VALIDATION.md). Application/core remain NO-GO.

### Original allocation failure evidence

The [original distinct-request test](tests/test_policy_effect_store.py) now
collects sanitized reply classes and read-only original/row observations after
both children finish, before its required `[0,20]` and exactly-one assertions.
An unavailable readback is explicit; raw output and exception text are omitted.
[Eight diagnostic methods](tests/test_policy_effect_diagnostics.py) cover the
strict failure path, retained postcommit charge, privacy and cancellation.
The Stage 102 snapshot did not emit native error details, and the old CI
cause remains UNRESOLVED. See the [scope](docs/POLICY_EFFECT_CONTENTION.md#original-allocation-failure-evidence)
and [local snapshot](docs/STAGE102_VALIDATION.md). Application/core remain NO-GO.

### Bounded original native execute observations

The original actor now offers a fixed test-only observation option. The strict
distinct-request test selects it to retain native execute phases and exact BUSY
code 5 before store exception wrapping. Legacy output remains the default;
SQL, timeout, cap and request bindings remain unchanged. Missing or incomplete
observations never mean zero retained charges or permission to retry. See the
[selected scope](docs/POLICY_EFFECT_CONTENTION.md#bounded-original-native-execute-observation)
and [Stage 103 snapshot](docs/STAGE103_VALIDATION.md). Application/core remain NO-GO.

### Native rollback and secondary cleanup observations

[Eight additional methods](tests/test_policy_effect_rollback_observation.py)
qualify native rollback refusal with explicit SQLite authorizer fixtures. The
Stage 104 original actor emitted an unknown-outcome report before a secondary
context-exit failure; reply class, process exit and reopened rows are separate
observations. These fixtures preserve store SQL, the observer and the strict
original tests. They add no allocation retry or recovery permission. See the
[selected limits](docs/POLICY_EFFECT_CONTENTION.md#native-rollback-and-secondary-cleanup)
and [Stage 104 snapshot](docs/STAGE104_VALIDATION.md). Application/core remain NO-GO.

### Original actor terminal cleanup

The test actor now closes only an open handle, preserving its unknown outcome
and bounded native report when the store has already disposed the connection.
Eight added methods cover open-handle cleanup and separate command, readiness,
postcommit and terminal cancellation boundaries. The native-authorizer child
control now requires exit 20 and empty stderr in both legacy and observed modes.
Store SQL, the observer, request bindings and the original strict contention
expectations remain unchanged. See the
[selected limits](docs/POLICY_EFFECT_CONTENTION.md#original-actor-terminal-cleanup)
and [Stage 105 snapshot](docs/STAGE105_VALIDATION.md). Application/core remain NO-GO.

### Original actor output loss

[Eight additional controls](tests/test_policy_effect_output_loss.py) qualify
existing output boundaries while the actor, store and prior sources stay exact.
Native closed pipes and explicit synthetic flush faults separate received
records/reports from normal completion and retained rows. Two direct unbuffered
child controls commit before an output failure and retain one original charge
despite exit 1 and no readable reply. A stale-policy control has the same missing
reply class with zero retained charges. No observation grants permission to
retry. See the [selected limits](docs/POLICY_EFFECT_CONTENTION.md#original-actor-output-loss)
and [Stage 106 snapshot](docs/STAGE106_VALIDATION.md). Application/core remain NO-GO.

### Original actor buffered shutdown

[Ten additional controls](tests/test_policy_effect_buffered_shutdown.py) execute
the unchanged original actor with selected CPython pipe output. Default buffering
with the inherited unbuffered override removed gives exit 120 after a primary
BrokenPipeError and a separate shutdown diagnostic. Both a committed allocation
and a stale-policy refusal can lose all outcome/report output and exit 120,
while separate readback retains one or zero original charges respectively.
Paired unbuffered refusal controls exit 1 with zero charges. Normal buffered
controls deliver exact legacy/observed output with exit 0 or 20. Neither missing
output nor final status authorizes retry. See the
[selected limits](docs/POLICY_EFFECT_CONTENTION.md#original-actor-buffered-shutdown)
and [Stage 107 snapshot](docs/STAGE107_VALIDATION.md). Application/core remain NO-GO.

### Original actor compound faults

[Ten additional controls](tests/test_policy_effect_compound_faults.py) combine
selected primary failures with a synthetic fault raised after actual store close.
The outward exception is the selected terminal object; its context retains the
original cancellation, native SQLite setup error, native pipe error or selected
flush error. Refusal output failure preserves a three-object chain. Separately
retained records distinguish precommit rollback from a committed original even
when no outcome is delivered. An already-disposed control skips terminal close
and preserves the primary cancellation. These are selected in-process controls;
they establish no child status, natural native-close fault or signal behavior.
See the [selected limits](docs/POLICY_EFFECT_CONTENTION.md#original-actor-compound-faults)
and [Stage 108 snapshot](docs/STAGE108_VALIDATION.md). Application/core remain NO-GO.

### Original actor constructor interruptions

[Fourteen additional controls](tests/test_policy_effect_actor_constructor.py)
qualify construction before the original actor enters its terminal guard.
Thirteen selected interruptions produce no actor reply, allocation or public
actor close; constructor disposal is measured separately. Native SQLite errors,
selected cancellation and faults raised after a successful native close retain
different exact exception chains. Every control preserves a previously charged
original with no effect. A healthy baseline returns that original without a
duplicate charge. Explicit SQL calls and native authorizer callbacks are counted
separately. See the
[selected limits](docs/POLICY_EFFECT_CONTENTION.md#original-actor-constructor-interruptions)
and [Stage 109 snapshot](docs/STAGE109_VALIDATION.md). Application/core remain NO-GO.

### Constructor refusals before native connection

[Twelve additional controls](tests/test_policy_effect_constructor_preflight.py)
separate six original actor inputs from six direct constructor inputs. Invalid
labels, paths and provisioning profiles refuse before object fields exist;
existing and dangling symlinks refuse after fields exist but before connection.
Neither group invokes constructor disposal or reaches native database/file
opening. Actor cases emit no reply; direct profile cases do not claim actor
support for provisioning. Each preserves one existing original charge and zero
effects. See the [scope note](docs/POLICY_EFFECT_CONTENTION.md#constructor-preconnection-refusals)
and [Stage 110 snapshot](docs/STAGE110_VALIDATION.md). Application/core remain NO-GO.

### Constructor path and provisioning failures

[Fourteen additional controls](tests/test_policy_effect_constructor_paths.py)
separate selected path-method interruptions from native directory/open and
exclusive-provisioning failures. Four interruptions precede the disposal guard;
ten later failures invoke disposal without a SQLite handle. Three direct API
selections retain a newly reserved empty file after successful native descriptor
close, with no connection or usable store. Actor replies, exact exceptions,
descriptor closure and the existing original are checked separately. See the
[scope note](docs/POLICY_EFFECT_CONTENTION.md#constructor-path-and-provisioning-boundaries)
and [Stage 111 snapshot](docs/STAGE111_VALIDATION.md). Application/core remain NO-GO.


## Stage 112: retained empty reservation refusals

Nine [followup reservation controls](docs/POLICY_EFFECT_CONTENTION.md#retained-empty-reservation-refusal-boundaries)
carry the same empty file from a selected constructor interruption into direct
open, original actor open or exclusive provisioning. Native schema refusal,
rollback/close and native EEXIST remain distinct. Original bytes and complete
charge/event sequence 1 survive; the reservation stays empty and mode 0600.
No automatic retry, replacement or application behavior is added. See the
[validation snapshot](docs/STAGE112_VALIDATION.md); independent assessment is
absent and application/core remain **NO-GO**.

## Stage 113: retained reservation disposal interruptions

Twelve [selected disposal controls](docs/POLICY_EFFECT_CONTENTION.md#retained-reservation-disposal-boundaries)
separate the outward exception, private closed flag and actual native handle
after an empty-schema refusal. A caught SQLite close error can leave a live
connection behind a closed flag; an escaping OSError or cancellation can leave
the flag false after native close succeeded. The existing behavior is measured
without changing the store or actor. Original bytes and charge/event sequence 1
remain exact. Fixture release occurs only after verification and only for a
still-owned handle. See the [validation snapshot](docs/STAGE113_VALIDATION.md).
These selected faults do not qualify natural close errors, child delivery,
automatic recovery or application cryptography. Application/core remain **NO-GO**.

Stage 114 corrects the [synthetic lease fixture input lifetime](docs/STAGE114_VALIDATION.md)
after a preserved main CI failure with an unresolved original child cause. The
positive fixture drains input until EOF before its unchanged reply; two native
inner-transport controls distinguish a successfully reaped nonreading child from
a draining child awaiting input. Runtime, guard, admission, timeout and CI policy
stay exact. Complete local and hosted acceptance remain separate gates;
application/core remain **NO-GO**.

## Stage 115: retained reservation BEGIN interruptions

Twelve [selected BEGIN controls](tests/test_policy_effect_reservation_begin.py)
carry a retained empty reservation into direct or original actor constructor
entry. Interruptions before and after successful native BEGIN distinguish two
rollback-helper calls from zero or one actual SQL rollback. Exact outward
exceptions, successful native close and the previously charged original are
checked separately. See the [validation snapshot](docs/STAGE115_VALIDATION.md).
These controls add no automatic recovery or application behavior;
application/core remain **NO-GO**.

## Stage 116: retained reservation rollback interruptions

Twelve [selected compound rollback controls](tests/test_policy_effect_reservation_rollback.py)
carry a retained reservation through an original BEGIN interruption and a
secondary SQLite rollback interruption. Helper results, disposal busy states,
native closed-property refusals and exact exception contexts are checked
separately from SQL rollback and native close calls. The original synthetic
charge remains available with zero effects. See the
[validation snapshot](docs/STAGE116_VALIDATION.md). These selected observations
add no automatic recovery or application behavior; application/core remain
**NO-GO**.

## Stage 117: non-SQLite reservation rollback boundaries

Twenty-four [selected secondary rollback controls](tests/test_policy_effect_reservation_secondary_rollback.py)
separate an original BEGIN error or cancellation from a secondary OSError or
cancellation during rollback. Before native rollback, constructor failure leaves
an active connection and journal until explicit test-fixture close; the secondary
outcome also replaces the original outward primary. These passing controls
document an unsafe cleanup boundary. See the
[validation snapshot](docs/STAGE117_VALIDATION.md). They add no recovery or
application behavior; application/core remain **NO-GO**.

## Stage 118: isolated selected failure-cleanup guard

A [separate offline guard](qualification/selected_cleanup.py) attempts close after
selected rollback return or escape and preserves the first outward exception.
Callback diagnostics remain separate from native resource observations; an
escaped close callback can leave an open handle or follow successful native
close. Thirty-two [controls](tests/test_selected_cleanup.py) retain the earlier
store behavior and distinguish explicit fixture cleanup. See the
[validation snapshot](docs/STAGE118_VALIDATION.md). No store, actor or application
uses the guard; application/core remain **NO-GO**.

## Stage 119: returned callbacks and native release

Four [selected callback controls](tests/test_selected_cleanup_noop.py) compare
successful callback return with separately measured native rollback and close.
Three returned close callbacks leave an owned handle available until explicit
fixture cleanup; two also retain an active transaction and journal. The native
forwarding comparison closes the handle. Complete original readback remains
available before and after fixture cleanup, with one original and zero effects.
See the [validation snapshot](docs/STAGE119_VALIDATION.md). The selected guard
and existing store remain unchanged; application/core remain **NO-GO**.

## Stage 120: closed APIs and native lock release

Two [native controls](tests/test_selected_native_release.py) show that a returned
connection close and rejected SELECT can coexist with a retained reader lock.
Closing the cursor first supplies a distinct lock-release comparison; explicit
fixture reference release remains separate. The source-pinned
[requirements](docs/NATIVE_RELEASE_REQUIREMENTS.md) distinguish API invalidation,
subordinate handles, selected lock observations and exact original retention.
See the [validation snapshot](docs/STAGE120_VALIDATION.md). Existing store and
guard remain unchanged; application/core remain **NO-GO**.
