# Zenon PTLC Swap Research

An offline foundation for investigating a bilateral Bitcoin-to-Zenon atomic swap.

Independent research, not an official Zenon implementation or activation proposal.

**Status: Stage 36 finite governor provenance and current-policy comparison. There is no usable swap client or production signing implementation in this repository.** CANDIDATE-01 fixes a graph for modeling and finite qualification; its complete construction and implementation remain subject to review.

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

## Run the offline checks

Requirements: Python 3.9 or later with SQLite, a POSIX host supporting advisory file locks, Git supporting `--no-lazy-fetch` and `--no-replace-objects`, and OpenSSL with Ed25519 verification support. Acquire the two pinned source objects in the [review reproduction instructions](docs/OBSERVATION_REVIEW.md#reproduce-source-identity-offline) before discovery in a shallow checkout. Session tests target local Linux/macOS filesystems; only the platforms actually executed in the validation report are established. No Python packages, node software, credentials, or network access are required by the tests after acquisition. OpenSSL is an independent test verifier, not a selected application dependency. Artifact-checker tests use temporary Git repositories without configuring an identity or making commits; review-inventory tests write synthetic commit objects with explicit fixture metadata and no installed identity or hooks.

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
