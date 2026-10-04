# Threat model and evidence limits

Status: **DRAFT, carried through Stage 14 selected model/journal correspondence.** These are review requirements for a future bilateral reference swap, not guarantees from an implemented client. Read alongside [PROTOCOL.md](PROTOCOL.md), [CANDIDATE-01](TRANSACTION_GRAPH.md), [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) and the [public journal boundary](SESSION_JOURNAL.md).

## Security objective

Under an explicitly selected protocol and stated chain/availability assumptions, an honest participant must not lose the swap principal while the adversary obtains both principals. A participant must have a defined claim or refund recovery path that does not require fresh counterparty cooperation. This property must be argued for every reachable protocol state, including after secret disclosure.

Principal safety does not promise trade completion, equal opportunity, zero fees, immediate liquidity, price fairness, or protection from all censorship/reorgs. A malicious counterparty can abort, delay, lock liquidity and obtain an economic option over the agreed exchange. The reference design must report the costs and lock duration of those outcomes.

## Assets and trust boundaries

Protected assets include both principals; signing keys and nonce state; the swap secret and extraction material; recovery artifacts; the integrity of session commitments; and the ability to determine the exact outcome after interruption.

The adversary may control the counterparty and its software, supply malformed keys/signatures/transactions, reorder or withhold messages, race claim/refund paths, broadcast replacements, and exploit public knowledge. Network and RPC inputs may be stale, omitted, inconsistent or malicious. Separate local processes and restored snapshots can act as stale writers even without a malicious user.

The intended validation model uses independently validating Bitcoin and Zenon nodes. The client must authenticate and bind its connection to the intended nodes and chain identities. Node consensus correctness, host integrity, secure randomness, the selected cryptographic implementation, storage durability and timely network access remain assumptions to document and test where feasible. A local node alone does not eliminate eclipse, censorship, availability or deep-reorg risk.

## Threat inventory

| Threat | Required design response | Evidence required later |
| --- | --- | --- |
| Unsound adaptor or aggregation construction | Select a complete construction with stated assumptions; distinguish the adaptor point from signing keys; verify all adversarial inputs and partial artifacts. | Independent cryptographic assessment and relevant independent vectors; a self-generated success case is insufficient. |
| Nonce reuse after retry, crash or restored backup | Write-ahead consumption; exclusive state ownership; never recover an old nonce as unused; fail closed when ownership/history is uncertain. | Crash injection around signing and persistence, concurrent-process tests, stale-state/backup tests, and platform-specific durability evidence. |
| Rogue keys, malformed points or inconsistent encodings | Define and enforce the selected construction's key validation and canonicality rules. Validate aggregate-key and tweak handling if used. | Negative vectors and cross-implementation checks. Core admission-policy changes require separate review. |
| Funding substitution or transcript replay | Bind session/version/roles, chain identity, amounts, token, funding ID/outpoint, keys, destination and expiry; verify actual funding from the intended chain. | Cross-session/network substitutions, changed destination/amount/token/expiry, wrong outpoint, and reset-devnet scenarios. |
| Secret disclosure before safe counter-funding | Prove an artifact-exchange/funding order; validate sufficient confirmations and remaining claim margin before the last safe disclosure point. | Adversarial one-leg funding, withholding, late-message and reveal-before-acceptance scenarios. |
| Disclosure survives rejected spend or reorg | Separate irreversible knowledge from reversible chain observations. Persist exposure intent before transmitting revealing data. | Revealing signature observed off-chain/mempool, rejected or expired claim, replacement, reorg, and recovery after each. |
| Claim/refund race and late inclusion | Specify clock semantics and a derived safety margin; ensure each funded leg has an independently executable recovery path. | Boundary-time and competing-spend tests; delayed Zenon contract execution; Bitcoin refund/claim conflicts. |
| Fee pressure, pinning or replacement invalidates signing assumptions | Choose fee-bump mechanisms consistent with the graph and signed messages. Reserve claim/refund resources on both chains; do not improvise a new signing session after timeout. | Fee-policy and pinning scenarios, message/transaction replacement checks, resource exhaustion, and safe-abort cases. |
| RPC timeout, duplicate request or ambiguous broadcast | Preserve exact artifacts and unknown-outcome state; reconcile before retrying or replacing; distinguish identical retransmission from signing again. | Lost acknowledgement, partial persistence, duplicate delivery, node disagreement and restart tests. |
| Compromised host, signer or dependency | Minimize key exposure and dependency surface; pin and evaluate the selected library; specify secure storage and signer boundaries. | Dependency provenance/review and integration tests. Offline qualification cannot guarantee security against a fully compromised signing host. |
| Availability and economic griefing | State monitoring requirements, maximum intended lock duration, costs, and safe refusal/abort conditions. | Offline-party and censoring/delaying-counterparty simulations under explicit timing assumptions. |
| Correlation and metadata disclosure | Define the observer and claimed privacy improvement. Limit unnecessary protocol/log disclosures. | Analysis of amounts, timing, addresses, funding structure, network observations and the visible Zenon contract. No automatic anonymity claim. |

## Core and client review are separate

The pinned Zenon contract checks ordinary signatures and expiry. It does not prove the client's adaptor security, safe exchange order, or correct recovery. Conversely, a reviewed client cannot repair consensus-visible contract behavior from outside the node.

Core review must resolve the accepted point-encoding policy and unknown stored-type handling, preserve destination/ID binding and post-spend deletion semantics, and safely compose activation with current features. Existing exact-expiry and repeat-spend tests are evidence of intended coverage, not proof that every adversarial interleaving is handled. Details and pinned sources are in [PROTOCOL.md](PROTOCOL.md).

No demonstrated exploit of the normal core Create path is asserted by the unexpected stored-type concern. No safety claim is inherited from an experimental client merely because the contract verifies its final signature.

## What later evaluation can and cannot establish

| Evidence | Supports | Does not establish |
| --- | --- | --- |
| Source inspection and algebra | Concrete implementation observations or flaws under stated equations/assumptions | Successful execution, general cryptographic security, or production readiness |
| Independent test vectors | Conformance for the covered inputs and rules | A complete protocol proof or safe orchestration |
| Local regtest/devnet demonstration | Behavior for the selected code, setup and scenarios | Production consensus/finality, real fee-market resilience, or autonomous recovery under all failures |
| Restart and concurrency tests | Covered storage/process behavior on tested platforms | Untested-platform durability or protection against arbitrary stale backups |
| Independent review | Findings and confidence within its documented scope | Absence of all vulnerabilities or permission to activate a network feature |

The report must identify exact commits, dependency versions, environment and assumptions, failing/intermediate runs, excluded scenarios and unresolved findings. [Stage 1 results](STAGE1_VALIDATION.md) cover their stated inputs and schedules; [Stage 2 results](STAGE2_VALIDATION.md) cover public context and metadata lifecycle, including a demonstrated full-snapshot rollback limitation. Production activation and live-fund use require evidence beyond this offline package.

[Stage 3 results](STAGE3_VALIDATION.md) add nonce-round substitution checks, local duplicate-public-nonce history and an ephemeral Rust owner exercise. Full public nonce equality is only one detectable misuse; related or partly reused nonces, other journals and cloned/restored state remain outside that defense. Peer authentication, durable exchange ordering and the actual journal-to-signer crash boundary remain unimplemented.

[Stage 4 results](STAGE4_VALIDATION.md) add Bob's local artifact retention/release order and a real public-verification subprocess. The managed API prevents release before full verified extraction material is stored, under a trusted verifier/caller and existing storage assumptions. It does not constrain direct transmission by that caller, authenticate peers, validate funding/time policy, or provide secret signer ownership. Receipts are bound local verification records, not signed attestations.

[Stage 5 results](STAGE5_VALIDATION.md) add exact inbound context checks, Alice consume-before-producer/output-before-return ordering, and actual Bob verification/extraction/adaptation from retained public inputs. No private signing backend is integrated. Restoring both matching pre-consumption storage copies demonstrably permits a second synthetic Alice invocation. Ordinary completion keeps a structurally matching but invalid Bob observation pinned. [Stage 6](OBSERVATION_RECONCILIATION.md) permits explicit replacement after positive verification and exact original-input comparison, while preserving the original packet. Authenticated observation selection and repeated-verification denial of service remain unresolved. Neither completion, possible exposure nor exact replay establishes peer delivery or chain inclusion.

[Stage 7 transport](PUBLIC_WORKERS.md) limits captured stdout during concurrent pipe transfer and applies a per-invocation transfer/exit deadline. It removes unbounded temporary stdout spooling from both public adapters. It does not constrain arbitrary executable resource use, contain escaped descendants, enforce aggregate admission policy or establish private signer isolation. The worker and host remain trusted.

[Stage 8 admission](RECOVERY_ADMISSION.md) durably limits two Bob recovery APIs within an existing owned session. Every admitted attempt remains consumed after failure or restart. Initial artifact verification, Alice completion, direct helpers, new sessions and restored copies remain outside this policy. Malicious observations can exhaust the allowance before a legitimate recovery; a production application needs an independently reviewed recovery/availability policy and authenticated peer admission. No participant authentication follows from counters, public key fields or role labels.

[Stage 9 envelopes](COMPLETION_AUTHENTICATION.md) qualify one message direction relative to locally trusted pins. Correct signatures do not make the enclosed completion valid or fresh. Stage 10 adds optional [durable local pin binding](DURABLE_AUTHENTICATION_PINS.md), with no enrollment or rotation policy; existing recovery entry points remain callable without authentication. Verification calls are outside Bob's allowance; repeating valid or invalid envelopes can still cause work. Public pins and payloads supply neither confidentiality nor anonymity.

[Stage 11's bounded model](RECOVERY_ADMISSION_MODEL.md) makes recovery blockage executable without adding journal admission policy. A universal envelope requirement can block an independently authorized public witness; authenticated invalid inputs or interrupted work can spend a finite allowance. Ideal verifier results and explicit local authorization are model inputs, not an implemented trust source. Preserved state invariants do not establish funded availability or principal safety, and incomplete exploration must never be reported as success.

[Stage 12 candidate construction](PUBLIC_SIGNATURE_CANDIDATES.md) imports only public signature bytes into a locally reconstructed packet. Structural acceptance is neither cryptographic validity nor evidence that Alice transmitted it. The helper has no source authorization, journal mutation or allowance bypass; a later admitted invalid candidate can still poison ordinary selection or exhaust recovery. A coherent local snapshot remains a trusted input, not independently authenticated storage evidence.

[Stage 13 review preparation](INDEPENDENT_REVIEW.md) freezes the exact Stage 12 implementation subject and maps its evidence to unresolved assessment obligations. The inventory establishes source identity only; the report template is unfilled. External construction review, signer ownership, recovery availability and chain/funding/time evidence remain required before progression.

[Stage 14 correspondence](RECOVERY_MODEL_CORRESPONDENCE.md) replays selected baseline traces against journal admission snapshots and reopened state, using separate fake-oracle and actual-public-worker runs. It reproduces exhaustion without deriving observation authority, chain inclusion or Alice ownership. This is bounded implementation evidence, not a general refinement or funded-availability proof.
