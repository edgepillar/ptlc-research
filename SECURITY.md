# Security

This repository contains experimental offline PTLC research and synthetic qualification code. It has no production signing backend, wallet integration or supported live settlement path. Do not use its fixtures, fixed scalars, nonce inputs or reference arithmetic with real funds.

The [threat model](docs/THREAT_MODEL.md), [Stage 12 implementation report](docs/STAGE12_VALIDATION.md), [Stage 13 packaging report](docs/STAGE13_VALIDATION.md), [Stage 14 correspondence report](docs/STAGE14_VALIDATION.md), [Stage 15 reserve experiment](docs/STAGE15_VALIDATION.md), [Stage 16 observation experiment](docs/STAGE16_VALIDATION.md), [Stage 17 evidence contract](docs/STAGE17_VALIDATION.md), [Stage 18 local verifier](docs/STAGE18_VALIDATION.md), [Stage 19 record contract](docs/STAGE19_VALIDATION.md), [Stage 20 separate disk owner](docs/STAGE20_VALIDATION.md), [Stage 21 worker-held leases](docs/STAGE21_VALIDATION.md), [Stage 22 shared admission](docs/STAGE22_VALIDATION.md), [Stage 23 explicit worker resources](docs/STAGE23_VALIDATION.md) [Stage 24 durable resource selection](docs/STAGE24_VALIDATION.md) and [Stage 25 v4 process-death cuts](docs/STAGE25_VALIDATION.md) describe the current evidence and known limits. The [independent review brief](docs/INDEPENDENT_REVIEW.md) prepares an exact source subject; external assessment remains pending. In particular:

- Alice's completion producer returns a public fixture; it does not manage private signing material.
- Restoring both matching journal and checkpoint copies can reenable a synthetic producer. Local consistency checks do not provide clone or rollback protection.
- Restoring both matching pre-start files can also erase a later authentication-pin choice. Persisted pins supply local continuity, not trustworthy enrollment, an external trust anchor or protection against coherently rewritten state.
- Authenticated peer transport and observation selection remain unresolved. Explicit local reconciliation requires a positively verified replacement and retains the original candidate; it does not provide peer authentication or prevent repeated-verification denial of service.
- Completion-envelope qualification authenticates exact bytes only relative to independently supplied trusted pins. Optional pins are frozen at Bob start and reconstructed after reopen. Trustworthy enrollment, rotation, freshness and authenticated journal admission remain absent. A correctly authenticated message can contain an invalid completion; direct journal entry points remain callable without the envelope.
- Public verification and adaptation do not establish funding, chain identity, safe timing, transaction acceptance or settlement.
- Public worker pipe output and transfer/exit time are bounded per invocation. The executable and host remain trusted; process-group cleanup is best effort and does not contain arbitrary resource use or escaped descendants.
- A durable allowance bounds only Bob recovery admissions within one owned journal session. It does not authenticate peers or prevent new-session/restore bypass; exhaustion can prevent a later valid recovery.
- The separate admission model assumes ideal verification and externally supplied local authorization. Exhaustive search applies only to its configured finite graph. Its reference policy preserves modeled state constraints while still permitting recovery blockage; no funded-swap availability policy is selected.
- Selected model/journal trace comparisons qualify only their projected local fields and operations. External authentication, authorization, disclosure and inclusion facts are not journal policy or chain evidence; injected cancellation is not a process-death test.
- The separate reserve experiment protects attempts only under ideal public authorization. Finite reserves remain exhaustible under public-worker interruptions; a configured interruption bound is an external environment assumption, not an implemented guarantee. It provides neither fair scheduling nor a funded recovery policy, and changes no journal allowance.
- A separate exact-observation model permits locally authorized invalid public bytes. Their normal mathematical rejection can exhaust a reserve with zero worker interruptions. The ideal pre-admission validity filter in the comparison is unimplemented; local authority, authentication and inclusion labels do not prove that filter or funded availability.
- The evidence codec binds claims to exact inputs and a selected profile but cannot authenticate their producer or establish a mathematical outcome. Forged claims can match every field. Legacy completion failures do not establish normal negatives; no statement producer, negative cache or journal enforcement is selected.
- Public-signature candidate construction is pure formatting from retained context. It verifies no signature, authenticates no source and grants no recovery authority. Locally constructed Alice/Bob role labels do not prove who transmitted a packet, and coherent snapshot hashes do not prove hostile-storage integrity.
- Local tests and review are not an independent cryptographic audit or production security guarantee.

The separate local observation adapter requires a caller-provisioned entry-file hash and distinguishes normal mathematical verdicts from unknown work. File measurement authenticates neither source/build provenance nor host/runtime behavior and is not atomic with launch. It adds no durable evidence, cache, source authority or journal enforcement; caller cancellation produces no statement or persisted attempt. Review its fixed request domain and reused pure error paths before applying a negative to any recovery policy.

Pure bounded observation records retain attempts and normal claims separately, with explicit conflicts and no unknown-to-negative conversion. Their canonical history authenticates no producer or storage, and restoring an earlier valid value can replenish quota. Owned persistence, stale-writer exclusion, durable ordering and aggregate resource policy remain required before integrating a cache or recovery policy.

The separate observation disk owner adds cooperating local record-writer exclusion and pending/result persistence around the explicitly selected adapter. Native process-death tests establish covered publication ordering; they exercise neither power loss nor hostile storage. Pending publication recovers as charged unknown without worker replay. Stage 21 passes the two locked descriptions through a parent-watching guard to a selected cooperative nonforking worker. A killed guard can leave computation alive, but a live cooperative holder excludes reopen. The owner closes only its references, never explicitly unlocking a shared description. Stage 22 requires an explicit finite physical pool; a slot is acquired before pending persistence and retained by the guard/worker through live work. Saturation charges no attempt and launches no selected work. Store v3 binds the pool profile and rejects consistent old v1/v2 pairs without migration; mathematical profile identity is unchanged. Matching-profile pools in different directories admit independent work and can reopen matching store copies. Malicious/escaped workers, uninterruptible tasks, CPU/memory accounting, cumulative rate, fairness and trusted pool enrollment remain outside this construction. Matching pair restores can replenish quota. The public store ID and digests provide no authentication, external monotonic anchor or global-resource guarantee. No source, recovery admission, journal allowance or signer is connected by this store.

Stage 23 adds a separate Linux-only experimental limited path with explicit CPU-time and virtual-address-space maxima. The child installer disables core dumps, preserves stricter inherited soft/hard values, verifies readback and execs with three retained references. Unsupported hosts, root or incomplete setup select no entry; runtime failures remain unknown. macOS asserts refusal, not memory enforcement. The ordinary v3 entry still uses admitted work and stores no resource policy. Virtual address space is not RSS; nonzero UID does not prove absent capabilities. Parent/guard/preflight limits, hostile privilege, cumulative rate, fairness, enrollment, clone/restore protection and independent review remain open.

Stage 24 adds a separate explicit Linux v4 store entry with a required resource
profile in SQLite/checkpoint storage. Unsupported or missing policy refuses
before creation; cross-mode/policy reopen refuses before SQLite connect and
pending recovery. Live selection is checked before work and limited dispatch.
Saturation is uncharged; admitted failure/cancellation remains charged unknown
without fallback. Ordinary v3, pure records, pool configuration, math and journal
remain unchanged. Requested-versus-effective limits, aggregate budgets and
independent assessment remain separate boundaries. See
[v4 design](docs/DURABLE_RESOURCE_POLICY.md).

Stage 25 separately qualifies all nineteen named v4 initialization/admission/
result/recovery SIGKILL cuts. Real SQLite hot journals reject wrong resource/mode
selection before connect and remain byte-identical. Recovery retains charge and
old normal evidence without replay; divergent pairs quarantine. Python verdicts
and macOS host selection are explicit synthetic inputs; actual limited Rust
result/recheck death runs in a separate Linux qualifier. Production behavior and
the frozen subject are unchanged. Power loss, write/sync/replace faults, hostile
storage and funded availability remain outside this evidence. See
[cut design](docs/RESOURCE_STORE_CRASH_CUTS.md).

## Reporting a concern

Use GitHub private vulnerability reporting through the repository's Security tab **when that feature is enabled**. This document does not claim that private reporting has been configured. If it is unavailable, a public issue may request a private reporting channel without including sensitive details or an exploit that affects live systems.

A useful report identifies the affected commit, expected and observed behavior, and a minimal offline reproduction using synthetic inputs. Include a proposed fix or relevant public source references when available. Do not submit credentials, private keys, seed phrases, wallet files, real signing nonces, personal identifiers, private conversations or unredacted environment logs. Do not test against live funds or third-party systems to demonstrate a finding.
