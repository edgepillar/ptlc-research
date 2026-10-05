# Security

This repository contains experimental offline PTLC research and synthetic qualification code. It has no production signing backend, wallet integration or supported live settlement path. Do not use its fixtures, fixed scalars, nonce inputs or reference arithmetic with real funds.

The [threat model](docs/THREAT_MODEL.md), [Stage 12 implementation report](docs/STAGE12_VALIDATION.md), [Stage 13 packaging report](docs/STAGE13_VALIDATION.md), [Stage 14 correspondence report](docs/STAGE14_VALIDATION.md), [Stage 15 reserve experiment](docs/STAGE15_VALIDATION.md), [Stage 16 observation experiment](docs/STAGE16_VALIDATION.md), [Stage 17 evidence contract](docs/STAGE17_VALIDATION.md), [Stage 18 local verifier](docs/STAGE18_VALIDATION.md), [Stage 19 record contract](docs/STAGE19_VALIDATION.md), [Stage 20 separate disk owner](docs/STAGE20_VALIDATION.md), [Stage 21 worker-held leases](docs/STAGE21_VALIDATION.md), [Stage 22 shared admission](docs/STAGE22_VALIDATION.md), [Stage 23 explicit worker resources](docs/STAGE23_VALIDATION.md), [Stage 24 durable resource selection](docs/STAGE24_VALIDATION.md), [Stage 25 v4 process-death cuts](docs/STAGE25_VALIDATION.md) and [Stage 26 controlled storage failures](docs/STAGE26_VALIDATION.md) describe the current evidence and known limits. The [independent review brief](docs/INDEPENDENT_REVIEW.md) prepares an exact source subject; external assessment remains pending. In particular:

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

Stage 26 adds test-only before/after API failures, secondary rollback/cleanup
errors, poisoned ownership and a native file-size limit in a disposable writer.
Result failure returns no normal statement; consistent reopen retains charge and
prior normal evidence without replay. Synthetic EIO/ENOSPC/SQLite errors establish
no native storage fault or physical sync behavior. Native EFBIG qualifies only
file-size refusal; Linux actual-positive gates are separate from synthetic
discovery verdicts and macOS host selection. Runtime and frozen review subject
remain unchanged. Power loss, restore defense, independent review and funded
availability remain open. See [fault design](docs/RESOURCE_STORE_FAULTS.md).

Stage 27 prepares a [separate complete observation inventory](docs/OBSERVATION_REVIEW.md)
and [unfilled assessment report](docs/OBSERVATION_REVIEW_REPORT_TEMPLATE.md). The
checker uses local exact objects and protects working/indexed manifest bytes;
it establishes neither authenticated provenance nor independent security review.
The original 119-file subject is unchanged. All runtime, restore, source,
resource, storage and funded-availability exclusions above remain unresolved.
See [packaging validation](docs/STAGE27_VALIDATION.md).

Stage 28 separately qualifies [v4 coherent rewind and copied histories](docs/RESOURCE_STORE_RESTORES.md).
Consistent old pairs can replenish local allowances or erase later claims under
the same profiles; separately owned copies use separate histories even with the
same physical pool. Mismatched-pair quarantine and resource selection supply no
external freshness, clone defense or global quota. The synthetic conflict case
does not demonstrate contradictory actual mathematical verdicts. Application
behavior, both fixed subjects and pending assessments are unchanged. See
[validation](docs/STAGE28_VALIDATION.md).

Stage 29 separately [models freshness and dispatch authority](docs/OBSERVATION_AUTHORITY_MODEL.md).
Externally charged copyable receipts still permit duplicate abstract entries;
conditional unique dispatch assumes canonical enrollment, non-rollbackable
external state and a trusted enforcer. No backend or service implements these
premises. History fencing does not terminate old work, and receipt loss or
authority outage can prevent progress. Both fixed subjects and unfilled reports
remain unchanged; model results supply no restore defense, signer protection,
native storage or funded recovery guarantee. See [validation](docs/STAGE29_VALIDATION.md).

Stage 30 adds a [pure candidate authority codec](docs/OBSERVATION_AUTHORITY_CONTRACT.md).
It binds selected context, target and full expected head, checks exact types and
declared no-refund transitions, and returns only replayable public claims. Anyone
can forge a matching reply; digests, profile equality and changed head labels
prove no authentication, freshness, durability or actual worker entry. The codec
owns no target set, quota, idempotency table or dispatcher, and does not mutate
an exhausted journal. It is disconnected from existing entry points. Both fixed
subjects and unfilled reports remain unchanged; production integration, signer
ownership and funded recovery remain unresolved. See [validation](docs/STAGE30_VALIDATION.md).

Stage 31 separately [compares canonical enrollment](docs/OBSERVATION_ENROLLMENT_MODEL.md).
Caller label/profile/epoch variants can split a scope-keyed quota, claimed
resource equality can misbind charges, canonical source knowledge can lack owner
permission, and two cached absences can allocate duplicate canonical records.
The strongest result assumes independently trusted resource/owner facts, atomic
uniqueness and non-rollbackable registry lineage. A coherent rewind still refills
the allowance under otherwise identical rules. These are abstract charges, not
worker entries, authentication or native persistence evidence. No backend or
application integration is supplied; fixed subjects and assessments remain
unchanged. See [validation](docs/STAGE31_VALIDATION.md).

Stage 32 adds a [pure retained-resource and unsigned intent contract](docs/RETAINED_RESOURCE_INTENT.md).
All nine scope selections keep one selected seven-commitment content key but
change the full unsigned owner intent. Source/economic equivalence, namespace
and first-registration capture remain external. The public-key encoding checks
no curve membership, key control or role, and matching unsigned values replay.
Current snapshot consistency is not current-source authentication; stable keys
do not preserve charged history through restore. This pure codec includes no
owner verifier, registry, worker permission or runtime integration. See
[validation](docs/STAGE32_VALIDATION.md); both subjects and reports are unchanged.

## Reporting a concern

Use GitHub private vulnerability reporting through the repository's Security tab **when that feature is enabled**. This document does not claim that private reporting has been configured. If it is unavailable, a public issue may request a private reporting channel without including sensitive details or an exploit that affects live systems.

A useful report identifies the affected commit, expected and observed behavior, and a minimal offline reproduction using synthetic inputs. Include a proposed fix or relevant public source references when available. Do not submit credentials, private keys, seed phrases, wallet files, real signing nonces, personal identifiers, private conversations or unredacted environment logs. Do not test against live funds or third-party systems to demonstrate a finding.

Stage 33's [public enrollment signatures](docs/PUBLIC_ENROLLMENT_SIGNATURES.md)
check the exact local intent with the locked BIP340 backend and an explicit entry
pin. Valid self-selected keys/sources, stale signed expectations and repeated checks
supply no role, provenance, freshness or allowance. A malicious selected verifier
can forge positive result bytes. Measurement is not atomic launch or host trust;
legacy bounded transport adds no global work policy. Both review subjects/reports
are unchanged; governor/bootstrap, registry, signer and funded gates remain open.

Stage 34's [independent Go checks](docs/INDEPENDENT_ENROLLMENT_SIGNATURES.md)
confirm public intent mathematics and hash framing through a separate backend.
Valid self-selected source/key signatures, replay and reused IDs establish no
governor-role assignment, provenance, uniqueness or freshness. Raw intent signing
authenticates no extra outer permission field. Exact application framing and
trusted local expectations remain required; independent assessment, registry,
signer and funded gates are unresolved. Application behavior is unchanged.

Stage 35's [explicit local governor profile](docs/LOCAL_GOVERNOR_PROFILE.md)
matches independently selected key/resource/namespace/profile/cap rules without
producing a role certificate or permission. Caller-selected malicious or stale
rules can still match; parsing exact expected bytes supplies no bootstrap or
revocation proof. The unchanged signed intent does not commit the local profile
digest, and broader local caps can match the same signature. Format checks prove
no curve or source math and cannot repair a forged trusted-verifier positive.
Existing entry points do not require the helper; matching and repeated actual
signature checks preserve exhausted quota without creating allocation authority.
Current policy/source trust, registry lineage, dispatch, signer and funds remain
unresolved. Both fixed review subjects/reports remain unchanged.

Stage 36's [governor authority model](docs/GOVERNOR_AUTHORITY_MODEL.md) uses ideal
root/assignment/intent facts and hypothetical complete profile binding. Cached
current checks can miss update, rotation or revocation; coherent local anchor
restore admits old authority under a use-time rule. Its strongest conditional
policy assumes non-rollbackable current evidence at an indivisible use instant.
Repeated packet admission remains possible with no registry/idempotency or worker
proof. No real certificate, provisioning, cryptographic check or new wire format
is supplied; existing application behavior and both fixed subjects/reports remain
unchanged. Source, lineage, dispatch, signer and funded gates remain open.

[Stage 37 unsigned assignment and v2 intent](docs/GOVERNOR_ASSIGNMENT_CONTRACT.md)
commit an independently selected issuer and complete local profile; matching is
still only unsigned byte agreement. Format-valid zero keys, self-selected roots
and old retained expectations remain representable. No signature math, issued
role, source truth, latest head, revocation or indivisible use-time rule follows.
Old v1 signatures cannot be reused as v2 proof. New actual verifier/construction
assessment is required; the fixed subjects and unfilled reports are unchanged.
See [validation](docs/STAGE37_VALIDATION.md), including the initial fixture error.

[Stage 38 public issuer/owner verification](docs/GOVERNOR_SIGNATURE_QUALIFICATION.md)
qualifies actual BIP340 checks for these exact new messages. This authenticates
two statements relative to selected keys; it does not establish trusted issuer
provisioning, current permission, scope/source truth or a secure swap protocol.
Complete local expectations precede work, since an opaque scope hash cannot
prove requested caps. Old retained authority and request replay still verify;
malicious selected verifier positives remain forgeable. Entry-file measurement
is not atomic launch or provenance. No registry, use-time oracle, signer or
funded activity is connected; both assessments remain pending and fixed reports
unchanged. See [validation](docs/STAGE38_VALIDATION.md) and its Go setup failure.

[Stage 39 current-authority framing](docs/CURRENT_AUTHORITY_EVIDENCE.md) matches
checkpoint-bound source/query/claim bytes without contacting or authenticating
a policy source. Source root, issuer key, source incarnation and policy revision
have distinct meanings; matching their encodings supplies no provisioning,
latest-state proof or non-rollbackable history. Forged active claims, unchanged
old selections and coherent copies still match. Unavailable claims have no head
or assignment, but this pure parser implements no outage admission rule or cached
fallback prevention. Define and assess the actual protected-use instant and its
atomic policy/lineage/dispatch ordering before runtime integration. No existing
worker, journal, crypto or fixed review subject changes. See
[validation](docs/STAGE39_VALIDATION.md).

[Stage 40 source/use ordering](docs/POLICY_SOURCE_USE_MODEL.md) assumes a live
trusted current-policy source and serialized nonrewinding operation records.
Commit and entry cutoffs intentionally differ after revocation; neither is a
selected production rule. Lost replies retain the original operation and charge;
source-ledger restore can repeat charge/entry despite genuinely current policy.
Scoped idempotency provides no business-intent uniqueness or actual worker fence.
Detected compromise is an external trusted signal, not evidence of protection
against undetected compromise. Selected schedules exclude the separate directed
fault cases and the full graph. No runtime gate or source implementation changes;
both fixed subjects/reports remain unchanged. See
[validation](docs/STAGE40_VALIDATION.md).

[Stage 41 SQLite ordering](docs/OFFLINE_POLICY_EFFECT_STORE.md) protects only a
synthetic row in one owned local database. A local administrator and honest
SQLite/VFS behavior are premises; source labels and complete profile equality
provide no authentication. Native process-death tests supply no power-loss or
hardware durability proof. Coherent source restore repeats an effect and copies
split caps. Original result replay after revocation grants no new permission.
No physical worker fence, current-source adapter or compromised-source recovery
is implemented. See [validation](docs/STAGE41_VALIDATION.md).

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
