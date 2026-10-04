# Stage 22 validation: shared observation worker admission

Scope: a fixed explicit local lease pool shared by cooperating owned stores,
with one admission reference retained by the guard and selected worker. Source
parent: `7e267e9bc71c3a6c7c72577bb9177b07f43ed9af`.

The store uses version 3 and binds the pool profile in database/checkpoint state.
Saturation rejects before pending persistence without charging or launching.
Admitted results and failures retain earlier ordering and charges. Matching old
v1/v2 pairs quarantine without migration. Mathematical profile/predicate,
public schemas, pure record transitions, session journal, Rust/Go sources,
dependencies and frozen review manifest remain unchanged.

## Executed checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial adapted lease suite | 23 passed in 13.663 seconds, no skips | Existing native owner/guard checks through admitted store work |
| Initial adapted store suite | 41 passed in 38.076 seconds, no skips | Existing storage sequencing and crash matrix |
| Initial pool/unit store admission suite | 24 passed in 7.172 seconds, no skips | Metadata, fixed capacity, ordering and deliberate clone counterexamples |
| Initial native shared pool suite | 3 passed in 6.791 seconds, no skips | Two live stores, saturation/retry and owner/guard death |
| Expanded combined worker suites | 53 passed in 28.372 seconds, no skips | Lease, pool and native pool cases; excludes legacy pipe suite |
| Adapted store suite with genuine older schemas | 41 passed in 37.752 seconds, no skips | Canonically consistent v1 and v2 six-column pairs reject unchanged |
| Further combined worker suites | 55 passed in 28.723 seconds, no skips | Missing config-lock rejection, directory checks and native cancellation added |
| Legacy pipe suite | 15 passed in 3.466 seconds, no skips | Existing direct transport remains separate from shared admission |
| Final lease adapter suite | 26 passed in 14.148 seconds, no skips | Missing admission tested with two otherwise valid held owner descriptors |
| Final pool/unit store admission suite | 26 passed in 7.238 seconds, no skips | Added stored pool profile type/value/length quarantine |
| Required full offline Python suite | 540 passed in 574.665 seconds, no skips | Required independent OpenSSL mode |
| All seven actual-worker qualifiers | 48 passed: 2 + 9 + 11 + 9 + 7 + 4 + 6, no skips | Actual selected Rust executables; the store qualifier adds one saturation/retry case |
| Artifact, links and whitespace | 340 index/worktree versions, 170 tracked files, 444 local Markdown links; whitespace clean | ASCII/disclosure patterns and local targets/anchors; limited scans, not a privacy proof |

All executed suites passed their first run at each stated revision. There was
no failed test, skipped independent OpenSSL case or cryptographic repair in
this local stage. Intermediate counts are subsets/rechecks, not additional
unique cases. Source review strengthened the missing-admission adapter test to
use valid owner descriptors, added old v1/v2 schemas rather than changing only
the version field, rejected lost configuration locks without recreation, and
bounded the new stored pool-profile field before fetch.

Actual qualifier times were 1.415 seconds for exchange, 34.478 for completion,
23.135 for authentication, 52.054 for model/journal correspondence, 13.048 for
observation, 11.800 for pure records and 15.553 for the owned store. Rust/Go
primitive sources and dependency locks were unchanged; their separate primitive
suites were not rerun locally in this stage. The existing hosted jobs run them
against the published head. Local checks do not establish a hosted result.

## Covered behavior

- Canonical private fixed configuration reopens without inode/content changes.
  Invalid ID/count/platform rejects before pool creation. Configuration-lock
  contention and full slot capacity are nonblocking, with no queue or rewrite.
- Independent handles and a parent-path alias share finite physical capacity.
  Slots are distinct; closing a lease releases only its reference. Foreign
  threads, forked handles and closed leases cannot clear original ownership.
- Missing configuration/slot/configuration lock, partial first initialization,
  unknown contents, final symlinks, nonprivate directories/files, duplicate or
  replaced slot identity, malformed/oversized config and wrong expected choices
  quarantine without managed repair. Injected filesystem errors are sanitized.
- A busy pool leaves store pair bytes, revision and quotas unchanged with no
  selected adapter call. Two owned stores share a slot from before admission
  commit through result commit. Failed admission releases the acquired reference
  without work; admitted unknown/exception/cancellation retains its charge.
- Existing exhaustion/known/invalid target checks precede slot acquisition.
  Corrupted pool admission quarantines before a pending write. Wrong selected
  or stored pool profile rejects consistent store state unchanged. Pool/store
  storage overlap and missing explicit pool reject before store creation.
- Native two-worker saturation across different store processes admits no third
  worker or attempt until an explicit retry after release. Each controlled worker
  receives two ownership references and one admission reference, with no
  unrelated open-file inheritance. Owner death, guard death and cancellation
  exercise shared capacity lifetime independently from mathematical evidence.
- A killed guard leaves a live cooperative worker holding capacity after the
  owner records unknown and closes. Another store remains uncharged and busy.
  Owner-death/cancellation cleanup releases capacity without a cooperative
  release-file shortcut. Pending recovery keeps its charge without replay.
- Matching public profiles in different physical pools permit independent work;
  a store accepts a matching profile clone. These intentional negative cases
  establish that the profile is consistency evidence, not shared enrollment,
  anti-clone protection or a system-wide resource guarantee.

The actual store qualifier adds capacity exhaustion before selected work,
byte-for-byte unchanged pair/quota, and an actual mathematical positive after
explicit retry. Existing actual positive/negative restart, changed entry,
deadline, lost-result and exhausted-journal preservation cases remain separate.
Synthetic returns are not mathematical evidence or funded availability proof.

## Execution and remaining gates

Local Python is 3.9.6 on macOS. Full mode is
`REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -q`. The combined
worker pattern is test_worker*.py; store discovery is test_observation_store*.py
and the unchanged pipe pattern is test_public_worker.py. Qualifiers select
already built local public executables explicitly. Runtime measurement is not
trusted source/build enrollment. The unchanged seven-job hosted matrix has four
Linux/macOS Python 3.11/3.13 jobs, one Rust job and two Go jobs; configured CI is
not executed CI.

The [admission design](SHARED_WORKER_ADMISSION.md) bounds concurrent admitted
invocations only for cooperating callers sharing physical files. It supplies
no CPU/memory accounting, cumulative rate budget, fairness, preflight/parent
limit, hostile-worker sandbox, hard elapsed-time bound, trusted enrollment,
power-loss proof, matching-pair rollback defense, source authority or funded
policy. An uninterruptible holder can occupy a slot indefinitely. Legacy direct
or unadmitted guarded helpers and new/clone pools remain outside that bound.

The Stage 12 subject remains 119 files at
`e592633e4c630cfe3f4669876f6f63b80d2e33d6`; manifest SHA256 remains
`df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295`.
External independent assessment and later producer/storage/guard/pool delta
review remain pending. No private signer, wallet access, live RPC, transaction
broadcast, funded settlement, core contribution, activation or upstream outreach
is exercised.
