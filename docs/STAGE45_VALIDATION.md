# Stage 45 validation record

This later delta targets `b4dbd200e185093b5cb0e521f27c749387d5f11d` and qualifies
an isolated local SQLite read snapshot. It also corrects connection closure at
eleven inherited test-only sites without changing their commit/rollback context.
No store schema/implementation, cryptographic worker, fixture or dependency is
changed. The new read diagnostic neither signs nor authenticates a live response.

## Local execution

- New local read suite: **27 passed**, including four native process/writer/death
  groups, with no failures or skips.
- Before/after lifecycle trace: **147 inherited tests passed** in each run, using
  the real Python 3.9.6 SQLite connection subclass. The same 300 allocations
  changed from 22 unclosed allocations in ten methods to **zero unclosed**.
- Required full offline suite: **1,099 passed** in 974.583 seconds, with no failures or skips.
- Rust/Go workers and all fifteen actual-worker groups are unchanged and **not
  rerun locally** in this stage. Fresh exact-head hosted execution must retain
  their full checks; an earlier green run is not evidence for this new candidate.
- Artifact/index/worktree checks: **598 versions across 299 tracked files**,
  with **1,019 relative file links** resolving. Fixed inventories are complete at
  **189 and 119 files**. Checks repeat after staging this evidence update.
- Hosted Linux/macOS Python 3.11/3.13 checks and full-log warning inspection:
  **pending**. No local Python 3.13 runtime was selected or installed.

The first 25-test affected run reached one error because a new assertion named
`governor_assignment` instead of the existing `assignment` packet field. After
that correction, a 27-test run reached one failure because another assertion
compared a parsed claim object directly with a dictionary. Comparing its decoded
dictionary produced 27 passes. These were test-only assertion corrections, not
successful checks or independent review. A private edit-count assertion also
initially expected twelve sites instead of the observed eleven; the five-file
edit and trace were inspected and the count corrected. No test or warning was
suppressed.

## Boundary of the evidence

The [selected local construction](LOCAL_SOURCE_READ_ORDERING.md) samples the
complete root/profile/source/checkpoint/query/claim under a real owned SQLite
transaction. Native writer exclusion holds until read commit. A revocation can
commit after read commit but before the old active response is returned. The
original synthetic allocation/effect gate refuses old pending use and retains
charges; read diagnostics do not create charges or effects.

Coherent source restore and clones repeat reads and original synthetic effects.
The separate external audit list is an ideal witness and is not an implemented
nonrollback service. Arbitrary opaque root/profile selections can produce
unsigned local active claims. Original-operation association is in an unsigned
local sample, not the historical response's signed schema. There is no physical
entry implementation and no authenticated source claim.

Both fixed subject inventories, unfilled independent reports, earlier
qualification math/fixtures, journals/store logic, locked dependencies and the
CI workflow remain unchanged. Older test-only SQLite contexts now close their
connections. **All required local checks passed.** Fresh exact-head hosted checks, complete
log/merge-tree inspection and rendered publication verification remain separate. Offline
qualification is **GO**; application integration, core port, activation,
deployment, private signing and funded execution remain **NO-GO**.
