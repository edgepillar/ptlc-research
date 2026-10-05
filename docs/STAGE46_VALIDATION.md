# Stage 46 validation record

This later delta targets `88527956a163a184dccca28590f6c7491fbb2576` and adds a
separate unsigned original-operation read contract. Original id/revision/profile/
proposal, current selected policy and complete-retention record position are
bound without reinterpreting any retained signature schema. No service, source
adapter, signature worker, application recovery or protected-use gate is added.

## Local execution

- New original-read suite: **36 passed** in 0.378 seconds with no failures or
  skips. Thirty-two contract methods and four synchronous local-store controls
  are separate from inherited native death/writer suites.
- Required full offline suite: **1,135 passed** in 963.384 seconds, with no failures or skips.
- Existing Rust/Go workers and all fifteen actual-worker groups are unchanged
  and **not rerun locally**. Fresh exact-head hosted execution must retain their
  complete checks; an earlier green run is not evidence for this candidate.
- Artifact/index/worktree checks: **608 versions across 304 tracked files**,
  with **1,034 relative file links** resolving. Fixed inventories are complete at
  **189 and 119 files**. Checks repeat after staging this evidence update.
- Hosted Linux/macOS Python 3.11/3.13 execution and complete-log/merge-tree
  inspection: **pending**. Local full execution uses Python 3.9.6.

The first 34-method affected run reached one cleanup error: the coherent-restore
control explicitly closed its original store and its registered cleanup closed
it again. The store correctly refused that second close. Guarding cleanup with
the retained closed state fixed the test; the store was not changed. A 35-method
run passed, then adding the fixed unsigned framing fixture produced the final
36-method passing run. No test or warning was suppressed. A documentation patch
also initially refused a wrong anchor before writing files; it was corrected.
These are local implementation checks, not independent security review.

## Boundary of the evidence

The [contract and meanings](ORIGINAL_OPERATION_READ_CONTRACT.md) distinguish
absent, pending, completed and unavailable observations. The complete original
profile is retained when the selected head has changed, subject to a fixed
same-incarnation namespace rule. Both selected positions and the challenge are
bound. All resulting claims are forgeable unsigned bytes, including conflicting
claims under the same query. An opaque record digest/sequence is no proof of
complete or nonrollbackable lineage.

Coherent source restore/copy still repeats original synthetic effects. New
challenges can frame old active policy and old records. A record can age before
delivery or a blind external ideal actuator's use. The unchanged local store
continues to refuse pending effects after revocation and retains their charges;
the parser does not access it. No absence/unavailable result automatically
authorizes retry, refund or authoritative unknown-outcome reconciliation.

The old schemas, source/store/journal implementations, workers, earlier fixtures,
locked dependencies, workflow, both fixed inventories and unfilled independent
reports remain unchanged. A future historical signature worker requires a
separate response envelope/domain and qualification; it is not implemented here.
**All required local checks passed.** Fresh exact-head hosted execution, complete
log/merge-tree inspection and rendered publication verification remain separate.
Offline framing qualification is
**GO**; source integration, application/private signing, core port, activation,
deployment, wallet access, broadcasts and funded execution remain **NO-GO**.
