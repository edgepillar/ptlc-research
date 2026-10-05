# Stage 43 validation record

This later delta targets the source-root-role qualification branch at
`d2766ffb0fbd5ff8be5d11417c208a4a1e8d5bc2`. It qualifies an isolated historical
administrator command, never a source service or authenticated SQLite mutation.

## Local execution

- New selection/transport Python suite: **26 passed** with no skips.
- Required complete offline Python suite: **1,045 passed** in 906.734 seconds, with no failures or skips.
- Complete locked offline Rust suite: **98 passed**, no failures or ignored tests.
- Both locked Go modules: **38 top-level tests passed** (30 and 8).
- New Rust command tests: **10 passed**. New Go command groups: **6 passed**,
  including 12 positive and 18 signed-refusal vector subtests.
- New actual public worker group: **11 passed**. This includes raw signed-rule
  refusals, wrong signing roles/domain/scalars, every byte of both signatures,
  alternate signatures, old signatures against changed selections, replay/restore,
  forged callback positives and unchanged temporary SQLite state/charges.
- The retained earlier actual-worker groups were **not rerun locally** in this
  stage. Fresh hosted execution must cover all fourteen groups at the exact head.
- Rust/Go formatting: passed. Staged/worktree hygiene covers **568 versions**
  across **284 tracked files**; **980 relative file links** resolve. Fixed source
  inventories are complete at **189 and 119 files**. Artifact checks repeat after
  staging this evidence update.

**All required local checks passed.** Hosted checks still require the exact new
commit and complete log/merge-tree inspection.

The first affected Python run reached 26 tests and failed five transport tests
because their assertions used the previous stage's exception class name. The
qualification modules were unchanged; correcting those test assertions produced
26 passes. A later strengthening used an exactly sized hostile result-key control
and tested each positive flag separately; all 26 passed again. The first fixture
output run passed its one selected generator test. No failed verification is
represented as a success, and no independent assessment is supplied. The first
private candidate-check helper expected the old worker option in its exact workflow
comparison; correcting that helper expectation passed against the unchanged new
workflow step. This was a qualification-check failure, not application execution.

The required complete suite includes the inherited independent OpenSSL checks and
native store/journal tests. Hosted Linux/macOS runs and exact-head merge-tree
inspection are separate evidence; a local pass does not establish hosted success.

## Boundary of the evidence

Twelve valid command packets verify historically. Eighteen refusal packets have
valid administrator mathematics under their claimed key, as checked by both Rust
and Go, but fail the independently chosen rule or retained role/context binding.
A valid signature alone cannot grant increases, reactivation, rotation or new
configuration/owner powers. Complete old/new profiles, source context, root digest,
expected revision and original identifier are bound by the command signature.

The raw worker uses the packet's root and administrator roles; complete independent
selection still comes from outside it. A new valid peer packet cannot replace that
selection before callback work. A second valid signature changes request/result
binding. The selected callback can nevertheless forge both positives for zero
signatures that the actual worker refuses. File measurement is not atomic launch,
provenance or a sandbox. Signing remains confined to public synthetic test tags.

An expected revision is a signed comparison label, not a current state read. Old
commands and restored/copy expectations continue to verify after newer signed
revocation, revision, administrator, root and incarnation selections. Replays have
no command receipt or deduplication. The historical root profile becomes a cap
ceiling only through this additional selected rule; no operational permission is
inferred from its root signature alone. All non-cap labels stay fixed.

The temporary Stage 41 store has its complete view/database bytes unchanged after
valid reduction/revocation checks. Separate local revocation does not make old
revision-zero mathematics invalid; a charged pending effect remains refused with
no refund. This demonstrates isolation. No command is applied to the store and
no current source, physical entry, chain, wallet, real funds or private production
signing is connected.

The original source subjects, manifests and unfilled reports remain fixed. Offline
qualification is **GO**. Source integration, core port, activation, deployment,
private signing and funded recovery remain **NO-GO**.
