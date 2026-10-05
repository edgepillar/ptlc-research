# Stage 44 validation record

This later delta targets the source-administrator qualification branch at
`586ed7bc0bd74dd82164ff74b7d7ec5e548dac22`. It qualifies isolated historical source
response mathematics over the unchanged checkpoint read contract, without source
integration, authenticated SQLite mutation or protected-use entry.

## Local execution

- New selection/transport Python suite: **26 passed**, no failures or skips.
- Required complete offline Python suite: **1,072 passed** in 947.602 seconds, with no failures or skips.
- Complete locked offline Rust suite: **108 passed**, no failures or ignored tests.
- Both locked Go modules: **44 top-level tests passed** (36 and 8).
- New Rust response tests: **10 passed**. New Go response groups: **6 passed**,
  including 17 positive and 25 signed-refusal vector subtests.
- New actual public worker group: **12 passed**, including all four observations,
  every signature byte/scalar boundary, 25 raw signed refusals, exact alternative
  signatures, stale/restored history, forged callback positives, newly challenged
  old active state and unchanged temporary SQLite view/database/charges.
- Earlier actual-worker groups were **not rerun locally** in this stage. Fresh
  hosted execution must cover all fifteen groups at the exact published head.
- Rust/Go formatting: passed. Staged/worktree hygiene covers **588 versions**
  across **294 tracked files**; **1,003 relative file links** resolve. Fixed source
  inventories are complete at **189 and 119 files**. Artifact checks repeat after
  staging this evidence update.

**All required local checks passed.** Hosted checks still require the exact new
commit and complete log/merge-tree inspection.

The first affected Python run reached 26 tests and failed five transport tests
because a local output variable shadowed the imported response module. Correcting
that module variable and the corresponding test-loop variable produced 26 passes.
The first actual-worker qualification reached twelve tests: eleven passed and
one had an obsolete administrator-signature keyword in the new script. Correcting
that test-only argument produced twelve passes. No failure is represented as a
successful check. A self-review also moved the signature-byte mutation control to
raw request packets, explicitly checking successful raw execution first; otherwise
an envelope schema alone could have caused a tautological refusal. The final
control checks all four signatures. Go numeric-alias controls were likewise
corrected to change the nested checkpoint rather than add an unknown field.
Direct dictionary, canonical-byte and digest conversion guards were checked before
publication. These are self-review corrections, not independent assessments.

The full offline suite retains independent OpenSSL and native journal/store checks.
Hosted Linux/macOS execution and exact-head merge-tree inspection are separate
required evidence; local passes do not establish hosted success.

## Boundary of the evidence

The [selected response construction](SOURCE_RESPONSE_SIGNATURE_QUALIFICATION.md)
binds the complete root, response role/key, profile, query, source incarnation,
checkpoint, challenge, full governor packet, decoded scope/resource and full claim.
Rust and independent Go separately confirm that all 25 refusal vectors have valid
response mathematics under their claimed key, while the complete selected rule
refuses them. The actual worker additionally checks root, issuer and owner math.

The raw worker uses self-selected packet keys. A selected callback can forge all
four positives for two zero signatures. Entry measurement is not atomic launch,
provenance or a sandbox. Operational key custody and independent selection remain
external. Test-only signing uses deliberately known synthetic tags.

Old exact or coherently restored selections still replay. A new challenge signed
with the same old active checkpoint passes all four mathematical checks, including
after a separate local store revocation. Such reads leave the store bytes/view,
charged count and pending-effect refusal unchanged. The worker neither reads nor
mutates the store; this demonstrates isolation, not authenticated current state.

Fixed source subjects, manifests, unfilled reports, earlier workers/fixtures,
dependencies, journals and SQLite implementation remain unchanged. One additional
actual-worker step preserves all older steps, action pins and timeouts. Offline
qualification is **GO**. Source integration, core port, activation, deployment,
private signing and funded recovery remain **NO-GO**. Current serialized reads,
external nonrollback lineage, compromise recovery and physical-use fencing remain open.
