# Stage 90 validation snapshot

Status: corrected layout passed local qualification. New exact-head hosted
qualification is pending. Application and core progression remain **NO-GO**.
The parent is `b86af7abcf575ad900fa5bf7fb5b85788d181126`.

The [selected construction](NATIVE_PARTIAL_JOURNAL_HANDOFF.md) uses a separate
[`publish = false` crate](../qualification-native-partial/Cargo.toml), with no
application signer API. Its private owner helper definitions are copied byte
exact from the accepted original under the root MIT license. The test-only file
allows retained unused fault variants; those variants are outside this selected
profile. Real signer, entropy, durable custody and nonrollback authority remain
unselected. The trusted pipe event is not an authenticated admission grant.

## Corrected local source

- All five [native handoff methods](../qualification-native-partial/tests/native_partial_journal.rs)
  passed in 3.24 s including runner/build time. They
  select 32 owners/admissions in 24 children across four role/leg scopes, with
  24 valid synthetic native partials, four wrong-key backend refusals and four
  before-backend refusals: 28 signing backend entries. Twenty operations retain
  output; twelve reopen unknown. Eight copy/restore subcases repeat actual
  deterministic nonce/partial math with reconstructed test owners. Only the
  fixed public partial crosses the pipe. Selected result loss is not SIGKILL,
  native owner death, power-loss durability or changed-message key extraction.
- The entire original Rust qualification crate is byte exact. All 172 unique
  original methods passed in 15.115 s including runner/build
  time. With the separate five, this is 177 unique methods across two crates,
  not one production signer. Formatting passed. The copied imports emit one
  expected unused-import warning for `LiftedSignature` and `MaybeScalar`; those
  types are retained for exact source copying and unused in this selected profile.
- The completed corrected full Python suite passed all 2035 unchanged unique
  IDs in 1290.506 s; runner 1290.917 s,
  with required OpenSSL and no skips, failures or ResourceWarning lines. All 35
  sealed and twelve measured-adapter method bodies remain exact. The preceding
  44 SIGKILL schedules and eight fixed-output copy/restore subcases remain a
  separate retained qualification.
- Both selected Cargo resolution profiles passed against the unchanged baseline,
  each preparing exactly 55 fixed source files, with runner 130.749 s.
  These are metadata/content comparisons, not cross-platform native execution.
- The separate actual native Apple object-prefix profile completed two fresh
  builds and two public math groups/28 cases, with runner 284.22 s.
  The unsupported local Linux sealed schedules remain refusals, not local Linux
  execution. The initial twenty-method actual exchange run passed unchanged in
  13.829 s with five Apple unsupported-host sealed refusals and one Mach-O/ELF
  format refusal. Go and the full Linux worker profiles are not rerun locally.
- Artifact checks cover 1000 index/worktree versions across 500 tracked files and
  1719 resolved relative file links. Of 493 preceding files, 488 are exact,
  four documents are append-only and the workflow adds exactly two commands,
  preserving every old command and timeout. Seven files are new. All 296 other
  preceding non-document files are exact and all 302 current non-document files
  are frozen. Journal/primitive code, old actors/tests, fixtures, locks, fixed
  inventories, baselines and qualifiers remain unchanged. The separate crate
  changes only its root package identity in the copied dependency lock; dependency
  versions and declared dev-dependencies are the same.

## Original failure and correction

The initial source `9464833106b6199cdb33e4f423ed48297c121a42` passed its local
2035 Python methods in 1277.536 s and all 177 Rust methods.
The [first hosted run](https://github.com/edgepillar/ptlc-research/actions/runs/37719771165)
passed its native math tests but failed two fixed-source preparation steps. The
modified existing owner file was the sole differing member of the 55-file selected
qualification source. The guard correctly refused it; this is not a nonce or
signature test failure. The actual Apple profile and later Linux worker groups
were not qualified by that failed run.

One layout correction restores that file byte exact and moves the bridge to a
separate unpublished crate with exact copied owner helpers. Two additive native
CI commands test and format it. No fixed guard, inventory, baseline, dependency
version or production cryptography is changed. The targeted native suite and full
Python suite are each rerun once for this corrected source; original passes and
failed hosted job logs are retained. No local test failure, hidden fallback or
interrupted full run occurred. Three read-only guessed-path lookups missed; actual
filenames were then used. One private preflight summary retained the prior stage
number despite candidate-bound guards; it was corrected and its original retained.
A private local metadata finalizer first stopped on a blanket zero-warning
assertion for the known copied-import diagnostic. Only that helper check was
corrected to accept exactly the disclosed warning and rerun once. Its original
assertion error and both helper/orchestration exit 1 results remain retained.
No test or repository source was changed by this metadata correction.

Four fixed inventories, the earlier author handoff inventory and three unfilled
reports remain exact. No independent reviewer is contacted or assessment claimed.
Source-to-worker and reproducibility remain **NOT VERIFIED**; private consumed
inputs, producer origin and loaded runtime remain **NOT AUTHENTICATED**; privacy
remains **NOT ASSESSED**. No wallet, funds, chain, artifact release, broadcast,
deployment, activation, merge or core action is qualified.
