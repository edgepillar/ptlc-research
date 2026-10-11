# Send-derived NoM witness validation

Research baseline: `7327a9c52d657192871f5a1958bb530d4ea63a9b`.
Application/core remain **NO-GO**. See [scope and remaining gates](NOM_CREATED_FUNDING.md).

The complete local Python 3.12.14 suite passed 2,575 tests with required
OpenSSL, zero skips and zero ResourceWarnings. This includes all 20 new tests,
38 preserved opening controls, 48 authority/framing/model controls and 43
retention/death controls. All 431 code/fixture/CI/test files retained their hashes
through regression; all 678 preserved base files remain unchanged.

Both locked Rust suites passed 194 tests (180 primary and 14 native), including
three new send-derived witness/recovery/replay tests. Examples and both format
checks passed. The standalone Go suites passed 58 top-level tests. Actual unchanged
core momentum/wire/observation comparisons passed 51/45/37 tests including parents.
The new actual-created funding comparison passed 71 tests including its parent:
70 independent source controls, 35 per leg, over 20 public funding hash inputs.
Both legacy and new public recovery qualifiers passed; the new one used the
existing empty-environment profile. Separate complete core module-content checks
passed with network disabled and normative source module files unchanged.

The final directed Python run passed 20 tests without skips or warnings. Its
first run failed one test because it called `.hex()` on the frozen helper's
already-hexadecimal string. That assertion was corrected; no hash/witness helper
or old implementation was changed. Original first-run stdout/stderr and their
hashes remain preserved privately, together with all historical failed evidence
and original CI archives. No native/source comparison failed in this increment.

Staged/index/worktree artifact checks covered 1,384 versions of 692 files; staged
and worktree whitespace checks passed. Generic unsigned UTC commit metadata and
the exact publication destination are separately reviewed before publication.

Hosted PR checks, complete original console archive verification and exact-head,
history-preserving integration remain separate acceptance gates. Push-triggered
main CI is a further gate; a green PR result does not satisfy it. Completed
hosted evidence is recorded in the PR only after exact-head verification.

The first hosted PR run failed the generic Python matrix because its new actual
worker test assumed the executable built in a different job was available. The
native adaptor/created-recovery, fresh-worker and unchanged-core jobs passed.
That assumption was removed in a separate history-preserving commit: generic
Python tests now require missing-worker refusal before any journal opens; actual
native success remains mandatory in the dedicated job after example builds.
Original failed job logs and the complete failed workflow archive are retained
separately. The earlier local result is not a hosted pass. Corrected local and
fresh hosted acceptance gates must be completed before main integration.

The corrected local Python 3.12.14 suite passed all 2,575 tests with required
OpenSSL, zero skips/ResourceWarnings and unchanged hashes of all 431 selected
code/fixture/CI/test files. The corrected directed run passed 20 tests. The actual
created-context public worker recovery was rechecked separately and passed under
the empty-environment profile. The previous 194 Rust, 58 standalone Go and
51/45/37/71 source comparison results remain source-current: their measured
native source/fixture/qualifier hashes are unchanged by this tests/docs repair.
The complete failed original PR workflow ran 2,575 tests in each Python profile
with the same missing-worker error; all four profiles failed and seven other
jobs passed. That run and its original ZIP are not reclassified as success.
Corrected staged artifact checks cover 1,384 versions of 692 files; whitespace
checks pass. A fresh hosted run at the appended commit is mandatory before main.

These checks do not qualify the full VM, account signatures or custody, balance
accounting, acknowledged context authority, source/proof provisioning,
canonicality/finality, nonrollback current/restore mechanisms, atomic journal
entry or independent security assessment. The two legs use independent core
method stubs; public journal observations remain a synthetic allowlist. A receive
confirmation timestamp is not the method's execution frontier. The compiler,
cache, environment and host remain trusted. Overlay vet is unperformed. Hosted
private native streams and transient journal files are ephemeral and are not
included in the retained console ZIP; their underlying custody remains
unqualified. No deployment, activation, wallet access, application signing,
broadcast or real funds are performed. Application/core remain **NO-GO**.
