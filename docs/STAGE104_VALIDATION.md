# Stage 104 native rollback and secondary cleanup observation

Status: **NATIVE ROLLBACK BOUNDARIES AND COMPLETE LOCAL REGRESSION PASS; FRESH HOSTED QUALIFICATION PENDING AT THIS SNAPSHOT.**
Fresh exact-head hosted qualification is separate and has not run for this
candidate. Application/core remain NO-GO.

## Subject and selected limits

The immutable parent is `3cbd6845962e90469e10dd7b1bce05cb56f18f9b`, tree
`60bffb361eea423617be2ab9bdf2873bfdf197ed`. Two added test sources provide an
explicit native-authorizer fixture and eight methods. The store, original
actor, observer, classifiers, all 319 preceding non-document sources,
dependencies, workflows, fixtures, review packets, primitives/journals, custody
proposals and MIT license remain unchanged. No external implementation is copied.

The [scope note](POLICY_EFFECT_CONTENTION.md#native-rollback-and-secondary-cleanup)
distinguishes native command failures, repeated cleanup rollback, connection
disposal, original reply emission, context exit, process status and separate
reopen observations. Authorizer denial is a deliberate native SQLite control;
it does not reproduce a natural fault or the earlier hosted environment.
No SQL, timeout, cap, request binding, strict `[0,20]` expectation or retry policy
changes. All preceding tests remain exact.

## Focused execution

All eight added methods pass in 0.298 s (runner 1.113 s), selected Python 3.12.14 /
SQLite 3.53.1, required OpenSSL environment, no failures, skips or ResourceWarnings.
Two source-defined child executions delegate the actual original actor, one
legacy and one observed. Each emits an unknown outcome before a secondary
context-exit refusal terminates the process with exit 1. The fixed stderr hook
omits traceback and private data; it does not override the native exit. The
observed report retains event-insert and two rollback errors with null codes.
Native authorization refusal is outside the unchanged exact-code-5 allowlist.

Direct controls cover COMMIT BUSY plus denied rollback, denied event insertion,
stale policy refusal, successful second cleanup rollback, exact cancellation
propagation, committed refusal without a rollback statement, and native
closed-cursor/state failures outside execute observation. Closed handles refuse
later commands. Readback is explicitly unavailable locally or separately
available after reopen. Postcommit unknown retains one original charge and no
effect; precommit controls retain zero after close/reopen. No report or exception
establishes that result without the separately asserted rows.

## Remaining acceptance scope

Complete local regression is recorded below. Artifact/source preservation
checks are separate gates. Fresh exact-head hosted profiles remain separate. The
historical Stage 99 failure cause remains UNRESOLVED. Prior failed logs and
original archives are retained without reacquisition or replacement.
Independent assessment is absent; SC01-SC12 remain OPEN, physical F1-F4 and
future A01-A12 remain NOT EXECUTED. Signer, custody, current-policy owner and
nonrollback anchor remain UNSELECTED / NOT IMPLEMENTED. No wallet, funds,
broadcast, deployment, node activation, main merge, release, hardware/cloud
custody or reviewer contact occurs. Cancellation outside the direct command
boundary and terminal cleanup behavior are not newly repaired or qualified.

The complete 86-method policy focus passes in 8.327 s (runner 8.599 s),
retaining all 78 preceding methods. No qualification method has failed or been
retried for this candidate.

A read-only private CI-parser preflight against retained historical logs
failed because its runtime selector expected spaces in compact canonical JSON.
The original tool invocation and related unexecuted CI helper revision are
retained. The corrected selector is checked against the same original archive;
no current hosted qualification or archive reacquisition occurs for this repair.

A private storage-preparation helper failed with ENOSPC while opening its
before-record file, before any duplicate mutation or complete-suite execution.
Its original source and tool failure are retained; no separate disk log was
written. A byte-exact toolchain duplicate was unlinked and linked to its retained
installed copy. The remaining 115 duplicates were replaced with hard links,
preserving 22938 private evidence-file hashes and all 321 source pins at that
continuation cut. The 116 duplicate paths represent 514718681 apparent bytes.
No unique content or original archive was removed or replaced. This is a local
storage operation, not worker, ownership, durability or future identity proof.

One complete local run on the frozen final sources passes all 2109 exact unique
methods in 1022.165 s (runner 1022.74 s), required OpenSSL,
no skips, failures or ResourceWarnings. All 2101 preceding IDs remain and eight
disjoint IDs are added. All 319 preceding non-document sources remain exact;
two additions give 321 frozen sources. Two documentation modifications and three
added files give 543 files, with 538 of 540 preceding files exact. Full Rust/Go/
Linux/Apple profiles have not been rerun locally for this stage. Hosted execution
and independent assessment remain separate.
