# Stage 24 validation: durable explicit worker resources

Scope: a separate Linux-only v4 store entry binds an explicitly selected
CPU/address-space profile. Ordinary v3 work, pure records, mathematical profile,
pool configuration, journal and cryptographic sources remain unchanged.

Source parent: [`c0fcec8828c8506e61b3d5da0c412a18f43d1845`](https://github.com/edgepillar/ptlc-research/tree/c0fcec8828c8506e61b3d5da0c412a18f43d1845).
That parent had [seven successful hosted jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37188886865):
563 Python tests in each Linux/macOS 3.11/3.13 job, required OpenSSL, 55 Rust
checks, 13 Go top-level tests and 51 actual selected-worker cases. This is parent
evidence; it does not execute or independently assess the v4 delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| Existing store/crash/resource suites | 59 passed in 38.905 seconds, no skips | Ordinary v3 regression and synthetic resource policy checks |
| Initial v4 continuity cases | 23 passed in 13.166 seconds, no skips | Supported-host selection and mathematical outcomes are simulated |
| Local v4 platform cases | 5 passed in 0.439 seconds, no skips | macOS refusal before creation, not native Linux enforcement |
| Combined suites before selection preflight | 92 passed in 53.588 seconds, no skips | Includes inherited v3 process-death cases |
| Final combined suites after pre-SQLite selection | 93 passed in 53.404 seconds, no skips | Adds wrong-policy/downgrade refusal with a private sidecar fixture |
| Full required offline suite | 592 passed in 599.689 seconds, no skips | Independent OpenSSL required; local macOS resource platform cases are refusal only |
| Seven existing actual selected-worker qualifiers | 48 passed, no skips | Existing actual v3 and pure behavior; no new Linux v4 claim |
| Artifact, local links and whitespace | 364 index/worktree versions, 182 tracked files, 490 valid local Markdown links; final whitespace clean | English/ASCII and disclosure-pattern checks passed |

The first staged whitespace check found an extra EOF blank line in both new
documents; those were removed before delivery. No failed regression run has
occurred in this stage. The Stage 23 fixture failure
belongs to its historical report; no cryptographic repair is introduced here.
Rust/Go primitives and their dependencies are unchanged and are not rerun locally
for this delta; their exact-head hosted jobs remain a separate gate.

## Continuity, ordering and failure evidence

Twenty-four synthetic cases cover explicit v4 identity, byte-identical matched
reopen, ordinary v3 compatibility, rejected upgrade/downgrade, CPU/address-space
change, pending preservation before wrong-policy recovery, unchanged math/pool/
budget bindings, missing/unsupported policy, live policy change, three held
references, saturation and exhaustion. Normal negatives, conflicts, unavailable
work, cancellation and returned-result loss preserve the existing error partition.
Anchor and SQLite profile corruption quarantine without automatic repair.

Selection is now checked in the bounded checkpoint before SQLite connect.
The private sidecar fixture tests refusal before connect; it does not simulate a
complete native SQLite rollback-journal recovery. The complete canonical pair
must still validate before any pending record is interrupted.

Five controlled native Linux cases separately cover mapping/CPU failure as
charged unknown, owner death with matched pending recovery, guard-loss exclusion
before SQLite access, and cancellation without a cooperative release shortcut.
Signals target only tracked owned unreaped children, never cached worker PIDs.
On the local macOS host these cases test explicit refusal only.

## Actual Linux and hosted gate

The new [actual v4 qualifier](../scripts/qualify_observation_resource_store.py)
has eight cases using the selected Rust public observation executable: positive
and negative cached reopen, wrong-policy pending preservation, downgrade refusal,
unsupported-host and missing-policy refusal, busy-before-charge then actual work,
and actual returned-result loss recovering unknown. Every case checks unchanged
journal state, sequence, database and checkpoint bytes.

The new actual qualifier and native Linux enforcement are not run locally.
The existing Stage 23 three-case qualifier is likewise Linux-only. Configured CI
adds the new qualifier to the Rust job, alongside the unchanged seven-job matrix.
Only completed exact-head logs establish that these new Linux paths ran.
Hosted execution must be recorded separately; a configured step is not proof.

## Progression decision

The [v4 design](DURABLE_RESOURCE_POLICY.md) binds requested local policy
consistency. This is not effective-cap attestation, RSS, a hard elapsed-time cap,
an aggregate budget, a sandbox or protection from privilege/capability changes.
Guard/caller/bootstrap, clone/restore bypasses, enrollment, fairness and funded
availability remain outside it. No source, recovery admission, signer or node
activation is connected.

Next qualify real process-death cuts for each v4 storage/recovery boundary before
policy rotation or broader resource admission. Independent assessment remains
pending; the frozen 119-file Stage 12 subject and its manifest remain unchanged.
