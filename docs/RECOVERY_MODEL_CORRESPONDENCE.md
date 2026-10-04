# Selected recovery model traces against the journal

Stage 14 replays selected Stage 11 baseline traces against a real temporary
Bob journal, with comparisons during the admitted callback and after reopen.
It adds qualification code only. Journal v7, cryptographic dependencies, wire
schemas and the finite model are unchanged. No funded admission policy is
selected, and this is not an exhaustive implementation-refinement proof.

## Concrete purpose

The finite model already exposes recovery blockage. Separate journal tests
already exercise exhaustion and replacement. This bridge connects selected
model action sequences to actual durable operations instead of treating those
two evidence sets as automatically equivalent.

The [bridge cases](../tests/test_recovery_model_journal.py) prevalidate each
entire trace against the baseline model and its independent invariants. An
admission must be immediately followed by a supported worker outcome. Each
modeled candidate maps to one fixed public packet in the retained context:
`valid` uses the checked-in Zenon completion and `invalid` uses 64 zero bytes.
These labels select fixed synthetic bytes; they are not runtime verdicts about
arbitrary observations.

Python discovery uses explicitly fake fixture oracles for sequencing. The
[separate qualifier](../scripts/qualify_recovery_model.py) runs nine behavioral
cases with the actual public artifact and recovery executables. Positive
recovery must produce the existing Bitcoin fixture signature; failed attempts
retain their original and cannot produce a result. The three generated shortest
exhaustion traces are selected from complete baseline searches at limits 1, 2
and 3. Replaying those traces does not execute every state or edge of the model.

## Projection and deliberate exclusions

| Fact | Concrete comparison | Limit |
| --- | --- | --- |
| Shared admission count | Exact configured limit and consumed count in the getter, SQLite snapshot and checkpoint sequence | One owned journal; not global rate control or clone defense |
| Retained candidate and archive | Exact packet bytes for the model's fixed identities | No independent source authority or signed provenance |
| Pending admission | Callback reads the already committed candidate/count and matching checkpoint before verification or injected failure | Immediate admission/outcome pairs only; no general pending-event scheduler |
| Completion | Stage, receipt presence, persisted output, expected public Bitcoin signature and exact replay | Public fixture recovery, not private signing or chain acceptance |
| Original retention | Failed reconciliation preserves exact original bytes; positive reconciliation records their archive | Failure is not proof that the original is cryptographically invalid |
| Bob exposure marker | False before any admission, true after an admitted candidate | Model public disclosure can occur earlier and is outside this marker |
| Free replay and external events | Getter, sequence, database and checkpoint bytes unchanged | No chain observation or authorization API is fabricated |

The callback compares the in-memory getter against an independently read SQLite
snapshot and checkpoint sequence. Every completed operation is then compared
again through a newly opened journal. This qualifies matched local persistence
at the selected boundaries; it does not establish power-loss durability,
hostile-storage integrity or resistance to restoring both matching files.

The model's public observation, local authorization, authentication, claimed
inclusion, reorganization and witness knowledge are external facts. They do not
write Bob's journal in this bridge. Peer authentication and explicit local
authorization are model premises supplied by the test driver. The raw journal
does not enforce them. Replaying an authorized public path is therefore not
evidence that an authorization mechanism has been implemented.

Alice's consumed ownership is another starting premise of the model. This
bridge opens only Bob's journal, whose Alice state is absent. It does not
establish Alice's signing history or connect a private nonce owner.

## Failure and availability interpretation

`worker_verify` calls the selected public recovery adapter. `worker_fail`
injects a labeled ordinary exception, and `worker_cancel` injects a labeled
`KeyboardInterrupt`. Both leave the already charged attempt consumed. The
current completion adapter sanitizes `BaseException` into a completion failure;
the journal reports `Conflict`. Cancellation injection is not an actual process
kill or proof about every cancellation mechanism.

Process-death traces and external events interleaved between admission and
outcome are rejected by this bridge. Existing separate process-kill tests retain
their own scope. A trace ending with pending work is not reported as a completed
correspondence run.

After each exhaustion trace, the bridge tries the structurally eligible valid
retry or comparison-guarded replacement. It must raise `RecoveryExhausted`
without invoking the callback or changing stored bytes. Positive, failed and
cancelled reconciliation cases also qualify original retention and eventual
replacement when allowance remains. An intentionally dishonest fake recovery
callback that accepts the ideal invalid candidate must make the bridge fail;
this checks the bridge's ability to notice a model/backend mismatch.

The actual-executable cases reproduce recovery blockage with a retained valid
witness or a later available valid replacement. They do not prove principal
loss: there is no funding, deadline, fee market, chain identity or settlement.
Increasing a count or reserving a finite extra count does not by itself solve
unbounded interruption or adversarial exhaustion.

## Reproduction and progression

```sh
python3 -B -m unittest discover -s tests -p test_recovery_model_journal.py -v
python3 -B scripts/qualify_recovery_model.py --verifier qualification/target/debug/examples/verify_exchange --completion qualification/target/debug/examples/complete_exchange
```

Build the pinned public examples and populate dependencies using the existing
[offline commands](../README.md#run-the-offline-checks). Use the corresponding
executable paths when `CARGO_TARGET_DIR` is configured. The qualifier uses no
node, private signer, network call or real funds. It returns 0 only when all nine
selected behavioral cases pass, and 1 for a failed qualification. Exhaustion is
an expected finding asserted by those tests, not a safe policy verdict.

[Stage 14 validation](STAGE14_VALIDATION.md) separates fake-oracle discovery,
actual-executable results and intermediate failures. This new evidence is
outside the immutable Stage 12 subject in the [review brief](INDEPENDENT_REVIEW.md).
It does not update the frozen inventory or replace independent assessment.

The separate [Stage 15 reserve experiment](RECOVERY_RESERVE_MODEL.md) is not a
policy covered by this bridge. It adds model-only resource lanes and explicit
environment restrictions; the journal and this selected baseline qualifier
retain their existing shared-allowance behavior.

Observation authorization, funded availability, private signer/clone ownership
and chain/funding/time acceptance remain open gates. Live swaps and a core port
remain no-go.
