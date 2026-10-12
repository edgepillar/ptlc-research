# Pool dependency controls: validation boundary

Qualified source: `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; research baseline:
`38fc1cb13e80f2583ab17b61004402ead25d95a1`. Profile:
`zenon-pr138-pool-dependencies-v1`. All preserved inputs remain exact.

## Bootstrap evidence

The first new native bootstrap failed to compile because its own overlay tried
to call concrete event callbacks through the narrower public pool interface.
The overlay now explicitly asserts the public callback interface. Core source
and the public pool interface remain unchanged.

The second bootstrap failed with an actual pool pending-list panic when the
overlay queried between stable-root rollback reconstitution and the required
callback. Its old manager base still contained the promoted send, while the
selected stable root had already become empty. The fixed driver records only
stable/ledger/confirmation/mailbox reconstruction in that interval, then calls
the actual callback before reading the pool. It does not catch the failure and
report success, change core behavior, or claim atomic/concurrent caller safety.
Production callback ordering and concurrency remain separate requirements.

Both failed original attempts retain their commands, complete available streams
and all four pre-execution overlay source copies. Their failed outcomes remain
failed. The third native bootstrap passed four outcomes and the complete
independent projection. A fourth accepted bootstrap tightens readback: exact
confirmation lookup still runs when the send lookup is absent, and both global
map cardinalities are checked. Its complete projection supplied the final
fixture. The initial Python regression was intentionally interrupted for this
refinement and supplies no success; its original partial stream and all 25
completed native outcomes for the earlier readback subject remain retained. Prior accepted archives, old
failed evidence and the earlier profile's missing first-bootstrap source copy
remain preserved without reconstruction or reclassification.

## Local regression

Complete Python 3.12.14 regression passed 2,890 tests with required OpenSSL, zero skips and zero ResourceWarnings. All 32 new and 432 preserved directed methods occur with exact identities in the complete stream. All 496 selected code/fixture/CI/test hashes and 770 preserved baseline files stayed unchanged. Locked Rust subjects passed 202 tests (188 primary and 14 native), examples and both format checks. Standalone Go passed 58 top-level tests with normal vet. All 25 native steps and complete offline module-content checks passed. The new qualifier freshly reran all 287 preserved source outcomes followed by four new native outcomes, reproducing all 23 separate candidates, normal admissions and post-callback original queries. Two nonempty send callbacks removed the complete dependent recipient manager. Six unrelated originals survived and three unrelated stale suffixes disappeared. Index/worktree artifact checks cover 1,560 versions of 780 files; whitespace checks pass. Metadata, destination and hosted acceptance remain separate subsequent checks.

## Hosted acceptance

Publication requires fresh exact-head PR checks and the integrity and semantic
contents of their original complete log archive before history-preserving main
integration. Push-triggered main checks and their separate original archive
are an additional acceptance gate. Failed, skipped, pending or missing evidence
never supplies success. A PR description records acceptance only after these
checks pass. Original archives are not rewritten or normalized.

Overlay vet is explicitly not performed for synthetic Go 1.23 overlay paths;
standalone Go runs normal vet. Hosted private stream retention can be ephemeral.
Independent machine, source/host authentication, currentness, canonicality,
finality, custody, restore and construction assessment remain unfilled.
Application/core stay **NO-GO**. Recovery action remains **NONE**.
