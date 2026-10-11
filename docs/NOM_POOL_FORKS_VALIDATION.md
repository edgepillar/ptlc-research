# Separate pool controls: validation boundary

Source: `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; research baseline:
`1b8cc453f1bc5753f7995c054d384df1f6d0ad42`. Profile:
`zenon-pr138-pool-forks-v1`. All preserved inputs remain exact.

## Bootstrap evidence and corrections

The first native bootstrap exceeded its existing 240-second deadline. Its own
overlay repeatedly dumped the entire layered memory state around every generated
candidate, imposing unnecessary work. All three original overlay source copies,
commands, available streams, framing and original outcome remain retained. The
original outcome field was `UNKNOWN` after the exception; the retained command
deadline failure is separately classified as failed/incomplete, never accepted.

A premature projection attempt read that incomplete stream and refused it.
Its original failure evidence also remains retained. No partial stream supplied
the selected fixture.

The second native bootstrap reached all cap operations but refused its complete
record because repeated checkpoint wire lists exceeded the fixed eight-MiB record
bound. Its three source snapshots and complete failed streams remain retained.
No native bound or source cap was increased to pass it.

The overlay now checks each generation's frontier without repeatedly dumping
all prior layers; complete logical checkpoints independently verify state. The
pending sequence uses the documented exact length-framed wire digest while all
source candidates remain retained. The third bootstrap passed six native tests
and the complete independent Python projection before fixture selection.
No source implementation, old helper, old reader, old original or old fixture was
changed. No current-run original source snapshot is missing. The earlier pool
profile's first-bootstrap source-copy gap remains a separate unfilled historical
custody fact and is not repaired or relabeled here.

## Local regression

Complete Python 3.12.14 regression passed 2,858 tests with required OpenSSL, zero skips and zero ResourceWarnings. All 32 new and 400 preserved directed methods occur with exact identities in the complete stream. All 490 selected code/fixture/CI/test hashes and 762 preserved baseline files stayed unchanged. Locked Rust subjects passed 202 tests (188 primary and 14 native), examples and both format checks. Standalone Go passed 58 top-level tests with normal vet. All 24 native steps and complete offline module-content checks passed. The new qualifier freshly reran all 281 preserved source outcomes followed by six new native outcomes, reproducing all 522 separate candidates, 519 normal admissions, two priority refusals, two cap duplicates, one source-valid 501st cap refusal and 24 historical views. The actual cap stayed 500. Index/worktree artifact checks cover 1,544 versions of 772 files; whitespace checks pass. Metadata, destination and hosted acceptance remain separate subsequent checks.

## Hosted acceptance

Publication requires fresh exact-head PR checks and the integrity and semantic
contents of their original complete log archive before history-preserving main
integration. Push-triggered main checks and their separate original archive are
a further acceptance gate. Pending, failed, skipped or missing outcomes never
supply success. A PR body records hosted receipts only after these checks pass.

Overlay vet is explicitly not performed for the synthetic Go 1.23 overlay paths;
standalone Go runs normal vet. Hosted private stream retention can be ephemeral.
Independent machine, source/host authentication, currentness, canonicality,
finality, custody, restore and construction assessment remain unfilled.
Application/core stay **NO-GO**.
