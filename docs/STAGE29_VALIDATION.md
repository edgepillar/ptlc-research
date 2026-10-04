# Stage 29 validation: observation authority design comparison

Scope: a separate pure finite model, adversarial traces, bounded enumeration,
CLI reporting and explicit trust/implementation gates. It implements no external
service, enrollment, dispatcher, restore defense or application integration.
Application, journal, observation records, cryptography, storage formats,
qualifiers and dependencies are unchanged.

Source parent: [`b94f04d4e03ff747a72c0b6b5f3ab691cf6853f1`](https://github.com/edgepillar/ptlc-research/tree/b94f04d4e03ff747a72c0b6b5f3ab691cf6853f1).
Its [seven successful jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37206694311)
ran 643 Python tests per Linux/macOS 3.11/3.13 job with required OpenSSL,
55 Rust tests, 13 Go top-level tests and 68 actual-worker cases including
17 v4 cases. Parent execution is not execution of the new model delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| First new model suite | 20 ran in 4.038 seconds; 19 passed, 1 failed | The expected rollbackable policy finding set incorrectly included stale entry even though its current-head check remains enforced |
| Corrected model suite | 20 passed in 4.084 seconds, no skips | Expectation distinguishes authority rollback quota/identity reuse from current-head refusal; explicit old-receipt rejection retained |
| Full required offline suite | 663 passed in 715.297 seconds, no skips | Required OpenSSL; all twenty current model methods and existing lifecycle, actual-file, native/refusal and pinned-inventory checks |
| Finite policy comparison | All five policies exhausted their finite domains; counts below | Two copies, allowance one, entry domain two; ideal external state and dispatcher are premises |
| Artifact, links, whitespace and frozen manifests | 404 staged index/worktree versions, 202 tracked files, 638 valid local Markdown links; two affected Python files parse; whitespace and both fixed hashes pass | Limited ASCII/disclosure checks; no guarantee of anonymity or independent assessment |

The initial failed expectation did not expose a model transition that accepted
an immediately stale receipt in the rollbackable-dispatch policy. Its dispatcher
still refuses a mismatched current revision. The corrected suite explicitly
tests that refusal, then restores both authority and local history and requires
quota replenishment and reused receipt identity. No worker-entry quota assertion
or ideal policy premise was weakened. Subsequent state-shape checks also reject
inconsistent charged/pending/resolved partitions before exploration.

| Policy | Reachable states | Transitions | Safety findings |
| --- | --- | --- | --- |
| Local history | 177 | 704 | Scope entry quota exceeded |
| Cached head check | 11,176 | 68,376 | Scope entry quota exceeded; stale entry |
| External charge, copyable receipt | 3,320 | 16,145 | Scope entry quota exceeded; reused receipt; stale entry |
| Ideal external unique dispatch | 372 | 1,853 | None within this finite domain and its ideal premises |
| Rollbackable external dispatch | 7,740 | 45,322 | Scope entry quota exceeded; reused receipt |

All 22,785 states and 132,400 transitions above are abstract model events,
not actual-worker tests. Separate boundary traces retain receipt-loss exhaustion,
authority outage, lost publication and late-result refusal. Explicit state caps
are intentionally incomplete, return exit two and are not failed regressions.

The twenty methods cover coherent local rewind, stale cached reads, copied
charged receipts, revoked local receipt entry, ideal unique dispatch, stale
history/sync, lost acknowledgment, service outage, lost normal publication,
result fencing while old work remains running, authority rollback, normal versus
unknown classification, idle snapshot restrictions, exact enrollment premises,
invalid input, complete comparisons, exact trace replay, invariant transitions,
explicit search caps and CLI status/exit behavior.

An allowance-two deterministic trace demonstrates history recovery with two
abstract running workers and a refused old result; it is not a completed search
of the larger allowance-two domain or an executed process test. These models
provide no native enforcement, mathematical verdict, authenticated source,
physical durability, signer or funded availability evidence.

## Hosted and independent gates

All seven exact-head hosted jobs remain required. The four Python/OpenSSL jobs
must execute all new methods and complete both fixed-inventory checks. The
unchanged Rust/Go and nine actual-worker groups remain selected; their expected
counts are 55, 13 and 68, including 17 v4 cases. They do not execute or implement
the model's ideal authority. Native Linux actual-worker checks and unchanged
Rust/Go primitives are not rerun locally on macOS for this model delta.

Configured CI, parent execution and synthetic events supply no new hosted
execution. Completed exact-head results must be recorded separately from this
source report. Independent assessments remain unfilled; the original 119-file
and separate 189-file subjects are unchanged, and this model lies outside both.
The [authority comparison](OBSERVATION_AUTHORITY_MODEL.md) selects no backend or
wire protocol. Production integration, private signing, core port, node
activation and real funds remain no-go.
