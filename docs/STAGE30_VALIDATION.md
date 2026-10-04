# Stage 30 validation: candidate observation authority contract

Scope: a new pure bounded scope/request/reply codec and adversarial binding tests.
It implements no enrollment owner, service, authenticated transport, durable
authority, dispatcher, worker-start capability or integration with existing
entry points. Existing application modules, journal/records/store, worker/resource
paths, models, cryptography, qualifiers, workflows and dependencies are unchanged.

Source parent: [`01f0a647b2f2de27209cfd45b4b4158c8ea9b802`](https://github.com/edgepillar/ptlc-research/tree/01f0a647b2f2de27209cfd45b4b4158c8ea9b802).
Its [seven successful jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37210225868)
ran 663 Python tests per Linux/macOS 3.11/3.13 job with required OpenSSL,
55 Rust tests, 13 Go top-level tests and 68 actual-worker cases including
17 v4 cases. Parent execution is not execution of the new codec delta.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| First new contract suite | 29 passed in 42.573 seconds, no skips | Pure scope/request/reply binding, strict numeric types, declared transition checks and explicit forgery/replay limits |
| Full required offline suite | 692 passed in 749.088 seconds, no skips | Required OpenSSL; all new codec and existing lifecycle, actual-file, native/refusal and fixed-inventory methods |
| Artifact, links, whitespace and frozen manifests | 412 staged index/worktree versions, 206 tracked files, 659 valid relative file links; two affected Python files parse; whitespace and both fixed hashes pass | Limited ASCII/disclosure checks, source identity and packaging; no anonymity or independent assessment guarantee |

No failed Stage 30 test run is omitted. Before the first run, inspection tightened
before-head echo validation to reject Boolean/float aliases despite Python's
numeric equality, and added sanitized incomplete-head refusal. The tests exercise
these checks for successful, not-applied and unresolved claims. No runtime entry
point, authority requirement or dispatch premise was weakened.

The 29 methods cover both retained bundle/release domains, exact public context
and selected profiles, candidate-independent scope, changed sessions/terms/nonce
rounds/bundles, rejected local-label overrides, finite numeric bounds, malformed
or wrong-stage state, sealed factory objects and defensive copies, full head
partitions, exact target/request digests and locally selected wire matching.
All four operation phases and their statement partitions are exercised, including
wrong attempts, busy/exhausted/max-revision heads, explicit normal/unknown claims,
wrong profile/target statements, noncanonical and duplicate/deep JSON, hostile
local subclasses and sanitized bounded input refusal.

Reply tests bind every echo and before head, require single-revision/no-refund
declared transitions, reject skipped charges and contradictory pending/dispatch
markers, and distinguish not-applied from unresolved/missing/malformed replies.
The last JSON-safe revision is accepted only as a claim; no automatic epoch
rollover follows. Existing cryptographic algorithms are not executed as an
authority authentication mechanism.

Explicit negative evidence is retained: a forged matching success parses twice,
the same request ID can label different proposals, invalid signature math can
be formatted, and a selected target limit does not enforce a target set. Parsed
claims supply no authenticated truth, current head, enrollment, idempotency,
durability or one-use dispatch. The real reopened exhausted-journal case checks
unchanged state/sequence and exact SQLite/checkpoint bytes, preserved original
candidate and zero recovery callback entries after pure forged claim parsing.
Its journal setup/verdict callbacks are synthetic; it is not an authority service
or actual worker-entry qualification.

## Reproduction and remaining gates

From the repository root, without network or an authority:

```sh
python3 -B -m unittest discover -s tests -p test_authority_contract.py -v
REQUIRE_OPENSSL=1 python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
python3 -B scripts/check_observation_subject.py --expect-commit f81e376e96e339647bb065739b4461235f865d2c
git diff --check
git diff --cached --check
```

All seven exact-head hosted jobs remain required. The four Python/OpenSSL jobs
must execute the 29 new contract methods and complete both fixed-inventory checks.
The unchanged Rust/Go and nine actual-worker groups remain selected; expected
counts are 55, 13 and 68, including 17 v4 cases. They do not execute or supply an
external authority. Native Linux actual-worker checks and unchanged Rust/Go
primitives are not rerun locally on macOS for this pure codec delta.

Configured CI and parent execution supply no new hosted execution. Completed
exact-head results must be recorded separately from this source report. Both
independent assessments remain unfilled; their fixed 119-file and 189-file
subjects are unchanged. The [candidate contract](OBSERVATION_AUTHORITY_CONTRACT.md)
requires a separate exact delta assessment and selects no backend. Authentication,
canonical enrollment, non-rollbackable history, durable one-use dispatch, physical
containment, funded recovery and secret nonce ownership remain unresolved. Core
port, node activation, private signing and real funds remain no-go.
