# Stage 31 validation: canonical observation enrollment model

Scope: a separate pure finite comparison of enrollment keys, canonical resource
binding, independent owner facts, atomic uniqueness and registry rewind. It
implements no source/authentication mechanism, enrollment service, backend,
dispatcher or application integration. Existing codec, journal/store entry
points, cryptography, formats, models, qualifiers, workflows and dependencies
are unchanged.

Source parent: [`3ecc884f1b5179f7adb977f6559f16fcf4e6c453`](https://github.com/edgepillar/ptlc-research/tree/3ecc884f1b5179f7adb977f6559f16fcf4e6c453).
Its [seven successful jobs](https://github.com/edgepillar/ptlc-research/actions/runs/37214410686)
ran 692 Python tests per Linux/macOS 3.11/3.13 job with required OpenSSL,
55 Rust tests, 13 Go top-level tests and 68 actual-worker cases including
17 v4 cases. Parent execution is not execution of this new model.

## Local checks

| Check | Result | Boundary |
| --- | --- | --- |
| Initial exploration with 20,000-state caps | Both naive policies reported incomplete; stronger comparisons completed | Deliberately bounded characterization, not failed regressions or security success |
| First new model suite | 26 passed in 103.815 seconds, no skips | Complete default comparisons, exact replay, direct counterexamples, immutable/type/partition checks and CLI cap reporting |
| Follow-up malformed-state guard | One method passed, no skips | Charge-event types are validated before reading generation fields; explicit null-event cases reject with ValueError |
| Full required offline suite | 718 passed in 899.147 seconds, no skips | Required OpenSSL; all 26 new model methods, 29 unchanged codec methods and existing lifecycle/native-refusal/fixed-inventory checks |
| Artifact, links, whitespace and frozen manifests | 420 index/worktree versions; 210 tracked files; 680 valid relative file links; two new Python sources parse; whitespace and both frozen hashes match | Limited ASCII/disclosure and source-identity checks, not anonymity or independent assessment |

No failed Stage 31 test run is omitted. Before the first suite, current canonical
charge binding and audit-reference checks were tightened. Successor pruning then
removed candidates that the same transition rules already refuse; regression
counts and finding traces are unchanged. The default cap was raised to one
million so both naive policies complete. After the first suite was started,
malformed charge-event validation was ordered before generation-field access
and a focused method passed; the full suite includes those current null cases.

| Policy | Reachable states | Transitions | Safety findings |
| --- | --- | --- | --- |
| Scope-keyed allowance | 202,242 | 427,882 | Duplicate canonical enrollment; protected quota exceeded; unauthorized enrollment/charge; unreviewed epoch/profile |
| Caller-claimed resource | 531,522 | 1,075,882 | Same five findings plus charge crossing a canonical binding |
| Canonical source only | 18,626 | 39,666 | Unauthorized enrollment and charge |
| Owner with cached absence check | 5,156 | 12,316 | Duplicate canonical enrollment and protected quota exceeded |
| Atomic canonical owner | 1,954 | 3,714 | None in this finite domain under independent owner/source and non-rollbackable registry premises |
| Rollbackable canonical owner | 9,410 | 19,810 | Reused registration identity and protected quota exceeded |

All 768,910 states and 1,579,270 transitions above are abstract events, not
worker executions. The default domain has two protected budget classes, two
copies, baseline/four single-field variants per class, allowance one, two total
registrations, two charges and one binding loss. Combined variants, more classes,
more losses and larger histories are excluded. The rollbackable comparison
permits one registry rewind; its generation is only an audit marker.

The 26 methods exercise label/epoch/profile splitting, caller-resource alias and
cross-binding charge, canonical knowledge without owner permission, absent owner
facts before enrollment and at every charge, frozen source/profile/epoch checks,
two cached missing checks with different or identical labels, atomic duplicate
refusal and exact shared lookup, lost binding without refund, registry outage,
coherent restore and identity reuse, stale/mismatched binding refusal, distinct
resource allowances and a separate allowance-two quota-splitting trace.
Malformed/unknown types, numeric aliases and inconsistent audit partitions reject;
finding traces replay exactly and every atomic transition preserves unique current
enrollment and charged history. Explicit caps remain incomplete, including when
no finding has yet been seen. CLI output includes no private paths.

Owner facts and canonical classes are fixed environmental inputs, not validated
credentials or implemented context equivalence. Refusing false owner facts in a
model does not authenticate a real caller. Frozen profile/epoch values are a
comparison choice, not a universal rotation rule. No target set, request
idempotency, worker entry, result truth, process containment, native durability,
chain observation or funded availability is proved.

## Hosted and independent gates

All seven exact-head hosted jobs remain required. The four Python/OpenSSL jobs
must execute all 26 new methods, the unchanged 29 codec methods and both complete
fixed inventories. Rust/Go and nine actual-worker groups remain selected, with
expected counts 55, 13 and 68 including 17 v4 cases. They do not supply or execute
an enrollment authority. Unchanged Rust/Go primitives and native Linux actual
qualifiers are not rerun locally on macOS for this separate model delta.

Configured CI and parent execution supply no new hosted execution; completed
exact-head results must be recorded separately from this source report. Both
independent assessments remain unfilled and fixed 119/189-file subjects remain
unchanged. This later [enrollment comparison](OBSERVATION_ENROLLMENT_MODEL.md)
requires its own exact delta assessment. Backend selection, private signing,
funded recovery, core port, node activation and real funds remain no-go.
