# Public native suspension and custody intervals

Status: **TEST-ONLY PUBLIC SYNTHETIC QUALIFICATION. NO CUSTODY AUTHORITY
IMPLEMENTED.** This experiment makes a suspended native continuation observable.
Policy acceptance, epoch and commit are local coordinator labels. They are not
authenticated revocation, a nonrewinding order, a lease or a private work permit.
All SC01-SC12 requirements remain OPEN; application/core remain NO-GO.

## What is exercised

The [authority interface proposal](CUSTODY_AUTHORITY_INTERFACE.md) requires an
earlier affected effect interval to end, or every usable continuation to be
certified fenced, before effective revocation can commit. An elapsed deadline
does not establish this condition. This test applies real process suspension
and three orderings to the existing public synthetic nonce owner.

The [Rust test](../qualification-native-partial/tests/native_custody_intervals.rs)
has three methods. Each exercises Bitcoin/Alice, Bitcoin/Bob, Zenon/Alice and
Zenon/Bob: twelve fixed process cases in total. A separate
[Python coordinator](../tests/native_custody_interval_actor.py) launches exactly
one selected native child per case. The child consumes its nonce option, checks
the complete ordered context and acknowledges `before-backend`, with zero
backend entries. The coordinator then sends actual SIGSTOP and observes the
OS stopped-child status. A finite synthetic deadline elapses with no output.
The nonce still exists in the suspended call's local stack; removing it from
the owner's option did not erase it.

| Mode | Observed ordering | Native computation | Original after reopen |
| --- | --- | --- | --- |
| `early-commit` | Stop, deadline, synthetic fence/commit, resume, compute, retain, finish/reap | One actual partial after the synthetic commit label | Exact retained bytes replay twice without new backend work |
| `pending-completion` | Stop, deadline, synthetic fence, resume, compute, retain, finish/reap, synthetic commit | One earlier admitted partial while the synthetic commit remains pending | Exact retained bytes replay twice without new backend work |
| `kill-before-commit` | Stop, deadline, synthetic fence, SIGKILL/reap, synthetic commit | Zero entries and no retained partial for this observed child | Consumed/unknown remains spent; replay and replacement refuse |

The first mode is an intentionally invalid early-commit negative control. Its
real computation demonstrates why suppressing an outward result, timing out or
declaring revocation cannot invalidate an already usable native continuation.
The second permits the earlier admitted interval to finish before the synthetic
commit, at the cost of waiting. The third observes termination and reaping of
this one selected child before the synthetic commit. A kill request alone is
not the asserted termination evidence.

Neither positive ordering establishes a real custody construction. The native
owner never reads the synthetic policy, authenticates a revocation, obtains
nonrollback state or shares an effective-policy order with an issuer. The
coordinator's in-memory fence refuses its modeled new outward-release attempts.
That assertion does not prove private release enforcement or transport behavior.
The experiment does not restore process images or enumerate other usable copies.
It proves neither all-copy fencing nor secure erasure, and it does not qualify
abrupt coordinator death, private recovery or platform administration.

## Actual public computation and retention

The selected owner invokes the pinned backend's actual `adaptor::sign_partial`
and `adaptor::verify_partial`. It uses the existing complete ordered nonce round,
per-leg keys, Bitcoin Taproot refund tweak, adaptor point and exact message.
All inputs are fixed public test constants. No input path for a private scalar,
nonce seed, wallet or entropy source is added. The actual serialized partial
must equal the existing public fixture for the selected party/leg. A second
call on the same native owner refuses as spent without another backend entry.

The completed frame carries those actual public bytes over the internal test
harness pipe into the existing journal callback. This is internal retention in
the experiment, not outward private delivery or authenticated original
provenance. Both continuation modes retain `OUTPUT_RECORDED`; the journal is
closed and reopened, the exact original replays twice and another producer,
nonce tag or replacement operation is refused. The killed mode retains no
output, starts as `CONSUMED` and reopens as `OUTCOME_UNKNOWN`; none of those
outcomes authorizes a new nonce, operation, session or reset as repair.

Important checks run outside the journal callback's exception wrapper. They
require the exact acknowledged pauses, stopped-child evidence, ordering,
callback count, backend/partial counts, exit status, retained/unknown state and
release refusals. An unrelated callback failure cannot qualify merely because
the journal turns it into an unknown outcome. Frames, waits and output are
bounded. The coordinator emits one public JSON result or a constant sanitized
refusal. Local process identifiers and paths are not result fields.

## Selected source and reuse

The selected local MIT source is immutable commit
`3624a2408819935d614ee13ebf3b4f56f97f870a`, tree
`5b3364e6b56972a4d5f825543d28ac61a4d08c52`, specifically
[the preceding nonce-boundary owner](../qualification-native-partial/tests/native_nonce_boundary.rs)
with SHA256
`b6db9b59f31c0039a89946e5a21cc66dce1e64eefcf42ebb18d88530e8d99d92`.
Its selected owner/context/nonce/backend block is copied byte exactly into the
new test, including existing unused variants; the original file and its three
test methods remain unchanged. The new process wrapper is separate so the old
child's exact libtest method inventory and framing remain unchanged. Reused
material is covered by the unchanged root [MIT license](../LICENSE). No new
external implementation or dataset is copied; the existing pinned dependencies,
licenses and attributions remain unchanged.

The Python actor reuses the preceding bounded public frame reader, native-child
cleanup and spent-journal assertions. It does not modify their source, existing
journal behavior or a production API. Neither reference arithmetic nor fixture
agreement qualifies application cryptography or the replacement swap protocol.

## Evidence and remaining decisions

The [local snapshot](STAGE99_VALIDATION.md) separates the three new native Rust
methods from the unchanged Python suite and from fresh hosted scopes. Existing
CI runs the new Rust file as part of the native qualification crate. Successful
method results establish the twelve source-defined fixed cases; the workflow
does not publish a new standalone twelve-case JSON report. Existing Linux and
Apple worker inventories are separate and unchanged.

The [candidate](CUSTODY_CANDIDATE_01.md),
[mechanism feasibility study](CUSTODY_MECHANISM_FEASIBILITY.md),
[finite model](CUSTODY_ENTRY_MODEL.md), and descriptive authority record remain
unchanged. Their physical F1-F4 and future construction A01-A12 acceptance cases
are NOT EXECUTED. This narrower public suspension experiment relates to the
suspended-worker concern but does not execute or close construction case A04.
The same effective-policy issuer/owner order, protected actual inputs,
independent nonrewinding anchor, all-copy fencing, exact-original authentication
and separately current outward releases remain unresolved. Independent
assessment is absent; no reviewer is contacted. Real signer and platform remain
UNSELECTED / NOT IMPLEMENTED. Private inputs, producer and runtime remain NOT
AUTHENTICATED; source-to-worker/reproducibility remain NOT VERIFIED; privacy
remains NOT ASSESSED. No hardware/cloud provisioning, funds, wallet, broadcast,
live chain, activation, deployment or core contribution is authorized by this
test.
