# Stage 10 validation: durable local authentication pins

Scope: freeze optional Bob authentication pins at exchange start and reconstruct
the existing envelope verification context from stored terms and pins. The
journal-scoped helper writes nothing. It grants no admission authority and
leaves both raw recovery paths available without an envelope.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode full Python suite | 282 passed, no skips | Prior 262 tests plus 20 durable-pin and process-death tests |
| New durable-pin boundary suite | 18 passed after test fixture corrections | Strict inputs, restart, continuity, callback ownership and zero-write behavior |
| New process-death tests | 2 passed, 5 SIGKILL cases | Four Bob start commit checkpoints and one read-only authentication checkpoint |
| Actual authentication subprocess integration | 11 passed | Existing 6 envelope cases plus 5 durable-pin cases with real public verifiers |
| Existing artifact/completion subprocess integration | 2 plus 6 passed | Current journal with the unchanged actual Rust executables |
| Artifact hygiene, local links and whitespace | Passed | Limited source checks, not comprehensive secret detection or anonymity |

Local execution uses Python 3.9.6 on macOS and previously built pinned public
Rust executables. The final required-mode Python run includes the independent
OpenSSL regression verifier. All nineteen subprocess integration tests run
separately from Python discovery. Rust/Go sources, dependencies and fixtures
are unchanged and their suites were not independently rerun locally for this
journal-only change. Hosted results must be read from the corresponding
commit/PR checks; the existing CI matrix continues to run those suites.

## Binding and ownership evidence

Tests configure copied optional pins at Bob start and reopen with the same
stored pair. The context always derives from the retained Bitcoin terms.
Caller changes to input dictionaries and returned snapshots cannot replace
stored pins. Wrong fields, types, encodings, equal keys and overlap with the
explicit swap keys reject. Python still checks encoded separation, not curve
membership; real verification performs the latter.

Continuity tests reject changed/removed pins, late pin setup after an unpinned
start, coherent changes of stored Bitcoin context or terms, and session removal.
Malformed stored bindings and a correctly resealed v6 checkpoint quarantine
without modifying either file. Restoring both matching pre-start snapshots
deliberately demonstrates that the choice can be erased and reconfigured.

Successful, failed, cancelled and repeated authentication preserve the database,
anchor, sequence and complete session snapshot. Verification is available at
all Bob stages. Callback tests exercise reentrancy, cross-session mutation,
close, thread/fork ownership and competing owners. The helper rechecks owner
identity before returning bytes. None of these checks makes an arbitrary
callback, hostile host or rewritten implementation trustworthy.

## Crash and actual cryptographic evidence

The start matrix terminates a real child at the existing persistence checkpoints.
Before database commit, the generic session survives with no selected pins.
Committed database state without a matching checkpoint quarantines. Matched
start snapshots retain the complete Bob exchange and its pins after reopen.
An additional child is terminated while executing the read-only verifier;
reopening retains byte-identical storage and the same unused recovery allowance.
These are process-termination tests, not power-loss simulations.

Real subprocess tests authenticate using persisted pins after reopen, reject
remote context substitutions before the worker, and reject a bad outer signature
with the actual Rust verifier. Correctly authenticated invalid inner completion
bytes still fail actual recovery. Neither successful nor failed helper calls
record or clear possible witness exposure. A raw completion succeeds without
an envelope even with pins configured, and raw reconciliation preserves pins
while archiving/replacing its candidate under existing rules.

## Intermediate results

The initial 18-test pin run had two test-side `KeyError` errors from reading
the synthetic terms at the wrong nesting level; the other 16 tests passed.
The fixture access was corrected without changing journal behavior, and the
new 20-test focused set passed in 7.383 seconds. The final focused run passed
45 tests in 93.009 seconds, including the new tests and affected existing
recovery/reconciliation regressions. The full required-mode suite passed all
282 tests in 337.465 seconds with no skips. Parallel review found no implementation defect;
it is not an independent human security or construction audit.

## Compatibility and remaining gates

Journal schema and digest domain advance to v7; versions 1 through 6 are
quarantined without migration. Public packet schemas, authentication messages,
cryptographic dependencies and fixtures remain unchanged. The optional keyword
preserves unconfigured behavior, but its absence is now an immutable choice
once Bob mode begins.

The [durable-pin design](DURABLE_AUTHENTICATION_PINS.md) separates local binding
from key establishment, freshness, evidence retention and authenticated
admission. Authentication consumes no recovery allowance and repeated calls
remain a separate resource-policy issue. Restored copies and arbitrary host
rewrites remain outside the local continuity guarantee.

Peer-message admission cannot be a universal prerequisite for public-witness
recovery: Alice can publish a valid Zenon signature while withholding the
auxiliary envelope. Trusted observation authorization and evidence retention
still need separate design. Authentication rejection does not prove that a
witness remained private or authorize resetting a signer. Private signing,
clone protection, authenticated chain identity, funded timing and independent
construction review remain prerequisites. Live swaps and a core port remain
no-go.
