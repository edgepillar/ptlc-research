# Stage 9 validation: offline completion-envelope authentication

Scope: public BIP340 verification of exact Alice-to-Bob bytes against locally
selected terms and dedicated key pins. Authentication is separate from inner
completion validity, freshness, pin enrollment and journal admission. No
production signer, transport, journal migration or new dependency is added.

## Executed checks

| Check | Result | Evidence boundary |
| --- | --- | --- |
| Required-mode full Python suite | 262 passed, 0 failed, 0 skipped | Existing 241 tests plus 21 authentication tests |
| Focused Python authentication suite | 21 passed | Strict local policy, canonical parsing and fake callback/adapter boundaries |
| Locked offline Rust suite | 47 passed | Existing 37 plus 10 actual BIP340 authentication tests |
| Independent Go core-verifier suite | 5 top-level tests passed | New fixture message reconstruction and signature verification with pinned btcec |
| Independent Go Bitcoin suite | 8 top-level tests passed | Existing transaction/script-engine qualification |
| Actual authentication subprocess integration | 6 passed | Public authentication, existing completion verification and journal composition limits |
| Existing artifact/completion subprocess integration | 2 plus 6 passed | Separate real public executables and synthetic journals |
| Formatting, workflow syntax, local links and artifact checks | Passed | Limited source hygiene, not anonymity or comprehensive secret detection |

Local runs use Python 3.9.6 on macOS, Rust/Cargo 1.90.0 and Go 1.23.12 with
previously populated dependency caches. Required Python mode includes the
independent OpenSSL regression verifier. Go's historical compatibility versions
remain test subjects, not recommendations for an application dependency.
Hosted results must be read from the corresponding commit/PR checks.

The final required Python suite passed all 262 tests in 327.455 seconds. All
fourteen actual subprocess integration tests run separately from discovery:
two artifact tests, six completion tests and six authentication tests. No final
run failed or skipped verification. CI retains the existing seven-job matrix
and adds actual authentication integration to the Rust qualification job.

## Verified behavior

Python reconstructs the full local terms commitment and rejects equal auth
pins or overlap with explicit swap-key x-coordinates, including opposite SEC1
parity. Its context is an immutable public snapshot; malformed exact objects,
subclasses, noncanonical wire, oversized bytes, duplicate/unknown fields and
stale or nonliteral verifier results reject. Callback mutation cannot replace
the retained payload. The subprocess adapter uses the existing bounded pipe
runner and accepts only the exact request-bound canonical result.

Rust validates both actual x-only curve points and verifies Alice's BIP340
signature over the exact framed message. Tests mutate every context binding,
payload and signature, reject invalid point encodings and malformed wire, and
exercise payload bounds. Both fixtures regenerate exactly inside test-only
signing code. Python reproduces their message/request digests; Go independently
reconstructs and verifies their authentication signatures with the separate
btcec implementation. This is finite interoperability evidence, not a full
construction audit or complete backend-conformance claim.

The six real-subprocess tests demonstrate exact fixture completion bytes,
successful authentication replay, actual rejection of changed payload or
signature, and local context rejection before the worker. In the test-only
composition, failed authentication preserves both journal files and the
recovery allowance. Valid authentication followed by valid recovery completes
and replays across reopen. A correctly authenticated invalid Zenon signature
still fails real recovery and spends its admitted attempt. A direct call to
the unchanged journal without authentication succeeds, explicitly recording
the missing enforcement boundary.

## Intermediate findings

The initial focused Python run was interrupted with exit 130: its test expected
`KeyboardInterrupt` to be converted to `AuthenticationError`. The stateless
helper intentionally preserves cancellation and process-exit exceptions,
matching the worker boundary. The test expectation was corrected; all 21 tests
then passed. A separate run excluding that case passed the other 20 tests.

Review also identified two minor input-sanitization gaps. An incomplete exact
`Commitment` now rejects as `AuthenticationError`, and deadline range validation
precedes float finiteness checking so enormous integers cannot cause an
uncaught conversion overflow. Both regression cases passed. The first and
final Rust runs passed; no dependency or cryptographic library implementation
was changed. Parallel code review is not an independent human security audit.

## Remaining gates

The [envelope design](COMPLETION_AUTHENTICATION.md) specifies the trust inputs,
wire bytes and boundaries. No pin is persisted by journal v6, no peer identity
is enrolled, and journal entry points do not enforce use of the helper.
Authenticated bytes can be invalid, stale, conflicting or deliberately costly.
Repeated authentication calls remain outside Bob's recovery allowance. Pin
bootstrap/rotation, durable policy, admission/resource controls, observation
selection, confidentiality and transport remain unresolved.

All new exported fixtures contain public synthetic values. No signer is
connected to the journal. Private nonce ownership, clone protection, chain
trust, funded timing, independent construction review and coordinated node
integration remain separate prerequisites. Live swaps and a core port remain
no-go.
