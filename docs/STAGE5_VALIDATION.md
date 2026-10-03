# Stage 5 validation: completion and public recovery

Date: 2026-10-03. This milestone uses public synthetic fixtures, temporary local journals and cached dependencies. Alice's producer copies an existing fixture signature; no private signing backend is connected. Bob's Rust executable performs actual final-signature verification, witness extraction and Bitcoin signature adaptation using public inputs. No wallet, private participant identity, peer transport, live RPC, node, broadcast, real funds, commit or publication was used.

## Executed checks

| Check | Result | Scope |
| --- | --- | --- |
| Required-mode Python suite | 182 passed, 0 failed, 0 skipped | Includes the final strict-context regression; required OpenSSL verification enabled |
| Rust locked offline suite | 37 passed, 0 failed, 0 ignored | Previous 30 tests plus 7 completion tests; Rust/Cargo 1.90.0 |
| Public Rust examples | Built successfully | Both artifact verifier and completion/recovery worker; unchanged manifest and lockfile |
| Real completion integration | 3 passed | Separate Alice/Bob journals, actual Rust verification/recovery, invalid final signatures and retained observations |
| Existing real exchange integration | 2 passed | Stage 4 retention/release flow with current v2 release packets |
| Legacy core-verifier Go module | Passed all 4 top-level tests | Go 1.23.12, readonly modules and offline cache |
| Bitcoin Go module | Passed all 8 top-level tests | Existing independent synthetic transaction/script checks |
| Rust formatting and workflow YAML syntax | Passed | Hosted workflow execution not established |
| Artifact hygiene, local document links and whitespace | Passed | 79 candidate file versions inspected for ASCII and disclosure patterns; no anonymity proof |

The final Python total is the previous 145 tests plus 18 completion/adapter tests, 17 completion-journal tests and 2 process-death matrix tests. Python 3.9.6 and required OpenSSL verification ran on local macOS. Ordinary completion tests use explicitly fake callbacks to isolate sequencing and persistence. The five actual Rust subprocess integration tests run separately and are not included in the Python discovery count. The existing public signature and transaction fixtures are unchanged; the recovered Bitcoin signature must exactly equal the fixture also checked by Go.

The workflow now builds both examples and runs the completion integration alongside existing checks. No hosted CI run, Linux run, additional Python version or independent human cryptographic audit occurred in this milestone. Parallel code review inspected the implementation and found the repaired strict-context defect below; that review is not a protocol security proof.

## Implemented behavior

Alice starts after her public Zenon partial already exists. She verifies that partial and accepts only Bob's canonical v2 release with the exact chain/round context, unchanged Alice partial, both valid ordered partials and their exact aggregate pre-signature. The journal commits consumption and possible exposure before entering the synthetic producer. A verified final output is committed before return. An interrupted or rejected completion cannot reenable that producer; restart without committed output becomes `OUTCOME_UNKNOWN`. Replay returns only the exact stored packet.

Bob accepts a structurally bound Zenon completion only after recording his release. He persists the exact candidate and possible exposure before calling the public recovery executable. The executable verifies the complete Zenon bundle and final signature before extraction, requires a nonzero witness matching the committed adaptor point, verifies the Bitcoin bundle with the same point, adapts the Bitcoin signature and verifies its final result. It serializes no extracted scalar. Only after successful recovery does the journal store a request-bound receipt and Bitcoin output. Neither output is a transaction broadcast or receipt of funds.

Failure after Bob candidate retention leaves that exact input available for public recomputation; no secret signing nonce is recreated. Another candidate cannot replace it. A structurally correct but invalid signature therefore remains pinned and can block later valid input. The integration tests demonstrate this behavior. Observation selection and invalid-candidate reconciliation are unresolved requirements before network use.

Storage schema/domain v4 separates generic, managed Alice and managed Bob modes. Versions 1-3 quarantine without automatic migration. Reload reconstructs contexts, stage/artifact requirements, receipts, exposure flags and exact packet relationships; it does not rerun external cryptographic verification. A receipt is a local request hash under a trusted-verifier assumption, not a signed attestation.

## Cryptographic and API rejection coverage

The seven new Rust tests cover valid completion/recovery and exact fixture equality; invalid final signatures; unrelated valid signatures under the same key/message; an invalid final signature for which extraction alone can return a scalar; separately valid bundles with different adaptor points; altered bundles/roles/legs; and strict request types, fields, canonical encoding, duplicate keys and bounds. The worker reuses the existing bundle verifier rather than introducing replacement curve arithmetic.

Python tests cover exact role/context/round binding, bool-versus-integer substitutions, release version and own-partial substitution, consumption/recovery ordering, mutation-safe callback inputs, literal successful response shape and request binding, stored-state tampering, generic/managed-path exclusion, ownership/reentrancy, callback interruption and exact replay. The subprocess adapter also rejects malformed, oversized, noncanonical, deeply nested, unbound and timed-out responses. It accepts an explicitly selected trusted executable; its disk-backed output acceptance bound is not an operating-system resource sandbox.

The three real completion integration tests establish:

1. Alice and Bob use separate journals with actual artifact verification. Alice's fixture completion is verified, reopened and replayed. An interrupted Bob recovery retains the candidate, then actual recovery from that same input produces the exact expected Bitcoin signature and replay packet.
2. An invalid Alice final signature is rejected by the real worker and does not permit another producer invocation after restart.
3. An invalid but structurally matching Bob observation is retained without a verification receipt or Bitcoin output; a later valid replacement is refused.

Rust treats application context hashes as opaque and Bitcoin messages/roots as supplied commitments. Python reconstructs the contexts. These checks do not independently establish chain identity, funding, timing, peer authentication, refund availability or full transaction construction.

## Real process-death matrices

Two tests terminate actual child processes with `SIGKILL` in 12 subcases. Public fake callbacks and invocation-count markers isolate journal ordering; actual cryptographic computation is covered separately above.

| Alice interruption | Reopened result |
| --- | --- |
| Before consumption database commit | Pre-signature retained, no exposure, no invocation; first completion remains available |
| After database commit before checkpoint update | Quarantined; no automatic repair or invocation |
| After checkpoint replacement | `OUTCOME_UNKNOWN`, possible exposure, no invocation |
| After checkpoint synchronization | Same unknown/exposure result |
| After the consumption hook | Same unknown/exposure result |
| After producer return before output commit | `OUTCOME_UNKNOWN`, one invocation, no second invocation |
| After output commit before return | Exact recorded completion, one invocation, replay only |

| Bob interruption | Reopened result |
| --- | --- |
| Before observation database commit | Release remains, no stored candidate or exposure, no recovery invocation |
| After database commit before checkpoint update | Quarantined |
| After observation commit | Exact candidate and possible exposure retained; recovery can use only that input |
| After public recovery before output commit | Same candidate retained; public computation may repeat |
| After Bitcoin output commit before return | Exact recorded Bitcoin output and original release are replayable |

These are process-death results, not power-cut simulations or platform-wide durability guarantees. In-process callback and checkpoint exceptions are tested separately. No output is sent to a peer.

## Intermediate failures and repairs

The first new Rust test compile failed with `E0282`: a synthetic alternate-bundle helper needed an explicit `Vec<PartialSignature>` annotation. The annotation fixed the test helper; the targeted seven tests and complete 37-test locked suite then passed. No cryptographic dependency code was changed.

Adversarial review reproduced a strict-context defect: Python dictionary equality treated boolean `true` as equal to integer `1` in an incoming context's `point_type`. The new regression failed in both Alice and Bob subcases. Incoming contexts now compare canonical bytes with fully reconstructed expected commitments. This restores the exact-type binding contract. Cryptographic requests had been derived from retained canonical contexts, so the reproducer did not demonstrate acceptance of an invalid cryptographic signature.

The first attempt to run that targeted regression used an incorrect test-class name and produced a loader `AttributeError` before executing assertions. The corrected command passed after the implementation fix. An earlier combined suite passed 181 tests before the new regression; the final 182-test suite passed with it included. The actual three-test completion integration also passed after the fix. No failing test remains unresolved.

## Remaining gates

- Connect a reviewed private signing worker with appropriate fresh entropy, nonce ownership, secret handling and process-lifetime behavior. Alice currently copies a public fixture, and the Stage 3 ephemeral owner remains separate.
- Resolve restored-copy/clone protection. A new test restores both matching pre-consumption storage copies after a completed Alice run and successfully invokes the synthetic producer again. Local database/checkpoint agreement cannot prevent this rollback.
- Define authenticated transport, observation selection, invalid-candidate reconciliation and delivery outcomes while preserving exact retained extraction material.
- Implement actual funding/transaction construction, safe time/fee/resource policy, chain observations and ambiguity/reorg handling before regtest/devnet settlement.
- Obtain independent construction review and coordinate any narrow core/SDK work with current upstream owners. Production and node activation remain no-go.

The [completion design](COMPLETION_LIFECYCLE.md) describes the implemented interface and reproduction command. English-only candidate contents remain local; artifact pattern scans are bounded hygiene checks, not anonymity or secret-detection guarantees.
