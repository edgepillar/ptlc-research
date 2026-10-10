# Fixed-recipient NoM reference recovery

Status: additive offline CANDIDATE-02 qualification subject. Application and core
remain **NO-GO**. This is not a released swap client or a replacement for the
historical CANDIDATE-01 Bitcoin/MuSig2 subject and its unfilled reviews.

## Selected graph and public bindings

Alice funds the long-expiry PTLC under Alice's single BIP340 key with Bob as its
fixed recipient. Bob funds the short-expiry PTLC under Bob's single BIP340 key
with Alice as its fixed recipient. Both public pre-signatures use the same full
compressed adaptor point. No aggregate NoM key, Bitcoin transaction, transport,
private signing or core node change is introduced.

`offline_session/nom_recovery.py` freezes the pinned PR #138 profile, session,
chain identifier, genesis, exact entry identifiers, role assignments, both funder
keys, fixed destinations, token standards, exact integer amounts, expiries and a
declared minimum gap. The terms commitment binds fields that the core unlock
message itself does not bind. The gap is a scenario input, not a demonstrated
network, confirmation or funded-swap safety margin.

The public Rust worker checks both pre-signatures against the locally derived
keys/messages/adaptor point before accepting any completion. Ordinary signature
validity alone is insufficient: a completion from a different nonce can verify
under the funder's key yet fail extraction from the retained pre-signature.
Recovery checks the extracted point, completes the long leg, verifies it and
returns only the public signature. It never returns the extracted scalar and
accepts no private key or nonce input. The Python adapter binds the exact request
and response and measures the explicitly selected executable before and after
work. Loader/runtime qualification for this new executable is still unfilled.

## Durable disclosure and recovery order

1. Each cooperating party owns a separate private-directory, append-only public
   journal. Terms and the verified public pair are immutable selections.
2. Both funding observations must match the selected network and complete entry
   commitments. An explicit trusted observation verifier is required. The shipped
   qualifier uses a synthetic allowlist; no authenticated chain observer exists.
3. Alice verifies and retains the exact short-leg original envelope. Before its
   bytes leave `prepare_attempt`, the journal fsyncs disclosure intent and
   `OUTCOME_UNKNOWN`. A timeout, lost acknowledgement or an `unseen` response
   never authorizes a new signature, hash, session or replacement transaction.
4. Bob retains the exact short original before recovery. A send acknowledgement
   alone cannot authorize the reverse leg. Independently admitted, entry-bound
   `unlock-confirmed` evidence is required, and recovery allowance is durably
   charged before the public worker runs. Interrupted work keeps its original
   evidence and charged attempt. Exact completed recovery can be replayed.
5. Bob verifies and durably retains the recovered long original before returning
   it. Sending it uses the same original-only, unknown-before-output discipline.
6. Absence cannot downgrade positive send/execution evidence. Changed confirming
   momentum requires explicit reorg reconciliation. Reorg can reopen an unknown
   outcome and invalidate funding observations, but never erases possible
   disclosure or substitutes new original bytes.

The source pin's expiry rule uses the original send-confirming momentum. The
reference refuses send confirmation at or after expiry but permits a later
contract receive when the original send confirmation was timely. Merely declaring
matching momentum fields is not proof that a node produced or finalized them.

## Evidence and boundaries

The original envelope and SHA3 transaction identifier are explicitly **synthetic**.
They are not a Zenon ABI/account-block serialization, node hash, account signature
or broadcastable transaction. Public adaptor signatures in the fixtures are
generated only from deliberately public test constants. `scripts/qualify_nom_recovery.py`
exercises the actual Rust public worker across both journals, lost acknowledgements,
reopen, recovery and invalid-completion controls. Unit tests use identified fixture
oracles for storage failures; they are not hidden cryptographic substitutes.

Hash chaining, strict canonical input, file ownership checks and cooperating
POSIX locks detect incomplete/corrupt local history and conflicting owners. They
do not prevent malicious rewriting, restored complete histories, copied owners,
ancestor-directory attacks or a privileged local attacker. The old-log restore
test intentionally demonstrates lost disclosure history after coherent rewind.
This is a counterexample to application readiness, not an anti-rollback defense.
Finite event/recovery limits can also prevent later recovery after exhaustion.

The first Rust compile failed on a `MaybePoint`/`Point` comparison; its original
private log is retained. The corrected compile is a separate result. An initial
legacy native suite under system Python 3.9 returned `OutcomeUnknown` where a
recorded-output replay was expected. The complete native suite passed under the
selected Python 3.12 runtime; the initial failure's cause is not established.
Both results and the original native build outputs are retained privately.
Build outputs initially failed artifact hygiene, were moved into ignored private
storage, and their native target directory is now excluded from Git candidates.
Old failed CI evidence remains unchanged when incorporated historical PRs close.

## Next acceptance gates

| Gate | Required evidence | Current state |
|---|---|---|
| Current core compatibility | Immutable target, message/witness/policy corpus, actual-core differential run | Executable additive subject; record each run separately |
| Independent construction review | Two-party graph, adaptor construction, disclosure order and economic assumptions | UNFILLED |
| New public worker qualification | Complete source/dependency/runtime subject and independent assessment | UNFILLED; legacy worker reviews do not cover this executable |
| Signing and durable custody | Selected reviewed backend, unique nonce ownership, rollback/restore policy, narrow signer interface | UNSELECTED / UNFILLED |
| Chain observation | Exact node/genesis/spork, funding and descendant payout semantics, canonical momentum and reorg proofs | UNIMPLEMENTED |
| Real original transaction | Typed ABI/account block and hash, retained exact signed bytes, account-chain/Plasma and unknown-outcome reconciliation | UNIMPLEMENTED |
| Controlled network composition | Independent party stores, process/network interruption, expiry/refund races and reorg scenarios without real funds | NOT AUTHORIZED BY STAGE 0 |
| Bitcoin extension | Existing transaction/sighash/regtest subject integrated only after NoM gates | Separate later subject |

Offline and hosted regression can qualify the declared reference behavior. Neither
changes these application/core gates, authorizes activation or establishes live
atomicity. Keep peer claims separate from independently selected terms and facts.
