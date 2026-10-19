# Finite disclosure and timeout counterexamples

Status: offline author study. Application/core are **NO-GO**. Independent
assessment and AS-1 through AS-7 remain **UNFILLED**. The model selects no safe
disclosure decision, wait duration, custody backend or current-source journal
adapter. It never executes a signer, worker, journal or chain operation.

## What the model can establish

The [bounded analyzer](../qualification/nom_disclosure_timeout.py) replays
explicitly hypothetical traces for the fixed-recipient long and short legs.
The [20-case corpus](../compatibility/fixtures/nom_disclosure_timeout_v1.json)
contains boundary controls and counterexamples to incomplete safety arguments.
Every prefix and result remains HOLD, with recovery action NONE. Passing a
modelled expiry component does not authorize an action.

The inputs declare two expiries, opaque original-reference descriptors, a
bounded count of charged UNKNOWN work and up to 32 events. An original reference
contains only an optional wire SHA-256 and optional node hash. These are
unverified descriptors, not original bytes, proof of their mutual binding or
available custody. The analyzer accepts no signature, private key or wire bytes
and never derives or reconstructs a missing descriptor from a fixture.

| Finite case | Consequence in the declared model |
| --- | --- |
| Possible short-leg disclosure followed by a long-leg price refusal | Later HOLD cannot undo possible disclosure; an earlier component pass supplies no future inclusion bound |
| Account frontier/order refusal after disclosure | Retaining the same original does not establish its continued includability |
| Missing wire or node reference, unavailable custodian, observer or counterparty | Matching terms and elapsed time do not supply the missing material or response |
| Arbitrarily enlarged declared expiry gap without a timely long send | The gap alone is not a proof of eventual inclusion; no particular duration is recommended |
| Unlock send at exact expiry | The selected expiry component refuses |
| Timely Unlock send with a later contract receive | The expiry component can pass; the later processing time must not replace the declared send-confirming time |
| Later price refusal after a declared timely send | A future-admission refusal does not retroactively reprice the earlier declaration |
| Unlock/Reclaim receive order alternatives | First consumption changes the modelled outcome; reachability of either order under the real scheduler remains unestablished |
| Reorg after possible disclosure or charged UNKNOWN work | Supplied observations can become unknown while possible disclosure and charges remain |
| Timeout or exhaustion after UNKNOWN work | Time and reorg never refill the allowance, erase charges or create replacement originals |

These are finite implications of supplied assumptions. They are not attacks
demonstrated against the current core, a liveness theorem, a complete adversary
model or an independent assessment of swap atomicity.

## Source relationship and conditional receive order

The selected source is
[go-zenon 85c3979](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. The retained complete source
inventory is [separately pinned](../compatibility/nom_current_admission_source_v1.json).

The selected
[PTLC implementation](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/vm/embedded/implementation/ptlc.go)
reads the entry before consuming it and compares the selected VM momentum time
with expiry: Unlock requires an earlier time; Reclaim requires expiry or later.
The implementation file has SHA-256
`e17afeb9dc3532c2866cb9ae67aafa1a2af21961a1e78ccdf526ca5cba40edb1`.
The upstream
[delayed-receive test](https://github.com/zenon-network/go-zenon/blob/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe/zenon/mock/ptlc_delayed_receive_test.go)
specifically checks that a generated delayed Unlock receive acknowledges its
send-confirming momentum and refuses a receive forged to acknowledge the later
frontier. Its file SHA-256 is
`b6494b06629398ef3be653541ba334e78161206e579e13bfd408a8aff1849b2f`.
Source inspection of these files is not a fresh execution of that upstream test.

The finite model therefore separates its event/report time from the declared
send-confirming timestamp. Its Reclaim path uses the same explicitly declared
context assumption; it is not a newly executed delayed-Reclaim comparison.
Neither timestamp is authenticated by this analyzer.

The two receive-order traces deliberately assume alternative contract entry
consumption orders. The real supervisor's selection, receive ordering, account
authorization, state path and full admission have not been composed here. In
particular, a timely Unlock losing to a later Reclaim is a **conditional model
branch**, not an established reachable core race or an upstream vulnerability.
The output always marks `model_reachability` as `NOT_ESTABLISHED_BY_CORE`.

## Preserved uncertainty and absence

Possible disclosure is monotonic over the supplied trace. Charged UNKNOWN work
never decreases, even after elapsed time, exhausted allowance or reorg. A reorg
can invalidate a declared send and reset the hypothetical entry state, but
cannot erase those charges or undisclose a completion. Missing original
references stay missing; a supplied reference and custodian availability are
different fields and neither proves original-byte custody.

History completeness is an explicit assumption. Supplying an older truncated
trace can hide events from this pure function. This model is not a restore
fence, durable ledger, independently selected current head or anti-rollback
mechanism. It must not be used to decide that an omitted disclosure or UNKNOWN
charge never happened. Existing journals and earlier review subjects remain
unchanged.

## Reproduction and limits

The analyzer uses only the Python standard library and no core source or native
worker at runtime. JSON input is limited to 32 KiB, traces to 32 events, times to
nonnegative signed-63-bit integers and work limits to four. Expiries must be
positive and the long expiry later than the short expiry. The time values in
the corpus are synthetic units, not selected operational safety margins.
Duplicate keys, nonfinite values, booleans in integer fields, missing/extra
fields, changed send declarations without an explicit model reorg and unknown
retry/replacement/refill events refuse. CLI refusals do not echo private input
paths or values. Checks remain active with Python optimization enabled.

```text
python3 -B -W error::ResourceWarning -m unittest discover \
  -s tests -p test_nom_disclosure_timeout.py -v
python3 -B -m qualification.nom_disclosure_timeout --request SELECTED_PRIVATE_JSON
REQUIRE_OPENSSL=1 python3 -B -W error::ResourceWarning -m unittest discover -s tests -v
python3 -B scripts/check_artifacts.py
```

The focused controls also enumerate all 120 orders of five selected failure,
disclosure, absence and work events. This is exhaustive only for that declared
finite set. Source/test review, focused execution, complete offline regression,
hosted PR checks and subsequent push/main acceptance require their own actual
evidence; a corpus or preparation snapshot does not fill any of them.

The remaining protocol work is to assess which conditional branches are
reachable on one complete, authenticated account/VM/pool/momentum path and to
state explicit inclusion, finality, reorg and availability assumptions. A safe
disclosure argument must cover the entire remaining path after irreversible
disclosure. Independent construction and custody/runtime assessment remain
required before any application integration. This study closes no service gate
and introduces no live or signed transaction adapter.
