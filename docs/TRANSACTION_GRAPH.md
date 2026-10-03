# CANDIDATE-01: aggregate-adaptor swap with independent refunds

Status: **Selected for offline modeling and transaction qualification; review pending, with no executable swap client.** This candidate fixes one direction and graph. It does not select a production backend or establish atomicity under real network conditions. The original linkage test uses an untweaked aggregate key and synthetic Bitcoin message. A separate transaction harness qualifies real synthetic Taproot claim/refund bytes, tweaks and sighashes, checked by an independent Go script engine. Stages 4-5 add durable local artifact retention and a public completion lifecycle. Authenticated exchange, private signing integration and the complete cross-chain implementation remain absent.

This is an application of the established [two-party scriptless swap structure][scriptless] to [BIP340][bip340], [Taproot][bip341], and the pinned [Zenon PTLC proposal][ptlc]. Its multisignature family is two-party MuSig2 with an adaptor extension. [BIP327][bip327] specifies ordinary MuSig2, not this complete adaptor swap. The inspected [MuSig adaptor API notes][musig] provide concrete adaptation/extraction and partial-verification requirements; their existence does not establish an independently reviewed BTC/Zenon protocol. No new scalar-signing formulas are specified here.

## Roles, keys, and one direction

| Item | Fixed choice |
| --- | --- |
| Alice | Initially owns the BTC; receives ZNN; generates fresh nonzero adaptor secret `t` and public point `T = tG`. |
| Bob | Initially owns the ZNN; receives BTC; initially knows `T` but not `t`. |
| Funding order | Alice's BTC output first; verified Bitcoin claim pre-signature second; Bob's Zenon deposit third. |
| Claim order | Alice releases a completed Zenon claim signature; Bob extracts `t` and completes the Bitcoin claim. Inclusion order may differ from disclosure order. |
| Refund order | Bob's Zenon reclaim becomes available at the shorter hard expiry `E_Z`; Alice's Bitcoin refund becomes available at a later locktime `L_B`. |
| Cryptographic scope | Both inner claim signatures are BIP340/secp256k1. Each chain uses distinct fresh participant signing keys and nonces. Ordinary Zenon account authentication remains separate. |

Let `P_B` be the correctly aggregated internal Bitcoin key of Alice and Bob. Let `P_Z` be their separately aggregated Zenon claim key. Both must use the selected rogue-key-resistant aggregation and encoding rules; neither is the naive unchecked sum of arbitrary supplied keys. Alice also controls a separate Bitcoin refund key `A_R`. The common adaptor point is `T`, not either aggregate signing key.

**Neither recipient alone controls a success key.** Bob cannot create an unrelated valid signature under the Bitcoin output key, and Alice cannot create one under `P_Z`, assuming the selected aggregate-adaptor construction and nonce discipline hold. This is why two standalone recipient signing keys plus single-signer adaptor APIs are insufficient: a recipient controlling the full key could bypass the pre-signature and avoid disclosing the agreed witness.

## The two funded objects

| Object | Success path | Independent refund path |
| --- | --- | --- |
| Bitcoin `F_B:output_index` | Taproot key-path signature under output key `Q_B`, derived from aggregate internal key `P_B` and the exact refund-leaf commitment. The fixed claim transaction `C_B` pays Bob. | A single tapscript leaf: `<L_B> OP_CHECKLOCKTIMEVERIFY OP_DROP <xonly(A_R)> OP_CHECKSIG`. Alice has the refund key, leaf script and control block. She needs no later Bob signature. |
| Zenon entry `id_Z` | `PointTypeBIP340`, `PointLock = xonly(P_Z)`. `Unlock(id_Z, sigma_Z)` submitted by Alice authorizes her exact Zenon destination. | Native `Reclaim(id_Z)` by Bob, who created the entry, at or after `E_Z`. No Alice signature or adaptor secret is needed. |

Bitcoin has exactly this refund leaf for the candidate. Both parties verify the aggregate internal key, Taproot tweak, leaf version/script, output key, amount and outpoint. The aggregate signing session must apply the same tweak and parity handling; signing under untweaked `P_B` is insufficient. The refund witness includes Alice's signature, the agreed leaf script and its control block, with no annex. [BIP341][bip341] and [BIP342][bip342] define the relevant key/script-path rules.

The fixed Bitcoin claim `C_B` has version 2, locktime 0, the single agreed funding input with sequence `0xfffffffd`, no annex, and one output to Bob's agreed destination. Its value is the funding value minus an agreed fee. Use `SIGHASH_DEFAULT`, committing to the actual input and complete output set. No `ANYONECANPAY`, `SINGLE`, alternative destination, or different fee transaction is implicitly authorized. Alice's refund transaction uses time-based `nLockTime = L_B` and a nonfinal input sequence; its outputs and fee are under Alice's sole control.

`L_B` is an absolute timestamp locktime, evaluated with Bitcoin median-time-past rules. The refund leaf is a **lower bound**, not an expiry for Bob's key-path claim. With `nLockTime = L_B`, finality requires the relevant previous-block median time to be greater than `L_B`; equality is not enough. Once refund is possible, both spends may compete until the output is actually spent. See [BIP65][bip65] and [BIP113][bip113].

Zenon has a different boundary: at frontier momentum timestamp `E_Z`, Unlock rejects and Reclaim is eligible. The signed claim message is exactly `H(id_Z || Alice_destination)` as encoded by the pinned core. That signature cannot redirect the transfer or apply to another entry. The model's Zenon claim event represents successful contract execution and its transfer to Alice, not submission or RPC acceptance; subsequent account receipt and spendability need separate integration evidence. [Core semantics][ptlc]

## Messages and transitions

Every row requires immutable session/version/chain commitments and durable nonce/session ownership from [PROTOCOL.md](PROTOCOL.md). Public nonces may be exchanged only within the selected construction's rules. Secret nonces, signing scalars and products such as a public challenge times a private scalar are never transmitted. All partial signatures, aggregate pre-signatures, tweaks and extraction contexts must be verified as the selected backend requires.

| Step | Message or action | Preconditions and retained state | Abort behavior |
| --- | --- | --- | --- |
| 0 | Agree session, asset amounts, destinations, `T`, all public keys, `E_Z`, `L_B`, fee policy and refund leaf. | Validate both networks, encodings, key ownership assumptions and the clock/confirmation policy. Freeze the terms. | Nothing funded. |
| 1 | Alice creates and broadcasts Bitcoin funding `F_B`. | She already possesses her unilateral refund authority and verifies the exact P2TR output. Both parties wait for the chosen funding acceptance policy. | Alice can later refund without Bob. Her initial fee and lock duration are not recoverable guarantees. |
| 2 | Create the exact Bitcoin claim message for `C_B`; run a fresh two-party adaptor signing session with `T`. Alice supplies a verified partial; Bob supplies his own and retains the complete verified pre-signature `pre_B`, including parity/tweak context. Bob can return the complete pre-signature for Alice to verify. | Both verify actual funding outpoint/value and the exact claim paying Bob. Bob must hold a usable `pre_B` **before** funding Zenon. Alice knows `t`, but completing this fixed claim only pays Bob. | If this fails, Bob does not fund. Alice retains the refund path. |
| 3 | Bob creates the Zenon entry using `P_Z`, the exact ZNN amount and `E_Z`. | The BTC funding and `pre_B` remain valid, and sufficient time remains. The actual accepted Create block determines `id_Z`. Alice validates the resulting entry and confirmation evidence independently. | If Alice will not continue, Bob reclaims after `E_Z`; Alice refunds later. |
| 4 | Construct `m_Z = H(id_Z || Alice_destination)` and start a distinct adaptor signing session with `T`. Alice sends her partial first. | Both use the actual validated ID; no signing message is inferred from a promised or stale deposit. Bob verifies Alice's partial and computes his own. | No completed claim signature is released. Both refunds remain available on schedule. |
| 5 | Bob durably stores the complete verified Zenon pre-signature `pre_Z`, public transcript and parity/extraction context, then releases his final partial or equivalent complete pre-signature to Alice. | **Extraction material must exist at Bob before Alice can complete the claim.** Bob checks the remaining BTC claim margin before releasing this artifact. Alice verifies it and rechecks funding and her own reveal margin. | Failure before release leaves Alice unable to complete this signature. An uncertain release is not rolled back or repeated as a fresh signing use. |
| 6 | Alice persists possible exposure, completes `pre_Z` using `t`, independently verifies `sigma_Z`, then submits the exact Zenon claim. | Both funding legs and transcripts are valid; the strict reveal cutoff is satisfied. Local transmission, counterparty delivery or a public pending block can expose `t` before inclusion. | After possible exposure, Alice must monitor/reconcile and pursue the existing claim as permitted. She cannot revert to a secret-hidden abort. |
| 7 | Bob matches `sigma_Z` to retained `pre_Z`, verifies the completed signature and extracted witness against `T`, completes `pre_B`, independently verifies `sigma_B`, and broadcasts `C_B`. | Bob needs no fresh Alice signature. He acts within the stated observation and inclusion bounds; he does not assume Zenon finality is necessary to learn `t`. | Unknown submission outcome is reconciled using the fixed artifacts. A timeout does not authorize another signing session. |
| 8 | Observe both terminal spends under the chosen policies, or execute eligible independent refunds for still-unspent objects. | Track chain history separately from the monotonic fact of possible exposure. Bitcoin claim/refund remain competing paths after the refund threshold. | Report principal ownership, fees, lock duration and unresolved observations separately. |

The ordering in steps 4-5 matters. If Bob gives Alice his last contribution before receiving and retaining the material required to reconstruct `pre_Z`, a final aggregate signature alone need not let him extract `t`. Storing a comment that an adaptor was used is not extraction material. The [inspected MuSig adaptor API][musig] specifically requires verification of every partial and retention of the appropriate pre-signature/parity context.

### The funding-ID dependency is explicit

Zenon's signature commits to `id_Z`, which is the Create send-block hash. This candidate waits for the actual entry before creating its signing session. It therefore makes no claim that a final usable Zenon pre-signature was exchanged before funding. Bob funds only after securing the Bitcoin claim artifact; Alice's BTC was already protected by her noninteractive refund. A counterparty can still refuse to sign and cause fees or time locks. That abort is part of the graph, not proof of principal theft.

## Timing assumptions and inequalities

The model uses one abstract scheduler clock. Real integration must map that abstraction to Zenon momentum timestamps and Bitcoin median-time-past, including disagreement, stalls and reorg effects. Comparing `E_Z` and `L_B` as raw integers is insufficient.

Define these conditional bounds in a common analysis time coordinate:

- `z_early`: earliest instant at which Zenon's hard expiry can be reached under the admitted clock behavior.
- `z_late`: latest instant a successful pre-expiry Zenon claim can occur under the admitted progress/clock behavior.
- `b_early`: earliest instant at which Alice's Bitcoin refund can be included under the admitted Bitcoin clock behavior.
- `D_Z`: Alice's worst admitted claim inclusion, observation and bounded rollback/reinclusion time after disclosure.
- `D_B`: Bob's worst admitted signature detection, extraction/recovery, claim inclusion and chosen confirmation-policy time.
- `M > 0`: additional explicitly chosen safety margin; it is not a substitute for the preceding bounds.

For an honest Alice disclosure at time `r`, require:

```text
r + D_Z + M < z_early
z_late + D_B + M < b_early
```

The second inequality protects Bob even if a malicious Alice obtains the ZNN near the last allowed claim instant. It must not be weakened to the earlier cutoff that only an honest Alice follows. Bob also refuses to release step 5 if the current observations can no longer support the gap. Once a usable pre-signature is released, it cannot be revoked by a later local timeout.

The finite model discretizes these boundaries: the last accepted Zenon tick is `E_Z - 1`, so its honest reveal cutoff satisfies `r + D_Z <= E_Z - 1`. Its Bitcoin gap exceeds `E_Z - 1 + observation_delay + inclusion_delay`. This encodes strict boundary separation in whole ticks; it is not a numerical calibration of the additional real-world margin `M` or of cross-chain clocks.

There is no unconditional finite `D_B` or deterministic Bitcoin finality guarantee. Unbounded censorship, loss of monitoring, resource exhaustion, long chain stalls or reorgs beyond the model's assumptions can invalidate these inequalities. In particular, a stalled Zenon clock must not be assumed to preserve the ordering while Bitcoin's refund clock progresses. Numerical regtest delays will be test parameters, not production safety recommendations.

If Zenon's claim is reorganized after Bob learns `t`, exposure remains true. Alice must still have time and resources to obtain a canonical claim before `E_Z`. If she cannot, Bob may obtain BTC and later reclaim ZNN. That is a required failure trace when the admitted reinclusion bound or reveal guard is removed, not a state the model should conceal by resetting secret knowledge.

## Fee and transaction replacement boundary

The modeled Bitcoin claim is one fixed signed message. Although its sequence permits replacement signaling, an RBF replacement changing outputs/fees requires a different aggregate-adaptor signing context. This candidate does not assume Alice will cooperate after disclosure and does not re-sign using old nonce state. An adequate fixed fee/inclusion bound is therefore an explicit model assumption and a real integration blocker. Bob's ability to spend his claim output in a CPFP child may be evaluated later, but package admission, pinning and fee reserve behavior are not established here.

Alice can independently sign or replace her refund using her refund key, subject to ordinary fee, nonce and broadcast safety. That ability does not give a refund priority over Bob's claim. Zenon claim/reclaim likewise need sufficient execution resources and timely inclusion; an expiry timer does not supply Plasma or guarantee execution.

## Assumptions exposed to the finite-state model

- Aggregate-key unforgeability, correct adaptor completion/extraction, correct nonce handling and both verified pre-signatures are idealized prerequisites. The model does not prove them.
- Actual funding and validated observations are distinct. A claim authorization requires agreement on the exact funded objects and enough remaining time.
- Alice initially knows `t`. Bob learns it from possible disclosure only when he has the correct retained extraction material. A malicious secret owner deliberately exposing it without safe counter-funding can harm herself; this is not an honest-party guarantee failure.
- Secret exposure is monotonic across rejected calls, lost acknowledgements and modeled reveal-leg reorgs. Reorgs change ownership/chain observations, not prior knowledge.
- Native Zenon claim requires time strictly before expiry; reclaim requires time at or after expiry. Bitcoin claim has no refund-time upper bound and races an eligible refund until one spends the output.
- Honest scheduling guards and bounded monitoring/inclusion/reinclusion are explicit assumptions. Adversarial schedules outside them must produce visible counterexamples rather than disappear from exploration.
- A modeled principal-safety result covers the selected horizon, transitions and reorg bounds only. It does not demonstrate a node swap, a safe cryptographic implementation, or production readiness.

## Current qualification evidence

The [offline qualification harness](../qualification/README.md) covers single-signer primitives and a two-party MuSig2 adaptor exercise with distinct aggregate keys, distinct messages and one witness. It verifies all partial signatures and both aggregate pre-signatures before completing the first signature; extraction then permits completion of the second. This is primitive-linkage coverage, not an execution of the exchange order, durable handoff or node transactions in this graph.

Both aggregate keys in the original linkage test are untweaked. Its Bitcoin-side message is a synthetic 32-byte value, not a transaction sighash. Its Zenon-side message is a concrete synthetic `SHA3-256(id32 || destination20)` digest matching the pinned contract rule. The [public fixture](../qualification/fixtures/completed_signatures.json) exports four completed signature examples checked by the isolated core-verifier Go harness.

The separate [Bitcoin transaction fixture](../qualification/fixtures/bitcoin_transactions.json) contains an actual synthetic Taproot key-path claim and Alice-only CLTV refund with exact serialization, output-key tweak, script commitment and sighashes. Rust exercises signing/adaptation/extraction across all four internal/output parity combinations. The [Bitcoin Go harness](../qualification-bitcoin-go/README.md) independently verifies the fixed public example's commitments, digests and both script paths. Detailed executed results and boundaries are in [STAGE1_VALIDATION.md](STAGE1_VALIDATION.md).

[Stage 2](SESSION_JOURNAL.md) binds public staged session contexts and qualifies one-use synthetic producer/output persistence. It does not connect the signing libraries to a complete interactive exchange, verify actual chain observations, or store secret nonce objects. Durable metadata evidence must not be promoted into an implemented cross-chain session.

[Stage 3](NONCE_ROUNDS.md) binds public nonce rounds to these contexts and qualifies a separate ephemeral Rust owner with the same public fixture. A nonce-bound context and public output replay do not enforce the graph's authenticated exchange sequence or Bob's pre-signature retention requirement. The runtime components remain separate.

[Stage 4](ARTIFACT_EXCHANGE.md) now implements Bob's local public-artifact sequence through verified pre-signature retention and durable release, using an actual Rust public verifier. It requires the unchanged retained Alice partial in the Zenon bundle. This addresses the local ordering requirement in steps 4-5, without implementing authenticated transport, funding/time decisions, witness completion or the actual signing-worker boundary.

[Stage 5](COMPLETION_LIFECYCLE.md) qualifies the local public-artifact lifecycle in steps 6-7: Alice verifies the retained bundle and records a synthetic completion, then Bob verifies that signature, extracts against the exact retained pre-signature and actually adapts the Bitcoin signature. Separate journals persist the corresponding transitions. Alice private signing and the graph's funding, time, transport and chain requirements remain outside this implementation.

## Remaining blockers before implementation

1. Independently assess the exact two-party MuSig2 adaptor construction, share order, backend revision and binding. Finite primitive and tweaked-transaction tests are not this assessment. Connect the currently separate examples into the exact cross-chain session and binding logic.
2. Extend the qualified synthetic Taproot script/control-block and transaction example into validated funding/transaction handling. Implement Zenon account-block/ID/address encoding and execute source-pinned contract tests. No native node test is claimed here.
3. Choose credible confirmation, clock, fee/resource and availability assumptions; evaluate reorg/censorship/stall failures and claim/refund races. Translate model bounds to real chain observations without claiming absolute finality.
4. Resolve production-safe nonce lifecycle, durable extraction material, multi-process ownership and ambiguous broadcast recovery according to the chosen library's restrictions.
5. Coordinate any necessary core port and SDK changes with current upstream work. This graph does not authorize feature activation or live funds.

## Primary references

All external links above resolve to immutable source revisions. The historical scriptless description supplies the protocol structure; the BIPs and node source supply their respective consensus rules. Their composition into this candidate remains subject to the blockers above.

[scriptless]: https://github.com/BlockstreamResearch/scriptless-scripts/blob/fd2000d2c30cc8d9125ecd85b0dc14edf32266a3/md/atomic-swap.md
[musig]: https://github.com/BlockstreamResearch/secp256k1-zkp/blob/8e1f96c20e16bf960be6caec7f3c94acb360cdf2/doc/musig.md
[ptlc]: https://github.com/zenon-network/go-zenon/blob/8ed1ca1e012a2c7a2e9ecc456fb82bdef75a4a18/vm/embedded/implementation/ptlc.go
[bip340]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki
[bip341]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0341.mediawiki
[bip342]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0342.mediawiki
[bip327]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0327.mediawiki
[bip65]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0065.mediawiki
[bip113]: https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0113.mediawiki
