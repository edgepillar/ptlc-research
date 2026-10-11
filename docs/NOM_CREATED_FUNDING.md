# Send-derived NoM witness qualification

Application/core remain **NO-GO**. This additive offline corpus closes one
specific comparison gap: the old successful witness cases used explicitly seeded
synthetic entry ids. The new cases call unchanged `Create.ReceiveBlock`, read the
stored entry under the recomputed Create send hash, and use public test witnesses
for that exact id on each leg. They qualify isolated method behavior, not admitted
funding, a complete VM execution chain or a secure replacement swap protocol.

## Selected source and public inputs

The research baseline is `7327a9c52d657192871f5a1958bb530d4ea63a9b`.
The separately obtained, unchanged PR #138 source remains pinned to
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, tree
`b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. Source citations:

- [Create, unlock and reclaim methods](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/embedded/implementation/ptlc.go).
- [Unlock domain and witness context](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/embedded/definition/ptlc.go).
- [Full account hash inputs](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/nom/account_block.go).
- [Execution context selection](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/supervisor.go).
- [Core license](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/LICENSE): GPL-3.0; source is separately referenced and executed. No implementation is copied. Tests, generators and public toy fixtures here are independently written MIT material.

The manifest pins seven new inputs, selected preserved research inputs and the
unchanged core files. No dependency, core source, production executable, signer
or legacy worker profile is changed.

`scripts/generate_nom_created_funding.py` creates twenty complete account hash
input records: baseline long/short sends plus nine mutations per leg. Neither
record has an outer account signature, authenticated predecessor, proven balance
or admitted Plasma/nonce context. Addresses, amounts, genesis, previous hashes,
momentum acknowledgements and network labels are public synthetic values.

Only the new public context uses the computed send-derived ids. Existing terms,
completions, wire/observation/momentum corpora, recovery logic, authority model,
opening comparator and pinned public worker remain unchanged. The new session
selection is distinct; no original is replaced inside an existing session.

## Witness and execution comparisons

`qualification/tests/nom_created_funding.rs` reproduces adaptor pre-signatures and
completed BIP340 witnesses using the disclosed toy constants 1, 2 and 3 with
fixed test nonce inputs. This exists only in the test target. It accepts no
private signing input, exposes no application signing endpoint and emits only
public fixture bytes when explicitly asked to regenerate the fixture. Test-only
SHA3 arithmetic is independently checked against Python and actual core message
verification; it is never an application hash backend.

Three Rust controls require exact reproducibility, both ordinary signatures and
adaptor relations, extraction from the selected short pre-signature, and exact
recovery of the retained long completion. Old-id/cross-leg/context replay and an
unrelated ordinarily valid completion are refused. Ordinary validity alone does
not establish extraction from the selected pre-signature.

`scripts/qualify_nom_created_core.py` overlays only the independent test driver;
the clean core checkout is unchanged before/after. Seventy selected controls
(thirty-five per leg, plus their parent test) execute actual Create, Unlock,
ProxyUnlock and Reclaim methods using fresh account-storage/time stubs. Every
successful preparation uses Create; no entry is seeded manually. Checks include:

- The source recomputes each full send hash, Create stores that id and all selected
  entry terms, and canonical send normalization preserves the id.
- The new witness succeeds before expiry for its fixed recipient. Direct Unlock
  binds the caller; ProxyUnlock permits another caller while retaining that
  destination. Wrong direct caller or proxy destination is refused.
- A method frontier timestamp exactly at expiry refuses Unlock; authorized
  Reclaim succeeds at/after expiry. Reclaim before expiry is refused.
- Changing predecessor, nonce, amount, token, expiry, key, recipient, chain or
  funder changes the created id and refuses the baseline witness. Old-id,
  old-witness, cross-leg, wrong-chain, corrupt and wrong-width inputs are refused.
- Failure preserves the original entry and a subsequent valid witness succeeds.
  Success removes the entry; duplicate unlock, unlock/reclaim and reclaim/unlock
  sequences cannot issue a second payout in that same synthetic store.
- A successful method returns one exact token/amount/destination payout skeleton.
  Its zero hash/height and absent finalized parent/receipt remain explicit.

The two legs use separate core contexts. There is no shared atomic swap, full
dispatcher, balance debit/credit, account signature verification, finalized
contract receive or recipient account receive in this new source comparison.
The compiler/cache/environment/host are trusted; overlay vet is not performed.

## Public reference recovery and time boundaries

`scripts/qualify_nom_created_recovery.py` uses the existing public-only worker and
unchanged two-journal reference with the new public terms/pair. The actual worker
executes with the existing empty-environment profile. It refuses old/cross-leg
completions, retains the exact synthetic original across unknown outcome/reopen,
and recovers the exact long completion only once from the selected short witness.
The original envelopes and their hashes remain synthetic, never signed account
wire or account-block identities.

The allowlist declares short send confirmation at 900 and receive confirmation
at 950, before the synthetic short expiry 1000. The source corpus separately
tests a method frontier at 900. These matching numbers do not join the two
systems or authenticate the claimed acknowledged momentum. A later contract
receive inclusion timestamp is not the method frontier timestamp: source VM
context selection uses the acknowledged store. Neither the latest node clock
nor receive-confirmation time may be substituted for that context. A source
method frontier at/after expiry refuses Unlock even with a valid witness.

## Remaining acceptance gates

This increment provides mathematical and isolated source compatibility evidence.
It selects no deployed node, active spork, observation/proof authority, nonrollback
consumer/source fence or transaction transport. The public allowlist, caller pins,
matching hashes and green tests remain insufficient for these independent gates:

| Gate | Status |
|---|---|
| Outer signed-wire authorization and original custody | NOT PERFORMED / UNFILLED |
| Full VM, balances, live entry and composed payout/receipt evidence | NOT PERFORMED |
| Provisioned source/proof authority and authenticated execution context | UNFILLED |
| Canonicality, finality, reorg reconciliation and funded timing margins | UNFILLED |
| Nonrollback source/current-position and consumer restore fence | UNFILLED |
| Core-to-journal admission and atomic use-time validation | NOT PERFORMED |
| Independent construction/implementation assessment | UNFILLED |
| Application/core acceptance | NO-GO |

Next qualify the composed Create-to-payout/receipt evidence against an explicit
account/acknowledgement context, retaining these negative controls. Select and
independently assess source/proof, original custody, restore and atomic use-time
mechanisms before connecting that evidence to recovery. Keep client observation,
recovery and transaction construction outside the core contribution.

See [validation](NOM_CREATED_FUNDING_VALIDATION.md) and the independent
[observation requirements](NOM_OBSERVATION_REQUIREMENTS.md).
