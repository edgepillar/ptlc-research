# Account frontiers and selected public verifier entry points

This additive offline profile calls the pinned source's public `AccountBlock`
and `AccountBlockTransaction` entry points independently. It retains the exact
original bytes, candidate bytes, source semantic predecessor, ledger selections,
real memory account state and both outcomes. Application and core remain
**NO-GO**. Their conjunction is not supervisor, VM, Plasma, account pool or
momentum admission, and supplies no recovery capability.

## Exact subject and custody

The qualifier first reruns the entire preserved account-authorization profile:
all 58 VM/verifier tests, all 32 VM records and all 126 authorization controls.
Its fresh typed bytes and actual before/after recipient VM patches become a
retained handoff to a new independently written overlay. All 84 context controls
and their parent must complete: 270 source tests including preserved parents.
Fresh output must equal the selected public corpus; failure has no fixture
fallback. Original command streams, handoffs and failed attempts are retained in
separate private directories. Hosted private custody may be ephemeral; an
original console ZIP does not replace it.

The new overlay does not start a chain. Account lookup matches the selected
address and exact hash-height against a real memory account store. Momentum,
confirmation, send availability and source branch are explicit ledger stubs;
no inclusion, currentness, canonicality, finality or source authentication is
implemented. Mailboxes and received markers use actual source storage methods.
For recipient replay controls the exact actual VM patch is applied unchanged.
The extra Create received marker is deliberately set by a test storage call,
and is not presented as a VM-derived or authenticated chain observation.

## Observed boundaries

| Selection | Pinned-source observation | Recovery implication |
| --- | --- | --- |
| Preserved funding and Unlock users, including public-key relocation | Their fabricated predecessors have no matching selected account store. With an empty global frontier this source context path panics. | A valid signature cannot manufacture prior account history. These eight panic controls are test-context observations, not normal refusals or a demonstrated live-node finding. |
| New public signed funding at height one, then a signed height-two successor | Both selected entry points pass under the explicit matching memory frontier. Exact signed predecessor bytes are retained. | Address, funding hash, entry id and raw original all differ from the old swap. Old inner witnesses, selected terms and journals cannot be inherited. No VM executes these new Create inputs. |
| Wrong predecessor, cemented ancestor or cemented competing predecessor | The source returns distinct previous-context errors with real stored frontier/history bytes. | Recovery needs the selected account branch and original custody, not a guessed replacement previous hash. |
| Older, missing or wrong-hash acknowledgement | Structural checks refuse while a valid transaction-only signature can pass. | Authentication of signed contents and availability of the selected momentum context are separate requirements. |
| Old receipt after applying the actual post-VM patch | Original height-one replay fails at the cemented frontier; a new height-two successor reaches the actual received marker and refuses. | An exact replay and a replacement receipt are different originals and different refusal paths. Neither permits replacing a disclosed operation. |
| Relocate a recipient to a public test account | Transaction-only authorization passes; structural receiver enforcement refuses the fixed payout destination. | A new account signature does not authorize receipt of the old selected payout. |
| Receiver mismatch below/at enforcement | The actual ledger frontier selects enforcement, even when a declared acknowledgement is higher. | A declared acknowledgement height cannot stand in for authenticated current ledger state. |
| Contract parent with payout descendants | The source's semantic `Previous()` is the first child's predecessor, which differs from the parent's header predecessor. | Account context lookup must preserve the complete batch, not project only the parent header. |
| Empty or wrong mailbox head | The real mailbox/sequencer structural check refuses despite a matching parent hash and required empty embedded signature. | Send confirmation and ordered contract execution are separate evidence roles. |
| Child version or acknowledgement changes | Parent and child checks produce separately selected errors. | A parent hash match does not establish descendant admission. |
| Wrong advertised child hash with recomputed parent hash | Both selected public entry points pass while the child's independently recomputed hash differs. The transaction entry point performs child structural checks here. | This explicitly limits the two-entry-point result. Supervisor-generated execution, recursive hash/ancestry comparison and complete admission remain separate, unperformed gates; this is not a demonstrated production bypass. |
| Standalone contract payout | Both entry points refuse before account lookup. | A valid embedded payout cannot be submitted as an external contract send. |

The first native context attempt stopped on the empty-global-frontier panic.
A test-only wrapper now records `SOURCE_PANIC` explicitly and continues other
controls; it does not repair the source, turn a panic into a refusal, or confer
admission. Unexpected panics in other controls fail the selected comparison.
An earlier harness attempt used an unsupported command label and did not execute
the new native overlay. Both failures remain distinct from corrected runs.

## Reproduction and next gates

The [manifest](../compatibility/nom_account_context_manifest.json) pins source
[commit `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced),
tree `b8bb3720dd36e6f9ba0537864c18bbb4a001b910`, source/license files and all
selected/preserved inputs. The GPL-3.0 node is separately obtained and referenced;
no implementation is copied. New MIT overlays are independently written.
Only deliberately public constant test seeds produce the isolated synthetic
account signatures. There is no external seed input or application signer.
Independent OpenSSL verifies their public signatures; it does not assess the
swap construction, ledger view, loader, runtime, host or restore policy.

```sh
python3 -B scripts/qualify_nom_account_context.py --checkout CORE_SOURCE --go GO_EXECUTABLE
```

Dependencies must be acquired separately before offline execution. Overlay vet
is not performed because synthetic overlay paths are unavailable to the selected
Go 1.23 vet; standalone Go suites retain normal vet behavior. The compiler,
dependency cache, standard library, loader, environment and host are trusted
reproduction inputs.

Next select a coherent new two-party account graph with reviewed original-byte
custody. Recompute its funding ids and independently bound inner witnesses;
retain exact account predecessors and recipient destinations across both legs.
Qualify supervisor/VM/Plasma and account-pool/momentum admission against that
separate subject before composing a real original with the journal. Source
branch authentication, currentness, canonicality, finality, rollback fencing,
signer/nonce ownership and independent assessment remain unfilled. Existing
synthetic journals, public worker, old witnesses and authority grammars remain
unchanged and return no new permission.
