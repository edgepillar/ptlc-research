# Bounded account-history comparisons

This additive offline diagnostic profile extends coverage beyond the frozen
[four-role opening comparison](NOM_VM_OPENINGS.md). It selects twenty account
windows across ten public case/leg projections. Earlier query, fact, witness,
momentum, worker, journal and source driver profiles remain unchanged.
Application and core remain **NO-GO**. No signer, observer service, journal
admission, node activation, transaction broadcast or funds are connected.

## Separate selection and framing

An immutable `NoMHistoryQuery` retains the exact independently selected old read
query, source claim, base opening wire and VM opening wire in memory. The new
domain-separated query digest commits to those selections and four explicit
windows: contract/recipient for long/short. This auxiliary selection adds no
authority fact and does not extend the old eleven-obligation grammar. The same
four authority payload grammars remain unselected; none of the eleven facts has
acquired independent authority.

Each window selects address, canonical uint64 first/last heights, expected head
hash and either an exact adjacent prior anchor or `null`. The height interval
contains at most 64 positions. The fixture's contract anchor at height zero is a
local synthetic comparison input, not authenticated genesis. The recipient's
null anchor means its prior frontier remains unselected.

A sidecar claim binds the exact new query digest and an untrusted
supported/contradicted/unknown status to a typed payload digest. Known status with
no payload is missing history; unknown requires null payload/digest. Each window
is a list of at most 64 complete hash-input records, or null for a missing window.
Empty lists are retained and compared; they do not establish remote absence.
Query bytes are bounded by 8 KiB, sidecar and commitment bytes by 512 KiB and JSON
depth by the preserved twelve-level decoder. All record widths, field sets,
canonical integers and public byte limits use the preserved account codec.
Limits apply per call; aggregate caller/service work policy remains unselected.

Incoming lists are compared in their original order. The consumer never sorts,
fills gaps, resolves forks, repairs hashes or changes an old selection. Bad wire
framing refuses with a sanitized error. Well-shaped contradictions remain
diagnostics. Original malformed evidence must be retained separately by callers;
this pure helper performs no I/O or durable custody.

## Comparisons and limits

| Comparison | Selected behavior | Remaining independent requirement |
| --- | --- | --- |
| Height coverage | Raw heights must equal every selected height in order; missing, outside-window and duplicate positions remain explicit. | Admitted canonical history and any complete-chain coverage. |
| Previous hashes and head | Recomputed hashes join adjacent heights and match the selected final head and optional prior anchor. | Trusted account frontier, actual signed wire and account authorization. |
| Account profile and acknowledgement order | Address, version, chain id, account type and monotonic selected acknowledgement claims are compared. | Actual network provisioning, source state, canonical momenta and time authority. |
| Frozen role membership | Funding parent, terminal parent, payout and final receipt must occur under recomputed hashes. | VM execution/state proof and admission of each role. |
| Embedded children | A contract receive's descendant hashes must match the immediately preceding send records on the same account with the exact acknowledgement. Missing prior children and unassigned sends stay explicit. | Supervisor, Plasma, state and whole-account execution checks. |
| Repeated receive claim | Multiple receives sharing a from-hash are listed with their original indices. | Received-marker state proof and actual duplicate-admission checks. |

Advertised hashes never replace recomputed account hashes. `ChangesHash` remains
an opaque separate patch claim, not an account-hash input or execution proof.
Candidate membership uses the unchanged selected momentum claim; fixture records
remain outside that candidate. A match cannot authenticate the source, canonical
branch, finality, freshness, nonrollback retention or spendable balance.

## Fresh-source cases and retained counterexamples

The generator requires all 32 original VM records before projecting five cases
on each leg: direct success, both proxy caller paths, failed Unlock at expiry
followed by Reclaim, and raw recipient-receive replay. Projection orders the
validated local driver output by height; it does not prescribe normalization of
an incoming source reply. The fresh qualifier reruns the unchanged VM/verifier
suite, preserves original private command streams and actual patch handoffs,
requires all 58 tests including parents and compares the complete public fixture.
There is no fixture fallback on failure.

The Reclaim window contains four contract records, including the failed Unlock
receive between funding and payout. Complete window ancestry now matches while
the earlier adjacency comparison still differs. Reclaim still refunds the funder;
its method, witness and fixed-recipient role conflicts are preserved. This is no
proof that Reclaim is a successful swap or that an observed status is authentic.

Raw replay contains two actual recipient receipts with the same payout from-hash.
The selected heights and hashes join, but repetition is reported as
`REPEATED_CLAIM`. The source fixture deliberately bypasses the verifier and credits
twice. The separately preserved received-marker checks remain required; this
helper does not reproduce account admission or make raw replay safe.

The direct Unlock send remains at caller height 21 and the actual recipient
credit remains at height one. Reclaim also uses an independent caller frontier;
proxy callers are on a different selected account. The new windows do not join
these unrelated frontiers or replace the numbered momentum stubs. Old recipient
continuity conflicts, missing prior frontiers and candidate mismatches remain.

The source is pinned to PR #138 commit
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, tree
`b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. The separately obtained GPL-3.0 source
is referenced under [the manifest](../compatibility/nom_account_history_manifest.json);
no implementation is copied. New MIT code and synthetic projections are written
independently. Toolchain, cache and host remain trusted reproduction inputs.

## Next acceptance gates

Choose and independently assess source/proof provisioning, authenticated account
frontiers and actual received-marker/entry proof syntax before coupling these
diagnostics to a recovery journal. Specify currentness, finality, restore fencing
and finite repeated-read policy separately. A complete selected interval cannot
fill those requirements. Recovery action stays `NONE`, terminal outcome stays
`NOT_ESTABLISHED`, prior originals/disclosure remain retained and work is never
replenished by a missing or apparently successful history reply.
