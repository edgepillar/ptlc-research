# Finite NoM contract receive commits

This study extends the [receive sequencing probe](NOM_RECEIVE_SEQUENCING.md)
with insertion and confirmation of two selected contract receives. It selects
[`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. This immutable source
selection supplies no claim about a current branch, activated network or
deployed node.

## Selected transition

Each case uses a fresh in-process public-genesis mock and a fixed-recipient
entry containing 10 synthetic ZNN. The probe holds automatic contract insertion
while confirming two sends at distinct momentum heights. It first checks the
preceding generation-only observations: the later send refuses with
`ErrABSequencerNotNext`, the legal head generates exactly one payout, and
generation leaves the contract frontier and entry unchanged.

These entries select `PointTypeED25519` and public genesis keys. Other point
types and adaptor-signature completion remain separate qualification subjects.

| Case | Selected head | Later send | Head payout |
| --- | --- | --- | --- |
| `unlock-first` | Unlock confirmed strictly before expiry | Reclaim confirmed at or after expiry | Fixed recipient |
| `reclaim-first` | Reclaim confirmed at or after expiry | Unlock confirmed later | Entry owner |

The probe inserts that exact generated head through the mock producer's
`CreateAccountBlock` path and confirms it in a new momentum. The stored receive
and payout hashes must match the generated blocks, the entry must be absent,
and the contract's ZNN balance must be zero.

With later insertion still held, the original supervisor then generates the
later receive. Its method error must be `ErrDataNonExistent`. The generated
receive must acknowledge the later send's exact confirming momentum, extend the
committed head, contain a nonzero error status and have no descendant payout.
Generation must leave the stored head unchanged. The probe inserts and confirms
this exact error receive, then checks its stored hash, absent entry, zero payout
and zero contract balance. Both receive confirmation heights must follow the
two selected send confirmation heights in the declared order.

These are two finite queue transitions in one contract. The study does not
assess recipient balance credit, every queue schedule, same-momentum ordering,
availability, liveness, canonicality, finality, bilateral atomicity or a safe
disclosure deadline. The explicit hold is a test intervention. No journal write,
recovery permission, signing integration or automatic retry follows from a
matching record.

## Source and original outputs

The [selection manifest](../compatibility/nom_receive_commit_manifest.json)
pins the complete 444-file upstream source inventory, one added probe, its
license notice, the reader and its synthetic controls. The source comparator
requires exactly those 445 file contents. Compiler caches belong outside the
selected source directory.

Place the [probe](../compatibility/nom_receive_commit_test.go.txt) at
`zenon/mock/zz_research_nom_receive_commit_test.go` in that selected source and
execute both cases in one compiler context:

```sh
GOMAXPROCS=1 go test -p=1 -json -mod=readonly -count=1 -timeout=8m \
  -run '^TestResearchNoMReceiveCommit$' ./zenon/mock
```

Retain the original stdout and stderr separately, with the actual command exit,
capture completeness, source and toolchain selection. Compare their bounded
contents from this research repository:

```sh
python3 -B -m qualification.nom_receive_commit \
  --source selected-core --stdout original.stdout --stderr original.stderr
```

Go may split a single printed record across multiple JSON `Output` events. The
reader reassembles bounded lines within the exact selected test label before
decoding a record. Missing fragments, changed labels, unfinished lines,
duplicated records, extra fields, invalid event order and false authority claims
refuse. One parent and both child outcomes, followed by package success, are
required. Synthetic reframing controls establish reader behavior only.

The reader executes no Go or artifact code and does not authenticate a producer,
establish an actual process exit or infer complete command capture. Original
command receipts, complete source checks and local or hosted acceptance remain
separate evidence. A repaired local reader must retain its original failure
and original streams; it must identify any data-only reconciliation separately
from another Go execution.

The harness uses public genesis test signing helpers within the mock. It starts
no node server, contacts no chain, accesses no user wallet, and performs no
application signing or broadcast. Repeating this author study with the same
author or model does not fill independent review. Independent assessment and
AS1-AS7 remain unfilled; application and core remain **NO-GO**.

The adapted probe retains GPL-3.0-only terms under its
[source and license notice](NOM_RECEIVE_COMMIT_NOTICE.md). Original reader,
synthetic controls and explanatory documents retain the project MIT license.
