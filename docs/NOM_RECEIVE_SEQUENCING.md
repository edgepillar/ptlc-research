# Finite NoM contract receive sequencing

This study tests whether a later confirmed PTLC send can bypass the first
confirmed send in the contract's receive queue. It selects
[`go-zenon` commit `85c3979`](https://github.com/zenon-network/go-zenon/tree/85c39796fa5ab6fb5ca16e61af34b6616f0ceafe),
tree `cdeb5b6276c13447197c829c5855faa72afd86b9`. This immutable selection is
not a claim about the latest branch, an activated network or a deployed node.

The preceding [disclosure and timeout model](NOM_DISCLOSURE_TIMEOUT.md)
enumerates hypothetical receive-order branches. This source probe narrows two
of those branches through the selected original verifier and mock supervisor.
It does not compose that model with a recovery service or establish a safe
disclosure deadline.

## Selected cases

Both cases create a public-genesis fixed-recipient entry, then hold automatic
contract receive insertion while the ordinary send path confirms two sends.

| Case | Queue head | Later send | Required observations |
| --- | --- | --- | --- |
| `unlock-first` | Unlock confirmed strictly before expiry | Reclaim confirmed at or after expiry | Later Reclaim generation refuses `ErrABSequencerNotNext`; the head Unlock generates the fixed recipient payout |
| `reclaim-first` | Reclaim confirmed at or after expiry | Unlock confirmed later | Later Unlock generation refuses `ErrABSequencerNotNext`; the head Reclaim generates the owner payout |

The probe checks distinct confirmation heights, confirmation timestamps,
expiry, later processing time, and the generated receive's exact confirming
momentum hash and height. It checks the selected original send hash, one
descendant payout, ZNN token and expected synthetic amount. Generating these
receives must leave the stored contract frontier and PTLC entry unchanged.
The generated head receive is not inserted by this probe. Successful generation
therefore does not establish committed payout or subsequent queue progress.

The harness uses existing public genesis fixtures and their test signing
helpers inside the in-process mock. It starts no node server, contacts no chain,
accesses no user wallet, and performs no application signing or broadcast.
`SkipVmChanges` selects the harness's debug comparison behavior; it does not
replace the send supervisor or original account-block verifier. The queue hold
is an explicit test intervention, not evidence that an adversary can cause
that condition on a network.

## Evidence and reproduction

The [selection manifest](../compatibility/nom_receive_sequencing_manifest.json)
pins the complete 444-file upstream inventory, one added probe, its license,
the reader and its controls. The [source inventory](../compatibility/nom_current_admission_source_v1.json)
reconstructs the selected Git tree. Acquire dependencies separately under an
owned, bounded qualification task; keep source, transport and actual exit
receipts. No dependency acquisition is performed by the reader.

Place the [probe](../compatibility/nom_receive_sequencing_test.go.txt) at
`zenon/mock/zz_research_nom_receive_sequencing_test.go` in a source directory
containing exactly the selected 444 files and this one probe. Keep compiler
caches outside that directory. Execute both subcases in one compiler context:

```sh
GOMAXPROCS=1 go test -p=1 -json -mod=readonly -count=1 -timeout=8m \
  -run '^TestResearchNoMReceiveSequencing$' ./zenon/mock
```

Retain original stdout and stderr separately along with the actual command
receipt. From this research repository, compare their bounded contents:

```sh
python3 -B -m qualification.nom_receive_sequencing \
  --source selected-core --stdout original.stdout --stderr original.stderr
```

The reader requires all three Go test outcomes (parent plus two children),
one terminal package success, one complete record per child, legal event
ordering and exact scope labels. It rejects failures, skips, missing or
duplicated outcomes, relabelled cases, nonfinite values, Boolean integer
substitutions, forged authority fields, changed source bytes and linked inputs.
It checks that the two timestamp relations match their declared case. Its
stdout is a sanitized value comparison; it prints no input paths or raw logs.

The reader does not authenticate the producer, establish the actual process
exit, or execute Go. Synthetic test streams exercise its refusal rules and
are never source execution evidence. A complete independent command receipt,
source comparison and original stream acceptance remain separate requirements.
Any local and hosted execution observations must be identified by their own
source, platform and run selection; a pass label alone is insufficient.

## Remaining boundaries

These two finite source cases do not prove all queue schedules, send admission,
adversarial inclusion, economic viability, bilateral atomicity, chain
canonicality, finality, liveness, durable custody or a safe timeout margin.
No retry, settlement, journal write or recovery action follows from a match.
The original operations and possible disclosure remain subject to the existing
HOLD rules.

This is an author review and executable research aid. Repeating it with the
same author or model is not independent protocol review. Independent assessment
and AS1-AS7 remain unfilled; application and core remain **NO-GO**. The next
assurance step is a separately attributable review of the source-pinned
assumptions and counterexamples, with explicit unresolved findings.

The adapted probe retains GPL-3.0-only terms; see the
[source and license notice](NOM_RECEIVE_SEQUENCING_NOTICE.md). Original reader,
controls and explanatory text retain the project license.
