# Separately selected direct send-caller corpus

Application/core remain **NO-GO**. Combined account admission, independent
assessment and AS1-AS7 remain **UNFILLED**. The recovery journal source is not
upgraded. This additive selection calls `VM.applySend` directly in 23 finite
scenarios with declared context flags and synthetic balances.

## Immutable source and separate inputs

The source is [go-zenon 5e65a0b](https://github.com/zenon-network/go-zenon/tree/5e65a0bdb83700aa1d15b17456a17352b7d04ea9),
tree `3668425af59cfe9b88d8b8818b4467ce3f527d73`. The unchanged
[474-file inventory](../compatibility/nom_dev_admission_source_v1.json) has SHA-256
`2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298`.
The separately retained GPL-3.0 source archive has SHA-256
`3db43d54bf05cf7f02d7a4cb26dcb5310575a09ee320cb8e996e17f9d0676407`
and 1,926,371 bytes. Node implementation is not vendored into this MIT workspace.
The added producer is independently written MIT test code; its four canonical
wire inputs reuse the unchanged MIT [ABI corpus](NOM_DEV_ABI_BOUNDARY.md).

Install the [producer](../compatibility/nom_dev_send_caller_test.go.txt) as
`vm/research_nom_dev_send_caller_test.go` in a separately owned source view. Exactly
474 upstream files plus this one producer are selected, for 475 files. Earlier
dev, receive-data and isolated ABI selections keep their own inputs and evidence.

## What the direct caller adds

The [selected caller](https://github.com/zenon-network/go-zenon/blob/5e65a0bdb83700aa1d15b17456a17352b7d04ea9/vm/vm.go#L180-L225)
dispatches first, gates the trailing-data helper on Dynamic Plasma, then performs
static send validation before reading and debiting the balance. The
[isolated ABI corpus](NOM_DEV_ABI_BOUNDARY.md) calls those helpers separately;
this selection observes their composition within `applySend`.

| Declared group | Cases | Compared behavior |
| --- | ---: | --- |
| Canonical four-method calls | 4 | Data stays unchanged; a balance read precedes its debit. |
| Trailing byte with Dynamic Plasma off | 4 | Static validation normalizes data before balance effects. |
| Trailing byte with Dynamic Plasma on | 4 | Length refusal occurs before balance effects; original data stays intact. |
| Equal-length padding aliases | 2 | Length checking permits the declared aliases and static validation normalizes them. |
| Insufficient Create balance | 2 | No debit occurs; an alias can already have been normalized before refusal. |
| Short Unlock witness | 1 | Width refusal precedes balance access. |
| Absent PTLC and unknown embedded contract | 2 | Route refusal precedes balance access. |
| Nonembedded destination | 1 | ABI and declared spork lookups are bypassed; balance effects still occur. |
| Unknown, truncated and empty method data | 3 | Selected dispatch or static-validation refusal occurs before balance access. |

Records retain original and resulting data digests, data mutation, balance values,
read/debit counts and order, and Dynamic Plasma/PTLC query counts. The digests are
SHA-256 of data bytes, not NoM account-block hashes. Query counts describe only
this pinned caller and these stubs, not a public chain observation protocol.

`APPLIED` means only that this direct `applySend` call returned nil. The producer
calls neither full `ApplyBlock`, `packBlock`, the account verifier nor
`ReceiveBlock`. Its context embeds an unused interface and implements only the
selected flags and balance operations; unselected context calls cannot supply
chain state. The 64 zero witness bytes assert width only, not a valid signature.
There is no signer, witness verification, complete account admission, persistence
or authorized recovery action. Mutation before a local refusal does not establish
that a complete signed transaction can be admitted or committed.

The strict research wire codec deliberately refuses aliases accepted by the
node's isolated decoding path. Neither behavior silently replaces the other.
Fixtures are declared finite expectations, not execution evidence or a security
finding about full signed transactions.

## Retained author execution

The retained author run used Go 1.23.12 on macOS, a read-only offline module proxy
and one newly owned compiler workspace. Both original commands completed with
actual exit 0 and complete, separate stdout/stderr. Normal default vet was enabled.
The selected test produced 23 child passes and its parent pass, for 24 outcomes;
the package pass is not an additional scenario. Earlier native profiles were not
rerun to obtain or compare these results.

Original stdout has SHA-256
`42864e6d5ba88b5ce8218f1adc4abd54320e2f78acc94c9033ff7ca961a2320c`
and 34,751 bytes. Separate stderr has SHA-256
`fe53fd91d0e24c2d9c7f3831d2af0af19df292ae22a471d55ea54df48a11dc96`
and 1,422 bytes. The producer has SHA-256
`0d6de69859f26cf76901d3fdc0c4a4ff0afd6fa4ff767c66cce33feafaa1d993`
and 10,819 bytes. These identify retained bytes without authenticating the build,
dependencies, compiler, producer or execution origin.

A separate private capture reader rejected 58 synthetic framing/value mutations.
Those controls, the public Python reader tests, the retained author execution and
hosted execution remain distinct evidence. Synthetic frames are not fresh native
execution, and hosted Python tests do not execute this Go producer.

## Reproduction and reader limits

Prepare the pinned source and dependencies independently. Select only this parent:

```text
go test -json -p 2 -count=1 -run '^TestResearchNoMDevSendCaller$' ./vm
```

Retain actual status and separate stdout/stderr independently. The
[read-only reader](../qualification/nom_dev_send_caller.py) requires exactly
`send-caller.stdout` and `send-caller.stderr`:

```text
python3 -B -m qualification.nom_dev_send_caller \
  --source OWNED_PINNED_SOURCE \
  --streams OWNED_ORIGINAL_STREAM_DIRECTORY
```

It checks bounded regular files, all source digests and Git blobs, the exact
producer, 23 declared records and 24 parent/subtest identities. Parent-owned output
fragments are joined before complete JSON lines are interpreted. Separate stderr
is bounded opaque diagnostic data. Extra files, links, changed inputs, missing or
duplicate identities, failed/skipped events and changed records refuse.

Matching manufactured streams can pass. Content equality cannot establish actual
exit, execution origin, stream completeness, source/build authentication or an
atomic snapshot. Hosted native jobs retain their earlier source pins; their pass
is not hosted execution of this producer. Complete admission, original custody,
journal composition, external assessment and [AS1-AS7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain separate requirements. No wallet, application signing, broadcast,
activation, deployment or real funds are connected.
