# Separately selected receive-data method corpus

Application/core remain **NO-GO**, combined admission and independent assessment
remain **UNFILLED**, and the recovery journal source is not upgraded. This corpus
compares fourteen finite branches of two isolated account-verifier methods. It
does not establish complete account admission, a trusted spork state or recovery
permission.

## Source and selected producer

The source is [go-zenon 5e65a0b](https://github.com/zenon-network/go-zenon/tree/5e65a0bdb83700aa1d15b17456a17352b7d04ea9),
tree `3668425af59cfe9b88d8b8818b4467ce3f527d73`. The preserved
[474-file inventory](../compatibility/nom_dev_admission_source_v1.json) has SHA-256
`2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298`.
Its separately retained source archive has SHA-256
`3db43d54bf05cf7f02d7a4cb26dcb5310575a09ee320cb8e996e17f9d0676407`
and 1,926,371 bytes. The GPL-3.0 node source is acquired separately. The added
[MIT producer](../compatibility/nom_dev_receive_data_test.go.txt) is independently
written and has SHA-256
`f631e888a67d09e4a2dd153be27f72a0213122c4062468c0cedea1a99158ad5e`.

Install that producer as `verifier/research_nom_dev_receive_data_test.go` in a
separately owned source view. The comparison requires exactly 474 upstream files
and that one producer, for 475 files. The earlier 490-file, sixteen-producer
[dev component corpus](NOM_DEV_ADMISSION.md) remains unchanged and separate.
Neither an earlier producer nor a report for a nearby source fills this selection.

## What the fourteen cases compare

The selected source's `receiveData` method exempts send blocks, embedded receive
blocks and empty receive data. For a user receive with nonempty data it queries
Dynamic Plasma at the selected acknowledged momentum context: an attached
momentum store takes precedence, otherwise the chain cache is requested with the
block's exact `MomentumAcknowledged` value. An active flag refuses the data;
lookup errors and absent required context refuse separately.

| Group | Cases | Compared behavior |
| --- | ---: | --- |
| Method exemptions | 3 | Send, embedded receive and empty user receive require no spork lookup. |
| Attached momentum store | 5 | Active/inactive/error outcomes, precedence over a contradictory cache, and operation without a chain/cache. |
| Acknowledged-momentum cache | 4 | Active/inactive/error outcomes and an exact lookup after changing both acknowledgement hash and height. |
| Missing context | 2 | Absent chain and absent selected cache refuse; absence does not become an inactive spork claim. |

The producer records each selected result, exact acknowledgement, data length,
spork-call counts and cache-read count. Unselected interface methods panic in the
stubs. The declared values in the [fixture](../compatibility/fixtures/nom_dev_receive_data_v1.json)
are finite expectations, not native execution evidence.

These methods are called directly. The probe does not call the full verifier
pipeline or establish valid block structure, hash/signature admission, mailbox
credit, context provenance, currentness, inclusion, finality or live activation.
Its zeroed or synthetic block fields must not be treated as admissible account
blocks. The test's declared active/inactive stores do not authenticate any chain.

## Retained author execution and preserved failures

The retained author experiment used Go 1.23.12 on macOS, a read-only offline
module proxy and one newly owned compiler workspace. The producer was a physical
source file, and the selected package ran with normal default vet. Two original
commands completed with actual exit 0 and complete, separate stdout/stderr. The
selected test produced fourteen child passes and its parent pass, for fifteen
test outcomes; the package pass is not an additional method case.

The original native stdout has SHA-256
`1ccfb084bf3a6cd1952f6e594a8a92c2a362af53370ddcba4fafa3f08d8513d1`
and 17,877 bytes; its separate stderr has SHA-256
`15d444bea27fb05affe26d3ef584c979826e45831c51d877b8fc9c6516826be8`
and 1,124 bytes. Digests identify retained bytes; they do not authenticate an
execution, compiler, build support, dependency closure or producer.

An initial preparation attempt stopped before native execution because a new
controller had not yet been registered for source retention. The subsequent
driver retained both successful Go commands but failed to decode the producer's
long JSON line: Go `test2json` split it across four `Output` events, with 1,024-byte
nonterminal fragments. The containing qualification task remains **FAILURE**.

A separate byte-only reconciliation joined the original parent-owned output,
compared all fourteen records and fifteen test outcomes, and rejected 23 framing,
identity, value and JSON mutations. It reran neither Go command and did not
reclassify either failed attempt. The public reader and its own controls are a
later source selection; their original-stream qualification remains distinct
from that earlier reconciliation.

Existing hosted native jobs retain their earlier source selections. Their passes
are not a hosted native execution of this receive-data probe. Python unit tests
manufacture explicitly synthetic pass envelopes and establish only reader
behavior. External assessment and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain unfilled.

## Read-only comparison and reproduction

The [reader](../qualification/nom_dev_receive_data.py) downloads and executes
nothing. It compares the exact source inventory, producer bytes and Git blobs,
bounded regular files, the complete fifteen test identities and the fourteen
declared method records. Source aliases, hard links, extra files/directories,
missing frames, changed owners/values, duplicate JSON keys, nonfinite numbers,
skipped/failed tests and incomplete run/pass framing refuse.

One owner's `Output` events are joined before JSON lines are decoded. Fragment
boundaries do not supply new test outcomes. Fixed stream, event and source bounds
remain enforced. Separate bounded stderr is hashed as opaque diagnostic data;
its presence or absence is not an exit code. File content cannot establish actual
exit, original stream completeness or execution origin. Matching synthetic bytes
can pass this finite comparison. Filesystem executable-mode equality and an
atomic source snapshot are not asserted.

Prepare the source and dependencies independently. In the selected 475-file view,
the author recipe selects only the new parent:

```text
go test -json -p 2 -count=1 -run '^TestResearchNoMDevReceiveData$' ./verifier
```

Retain actual command status and separate original streams independently. Supply
exactly `receive-data.stdout` and `receive-data.stderr` in the stream directory:

```text
python3 -B -m qualification.nom_dev_receive_data \
  --source OWNED_PINNED_SOURCE \
  --streams OWNED_ORIGINAL_STREAM_DIRECTORY
```

The reader checks fixed inventory and fixture digests without rerunning earlier
profile generators. Focused controls reuse one small synthetic file-walk frame;
they do not download source or rebuild a compiler. Earlier native results require
their unchanged source/input bindings and separate evidence. This reduces repeated
work without supplying a timing, physical-space-reclaim or security guarantee.

Next work includes the selected ABI/trailing-data boundary and a separate review
of complete admission and original custody. No signed original is rewritten,
wallet accessed, transaction broadcast, node activated or deployment authorized.
