# Separately selected ABI layer corpus

Application/core remain **NO-GO**, combined admission and independent assessment
remain **UNFILLED**, and the recovery journal source is not upgraded. This additive
selection compares 26 finite scenarios at four isolated layers: ABI decode/repack,
length checking, embedded method dispatch and static send-method validation.

## Immutable source and separate inputs

The source is [go-zenon 5e65a0b](https://github.com/zenon-network/go-zenon/tree/5e65a0bdb83700aa1d15b17456a17352b7d04ea9),
tree `3668425af59cfe9b88d8b8818b4467ce3f527d73`. Its unchanged
[474-file inventory](../compatibility/nom_dev_admission_source_v1.json) has SHA-256
`2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298`.
The separately retained GPL-3.0 source archive has SHA-256
`3db43d54bf05cf7f02d7a4cb26dcb5310575a09ee320cb8e996e17f9d0676407`
and 1,926,371 bytes. Node implementation is not vendored into this MIT workspace.
The added producer is independently written MIT test code.

Install the [producer](../compatibility/nom_dev_abi_boundary_test.go.txt) as
`vm/embedded/research_nom_dev_abi_boundary_test.go` in a separately owned source
view. The comparison selects exactly 474 upstream files plus this one producer,
for 475 files. The [earlier dev components](NOM_DEV_ADMISSION.md) and
[receive-data method selection](NOM_DEV_RECEIVE_DATA.md) retain their own inputs.

## Why four results are kept separate

In the [selected length checker](https://github.com/zenon-network/go-zenon/blob/5e65a0bdb83700aa1d15b17456a17352b7d04ea9/vm/embedded/embedded.go#L354-L390),
successful decoding is repacked and its length is compared. This does not require
byte equality. Unknown or insufficient data can be deferred without a length
error. The [send caller](https://github.com/zenon-network/go-zenon/blob/5e65a0bdb83700aa1d15b17456a17352b7d04ea9/vm/vm.go#L180-L198)
separately gates this helper on Dynamic Plasma and dispatches before static method
validation. Calling the helper directly does not reproduce that caller.

| Declared group | Cases | Separate compared properties |
| --- | ---: | --- |
| Canonical four-method calls | 4 | Independent wire bytes, unchanged repacking and static validation. |
| Appended data | 8 | One or 32 extra bytes per method, length refusal and direct static normalization. |
| Offset or padding aliases | 3 | Offset gaps and equal-length aliases; length equality does not imply canonical bytes. |
| Invalid witness width | 2 | Successful ABI decoding and no length error remain separate from static width refusal. |
| Missing selector or arguments | 5 | Unknown selector, truncated head, selector-only data, empty data and offset overflow. |
| Declared flags or addresses | 4 | Absent PTLC registry, isolated helper with Dynamic Plasma off, nonembedded and unknown embedded destinations. |

The records include all four layer outcomes, repack equality, input length,
SHA-256 of original and post-validation data, mutation status and declared flags.
These SHA-256 values identify data bytes; they are not NoM account-block hashes.
Fixture values are finite expectations, not execution evidence.

The 64 zero witness bytes used by width-positive cases are not a valid signature
claim. The producer calls neither `ReceiveBlock` nor witness verification. It uses
synthetic block fields and declared context flags, and calls selected methods
directly even in cases where dispatch refuses. A static-method pass in those cases
cannot establish contract availability, full account admission or unlock success.

The [strict research wire codec](../offline_session/nom_wire.py) deliberately
refuses aliases that the isolated node ABI decoder can decode. Neither contract
is silently substituted for the other. This finite comparison is not a security
finding about a complete signed transaction.

## Retained author execution

The retained author run used Go 1.23.12 on macOS, a read-only offline module proxy
and one newly owned compiler workspace. The physical producer ran with normal
default vet. Both original commands completed with actual exit 0 and complete,
separate stdout/stderr. The selected test produced 26 child passes and its parent
pass, for 27 outcomes; the package pass is not an additional scenario.

Original stdout has SHA-256 `b87b278317171e69b183426d5377a2bfcfb42b0600f0ed29115633c13cd0c262` and
39,296 bytes. Separate stderr has SHA-256
`d661a55525680981f42fc30710f90cd4d5f78a639e42871764e5194fccf1efb6` and 1,422 bytes.
The producer has SHA-256 `6836919a207049c5a1df0a234fecae5ceec196b3ca509b5381fc2f0510451d06` and 12,543 bytes. These digests
identify retained bytes; they do not authenticate the execution, build support,
dependencies, producer or compiler. Earlier native profiles were not rerun.

A separate private capture reader rejected 44 synthetic framing/value mutations.
Its controls and this later public reader remain distinct selections. Synthetic
Python unit tests establish reader behavior, not new native execution. Original
streams and actual command status remain separate requirements for reproduction.

## Reproduction and evidence boundaries

Prepare the source and dependencies independently. Select only the new parent:

```text
go test -json -p 2 -count=1 -run '^TestResearchNoMDevABIBoundary$' ./vm/embedded
```

Retain actual status and separate stdout/stderr independently. The
[read-only reader](../qualification/nom_dev_abi_boundary.py) requires exactly
`abi-boundary.stdout` and `abi-boundary.stderr`:

```text
python3 -B -m qualification.nom_dev_abi_boundary \
  --source OWNED_PINNED_SOURCE \
  --streams OWNED_ORIGINAL_STREAM_DIRECTORY
```

The reader checks bounded regular files, source digests and Git blobs, the exact
producer, 26 declared records and 27 parent/subtest identities. It reassembles
parent-owned output before interpreting complete JSON lines. Separate stderr is
bounded opaque diagnostic data. Extra source files, aliases, missing or duplicated
events, changed records, failed/skipped tests and invalid JSON refuse.

Matching manufactured streams can pass. File content cannot establish actual
exit, execution origin, stream completeness, source/build authentication or an
atomic snapshot. Existing hosted native jobs retain their earlier source pins;
their success is not hosted execution of this selection. No earlier native profile
needs to be rerun merely to compare this additive corpus.

Complete admission, original custody and journal composition remain separate
obligations. External assessment and [AS-1 through AS-7](NOM_ANCHOR_SERVICE_ACCEPTANCE.md)
remain unfilled. No wallet, application signer, broadcast, activation, deployment
or real funds are connected.
