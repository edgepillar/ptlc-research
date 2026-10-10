# Pinned NoM public ABI and account hash conformance

Status: additive offline CANDIDATE-02 evidence. Application/core remain
**NO-GO**; independent assessment is **UNFILLED**. This subject adds no signer,
transaction submission, network observer, node change or wallet operation.

## Source and independently written subject

The manifest `compatibility/nom_wire_manifest.json` pins PR #138 at
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`, its exact Git tree, selected source
files, license, module inputs and the public fixture/overlay bytes. The node's
GPL-3.0 implementation is separately obtained and referenced only; the reference
codec, public synthetic fixture and overlay tests are independently written MIT
research material. No third-party implementation or fixture was copied.

Normative source:

- [PTLC method definitions](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/embedded/definition/ptlc.go).
- [ABI selector construction](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/abi/method.go) and [argument packing](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/vm/abi/pack.go).
- [Account block hashing and protobuf serialization](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/nom/account_block.go).
- [Account transaction verification](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/verifier/account_block.go).

The historical PR #13 and existing PR #138 compatibility fixtures, module inputs,
NoM journals, worker construction and frozen assessment subjects remain separate.
The new fixture does not silently enlarge the separately frozen worker subject.

Full-graph dependency acquisition uses copies of the node's module inputs. Go
1.23 adds checksum rows for the broader graph; the manifest separately pins that
acquisition `go.sum` digest while preserving the normative node `go.mod` and
`go.sum`. Module-content verification runs over the acquired graph, and the
offline differential still uses the exact unchanged node files. Acquiring
checksums does not authenticate the compiler, runtime or later cache use.

## Concrete wire boundaries

`offline_session/nom_wire.py` encodes the four proposed contract calls:
`Create(int64,uint8,bytes,address)`, `Unlock(hash,bytes)`,
`ProxyUnlock(hash,address,bytes)` and `Reclaim(hash)`. The four-byte selector uses
SHA3-256, not Ethereum's legacy Keccak. Arguments use 32-byte words, explicit
dynamic offsets and zero tail padding. Negative int64 values use signed extension.

The reference decoder requires exact canonical re-encoding. It refuses extra
bytes, offset gaps, nonzero address/tail padding, truncation, width overflow,
integer aliases and unselected fields. This is a local research boundary, **not**
a claim that the node rejects every such input. Seven controls separately measure
actual send admission. The node accepts and normalizes four alias forms:
trailing unlock words, an unlock dynamic-offset gap, high address padding and a
trailing proxy byte. Normalizing those forms changes the account hash input.
Canonical encoding alone does not establish point admission, witness validity,
funding, a payable destination or account eligibility. The 31-byte witness is
canonical ABI but fails the node's send witness-size rule.

The bounded reference computes the source's **306-byte hash preimage**. It includes
uint64 version/chain/type, previous hash and height, acknowledged momentum hash
and height, source/destination addresses, uint256 amount, token standard, source
send hash, ordered advertised-descendant hash digest, data digest, fused Plasma,
difficulty and the eight public PoW nonce bytes. This public nonce is unrelated
to a secret adaptor-signing nonce. Limits of 4,096 data bytes and 64 descendant
claims are research limits, not node consensus maxima.

This preimage is neither `AccountBlock.Serialize()` protobuf nor RPC JSON. No
protobuf/RPC encoding, signed capsule, account key or account signature is
produced. The original envelope in `nom_recovery.py` remains explicitly synthetic
and uses its original separate identifier; it is not migrated to this hash.
The hash baseline is a structural control, not a validated swap caller or funded
entry. The inner BIP340 PTLC witness and the outer Ed25519 account signature are
different authorization layers; verifying one supplies no proof of the other.

## Counterexamples an observer must preserve

| Observed source behavior | Consequence for later recovery |
|---|---|
| Changing any selected hash field or ordered advertised child hash changes the digest | Freeze the complete chosen hash inputs before obtaining an account signature |
| Hash, base/used Plasma, changes hash, public key and signature are excluded from `ComputeHash` | Equal hashes do not establish equal serialized originals, valid signatures, state changes or spendability |
| Changing a child payload while retaining its advertised hash leaves the parent digest unchanged | Recompute each child hash and verify its account/receive linkage; a parent hash alone cannot authenticate a payout |
| Positive and negative equal-magnitude amounts produce the same direct `ComputeHash` result | Hash calculation alone is not node admission; the reference refuses negative amounts |
| Send ABI validation can normalize accepted input | Select canonical data before signing; retain and reconcile exact originals, never silently normalize already retained bytes |
| Genesis, active sporks, canonical inclusion and finality are external to this hash preimage | Independently establish the network and observation authority |

These controls exercise helpers and send syntax. They do not demonstrate a
consensus vulnerability: the node's separate verifier checks hash, producer,
account signature, descendants and other admission/state rules. The deliberately
invalid metadata/amount controls are not admitted account transactions.

## Execution and evidence custody

`scripts/qualify_nom_wire_core.py` requires the exact clean source pin/tree and
selected file hashes, then overlays only the MIT test file without editing the
node. Dependency acquisition occurs separately; the differential runs with
`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, read-only module inputs and
uncached test execution. Compilation may use the trusted Go build cache.

The existing bounded native command helper retains original private stdout,
stderr, exit/deadline/overflow evidence and hashes in a fresh private directory.
A zero exit is insufficient: every selected test and the package must report a
single pass, with no missing, duplicated, failed or skipped result. Source,
selected packaging inputs and the selected Go executable are remeasured after
the run. The event parser still trusts the selected tool and host; forged event
claims are not producer authentication.

The overlay uses `-vet=off` explicitly because Go 1.23 vet cannot open the synthetic
path. Vet is **not performed** for this overlay; normal Go corpus jobs retain
their existing vet behavior. The added `nom-wire-core` job obtains immutable core
source and dependencies separately, then executes the same offline differential.
Its raw private command files live on the hosted runner and are **ephemeral**;
the console archive retains the sanitized report, not those raw files. Durable
hosted private-stream custody remains unqualified. Existing CI jobs are preserved.

## Required next boundaries

The [observation requirements](NOM_OBSERVATION_REQUIREMENTS.md) map these bindings
to the pinned source without selecting an authority or implementing an observer.

1. Independently assess the fixed-recipient graph, adaptor construction and worker.
2. Specify authenticated node/network/spork and canonical-momentum evidence.
3. Bind funding to the exact Create send hash, full entry terms and its successful
   contract execution; the existing synthetic entry identifiers are not real
   funding transactions.
4. Bind successful unlock execution, descendant contract payout and recipient
   receive separately. Absence of an entry alone cannot distinguish unlock,
   reclaim, unobserved history or a fork.
5. Select reviewed account signing, nonce custody, exact signed protobuf/RPC
   originals, account-chain/Plasma behavior, durable unknown-outcome reconciliation
   and restore protection before changing the synthetic journal boundary.

No live observer, transport, deployment, activation, transaction broadcast or
funded swap is authorized by this conformance subject.
