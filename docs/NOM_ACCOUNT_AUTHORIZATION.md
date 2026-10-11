# Account authorization and exact public wire comparisons

This additive offline profile executes selected transaction hash, signature and
producer checks against the unchanged PR #138 source. It also records that
source's typed protobuf serialization and deserialization. Application and core
remain **NO-GO**. No application signer, wallet, observer, journal admission,
node activation, broadcast or funds are connected.

## Selected subject

The qualifier first reruns all 58 preserved VM/verifier tests and requires all
32 original VM records. It then passes actual direct-success blocks for both
legs to an independently written test overlay. Six roles per leg cover funding
send, Unlock send, recipient receive, Create receive, Unlock payout and Unlock
receive. All contract descendants are reconstructed from the actual source
records before serialization; advertised child hashes alone are insufficient.

There are 96 user-account controls and 30 embedded-account controls, plus the
outer test parent. Each record retains complete account hash inputs, advertised
and recomputed hashes, separate changes/Base/used Plasma claims, public key and
signature, exact raw protobuf bytes and SHA256, reencoded bytes, the original
unsigned source bytes and the three separate check results. Python recomputes
account hashes and compares exact selected transformations. Independent OpenSSL
tests check public Ed25519 signatures separately from the Go implementation.

The isolated overlay uses two deliberately public constant test seeds. No seed,
private key or signing interface is accepted from an application or peer. These
test signatures are not wallet material or signatures for the selected swap.
Source execution, compiler, cache, standard library, loader, environment and host
are trusted reproduction inputs; no executable authentication is implemented.

## What the controls establish

| Control | Observed pinned-source behavior | Recovery implication |
| --- | --- | --- |
| Exact unsigned user blocks | Account hashes match; account signature is missing. | A correct hash or inner PTLC witness cannot authorize the account. |
| Public test key signs the unchanged source hash | Signature verifies; producer address differs. | A valid signature by an unrelated account does not authorize the selected funder/caller/recipient. |
| Relocate to the public key's derived address and sign the new hash | Selected user transaction-only checks pass. | Account, hash and raw original change. Funding entry ids, retained Unlocks and prior account frontiers cannot be inherited. |
| Change data and keep the old advertised hash | Signature over that old hash still verifies; hash check refuses. | Check order and complete contents matter. |
| Recompute a changed block while retaining its signature | Hash matches; signature refuses. | Retained authorization cannot cover changed contents. |
| Sign the changed contents with the public test key | Outer checks pass for a different original. | This establishes no valid inner witness, retained selection or VM execution for those contents. |
| Change changes hash or Base/used Plasma | Account hash and signature remain equal; raw bytes change. | Equal account hashes are insufficient for exact-original retention or state/Plasma proof. |
| Append an unknown protobuf field or duplicate version | Distinct raw bytes decode to the same typed block; reencoding drops the extra bytes. | Decode/reencode is not preservation of the originally disclosed bytes. |
| Embedded accounts | Empty key/signature is required; either nonempty field refuses. | Empty authorization is an embedded-account rule, not source authenticity or external permission to submit a contract send. |

The source's user `AccountBlockTransaction` check is separate from its structural
`AccountBlock` checks and from the supervisor/VM/Plasma path. The overlay invokes
hash, signature and producer helpers independently, including on negative
controls, so their results must not be presented as ordered admission. For user
controls with all three matches it also runs the transaction-only composite;
these users have no descendants. Contract descendant admission and the external
contract-send prohibition remain separate requirements. No structural account
context or source branch becomes authenticated by these comparisons.

The recorded protobuf bytes are observations of this exact source/toolchain
subject. They are not a selected canonical network wire policy, a transaction
builder, a new decoder for untrusted network input or a journal migration. Raw
aliases are counterexamples to replacing retained originals with typed values;
no parser repair, normalization or replacement operation is authorized.

## Reproduction and custody

The [manifest](../compatibility/nom_account_authorization_manifest.json) pins
source [commit `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced), tree
`b8bb3720dd36e6f9ba0537864c18bbb4a001b910`, source/license files, new inputs and
preserved profiles. The GPL-3.0 source is obtained separately and referenced;
no implementation is copied. New MIT test overlays and public synthetic
projections are independently written. Earlier witnesses, journals, authorities,
account histories and VM drivers remain unchanged.

```sh
python3 -B scripts/qualify_nom_account_authorization.py --checkout CORE_SOURCE --go GO_EXECUTABLE
```

Dependencies must be acquired separately before the offline run. The qualifier
preserves original private command streams, plan, overlay and actual VM handoff,
uses finite stream/time bounds and creates a new private evidence directory per
attempt. Failure never falls back to fixture output. Hosted private custody can
be ephemeral; a console archive is not a replacement for those original files.
Overlay vet is explicitly not performed because the synthetic overlay paths are
unavailable to the selected Go 1.23 vet. Standalone Go suites retain their normal
vet behavior. Independent construction, source/runtime, canonicality, finality,
currentness and restore assessments remain unfilled.

Next select and independently review the real original-byte/custody interface,
account frontier and complete admission policy before coupling any signed wire
to recovery. Authenticate funding entry state, source branch/currentness and
received markers independently. The unsigned synthetic journals and their
unknown-before-disclosure discipline are preserved; this corpus returns no
recovery capability and supplies no permission to replace an original.
