# Fee-bound original account attempts at 661b5ef

This is a separate offline reference corpus. Application and core remain
**NO-GO**, recovery action is **NONE**, and independent assessment remains
**UNFILLED**. No original, historical journal, nonce policy or source context is
replaced by these diagnostic copies.

## Source and selected context

The selected go-zenon source is
[`661b5ef404487cd41685654bf87530f10adebbe4`](https://github.com/zenon-network/go-zenon/tree/661b5ef404487cd41685654bf87530f10adebbe4),
tree `78937597e8e0e5835a8856cb44d592e349451d9f`. The complete 518-file inventory,
archive identity, licensing and baseline profiles remain recorded in the
[source comparison](NOM_DEV_661B5EF.md). Preparation adds the unchanged 25 project
files from that selection and one new test producer, giving 544 files.

Only the two existing public synthetic signed `Unlock` originals are admitted.
Their exact bytes, signatures, public keys, predecessor snapshots and acknowledged
momentum inputs are preserved. Both originals declare 73,500 fused Plasma, zero
work difficulty and 164 ABI data bytes. The selected synthetic memory context
enforces Dynamic Plasma and supplies 367,500 available Plasma before each call.
It is not a current quote, authenticated chain state or availability guarantee.

Under that context, the selected withdrawal tier plus argument pricing requires
`73500 + (164 - 4) * 68 = 84380` Plasma. More available capacity does not change
the amount already declared in a signed block.

## Fourteen finite attempts

Each leg retains its original and adds three diagnostic fused amounts, each with
the old advertised hash or a recomputed advertised hash. The existing outer
signature is retained in every copy. No new key or signature is produced.

| Attempt per leg | Declared fused Plasma | Advertised hash | Expected refusal |
| --- | ---: | --- | --- |
| Existing original | 73,500 | Original | `ErrNotEnoughTotalPlasma` |
| Below threshold | 84,379 | Original | `ErrNotEnoughTotalPlasma` |
| Below threshold | 84,379 | Recomputed | `ErrNotEnoughTotalPlasma` |
| Exact threshold | 84,380 | Original | `ErrABHashInvalid` |
| Exact threshold | 84,380 | Recomputed | `ErrABSignatureInvalid` |
| Above threshold | 84,381 | Original | `ErrABHashInvalid` |
| Above threshold | 84,381 | Recomputed | `ErrABSignatureInvalid` |

There are six earlier fee refusals, four later hash refusals and four later
signature refusals. All attempts return no transaction and leave the selected
base account and contract stores unchanged. Eight enter the packed transaction
verifier. The declared values independently bind entry/post-call wire digests,
advertised/computed node hashes, signature preservation and the verifier trace.
Derived Base/total Plasma changes remain separate from hash-committed fields.

The selected node
[hash input](https://github.com/zenon-network/go-zenon/blob/661b5ef404487cd41685654bf87530f10adebbe4/chain/nom/account_block.go#L281)
includes `FusedPlasma`. The packed verifier checks the computed hash before
[checking the existing outer signature](https://github.com/zenon-network/go-zenon/blob/661b5ef404487cd41685654bf87530f10adebbe4/verifier/account_block.go#L495).
Consequently, altering the allowance cannot repair these exact signed originals
without a separately authorized transaction. This finite result does not select
such an authorization or create a replacement original.

The reader accepts only the fixed public input projection and declared values.
Malformed, incomplete, failed, skipped, foreign-source or authority-promoting
streams refuse. A matching manufactured stream can pass data comparison; it
does not establish native execution origin. Spork-read order and packed delta
contents remain explicitly labeled observations rather than admission proofs.
These are account-send refusal cases. They do not execute contract receive,
settlement, recipient credit or a complete swap recovery.

## Direct caller and a separate proxy path

For a nonzero fixed destination, direct
[`Unlock`](https://github.com/zenon-network/go-zenon/blob/661b5ef404487cd41685654bf87530f10adebbe4/vm/embedded/implementation/ptlc.go#L524)
uses the sender as the payout destination, which must match that fixed recipient.
[`ProxyUnlock`](https://github.com/zenon-network/go-zenon/blob/661b5ef404487cd41685654bf87530f10adebbe4/vm/embedded/implementation/ptlc.go#L581)
supplies the destination separately; a different sender can pay while the same
fixed-destination and witness checks remain in force.

This corpus selects direct `Unlock` only. A separate proxy selection has 196 data
bytes for the existing 64-byte witness and a declared argument-priced requirement
of `73500 + (196 - 4) * 68 = 86556` Plasma under the same tier. That arithmetic is
not native proxy execution or admission evidence. A proxy recovery design needs
its own outer authorization, account/funding context, custody policy and timing
assessment. It cannot silently replace a retained direct original or upgrade an
old journal. No proxy signer or operational adapter is selected here.

## Reproduce the separate component

Use explicitly owned new source, input and evidence paths, a separately selected
Go 1.23.12 toolchain, an offline dependency proxy and an explicit compiler/SDK
selection. Admit their quotas and free-space floor before preparation. Neither
the source preparer nor data reader provisions those resources or runs a node.

```text
python3 -B scripts/prepare_nom_fee_original_boundary.py --archive CORE_ARCHIVE --destination NEW_COMPONENT_SOURCE
python3 -B -m qualification.nom_fee_original_boundary --emit-public-inputs
```

Retain the emitted public input bytes in a new owned file. Set
`PTLC_NOM_FEE_ORIGINAL_INPUT` to that file for the selected Go process. In the
prepared source view, use the separately configured offline environment:

Select `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`, `GOFLAGS=-trimpath`,
`GOVCS=*:off` and the retained file-only `GOPROXY`. Select `GOSUMDB=off` only for
that explicit offline dependency snapshot; this is not dependency authentication.
Give `GOCACHE`, `GOMODCACHE`, `GOTMPDIR` and the child home their own admitted
workspace paths. Select the C compiler and, on Darwin, the SDK and diagnostic
profile explicitly as described by the pinned baseline.

```text
go version
go test -json -p 2 -mod=readonly -count=1 -run '^TestResearchNoMCurrentFeeOriginalBoundary$' ./vm
go mod verify
```

Default vet stays enabled and `-count=1` prevents test-result reuse. One fresh
compiler workspace is sufficient for this new profile; the unchanged 31-profile
subject has a separate source-bound qualification. Retain actual exits, complete
original stdout/stderr, source snapshots before/after, compiler identities and
process cleanup results. Reading a saved stream is a separate operation:

```text
python3 -B -m qualification.nom_fee_original_boundary --stream OWNED_ORIGINAL_GO_JSON
```

The declared fixture is an oracle, not captured Go output. Initial author
qualification executed fourteen children plus their parent using three actual
Go commands and retained all six Go streams. The exact compiled producer and
declared value bytes are preserved by this addition. That component evidence
does not qualify a new publication revision, hosted PR/main execution, compiler
or SDK authenticity, canonical state, signing custody or independent review.
The repository suite exercises synthetic reader/source controls and does not
silently run the new native profile.

The upstream GPL version 3 implementation is obtained separately. Its source is
not vendored or relicensed by the independently written project probe. Existing
source notices, original archives, failed evidence and frozen assessments remain
in place. External protocol/custody review and AS-1 through AS-7 remain unfilled.
