# Source and pricing comparison at 661b5ef

Status: selected source bytes, independent finite helper expectations and runtime
readers. Complete local regression, actual native execution, original-output
retention, hosted PR acceptance and subsequent main acceptance are separate
gates. A declared plan or manufactured event stream fills none of those execution
gates. Application and core remain **NO-GO**, recovery action is **NONE** and
independent assessment remains **UNFILLED**.

## Immutable source and retained history

The input is go-zenon
[`661b5ef404487cd41685654bf87530f10adebbe4`](https://github.com/zenon-network/go-zenon/tree/661b5ef404487cd41685654bf87530f10adebbe4),
Git tree `78937597e8e0e5835a8856cb44d592e349451d9f`.
The [inventory](../compatibility/nom_dev_661b5ef_source_v1.json) binds all 518
files by byte count, SHA-256, Git blob and logical mode. Its SHA-256 is
`a6eec89b1ca82e66cb6bcc855b1efc8b95981ffb7e43b1e3528d3daf8ba956fa`.
The separately acquired source archive is 2,053,008 bytes with SHA-256
`9ccc6b8aaa4c4f5a28d11236a3393727bd2f4959c13385c05a0fb81fe4c09acd`.

Against [ac16bfd](NOM_DEV_AC16BFD.md), four files are added, ten change and 504
remain byte-identical. No file is removed. All eighteen selected PTLC files,
`LICENSE`, `go.mod` and `go.sum` remain byte-identical. The upstream GPL version 3
implementation is neither vendored nor relicensed. Historical inventories,
fixtures, source labels, original evidence and journal pins remain intact.

The six-commit delta includes
[embedded argument pricing and bounds](https://github.com/zenon-network/go-zenon/pull/223),
[the epoch-point walk bound](https://github.com/zenon-network/go-zenon/pull/225)
and [downloader stop and hash-reply bounds](https://github.com/zenon-network/go-zenon/pull/226).
Unchanged PTLC file bytes do not establish unchanged outer admission, prices,
chain observation or recovery behavior.

## Independent finite argument-pricing values

The [helper selection](../compatibility/nom_embedded_argument_pricing_manifest.json)
compares `vm.EmbeddedSendBasePlasma` using 85 inputs: five unsigned tiers crossed
with seventeen signed data lengths. The independent Python arithmetic charges
68 Plasma per byte after the four-byte selector and rejects a complete data
length above 16,384 bytes. The cap and pricing are selected upstream behavior;
this arithmetic introduces no separate protocol requirement.

The inputs include selector-only lengths, the first argument byte, ABI word
boundaries, both sides of the cap and signed machine limits. Maximum-tier probes
record the helper's unsigned 64-bit wraparound. Actual method callers provide
fixed tiers; these probes supply no valid user quote or arbitrary-tier API.
Likewise, the helper returning a tier for a negative or short length does not
make a negative length or incomplete ABI selector a valid transaction.

The Go producer receives only the public input table. It never receives the
independent expected-value fixture. Readers require all 85 named children, the
parent, exact values, closed event lifecycles and the terminal newline. Source
substitution, missing cases, failures, skips and promoted authority fields are
refused. A correct data stream alone establishes neither actual process exit
nor execution origin. The original failed author control remains retained; its
missing-newline refusal led to the explicit terminal-line check.

## Selected runtime assertions and one workspace

The [combined selection](../compatibility/nom_dev_661b5ef_manifest.json) selects
twenty legacy profiles and one reclaim profile with 556 reference outcomes.
The added pricing parent and 85 children bring the project reference total to
642 outcomes across 22 producers. Historical fixtures remain intact. The twelve
source-specific fee refusals below are derived from declared pricing and control
flow; newly observed Go output does not supply the oracle.

The [runtime selection](../compatibility/nom_dev_661b5ef_runtime_v1.json) preserves
the seven earlier runtime profiles and adds two inert profiles:

| Profile | Required top-level functions | Scope |
| --- | ---: | --- |
| Embedded pricing | 1 | Upstream helper boundary assertions |
| Quote snapshot | 5 | Captured-cache refusal, fused targets and JSON behavior |

The complete runtime selection has nine profiles and 58 required top-level
functions. These are upstream implementation assertions, separately identified
from independent project values. Child counts are observed closure rather than
an independently enumerated case total. The RPC tests use synthetic in-memory
chain interfaces; they invoke no network client or real node startup.

The combined plan has 31 profiles, one 543-file source view, one cold-build
package set and one fresh compiler cache. That view contains 518 upstream files,
22 reference producers and three explicit test logging initializers. Default
vet remains enabled and `-count=1` disables test-result reuse. The 35 required
actual Go commands comprise 31 profiles, version, cold build, definition tests
and module verification. All 62 original profile streams remain required.

The existing current-core CI job selects this source. Other historical jobs are
retained. The explicit `GOFLAGS=-trimpath`, narrow Protobuf diagnostic inspection,
test logging configuration and selected Darwin diagnostic flags retain the
[earlier scope](NOM_DEV_AC16BFD.md). Original output is never sanitized or
replaced. Toolchain, SDK and dependency authentication remain separate unfilled
requirements.

## Existing signed originals and the earlier fee refusal

Both existing public synthetic `Unlock` originals declare 73,500 fused Plasma,
zero work difficulty and 164 data bytes. At this source, Dynamic Plasma charges
the 73,500 withdrawal tier plus `160 * 68`, requiring 84,380 Plasma. The diagnostic
copy with one trailing byte requires 84,448. The shortfalls are 10,880 and 10,948,
respectively. Increasing available fused capacity alone does not change the
73,500 amount declared in the signed block.

The first actual native comparison stopped at the insufficient-total-Plasma
refusal. Its failed output remains failure evidence. That observation prompted
the source review; it does not qualify the corrected full candidate. In
[`enoughPlasma`](https://github.com/zenon-network/go-zenon/blob/661b5ef404487cd41685654bf87530f10adebbe4/vm/vm.go),
the total is checked before send validation, packing and the packed transaction
verifier. The new finite oracle therefore expects `ErrNotEnoughTotalPlasma` for
all twelve Dynamic Plasma cases. Missing or corrupt outer signatures, a changed
witness and trailing bytes cannot reach their later checks with this exact
funding. The twelve pre-spork expectations remain byte-identical to history.

The VM updates derived `BasePlasma` on the ephemeral call copy before refusing.
That field is serialized, so the oracle independently checks its changed wire
digest. `TotalPlasma` remains 73,500. The immutable original, declared fused
amount, difficulty, hash, public key, signature and predecessor state remain
preserved. The private binding of historical reader functions adds only this
explicit current-source oracle; the historical module is not mutated. The Go
descendant admits only the corresponding error label and expected earlier
refusal in addition to its exact source-label change.

The recovery implication is to retain the exact original and hold progress.
This comparison selects no top-up, replacement, new signature, journal source
upgrade or broadcast. A later ABI or signature error is not qualified by a fee
refusal. Complete fresh local, native and hosted acceptance remain separate.

## Observation and recovery boundaries

The selected RPC source captures a frontier momentum and reads its cache by
that exact identifier. Missing captured-cache state refuses a quote. Dynamic
Plasma capacity follows the spork state even at a version-one enforcement
momentum, while version-two price scaling retains its separate condition.
A coherent local quote is not canonicality, insertion, settlement or recipient
credit evidence.

The complete source inventory also contains new mock-chain send-bound tests,
consensus traversal tests and downloader tests. This runtime selection does not
execute those new suites. In particular, the HTLC preimage bound, bridge
signature bound, actual chain insertion and downloader recovery are not qualified
by the helper pricing cases. Those behaviors require their own scoped runtime
selection and observation obligations.

The recovery journal keeps its previous source context. A source comparison,
author review or green CI run cannot independently qualify signed custody,
rollback handling or the fixed-recipient swap protocol. Independent protocol
assessment remains required. No deployment, activation, real wallet use,
transaction broadcast or real funds are authorized by this corpus.
