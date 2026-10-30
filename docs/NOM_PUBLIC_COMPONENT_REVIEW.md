# Public NoM component: scoped assessment reading packet

Status: **preparation only; NOT ASSESSED / UNFILLED**. This document is an
author-prepared reading map and question set. It is not an independent review,
a review submission, a reviewer appointment or a complete-protocol assessment.
Application and core remain **NO-GO**, with action permission `NONE`.

## Exact subject

The selected subject is public component source
[`4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447`](https://github.com/edgepillar/ptlc-research/tree/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447).
It contains offline agreement/funding inspection, public presignature request
derivation and a separate public-only adaptor relation checker. No signer,
authenticated chain observer or durable operational client store is selected.
Later commits require a new declared assessment subject; an unchanged subset
or successful CI does not convert this packet into assessment of a new revision.

Selected NoM behavior is
[`77ba9c7ee8c881e90911946756cdb67d8b586043`](https://github.com/zenon-network/go-zenon/tree/77ba9c7ee8c881e90911946756cdb67d8b586043).
The public backend is
[`74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce`](https://github.com/LLFourn/secp256kfun/tree/74d18bbf864f98e5cf7c18dcfb74ba1ecfe837ce).
Historical codec markers and upstream tracking labels do not establish latest
upstream compatibility or activation.

## Evidence and its limits

The separately accepted baseline is
[`285cd07e371c48743583dbd641b1133cb8e62e60`](https://github.com/edgepillar/ptlc-research/tree/285cd07e371c48743583dbd641b1133cb8e62e60).
The [CI-tier PR record](https://github.com/edgepillar/ptlc-research/pull/217)
records separate acceptance of
[PR attempt 40972712319/1](https://github.com/edgepillar/ptlc-research/actions/runs/40972712319/attempts/1)
and its own
[main attempt 40985764730/1](https://github.com/edgepillar/ptlc-research/actions/runs/40985764730/attempts/1).
Each completed 17 jobs: 16 succeeded and the fast job was explicitly unexecuted.
All 14 runtime jobs, both control originals, nine artifact families and complete
console were accepted, including four 4,609-case Python profiles and 217 Rust
tests. The public Rust subset contains five library and five process cases.
Those baseline results do not qualify the later subject selected above.

The subject adds Python IO handling and seven directed cases to the existing
Python component tests. An earlier local 17-case component run used the exact
entry-point and test-file hashes listed below; its uncommitted scope does not
qualify this complete commit. Full source qualification, the containing PR and
its own main push remain separate records and subjects. No assessment is
inferred from matching files, successful parsing, local checks or green CI.

The [scenario matrix](NOM_PUBLIC_CLIENT_MATRIX.md) preserves the distinct Rust
and Python counterexamples. Python source `285cd07e` returned zero for an
injected zero-character writer, whereas its actual closed-output process exited
120 with deliberately uncollected output. The later candidate requires complete
local writing and flushing. Discarded or missing output still supplies no parsed
receipt or receiver-custody proof. None of these controls is operational recovery.

This reading subject is frozen before the reading map's addition. Later reading
and status changes have their own source identity; they do not change the hashes
or assessment status of this subject. Any assessor must explicitly select the
complete examined subject and relevant delta, rather than inherit a review.

## Reading order and questions

Read the protocol and scenario matrix before the Python preparation path,
then examine the public Rust package, tests, dependency contexts and evidence.
The questions below request examination; they do not state completed findings.

### PUBLIC-M4-01: Protocol and public preparation

Are the pre-funding agreement, ordered long/short Create projections and locally derived Unlock requests correctly separated from authenticated agreement, actual execution and live entry evidence?

### PUBLIC-M4-02: Message and economic binding

Confirm the exact selected 101-byte contract message and the fields it excludes. Assess how any future authenticated agreement must bind economics and the full adaptor point without treating the echoed context digest as authentication.

### PUBLIC-M4-03: Selected public relation

Assess the pinned encrypted-signature representation, curve/scalar/parity validation, full-point binding and refusal boundaries. Public mathematical validity must grant no funding, disclosure or recovery authority.

### PUBLIC-M4-04: IO and result custody

Assess the Python complete-write, flush, generic-refusal and standalone shutdown paths alongside the Rust process boundary. Missing or discarded output remains UNKNOWN; examine failure and custody limits without granting retries or actions.

### PUBLIC-M4-05: D1 observation, not connected

Before connecting an observer, select source/genesis/node ownership, currentness, evaluation context, confirmation/reorg assumptions and distinct send, contract execution, payout and recipient receive evidence.

### PUBLIC-M4-06: D2 signer, not selected

Before implementing a signing owner, assess the exact API/construction, key/message/full-point and nonce/context binding, retry/restore/copy assumptions and disclosure order. Existing synthetic tests are not application signer selection.

### PUBLIC-M4-07: D3 candidates and durable recovery, not selected

Before implementing persistence or fee refresh, assess exact original custody, UNKNOWN handoffs, possible disclosure, account predecessor/outer envelope changes and reconciliation. Missing output or a matching restored copy must not authorize replacement or nonce reuse.

### PUBLIC-M4-08: Dependencies and distribution

Assess actual selected dependency sources/features, build contexts and distribution/notice obligations. Package metadata and a process boundary alone are not a license conclusion.

### PUBLIC-M4-09: Independent assessment subject

Define the exact examined protocol/code/dependency/evidence scope, assumptions, independence limits, exclusions and finding dispositions. The historical e61aa174 handoff must not be relabeled as this later public component.

## Immutable source reading map

Paths and SHA-256 values select the exact files below; all links use the
subject commit. The table is a reading subset, not a complete dependency or
execution closure.

| File | SHA-256 |
| --- | --- |
| [README.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/README.md) | `5a01c10dea4dff683e01c41d77c282cda8ca536f1716fbf6248ae2bef1c72a0b` |
| [STATUS.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/STATUS.md) | `e74aafa5826673099c59c826b01f0a68bdf66e964052feb24bd9a11e57d949aa` |
| [THIRD_PARTY_NOTICES.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/THIRD_PARTY_NOTICES.md) | `a118c6d5c040435025200f98add35e2a24127ee5fa87e60a43ad6d02c9d529df` |
| [docs/NOM_PUBLIC_CLIENT_MATRIX.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/docs/NOM_PUBLIC_CLIENT_MATRIX.md) | `fe513414ef55c027539312a5f48c39997fbc5c1c9123b25698d122c6e9a84407` |
| [docs/NOM_REFERENCE_CLIENT_PROTOCOL.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/docs/NOM_REFERENCE_CLIENT_PROTOCOL.md) | `c156267c3e45ab61ab69d78eebc6a767b5ccf86507ae86d9b9b4489fb994a4d7` |
| [docs/REFERENCE_CLIENT_ROADMAP.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/docs/REFERENCE_CLIENT_ROADMAP.md) | `896ed6ca61eefc6f9cab0a5397c512b30d347ccce43dacedff26facca49ad227` |
| [offline_session/__init__.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/offline_session/__init__.py) | `6c75853d50426321eb81fea287dd7a6063bcaa979c55a3d7f8a7ccc657fc2fd4` |
| [offline_session/nom_wire.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/offline_session/nom_wire.py) | `d79dd83b98b6a31c3b5b15deb26ea4b671d2ed96dab03bf02381b9648492b839` |
| [offline_session/pr138.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/offline_session/pr138.py) | `5fde0d8409885faa0fe7ad2f2507ee422ce964cee50800e04296f8fcc5b79c9d` |
| [public_crypto/Cargo.lock](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/Cargo.lock) | `b52bc442eb16ef7576f91a30ed01fa61b6a1d58888f3220ea12e42c4c16dbbc3` |
| [public_crypto/Cargo.toml](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/Cargo.toml) | `c2190e4c23a496d733d9bce0dc79f65e185ed503f87118d41a21eb00a9824d84` |
| [public_crypto/README.md](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/README.md) | `ebc838f09b8c3d280af8923bb76e3b53abbbbcd3b6c8b1bdc8232cdc4d1b8908` |
| [public_crypto/src/lib.rs](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/src/lib.rs) | `d5e4448404eefeda09ef76a327746da1b20da73d6aadb4911d8cea48e540470c` |
| [public_crypto/src/main.rs](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/src/main.rs) | `7e532a4dd037a9314d00306bcb10b89bebf489b5980e168ab7ae19e267d24513` |
| [public_crypto/synthetic_long_request.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/synthetic_long_request.json) | `d6742380a39e002d940465342ff34c0e05c0dce574dcfa995a0d70e5068877d8` |
| [public_crypto/synthetic_request_provenance.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/public_crypto/synthetic_request_provenance.json) | `4a5798d7a1ea64d257494f170c8ba6a4e65a1ab6bb86f379d393dcd7eec82624` |
| [qualification/Cargo.lock](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/qualification/Cargo.lock) | `0b11653ef036a40eeff432fe021c3f479811f28b4d99e6853e68d3a1d68161af` |
| [qualification/Cargo.toml](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/qualification/Cargo.toml) | `7a7494e660c0928889bab63185876580dd65a5f14706b4fbabac434aef59fc8b` |
| [qualification/examples/verify_client_presignature.rs](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/qualification/examples/verify_client_presignature.rs) | `bec2305dd81b4d2dc37f1a2a62fd05492c5905491ff66d80742ab00ca04493a3` |
| [qualification/tests/client_public_crypto.rs](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/qualification/tests/client_public_crypto.rs) | `30a57f8e8de3643c2596f24dd2d60e66171126d25169afed26da7eb7a23f605b` |
| [qualification/tests/client_public_crypto_process.rs](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/qualification/tests/client_public_crypto_process.rs) | `e3791b0ddfcd3640ada506215ce337a03a631f84edd4446e583a7be1beb3fc9c` |
| [reference_client/__init__.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/__init__.py) | `ebc1e13d4ecfa4b56599888c33952a534b0d0f6ee2eaecd5f4bb618ae780607e` |
| [reference_client/__main__.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/__main__.py) | `ad5dbd22f1cc71598e65b826053fc109a040461ee3d174e4960d1f77d6fa3355` |
| [reference_client/agreement.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/agreement.py) | `6931a238770ff80c94196ec8f793f208a730a05f40f27548cab55d53f45e5409` |
| [reference_client/plan.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/plan.py) | `cdf476f186af6ce01f207d2da5b577d8df0c19b92bcaab553d2c2c1ff0fb3046` |
| [reference_client/presignature.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/presignature.py) | `0bdfe807219e3a95b620d5d778646f5071994b3d7329f6a27105a312797aadd6` |
| [reference_client/synthetic_agreement.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/synthetic_agreement.json) | `8d38081e28ca321a708f22c1d88a60af74cf013f12064411a6e27dcb39707f83` |
| [reference_client/synthetic_funding_request.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/synthetic_funding_request.json) | `4b7dcabaed7293285301b686616e764351e53621d87dc0968de11a5ca3ac9b14` |
| [reference_client/synthetic_presignature_request.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/synthetic_presignature_request.json) | `4ea0bb980bb1586add110906e6a298c05b82142e42eb4c8dea7a52d061fea792` |
| [reference_client/synthetic_terms.json](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/reference_client/synthetic_terms.json) | `e0e52a08076e15a0f3e2fe3042a08e96b97bd3536df66c7396a55ef1f3009389` |
| [tests/test_client_agreement.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/tests/test_client_agreement.py) | `0fed8605a8ce520bf43280a9daefed529322be13fb38039af570e4902b743d95` |
| [tests/test_client_presignature.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/tests/test_client_presignature.py) | `afdb50092bc1158a3272ecf02cd0eb063c8c66ce43942bab7f0d2f2544fe4dad` |
| [tests/test_reference_client.py](https://github.com/edgepillar/ptlc-research/blob/4bd83e3c1d8ba09cc41a743ce05b13ed76bf0447/tests/test_reference_client.py) | `eaf7eed0e156db46b10a356699042de5f83cc5971744489a61d05720e4021e57` |

## Import and build contexts

The prepared static Python reading follows eight local files: the three
`reference_client` preparation modules, its entry point and package initializer,
plus `offline_session` initialization, `nom_wire` and `pr138`. Static reading
found no dynamic import/execution sites in that selected map. The Python standalone
refusal path now handles standard-stream shutdown through the fixed null
device; it selects no caller file path or durable client state. Runtime search
paths, toolchain and supply-chain trust require separate examination.

The small Rust package selects `schnorr_fun` at the pinned backend, `sha2`
`0.10.9` and `serde_json` `1.0.151`; its library, binary and integration test
are distinct targets. Its lock SHA-256 is
`b52bc442eb16ef7576f91a30ed01fa61b6a1d58888f3220ea12e42c4c16dbbc3`.
The full qualification crate is a separate build context. Package metadata and
process boundaries alone are not a license conclusion. Examine actual sources,
features, selected targets and distribution/notice obligations before vendoring
or distributing binaries.

## Required assessment record and exclusions

An eventual assessor must declare the exact protocol/code/dependency/evidence
subject, assumptions, examined questions, findings, dispositions, exclusions
and independence limitations. Author review and cross-implementation controls
remain valuable engineering inputs but do not satisfy independent assessment.
The older `e61aa174` handoff remains a different frozen, unassessed subject.

Operational signing/observation/storage, actual bilateral funding or settlement,
node/spork activation, wallet access, broadcast, real funds, operational restore,
all-copy fencing and the Bitcoin extension are excluded. No reviewer has been
contacted or appointed by this packet, and no operational permission follows.
