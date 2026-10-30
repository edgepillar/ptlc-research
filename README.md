# Zenon PTLC Swap Research

An offline reference workspace for a fixed-recipient NoM-to-NoM swap client,
with preserved Bitcoin-to-Zenon construction and qualification research.
Independent research; no official implementation or activation proposal.

**Application and core remain NO-GO.** No usable swap client, production signer,
authenticated chain observer, wallet integration or deployed service is supplied.

## Start here

- [Status and source-bound evidence](STATUS.md)
- [Reference-client roadmap and acceptance boundaries](docs/REFERENCE_CLIENT_ROADMAP.md)
- [NoM reference-client protocol candidate](docs/NOM_REFERENCE_CLIENT_PROTOCOL.md)
- [Contribution, privacy and identity rules](CONTRIBUTING.md)

The initial executable client slice consists of public, offline JSON inspection
and codec tools:

```sh
python3 -B -m reference_client inspect-agreement < reference_client/synthetic_agreement.json
python3 -B -m reference_client bind-funding < reference_client/synthetic_funding_request.json
python3 -B -m reference_client prepare-presignature-check < reference_client/synthetic_presignature_request.json
python3 -B -m reference_client inspect-terms < public-input.json
python3 -B -m reference_client encode-call < public-input.json
python3 -B -m reference_client hash-account-block < public-input.json
```

Each command reads bounded JSON from standard input and writes JSON to standard
output. The tools use no network, private keys, signing interface or persistent
client state. Public requests return success after one complete local write and
flush. IO failures return a generic refusal when diagnostics are available;
missing or incomplete output remains UNKNOWN. Even a zero exit and successful
flush cannot prove that a caller captured and validated the JSON result.
`inspect-agreement` omits entry IDs. `bind-funding` checks ordered declared
Create hash/entry projections and refuses conflicting replacements.
The client profiles select the pinned source and local-devnet chain 69. Its
post-funding terms are public claims, not authenticated observations or
permission to fund, sign, recover or broadcast. RPC, signing and durable client
state remain planned work; see the protocol candidate for input contracts.

`prepare-presignature-check` derives one already bound leg's public verification
request. The separate [Rust public checker](public_crypto/README.md) checks the
selected adaptor relation with the existing pinned backend. It authenticates no
agreement or chain fact and returns action permission `NONE`. It supplies no
signing, adaptation, extraction or funding action.

## Evidence and checks

The recorded accepted baseline is
[`a51ba436`](https://github.com/edgepillar/ptlc-research/tree/a51ba436e5c5556319dcce5cf9397ce1198cd3b0),
including accepted [main CI attempt 41071695312/1](https://github.com/edgepillar/ptlc-research/actions/runs/41071695312/attempts/1).
Its own 17 jobs were accounted for: 16 succeeded and the fast job was unexecuted.
All 14 runtime jobs, nine original artifact families, both controls and complete
console were accepted separately from [PR #220](https://github.com/edgepillar/ptlc-research/pull/220).
Each of four Python profiles contained 4,621 cases; the original Rust console
contained 217 cases, including ten selected public checker cases. The earlier
[`39453004`](https://github.com/edgepillar/ptlc-research/tree/39453004bff7ba7f39178012c5fac5b4df8366dc),
[`db05a929`](https://github.com/edgepillar/ptlc-research/tree/db05a9294aa3fb40ebc35f0f926e76d6f989982b)
and [main attempt 40670225920/1](https://github.com/edgepillar/ptlc-research/actions/runs/40670225920/attempts/1)
remain separate historical evidence.
That evidence belongs to its exact source and does not qualify later changes,
independent review, signing custody or a real swap.

Run the public artifact hygiene check with:

```sh
python3 -B scripts/check_artifacts_batch.py
```

The client tests join the existing offline suite. Preserve the distinction
between focused tests, complete offline regression, native comparisons and hosted
acceptance; a fast check does not replace the complete selected baseline.
For focused public client feedback in the declared qualification environment:

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -p 'test_*client*.py' -v
cargo test --locked --offline --manifest-path public_crypto/Cargo.toml
```

The first command selects the three client modules and CI scope/transport controls.
The Rust command selects the
small package's library and process cases with its existing three dependencies.
See the [public client scenario matrix](docs/NOM_PUBLIC_CLIENT_MATRIX.md) for the
applicable checks and excluded operational scenarios.
See [regression and source custody](docs/OFFLINE_TEST_SHARDS.md) for the existing
full-profile requirements.
The [CI tiers](docs/CI_TIERS.md) keep main on full qualification and select
focused PR work only from a complete, trusted source range. At the recorded
baseline, [PR #219](https://github.com/edgepillar/ptlc-research/pull/219)
separately records a successful 71-Python/ten-Rust fast run in 27 seconds,
including setup, fetch and post work. Its one measured workspace peak is
110,651,061 bytes; neither measurement qualifies unexecuted full/native work.
The [fast-path qualification procedure](docs/PUBLIC_CLIENT_FAST_QUALIFICATION.md)
defines the separate source, original-stream, nonexecution and measurement gates.

The [821bdd2 upstream tracking corpus](docs/NOM_DEV_821BDD2.md) records complete
source bytes and changed shared paths. Tracking remains separate from the
`77ba9c7` behavior selection and the candidate's unfilled native comparison.
The [candidate native plan](docs/NOM_DEV_821BDD2_NATIVE.md) preserves all prior
profiles and adds the changed upstream tests, with a separate fee-original stage
sharing one fresh compiler workspace. It records no completed native attempt.

## Preserved research

The [public component assessment reading map](docs/NOM_PUBLIC_COMPONENT_REVIEW.md)
freezes an explicit source and nine questions. It is author preparation only;
independent assessment remains UNFILLED.

The [full qualification history](README_QUALIFICATION_HISTORY.md) preserves the
baseline README byte-for-byte at its original relative-link depth. It is a
historical reading index, not the current delivery plan. All existing code,
tests, frozen source inventories, failed evidence and review subjects remain in
place. The [current-source review packet](docs/NOM_CURRENT_REVIEW_HANDOFF.md)
selects an older explicit subject and remains unassessed.

Original contributions use the [MIT license](LICENSE). External material retains
its own terms; [third-party notices](THIRD_PARTY_NOTICES.md) describe the current
inventory and the additional work required before dependency or binary release.
