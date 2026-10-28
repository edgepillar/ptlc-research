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
python3 -B -m reference_client inspect-terms < public-input.json
python3 -B -m reference_client encode-call < public-input.json
python3 -B -m reference_client hash-account-block < public-input.json
```

Each command reads bounded JSON from standard input and writes JSON to standard
output. The tools use no network, files, private keys or signing operation.
`inspect-agreement` omits entry IDs. `bind-funding` checks ordered declared
Create hash/entry projections and refuses conflicting replacements.
The client profiles select the pinned source and local-devnet chain 69. Its post-funding terms are public claims, not authenticated observations or
permission to fund, sign, recover or broadcast. RPC, signing and durable client
state remain planned work; see the protocol candidate for input contracts.

## Evidence and checks

The recorded accepted baseline is
[`db05a929`](https://github.com/edgepillar/ptlc-research/tree/db05a9294aa3fb40ebc35f0f926e76d6f989982b),
including accepted [main CI attempt 40670225920/1](https://github.com/edgepillar/ptlc-research/actions/runs/40670225920/attempts/1).
That evidence belongs to its exact source and does not qualify later changes,
independent review, signing custody or a real swap.

Run the public artifact hygiene check with:

```sh
python3 -B scripts/check_artifacts_batch.py
```

The client tests join the existing offline suite. Preserve the distinction
between focused tests, complete offline regression, native comparisons and hosted
acceptance; a fast check does not replace the complete selected baseline.
See [regression and source custody](docs/OFFLINE_TEST_SHARDS.md) for the existing
full-profile requirements.

## Preserved research

The [full qualification history](README_QUALIFICATION_HISTORY.md) preserves the
baseline README byte-for-byte at its original relative-link depth. It is a
historical reading index, not the current delivery plan. All existing code,
tests, frozen source inventories, failed evidence and review subjects remain in
place. The [current-source review packet](docs/NOM_CURRENT_REVIEW_HANDOFF.md)
selects an older explicit subject and remains unassessed.

Original contributions use the [MIT license](LICENSE). External material retains
its own terms; [third-party notices](THIRD_PARTY_NOTICES.md) describe the current
inventory and the additional work required before dependency or binary release.
