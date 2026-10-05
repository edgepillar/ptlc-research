# Historical original-read response signature qualification

This later isolated candidate extends the [unsigned original-read grammar](ORIGINAL_OPERATION_READ_CONTRACT.md)
at `780b351ab4a57e035a8deeedecd8b2637387130e`. It checks a selected root signature
and a separately scoped response signature. The entire original operation and
both selected checkpoints are covered. It adds no source service, application
signer, recovery adapter, caller lookup permission or protected-use gate.

**GO for isolated offline qualification; NO-GO for source integration, application
cryptography, core port, activation, deployment or funded execution.** Neither
fixed independent report is filled by this work. See [executed validation](STAGE47_VALIDATION.md).

## Requirements, selected construction and execution

| Boundary | Meaning |
| --- | --- |
| Required independently selected inputs | Complete root/source, original id/revision/profile/proposal, policy and record checkpoints, challenge and complete claim before incoming bytes. Root trust and current checkpoint selection remain external premises. |
| Selected historical rule | Same-incarnation retained-original grammar, including historical profiles that differ from the selected head. Four observations remain absent, pending, completed and unavailable. |
| Selected response role | `historical-original-responder`, using the exact selected declaration's `source_response_key_hex`, under `historical-original-checkpoint-read-v1`. This declares the isolated check's meaning; it does not operationally authorize the old role to serve queries. |
| Actual public checks | Locked Rust Bitcoin/libsecp256k1 verifies the root and response. Separate Go btcec tests recompute the tagged message, check the same public vectors and enforce complete grammar. Neither implements a source or client service. |
| Historical owner key | The actual mathematical checks additionally require the original profile's owner key to be a valid x-only curve key. This is no owner signature, possession proof or historical profile provenance. The Python codec checks shape only. |
| Successful return | The identical unsigned independently selected `OriginalReadResponse`, with no receipt, current-authority, refund, retry, reconciliation or entry capability. |

The complete claim is deliberately selected as an expectation for these offline
tests. This is not a live lookup adapter that discovers an unknown observation.
The raw worker can verify a packet's self-selected historical mathematics. Only
the Python wrapper compares it with independent expectations before launch.
Self-selecting those expectations from a peer would remove that boundary.

## Exact bytes, domains and role binding

The response has eleven fields: `schema`, `purpose`, `algorithm`, `read_rule`,
`root_declaration_digest_hex`, `source_response_role`, `source_response_key_hex`,
`source_context`, `query`, `claim` and `claim_digest_hex`. Its fixed schema is
`ptlc-observation-original-read-response-v1`; purpose is
`original-checkpoint-response`, and algorithm is `BIP340-SHA256`.

The original operation retains all five fields, including its entire fourteen
field profile. The nine field query binds the exact source/root, original,
selected policy checkpoint, complete-retention record checkpoint and challenge.
The ten field claim binds that query, source/root, both checkpoints, head policy,
observation and original record. A recorded original must match all five original
fields. Charges are positive and within the selected record sequence. Completed
effects follow the charge within that sequence; pending effects are null.
Unavailable claims have no state, policy or record. Absent claims have no record.
An opaque lineage digest and a syntactically ordered sequence prove no lineage.

Historical originals must retain the selected source's authority/resource/role
namespace. Their revision cannot exceed the selected policy revision. At the
same revision their profile must equal the complete selected head profile. Older
profiles can differ in owner, caps, epoch and other profile commitments. No old
governor assignment or owner-admission signature packet is reinterpreted.

Canonical JSON uses sorted keys, compact separators and ASCII, with exact fields,
types and lowercase hex. Numbers are exact non-boolean integers in `0..2^53-1`,
except positive epoch/revision requirements inherited by the root, positive
charge/effect positions and caps in `1..64`. No aliases, floats, duplicate keys,
unknown privileges, extra fields or trailing bytes are accepted by the codec.
The public raw worker additionally permits exactly one terminal LF.

| Item | Selected framing |
| --- | --- |
| Response signing message | `SHA256(SHA256(tag) || SHA256(tag) || canonical(response))`, where ASCII tag is `PTLC/observation-original-read-response/v1`, without NUL. The resulting 32 bytes are supplied as the BIP340 message. |
| Root signing message | Unchanged `SHA256("PTLC/observation-source-root-declaration/v1\0" || canonical(declaration))`. |
| Query / claim digest | Unchanged Stage 46 `PTLC/observation-original-read-query/v1\0` and `PTLC/observation-original-read-claim/v1\0` prefix hashes. |
| Envelope / request | Exact four fields `schema`, `root_envelope`, `response`, `response_signature_hex`, with schemas `ptlc-observation-original-read-response-envelope-v1` and `ptlc-observation-original-read-response-request-v1`. |
| Complete request digest | `SHA256("PTLC/observation-original-read-response-request/v1\0" || canonical(request))`, including both signature encodings and all nested bytes. |
| Result | Exactly `schema`, `request_digest_hex`, `root_signature_valid`, `response_signature_valid`; schema `ptlc-observation-original-read-response-result-v1`, both flags literal true. No owner/issuer/current-state flag exists. |

The new tagged response domain is a selected application prehash convention. It
does not change the retained root/query/claim formulas or BIP340's own internal
tagged hashes. The old Stage 44 four-signature response, governor request and
root-only packet are separate schemas. Plain-prefix and legacy-domain response
signatures are refused by the actual checks.

Both signatures are exact 64 byte public values. Root verification reuses the
unchanged root worker, including its five distinct curve-key checks. The response
key must equal the selected delegated key. Public curve membership, distinct
encodings and successful signatures establish no independent key custody.

## Bounds and selected worker trust

The request/envelope bound is 16,384 bytes. The selected Python public checker
requires an absolute executable and matching SHA256 entry measurement. It
remeasures before launch, uses the existing bounded public runner with a 512 byte
result bound and five second default timeout, and requires the exact canonical
result with optional one LF. Worker refusal is exit 1 with empty stdout/stderr.
Errors are sanitized; cancellation propagates. Request data is defensively copied
and independent selections are revalidated after a callback.

The path is only a runtime input and is never retained in an artifact. Entry
measurement is not atomic launch, binary provenance, a sandbox or authenticated
source identity. A malicious selected callback can forge both true flags for
zero signatures; the actual worker refuses those same bytes. The caller's worker,
runtime and independently selected expectations remain trust premises.

## Executed unsafe controls and open gates

| Control | Observed limit |
| --- | --- |
| Fresh challenge over old active policy and original | Valid historical signatures still match. No live source lookup or freshness follows. |
| Same id with changed proposal/revision/profile | Independently self-selected statements can each have valid signatures. Signature math does not enforce atomic source idempotency. The unchanged owned local store separately refuses conflicting retained originals. |
| Different ids with same proposal | Both selected statements verify; business-intent uniqueness is not established. |
| Old profile after head-profile change | Complete old profile stays bound, without granting new enrollment or proving that historical profile was actually issued. |
| Valid signed malformed rules | Root and response mathematics verify separately, but 43 complete forbidden-read vectors are refused by the worker's grammar/role checks. |
| Revoked local pending operation | Checking an old response does not mutate SQLite, release its charge, commit a pending effect or restore local authority. |
| Coherent source clone / restore | The same original synthetic effect repeats in independent copied or restored databases while historical math still verifies. There is no external nonrollback witness. |
| Absent, unavailable or lost callback return | Local pending state and charge remain unchanged. No automatic retry, refund, fresh id or authoritative reconciliation occurs. |
| Queued response after revocation | Historical math still verifies. The managed synthetic effect refuses; a deliberately blind ideal list actuator can still append an entry. This is no physical device test or use fence. |
| Alternate valid signature encoding | Both mathematical checks succeed, but the complete request digest/result changes. A cached old result refuses. |

The local-store controls exercise real owned SQLite ordering, but their selected
signed fixtures are separate synthetic premises. No signed reply is produced by,
sampled from, compared to or authenticated by the source store. Their opaque
checkpoint commitments are not receipts for actual local event history. This
separation is intentional and is part of the source-integration NO-GO.

Before any integration, independently select and review operational root/response
custody, actual authenticated current source and head selection, retained old
profile provenance, caller lookup authorization and disclosure rules, retention
duration, external nonrollback original/charge/effect lineage, source compromise
and authorized incarnation transitions, and the physical-entry revocation cutoff.
Atomic administrator commit/deduplication and authoritative unknown-outcome
reconciliation remain separate missing constructions. Neither local nor hosted
regression success fills either independent assessment.

## Source and reuse record

Primary specification reference: [BIP340 at immutable commit
2885f13d3f37890e328683166dbcbc60b488d13a](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki).
It specifies x-only public keys, Schnorr verification and tagged hashing, and
recommends application context separation, including a context-specific tagged
prehash option. Those are source facts. This candidate's schemas, lookup role,
tag, bounded result and original binding are project choices. Executed tests
establish only their reported behavior, not protocol security or source trust.

The specification's text license is BSD-2-Clause; its code has the separately
listed BSD-2-Clause/MIT/CC0 alternatives. No passage, implementation or upstream
vector is copied. The new code and deliberately synthetic public fixture are
original project MIT material, reusing project patterns at the parent commit.
Locked Rust Bitcoin/libsecp256k1 and btcec dependencies and their notices remain
unchanged. This is no replacement cryptographic construction for a real swap.

## Offline commands

```sh
python3 -B -m unittest discover -s tests -p test_original_read_response.py -v
python3 -B -m unittest discover -s tests -v
cargo +1.90.0 test --locked --offline --manifest-path qualification/Cargo.toml
cargo +1.90.0 build --locked --offline --manifest-path qualification/Cargo.toml --examples
python3 -B scripts/qualify_original_read_response.py --original-response-verifier qualification/target/debug/examples/verify_original_read_response
go -C qualification-go test -mod=readonly -count=1 -v ./...
go -C qualification-bitcoin-go test -mod=readonly -count=1 -v ./...
python3 -B scripts/check_artifacts.py
```

The Rust command notation assumes the recorded rustup toolchain selection;
direct cached toolchains use the corresponding Cargo binary without that suffix.
