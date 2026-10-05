# Test-only signature binding of owned original snapshots

This delta targets `38ee5559a1006f0682e3db6370b9912bcc55bade` and joins two
already isolated experiments: the [owned local sampler](ORIGINAL_READ_SNAPSHOT_QUALIFICATION.md)
and the [historical public signature construction](ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md).
The application modules, signature worker, earlier fixtures, store and journals
are unchanged. Only synthetic test fixtures and qualification harnesses sign
sampled bytes; no application signer or source service is introduced.

## Requirements, selected construction and verified boundary

| Layer | Statement |
| --- | --- |
| Protocol requirement | Select the complete root, source/incarnation, original id/revision/historical profile/proposal, both policy and record heads, and challenge before consuming a peer reply. Signature validity must not become current truth, lookup authority, recovery or permission to use. |
| Selected construction | A Python test harness constructs actual bounded SQLite scenarios, selects the local diagnostic heads and complete query, then samples the existing unsigned claim. A separate Rust integration test signs the existing root and response messages with known synthetic values. Python and Go consume only public fixtures. |
| Verified implementation behavior | Recreated actual rows produce the exact signed response bytes and both retained-head commitments. The existing public worker verifies those bytes, with its unchanged four-field result containing only root and response signature flags. |
| Explicit premises | Root selection, local store ownership, honest SQLite/VFS behavior and selected executable/runtime trust. The diagnostic local heads are not an authenticated latest-head service. |
| Unresolved operational requirement | Authenticate source identity and both current heads; establish historical profile and original provenance, caller lookup authority, nonrollback retention, signer custody, administrative command deduplication and authorized incarnation changes; define recovery/use ordering and obtain independent assessment. |

The bridge is test-only. It does not sample and sign arbitrary runtime requests,
hold a signing key in an application process, export a signing function, install
a service, authorize a lookup or connect to recovery. The fixture-generation
test emits public signatures only. A valid public fixture is never a capability.

## Reproducible synthetic scenarios

The [Python helper](../tests/original_snapshot_vectors.py) prepares ten distinct
real stores. Before sampling, it selects the complete root, original, challenge
and both diagnostic local heads independently of any incoming envelope.

| Scenario | Actual retained state |
| --- | --- |
| `initial_absent` | No original or event; no admission is implied. |
| `pending` | Original charge at event 1, without effect. |
| `completed` | Charge at event 1 and synthetic effect at event 2. |
| `revoked_absent` | Retained old profile with an absent original after revocation. |
| `revoked_pending` | Old charge retained after revocation; effect stays refused. |
| `revoked_completed` | Old completed record retained after revocation. |
| `replaced_completed` | Old completed original survives changes to current owner, epoch, caps and four scope pins. The changed owner is another public synthetic curve key. |
| `reduced_pending_two_charges` | Two old charges remain when the current cap is reduced to one; no refund or new effect/admission occurs. |
| `unavailable_pending` | One old pending charge retained; all four response state fields are null. |
| `mode_round_trip_pending` | Policy digest repeats after unavailable/live; complete retained record history and its digest differ. |

The [unsigned inputs](../qualification/fixtures/original_read_snapshot_inputs.json)
include the complete synthetic retained material separately from each response.
The existing record digest commits to all policies, originals, effects and events,
including other originals. The response signs the selected digest, not a separately
authenticated row proof. Rust and Go reproduce both canonical commitment formulas.

The [Rust integration test](../qualification/tests/original_read_snapshot_response.rs)
reads those inputs and generates a separate [public fixture](../qualification/fixtures/original_read_snapshot_response.json).
It uses the existing root declaration digest, response tagged prehash, request
domain, envelope schema and exact two-flag result. No earlier fixture or worker
changes. Both signature arrays and selected statement fields remain bound.

Reproduction uses the recorded toolchain and locked dependencies:

```text
python3 -B -m unittest discover -s tests -p test_original_read_snapshot_response.py -v
cargo test --locked --offline --manifest-path qualification/Cargo.toml --test original_read_snapshot_response
go -C qualification-go test -mod=readonly -count=1 -v ./...
python3 -B scripts/qualify_original_read_snapshot_response.py --original-response-verifier qualification/target/debug/examples/verify_original_read_response
```

Set `PTLC_PUBLIC_SNAPSHOT_RESPONSE_VECTOR_OUTPUT=1` only for the Rust generator
test with `--nocapture` to emit its `PUBLIC_SNAPSHOT_RESPONSE_VECTORS:` public
JSON record. Python tests independently reproduce the unsigned input fixture;
the Rust reproduction test compares the entire regenerated public fixture.

## Validly signed counterclaims and temporal limits

Six deliberately self-selected counterclaims pass actual public signature math:

| Counterclaim | Why it is not an owned current lookup |
| --- | --- |
| False absence at the pending head | Actual original exists with a retained charge. |
| False completion at the two-charge head | Claimed effect event 2 is actually another original's charge. The grammar accepts the selected numeric order but has no authenticated row proof. |
| False active flag at the revoked head | Actual current policy is inactive. |
| Same id with another proposal | Actual source refuses the conflicting complete original. |
| Same id with another historical profile | Actual retained historical profile differs; the signed historical grammar alone does not establish its issuance. |
| Fresh challenge over initial absence | A challenge changes message/request binding. After a managed charge, the previously selected heads are stale and the sampler refuses. |

An independently reconstructed actual expectation refuses every counterclaim
before invoking the selected checker. Deliberately reconstructing an expectation
from the counterclaim itself still accepts its signatures. This contrast is the
qualification result: mathematical integrity protects a selected statement;
it does not choose or authenticate that statement's source of truth.

The [actual-worker harness](../scripts/qualify_original_read_snapshot_response.py)
also exposes:

- Two forged positive callback flags for zero signatures; actual public math refuses.
- Revocation after the read's commit but before delivery: the old complete signed
  statement still verifies, while a new read of the old heads and the pending
  effect refuse. A blind ideal external entry can still act on the old statement.
- Coherent restored and cloned pending stores reproducing exactly the signed
  checkpoint and repeating the synthetic effect. An external audit list observes
  three repetitions; it is not an implemented history service or use fence.
- Unavailable/revoked/reduced-cap reads and lost post-commit delivery retaining
  charges without allocation, retry, refund, authoritative recovery or effect.
- A changed executable checksum and a cached result for another complete request
  refusing. Checksum measurement still assumes a trusted launch/runtime boundary.

No real device, chain transaction, wallet, deployment or private signing is used.
The earlier native writer/death controls remain separate evidence for their exact
local ordering boundary. Joining the bytes does not expand that boundary.

## Source and reuse record

New harnesses, fixtures and documentation are original project MIT material,
reusing unchanged project code at `38ee5559a1006f0682e3db6370b9912bcc55bade`.
Existing framing and signature math remain pinned to the [Stage 47 source and
license record](ORIGINAL_READ_RESPONSE_SIGNATURE_QUALIFICATION.md#source-and-reuse-record),
including locked Rust Bitcoin/libsecp256k1 and btcec dependencies. No upstream
code, passage or vector is copied, and no dependency is added or upgraded.

The workflow adds one bounded test-only harness invocation to the existing
adaptor job. All jobs, toolchain/action pins, timeouts, earlier qualification
steps and fixed independent-review inventories/reports are retained.

## Acceptance decision

Exact actual-sample byte binding under the existing historical signature grammar
is **GO for isolated offline qualification**. Authenticated source integration,
application/private signing, recovery integration, core port, activation,
deployment, wallet access, broadcasts, physical entry and funded execution
remain **NO-GO**. Both independent assessment reports remain unfilled. See
[execution evidence](STAGE49_VALIDATION.md) for tested and skipped boundaries.
