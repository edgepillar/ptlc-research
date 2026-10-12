# Explicit strict read-only reference open

The selected `ptlc-nom-strict-read-only-open-v1` profile opens an existing public
reference journal with a read-only descriptor and a cooperating POSIX owner
lock. It independently verifies a present retained long completion before
returning the owner. This is a separately selected research profile. The frozen
v1 writer, encoding-only legacy result replay, original actor and prior
qualification manifests remain unchanged.

`StrictNomRecovery.open` reuses the frozen journal parser, terms, adaptor-pair
and original-claim rules. Pair verification and actual retained original checks
remain explicit trusted verifier boundaries. A result-only record receives a
direct `verify_claim("long", retained_result)` call; no synthetic long envelope
is constructed. A complete journal checks both its actual original and its
separate retained result, even when their signature values coincide. Missing
results and originals remain absent, and the persisted recovery charge remains
unchanged. Replayed observation records remain historical evidence; strict open
does not reinvoke the observation verifier or establish current funding.

The selected owner refuses observation writes, original retention, attempt
preparation and recovery before entering a worker. It cannot create a missing
journal. Nonblocking file selection rejects a FIFO without waiting for a writer;
the preserved ownership rules require a private, singly linked regular file.
Refusal, unavailable verifier and interruption close its descriptors
without retry, work replenishment or recovery admission. This additional owner
cleanup does not modify the legacy opener. A final continuity check can detect
selected file growth; it does not prove protection against hostile concurrent
same-size rewriting, copied owners, coherent old prefixes or power loss.

## Actual qualification and independent limits

`python3 -B scripts/qualify_nom_strict_open.py` uses the unchanged explicitly
trusted actor to produce five disposable process-death journals with actual
`os._exit(72)` receipts. It selects the independently built public-only Rust
worker under the empty-environment execution profile. Before its first actor or
worker spawn, it retains every selected source, the exact public executable and
the exact Python actor executable. Each child request, complete observed reply,
stderr and exit remains original diagnostic custody. Qualification metadata
uses a separate encoder; no protocol value size limit is relaxed.

| Actor cut | Persisted charge | Strict open | Retained long original |
| --- | ---: | --- | --- |
| After remote short | 0 | Pair and remote short only | Absent |
| After admitted recovery | 1 | Pair and remote short only | Absent |
| After returned public reply | 1 | Pair and remote short only | Absent |
| After retained result | 1 | Also directly verify present result | Absent |
| After retained original | 1 | Verify actual original and present result | Present |

A returned diagnostic reply in the third case is not supplied to the journal.
The zero-charge case remains outside the separately admitted partial-custody
profile. All five exact original files survive strict read-only open unchanged.
One additional adversarial file is separately constructed by replacing the
result with a disclosed zero public signature and recomputing its self-hashes.
Legacy open accepts its encoding; selected strict open refuses it before owner
return through an actual public worker exit 2. The refusal and original streams
are retained, the cooperative owner is released and the copy stays unchanged.
No original journal is replaced by this construction.

This qualification observes 34 public-worker calls, including one expected
negative exit. Unit fixture workers have no arithmetic and cannot supply the
native mathematical proof. Read-only acceptance is not restore authority,
authenticated current-chain observation, an independent machine assessment or
a complete hold/query composition. Interior write/fsync faults, power loss,
hostile process containment and atomic durable-work admission remain unfilled.
Application and core remain **NO-GO**; recovery action remains **NONE**.

See [validation](NOM_STRICT_OPEN_VALIDATION.md). The research baseline is
`9a6c97054713e1075b3c159f405665d49850d2a0`. This profile adds no core-node,
cryptographic construction, wallet, signing, broadcast or real-funds behavior.
