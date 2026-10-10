# PR #138 corpus and NoM reference validation

This record covers the additive offline subject on the preserved research
baseline `515a591a6b340e1ebf8bee51c4cbba4af69a2f9e`. It does not fill an
independent assessment or change application/core **NO-GO**.

## Completed local qualification

| Check | Result | Boundary |
|---|---|---|
| Complete Python offline regression | 2,334 passed; no skips or ResourceWarning | Python 3.12.14, SQLite 3.53.1; independent OpenSSL required |
| Locked Rust qualification | 177 passed | Existing lockfile and candidate libraries unchanged |
| Separate native partial qualification | 14 passed | Selected Python 3.12; initial system-Python failure retained separately |
| Legacy Go verifier | 47 top-level tests passed | Old PR #13 message and dependency graph retained |
| Bitcoin Go verifier | 8 top-level tests passed | Existing transaction/script subject unchanged |
| Separate PR #138 Go verifier | 3 top-level tests and 26 witness subtests passed | Target verifier resolution, Go 1.23.12 |
| Public Rust examples and both formatting checks | Passed | Builds only; new worker runtime/independent review still unfilled |
| Actual public NoM worker with two journals | Passed | Synthetic original envelopes and synthetic observation allowlist |
| Exact clean PR #138 node differential | 48 messages, 26 witnesses, 15 destination policies and 2 bound NoM completions matched | Private offline overlay at `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`; no source edit, no activation |
| Separate Go module contents | `go mod verify` passed | Acquisition separate from offline execution |

The selected independent verifier was OpenSSL 3.6.5. Version strings identify the
tested local profile; they are not private environment logs or release claims.
The compatibility manifest pins fixture bytes, new module inputs and unchanged
legacy module inputs. Artifact checks inspect both index blobs and worktree
candidates; publication requires a fresh successful check after staging.

## Failed evidence retained

- The first new Rust compile failed on a `MaybePoint`/`Point` comparison before
  tests ran. The corrected compile and suite are separate successful records.
- The first actual-core overlay failed before tests ran because Go 1.23 vet
  could not open its synthetic path. Only this overlay run disables vet; normal
  Go corpus tests use the default vet behavior. Original output is retained.
- The initial legacy native suite under system Python 3.9 failed
  `native_owner_sigkill_after_public_delivery_replays_recorded_bytes`, returning
  `OutcomeUnknown`. The selected Python 3.12 full native run passed; the earlier
  failure's cause is **NOT ESTABLISHED** and it is not reclassified as passed.
- Initial native build outputs failed artifact hygiene as untracked candidates.
  Original outputs were moved to ignored private storage, the native target
  directory is now excluded, and the subsequent artifact check passed.

No original failed logs, native outputs or historical CI archives were erased.
This record includes no raw private output. Hosted PR checks, exact published
main verification and push-triggered main CI are separate subsequent gates.

## Historical PR cleanup

Before new publication, all 123 existing research PRs were inspected for exact
heads, file scope, discussions/reviews and incorporation in main. Seventeen were
already merged. All 106 remaining open heads were ancestors of the accepted main
baseline, with no external discussion or outstanding review request found.
Those redundant entries were closed with verified English closure records.
Original heads, branches, descriptions and commit history were preserved; each
description gained only its closure record. Closing them does not establish that
every historical check passed or that an independent review occurred.

See [fixed-recipient recovery](NOM_FIXED_RECOVERY.md) for remaining custody,
observation, actual transaction, restored-copy and independent-review gates.
