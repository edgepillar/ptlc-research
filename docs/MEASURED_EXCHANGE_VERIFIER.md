# Explicit measured exchange verifier selection

Status: opt-in offline reference adapter. Application and core progression
remain **NO-GO**. Entry-file comparison is selected; source authentication,
complete runtime identity and atomic measurement-to-launch are not selected.

## Requirement and selected construction

The [path continuity control](EXCHANGE_PROGRAM_SELECTION.md) showed that retaining
one adapter and executable path does not retain the program executed by later
calls. A caller must explicitly choose any expected program measurement rather
than treating a received program's own hash as an authenticated expectation.

[MeasuredSubprocessVerifier](../offline_session/measured_artifact_verifier.py)
is a separate optional subclass of the unchanged legacy
[SubprocessVerifier](../offline_session/artifact_verifier.py). Its constructor
requires `expected_executable_sha256_hex` as an exact lower-case 64-character
string. The expectation is never discovered, refreshed or replaced by a result,
receipt or measured mismatch. The constructor checks the existing absolute file,
execute permission and deadline requirements, then compares the bounded existing
[file measurement](../offline_session/observation_verifier.py) with that expectation.
Every call repeats the same bounded entry-file comparison before delegating to
the existing public runner and canonical receipt contract. A mismatch or failed
measurement raises a sanitized verification error before the runner is called.
Direct cancellation propagates. No new result fields or receipt digest are added.

The caller still chooses what bytes are trusted and how to provision the expected
digest. This workspace provides no authenticated distribution, build attestation,
policy registry or automatic update mechanism. There is no application migration:
all existing imports, exchange consumers, completion consumers and guarded
observation profiles retain their previous implementation and selection premise.

## Verified behavior and counterclaims

The [ordinary tests](../tests/test_measured_artifact_verifier.py) cover explicit
expectations, configuration refusal, repeated measurement, changed and missing
entries, nonregular and bounded file refusal, canonical receipts, sanitized
failures and cancellation. Changed-entry refusal does not advance the original
pure exchange state. Equal-byte replacements and restored expected bytes pass:
the contract compares file bytes, not inode continuity, freshness or producer
origin. These ordinary controls use synthetic files and mocked transport results;
they perform no public curve verification.

One additional [actual exchange control](../scripts/qualify_exchange.py) provisions
the expected digest from the explicitly selected original local native verifier,
copies that file into private temporary storage and retains one measured adapter.
Three original complete public requests pass native equations; three previously
selected scalar mutations refuse. Missing-entry and same-path synthetic
replacement attempts refuse before the runner. Restoring the retained original
file restores the original native acceptances and refusals. A wrong explicit
expectation also refuses construction without a launch.

The control then deliberately provisions a matching expected hash for the existing
synthetic receipt actor. That measured actor accepts all three mathematically
invalid requests while the independently selected unchanged native verifier
refuses them. A matching pin therefore measures caller selection only: it cannot
authenticate the selected program's equations or a canonical receipt's claim.
All complete requests and the original build output remain unchanged. Four
explicit test-only public file digest acquisitions are separate from the new
adapter's repeated entry measurements and the unchanged worker-profile artifact
observation acquisitions. No journal transition, release, signer bridge or private
input is added by the new actual control.

## Remaining selection and execution requirements

The existing measurement is a bounded nonblocking regular-file read. It does not
pin a descriptor for execution or compare a complete runtime closure. The named
file may change after measurement; symlinks and equal-byte copies supply no
source identity. Interpreter, libraries, environment, host behavior and the
selected program remain trusted. The new tests replace files between completed
calls and do not qualify a launch race or hostile-host containment.

Legacy durable exchange reload still checks structure and recomputed public
request hashes without re-executing equations or authenticating historical
callback execution. The new adapter neither migrates stored receipts nor adds
nonrollback selection history. Its pin is not a chain proof, freshness witness,
nonce custody boundary, authentication credential or permission to sign.

Both nonce models, four fixed inventories and three unfilled assessment reports
remain exact. Source-to-worker and reproducibility remain **NOT VERIFIED**;
actual private consumed inputs and producer origin remain **NOT AUTHENTICATED**;
independent privacy remains **NOT ASSESSED**. Secure entropy, secure memory,
nonrollback effect coupling, physical failure, adapted-infinity application policy
and independent review remain open. No upstream content is copied. See the
[validation record](STAGE82_VALIDATION.md) for the selected evidence and limits.
