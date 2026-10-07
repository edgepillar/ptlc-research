# Measured public verifier execution boundaries

Status: offline negative qualification only. Application and core progression
remain **NO-GO**. Two actual execution controls are selected; an atomic launch or
complete runtime authentication construction is **NOT SELECTED**.

## Requirement and selected controls

The optional [measured adapter](MEASURED_EXCHANGE_VERIFIER.md) compares a selected
entry file with a caller-provisioned SHA256 before using the existing public
runner. A successful file comparison proves the bytes read at that comparison.
It supplies neither continuity to the later launch nor a measurement of every
program or dependency that entry may execute. The caller's provisioned pin also
requires its own trust premise; a hash learned from a received program does not
authenticate that program's source.

Two additional methods in the existing [actual exchange qualifier](../scripts/qualify_exchange.py)
exercise these boundaries with the existing native verifier and existing synthetic
receipt actor. Each retains one measured adapter and the same expected pin.
Each uses the original complete public Bitcoin bundle, Zenon Alice partial and
Zenon bundle requests, plus the three previously selected public scalar mutations.
The unchanged independently selected native verifier refuses those mutations.
Both controls restore native behavior and leave the complete requests and
original build output unchanged. No new actor, receipt grammar, journal action,
release, private signer input or nonce consumption is added.

## Deterministic measurement-to-launch cut

The first control initially copies the selected native verifier and provisions
its actual digest. Three original public requests pass, and the three mutations
refuse. For each invalid request, a test-only hook invokes the unchanged bounded
file reader on that native entry and retains its actual original digest. After
that read completes, the hook moves the native file aside and substitutes the
existing synthetic receipt program at the same path. It returns the digest
actually read. The adapter's unchanged real runner then launches the substitute
and accepts its canonical positive receipt. Independent native verification of
the same complete request refuses. Each native file is restored before the next
selected cut; the final native positives and refusals are repeated.

The file reader and subprocess execution are real. Only the deterministic cut
between them is inserted by a hook. No digest or transport result is fabricated
by that hook. This is a controlled schedule showing the missing continuity
premise; it is not an observed spontaneous race, an attacker success-rate
measurement, hostile-host containment or qualification of any atomic launch API.

## Unchanged entry with a replaced dependency

The second control provisions the actual SHA256 of a private generated shell
entry that executes a separately selected target. The target initially contains
the native verifier: three original requests pass and three mutations refuse.
Only the target is then replaced by the existing synthetic receipt program.
The entry path, bytes and pin remain unchanged. Every adapter call faithfully
remeasures that entry, but all three invalid requests receive accepted canonical
positives from the substituted target. The unchanged independent native verifier
refuses each request. Restoring the target restores the original native behavior.

This control changes no entry file between measurement and launch. Its successful
entry comparison therefore supplies no authentication of the launched target,
shell interpreter, Python interpreter, environment or other dependencies. It
qualifies only the selected shell-entry schedule on the tested runtime; it is
not a complete inventory or a containment guarantee for an arbitrary runtime.

## Evidence accounting and remaining requirements

The two new methods add six accepted synthetic positives with six independent
native equation refusals. Together they also perform six original native
acceptances and six native refusals before substitution, repeated after
restoration. Fourteen explicit test-only public file digest acquisitions are
separate from 32 successful adapter entry measurements, including the three
actual bounded reads delegated through the deterministic cut. These are also
separate from the unchanged worker-profile artifact observation acquisitions.
No private consumed-input measurement or new artifact release is selected.

Any later execution construction must state its exact platform, executable
kind, measurement-to-launch relationship, interpreter and dependency scope,
environment premise, pin provisioning, update policy and failure behavior before
claiming a complete application verifier policy. No API or construction is chosen
here. The existing legacy adapter, optional measured adapter, public runner,
completion consumers and guarded profiles remain byte exact. Historical receipt
reload still checks structure and recomputed request hashes without rerunning
equations or authenticating historical execution.

Both nonce models, four fixed inventories and three unfilled reports retain exact
bytes. Source-to-worker and reproducibility remain **NOT VERIFIED**; producer
origin and actual private consumed inputs remain **NOT AUTHENTICATED**;
independent privacy remains **NOT ASSESSED**. Secure entropy, secure memory,
nonrollback effect coupling, physical failure, adapted-infinity application policy
and independent review remain unresolved. No upstream content is copied. See
the [validation record](STAGE83_VALIDATION.md) for selected checks and limits.
