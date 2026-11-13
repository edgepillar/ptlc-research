# NoM ab8ee8d finite native comparison

This plan selects the exact tracked source at
`ab8ee8da3a50231b0910c536632e9b05fff42795`, tree
`9576b71caf1dcf0e6931e2c39af53522b63102c6`.
The [source record](NOM_DEV_AB8EE8D.md) describes the complete inventory and the
shared paths that changed. Declaring this selection establishes no Go result.
Native compatibility, hosted PR acceptance and own-main acceptance remain
**UNFILLED** until their distinct original evidence is accepted.

## Finite selection

The runner retains all 39 selected top-level tests from the preceding
`008bdcd` comparison. It adds 89 top-level tests and selects 128 in 19 packages.
All observed descendants must pass; skipped tests, missing parents, extra
parents, incomplete package framing and incomplete output are refused.

| Selection | Top-level tests |
|---|---:|
| Preserved ABI, independent PR #138 corpus, mailbox, decoding, store-failure, verifier and VM rollback controls | 39 |
| Chain acknowledgement recency, pool admission and suffix eviction | 14 |
| Node HTTP request and connection admission | 9 |
| Producer content selection under recency enforcement | 1 |
| Downloader queue, cancellation, progress and stall boundaries | 18 |
| RPC HTTP request lifetime, refusal, body drain and reply completion | 14 |
| Embedded refund recovery-height selection and logarithmic lookup bound | 2 |
| Embedded acknowledgement recency, refund, send-data and spork boundaries | 31 |
| Total | 128 |

The exact package/root map is in
[`qualification/nom_dev_ab8ee8d_native.py`](../qualification/nom_dev_ab8ee8d_native.py).
The refund table includes ordinary user sends, user burns, zero amounts and
non-refund methods as exclusions. This does not make an ordinary PTLC Unlock
eligible for the embedded-refund exception.

## One source and compiler workspace

One checked upstream ZIP supplies all 574 original files. The existing MIT
research test overlay adds one file, giving one physical source view of 575
files. The four synthetic corpus fixtures retain their exact project digests.
The source is compared before and after dependency acquisition and execution.
No upstream source is vendored into this repository.

The hosted Linux lane pins Go 1.23.12. It acquires only selected package
dependencies in a separate bootstrap module view, checks original checksum
entries, verifies modules and preserves the unchanged source module files.
The subsequent native command uses module-network settings OFF, normal default
vet, a finite anchored test filter, `-mod=readonly`, `-count=1`, package
parallelism two and bounded timeouts. Operating-system network isolation is not
claimed. HTTP tests use synthetic loopback fixtures rather than a chain node.

The four actual commands are Go version, selected dependency acquisition,
module verification and the single finite native comparison. Their actual
exit, cleanup and stream-completeness records accompany the result. A failure
or interrupted attempt remains a failure or incomplete result. There is no
automatic retry, historical test-result reuse or complete-upstream-suite claim.

The workflow uploads only the checked result and individually selected safe
original streams. A separate reader must bind the exact research head, source
digest, workflow, run, attempt, original ZIP digest, console archive and all
observed event values. A green PR run does not qualify the later main push.

## Remaining boundaries

The selected behavior and recovery journal stay at `77ba9c7`. This comparison
does not upgrade them or establish complete account admission, live-chain
observation, spork activation, canonicality, finality, operational signing,
wallet custody, broadcast or funds safety. The acknowledgement and refund
sporks remain separate conditions. Refusal grants no re-signing, rebasing,
replacement or journal-migration authority.

Independent protocol, cryptography and recovery assessment remains
**UNFILLED**. Application and core remain **NO-GO**.
