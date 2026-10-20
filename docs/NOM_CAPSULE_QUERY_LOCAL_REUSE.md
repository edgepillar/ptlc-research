# Call-local capsule validation reuse

The retained-query field comparison validates the complete capsule once per
call. It uses that call's decoded projection and partial hold to compare the
separately supplied read query. The capsule digest covers the exact bytes that
were validated. The earlier implementation decoded the same capsule four times
while producing one field dictionary.

This is local reuse within one pure operation. No result or decoded object is
cached on the capsule, binding, process or filesystem. Every later call validates
its selected bytes again, including after a refusal. Returned mutable charge
rows belong to the current result. Missing originals remain missing; a complete
binding remains HOLD with recovery action NONE.

The complete decoder and its journal replay, original-custody checks and refusal
rules remain unchanged. No file operation, journal append, worker call, source
observation or effectful qualification is replaced by a cached result. This
change does not qualify concurrent mutation, modified class methods or hostile
code in the process.

## Finite comparison and source selection

The [reference function](../compatibility/fixtures/nom_capsule_query_fields_reference.py.txt)
is copied exactly from `_fields` in the public
[`32c0d7c` source](https://github.com/edgepillar/ptlc-research/blob/32c0d7cbe9e27ab6d3844bc869bd1ee8323b46f3/offline_session/nom_capsule_query.py).
Its SHA-256 is
`957e4e03eaab4a7142be8d66df6e8f25f7a6386f54c9d742f58423edbbb4f60f`.
It is original project code under the repository MIT license, not application
cryptography or an independent implementation.

Four added methods check one complete decode per call, validation after changed
bytes and refusal, and isolation of returned charges. One of those methods
compares 28 finite values or exact refusal types/messages against the frozen
reference, with file operations prohibited during each comparison. These finite
controls are not a proof of general equivalence or protocol security.

The nine capsule-query and downstream selection manifests identify the current
source closure. Their selected files, schemas, corpora and boundary statements
are preserved; only content digests change to select the new implementation and
the resulting downstream manifest bytes. Historical commits, frozen review
subjects and retained execution evidence remain separate and unchanged. No old
execution is relabeled as a test of this change.

Complete current-source regression, artifact checks, own-head hosted PR checks
and later main-push acceptance remain separate requirements. A prior private
timing experiment is not a current complete-suite speedup measurement.
Independent assessment and AS1-AS7 remain UNFILLED; application/core remain
NO-GO. No deployment, activation, wallet, application signer, transaction
broadcast or real funds are connected.
