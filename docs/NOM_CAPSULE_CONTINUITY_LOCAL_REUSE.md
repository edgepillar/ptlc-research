# Call-local continuation validation reuse

Each continuation comparison completely decodes both selected capsule arguments
once. It retains that call's decoded projections, exact journal bytes and partial
holds. The capsule digests cover the exact bytes that passed complete validation.
The previous function decoded the pair eight times for an extension and ten
times for an equal-journal comparison.

This is reuse within one pure comparison. Every later comparison or public
review validates its selected bytes again. No result or decoded value is cached
on the capsule, continuation, process or filesystem. Even when both arguments
refer to the same object, each selected argument receives its own full decode.
The two selections are read in the original evaluation order; this does not
establish an atomic snapshot against concurrent mutation or hostile class edits.

Complete capsule decoding, exact raw-journal prefix comparison, retained public
originals, charged UNKNOWN work and every refusal rule remain selected. Equal
heads and counters cannot replace journal bytes. Coherently restoring both
inputs can still match. The result remains HOLD with recovery action NONE; it
provides no current source authority, restore fence or recovery admission.

No file operation, journal append, worker execution or effectful qualification
is replaced by a cached result. The public constructor still independently
validates the candidate's selected digest before comparison.

## Finite comparison and source selection

The [reference function](../compatibility/fixtures/nom_capsule_continuity_compare_reference.py.txt)
is copied exactly from `_compare` in the public
[`5f11a54` source](https://github.com/edgepillar/ptlc-research/blob/5f11a54260c00a5611ddbcabb247f187de0a7d85/offline_session/nom_capsule_continuity.py).
Its SHA-256 is
`b5e9b6def96ee2bde5e28137561ffe9caf4415aa2e7c2746b2c2761a28de80d7`.
It is original project code under the repository MIT license, not an independent
implementation or application cryptography.

Four added methods check complete validation on every call, both selected inputs
after success or refusal, and later public reviews after changed bytes or mutated
returned values. One method compares 54 finite values or exact refusal types and
messages with the frozen function while prohibiting file operations. These
finite cases are not a proof of general equivalence or protocol security.

The continuity and downstream selection manifests retain their files, schemas,
corpora and boundary statements. Only content digests change to select the new
implementation and resulting manifest bytes. Frozen review subjects, historical
commits and original execution evidence remain separate. Earlier executions are
not relabeled as tests of this source.

Complete current-source regression, artifact checks, hosted PR validation and
later main-push acceptance remain separate requirements. A decode-count reduction
is not a measured complete-suite speedup. Independent assessment and AS1-AS7
remain UNFILLED; application/core remain NO-GO. No deployment, activation, wallet,
application signer, transaction broadcast or real funds are connected.
