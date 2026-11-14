# One fresh opening walk within an ordered reference operation

This bounded M2/M3 maintenance item reduces repeated reference validation while
preserving the existing recovery/refusal conditions.

The ordered checkpoint validator previously constructed a typed opening and then
immediately exported it. Construction and export each walked the same complete
lineage. The validator now derives its public opening description directly from
one fresh complete history walk. The public opening wrapper uses the same
description function; its construction and each later export still validate
their actual retained inputs separately.

The existing operation-local map may reuse that derived value during the same
pure synchronous operation. No result is stored on a checkpoint, opening,
process or filesystem. Every new public operation starts a fresh validation
scope and checks all ancestors again, including their actual retained contexts.
Neither a digest nor a serialized descriptor reconstructs missing custody.

The [frozen previous method](../compatibility/fixtures/nom_order_opening_reference.py.txt)
is copied from `_Validation.opening` in the public
[`33a7d7f` source](https://github.com/edgepillar/ptlc-research/blob/33a7d7f74eea9bffa201a6941c34f763c8e4242d/offline_session/nom_checkpoint_read_ordering.py).
Its SHA-256 is
`7e0e4a6f884d07d3083038fb9b1522b839dce0689b836facc830bc7b266955db`.
It is original project code under the repository MIT license, not an independent
implementation or assessment.

Four additional controls compare 35 finite values or exact refusal classes and
messages, count every selected ancestor validation, check isolated return values,
and exercise mutation, refusal and restoration between operations. A retained
public wrapper must also revalidate after its ancestor changes. The finite
comparison prohibits file operations and subprocess entry. It is not a general
equivalence proof or an atomic snapshot guarantee against concurrent mutation or
hostile class replacement.

The six dependent qualification manifests retain their complete input key sets,
selected corpora, refusal requirements and operational boundaries. Only source
hash values and the hashes of affected preceding manifests change. Unexpected
source bytes still refuse qualification.

This item stops after its current-source full regression, artifact/privacy
checks, selected hosted PR gates and distinct original push/main acceptance.
Reducing complete-history calls does not establish a full-suite or production
speedup, a storage reduction, new upstream compatibility, chain currentness or
nonrollback protection. It supplies no journal shortcut, work permission,
signer, observer or operational recovery. Independent assessment and AS-1
through AS-7 remain UNFILLED; application/core remain NO-GO and recovery remains
NONE. No node activation, wallet access, application signing, broadcast or real
funds are connected.
