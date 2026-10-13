# Exact retained NoM capsule journal continuation

This separate offline comparison implements a local retention requirement over
the unchanged full projection capsules. It selects no authenticated current
source, consumer nonrollback checkpoint, recovery admission or operational
observer. Application and core remain **NO-GO**; recovery action is **NONE**.

## Requirement and selected construction

After retaining a full journal, a consumer must not treat an older, conflicting
or different-resource history as its continuation. A larger sequence, matching
head, new challenge or valid signature encoding cannot erase retained bytes,
originals, possible disclosure or charged unknown work. The exact prior selection
must be independent of the incoming candidate.

`compare_continuation(retained, candidate_wire, expected_candidate_digest_hex=...)`
requires the exact immutable prior `CapsuleView` and parses the bounded incoming
capsule under its explicitly selected digest. It compares complete terms, pair,
verification context and original remote short bytes. The complete candidate
journal must start with the exact retained raw journal, including line endings.
Both journals undergo the frozen structural replay separately. Candidate work
must preserve every retained charged ordinal; any previously present result or
long original must remain exact. No signature mathematics is performed.

The immutable result distinguishes:

| Relation | Selected meaning |
| --- | --- |
| `EXACT_REPLAY` | Both complete capsules match. No new knowledge or use follows. |
| `SAME_JOURNAL` | Exact journal bytes match while the independently selected challenge differs. Work and original custody are unchanged. |
| `STRICT_EXTENSION` | The complete raw candidate journal extends the exact retained prefix. Added public custody is not current source or work authority. |
| Refusal | Regression, divergence, another original resource, malformed bytes or a digest mismatch. Preserve both original inputs for review. |

The review binds both capsule hashes, journal hashes, heads, sequences, context
and charge counts. Its domain-separated digest is a research comparison id, not
an account hash, external checkpoint or transferable capability. Returned copies
cannot mutate either input. This module opens no path, reads no clock or network,
starts no worker, writes no retained selection and constructs no original.
The caller must preserve both complete originals; this module provides no store.

## Concrete controls and remaining restore requirement

The four admitted actual-cut journals supply sixteen ordered comparisons.
The admitted cut and returned-but-not-appended public result have identical
journals: neither comparison invents retained output. Result and original
retention produce strict extensions; reversing those deliveries refuses.

Additional controls retain equal event heads and sequences while changing raw
line endings, rehash a larger conflicting branch with the same work identifiers,
and select a second charged UNKNOWN ordinal. Exact continuation refuses the
first two; a genuine selected prefix extension keeps both charges. The second
charge is a separate structural control, not another observed worker execution.

Retaining the later selection detects an earlier copy. Coherently restoring the
prior selection and candidate together still matches the older pair, including
with a new challenge. Cold bootstrap has the same limit. This successful unsafe
control is required evidence of the **UNFILLED external restore fence**.
Detection while a later copy survives is not nonrollback protection or source
deduplication. No result selects the latest or canonical chain, reanchors an
incarnation, replenishes work, retries unknown execution or repairs history.

The new manifest preserves all 169 previous measured inputs and adds five
separate measurements. Original MIT framing is reused under the repository
license; no dependency, upstream source or cryptographic construction is copied.
The source baseline is
`a0b6aa44e8fa8775c00b1538533fc18cf4439987`.

Next, select and independently assess authenticated source provisioning and a
consumer checkpoint outside coherent copied state, including availability,
rotation, conflicting successors and the exact use boundary. That mechanism
must retain originals, disclosure and every unknown charge without resetting
work. Actual signed-account custody, native refusal/query pairing, atomic work
authority, independent construction/runtime review and physical power-loss
survival remain separate gates. See [validation](NOM_CAPSULE_CONTINUITY_VALIDATION.md).
