# Candidate retained-resource key and unsigned enrollment intent

Status: **Stage 32 pure bounded encoding experiment. No source equivalence
authority, owner verifier, enrollment registry or runtime integration exists.**
The selected class is equality of an exact public commitment tuple. It is not
economic resource identity, authenticated chain evidence or enrollment permission.

Source parent: [`2d41e7e1d130bf2ff1e9b2ca95430a5719074f74`](https://github.com/edgepillar/ptlc-research/tree/2d41e7e1d130bf2ff1e9b2ca95430a5719074f74).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37219021046)
qualifies the previous [finite enrollment comparison](OBSERVATION_ENROLLMENT_MODEL.md),
not this new encoding. That comparison takes canonical classes and independent
owner facts as inputs. This experiment specifies one narrower candidate content
class and unsigned owner-binding bytes without implementing those facts.

## Requirement, selected unit and implemented behavior

| Requirement | Candidate choice | Current evidence and missing mechanism |
| --- | --- | --- |
| Caller labels/profiles cannot give the same retained source another content key | Derive a key from seven retained public commitments only | All nine external scope selections keep this key; no registry count or duplicate enrollment is owned |
| A resource choice must remain bound to the selected paired source | Match every commitment to an independently prepared scope and rederive that scope from the supplied current snapshot when preparing intent | Changed fixture sources reject the old choice; snapshot provenance and actual latest-source evidence remain external |
| An owner decision must address the full requested configuration | Bind exact scope/resource digests, independent public-key selection, request ID, role, purpose and algorithm in unsigned bytes | Every selection changes intent; no curve check, signature, role assignment or authorization is performed |
| A peer must not replace the expected owner or resource | Parsing requires an independently prepared immutable local expectation | Changed owner/source bytes refuse; anyone can synthesize matching unsigned bytes and replay them |
| Changed source must not silently obtain fresh economic allowance | Leave source/economic equivalence, namespace and first-registration policy explicit | Changed terms/contexts create another candidate content key; no permission, reset or allocation follows |

The [implementation](../offline_session/enrollment_contract.py) imports only
standard pure helpers and the existing pure [authority codec](OBSERVATION_AUTHORITY_CONTRACT.md).
It adds no callback, signer, verifier, clock, entropy, file, process or transport
interface. Existing codecs, journal/store entry points, mathematical predicates,
formats, models, qualifiers, workflows and dependencies are unchanged. New tests
exercise a real temporary exhausted journal only to establish that these pure
operations change none of its bytes or allowance and enter no recovery callback.

## Selected resource equality

`retained_resource` takes an exact locally prepared `AuthorityScope`. It produces
canonical JSON with fixed `schema: ptlc-observation-retained-resource-v1`,
`predicate: zenon-completion-v1`, `resource_kind: exact-paired-release-v1` and:

| Public binding | Source in the existing scope |
| --- | --- |
| `session_id` | Coupled retained session identifier |
| `terms_digest_hex` | Agreed terms commitment |
| `bitcoin_context_digest_hex`, `zenon_context_digest_hex` | Complete retained signing contexts, including public nonce-round bindings |
| `bitcoin_bundle_digest_hex`, `zenon_bundle_digest_hex` | Complete public bundle commitments under the existing authority domains |
| `release_digest_hex` | Exact retained release commitment under the existing authority domain |

The experiment's equality class is **equality of these seven encoded fields**.
Treating their equality as equality of the complete underlying public source
additionally relies on the existing hash commitments; encoding tests prove no
collision-resistance theorem. This is a selected conservative content class,
not an adopted global protocol requirement or semantic/funding classifier.

Authority/enrollment IDs, epoch, all four selected profiles, attempt/target limits,
candidate signatures, request IDs, owner pins and local paths are excluded from
the resource key. Changing any of the nine scope selections keeps this key while
changing the full scope and intent. Different candidate bytes under the same
retained release also keep it. No candidate or path can be passed to the factory.

Changing the session, terms, nonce round or retained bundles changes the tested
commitment tuple. Selecting that new tuple is representable. It supplies no
evidence that the economic resource, funded recovery right or public-source
authority changed. A future governor must classify those variations and reject
unauthorized first-registration capture, reset and duplicate economic allowance.
Two swap legs are one selected paired tuple; they are not two independent quotas.

The content key also excludes the authority namespace. Two independently operated
registries may still give the same key separate allowances. A common digest
proves no shared registry, unique governor or host/ecosystem budget. Source
selection, namespace identity and cross-authority duplicate handling remain gates.

## Canonical bytes and domains

Both resource and intent are bounded to 4,096 bytes. All digests, request labels
and public-key encodings are exactly 64 lowercase hex characters. JSON uses exact
field sets, sorted keys, compact ASCII encoding and no terminal newline.
Duplicate keys, escaped aliases, whitespace alternatives, non-ASCII, deep values,
numeric aliases and extra authority/signature fields reject with constant errors.
Factories and parsers require exact local object types; this is no hostile-host
sandbox or protection against an interpreter rewriting its own objects.

| Digest | SHA256 input |
| --- | --- |
| Resource key | `PTLC/observation-retained-resource/v1` + NUL + canonical resource bytes |
| Candidate owner message | `PTLC/observation-enrollment-owner-intent/v1` + NUL + canonical intent bytes |

The scope digest and seven source commitments reuse the unchanged earlier
authority domains. The two new domains are local experimental framing, not a
Bitcoin/Zenon standard, receipt, nonce owner or signature construction assessment.

## Unsigned owner intent

`enrollment_intent` requires the supplied retained `RELEASE_RECORDED` snapshot,
exact locally prepared scope, expected resource, independently supplied
`owner_auth_key_hex` and externally selected `request_id_hex`. It first checks
the scope/resource commitment match, then reconstructs the selected scope from
the snapshot without invoking any verifier. Broken/finished snapshots and changed
source refuse; observation candidate changes leave the selected source intact.
Reconstruction establishes supplied-view consistency, not authenticated freshness.

Intent has exactly eight fields:

| Field | Candidate binding |
| --- | --- |
| `schema` | `ptlc-observation-enrollment-intent-v1` |
| `purpose` | `observation-enrollment` |
| `role` | `enrollment-governor` |
| `algorithm` | `BIP340-SHA256`, a framing descriptor only |
| `resource_digest_hex`, `scope_digest_hex` | Expected content class and full requested scope |
| `owner_auth_key_hex` | Independent local public-key selection |
| `request_id_hex` | External public request label, not a capability or signing nonce |

The [pinned BIP340 specification](https://github.com/bitcoin/bips/blob/927b6de9915c9262615a6399de51b200f81e5aa4/bip-0340.mediawiki)
defines the underlying 32-byte public-key encoding. Its specification license is
BSD-2-Clause; no external source or reference arithmetic is copied here. The
candidate intent exposes a 32-byte SHA256 message as lowercase hex. It implements
no BIP340 signing or verification, no curve membership check and no secret input.
The all-zero key encoding deliberately passes formatting; acceptance is no
curve-validity or key-control assertion. Independent key generation, provisioning,
role assignment, compromise, delegation and revocation remain unselected.

The governor is not inferred from a completion sender, an opaque participant ID,
a scope hash or the existing optional journal pins. The earlier
[completion envelope](COMPLETION_AUTHENTICATION.md) and
[durable local pins](DURABLE_AUTHENTICATION_PINS.md) provide no enrollment-owner
role. Their signed purpose and payload framing are separate. A future protocol
must establish the governor independently and preserve an independently authorized
public-witness recovery policy; an authenticated inbox is no universal recovery rule.

## Replay and non-authority

`parse_retained_resource` and `parse_enrollment_intent` require independent local
expectations. They never obtain the expected owner/key/scope by adopting incoming
fields. Matching unsigned bytes parse repeatedly and return the same immutable
public object. Anyone can construct those bytes; no signature field exists.
There is no `authorized`, `owner_verified`, `enrolled`, `permit` or `can_start` value.

The full scope digest binds all requested labels, epoch, profiles and limits.
Changing any selection keeps the same content key but changes the intent.
Reusing a request ID with another owner or scope is representable and changes the
message digest; no idempotency table, order, latest head, rotation or single-use
rule is implemented. Parsing a retained old intent after the actual source changed
still succeeds relative to that old expectation. It is not a freshness check.

A coherent restore can retain the same content key while erasing consumed history.
Stable resource bytes therefore do not prevent quota refill. The unchanged
[restore experiments](RESOURCE_STORE_RESTORES.md) and
[enrollment model](OBSERVATION_ENROLLMENT_MODEL.md) retain their counterexamples.
No registry, charged lineage, target owner or unique dispatcher exists here.

## Next gates

1. Assess whether this exact commitment class is an appropriate protected unit.
   Define changed-context/funding/source equivalence, authenticated source evidence,
   governor/namespace identity and first-registration capture before allocation.
2. Define independently established owner pins and role/compromise/rotation policy.
   Assess this framing, then qualify an actual public signature verifier against
   exact expected inputs. Signature validity must remain separate from authorization.
3. Select atomic uniqueness, exact duplicate lookup and authorized reset rules
   backed by non-rollbackable enrollment and charged lineage. Qualify concurrent
   copies, storage/power failures, coherent restore and uncertain replies.
4. Specify scoped idempotency, target retention and trusted single-use dispatch.
   Preserve source-journal authority, physical/resource limits and funded recovery.
5. Independently assess this exact delta, then every later verifier/backend and
   integration. Fixed [119-file](INDEPENDENT_REVIEW.md) and
   [189-file](OBSERVATION_REVIEW.md) subjects and unfilled reports are unchanged.

**Go:** assess this selected content class and unsigned owner framing in offline
research. **No-go:** use hashes/parsed intents as owner authentication, claim
implemented canonical economic equivalence, restore/clone defense or shared quota,
connect private signing, select production activation, port core rules or use funds.
See [Stage 32 validation](STAGE32_VALIDATION.md) for executed evidence and limits.
