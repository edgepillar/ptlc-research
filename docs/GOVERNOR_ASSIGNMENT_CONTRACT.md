# Unsigned governor assignment and complete-profile-bound intent

Status: **Stage 37 pure bounded framing experiment. The assignment and v2 owner
intent are unsigned. Independent issuer/profile selection is an external trust
decision. No issued credential, signature verification, current-authority source,
registry, worker admission or application integration is implemented.**

[Stage 36's finite comparison](GOVERNOR_AUTHORITY_MODEL.md) treats complete
assignment and intent binding as ideal premises. This experiment selects exact
candidate bytes for one of those obligations. It does not implement the model's
trusted root or indivisible current-state oracle. Authenticated provisioning
could use another construction; this framing is not a universal protocol rule.

## Requirement and selected construction

The old [local governor profile](LOCAL_GOVERNOR_PROFILE.md) has 14 fields. Its
opaque authority profile pin is not the digest of that complete profile. Broader
local caps can therefore match the same eight-field v1 intent and valid v1
signature. A future owner decision that must commit the complete assigned policy
needs an explicit additional binding.

This candidate wraps the complete profile and an independently selected issuer
key in an unsigned assignment. A separate nine-field v2 owner intent commits
the resulting assignment digest as well as all existing owner/resource/scope/
request bindings. Broader caps and another issuer now change the candidate
message. This is byte-content binding subject to existing SHA256 assumptions,
not a signature, authorization or collision-resistance proof.

The [pure implementation](../offline_session/governor_contract.py) imports only
`dataclasses` and the existing pure enrollment/profile helpers. All old codecs,
messages, signature fixture, verifiers, models, journals, dependencies and
workflow remain unchanged. No existing entry point requires these new objects.

## Unsigned assignment

The assignment has exactly five top-level fields:

| Field | Candidate binding |
| --- | --- |
| `schema` | `ptlc-observation-governor-assignment-v1` |
| `purpose` | `observation-governor-assignment` |
| `algorithm` | `BIP340-SHA256`, a framing descriptor |
| `issuer_auth_key_hex` | Independently selected 32-byte public-key encoding |
| `governor_profile` | Complete canonical 14-field local profile object |

The nested profile includes its owner, resource, namespace/epoch, four opaque
profile pins, role/purpose/algorithm and two proposal caps. It is not an incoming
profile used to discover an expected issuer or owner. `governor_assignment`
requires an exact independently selected `GovernorProfile` and explicit issuer.
Issuer and owner are separate role bindings; distinct keys are not required by
this codec, and equal or different encodings establish neither role.

```text
assignment digest = SHA256("PTLC/observation-governor-assignment/v1" || NUL || canonical assignment)
```

This digest is both the candidate issuer message and the assignment content
commitment referenced by v2. It contains no signature. Neither this digest nor
the old governor profile digest is silently placed into the profile's opaque
`authority_profile_digest_hex` field; no self-referential hash is introduced.

## New unsigned owner intent

`bound_enrollment_intent` requires an exact selected assignment and an exact
independently prepared [v1 unsigned intent](RETAINED_RESOURCE_INTENT.md). It
revalidates both, checks the complete local profile's owner/resource, all six
scope pins and both requested caps, then explicitly prepares different bytes.
It does not reread a chain or source snapshot.

The new object has exactly nine fields: the old `purpose`, `role`, `algorithm`,
`resource_digest_hex`, `scope_digest_hex`, `owner_auth_key_hex` and `request_id_hex`,
plus `schema: ptlc-observation-enrollment-intent-v2` and
`governor_assignment_digest_hex`. The old intent object and bytes are unchanged.

```text
v2 owner message = SHA256("PTLC/observation-enrollment-owner-intent/v2" || NUL || canonical v2 intent)
```

Binding the assignment digest commits its independently selected issuer and
every embedded profile field. The requested scope digest remains separate from
the profile's maximum caps. Changing caps from two to three under the same owner
and opaque pin keeps the old requested scope and v1 message, but changes the
assignment digest and v2 message. Tests retain that positive control.

This experiment neither migrates signatures nor adds a v2 signature envelope,
request, result or verifier. Existing Python/Rust/Go v1 interfaces continue to
use their existing schemas; a v1 signature must not be reinterpreted as a v2
signature. Root/owner signature construction and actual independent verifiers
must be qualified against these exact new messages in a later delta.

## Canonical selection and refusal

Each wire is bounded to 4,096 bytes. Encoding is sorted compact ASCII JSON with
exact field sets and no terminal newline. Duplicate keys, escaped aliases,
whitespace variants, numeric aliases, non-ASCII, oversized/deep inputs and extra
signature/authority claims refuse. Profile numeric bounds remain those of the
unchanged profile codec. Public-key formatting is not curve membership.

Both classes are frozen, factory-only objects whose selected references and
bytes are revalidated on use. Returned nested dictionaries are defensive copies.
Parsing requires an independently prepared complete expectation and returns
that same unsigned object; peers cannot replace its issuer, profile or request.
Exact-type checks refuse hostile subclasses without invoking foreign hooks.
This is no hostile-interpreter sandbox or current-state storage protection.

Matching bytes replay repeatedly. A retained old assignment and intent still
parse relative to the old expectation after a newer epoch/profile is selected
elsewhere. No latest head, authenticated epoch, revocation, clock, monotonic store
or use-time transaction follows. Choosing matching peer-derived expectations
remains an untrusted provisioning decision. The separate finite model retains
its stale-check and coherent-restore counterexamples.

The [public fixture](../qualification/fixtures/governor_contract.json) contains
only unsigned synthetic public encodings and message/content digests. It is a
Python byte-framing vector, not cross-language signature evidence. The
[30 affected methods](../tests/test_governor_contract.py) cover complete bindings,
legacy separation, arbitrary format-valid keys, stale expectations, malformed
inputs and a real exhausted journal reopen. Repeated construction/parsing changes
none of that journal's bytes, charged allowance or recovery callback behavior.
See [validation](STAGE37_VALIDATION.md), including the corrected first test run.

The internal MIT profile/intent helpers and public fixture sequencing are reused
from the [immutable parent](https://github.com/edgepillar/ptlc-research/tree/a61a9947970a3b4843580ae1bb67a9df4d0705ce).
No external implementation, arithmetic or dependency is copied. The fixed
119-file/189-file subjects, public signature fixture and both unfilled reports
remain unchanged. This later construction needs separate independent review.

## Next gates

Assess these exact domains and the assignment-to-owner binding. Specify issuer
provisioning, role/scope authority, compromise and rotation/revocation policy.
Qualify actual root and owner signature checks without trusting peer Booleans
or verifier-shaped results. Select the independent current-authority source,
stale/outage behavior and its atomic relationship to actual use. Then address
source/economic equivalence, first-registration ownership, non-rollbackable
charged lineage, exact scoped idempotency and trusted unique dispatch.

**GO:** further offline assessment and public-signature qualification of these
candidate messages. **NO-GO:** treat matching unsigned objects as issued/current
authority, reuse v1 signatures for v2, connect a registry/dispatcher or private
signer, port current-node core rules, deploy or use real funds.
