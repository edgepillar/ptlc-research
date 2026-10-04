# Explicit local governor-role profiles

Status: **Stage 35 pure local proposal-rule matching. Profile selection is an
external trust decision; no governor certificate, role assignment, enrollment,
allowance or enforced admission is implemented.** All qualification uses public
synthetic inputs.

## Requirements and selected construction

A future enrollment mechanism must independently establish who can govern a
resource in a namespace, which current policy applies, and how that authority
survives compromise, rotation, revocation and coherent restore. A signature under
a key chosen by its sender cannot establish those facts. Neither the
[enrollment model](OBSERVATION_ENROLLMENT_MODEL.md) nor cross-verifier agreement
implements them.

This stage selects a smaller inspectable construction: an explicitly prepared
local profile matches a locally prepared [unsigned intent](RETAINED_RESOURCE_INTENT.md)
before optional [public signature verification](PUBLIC_ENROLLMENT_SIGNATURES.md).
It refuses changed local rules without treating agreement as evidence of their
provenance. Existing entry points do not require this helper. The profile is
optional qualification code, with no service, storage owner or worker capability.

## Exact local profile

The schema is `ptlc-observation-governor-profile-v1`. Its only 14 fields are:

| Fields | Required meaning or representation |
| --- | --- |
| `schema`, `purpose`, `role`, `algorithm` | Exact schema, `observation-enrollment`, `enrollment-governor`, `BIP340-SHA256` |
| `owner_auth_key_hex` | Independently selected 32-byte public-key encoding |
| `resource_digest_hex` | Digest of the exact independently retained resource |
| `authority_id_hex`, `authority_epoch` | Independently selected namespace and positive epoch label |
| `authority_profile_digest_hex`, `verifier_profile_digest_hex`, `pool_profile_digest_hex`, `resource_profile_digest_hex` | Four independently selected opaque profile pins |
| `max_attempt_limit`, `max_target_limit` | Separate local upper bounds on the requested scope limits |

All seven hex fields require exact lowercase 64-character strings. The epoch
requires an exact integer from 1 through `2^53 - 1`; each cap requires an exact
integer from 1 through 64. Boolean and floating-point values refuse. These are
format and proposal bounds, not curve checks, live epochs or allocated budgets.

Wire bytes use exact sorted compact ASCII JSON, with a 4096-byte bound. Missing,
extra, duplicate, escaped-alias, whitespace, non-ASCII, wrong-type and deeply
nested forms refuse. The frozen object holds independently selected canonical
bytes and returns fresh dictionaries. Factories and parsers revalidate exact
types; incoming data cannot substitute a profile object or choose the root.

```text
profile digest = SHA256("PTLC/observation-governor-profile/v1" || NUL || canonical profile)
```

This digest identifies these local bytes. It is separate from the retained
resource, authority scope and owner-intent message domains. It is not a signed
role certificate or a registry head.

## Selection, parsing and matching

`governor_profile` requires an exact retained resource and every local key,
namespace, epoch, profile pin and cap as explicit arguments. Select these from
an independently trusted source before receiving peer proposals. The factory
checks encoding and resource consistency; it cannot determine whether the
caller actually made a trustworthy selection. No peer-bootstrap API exists.

`parse_governor_profile(expected, wire)` accepts only the exact selected bytes
and returns the same expected object. A matching repeated wire remains valid.
It does not import a new key, refresh policy, prove freshness or persist history.

`match_governor_profile(profile, intent)` revalidates both objects, then matches
the purpose, role, algorithm, owner key, resource and all six scope pins. Each
requested scope limit must fit its separate cap. It returns the same unsigned
`EnrollmentIntent`. No callback, signature math, process, I/O, journal change,
permission flag or allocation occurs.

Enrollment and request IDs are deliberately absent from the role profile. They
remain signed scope/intent bindings under the unchanged construction. Changing
them changes the old signed message, but profile agreement is not a duplicate
rule and permits no extra registration or allowance. Actual signature checks
also return the same unsigned intent; no combination produces a permit.

## Positive controls that remain unsafe as authority

1. A valid alternate-owner signature refuses the original local role profile
   before selected signature work. If the caller instead independently selects
   that alternate key as a new profile, agreement and valid math both succeed.
   This demonstrates the missing bootstrap decision, not trusted role assignment.
2. The local profile digest is **not committed by the unchanged owner intent**.
   `authority_profile_digest_hex` remains an independent opaque selection, not
   a derived commitment to these 14 fields. Raising both local caps from two to
   three changes the profile digest while the same requested scope, intent and
   valid signature still match. Policy-version binding is unresolved; do not
   equate that opaque pin with the profile digest or claim a signed policy.
3. A retained old profile and intent still match after a mutable source copy
   changes. Old selected bytes carry no clock, latest-source check or revocation
   evidence. Coherent rollback of profile selection remains outside this helper.
4. A well-formed zero public-key encoding and a structurally selected invalid
   pre-signature can match local rules. Actual public cryptographic verification
   is separate and rejects the non-curve key or invalid signature. Profile
   matching cannot make an unverified source true.
5. A forged positive callback can pass the existing trusted-verifier interface
   with a zero signature. Adding this profile does not repair that trust boundary.
   Unit sequencing oracles are not real signature evidence.
6. Profile/signature checks remain repeatable after a real source journal
   exhausts its allowance. They change neither journal bytes nor consumption and
   cannot admit a subsequent blocked recovery. They provide no aggregate limit
   on repeated public checking.

## Qualification, reuse and remaining gates

[Python unit tests](../tests/test_governor_profile.py) cover exact framing,
selection, field/pin/cap changes, wrong object types, replay and the above trust
counterexamples. Their local fixture helper derives rules only from a synthetic
locally prepared context; it is not application peer-bootstrap guidance.
[The separate actual qualifier](../scripts/qualify_governor_profile.py) uses
unchanged public Rust signature, artifact and completion executables, and tests
a real exhausted/reopened journal. [Validation](STAGE35_VALIDATION.md) separates
executed checks from configured or historical evidence.

The helper reuses internal MIT codec validation from
[the unchanged parent contract](https://github.com/edgepillar/ptlc-research/blob/b877b3a22004236569042aa5b647cc5d84dd522f/offline_session/enrollment_contract.py).
The qualifier reuses internal MIT
[public enrollment qualification](https://github.com/edgepillar/ptlc-research/blob/b877b3a22004236569042aa5b647cc5d84dd522f/scripts/qualify_enrollment_signature.py)
and public synthetic fixtures. No external implementation, new dependency,
signer or replacement arithmetic is introduced. Both fixed review subjects and
their unfilled reports remain unchanged; this exact delta needs its own review.

Before an enrollment backend, select and assess independently authenticated
governor provisioning/role assignment, policy-version binding and rotation or
revocation, authenticated source/economic equivalence, and first-registration
capture rules. Later allocation still needs non-rollbackable atomic uniqueness,
charged lineage, scoped idempotency, bounded public work and trusted unique
dispatch. Existing journal and observation APIs enforce none of this profile.

**GO:** further offline role/bootstrap and policy-binding qualification.
**NO-GO:** treat profile matching or a valid signature as a governor certificate,
allocate fresh quota, connect a registry or dispatch path, integrate private
signing, port current-node consensus rules or use real funds.

The later [Stage 36 comparison](GOVERNOR_AUTHORITY_MODEL.md) separates trusted
assignment, hypothetical complete intent binding and current authority at use.
Static signatures/binding still allow old policy/key authority; cached-current
checks and coherent local anchor restore have distinct failures. The ideal
current oracle is not implemented and repeated packet admission remains possible.
The existing profile and v1 message are unchanged; see [validation](STAGE36_VALIDATION.md).

[Stage 37's unsigned assignment](GOVERNOR_ASSIGNMENT_CONTRACT.md) embeds every
field of this unchanged local profile, plus an independently selected issuer.
Its separate unsigned v2 intent commits the assignment digest, including complete
caps. The old profile digest, opaque authority pin and v1 message remain separate.
Byte binding supplies no issued role, real signature, provisioning or current
state; old expectations still parse. See [validation](STAGE37_VALIDATION.md).
