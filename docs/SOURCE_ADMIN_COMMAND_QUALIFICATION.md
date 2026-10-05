# Offline administrator command qualification

Status: **Stage 43 selected construction; historical public mathematics only.**

A delegated administrator key does not by itself define permissible operations.
This candidate independently selects a small transition rule on top of the
[historical root declaration](SOURCE_ROOT_ROLE_QUALIFICATION.md). It does not
connect to a policy service, SQLite mutation, registry, application admission or
protected worker entry. No signer or private-key input is added to an application.

## Requirements and selected rule

An operational source needs independently provisioned root custody, explicit
administrator powers, complete expected predecessor binding, original-command
identity and atomic deduplication, current revision/revocation, compromise recovery,
external nonrollback lineage and an effect cutoff. These remain requirements,
not results of this stage. The following rule is one offline candidate, not a
universal PTLC requirement or a replacement swap protocol.

The fixed `attenuate-or-revoke-v1` rule permits exactly two operations:

| Operation | Selected transition |
| --- | --- |
| `reduce-limits` | Both states are active. Neither cap increases and at least one strictly decreases. Every other profile field stays identical. |
| `revoke` | Active becomes inactive. The complete profile stays identical. |

A no-op, mixed increase/decrease, limit increase, reactivation, key or owner change,
root rotation, namespace/epoch change and configuration-label replacement refuse,
including when a carried key supplied valid signature mathematics. Revocation does
not reduce caps to zero: the independent active flag describes the requested state.
A previously revoked predecessor has no supported command in this construction.

The independently selected root profile is a historical anchor. For this candidate
only, its caps are an upper bound and all twelve other profile fields must match
both old and new profiles exactly. Old profiles may already have lower caps.
The Stage 42 root declaration itself assigns no transition powers; this rule is an
additional independently selected interpretation. Opaque configuration digests
are retained labels, not recomputed hashes of caps or evidence of configuration.
A future source must separately review whether this anchor interpretation suits
its policy model. No operational delegation or root-provisioning fact is claimed.

## Complete framing and verification

The fifteen command fields are `schema`, `purpose`, `algorithm`,
`administration_rule`, `source_context`, `root_declaration_digest_hex`,
`administrator_role`, `administrator_key_hex`, `original_command_id_hex`,
`expected_policy_revision`, `old_profile`, `new_profile`, `old_active`, `new_active`
and `operation`. The context has all eight retained fields; both profiles have
all fourteen fields. The administrator key must equal the root declaration's
selected delegated administrator key. The selected role is `policy-administrator`.
The command binds the exact root declaration message digest and complete context.

The expected policy revision is an exact integer from zero through `2^53-2`, with
headroom for a possible later one-step revision. This stage neither advances nor
reads a revision. It is distinct from the root declaration revision. The 32-byte
original command identifier is an opaque comparison label; uniqueness, ownership,
idempotent receipts and deduplication are not implemented.

Command messages hash the sorted, compact canonical ASCII command after
`PTLC/observation-source-admin-command/v1` and one zero byte. The envelope carries
that command, its 64-byte BIP340 administrator signature and the complete retained
root envelope. The bounded worker independently checks the root signature under
the packet root, reusing the unchanged exact root worker's five point/role checks,
and checks the command signature under the declared administrator. It cannot
provision either key or discover a current source. Its four-field result binds
SHA256 of the complete request after `PTLC/observation-source-admin-request/v1`
and one zero byte, including both particular public signatures.

All exact-field, lowercase hex, numeric/type and canonical constraints apply at
every nested level. Requests are bounded to 8,192 bytes, results to 512 bytes.
Envelopes accept no trailing LF; the public worker permits at most one request LF.
A second valid root or administrator signature keeps the selected unsigned command
unchanged but requires a different complete request result.

The [pure framing](../qualification/source_admin_command.py) requires independently
selected complete root and command bytes before peer parsing. Valid peer replacement
commands, revisions, roots, incarnations and keys refuse before callback work. It
returns the same unsigned historical selection, without permission, committed-state
or current-authority flags. A malicious selected callback can forge both positives;
the zero-signature unsafe control remains explicit. The [bounded transport](../qualification/source_admin_verifier.py)
repeatedly measures a selected executable. This is not atomic launch, provenance,
a sandbox or an application source adapter. Runtime trust stays external.

## Execution evidence and open gates

The [public fixture](../qualification/fixtures/source_admin_command.json) includes
12 positive commands and 18 signed refusal controls. Its SHA256 is
`e1be072b95cc01aeb40642fb1c2c3079d49fa85301939b9b02164f008968229b`.
[Original Rust tests](../qualification/tests/source_admin_command.rs)
generate signatures only from deliberately known public synthetic scalar tags;
all five primary role keys are reproduced inside one process. Distinct role bytes
do not prove independent custody. [Go checks](../qualification-go/source_admin_command_test.go)
use the existing locked backend without signing. Both check that refusal controls
have valid mathematics under their claimed key before the selected rule refuses.
The [actual-worker checks](../scripts/qualify_source_admin_command.py) exercise the
new executable, including both signature arrays, alternate signatures and raw
signed-rule refusals. See [validation](STAGE43_VALIDATION.md) for runs and failures.

Replay and coherent copied/restored selections still succeed after a newer signed
revision, revocation, root, administrator or incarnation selection. No current
revision lookup, original-command commit, external lineage or revocation oracle
exists. A temporary SQLite control retains its view, bytes and charge when valid
commands are checked; even after separate local revocation, old revision-zero
commands still verify as history and the pending synthetic effect refuses. This
proves isolation, not authenticated SQLite application or physical effect safety.

Before integration, require separately reviewed custody/provisioning, operational
transition rules, authenticated current source responses, atomic original-command
commit and predecessor checks, lineage outside rollbackable copies, compromised-key
recovery and protected-use fencing. The fixed 119-file and 189-file review subjects
and their unfilled independent assessments remain unchanged. Offline qualification
is **GO**. Source integration, core port, activation, deployment, private signing
and funded recovery remain **NO-GO**.

## Source and reuse record

The [BIP340 specification pinned at
2885f13d3f37890e328683166dbcbc60b488d13a](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki)
defines the public signature/key encoding and mathematical verification. The
specification is BSD-2-Clause; its reference code has separate alternatives.
No specification passage, upstream code or test vector is copied here. Domain,
rule and framing choices are original project MIT material, reusing only original
project patterns pinned at `d2766ffb0fbd5ff8be5d11417c208a4a1e8d5bc2`.
Existing [locked dependency/license records](../THIRD_PARTY_NOTICES.md) remain
unchanged. Two executing backends do not reproduce dependency provenance or supply
an independent cryptographic/security assessment.
