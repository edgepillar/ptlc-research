# Offline source root role qualification

Status: **Stage 42 selected construction; historical signature mathematics only.**

The [isolated SQLite candidate](OFFLINE_POLICY_EFFECT_STORE.md) treats its
administrator and source labels as local premises. The
[read contract](CURRENT_AUTHORITY_EVIDENCE.md) likewise treats independently
selected provisioning roots as external facts. This stage qualifies one public
root statement separately, without connecting either component to it. No source
service, administrator command, current-state response, registry enrollment,
worker admission or physical effect is authenticated by this stage.

## Requirement and selected construction

A later operational source needs independently provisioned root ownership,
separate administrator/response/issuer/owner responsibilities, complete resource
and policy binding, current revision and revocation handling, compromise
recovery, and a protected-use cutoff. A valid signature alone supplies none of
those operational facts. The choices below are one candidate, not mandatory
PTLC requirements or a replacement swap protocol.

| Candidate choice | Meaning and limit |
| --- | --- |
| Independent complete expectation | Root, source context, profile and delegated keys are selected out of band before parsing a peer packet. Selecting a peer's valid root as one's own expectation is still self-provisioning. |
| Five distinct x-only key encodings | Provisioning root, policy administrator, source response, governor issuer and enrollment owner differ in bytes. Distinct encodings do not prove independent people, key custody, governance, proof of possession or operational control. |
| One root signature over the complete declaration | Binds the complete eight-field declaration, including the eight-field source context, fourteen-field governor profile and three delegated keys. It records a historical declaration under the selected root. It does not authenticate a subsequent administrator command or source response. |
| Declaration revision | Exact integer from 1 through `2^53-1`. This is a comparison label, not time, latest-head discovery, a monotonic ledger or the SQLite policy revision. |
| Independent reprovisioning | A fixed transition label. Root replacement requires a separately chosen complete expectation; there is no self-signed rotation procedure or compromise-recovery implementation. |
| Public worker result | Three fields bind the complete request, including its particular signature bytes. No authority, permission, quota or current-state flag is returned. |

The root declaration schema is `ptlc-observation-source-root-declaration-v1`.
Its fields are `schema`, `purpose`, `algorithm`, `declaration_revision`,
`source_context`, `governor_profile`, `delegated_keys` and `root_transition`.
The three delegated keys are `policy_admin_key_hex`, `source_response_key_hex`
and `governor_issuer_key_hex`. Resource, authority namespace and role must agree
between the source context and profile. Opaque source/profile digests are not
decoded into source configuration or resource usage.

The exact canonical ASCII object uses sorted keys, no whitespace, exact fields,
lowercase hexadecimal, and no duplicate names, Unicode aliases or numeric
aliases. The declaration message is SHA256 of
`PTLC/observation-source-root-declaration/v1` followed by one zero byte and the
complete canonical declaration. The distinct request digest uses
`PTLC/observation-source-root-request/v1`, one zero byte and the complete request.
BIP340 verifies that 32-byte message with the root's 32-byte x-only key and a
64-byte signature. These framing/domain choices are local construction choices,
not additions to the BIP340 specification. Canonical envelopes have no trailing
LF; the bounded public worker accepts at most one trailing LF on its request.
Requests are bounded to 8,192 bytes; selected transport results to 512 bytes.

## Implemented boundary

[Pure selection/framing](../qualification/source_root_roles.py) uses only
existing pure source/profile decoding. It packages supplied public signatures
without signing or verifying curves. Incoming declarations must equal the
complete independently selected bytes before a callback is invoked. The same
unsigned historical selection is returned after an exact bound callback result.
A malicious selected callback can forge all positive fields; a zero-signature
fake positive remains an explicit passing unsafe control.

The [public worker](../qualification/examples/verify_source_root.rs) uses the
existing locked Rust Bitcoin re-export of libsecp256k1-backed BIP340 verification.
It checks all five points and the root signature, but deliberately verifies
under the root carried in the request: it cannot select a trusted root. The
[qualification-only transport](../qualification/source_root_verifier.py) measures
an explicitly selected executable before each bounded pipe invocation. This is
not atomic launch, provenance, executable containment or a trusted source
adapter. Runtime/host and selected-verifier trust remain premises.

The [public fixture](../qualification/fixtures/source_root_roles.json) contains
ten valid declarations, public message/request/result bytes, a signed role
collision refusal control, a valid alternate signature and wrong-domain/key
signatures. Its SHA256 is
`428d45b3710501de35faae9151dc758dce9c6638d71c8e35291a8e4fa723c3e3`.
The [Rust tests](../qualification/tests/source_root_roles.rs) generate it using
only deliberately public test scalar tags, including 96, 97 and 98 for the new
synthetic roles. All five keys originate in one test process, directly showing
why distinct bytes do not prove independent ownership. The fixture contains
no signing scalar. No application signer or private-key input is added.

The [Go checks](../qualification-go/source_root_roles_test.go) use the existing
locked btcec backend without a signer. Cross-language agreement is additional
execution evidence, not independent authorship, source provisioning or a security
review. The [actual-worker qualification](../scripts/qualify_source_root_roles.py)
explicitly selects its executable, checks real mathematical refusals and preserves
a revoked temporary SQLite store's charge/state/bytes. That test does not connect
the store to the root worker or assert atomic external effects.

## Replay, stale state and remaining gates

A valid independently selected old declaration still verifies after observing a
new revision, root, administrator, response key, source incarnation or profile
epoch. A coherent restored/copy selection likewise verifies; complete replay
returns the same historical result. This stage has no clock, external current
source, nonrollbackable lineage, copy protection, revocation oracle or mechanism
for discovering the latest declaration. Passing these unsafe controls exposes
the missing gates.

Before a source prototype may consume this construction, require separately
reviewed operational root provisioning and custody, authenticated complete
administrator commands and source responses, explicit rotation/revocation and
compromise rules, durable monotonic lineage outside rollbackable copies, and
current-policy checks at the intended protected effect. Physical worker entry
requires a separately evaluated fence/dispatcher; a signed historical statement
or atomic SQLite row is insufficient. A source response cannot bootstrap any of
these expectations.

The original [119-file baseline](INDEPENDENT_REVIEW.md) and
[189-file observation subject](OBSERVATION_REVIEW.md), their manifests and
unfilled assessment reports remain fixed. Review this later delta separately.
Offline qualification is **GO**. Source integration, core port, activation,
deployment, private signing and funded recovery remain **NO-GO**.

## Source and reuse record

The [BIP340 specification at immutable commit
2885f13d3f37890e328683166dbcbc60b488d13a](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki)
provides the signature/key encoding and verification definition. The specification
is BSD-2-Clause; its reference code has separate alternatives. No specification
passages, reference implementation or upstream vectors were copied. Existing
pinned dependency/license records are in [third-party notices](../THIRD_PARTY_NOTICES.md).
The new framing, tests and fixture are original project MIT material, reusing
only original project patterns pinned at parent
`8434d5614f2a1c06213d1fe006509691ecc09e0d`. Dependency source versus recorded crate
bytes was not independently reproduced in this stage. Executing two backends is
separate from provenance, key custody and protocol security.
