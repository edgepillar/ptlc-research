# Offline source response signature qualification

Status: **Stage 44 selected construction; historical public mathematics only.**

A signature can bind a response to a selected query without establishing that
its checkpoint describes current state. This isolated candidate combines the
[retained read contract](CURRENT_AUTHORITY_EVIDENCE.md) and
[historical root declaration](SOURCE_ROOT_ROLE_QUALIFICATION.md). No source
service, current-state lookup, application gate, SQLite authentication, protected
physical entry or production signer is connected.

## Requirements and selected construction

An operational source needs independently provisioned root and response-key
custody, complete query and claim binding, a serialized current-policy read,
nonrollback lineage, compromise/revocation recovery and a cutoff at protected use.
These are requirements, not results of this stage. The independent selections
and selected worker/runtime remain trust premises.

The additional `exact-profile-checkpoint-read-v1` rule requires the query's
complete fourteen-field governor profile to equal the historical root profile,
and its issuer to equal the root's declared issuer key. This is one deliberately
narrow interpretation, not an operational delegation granted by a root signature
or a universal PTLC rule. The previous administrator construction can describe
attenuated profiles; this response candidate does not infer them from a command
or consult a store. Supporting such profiles requires a separate reviewed policy
model. Opaque configuration digests are labels, not rederived configuration.

The root, complete previously prepared read query and observation are chosen
before receiving a peer packet. Observations are `active`, `revoked`, `absent`
and `unavailable`; all remain historical claims. An unavailable claim asserts no
checkpoint or assignment; an absent claim asserts no assignment. Neither yields
a refund, permission or fallback. Choosing an observation before checking its
signature is a qualification fixture selection, not discovery of current state.

## Framing and mathematical checks

The eleven response fields are `schema`, `purpose`, `algorithm`, `read_rule`,
`root_declaration_digest_hex`, `source_response_role`, `source_response_key_hex`,
`source_context`, `query`, `claim` and `claim_digest_hex`. The role is
`checkpoint-responder`; its key must match the independently selected complete
root declaration. All eight context fields, the declaration revision and digest,
complete governor assignment and both carried public signatures are retained.

The query includes its eight fields, exact checkpoint, caller-selected challenge,
full governor signature request, decoded scope and retained resource. The scope
and resource hashes are rederived from their complete canonical bytes. All scope
pins match the profile, caps are bounded, and retained resource bindings match the
scope. None of this independently establishes chain/source truth. The seven-field
claim binds the complete query digest, source-context digest, challenge, observation,
checkpoint and assignment digest with the retained read-contract semantics.

SHA256 domains followed by one zero byte are:

| Object | Domain |
| --- | --- |
| Source response message | `PTLC/observation-source-response/v1` |
| Complete claim digest | `PTLC/observation-policy-read-claim/v1` |
| Complete request/result binding | `PTLC/observation-source-response-request/v1` |

The unchanged root, query, source, scope, resource, assignment and v2 owner domains
keep their prior meanings. Complete claims are included in the signed response;
the additional claim digest uses a distinct selected domain. The request includes
the full root envelope, response and particular response signature. Its digest
also includes the carried issuer and owner signatures through the complete query.

The [public worker](../qualification/examples/verify_source_response.rs) reuses the
unchanged root worker for five distinct curve-key checks and root-signature math,
and the unchanged governor worker for issuer-assignment and v2 owner-intent math.
It then verifies the response signature. Four positive flags in a six-field result
mean only historical mathematical checks under the packet-selected keys. The raw
worker cannot provision these roles or discover which checkpoint is current.
The five primary test roles are reproducible from deliberately known synthetic
tags in one test process; distinct encodings are not independent custody.

Requests are compact sorted-key ASCII JSON bounded to 16,384 bytes; the largest
fixture request is 9,362 bytes. Results are bounded to 512 bytes (262 fixture bytes).
Exact nested fields, lowercase hex, integer/type rules and re-encoding reject
aliases and duplicate keys. Checkpoint revisions are exact integers from zero to
`2^53-1`; they need no increment headroom because this construction applies no
transition. Envelopes accept no trailing LF; the raw worker permits at most one
request LF. A second valid root or response signature changes complete request
binding while preserving the unsigned selection.

The [pure selection wrapper](../qualification/source_response.py) refuses valid
peer replacements before callback work, defensively revalidates its prepared query
and returns the same unsigned historical selection. Direct conversion, canonical
bytes and message-digest access refuse foreign descriptors or subclass conversion
hooks before access. A malicious selected callback can forge all four positives
for zero root/response signatures which the actual worker refuses. The
[bounded transport](../qualification/source_response_verifier.py) repeatedly measures
a selected entry. This is not atomic launch, provenance, a sandbox or a source adapter.

## Unsafe controls and execution evidence

Seventeen positive packets cover all observations, new challenge/checkpoints,
maximum revision, state digest, root/admin/response/issuer/owner keys, broader
profile, epoch, root revision and source incarnation. Twenty-five refusal packets
carry valid response mathematics under their claimed key, separately checked by
Rust and Go, but violate role/root/context/query/claim/profile binding or retain
invalid nested issuer/owner mathematics. Actual worker checks include every byte
and scalar boundaries of all four signatures. See [validation](STAGE44_VALIDATION.md).

Old exact queries and responses replay after new signed checkpoint, revocation,
root, response key or incarnation histories. Restoring the complete old root,
query, challenge, checkpoint and response expectations makes the old packet match
again. A newly selected challenge can accompany the same old active checkpoint,
assignment and profile, signed with the selected response key, and pass all four
mathematical checks. Challenges are opaque supplied comparison values; generation,
uniqueness, consumption and source serialization are not implemented. This is
an explicit unsafe control, not a current-authority result.

Valid historical reads leave the temporary Stage 41 store's complete view and
database bytes unchanged. After separate local revocation, all four observation
labels and a newly challenged old active response still verify mathematically;
a charged pending synthetic effect remains refused, without refund. This proves
isolation of the check. It does not authenticate that store or define operational
revocation. No chain, wallet, real funds or private production signing is involved.

Both fixed review subjects, inventories and independent assessment reports remain
unchanged and unfilled. Offline qualification is **GO**. Source integration, core
port, activation, deployment, private signing and funded recovery remain **NO-GO**.
The next useful work is a concrete source/read ordering and nonrollback lineage
design, with recovery and effect-cutoff acceptance gates before any integration.

## Source and reuse record

Framing, selected rule, public vectors and tests are original project MIT material,
reusing project patterns at `586ed7bc0bd74dd82164ff74b7d7ec5e548dac22`. No upstream
implementation or vectors are copied and no dependency is added or changed.
BIP340 message/key/signature facts use the immutable
[specification at 2885f13](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki),
licensed BSD-2-Clause, with code alternatives BSD-2-Clause, MIT or CC0-1.0.
Existing locked secp256k1 0.29.1 via bitcoin 0.32.7 supplies the Rust public check;
its Rust binding is CC0-1.0 and bundled C backend MIT, separately recorded in the
[earlier pinned license record](SOURCE_ROOT_ROLE_QUALIFICATION.md#source-and-reuse-record).
The existing independent Go backend checks public mathematics only. Compatibility
and fresh CI are neither independent security assessment nor source provenance.
