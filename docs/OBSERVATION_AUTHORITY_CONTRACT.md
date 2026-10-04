# Candidate observation authority scope and message contract

Status: **Stage 30 pure bounded research codec. No external authority,
enrollment owner, authenticated transport, dispatcher or runtime integration is
implemented.** Parsing returns public claims, never permission to start work.
The candidate schemas below are review inputs, not an interoperable service or
an assessed production protocol.

Source parent: [`01f0a647b2f2de27209cfd45b4b4158c8ea9b802`](https://github.com/edgepillar/ptlc-research/tree/01f0a647b2f2de27209cfd45b4b4158c8ea9b802).
Its [completed seven-job run](https://github.com/edgepillar/ptlc-research/actions/runs/37210225868)
qualifies the prior implementation and [finite authority comparison](OBSERVATION_AUTHORITY_MODEL.md).
That comparison requires canonical enrollment, non-rollbackable external state
and unique dispatch to make its strongest bounded claim. This codec specifies
some public bindings for assessing a future construction; it supplies none of
those premises. [V4 coherent restore](RESOURCE_STORE_RESTORES.md) remains able
to replenish local quota.

## Requirement, selected encoding and implemented boundary

| Requirement | Candidate choice | Current behavior and missing mechanism |
| --- | --- | --- |
| Changing an observation must not refresh one protected scope's allowance | Scope excludes candidate signature, request ID and local path; it includes both retained legs and selected enrollment/profile labels | Different candidates and local copies produce the same scope for the same retained context and selection; canonical enrollment and duplicate detection are absent |
| A peer must not choose the trusted authority, epoch or expected head | Caller prepares immutable scope/request objects from local selections; incoming bytes must match that exact request | No field from a reply selects a different context; provenance of the original local selection and latest-head authentication remain external |
| Reservation, dispatch and publication must address the same charged attempt | Full expected head, operation, exact target and request ID are bound into each request digest | Phase checks and declared transitions are enforced on bytes only; no atomic transaction, receipt owner or dispatcher exists |
| Lost replies or uncertain work must not establish refund permission | Unresolved replies assert no head or attempt; successful resolution keeps consumed unchanged | Missing/malformed replies fail parsing; no recovery, retry, refund or fallback action is performed |
| A normal result must refer to the selected evidence target | Publish carries an exact bound evidence statement and selected verifier profile | All three statement outcomes remain forgeable claims; the codec invokes no mathematical producer and authenticates no source |
| Counts and target retention must remain bounded across copies | Attempt/target limits are selected scope fields; declared heads use finite counts and one pending attempt | No shared count or target-set owner exists; formatting multiple proposals does not enforce either limit across callers |

The [implementation](../offline_session/authority_contract.py) imports only pure
context, completion and evidence helpers. Existing journal/store entry points,
worker/resource paths, models, qualifiers, cryptographic code, dependencies and
storage formats are unchanged. The new codec is not imported by those entry
points, and it offers no socket, file, clock, subprocess or callback API.

## Scope identity and enrollment gap

`authority_scope` requires a validated plain `RELEASE_RECORDED` snapshot and nine
explicit local selections. All digest/ID fields are exactly 64 lowercase hex
characters. No IDs or epochs are minted by the codec.

| Fields | Meaning and provenance |
| --- | --- |
| `schema`, `predicate` | Fixed `ptlc-observation-authority-scope-v1` and existing `zenon-completion-v1` |
| `authority_id_hex`, `enrollment_id_hex`, `authority_epoch` | Externally selected authority/enrollment labels and a positive epoch; labels are not certificates or public keys |
| `authority_profile_digest_hex`, `verifier_profile_digest_hex` | Selected authority semantics and existing public mathematical verifier profile; equality proves no implementation, build or host integrity |
| `pool_profile_digest_hex`, `resource_profile_digest_hex` | Selected physical-admission and requested resource profiles; digests do not prove physical pool identity, effective caps or trusted enrollment |
| `attempt_limit`, `target_limit` | Selected finite values from 1 through 64; no automatic reset, growth or target-set enforcement |
| `session_id`, `terms_digest_hex` | Derived from the retained Bitcoin context and agreed terms, checked with the coupled Zenon context |
| `bitcoin_context_digest_hex`, `zenon_context_digest_hex` | Derived exact retained signing contexts, including public nonce-round bindings |
| `bitcoin_bundle_digest_hex`, `zenon_bundle_digest_hex`, `release_digest_hex` | Derived commitments to both complete retained public bundles and exact release bytes |

Different candidates under one fixed context have different targets but the
same scope. Retaining another candidate without changing the release context
also leaves the scope unchanged. The codec accepts no local file path, store ID
or caller-provided context override. A changed retained bundle, nonce round,
session or agreed term produces a different scope and refuses the previously
selected scope when preparing a request.

Changing a selected enrollment ID, authority, epoch, profile, limit or retained
context can still construct a different public scope. This is **not external
enrollment or a fresh allowance**. A future owner must define which protected
resource these variations refer to, authenticate that mapping and reject
duplicate/unauthorized enrollment. Simply indexing a database by this digest
would permit caller-label evasion if arbitrary scopes were admitted. The current
tests deliberately demonstrate multiple proposals under a selected target
limit of one; no target set is owned or mutated here.

## Exact bytes and domains

All messages use sorted-key, compact, ASCII JSON with exact field sets and no
terminal newline. Duplicate keys, whitespace variants, escaped alternatives,
non-ASCII bytes, invalid numeric values and trailing bytes are rejected. The
scope is bounded to 4,096 bytes; requests and replies to 16,384 bytes. Publish
statements retain the existing 4,096-byte bound and are carried as lowercase
hex. Parsing catches malformed/deep JSON and emits constant sanitized errors
without echoing input or peer diagnostics. This is bounded decoding, not a
hostile-runtime sandbox.

All numeric fields require exact integers, excluding Boolean/float aliases.
Epoch is 1 through `2^53 - 1`; revision is 0 through `2^53 - 1`. A request whose
head cannot advance by one is refused. The last safe revision can be claimed by
a reply, but further work needs explicitly reviewed epoch handling; no rollover
or re-enrollment is automatic.

| Digest | SHA256 input prefix followed by exact bytes |
| --- | --- |
| Bitcoin bundle | `PTLC/authority-bitcoin-bundle/v1` + NUL + canonical bundle |
| Zenon bundle | `PTLC/authority-zenon-bundle/v1` + NUL + canonical bundle |
| Release | `PTLC/authority-release/v1` + NUL + raw release bytes |
| Scope | `PTLC/observation-authority-scope/v1` + NUL + canonical scope |
| Request | `PTLC/observation-authority-request/v1` + NUL + canonical request |

The target reuses the three derived bindings from the
[evidence contract](OBSERVATION_EVIDENCE_CONTRACT.md): `evidence_key_hex`,
`binding_digest_hex` and its Zenon verification `request_digest_hex`. The outer
authority request has its own separate digest/domain. SHA256 matching proves
byte identity only; it authenticates neither authority nor verdict truth.

## Head and request phases

An `AuthorityHead` contains exactly `revision`, `state_digest_hex`, `consumed`,
`pending_attempt_id` and `dispatch_recorded`. Revision cannot be below consumed.
Consumed is bounded by the selected attempt limit. Pending is either null or
the latest consumed attempt; without pending, dispatch must be false. The state
digest is an externally selected opaque commitment label. The codec neither
defines the authoritative state's serialization nor recomputes its digest.

Each request contains exactly `schema`, `operation`, `scope_digest_hex`,
`authority_epoch`, `request_id_hex`, `expected_head`, `target`, `attempt_id` and
`statement_hex`. Schema is `ptlc-observation-authority-request-v1`. Request ID is
an externally selected public opaque label, **not a signing nonce or capability**.
Preparing the request revalidates the live retained release against its scope
and derives the target from the exact 64-byte public signature. Invalid signature
math can be formatted; no validity assertion or worker runs.

| Operation | Expected phase | Attempt/statement |
| --- | --- | --- |
| `reserve` | Available nonpending head; consumed below selected attempt limit | Both null |
| `dispatch` | Exact pending attempt, dispatch false | Selected pending ID; no statement |
| `publish` | Exact pending attempt, dispatch true | Selected pending ID; exact bound normal or unknown statement |
| `resolve-unknown` | Exact pending attempt, with either dispatch marker | Selected pending ID; no statement |

`parse_request` requires the exact locally prepared `AuthorityRequest` and
matches the incoming canonical bytes. It is not a generic peer admission
endpoint. Replaying matching bytes parses again. Reusing a request ID for a
different locally prepared body is representable but creates a different
digest; no idempotency table or one-use owner is implemented.

## Reply claims and uncertain delivery

Reply schema is `ptlc-observation-authority-reply-claim-v1`. Exact fields are
`schema`, `operation`, `scope_digest_hex`, `authority_epoch`, `request_id_hex`,
`request_digest_hex`, `before_head`, `status`, `after_head` and `attempt_id`.
Every echo must match the selected request, including the complete before head
and outer request digest. Both heads are independently checked for exact types;
numeric alias equality cannot replace the selected integer values.

| Status | Declared transition checked by the parser |
| --- | --- |
| `reserved` | Reserve only: revision +1, consumed +1, pending is new consumed, dispatch false, matching new attempt ID |
| `dispatch-recorded` | Dispatch only: revision +1, unchanged charge/pending, dispatch true, same attempt ID |
| `result-recorded` | Publish only: revision +1, unchanged charge, pending cleared and dispatch false, same attempt ID |
| `unknown-recorded` | Resolve only: same completion shape and unchanged charge, same attempt ID |
| `not-applied` | Exact expected head echoed with no attempt ID; no claim of the globally current head or authenticated absence of a charge |
| `unresolved` | No after head or attempt ID; no inference of an unspent attempt, refund, safe retry or permission to start |

Each success requires a changed claimed state digest. That inequality proves no
actual commit, durability, current state, dispatch or result publication.
`dispatch-recorded` does not attest that a process entered. A future backend must
specify how durable dispatch ownership relates to physical entry and crash cuts;
an acknowledgment followed by local spawn fails the model's unique-entry premise.

`AuthorityReplyClaim` contains only status, bound request digest, claimed head
and claimed attempt ID. **Anyone can forge a fully matching reply and replay it.**
The tests require such a forged reply to parse twice and expose no `authorized`,
`permit` or `can_start` property. Missing, malformed and lost replies instead
raise a sanitized parse error; they are not a manufactured `not-applied` result.
No reply directly mutates state, reconciles a journal or launches a worker.

The pure contract can fence declared old-head publication only relative to a
locally prepared expectation. It cannot establish that expectation's freshness,
revoke earlier execution or stop already running work. Physical leases, pool
capacity and resource limits remain separate requirements. The exhausted-journal
test checks that even a forged matching reserve claim leaves SQLite/checkpoint
bytes and original candidate history unchanged, with no recovery callback entry.

## Gates before selecting a backend

1. Specify canonical enrollment ownership, protected-resource mapping, duplicate
   detection, initial trust pins and explicit rotation/reset authority. Address
   caller-controlled label/context changes without minting fresh budget.
2. Select authority authentication and latest-head evidence, full authoritative
   state serialization, non-rollbackable anchoring and native durability. Test
   stale/concurrent requests, scoped idempotency, reply loss, coherent restore,
   owner cloning and power loss under explicit host/storage assumptions.
3. Select the trusted dispatcher and one-use entry mechanism. Assess copied
   acknowledgments, crash between persistence and actuation, uncertain spawn,
   enforcer cloning, stale publication and old running work. Fail closed rather
   than infer exactly-once completion from receipt matching.
4. Review outage, exhausted allowance, legitimate late witness, source/verdict
   trust, target retention, recovery authorization and remaining funded paths.
   Existing journal authority, physical capacity and requested limits stay separate.
5. Independently assess this exact codec delta and any later backend/integration.
   Both [119-file](INDEPENDENT_REVIEW.md) and [189-file](OBSERVATION_REVIEW.md)
   subjects and their unfilled reports remain fixed; this work is outside both.

**Go:** assess the pure bindings and specify the missing enrollment, authenticated
authority, durable dispatch and recovery mechanisms. **No-go:** claim implemented
restore/clone defense, use a parsed reply as worker authorization, connect private
signing or real funds, select production activation or port core rules.
See [Stage 30 validation](STAGE30_VALIDATION.md) for executed evidence and gates.

The later [Stage 31 enrollment comparison](OBSERVATION_ENROLLMENT_MODEL.md)
separately exposes quota splitting, unauthorized canonical registration, cached
absence races and registry rewind. Its stronger resource/owner facts and atomic
lineage are model premises, not mechanisms added to this codec. Existing codec
behavior and replayable claim limits remain unchanged. See
[Stage 31 validation](STAGE31_VALIDATION.md) for that finite delta's evidence.
