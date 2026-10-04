# Observation evidence: exact target and mathematical statement

Status: **Stage 17 offline binding and claim codec. No trusted statement
producer, observation source, negative cache or journal enforcement is selected.**

The source parent is Stage 16 commit
`c90f7e2318372a3f6416e50d7c1d6bde82828214`. Its
[observation experiment](PUBLIC_OBSERVATION_MODEL.md) shows that normal invalid
rejection can consume a protected reserve. Retrying the same invalid candidate
is permitted by that experiment. A future policy using negative results needs
exact input binding and a trustworthy distinction between normal mathematical
rejection and a verifier that did not reach a reliable decision.

## Requirements and selected construction

| Requirement | Selected offline construction | Obligation still open |
| --- | --- | --- |
| Identify exact candidate bytes | Existing completion-observation digest, plus a separate signature digest | Trusted acquisition of those bytes |
| Bind one local session and both legs | Session, terms, both signing contexts and complete recovery-request digest | Authenticate funding, chain identity and timing |
| Identify the mathematical predicate | `zenon-completion-v1` and the exact verification-request digest | Review and qualify a producer of explicit normal verdicts |
| Separate verifier semantics | A locally supplied 32-byte profile digest in a domain-separated evidence key | Define, provision and authenticate the profile; the digest alone is not measurement or trust |
| Represent interrupted or ambiguous work | Explicit `unknown` statement; malformed records raise a sanitized error | Durable attempt/outcome ordering and aggregate resource policy |
| Keep source authority separate | No provenance, envelope, inclusion or authorization fields in the math statement | Specify source evidence and exact per-candidate authority independently |

The [codec](../offline_session/observation_evidence.py) performs no arithmetic,
worker invocation, file access, source verification or admission. Its immutable
targets contain public bytes only. Its immutable parsed statements contain
claims only. Matching hashes do not authenticate a producer or prove an outcome.

## Exact local target

`prepare(state, signature)` accepts a plain exact 64-byte public signature and a
structurally validated Bob snapshot at `RELEASE_RECORDED`. It takes a private
copy of that public snapshot, uses existing candidate construction, and prepares
either the ordinary request or the existing exact-comparison reconciliation
request when another candidate is retained. Nothing is retained or replaced.
The snapshot's comparison guard cannot authorize a later journal operation;
the journal must check its current original again under its own ownership.

The returned target has three immutable byte strings:

- The existing canonical candidate packet derived entirely from local context.
- A canonical `verify-zenon-completion` request with `bitcoin` set to null.
- A canonical `ptlc-observation-evidence-binding-v1` binding.

The binding contains exactly these fields:

| Field | Exact meaning |
| --- | --- |
| `schema` | Fixed binding schema |
| `session_id` | Locally retained session identity |
| `terms_digest_hex` | Both parties' supplied terms commitment |
| `bitcoin_context_digest_hex` | Bob's retained Bitcoin partial-signing context |
| `zenon_context_digest_hex` | Bob's retained Zenon partial-signing context |
| `candidate_digest_hex` | Exact canonical candidate bytes, using the existing observation domain |
| `signature_digest_hex` | Exact signature bytes under `PTLC/observed-signature/v1` plus a zero byte |
| `recovery_request_digest_hex` | Full existing request including both retained bundles |
| `verification_request_digest_hex` | Exact Zenon-only predicate request |

The binding digest is SHA256 over `PTLC/observation-evidence-binding/v1`, a zero
byte and the exact binding bytes. The evidence key is SHA256 over
`PTLC/observation-evidence-key/v1`, a zero byte and canonical JSON containing the
binding digest, predicate and selected verifier-profile digest. Existing
completion request digests keep their existing domain and meaning.

This deliberately binds more than a raw signature, packet or Zenon predicate.
Changing a retained Zenon bundle can change the key while the candidate packet
stays identical. Changing only the retained Bitcoin bundle changes the key even
when the candidate packet and Zenon-only request stay identical. No result
transfers to a different full recovery target by accident.

The key does not contain a source label, an envelope, an observation order or
the identity of a different retained candidate. Those facts do not change the
predicate for the exact target. Their separate authority and history constraints
still apply to a future admission or replacement. No such policy is selected.

## Predicate and statement

`zenon-completion-v1` means the exact retained Zenon bundle, final signature and
adaptor relation satisfy the specified public completion predicate. A normal
positive producer must validate the ordered keys, nonces, partials, aggregation,
final key/message signature and nonzero witness-to-adaptor relation. A normal
negative producer must reliably decide that same exact predicate is false.
A negative result is not necessarily a statement about the final signature
alone: the bundle or adaptor relation may be the failing mathematical input.
Schema/transport failure and implementation uncertainty are not normal negatives.

This scope does not produce a Bitcoin signature, authorize a recovery call or
establish transaction inclusion. The full recovery target is bound so that a
future consumer cannot silently substitute its other leg or retained artifacts.

A statement contains exactly `schema`, `predicate`, `binding_digest_hex`,
`evidence_key_hex`, `verifier_profile_digest_hex`, `request_digest_hex` and
`outcome`. The schema is `ptlc-observation-math-statement-v1`. The request digest
must match the Zenon-only request, not a response-selected request. Digests are
plain lowercase hex with exactly 64 characters. The outcomes are:

| Outcome | Required producer meaning | What the codec establishes |
| --- | --- | --- |
| `verified` | Normal reliable positive decision for the exact predicate | A positive claim matches the local target/profile |
| `rejected` | Normal reliable negative decision for the exact predicate | A negative claim matches the local target/profile |
| `unknown` | No reliable normal decision | An unresolved claim matches the local target/profile |

`parse_statement` accepts only plain nonempty bytes, at most 4096 bytes, encoded
as compact canonical ASCII JSON without a trailing LF. Unknown/missing fields,
duplicate keys, altered bindings, alternate encodings and unsupported outcomes
are rejected. Malformed claims are rejected before rebuilding the local target;
a well-formed claim still requires fresh local derivation and exact comparison.

The profile digest comes from a separate explicit local parameter. It must not
be selected by the response. A future reviewed profile must pin the predicate,
construction, backend source/dependencies, configuration and verdict semantics.
This codec does not measure an executable, validate such a profile or grant it
trust. A peer can forge even a perfectly matching `verified` or `rejected`
statement. Tests deliberately demonstrate that a forged success for invalid
fixture bytes parses as a claim. Applying it as truth would be a trust-boundary
error outside this codec's promise.

## Legacy failure boundary

At the source parent, the [completion executable](../qualification/examples/complete_exchange.rs)
uses the same rejected exit path for failed mathematical checks, request errors,
I/O errors and caught panics. The [pipe runner](../offline_session/public_worker.py)
reports nonzero exit as `WorkerError`; the [completion adapter](../offline_session/completion_verifier.py)
and [lifecycle](../offline_session/completion.py) require an exact positive result
and otherwise report a sanitized failure. None emits this statement schema.

**No-go:** derive `rejected` from legacy `CompletionError`, nonzero exit, missing
output, timeout, cancellation, crash, malformed output or matching error text.
Those channels establish no normal mathematical negative. Legacy positive
results also need a separately reviewed adapter to claim this exact predicate;
they are not accepted as statements by the codec.

`unknown_statement` creates only an exact unresolved statement and accepts no
exception, worker output, reason text or environment data. There is no helper
that fabricates a positive or negative decision. No actual worker is connected.

## Prospective cache and source gates

A future cache may use the exact evidence key only after its producer is
independently trusted and its normal outcome semantics are qualified. A changed
candidate, context, retained bundle or verifier profile requires a different
key. Interrupted work must not become a permanent negative or erase a prior
trusted normal verdict; attempt events and mathematical claims need distinct
storage semantics. Review must address conflicting verdicts and profile changes.

No cache is implemented here. Durable ordering, one-sided/paired restore,
retention/eviction, crash recovery, concurrent ownership and aggregate limits
remain open. Deduplicating one known invalid target does not bound an attacker
who supplies many distinct targets or repeatedly interrupts work. Moving checks
outside an allowance creates a separate aggregate-resource obligation.

An observation-source contract must separately bind the exact candidate to its
session/context, document its acquisition and trust assumptions, retain the
source evidence, and identify who supplies authority for that candidate. A
source label, envelope or inclusion claim cannot fill those requirements alone.
Neither the source mechanism nor chain verification is selected by this codec.

**Go:** review this exact data contract and qualify a separate public-only
producer that explicitly distinguishes normal positive/negative decisions from
unknown work. Keep its local trust and resource boundary explicit before any
negative cache or journal policy is connected.

**No-go:** treat parsed claims as authentication, cryptographic certificates,
funded recovery guarantees or authorization for live swaps or a core port.
The fixed Stage 12 review subject is unchanged; this later code needs its own
delta assessment. See [Stage 17 validation](STAGE17_VALIDATION.md).
