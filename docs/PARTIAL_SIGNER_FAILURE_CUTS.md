# Partial-signing journal failure cuts

Status: **OFFLINE QUALIFICATION ONLY / NO SIGNER INTEGRATION**. This map targets
nonce-dependent partial generation through `reserve`, `produce_once` and `replay`.
The new tests use fixed public fixture bytes, not a private signing backend.
No entropy, durable secret custody or restored-copy protection construction is
selected. Application and core progression remain **NO-GO**.

## Selected source and separate boundaries

The examined implementation is the accepted source at
[`242a75cbc0152b5047d13aa4f77a8a83f7026764`](https://github.com/edgepillar/ptlc-research/tree/242a75cbc0152b5047d13aa4f77a8a83f7026764),
Git tree `1f83513f9a57393be0853bb7c2698a24f8102775`. All existing implementation,
native qualification, fixtures and dependency bytes remain unchanged by this
slice. New tests and this map are later qualification material, outside that
source and outside the four fixed independent review subjects.

| Boundary | Existing implementation fact | Missing signer requirement |
| --- | --- | --- |
| Local reservation | [`Journal.reserve`](https://github.com/edgepillar/ptlc-research/blob/242a75cbc0152b5047d13aa4f77a8a83f7026764/offline_session/journal.py#L652-L674) pins session, leg, role, purpose and nonce round; the public tag is unique within the visible journal history | Identify the actual secret nonce, selected backend and nonexportable owner; bind them to this exact request |
| Consume admission | [`produce_once`](https://github.com/edgepillar/ptlc-research/blob/242a75cbc0152b5047d13aa4f77a8a83f7026764/offline_session/journal.py#L676-L724) persists `CONSUMED` before invoking the synthetic callback | Specify durable irreversible secret consumption and how copied permissions or stale owners cannot perform the same work |
| Persistence | [`_persist`](https://github.com/edgepillar/ptlc-research/blob/242a75cbc0152b5047d13aa4f77a8a83f7026764/offline_session/journal.py#L510-L570) commits SQLite before separately replacing and syncing its anchor | Define storage/runtime assumptions and resolve ambiguous outcomes without authorizing another nonce-dependent computation |
| Ephemeral secret owner | [`Ready::sign_once`](https://github.com/edgepillar/ptlc-research/blob/242a75cbc0152b5047d13aa4f77a8a83f7026764/qualification/tests/nonce_lifecycle.rs#L242-L281) checks process/thread, takes an in-memory `Option<SecNonce>` and then checks context or calls the backend | The integration-test owner has no durable journal bridge; a moved Rust value is not protection against a copied or restored execution environment |
| Output retention | `produce_once` stores exact public bytes as `OUTPUT_RECORDED` before return | Couple the retained artifact to the actual signing request and verifier policy; a byte record proves neither signature validity nor remote delivery |
| Replay | [`replay`](https://github.com/edgepillar/ptlc-research/blob/242a75cbc0152b5047d13aa4f77a8a83f7026764/offline_session/journal.py#L726-L732) reads only retained bytes in the same validated context | Replay must perform no new nonce-dependent work; an unknown unretained output stays spent |

The [managed completion lifecycle](COMPLETION_LIFECYCLE.md) starts after partial
signatures already exist. `complete_alice` and possible witness disclosure are
later operations. They cannot stand in for the missing partial signer/journal
bridge. In particular, `possible_exposure == false` for a partial operation does
not mean that nonce use is safe, secret data cannot leak, or that a returned
partial is valid. That flag tracks the selected witness-disclosure policy.

## Executed fixture-only process-death matrix

The [new test](../tests/test_partial_journal_boundary.py) and
[separate child actor](../tests/partial_journal_actor.py) reconstruct the existing
nonce-bound public fixture contexts for Bitcoin/Alice, Bitcoin/Bob, Zenon/Alice
and Zenon/Bob. Each scope runs all eleven schedules below: **44 actual child
processes killed with SIGKILL**, not eleven or forty-four new test methods.

The four database/anchor hook names occur twice during `produce_once`: first
while consuming admission, then while recording output. The actor selects the
first or second occurrence after reservation, so a test of consumption cannot
silently substitute for a test of output persistence. The public callback writes
one flushed invocation marker and returns the same fixed fixture bytes.

| Killed at | Commit occurrence | Expected callback count | Reopen outcome | Permitted output action |
| --- | --- | ---: | --- | --- |
| Before database commit | Consumption / first | 0 | `RETIRED` | No output or producer retry |
| After database commit, before anchor replacement | Consumption / first | 0 | `QUARANTINED` | Refuse opening; no automatic repair |
| After anchor replacement, before directory sync | Consumption / first | 0 | `OUTCOME_UNKNOWN` | No output or producer retry |
| After anchor commit | Consumption / first | 0 | `OUTCOME_UNKNOWN` | No output or producer retry |
| After consume checkpoint | Consumption complete | 0 | `OUTCOME_UNKNOWN` | No output or producer retry |
| After callback checkpoint | Output not committed | 1 | `OUTCOME_UNKNOWN` | No output or producer retry |
| Before database commit | Output / second | 1 | `OUTCOME_UNKNOWN` | No output or producer retry |
| After database commit, before anchor replacement | Output / second | 1 | `QUARANTINED` | Refuse opening; no automatic repair |
| After anchor replacement, before directory sync | Output / second | 1 | `OUTPUT_RECORDED` | Exact byte replay only |
| After anchor commit | Output / second | 1 | `OUTPUT_RECORDED` | Exact byte replay only |
| After output checkpoint, before caller return | Output complete | 1 | `OUTPUT_RECORDED` | Exact byte replay only |

Every successful reopen checks the exact operation state and nonce-round digest,
the partial operation's false witness-exposure flag, refusal of another producer
invocation and refusal of replacement reservation with either a new or repeated
tag. Retained output is replayed twice without changing the session snapshot or
invocation marker; unretained output refuses replay. Quarantined cuts refuse
opening and preserve the expected marker count.

An anchor replacement visible after process death can survive this schedule even
when the child had not yet synced its directory. This is an observed process
schedule under the running OS and filesystem, **not evidence of power-loss
durability**. The matrix does not simulate storage rollback, lying flushes,
kernel failure, callback side effects or every instruction in a signing backend.
Existing exception, process-death and managed-completion tests remain separate.
See the [Stage 89 validation record](STAGE89_VALIDATION.md) for actual runs.

## Two local-history counterexamples

Two additional methods cover each of the four partial contexts, for eight
copy/restore subcases. They retain ordinary one-use refusal inside each local
history while demonstrating its limited reach:

1. **Distinct live copies:** copy the matching database and anchor before any
   reservation. Open both copies together on distinct database and anchor lock
   files. Both can reserve the same operation ID, tag and context, then each can
   invoke its synthetic producer once. Both reopen with their own exact retained
   output. The owner handles coexist; the callback invocations are sequential.
   This is not a concurrent-thread or real signing experiment.
2. **Coherent pre-reservation restore:** save the matching pair, reserve and
   produce once, then close and restore both earlier files. The same operation,
   tag and context can be reserved and produced again. Within each history,
   another invocation and replacement reservation still refuse.

Each subcase records exactly two synthetic callbacks and keeps the partial
witness-exposure flag false. These are **expected negative controls**, not test
failures. They do not demonstrate real secret nonce reuse, a repeated backend
partial signature, a key-extraction attack or a fix for restored copies. The
public fixture output is not itself a verified partial signature.

Retain the earlier [deterministic public-nonce counterexample](SIGNER_NONCE_REVIEW_HANDOFF.md)
and paired Alice-completion restore example as distinct facts. Context binding,
a globally unique tag within one database, a local lock and matching copies do
not supply freshness or authority outside that visible history.

## Requirements before a native integration harness

The requirements below are unresolved design obligations. This test actor is
not a selected signer construction, remote authority or application API.

1. Identify exact backend revisions, both signing roles, message/tweak/parity,
   complete nonce round and the actual secret owner. Select a public-synthetic
   test harness separately from any future real-key interface.
2. Define separate events for durable admission, irreversible nonce consumption,
   backend entry, partial output, durable retention and caller delivery. Map
   cancellation, panic, process death and uncertainty at each actual boundary.
   A public callback count cannot qualify secret consumption.
3. Specify an authority that remains current outside coherent copies, with its
   outage, compromise and recovery assumptions. Cover copied post-consumption
   permission as well as pre-consumption restore. The
   [invocation model](NONCE_INVOCATION_MODEL.md) and
   [grant/copy model](NONCE_GRANT_COPY_MODEL.md) retain their unimplemented ideal
   external premises; final-result fencing does not prevent repeated secret work.
4. Require exact retained-output recovery without deriving or signing again.
   Unknown unretained work must stay spent. Do not add automatic repair, reset,
   fee replacement or retry as an availability shortcut.
5. Preserve these counterexamples, the four fixed inventories and all three
   unfilled independent reports. Assess the exact adaptor construction, proposed
   custody, signer/journal integration, provenance and privacy independently
   before making an application-readiness claim.

The next bounded research step is to review this cut map against a proposed
public-synthetic native harness specification. No native partial signer is wired
into the journal here. Bitcoin construction, recovery and chain observation stay
outside core; a core contribution requires a narrow, coordinated proposal.
No wallet, real funds, broadcast, deployment, activation or core change is
authorized or qualified by this slice.
