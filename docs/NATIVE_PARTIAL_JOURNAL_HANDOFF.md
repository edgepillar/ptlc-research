# Public-synthetic native partial and journal handoff

Status: selected test construction. A real signer, entropy source, durable secret
custody and independent nonrollback authority remain **UNSELECTED**. Application
and core progression remain **NO-GO**. The preceding accepted source is
`b86af7abcf575ad900fa5bf7fb5b85788d181126`.

## Requirement and selected scope

A partial-signing client must distinguish durable admission, secret nonce
consumption, backend invocation, public result delivery, durable result retention
and byte replay. Losing a result must not permit another use of the nonce. Local
one-use state must not be mistaken for protection across restored or copied
histories. These requirements are broader than this selected test construction.

The [separate Rust test crate](../qualification-native-partial/Cargo.toml) has no
application API and is marked `publish = false`. Its
[five new tests](../qualification-native-partial/tests/native_partial_journal.rs)
retain the nonce in the original test thread. The
[separate Python actor](../tests/native_partial_journal_actor.py) owns a journal
and reconstructs only the existing public context. Both legs and both roles use
the fixed [public nonce fixture](../qualification/fixtures/nonce_rounds.json).
The scalar keys and seeds are intentionally public test values. There is no
arbitrary key import, nonce serialization, application API or network transport.
The actor accepts only the exact corresponding public fixture partial.

The private owner helper definitions are copied byte exact from the
[existing test owner](../qualification/tests/nonce_lifecycle.rs) at the accepted
parent under the root MIT license. This is a source-pinned test copy, not a shared
production signer implementation. The copied helpers retain unused fault
variants under a test-file `dead_code` allowance; the selected five methods do
not qualify those unused variants.

No primitive or journal implementation changes. The entire existing qualification
crate, including all tests, fixtures and dependency locks, remains byte exact.
The separate crate uses the same dev-dependency declarations and locked dependency
versions; only its root package name/description differ. All preceding Python
tests and actors are exact. Two native job commands are added for this separate
crate; all preceding CI commands remain intact. The [Stage 89 SIGKILL matrix](PARTIAL_SIGNER_FAILURE_CUTS.md)
remains a separate synthetic-callback qualification. It is not substituted for
native owner process-death or machine power-loss qualification.

## Ordered handoff

1. Rust creates a test-only `Ready` owner with the existing deterministic public
   inputs. Python creates a session and reserves its full public signing context.
   Rust checks the peer's exact role, leg, history and nonce-round digest while
   the owner still has its nonce and its backend entry count is zero.
2. Python calls `Journal.produce_once`. The existing journal persists `CONSUMED`
   before its callback emits the `invoke` event. Rust checks that event against
   its full bound nonce-round digest. This is a trusted test peer assertion;
   it is not an authenticated grant or independent durable admission proof.
3. Rust calls the existing `Ready.sign_once` on its original thread. That method
   removes the local nonce before context checking and before entering the pinned
   `musig2::adaptor::sign_partial` primitive. It separately verifies the produced
   partial equation. `Ready.calls` counts entry into that signing boundary, not
   every verification operation. The returned scalar matches the existing public
   fixture for the selected leg and role.
4. Only the public partial scalar, encoded as 64 lowercase hex characters,
   crosses the pipe. Python checks those exact bytes and retains them through
   the existing output commit. The native nonce and test key never cross the pipe.
5. After close/reopen, recorded outputs replay exactly twice. Another producer
   invocation and replacement reservation refuse. The same native owner also
   refuses with `Spent`, without another signing backend entry. Replay is byte
   retention, not a new cryptographic computation or a fresh authorization.

Each input command is at most 256 bytes including its newline; each parsed peer
event is at most 2048 bytes. Event and normal-exit waits have a 15-second bound.
An initialized POSIX peer reaps its child and removes its temporary public state
on normal completion and Rust test unwinding. Peer errors emit only an exception type;
stderr is not forwarded. These bounds do not authenticate the selected Python
runtime, prevent a compromised test host or guarantee cleanup after failed peer
construction or parent death.

## Executed scenarios and explicit negative controls

Five new Rust test methods cover four role/leg scopes. They select 32 owners and
32 journal producer admissions in 24 separate child runs. Of those attempts,
24 produce valid public-synthetic native partials, four reach the signing backend
and refuse the injected wrong key, and four refuse before backend entry. This
defines 28 signing backend entries. The unused counterpart owner constructed by
the existing `owners` helper is discarded; no erasure guarantee follows.

| Scenario | Scope subcases | Selected native attempts | Retained behavior |
| --- | ---: | ---: | --- |
| Normal output | 4 | 4 valid partials | Recorded bytes replay after reopen; no reentry |
| Result discarded before delivery | 4 | 4 valid partials | Reopen yields `OUTCOME_UNKNOWN`; native owner is spent |
| Refused native attempts | 8 | 4 before-backend refusals and 4 backend refusals | Consumed admission cannot retry or replay |
| Two simultaneously open copied journals | 4 | 8 valid partials from two reconstructed owners per scope | Each history retains bytes and refuses local reuse |
| Matching pre-reservation restore | 4 | 8 valid partials from two reconstructed owners per scope | Restore erases prior local admission and allows it again |

For result loss, Rust actually computes and verifies the partial, then deliberately
discards it before delivery and sends the fixed `lost` command. This is selected
handoff loss, **not SIGKILL**, backend-process death, an OS durability experiment
or power-loss evidence. The live journal remains `CONSUMED`; reopen converts it to
`OUTCOME_UNKNOWN`. The original owner remains spent with one backend entry. The
two refusal injections have the same journal outcome, with distinct native entry
counts. The error-command check and forbidden-callback counter are asserted
outside the journal's producer exception wrapper.

The copied-history tests keep both local journal locks open together. They use
the same operation, context and nonce tag. The restore tests close all owners of
the journal before rewriting a matching pre-reservation database/anchor pair.
Both controls independently reconstruct two native test owners from the same
public fixed inputs, and explicitly check equal full nonce rounds and equal
public nonces. Both resulting partial scalars match the same fixture. Each
original owner refuses a second use, while the reconstructed owner and other
matching history can each sign once.

This demonstrates actual repeated deterministic nonce/partial mathematics in
the selected test construction. It does not demonstrate an attack with changed
messages, key extraction, cloning an opaque live secret owner or a production
rollback exploit. The false partial witness-exposure flag remains unrelated to
nonce safety. Adaptor completion and witness extraction are later boundaries.

## Fixed source guard and the layout correction

The initial candidate appended this handoff to the existing owner test file.
Its local Rust/Python suites passed, but the first hosted run correctly refused
two fixed-source preparation steps: that file belongs to the immutable selected
qualification source. The original file is now restored byte exact. The new
construction lives in a separate crate outside that inventory, and two additive
CI commands qualify it. No fixed inventory, baseline or source guard is relaxed.
The first failed run and local results are retained and disclosed separately.

## Gates still open

- Fresh entropy, nonce commitment policy, signer identity and authenticated
  admission remain unresolved. Public fixture equality supplies none of them.
- Process identity/thread fencing and an in-memory `Option<SecNonce>` do not
  provide durable custody, secure erasure or recovery after native owner death.
- A copied SQLite/anchor pair and deterministic native reconstruction defeat
  the local history premise. No independent current or nonrollback authority is
  selected, provisioned or authenticated.
- Parser-selected peers and pinned primitive source do not authenticate worker
  distribution, loaded dependencies, consumed private inputs or runtime closure.
- Real producer death, lost delivery after different persistence cuts, refund
  races, fees, replacements, reorgs and chain finality still need separate work.
- Four independent source inventories and three unfilled reports remain exact.
  No reviewer contact or independent assessment is performed.

See [local validation](STAGE90_VALIDATION.md) and the
[signer/nonce handoff](SIGNER_NONCE_REVIEW_HANDOFF.md). This test bridge advances
integration evidence for deliberately public synthetic keys; it selects no real
signer/custody construction and grants no wallet, funds, chain, release, broadcast,
deployment, activation, merge or core permission.
