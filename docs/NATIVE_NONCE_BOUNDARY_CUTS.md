# Acknowledged native nonce-boundary cuts

Status: selected test construction. Local execution evidence belongs to the
validation snapshot; completed hosted evidence belongs to the candidate pull
request. A real signer, entropy/custody construction and independent nonrollback
authority remain UNSELECTED. Application/core progression remains NO-GO.

## Requirements and selected construction

A consumed signing admission must not automatically authorize a replacement
producer when a native computation disappears. A public output may be replayed
only from its retained bytes. These requirements are separate from this test
construction and from its measured execution.

The accepted [five-cut process-death matrix](NATIVE_OWNER_PROCESS_DEATH.md) kills
a public-synthetic native owner before consumption, before the sign command,
after computation, after public delivery and after retention. It does not stop
a live `sign_once` call after nonce removal and before backend entry. This slice
adds a separate integration test, without changing that accepted owner or matrix:

- [Instrumented public test owner](../qualification-native-partial/tests/native_nonce_boundary.rs).
- [Surviving journal coordinator](../tests/native_nonce_boundary_actor.py).
- [Local validation snapshot](STAGE92_VALIDATION.md).

The new test owner is adapted from immutable accepted source
`5c5fd7c771996a13df80da60256f7c31e81cb7cc`,
`qualification-native-partial/tests/native_owner_sigkill.rs`, under the unchanged
root [MIT license](../LICENSE). Its helper block changes only a noop wrapper,
an alternate method signature and two pause callback sites. Removing those
specified additions recovers the exact accepted helper block at SHA-256
`7b4cd1a839ccd895372cea1f3eda9d5685f47f99581ab765c04c0d35eb02bd81`.
This is a changed selected owner copy, not a claim that the full new block is
unmodified. The pinned signing primitive and dependency graph remain exact.

| Acknowledged pause | Executed position | Native backend entries | Local nonce location |
| --- | --- | --- | --- |
| `nonce-removed` | After `Option::take`, before round equality and fault checks | 0 | The live call owns the moved `SecNonce` |
| `before-backend` | After round/fault checks and key selection, before the entry counter and aggregate construction | 0 | The live call still owns `SecNonce` |

The original owner/process/thread checks still precede removal. The second pause
is before both `calls += 1` and the unchanged `adaptor::sign_partial` call.
Neither pause is inside the primitive, during aggregate construction, at a CPU
instruction, or after a partial has been produced. `nonce_present = false`
means only that the owner's Option is empty; it does not mean that the live
stack nonce, key or other copies were erased.

Only four fixed public scopes are accepted: Bitcoin/Zenon and Alice/Bob.
Keys, seeds, messages and expected partials remain deliberately public synthetic
fixtures. There is no arbitrary key import, private-input bridge, nonce
serialization, application signer API, wallet access or chain interaction.
The test harness also constructs unused expected/counterpart owners, so
exclusive custody and secret isolation are not inferred.

## Selected execution and controls

A complete execution of both matrix methods launches twelve native children
and twelve Python journal coordinators:

- Eight children acknowledge one of the two pauses across the four scopes,
  then are killed/reaped with actual SIGKILL exit status. The selected child
  reports an empty owner Option and zero native backend entries at the pause.
  Its surviving coordinator retains live CONSUMED admission, then close/reopen
  produces OUTCOME_UNKNOWN. There is no output, replacement child or producer
  retry. A forbidden callback counter is checked outside exception wrapping.
- Four separate normal-path children acknowledge both pauses, continue through
  the unchanged pinned primitive and equation check, and match the existing
  exact partial fixtures. Their process exits normally after output retention.
  The coordinator checks producer refusal and replays identical recorded bytes
  twice before close and twice after reopen without native reentry.
- In the ordinary test run, the child/helper method executes four additional
  inline public positives and eight separate refusal controls. A changed round
  or the selected before-backend fault consumes the local owner, acknowledges
  only the first pause, enters no backend and refuses subsequent local reuse.
  Normal positives acknowledge both pauses and local reuse remains Spent.
  The copied Panic/WrongKey variants are not selected in this new profile.

The expected subcase inventory is derived from exact source and kept separate
from unique test method counts. The two matrix methods and nonempty helper are
three new Rust IDs. Targeted, full-crate and hosted executions repeat those
subcases; they are not twelve globally unique observations across all runs.
No Python unittest method is added; Rust discovers the new file through the
existing separate-crate command without a workflow change.

Native frames/commands and waits remain bounded. An initialized parent guard
reaps its coordinator and removes the private test directory during normal or
unwinding cleanup. Constructor failure, compromised peers, coordinator/parent
death and orphan containment are not qualified. The native events are trusted
test assertions; an executable path or matching fixture is not runtime
authentication or an admission grant.

## Limits and open decisions

This slice is author qualification with public values. It does not select or
audit real entropy, private signing inputs, secure erasure, persistent custody,
hardware signing, recovery of a secret owner, rollback-resistant authority or
a production swap protocol. Killing a test owner does not repair the retained
copied-history and coherent-restore counterexamples.

All earlier method bodies, primitives, fixtures, journal behavior, fixed
inventories, baselines, source guards and workflow commands/timeouts remain
unchanged. Four fixed independent inventories, the earlier author handoff
packet and three unfilled reports retain their exact subjects. No reviewer
contact or independent assessment is performed.

Source-to-worker and reproducibility remain NOT VERIFIED; private consumed
inputs, producer origin and loaded runtime remain NOT AUTHENTICATED; privacy
remains NOT ASSESSED. Selecting an actual signer/custody construction and its
independent review remains a separate unresolved decision. No release, wallet,
funds, chain, broadcast, deployment, activation, merge or core action follows.
