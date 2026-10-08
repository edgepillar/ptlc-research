# Public-synthetic native owner process death

Status: selected **test-only** construction. A real signer, fresh entropy,
durable secret custody and independent nonrollback authority remain
**UNSELECTED**. Application and core progression remain **NO-GO**. The accepted
parent is `047431b63712de6ed9e0f21061abb6f6ff285fa6`.

## Requirements and selected construction

Signer failure must be separated from journal failure, lost delivery and machine
power loss. Admission, local nonce consumption, signing backend entry, equation
verification, public result delivery, output retention and replay have different
boundaries. A lost result must not authorize another use of the same consumed
admission. These requirements are broader than this construction.

The [new Rust integration file](../qualification-native-partial/tests/native_owner_sigkill.rs)
uses the existing publish-false test crate. Its private owner helper block is
copied byte exact from the [Stage 90 test owner](../qualification-native-partial/tests/native_partial_journal.rs)
at the accepted parent under the root MIT license. Retained unused imports and
fault variants have an explicit test-file allowance; those unused variants are
not qualified by the new methods. This copy adds no shared signer API.

The [new Python coordinator](../tests/native_owner_sigkill_actor.py) owns the
unchanged journal and launches one native libtest child for one fixed role/leg
scope. An external Rust test harness launches and waits for that coordinator.
The native child's only input selection is one of four public fixture scopes;
the selected coordinator sends only the fixed `sign` and `release` tokens. The
child waits for an unused `finish` token after delivery; all matrix children
are killed at their selected cut. There is no arbitrary
key/seed/message import, nonce serialization, wallet or network interface.

All scalar keys and seeds are deliberately public test values. The harness also
constructs an unused test owner to derive the expected public round; the original
`owners` helper constructs an unused counterpart. This is not secret isolation,
erasure or exclusive custody. Only the selected native child performs the
partial-signing operation for a matrix case.

The child emits a `prepared` public event with zero backend entries and its
nonce present. After `sign`, the copied owner consumes its nonce, calls the
pinned native partial primitive, verifies the partial equation, matches the
existing public fixture and refuses a second local use. It then emits `computed`
with one backend entry and no nonce remaining. The public partial payload is
withheld until `release`. These events are assertions from trusted test code;
they are not authenticated admission grants or independent runtime attestation.

## Selected process-death matrix

Two new integration methods cover five cuts for Bitcoin/Alice, Bitcoin/Bob,
Zenon/Alice and Zenon/Bob. **Each execution of the two matrix methods launches
20 Python coordinators and kills/reaps 20 separate native children with actual
SIGKILL.** The journal coordinators exit normally. This is distinct from the
preceding 44 fixture-only journal-child SIGKILL schedules and from Stage 90's
explicit `lost` result command; both preceding constructions remain exact.

| Native child killed at | Callback entries per case | Signing backend entries per case | Reopen status | Output action |
| --- | ---: | ---: | --- | --- |
| Prepared, after reservation but before consumption | 0 | 0 | `RETIRED` | No output or replacement producer |
| Journal `CONSUMED`, before sending native `sign` | 1 | 0 | `OUTCOME_UNKNOWN` | No output or producer retry |
| Computation and equation verification complete, before payload release | 1 | 1 | `OUTCOME_UNKNOWN` | No output or producer retry |
| Public partial received, before callback returns for output retention | 1 | 1 | `OUTPUT_RECORDED` | Exact retained byte replay only |
| Output recorded and producer call returned | 1 | 1 | `OUTPUT_RECORDED` | Exact retained byte replay only |

For the reservation cut, killing the child leaves the live operation `RESERVED`.
The surviving coordinator closes and reopens the journal, whose established
recovery behavior retires that reservation. Death alone does not automatically
retire a live journal operation.

For the two consumed/undelivered cuts, the coordinator observes and reaps
SIGKILL; another read from that selected dead child raises `NativeOwnerDied`.
The existing producer wrapper yields `OutcomeUnknown`. The live operation stays
`CONSUMED`; close/reopen changes it to `OUTCOME_UNKNOWN`. No `lost` command,
replacement native child, deterministic owner reconstruction or producer retry
is used as a recovery path.

For delivery before retention, the callback has already received and checked
the exact public partial. It kills the waiting native child, checks that the
journal is still `CONSUMED`, then returns those retained public bytes. The journal
records them despite the producer's death. The final cut instead kills the
waiting child after `produce_once` has returned recorded bytes. It does not
claim a pause between output commit and caller return.

Across each matrix execution, twelve native signing entries produce twelve
valid public partials. Eight payloads are delivered and recorded, four computed
partials are not delivered, four reservations reopen retired and eight consumed
operations reopen unknown. Recorded outputs replay exactly twice after reopen
and twice before close. Another producer callback remains uninvoked, replacement
reservations with a repeated or new nonce tag refuse, and replay changes no
session snapshot. Refusal assertions remain outside the producer's exception
wrapper. The partial witness-exposure flag retains its existing false meaning;
it is unrelated to secret erasure or nonce custody.

The third new Rust method is also the child entry point. In an ordinary test
run with no child scope selected, it performs four actual public fixture
computations and checks local one-use refusal. It is not an empty or skipped
helper test. Its four positives are separate from the twelve matrix positives.
Child invocations are internal process subcases, not extra top-level test IDs.

## Boundaries, cleanup and open gates

- Native public frames are bounded to 2048 buffered bytes. Only a fixed frame
  prefix and a bounded exact libtest display are accepted. Native commands are
  at most 64 bytes including newline. Native event/death waits have a ten-second
  bound; harness coordinator event/normal-exit waits have a fifteen-second bound.
- Each coordinator retains the exact child process it launched, sends SIGKILL
  to that child, checks the negative SIGKILL exit status, empty stderr and no
  undelivered pending payload, and reaps it before reporting. Initialized native
  and harness guards clean up on normal completion or their own unwinding.
  Construction failure, coordinator/parent death, a compromised host and orphan
  containment are not qualified by these successful schedules.
- The backend-entry count is observed before the call or after its return.
  There is no selected kill inside nonce removal or an instruction within the
  signing primitive. An interrupted in-flight backend, kernel/storage failure,
  power loss, flush truthfulness and persistent secret recovery remain open.
- The Stage 90 copied-history and coherent-restore controls remain separate
  actual deterministic nonce/partial counterexamples. Killing one native owner
  does not provide independent freshness or nonrollback authority.
- The entire original qualification crate, the preceding five native handoff
  methods, all Python tests/actors, fixtures, dependency locks, fixed inventories,
  baselines and source guards remain exact. No CI command or timeout changes;
  the existing separate-crate test command discovers the new integration file.
- Four fixed independent inventories, the earlier author handoff packet and
  three unfilled reports remain exact. No reviewer is contacted and no
  independent assessment is claimed. Source-to-worker and reproducibility remain
  NOT VERIFIED; private consumed inputs, producer origin and loaded runtime remain
  NOT AUTHENTICATED; privacy remains NOT ASSESSED.

See the [Stage 91 local validation snapshot](STAGE91_VALIDATION.md),
[Stage 90 handoff](NATIVE_PARTIAL_JOURNAL_HANDOFF.md) and
[signer/nonce review handoff](SIGNER_NONCE_REVIEW_HANDOFF.md).
This construction qualifies no release, funds, wallet, chain, broadcast,
deployment, activation, merge or core action.
