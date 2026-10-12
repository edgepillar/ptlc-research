# Actual batched content and memory rollback caller

This additive offline profile joins the public account-pool content selector,
actual momentum VM and store, public momentum-pool insertion and rollback,
and registered account-pool listeners at the selected unchanged core commit
`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`. It does not authenticate a
chain, authorize recovery or qualify an application. Application and core
remain **NO-GO**.

The source is separately obtained GPL material. Both virtual overlays are
independently written MIT research code; no upstream implementation is copied
or patched. The manifest binds 79 source/license files and all 103 preserved
profile inputs. Every previous funding, inner witness, receipt and failure
remains unchanged. The earlier momentum-admission profile is freshly rerun
before this profile's seven additional native outcomes, for 313 outcomes
including parents.

## Selected construction

The initial memory root is an explicit Python projection of the preserved
`complete` Supervisor corpus: Alice's account after the original short unlock
send, Bob's account after short funding, and the shared PTLC account after
both Create receives. Global headers, selected confirmation heights, mailbox
ownership, complete contract sequencer and synthetic momentum entries are
selected inputs. They are not acquired from an authenticated chain.

The exact preserved short Unlock contract parent is applied by the actual
Supervisor. Its original child, parent, VM delta and inner witness bytes must
remain identical. Normal account-pool insertion produces an empty child patch
and a parent patch with the ordered child and parent frontier writes. The
actual `GetNewMomentumContent` returns child then parent. The driver has only
one pending account at selection, so no claim about cross-account map order is
made.

The actual Supervisor generates and exactly applies a momentum containing
those selected headers. Python separately projects the complete VM delta,
account roots, global headers, confirmations, balance index and mailboxes,
then independently encodes the momentum hash and protobuf. The public
`NewMomentumPool` performs insertion and its own prefetch. Three listeners are
registered in order: a stable-state observer, the actual account pool, and a
pool-state observer. No callback content is manually invented.

The actual source refuses the preserved old receipt: it acknowledges synthetic
height 10109301 while the child is now actually confirmed at 10109302. The
receipt is preserved, signs zero times and is never inserted in this profile.
This demonstrates why old synthetic context cannot establish admission in a
newly composed context.

Two fresh, separately labeled public memory controls then acknowledge the
actual inserted momentum: an Alice receive for the exact child and a later
zero-amount send. Both are generated and exactly reapplied by the Supervisor.
An unrelated zero-amount send explicitly acknowledges the retained synthetic
anchor. Only disclosed public test seeds 0x41, 0x61 and 0x64 are used. These
controls do not replace any original swap or perform application signing.

## Verified selected behavior

Public `RollbackTo` prefetches child and parent before popping the actual
memory manager. Its first delete observer sees the exact original stable root
already restored. The actual account-pool listener then removes the dependent
receive and its later suffix; the unrelated original remains byte-identical
with its original patch. Contract parent/child and removed receive aliases
cannot remain eligible. The final observer checks complete pool and stable
state.

Both the rolled-back send and stale acknowledgement conditions apply to the
fresh dependent controls. A unique eviction cause is not established. The
important caller observation is that the actual callback includes the child
as a top-level entry as well as inside its parent. A manually parent-only
callback cannot be substituted as evidence about this caller.

Five refused controls bind complete stable/pool checkpoint digests: missing
insertion locker, missing rollback locker, mismatched target height,
mismatched target hash, and the old receipt. All emit no callbacks, preserve
state and sign zero times. The height mismatch selects an existing retained
momentum with the wrong hash; it does not qualify missing-target behavior.
Seven fresh previous-store queries identify the exact selected anchor. Source
transaction checks verify public synthetic signatures; an independent Python
signature implementation is not supplied.

## Remaining acceptance gates

The PTLC account cache is explicitly selected while the actual spork store is
empty. This is a synthetic reference setup, not evidence of network spork
activation or canonical cache construction. Elected producer responses,
genesis and state provenance, canonicality, finality and original custody
remain unfilled. Single-threaded memory execution does not qualify persistent
manager recovery, concurrency, a node process, or the maximum momentum batch
boundary. Durable journal composition and restore fencing remain separate.

Next qualify the content-cap boundary and intact batches with independently
controlled selected states. Then evaluate persistent manager/caller failure
behavior without activating a node. Deployment, wallet access, broadcast,
real funds, application cryptography and protocol security assessment remain
outside this profile.
