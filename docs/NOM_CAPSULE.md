# Full projection capsule custody

The separate `ptlc-nom-full-projection-capsule-v1` construction retains a full
selected journal projection under a private cooperating POSIX owner. A consumer
compares exact bytes and returns HOLD only. Application and core remain NO-GO;
recovery action is NONE. This is not an application recovery protocol.

## Requirements and selected construction

The research baseline is
`9c77941751f3b6b3f5f6bd5962d4b8b3bd30e751`. All 163 previous measured inputs
remain unchanged. This MIT implementation copies no core code; the independently
obtained GPL core and its 342 selected outcomes remain separate.

The custody requirements are bounded exact-byte encoding, explicit selection,
retention before exposure, one cooperating owner, refusal of replacement and
honest interrupted persistence. Current source/funding authentication, external
work authority, consumer restore fencing and power-loss survival are separate
requirements that this construction does not satisfy.

`encode_capsule` accepts an exact selected `JournalPartialHold`. Its canonical
ASCII JSON envelope retains the full original journal and separate HOLD bytes.
The maximum encoded size is 5 MiB. The source parser and HOLD selection are
replayed structurally; encoding enters no verifier or recovery worker.

`CapsuleOwner.create` requires a nonexistent directory beneath a private owned
parent. It creates a private directory and owner marker, and observes ordinary
file/directory flush returns. It does not adopt an existing directory. Existing
owners are opened read-only and selected with an exclusive cooperating lease.
The owner binds its process, thread, directory identity and marker identity.
Symlink ancestors, linked markers, replacement and nonprivate modes are refused.

`store` creates one fixed capsule with exclusive creation and mode `0600`.
It completes bounded writes, flushes the file, changes the mode to `0400`,
flushes its metadata and then flushes the directory. Only complete successful
calls return a persistence receipt. Existing files are never overwritten.
Failed writes or flushes retain their original partial bytes and poison the
owner until close. No automatic retry, repair or replacement is provided.

The construction publishes a progressively written file under the owner lease;
it does not claim an atomic rename or hostile-writer containment. Cooperating
consumers cannot acquire the same lease during persistence. A separately opened
consumer requires an owned regular file with one link and mode `0400`. Two
bounded descriptor reads, unchanged inode/size/timestamps, matching path identity
and an explicitly selected SHA-256 must preserve the snapshot before exposure.
The consumer opens no legacy journal and enters no worker or history observer.

## What a readable capsule means

A readable view retains full original bytes in memory and reports HOLD. Missing
result and long original stay null. Every persisted charged ordinal stays UNKNOWN.
Challenges select different capsule bytes while preserving research work IDs.
Full journal bytes remain outside the bounded prior-evidence fields. The frozen
pure HOLD review retains its previous mathematics and durability claims.

The producer uses the selected strict opener before encoding. The consumer does
not repeat mathematics and cannot authenticate the producer from copied bytes.
Its review explicitly reports mathematics NOT_PERFORMED and producer origin
NOT_AUTHENTICATED. It offers no complete two-original query conversion.

Readability does not prove a producer receipt, directory flush or power-loss
survival. A process can exit after the readonly-mode change, before the final
flushes, and leave a structurally readable HOLD. A complete old copy can also
pass its own selected digest and shape checks. Neither case supplies currentness,
restored authority, new execution receipts or permission to replenish work.

## Qualification and remaining limits

The separate corpus selects seven actual actor exits with code 73 after capsule
creation, completed writing, first file flush, readonly mode, metadata flush,
directory flush and immediately before producer return. The first three file
shapes are refused; the remaining four can supply HOLD. The unchanged earlier
projection qualifier supplies its five actor exits and 49 public requests.
Fourteen additional actor strict-open requests and four successful-producer
requests select 67 total public requests; consumers enter zero workers.

Ordinary unit fixture matching, fault injection and actual public-worker execution
are recorded separately. Original source/runtime/worker selections and actual
streams must survive failure. The corpus has no new core-source outcome.

Read-only mode and self-hashes do not contain a same-user attacker, hostile
concurrent rewrites, an ABA restore or malicious Python mutation. Atomic
authenticated work admission, native refusal/query pairing, current funding,
independent machine/runtime assessment, interior disk faults and physical power
loss remain unfilled. Storage management does not confer any protocol authority.

See [validation scope](NOM_CAPSULE_VALIDATION.md).
