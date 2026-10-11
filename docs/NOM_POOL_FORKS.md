# Source-valid account forks and the actual pending cap

This Stage 0 profile uses separately obtained, unchanged GPL-3.0 source at
[`45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`](https://github.com/zenon-network/go-zenon/commit/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced),
tree `b8bb3720dd36e6f9ba0537864c18bbb4a001b910`. The research baseline is
`1b8cc453f1bc5753f7995c054d384df1f6d0ad42`. The independently written MIT
overlay copies no upstream implementation. Its complete source snapshots and
original native streams are privately retained before every run.

Protocol requirements, the selected controls, and observed implementation
behavior remain distinct. Pool policy does not establish swap security,
canonicality, finality, custody or recovery permission. Application and core
remain **NO-GO**.

## Separate control subject

Every preceding swap wire, funding identifier, inner witness, fixture, helper,
worker and journal remains byte-exact. These new controls are zero-amount plain
user sends to one fixed synthetic recipient. They contain no PTLC method or
inner witness, change no original funding under an existing witness, and access
no wallet or real funds.

The sole signer is the public test key obtained from the repeated `0x51` seed.
Its public key is
`c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a`.
The recipient public key derives from a separate disclosed repeated `0x52` test
seed. These keys have no application role. Each selected candidate is produced
by the actual `Supervisor.GenerateFromTemplate`, signed once, then reproduced
by actual `Supervisor.ApplyBlock` with identical wire and delta and zero signing
calls. The source verifies each outer signature. Python independently checks
hashes, the selected protobuf encoding, VM deltas, legacy cost and budget; it
does not claim a second cryptographic signature implementation.

One immutable synthetic momentum and empty stable account memory are selected.
The legacy cache supplies a synthetic fusion amount `500000000000`, committed
chain plasma zero and inactive Dynamic Plasma. This is the actual legacy maximum
of `10500000` plasma. No fusion transaction or active network state is inferred.
The pool and actual versioned memory manager are instantiated without `Init`,
`Start` or `ForceAdd`. Normal insertion holds the public insert locker.

## Competing branches

Four controls share a source-valid height-one predecessor. Two competing
height-two sends have one-byte data, canonical base plasma `21068`, and either
equal total plasma or a 2:1 total/base ratio. Two later source-valid blocks form
the old suffix. Both candidates are independently generated and exactly applied
against the retained common predecessor before pool comparison.

Observed normal insertion replaces the lower-ratio branch with the higher
ratio, removes the old height-two block and both descendants, and restores the
common predecessor state before applying the winner. An inferior candidate is
refused without consuming its delta or altering the retained suffix. At equal
ratio, the smaller hash wins in both selected arrival orders. The larger hash
receives the actual `ErrHashTieBreak`. Removed versions and patches are absent;
surviving historical views retain their own exact frontier and state digest.

These controls qualify selected legacy user forks. They do not establish the
Dynamic Plasma comparator, height-one replacement, concurrent producer behavior,
dependency eviction, committed rollback or complete chain admission.

## Actual 500-block boundary

The source global `MaxUncommittedBlocksPerAccount` stays exactly 500. The test
does not lower it, force insertion, forge pricing fields or bypass the supervisor.
A source-valid 501st block must be generated and exactly applied before the pool
refuses it. The refused delta remains intact and its version is absent.

500 all-fused minimum-cost sends exhaust the legacy `10500000` budget and would
confound the pool limit with a VM plasma refusal. Accordingly, the first block
uses a fixed public nonce `b46a980000000000` at difficulty `31500000` and fused
plasma zero. The source and independent Python SHA3 calculation both validate
this witness. Its private acquisition used a bounded deterministic loop over
the public source checker, starting at nonce zero; it called no entropy or wallet
function. The remaining 499 admitted originals consume `10479000` fused plasma,
leaving exactly `21000` for a source-valid 501st candidate.

At the cap, an exact retry of block 500 succeeds idempotently and consumes no
fresh delta. A separately generated height-500 competitor with fused/total
plasma `21001`, canonical base `21000`, and the exact height-499 predecessor
replaces the old height-500 block while the pending count remains 500. Its exact
retry is also idempotent. The rejected 501st candidate is not retried against
the changed predecessor and no replacement is reinterpreted as an old original.

## Independent complete-state comparison

The public corpus retains 522 source-generated candidates, their exact applied
wires/deltas, 519 normal admissions, two priority refusals, two cap duplicates,
one valid-501 cap refusal and 24 historical queries. Six new native test outcomes
follow fresh execution of all 281 preserved source outcomes.

Python separately constructs each expected VM delta and exact ordered augmented
batch, including all three frontier/index writes. It replays every admitted
delta, restores predecessor state for each winning replacement, and compares
complete logical iterator readback at selected checkpoints. Iterated tombstones
are excluded only when actual `Has` confirms absence; present empty values stay
present. No checkpoint is a snapshot's partial changes list.

Pending wire lists are bound in height order by SHA256 over repeated four-byte
unsigned big-endian wire lengths followed by exact wire bytes. All contributing
wires remain in the public candidate corpus. This avoids repeating 500 complete
wires at every checkpoint while independently checking their complete order.
Checkpoint reader bounds are explicit: four MiB, 2048 sorted unique puts,
8192-byte keys/values, canonical lengths and no deletes. Delta and ordered-batch
readers keep their preceding narrower bounds unchanged. Each native record is
bounded to eight MiB, with complete source framing required.

## Remaining acceptance gates

Pending or historical memory observations are not authority for recovery.
Source identity, host qualification, retained-original custody, observation
currentness, authenticated ledger facts, canonicality, finality, restore fences,
construction security and independent assessment remain separate requirements.
The preceding historical child aliases remain unchanged observations, with no
upgrade to currentness. No post-callback recovery uses unreconstituted ledger or
mailbox inputs.

Next, select dependency eviction and momentum acceptance with explicit stable
state, original ownership, confirmations/mailbox reconstitution and rollback
ownership. Preserve exact original hashes throughout unknown outcomes. Keep all
session, transport, Bitcoin construction and application recovery outside core.
