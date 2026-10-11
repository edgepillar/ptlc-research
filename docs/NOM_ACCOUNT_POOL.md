# Selected account-pool admission and historical views

This separate profile preserves the exact Supervisor originals selected at
`3cefef0efeab8d2d8424f8fd4f604edb91a2b85b`. It introduces no new funding id,
inner witness, public signing key or application signing. Application and core
remain **NO-GO**. A pending pool result or accessible historical view grants no
recovery permission.

The independently written MIT overlay executes separately obtained, unchanged
[go-zenon source](https://github.com/zenon-network/go-zenon/tree/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced)
under GPL-3.0. Its selected paths are the public `NewAccountPool`, normal
`AddAccountBlockTransaction`, `GetAccountStore`, `GetPatch`, pending enumeration
and a public `DeleteMomentum` callback. The real source versioned memory manager
owns pending versions. No source implementation or source tests are copied.

## Selected execution and limits

Two cases reproduce all 22 original transactions through `Supervisor.ApplyBlock`
on actual pool predecessor views. Every returned wire and transaction delta must
match the preserved corpus before one normal admission under a held insertion
mutex. Initial user token budgets and the empty contract database remain unchanged
stable inputs. Synthetic momentum, confirmation, legacy fusion and mailbox views
are explicit selections, not a committed chain or authenticated source.

| Selected action | Count | Required observation |
| --- | ---: | --- |
| Normal admission | 22 | Source consumes the transaction changes and stores its augmented patch |
| Exact original duplicate | 22 | PASS without consuming another delta or changing state |
| User duplicate with only advertised changes hash altered | 13 | Same identifier, different wire, PASS with the stored original preserved |
| Missing insertion locker | 2 | Refusal, no consumed delta or adopted effect |
| Selected stale acknowledgement callback | 2 | Truncate the pending suffix at height 10109301 |
| Child lookup immediately after parent admission | 4 | Requested child returns the full parent version |
| Post-callback version queries | 26 | Exact retained, removed or aliased results remain distinct |

The source manager appends three frontier writes for each child and parent to
the transaction batch. Repeated frontier keys retain their order. A separate
bounded Python reader compares every operation and independently replays it
against the entire observed logical state. The preserved unique-key delta reader
is unchanged. Logical iteration skips source iterator tombstones only after the
actual public `Has` method confirms absence; present empty values are retained.
This qualifies synthetic memory equality, not an authenticated state proof.

## Identifier idempotence and exact originals

The selected account hash excludes the advertised `ChangesHash`, as explicitly
documented in the pinned source. Direct pool insertion of an already present user
identifier succeeds even if those advertised bytes differ. The observed stored
wire stays equal to the original and the duplicate delta remains unconsumed.
This is an idempotence observation, not proof that supplied bytes were identical.

The preceding Supervisor profile already observed a freshly applied user block
with changed advertised metadata returning a computed delta without adopting it.
This profile changes no receiver, amount, inner witness, signature or funding id,
and makes no full-chain vulnerability or admission classification. Exact original
custody still requires its own wire bytes and their digest.

## Historical child aliases and selected truncation

Immediately after an embedded batch is admitted, requesting its child version
returns a store whose frontier is the parent. Its pool patch is present but empty.
That store contains the complete post-parent state, rather than a state whose
frontier is the requested child.

The selected public callback declares a popped synthetic momentum at 10109301,
a current selected momentum at 10109300 and **zero included account blocks**.
It truncates every pending suffix acknowledging the popped height or above.
Only the original funding blocks and the two Create parents remain pending;
their exact bytes remain unchanged. Pending user balances and contract entries
return to the pre-Unlock versions. Stable input databases are never modified.

Removed parent and user version lookups become unavailable. Four child aliases
remain accessible with their old parent frontiers and old post-parent state even
though those parents are absent from the pending enumeration. They are explicitly
historical aliases. A non-null lookup or present empty patch cannot establish
currentness, canonical ancestry, finality or recovery permission. The corpus
requires the alias mismatch; replacing it with an exact-child or current-state
claim fails qualification.

This callback is not `chain.RollbackTo`, authenticated momentum validation or a
complete rollback. The selected confirmation and mailbox inputs are not rebuilt
into a post-rollback chain. No subsequent signing, receive, reconciliation or
journal mutation runs against those inputs.

## Caller review and next acceptance gates

Read-only source review finds the pinned RPC route converts a raw block and calls
`Supervisor.ApplyBlock` before the broadcaster acquires insertion and calls the
pool. The peer bridge skips identifiers with an existing patch, skips standalone
contract sends, then applies other blocks before normal insertion. Its separate
forced insertion path is outside this selected execution. The momentum VM uses
pool patches and the momentum verifier checks its computed state commitment.

These caller paths were read, not executed. They do not transfer their checks to
this corpus. Source references:
[RPC](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/rpc/api/ledger.go),
[peer bridge](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/protocol/chain_bridge.go),
[broadcaster](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/protocol/broadcaster.go),
[pool](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/chain/account_pool.go),
[manager](https://github.com/zenon-network/go-zenon/blob/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced/common/db/versioned_db.go).

Next, qualify competing source-valid account branches, resource-cap behavior,
dependent receive eviction and actual momentum acceptance with explicit stable
state and rollback ownership. Then qualify exact subject re-observation against
an authenticated current source before composing it with durable recovery.
Dynamic Plasma, source authority, canonicality, finality, original custody,
restore fencing and independent construction review remain separate unfilled
gates. Existing journals, workers and application cryptography are unchanged.

The execution pin remains `45e1bbb48ce6fc19d44c5fbf59ccf5784981fced`. The later
PR #138 head `4cf0e443e777c5e386204ab9996a5a91ff982613` was previously compared
as a single comment change and has not received exact-head execution here.
Neither source review nor this corpus proves merged or activated PTLC capability.
See the [validation record](NOM_ACCOUNT_POOL_VALIDATION.md).
