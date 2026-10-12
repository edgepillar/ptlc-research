# Dependent receive eviction with explicit state reconstitution

This additive profile qualifies selected offline source behavior at
[45e1bbb48ce6fc19d44c5fbf59ccf5784981fced](https://github.com/zenon-network/go-zenon/commit/45e1bbb48ce6fc19d44c5fbf59ccf5784981fced).
It preserves every prior swap original, funding identifier, inner witness,
source profile, helper and fixture. Application/core remain **NO-GO**.

The upstream PR #138 head inspected for this scope is
`4cf0e443e777c5e386204ab9996a5a91ff982613`. Its one-file, one-comment change
from the qualified source is unchanged from the preceding profile review.
This newer head is not executed by this qualification.

## Selected controls

Three separate, zero-amount plain-account controls use the zero token standard.
They contain no PTLC method, contract opening, inner signature or swap witness.
The disclosed public Ed25519 test seeds are 32 repeated bytes of `0x61`, `0x62`
and `0x63` for sender, recipient and unrelated account respectively. They are
synthetic fixtures. No wallet, entropy, application signer or funds are used.

Each candidate executes actual `Supervisor.GenerateFromTemplate`, then exact
`Supervisor.ApplyBlock` and normal public `AddAccountBlockTransaction` with a
held insertion locker. Generation signs once; exact application signs zero
times and reproduces the original wire and VM delta. Actual source verification
checks the outer signature. Python independently checks the selected protobuf
encoding, account hash, canonical 21,000 cost, legacy budget, received marker,
ordered patches and complete logical state. This is not an independent Python
cryptographic implementation or a construction-security assessment.

All accounts start at empty synthetic stable roots. Legacy fusion is selected
at 20,000,000,000 units, giving a 420,000 Plasma budget. Dynamic Plasma is inactive;
committed-chain Plasma is explicitly zero. These are selected cache responses,
not authenticated on-chain state.

The recipient admits one ordinary send prefix and the unrelated account admits
two ordinary send prefixes acknowledging synthetic momentum M0 at height
10,109,300. The sender admits one send directed to the fixed recipient. Its exact
source-generated, pool-augmented patch is explicitly promoted to a new synthetic
stable root. The global send lookup, confirmation at M1 (height 10,109,301) and
the actual recipient mailbox's unreceived/pending entries are populated.
The mailbox sequencer remains empty because this is a plain user account.

This manual promotion does not execute a momentum VM, verify a producer,
authenticate a committed chain or authorize a real momentum. The actual
`InsertMomentum` event callback rebuilds pending managers on these explicit
roots: the promoted send is no longer pending, while both other prefixes retain
their exact original wires and logical state. Their retained patches include
the source's second ordered frontier augmentation during rebuild.

The sender then admits a second send. The recipient admits a receive referencing
the exact promoted send, followed by a suffix in two of the three controls.
The unrelated account admits a third send. These new candidates acknowledge M1.
The receive's VM delta includes the exact received marker for that send, a zero
balance under the zero token standard, and cumulative fused Plasma. No payment
or public recovery flow is composed with this pool experiment.

## Reconstitution and callback results

Before `DeleteMomentum`, the selected sender stable root is restored to empty,
the global send lookup and confirmation map are cleared, the actual mailbox is
rebuilt empty, and the ledger frontier returns to M0 with M1 removed. The other
stable roots remain empty. This complete caller-selected reconstruction is
separately recorded before the callback. Confirmation lookup is performed for
the exact original send hash even when the send is absent; both global map
cardinalities and complete mailbox state are checked. There is no intermediate
pool read.
The work is sequenced on one thread; caller atomicity and concurrency are not
qualified.

| Control | Included blocks in callback | Recipient after callback | Unrelated account |
| --- | --- | --- | --- |
| `included-send` | Exact promoted send | Entire pending manager removed, including prefix, receive and suffix | Two M0 originals retained; M1 third block removed |
| `included-send-without-suffix` | Exact promoted send | Entire pending manager removed, including prefix and receive | Same two originals retained; third block removed |
| `empty-inclusion-control` | Deliberately omitted send | M1 receive and suffix removed by height truncation; M0 prefix retained | Same two originals retained; third block removed |

The last row is a deliberately incomplete event notification, not a correctly
populated rollback event. It isolates the difference between whole-manager
dependency eviction and height-based suffix truncation. It does not establish
that the production caller omits the send or that a live chain has this state.

In all three controls the sender's pending second send disappears and its
frontier returns to the explicit empty stable root. Exact historical queries
confirm removed originals have neither a version nor a pending patch. Retained
prefixes have their original identifiers, complete historical state and exact
rebuilt patches. Presence of a historical view is not currentness authority.

Across the three controls, 23 candidates pass source generation, exact
application and normal pool admission; two nonempty send callbacks remove the
complete dependent recipient manager; six unrelated originals survive and three
unrelated stale suffix blocks disappear. All 23 post-callback original queries
are independently checked. The new four native outcomes preserve and freshly
rerun all 287 earlier source outcomes, for 291 including parents.

The manifest preserves 91 previous profile inputs, measures the five new inputs
and itself, and pins 67 source/license files. The MIT overlays are independently
written and run virtually over separately obtained unchanged GPL-3.0 core
source. No core implementation is copied into the research implementation.
Every current native attempt retains all four original overlay source copies
before execution. Exact original streams are retained privately.

## Remaining gates and next step

The next bounded scope is selected actual momentum acceptance: exact content
ordering, pool patch application into the actual momentum store, complete
account/confirmation/mailbox effects, changes-hash verification and producer
verification. Event callbacks alone do not qualify any of those acceptance
requirements. Source-valid account blocks alone do not qualify committed state.

Independent source/host authentication, currentness, canonicality, finality,
custody, restore fencing, construction assessment, independent-machine checks
and application composition remain unfilled. There is no post-callback replay,
generation, replacement, signing, journal recovery or recovery permission.
Node initialization, node start, activation, transaction broadcast, deployment
and real funds remain outside this workspace.
