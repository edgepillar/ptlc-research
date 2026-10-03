# Offline transcript and public-output journal

Status: experimental local qualification, now including [managed Bob exchange](ARTIFACT_EXCHANGE.md), the [Stage 5 Alice/Bob completion lifecycle](COMPLETION_LIFECYCLE.md), and [Stage 6 explicit reconciliation](OBSERVATION_RECONCILIATION.md). This module has no wallet, signing backend, transport, RPC, broadcaster or node integration. It stores public synthetic commitments and output bytes. An explicitly selected public verifier checks the managed flow's artifacts. It does not serialize a cryptographic library's secret nonce object or implement secure key storage.

## Staged session commitments

`offline_session.transcript` separates agreed terms, actual Bitcoin funding/message bindings, actual Zenon entry/message bindings, and role-specific operation contexts. Bitcoin signing does not depend on a Zenon entry that has not been created yet. The Zenon stage extends the Bitcoin commitment after the concrete entry ID becomes available.

Each stage uses strict, versioned fields and a distinct hash domain. Encodings are canonical ASCII JSON with exact integer and hexadecimal rules. Inputs are copied into immutable snapshots; returned dictionaries are copies. Changing a participant, network/genesis identity, amount, key, destination, refund condition, funding object or signed message changes the relevant context or is rejected when inconsistent with earlier terms.

The journal accepts only a revalidated signing-context object, derives its purpose from that object and requires the same terms commitment as the stored session. The first reservation also pins the Bitcoin binding for the session; the first Zenon reservation pins its Zenon binding and must use that same Bitcoin predecessor. All later roles/purposes must use those exact stage commitments. Per-operation hashes alone would allow different operations to refer to different deposits in one session. The supported purposes are:

| Purpose | Role | Binding | Exposure treatment |
| --- | --- | --- | --- |
| `bitcoin-claim-partial` | Alice or Bob | Bitcoin | No witness-exposure flag implied by this metadata operation. |
| `zenon-claim-partial` | Alice or Bob | Zenon | No witness-exposure flag implied by this metadata operation. |
| `zenon-claim-complete` | Alice | Zenon | Possible exposure is persisted before invoking the producer. |
| `bitcoin-claim-complete` | Bob | Bitcoin | The model assumes the witness is already available to Bob; it is not stored here. |

The application context hash is not substituted for a Bitcoin sighash or Zenon's contract message. The Zenon binding independently recomputes SHA3-256 of the entry ID and destination. Bitcoin transaction IDs/sighashes and curve-point encodings are supplied public inputs here; this Python module does not reimplement or execute their cryptographic validation. The separate Stage 1 harnesses check the shared synthetic examples.

Commitments do not authenticate a counterparty or prove funding, finality, agreement, pre-signature validity or sufficient time to reveal. Those checks remain mandatory before a future application authorizes a producer. Stage 3 adds an optional fully reconstructed [public nonce round](NONCE_ROUNDS.md) to signing contexts. Legacy static contexts remain for qualification, and a leg cannot mix static and nonce-bound operations. These factories are not a complete interactive MuSig session implementation.

On the first reservation for a leg, `signing_rounds` records its exact nonce-round digest, or `null` for static mode. An absent leg is unpinned. Every subsequent role and purpose must match; completion cannot switch the round used for partial signatures. Dynamic rounds also record ordered hashes of the full Alice/Bob public nonce encodings in `signing_round_nonces`. Identical encodings already assigned to another visible session/leg are rejected. Repeated operations within the same pinned round remain possible for its different roles/purposes. This public-byte history does not prove fresh randomness, secret ownership, or uniqueness outside this journal.

## Exclusive ownership and persistence order

The journal uses persistent POSIX advisory locks for the directory and separate checkpoint before loading mutable state, and holds ownership through the complete context lifetime. Companion lock files are not deleted or replaced on close. A second writer fails immediately. The instance is bound to its opening process and exact thread; a different thread cannot operate or close it. Inherited use after `fork` is rejected; child cleanup must not unlock the parent's open file description.

SQLite stores a canonical public-state snapshot and its version, lineage, sequence and digest. A separately stored checkpoint outside the journal directory records the corresponding head. Opening recomputes the actual state digest and checks the checkpoint; comparing only two stored digest fields would miss payload changes.

The current storage schema and digest domain are version 7. Opening versions 1 through 6 quarantines them without modifying either copy. No automatic migration or reset is provided. Transcript schema v1 remains unchanged; optional nonce-bound contexts extend it while historical static context bytes remain identical.

For each mutation the database commit precedes checkpoint replacement. The checkpoint is written to a temporary file, flushed, atomically replaced and its parent directory synchronized before success is returned. This is deliberately **not** presented as one atomic transaction across two files. An interruption in the gap can leave mismatched heads, which cause quarantine instead of automatic repair or another producer attempt.

SQLite and filesystem synchronization rely on the operating system and storage stack. SQLite describes these assumptions in its [atomic-commit documentation](https://www.sqlite.org/atomiccommit.html) and [synchronization pragmas](https://www.sqlite.org/pragma.html#pragma_synchronous). The Python [flock interface](https://docs.python.org/3/library/fcntl.html#fcntl.flock) supplies advisory ownership, not access control against a compromised host. Process-termination tests do not simulate a power cut, a lying flush implementation, all network filesystems or a kernel failure.

## Reservation and output lifecycle

The lifecycle below applies to the original generic synthetic producer. A fresh session may instead enter managed Bob exchange or managed Alice completion before any generic reservation. These three modes are mutually exclusive. Managed sessions cannot use generic reserve/produce/replay operations; verifier calls, transitions and persistence remain under the same mutation/ownership guard. Stored exchange contexts supply that session's binding/round/nonce pins and must match them on reload. See the [managed state machine](ARTIFACT_EXCHANGE.md) for retention/release and the [completion lifecycle](COMPLETION_LIFECYCLE.md) for Alice consumption, retained Bob observations and public-input recovery. A failed Bob recovery may retry its exact retained public input; explicit reconciliation additionally accepts a different positively verified candidate while preserving the old packet. An uncertain Alice producer may not run again.

Managed Bob start now requires an explicit `recovery_limit` from 1 through 64. [Stage 8 admission](RECOVERY_ADMISSION.md) durably consumes one shared allowance before ordinary recovery or reconciliation, including unsuccessful attempts. Retry therefore also requires remaining allowance. Exact output/release replay costs nothing. Initial artifact verification and Alice's producer/completion path are not charged by this Bob-only policy.

[Stage 10](DURABLE_AUTHENTICATION_PINS.md) adds optional authentication pins at Bob start. The pair, its absence, stored Bitcoin context and terms are immutable after that start. `authenticate_exchange_envelope` reconstructs context from those stored inputs under the existing ownership guard; success, failure and replay write nothing. This helper neither observes a completion nor changes possible exposure or recovery admission. Raw recovery/reconciliation remain available without an envelope. Restoring both pre-start files can erase the local choice.

```text
RESERVED -> CONSUMED -> OUTPUT_RECORDED
    |          |
 restart    uncertain producer or restart
    |          |
 RETIRED   OUTCOME_UNKNOWN
```

A reservation binds an operation ID, session, role, purpose, full context digest and globally unique public nonce tag. The tag is an opaque test identifier, not a nonce value or proof of fresh cryptographic randomness. The journal additionally seals each session/role/purpose on its first reservation. A different operation ID, context or nonce tag cannot restart that operation after uncertainty or retirement. Replacement and fee-bump signing need a future reviewed policy; there is no reset API.

`produce_once` first consumes the reservation durably. For a revealing Zenon completion it also records possible exposure before any callback runs. Only after both database and checkpoint persistence succeed does it invoke the local synthetic producer. The resulting public bytes are persisted before returning them. If a producer raises or the result/persistence is uncertain, the reservation cannot be used again.

The callback is trusted local computation: it must not transmit, broadcast, log private material or independently use a signing nonce elsewhere. This wrapper cannot prevent side effects inside an arbitrary callback. Qualification callbacks return public bytes and, in process-death tests only, write a public invocation-count marker. No real signing function is wired into this interface.

After reopening, reservations from the previous process are retired and consumed operations without a recorded output become `OUTCOME_UNKNOWN`. No secret nonce is reconstructed. `replay` returns only the exact previously recorded output for the same validated context; it does not invoke the producer or resend anything. Returning a replayable artifact is not authorization to broadcast it.

Observation changes and reorg markers do not erase possible exposure. This is a monotonic local record under the stated checkpoint assumptions, not a claim that the application knows whether another participant actually learned the witness.

## Rollback detection has a precise limit

Restoring only the database, restoring only the checkpoint, replacing one with another lineage, or changing a valid SQLite payload without its corresponding checkpoint causes a mismatch. Missing, corrupt or unsupported state is not silently replaced with an empty journal.

Restoring **both** the database and its matching old checkpoint is indistinguishable from the earlier state. The tests explicitly demonstrate this limitation. Keeping the checkpoint outside the database directory offers logical separation, not a trusted hardware counter, independent physical failure domain or remote witness. A complete backup rollback or clone can defeat this local history check. Production anti-rollback and safe nonce ownership across replicas remain unresolved.

The module assumes a trusted local directory and cooperating writers. It does not resist arbitrary changes by a process with equal filesystem privileges, prevent all path replacement races, or protect against a compromised application. It does not identify or recover a missing valid output from an ambiguous cryptographic computation.

## Executed evidence and next work

See [STAGE2_VALIDATION.md](STAGE2_VALIDATION.md) and [STAGE3_VALIDATION.md](STAGE3_VALIDATION.md) for historical cases, [STAGE4_VALIDATION.md](STAGE4_VALIDATION.md) for retention/release, [STAGE5_VALIDATION.md](STAGE5_VALIDATION.md) for completion, and [STAGE6_VALIDATION.md](STAGE6_VALIDATION.md) for current reconciliation results. The process tests terminate actual child processes at commit/producer/output boundaries, rather than treating an in-process exception as equivalent to process death. Both kinds of failure are tested separately; matrices cover generic static/nonce-bound operations, managed artifact retention/release, Alice consumption/output and Bob observation/recovery/output.

Before a real signer is attached: implement authenticated exchange and validated artifact order, review the backend-specific secret-nonce owner and its durable worker boundary, define protection against restored copies, bind actual chain observations and timing decisions, and independently assess the resulting protocol. The separate Rust owner remains test-only and ephemeral. A local SQLite record is not a replacement for those requirements.
