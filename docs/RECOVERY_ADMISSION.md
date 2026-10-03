# Durable allowance for Bob public recovery

Status: offline local resource policy introduced in journal v6; current storage is v7. This is not authenticated peer admission, a global rate limit or a safe funded-swap recovery policy. No authentication key provisioning, rotation or transport construction has been selected by this change.

## Scope and configuration

Bob's ordinary completion and explicit reconciliation both invoke potentially repeated public cryptographic recovery. The [bounded worker transport](PUBLIC_WORKERS.md) limits one subprocess invocation, but does not limit how often the journal calls it. These two journal APIs now share one durable allowance:

```python
journal.start_exchange(session_id, bitcoin_context, recovery_limit=3)
```

The keyword is required. The caller must choose an exact integer from 1 through 64; booleans, floats, zero and unlimited sentinels are rejected. Three is an illustrative test policy, not a production recommendation. The upper bound is an offline implementation bound, not a cryptographically derived safety parameter.

The session stores `recovery_budget = {"limit": N, "consumed": 0}` when Bob mode starts. Generic sessions and Alice completion sessions keep this field null. There is no refill, reset or limit-change API. Ordinary recovery and reconciliation share the same count across reopen. Getters return defensive copies; they do not grant mutable access to the allowance.

Initial artifact verification, Alice completion, pure reducers and direct worker calls are outside this allowance. New sessions, independent journals and restored copies can also bypass a per-session count. The caller and host remain trusted. Participant identifiers and role labels still do not authenticate a peer.

## Admission before computation

Both APIs validate callable adapters, stage, exact packet encoding and the complete signing context before charging. Reconciliation additionally requires a different packet and the exact original-observation digest. Malformed packets, wrong stages, stale comparison digests and implicit replacements do not consume an attempt. This free structural work is itself not protected by the allowance.

If `consumed == limit`, a structurally eligible call raises `RecoveryExhausted` before changing the observation or invoking recovery. Otherwise the journal adds one to `consumed`, commits the resulting snapshot and matching checkpoint, and only then invokes the trusted recovery callback:

- Ordinary completion includes the retained candidate and possible-exposure marker in the same admission snapshot. Omitting the packet retries that exact candidate and consumes another attempt.
- Reconciliation persists only the allowance change before recovery. The original candidate remains authoritative. A positive result then commits the completed replacement, original archive and Bitcoin output in a second snapshot.

Rejected or exceptional callbacks, malformed results, transport failures and interruption never refund an admission. The count measures admitted attempts, not proven worker invocations: a crash after admission can spend a slot before the worker starts. Failure is not evidence that a candidate is invalid. The allowance cannot authorize implicit replacement, clear exposure or reenable Alice's producer.

Admission persistence runs outside the callback exception catcher so a durability failure remains a quarantine result. Ownership and mutation guards cover preflight, admission, callback and output persistence. The final result is applied to the current snapshot, preserving the consumed count. Successful exact output or release replay invokes no worker and consumes no allowance.

## Stored invariants

Limits and counts use exact integers, with `0 <= consumed <= limit <= 64`. A Bob budget exists exactly when managed Bob exchange state exists. Consumption is zero before release; a retained completion candidate exists exactly when consumption is positive. Completed Bitcoin output therefore requires at least one admission. A superseded-observation archive requires at least two: one to retain the original and another to reconcile it.

Persistence checks continuity against the currently owned snapshot. An existing Bob session or budget cannot disappear, its limit cannot change, and consumption cannot decrease or advance by more than one in one commit. A newly configured budget starts at zero. These checks detect accidental stale-state publication through this journal; they do not resist arbitrary filesystem rewriting or modification of the implementation.

## Process death and storage gaps

Every snapshot still uses a database commit followed by a separate checkpoint replacement. The two files do not form one atomic transaction. Reconciliation now has an admission snapshot and, after positive verification, a result snapshot.

| Interruption | Reopened outcome |
| --- | --- |
| Before admission database commit | Previous allowance and protocol state; no worker invocation |
| Admission database committed without matching checkpoint | Quarantine; no automatic repair or worker retry |
| Admission and checkpoint matched, before worker | Attempt remains consumed; ordinary candidate retained or reconciliation original preserved |
| During recovery or before result database commit | Attempt remains consumed; no durable completed output; another admitted public retry needs remaining allowance |
| Result database committed without matching checkpoint | Quarantine |
| Result and checkpoint matched, including before return | Exact completed output replay; no new admission |

Process kills do not establish power-loss durability. Restoring both matching pre-admission files remains undetectable and can replenish the allowance. The existing joint-restore limitation also remains relevant to Alice's one-use synthetic producer; this change does not repair secret ownership.

## Availability and compatibility

Invalid observations can consume the final slot and prevent a later valid recovery. Exhaustion is an intentional local stopping condition, not proof of swap failure, safe refund, or permission to start over. A real funded application needs a separately reviewed availability, emergency recovery and authenticated admission policy before using such a limit.

The separate [Stage 11 admission model](RECOVERY_ADMISSION_MODEL.md) explores
this blockage, including authenticated invalid inputs and interrupted public
work. It changes neither the journal allowance nor its admission rules, and it
does not select a funded-swap exhaustion policy.

Stage 8 advanced journal schema and digest domain to v6. Current v7 adds optional [durable authentication pins](DURABLE_AUTHENTICATION_PINS.md); versions 1 through 6 are quarantined without modification or migration. Public packet/result schemas, cryptographic inputs and fixture signatures are unchanged. See [Stage 8 validation](STAGE8_VALIDATION.md) for executed tests and remaining gates.
