# Durable local authentication pins

Stage 10 binds an optional pair of public authentication keys when a managed
Bob exchange starts, then reconstructs the Stage 9 envelope context from that
stored pair and the exchange's validated terms. It provides local continuity
across reopen. It does not enroll a peer, enforce authenticated admission or
authorize a public witness-recovery observation.

## Configuration and reconstruction

`start_exchange` keeps the required `recovery_limit` and adds optional
`authentication_pins`. Omission or `None` selects no pins. A configured value is
an exact plain dictionary with two exact plain strings:

```text
{
  "alice_auth_key_hex": <32-byte lowercase x-only public-key hex>,
  "bob_auth_key_hex": <32-byte lowercase x-only public-key hex>
}
```

Supply the pair through trusted local policy, never by adopting fields from an
incoming envelope. Key establishment, secure provisioning and compromise
recovery remain external assumptions. The journal copies and validates the
pair using the [Stage 9 context factory](COMPLETION_AUTHENTICATION.md). It
rejects equal pins and overlap with explicit swap-key x-coordinates. Python
does not validate curve membership; the actual Rust verifier parses both keys
when a message is verified. Stored encoding validity is not proof of a usable
or trustworthy authentication key.

The full authentication context is reconstructed from the managed exchange's
stored Bitcoin signing context and its terms, plus those two pins. The journal
does not accept a caller-supplied expected authentication context on later use.
Session and terms commitments already have to match the complete stored
exchange. No parallel mutable copy of roles, purpose or participant IDs is
introduced.

Start commits the exchange, recovery allowance and copied pins together in one
state snapshot. Once Bob mode exists, both the configured pair and the choice
of no pins are frozen. The persistence continuity guard rejects adding,
replacing or removing pins, replacing the stored Bitcoin context or terms,
removing the session, or switching away from Bob mode. There is no late setup,
rotation, downgrade or reset API. Generic and Alice sessions require null pins.
These are local continuity checks under an honest host, not authentication of
arbitrarily rewritten storage or protection against a malicious interpreter.

## Journal-scoped verification

`authenticate_exchange_envelope(session_id, envelope_bytes, verifier=...)`
requires a managed Bob session with configured pins. It is available at every
Bob stage because it returns no admission authority. It rebuilds the expected
context from stored state and uses the existing strict envelope parser and
request-bound public verifier. Successful output is the helper's own retained
exact opaque payload bytes, not a worker-selected replacement.

The existing process/thread ownership check and active-callback guard cover
reconstruction, verification and return. Reentrant mutation, nested journal
authentication and close are refused; read-only snapshots remain available to
the owner. Ownership is checked again after the callback. Ordinary verification
failures become `Conflict`; an invalid callable is `InvalidInput`. Explicit
`KeyboardInterrupt` and `SystemExit` propagate while the guard is cleared.

Neither success, rejection, cancellation nor replay writes a receipt,
observation, counter, exposure flag, stage, sequence or checkpoint. This is a
stateless verification operation over durably selected inputs. It must not be
reported as a retained authenticated observation. Repeated authentication can
perform repeated work and remains outside Bob's recovery allowance.

## Persistence and compatibility

Journal storage and digest domain advance to v7. The session gains nullable
`authentication_pins`; versions 1 through 6 quarantine without migration or
modification. Envelope, transcript, artifact, completion and verifier schemas
remain unchanged, as do all cryptographic fixtures and dependencies.

The existing database-then-checkpoint ordering still applies. A start crash
before database commit retains the previous generic session. A database commit
without its matching anchor quarantines on reopen. Once both copies match,
reopen retains the complete Bob start and pins. Killing a read-only verification
does not create a journal commit or consume an allowance. Process termination
tests do not establish power-loss behavior.

Restoring both matching earlier files remains undetectable. In particular,
restoring the pre-start session can erase the local choice and permit a fresh
start with different pins. A digest is not a MAC or an external monotonic
trust anchor. This milestone does not solve rollback, clone protection, trusted
pin bootstrap or independent key generation.

## Recovery and exposure boundaries

Ordinary public recovery and explicit reconciliation remain callable with or
without configured pins and with no auxiliary envelope. This is intentional
offline qualification, not a trusted chain-observation interface or an
authenticated inbox policy. Successful envelope verification still does not
make the inner Zenon signature valid, establish freshness, or select a recovery
candidate. The existing recovery APIs apply their own validity and allowance
rules when called separately.

The helper does not record witness exposure even when it returns bytes. A
false exposure flag is not proof that a witness has stayed private. Conversely,
rejected outer authentication cannot establish that the inner public signature
was undisclosed, clear an existing exposure marker or justify signing again.

Alice could publish a valid Zenon signature while withholding its authentication
envelope. A future peer-message admission policy must therefore remain distinct
from independently authorized recovery of a publicly observed witness. Define
those policies, evidence retention, admission/resource controls, compromise and
rotation handling before enforcing any envelope requirement. Private signing,
authenticated chain observations and a funded timing policy remain unimplemented.
Live swaps and a core port remain no-go.

Stage 11 explores these admission questions in a separate
[bounded policy model](RECOVERY_ADMISSION_MODEL.md). Its counterexamples do not
change this helper or enforce a new journal policy.
