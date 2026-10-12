# Selected read-only journal partial HOLD projection

The separate `ptlc-nom-journal-partial-hold-v1` profile reads full existing v1
reference-journal custody under an exact `StrictNomRecovery` owner. It projects
only persisted admitted work into the frozen partial HOLD encoding. It supplies
no recovery admission or complete two-original authority-query conversion.
Application and core remain NO-GO; recovery action is NONE.

The research baseline is
`8c4e1d2f63f1ab8d7812a242622b45f32c11f9fa`. The manifest preserves all 158
previous measured inputs, including the strict opener, writer, partial HOLD,
complete query, actor, worker and source/license pins. Their selected claims
remain unchanged. This MIT adapter contains no copied core implementation;
the independently obtained GPL core remains separate and unchanged.

## Selected construction

`project_partial_hold(owner, challenge_hex=...)` requires the exact selected
strict owner. It reads through that owner's existing descriptor using bounded
`pread`, leaves the offset unchanged and replays the frozen parser in memory.
The complete raw bytes, loaded head, sequence, state, terms, pair and role must
agree. A second bounded read and ownership check must preserve the snapshot
before return. The function performs no reopen, close, creation, write, worker
entry, history revalidation or retry. The caller retains ownership on refusal.

The returned immutable object retains the full raw journal in memory and the
separate partial HOLD. The full journal is not packed into bounded prior-evidence
fields; those remain empty. Returned copies cannot mutate the selected object.
The object does not implement a durable export, authenticated receipt or custody
handoff. Its hashes bind selected bytes locally, without authenticating origin.

V1 retains a recovery count, public result and exact originals but no individual
worker execution receipts. For persisted ordinals 1 through that count, the
adapter selects research identifiers with domain
`ptlc-nom-journal-charged-work-v1`, binding the verification-context digest,
exact short-original digest and charged ordinal. Complete terms and pair enter
through the context. Path, time, challenge, result progress, source label and
diagnostic reply do not mint a new work identity. Every work outcome remains
UNKNOWN, even when a retained public result passed strict mathematical checks.
These identifiers cannot authenticate work, prevent copied owners or replenish
an external budget. Zero persisted charges are outside this admitted profile
and are refused, rather than turned into an invented attempt.

Missing result and long original remain null. A reply retained only in separate
diagnostic evidence is ignored. A present long original stays exact; the adapter
never constructs an absent original. Structural validation of an actually
retained original is distinct from constructing missing output.

The strict opener checks present public result mathematics before returning
ownership. The projection calls no verifier. Its wrapper review identifies
that selected open gate separately from the frozen pure HOLD review, whose
mathematics, durability and journal-composition claims remain unchanged.
Neither review grants current funding, execution or chain authority.

## Qualification and limits

The native qualifier retains all source inputs and exact public/Python executable
copies before the first actor or worker spawn. It reuses the unchanged strict
qualification: five actual `os._exit(72)` journals and one separately rehashed
invalid-result copy. Its 34 original worker requests include one expected exit 2.
Fifteen additional actual strict-open requests project four admitted journals
and one coherent old copy, and open the zero-charge journal before projection
refusal. Projection itself enters zero workers. The 49 requests and full
original streams remain distinct from ordinary unit fixture matching.

Two challenges preserve work identities while selecting different HOLD bytes.
Full original journals stay unchanged. The diagnostic returned result at the
pre-append cut remains absent from projection. The coherent admitted old copy
is accepted only as HOLD and exposes the missing restore authority.

The cooperating owner and selected repeated snapshots detect tested growth,
replacement and coherent same-size rewrites after open. They do not contain
hostile concurrent rewriting, an ABA restore, malicious Python mutation or
arbitrary processes. A complete old copy can still pass its own strict open
and projection. Current authenticated source/funding, external durable custody,
consumer restore fencing, atomic authenticated work admission, native refusal
query pairing, interior disk faults, power loss and independent machine/runtime
assessment remain unfilled.

See [validation scope](NOM_JOURNAL_HOLD_VALIDATION.md).
