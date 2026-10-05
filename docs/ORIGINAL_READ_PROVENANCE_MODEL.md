# Bounded original-read provenance and delivery model

This isolated delta targets `76d7b30fa5918a4ecd7c2a11f08b9a1c4ac7001f`.
It compares expectation binding, response delivery and ideal protected entry.
It changes no application module, sampler, worker, signature framing, fixture,
store, journal, dependency, frozen inventory or independent report.

## Requirements, construction and evidence

| Layer | Statement |
| --- | --- |
| Protocol requirement | Independently select the complete root/source/incarnation, original id/revision/historical profile/proposal, both heads and challenge. Establish authenticated authority for the resulting observation and the current-use boundary separately from signature validity. |
| Selected construction | A pure finite Python model uses opaque complete-object symbols, two readers, separate sample/deliver/verify/entry events, and an external truth/entry audit outside coherent source restore. |
| Verified implementation behavior | Directed tests project all ten unchanged public samples and six signed counterclaims into the model, recreate the ten owned stores, and replay every reported witness. Selected schedule shuffles compare three entry policies. |
| Signature premise | The model performs no signature mathematics. Its valid-signature symbols refer to the named public fixtures checked by the existing isolated worker in the [sample-to-message qualification](ORIGINAL_READ_SNAPSHOT_SIGNATURE_BINDING.md). The unchanged actual-worker suite remains a separate CI step. |
| Ideal entry premise | Independent current original and policy facts, available source, an entry-eligible pending record, and serialized nonrollback entry history. There is no implemented provider or adapter for these premises. |
| Open requirement | Authenticate source and current heads, historical issuance and full original provenance, private lookup authority, signer custody, nonrollback retention and authorized administrative transitions; define authoritative recovery and physical-use ordering; obtain independent assessment. |

Matching a complete independent expectation can prevent a peer replacement. It
cannot make an expectation selected from restored or compromised local state
authoritative. The model's external truth and nonrollback audit are assumptions,
not facilities added to the owned SQLite store. The model emits no capability.
`snapshot-bound` is a qualification oracle with a separately owned sampled
claim. It is not a deployed lookup protocol that independently learns response
truth. A real lookup needs an authenticated authority for an initially unknown
observation; this model implements no such authority.

## Binding policies and fixture correspondence

The [model](../scripts/model_original_read_provenance.py) compares three read
bindings. `peer-selected` trusts the incoming statement's own selection.
`query-bound` checks the complete independently selected query but accepts a
different claim under that query. `snapshot-bound` checks both query and complete
owned claim. All normally require the explicit symbolic signature premise.

The [tests](../tests/test_original_read_provenance_model.py) map complete root
declarations, complete profiles and both complete checkpoints to distinct opaque
symbols. They refuse conflicting or collapsed mappings. The original profile
remains distinct from a replaced current owner/profile. The projected original
record must match the complete queried original and both claimed heads must
match their query; unavailable retains null state facts. Actual owned samples
are reproduced without database mutation. No curve arithmetic or signer is added.

| Existing signed counterclaim | Directed comparison |
| --- | --- |
| `false_absence_at_pending_head` | Query binding accepts false absence at the exact pending heads; complete snapshot binding refuses the changed claim. |
| `false_completion_at_two_charge_head` | Query binding accepts a claimed effect at the position of another charge; the owned snapshot remains pending. |
| `false_active_at_revoked_head` | Query binding accepts active=true at the exact revoked heads; complete snapshot binding refuses it. |
| `same_id_other_proposal` | Peer selection accepts a different proposal for the same id; independent complete-query binding refuses it. |
| `same_id_other_historical_profile` | Peer selection accepts a substituted old profile while the current root stays fixed; independent complete-query binding refuses it. |
| `fresh_challenge_over_initial_absence` | A changed challenge refuses the old independently selected query. After coherent restore and a new local selection, the same freshly challenged absent statement can match while external history has a charge. |

The `callback-flags` directed unsafe control accepts the modeled zero-signature
packet. Its flags are not mathematical evidence. Existing actual worker tests
separately refuse zero signatures. None of these controls creates a signing API.

## Delivery, unknown outcomes and entry

Sampling, delivery and verification are separate events. Revocation after sample
commit can leave a valid historical pending response deliverable and verifiable.
The `no-entry` policy produces no abstract entry and never clears an original's
unknown outcome. Each modeled reader begins with an unknown original outcome;
no authoritative reconciliation transition is modeled. Lost delivery and coherent
reader restore also leave it unknown.
Unavailable is not absence, and reduced caps do not refund prior charges.

`receipt-entry` is a deliberately unsafe control: an accepted active pending
response is treated as permission without current facts or deduplication. Two
readers can enter twice, a stale response can enter after revocation, and a
coherently restored pending view can enter after external completion.

`ideal-current-entry` checks independent current facts at the entry event and
serializes a one-original entry audit outside restore. It refuses those traces
under its stated premises. A later revocation does not retroactively invalidate
an earlier eligible entry. Reduced-cap and unavailable states stay ineligible.
This is an abstract audit event, not a worker, transaction or synthetic SQL effect.
Even a modeled entry does not clear unknown outcomes or provide a recovery API.

The actual [Stage 49 controls](../scripts/qualify_original_read_snapshot_response.py)
separately execute post-commit revocation, coherent pending clones/restores and
repeated synthetic effects. Two readers in this model do not simulate filesystem
cloning, process death, signature workers or database commits. Those remain
distinct executed boundaries in the earlier qualification suites.

## Finite schedule scope

Each of two readers samples once, receives that sample, verifies and attempts
entry. Three environment streams are selected: one revocation; an ordered
unavailable/live round trip; and an ordered external completion/source restore.
All shuffles preserve each stream's order. They contain 630, 3150 and 3150
schedules respectively: 6930 schedules and 68670 transitions per entry policy.
The complete selected comparison across three entry policies therefore contains
20790 schedules and 206010 transitions. Findings retain replayable prefixes,
including boundaries that appear before the end of a schedule.

This is not a full action graph. It excludes other numbers of readers, other
originals, arbitrary repeated source changes, arbitrary packet replacement and
real transport or crash behavior. Signed lies, collisions, zero signatures,
fresh challenges and lost delivery are separate directed tests, not enumerated
schedule actions. The policy/profile/record symbols are finite representatives;
they do not establish collision resistance, provenance, privacy or liveness.

The default schedule cap is 10000. A smaller exhausted cap reports `incomplete`
with exit 2; invalid parameters are errors, not security results. A complete
selected search is also not a protocol security or implementation proof.

```text
python3 -B -m unittest discover -s tests -p test_original_read_provenance_model.py -v
python3 -B scripts/model_original_read_provenance.py --use no-entry
python3 -B scripts/model_original_read_provenance.py --use receipt-entry
python3 -B scripts/model_original_read_provenance.py --use ideal-current-entry
```

Offline qualification is GO. Operational source/recovery integration, private or
application signing, core port, deployment, broadcast and funded use remain NO-GO.
Both fixed independent reports remain unfilled. See [validation](STAGE50_VALIDATION.md).
