#!/usr/bin/env python3
"""Qualify selected local reference retention; never an independent anchor."""
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from offline_session import enrollment_contract as codec  # noqa: E402
from offline_session import nom_anchor_transition_journal as journal  # noqa: E402
from offline_session import nom_anchor_lifecycle as lifecycle  # noqa: E402
from scripts import qualify_nom_anchor_lifecycle as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402

PROFILE = "ptlc-nom-anchor-transition-journal-qualification-v1"
BASE = "4105577f0b5d87b44ae9c00f4cb332d1fecd0dc4"
MANIFEST = "compatibility/nom_anchor_transition_journal_manifest.json"
FIXTURE = "compatibility/fixtures/nom_anchor_transition_journal_v1.json"
SELECTED = ("offline_session/nom_anchor_transition_journal.py", "scripts/qualify_nom_anchor_transition_journal.py",
            "tests/test_nom_anchor_transition_journal.py", FIXTURE)
RELATIONS = ("pending_reference_not_found", "retained_reference_request", "exact_reopen", "retirement_tombstone",
             "ack_lost_before_fsync", "ack_lost_after_fsync", "ack_lost_before_return", "inspection_does_not_append")
REFUSALS = ("missing_existing", "duplicate_create", "duplicate_transition", "descriptor_before", "descriptor_hold",
            "changed_request", "wrong_before", "partial_record", "extra_tail", "reordered_records", "symlink", "hardlink")
UNSAFE = ("coherent_old_restore", "independent_file_copies", "explicit_reenrollment", "restored_pre_retirement")
BOUNDARY = dict(application="NO-GO", core="NO-GO", recovery_action="NONE", publication_outcome="UNKNOWN",
    new_worker_calls=0, additional_signature_requests=0, new_core_source_outcomes=0, preserved_core_source_outcomes=342,
    retention="SELECTED LOCAL FSYNC; COMPLETE ACTUAL CUSTODY REQUIRED SEPARATELY", nonrollback="UNPROTECTED",
    current_lookup_authentication="NOT_ESTABLISHED", shared_service_cas="NOT_IMPLEMENTED", atomic_work_entry="NOT_IMPLEMENTED",
    authority_provisioning="UNFILLED", independent_assessment="UNFILLED", physical_power_loss="UNQUALIFIED",
    automatic_retry=False, same_request_republication=False, replenish_work=False, automatic_reenrollment=False)


def corpus():
    return dict(schema=PROFILE, research_baseline_commit=BASE, relation_controls=list(RELATIONS),
        refusal_controls=list(REFUSALS), unsafe_controls=list(UNSAFE), max_records=2,
        max_record_bytes=journal.MAX_RECORD_BYTES, max_log_bytes=journal.MAX_LOG_BYTES,
        synthetic_notice="Selected POSIX reference retention; no independent service or original work", boundary=BOUNDARY)


def inputs(root=ROOT):
    _, preserved = prior.inputs(root)
    selected = {name: sha((root/name).read_bytes()) for name in SELECTED}
    expected = dict(schema="ptlc-nom-anchor-transition-journal-manifest-v1", profile=PROFILE,
        research_baseline_commit=BASE, input_sha256=selected, preserved_file_sha256=preserved, boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text('ascii')) != corpus() or json.loads((root/MANIFEST).read_text('ascii')) != expected:
        raise ValueError('selected anchor transition journal inputs changed')
    return expected, {**preserved, **selected, MANIFEST: sha((root/MANIFEST).read_bytes())}


def qualify(root=ROOT):
    _, measured = inputs(root)
    f = prior.fixture_contexts(root)
    before, held, local = f['anchors']['initial'], f['holds']['first'], f['contexts']['primary']
    results, refused, unsafe, images = {}, [], {}, {}
    cls = journal.AnchorTransitionJournal
    def refuse(name, operation):
        try:
            operation()
        except journal.AnchorJournalRefused:
            refused.append(name)
        else:
            raise AssertionError('required journal refusal missing')
    def write(path, data):
        path.write_bytes(data)
        path.chmod(0o600)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        path = directory/'anchor.log'
        refuse('missing_existing', lambda: cls.open_existing(path, before, held))
        assert not path.exists()
        owner = cls.create(path, before, held)
        try:
            initial = path.read_bytes()
            results['pending_reference_not_found'] = owner.inspect(local)
            refuse('duplicate_create', lambda: cls.create(path, before, held))
            owner.commit_retained_reference()
            complete = path.read_bytes()
            results['retained_reference_request'] = owner.inspect(local)
            refuse('duplicate_transition', owner.commit_retained_reference)
            results['inspection_does_not_append'] = owner.inspect(local)
            assert path.read_bytes() == complete
        finally:
            owner.close()
        images.update(initial=initial.hex(), complete=complete.hex())
        with cls.open_existing(path, before, held) as reopened:
            results['exact_reopen'] = reopened.inspect(local)
        refuse('descriptor_before', lambda: cls.open_existing(path, before.as_dict(), held))
        refuse('descriptor_hold', lambda: cls.open_existing(path, before, held.as_dict()))
        other = prior.advance(before, f['traces']['second'], 'f8')
        other_hold = lifecycle.retain_unknown_anchor_acknowledgment(other)
        refuse('changed_request', lambda: cls.open_existing(path, before, other_hold))
        refuse('wrong_before', lambda: cls.open_existing(path, f['anchors']['active'], held))
        for name, data in (('partial_record', complete[:-1]), ('extra_tail', complete+b'x'),
                           ('reordered_records', complete[len(initial):]+initial)):
            selected = directory/(name+'.log')
            write(selected, data)
            refuse(name, lambda: cls.open_existing(selected, before, held))
            assert selected.read_bytes() == data
        alias = directory/'alias.log'
        alias.symlink_to(path.name)
        refuse('symlink', lambda: cls.open_existing(alias, before, held))
        alias.unlink()
        os.link(path, alias)
        refuse('hardlink', lambda: cls.open_existing(path, before, held))
        alias.unlink()
        class FaultOwner(cls):
            point = None
            def _cut(self, label):
                if label == self.point:
                    raise OSError('synthetic selected acknowledgment failure')
        for name, cut in (('ack_lost_before_fsync', 'append-before-fsync'),
                          ('ack_lost_after_fsync', 'append-after-fsync'), ('ack_lost_before_return', 'append-before-ack')):
            selected = directory/(name+'.log')
            fault = FaultOwner.create(selected, before, held)
            try:
                fault.point = cut
                try:
                    fault.commit_retained_reference()
                except journal.AnchorJournalOutcomeUnknown:
                    pass
                else:
                    raise AssertionError('unknown acknowledgment control did not fail')
                try:
                    fault.status()
                except journal.AnchorJournalQuarantined:
                    pass
                else:
                    raise AssertionError('poisoned owner returned a cached acknowledgment')
            finally:
                fault.close()
            data = selected.read_bytes()
            with cls.open_existing(selected, before, held) as reopened:
                results[name] = reopened.inspect(local)
            assert selected.read_bytes() == data == complete
        write(path, initial)
        with cls.open_existing(path, before, held) as restored:
            unsafe['coherent_old_restore'] = restored.inspect(local)
        copies = []
        for number in range(2):
            selected = directory/('copy-'+str(number)+'.log')
            write(selected, initial)
            with cls.open_existing(selected, before, held) as copied:
                copies.append(copied.commit_retained_reference())
            assert selected.read_bytes() == complete
        unsafe['independent_file_copies'] = copies
        selected = directory/'reenrolled.log'
        with cls.create(selected, before, held) as reenrolled:
            unsafe['explicit_reenrollment'] = reenrolled.status()
        retirement_before, retirement_hold = f['anchors']['after_third'], f['holds']['retirement']
        selected = directory/'retirement.log'
        with cls.create(selected, retirement_before, retirement_hold) as retiring:
            old = selected.read_bytes()
            retiring.commit_retained_reference()
            retired = selected.read_bytes()
            results['retirement_tombstone'] = retiring.inspect(f['contexts']['third'])
        images.update(before_retirement=old.hex(), retired=retired.hex())
        write(selected, old)
        with cls.open_existing(selected, retirement_before, retirement_hold) as restored:
            unsafe['restored_pre_retirement'] = restored.status()
        assert unsafe['restored_pre_retirement']['reference_anchor_phase'] == 'ACTIVE'
    for value in list(results.values()) + [unsafe['coherent_old_restore'], unsafe['explicit_reenrollment'],
                                         unsafe['restored_pre_retirement']] + unsafe['independent_file_copies']:
        assert value['state'] == 'HOLD' and value['publication_outcome'] == 'UNKNOWN' and value['recovery_action'] == 'NONE'
        assert not any(value[field] for field in ('new_work_allowed', 'automatic_retry', 'same_request_republication',
            'replenish_work', 'replacement_original_allowed', 'automatic_bootstrap', 'automatic_reenrollment'))
    assert set(results) == set(RELATIONS) and set(refused) == set(REFUSALS) and set(unsafe) == set(UNSAFE)
    return dict(schema="ptlc-nom-anchor-transition-journal-result-v1", profile=PROFILE, outcome="PASS",
        input_sha256=measured, comparison_results=results, refusal_controls=refused, unsafe_controls=unsafe,
        original_public_images_hex=images, boundary=BOUNDARY,
        execution_scope="ACTUAL SELECTED LOCAL FILES; NO NEW WORKER OR SIGNATURE; NOT POWER-LOSS QUALIFICATION")


def check_cases(value, root=ROOT):
    # Replay includes actual selected filesystem operations, never service work.
    if codec._canonical(value) != codec._canonical(qualify(root)):
        raise ValueError('complete selected anchor transition journal result changed')


def main():
    try:
        value = qualify()
    except (ValueError, TypeError, OSError, KeyError):
        print('selected anchor transition journal qualification refused', file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
