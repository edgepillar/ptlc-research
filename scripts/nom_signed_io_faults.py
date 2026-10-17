"""Fixture-only syscall exception probes for the selected offline journal.

This source creates no native worker, key, signer, node or network operation.
The finite lookup and mathematical fixture oracle are disclosed test inputs.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('ascii')

def save(path, raw):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)

def qualify(root, output, subject_commit=None):
    if sys.flags.optimize:
        raise ValueError('signed I/O fault qualification requires assertions enabled')
    from scripts.nom_signed_io_evidence import (profile_inputs, inspect, original_names,
        TARGETS, MODES, require)
    from scripts.qualify_nom_signed_io_faults import verify_subject
    ROOT, OUTPUT = root, output
    pins = profile_inputs(ROOT)
    verify_subject(subject_commit, ROOT)
    require(OUTPUT.is_absolute() and OUTPUT.is_dir() and not OUTPUT.is_symlink() and not any(OUTPUT.iterdir()))
    python_pin = hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()
    save(OUTPUT/'source-selection.json', encode(dict(schema='ptlc-nom-signed-io-selection-v1',
        input_sha256=pins, subject_commit=subject_commit, python_sha256=python_pin,
        fixture_oracle='DISCLOSED_FIXTURE_ORACLE; NO_SIGNATURE_MATHEMATICS')))
    from offline_session import nom_recovery as base
    from offline_session.nom_signed_recovery import SignedNomRecoveryCandidate, CONTEXT_SCHEMA
    from scripts.nom_signed_corpus import SourceCorpusAllowlist, signed_observation
    spec=importlib.util.spec_from_file_location('_selected_io_fault_fixture',ROOT/'tests/nom_signed_fixture_oracle.py')
    fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
    FixturePublicMath=fixture.FixturePublicMath

    assert OUTPUT.is_dir() and {path.name for path in OUTPUT.iterdir()} == {'source-selection.json'}
    inputs = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())
    completions = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    records = json.loads((ROOT/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes())
    terms, pair = inputs['terms'], completions['pair']
    selection = dict(schema=CONTEXT_SCHEMA, source_commit='137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598',
        source_tree='1897e82296a7cc0d558a39d00398840495638bfd',
        corpus_sha256=hashlib.sha256(json.dumps(records,sort_keys=True).encode('ascii')).hexdigest(),
        contract_hex=records['long-original']['block']['to_address_hex'])
    short = bytes.fromhex(records['short-original']['wire_hex'])
    long = bytes.fromhex(records['long-original']['wire_hex'])
    rows = []
    for target in TARGETS:
      for mode in MODES:
        name = target+'--'+mode
        directory = OUTPUT/name
        directory.mkdir(mode=0o700)
        journal = directory/'journal.log'
        oracle = SourceCorpusAllowlist(terms,pair,selection,records)
        math = FixturePublicMath(terms,completions)
        def proof(leg,kind,raw=None):
            return signed_observation(terms,completions,oracle,leg,kind,raw)
        allowed = {proof(leg,'funded') for leg in ('long','short')}
        confirmation = proof('short','unlock-confirmed',short)
        allowed.add(confirmation)
        fault = dict(armed=False, fired=False, writes=0, written=0, syncs=0,
            real_syncs=0, before=None, wire=None)
        def hook(kind):
            if fault['armed'] and mode=='post-sync-error':
                fault['fired']=True
                raise OSError('synthetic post-sync acknowledgement refusal')
        def open_owner():
            return SignedNomRecoveryCandidate.open(journal,terms,pair,role='bob',verifier=math,
                raw_verifier=oracle,observation_verifier=lambda wire:wire in allowed,selection=selection,hook=hook)
        owner=open_owner()
        try:
            for leg in ('long','short'):
                owner.record_signed_observation(proof(leg,'funded'))
            if target in ('signed-long','signed-attempt'):
                assert owner.recover_long_completion(short,confirmation)==completions['long_signature_hex']
            if target=='signed-attempt':
                owner.retain_signed_original('long',long)
            initial_recoveries=math.recovery_entries
            original_append=owner._append
            real_write,real_sync=os.write,os.fsync
            selected_kind='signed-original' if target in ('signed-short','signed-long') else target
            selected_leg='short' if target=='signed-short' else 'long'
            def append(event):
                selected=event['kind']==selected_kind and (selected_kind!='signed-original' or event['leg']==selected_leg)
                if not selected:
                    return original_append(event)
                assert not fault['fired'] and fault['before'] is None
                fault['before']=journal.read_bytes()
                record=dict(schema='ptlc-nom-recovery-log-v1',sequence=owner._sequence+1,
                    previous_hash_hex=owner._head,event=event)
                record['hash_hex']=base.digest(b'ptlc-nom-log-v1',record)
                fault['wire']=base.canonical(record)+b'\n'
                fault['armed']=True
                def write(fd,raw):
                    if fd!=owner._fd:
                        return real_write(fd,raw)
                    fault['writes']+=1
                    if mode=='before-write':
                        fault['fired']=True
                        raise OSError('synthetic pre-write refusal')
                    if mode=='zero-write':
                        fault['fired']=True
                        return 0
                    if mode=='partial-write':
                        if fault['writes']==1:
                            assert len(raw)>17
                            count=real_write(fd,raw[:17])
                            assert count==17
                            fault['written']+=count
                            return count
                        fault['fired']=True
                        raise OSError('synthetic refusal after a partial write')
                    count=real_write(fd,raw)
                    assert count==len(raw)
                    fault['written']+=count
                    if mode=='complete-write-error':
                        fault['fired']=True
                        raise OSError('synthetic refusal after a complete write')
                    return count
                def sync(fd):
                    if fd!=owner._fd:
                        return real_sync(fd)
                    fault['syncs']+=1
                    if mode=='file-sync-error':
                        fault['fired']=True
                        raise OSError('synthetic file-sync refusal')
                    result=real_sync(fd)
                    fault['real_syncs']+=1
                    return result
                try:
                    with patch('offline_session.nom_recovery.os.write',side_effect=write), \
                         patch('offline_session.nom_recovery.os.fsync',side_effect=sync):
                        return original_append(event)
                finally:
                    fault['armed']=False
            owner._append=append
            def operation():
                if target=='signed-short':
                    return owner.retain_signed_original('short',short)
                if target in ('signed-admitted','signed-recovered'):
                    return owner.recover_long_completion(short,confirmation)
                if target=='signed-long':
                    return owner.retain_signed_original('long',long)
                return owner.prepare_signed_attempt('long')
            returned=False
            try:
                operation()
                returned=True
            except base.Quarantined as error:
                refusal=str(error)
            assert not returned and fault['fired'] and fault['before'] is not None
            try:
                owner.status()
            except base.Quarantined:
                current_owner_poisoned=True
            else:
                raise AssertionError('uncertain owner remained usable')
        finally:
            owner.close()
        before=fault['before'];after=journal.read_bytes();wire=fault['wire']
        complete=mode in ('complete-write-error','file-sync-error','post-sync-error')
        expected=before+(wire if complete else wire[:17] if mode=='partial-write' else b'')
        assert after==expected
        assert fault['written']==(len(wire) if complete else 17 if mode=='partial-write' else 0)
        assert fault['real_syncs']==(1 if mode=='post-sync-error' else 0)
        after_recovery_entries=math.recovery_entries
        assert after_recovery_entries==initial_recoveries+(target=='signed-recovered')
        retry_checked=False
        try:
            reopened=open_owner()
        except base.Quarantined:
            assert mode=='partial-write'
            status=None;reopen='QUARANTINED_TORN_ORIGINAL'
        else:
            try:
                assert mode!='partial-write'
                status=reopened.status();reopen='COMPLETE_EXISTING_IMAGE_SYNCED'
                charge=(int(complete) if target=='signed-admitted' else
                    1 if target in ('signed-recovered','signed-long','signed-attempt') else 0)
                completion=target in ('signed-long','signed-attempt') or (target=='signed-recovered' and complete)
                assert status['recovery_charges']==charge
                assert bool(status['long_completion_hex'])==completion
                assert ('long' in status['signed_originals'])==(target=='signed-attempt' or target=='signed-long' and complete)
                assert ('short' in status['signed_originals'])==(target!='signed-short' or complete)
                if target=='signed-attempt':
                    assert status['attempts'].get('long',0)==int(complete)
                    assert status['phases']['long']==('OUTCOME_UNKNOWN' if complete else 'ORIGINAL_RETAINED')
                if charge and not completion:
                    try:
                        reopened.recover_long_completion(short,confirmation)
                    except base.Quarantined:
                        retry_checked=True
                    else:
                        raise AssertionError('unknown charged recovery was repeated')
            finally:
                reopened.close()
        assert math.recovery_entries==after_recovery_entries
        assert journal.read_bytes()==after
        save(directory/'before-target.log',before)
        row=dict(case=name,target=target,mode=mode,original_operation_returned=False,
            current_owner_poisoned=current_owner_poisoned,intercepted_write_calls=fault['writes'],
            actual_written_bytes=fault['written'],intercepted_file_sync_calls=fault['syncs'],completed_file_syncs=fault['real_syncs'],
            before_sha256=hashlib.sha256(before).hexdigest(),after_sha256=hashlib.sha256(after).hexdigest(),
            before_bytes=len(before),after_bytes=len(after),reopen=reopen,
            recovery_entries_before_operation=initial_recoveries,recovery_entries_after_operation=after_recovery_entries,
            recovery_entries_on_reopen=math.recovery_entries-after_recovery_entries,
            explicit_unknown_retry_refused=retry_checked,status=status,refusal=refusal,
            worker='DISCLOSED_FIXTURE_ORACLE; NO_SIGNATURE_MATHEMATICS',physical_power_loss='NOT_TESTED')
        save(directory/'case-result.json',encode(row))
        rows.append(row)
    report=dict(outcome='PASS_FINITE_AUTHOR_SYSCALL_EXCEPTION_PROBES',cases=30,
        complete_image_reopens=sum(row['reopen']=='COMPLETE_EXISTING_IMAGE_SYNCED' for row in rows),
        torn_image_quarantines=sum(row['reopen']=='QUARANTINED_TORN_ORIGINAL' for row in rows),
        recovery_entries_on_reopen=sum(row['recovery_entries_on_reopen'] for row in rows),
        explicit_unknown_retry_refusals=sum(row['explicit_unknown_retry_refused'] for row in rows),
        native_mathematical_executions=0,external_process_kills=0,physical_power_loss='NOT_TESTED',
        independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')
    assert report['complete_image_reopens']==25 and report['torn_image_quarantines']==5
    assert report['recovery_entries_on_reopen']==0 and report['explicit_unknown_retry_refusals']==5
    report.update(schema='ptlc-nom-signed-io-faults-v1', outcome='PASS', input_sha256=pins,
        subject_commit=subject_commit, python_sha256=python_pin)
    inspect({name:(OUTPUT/name).read_bytes() for name in original_names()}, report, ROOT)
    assert profile_inputs(ROOT)==pins
    return report
