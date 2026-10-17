"""Selected actual-process cuts for the offline signed-wire recovery candidate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import argparse
import re
import stat

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

CUTS=('after-signed-short','after-signed-admitted','after-public-reply','after-signed-recovered',
    'after-signed-long','after-signed-attempt')
ACTOR_MODES=(('verify-pair','verify-short'),('verify-pair','verify-short'),
    ('verify-pair','verify-short','recover-long'),
    ('verify-pair','verify-short','recover-long','verify-long'),
    ('verify-pair','verify-short','recover-long','verify-long','verify-long'),
    ('verify-pair','verify-short','recover-long','verify-long','verify-long'))
REOPEN_MODES=(('verify-pair','verify-short'),('verify-pair','verify-short'),('verify-pair','verify-short'),
    ('verify-pair','verify-short','verify-long'),('verify-pair','verify-long','verify-short','verify-long'),
    ('verify-pair','verify-long','verify-short','verify-long'))

def check(report):
    assert report['schema']=='ptlc-nom-signed-process-cuts-v1' and report['outcome']=='PASS'
    assert len(report['cases'])==6
    for index,(cut,row) in enumerate(zip(CUTS,report['cases'])):
        assert row['cut']==cut and row['actor_exit']==72 and row['actor_complete'] is True
        assert row['charge']==(0 if index==0 else 1)
        assert row['completion_present'] is (index>=3) and row['signed_long_present'] is (index>=4)
        assert row['short_original_exact'] and row['long_original_exact_or_absent']
        assert row['actor_modes']==list(ACTOR_MODES[index]) and row['reopen_modes']==list(REOPEN_MODES[index])
        assert row['reopen_recovery_entries']==row['reopen_observer_calls']==0
        assert row['actor_recovery_entries']==row['actor_recovery_returns']==(1 if index>=2 else 0)
        assert row['diagnostic_result_present'] is (index>=2) and row['journal_unchanged']
        assert row['unknown_retry_refused'] is (index in (1,2))
        assert row['attempts']==({'long':1} if index==5 else {})
        assert row['long_phase']==('OUTCOME_UNKNOWN' if index==5 else 'ORIGINAL_RETAINED' if index==4 else None)
    assert report['actor_worker_calls']==21 and report['reopen_worker_calls']==17
    assert report['additional_recovery_entries_on_reopen_or_retry']==0
    assert report['application']==report['core']=='NO-GO' and report['independent_assessment']=='UNFILLED'
    return report

def qualify(root,actor,executable,pin,evidence):
    if sys.flags.optimize:raise ValueError('process-cut qualification requires assertions enabled')
    sys.path.insert(0,str(root))
    from offline_session import nom_recovery as base
    from offline_session.nom_signed_recovery import SignedNomRecoveryCandidate,CONTEXT_SCHEMA
    from offline_session.nom_verifier import NomPublicVerifier,CLEAN_EXECUTION_PROFILE
    from scripts.nom_cut_capture import OriginalCapture,retain,sha
    from scripts.qualify_nom_recovery_cuts import CountedVerifier,journal_records
    from scripts.nom_signed_corpus import SourceCorpusAllowlist,signed_observation
    from scripts.qualify_nom_signed_originals import inputs
    assert evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir())
    manifest,unused,records=inputs(root);pins=profile_inputs(root)
    python=Path(sys.executable).resolve();python_pin=sha(python.read_bytes());actor_pin=sha(actor.read_bytes())
    assert sha(executable.read_bytes())==pin
    terms=json.loads((root/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    completed=json.loads((root/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    selection=dict(schema=CONTEXT_SCHEMA,source_commit=manifest['core_commit'],source_tree=manifest['core_tree'],
        corpus_sha256=manifest['record_set_payload_sha256'],contract_hex=records['long-original']['block']['to_address_hex'])
    raw=SourceCorpusAllowlist(terms,completed['pair'],selection,records)
    short=bytes.fromhex(records['short-original']['wire_hex']);long=bytes.fromhex(records['long-original']['wire_hex'])
    funded=[signed_observation(terms,completed,raw,leg,'funded') for leg in ('long','short')]
    proof=signed_observation(terms,completed,raw,'short','unlock-confirmed',short)
    allowed=set(funded+[proof])
    retain(evidence/'subject-before-first-spawn.json',json.dumps(dict(public_inputs=pins,actor_sha256=actor_pin,
        parent_sha256=sha(Path(__file__).read_bytes()),python_sha256=python_pin,worker_sha256=pin,
        profile='SELECTED_OFFLINE_PROCESS_CUTS_ONLY'),sort_keys=True).encode('ascii'))
    parent=evidence/'reopen-worker';parent.mkdir(mode=0o700)
    capture=OriginalCapture(parent,executable,pin)
    public=NomPublicVerifier(executable,pin,terms,completed['pair'],execution_profile=CLEAN_EXECUTION_PROFILE)
    rows=[];actor_calls=0;all_originals=['subject-before-first-spawn.json']
    for index,cut in enumerate(CUTS):
        directory=evidence/cut;directory.mkdir(mode=0o700);(directory/'worker').mkdir(mode=0o700)
        config=dict(schema='ptlc-nom-signed-process-selection-v1',worker_sha256=pin,
            source_input_sha256=pins,actor_sha256=actor_pin,python_sha256=python_pin,cut=cut)
        retain(directory/'configuration-before-spawn.json',json.dumps(config,sort_keys=True).encode('ascii'))
        process=None;output=error=b'';receipt=dict(exit_code=None,stream_completeness='NOT_ESTABLISHED')
        try:
            process=subprocess.Popen([str(python),'-B','-u',str(actor),'--source-root',str(root),'--directory',str(directory),
                '--executable',str(executable),'--configuration',str(directory/'configuration-before-spawn.json')],
                env={},close_fds=True,start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:output,error=process.communicate(timeout=30);receipt['stream_completeness']='COMPLETE'
            except subprocess.TimeoutExpired:
                process.kill();output,error=process.communicate(timeout=2)
                receipt['stream_completeness']='COMPLETE_AFTER_TIMEOUT'
        finally:
            if process is not None and process.returncode is None:
                process.kill();output,error=process.communicate(timeout=2)
            if process is not None:
                receipt['exit_code']=process.returncode
                for stream in (process.stdout,process.stderr):
                    if stream is not None:stream.close()
            receipt.update(stdout_hex=output.hex(),stderr_hex=error.hex(),stdout_sha256=sha(output),stderr_sha256=sha(error))
            retain(directory/'actor.stdout',output);retain(directory/'actor.stderr',error)
            retain(directory/'actor.receipt.json',base.canonical(receipt))
        assert receipt['exit_code']==72 and receipt['stream_completeness']=='COMPLETE'
        assert output==base.canonical(dict(schema='ptlc-nom-signed-process-marker-v1',cut=cut,method='os._exit(72)'))+b'\n' and error==b''
        cut_receipt=json.loads((directory/'cut-receipt.json').read_bytes())
        assert cut_receipt['schema']=='ptlc-nom-signed-process-cut-v1' and cut_receipt['cut']==cut
        calls=[]
        for number,mode in enumerate(ACTOR_MODES[index],1):
            prefix=f'call-{number:03d}.';call=json.loads((directory/'worker'/(prefix+'receipt.json')).read_bytes())
            assert call['number']==number and call['exit_code']==0 and call['stream_completeness']=='COMPLETE'
            assert json.loads((directory/'worker'/(prefix+'stdin')).read_bytes())['mode']==mode
            for suffix,label in (('stdin','request'),('stdout','stdout'),('stderr','stderr')):
                wire=(directory/'worker'/(prefix+suffix)).read_bytes()
                assert call[label+'_hex']==wire.hex() and call[label+'_sha256']==sha(wire)
            calls.append(call)
        assert len(list((directory/'worker').iterdir()))==4*len(calls)
        actor_calls+=len(calls)
        image=(directory/'journal.log').read_bytes();journal_records(image)
        observer_calls=[]
        def observer(wire):observer_calls.append(wire.hex());return wire in allowed
        counted=CountedVerifier(public);capture.phase=cut+':reopen'
        with patch('offline_session.nom_verifier.run_clean_environment_public_worker',capture.run):
            with SignedNomRecoveryCandidate.open(directory/'journal.log',terms,completed['pair'],role='bob',
                    verifier=counted,raw_verifier=raw,observation_verifier=observer,selection=selection) as store:
                status=store.status();observer_on_reopen=len(observer_calls);reopen_modes=list(counted.modes)
                refused=False
                if index in (1,2):
                    try:store.recover_long_completion(short,proof)
                    except base.Quarantined:refused=True
                    else:raise AssertionError('unknown charged work reentered recovery')
                    assert len(observer_calls)==1 and counted.modes==reopen_modes
                if index<4:
                    try:store.prepare_signed_attempt('long')
                    except base.RecoveryError:pass
                    else:raise AssertionError('missing signed long original was manufactured')
                assert store.status()==status
        assert image==(directory/'journal.log').read_bytes()
        if index>=3:assert status['long_completion_hex']==completed['long_signature_hex']
        if index>=4:assert status['signed_originals']['long']['wire_hex']==long.hex()
        assert cut_receipt['worker_modes']==list(ACTOR_MODES[index])
        assert cut_receipt['charge']==status['recovery_charges']
        assert cut_receipt['retained_completion']==status['long_completion_hex']
        assert cut_receipt['signed_legs']==sorted(status['signed_originals'])
        rows.append(dict(cut=cut,actor_exit=72,actor_complete=True,charge=status['recovery_charges'],
            completion_present=status['long_completion_hex'] is not None,signed_long_present='long' in status['signed_originals'],
            short_original_exact=status['signed_originals']['short']['wire_hex']==short.hex(),
            long_original_exact_or_absent='long' not in status['signed_originals'] or status['signed_originals']['long']['wire_hex']==long.hex(),
            actor_modes=cut_receipt['worker_modes'],reopen_modes=reopen_modes,reopen_recovery_entries=counted.entries,
            reopen_observer_calls=observer_on_reopen,actor_recovery_entries=cut_receipt['recovery_entries'],
            actor_recovery_returns=cut_receipt['recovery_returns'],diagnostic_result_present=cut_receipt['diagnostic_public_result'] is not None,
            journal_unchanged=True,unknown_retry_refused=refused,attempts=status['attempts'],long_phase=status['phases'].get('long')))
        all_originals += [cut+'/'+name for name in ('configuration-before-spawn.json','actor.stdout','actor.stderr','actor.receipt.json','cut-receipt.json','journal.log')]
        all_originals += [cut+f'/worker/call-{n:03d}.'+suffix for n in range(1,len(calls)+1)
            for suffix in ('stdin','stdout','stderr','receipt.json')]
    all_originals += [f'reopen-worker/call-{n:03d}.'+suffix for n in range(1,len(capture.calls)+1)
        for suffix in ('stdin','stdout','stderr','receipt.json')]
    report=dict(schema='ptlc-nom-signed-process-cuts-v1',outcome='PASS',cases=rows,
        actor_worker_calls=actor_calls,reopen_worker_calls=len(capture.calls),additional_recovery_entries_on_reopen_or_retry=0,
        source_input_sha256=pins,actor_sha256=actor_pin,worker_sha256=pin,python_sha256=python_pin,
        original_files=all_originals,application='NO-GO',core='NO-GO',independent_assessment='UNFILLED',
        observation_source='DISCLOSED_SYNTHETIC_ALLOWLIST',raw_verifier='DISCLOSED_SOURCE_CORPUS_LOOKUP',
        process_cut='ACTUAL SELF EXIT72 AFTER COMPLETE FSYNC OR REAPED PUBLIC REPLY',power_loss='NOT_PERFORMED',
        restore_fence='UNFILLED',worker_build='BYTE_PIN_ONLY; SOURCE_BUILD_AND_LOADER_AUTHENTICATION_SEPARATE',
        containment='TRUSTED_NONFORKING_ACTOR_AND_WORKER; NOT_HOSTILE_PROCESS_SANDBOX',profile='OFFLINE_RESEARCH_CANDIDATE_ONLY')
    check(report)
    assert len(all_originals)==len(set(all_originals))==189
    assert sha(actor.read_bytes())==actor_pin and sha(executable.read_bytes())==pin and sha(python.read_bytes())==python_pin
    assert all(sha((root/name).read_bytes())==value for name,value in pins.items());profile_inputs(root)
    return report


def require(value):
    if not value:raise ValueError('selected signed process-cut qualification refused')


def profile_inputs(root):
    """Select exact project sources; a hash table is not source authentication."""
    from scripts.qualify_nom_signed_originals import inputs
    selected=json.loads((root/'compatibility/nom_signed_process_cuts_manifest.json').read_bytes())
    require(selected['schema']=='ptlc-nom-signed-process-cuts-manifest-v1')
    require(selected['source_subject_base_commit']=='35298ee88478f04fd62a976deab1900fd0588215')
    source,unused,unused_records=inputs(root)
    require(selected['core_commit']==source['core_commit'] and selected['core_tree']==source['core_tree'])
    names=set(source['input_sha256'])|{
        'scripts/nom_signed_process_actor.py','scripts/qualify_nom_signed_process_cuts.py',
        'scripts/nom_signed_process_evidence.py'}
    pins=selected['input_sha256']
    require(type(pins) is dict and set(pins)==names)
    for name,pin in pins.items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin))
        require(hashlib.sha256((root/name).read_bytes()).hexdigest()==pin)
    require(all(pins[name]==pin for name,pin in source['input_sha256'].items()))
    require(selected['application']==selected['core']=='NO-GO' and selected['independent_assessment']=='UNFILLED')
    return pins


def verify_subject(subject,root=ROOT):
    if subject is None:return
    require(type(subject) is str and re.fullmatch('[0-9a-f]{40}',subject))
    pins=dict(profile_inputs(root))
    name='compatibility/nom_signed_process_cuts_manifest.json'
    pins[name]=hashlib.sha256((root/name).read_bytes()).hexdigest()
    for name,pin in pins.items():
        result=subprocess.run(['git','show',subject+':'+name],cwd=root,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=30,check=False)
        require(result.returncode==0 and len(result.stdout)<=1024**2 and hashlib.sha256(result.stdout).hexdigest()==pin)


def retain_manifest(evidence,report,subject_commit,root=ROOT):
    """Enumerate known originals, including partial failed output, without repair."""
    from scripts.nom_signed_process_evidence import names,inspect
    from scripts.check_artifacts import PATTERNS
    files={};payloads={}
    for name in names():
        path=evidence/name
        if not path.exists():continue
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=256*1024)
        raw=path.read_bytes();payloads[name]=raw
        files[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    require(sum(row['bytes'] for row in files.values())<=8*1024**2)
    if report.get('outcome')=='PASS':
        inspect(payloads,report,root)
        require(len(files)==189)
    for raw in payloads.values():
        text=raw.decode('ascii')
        require(not any(pattern.search(text) for unused,pattern in PATTERNS))
        require(not re.search(r'/(?:Users|Volumes|private)/|localhost|\b[A-Za-z0-9_-]+[.]local\b',text,re.I))
    report['subject_commit']=subject_commit
    result=(json.dumps(report,sort_keys=True)+'\n').encode('ascii')
    from scripts.nom_cut_capture import retain
    retain(evidence/'qualification-result.json',result)
    files['qualification-result.json']=dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())
    value=dict(schema='ptlc-nom-signed-process-cut-originals-v1',subject_commit=subject_commit,
        qualification_outcome=report['outcome'],files=files,originals_complete=report['outcome']=='PASS',
        package='EXPLICIT_RELATIVE_FILES_ONLY; NO_ENVIRONMENT_OR_BINARY_BUNDLE',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    retain(evidence/'retention-manifest.json',(json.dumps(value,sort_keys=True)+'\n').encode('ascii'))
    return hashlib.sha256((evidence/'retention-manifest.json').read_bytes()).hexdigest()


def main():
    if sys.flags.optimize:
        print('FAIL: signed process-cut qualification requires assertions enabled',file=sys.stderr);return 1
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--expect-executable-sha256',required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--subject-commit')
    args=parser.parse_args();evidence=args.evidence
    if not (evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir())):
        print('FAIL: new empty process-cut evidence directory required',file=sys.stderr);return 1
    try:
        require(args.executable.is_absolute() and re.fullmatch('[0-9a-f]{64}',args.expect_executable_sha256))
        verify_subject(args.subject_commit)
        report=qualify(ROOT,ROOT/'scripts/nom_signed_process_actor.py',args.executable,
            args.expect_executable_sha256,evidence)
        report['outcome']='PASS'
    except (AssertionError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        report=dict(schema='ptlc-nom-signed-process-cuts-v1',outcome='FAILED_OR_INCOMPLETE',
            error_type=type(error).__name__,actual_worker_count='NOT_QUALIFIED',
            application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    try:
        pin=retain_manifest(evidence,report,args.subject_commit if args.subject_commit
            and re.fullmatch('[0-9a-f]{40}',args.subject_commit) else None)
    except (AssertionError,OSError,ValueError,KeyError,TypeError):
        print('FAIL: process-cut retention incomplete; preserve all originals',file=sys.stderr);return 1
    print(json.dumps(dict(report,retention_manifest_sha256=pin),sort_keys=True))
    return 0 if report['outcome']=='PASS' else 1


if __name__=='__main__':sys.exit(main())
