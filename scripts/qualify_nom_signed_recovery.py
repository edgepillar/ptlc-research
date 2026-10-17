"""Offline two-phase journal scenario using an explicitly selected public worker.

The source-corpus allowlist and observation allowlist are disclosed test choices.
OriginalCapture is a single-thread qualification transport for a trusted,
nonforking worker; its post-collection bounds are not a hostile-process sandbox.
"""
import hashlib
import json
from pathlib import Path
import sys
import argparse
import os
import re
import stat
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from offline_session import nom_recovery as base
from offline_session.nom_verifier import NomPublicVerifier, CLEAN_EXECUTION_PROFILE
from scripts.nom_cut_capture import OriginalCapture
from scripts.qualify_nom_recovery_cuts import CountedVerifier
from offline_session.nom_signed_recovery import SignedNomRecoveryCandidate, CONTEXT_SCHEMA
from scripts.nom_signed_corpus import SourceCorpusAllowlist, signed_observation
from scripts.qualify_nom_signed_originals import inputs as source_inputs


def require(value):
    if not value: raise ValueError('selected signed-wire worker qualification refused')


def qualify(executable, expected_pin, evidence, record_path=None):
    if sys.flags.optimize:
        raise ValueError('signed-wire qualification requires assertions enabled')
    manifest, unused, unused_records = source_inputs(ROOT)
    if record_path is None: record_path = ROOT/'compatibility/fixtures/nom_signed_originals_v1.json'
    require(evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir()))
    require(record_path.is_file() and not record_path.is_symlink() and record_path.stat().st_size <= 512*1024)
    records_raw = record_path.read_bytes()
    records = json.loads(records_raw)
    require(hashlib.sha256(json.dumps(records,sort_keys=True).encode('ascii')).hexdigest()==manifest['record_set_payload_sha256'])
    terms = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    completions = json.loads((ROOT/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    selection = dict(schema=CONTEXT_SCHEMA, source_commit='137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598',
        source_tree='1897e82296a7cc0d558a39d00398840495638bfd', corpus_sha256=hashlib.sha256(json.dumps(records,sort_keys=True).encode('ascii')).hexdigest(),
        contract_hex=records['long-original']['block']['to_address_hex'])
    allowlist = SourceCorpusAllowlist(terms, completions['pair'], selection, records)
    selected = NomPublicVerifier(executable,expected_pin,terms,completions['pair'],execution_profile=CLEAN_EXECUTION_PROFILE)
    verifier = CountedVerifier(selected)
    for name in ('worker','journals'): (evidence/name).mkdir(mode=0o700)
    capture = OriginalCapture(evidence/'worker',executable,expected_pin)
    capture.phase = 'nom-signed-wire-recovery-candidate'
    short = bytes.fromhex(records['short-original']['wire_hex'])
    long = bytes.fromhex(records['long-original']['wire_hex'])
    alias = bytes.fromhex(records['long-unknown-protobuf-field']['wire_hex'])
    funded = [signed_observation(terms,completions,allowlist,leg,'funded') for leg in ('long','short')]
    confirmed = signed_observation(terms,completions,allowlist,'short','unlock-confirmed',short)
    unseen = signed_observation(terms,completions,allowlist,'short','unseen',short)
    allowed = set(funded+[confirmed,unseen])
    def open_store(role,name=None):
        return SignedNomRecoveryCandidate.open(evidence/'journals'/(name or role+'.log'),terms,completions['pair'],
            role=role,verifier=verifier,raw_verifier=allowlist,selection=selection,
            observation_verifier=lambda wire:wire in allowed)
    with patch('offline_session.nom_verifier.run_clean_environment_public_worker',capture.run):
        with open_store('alice') as alice:
            for proof in funded: alice.record_signed_observation(proof)
            alice.retain_signed_original('short',short)
            output = alice.prepare_signed_attempt('short'); require(output == short)
        with open_store('alice') as alice:
            require(alice.status()['phases']['short'] == 'OUTCOME_UNKNOWN')
            alice.record_signed_observation(unseen)
            output = alice.prepare_signed_attempt('short'); require(output == short)
            alice.record_signed_observation(confirmed)
        with open_store('bob') as bob:
            for proof in funded: bob.record_signed_observation(proof)
            completed = bob.recover_long_completion(short,confirmed)
            require(completed == completions['long_signature_hex'])
            require('long' not in bob.status()['signed_originals'])
            require('long' not in bob.status()['synthetic_reference_derivatives']['owned'])
            try: bob.prepare_signed_attempt('long')
            except base.RecoveryError: pass
            else: raise ValueError('absent signed long wire was returned')
        with open_store('bob') as bob:
            require(bob.status()['long_completion_hex'] == completed and 'long' not in bob.status()['signed_originals'])
            bob.retain_signed_original('long',long)
            output = bob.prepare_signed_attempt('long'); require(output == long)
            before = (evidence/'journals/bob.log').read_bytes()
            try: bob.retain_signed_original('long',alias)
            except base.RecoveryError: pass
            else: raise ValueError('different raw original replaced retained bytes')
            require((evidence/'journals/bob.log').read_bytes() == before)
        with open_store('bob') as bob:
            require(bob.status()['phases']['long'] == 'OUTCOME_UNKNOWN')
            output = bob.prepare_signed_attempt('long'); require(output == long)
            replay = bob.recover_long_completion(short,confirmed)
            require(replay == completed and bob.status()['recovery_charges'] == 1)
            require(bytes.fromhex(bob.status()['signed_originals']['long']['wire_hex']) == long)
        with open_store('alice','invalid-wire-control.log') as control:
            before = (evidence/'journals/invalid-wire-control.log').read_bytes()
            invalid = bytes.fromhex(records['short-invalid-signature']['wire_hex'])
            try: control.retain_signed_original('short',invalid)
            except base.RecoveryError: pass
            else: raise ValueError('unqualified signed original was retained')
            require((evidence/'journals/invalid-wire-control.log').read_bytes() == before)
        for leg in ('long','short'):
            try: verifier.verify_claim(leg,'00'*64)
            except base.RecoveryError: pass
            else: raise ValueError('invalid public completion was accepted')
    require(verifier.entries == verifier.returns == 1)
    require(len(capture.calls) == len(verifier.modes) == 19)
    require(all(row['stream_completeness'] == 'COMPLETE' for row in capture.calls))
    require(all(row['exit_code'] == 0 for row in capture.calls[:-2]))
    require([row['exit_code'] for row in capture.calls[-2:]] == [2,2])
    require(hashlib.sha256(executable.read_bytes()).hexdigest() == expected_pin)
    require(short != long and long != alias and records['long-original']['hash_hex'] == records['long-unknown-protobuf-field']['hash_hex'])
    return dict(schema='ptlc-nom-public-signed-recovery-candidate-qualification-v1',
        result=dict(two_journal_real_byte_custody='PASS',long_completion_before_signed_original='SEPARATE_PHASES',
            absent_signed_long='REMAINS_ABSENT_ACROSS_REOPEN',same_node_hash_replacement='REFUSED_WITHOUT_APPEND',
            unknown_output='EXACT_ORIGINAL_ONLY',recovery_worker_entries=verifier.entries,recovery_worker_returns=verifier.returns,
            invalid_raw_wire='REFUSED_WITHOUT_APPEND',invalid_completions='TWO_ACTUAL_NATIVE_REFUSALS'),
        public_worker_calls=len(capture.calls),executable_sha256=expected_pin,execution_profile=CLEAN_EXECUTION_PROFILE,
        selected_source_record_set_sha256=selection['corpus_sha256'],
        raw_verifier='DISCLOSED_SOURCE_CORPUS_ALLOWLIST; NOT_A_GENERAL_SIGNATURE_VERIFIER',
        observer='DISCLOSED_SYNTHETIC_ALLOWLIST; NOT_A_CHAIN_AUTHORITY',
        original_capture='SINGLE_THREAD_TRUSTED_NONFORKING_WORKER; NOT_RUNTIME_SANDBOX',
        original_worker_streams='RETAINED_IN_PRIVATE_EVIDENCE',original_journals=3,
        source_build_and_loader_authentication='SEPARATE_UNFILLED_GATE',rollback_fence='UNFILLED',
        signer='NOT_IMPLEMENTED',broadcast='NOT_PERFORMED',independent_assessment='UNFILLED',
        selected_input_sha256=manifest['input_sha256'],
        application='NO-GO',core='NO-GO',recovery_action='NONE',profile='OFFLINE_RESEARCH_CANDIDATE_ONLY')


def retain_manifest(evidence, report, subject_commit):
    """Explicitly enumerate originals, including partial known failed output.

    No directory is recursively packaged and no original is normalized, replaced
    or deleted. Unknown contents remain at their original names for inspection.
    """
    names=['journals/'+name for name in ('alice.log','bob.log','invalid-wire-control.log')]
    names += [f'worker/call-{number:03d}.'+suffix for number in range(1,65)
        for suffix in ('stdin','stdout','stderr','receipt.json')]
    files={}
    for name in names:
        path=evidence/name
        if not path.exists(): continue
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size <= 256*1024)
        raw=path.read_bytes()
        files[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    if report.get('outcome')=='PASS':
        require(report['public_worker_calls']==19 and len(files)==79)
        for number in range(1,20):
            receipt=json.loads((evidence/f'worker/call-{number:03d}.receipt.json').read_bytes())
            require(receipt['number']==number and receipt['stream_completeness']=='COMPLETE'
                and receipt['exit_code']==(2 if number>17 else 0))
    report['subject_commit']=subject_commit
    report['original_files']=len(files)
    result=(json.dumps(report,sort_keys=True)+'\n').encode('ascii')
    target=evidence/'qualification-result.json'
    with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:
        stream.write(result)
    files['qualification-result.json']=dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())
    value=dict(schema='ptlc-nom-signed-recovery-originals-v1',subject_commit=subject_commit,
        qualification_outcome=report['outcome'],files=files,originals_complete=report['outcome']=='PASS',
        package='EXPLICIT_RELATIVE_FILES_ONLY; NO_ENVIRONMENT_OR_BINARY_BUNDLE',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    target=evidence/'retention-manifest.json'
    with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:
        stream.write((json.dumps(value,sort_keys=True)+'\n').encode('ascii'))
    return hashlib.sha256(target.read_bytes()).hexdigest()


def verify_subject(subject):
    """Bind declared publication metadata to each selected current source file."""
    if subject is None:return
    require(re.fullmatch('[0-9a-f]{40}',subject))
    manifest,unused,unused_records=source_inputs(ROOT)
    for name,pin in manifest['input_sha256'].items():
        result=subprocess.run(['git','show',subject+':'+name],cwd=ROOT,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        require(result.returncode==0 and len(result.stdout)<=1024**2
            and hashlib.sha256(result.stdout).hexdigest()==pin)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--expect-executable-sha256',required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--subject-commit')
    args=parser.parse_args()
    if sys.flags.optimize:
        print('FAIL: signed-wire qualification requires assertions enabled',file=sys.stderr);return 1
    evidence=args.evidence
    if not (evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir())):
        print('FAIL: new empty signed-wire evidence directory required',file=sys.stderr);return 1
    try:
        verify_subject(args.subject_commit)
        report=qualify(args.executable,args.expect_executable_sha256,evidence)
        report['outcome']='PASS'
    except (AssertionError,OSError,ValueError,KeyError,TypeError,base.RecoveryError,subprocess.SubprocessError) as error:
        report=dict(schema='ptlc-nom-public-signed-recovery-candidate-qualification-v1',outcome='FAILED_OR_INCOMPLETE',
            error_type=type(error).__name__,actual_worker_count='NOT_QUALIFIED',
            application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    try:
        pin=retain_manifest(evidence,report,args.subject_commit if args.subject_commit and re.fullmatch('[0-9a-f]{40}',args.subject_commit) else None)
    except (AssertionError,OSError,ValueError,KeyError,TypeError):
        print('FAIL: signed-wire evidence retention incomplete; preserve all originals',file=sys.stderr);return 1
    print(json.dumps(dict(report,retention_manifest_sha256=pin),sort_keys=True))
    return 0 if report['outcome']=='PASS' else 1


if __name__=='__main__':sys.exit(main())
