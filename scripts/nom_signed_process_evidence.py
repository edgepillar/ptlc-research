"""Read six selected cut originals without replaying the journal implementation.

This same-author finite-scenario reader is not independent protocol assessment,
native execution, physical power-loss proof, or a rollback authority.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat
from scripts.qualify_nom_signed_process_cuts import CUTS,ACTOR_MODES,REOPEN_MODES,profile_inputs

def require(value):
    if not value:raise ValueError('selected process-cut originals refused')

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result);result[key]=value
    return result

def decode(raw):
    require(type(raw) is bytes and len(raw)<=256*1024)
    def constant(unused):raise ValueError('nonfinite JSON refused')
    return json.loads(raw.decode('ascii'),object_pairs_hook=unique,parse_constant=constant)

def names():
    result=['subject-before-first-spawn.json']
    for cut,modes in zip(CUTS,ACTOR_MODES):
        result += [cut+'/'+name for name in ('configuration-before-spawn.json','actor.stdout','actor.stderr',
            'actor.receipt.json','cut-receipt.json','journal.log')]
        result += [cut+f'/worker/call-{n:03d}.'+suffix for n in range(1,len(modes)+1)
            for suffix in ('stdin','stdout','stderr','receipt.json')]
    result += [f'reopen-worker/call-{n:03d}.'+suffix for n in range(1,18)
        for suffix in ('stdin','stdout','stderr','receipt.json')]
    return result

def journal_events(wire):
    require(type(wire) is bytes and 0<len(wire)<=256*1024 and wire.endswith(b'\n'))
    previous='00'*32;events=[]
    lines=wire.splitlines();require(0<len(lines)<=10)
    for number,line in enumerate(lines,1):
        row=decode(line)
        require(type(row) is dict and set(row)=={'schema','sequence','previous_hash_hex','event','hash_hex'})
        require(type(row['sequence']) is int and row['sequence']==number)
        require(row['schema']=='ptlc-nom-recovery-log-v1' and row['previous_hash_hex']==previous)
        body={key:value for key,value in row.items() if key!='hash_hex'}
        require(row['hash_hex']==sha(b'ptlc-nom-log-v1\0'+canonical(body)))
        require(canonical(row)==line)
        previous=row['hash_hex'];events.append(row['event'])
    return events

def check_report(report):
    require(type(report) is dict and report['schema']=='ptlc-nom-signed-process-cuts-v1' and report['outcome']=='PASS')
    require(type(report['cases']) is list and len(report['cases'])==6)
    expected_files=['subject-before-first-spawn.json']
    for index,(cut,row) in enumerate(zip(CUTS,report['cases'])):
        require(type(row) is dict and row['cut']==cut and type(row['actor_exit']) is int and row['actor_exit']==72)
        require(type(row['charge']) is int and row['charge']==(0 if index==0 else 1))
        booleans=dict(actor_complete=True,completion_present=index>=3,signed_long_present=index>=4,
            short_original_exact=True,long_original_exact_or_absent=True,diagnostic_result_present=index>=2,
            journal_unchanged=True,unknown_retry_refused=index in (1,2))
        require(all(type(row[key]) is bool and row[key] is value for key,value in booleans.items()))
        require(row['actor_modes']==list(ACTOR_MODES[index]) and row['reopen_modes']==list(REOPEN_MODES[index]))
        counts=dict(reopen_recovery_entries=0,reopen_observer_calls=0,
            actor_recovery_entries=1 if index>=2 else 0,actor_recovery_returns=1 if index>=2 else 0)
        require(all(type(row[key]) is int and row[key]==value for key,value in counts.items()))
        require(type(row['attempts']) is dict and row['attempts']==({'long':1} if index==5 else {}))
        if index==5:require(type(row['attempts']['long']) is int)
        require(row['long_phase']==('OUTCOME_UNKNOWN' if index==5 else 'ORIGINAL_RETAINED' if index==4 else None))
        expected_files += [cut+'/'+name for name in ('configuration-before-spawn.json','actor.stdout','actor.stderr',
            'actor.receipt.json','cut-receipt.json','journal.log')]
        expected_files += [cut+f'/worker/call-{n:03d}.'+suffix for n in range(1,len(ACTOR_MODES[index])+1)
            for suffix in ('stdin','stdout','stderr','receipt.json')]
    expected_files += [f'reopen-worker/call-{n:03d}.'+suffix for n in range(1,18)
        for suffix in ('stdin','stdout','stderr','receipt.json')]
    require(type(report['original_files']) is list and report['original_files']==expected_files and len(expected_files)==189)
    for key,value in dict(actor_worker_calls=21,reopen_worker_calls=17,additional_recovery_entries_on_reopen_or_retry=0).items():
        require(type(report[key]) is int and report[key]==value)
    boundaries=dict(application='NO-GO',core='NO-GO',independent_assessment='UNFILLED',
        observation_source='DISCLOSED_SYNTHETIC_ALLOWLIST',raw_verifier='DISCLOSED_SOURCE_CORPUS_LOOKUP',
        process_cut='ACTUAL SELF EXIT72 AFTER COMPLETE FSYNC OR REAPED PUBLIC REPLY',power_loss='NOT_PERFORMED',
        restore_fence='UNFILLED',worker_build='BYTE_PIN_ONLY; SOURCE_BUILD_AND_LOADER_AUTHENTICATION_SEPARATE',
        containment='TRUSTED_NONFORKING_ACTOR_AND_WORKER; NOT_HOSTILE_PROCESS_SANDBOX',profile='OFFLINE_RESEARCH_CANDIDATE_ONLY')
    require(all(report[key]==value for key,value in boundaries.items()))
    return dict(outcome='PASS_SELECTED_REPORT_ONLY',cases=6,original_files=189,native_executions=0)

def inspect(payloads,report,root):
    check_report(report)
    from offline_session.nom_verifier import NomPublicVerifier
    from offline_session import nom_recovery as base
    from offline_session.nom_signed_recovery import CONTEXT_SCHEMA
    from scripts.nom_signed_corpus import SourceCorpusAllowlist,signed_observation
    from scripts.qualify_nom_signed_originals import inputs
    expected_names=names()
    require(type(payloads) is dict and set(payloads)==set(expected_names) and len(payloads)==189)
    require(all(type(raw) is bytes and len(raw)<=256*1024 for raw in payloads.values()))
    require(sum(map(len,payloads.values()))<=8*1024**2)
    for name in payloads:
        selected=PurePosixPath(name)
        require(not selected.is_absolute() and selected.as_posix()==name and '..' not in selected.parts and '\\' not in name)
    require(report['schema']=='ptlc-nom-signed-process-cuts-v1' and report['outcome']=='PASS')
    require(report['original_files']==expected_names and len(report['cases'])==6)
    require(report['application']==report['core']=='NO-GO' and report['independent_assessment']=='UNFILLED')
    require(report['power_loss']=='NOT_PERFORMED' and report['restore_fence']=='UNFILLED')
    manifest,unused,records=inputs(root);selected_inputs=profile_inputs(root)
    terms=decode((root/'compatibility/fixtures/nom_supervisor_inputs_v1.json').read_bytes())['terms']
    completions=decode((root/'compatibility/fixtures/nom_supervisor_completions_v1.json').read_bytes())
    pair=completions['pair']
    selection=dict(schema=CONTEXT_SCHEMA,source_commit=manifest['core_commit'],source_tree=manifest['core_tree'],
        corpus_sha256=manifest['record_set_payload_sha256'],contract_hex=records['long-original']['block']['to_address_hex'])
    lookup=SourceCorpusAllowlist(terms,pair,selection,records)
    short=bytes.fromhex(records['short-original']['wire_hex']);long=bytes.fromhex(records['long-original']['wire_hex'])
    funded=[signed_observation(terms,completions,lookup,leg,'funded') for leg in ('long','short')]
    confirmed=signed_observation(terms,completions,lookup,'short','unlock-confirmed',short)
    short_event=dict(kind='signed-original',leg='short',wire_hex=short.hex(),facts_wire_hex=lookup.verify_original('short',short).hex())
    long_event=dict(kind='signed-original',leg='long',wire_hex=long.hex(),facts_wire_hex=lookup.verify_original('long',long).hex())
    builder=NomPublicVerifier.__new__(NomPublicVerifier);builder._terms=terms;builder._pair=pair
    builder.context_digest_hex=base.verification_context_digest(terms,pair)
    prelude=decode(payloads['subject-before-first-spawn.json'])
    require(set(prelude)=={'public_inputs','actor_sha256','parent_sha256','python_sha256','worker_sha256','profile'})
    require(prelude['profile']=='SELECTED_OFFLINE_PROCESS_CUTS_ONLY')
    require(prelude['parent_sha256']==selected_inputs['scripts/qualify_nom_signed_process_cuts.py'])
    require(prelude['actor_sha256']==selected_inputs['scripts/nom_signed_process_actor.py'])
    require(prelude['public_inputs']==report['source_input_sha256']==selected_inputs)
    for key in ('actor_sha256','python_sha256','worker_sha256'):
        require(prelude[key]==report[key])
    seen_calls=0;seen_recoveries=0
    def calls(prefix,modes,phases):
        nonlocal seen_calls,seen_recoveries
        for number,(mode,phase) in enumerate(zip(modes,phases),1):
            stem=prefix+f'call-{number:03d}.'
            receipt=decode(payloads[stem+'receipt.json'])
            require(set(receipt)=={'number','phase','request_hex','request_sha256','stdout_hex','stdout_sha256',
                'stderr_hex','stderr_sha256','exit_code','stream_completeness'})
            require(type(receipt['number']) is int and receipt['number']==number)
            require(type(receipt['exit_code']) is int and receipt['exit_code']==0 and receipt['stream_completeness']=='COMPLETE')
            require(receipt['phase']==phase)
            for suffix,label in (('stdin','request'),('stdout','stdout'),('stderr','stderr')):
                wire=payloads[stem+suffix]
                require(receipt[label+'_hex']==wire.hex() and receipt[label+'_sha256']==sha(wire))
            signature='' if mode=='verify-pair' else completions[('short' if mode in ('verify-short','recover-long') else 'long')+'_signature_hex']
            request=canonical(builder.request(mode,signature))
            require(payloads[stem+'stdin']==request and payloads[stem+'stderr']==b'')
            require(payloads[stem+'stdout']==canonical(dict(schema='ptlc-nom-public-verification-result-v1',
                request_digest_hex=sha(request),valid=True,
                completed_long_hex=completions['long_signature_hex'] if mode=='recover-long' else '')))
            seen_calls+=1;seen_recoveries+=int(mode=='recover-long')
    for index,(cut,modes,row) in enumerate(zip(CUTS,ACTOR_MODES,report['cases'])):
        config=decode(payloads[cut+'/configuration-before-spawn.json'])
        require(set(config)=={'schema','cut','source_input_sha256','actor_sha256','python_sha256','worker_sha256'}
            and config['schema']=='ptlc-nom-signed-process-selection-v1')
        require(config['cut']==cut and config['source_input_sha256']==selected_inputs)
        require(config['actor_sha256']==report['actor_sha256'] and config['python_sha256']==report['python_sha256']
            and config['worker_sha256']==report['worker_sha256'])
        marker=canonical(dict(schema='ptlc-nom-signed-process-marker-v1',cut=cut,method='os._exit(72)'))+b'\n'
        require(payloads[cut+'/actor.stdout']==marker and payloads[cut+'/actor.stderr']==b'')
        actor=decode(payloads[cut+'/actor.receipt.json'])
        require(set(actor)=={'exit_code','stream_completeness','stdout_hex','stdout_sha256','stderr_hex','stderr_sha256'})
        require(type(actor['exit_code']) is int and actor['exit_code']==72 and actor['stream_completeness']=='COMPLETE')
        for suffix in ('stdout','stderr'):
            require(actor[suffix+'_hex']==payloads[cut+'/actor.'+suffix].hex()
                and actor[suffix+'_sha256']==sha(payloads[cut+'/actor.'+suffix]))
        events=[dict(kind='init',role='bob',terms=terms,pair=pair),dict(kind='signed-context',selection=selection)]
        events += [dict(kind='signed-observation',wire_hex=value.hex()) for value in funded]
        events.append(short_event)
        if index>=1:events += [dict(kind='signed-observation',wire_hex=confirmed.hex()),dict(kind='signed-admitted',wire_sha256=sha(short))]
        if index>=3:events.append(dict(kind='signed-recovered',wire_sha256=sha(short),signature_hex=completions['long_signature_hex']))
        if index>=4:events.append(long_event)
        if index>=5:events.append(dict(kind='signed-attempt',leg='long',wire_sha256=sha(long)))
        require(canonical(journal_events(payloads[cut+'/journal.log']))==canonical(events))
        retained=completions['long_signature_hex'] if index>=3 else None
        diagnostic=completions['long_signature_hex'] if index>=2 else None
        hook=('SIGNED_SHORT_RETAINED','signed-admitted','PUBLIC_REPLY_BEFORE_RECOVERED_APPEND',
            'signed-recovered','SIGNED_LONG_RETAINED','signed-attempt')[index]
        expected_cut=dict(schema='ptlc-nom-signed-process-cut-v1',cut=cut,hook=hook,method='os._exit(72)',
            worker_modes=list(modes),recovery_entries=int(index>=2),recovery_returns=int(index>=2),
            diagnostic_public_result=diagnostic,observer_calls_before_cut=[value.hex() for value in funded+([confirmed] if index>=1 else [])],
            charge=int(index>=1),retained_completion=retained,signed_legs=['long','short'] if index>=4 else ['short'],
            attempts={'long':1} if index==5 else {})
        require(payloads[cut+'/cut-receipt.json']==canonical(expected_cut))
        require(row['cut']==cut and type(row['actor_exit']) is int and row['actor_exit']==72)
        require(type(row['charge']) is int and row['charge']==int(index>=1))
        require(type(row['completion_present']) is bool and row['completion_present'] is (index>=3))
        require(type(row['signed_long_present']) is bool and row['signed_long_present'] is (index>=4))
        calls(cut+'/worker/',modes,[cut+':write']*len(modes))
    reopen_modes=tuple(mode for modes in REOPEN_MODES for mode in modes)
    reopen_phases=[cut+':reopen' for cut,modes in zip(CUTS,REOPEN_MODES) for unused_mode in modes]
    calls('reopen-worker/',reopen_modes,reopen_phases)
    require(seen_calls==38 and seen_recoveries==4)
    return dict(outcome='PASS_FINITE_ORIGINALS_ONLY',original_files=189,selected_actor_exit_receipts=6,
        retained_worker_calls=38,retained_recovery_calls=4,reopen_recovery_calls=0,
        journal_apply_method_used=False,additional_native_execution=0,rollback_authority='UNFILLED',
        physical_power_loss='NOT_PERFORMED',independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')


def selected_artifact_names(evidence,root):
    """Validate an explicit manifest, including known safe partial failure files."""
    from scripts.check_artifacts import PATTERNS
    retained=decode((evidence/'retention-manifest.json').read_bytes())
    require(retained['schema']=='ptlc-nom-signed-process-cut-originals-v1')
    require(retained['application']==retained['core']=='NO-GO' and retained['independent_assessment']=='UNFILLED')
    complete=retained['originals_complete'];require(type(complete) is bool)
    require(retained['qualification_outcome']==('PASS' if complete else 'FAILED_OR_INCOMPLETE'))
    expected=set(names())|{'qualification-result.json'}
    require(type(retained['files']) is dict and set(retained['files'])<=expected and 'qualification-result.json' in retained['files'])
    if complete:require(set(retained['files'])==expected)
    payloads={}
    for name,pin in retained['files'].items():
        path=evidence/name;info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=256*1024)
        raw=path.read_bytes()
        require(type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int)
        require(pin==dict(bytes=len(raw),sha256=sha(raw)));payloads[name]=raw
    require(sum(map(len,payloads.values()))<=8*1024**2)
    report=decode(payloads['qualification-result.json'])
    require(report['outcome']==retained['qualification_outcome'] and report['subject_commit']==retained['subject_commit'])
    if complete:inspect({name:payloads[name] for name in names()},report,root)
    payloads['retention-manifest.json']=(evidence/'retention-manifest.json').read_bytes()
    for raw in payloads.values():
        text=raw.decode('ascii')
        require(not any(pattern.search(text) for unused,pattern in PATTERNS))
        require(not re.search(r'/(?:Users|Volumes|private)/|localhost|\b[A-Za-z0-9_-]+[.]local\b',text,re.I))
    return sorted(payloads)
