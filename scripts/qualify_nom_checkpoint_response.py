#!/usr/bin/env python3
"""Qualify selected public response mathematics without an operational service."""
import argparse
import copy
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from offline_session import nom_checkpoint_response as framing  # noqa: E402
from offline_session import nom_checkpoint_discovery as discovery  # noqa: E402
from offline_session.public_worker import WorkerError  # noqa: E402
from qualification.nom_checkpoint_response_verifier import PublicCheckpointResponseCheck  # noqa: E402
from scripts import qualify_nom_checkpoint_discovery as prior  # noqa: E402
from scripts.nom_cut_capture import sha  # noqa: E402
from scripts.nom_checkpoint_response_capture import capture_original  # noqa: E402

PROFILE = "ptlc-nom-checkpoint-response-qualification-v1"
BASE = "2bf22c4abcf253807b46d04138ae1f50759a60ab"
MANIFEST = "compatibility/nom_checkpoint_response_manifest.json"
FIXTURE = "compatibility/fixtures/nom_checkpoint_response_v1.json"
SIGNED = "qualification/fixtures/nom_checkpoint_response.json"
UNSIGNED = "qualification/fixtures/nom_checkpoint_response_unsigned.json"
ROOT_KEY = "6a27aedb12c9a3015ecdf2ead78755cfc3ef72d2c60ccd0033da18fbf9979641"
ALTERNATE_ROOT_KEY = "9fbe8ad98eb962605c09d4541bf3ea4f95323236e3d729824e946376160f7031"
POSITIVE = ("minimum_candidate","newer_candidate","later_minimum","unavailable_service",
    "fresh_old_candidate","sibling_candidate","root_rotation","new_epoch")
SELECTED = ("offline_session/nom_checkpoint_response.py", "qualification/nom_checkpoint_response_verifier.py",
    "qualification/examples/verify_nom_checkpoint_response.rs", "qualification/tests/nom_checkpoint_response.rs",
    "qualification-go/nom_checkpoint_response_test.go", "scripts/nom_checkpoint_response_capture.py",
    "scripts/qualify_nom_checkpoint_response.py", "tests/test_nom_checkpoint_response.py", FIXTURE, SIGNED, UNSIGNED)
BOUNDARY = dict(application="NO-GO",core="NO-GO",recovery_action="NONE",framing_core_worker_calls=0,
    signature_mathematics="SELECTED PUBLIC ROOT GRANT AND RESPONSE; ACTUAL NATIVE EXITS MEASURED SEPARATELY",
    root_provisioning="UNFILLED",current_service_read="NOT_IMPLEMENTED",candidate_latest="NOT_ESTABLISHED",
    service_nonrollback="NOT_IMPLEMENTED",checkpoint_storage="NOT_IMPLEMENTED",atomic_service_cas="NOT_IMPLEMENTED",
    atomic_work_entry="NOT_IMPLEMENTED",independent_assessment="UNFILLED",physical_power_loss="UNFILLED",
    preserved_core_source_outcomes=342,new_core_source_outcomes=0,
    actual_openings="COMPLETE RETAINED CONTEXTS REQUIRED BEFORE VERIFICATION; NEVER RECONSTRUCTED")


def corpus():
    return dict(schema=PROFILE,research_baseline_commit=BASE,positive_contexts=list(POSITIVE),
        expected_native_requests=23,expected_native_successes=9,expected_native_refusals=14,
        unsafe_controls=["freshly_signed_old_candidate","coherent_restore","signed_siblings",
            "packet_selected_root_mathematics","forged_callback_zero_response_signature","signed_outage"],
        root_role="SEPARATE SELECTED ROOT; SERVICE POLICY FIXES THE RESPONSE KEY; REAL PROVISIONING UNFILLED",
        synthetic_notice="Fixed disclosed tags 111,112 and 83; no application signer or private key input",boundary=BOUNDARY)


def inputs(root=ROOT):
    _,preserved=prior.inputs(root)
    selected={name:sha((root/name).read_bytes()) for name in SELECTED}
    expected=dict(schema="ptlc-nom-checkpoint-response-manifest-v1",profile=PROFILE,
        research_baseline_commit=BASE,input_sha256=selected,preserved_file_sha256=preserved,boundary=BOUNDARY)
    if json.loads((root/FIXTURE).read_text('ascii'))!=corpus() or json.loads((root/MANIFEST).read_text('ascii'))!=expected:
        raise ValueError("selected checkpoint response inputs changed")
    return expected,{**preserved,**selected,MANIFEST:sha((root/MANIFEST).read_bytes())}


def fixture_cases(root=ROOT):
    _,contexts,_,refs=prior.fixture_contexts(root)
    reads={name:discovery.checkpoint_read(refs[minimum],challenge_hex=challenge) for name,minimum,challenge in
        (("initial","initial","d1"*32),("later","latest","d1"*32),("fresh","initial","d2"*32))}
    openings={name:discovery.checkpoint_opening(refs[name]) for name in ("initial","latest","tail","sibling")}
    choices=(
        ("minimum_candidate","initial","initial",ROOT_KEY,1),
        ("newer_candidate","initial","latest",ROOT_KEY,1),
        ("later_minimum","later","tail",ROOT_KEY,1),
        ("unavailable_service","initial",None,ROOT_KEY,1),
        ("fresh_old_candidate","fresh","initial",ROOT_KEY,1),
        ("sibling_candidate","initial","sibling",ROOT_KEY,1),
        ("root_rotation","initial","latest",ALTERNATE_ROOT_KEY,1),
        ("new_epoch","initial","latest",ROOT_KEY,2))
    cases={}
    for name,read_name,opening_name,key,epoch in choices:
        read=reads[read_name];opening=None if opening_name is None else openings[opening_name]
        selected=framing.select_response_authority(read,root_key_hex=key,epoch=epoch)
        reply=discovery.unavailable_reply(read) if opening is None else discovery.discovery_reply(read,opening)
        cases[name]=dict(selected=selected,reply=reply,opening=opening,local=contexts['primary'])
    return cases


def unsigned_fixture(cases):
    rows={}
    for name,case in cases.items():
        envelope=framing.response_envelope(case['selected'],root_signature_hex="00"*64,response_signature_hex="00"*64)
        rows[name]=framing.response_signature_request(case['selected'],case['reply'],envelope,case['opening'])
    return dict(schema="ptlc-nom-checkpoint-response-unsigned-fixture-v1",cases=rows,
        synthetic_notice="Public framing only; native test generator signs fixed disclosed tags 111,112 and 83")


def public_fixture(root=ROOT):
    value=json.loads((root/SIGNED).read_text('ascii'))
    if value['schema']!='ptlc-nom-checkpoint-response-public-vectors-v1' or set(value['positive_vectors'])!=set(POSITIVE):
        raise ValueError("selected response vectors changed")
    return value


def expected_native_requests(root=ROOT):
    fixture=public_fixture(root);vectors=fixture['positive_vectors']
    rows=[(name,vectors[name]['request'],0) for name in POSITIVE]
    primary=vectors['newer_candidate']['request']
    alternate=copy.deepcopy(primary);alternate['response_signature_hex']=fixture['alternate_response_signature_hex']
    rows.append(('alternate-response-signature',alternate,0))
    for group in ('wrong_domain_signatures','wrong_role_signatures'):
        for field in ('root_signature_hex','response_signature_hex'):
            changed=copy.deepcopy(primary);changed[field]=fixture[group][field];rows.append((group+':'+field,changed,1))
    for field in ('root_signature_hex','response_signature_hex'):
        changed=copy.deepcopy(primary);changed[field]='00'*64;rows.append(('zero:'+field,changed,1))
    old=json.loads((root/'qualification/fixtures/enrollment_signature.json').read_text('ascii'))
    changed=copy.deepcopy(primary);changed['response_signature_hex']=old['request']['signature_hex']
    rows.append(('old-enrollment-permission',changed,1))
    old=json.loads((root/'qualification/fixtures/nom_source_checkpoint.json').read_text('ascii'))['positive_vectors']['primary']['request']
    for field,old_field in (('root_signature_hex','root_signature_hex'),('response_signature_hex','source_signature_hex')):
        changed=copy.deepcopy(primary);changed[field]=old[old_field];rows.append(('old-source-permission:'+field,changed,1))
    for phase,field in (('changed-discovery-message','discovery_message_digest_hex'),('changed-query','query_digest_hex')):
        changed=copy.deepcopy(primary);changed[field]='81'*32;rows.append((phase,changed,1))
    changed=copy.deepcopy(primary);changed['declaration']['work_scope_digest_hex']='82'*32;rows.append(('changed-work-scope',changed,1))
    changed=copy.deepcopy(primary);changed['declaration']['root_key_hex']=ALTERNATE_ROOT_KEY;rows.append(('changed-root',changed,1))
    old=json.loads((root/'qualification/fixtures/enrollment_signature.json').read_text('ascii'))
    changed=copy.deepcopy(primary);policy=changed['declaration']['service_selection']
    policy['checkpoint_key_hex']=old['alternate_owner']['intent']['owner_auth_key_hex']
    changed['declaration']['service_selection_digest_hex']=framing.protocol._hash(framing.protocol.POLICY_DOMAIN,policy)
    rows.append(('changed-service-key',changed,1))
    if len(rows)!=23 or sum(code==0 for _,_,code in rows)!=9: raise ValueError("native response plan changed")
    return rows


class ResponseCapture:
    """One exact trusted math request at a time; transport may be manager-backed."""
    def __init__(self,executable,pin,*,transport=None,emit_original=None):
        self.executable=Path(executable).resolve();self.pin=pin;self.calls=[];self.phase='UNSELECTED';self.transport=transport
        self.emit_original=emit_original

    def run(self,executable,wire,*,timeout,max_input_bytes,max_output_bytes):
        if Path(executable)!=self.executable or sha(self.executable.read_bytes())!=self.pin or timeout!=5 or max_input_bytes!=8192 or max_output_bytes!=512:
            raise WorkerError("selected response capture boundary changed")
        row=(self.transport(self.phase,wire) if self.transport is not None else capture_original(self.executable,wire,
            expected_pin=self.pin,timeout=timeout,max_input_bytes=max_input_bytes,max_output_bytes=max_output_bytes))
        row=dict(row,number=len(self.calls)+1,phase=self.phase)
        self.calls.append(row)
        if self.emit_original is not None:
            self.emit_original(row)
        if row['stream_completeness']!='COMPLETE' or row['exit_code']!=0:
            raise WorkerError("actual public response worker refused or was not qualified")
        return bytes.fromhex(row['stdout_hex'])


def validate_native_calls(calls,root=ROOT):
    requests=expected_native_requests(root)
    if len(calls)!=len(requests): raise ValueError("native response request count changed")
    for number,(row,(phase,request,code)) in enumerate(zip(calls,requests),1):
        wire=framing.codec._canonical(request)
        expected=b'' if code else framing.codec._canonical(framing.expected_result(framing.request_digest(request)))+b'\n'
        error=b'selected public checkpoint signature check refused\n' if code else b''
        if (type(row['number']) is not int or type(row['exit_code']) is not int
            or row['number']!=number or row['phase']!=phase or row['request_hex']!=wire.hex()
            or row['request_sha256']!=sha(wire) or row['exit_code']!=code or row['stream_completeness']!='COMPLETE'
            or row['stdout_hex']!=expected.hex() or row['stdout_sha256']!=sha(expected)
            or row['stderr_hex']!=error.hex() or row['stderr_sha256']!=sha(error)):
            raise ValueError("native response original outcome changed")


def unsafe_results(results,cases,fixture):
    minimum=cases['minimum_candidate'];vector=fixture['positive_vectors']['minimum_candidate']
    old=minimum['selected']
    # A fresh equivalent reference selection retains the same actual originals.
    # This controlled comparison is not an actual storage restore or power cut.
    read=discovery.checkpoint_read(old._read._minimum,challenge_hex=old._read.as_dict()['challenge_hex'])
    restored=framing.select_response_authority(read,root_key_hex=old._root_key_hex,epoch=old._epoch)
    opening=discovery.checkpoint_opening(minimum['opening']._candidate)
    def exact_cached(request):
        if framing.codec._canonical(request)!=framing.codec._canonical(vector['request']):
            raise ValueError('cached public signature result changed request')
        return copy.deepcopy(vector['result'])
    coherent=framing.inspect_signed_discovery(minimum['local'],restored,minimum['reply'],
        framing.codec._canonical(vector['envelope']),opening,verify_public=exact_cached)
    case=cases['newer_candidate'];zero=copy.deepcopy(fixture['positive_vectors']['newer_candidate']['envelope'])
    zero['response_signature_hex']='00'*64
    echo=framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],framing.codec._canonical(zero),case['opening'],
        verify_public=lambda request:framing.expected_result(framing.request_digest(request)))
    first=results['newer_candidate'];second=results['sibling_candidate']
    return dict(freshly_signed_old_candidate=results['fresh_old_candidate'],
        coherent_restore=dict(comparison=coherent,additional_native_requests=0,
            scope='EQUIVALENT COMPLETE REFERENCE SELECTION; EXACT PREVIOUS PUBLIC RESULT REUSED; NO PHYSICAL RESTORE'),
        signed_siblings=dict(first=first['candidate_checkpoint_digest_hex'],second=second['candidate_checkpoint_digest_hex'],
            same_sequence=first['candidate_sequence']==second['candidate_sequence'],unique_current_head='NOT_ESTABLISHED'),
        packet_selected_root_mathematics=dict(native_phase='root_rotation',mathematics_verified=True,root_provisioning='UNFILLED'),
        forged_callback_zero_response_signature=dict(comparison=echo,actual_native_refusal_phase='zero:response_signature_hex',
            additional_native_requests=0,callback_mathematics='ASSERTION ONLY; ACTUAL WORKER REFUSES THIS EXACT ZERO SIGNATURE'),
        signed_outage=results['unavailable_service'])


def compare(cases,fixture,checker,capture):
    results={}
    with patch('qualification.nom_checkpoint_response_verifier.run_public_worker',side_effect=capture.run):
        for name in POSITIVE:
            case=cases[name];vector=fixture['positive_vectors'][name];envelope=framing.codec._canonical(vector['envelope'])
            request=framing.response_signature_request(case['selected'],case['reply'],envelope,case['opening'])
            if request!=vector['request']: raise ValueError("public response vectors differ from actual complete inputs")
            capture.phase=name
            results[name]=framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],envelope,case['opening'],verify_public=checker)
        refused=[]
        for phase,request,code in expected_native_requests():
            if phase in POSITIVE: continue
            capture.phase=phase
            try: checker(request)
            except framing.CheckpointResponseRefused:
                if code!=1: raise
                refused.append(phase)
            else:
                if code!=0: raise ValueError("actual response worker accepted invalid public mathematics")
    return results,refused,unsafe_results(results,cases,fixture)


def qualify(executable,*,transport=None,capture=None,root=ROOT):
    _,measured=inputs(root);cases=fixture_cases(root);fixture=public_fixture(root)
    if json.loads((root/UNSIGNED).read_text('ascii'))!=unsigned_fixture(cases):
        raise ValueError("unsigned response fixture differs from actual complete openings")
    pin=sha(Path(executable).read_bytes())
    if capture is None: capture=ResponseCapture(executable,pin,transport=transport)
    if capture.executable!=Path(executable).resolve() or capture.pin!=pin: raise ValueError('capture subject changed')
    checker=PublicCheckpointResponseCheck(Path(executable).resolve(),expected_executable_sha256_hex=pin)
    results,refused,unsafe=compare(cases,fixture,checker,capture)
    validate_native_calls(capture.calls,root)
    return dict(schema='ptlc-nom-checkpoint-response-result-v1',profile=PROFILE,outcome='PASS',input_sha256=measured,
        executable_sha256=pin,native_calls=capture.calls,native_requests=23,native_successes=9,native_refusals=14,
        comparison_results=results,expected_refusals=refused,unsafe_controls=unsafe,boundary=BOUNDARY)


def check_cases(value,root=ROOT):
    if value['schema']!='ptlc-nom-checkpoint-response-result-v1' or value['profile']!=PROFILE or value['outcome']!='PASS' or value['boundary']!=BOUNDARY:
        raise ValueError("response qualification boundary changed")
    if value['input_sha256']!=inputs(root)[1] or (value['native_requests'],value['native_successes'],value['native_refusals'])!=(23,9,14):
        raise ValueError("response qualification input or native scope changed")
    validate_native_calls(value['native_calls'],root)
    cases=fixture_cases(root);fixture=public_fixture(root)
    if json.loads((root/UNSIGNED).read_text('ascii'))!=unsigned_fixture(cases): raise ValueError("complete unsigned openings changed")
    for name in POSITIVE:
        case=cases[name];vector=fixture['positive_vectors'][name]
        request=framing.response_signature_request(case['selected'],case['reply'],framing.codec._canonical(vector['envelope']),case['opening'])
        if request!=vector['request']: raise ValueError("complete response opening changed")
        result=framing.inspect_signed_discovery(case['local'],case['selected'],case['reply'],framing.codec._canonical(vector['envelope']),case['opening'],
            verify_public=lambda request:framing.expected_result(framing.request_digest(request)))
        if framing.codec._canonical(result)!=framing.codec._canonical(value['comparison_results'][name]):
            raise ValueError("complete response comparison changed")
    if value['expected_refusals']!=[phase for phase,_,code in expected_native_requests(root) if code==1]:
        raise ValueError("expected actual response refusals changed")
    if set(value['unsafe_controls'])!=set(corpus()['unsafe_controls']): raise ValueError("unsafe response controls missing")
    if framing.codec._canonical(value['unsafe_controls'])!=framing.codec._canonical(unsafe_results(value['comparison_results'],cases,fixture)):
        raise ValueError('complete unsafe response controls changed')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',type=Path,default=ROOT/'qualification/target/debug/examples/verify_nom_checkpoint_response')
    args=parser.parse_args()
    capture=None
    try:
        pin=sha(args.executable.read_bytes())
        def emit_original(row):
            print('PUBLIC_CHECKPOINT_RESPONSE_NATIVE_ORIGINAL:'+json.dumps(row,sort_keys=True),flush=True)
        capture=ResponseCapture(args.executable,pin,emit_original=emit_original)
        value=qualify(args.executable,capture=capture)
    except (ValueError,TypeError,OSError,KeyError):
        print(json.dumps(dict(schema='ptlc-nom-checkpoint-response-unqualified-originals-v1',outcome='NOT_QUALIFIED',
            native_calls=[] if capture is None else capture.calls,boundary=BOUNDARY),sort_keys=True),flush=True)
        print('selected public checkpoint response qualification refused',file=sys.stderr);return 1
    print(json.dumps(value,sort_keys=True));return 0


if __name__=='__main__': raise SystemExit(main())
