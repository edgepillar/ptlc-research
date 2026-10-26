"""Independent reclaim encodings and finite VM expectations, without authority.

Public fixture keys are intentionally known constants. This module signs
nothing, launches no process and supplies no application cryptography.
"""
import ast
import copy
import hashlib
from pathlib import Path

from offline_session import nom_wire, pr138
from qualification import nom_dev_661b5ef_legacy as legacy
from qualification import nom_dev_abi_boundary as framing

ROOT, CORE, TREE = legacy.ROOT, legacy.CORE, legacy.TREE
common = legacy.earlier
require = common.require
MANIFEST = 'compatibility/nom_dev_661b5ef_reclaim_manifest.json'
INPUT = 'compatibility/fixtures/nom_dev_661b5ef_reclaim_inputs_v1.json'
VALUES = 'compatibility/fixtures/nom_dev_661b5ef_reclaim_values_v1.json'
DRIVER = 'compatibility/nom_dev_661b5ef_reclaim_test.go.txt'
DESTINATION = 'vm/zz_research_nom_dev_661b5ef_reclaim_test.go'
PARENT = 'TestResearchNoMCurrentReclaim'
PACKAGE = 'github.com/zenon-network/go-zenon/vm'
UNIT = 'reclaim-current'
FRAMING = 'qualification/nom_dev_abi_boundary.py'
MAX_STDOUT, MAX_STDERR, MAX_REPORT, MAX_EVENTS = 2*common.MIB, 64*1024, common.MIB, 4096
OWN_INPUTS = {INPUT, VALUES, DRIVER, FRAMING, legacy.MANIFEST,
    'qualification/nom_dev_661b5ef_reclaim.py', 'tests/test_nom_dev_661b5ef_reclaim.py'}
DOMAIN = b'zenon-ptlc-reclaim:v1'
CREATE = 'CreateWithReclaimLock'
RECLAIM = 'ReclaimWithSignature'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def declaration():
    materials = dict(chain_id='69', creator_hex='00'+'11'*19,
        destination_hex='00'+'22'*19, other_hex='00'+'33'*19,
        token_hex='44'*10, amount='1000', expiration_time='1000', create_time='900',
        claim_points={
            '0':'8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            '1':'5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc',
            '2':'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'},
        reclaim_points={
            '0':'3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29',
            '1':'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'},
        alternate_reclaim_points={
            '0':'d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            '1':'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'})
    cases = []
    def add(kind, mode, claim=2, reclaim=0):
        cases.append(dict(id=kind+'_'+mode+'_c'+str(claim)+'_r'+str(reclaim),
            kind=kind, mode=mode, claim_type=claim, reclaim_type=reclaim))
    for claim in range(3):
        for reclaim in range(2):add('message','base',claim,reclaim)
    for mode in ('chain_zero','chain_max','chain_endian','other_creator','open_destination',
        'other_destination','other_token','amount_one','amount_max','expiry_endian',
        'other_claim_point','other_id'):add('message',mode)
    for method in ('create','reclaim'):
        for mode in ('canonical','trailing_1','trailing_32','truncated','unknown_selector'):
            add('send',method+'_'+mode)
    for mode in ('create_zero_amount','create_negative_amount','create_scalar_reclaim',
        'create_bad_claim_type','create_short_reclaim_point','create_multisig_destination',
        'reclaim_nonzero_amount','reclaim_short_signature'):add('send',mode)
    for reclaim in range(2):
        for mode in ('reclaim_before','reclaim_at','reclaim_after','wrong_caller',
            'wrong_signature','wrong_chain','wrong_terms','wrong_domain','missing_lock',
            'plain_reclaim_locked','short_signature','fresh_reclaim_key','unlock_before',
            'unlock_at','unlock_wrong_destination','reclaim_payout_failure',
            'unlock_payout_failure','same_terms_other_id'):add('vm',mode,reclaim=reclaim)
        for claim in (0,1):add('vm','unlock_before',claim,reclaim)
    require(len(cases)==76 and len({row['id'] for row in cases})==76)
    return dict(schema='ptlc-nom-dev-661b5ef-reclaim-inputs-v1',core_commit=CORE,core_tree=TREE,
        scope='PUBLIC SYNTHETIC INPUTS; KNOWN TEST CONSTANTS; NO APPLICATION KEYS',
        materials=materials,cases=cases)


def word(number):
    return (number % (1<<256)).to_bytes(32,'big')


def tail(raw):
    return word(len(raw))+raw+bytes((-len(raw))%32)


def abi(method, entry, reclaim_type, reclaim_point, *, identifier=bytes(32), signature=bytes(64)):
    if method=='Create':
        return nom_wire.encode_call(dict(method=method,expiration_time=entry['expiration_time'],
            point_type=entry['point_type'],point_lock_hex=entry['point_hex'],destination_hex=entry['destination_hex']))
    if method=='Reclaim':return nom_wire.encode_call(dict(method=method,entry_id_hex=identifier.hex()))
    if method==RECLAIM:
        selector=hashlib.sha3_256(b'ReclaimWithSignature(hash,bytes)').digest()[:4]
        return selector+identifier+word(64)+tail(signature)
    require(method==CREATE)
    point=bytes.fromhex(entry['point_hex']);offset=192+len(tail(point))
    selector=hashlib.sha3_256(b'CreateWithReclaimLock(int64,uint8,bytes,address,uint8,bytes)').digest()[:4]
    return (selector+word(int(entry['expiration_time']))+word(entry['point_type'])+word(192)
        +bytes(12)+bytes.fromhex(entry['destination_hex'])+word(reclaim_type)+word(offset)
        +tail(point)+tail(bytes.fromhex(reclaim_point)))


def entry_for(materials, case):
    return dict(creator_hex=materials['creator_hex'],destination_hex=materials['destination_hex'],
        token_hex=materials['token_hex'],amount=materials['amount'],expiration_time=materials['expiration_time'],
        point_type=case['claim_type'],point_hex=materials['claim_points'][str(case['claim_type'])])


def message(chain, reclaim_type, entry):
    raw=(DOMAIN+int(chain).to_bytes(8,'big')+bytes.fromhex(pr138.CONTRACT_HEX)+bytes([reclaim_type])
        +bytes.fromhex(entry['creator_hex'])+bytes.fromhex(entry['destination_hex'])+bytes.fromhex(entry['token_hex'])
        +int(entry['amount']).to_bytes(32,'big')+int(entry['expiration_time']).to_bytes(8,'big',signed=True)
        +bytes([entry['point_type']])+bytes.fromhex(entry['point_hex']))
    return raw,hashlib.sha3_256(raw).hexdigest()


def info_bytes(entry):
    return (bytes(12)+bytes.fromhex(entry['creator_hex'])+bytes(22)+bytes.fromhex(entry['token_hex'])
        +word(int(entry['amount']))+word(int(entry['expiration_time']))+word(entry['point_type'])
        +word(224)+bytes(12)+bytes.fromhex(entry['destination_hex'])+tail(bytes.fromhex(entry['point_hex'])))


def lock_bytes(point_type, point):
    return word(point_type)+word(64)+tail(bytes.fromhex(point))


def funding(materials, entry, reclaim_type, reclaim_point, *, legacy_entry=False, previous=None):
    data=abi('Create' if legacy_entry else CREATE,entry,reclaim_type,reclaim_point)
    block=dict(version='1',chain_id=materials['chain_id'],block_type='2',previous_hash_hex=previous or '00'*32,
        height='2' if previous else '1',momentum_hash_hex='55'*32,momentum_height='9',
        address_hex=entry['creator_hex'],to_address_hex=pr138.CONTRACT_HEX,amount=entry['amount'],
        token_standard_hex=entry['token_hex'],from_block_hash_hex='00'*32,descendant_hashes_hex=[],
        data_hex=data.hex(),fused_plasma='0',difficulty='0',nonce_hex='00'*7+('01' if previous else '00'))
    return nom_wire.account_block_hash(block)


def message_record(materials, case):
    e=entry_for(materials,case);chain=materials['chain_id'];mode=case['mode']
    if mode=='chain_zero':chain='0'
    elif mode=='chain_max':chain=str((1<<64)-1)
    elif mode=='chain_endian':chain=str(0x0102030405060708)
    elif mode=='other_creator':e['creator_hex']=materials['other_hex']
    elif mode=='open_destination':e['destination_hex']='00'*20
    elif mode=='other_destination':e['destination_hex']=materials['other_hex']
    elif mode=='other_token':e['token_hex']='66'*10
    elif mode=='amount_one':e['amount']='1'
    elif mode=='amount_max':e['amount']=str((1<<256)-1)
    elif mode=='expiry_endian':e['expiration_time']=str(0x0102030405060708)
    elif mode=='other_claim_point':e['point_hex']='02'+materials['claim_points']['1']
    identifier=('22' if mode=='other_id' else '11')*32
    raw,digest=message(chain,case['reclaim_type'],e)
    return dict(kind='message',reclaim_preimage_hex=raw.hex(),reclaim_message_hex=digest,
        unlock_message_hex=pr138.unlock_message(dict(profile=pr138.PROFILE,chain_id=chain,
            point_type=e['point_type'],entry_id_hex=identifier,destination_hex=e['destination_hex'])),
        changing_id_preserves_reclaim=True,changing_id_changes_unlock=True)


def send_record(materials, case):
    mode=case['mode'];e=entry_for(materials,case);reclaim_type=case['reclaim_type']
    point=materials['reclaim_points'][str(reclaim_type)];signature=bytes(64)
    method=CREATE if mode.startswith('create_') else RECLAIM
    amount=int(e['amount']) if method==CREATE else 0
    error='NONE'
    if mode=='create_scalar_reclaim':reclaim_type=2;point=materials['claim_points']['2'];error='ErrInvalidPointType'
    elif mode=='create_bad_claim_type':e['point_type']=3;error='ErrInvalidPointType'
    elif mode=='create_short_reclaim_point':point=point[:-2];error='ErrInvalidPointLock'
    elif mode=='create_multisig_destination':e['destination_hex']='02'+'22'*19;error='ErrInvalidDestination'
    elif mode=='create_zero_amount':amount=0;error='ErrInvalidTokenOrAmount'
    elif mode=='create_negative_amount':amount=-1;error='ErrInvalidTokenOrAmount'
    elif mode=='reclaim_nonzero_amount':amount=1;error='ErrInvalidTokenOrAmount'
    elif mode=='reclaim_short_signature':signature=bytes(32);error='ErrInvalidPointSignature'
    raw=abi(method,e,reclaim_type,point,identifier=bytes.fromhex('11'*32),signature=signature)
    canonical=raw
    if mode.endswith('trailing_1'):raw+=b'\0'
    elif mode.endswith('trailing_32'):raw+=bytes(32)
    elif mode.endswith('truncated'):raw=raw[:35];error='ErrUnpackError'
    elif mode.endswith('unknown_selector'):raw=bytes.fromhex('deadbeef')+raw[4:];error='ErrUnpackError'
    return dict(kind='send',method=method,amount=str(amount),input_hex=raw.hex(),
        post_validation_hex=(canonical if error=='NONE' else raw).hex(),returned_error=error)


def vm_record(materials, case):
    mode=case['mode'];e=entry_for(materials,case);rt=case['reclaim_type']
    point=materials['alternate_reclaim_points' if mode=='fresh_reclaim_key' else 'reclaim_points'][str(rt)]
    legacy_entry=mode=='missing_lock'
    primary=funding(materials,e,rt,point,legacy_entry=legacy_entry)
    count=2 if mode=='same_terms_other_id' else 1
    target=funding(materials,e,rt,point,previous=primary) if count==2 else primary
    at='999' if mode in ('reclaim_before','unlock_before','unlock_wrong_destination','unlock_payout_failure') else '1000'
    if mode=='reclaim_after':at='1001'
    error={'reclaim_before':'ReclaimNotDue','wrong_caller':'ErrPermissionDenied',
        'wrong_signature':'ErrInvalidPointSignature','wrong_chain':'ErrInvalidPointSignature',
        'wrong_terms':'ErrInvalidPointSignature','wrong_domain':'ErrInvalidPointSignature',
        'missing_lock':'ErrNoReclaimLock','plain_reclaim_locked':'ErrReclaimSignatureRequired',
        'short_signature':'ErrInvalidPointSignature','fresh_reclaim_key':'ErrInvalidPointSignature',
        'unlock_at':'ErrExpired','unlock_wrong_destination':'ErrPermissionDenied',
        'reclaim_payout_failure':'ErrInsufficientBalance','unlock_payout_failure':'ErrInsufficientBalance'}.get(mode,'NONE')
    amount=int(e['amount']);balance=count*amount-(1 if mode.endswith('payout_failure') else 0)
    success=error=='NONE';after=balance-(amount if success else 0)
    entry_hex=info_bytes(e).hex();lock_hex='' if legacy_entry else lock_bytes(rt,point).hex()
    primary_remains=not success or count==2
    digest=message(materials['chain_id'],rt,e)[1]
    signing=digest
    if mode=='wrong_chain':signing=message(str(int(materials['chain_id'])+1),rt,e)[1]
    elif mode=='wrong_terms':other=dict(e,amount=str(amount+1));signing=message(materials['chain_id'],rt,other)[1]
    elif mode=='wrong_domain' or mode.startswith('unlock_'):
        signing=pr138.unlock_message(dict(profile=pr138.PROFILE,chain_id=materials['chain_id'],point_type=e['point_type'],
            entry_id_hex=target,destination_hex=materials['other_hex'] if mode=='unlock_wrong_destination' else e['destination_hex']))
    if mode=='plain_reclaim_locked' or mode.startswith('unlock_') and case['claim_type']==2:
        signing=''
    return dict(kind='vm',funding_id_hex=primary,target_id_hex=target,fundings=count,
        confirming_time=at,reclaim_message_hex=digest,signing_message_hex=signing,
        witness_bytes=0 if mode=='plain_reclaim_locked' else 32 if mode=='short_signature' or mode.startswith('unlock_') and case['claim_type']==2 else 64,
        before_target_entry_hex=entry_hex,before_target_lock_hex=lock_hex,
        after_target_entry_hex='' if success else entry_hex,after_target_lock_hex='' if success else lock_hex,
        after_primary_entry_hex=entry_hex if primary_remains else '',
        after_primary_lock_hex=lock_hex if primary_remains else '',
        contract_balance_before=str(balance),contract_balance_after=str(after),returned_error=error,
        receipt_status='1' if success else '2',receipt_height=str(count+1+int(success)),
        receipt_momentum_hash_hex='66'*32,receipt_momentum_height='10',
        payouts=int(success),payout_amount=str(amount) if success else '0',
        payout_destination_hex=(e['destination_hex'] if mode.startswith('unlock_') else e['creator_hex']) if success else '',
        receipt_hash_self_consistent=True,original_send_bound=True,
        same_terms_other_id_message_equal=count==2)


def expected_report(declared=None):
    declared=declaration() if declared is None else declared
    common.rebase.exact(declaration(),declared)
    methods={'message':message_record,'send':send_record,'vm':vm_record}
    return dict(schema='ptlc-nom-dev-661b5ef-reclaim-result-v1',selected_core_commit=CORE,
        scope='FINITE PUBLIC ENCODING AND SELECTED MEMORY VM PATHS',
        records={case['id']:methods[case['kind']](declared['materials'],case) for case in declared['cases']},
        fixture_signing='KNOWN PUBLIC TEST CONSTANTS ONLY',application_signer_calls=0,
        account_admission='NOT_CALLED',chain_insertion='NOT_CALLED',journal_write='NOT_PERFORMED',
        recovery_action='NONE',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')


def inputs(root=ROOT):
    root=common.physical(root);legacy.inputs(root)
    manifest=legacy.read_json(root/MANIFEST)
    fixed=dict(schema='ptlc-nom-dev-661b5ef-reclaim-selection-v1',core_commit=CORE,core_tree=TREE,
        upstream_source_files=518,project_producers=21,combined_source_files=539,
        legacy_profiles=20,legacy_outcomes=479,reclaim_cases=76,reclaim_outcomes=77,
        application='NO-GO',core='NO-GO',journal_source_upgrade='NOT_SELECTED',independent_assessment='UNFILLED')
    require(set(manifest)==set(fixed)|{'input_sha256'})
    common.rebase.exact(fixed,{key:manifest[key] for key in fixed})
    require(set(manifest['input_sha256'])==OWN_INPUTS)
    for name,pin in manifest['input_sha256'].items():require(sha(common.regular(root/name,2*common.MIB))==pin)
    declared=legacy.read_json(root/INPUT);common.rebase.exact(declaration(),declared)
    values=legacy.read_json(root/VALUES);common.rebase.exact(expected_report(declared),values)
    return manifest,declared


def probes(root=ROOT):
    selected=dict(legacy.probes(root));require(DESTINATION not in selected)
    selected[DESTINATION]=DRIVER
    return selected


def compare_source(directory,root=ROOT):
    inputs(root)
    def selected_inputs(selected_root):
        unused,declared=inputs(selected_root)
        return unused,legacy.source.inputs(selected_root)[1]
    namespace=dict(vars(legacy.prior));namespace.update(CORE=CORE,TREE=TREE,inputs=selected_inputs,
        probes=lambda selected_root,profile:probes(selected_root))
    bound,unused=legacy._functions(root,legacy.prior,{'compare_source'},namespace)
    return bound['compare_source'](directory,root,'all')


def report_from_events(raw,root=ROOT):
    unused,declared=inputs(root)
    expected=expected_report(declared)
    selected={PACKAGE:{PARENT}|{PARENT+'/'+name for name in expected['records']}}
    measured=common.event_stream(raw,selected)
    require(measured['passed_including_parent']==77)
    path=Path(root)/FRAMING;source=common.regular(path,2*common.MIB)
    nodes=[node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name=='report_from_events']
    require(len(nodes)==1)
    namespace=dict(vars(framing));namespace.update(PARENT=PARENT,PACKAGE=PACKAGE,
        MAX_STDOUT=MAX_STDOUT,MAX_STDERR=MAX_STDERR,MAX_REPORT=MAX_REPORT,MAX_EVENTS=MAX_EVENTS,
        scenarios=lambda:expected['records'],expected_report=lambda:expected)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged-strict-reclaim-framing>','exec'),namespace)
    report,stats=namespace['report_from_events'](raw)
    require(stats['passed_including_parent']==27)
    stats.update(passed_including_parent=77,historical_summary_outcomes=27,
        framing_source_sha256=sha(source),imported_module_mutated=False)
    return report,stats


def compare_payloads(payloads,root=ROOT):
    require(type(payloads) is dict and set(payloads)=={UNIT+'.stdout',UNIT+'.stderr'})
    require(all(type(value) is bytes for value in payloads.values()) and len(payloads[UNIT+'.stderr'])<=MAX_STDERR)
    report,stats=report_from_events(payloads[UNIT+'.stdout'],root)
    return dict(schema='ptlc-nom-dev-661b5ef-reclaim-comparison-v1',outcome='PASS_FINITE_RECLAIM_VALUES_ONLY',
        core_commit=CORE,core_tree=TREE,reclaim_cases=76,reclaim_outcomes=77,native_report=report,stdout=stats,
        stderr=dict(bytes=len(payloads[UNIT+'.stderr']),sha256=sha(payloads[UNIT+'.stderr'])),
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_READER',journal_source_upgrade='NOT_SELECTED',
        recovery_action='NONE',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
