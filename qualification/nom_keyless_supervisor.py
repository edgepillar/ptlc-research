"""Independent finite byte/data expectations; no signing or recovery authority."""
import copy
import hashlib
import json
import re
from qualification import nom_current_admission as common
from qualification import nom_dev_5cb as selected

CORE = '5cb5aac3bb21d012111d87466f946cbdccd344f6'
PARENT = 'TestResearchNoMKeylessOriginalSupervisor'
PACKAGE = 'github.com/zenon-network/go-zenon/vm'
BASENAME = 'research_nom_5cb_keyless_supervisor_test.go'
MAX_STREAM = 512*1024
ROOT = common.ROOT
VARIANT_NAMES = ('canonical','protobuf_repeated_version','trailing_abi_byte',
    'changed_witness_byte','missing_outer_signature','corrupt_outer_signature')
CASE_IDS = frozenset(leg+'-dp-'+str(flag).lower()+'-'+variant
    for leg in ('long','short') for flag in (False,True) for variant in VARIANT_NAMES)


def inputs(root=ROOT):
    selected.inputs(root)
    declared=selected.read_json(root/selected.KEYLESS_INPUT)
    assert declared['schema']=='private-nom-5cb-keyless-original-inputs-v1'
    assert declared['selected_core']==CORE and declared['selected_tree']==selected.TREE
    assert set(declared['variants'])==set(VARIANT_NAMES)
    assert len(declared['declared_case_ids'])==24 and set(declared['declared_case_ids'])==CASE_IDS
    assert 'source_acquisition_task' not in declared
    assert declared['new_keys']==declared['new_signatures']==declared['native_runs']==0
    signed=selected.read_json(root/'compatibility/fixtures/nom_signed_originals_v1.json')
    plasma=selected.read_json(root/'compatibility/fixtures/nom_supervisor_plasma_v1.json')
    for name,pin in declared['frozen_input_sha256'].items():
        assert selected.sha(common.regular(root/name,2*common.MIB))==pin
    fixture=selected.read_json(root/selected.KEYLESS_VALUES)
    assert set(fixture)=={'schema','core_commit','scope','records','spork_read_order',
                         'application','core','independent_assessment'}
    assert fixture['schema']=='ptlc-nom-dev-5cb-keyless-values-v1' and fixture['core_commit']==CORE
    assert fixture['scope']=='FINITE DECLARED EXPECTATIONS; NOT EXECUTION ORIGIN OR CHAIN EVIDENCE'
    assert fixture['spork_read_order']=='OBSERVATIONS ONLY; EXACT ORDER NOT QUALIFIED'
    assert fixture['application']==fixture['core']=='NO-GO' and fixture['independent_assessment']=='UNFILLED'
    common.rebase.exact(expected(declared,signed,plasma),fixture['records'])
    return declared,signed,plasma



def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value):
    assert type(value) is int and 0 <= value < 2**64
    out = bytearray()
    while value > 127:
        out.append((value&127)|128); value >>= 7
    out.append(value)
    return bytes(out)


def number(raw, at):
    start = at; value = 0
    for shift in range(0,70,7):
        assert at < len(raw)
        byte = raw[at]; at += 1
        value |= (byte&127)<<shift
        if byte < 128:
            assert raw[start:at] == uint(value)
            return value,at
    raise ValueError('bounded canonical integer required')


def replace_bytes(raw, field, value):
    """Replace one canonical outer protobuf bytes field, preserving others."""
    assert type(raw) is bytes and 0 < len(raw) <= 8192
    assert value is None or type(value) is bytes
    at = 0; out = bytearray(); seen = set(); replacements = 0
    while at < len(raw):
        start = at; tag,at = number(raw,at); identifier,kind = tag>>3,tag&7
        assert identifier > 0 and identifier not in seen and len(seen) < 48
        seen.add(identifier)
        if kind == 0:
            ignored,at = number(raw,at)
        elif kind == 2:
            size,at = number(raw,at); assert size <= 8192 and at+size <= len(raw)
            at += size
        else:
            raise ValueError('selected outer protobuf field required')
        if identifier == field:
            assert kind == 2
            replacements += 1
            if value:
                out.extend(uint(tag)+uint(len(value))+value)
        else:
            out.extend(raw[start:at])
    assert replacements == 1
    return bytes(out)


def expected(inputs, signed, plasma):
    assert inputs['selected_core'] == CORE and len(inputs['originals']) == 2
    assert set(inputs['variants'])==set(VARIANT_NAMES)
    assert len(inputs['declared_case_ids'])==24 and set(inputs['declared_case_ids'])==CASE_IDS
    result = {}
    for identifier in inputs['declared_case_ids']:
        leg = identifier.split('-',1)[0]
        dynamic = '-dp-true-' in identifier
        variant = next(name for name in inputs['variants'] if identifier.endswith('-'+name))
        original = signed[leg+'-original']
        selection = inputs['originals'][leg]
        original_wire = bytes.fromhex(original['original_wire_hex'])
        original_data = bytes.fromhex(original['block']['data_hex'])
        original_signature = bytes.fromhex(original['signature_hex'])
        assert sha(original_wire) == selection['original_wire_sha256']
        assert replace_bytes(original_wire,14,original_data) == original_wire
        assert replace_bytes(original_wire,23,original_signature) == original_wire
        data,signature,entry = original_data,original_signature,original_wire
        if variant == 'trailing_abi_byte': data += b'\0'
        elif variant == 'changed_witness_byte': data = data[:-1]+bytes([data[-1]^1])
        elif variant == 'missing_outer_signature': signature = b''
        elif variant == 'corrupt_outer_signature': signature = bytes([signature[0]^1])+signature[1:]
        entry = replace_bytes(entry,14,data)
        entry = replace_bytes(entry,23,signature)
        post_data = original_data if variant == 'trailing_abi_byte' and not dynamic else data
        post = replace_bytes(original_wire,14,post_data)
        post = replace_bytes(post,23,signature)
        verdict = 'PASS'
        if variant == 'trailing_abi_byte' and dynamic: verdict = 'TRAILING_DATA'
        elif variant == 'changed_witness_byte': verdict = 'ErrABHashInvalid'
        elif variant == 'missing_outer_signature': verdict = 'ErrABSignatureMissing'
        elif variant == 'corrupt_outer_signature': verdict = 'ErrABSignatureInvalid'
        packed = verdict != 'TRAILING_DATA'
        trace = ['ACCOUNT_PRECHECK_ENTER','ACCOUNT_PRECHECK_PASS']
        if packed: trace += ['PACK_TRANSACTION_VERIFIER_ENTER',
                             'TRANSACTION_VERIFIER_PASS' if verdict=='PASS' else 'TRANSACTION_VERIFIER_REFUSE']
        old_trace = [r for r in plasma['records']['complete']['trace'] if r['label']==leg+'-unlock-send']
        assert len(old_trace) == 1
        decode_input = original_wire+(b'\x08\x01' if variant=='protobuf_repeated_version' else b'')
        result[identifier] = dict(leg=leg,variant=variant,declared_dynamic_plasma=dynamic,
            original_wire_sha256=selection['original_wire_sha256'],original_hash_hex=selection['original_hash_hex'],
            raw_decode_input_sha256=sha(decode_input),raw_decode_input_bytes=len(decode_input),
            entry_wire_sha256=sha(entry),entry_data_sha256=sha(data),
            post_call_wire_sha256=sha(post),post_call_data_sha256=sha(post_data),
            original_signature_sha256=sha(original_signature),entry_signature_sha256=sha(signature),
            post_call_signature_sha256=sha(signature),selected_signature_preserved=True,
            public_key_preserved=True,advertised_hash_preserved=True,
            returned_error=verdict,transaction_present=verdict=='PASS',verifier_trace=trace,
            pack_entered=packed,packed_delta_hex=old_trace[0]['delta_patch_hex'] if packed else '',
            packed_hash_matches=packed and variant!='changed_witness_byte',
            packed_data_sha256=sha(post_data) if packed else '',
            returned_wire_hex=original_wire.hex() if verdict=='PASS' else '',
            base_patch_sha256=selection['before_account_patch_sha256'],base_unchanged=True,
            immutable_original_unchanged=True,application_signer_calls=0,application_admission='NOT_ESTABLISHED')
    assert len(result) == len(set(inputs['declared_case_ids'])) == 24
    return result


def read(raw, inputs, signed, plasma):
    assert type(raw) is bytes and 0 < len(raw) <= MAX_STREAM
    expected_rows = expected(inputs,signed,plasma)
    identities = {PARENT}|{PARENT+'/'+name for name in expected_rows}
    stats = common.event_stream(raw,{PACKAGE:identities})
    assert stats['passed_including_parent'] == 25
    text = ''
    started = False
    prefix = re.compile(r'^    '+re.escape(BASENAME)+r':[0-9]+: (.*)$',re.S)
    for line in raw.splitlines():
        event = common.decoded(line,MAX_STREAM)
        if event['Action']!='output' or event.get('Test')!=PARENT: continue
        output = event.get('Output','')
        found = prefix.match(output)
        if found:
            assert not started
            started = True; text = found.group(1)
        elif started and not text.endswith('\n'):
            text += output
        assert len(text) <= 256*1024
    assert started and text.endswith('\n')
    report = common.decoded(text.encode('ascii'),256*1024)
    assert set(report) == {'schema','selected_core_commit','records','new_keys','new_signatures',
        'scope','application','core','independent_assessment','pool_admission','chain_insertion',
        'journal_source_upgrade','transaction_broadcast'}
    assert report['schema']=='private-nom-5cb-keyless-original-supervisor-result-v1'
    assert report['selected_core_commit']==CORE
    assert type(report['new_keys']) is type(report['new_signatures']) is int
    assert report['new_keys']==report['new_signatures']==0
    assert report['application']==report['core']=='NO-GO' and report['independent_assessment']=='UNFILLED'
    assert report['pool_admission']==report['chain_insertion']=='NOT_CALLED'
    assert report['journal_source_upgrade']=='NOT_SELECTED' and report['transaction_broadcast']=='NOT_PERFORMED'
    assert report['scope']=='SELECTED SUPERVISOR ENTRY WITH DECLARED SYNTHETIC MEMORY VIEWS'
    assert type(report['records']) is dict and set(report['records'])==set(expected_rows)
    for name, row in report['records'].items():
        assert type(row) is dict and set(row)==set(expected_rows[name])|{'spork_reads'}
        reads = row['spork_reads']
        assert type(reads) is list and 1 <= len(reads) <= 64
        assert all(type(item) is str and item in ('DYNAMIC_PLASMA','OTHER_SELECTED_SPORK') for item in reads)
        assert 'DYNAMIC_PLASMA' in reads
        common.rebase.exact(expected_rows[name],{key:row[key] for key in expected_rows[name]})
    return report,dict(stats,actual_selected_cases=24,
        spork_read_order='RETAINED OBSERVATIONS ONLY; EXACT ORDER NOT QUALIFIED',
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        complete_account_admission='UNFILLED',application='NO-GO',core='NO-GO')
