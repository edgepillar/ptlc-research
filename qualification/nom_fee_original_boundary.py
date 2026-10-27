"""Compare a finite stream; reading data never establishes execution origin.

Only the selected public synthetic originals are accepted. Account admission,
canonical-chain authority, signing and recovery remain separate requirements.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_current_admission as common
from qualification import nom_dev_661b5ef_source as upstream
from qualification.nom_keyless_supervisor import number, replace_bytes, uint
from offline_session.nom_wire import account_block_hash

CORE = '661b5ef404487cd41685654bf87530f10adebbe4'
TREE = '78937597e8e0e5835a8856cb44d592e349451d9f'
PARENT = 'TestResearchNoMCurrentFeeOriginalBoundary'
PACKAGE = 'github.com/zenon-network/go-zenon/vm'
BASENAME = 'research_nom_661b5ef_fee_original_boundary_test.go'
MAX_STREAM = 512*1024
INPUT_SHA = '3cf837ddc90308f3ee2ab621f341e25773f609d54e84e5e3a682943b5ff16280'
EXPECTED_SHA = 'f25c4354e5f54f355114123cfb26a8b011d4c1d09775163ef6fc63fee4caa0a8'
VARIANTS = ('original', 'below-stale-hash', 'below-computed-hash',
    'exact-stale-hash', 'exact-computed-hash', 'above-stale-hash', 'above-computed-hash')
CASES = frozenset(leg+'-dp-true-'+variant for leg in ('long','short') for variant in VARIANTS)
MANIFEST = 'compatibility/nom_fee_original_boundary_manifest.json'
VALUES = 'compatibility/fixtures/nom_fee_original_boundary_values_v1.json'
DRIVER = 'compatibility/nom_fee_original_boundary_test.go.txt'
DESTINATION = 'vm/'+BASENAME
LEGACY_INPUT = 'compatibility/fixtures/nom_dev_661b5ef_keyless_inputs_v1.json'
SIGNED = 'compatibility/fixtures/nom_signed_originals_v1.json'
FROZEN = {
    LEGACY_INPUT:'114d3525c2cb95f6e7771c50e85a294652f50a824f15547749c3f486f28c4059',
    SIGNED:'aef86fe911de1f7505fafbf216f33a9e10d8c32304ba91fa81e147035b03b0d9',
    'qualification/nom_keyless_supervisor.py':'bd55e2ad506fcfd03f0e05a4ee9fadf0d6b772dd6de0e94576a74784343f3a53',
    'offline_session/nom_wire.py':'d79dd83b98b6a31c3b5b15deb26ea4b671d2ed96dab03bf02381b9648492b839',
}
OWN_INPUTS = {DRIVER,VALUES,'qualification/nom_fee_original_boundary.py',
    'scripts/prepare_nom_fee_original_boundary.py','tests/test_nom_fee_original_boundary.py'}


def frozen_json(name,root=ROOT):
    raw = common.regular(Path(root)/name,128*1024)
    assert sha(raw) == FROZEN[name]
    return common.decoded(raw,128*1024)


def input_bytes(root=ROOT):
    """Project two published toy originals; supply no expected results to Go."""
    old = frozen_json(LEGACY_INPUT,root)
    assert old['selected_core'] == CORE and old['selected_tree'] == TREE
    cases = [leg+'-dp-true-'+variant for leg in ('long','short') for variant in VARIANTS]
    value = dict(schema='private-nom-661b5ef-fee-original-boundary-inputs-v1',
        selected_core=CORE,selected_tree=TREE,originals=old['originals'],declared_case_ids=cases)
    raw = (json.dumps(value,indent=2,sort_keys=True)+'\n').encode('ascii')
    assert sha(raw) == INPUT_SHA
    return raw


def expected_bytes(root=ROOT):
    raw = common.regular(Path(root)/VALUES,128*1024)
    assert sha(raw) == EXPECTED_SHA
    return raw


def replace_scalar(raw,field,replacement):
    """Change a diagnostic copy's existing canonical scalar, never its source."""
    assert type(raw) is bytes and 0 < len(raw) <= 8192
    assert type(field) is int and field in (15,19,20)
    assert type(replacement) is int and 0 <= replacement < (1 << 64)
    at,replaced = 0,0
    out,seen = bytearray(),set()
    while at < len(raw):
        start = at
        tag,at = number(raw,at)
        identifier,kind = tag >> 3,tag & 7
        assert identifier > 0 and identifier not in seen and len(seen) < 48
        seen.add(identifier)
        if kind == 0:
            value,at = number(raw,at)
        else:
            assert kind == 2
            size,at = number(raw,at)
            assert size <= 8192 and at+size <= len(raw)
            at += size
        if identifier == field:
            assert kind == 0 and value == 73500
            out.extend(uint(tag)+uint(replacement))
            replaced += 1
        else:
            out.extend(raw[start:at])
    assert replaced == 1
    return bytes(out)


def expected_values(root=ROOT):
    """Derive finite values from unchanged public inputs, independently of Go."""
    declared = common.decoded(input_bytes(root),128*1024)
    signed = frozen_json(SIGNED,root)
    rows = {}
    for leg in ('long','short'):
        original = signed[leg+'-original']
        wire = bytes.fromhex(original['original_wire_hex'])
        old_hash = account_block_hash(original['block'])
        assert old_hash == original['hash_hex'] == declared['originals'][leg]['original_hash_hex']
        assert sha(wire) == declared['originals'][leg]['original_wire_sha256']
        data = bytes.fromhex(original['block']['data_hex'])
        required = 73500+(len(data)-4)*68
        assert len(wire) == 584 and len(data) == 164 and required == 84380
        for variant in VARIANTS:
            fused = 73500 if variant == 'original' else {
                'below':required-1,'exact':required,'above':required+1}[variant.split('-')[0]]
            block = copy.deepcopy(original['block'])
            block['fused_plasma'] = str(fused)
            computed = account_block_hash(block)
            advertised = computed if variant.endswith('-computed-hash') else old_hash
            entry = replace_bytes(replace_scalar(wire,15,fused),4,b'\x0a\x20'+bytes.fromhex(advertised))
            if variant == 'original':
                assert entry == wire
            else:
                assert computed != old_hash and entry != wire
            post = replace_scalar(replace_scalar(entry,19,required),20,fused)
            packed = fused >= required
            error = 'ErrNotEnoughTotalPlasma' if not packed else (
                'ErrABSignatureInvalid' if variant.endswith('-computed-hash') else 'ErrABHashInvalid')
            trace = ['ACCOUNT_PRECHECK_ENTER','ACCOUNT_PRECHECK_PASS']
            if packed:
                trace += ['PACK_TRANSACTION_VERIFIER_ENTER','TRANSACTION_VERIFIER_REFUSE']
            rows[leg+'-dp-true-'+variant] = dict(leg=leg,variant=variant,
                declared_dynamic_plasma=True,original_wire_sha256=sha(wire),original_hash_hex=old_hash,
                raw_decode_input_sha256=sha(wire),raw_decode_input_bytes=len(wire),
                entry_wire_sha256=sha(entry),post_call_wire_sha256=sha(post),
                entry_data_sha256=sha(data),entry_advertised_hash_hex=advertised,
                entry_computed_hash_hex=computed,post_call_computed_hash_hex=computed,
                entry_fused_plasma=str(fused),post_call_base_plasma=str(required),
                post_call_total_plasma=str(fused),available_plasma='367500',
                original_hash_preserved=advertised==old_hash,advertised_hash_preserved=True,
                returned_error=error,transaction_present=False,verifier_trace=trace,
                pack_entered=packed,packed_hash_matches=packed and advertised==computed,
                returned_wire_hex='',application_signer_calls=0,application_admission='NOT_ESTABLISHED')
    assert set(rows) == CASES and sum(row['pack_entered'] for row in rows.values()) == 8
    return dict(schema='private-current-fee-original-boundary-expected-v1',core_commit=CORE,
        core_tree=TREE,records=rows,scope='AUTHOR-DECLARED EXPECTATIONS; GO EXECUTION NOT PERFORMED',
        native_execution='NOT_PERFORMED',new_keys=0,new_signatures=0,
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')


def inputs(root=ROOT):
    root = common.physical(root)
    unused,index = upstream.inputs(root)
    manifest = common.decoded(common.regular(root/MANIFEST,128*1024),128*1024)
    fixed = dict(schema='ptlc-nom-fee-original-boundary-selection-v1',core_commit=CORE,
        core_tree=TREE,upstream_files=518,baseline_project_files=25,additional_project_files=1,
        combined_source_files=544,cases=14,outcomes=15,earlier_fee_refusals=6,
        later_hash_refusals=4,later_signature_refusals=4,producer=DRIVER,parent=PARENT,
        package=PACKAGE,caller_scope='DIRECT_UNLOCK_WITH_FIXED_RECIPIENT_AS_CALLER',
        price_context='DECLARED_DYNAMIC_SPORK_AND_SYNTHETIC_MEMORY_SNAPSHOTS',
        native_execution='NOT_PERFORMED_BY_READER',journal_source_upgrade='NOT_SELECTED',
        original_replacement='NOT_SELECTED',application='NO-GO',core='NO-GO',
        recovery_action='NONE',independent_assessment='UNFILLED')
    assert set(manifest) == set(fixed)|{'input_sha256','frozen_input_sha256','upstream_sha256'}
    common.rebase.exact(fixed,{key:manifest[key] for key in fixed})
    common.rebase.exact(FROZEN,manifest['frozen_input_sha256'])
    assert set(manifest['input_sha256']) == OWN_INPUTS
    for name,pin in {**FROZEN,**manifest['input_sha256']}.items():
        assert sha(common.regular(root/name,2*common.MIB)) == pin
    paths = ('chain/nom/account_block.go','verifier/account_block.go','vm/vm.go',
        'vm/plasma.go','vm/embedded/implementation/ptlc.go','wallet/crypto.go')
    common.rebase.exact({name:index[name]['sha256'] for name in paths},manifest['upstream_sha256'])
    common.rebase.exact(expected_values(root),common.decoded(expected_bytes(root),128*1024))
    return manifest,index


def source_payloads(root=ROOT):
    from qualification import nom_dev_661b5ef as baseline
    unused,index = inputs(root)
    expected = {name:pin['sha256'] for name,pin in index.items()}
    for name,path in baseline.probes(root,'all').items():
        assert name not in expected
        expected[name] = sha(common.regular(Path(root)/path,2*common.MIB))
    assert len(expected) == 543 and DESTINATION not in expected
    expected[DESTINATION] = sha(common.regular(Path(root)/DRIVER,128*1024))
    return expected


def compare_files(directory,expected):
    """Check a selected fresh file set; reject aliases, extras and substitutions."""
    directory = common.physical(directory)
    assert directory.is_dir() and type(expected) is dict and 0 < len(expected) <= 1024
    directories = {''}
    for name,pin in expected.items():
        assert type(name) is str and name.isascii() and '\\' not in name and ':' not in name
        assert not Path(name).is_absolute() and all(part not in ('','..','.','.git') for part in name.split('/'))
        assert type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) is not None
        parts = name.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    assert len({name.casefold() for name in expected}) == len(expected)
    seen = {}
    device = directory.stat().st_dev
    for path in sorted(directory.rglob('*')):
        assert not path.is_symlink()
        info = path.lstat()
        assert info.st_dev == device
        name = path.relative_to(directory).as_posix()
        if stat.S_ISDIR(info.st_mode):
            assert name in directories
            continue
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        assert name in expected and name not in seen
        seen[name] = sha(common.regular(path,8*common.MIB))
    assert seen == expected
    return dict(files=len(seen),sha256=sha(json.dumps(seen,sort_keys=True).encode('ascii')))


def compare_source(directory,root=ROOT):
    expected = source_payloads(root)
    assert len(expected) == 544
    snapshot = compare_files(directory,expected)
    return dict(core_commit=CORE,core_tree=TREE,upstream_files=518,project_files=26,
        snapshot=snapshot,content='EXACT_SELECTED_544_FILE_COMPONENT',
        native_execution='NOT_PERFORMED_BY_READER',source_authentication='UNFILLED')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def declarations(input_raw, expected_raw):
    assert type(input_raw) is type(expected_raw) is bytes
    assert sha(input_raw) == INPUT_SHA and sha(expected_raw) == EXPECTED_SHA
    inputs = common.decoded(input_raw, 128*1024)
    expected = common.decoded(expected_raw, 128*1024)
    assert set(inputs) == {'schema','selected_core','selected_tree','originals','declared_case_ids'}
    assert inputs['schema'] == 'private-nom-661b5ef-fee-original-boundary-inputs-v1'
    assert inputs['selected_core'] == CORE and inputs['selected_tree'] == TREE
    assert len(inputs['declared_case_ids']) == 14 and set(inputs['declared_case_ids']) == CASES
    assert set(inputs['originals']) == {'long','short'}
    assert expected['schema'] == 'private-current-fee-original-boundary-expected-v1'
    assert expected['core_commit'] == CORE and expected['core_tree'] == TREE
    assert expected['scope'] == 'AUTHOR-DECLARED EXPECTATIONS; GO EXECUTION NOT PERFORMED'
    assert expected['native_execution'] == 'NOT_PERFORMED'
    assert expected['new_keys'] == expected['new_signatures'] == 0
    assert expected['application'] == expected['core'] == 'NO-GO'
    assert expected['independent_assessment'] == 'UNFILLED'
    assert set(expected['records']) == CASES
    rows = copy.deepcopy(expected['records'])
    for row in rows.values():
        original = inputs['originals'][row['leg']]
        assert original['original_hash_hex'] == row['original_hash_hex']
        assert original['original_wire_sha256'] == row['original_wire_sha256']
        signature = bytes.fromhex(original['signature_hex'])
        assert len(signature) == 64
        row.update(post_call_data_sha256=row['entry_data_sha256'],
            original_signature_sha256=sha(signature),entry_signature_sha256=sha(signature),
            post_call_signature_sha256=sha(signature),selected_signature_preserved=True,
            public_key_preserved=True,base_patch_sha256=original['before_account_patch_sha256'],
            base_unchanged=True,immutable_original_unchanged=True,
            packed_data_sha256=row['entry_data_sha256'] if row['pack_entered'] else '')
    return rows


def read(raw, input_raw, expected_raw):
    assert type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b'\n')
    expected = declarations(input_raw, expected_raw)
    identities = {PARENT} | {PARENT+'/'+name for name in CASES}
    stats = common.event_stream(raw, {PACKAGE:identities})
    assert stats['passed_including_parent'] == 15
    prefix = re.compile(r'^    '+re.escape(BASENAME)+r':[0-9]+: (.*)$', re.S)
    text = ''
    started = False
    for line in raw.splitlines():
        event = common.decoded(line, MAX_STREAM)
        if event['Action'] != 'output' or event.get('Test') != PARENT:
            continue
        output = event.get('Output','')
        found = prefix.match(output)
        if found:
            assert not started
            started = True
            text = found.group(1)
        elif started and not text.endswith('\n'):
            text += output
        assert len(text) <= 128*1024
    assert started and text.endswith('\n')
    report = common.decoded(text.encode('ascii'), 128*1024)
    fixed = dict(schema='private-nom-661b5ef-fee-original-boundary-result-v1',
        selected_core_commit=CORE,new_keys=0,new_signatures=0,
        scope='DIAGNOSTIC MUTATED COPIES WITH SYNTHETIC MEMORY VIEWS; ORIGINALS NEVER REPLACED',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED',
        pool_admission='NOT_CALLED',chain_insertion='NOT_CALLED',
        journal_source_upgrade='NOT_SELECTED',transaction_broadcast='NOT_PERFORMED')
    assert set(report) == set(fixed) | {'records'}
    common.rebase.exact(fixed, {key:report[key] for key in fixed})
    assert set(report['records']) == CASES
    observed = {}
    for identifier, wanted in expected.items():
        row = report['records'][identifier]
        assert type(row) is dict and set(row) == set(wanted) | {'spork_reads','packed_delta_hex'}
        common.rebase.exact(wanted, {key:row[key] for key in wanted})
        reads = row['spork_reads']
        assert type(reads) is list and 0 < len(reads) <= 128
        assert all(type(value) is str and value in ('DYNAMIC_PLASMA','OTHER_SELECTED_SPORK') for value in reads)
        assert 'DYNAMIC_PLASMA' in reads
        delta = row['packed_delta_hex']
        assert type(delta) is str and len(delta) % 2 == 0
        assert re.fullmatch('[0-9a-f]{0,32768}', delta) is not None
        assert bool(delta) is row['pack_entered']
        observed[identifier] = dict(spork_reads=list(reads),
            packed_delta_bytes=len(delta)//2,packed_delta_sha256=sha(bytes.fromhex(delta)))
    return dict(outcome='PASS_DECLARED_CURRENT_FEE_FINITE_STREAM_ONLY',source=CORE,
        cases=14,outcomes_including_parent=15,earlier_fee_refusals=6,
        later_hash_refusals=4,later_signature_refusals=4,originals_replaced=0,
        new_keys=0,new_signatures=0,spork_read_order='OBSERVATIONS_ONLY',
        packed_delta_semantics='OBSERVATIONS_ONLY; NO_STATE_ADMISSION_CLAIM',observations=observed,
        native_execution_origin='NOT_ESTABLISHED_BY_DATA_READER',
        full_account_admission='NOT_ESTABLISHED',application='NO-GO',core='NO-GO',
        recovery_action='NONE',independent_assessment='UNFILLED')


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('bounded current fee stream arguments required')
    parser = QuietParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--stream',type=Path)
    mode.add_argument('--emit-public-inputs',action='store_true')
    parser.add_argument('--inputs',type=Path)
    parser.add_argument('--expected',type=Path)
    try:
        args = parser.parse_args()
        assert sys.dont_write_bytecode and not sys.flags.optimize
        inputs()
        if args.emit_public_inputs:
            assert args.inputs is None and args.expected is None
            sys.stdout.buffer.write(input_bytes())
            return 0
        values = read(common.regular(args.stream, MAX_STREAM),
            input_bytes() if args.inputs is None else common.regular(args.inputs,128*1024),
            expected_bytes() if args.expected is None else common.regular(args.expected,128*1024))
    except (AssertionError,ValueError,KeyError,TypeError,OSError):
        print('REFUSED: current fee original diagnostic stream',file=sys.stderr)
        return 1
    print(json.dumps(values,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
