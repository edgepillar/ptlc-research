"""Read exact public-original source comparisons, without custody authority."""
import copy
import hashlib
import json
import re
from pathlib import Path
import sys
import argparse
import os
import stat
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from offline_session.nom_wire import account_block_hash, decode_call
from offline_session.nom_recovery import validate_terms
from scripts.qualify_nom_vm_path import selected_outcome

TEST = 'TestResearchNoMSignedOriginalByteCustody'
PACKAGE = 'github.com/zenon-network/go-zenon/verifier'
PREFIX = 'PTLC_NOM_SIGNED_ORIGINAL_RECORD='
KINDS = ('original', 'unknown-protobuf-field', 'duplicate-protobuf-version',
    'changed-changes-hash', 'changed-base-plasma', 'changed-total-plasma',
    'changed-data-old-hash', 'changed-data-old-signature', 'missing-signature',
    'missing-key', 'invalid-signature', 'malformed-protobuf')
FIELDS = {'schema', 'id', 'leg', 'kind', 'wire_hex', 'wire_sha256', 'original_wire_hex',
    'decoded', 'hash_hex', 'computed_hash_hex', 'changes_hash_hex', 'base_plasma', 'total_plasma',
    'public_key_hex', 'signature_hex', 'reencoded_wire_hex', 'block', 'checks'}
CORE = '137fc528f10ad1ac37ca6d9c4f90ed4b9ee8e598'
CORE_TREE = '1897e82296a7cc0d558a39d00398840495638bfd'
ARCHIVE_SHA256 = '56def1c1da2fa6e8a0b78950ea8aa63ebbd13e417c0ef1e283e874a132054977'
INDEX_PAYLOAD_SHA256 = '57c3c7c54d56e237a85f450b10cbab096718eba27e579926aa6b2fc6e9294f0b'
RECORD_PAYLOAD_SHA256 = '0b480077c1ed39dd0ae9dade355fe62a9077124f184d2befc5b86c73e762d483'
MANIFEST = 'compatibility/nom_signed_originals_manifest.json'
SOURCE_INDEX = 'compatibility/nom_signed_originals_source_v1.json'
FIXTURE = 'compatibility/fixtures/nom_signed_originals_v1.json'
DRIVER = 'compatibility/nom_signed_originals_test.go.txt'
PROBE = 'verifier/zz_research_nom_signed_original_probe_test.go'
SELECTED_INPUTS = (SOURCE_INDEX, FIXTURE, DRIVER,
    'compatibility/fixtures/nom_supervisor_plasma_v1.json',
    'compatibility/fixtures/nom_supervisor_inputs_v1.json',
    'compatibility/fixtures/nom_supervisor_completions_v1.json',
    'offline_session/nom_signed_recovery.py', 'scripts/nom_signed_corpus.py',
    'scripts/qualify_nom_signed_originals.py', 'scripts/qualify_nom_signed_recovery.py',
    'scripts/prepare_nom_signed_originals.py',
    'tests/test_nom_signed_recovery.py', 'tests/nom_signed_fixture_oracle.py',
    'tests/test_nom_signed_originals.py', 'tests/nom_signed_source_frames.py',
    'offline_session/nom_recovery.py', 'offline_session/nom_recovery_snapshot.py',
    'offline_session/nom_verifier.py', 'offline_session/nom_wire.py', 'offline_session/pr138.py',
    'offline_session/public_worker.py', 'scripts/nom_cut_capture.py',
    'scripts/qualify_nom_recovery_cuts.py', 'scripts/qualify_nom_vm_path.py',
    'scripts/qualify_nom_observation_core.py')


def _check(condition):
    if not condition:
        raise ValueError('selected signed-original qualification refused')


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''): value.update(chunk)
    return value.hexdigest()


def git_tree(index):
    """Reconstruct the complete selected Git tree from names, modes and blobs."""
    tree = {}
    for name, record in index.items():
        parts = name.split('/')
        _check(parts and all(part not in ('', '.', '..') for part in parts) and '\\' not in name)
        branch = tree
        for part in parts[:-1]:
            branch = branch.setdefault(part, {})
            _check(type(branch) is dict)
        _check(parts[-1] not in branch)
        branch[parts[-1]] = (record['mode'], record['git_blob_sha1'])
    def digest(branch):
        content = b''
        for name, value in sorted(branch.items(), key=lambda item: item[0]+('/' if type(item[1]) is dict else '')):
            mode, pin = ('40000', digest(value)) if type(value) is dict else value
            content += (mode+' '+name).encode('ascii')+b'\0'+bytes.fromhex(pin)
        return hashlib.sha1(b'tree '+str(len(content)).encode('ascii')+b'\0'+content).hexdigest()
    return digest(tree)


def inputs(root=ROOT):
    manifest = json.loads((root/MANIFEST).read_bytes(), object_pairs_hook=_unique)
    _check(manifest['schema'] == 'ptlc-nom-signed-originals-manifest-v1'
        and manifest['core_commit'] == CORE and manifest['core_tree'] == CORE_TREE
        and manifest['archive_sha256'] == ARCHIVE_SHA256
        and manifest['source_index_payload_sha256'] == INDEX_PAYLOAD_SHA256
        and manifest['record_set_payload_sha256'] == RECORD_PAYLOAD_SHA256
        and manifest['application'] == manifest['core'] == 'NO-GO'
        and manifest['independent_assessment'] == 'UNFILLED')
    _check(set(manifest['input_sha256']) == set(SELECTED_INPUTS))
    for name, pin in manifest['input_sha256'].items():
        _check(re.fullmatch('[0-9a-f]{64}', pin) and sha(root/name) == pin)
    index = json.loads((root/SOURCE_INDEX).read_bytes(), object_pairs_hook=_unique)
    records = json.loads((root/FIXTURE).read_bytes(), object_pairs_hook=_unique)
    _check(len(index) == 443 and git_tree(index) == CORE_TREE)
    _check(hashlib.sha256(json.dumps(index,sort_keys=True).encode('ascii')).hexdigest() == INDEX_PAYLOAD_SHA256)
    _check(hashlib.sha256(json.dumps(records,sort_keys=True).encode('ascii')).hexdigest() == RECORD_PAYLOAD_SHA256)
    for record in index.values():
        _check(set(record) == {'bytes','sha256','git_blob_sha1','mode'}
            and type(record['bytes']) is int and 0 <= record['bytes'] <= 16*1024**2
            and re.fullmatch('[0-9a-f]{64}',record['sha256'])
            and re.fullmatch('[0-9a-f]{40}',record['git_blob_sha1'])
            and record['mode'] in ('100644','100755'))
    _check(index['LICENSE']['sha256'] == manifest['source_license_sha256'])
    return manifest, index, records


def check_source(checkout, index, *, root=ROOT):
    """Require all selected source bytes and exactly the separately supplied probe.

    Git executable modes are retained source metadata, not an attestation of the
    host's filesystem modes, compiler, loader or producer identity.
    """
    _check(checkout.is_dir() and not checkout.is_symlink())
    expected = dict(index)
    probe = (root/DRIVER).read_bytes()
    _check(PROBE not in expected)
    expected[PROBE] = dict(sha256=hashlib.sha256(probe).hexdigest(),bytes=len(probe))
    actual = set()
    for path in checkout.rglob('*'):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            _check(not path.is_symlink())
            continue
        name = path.relative_to(checkout).as_posix()
        _check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and name in expected
            and info.st_size == expected[name]['bytes'])
        raw = path.read_bytes()
        _check(hashlib.sha256(raw).hexdigest() == expected[name]['sha256'])
        if name != PROBE:
            _check(hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest() == expected[name]['git_blob_sha1'])
        actual.add(name)
    _check(actual == set(expected))


def qualify(checkout, go, evidence, *, root=ROOT):
    if sys.flags.optimize:
        raise ValueError('signed-original qualification requires assertions enabled')
    manifest, index, frozen = inputs(root)
    _check(evidence.is_absolute() and evidence.is_dir() and not evidence.is_symlink() and not any(evidence.iterdir()))
    _check(go.is_absolute() and go.is_file() and not go.is_symlink())
    check_source(checkout,index,root=root)
    go_pin = sha(go)
    selected = dict(manifest['input_sha256'])
    environment=dict(os.environ,GOTOOLCHAIN='local',GOWORK='off',GOENV='off',GOFLAGS='',GOTELEMETRY='off',
        PTLC_NOM_SIGNED_ORIGINAL_FIXTURE=str((root/'compatibility/fixtures/nom_supervisor_plasma_v1.json').resolve()))
    command = [str(go),'test','-json','-mod=readonly','-count=1','-run','^'+TEST+'$','./verifier']
    report = dict(schema='ptlc-nom-signed-original-source-result-v1',outcome='UNKNOWN',
        core_commit=CORE,core_tree=CORE_TREE,source_files=443,combined_probe_files=444,
        go_executable_sha256=go_pin,vet='NORMAL DEFAULT',selected_input_sha256=selected,
        actual_exit=None,output_complete=False,
        node_activation='NOT_PERFORMED',journal_composition='NOT_PERFORMED',
        source_authentication='UNFILLED',independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')
    try:
        version=subprocess.run([str(go),'version'],cwd=checkout,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
        (evidence/'go-version.stdout').write_bytes(version.stdout)
        (evidence/'go-version.stderr').write_bytes(version.stderr)
        _check(version.returncode==0 and re.fullmatch(rb'go version go1\.23\.12 (linux|darwin)/(amd64|arm64)\n',version.stdout))
        report['go_version']=version.stdout.decode('ascii').strip()
        process = subprocess.Popen(command,cwd=checkout,env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            output,error = process.communicate(timeout=240)
            report.update(actual_exit=process.returncode,output_complete=True)
        except subprocess.TimeoutExpired:
            process.kill();output,error = process.communicate(timeout=5)
            report.update(actual_exit=process.returncode,output_complete=False,outcome='TIMEOUT_NOT_QUALIFIED')
        (evidence/'core.stdout').write_bytes(output)
        (evidence/'core.stderr').write_bytes(error)
        _check(len(output) <= 2*1024**2 and len(error) <= 2*1024**2)
        report.update(stdout_sha256=hashlib.sha256(output).hexdigest(),stdout_bytes=len(output),
            stderr_sha256=hashlib.sha256(error).hexdigest(),stderr_bytes=len(error))
        _check(report['actual_exit'] == 0 and report['output_complete'])
        fixture, terms, completed = [json.loads((root/name).read_bytes()) for name in (
            'compatibility/fixtures/nom_supervisor_plasma_v1.json',
            'compatibility/fixtures/nom_supervisor_inputs_v1.json',
            'compatibility/fixtures/nom_supervisor_completions_v1.json')]
        analysis, records = inspect(output,fixture,terms,completed)
        _check(records == frozen)
        check_source(checkout,index,root=root)
        _check(sha(go) == go_pin and all(sha(root/name) == pin for name,pin in selected.items()))
        report.update(outcome='PASS',comparison=analysis,source_unchanged=True,
            original_streams='RETAINED_IN_SELECTED_EVIDENCE_DIRECTORY; NOT_RUNTIME_ATTESTATION')
        return report
    finally:
        if report['outcome'] == 'UNKNOWN': report['outcome'] = 'FAILED_OR_INCOMPLETE'
        (evidence/'qualification-result.json').write_text(json.dumps(report,sort_keys=True)+'\n',encoding='ascii')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout',type=Path,required=True)
    parser.add_argument('--go',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    try:
        report=qualify(args.checkout,args.go,args.evidence)
    except (AssertionError,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print('FAIL: signed-original source qualification; preserve original selected evidence',file=sys.stderr)
        return 1
    # The selected probe prints public synthetic values and relative test labels.
    # Preserve its original structured output in the CI console as well.
    sys.stdout.buffer.write((args.evidence/'core.stdout').read_bytes());sys.stdout.buffer.flush()
    print(json.dumps(report,sort_keys=True))
    return 0


def raw_hex(value, maximum=2048):
    assert type(value) is str and re.fullmatch('[0-9a-f]*', value) and len(value) % 2 == 0
    assert len(value) <= maximum * 2
    return bytes.fromhex(value)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


def inspect(stream, fixture, inputs, completions):
    assert fixture['schema'] == 'zenon-nom-supervisor-corpus-v1'
    terms = validate_terms(inputs['terms'])
    expected = {TEST} | {TEST+'/'+leg+'-'+kind for leg in ('long', 'short') for kind in KINDS}
    assert selected_outcome(stream, {PACKAGE: expected}) == 25
    rows = fixture['records']['complete']['trace']
    originals = {leg: [row for row in rows if row['label'] == leg+'-unlock-send']
        for leg in ('long', 'short')}
    assert all(len(value) == 1 for value in originals.values())
    records = {}
    # test2json splits long t.Logf lines into output fragments. Reassemble
    # only within the exact package/test identity, with a finite byte bound.
    outputs = {}
    for line in stream.splitlines():
        event = json.loads(line, object_pairs_hook=_unique)
        text = event.get('Output', '')
        if event.get('Action') != 'output' or event.get('Test') not in expected:
            assert PREFIX not in text
            continue
        assert event['Package'] == PACKAGE and type(text) is str
        identity = event['Test']
        outputs[identity] = outputs.get(identity, '') + text
        assert len(outputs[identity].encode('utf-8')) <= 32768
    for identity, output in outputs.items():
        for text in output.splitlines(keepends=True):
            if PREFIX not in text:
                continue
            match = re.fullmatch(r'\s+zz_research_nom_signed_original_probe_test.go:[0-9]+: '
                + PREFIX + r'(\{.*\})\n', text)
            assert match
            record = json.loads(match.group(1), object_pairs_hook=_unique)
            assert type(record) is dict and set(record) == FIELDS
            identifier = record['id']
            assert identifier not in records and identity == TEST+'/'+identifier
            records[identifier] = record
    assert set(records) == {leg+'-'+kind for leg in ('long', 'short') for kind in KINDS}
    accepted = refused = 0
    for leg in ('long', 'short'):
        original = originals[leg][0]
        subject = original['block']
        original_raw = raw_hex(subject['wire_hex'])
        assert original_raw and hashlib.sha256(original_raw).hexdigest() == subject['wire_sha256']
        call = decode_call(bytes.fromhex(subject['block']['data_hex']))
        assert call == dict(method='Unlock', entry_id_hex=terms[leg]['entry_id_hex'],
            witness_hex=completions[leg+'_signature_hex'])
        assert subject['block']['address_hex'] == terms[terms[leg]['recipient']+'_address_hex']
        assert account_block_hash(subject['block']) == subject['hash_hex'] == subject['computed_hash_hex']
        for kind in KINDS:
            r = records[leg+'-'+kind]
            assert r['schema'] == 'ptlc-nom-public-signed-original-comparison-v1'
            assert (r['id'], r['leg'], r['kind']) == (leg+'-'+kind, leg, kind)
            raw = raw_hex(r['wire_hex'])
            assert raw and hashlib.sha256(raw).hexdigest() == r['wire_sha256']
            assert r['original_wire_hex'] == original_raw.hex() and type(r['decoded']) is bool
            if kind == 'malformed-protobuf':
                assert raw == b'\0' and r['decoded'] is False and r['checks'] is r['block'] is None
                assert all(r[field] == '' for field in ('hash_hex', 'computed_hash_hex', 'changes_hash_hex',
                    'base_plasma', 'total_plasma', 'public_key_hex', 'signature_hex', 'reencoded_wire_hex'))
                refused += 1
                continue
            assert r['decoded'] is True
            block = copy.deepcopy(subject['block'])
            checks = dict(hash='PASS', signature='PASS', producer='PASS')
            changes = subject['changes_hash_hex']
            base, total = original['plasma']['base'], original['plasma']['total']
            key, signature = subject['public_key_hex'], subject['signature_hex']
            if kind == 'changed-changes-hash':
                value = bytearray.fromhex(changes); value[0] ^= 1; changes = value.hex()
            elif kind == 'changed-base-plasma': base = str(int(base)+1)
            elif kind == 'changed-total-plasma': total = str(int(total)+1)
            elif kind in ('changed-data-old-hash', 'changed-data-old-signature'):
                value = bytearray.fromhex(block['data_hex']); value[-1] ^= 1; block['data_hex'] = value.hex()
                checks['hash' if kind == 'changed-data-old-hash' else 'signature'] = (
                    'ErrABHashInvalid' if kind == 'changed-data-old-hash' else 'ErrABSignatureInvalid')
            elif kind == 'missing-signature': signature = ''; checks['signature'] = 'ErrABSignatureMissing'
            elif kind == 'missing-key':
                key = ''; checks.update(signature='ErrABPublicKeyMissing', producer='ErrABPublicKeyWrongAddress')
            elif kind == 'invalid-signature':
                value = bytearray.fromhex(signature); value[0] ^= 1; signature = value.hex()
                checks['signature'] = 'ErrABSignatureInvalid'
            assert r['block'] == block and r['checks'] == checks
            computed = account_block_hash(block)
            assert r['computed_hash_hex'] == computed
            assert r['hash_hex'] == (computed if kind == 'changed-data-old-signature' else subject['hash_hex'])
            assert (r['changes_hash_hex'], r['base_plasma'], r['total_plasma'], r['public_key_hex'], r['signature_hex']) == (
                changes, base, total, key, signature)
            encoded = raw_hex(r['reencoded_wire_hex'])
            assert encoded
            if kind in ('unknown-protobuf-field', 'duplicate-protobuf-version'):
                suffix = bytes.fromhex('a00601' if kind == 'unknown-protobuf-field' else '0801')
                assert raw == original_raw+suffix and encoded == original_raw and raw != encoded
            else:
                assert raw == encoded
                assert (raw == original_raw) is (kind == 'original')
            if checks == dict(hash='PASS', signature='PASS', producer='PASS'):
                accepted += 1
                assert r['hash_hex'] == subject['hash_hex']
            else:
                refused += 1
    assert accepted == refused == 12
    return dict(outcome='PASS_SELECTED_SOURCE_PUBLIC_ORIGINAL_COMPARISON', records=24,
        outcomes_with_parent=25, transaction_only_accepted=12, selected_refusals=12,
        raw_alias_cases=4, hash_excluded_metadata_cases=6, fresh_journal_composition='NOT_PERFORMED',
        public_worker_composition='NOT_PERFORMED', wire_normalization='NOT_SELECTED',
        canonicality='UNFILLED', finality='UNFILLED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO', recovery_action='NONE'), records


if __name__=='__main__':sys.exit(main())
