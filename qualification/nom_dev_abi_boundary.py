"""Read isolated ABI layer comparisons; no complete admission or recovery authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('ABI boundary comparison requires assertions enabled')
import hashlib
import json
import math
import os
from pathlib import Path
import re
from qualification import nom_current_admission as common
from offline_session.nom_wire import encode_call
ROOT = common.ROOT
CORE = '5e65a0bdb83700aa1d15b17456a17352b7d04ea9'
TREE = '3668425af59cfe9b88d8b8818b4467ce3f527d73'
SOURCE = 'compatibility/nom_dev_admission_source_v1.json'
INDEX_SHA256 = '2f031704a76b772f66736dadd5d9a7c0d5e3e2e07d97a2b2364cf072fe63b298'
PREVIOUS_MANIFEST = 'compatibility/nom_dev_admission_manifest.json'
PREVIOUS_MANIFEST_SHA256 = '2b4715b8be83eb3aefe295867ed7747cd126a03f9c2a93dcdfb8bd356bd5d4f9'
DRIVER = 'compatibility/nom_dev_abi_boundary_test.go.txt'
DESTINATION = 'vm/embedded/research_nom_dev_abi_boundary_test.go'
FIXTURE = 'compatibility/fixtures/nom_dev_abi_boundary_v1.json'
MANIFEST = 'compatibility/nom_dev_abi_boundary_manifest.json'
SCHEMA = 'ptlc-nom-dev-abi-boundary-selection-v1'
PARENT = 'TestResearchNoMDevABIBoundary'
PACKAGE = 'github.com/zenon-network/go-zenon/vm/embedded'
MAX_STDOUT, MAX_STDERR, MAX_REPORT = 256*1024, 64*1024, 64*1024
MAX_EVENTS = 512
MAX_SOURCE_FILE, MAX_SOURCE_TOTAL = 8*common.MIB, 48*common.MIB
OWN_INPUTS = {SOURCE, PREVIOUS_MANIFEST, DRIVER, FIXTURE,
    'qualification/nom_dev_abi_boundary.py', 'tests/test_nom_dev_abi_boundary.py',
    'offline_session/nom_wire.py', 'offline_session/pr138.py',
    'qualification/nom_current_admission.py', 'qualification/nom_rpc_quote_source.py'}
DRIVER_SHA256 = '6836919a207049c5a1df0a234fecae5ceec196b3ca509b5381fc2f0510451d06'
FIXED_DEPENDENCIES = {'offline_session/nom_wire.py': 'd79dd83b98b6a31c3b5b15deb26ea4b671d2ed96dab03bf02381b9648492b839', 'offline_session/pr138.py': '5fde0d8409885faa0fe7ad2f2507ee422ce964cee50800e04296f8fcc5b79c9d', 'qualification/nom_current_admission.py': '06398a328df82f1429b6b1358e6ca7ed58be3f685725b0cf3fd5c41ebae99dac', 'qualification/nom_rpc_quote_source.py': '7c2c5a52e2e76bae8957e8dd64e59f5916cb546921af6de3d0936b63da9c3148'}



def require(value):
    if not value:
        raise ValueError('isolated ABI boundary comparison refused')


def scenarios():
    entry = '112233' + '00' * 29
    destination = '003142' + '00' * 17
    calls = {
        'Create': dict(method='Create', expiration_time='1700000010', point_type=1,
            point_lock_hex='79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            destination_hex=destination),
        'Reclaim': dict(method='Reclaim', entry_id_hex=entry),
        'Unlock': dict(method='Unlock', entry_id_hex=entry, witness_hex='00' * 64),
        'ProxyUnlock': dict(method='ProxyUnlock', entry_id_hex=entry,
            destination_hex=destination, witness_hex='00' * 64),
    }
    canonical = {name: encode_call(value) for name, value in calls.items()}
    selected = {}

    def add(name, method, data, guard='NO_ERROR', unpack='UNPACKED',
            validation='VALIDATED', route='FOUND', equal=True, changes=False,
            dp=True, ptlc=True):
        require(name not in selected and type(data) is bytes)
        output = canonical[method] if changes else data
        selected[name] = dict(input=data, output=output, method=method,
            guard_outcome=guard, dispatch_outcome=route, unpack_outcome=unpack,
            validation_outcome=validation, repack_equal=equal,
            validation_changes_data=changes, dp_flag=dp, ptlc_flag=ptlc)

    for method in ('Create', 'Reclaim', 'Unlock', 'ProxyUnlock'):
        add(method + '_canonical', method, canonical[method])
        for count in (1, 32):
            add(method + '_trailing_' + str(count), method,
                canonical[method] + bytes(count), guard='TRAILING_DATA', equal=False, changes=True)
    gap = canonical['Unlock'][:36] + (96).to_bytes(32, 'big') + bytes(32) + canonical['Unlock'][68:]
    add('unlock_offset_gap', 'Unlock', gap, guard='TRAILING_DATA', equal=False, changes=True)
    padded = bytearray(canonical['ProxyUnlock']); padded[36] = 1
    add('proxy_address_high_padding', 'ProxyUnlock', bytes(padded), equal=False, changes=True)
    padded = bytearray(canonical['Create']); padded[36] = 1
    add('create_point_type_high_padding', 'Create', bytes(padded), equal=False, changes=True)
    short = encode_call(dict(calls['Unlock'], witness_hex='00' * 31))
    add('unlock_invalid_witness_width', 'Unlock', short, validation='WITNESS_REFUSED')
    add('unlock_invalid_width_nonzero_padding', 'Unlock', short[:-1] + b'\x01',
        validation='WITNESS_REFUSED', equal=False)
    add('unlock_unknown_selector', 'Unlock', bytes.fromhex('deadbeef') + canonical['Unlock'][4:],
        unpack='UNPACK_REFUSED', validation='UNPACK_REFUSED', route='METHOD_MISSING', equal=False)
    for name, data, route in (
            ('unlock_truncated_head', canonical['Unlock'][:35], 'FOUND'),
            ('unlock_selector_only', canonical['Unlock'][:4], 'FOUND'),
            ('unlock_empty_data', b'', 'METHOD_MISSING'),
            ('unlock_offset_overflow', canonical['Unlock'][:36] + b'\x80' + bytes(31) + canonical['Unlock'][68:], 'FOUND')):
        add(name, 'Unlock', data, unpack='UNPACK_REFUSED', validation='UNPACK_REFUSED', route=route, equal=False)
    add('ptlc_registry_absent', 'Reclaim', canonical['Reclaim'], route='CONTRACT_MISSING', ptlc=False)
    add('dp_flag_off_isolated_helper', 'Reclaim', canonical['Reclaim'] + b'\0',
        guard='TRAILING_DATA', equal=False, changes=True, dp=False)
    add('nonembedded_address', 'Reclaim', canonical['Reclaim'], route='NOT_CONTRACT')
    add('unknown_embedded_address', 'Reclaim', canonical['Reclaim'], route='CONTRACT_MISSING')
    require(len(selected) == 26)
    return selected


def expected_report():
    records = {}
    for name, selected in scenarios().items():
        row = {key: value for key, value in selected.items() if key not in ('input', 'output')}
        row.update(data_bytes=len(selected['input']),
            input_sha256=hashlib.sha256(selected['input']).hexdigest(),
            validated_data_sha256=hashlib.sha256(selected['output']).hexdigest())
        records[name] = row
    return dict(schema='zenon-nom-dev-abi-boundary-result-v1', selected_core_commit=CORE,
        scope='ISOLATED_ABI_AND_METHOD_LAYERS_ONLY', records=records,
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def fixture():
    return dict(schema='ptlc-nom-dev-abi-boundary-values-v1', core_commit=CORE, core_tree=TREE,
        scope='FINITE DECLARED ABI LAYER VALUES; NOT EXECUTION EVIDENCE', expected=expected_report())


def fixed_manifest():
    return dict(schema=SCHEMA, core_commit=CORE, core_tree=TREE,
        source_index_sha256=INDEX_SHA256, source_files=474, project_probe_files=1,
        source_view_files=475, producer_sha256=DRIVER_SHA256,
        producer_destination=DESTINATION, prior_selection_sha256=PREVIOUS_MANIFEST_SHA256,
        finite_layer_cases=26, parent_and_subtest_outcomes=27,
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED',
        combined_admission='UNFILLED', journal_source_upgrade='NOT_SELECTED')


def inputs(root=ROOT):
    root = common.physical(root)
    manifest = common.decoded(common.regular(root / MANIFEST, common.MIB), common.MIB)
    fixed = fixed_manifest()
    require(type(manifest) is dict and set(manifest) == set(fixed) | {'input_sha256'})
    require(common.canonical({key: manifest[key] for key in fixed}) == common.canonical(fixed))
    pins = manifest['input_sha256']
    require(type(pins) is dict and set(pins) == OWN_INPUTS)
    selected = {}
    for name, digest in pins.items():
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest))
        raw = common.regular(root / name, 2 * common.MIB)
        require(hashlib.sha256(raw).hexdigest() == digest)
        selected[name] = raw
    require(all(pins[name] == pin for name, pin in FIXED_DEPENDENCIES.items()))
    require(pins[SOURCE] == INDEX_SHA256 and pins[PREVIOUS_MANIFEST] == PREVIOUS_MANIFEST_SHA256)
    require(pins[DRIVER] == DRIVER_SHA256 and len(selected[DRIVER]) == 12543)
    # The immutable inventory suffices here; no earlier profile generator runs.
    index = common.decoded(selected[SOURCE], common.MIB)
    require(type(index) is dict and len(index) == 474)
    for name, row in index.items():
        require(type(name) is str and name.isascii() and '\\' not in name)
        require(not Path(name).is_absolute() and all(part not in ('', '.', '..', '.git') for part in name.split('/')))
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'git_blob_sha1', 'mode'})
        require(type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_SOURCE_FILE)
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']))
        require(type(row['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}', row['git_blob_sha1']))
        require(row['mode'] in ('100644', '100755'))
    require(common.git_tree(index) == TREE)
    values = common.decoded(selected[FIXTURE], common.MIB)
    require(common.canonical(values) == common.canonical(fixture()))
    return manifest, index, values


def compare_source(source, root=ROOT):
    unused_manifest, index, unused_values = inputs(root)
    require(type(index) is dict and len(index) == 474)
    source = common.physical(source)
    require(source.is_dir())
    expected = {name: dict(row) for name, row in index.items()}
    raw = common.regular(Path(root) / DRIVER, MAX_SOURCE_FILE)
    require(DESTINATION not in expected)
    expected[DESTINATION] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
        git_blob_sha1=hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest())
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent != Path('.')}
    seen, total = set(), 0
    for directory, children, names in os.walk(source, followlinks=False):
        parent = Path(directory)
        require(not parent.is_symlink())
        for name in children:
            path = parent / name
            require(not path.is_symlink() and path.relative_to(source).as_posix() in directories)
        for name in names:
            path = parent / name
            relative = path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw = common.regular(path, MAX_SOURCE_FILE)
            row = expected[relative]
            total += len(raw)
            require(total <= MAX_SOURCE_TOTAL and len(raw) == row['bytes'])
            require(hashlib.sha256(raw).hexdigest() == row['sha256'])
            require(hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest() == row['git_blob_sha1'])
            seen.add(relative)
    require(seen == set(expected) and len(seen) == 475)
    return dict(core_commit=CORE, core_tree=TREE, upstream_files=474,
        project_probe_files=1, combined_files=475, content='EXACT_SELECTED_CONTENTS',
        filesystem_mode_equality='NOT_ASSERTED', execution_binding='NOT_ESTABLISHED_BY_THIS_READER',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def report_from_events(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STDOUT)
    lines = raw.splitlines()
    require(0 < len(lines) <= MAX_EVENTS)
    events = [common.decoded(line, MAX_STDOUT) for line in lines]
    expected = {PARENT} | {PARENT + '/' + name for name in scenarios()}
    started, passed, output = set(), set(), []
    package_starts = package_passes = 0
    for number, event in enumerate(events):
        require(type(event) is dict and {'Action', 'Package'} <= set(event) <= common.EVENT_FIELDS)
        require(event['Package'] == PACKAGE and event['Action'] in ('start', 'run', 'output', 'pass'))
        require('FailedBuild' not in event)
        if 'Test' in event:
            require(type(event['Test']) is str and event['Test'] in expected)
        if 'Time' in event:
            require(type(event['Time']) is str and len(event['Time']) <= 128)
        if 'Elapsed' in event:
            require(type(event['Elapsed']) in (int, float) and math.isfinite(event['Elapsed']) and event['Elapsed'] >= 0)
        action, name = event['Action'], event.get('Test')
        require(('Output' in event) == (action == 'output'))
        if action == 'start':
            require(number == 0 and name is None)
            package_starts += 1
        elif action == 'run':
            require(package_starts == 1 and name is not None and name not in started)
            require(name == PARENT or PARENT in started and PARENT not in passed)
            started.add(name)
        elif action == 'pass':
            if name is None:
                require(number == len(events) - 1 and passed == expected)
                package_passes += 1
            else:
                require(name in started and name not in passed)
                if name == PARENT:
                    require(passed == expected - {PARENT})
                passed.add(name)
        else:
            require(package_starts == 1 and package_passes == 0 and type(event['Output']) is str)
            if name is not None:
                require(name in started and name not in passed)
            if name == PARENT:
                output.append(event['Output'])
    require(package_starts == package_passes == 1 and started == passed == expected)
    text = ''.join(output)
    require(len(text.encode('utf-8')) <= MAX_REPORT)
    reports = [common.decoded(line.encode('utf-8'), MAX_REPORT) for line in text.splitlines() if line.startswith('{')]
    require(len(reports) == 1 and common.canonical(reports[0]) == common.canonical(expected_report()))
    return reports[0], dict(event_count=len(events), passed_including_parent=27,
        stdout_sha256=hashlib.sha256(raw).hexdigest(), stdout_bytes=len(raw))


def compare_payloads(payloads, root=ROOT):
    inputs(root)
    require(type(payloads) is dict and set(payloads) == {'abi-boundary.stdout', 'abi-boundary.stderr'})
    require(all(type(value) is bytes for value in payloads.values()))
    stderr = payloads['abi-boundary.stderr']
    require(len(stderr) <= MAX_STDERR)
    report, stream = report_from_events(payloads['abi-boundary.stdout'])
    return dict(schema='ptlc-nom-dev-abi-boundary-comparison-v1', outcome='PASS_FINITE_LAYER_VALUES_ONLY',
        core_commit=CORE, core_tree=TREE, finite_layer_cases=26, native_report=report,
        stdout=stream, stderr=dict(bytes=len(stderr), sha256=hashlib.sha256(stderr).hexdigest()),
        complete_source='SEPARATE_CONTENT_CHECK_REQUIRED', native_execution='NOT_PERFORMED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER', execution_origin='NOT_ESTABLISHED_BY_THIS_READER',
        stream_completeness='NOT_ESTABLISHED_BY_FILE_CONTENT',
        combined_admission='UNFILLED', source_authentication='UNFILLED', independent_assessment='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', journal_write='NOT_PERFORMED', signing='NOT_PERFORMED',
        transaction_broadcast='NOT_PERFORMED', activation='NOT_PERFORMED', application='NO-GO', core='NO-GO')


def load_payloads(directory):
    directory = common.physical(directory)
    require(directory.is_dir())
    require({path.name for path in directory.iterdir()} == {'abi-boundary.stdout', 'abi-boundary.stderr'})
    return {name: common.regular(directory / name, limit) for name, limit in
            (('abi-boundary.stdout', MAX_STDOUT), ('abi-boundary.stderr', MAX_STDERR))}


def main():
    import argparse

    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('ABI boundary comparison refused')

    parser = QuietParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--streams', type=Path, required=True)
    try:
        args = parser.parse_args()
        source = compare_source(args.source)
        result = compare_payloads(load_payloads(args.streams))
        result['complete_source'] = source
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RecursionError, OverflowError):
        raise SystemExit('REFUSED: ABI boundary component comparison') from None
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
