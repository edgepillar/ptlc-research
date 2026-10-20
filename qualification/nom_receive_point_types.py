"""Compare six finite public-fixture point-type cases without recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('point type comparison requires assertions enabled')

import hashlib
import math
import os
from pathlib import Path

from qualification import nom_receive_credit as parent

ROOT = Path(__file__).resolve().parents[1]
source_reader = parent.source_reader
CORE, TREE = parent.CORE, parent.TREE
MANIFEST = 'compatibility/nom_receive_point_types_manifest.json'
DRIVER = 'compatibility/nom_receive_point_types_test.go.txt'
DESTINATION = 'zenon/mock/zz_research_nom_receive_point_types_test.go'
NOTICE = 'docs/NOM_RECEIVE_POINT_TYPES_NOTICE.md'
LICENSE = parent.LICENSE
SELECTED = {DRIVER, NOTICE, LICENSE, source_reader.SOURCE,
    'qualification/nom_receive_point_types.py', 'tests/test_nom_receive_point_types.py',
    'qualification/nom_receive_credit.py', parent.MANIFEST}
MODES = {
    'ed25519': (0, 'ED25519_SIGNATURE', 'OPERATION_MESSAGE'),
    'bip340': (1, 'BIP340_SIGNATURE', 'OPERATION_MESSAGE'),
    'secp256k1-point': (2, 'SECP256K1_SCALAR', 'NO_OPERATION_MESSAGE_BINDING'),
}
CASES = {mode + '-' + case: (mode, *selected, case)
    for mode, selected in MODES.items() for case in parent.CASES}
TEST = 'TestResearchNoMReceivePointTypes'
TESTS = {TEST, *(TEST + '/' + case for case in CASES)}
PACKAGE = parent.PACKAGE
MARKER = 'PTLC_NOM_RECEIVE_POINT_TYPES_RECORD='
MAX_STDOUT, MAX_STDERR = parent.MAX_STDOUT, parent.MAX_STDERR
MAX_EVENT, MAX_OUTPUT_LINE = parent.MAX_EVENT, parent.MAX_OUTPUT_LINE
require, regular, canonical = parent.require, parent.regular, parent.canonical
decode = parent.decode


def inputs(root=ROOT):
    root = source_reader.physical(root)
    parent_manifest, index = parent.inputs(root)
    manifest = source_reader.decoded(regular(root / MANIFEST, 64 * 1024), 64 * 1024)
    fixed = dict(schema='ptlc-nom-receive-point-types-selection-v1', core_commit=CORE,
        core_tree=TREE, upstream_files=444, project_probe_files=1,
        expected_go_outcomes=7, expected_cases=sorted(CASES),
        point_modes={name: list(values) for name, values in MODES.items()},
        credit_amount_units='1000000000', credit_balance_encoding='CANONICAL_UINT256_DECIMAL',
        explicit_user_receives_per_case=1, duplicate_credit_commits_per_case=0,
        event_output_fragments='SAME_TEST_LINE_REASSEMBLY', max_output_line_bytes=MAX_OUTPUT_LINE,
        source_index_sha256=source_reader.INDEX_SHA256, probe_license='GPL-3.0-only',
        raw_scalar_witness='NO_OPERATION_MESSAGE_BINDING; FIXED_NONZERO_DESTINATION_REQUIRED',
        adaptor_signature_completion='NOT_ASSESSED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO')
    require(type(manifest) is dict and set(manifest) == set(fixed) | {'input_sha256'})
    require(canonical({key: manifest[key] for key in fixed}) == canonical(fixed))
    pins = manifest['input_sha256']
    require(type(pins) is dict and set(pins) == SELECTED)
    for name, pin in pins.items():
        require(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin))
        require(hashlib.sha256(regular(root / name, 2 * 1024**2)).hexdigest() == pin)
    require(pins[LICENSE] == parent_manifest['input_sha256'][LICENSE])
    return manifest, index


def compare_source(source, root=ROOT):
    manifest, index = inputs(root)
    source = source_reader.physical(source)
    require(source.is_dir())
    expected = {name: row['sha256'] for name, row in index.items()}
    require(DESTINATION not in expected)
    expected[DESTINATION] = manifest['input_sha256'][DRIVER]
    seen, total = set(), 0
    for directory, children, names in os.walk(source, followlinks=False):
        directory = Path(directory)
        require(not directory.is_symlink())
        require(all(not (directory / name).is_symlink() for name in children))
        for name in names:
            path = directory / name
            relative = path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw = regular(path, 8 * 1024**2)
            total += len(raw)
            require(total <= 40 * 1024**2)
            require(hashlib.sha256(raw).hexdigest() == expected[relative])
            seen.add(relative)
    require(seen == set(expected) and len(seen) == 445)
    return dict(upstream_files=444, project_probe_files=1, combined_files=445,
        content='EXACT_SELECTED_CONTENTS', filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def compare_record(value, case):
    extra = {'point_type', 'point_mode', 'witness_kind', 'witness_binding'}
    require(type(value) is dict and case in CASES and extra <= set(value), 'unselected point-type record')
    mode, kind, witness, binding, prior_case = CASES[case]
    fixed = dict(schema='ptlc-nom-receive-point-types-source-v1', case=case,
        point_type=kind, point_mode=mode, witness_kind=witness, witness_binding=binding)
    for key, expected in fixed.items():
        require(type(value.get(key)) is type(expected) and value[key] == expected, 'unselected point-type binding')
    projected = {key: item for key, item in value.items() if key not in extra}
    projected['schema'] = 'ptlc-nom-receive-credit-source-v1'
    projected['case'] = prior_case
    # Keep every earlier expiry, ordering, credit and authority comparison.
    parent.compare_record(projected, prior_case)
    return value


def compare_stream(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STDOUT, 'unbounded stream')
    require(raw.endswith(b'\n'), 'incomplete event stream')
    buffers, runs, passed, records = {}, set(), set(), {}
    started = finished = False
    events = 0
    for line in raw.splitlines():
        require(0 < len(line) <= MAX_EVENT, 'unbounded event')
        event = decode(line)
        events += 1
        require(type(event) is dict and set(event) <= source_reader.EVENT_FIELDS and not finished,
            'unselected event fields or data after outcome')
        require('FailedBuild' not in event, 'failed build field')
        if 'Time' in event:
            require(type(event['Time']) is str and 0 < len(event['Time']) <= 128, 'invalid event time')
        if 'Elapsed' in event:
            elapsed = event['Elapsed']
            require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0, 'invalid elapsed value')
        if 'Output' in event:
            require(type(event['Output']) is str and event.get('Action') == 'output', 'invalid output field')
        require(event.get('Package') == PACKAGE, 'unselected package')
        action, test = event.get('Action'), event.get('Test')
        require(type(action) is str and action in ('start', 'run', 'output', 'pass'), 'failed or unselected action')
        if 'Test' in event:
            require(type(test) is str and test in TESTS, 'unselected explicit Test')
        if action == 'start':
            require('Test' not in event and not started and not runs and not buffers, 'duplicate package start')
            started = True
            continue
        require(started, 'event before package start')
        if action == 'run':
            require('Test' in event and test not in runs, 'duplicate test run')
            if test != TEST:
                require(TEST in runs and TEST not in passed, 'child outside parent run')
                require(not (runs - passed - {TEST}), 'overlapping finite cases')
            else:
                require(not runs, 'parent after child')
            runs.add(test)
            continue
        if action == 'output':
            output = event.get('Output')
            require(type(output) is str and len(output.encode('utf-8')) <= MAX_EVENT, 'unbounded Output')
            if 'Test' in event:
                require(test in runs and test not in passed, 'output outside test run')
            pending = buffers.get(test, '') + output
            while '\n' in pending:
                text, pending = pending.split('\n', 1)
                require(len(text.encode('utf-8')) <= MAX_OUTPUT_LINE, 'unbounded output line')
                if MARKER not in text:
                    continue
                require(test in TESTS - {TEST} and text.startswith(MARKER) and text.count(MARKER) == 1,
                    'unbound record line')
                case = test.split('/', 1)[1]
                require(case not in records, 'duplicate case record')
                records[case] = compare_record(decode(text[len(MARKER):]), case)
            require(len(pending.encode('utf-8')) <= MAX_OUTPUT_LINE, 'unbounded partial line')
            buffers[test] = pending
            continue
        if 'Test' in event:
            require(test in runs and test not in passed and not buffers.get(test, ''), 'incomplete or duplicate test outcome')
            if test == TEST:
                require(passed == TESTS - {TEST}, 'parent before complete children')
            else:
                require(test.split('/', 1)[1] in records, 'missing child record')
            passed.add(test)
        else:
            require(passed == runs == TESTS and not any(buffers.values()), 'incomplete package outcome')
            finished = True
    require(started and finished and passed == TESTS and set(records) == set(CASES), 'missing terminal outcomes')
    return dict(outcome='PASS_SIX_FINITE_POINT_TYPE_VALUES_ONLY', cases=records, events=events,
        passed_including_parent=7, package_passes=1, stdout_sha256=hashlib.sha256(raw).hexdigest(),
        execution='NOT_PERFORMED_BY_READER', producer_authentication='NOT_ESTABLISHED_BY_READER',
        application='NO-GO', core='NO-GO')


def compare_payloads(stdout, stderr, root=ROOT):
    manifest, unused_index = inputs(root)
    require(type(stderr) is bytes and len(stderr) <= MAX_STDERR)
    checked = compare_stream(stdout)
    return dict(schema='ptlc-nom-receive-point-types-comparison-v1', outcome=checked['outcome'],
        core_commit=CORE, core_tree=TREE, probe_sha256=manifest['input_sha256'][DRIVER],
        cases=checked['cases'], passed_including_parent=7, package_passes=1,
        parsed_events=checked['events'], event_output_fragments='SAME_TEST_LINE_REASSEMBLY',
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stdout_bytes=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), stderr_bytes=len(stderr),
        actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER', producer_authentication='NOT_ESTABLISHED_BY_THIS_READER',
        source_content='SEPARATE_COMPLETE_CONTENT_CHECK_REQUIRED', native_execution='NOT_PERFORMED_BY_READER',
        independent_assessment='UNFILLED', canonicality='UNFILLED', finality='UNFILLED', liveness='UNFILLED',
        recipient_balance_credit='SIX_FINITE_EXPLICIT_USER_RECEIVE_VALUES_ONLY',
        adaptor_signature_completion='NOT_ASSESSED', swap_atomicity='NOT_ASSESSED',
        safe_disclosure_margin='NOT_SELECTED', journal_source_upgrade='NOT_SELECTED',
        journal_write='NOT_PERFORMED', signing='NOT_PERFORMED_BY_READER',
        transaction_broadcast='NOT_PERFORMED', recovery_action='NONE', application='NO-GO', core='NO-GO')


def main():
    import argparse

    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('point type comparison refused')

    parser = QuietParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stdout', type=Path, required=True)
    parser.add_argument('--stderr', type=Path, required=True)
    try:
        args = parser.parse_args()
        source = compare_source(args.source)
        result = compare_payloads(regular(args.stdout, MAX_STDOUT), regular(args.stderr, MAX_STDERR))
        result['complete_source'] = source
    except (AssertionError, ValueError, TypeError, KeyError, OSError, UnicodeError, OverflowError):
        print('point type comparison refused', file=sys.stderr)
        return 1
    print(canonical(result).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
