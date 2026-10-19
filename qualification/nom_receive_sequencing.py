"""Read two pinned mock receive-order cases without granting recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('receive sequencing comparison requires assertions enabled')

import hashlib
import json
import math
import os
from pathlib import Path

from qualification import nom_current_admission as source_reader

ROOT = Path(__file__).resolve().parents[1]
CORE = source_reader.CORE
TREE = source_reader.TREE
MANIFEST = 'compatibility/nom_receive_sequencing_manifest.json'
DRIVER = 'compatibility/nom_receive_sequencing_test.go.txt'
DESTINATION = 'zenon/mock/zz_research_nom_receive_sequencing_test.go'
LICENSE = 'licenses/GPL-3.0-go-zenon.txt'
SELECTED = {DRIVER, LICENSE, source_reader.SOURCE,
    'qualification/nom_receive_sequencing.py', 'tests/test_nom_receive_sequencing.py'}
PACKAGE = 'github.com/zenon-network/go-zenon/zenon/mock'
TEST = 'TestResearchNoMReceiveSequencing'
CASES = {'unlock-first': 'unlock', 'reclaim-first': 'reclaim'}
TESTS = {TEST, *(TEST + '/' + case for case in CASES)}
MARKER = 'PTLC_NOM_RECEIVE_SEQUENCING_RECORD='
MAX_STDOUT = 8 * 1024**2
MAX_STDERR = 1024**2
require = source_reader.require
decoded = source_reader.decoded
regular = source_reader.regular
canonical = source_reader.canonical


def inputs(root=ROOT):
    root = source_reader.physical(root)
    manifest = decoded(regular(root / MANIFEST, 64 * 1024), 64 * 1024)
    fixed = dict(schema='ptlc-nom-receive-sequencing-selection-v1', core_commit=CORE,
        core_tree=TREE, upstream_files=444, project_probe_files=1,
        expected_go_outcomes=3, expected_cases=sorted(CASES),
        source_index_sha256=source_reader.INDEX_SHA256,
        probe_license='GPL-3.0-only', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO')
    require(type(manifest) is dict and set(manifest) == set(fixed) | {'input_sha256'})
    require(canonical({key: manifest[key] for key in fixed}) == canonical(fixed))
    pins = manifest['input_sha256']
    require(type(pins) is dict and set(pins) == SELECTED)
    for name, pin in pins.items():
        require(type(pin) is str and len(pin) == 64 and all(c in '0123456789abcdef' for c in pin))
        require(hashlib.sha256(regular(root / name, 2 * 1024**2)).hexdigest() == pin)
    raw = regular(root / source_reader.SOURCE, 1024**2)
    require(hashlib.sha256(raw).hexdigest() == source_reader.INDEX_SHA256)
    index = decoded(raw, 1024**2)
    require(type(index) is dict and len(index) == 444)
    require(source_reader.git_tree(index) == TREE)
    require(index['LICENSE']['sha256'] == pins[LICENSE])
    return manifest, index


def compare_source(source, root=ROOT):
    manifest, index = inputs(root)
    source = source_reader.physical(source)
    require(source.is_dir())
    expected = {name: row['sha256'] for name, row in index.items()}
    require(DESTINATION not in expected)
    expected[DESTINATION] = manifest['input_sha256'][DRIVER]
    seen = set()
    total = 0
    for directory, children, names in os.walk(source, followlinks=False):
        parent = Path(directory)
        require(not parent.is_symlink())
        require(all(not (parent / name).is_symlink() for name in children))
        for name in names:
            path = parent / name
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


def record(value, case):
    fixed = dict(schema='ptlc-nom-receive-sequencing-source-v1', case=case,
        selected_head=CASES[case], later_send_refusal='ErrABSequencerNotNext',
        head_receive_acknowledges_confirmation=True, fixed_recipient_or_owner_payout=True,
        contract_entry_unchanged_after_generation=True, generation_commits=0,
        source_execution='IN_PROCESS_MOCK_ONLY', canonicality='UNFILLED',
        swap_atomicity='NOT_ASSESSED', safe_disclosure_margin='NOT_SELECTED',
        recovery_action='NONE', application='NO-GO', core='NO-GO')
    numbers = {'head_confirmation_height', 'later_confirmation_height', 'expiration',
        'head_confirmation_time', 'later_confirmation_time', 'processing_time'}
    require(type(value) is dict and set(value) == set(fixed) | numbers)
    require(canonical({key: value[key] for key in fixed}) == canonical(fixed))
    require(all(type(value[key]) is int and 0 < value[key] < 2**63 for key in numbers))
    require(value['head_confirmation_height'] < value['later_confirmation_height'])
    head, later = value['head_confirmation_time'], value['later_confirmation_time']
    require(head < later <= value['processing_time'])
    require(value['expiration'] <= later)
    if case == 'unlock-first':
        require(head < value['expiration'])
    else:
        require(value['expiration'] <= head)
    return value


def compare_payloads(stdout, stderr, root=ROOT):
    manifest, unused_index = inputs(root)
    require(type(stdout) is bytes and 0 < len(stdout) <= MAX_STDOUT)
    require(type(stderr) is bytes and len(stderr) <= MAX_STDERR)
    started, passed, records = set(), set(), {}
    package_started = package_passed = False
    for line in stdout.splitlines():
        event = decoded(line, MAX_STDOUT)
        require(type(event) is dict and set(event) <= source_reader.EVENT_FIELDS)
        require({'Action', 'Package'} <= set(event) and event['Package'] == PACKAGE)
        action = event['Action']
        require(type(action) is str and action in {'start', 'run', 'output', 'pass'})
        require('FailedBuild' not in event and not package_passed)
        if 'Time' in event:
            require(type(event['Time']) is str and 0 < len(event['Time']) <= 128)
        if 'Elapsed' in event:
            value = event['Elapsed']
            require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
        if 'Output' in event:
            require(type(event['Output']) is str and action == 'output')
        if action == 'start':
            require(not package_started and 'Test' not in event)
            package_started = True
            continue
        require(package_started)
        test = event.get('Test')
        if 'Test' in event:
            require(type(test) is str and test in TESTS)
        if action == 'run':
            require(test is not None and test not in started and test not in passed)
            require(test == TEST or (TEST in started and TEST not in passed))
            started.add(test)
        elif action == 'pass':
            if test is None:
                require(passed == TESTS and set(records) == set(CASES))
                package_passed = True
            else:
                require(test in started and test not in passed)
                if test == TEST:
                    require(TESTS - {TEST} <= passed)
                else:
                    require(test.removeprefix(TEST + '/') in records)
                passed.add(test)
        else:
            output = event.get('Output', '')
            require(test is None or (test in started and test not in passed))
            if MARKER in output:
                require(test in TESTS - {TEST} and output.startswith(MARKER))
                require(output.count(MARKER) == 1)
                case = test.removeprefix(TEST + '/')
                require(case not in records)
                records[case] = record(decoded(output[len(MARKER):].encode('ascii'), 64 * 1024), case)
    require(package_started and package_passed and started == passed == TESTS)
    return dict(schema='ptlc-nom-receive-sequencing-comparison-v1',
        outcome='PASS_TWO_FINITE_MOCK_RECEIVE_SEQUENCING_VALUES_ONLY',
        core_commit=CORE, core_tree=TREE, probe_sha256=manifest['input_sha256'][DRIVER],
        cases=records, passed_including_parent=3,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(), stdout_bytes=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(), stderr_bytes=len(stderr),
        actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER',
        source_content='SEPARATE_COMPLETE_CONTENT_CHECK_REQUIRED',
        native_execution='NOT_PERFORMED_BY_READER', independent_assessment='UNFILLED',
        canonicality='UNFILLED', finality='UNFILLED', liveness='UNFILLED',
        swap_atomicity='NOT_ASSESSED', safe_disclosure_margin='NOT_SELECTED',
        journal_source_upgrade='NOT_SELECTED', journal_write='NOT_PERFORMED',
        signing='NOT_PERFORMED', transaction_broadcast='NOT_PERFORMED',
        recovery_action='NONE', application='NO-GO', core='NO-GO')


def main():
    import argparse

    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('receive sequencing comparison refused')

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
        print('receive sequencing comparison refused', file=sys.stderr)
        return 1
    print(canonical(result).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
