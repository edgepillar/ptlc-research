#!/usr/bin/env python3
"""Select privacy-checked originals for explicit retention, without native work.

Private argv receipts, cache contents and generated handoff paths are excluded.
A checked manifest is neither execution-origin attestation nor CI acceptance.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('REFUSED: 5cb evidence check requires assertions enabled')
import argparse
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_dev_5cb as selected
from qualification import nom_dev_5cb_reproduction as reproduction
from scripts import nom_5cb_command as capture
from scripts.check_artifacts import PATTERNS

require = selected.earlier.require
MAX_TOTAL = 96 * 1024**2
BASE_REPORT_FIELDS = frozenset((
    'schema', 'outcome', 'core_commit', 'core_tree', 'profile', 'source_before',
    'go_sha256', 'cc_sha256', 'platform_sdk', 'compiler_identity_scope', 'compiler_workspaces',
    'source_views', 'selected_commands', 'free_space_floor', 'expected_reservation',
    'os_filesystem_quota', 'normal_default_vet', 'test_result_cache', 'commands',
    'automatic_native_retry', 'complete_account_admission', 'source_build_authentication',
    'journal_source_upgrade', 'application', 'core', 'independent_assessment',
))
COMPLETE_REPORT_FIELDS = frozenset((
    'go_version', 'comparison', 'complete_profiles', 'selected_parent_and_child_outcomes',
    'complete_original_profile_streams', 'actual_native_commands', 'source_unchanged',
    'compiler_unchanged', 'elapsed_seconds',
))


def privacy(raw):
    require(type(raw) is bytes)
    text = raw.decode('ascii')
    roots = ('Users', 'Volumes', 'private', 'home', 'tmp', 'var',
             'opt', 'Applications', 'Library', 'usr')
    # Inspect escaped representations too. Retained originals are never decoded,
    # redacted, replaced or rewritten. Each view is bounded by the input length.
    for unused_depth in range(8):
        require(text.isascii())
        require(not any(pattern.search(text) for unused, pattern in PATTERNS))
        require(not re.search(r'(?i)/(?:' + '|'.join(roots) + r')/', text))
        require(not re.search(r'(?i)localhost|\b[A-Za-z0-9_-]+[.]local\b|127[.]0[.]0[.]1', text))
        decoded = re.sub(r'\\u([0-9a-fA-F]{4})',
                         lambda match: chr(int(match.group(1), 16)), text)
        decoded = decoded.replace(chr(92) * 2, chr(92))
        if decoded == text:
            return
        text = decoded
    require(False)


def expected_arguments(root=ROOT):
    plan = reproduction.plan(root, 'all')
    packages = sorted({'./' + row['package'] for row in plan['units']})
    result = dict((row['unit'], row['arguments']) for row in plan['units'])
    result.update({
        'go-version': ['version'],
        'cold-build': ['test', '-json', '-p', '2', '-mod=readonly', '-count=1', '-run', '^$', *packages],
        'upstream-definition': ['test', '-json', '-p', '2', '-mod=readonly', '-count=1', './vm/embedded/definition'],
        'module-verify': ['mod', 'verify'],
    })
    require(len(result) == 24 and set(result) == capture.LABELS)
    return result


def inspect(workspace, *, allow_incomplete=False, root=ROOT):
    require(not sys.flags.optimize and type(allow_incomplete) is bool)
    workspace = selected.earlier.physical(workspace)
    expected = expected_arguments(root)
    success = (workspace / 'native-result.json').is_file()
    require(not (success and (workspace / 'native-failure.json').exists()))
    filename = 'native-result.json' if success else 'native-failure.json'
    require(success or allow_incomplete)
    files, total = {}, 0

    def retained(name, limit=2 * 1024**2):
        nonlocal total
        require(name not in files)
        raw = selected.earlier.regular(workspace / name, limit)
        total += len(raw)
        require(total <= MAX_TOTAL)
        privacy(raw)
        files[name] = dict(bytes=len(raw), sha256=selected.sha(raw))
        return raw

    report = selected.earlier.decoded(retained(filename), 2 * 1024**2)
    require(type(report) is dict and BASE_REPORT_FIELDS <= set(report)
        and set(report) <= BASE_REPORT_FIELDS | COMPLETE_REPORT_FIELDS | {'exception_type'})
    if success:
        require(set(report) == BASE_REPORT_FIELDS | COMPLETE_REPORT_FIELDS)
    else:
        require({'exception_type', 'elapsed_seconds'} <= set(report))
    require(report['source_before'] == dict(core_commit=selected.CORE,
        core_tree=selected.TREE, profile='all', upstream_files=482,
        project_producers=20, combined_files=502, content='EXACT_SELECTED_CONTENTS',
        filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_READER'))
    require(report['schema'] == 'ptlc-nom-5cb-native-attempt-v1'
        and report['core_commit'] == selected.CORE and report['core_tree'] == selected.TREE
        and report['profile'] == 'all' and report['compiler_workspaces'] == report['source_views'] == 1
        and report['normal_default_vet'] is True
        and report['test_result_cache'] == 'DISABLED_BY_COUNT_ONE'
        and report['automatic_native_retry'] is False
        and report['application'] == report['core'] == 'NO-GO'
        and report['independent_assessment'] == 'UNFILLED'
        and report['journal_source_upgrade'] == 'NOT_SELECTED')
    require(report['platform_sdk'] in (
        'NOT_SELECTED', 'DARWIN_SDKROOT_SELECTED_CONTENT_UNAUTHENTICATED'))
    if report['platform_sdk'] != 'NOT_SELECTED' and 'go_version' in report:
        require(report['go_version'] == 'go version go1.23.12 darwin/arm64')
    directory = workspace / 'commands'
    require(directory.is_dir())
    names = {path.name for path in directory.iterdir()}
    suffixes = ('.stdout', '.stderr', '.receipt.json')
    require(names <= {label + suffix for label in expected for suffix in suffixes})
    labels = {label for label in expected if any(label + suffix in names for suffix in suffixes)}
    if success:
        require(names == {label + suffix for label in expected for suffix in suffixes})
    commands, payloads = {}, {}
    fields = ('actual_exit', 'result', 'bytes', 'complete', 'sha256', 'elapsed_seconds')
    for label in sorted(labels):
        present = {suffix for suffix in ('stdout', 'stderr') if label + '.' + suffix in names}
        if label + '.receipt.json' not in names:
            require(allow_incomplete and not success)
            retained_streams = {}
            for suffix in sorted(present):
                raw = retained('commands/' + label + '.' + suffix,
                    capture.MAX_STDOUT if suffix == 'stdout' else capture.MAX_STDERR)
                retained_streams[suffix] = files['commands/' + label + '.' + suffix]
                if label in selected.units('all'):
                    payloads[label + '.' + suffix] = raw
            commands[label] = dict(result='UNKNOWN_ORIGINAL_RECEIPT_MISSING',
                actual_exit=None, planned_arguments=expected[label],
                executed_arguments='NOT_ESTABLISHED', retained_streams=retained_streams,
                missing_streams=sorted({'stdout', 'stderr'} - present))
            continue
        # The original private receipt is checked but never selected for public
        # retention. Its absolute executable path is not copied or normalized.
        receipt = selected.earlier.decoded(selected.earlier.regular(
            directory / (label + '.receipt.json'), 64 * 1024), 64 * 1024)
        require(receipt['schema'] == 'ptlc-nom-5cb-native-command-v1'
            and receipt['label'] == label and receipt['automatic_retry'] is False
            and type(receipt['argv']) is list and len(receipt['argv']) >= 2
            and type(receipt['argv'][0]) is str and Path(receipt['argv'][0]).is_absolute()
            and receipt['argv'][1:] == expected[label]
            and (receipt['actual_exit'] is None or type(receipt['actual_exit']) is int)
            and type(receipt['elapsed_seconds']) in (int, float)
            and math.isfinite(receipt['elapsed_seconds']) and receipt['elapsed_seconds'] >= 0)
        require(all(type(receipt[key]) is dict and set(receipt[key]) == {'stdout', 'stderr'}
                    for key in ('bytes', 'sha256', 'complete')))
        for suffix in ('stdout', 'stderr'):
            require(type(receipt['bytes'][suffix]) is int and receipt['bytes'][suffix] >= 0
                and type(receipt['sha256'][suffix]) is str
                and re.fullmatch('[0-9a-f]{64}', receipt['sha256'][suffix])
                and type(receipt['complete'][suffix]) is bool)
            if suffix not in present:
                require(allow_incomplete and not success)
                continue
            raw = retained('commands/' + label + '.' + suffix,
                           capture.MAX_STDOUT if suffix == 'stdout' else capture.MAX_STDERR)
            require(receipt['bytes'][suffix] == len(raw)
                and receipt['sha256'][suffix] == selected.sha(raw))
            if label in selected.units('all'):
                payloads[label + '.' + suffix] = raw
        if label in report['commands']:
            require(report['commands'][label] == {key: receipt[key] for key in fields})
        projection = {key: receipt[key] for key in fields}
        projection.update(arguments=expected[label], cleanup_complete=receipt['cleanup_complete'])
        if 'failure' in receipt:
            projection['failure'] = receipt['failure']
        if 'truncated_stream' in receipt:
            projection['truncated_stream'] = receipt['truncated_stream']
        if present != {'stdout', 'stderr'}:
            projection.update(result='UNKNOWN_ORIGINAL_STREAM_MISSING',
                reported_result=receipt['result'], reported_complete=receipt['complete'],
                complete={suffix: suffix in present and receipt['complete'][suffix]
                          for suffix in ('stdout', 'stderr')},
                missing_streams=sorted({'stdout', 'stderr'} - present))
        privacy(json.dumps(projection, sort_keys=True).encode('ascii'))
        commands[label] = projection
    require(set(report['commands']) <= labels)
    if success:
        require(report['outcome'] == 'PASS_SELECTED_NATIVE_FINITE_COMPARISONS_ONLY'
            and set(commands) == set(expected) and report['complete_profiles'] == 20
            and report['selected_parent_and_child_outcomes'] == 479
            and report['complete_original_profile_streams'] == 40
            and report['actual_native_commands'] == 24
            and report['source_unchanged'] is report['compiler_unchanged'] is True)
        for receipt in commands.values():
            require(receipt['actual_exit'] == 0
                and receipt['result'] == 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
                and receipt['complete'] == {'stdout': True, 'stderr': True}
                and receipt['cleanup_complete'] is True)
        raw = retained('finite-value-comparison.json')
        require(files['finite-value-comparison.json'] == report['comparison'])
        comparison = selected.earlier.decoded(raw, 2 * 1024**2)
        require(comparison == selected.compare_payloads(payloads, root, 'all'))
    else:
        require(report['outcome'] == 'FAILURE_OR_INCOMPLETE_PRESERVED')
    return dict(schema='ptlc-nom-5cb-explicit-retention-v1',
        outcome='PASS_PRIVACY_AND_ORIGINAL_SELECTION_ONLY' if success else 'INCOMPLETE_RETENTION_ONLY',
        core_commit=selected.CORE, core_tree=selected.TREE, full_attempt=success,
        files=files, commands=commands, original_profile_streams=len(payloads),
        total_bytes=total, private_argv_receipts='EXCLUDED', cache_and_handoffs='EXCLUDED',
        native_execution='NOT_PERFORMED_BY_CHECKER', ci_acceptance='NOT_PERFORMED',
        execution_origin='NOT_ESTABLISHED_BY_CHECKER', application='NO-GO', core='NO-GO')


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('selected 5cb evidence check refused')
    parser = QuietParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--allow-incomplete-for-retention', action='store_true')
    parser.add_argument('--artifact-files', action='store_true')
    try:
        args = parser.parse_args()
        manifest = inspect(args.workspace, allow_incomplete=args.allow_incomplete_for_retention)
        if args.artifact_files:
            import os
            path = selected.earlier.physical(args.workspace) / 'retention-manifest.json'
            raw = json.dumps(manifest, sort_keys=True, ensure_ascii=True).encode('ascii')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
    except (AssertionError, OSError, ValueError, KeyError, TypeError, RuntimeError):
        print('REFUSED: 5cb retention check; preserve private originals without export', file=sys.stderr)
        return 1
    if args.artifact_files:
        print('\n'.join(sorted([*manifest['files'], 'retention-manifest.json'])))
    else:
        print(json.dumps(manifest, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
