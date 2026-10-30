"""Select original two-stage outputs without executing or authenticating them.

Private argv receipts are checked in place and excluded from public retention.
An incomplete selection retains UNKNOWN status and cannot qualify a full run.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_dev_821bdd2 as selected
from qualification import nom_fee_original_boundary as fee
from scripts import check_nom_821bdd2_evidence as baseline_checker
from scripts import nom_821bdd2_command as capture

require = selected.require
MAX_TOTAL = baseline_checker.MAX_TOTAL + 48 * 1024**2
ARGUMENTS = {
    'fee-original-boundary': ['test','-json','-p','2','-mod=readonly','-count=1',
        '-run','^'+fee.PARENT+'$','./vm'],
    'fee-module-verify': ['mod','verify'],
}


def exact(actual, expected):
    fee.common.rebase.exact(expected, actual)


def seconds(value):
    require(type(value) in (int,float) and 0 <= value <= 86400
        and math.isfinite(value))


def expected_fee_source(root):
    values = selected.source_payloads(root, fee_stage=True)
    require(len(values) == 549)
    return dict(core_commit=selected.CORE, core_tree=selected.TREE, profile='all',
        upstream_files=523, project_producers=26, combined_files=549,
        snapshot=dict(files=549,sha256=selected.sha(json.dumps(values,sort_keys=True).encode('ascii'))),
        reference_fixture_core=selected.FIXTURE_CORE,
        content='EXACT_SELECTED_CONTENTS; UNCHANGED REFERENCE PRODUCERS',
        filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_READER')


def inspect(workspace, *, allow_incomplete=False, root=ROOT):
    require(sys.dont_write_bytecode and not sys.flags.optimize
        and type(allow_incomplete) is bool)
    workspace = selected.earlier.physical(workspace)
    base = baseline_checker.inspect(workspace, allow_incomplete=allow_incomplete, root=root)
    files = dict(base['files'])
    total = sum(pin['bytes'] for pin in files.values())

    def retained(name, limit=2 * 1024**2):
        nonlocal total
        require(name not in files)
        raw = selected.earlier.regular(workspace / name, limit)
        baseline_checker.privacy(raw)
        total += len(raw)
        require(total <= MAX_TOTAL)
        files[name] = dict(bytes=len(raw),sha256=selected.sha(raw))
        return raw

    def document(name):
        return selected.earlier.decoded(retained(name), 2 * 1024**2)

    base_retention = None
    if (workspace / 'base-stage-retention.json').is_file():
        base_retention = document('base-stage-retention.json')
    base_matches = base_retention == base
    bundle_success = (workspace / 'bundle-native-result.json').is_file()
    bundle_failure = (workspace / 'bundle-native-failure.json').is_file()
    require(not (bundle_success and bundle_failure))
    bundle = document('bundle-native-result.json' if bundle_success else
        'bundle-native-failure.json') if bundle_success or bundle_failure else None
    if bundle is not None:
        fixed = dict(schema='ptlc-nom-821bdd2-two-stage-native-v1',
            core_commit=selected.CORE, core_tree=selected.TREE,
            reference_fixture_core=selected.FIXTURE_CORE,
            reference_fixture_tree=selected.FIXTURE_TREE,
            embedded_core_labels='UNCHANGED REFERENCE LABELS; NOT COMPILATION INPUT IDENTITIES',
            compiler_workspaces=1, physical_source_views=1, source_stages=2,
            normal_default_vet=True, test_result_cache='DISABLED_BY_COUNT_ONE',
            automatic_retry=False, original_streams_rewritten=False,
            journal_source_upgrade='NOT_SELECTED', application='NO-GO', core='NO-GO',
            recovery_action='NONE', independent_assessment='UNFILLED')
        exact({key:bundle[key] for key in fixed}, fixed)
        require(bundle['outcome'] == ('PASS_TWO_FRESH_OFFLINE_NATIVE_STAGES_ONLY'
            if bundle_success else 'FAILURE_OR_INCOMPLETE_PRESERVED'))
        success_fields = {
            'baseline_retention','baseline_result','fee_producer','baseline_source','fee_source',
            'baseline_profiles','fee_profiles','complete_profiles','baseline_native_commands',
            'fee_native_commands','actual_native_commands','reference_outcomes',
            'prior_runtime_outcomes','upstream_test_outcomes','fee_outcomes','total_outcomes',
            'baseline_originals_unchanged','source_extractions_performed_by_runner',
            'baseline_result_reused','historical_cache_adopted','elapsed_seconds'}
        if bundle_success:
            require(set(bundle) == set(fixed) | {'outcome'} | success_fields)
        else:
            required = set(fixed) | {'outcome','exception_type','fee_producer_appended','elapsed_seconds'}
            require(required <= set(bundle) <= required | {
                'baseline_retention','baseline_result','fee_producer'})
            require(type(bundle['fee_producer_appended']) is bool
                and type(bundle['exception_type']) is str
                and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',bundle['exception_type']))
        seconds(bundle['elapsed_seconds'])

    fee_result = (workspace / 'fee-native-result.json').is_file()
    fee_intent = (workspace / 'fee-native-intent.json').is_file()
    declared = document('fee-native-result.json') if fee_result else None
    intent = None
    if fee_intent:
        intent = document('fee-native-intent.json')
        require(intent['outcome'] == 'UNKNOWN')
        if declared is None:
            declared = intent
    fee_comparison = document('fee-value-comparison.json') if (
        workspace / 'fee-value-comparison.json').is_file() else None
    if declared is not None:
        input_raw, expected_raw = fee.input_bytes(root), fee.expected_bytes(root)
        fixed = dict(schema='ptlc-nom-821bdd2-fee-stage-v1',
            core_commit=selected.CORE, core_tree=selected.TREE,
            reference_fixture_core=fee.CORE, reference_fixture_tree=fee.TREE,
            reference_input=dict(bytes=len(input_raw),sha256=selected.sha(input_raw)),
            reference_expected=dict(bytes=len(expected_raw),sha256=selected.sha(expected_raw)),
            source_before=expected_fee_source(root), source_stage=2,
            compiler_workspace='SAME_LIVE_INVOCATION',
            test_result_cache='DISABLED_BY_COUNT_ONE', normal_default_vet=True,
            automatic_retry=False, new_keys=0, new_signatures=0,
            journal_source_upgrade='NOT_SELECTED', original_replacement='NOT_SELECTED',
            application='NO-GO', core='NO-GO', recovery_action='NONE',
            independent_assessment='UNFILLED')
        exact({key:declared[key] for key in fixed}, fixed)
        require(type(declared['commands']) is dict and set(declared['commands']) <= set(ARGUMENTS))
        base_fields = set(fixed) | {'outcome','commands'}
        if fee_result:
            require(set(declared) == base_fields | {
                'source_after','source_unchanged','comparison','actual_native_commands',
                'actual_cases','outcomes_including_parent','baseline_originals_unchanged',
                'elapsed_seconds'})
            seconds(declared['elapsed_seconds'])
        else:
            require(set(declared) == base_fields and declared['commands'] == {})
        if intent is not None:
            require(set(intent) == base_fields and intent['commands'] == {})
            exact({key:intent[key] for key in fixed}, fixed)

    commands, original_streams = {}, {}
    directory = workspace / 'fee-commands'
    if directory.exists():
        selected.earlier.physical(directory)
        require(directory.is_dir())
        names = {path.name for path in directory.iterdir()}
        require(names <= {label + suffix for label in ARGUMENTS
            for suffix in ('.stdout','.stderr','.receipt.json')})
        for label, arguments in sorted(ARGUMENTS.items()):
            present = {suffix for suffix in ('stdout','stderr')
                if label + '.' + suffix in names}
            if not present and label + '.receipt.json' not in names:
                continue
            for suffix in sorted(present):
                name = 'fee-commands/' + label + '.' + suffix
                original_streams[label + '.' + suffix] = retained(name,
                    capture.MAX_STDOUT if suffix == 'stdout' else capture.MAX_STDERR)
            if label + '.receipt.json' not in names:
                require(allow_incomplete)
                commands[label] = dict(result='UNKNOWN_ORIGINAL_RECEIPT_MISSING',
                    actual_exit=None, complete=dict(stdout=False,stderr=False),
                    arguments=arguments, missing_streams=sorted({'stdout','stderr'}-present))
                continue
            receipt = selected.earlier.decoded(selected.earlier.regular(
                directory / (label + '.receipt.json'), 64 * 1024), 64 * 1024)
            require(receipt['schema'] == 'ptlc-nom-821bdd2-native-command-v1'
                and receipt['label'] == label and receipt['automatic_retry'] is False
                and type(receipt['argv']) is list and len(receipt['argv']) >= 2
                and type(receipt['argv'][0]) is str and Path(receipt['argv'][0]).is_absolute()
                and receipt['argv'][1:] == arguments
                and (receipt['actual_exit'] is None or type(receipt['actual_exit']) is int)
                and type(receipt['elapsed_seconds']) in (int,float)
                and math.isfinite(receipt['elapsed_seconds']) and receipt['elapsed_seconds'] >= 0)
            fields = ('actual_exit','result','bytes','complete','sha256','elapsed_seconds')
            projection = {key:receipt[key] for key in fields}
            projection.update(arguments=arguments,cleanup_complete=receipt['cleanup_complete'])
            for key in ('bytes','complete','sha256'):
                require(type(receipt[key]) is dict and set(receipt[key]) == {'stdout','stderr'})
            for suffix in ('stdout','stderr'):
                limit = capture.MAX_STDOUT if suffix == 'stdout' else capture.MAX_STDERR
                require(type(receipt['bytes'][suffix]) is int and 0 <= receipt['bytes'][suffix] <= limit
                    and type(receipt['complete'][suffix]) is bool
                    and type(receipt['sha256'][suffix]) is str
                    and re.fullmatch('[0-9a-f]{64}',receipt['sha256'][suffix]))
                if suffix in present:
                    raw = original_streams[label + '.' + suffix]
                    require(len(raw) == receipt['bytes'][suffix]
                        and selected.sha(raw) == receipt['sha256'][suffix])
                else:
                    require(allow_incomplete)
            if present != {'stdout','stderr'}:
                projection.update(result='UNKNOWN_ORIGINAL_STREAM_MISSING',
                    reported_result=receipt['result'], reported_complete=receipt['complete'],
                    complete={suffix:suffix in present and receipt['complete'][suffix]
                        for suffix in ('stdout','stderr')},
                    missing_streams=sorted({'stdout','stderr'}-present))
            if declared is not None and label in declared['commands']:
                exact(declared['commands'][label], {key:receipt[key] for key in fields})
            baseline_checker.privacy(json.dumps(projection,sort_keys=True).encode('ascii'))
            commands[label] = projection

    complete_commands = set(commands) == set(ARGUMENTS) and all(
        row['actual_exit'] == 0 and row['result'] == 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
        and row['complete'] == {'stdout':True,'stderr':True}
        and row.get('cleanup_complete') is True for row in commands.values())
    full = bool(bundle_success and base['full_attempt'] and base_matches
        and fee_result and fee_intent and fee_comparison is not None and complete_commands)
    require(full or allow_incomplete)
    if full:
        require(set(declared['commands']) == set(ARGUMENTS)
            and declared['outcome'] == 'PASS_FRESH_NATIVE_FEE_ORIGINAL_REFUSALS_ONLY'
            and declared['source_after'] == declared['source_before']
            and declared['source_unchanged'] is True
            and declared['baseline_originals_unchanged'] is True)
        exact({key:declared[key] for key in (
            'actual_native_commands','actual_cases','outcomes_including_parent')},
            dict(actual_native_commands=2,actual_cases=14,outcomes_including_parent=15))
        require(original_streams['fee-original-boundary.stderr'] == b'')
        require(fee_comparison == fee.read(original_streams['fee-original-boundary.stdout'],
            fee.input_bytes(root), fee.expected_bytes(root)))
        require(declared['comparison'] == files['fee-value-comparison.json'])
        require(bundle['baseline_retention'] == files['base-stage-retention.json']
            and bundle['baseline_result'] == base['files']['native-result.json']
            and bundle['baseline_source'] == selected.earlier.decoded(
                selected.earlier.regular(workspace / 'native-result.json',2*1024**2),
                2*1024**2)['source_before']
            and bundle['fee_source'] == declared['source_after'])
        producer_raw = selected.earlier.regular(Path(root) / fee.DRIVER,128*1024)
        exact(bundle['fee_producer'],dict(bytes=len(producer_raw),sha256=selected.sha(producer_raw)))
        fixed = dict(baseline_profiles=36,fee_profiles=1,complete_profiles=37,
            baseline_native_commands=40,fee_native_commands=2,actual_native_commands=42,
            reference_outcomes=642,prior_runtime_outcomes=58,upstream_test_outcomes=67,
            fee_outcomes=15,total_outcomes=782,baseline_originals_unchanged=True,
            source_extractions_performed_by_runner=0,baseline_result_reused=False,
            historical_cache_adopted=False)
        exact({key:bundle[key] for key in fixed}, fixed)
    return dict(schema='ptlc-nom-821bdd2-bundle-retention-v1',
        outcome='PASS_PRIVACY_AND_TWO_STAGE_SELECTION_ONLY' if full else 'INCOMPLETE_RETENTION_ONLY',
        core_commit=selected.CORE,core_tree=selected.TREE,
        reference_fixture_core=selected.FIXTURE_CORE,
        full_attempt=full,baseline_full_attempt=base['full_attempt'],
        baseline_manifest_matches=base_matches,fee_result_present=fee_result,
        bundle_result_present=bundle_success,files=files,fee_commands=commands,
        total_bytes=total,private_argv_receipts='EXCLUDED',cache_and_handoffs='EXCLUDED',
        interrupted_outcome='NOT_APPLICABLE' if full else 'UNKNOWN_OR_FAILED; NOT_RECLASSIFIED',
        native_execution='NOT_PERFORMED_BY_CHECKER',ci_acceptance='NOT_PERFORMED',
        execution_origin='NOT_ESTABLISHED_BY_CHECKER',application='NO-GO',core='NO-GO')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--allow-incomplete-for-retention',action='store_true')
    parser.add_argument('--artifact-files',action='store_true')
    try:
        args = parser.parse_args()
        result = inspect(args.workspace,allow_incomplete=args.allow_incomplete_for_retention)
        if args.artifact_files:
            path = selected.earlier.physical(args.workspace) / 'bundle-retention-manifest.json'
            descriptor = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(descriptor,'wb') as output:
                output.write(json.dumps(result,sort_keys=True).encode('ascii'))
                output.flush();os.fsync(output.fileno())
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RuntimeError):
        print('REFUSED: two-stage retention; preserve private originals without export',file=sys.stderr)
        return 1
    if args.artifact_files:
        print('\n'.join(sorted([*result['files'],'bundle-retention-manifest.json'])))
    else:
        print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
