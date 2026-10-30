"""Run two owned source stages in one fresh offline compiler workspace.

The baseline result is retained before appending the fee producer. This accepts
no historical cache or completed result as a replacement for native execution.
The caller separately owns storage admission and original evidence custody.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_dev_821bdd2 as selected
from qualification import nom_fee_original_boundary as fee
from scripts import qualify_nom_821bdd2_native as native
from scripts import check_nom_821bdd2_evidence as baseline_checker
from scripts import nom_821bdd2_command as capture

require = selected.require


def write_raw_new(path, raw):
    require(type(raw) is bytes and len(raw) <= 2 * 1024**2)
    path = selected.earlier.physical(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def freeze_originals(workspace, manifest):
    names = set(manifest['files']) | {'native-intent.json', 'base-stage-retention.json'}
    names.update('commands/' + label + '.receipt.json'
        for label in manifest['commands'])
    frozen = {}
    for name in sorted(names):
        path = workspace / name
        raw = selected.earlier.regular(path, capture.MAX_STDOUT)
        info = path.lstat()
        frozen[name] = (selected.sha(raw), info.st_dev, info.st_ino,
                        info.st_size, info.st_mtime_ns, info.st_mode)
    return frozen


def originals_unchanged(workspace, frozen):
    for name, expected in frozen.items():
        path = workspace / name
        raw = selected.earlier.regular(path, capture.MAX_STDOUT)
        info = path.lstat()
        require(expected == (selected.sha(raw), info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, info.st_mode))


def qualify(source, workspace, go, expected_go, proxy, cc, *, root=ROOT, sdk=None):
    require(sys.dont_write_bytecode and not sys.flags.optimize)
    source, workspace, go, proxy, cc = map(selected.earlier.physical,
        (source, workspace, go, proxy, cc))
    if sdk is not None:
        sdk = selected.earlier.physical(sdk)
    started = time.monotonic()
    # The unchanged freshness checks in the native runner reject a pre-existing
    # workspace. Only this invocation may supply the cache to the second stage.
    baseline = native.qualify(source, workspace, go, expected_go, proxy, cc,
                              root=root, sdk=sdk)
    require(baseline['complete_profiles'] == 36
        and baseline['actual_native_commands'] == 40
        and baseline['source_before']['combined_files'] == 548)
    report = dict(schema='ptlc-nom-821bdd2-two-stage-native-v1', outcome='UNKNOWN',
        core_commit=selected.CORE, core_tree=selected.TREE,
        reference_fixture_core=selected.FIXTURE_CORE,
        reference_fixture_tree=selected.FIXTURE_TREE,
        embedded_core_labels='UNCHANGED REFERENCE LABELS; NOT COMPILATION INPUT IDENTITIES',
        compiler_workspaces=1, physical_source_views=1, source_stages=2,
        normal_default_vet=True, test_result_cache='DISABLED_BY_COUNT_ONE',
        automatic_retry=False, original_streams_rewritten=False,
        journal_source_upgrade='NOT_SELECTED', application='NO-GO', core='NO-GO',
        recovery_action='NONE', independent_assessment='UNFILLED')
    appended = False
    try:
        manifest = baseline_checker.inspect(workspace, root=root)
        require(manifest['full_attempt'] is True
            and manifest['outcome'] == 'PASS_PRIVACY_AND_ORIGINAL_SELECTION_ONLY'
            and len(manifest['commands']) == 40)
        report['baseline_retention'] = native.write_new(
            workspace / 'base-stage-retention.json', manifest)
        frozen = freeze_originals(workspace, manifest)
        report['baseline_result'] = dict(bytes=len(selected.earlier.regular(
            workspace / 'native-result.json', 2 * 1024**2)),
            sha256=selected.sha(selected.earlier.regular(
                workspace / 'native-result.json', 2 * 1024**2)))
        require(selected.compare_source(source, root) == baseline['source_before'])
        require(shutil.disk_usage(workspace).free >= native.FLOOR)
        producer = selected.earlier.regular(Path(root) / fee.DRIVER, 128 * 1024)
        report['fee_producer'] = write_raw_new(source / fee.DESTINATION, producer)
        appended = True
        before = selected.compare_source(source, root, fee_stage=True)
        require(before['combined_files'] == 549)
        input_raw, expected_raw = fee.input_bytes(root), fee.expected_bytes(root)
        input_path = workspace / 'handoffs/fee-original-input.json'
        input_pin = write_raw_new(input_path, input_raw)
        commands = workspace / 'fee-commands'
        commands.mkdir(mode=0o700)
        environment = native.selected_environment(workspace, proxy, cc, sdk)
        environment['PTLC_NOM_FEE_ORIGINAL_INPUT'] = str(input_path)
        intent = dict(schema='ptlc-nom-821bdd2-fee-stage-v1', outcome='UNKNOWN',
            core_commit=selected.CORE, core_tree=selected.TREE,
            reference_fixture_core=fee.CORE, reference_fixture_tree=fee.TREE,
            reference_input=input_pin,
            reference_expected=dict(bytes=len(expected_raw),sha256=selected.sha(expected_raw)),
            source_before=before, source_stage=2, compiler_workspace='SAME_LIVE_INVOCATION',
            test_result_cache='DISABLED_BY_COUNT_ONE', normal_default_vet=True,
            automatic_retry=False, commands={}, new_keys=0, new_signatures=0,
            journal_source_upgrade='NOT_SELECTED', original_replacement='NOT_SELECTED',
            application='NO-GO', core='NO-GO', recovery_action='NONE',
            independent_assessment='UNFILLED')
        native.write_new(workspace / 'fee-native-intent.json', intent)

        def command(label, arguments):
            remaining = native.TOTAL_SECONDS - (time.monotonic() - started)
            require(remaining > 0 and shutil.disk_usage(workspace).free >= native.FLOOR)
            receipt = capture.run([str(go), *arguments], environment=environment,
                directory=source, evidence=commands, label=label,
                timeout=min(1200, remaining))
            require(receipt['actual_exit'] == 0
                and receipt['result'] == 'RETURNED_ZERO_WITH_COMPLETE_STREAMS'
                and receipt['complete'] == {'stdout':True,'stderr':True}
                and receipt['cleanup_complete'] is True)
            intent['commands'][label] = {key: receipt[key] for key in (
                'actual_exit','result','bytes','complete','sha256','elapsed_seconds')}
            return receipt

        receipt = command('fee-original-boundary', ['test','-json','-p','2',
            '-mod=readonly','-count=1','-run','^'+fee.PARENT+'$','./vm'])
        stdout = native.original(commands, 'fee-original-boundary', 'stdout', receipt)
        stderr = native.original(commands, 'fee-original-boundary', 'stderr', receipt)
        require(stderr == b'')
        comparison = fee.read(stdout, input_raw, expected_raw)
        require(comparison['cases'] == 14
            and comparison['outcomes_including_parent'] == 15
            and comparison['earlier_fee_refusals'] == 6
            and comparison['later_hash_refusals'] == comparison['later_signature_refusals'] == 4)
        command('fee-module-verify', ['mod','verify'])
        after = selected.compare_source(source, root, fee_stage=True)
        require(after == before
            and selected.sha(selected.earlier.regular(go, 64 * 1024**2)) == expected_go
            and selected.sha(selected.earlier.regular(cc, 256 * 1024**2)) == baseline['cc_sha256'])
        originals_unchanged(workspace, frozen)
        intent.update(outcome='PASS_FRESH_NATIVE_FEE_ORIGINAL_REFUSALS_ONLY',
            source_after=after, source_unchanged=True,
            comparison=native.write_new(workspace / 'fee-value-comparison.json', comparison),
            actual_native_commands=2, actual_cases=14, outcomes_including_parent=15,
            baseline_originals_unchanged=True,
            elapsed_seconds=round(time.monotonic()-started, 6))
        native.write_new(workspace / 'fee-native-result.json', intent)
        report.update(outcome='PASS_TWO_FRESH_OFFLINE_NATIVE_STAGES_ONLY',
            baseline_source=baseline['source_before'], fee_source=after,
            baseline_profiles=36, fee_profiles=1, complete_profiles=37,
            baseline_native_commands=40, fee_native_commands=2, actual_native_commands=42,
            reference_outcomes=642, prior_runtime_outcomes=58,
            upstream_test_outcomes=67, fee_outcomes=15, total_outcomes=782,
            baseline_originals_unchanged=True, source_extractions_performed_by_runner=0,
            baseline_result_reused=False, historical_cache_adopted=False,
            elapsed_seconds=round(time.monotonic()-started, 6))
        native.write_new(workspace / 'bundle-native-result.json', report)
        return report
    except BaseException as failure:
        report.update(outcome='FAILURE_OR_INCOMPLETE_PRESERVED',
            exception_type=type(failure).__name__, fee_producer_appended=appended,
            elapsed_seconds=round(time.monotonic()-started, 6))
        native.write_new(workspace / 'bundle-native-failure.json', report)
        raise


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('selected two-stage native qualification refused')
    parser = QuietParser(description=__doc__)
    for name in ('source','workspace','go','offline-proxy','cc'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--sdk-root', type=Path)
    parser.add_argument('--expect-go-sha256', required=True)
    try:
        args = parser.parse_args()
        report = qualify(args.source, args.workspace, args.go,
            args.expect_go_sha256, args.offline_proxy, args.cc, sdk=args.sdk_root)
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RuntimeError):
        print('REFUSED: two-stage qualification; preserve original owned evidence',file=sys.stderr)
        return 1
    print(json.dumps({key:report[key] for key in ('outcome','core_commit','core_tree',
        'compiler_workspaces','physical_source_views','source_stages',
        'complete_profiles','actual_native_commands','total_outcomes',
        'baseline_originals_unchanged')},sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
