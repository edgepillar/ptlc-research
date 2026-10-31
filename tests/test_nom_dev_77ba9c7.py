"""Synthetic routing and failure controls; these execute no Go compiler or node."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from qualification import nom_dev_77ba9c7 as selected
from qualification import nom_fee_original_boundary as fee
from scripts import nom_77ba9c7_command as capture
from scripts import qualify_nom_77ba9c7_native as native
from scripts import qualify_nom_77ba9c7_bundle as bundle
from scripts import qualify_nom_821bdd2_bundle as candidate_bundle

ROOT = Path(__file__).resolve().parents[1]
REFUSALS = (ValueError, AssertionError, KeyError, TypeError)


def frames(unit):
    spec = selected.UPSTREAM[unit]
    package = 'github.com/zenon-network/go-zenon/' + spec['package']
    events = [dict(Action='start', Package=package)]
    for parent in sorted(spec['parents']):
        events.append(dict(Action='run', Package=package, Test=parent))
        for name in sorted(n for n in selected.identities(unit) if n.startswith(parent + '/')):
            events.extend([dict(Action='run', Package=package, Test=name),
                           dict(Action='pass', Package=package, Test=name)])
        events.append(dict(Action='pass', Package=package, Test=parent))
    events.append(dict(Action='pass', Package=package))
    return b'\n'.join(json.dumps(row, sort_keys=True).encode('ascii') for row in events) + b'\n'


class CurrentReferenceControls(unittest.TestCase):
    def test_compiled_source_and_embedded_reference_labels_are_separate(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No process permitted')):
            description, index = selected.inputs()
        self.assertEqual(len(index), 521)
        self.assertNotEqual(description['core_commit'], description['reference_fixture_core'])
        self.assertEqual(description['native_compatibility'], 'UNFILLED')
        self.assertEqual(description['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(description['core'], 'NO-GO')

    def test_plan_keeps_all_previous_profiles_and_count_one_default_vet(self):
        plan = selected.plan()
        prior = selected.reference.plan()
        self.assertEqual(plan['units'][:len(prior['units'])], prior['units'])
        self.assertEqual(plan['producers'], prior['producers'])
        self.assertEqual(len(plan['units']), 34)
        self.assertEqual(sum(len(row['parents']) for row in selected.UPSTREAM.values()), 17)
        self.assertEqual(sum(len(selected.identities(unit)) for unit in selected.UPSTREAM), 41)
        for row in plan['units']:
            self.assertIn('-count=1', row['arguments'])
            self.assertNotIn('-vet=off', row['arguments'])

    def test_fee_stage_adds_exactly_one_unchanged_producer(self):
        base = selected.source_payloads()
        later = selected.source_payloads(fee_stage=True)
        self.assertEqual((len(base), len(later)), (546, 547))
        self.assertEqual(set(later) - set(base), {fee.DESTINATION})
        self.assertEqual({name: later[name] for name in base}, base)
        self.assertEqual(later[fee.DESTINATION], selected.sha((ROOT / fee.DRIVER).read_bytes()))

    def test_manufactured_upstream_streams_establish_no_native_origin(self):
        for unit in selected.UPSTREAM:
            result = selected.read_upstream(unit, frames(unit), b'')
            self.assertEqual(result['parent_and_child_outcomes'], len(selected.identities(unit)))
            self.assertEqual(result['native_execution_origin'], 'NOT_ESTABLISHED_BY_DATA_READER')

    def test_missing_failed_skipped_and_unselected_upstream_events_refuse(self):
        unit = 'upstream-guardians'
        original = [json.loads(line) for line in frames(unit).splitlines()]
        chosen = next(row['Test'] for row in original if '/' in row.get('Test', ''))
        for action in ('missing', 'fail', 'skip', 'foreign'):
            events = [dict(row) for row in original]
            if action == 'missing':
                events = [row for row in events if row.get('Test') != chosen]
            else:
                row = next(row for row in events if row.get('Test') == chosen and row['Action'] == 'pass')
                if action == 'foreign':
                    row['Test'] += '_unselected'
                else:
                    row['Action'] = action
            raw = b'\n'.join(json.dumps(row).encode('ascii') for row in events) + b'\n'
            with self.subTest(action=action), self.assertRaises(REFUSALS):
                selected.read_upstream(unit, raw, b'')

    def test_upstream_diagnostics_and_authority_fields_refuse(self):
        unit = 'upstream-bridge-json'
        with self.assertRaises(REFUSALS):
            selected.read_upstream(unit, frames(unit), b'unselected diagnostic')
        events = [json.loads(line) for line in frames(unit).splitlines()]
        events[0]['source_authenticated'] = True
        with self.assertRaises(REFUSALS):
            selected.read_upstream(unit, b'\n'.join(json.dumps(row).encode()
                for row in events) + b'\n', b'')

    def test_reference_streams_are_delegated_without_relabeling(self):
        original = {unit + suffix: b'unchanged reference bytes'
            for unit in selected.reference.units() for suffix in ('.stdout', '.stderr')}
        payloads = dict(original)
        for unit in selected.UPSTREAM:
            payloads[unit + '.stdout'], payloads[unit + '.stderr'] = frames(unit), b''
        reference = dict(core_commit=selected.FIXTURE_CORE, marker='synthetic reference result')
        with mock.patch.object(selected.reference, 'compare_payloads', return_value=reference) as reader:
            result = selected.compare_payloads(payloads)
        self.assertEqual(reader.call_args.args[0], original)
        self.assertEqual(result['reference'], reference)
        self.assertEqual(result['reference']['core_commit'], selected.FIXTURE_CORE)
        self.assertEqual(result['core_commit'], selected.CORE)
        self.assertIs(result['original_streams_rewritten'], False)
        self.assertEqual(result['execution_origin'], 'NOT_ESTABLISHED_BY_READER')


class CurrentCommandControls(unittest.TestCase):
    def test_selected_label_retains_actual_synthetic_process_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            result = capture.run([sys.executable, '-c', 'print("synthetic stream")'],
                environment={'PATH': os.defpath}, directory=directory, evidence=directory,
                label='upstream-bridge-json', timeout=5)
            self.assertEqual(result['actual_exit'], 0)
            self.assertEqual((directory / 'upstream-bridge-json.stdout').read_bytes(), b'synthetic stream\n')
            self.assertIs(result['automatic_retry'], False)
            self.assertEqual(result['complete'], {'stdout': True, 'stderr': True})

    def test_deadline_keeps_failed_originals_and_never_returns_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with self.assertRaises(capture.WorkerError):
                capture.run([sys.executable, '-c', 'import time; time.sleep(5)'],
                    environment={'PATH': os.defpath}, directory=directory, evidence=directory,
                    label='fee-original-boundary', timeout=0.05)
            receipt = json.loads((directory / 'fee-original-boundary.receipt.json').read_bytes())
            self.assertEqual(receipt['failure'], 'DEADLINE_EXCEEDED')
            self.assertNotEqual(receipt['result'], 'RETURNED_ZERO_WITH_COMPLETE_STREAMS')
            self.assertIs(receipt['automatic_retry'], False)

    def test_unselected_label_refuses_before_creating_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with self.assertRaises(capture.WorkerError):
                capture.run([sys.executable, '-c', 'print("unused")'],
                    environment={'PATH': os.defpath}, directory=directory, evidence=directory,
                    label='unselected-native-action', timeout=5)
            self.assertEqual(list(directory.iterdir()), [])


class BundleCliControls(unittest.TestCase):
    def invoke(self, module, producer, output, errors):
        arguments = ['synthetic-bundle-cli', '--source', 'synthetic-source',
            '--workspace', 'synthetic-workspace', '--go', 'synthetic-compiler',
            '--offline-proxy', 'synthetic-proxy', '--cc', 'synthetic-cc',
            '--expect-go-sha256', '0' * 64]
        with mock.patch.object(sys, 'argv', arguments), \
                mock.patch.object(module, 'qualify', producer), \
                redirect_stdout(output), redirect_stderr(errors):
            return module.main()

    def test_worker_failure_returns_one_without_disclosing_exception_content(self):
        for module in (bundle, candidate_bundle):
            with self.subTest(module=module.__name__):
                output, errors = io.StringIO(), io.StringIO()
                producer = mock.Mock(side_effect=module.capture.WorkerError(
                    'synthetic-sensitive-diagnostic'))
                result = self.invoke(module, producer, output, errors)
                self.assertEqual(result, 1)
                producer.assert_called_once()
                self.assertEqual(output.getvalue(), '')
                self.assertEqual(errors.getvalue(),
                    'REFUSED: two-stage qualification; preserve original owned evidence\n')

    def test_interrupts_propagate_without_a_success_or_refusal_projection(self):
        for module in (bundle, candidate_bundle):
            for failure in (KeyboardInterrupt(), SystemExit(7)):
                with self.subTest(module=module.__name__, failure=type(failure).__name__):
                    output, errors = io.StringIO(), io.StringIO()
                    producer = mock.Mock(side_effect=failure)
                    with self.assertRaises(type(failure)) as raised:
                        self.invoke(module, producer, output, errors)
                    self.assertIs(raised.exception, failure)
                    producer.assert_called_once()
                    self.assertEqual(output.getvalue(), '')
                    self.assertEqual(errors.getvalue(), '')

    def test_success_keeps_only_the_existing_public_projection(self):
        for module, profiles, commands, outcomes in (
                (bundle, 35, 40, 756), (candidate_bundle, 37, 42, 782)):
            with self.subTest(module=module.__name__):
                projected = dict(outcome='SYNTHETIC_SUCCESS_PROJECTION_ONLY',
                    core_commit='11' * 20, core_tree='22' * 20,
                    compiler_workspaces=1, physical_source_views=1, source_stages=2,
                    complete_profiles=profiles, actual_native_commands=commands,
                    total_outcomes=outcomes, baseline_originals_unchanged=True)
                output, errors = io.StringIO(), io.StringIO()
                producer = mock.Mock(return_value=dict(projected,
                    unselected_detail='synthetic-unpublished-detail'))
                self.assertEqual(self.invoke(module, producer, output, errors), 0)
                producer.assert_called_once()
                self.assertEqual(json.loads(output.getvalue()), projected)
                self.assertEqual(errors.getvalue(), '')


class CurrentStageControls(unittest.TestCase):
    def fixture(self, directory):
        paths = {name: directory / name for name in ('source', 'workspace', 'proxy', 'go', 'cc')}
        for name in ('source', 'workspace', 'proxy'):
            paths[name].mkdir(mode=0o700)
        (paths['source'] / 'vm').mkdir(mode=0o700)
        for name in ('go', 'cc'):
            paths[name].write_bytes(('synthetic ' + name).encode('ascii'))
            paths[name].chmod(0o700)
        return paths

    def test_native_runner_refuses_a_preexisting_cache_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary).resolve())
            (paths['workspace'] / 'existing-cache').write_bytes(b'synthetic cache')
            with mock.patch.object(selected, 'compare_source', return_value={'combined_files': 546}), \
                    mock.patch.object(capture, 'run', side_effect=AssertionError('No launch permitted')) as runner:
                with self.assertRaises(REFUSALS):
                    native.qualify(paths['source'], paths['workspace'], paths['go'],
                        selected.sha(paths['go'].read_bytes()), paths['proxy'], paths['cc'])
            runner.assert_not_called()
            self.assertFalse((paths['workspace'] / 'native-intent.json').exists())

    def run_stage(self, paths, *, corrupt=False, fail=False):
        workspace, source = paths['workspace'], paths['source']
        labels = ['synthetic-' + str(i) for i in range(38)]
        calls = []
        before = dict(combined_files=546, reference_fixture_core=selected.FIXTURE_CORE)
        after = dict(combined_files=547, reference_fixture_core=selected.FIXTURE_CORE)

        def baseline(*args, **kwargs):
            self.assertEqual(list(workspace.iterdir()), [])
            for name in ('commands', 'handoffs', 'build'):
                (workspace / name).mkdir(mode=0o700)
            (workspace / 'build/cache-marker').write_bytes(b'same invocation')
            (workspace / 'native-intent.json').write_bytes(b'{}')
            (workspace / 'native-result.json').write_bytes(b'{"synthetic":true}')
            for label in labels:
                (workspace / 'commands' / (label + '.receipt.json')).write_bytes(b'synthetic private receipt')
            calls.append('fresh-baseline')
            return dict(complete_profiles=34, actual_native_commands=38, source_before=before,
                cc_sha256=selected.sha(paths['cc'].read_bytes()))

        def source_check(*args, **kwargs):
            appended = (source / fee.DESTINATION).exists()
            self.assertEqual(appended, kwargs.get('fee_stage', False))
            return after if appended else before

        def command(argv, *, environment, directory, evidence, label, timeout):
            self.assertEqual(environment['GOCACHE'], str(workspace / 'build'))
            self.assertEqual((workspace / 'build/cache-marker').read_bytes(), b'same invocation')
            self.assertTrue((workspace / 'base-stage-retention.json').is_file())
            self.assertEqual((source / fee.DESTINATION).read_bytes(), (ROOT / fee.DRIVER).read_bytes())
            calls.append(label)
            if fail:
                (evidence / (label + '.stdout')).write_bytes(b'synthetic interrupted original')
                raise capture.WorkerError('synthetic interruption')
            if label == 'fee-original-boundary':
                spec = importlib.util.spec_from_file_location('synthetic_fee_fixture',
                    ROOT / 'tests/test_nom_fee_original_boundary.py')
                helper = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(helper)
                value, unused, unused = helper.report()
                stdout = helper.frames(value)
            else:
                stdout = b'all modules verified\n'
            (evidence / (label + '.stdout')).write_bytes(stdout)
            (evidence / (label + '.stderr')).write_bytes(b'')
            if corrupt and label == 'fee-original-boundary':
                path = workspace / 'native-result.json'
                path.write_bytes(b'{"synthetic":"replaced"}')
            return dict(actual_exit=0, result='RETURNED_ZERO_WITH_COMPLETE_STREAMS',
                bytes={'stdout': len(stdout), 'stderr': 0},
                complete={'stdout': True, 'stderr': True},
                sha256={'stdout': selected.sha(stdout), 'stderr': selected.sha(b'')},
                elapsed_seconds=0.01, cleanup_complete=True)

        manifest = dict(full_attempt=True, outcome='PASS_PRIVACY_AND_ORIGINAL_SELECTION_ONLY',
            files={'native-result.json': dict(bytes=18, sha256='synthetic')},
            commands={label: {} for label in labels})
        with mock.patch.object(native, 'qualify', side_effect=baseline), \
                mock.patch.object(bundle.baseline_checker, 'inspect', return_value=manifest), \
                mock.patch.object(selected, 'compare_source', side_effect=source_check), \
                mock.patch.object(capture, 'run', side_effect=command):
            if corrupt or fail:
                with self.assertRaises((ValueError, capture.WorkerError)):
                    bundle.qualify(source, workspace, paths['go'],
                        selected.sha(paths['go'].read_bytes()), paths['proxy'], paths['cc'])
                self.assertTrue((workspace / 'bundle-native-failure.json').is_file())
                self.assertFalse((workspace / 'bundle-native-result.json').exists())
            else:
                result = bundle.qualify(source, workspace, paths['go'],
                    selected.sha(paths['go'].read_bytes()), paths['proxy'], paths['cc'])
                self.assertIs(result['historical_cache_adopted'], False)
                self.assertIs(result['original_streams_rewritten'], False)
        return calls

    def test_second_stage_uses_only_the_same_live_cache_after_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary).resolve())
            self.assertEqual(self.run_stage(paths),
                ['fresh-baseline', 'fee-original-boundary', 'fee-module-verify'])

    def test_changed_baseline_original_refuses_the_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary).resolve())
            self.assertEqual(self.run_stage(paths, corrupt=True),
                ['fresh-baseline', 'fee-original-boundary', 'fee-module-verify'])

    def test_fee_interruption_preserves_original_and_does_not_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary).resolve())
            self.assertEqual(self.run_stage(paths, fail=True),
                ['fresh-baseline', 'fee-original-boundary'])
            self.assertEqual((paths['workspace'] / 'fee-commands/fee-original-boundary.stdout').read_bytes(),
                b'synthetic interrupted original')


if __name__ == '__main__':
    unittest.main()
