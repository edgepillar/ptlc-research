"""Candidate routing, original custody and failure controls; no Go execution."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from qualification import nom_dev_18c048a as selected
from qualification import nom_fee_original_boundary as fee
from scripts import nom_18c048a_command as capture
from scripts import prepare_nom_18c048a as preparation
from scripts import qualify_nom_18c048a_native as native
from scripts import qualify_nom_18c048a_bundle as bundle
from scripts import check_nom_18c048a_evidence as retention

ROOT = Path(__file__).resolve().parents[1]
REFUSALS = (ValueError, AssertionError, KeyError, TypeError)


def frames(unit):
    spec = selected.UPSTREAM[unit]
    package = 'github.com/zenon-network/go-zenon/' + spec['package']
    events = [dict(Action='start', Package=package)]
    for parent in sorted(spec['parents']):
        events.append(dict(Action='run', Package=package, Test=parent))
        for name in sorted(name for name in selected.identities(unit)
                           if name.startswith(parent + '/')):
            events.extend([dict(Action='run', Package=package, Test=name),
                           dict(Action='pass', Package=package, Test=name)])
        events.append(dict(Action='pass', Package=package, Test=parent))
    events.append(dict(Action='pass', Package=package))
    return b'\n'.join(json.dumps(row).encode('ascii') for row in events) + b'\n'


class CandidateReferenceControls(unittest.TestCase):
    def test_all_36_prior_profiles_and_labels_are_preserved(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No process permitted')):
            plan = selected.plan()
            previous = selected.prior.plan()
            description, index = selected.inputs()
        self.assertEqual(plan['units'][:36], previous['units'])
        self.assertEqual({name: plan['producers'][name] for name in previous['producers']}, previous['producers'])
        self.assertEqual(set(plan['producers']) - set(previous['producers']), set(selected.PRODUCERS))
        self.assertEqual(len(plan['units']), 41)
        self.assertEqual(len(index), 525)
        self.assertEqual(plan['last_qualified_behavior_core'], selected.prior.prior.CORE)
        self.assertNotEqual(plan['core_commit'], plan['last_qualified_behavior_core'])
        self.assertEqual(description['native_compatibility'], 'UNFILLED')
        self.assertEqual(description['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual((description['application'], description['core']), ('NO-GO', 'NO-GO'))
        for row in plan['units']:
            self.assertIn('-count=1', row['arguments'])
            self.assertNotIn('-vet=off', row['arguments'])
        self.assertEqual(len(retention.expected_arguments()), 45)
        self.assertEqual(len(capture.LABELS), 47)

    def test_two_source_stages_keep_exact_original_fee_producer(self):
        base = selected.source_payloads()
        later = selected.source_payloads(fee_stage=True)
        self.assertEqual((len(base), len(later)), (552, 553))
        self.assertEqual(set(later) - set(base), {fee.DESTINATION})
        self.assertEqual({name: later[name] for name in base}, base)
        self.assertEqual(later[fee.DESTINATION], selected.sha((ROOT / fee.DRIVER).read_bytes()))
        old = selected.prior.source_payloads(fee_stage=True)
        self.assertEqual(old[fee.DESTINATION], later[fee.DESTINATION])

    def test_frozen_plan_refuses_changed_subject_types_and_missing_profiles(self):
        original = selected.execution_plan()
        self.assertEqual(selected.frozen_plan(), original)
        self.assertEqual(original['planned_native_commands'], 47)
        for mutation in ('core', 'boolean-workspaces', 'missing-profile', 'historical-cache'):
            changed = json.loads(json.dumps(original))
            if mutation == 'core':
                changed['core_commit'] = selected.prior.CORE
            elif mutation == 'boolean-workspaces':
                changed['required_new_compiler_workspaces'] = True
            elif mutation == 'missing-profile':
                changed['baseline']['units'].pop()
            else:
                changed['compiler_cache'] = 'REUSE HISTORICAL CACHE'
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / selected.PLAN
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(changed), encoding='ascii')
                with mock.patch.object(selected, 'execution_plan', return_value=original), \
                        self.assertRaises(REFUSALS):
                    selected.frozen_plan(root)

    def test_fifteen_added_parents_and_sixteen_children_are_required(self):
        self.assertEqual(sum(len(spec['parents'])
            for spec in selected.ADDED_UPSTREAM.values()), 15)
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No process permitted')):
            for unit, outcomes in [('upstream-db-tombstones', 6),
                    ('upstream-definition-tombstones', 3), ('upstream-protocol-shutdown', 2),
                    ('research-storage-composition', 11), ('research-collection-boundaries', 9)]:
                result = selected.read_upstream(unit, frames(unit), b'')
                self.assertEqual(result['parent_and_child_outcomes'], outcomes)
                self.assertEqual(result['native_execution_origin'], 'NOT_ESTABLISHED_BY_DATA_READER')

    def test_missing_failed_skipped_duplicate_foreign_and_authority_events_refuse(self):
        original = [json.loads(line) for line in frames('research-collection-boundaries').splitlines()]
        child = 'TestPTLCResearchCollectionIteratorErrors/sentinel_get_all'
        for action in ('missing', 'fail', 'skip', 'duplicate', 'foreign', 'authority', 'package'):
            events = [dict(row) for row in original]
            chosen = next(row for row in events if row.get('Test') == child and row['Action'] == 'pass')
            if action == 'missing':
                events = [row for row in events if row.get('Test') != child]
            elif action == 'duplicate':
                events.insert(-1, dict(chosen))
            elif action == 'foreign':
                chosen['Test'] += '_foreign'
            elif action == 'authority':
                chosen['source_authenticated'] = True
            elif action == 'package':
                chosen['Package'] = 'synthetic/foreign'
            else:
                chosen['Action'] = action
            raw = b'\n'.join(json.dumps(row).encode('ascii') for row in events) + b'\n'
            with self.subTest(action=action), self.assertRaises(REFUSALS):
                selected.read_upstream('research-collection-boundaries', raw, b'')
        with self.assertRaises(REFUSALS):
            selected.read_upstream('upstream-per-entity', frames('upstream-per-entity'), b'diagnostic')

    def test_reference_bytes_are_delegated_without_source_relabeling(self):
        original = {unit + suffix: b'original reference stream'
            for unit in selected.reference.units() for suffix in ('.stdout', '.stderr')}
        payloads = dict(original)
        for unit in selected.UPSTREAM:
            payloads[unit + '.stdout'], payloads[unit + '.stderr'] = frames(unit), b''
        fixture = dict(core_commit=selected.FIXTURE_CORE, marker='synthetic reference comparison')
        with mock.patch.object(selected.reference, 'compare_payloads', return_value=fixture) as reader:
            result = selected.compare_payloads(payloads)
        self.assertEqual(reader.call_args.args[0], original)
        self.assertEqual(result['reference'], fixture)
        self.assertEqual(result['core_commit'], selected.CORE)
        self.assertEqual(result['reference']['core_commit'], selected.FIXTURE_CORE)
        self.assertEqual(len(result['upstream']), 10)
        self.assertEqual(result['upstream_outcomes'], 98)
        self.assertIs(result['original_streams_rewritten'], False)
        self.assertEqual(result['execution_origin'], 'NOT_ESTABLISHED_BY_READER')


class CandidatePreparationControls(unittest.TestCase):
    def fixture(self, mutation=None):
        raw = b'package synthetic\n'
        index = {'selected.go': dict(bytes=len(raw), sha256=selected.sha(raw),
            git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())}
        archive = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(archive, 'w') as output:
                name = preparation.ARCHIVE_PREFIX + '/selected.go'
                if mutation == 'traversal':
                    name = preparation.ARCHIVE_PREFIX + '/../selected.go'
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFLNK if mutation == 'link' else stat.S_IFREG) << 16
                output.writestr(info, b'changed' if mutation == 'bytes' else raw)
                if mutation == 'duplicate':
                    output.writestr(info, raw)
        archive.seek(0)
        return archive, index, raw

    def test_member_bytes_links_traversal_and_duplicates_are_checked_before_writes(self):
        archive, index, raw = self.fixture()
        with zipfile.ZipFile(archive) as source:
            self.assertEqual(preparation.checked_payloads(source, index), {'selected.go': raw})
        for mutation in ('traversal', 'link', 'bytes', 'duplicate'):
            archive, index, unused = self.fixture(mutation)
            with self.subTest(mutation=mutation), zipfile.ZipFile(archive) as source, \
                    self.assertRaises(REFUSALS):
                preparation.checked_payloads(source, index)

    def test_wrong_archive_refuses_without_a_source_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            archive = directory / 'wrong.zip'
            archive.write_bytes(b'synthetic wrong original')
            destination = directory / 'source'
            with self.assertRaises(REFUSALS):
                preparation.prepare(archive, destination)
            self.assertFalse(destination.exists())


class CandidateProcessControls(unittest.TestCase):
    def test_added_command_keeps_actual_exit_and_failed_original_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with self.assertRaises(capture.WorkerError):
                capture.run([sys.executable, '-c', 'print("synthetic failure"); raise SystemExit(3)'],
                    environment={'PATH': os.defpath}, directory=directory, evidence=directory,
                    label='upstream-final-tally', timeout=5)
            receipt = json.loads((directory / 'upstream-final-tally.receipt.json').read_bytes())
            self.assertEqual(receipt['actual_exit'], 3)
            self.assertEqual(receipt['result'], 'FAILURE_OR_INCOMPLETE')
            self.assertIs(receipt['automatic_retry'], False)
            self.assertEqual((directory / 'upstream-final-tally.stdout').read_bytes(), b'synthetic failure\n')
            with self.assertRaises(capture.WorkerError):
                capture.run([sys.executable, '-c', 'print("replacement")'],
                    environment={'PATH': os.defpath}, directory=directory, evidence=directory,
                    label='upstream-final-tally', timeout=5)
            self.assertEqual((directory / 'upstream-final-tally.stdout').read_bytes(), b'synthetic failure\n')

    def test_historical_cache_refuses_before_native_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            paths = {key: directory / key for key in ('source', 'workspace', 'proxy', 'go', 'cc')}
            for key in ('source', 'workspace', 'proxy'):
                paths[key].mkdir(mode=0o700)
            for key in ('go', 'cc'):
                paths[key].write_bytes(('synthetic ' + key).encode('ascii'))
                paths[key].chmod(0o700)
            (paths['workspace'] / 'old-cache').write_bytes(b'do not adopt')
            with mock.patch.object(selected, 'compare_source', return_value={'combined_files': 552}), \
                    mock.patch.object(capture, 'run', side_effect=AssertionError('No native launch')) as runner:
                with self.assertRaises(REFUSALS):
                    native.qualify(paths['source'], paths['workspace'], paths['go'],
                        selected.sha(paths['go'].read_bytes()), paths['proxy'], paths['cc'])
            runner.assert_not_called()
            self.assertFalse((paths['workspace'] / 'native-intent.json').exists())

    def test_fee_stage_uses_live_cache_and_refuses_changed_baseline_originals(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                paths = {key: root / key for key in ('source', 'workspace', 'proxy', 'go', 'cc')}
                for key in ('source', 'workspace', 'proxy'):
                    paths[key].mkdir(mode=0o700)
                (paths['source'] / 'vm').mkdir(mode=0o700)
                for key in ('go', 'cc'):
                    paths[key].write_bytes(('synthetic ' + key).encode('ascii'))
                    paths[key].chmod(0o700)
                workspace, source = paths['workspace'], paths['source']
                labels = sorted(retention.expected_arguments())
                calls = []
                before = dict(combined_files=552, marker='candidate baseline')
                after = dict(combined_files=553, marker='candidate fee stage')
                watched = 'commands/' + labels[0] + '.stdout'
                manifest = dict(full_attempt=True, outcome='PASS_PRIVACY_AND_ORIGINAL_SELECTION_ONLY',
                    commands={label: {} for label in labels},
                    files={'native-result.json': {}, watched: {}})

                def baseline(*args, **kwargs):
                    self.assertEqual(list(workspace.iterdir()), [])
                    for name in ('build', 'commands', 'handoffs'):
                        (workspace / name).mkdir(mode=0o700)
                    (workspace / 'build/live-marker').write_bytes(b'same invocation')
                    (workspace / 'native-intent.json').write_bytes(b'{}')
                    (workspace / 'native-result.json').write_bytes(b'{"synthetic":true}')
                    (workspace / watched).write_bytes(b'original baseline bytes')
                    for label in labels:
                        (workspace / ('commands/' + label + '.receipt.json')).write_bytes(b'{}')
                    calls.append('fresh-baseline')
                    return dict(complete_profiles=41, actual_native_commands=45,
                        source_before=before, cc_sha256=selected.sha(paths['cc'].read_bytes()))

                def source_check(*args, **kwargs):
                    appended = (source / fee.DESTINATION).exists()
                    self.assertEqual(appended, kwargs.get('fee_stage', False))
                    return after if appended else before

                def command(argv, *, environment, directory, evidence, label, timeout):
                    self.assertEqual(environment['GOCACHE'], str(workspace / 'build'))
                    self.assertEqual((workspace / 'build/live-marker').read_bytes(), b'same invocation')
                    self.assertTrue((workspace / 'base-stage-retention.json').is_file())
                    self.assertEqual((source / fee.DESTINATION).read_bytes(), (ROOT / fee.DRIVER).read_bytes())
                    calls.append(label)
                    if corrupt and label == 'fee-module-verify':
                        (workspace / watched).write_bytes(b'changed baseline bytes')
                    values = dict(stdout=b'synthetic fee stream', stderr=b'')
                    for kind, raw in values.items():
                        (evidence / (label + '.' + kind)).write_bytes(raw)
                    return dict(actual_exit=0, result='RETURNED_ZERO_WITH_COMPLETE_STREAMS',
                        bytes={key: len(raw) for key, raw in values.items()},
                        complete=dict(stdout=True, stderr=True), cleanup_complete=True,
                        sha256={key: selected.sha(raw) for key, raw in values.items()}, elapsed_seconds=0.01)

                comparison = dict(cases=14, outcomes_including_parent=15,
                    earlier_fee_refusals=6, later_hash_refusals=4, later_signature_refusals=4)
                with mock.patch.object(native, 'qualify', side_effect=baseline), \
                        mock.patch.object(bundle.baseline_checker, 'inspect', return_value=manifest), \
                        mock.patch.object(selected, 'compare_source', side_effect=source_check), \
                        mock.patch.object(capture, 'run', side_effect=command), \
                        mock.patch.object(fee, 'read', return_value=comparison):
                    arguments = (source, workspace, paths['go'], selected.sha(paths['go'].read_bytes()),
                                 paths['proxy'], paths['cc'])
                    if corrupt:
                        with self.assertRaises(REFUSALS):
                            bundle.qualify(*arguments)
                        self.assertTrue((workspace / 'bundle-native-failure.json').is_file())
                        self.assertFalse((workspace / 'bundle-native-result.json').exists())
                    else:
                        result = bundle.qualify(*arguments)
                        self.assertEqual(result['complete_profiles'], 42)
                        self.assertEqual(result['actual_native_commands'], 47)
                        self.assertEqual(result['total_outcomes'], 813)
                        self.assertIs(result['historical_cache_adopted'], False)
                        self.assertIs(result['baseline_result_reused'], False)
                        self.assertIs(result['baseline_originals_unchanged'], True)
                self.assertEqual(calls, ['fresh-baseline', 'fee-original-boundary', 'fee-module-verify'])
                self.assertEqual((workspace / 'native-result.json').read_bytes(), b'{"synthetic":true}')


def package_frames(required):
    rows = []
    for package, parents in sorted(required.items()):
        rows.append(dict(Action='start', Package=package))
        for parent in sorted(parents):
            rows.extend([dict(Action='run', Package=package, Test=parent),
                dict(Action='pass', Package=package, Test=parent)])
        rows.append(dict(Action='pass', Package=package))
    return b'\n'.join(json.dumps(row).encode('ascii') for row in rows) + b'\n'


class PackageSelectionControls(unittest.TestCase):
    def test_definition_roots_are_disjoint_and_complete_for_the_pinned_inventory(self):
        plan = selected.execution_plan()
        roots = set(selected.DEFINITION_COMPLEMENT)
        for unit in ('upstream-per-entity', 'upstream-definition-tombstones',
                'research-collection-boundaries'):
            chosen = set(selected.UPSTREAM[unit]['parents'])
            self.assertFalse(roots & chosen)
            roots.update(chosen)
        self.assertEqual(len(roots), 24)
        self.assertEqual(plan['separate_package_regression']['overlap_with_profile_roots'], 0)
        self.assertEqual(retention.expected_arguments()['upstream-definition'], selected.definition_arguments())
        self.assertIn('-run', selected.definition_arguments())

    def test_cold_packages_and_slash_labelled_parallel_child_have_exact_framing(self):
        required = {'synthetic/pkg': {'TestSelected'}}
        rows = [dict(Action='start', Package='synthetic/pkg')]
        for action, name in (('run', 'TestSelected'), ('run', 'TestSelected/a/b'),
                ('pause', 'TestSelected/a/b'), ('cont', 'TestSelected/a/b'),
                ('pass', 'TestSelected/a/b'), ('pass', 'TestSelected')):
            rows.append(dict(Action=action, Package='synthetic/pkg', Test=name))
        rows.append(dict(Action='pass', Package='synthetic/pkg'))
        raw = b'\n'.join(json.dumps(row).encode('ascii') for row in rows) + b'\n'
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No process permitted')):
            value = selected.package_events(raw, required)
            cold = selected.package_events(package_frames({'synthetic/a': set(), 'synthetic/b': set()}),
                {'synthetic/a': set(), 'synthetic/b': set()})
        self.assertEqual(value['observed_parent_and_child_outcomes'], 2)
        self.assertEqual(cold['packages'], 2)
        self.assertEqual(cold['observed_parent_and_child_outcomes'], 0)

    def test_package_fail_skip_duplicate_missing_foreign_and_bad_scalar_refuse(self):
        required = {'synthetic/pkg': {'TestSelected'}}
        original = [json.loads(row) for row in package_frames(required).splitlines()]
        for mutation in ('fail', 'skip', 'duplicate', 'missing', 'foreign', 'root', 'field', 'boolean'):
            rows = [dict(row) for row in original]
            if mutation in ('fail', 'skip'):
                rows[2]['Action'] = mutation
            elif mutation == 'duplicate':
                rows.insert(3, dict(rows[2]))
            elif mutation == 'missing':
                rows.pop()
            elif mutation == 'foreign':
                rows[1]['Package'] = 'synthetic/foreign'
            elif mutation == 'root':
                rows[1]['Test'] = 'TestForeign'
            elif mutation == 'field':
                rows[2]['source_authenticated'] = True
            else:
                rows[2]['Elapsed'] = True
            raw = b'\n'.join(json.dumps(row).encode('ascii') for row in rows) + b'\n'
            with self.subTest(mutation=mutation), self.assertRaises(REFUSALS):
                selected.package_events(raw, required)


class OriginalRetentionControls(unittest.TestCase):
    def fixture(self, directory, corrupt_complement=False, cold_stderr=b''):
        """Mock command stages only; original receipts and data readers are real."""
        paths = {key: directory / key for key in ('source', 'workspace', 'proxy', 'go', 'cc')}
        for key in ('source', 'workspace', 'proxy'):
            paths[key].mkdir(mode=0o700)
        for key in ('go', 'cc'):
            paths[key].write_bytes(('synthetic ' + key).encode('ascii'))
            paths[key].chmod(0o700)
        values = selected.source_payloads()
        before = dict(core_commit=selected.CORE, core_tree=selected.TREE, profile='all',
            upstream_files=525, project_producers=27, combined_files=552,
            snapshot=dict(files=552, sha256=selected.sha(json.dumps(values, sort_keys=True).encode('ascii'))),
            reference_fixture_core=selected.FIXTURE_CORE,
            content='EXACT_SELECTED_CONTENTS; UNCHANGED_REFERENCE_AND_NEW_BOUNDARY_PRODUCERS',
            filesystem_mode_equality='NOT_ASSERTED', producer_authentication='NOT_ESTABLISHED_BY_READER')
        arguments = retention.expected_arguments()
        packages = {'github.com/zenon-network/go-zenon/' + row['package']: set()
            for row in selected.plan()['units']}
        complement = {'github.com/zenon-network/go-zenon/vm/embedded/definition':
            set(selected.DEFINITION_COMPLEMENT)}
        comparison = dict(outcome='PASS_SELECTED_FINITE_VALUES_ONLY', synthetic=True)

        def command(argv, *, environment, directory, evidence, label, timeout):
            self.assertEqual(argv[1:], arguments[label])
            if label == 'go-version':
                platform = {'linux': 'linux/amd64', 'darwin': 'darwin/arm64'}[sys.platform]
                stdout = ('go version go1.23.12 ' + platform + '\n').encode('ascii')
            elif label == 'cold-build':
                stdout = package_frames(packages)
            elif label == 'upstream-definition':
                stdout = package_frames(complement)
                if corrupt_complement:
                    stdout = b'\n'.join(stdout.splitlines()[:-1]) + b'\n'
            else:
                stdout = b'synthetic finite stream\n'
            streams = dict(stdout=stdout, stderr=cold_stderr if label == 'cold-build' else b'')
            receipt = dict(schema='ptlc-nom-18c048a-native-command-v1', label=label,
                argv=argv, actual_exit=0, result='RETURNED_ZERO_WITH_COMPLETE_STREAMS',
                bytes={key: len(raw) for key, raw in streams.items()},
                complete=dict(stdout=True, stderr=True), cleanup_complete=True,
                sha256={key: selected.sha(raw) for key, raw in streams.items()},
                elapsed_seconds=0.01, automatic_retry=False)
            for key, raw in streams.items():
                (evidence / (label + '.' + key)).write_bytes(raw)
            (evidence / (label + '.receipt.json')).write_text(json.dumps(receipt), encoding='ascii')
            return receipt

        with mock.patch.object(selected, 'compare_source', return_value=before), \
                mock.patch.object(native, 'bindings', return_value={}), \
                mock.patch.object(capture, 'run', side_effect=command), \
                mock.patch.object(selected, 'compare_payloads', return_value=comparison):
            native.qualify(paths['source'], paths['workspace'], paths['go'],
                selected.sha(paths['go'].read_bytes()), paths['proxy'], paths['cc'])
        return paths['workspace'], comparison

    def test_selected_originals_include_fresh_cold_and_complement_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, comparison = self.fixture(Path(temporary).resolve())
            with mock.patch.object(selected, 'compare_payloads', return_value=comparison):
                result = retention.inspect(workspace)
            self.assertIs(result['full_attempt'], True)
            self.assertEqual(len(result['commands']), 45)
            self.assertEqual(result['original_profile_streams'], 82)
            self.assertEqual(len(result['files']), 92)
            self.assertNotIn('commands/go-version.receipt.json', result['files'])

    def test_cold_file_proxy_progress_is_retained_without_becoming_test_output(self):
        progress = b'go: downloading github.com/pkg/errors v0.9.1\n'
        with tempfile.TemporaryDirectory() as temporary:
            workspace, comparison = self.fixture(Path(temporary).resolve(), cold_stderr=progress)
            with mock.patch.object(selected, 'compare_payloads', return_value=comparison):
                result = retention.inspect(workspace)
            self.assertTrue(result['full_attempt'])
            self.assertEqual((workspace / 'commands/cold-build.stderr').read_bytes(), progress)
            self.assertEqual(result['files']['commands/cold-build.stderr'],
                dict(bytes=len(progress), sha256=selected.sha(progress)))
            report = json.loads((workspace / 'native-result.json').read_bytes())
            self.assertEqual(report['cold_build']['observed_parent_and_child_outcomes'], 0)
            self.assertEqual(report['actual_native_commands'], 45)
            # Repair synthetic receipt hashes too: rejection must still reach
            # the privacy gate, rather than merely detect a stale digest.
            unsafe = b'go: synthetic diagnostic /' + b'private' + b'/synthetic\n'
            (workspace / 'commands/cold-build.stderr').write_bytes(unsafe)
            receipt_path = workspace / 'commands/cold-build.receipt.json'
            receipt = json.loads(receipt_path.read_bytes())
            for value in (receipt, report['commands']['cold-build']):
                value['bytes']['stderr'] = len(unsafe)
                value['sha256']['stderr'] = selected.sha(unsafe)
            receipt_path.write_text(json.dumps(receipt), encoding='ascii')
            (workspace / 'native-result.json').write_text(json.dumps(report), encoding='ascii')
            with mock.patch.object(selected, 'compare_payloads', return_value=comparison), \
                    self.assertRaises(REFUSALS):
                retention.inspect(workspace)

    def test_boolean_float_source_counts_and_omitted_complement_do_not_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace, comparison = self.fixture(Path(temporary).resolve())
            path = workspace / 'native-result.json'
            original = json.loads(path.read_bytes())
            for mutation in ('boolean-workspaces', 'float-count', 'float-source', 'missing-complement', 'old-core'):
                changed = json.loads(json.dumps(original))
                if mutation == 'boolean-workspaces':
                    changed['compiler_workspaces'] = True
                elif mutation == 'float-count':
                    changed['actual_native_commands'] = 45.0
                elif mutation == 'float-source':
                    changed['source_before']['combined_files'] = 552.0
                elif mutation == 'missing-complement':
                    changed.pop('definition_complement')
                else:
                    changed['core_commit'] = selected.prior.CORE
                path.write_text(json.dumps(changed), encoding='ascii')
                with self.subTest(mutation=mutation), \
                        mock.patch.object(selected, 'compare_payloads', return_value=comparison), \
                        self.assertRaises(REFUSALS):
                    retention.inspect(workspace)

    def test_incomplete_complement_preserves_failure_instead_of_a_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            with self.assertRaises(REFUSALS):
                self.fixture(directory, corrupt_complement=True)
            workspace = directory / 'workspace'
            self.assertFalse((workspace / 'native-result.json').exists())
            value = json.loads((workspace / 'native-failure.json').read_bytes())
            self.assertEqual(value['outcome'], 'FAILURE_OR_INCOMPLETE_PRESERVED')
            self.assertFalse(value['automatic_native_retry'])
            self.assertTrue((workspace / 'commands/upstream-definition.stdout').is_file())


if __name__ == '__main__':
    unittest.main()
