"""Synthetic framing and file-boundary controls; no native or chain execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_dev_abi_boundary as reader

ROOT = Path(__file__).resolve().parents[1]


def encoded(events):
    return b''.join(json.dumps(row, sort_keys=True).encode('ascii') + b'\n' for row in events)


def synthetic_events(report=None, fragment=1024):
    # Manufactured success events are only parser controls, never native evidence.
    report = reader.expected_report() if report is None else report
    event = lambda action, **fields: dict(Package=reader.PACKAGE, Action=action, **fields)
    result = [event('start'), event('run', Test=reader.PARENT)]
    for name in reader.scenarios():
        result += [event('run', Test=reader.PARENT + '/' + name),
                   event('pass', Test=reader.PARENT + '/' + name, Elapsed=0.0)]
    raw = json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n'
    result += [event('output', Test=reader.PARENT, Output=raw[offset:offset + fragment])
               for offset in range(0, len(raw), fragment)]
    result += [event('pass', Test=reader.PARENT, Elapsed=0.0),
               event('output', Output='PASS\n'), event('pass', Elapsed=0.0)]
    return result


class EventTests(unittest.TestCase):
    def reject(self, events):
        with self.assertRaises(ValueError):
            reader.report_from_events(encoded(events))

    def test_complete_fragmented_synthetic_report(self):
        report, stream = reader.report_from_events(encoded(synthetic_events()))
        self.assertEqual(report, reader.expected_report())
        self.assertEqual(len(report['records']), 26)
        self.assertEqual(stream['passed_including_parent'], 27)

    def test_transport_boundaries_do_not_change_values(self):
        for size in (64, 97, 1024, 4096):
            with self.subTest(size=size):
                report, unused = reader.report_from_events(encoded(synthetic_events(fragment=size)))
                self.assertEqual(report, reader.expected_report())

    def test_missing_duplicate_and_reordered_fragments_refuse(self):
        original = synthetic_events()
        pieces = [index for index, row in enumerate(original) if row['Action'] == 'output' and row.get('Test') == reader.PARENT]
        for mode in ('missing', 'duplicate', 'reordered'):
            changed = copy.deepcopy(original)
            if mode == 'missing':
                changed.pop(pieces[1])
            elif mode == 'duplicate':
                changed.insert(pieces[0], copy.deepcopy(changed[pieces[0]]))
            else:
                changed[pieces[0]], changed[pieces[1]] = changed[pieces[1]], changed[pieces[0]]
            with self.subTest(mode=mode):
                self.reject(changed)

    def test_missing_duplicate_and_foreign_test_events_refuse(self):
        original = synthetic_events()
        for action in ('run', 'pass'):
            position = next(index for index, row in enumerate(original) if row['Action'] == action and row.get('Test') == reader.PARENT + '/unlock_offset_gap')
            for mode in ('missing', 'duplicate', 'foreign'):
                changed = copy.deepcopy(original)
                if mode == 'missing':
                    changed.pop(position)
                elif mode == 'duplicate':
                    changed.insert(position, copy.deepcopy(changed[position]))
                else:
                    changed[position]['Test'] = reader.PARENT + '/unselected'
                with self.subTest(action=action, mode=mode):
                    self.reject(changed)

    def test_failed_skipped_and_unknown_actions_refuse(self):
        for action in ('fail', 'skip', 'pause', 'cont', 'bench', 'unknown', False):
            changed = synthetic_events()
            changed[2]['Action'] = action
            with self.subTest(action=action):
                self.reject(changed)

    def test_package_start_and_terminal_must_be_complete(self):
        original = synthetic_events()
        for mode in ('missing-start', 'duplicate-start', 'missing-terminal', 'duplicate-terminal', 'late-output'):
            changed = copy.deepcopy(original)
            if mode == 'missing-start':
                changed.pop(0)
            elif mode == 'duplicate-start':
                changed.insert(0, copy.deepcopy(changed[0]))
            elif mode == 'missing-terminal':
                changed.pop()
            elif mode == 'duplicate-terminal':
                changed.append(copy.deepcopy(changed[-1]))
            else:
                changed.append(dict(Package=reader.PACKAGE, Action='output', Output='unselected\n'))
            with self.subTest(mode=mode):
                self.reject(changed)

    def test_pass_before_run_and_early_parent_completion_refuse(self):
        original = synthetic_events()
        changed = copy.deepcopy(original)
        changed[2], changed[3] = changed[3], changed[2]
        self.reject(changed)
        changed = copy.deepcopy(original)
        parent_pass = next(row for row in changed if row['Action'] == 'pass' and row.get('Test') == reader.PARENT)
        changed.remove(parent_pass)
        changed.insert(2, parent_pass)
        self.reject(changed)

    def test_output_requires_a_live_selected_owner(self):
        for name in (reader.PARENT + '/foreign', reader.PARENT + '/unlock_offset_gap'):
            changed = synthetic_events()
            changed.insert(-1, dict(Package=reader.PACKAGE, Action='output', Test=name, Output='unselected\n'))
            with self.subTest(name=name):
                self.reject(changed)
        changed = synthetic_events()
        changed.insert(1, dict(Package=reader.PACKAGE, Action='output', Test=reader.PARENT, Output='before run\n'))
        self.reject(changed)

    def test_event_fields_types_and_foreign_package_refuse(self):
        for key, value in (('Package', 'foreign'), ('unknown', True), ('FailedBuild', 'foreign'),
                           ('Time', False), ('Time', 'x' * 129), ('Elapsed', False), ('Elapsed', -1),
                           ('Elapsed', float('nan')), ('Output', 'misplaced output')):
            changed = synthetic_events()
            changed[0][key] = value
            with self.subTest(key=key, value=str(value)):
                self.reject(changed)

    def test_source_scope_and_operational_claim_changes_refuse(self):
        for key, value in (('selected_core_commit', '00' * 20), ('scope', 'COMPLETE_ADMISSION'),
                           ('application', 'GO'), ('core', 'GO'), ('independent_assessment', 'PASS'),
                           ('unexpected', True)):
            report = reader.expected_report()
            report[key] = value
            with self.subTest(key=key):
                self.reject(synthetic_events(report))

    def test_missing_extra_and_changed_method_records_refuse(self):
        for mode in ('missing', 'extra', 'changed'):
            report = reader.expected_report()
            if mode == 'missing':
                report['records'].pop('unlock_offset_gap')
            elif mode == 'extra':
                report['records']['unselected'] = report['records']['unlock_offset_gap']
            else:
                report['records']['unlock_offset_gap']['guard_outcome'] = 'NO_ERROR'
            with self.subTest(mode=mode):
                self.reject(synthetic_events(report))

    def test_layer_outcomes_and_original_data_hashes_are_exact(self):
        for key, value in (('guard_outcome', 'NO_ERROR'), ('dispatch_outcome', 'CONTRACT_MISSING'),
                           ('unpack_outcome', 'UNPACK_REFUSED'), ('validation_outcome', 'WITNESS_REFUSED'),
                           ('input_sha256', '00'*32), ('validated_data_sha256', '00'*32),
                           ('validation_changes_data', False), ('repack_equal', True),
                           ('dp_flag', False), ('method', 'Create')):
            report = reader.expected_report()
            report['records']['unlock_offset_gap'][key] = value
            with self.subTest(key=key):
                self.reject(synthetic_events(report))

    def test_boolean_float_null_and_container_counters_refuse(self):
        for value in (True, 1.0, None, '1', [1], {'value': 1}):
            report = reader.expected_report()
            report['records']['unlock_offset_gap']['data_bytes'] = value
            with self.subTest(value=value):
                self.reject(synthetic_events(report))

    def test_duplicate_report_and_duplicate_json_fields_refuse(self):
        events = synthetic_events()
        pieces = [copy.deepcopy(row) for row in events if row['Action'] == 'output' and row.get('Test') == reader.PARENT]
        position = next(index for index, row in enumerate(events) if row['Action'] == 'output')
        events[position:position] = pieces
        self.reject(events)
        raw = encoded(synthetic_events()).replace(b'"Action": "start"', b'"Action": "start", "Action": "start"', 1)
        with self.assertRaises(ValueError):
            reader.report_from_events(raw)
        events = synthetic_events(fragment=65536)
        position = next(index for index, row in enumerate(events) if row['Action'] == 'output' and row.get('Test') == reader.PARENT)
        events[position]['Output'] = events[position]['Output'].replace('"core":"NO-GO"', '"core":"NO-GO","core":"NO-GO"', 1)
        self.reject(events)

    def test_stdout_event_and_parent_output_bounds_refuse(self):
        raw = encoded(synthetic_events())
        with patch.object(reader, 'MAX_STDOUT', len(raw) - 1), self.assertRaises(ValueError):
            reader.report_from_events(raw)
        events = synthetic_events()
        position = next(index for index, row in enumerate(events) if row['Action'] == 'output' and row.get('Test') == reader.PARENT)
        events[position]['Output'] = 'x' * (reader.MAX_REPORT + 1)
        self.reject(events)
        events = synthetic_events()
        events[2:2] = [dict(Package=reader.PACKAGE, Action='output', Test=reader.PARENT, Output='')] * reader.MAX_EVENTS
        self.reject(events)

    def test_manufactured_passes_and_diagnostics_grant_no_authority(self):
        result = reader.compare_payloads({'abi-boundary.stdout': encoded(synthetic_events()),
            'abi-boundary.stderr': b'synthetic unqualified diagnostics\n'}, ROOT)
        self.assertEqual(result['finite_layer_cases'], 26)
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['actual_command_exit'], result['execution_origin'])
        self.assertEqual(result['execution_origin'], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['stream_completeness'], 'NOT_ESTABLISHED_BY_FILE_CONTENT')
        self.assertEqual(result['application'], result['core'])
        self.assertEqual(result['core'], 'NO-GO')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        for key in ('combined_admission', 'source_authentication', 'independent_assessment'):
            self.assertEqual(result[key], 'UNFILLED')

    def test_stream_set_types_and_stderr_bound_refuse(self):
        valid = {'abi-boundary.stdout': encoded(synthetic_events()), 'abi-boundary.stderr': b''}
        for mode in ('missing', 'extra', 'swapped', 'text', 'stderr-bound'):
            changed = dict(valid)
            if mode == 'missing':
                changed.pop('abi-boundary.stderr')
            elif mode == 'extra':
                changed['extra'] = b''
            elif mode == 'swapped':
                changed['abi-boundary.stdout'], changed['abi-boundary.stderr'] = changed['abi-boundary.stderr'], changed['abi-boundary.stdout']
            elif mode == 'text':
                changed['abi-boundary.stdout'] = changed['abi-boundary.stdout'].decode('ascii')
            else:
                changed['abi-boundary.stderr'] = b'x' * (reader.MAX_STDERR + 1)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                reader.compare_payloads(changed, ROOT)


class SelectionTests(unittest.TestCase):
    def copied_inputs(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        for name in reader.OWN_INPUTS | {reader.MANIFEST}:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        return root

    def update_pin(self, root, name):
        manifest = json.loads((root / reader.MANIFEST).read_bytes())
        manifest['input_sha256'][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
        (root / reader.MANIFEST).write_text(json.dumps(manifest), encoding='ascii')

    def test_exact_source_and_previous_subject_selection(self):
        manifest, index, values = reader.inputs(ROOT)
        self.assertEqual(len(index), 474)
        self.assertEqual(reader.common.git_tree(index), reader.TREE)
        self.assertEqual(manifest['source_view_files'], 475)
        self.assertEqual(values, reader.fixture())
        self.assertEqual(manifest['input_sha256'][reader.PREVIOUS_MANIFEST], reader.PREVIOUS_MANIFEST_SHA256)

    def test_nearby_source_count_boolean_and_go_claims_refuse(self):
        root = self.copied_inputs()
        original = json.loads((root / reader.MANIFEST).read_bytes())
        for key, value in (('core_commit', '00' * 20), ('core_tree', '00' * 20), ('source_files', 444),
                           ('project_probe_files', True), ('finite_layer_cases', 25),
                           ('combined_admission', 'PASS'), ('journal_source_upgrade', 'SELECTED')):
            changed = copy.deepcopy(original)
            changed[key] = value
            (root / reader.MANIFEST).write_text(json.dumps(changed), encoding='ascii')
            with self.subTest(key=key), self.assertRaises(ValueError):
                reader.inputs(root)

    def test_rebound_producer_and_previous_selection_refuse(self):
        for name in (reader.DRIVER, reader.PREVIOUS_MANIFEST, reader.SOURCE, *reader.FIXED_DEPENDENCIES):
            root = self.copied_inputs()
            (root / name).write_bytes((root / name).read_bytes() + b'\n')
            self.update_pin(root, name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                reader.inputs(root)

    def test_fixture_value_change_cannot_be_hidden_by_a_fresh_pin(self):
        root = self.copied_inputs()
        value = reader.fixture()
        value['expected']['records']['unlock_offset_gap']['data_bytes'] = True
        (root / reader.FIXTURE).write_text(json.dumps(value), encoding='ascii')
        self.update_pin(root, reader.FIXTURE)
        with self.assertRaises(ValueError):
            reader.inputs(root)

    def test_missing_extra_and_stale_input_pins_refuse(self):
        root = self.copied_inputs()
        original = json.loads((root / reader.MANIFEST).read_bytes())
        for mode in ('missing', 'extra', 'stale'):
            value = copy.deepcopy(original)
            if mode == 'missing':
                value['input_sha256'].pop(reader.DRIVER)
            elif mode == 'extra':
                value['input_sha256']['unselected'] = '00' * 32
            else:
                value['input_sha256'][reader.DRIVER] = '00' * 32
            (root / reader.MANIFEST).write_text(json.dumps(value), encoding='ascii')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                reader.inputs(root)


class SourceFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One reusable tiny frame avoids recreating 474 files for each refusal.
        # inputs() is explicitly mocked: these are not upstream source bytes.
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve()
        cls.source = cls.root / 'source'
        cls.source.mkdir()
        cls.raw = b'// synthetic file-walk framing only\n'
        cls.index = {}
        for number in range(474):
            name = 'synthetic/source_' + str(number) + '.go'
            path = cls.source / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(cls.raw)
            cls.index[name] = dict(bytes=len(cls.raw), sha256=hashlib.sha256(cls.raw).hexdigest(),
                git_blob_sha1=hashlib.sha1(b'blob ' + str(len(cls.raw)).encode() + b'\0' + cls.raw).hexdigest())
        cls.driver = (ROOT / reader.DRIVER).read_bytes()
        path = cls.source / reader.DESTINATION
        path.parent.mkdir(parents=True)
        path.write_bytes(cls.driver)

    def compare(self, source=None, index=None):
        with patch.object(reader, 'inputs', return_value=({}, self.index if index is None else index, reader.fixture())):
            return reader.compare_source(self.source if source is None else source, ROOT)

    def test_exact_synthetic_frame_is_content_only(self):
        value = self.compare()
        self.assertEqual(value['combined_files'], 475)
        self.assertEqual(value['project_probe_files'], 1)
        self.assertEqual(value['execution_binding'], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(value['filesystem_mode_equality'], 'NOT_ASSERTED')

    def test_missing_changed_extra_and_old_probe_files_refuse(self):
        target = self.source / 'synthetic/source_0.go'
        for mode in ('missing', 'changed', 'extra', 'old-probe'):
            extra = None
            try:
                if mode == 'missing':
                    target.unlink()
                elif mode == 'changed':
                    target.write_bytes(self.raw + b'// changed\n')
                else:
                    extra = self.source / ('vm/embedded/unselected_test.go' if mode == 'old-probe' else 'extra.txt')
                    extra.write_bytes(b'synthetic extra file\n')
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    self.compare()
            finally:
                target.write_bytes(self.raw)
                if extra is not None:
                    extra.unlink()

    def test_unselected_empty_directory_and_git_metadata_refuse(self):
        for name in ('unselected', '.git'):
            path = self.source / name
            path.mkdir()
            try:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.compare()
            finally:
                path.rmdir()

    def test_source_root_ancestor_and_file_symlinks_refuse(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.source, target_is_directory=True)
        try:
            with self.assertRaises(ValueError):
                self.compare(alias)
        finally:
            alias.unlink()
        target = self.source / 'synthetic/source_0.go'
        target.unlink()
        target.symlink_to(self.source / 'synthetic/source_1.go')
        try:
            with self.assertRaises(ValueError):
                self.compare()
        finally:
            target.unlink()
            target.write_bytes(self.raw)

    def test_synthetic_hard_link_and_producer_substitution_refuse(self):
        # Only toy files in this isolated frame are linked, never real evidence.
        alias = self.root / 'toy-link'
        os.link(self.source / 'synthetic/source_0.go', alias)
        try:
            with self.assertRaises(ValueError):
                self.compare()
        finally:
            alias.unlink()
        target = self.source / reader.DESTINATION
        target.write_bytes(b'// unselected synthetic producer\n')
        try:
            with self.assertRaises(ValueError):
                self.compare()
        finally:
            target.write_bytes(self.driver)

    def test_fixed_count_and_source_size_bounds_cannot_be_weakened(self):
        value = dict(self.index)
        value.pop('synthetic/source_0.go')
        with self.assertRaises(ValueError):
            self.compare(index=value)
        with patch.object(reader, 'MAX_SOURCE_FILE', len(self.raw) - 1), self.assertRaises(ValueError):
            self.compare()
        with patch.object(reader, 'MAX_SOURCE_TOTAL', len(self.raw)), self.assertRaises(ValueError):
            self.compare()


class FilesystemAndCliTests(unittest.TestCase):
    def test_stream_directory_missing_extra_and_alias_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            payloads = {'abi-boundary.stdout': encoded(synthetic_events()), 'abi-boundary.stderr': b''}
            for name, raw in payloads.items():
                (root / name).write_bytes(raw)
            self.assertEqual(reader.load_payloads(root), payloads)
            (root / 'abi-boundary.stderr').unlink()
            with self.assertRaises(ValueError):
                reader.load_payloads(root)
            (root / 'abi-boundary.stderr').symlink_to(root / 'abi-boundary.stdout')
            with self.assertRaises(ValueError):
                reader.load_payloads(root)
            (root / 'abi-boundary.stderr').unlink()
            (root / 'abi-boundary.stderr').write_bytes(b'')
            (root / 'extra').write_bytes(b'')
            with self.assertRaises(ValueError):
                reader.load_payloads(root)

    def test_cli_refuses_without_echoing_paths_or_arguments(self):
        result = subprocess.run([sys.executable, '-B', '-m', 'qualification.nom_dev_abi_boundary',
            '--unselected-private-control'], cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'REFUSED: ABI boundary component comparison\n')

    def test_optimization_refuses_before_any_inputs(self):
        result = subprocess.run([sys.executable, '-B', '-O', '-m', 'qualification.nom_dev_abi_boundary'],
            cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'ABI boundary comparison requires assertions enabled\n')


class LayerValueTests(unittest.TestCase):
    def test_four_canonical_methods_keep_original_data(self):
        from offline_session.nom_wire import decode_call
        cases = reader.scenarios()
        for method in ('Create', 'Reclaim', 'Unlock', 'ProxyUnlock'):
            row = cases[method+'_canonical']
            with self.subTest(method=method):
                self.assertEqual(decode_call(row['input'])['method'], method)
                self.assertEqual(row['input'], row['output'])
                self.assertTrue(row['repack_equal'])
                self.assertFalse(row['validation_changes_data'])

    def test_size_preserving_aliases_are_not_canonical_wire(self):
        from offline_session.nom_wire import decode_call
        for name in ('proxy_address_high_padding', 'create_point_type_high_padding'):
            row = reader.scenarios()[name]
            with self.subTest(name=name):
                self.assertEqual(row['guard_outcome'], 'NO_ERROR')
                self.assertEqual(len(row['input']), len(row['output']))
                self.assertNotEqual(row['input'], row['output'])
                self.assertFalse(row['repack_equal'])
                with self.assertRaises(ValueError):
                    decode_call(row['input'])

    def test_witness_width_refusal_remains_a_separate_layer(self):
        for name in ('unlock_invalid_witness_width', 'unlock_invalid_width_nonzero_padding'):
            row = reader.scenarios()[name]
            with self.subTest(name=name):
                self.assertEqual(row['guard_outcome'], 'NO_ERROR')
                self.assertEqual(row['unpack_outcome'], 'UNPACKED')
                self.assertEqual(row['validation_outcome'], 'WITNESS_REFUSED')
                self.assertFalse(row['validation_changes_data'])

    def test_declared_flags_do_not_promote_helper_results_to_admission(self):
        cases = reader.scenarios()
        row = cases['dp_flag_off_isolated_helper']
        self.assertFalse(row['dp_flag'])
        self.assertEqual(row['guard_outcome'], 'TRAILING_DATA')
        row = cases['ptlc_registry_absent']
        self.assertFalse(row['ptlc_flag'])
        self.assertEqual(row['dispatch_outcome'], 'CONTRACT_MISSING')
        self.assertEqual(row['validation_outcome'], 'VALIDATED')
        self.assertEqual(reader.expected_report()['core'], 'NO-GO')
