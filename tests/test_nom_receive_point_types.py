"""Synthetic point-type reader controls, separate from actual source execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from qualification import nom_receive_point_types as reader
from test_nom_receive_credit import synthetic_record as credit_record

ROOT = Path(__file__).resolve().parents[1]


def synthetic_record(case):
    mode, kind, witness, binding, prior_case = reader.CASES[case]
    value = credit_record(prior_case)
    value.update(schema='ptlc-nom-receive-point-types-source-v1', case=case,
        point_mode=mode, point_type=kind, witness_kind=witness, witness_binding=binding)
    return value


def synthetic_events():
    result = [dict(Action='start', Package=reader.PACKAGE),
        dict(Action='run', Package=reader.PACKAGE, Test=reader.TEST)]
    for case in sorted(reader.CASES):
        test = reader.TEST + '/' + case
        result.extend([dict(Action='run', Package=reader.PACKAGE, Test=test),
            dict(Action='output', Package=reader.PACKAGE, Test=test,
                Output=reader.MARKER + json.dumps(synthetic_record(case)) + '\n'),
            dict(Action='pass', Package=reader.PACKAGE, Test=test)])
    result.extend([dict(Action='pass', Package=reader.PACKAGE, Test=reader.TEST),
        dict(Action='pass', Package=reader.PACKAGE)])
    return result


def stream(events):
    return b''.join(json.dumps(value).encode('ascii') + b'\n' for value in events)


class ReceivePointTypeTests(unittest.TestCase):
    def compare(self, events=None):
        return reader.compare_payloads(stream(synthetic_events() if events is None else events), b'', ROOT)

    def refuse(self, events):
        with self.assertRaises((ValueError, AssertionError, KeyError, TypeError)):
            self.compare(events)

    def change_record(self, selected_case, **updates):
        events = synthetic_events()
        row = next(value for value in events if value.get('Test') == reader.TEST + '/' + selected_case
            and value['Action'] == 'output')
        record = json.loads(row['Output'][len(reader.MARKER):])
        record.update(updates)
        row['Output'] = reader.MARKER + json.dumps(record) + '\n'
        return events

    def copy_inputs(self, directory):
        names = reader.SELECTED | reader.parent.SELECTED | {reader.MANIFEST, reader.parent.MANIFEST}
        for name in names:
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        return directory

    def test_selected_content_license_and_probe_match(self):
        manifest, index = reader.inputs(ROOT)
        self.assertEqual(len(index), 444)
        self.assertEqual(reader.source_reader.git_tree(index), reader.TREE)
        self.assertEqual(manifest['probe_license'], 'GPL-3.0-only')
        self.assertEqual(manifest['input_sha256'][reader.DRIVER],
            '5842eaee51cf04fe3a20238d7b4d0fda8cf8a05aa231a50c5ccd0abd5b073587')
        self.assertEqual(index['LICENSE']['sha256'], manifest['input_sha256'][reader.LICENSE])

    def test_complete_synthetic_values_preserve_external_gates(self):
        result = self.compare()
        self.assertEqual(result['passed_including_parent'], 7)
        self.assertEqual(set(result['cases']), set(reader.CASES))
        for name in ('independent_assessment', 'canonicality', 'finality', 'liveness'):
            self.assertEqual(result[name], 'UNFILLED')
        for name in ('actual_command_exit', 'producer_authentication'):
            self.assertEqual(result[name], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['source_content'], 'SEPARATE_COMPLETE_CONTENT_CHECK_REQUIRED')
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['adaptor_signature_completion'], 'NOT_ASSESSED')
        self.assertEqual(result['application'], 'NO-GO')
        self.assertEqual(result['core'], 'NO-GO')
        self.assertEqual(result['recovery_action'], 'NONE')

    def test_raw_scalar_is_not_an_operation_bound_signature(self):
        result = self.compare()
        for case, record in result['cases'].items():
            if case.startswith('secp256k1-point-'):
                self.assertEqual(record['witness_binding'], 'NO_OPERATION_MESSAGE_BINDING')
                self.assertEqual(record['witness_kind'], 'SECP256K1_SCALAR')
                self.refuse(self.change_record(case, witness_binding='OPERATION_MESSAGE'))
            else:
                self.assertEqual(record['witness_binding'], 'OPERATION_MESSAGE')

    def test_missing_every_required_event_refuses(self):
        events = synthetic_events()
        for index in range(len(events)):
            with self.subTest(index=index):
                self.refuse(events[:index] + events[index + 1:])

    def test_duplicate_every_required_event_refuses(self):
        events = synthetic_events()
        for index in range(len(events)):
            with self.subTest(index=index):
                self.refuse(events[:index] + [events[index]] + events[index:])

    def test_every_record_field_is_required(self):
        for case in reader.CASES:
            record = synthetic_record(case)
            for name in record:
                with self.subTest(case=case, field=name):
                    value = dict(record)
                    del value[name]
                    with self.assertRaises(ValueError):
                        reader.compare_record(value, case)

    def test_wrong_record_types_refuse_in_every_case(self):
        for case in reader.CASES:
            for name in synthetic_record(case):
                with self.subTest(case=case, field=name):
                    self.refuse(self.change_record(case, **{name: None}))

    def test_cross_case_and_point_mode_substitutions_refuse(self):
        for case in reader.CASES:
            for field, value in (('case', 'unlock-first'), ('point_type', True),
                ('point_mode', 'unselected'), ('witness_kind', 'UNSELECTED'), ('extra', False)):
                with self.subTest(case=case, field=field):
                    self.refuse(self.change_record(case, **{field: value}))

    def test_balance_and_duplicate_credit_counterexamples_refuse(self):
        for case in reader.CASES:
            for update in ({'user_balance_after_credit': '2000000001'},
                {'user_balance_before_credit': '01000000000'},
                {'user_balance_after_credit': str(2**256)}, {'user_balance_after_credit': 2000000000},
                {'other_user_balance_unchanged': False}, {'duplicate_credit_commits': 1},
                {'recipient_balance_credit': 'AUTOMATIC'}, {'synthetic_credit_amount': '1'}):
                with self.subTest(case=case, update=update):
                    self.refuse(self.change_record(case, **update))

    def test_receive_order_and_expiry_counterexamples_refuse(self):
        for case in reader.CASES:
            for update in ({'user_receive_confirmation_height': 16},
                {'later_receive_confirmation_height': 14}, {'head_receive_confirmation_height': True},
                {'head_confirmation_time': 110 if case.endswith('unlock-first') else 100},
                {'later_confirmation_time': 109}, {'processing_time': 119}):
                with self.subTest(case=case, update=update):
                    self.refuse(self.change_record(case, **update))

    def test_split_record_output_reassembles_only_within_its_test(self):
        events = synthetic_events()
        position = next(index for index, row in enumerate(events) if row['Action'] == 'output')
        original = events[position]
        text = original['Output']
        pieces = [dict(original, Output=text[start:start + 71]) for start in range(0, len(text), 71)]
        result = self.compare(events[:position] + pieces + events[position + 1:])
        self.assertEqual(len(result['cases']), 6)

    def test_partial_record_cannot_move_to_package_or_other_test(self):
        events = synthetic_events()
        row = next(value for value in events if value['Action'] == 'output')
        original = row['Output']
        row['Output'] = original[:31]
        position = events.index(row)
        events.insert(position + 1, dict(Action='output', Package=reader.PACKAGE, Output=original[31:]))
        self.refuse(events)

    def test_parent_or_package_record_marker_refuses(self):
        for test in (None, reader.TEST):
            events = synthetic_events()
            row = next(value for value in events if value['Action'] == 'output')
            if test is None:
                row.pop('Test')
            else:
                row['Test'] = test
            self.refuse(events)

    def test_overlapping_child_runs_refuse(self):
        events = synthetic_events()
        other = next(row for row in events[5:] if row['Action'] == 'run')
        events.insert(3, copy.deepcopy(other))
        self.refuse(events)

    def test_failed_skipped_paused_and_build_outcomes_refuse(self):
        for action in ('fail', 'skip', 'pause', 'cont', 'bench'):
            events = synthetic_events()
            events[2]['Action'] = action
            self.refuse(events)
        events = synthetic_events()
        events[0]['FailedBuild'] = 'unselected'
        self.refuse(events)

    def test_unselected_package_fields_and_test_refuse(self):
        for update in ({'Package': 'unselected'}, {'Test': reader.TEST + '/unselected'},
            {'Unselected': True}, {'Output': 1}):
            events = synthetic_events()
            events[3].update(update)
            self.refuse(events)

    def test_nonfinite_or_boolean_elapsed_refuses(self):
        for elapsed in (True, -1, float('nan'), float('inf')):
            events = synthetic_events()
            events[0]['Elapsed'] = elapsed
            self.refuse(events)

    def test_duplicate_json_keys_refuse(self):
        raw = stream(synthetic_events()).replace(b'"Action": "start"', b'"Action": "start", "Action": "start"', 1)
        with self.assertRaises(ValueError):
            reader.compare_stream(raw)

    def test_incomplete_stream_and_post_terminal_output_refuse(self):
        raw = stream(synthetic_events())
        for altered in (raw[:-1], raw + b'{}\n', b'', b'{}\n'):
            with self.assertRaises(ValueError):
                reader.compare_stream(altered)

    def test_stream_event_line_and_error_limits_refuse(self):
        for raw in (b'x' * (reader.MAX_STDOUT + 1), b'x' * (reader.MAX_EVENT + 1) + b'\n'):
            with self.assertRaises(ValueError):
                reader.compare_stream(raw)
        events = synthetic_events()
        events[3]['Output'] = 'x' * (reader.MAX_OUTPUT_LINE + 1)
        self.refuse(events)
        with self.assertRaises(ValueError):
            reader.compare_payloads(stream(synthetic_events()), b'x' * (reader.MAX_STDERR + 1), ROOT)

    def test_missing_changed_and_extra_manifest_fields_refuse(self):
        for update in ({'expected_go_outcomes': 3}, {'expected_go_outcomes': 7.0},
            {'expected_cases': ['unlock-first']}, {'adaptor_signature_completion': 'PASS'}, {'extra': True}):
            with self.subTest(update=update), tempfile.TemporaryDirectory() as directory:
                root = self.copy_inputs(Path(directory))
                manifest = json.loads((root / reader.MANIFEST).read_bytes())
                manifest.update(update)
                (root / reader.MANIFEST).write_bytes(reader.canonical(manifest))
                with self.assertRaises(ValueError):
                    reader.inputs(root)

    def test_changed_selected_inputs_refuse(self):
        for name in sorted(reader.SELECTED):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = self.copy_inputs(Path(directory))
                (root / name).write_bytes(b'changed public input')
                with self.assertRaises(ValueError):
                    reader.inputs(root)

    def test_parent_credit_profile_stays_exact(self):
        manifest, unused = reader.parent.inputs(ROOT)
        self.assertEqual(hashlib.sha256((ROOT / 'qualification/nom_receive_credit.py').read_bytes()).hexdigest(),
            '9efce98315428cb71febecb95be65d5f569bb1306b58e437c5a4cba3f7d3a0c0')
        self.assertEqual(manifest['expected_go_outcomes'], 3)
        self.assertEqual(manifest['expected_cases'], ['reclaim-first', 'unlock-first'])
