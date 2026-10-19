"""Synthetic reader controls; no fixture here establishes source execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification import nom_receive_sequencing as reader

ROOT = Path(__file__).resolve().parents[1]


def synthetic_record(case):
    return dict(schema='ptlc-nom-receive-sequencing-source-v1', case=case,
        selected_head=reader.CASES[case], later_send_refusal='ErrABSequencerNotNext',
        head_confirmation_height=10, later_confirmation_height=12,
        expiration=110, head_confirmation_time=100 if case == 'unlock-first' else 110,
        later_confirmation_time=120, processing_time=130,
        head_receive_acknowledges_confirmation=True, fixed_recipient_or_owner_payout=True,
        contract_entry_unchanged_after_generation=True, generation_commits=0,
        source_execution='IN_PROCESS_MOCK_ONLY', canonicality='UNFILLED',
        swap_atomicity='NOT_ASSESSED', safe_disclosure_margin='NOT_SELECTED',
        recovery_action='NONE', application='NO-GO', core='NO-GO')


def synthetic_events():
    events = [dict(Action='start', Package=reader.PACKAGE),
        dict(Action='run', Package=reader.PACKAGE, Test=reader.TEST)]
    for case in sorted(reader.CASES):
        test = reader.TEST + '/' + case
        events.extend([dict(Action='run', Package=reader.PACKAGE, Test=test),
            dict(Action='output', Package=reader.PACKAGE, Test=test,
                Output=reader.MARKER + json.dumps(synthetic_record(case)) + '\n'),
            dict(Action='pass', Package=reader.PACKAGE, Test=test)])
    events.extend([dict(Action='pass', Package=reader.PACKAGE, Test=reader.TEST),
        dict(Action='pass', Package=reader.PACKAGE)])
    return events


def stream(events):
    return b''.join(json.dumps(event).encode('ascii') + b'\n' for event in events)


class ReceiveSequencingTests(unittest.TestCase):
    def compare(self, events=None):
        return reader.compare_payloads(stream(synthetic_events() if events is None else events), b'', ROOT)

    def refuse(self, events):
        with self.assertRaises((ValueError, AssertionError, KeyError, TypeError)):
            self.compare(events)

    def change_record(self, **updates):
        events = synthetic_events()
        row = next(row for row in events if reader.MARKER in row.get('Output', ''))
        value = json.loads(row['Output'][len(reader.MARKER):])
        value.update(updates)
        row['Output'] = reader.MARKER + json.dumps(value) + '\n'
        return events

    def test_selected_content_and_license_are_pinned(self):
        manifest, index = reader.inputs(ROOT)
        self.assertEqual(reader.source_reader.git_tree(index), reader.TREE)
        self.assertEqual(manifest['probe_license'], 'GPL-3.0-only')
        self.assertEqual(index['LICENSE']['sha256'], manifest['input_sha256'][reader.LICENSE])

    def test_complete_synthetic_stream_keeps_external_gates_unfilled(self):
        result = self.compare()
        self.assertEqual(result['passed_including_parent'], 3)
        self.assertEqual(set(result['cases']), set(reader.CASES))
        for key in ('independent_assessment', 'canonicality', 'finality', 'liveness'):
            self.assertEqual(result[key], 'UNFILLED')
        for key in ('actual_command_exit', 'producer_authentication'):
            self.assertEqual(result[key], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['native_execution'], 'NOT_PERFORMED_BY_READER')
        self.assertEqual(result['source_content'], 'SEPARATE_COMPLETE_CONTENT_CHECK_REQUIRED')
        self.assertEqual(result['journal_source_upgrade'], 'NOT_SELECTED')
        self.assertEqual(result['application'], 'NO-GO')
        self.assertEqual(result['core'], 'NO-GO')
        self.assertEqual(result['recovery_action'], 'NONE')

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

    def test_failure_skip_pause_and_build_failure_refuse(self):
        for action in ('fail', 'skip', 'pause', 'cont', 'bench'):
            events = synthetic_events(); events[2]['Action'] = action
            self.refuse(events)
        events = synthetic_events(); events[2]['FailedBuild'] = reader.PACKAGE
        self.refuse(events)

    def test_foreign_package_test_and_extra_fields_refuse(self):
        for field, value in (('Package', 'foreign/package'), ('Test', 'OtherTest'), ('Extra', True)):
            events = synthetic_events(); events[3][field] = value
            self.refuse(events)

    def test_terminal_events_cannot_precede_records_or_children(self):
        events = synthetic_events(); events[3], events[4] = events[4], events[3]
        self.refuse(events)
        events = synthetic_events(); events[1], events[-2] = events[-2], events[1]
        self.refuse(events)
        events = synthetic_events(); events.insert(2, events.pop())
        self.refuse(events)

    def test_data_after_package_terminal_refuses(self):
        events = synthetic_events()
        self.refuse(events + [dict(Action='output', Package=reader.PACKAGE, Output='late\n')])

    def test_explicit_null_test_field_is_not_a_package_event(self):
        events = synthetic_events(); events[-1]['Test'] = None
        self.refuse(events)
        events = synthetic_events()
        events.insert(1, dict(Action='output', Package=reader.PACKAGE, Test=None, Output='synthetic\n'))
        self.refuse(events)

    def test_marker_must_belong_to_selected_child(self):
        for test in (None, reader.TEST, reader.TEST + '/unlock-first'):
            events = synthetic_events()
            row = next(row for row in events if reader.MARKER in row.get('Output', ''))
            if test is None:
                del row['Test']
            else:
                row['Test'] = test
            self.refuse(events)

    def test_marker_cannot_be_hidden_or_repeated(self):
        for prefix, suffix in (('diagnostic ', ''), ('', reader.MARKER + '{}')):
            events = synthetic_events()
            row = next(row for row in events if reader.MARKER in row.get('Output', ''))
            row['Output'] = prefix + row['Output'] + suffix
            self.refuse(events)

    def test_booleans_cannot_replace_integer_observations(self):
        for key in ('head_confirmation_height', 'later_confirmation_height', 'expiration',
                'head_confirmation_time', 'later_confirmation_time', 'processing_time'):
            self.refuse(self.change_record(**{key: True}))

    def test_numeric_bounds_and_noninteger_observations_refuse(self):
        for value in (0, -1, 2**63, 10.0, '10', None):
            self.refuse(self.change_record(head_confirmation_height=value))

    def test_confirmation_order_must_be_strict(self):
        self.refuse(self.change_record(later_confirmation_height=10))
        self.refuse(self.change_record(later_confirmation_time=110))

    def test_unlock_must_be_confirmed_strictly_before_expiry(self):
        value = synthetic_record('unlock-first')
        value['head_confirmation_time'] = value['expiration']
        with self.assertRaises(ValueError):
            reader.record(value, 'unlock-first')

    def test_reclaim_must_be_confirmed_at_or_after_expiry(self):
        self.refuse(self.change_record(head_confirmation_time=109))

    def test_later_send_and_processing_cannot_precede_expiry(self):
        self.refuse(self.change_record(expiration=121))
        self.refuse(self.change_record(processing_time=119))

    def test_record_fields_and_authority_labels_are_exact(self):
        value = synthetic_record('unlock-first')
        for key in value:
            changed = copy.deepcopy(value); del changed[key]
            with self.assertRaises(ValueError):
                reader.record(changed, 'unlock-first')
        for key, item in (('canonicality', 'VERIFIED'), ('recovery_action', 'RETRY'),
                ('application', 'GO'), ('generation_commits', False),
                ('fixed_recipient_or_owner_payout', 1), ('source_execution', 'LIVE')):
            self.refuse(self.change_record(**{key: item}))
        self.refuse(self.change_record(extra_field='unselected'))

    def test_record_and_child_case_cannot_be_relabelled(self):
        self.refuse(self.change_record(case='unlock-first'))
        self.refuse(self.change_record(selected_head='unlock'))
        self.refuse(self.change_record(later_send_refusal='OTHER'))

    def test_duplicate_keys_and_nonfinite_json_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"value":NaN}', b'{"value":Infinity}', b'{}{}'):
            with self.assertRaises(ValueError):
                reader.decoded(raw, 1024)

    def test_elapsed_and_output_types_are_checked(self):
        for value in (True, -1, float('inf'), '1'):
            events = synthetic_events(); events[-2]['Elapsed'] = value
            self.refuse(events)
        events = synthetic_events(); events[3]['Output'] = 1
        self.refuse(events)

    def test_bounds_and_stderr_remain_data_only(self):
        raw = stream(synthetic_events())
        result = reader.compare_payloads(raw, b'diagnostic bytes', ROOT)
        self.assertEqual(result['stderr_sha256'], hashlib.sha256(b'diagnostic bytes').hexdigest())
        self.assertEqual(result['actual_command_exit'], 'NOT_ESTABLISHED_BY_THIS_READER')
        for out, err in ((b'', b''), (raw, b'x' * (reader.MAX_STDERR + 1)),
                (b'x' * (reader.MAX_STDOUT + 1), b''), (raw.decode('ascii'), b'')):
            with self.assertRaises(ValueError):
                reader.compare_payloads(out, err, ROOT)

    def test_incomplete_source_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(ValueError):
                reader.compare_source(Path(name).resolve(), ROOT)

    def test_linked_input_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name).resolve(); path = parent / 'synthetic'
            path.write_bytes(b'not evidence')
            (parent / 'symbolic').symlink_to(path)
            with self.assertRaises(ValueError):
                reader.regular(parent / 'symbolic', 1024)
            os.link(path, parent / 'hard')
            with self.assertRaises(ValueError):
                reader.regular(path, 1024)

    def test_cli_refusal_does_not_echo_arguments(self):
        result = subprocess.run([sys.executable, '-B', '-m', 'qualification.nom_receive_sequencing',
            '--unknown-private-argument'], cwd=ROOT, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'receive sequencing comparison refused\n')


if __name__ == '__main__':
    unittest.main()
