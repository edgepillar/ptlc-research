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

from qualification import nom_receive_credit as reader

ROOT = Path(__file__).resolve().parents[1]


def synthetic_record(case):
    return dict(schema='ptlc-nom-receive-credit-source-v1', case=case,
        selected_head=reader.CASES[case], later_send_refusal='ErrABSequencerNotNext',
        head_confirmation_height=10, later_confirmation_height=12,
        expiration=110, head_confirmation_time=100 if case == 'unlock-first' else 110,
        later_confirmation_time=120, processing_time=130,
        head_receive_acknowledges_confirmation=True, fixed_recipient_or_owner_payout=True,
        contract_entry_unchanged_after_generation=True, generation_commits=0,
        contract_receives_committed=2,head_committed_payouts=1,later_committed_payouts=0,
        head_receive_confirmation_height=14,later_receive_confirmation_height=16,
        later_method_error='ErrDataNonExistent',later_error_generation_commits=0,
        head_commit_matches_generated=True,later_commit_matches_generated=True,
        contract_entry_absent_after_commits=True,contract_token_balance_after_commits=0,
        recipient_balance_credit='ONE_EXPLICIT_SELECTED_USER_RECEIVE',queue_liveness='NOT_ASSESSED',
        user_receive_confirmation_height=18,user_balance_before_credit='1000000000',
        user_balance_after_credit='2000000000',synthetic_credit_amount='1000000000',
        other_user_balance_unchanged=True,duplicate_user_receive_refusal='ErrABFromBlockAlreadyReceived',
        duplicate_credit_commits=0,
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


class ReceiveCreditTests(unittest.TestCase):
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
        for value in (0, -1, 2**64, 10.0, '10', None):
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
        result = subprocess.run([sys.executable, '-B', '-m', 'qualification.nom_receive_credit',
            '--unknown-private-argument'], cwd=ROOT, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'receive credit comparison refused\n')

    def fragments(self, events, width):
        selected = []
        for event in events:
            if event['Action'] == 'output':
                text = event['Output']
                selected.extend(dict(event, Output=text[index:index + width])
                    for index in range(0, len(text), width))
            else:
                selected.append(copy.deepcopy(event))
        return selected

    def test_records_reassemble_across_arbitrary_output_fragments(self):
        expected = self.compare()['cases']
        for width in (1, 7, 31, 1024):
            with self.subTest(width=width):
                self.assertEqual(self.compare(self.fragments(synthetic_events(), width))['cases'], expected)

    def test_json_escapes_can_cross_output_fragments(self):
        events = synthetic_events()
        row = next(row for row in events if reader.MARKER in row.get('Output', ''))
        row['Output'] = row['Output'].replace('reclaim-first', '\\u0072eclaim-first')
        self.assertEqual(self.compare(self.fragments(events, 7))['cases'], self.compare()['cases'])

    def test_dropped_record_continuation_refuses(self):
        events = self.fragments(synthetic_events(), 17)
        first = next(index for index, row in enumerate(events) if row['Action'] == 'output')
        self.refuse(events[:first + 3] + events[first + 4:])

    def test_continuation_cannot_move_to_the_parent_test(self):
        events = self.fragments(synthetic_events(), 1024)
        first = next(index for index, row in enumerate(events) if row['Action'] == 'output')
        events[first + 1]['Test'] = reader.TEST
        self.refuse(events)

    def test_complete_record_still_requires_its_output_newline(self):
        events = synthetic_events()
        row = next(row for row in events if reader.MARKER in row.get('Output', ''))
        row['Output'] = row['Output'].removesuffix('\n')
        self.refuse(events)

    def test_record_can_precede_a_separate_diagnostic_line(self):
        events = synthetic_events()
        row = next(row for row in events if reader.MARKER in row.get('Output', ''))
        row['Output'] += 'synthetic diagnostic\n'
        self.assertEqual(self.compare(self.fragments(events, 31))['cases'], self.compare()['cases'])

    def test_duplicate_record_within_one_output_refuses(self):
        events = synthetic_events()
        row = next(row for row in events if reader.MARKER in row.get('Output', ''))
        row['Output'] += row['Output']
        self.refuse(events)

    def test_unfinished_diagnostic_line_at_terminal_refuses(self):
        events = synthetic_events()
        first = next(index for index, row in enumerate(events) if reader.MARKER in row.get('Output', ''))
        events.insert(first + 1, dict(events[first], Output='unfinished synthetic diagnostic'))
        self.refuse(events)

    def test_overlapping_selected_child_runs_refuse(self):
        events = synthetic_events()
        other = next(row for row in events if row['Action'] == 'run' and row.get('Test', '').endswith('/unlock-first'))
        events.insert(3, copy.deepcopy(other))
        self.refuse(events)

    def test_confirmation_heights_cover_both_sends_and_both_receives(self):
        for key, value in (('head_confirmation_height', 12), ('later_confirmation_height', 14),
                ('head_receive_confirmation_height', 12), ('later_receive_confirmation_height', 14),
                ('head_receive_confirmation_height', True), ('later_receive_confirmation_height', 2**64)):
            with self.subTest(key=key, value=value):
                self.refuse(self.change_record(**{key: value}))

    def test_only_one_payout_and_two_committed_receives_match(self):
        for key, value in (('contract_receives_committed', 1), ('contract_receives_committed', 3),
                ('contract_receives_committed', True), ('head_committed_payouts', 2),
                ('later_committed_payouts', 1), ('later_committed_payouts', False),
                ('contract_token_balance_after_commits', 1)):
            with self.subTest(key=key, value=value):
                self.refuse(self.change_record(**{key: value}))

    def test_commit_and_method_error_observations_are_exact(self):
        for key, value in (('head_commit_matches_generated', False), ('later_commit_matches_generated', False),
                ('contract_entry_absent_after_commits', False), ('later_method_error', 'ErrExpired'),
                ('later_error_generation_commits', 1), ('recipient_balance_credit', 'VERIFIED'),
                ('queue_liveness', 'PROVED')):
            with self.subTest(key=key, value=value):
                self.refuse(self.change_record(**{key: value}))

    def test_send_times_must_be_strictly_ordered(self):
        self.refuse(self.change_record(head_confirmation_time=120))
        self.refuse(self.change_record(head_confirmation_time=121))
        self.refuse(self.change_record(later_confirmation_time=110))

    def test_time_values_obey_signed_integer_bounds(self):
        for key in ('expiration', 'head_confirmation_time', 'later_confirmation_time', 'processing_time'):
            for value in (0, -1, 2**63, True, 1.0):
                with self.subTest(key=key, value=value):
                    self.refuse(self.change_record(**{key: value}))

    def test_probe_notice_is_pinned_and_carries_a_modification_date(self):
        manifest, unused_index = reader.inputs(ROOT)
        notice = (ROOT / reader.NOTICE).read_bytes()
        self.assertIn(b'Modification date: 2026-10-19.', notice)
        self.assertEqual(hashlib.sha256(notice).hexdigest(), manifest['input_sha256'][reader.NOTICE])
        self.assertEqual(manifest['input_sha256'][reader.DRIVER],
            'd76b578aae9abca0fea2b787603e8cf5037974a3e88309cfbd02b592d396e90a')


    def test_user_receive_height_must_follow_the_later_contract_receive(self):
        for height in (0, 14, 16, 2**64, True, 18.0, '18', None):
            with self.subTest(height=height):
                self.refuse(self.change_record(user_receive_confirmation_height=height))
        self.assertEqual(self.compare(self.change_record(user_receive_confirmation_height=17))[
            'cases']['reclaim-first']['user_receive_confirmation_height'], 17)

    def test_credit_amount_is_the_exact_synthetic_decimal_string(self):
        for amount in ('0', '1', '1000000001', 1000000000, True, None):
            with self.subTest(amount=amount):
                self.refuse(self.change_record(synthetic_credit_amount=amount))

    def test_balance_strings_are_canonical_bounded_unsigned_integers(self):
        for field in ('user_balance_before_credit', 'user_balance_after_credit'):
            for amount in ('', '00', '01', '-1', '+1', '1.0', ' 0', '\u0660',
                    str(2**256), '9'*79, 1000000000, True, None):
                with self.subTest(field=field, amount=amount):
                    self.refuse(self.change_record(**{field: amount}))

    def test_credit_delta_rejects_partial_double_and_negative_credit(self):
        for before, after in (('1000000000', '1999999999'), ('1000000000', '3000000000'),
                ('2000000000', '1000000000'), ('1000000000', '1000000000')):
            with self.subTest(before=before, after=after):
                self.refuse(self.change_record(user_balance_before_credit=before,
                    user_balance_after_credit=after))

    def test_credit_delta_accepts_zero_and_high_uint256_boundaries(self):
        for before in (0, 2**256-1-1000000000):
            result = self.compare(self.change_record(user_balance_before_credit=str(before),
                user_balance_after_credit=str(before+1000000000)))
            self.assertEqual(int(result['cases']['reclaim-first']['user_balance_after_credit'])-
                int(result['cases']['reclaim-first']['user_balance_before_credit']), 1000000000)

    def test_duplicate_and_other_user_observations_are_exact(self):
        for field, value in (('other_user_balance_unchanged', False), ('other_user_balance_unchanged', 1),
                ('duplicate_user_receive_refusal', 'NONE'), ('duplicate_user_receive_refusal', None),
                ('duplicate_credit_commits', 1), ('duplicate_credit_commits', False)):
            with self.subTest(field=field, value=value):
                self.refuse(self.change_record(**{field: value}))


if __name__ == '__main__':
    unittest.main()
