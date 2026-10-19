import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from qualification import nom_disclosure_timeout as model


ROOT = Path(__file__).resolve().parents[1]


class DisclosureTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((ROOT / 'compatibility/fixtures/nom_disclosure_timeout_v1.json').read_bytes())

    def request(self, *events):
        return dict(schema=model.SCHEMA, expires_at=dict(long=140, short=100),
            original_references={
                'long': dict(wire_sha256='11' * 32, node_hash_hex='aa' * 32),
                'short': dict(wire_sha256='22' * 32, node_hash_hex='bb' * 32)},
            unknown_work_charged=1, work_limit=2,
            events=list(events) or [dict(kind='possible-short-disclosure', at=90)])

    def event(self, kind, at, **values):
        return dict(kind=kind, at=at, **values)

    def assert_hold(self, result):
        self.assertEqual(result['state'], 'HOLD')
        self.assertEqual(result['recovery_action'], 'NONE')
        self.assertEqual(result['actions'], [])
        self.assertEqual(result['original_replacements'], 0)
        self.assertFalse(result['new_work_allowed'])
        self.assertEqual(result['native_worker_runs'], 0)
        self.assertEqual(result['application'], 'NO-GO')
        self.assertEqual(result['core'], 'NO-GO')
        self.assertEqual(result['independent_assessment'], 'UNFILLED')
        self.assertEqual(set(result['service_gates'].values()), {'UNFILLED'})
        for step in result['steps']:
            self.assertEqual(step['state'], 'HOLD')
            self.assertTrue(all(leg['state'] == 'HOLD' for leg in step['legs'].values()))

    def refuses(self, request):
        with self.assertRaises(ValueError):
            model.evaluate(request)

    def cli(self, raw, *extra, python_flags=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'private-request-name.json'
            path.write_bytes(raw)
            return subprocess.run([sys.executable, '-B', *python_flags, '-m',
                'qualification.nom_disclosure_timeout', '--request', str(path), *extra],
                cwd=ROOT, capture_output=True, timeout=20)

    def test_declared_counterexample_corpus_and_every_prefix_stay_hold(self):
        self.assertEqual(self.corpus['schema'], 'ptlc-nom-disclosure-timeout-corpus-v1')
        self.assertEqual(len(self.corpus['cases']), 20)
        self.assertEqual(len({case['id'] for case in self.corpus['cases']}), 20)
        for case in self.corpus['cases']:
            with self.subTest(case=case['id']):
                request = self.request(*case['events'])
                request['unknown_work_charged'] = case.get('initial_unknown_work', 1)
                request['expires_at']['long'] = case.get('long_expiry', 140)
                for leg, names in case.get('missing_references', {}).items():
                    for name in names:
                        request['original_references'][leg][name] = None
                result = model.evaluate(request)
                self.assert_hold(result)
                self.assertEqual(set(result['findings']), set(case['expected_findings']))
                self.assertEqual(result['unknown_work_charged'], case['expected_unknown_work'])
                self.assertEqual(result['legs']['long']['entry_in_model'], case['expected_long_entry'])
                self.assertEqual(result['legs']['short']['entry_in_model'], case['expected_short_entry'])
                for n in range(1, len(request['events']) + 1):
                    prefix = copy.deepcopy(request)
                    prefix['events'] = prefix['events'][:n]
                    self.assert_hold(model.evaluate(prefix))

    def test_all_120_failure_orders_preserve_disclosure_missing_reference_and_charge(self):
        events = [dict(kind='possible-short-disclosure'), dict(kind='charge-unknown-work'),
            dict(kind='price-refusal', leg='long'),
            dict(kind='original-unavailable', leg='long', part='wire_sha256'),
            dict(kind='reorg', leg='long')]
        for sequence in itertools.permutations(events):
            selected = [dict(event, at=n) for n, event in enumerate(sequence, 1)]
            result = model.evaluate(self.request(*selected))
            self.assert_hold(result)
            self.assertTrue(result['possible_disclosure'])
            self.assertEqual(result['unknown_work_charged'], 2)
            self.assertIsNone(result['legs']['long']['original_reference']['wire_sha256'])
            disclosed = False
            charged = 1
            absent = False
            for step in result['steps']:
                self.assertGreaterEqual(step['unknown_work_charged'], charged)
                self.assertFalse(disclosed and not step['possible_disclosure'])
                if absent:
                    self.assertIsNone(step['legs']['long']['original_reference']['wire_sha256'])
                disclosed = step['possible_disclosure']
                charged = step['unknown_work_charged']
                absent = step['legs']['long']['original_reference']['wire_sha256'] is None

    def test_price_or_order_pass_cannot_be_inferred_from_no_declared_refusal(self):
        result = model.evaluate(self.request())
        self.assert_hold(result)
        self.assertEqual(result['full_admission'], 'UNFILLED')
        self.assertEqual(result['model_reachability'], 'NOT_ESTABLISHED_BY_CORE')
        self.assertEqual(result['safe_disclosure_or_wait_duration'], 'NOT_SELECTED')

    def test_arbitrarily_large_selected_gap_still_has_no_timely_long_send(self):
        for expiry in (141, 1000000, model.MAX_TIME):
            request = self.request(self.event('possible-short-disclosure', 90),
                self.event('elapsed', expiry))
            request['expires_at']['long'] = expiry
            result = model.evaluate(request)
            self.assertIn('NO_TIMELY_LONG_SEND_ESTABLISHED_AFTER_DISCLOSURE', result['findings'])
            self.assert_hold(result)

    def test_exact_expiry_unlock_refuses_both_legs(self):
        for leg, expiry in (('short', 100), ('long', 140)):
            result = model.evaluate(self.request(
                self.event('declared-send-confirmed', expiry, leg=leg, send_timestamp=expiry),
                self.event('model-unlock-receive', expiry + 1, leg=leg)))
            self.assertEqual(result['steps'][-1]['model_outcome'], 'MODEL_UNLOCK_EXPIRY_COMPONENT_REFUSES')
            self.assertEqual(result['legs'][leg]['entry_in_model'], 'OPEN')

    def test_receive_time_does_not_replace_timely_send_timestamp(self):
        result = model.evaluate(self.request(
            self.event('declared-send-confirmed', 99, leg='short', send_timestamp=99),
            self.event('model-unlock-receive', 1000, leg='short')))
        self.assertEqual(result['steps'][-1]['model_outcome'], 'MODEL_UNLOCK_EXPIRY_COMPONENT_PASSES')
        self.assertIn('TIMELY_SEND_CAN_HAVE_LATE_MODEL_RECEIVE', result['findings'])
        self.assert_hold(result)

    def test_later_price_refusal_does_not_retroactively_reprice_declared_send(self):
        result = model.evaluate(self.request(
            self.event('declared-send-confirmed', 139, leg='long', send_timestamp=139),
            self.event('price-refusal', 140, leg='long'),
            self.event('model-unlock-receive', 141, leg='long')))
        self.assertEqual(result['legs']['long']['entry_in_model'], 'UNLOCKED')
        self.assertTrue(result['legs']['long']['future_price_refusal'])
        self.assert_hold(result)

    def test_reclaim_uses_its_declared_send_timestamp_too(self):
        result = model.evaluate(self.request(
            self.event('model-reclaim-receive', 1000, leg='short', send_timestamp=99)))
        self.assertEqual(result['steps'][-1]['model_outcome'], 'MODEL_RECLAIM_EXPIRY_COMPONENT_REFUSES')
        self.assertEqual(result['legs']['short']['entry_in_model'], 'OPEN')

    def test_both_receive_orders_are_conditional_and_never_core_reachability_proof(self):
        start = self.event('declared-send-confirmed', 99, leg='short', send_timestamp=99)
        unlock = self.event('model-unlock-receive', 101, leg='short')
        reclaim = self.event('model-reclaim-receive', 102, leg='short', send_timestamp=100)
        first = model.evaluate(self.request(start, unlock, reclaim))
        second = model.evaluate(self.request(start, dict(reclaim, at=101), dict(unlock, at=102)))
        self.assertEqual(first['legs']['short']['entry_in_model'], 'UNLOCKED')
        self.assertEqual(second['legs']['short']['entry_in_model'], 'RECLAIMED')
        for result in (first, second):
            self.assertEqual(result['model_reachability'], 'NOT_ESTABLISHED_BY_CORE')
            self.assert_hold(result)

    def test_reorg_invalidates_model_confirmation_but_not_disclosure_or_work(self):
        result = model.evaluate(self.request(self.event('possible-short-disclosure', 90),
            self.event('declared-send-confirmed', 99, leg='short', send_timestamp=99),
            self.event('model-unlock-receive', 101, leg='short'),
            self.event('charge-unknown-work', 102), self.event('reorg', 103, leg='short')))
        self.assertIsNone(result['legs']['short']['declared_send_timestamp'])
        self.assertEqual(result['legs']['short']['entry_in_model'], 'OPEN')
        self.assertTrue(result['possible_disclosure'])
        self.assertEqual(result['unknown_work_charged'], 2)

    def test_missing_descriptors_remain_missing_without_fixture_reconstruction(self):
        request = self.request(self.event('possible-short-disclosure', 90),
            self.event('reorg', 91, leg='long'), self.event('elapsed', 140))
        request['original_references']['long'] = dict(wire_sha256=None, node_hash_hex=None)
        result = model.evaluate(request)
        for step in result['steps']:
            self.assertEqual(step['legs']['long']['original_reference'], request['original_references']['long'])

    def test_custodian_availability_does_not_authenticate_present_descriptors(self):
        result = model.evaluate(self.request(self.event('custodian-unavailable', 90, leg='long')))
        self.assertFalse(result['legs']['long']['custodian_available_in_model'])
        self.assertIsNotNone(result['legs']['long']['original_reference']['wire_sha256'])
        self.assertEqual(result['original_byte_custody'], 'UNFILLED')

    def test_exhausted_unknown_work_is_not_refilled_by_time_or_reorg(self):
        request = self.request(self.event('charge-unknown-work', 90),
            self.event('elapsed', 1000), self.event('reorg', 1001, leg='long'))
        request['unknown_work_charged'] = 2
        result = model.evaluate(request)
        self.assertEqual([step['unknown_work_charged'] for step in result['steps']], [2, 2, 2])
        self.assertEqual(result['steps'][0]['model_outcome'], 'MODEL_WORK_LIMIT_EXHAUSTED')

    def test_input_objects_and_old_result_snapshots_are_independent(self):
        request = self.request(self.event('possible-short-disclosure', 90),
            self.event('original-unavailable', 91, leg='long', part='both'))
        before = copy.deepcopy(request)
        result = model.evaluate(request)
        self.assertEqual(request, before)
        self.assertIsNotNone(result['steps'][0]['legs']['long']['original_reference']['wire_sha256'])
        result['legs']['short']['original_reference']['wire_sha256'] = None
        self.assertEqual(request, before)

    def test_unknown_top_level_fields_and_authority_flags_refuse(self):
        for name in ('allow_signing', 'authenticated', 'refill_work', 'journal', 'replace_original'):
            request = self.request()
            request[name] = True
            self.refuses(request)

    def test_wrong_top_level_shapes_and_missing_fields_refuse(self):
        for value in (None, [], True, 1, 'request'):
            self.refuses(value)
        for name in self.request():
            request = self.request()
            del request[name]
            self.refuses(request)

    def test_schema_and_expiry_shapes_types_order_and_limits_refuse(self):
        request = self.request()
        request['schema'] = 'unknown'
        self.refuses(request)
        for value in (None, [], {}, dict(long=140), dict(long=140, short=100, other=90)):
            request = self.request()
            request['expires_at'] = value
            self.refuses(request)
        for value in (True, False, 0, -1, 100.0, '140', model.MAX_TIME + 1):
            request = self.request()
            request['expires_at']['long'] = value
            self.refuses(request)
        request = self.request()
        request['expires_at']['long'] = 100
        self.refuses(request)

    def test_work_counts_are_exact_bounded_integers(self):
        for name in ('work_limit', 'unknown_work_charged'):
            for value in (True, False, -1, 1.0, '1', None, model.MAX_WORK + 1):
                request = self.request()
                request[name] = value
                self.refuses(request)
        request = self.request()
        request['work_limit'] = 0
        self.refuses(request)
        request = self.request()
        request['unknown_work_charged'] = 3
        self.refuses(request)

    def test_reference_shapes_and_hex_types_refuse_without_derivation(self):
        for value in (None, [], {}, dict(long={}), dict(long={}, short={}, other={})):
            request = self.request()
            request['original_references'] = value
            self.refuses(request)
        for value in (True, [], {}, 'AA' * 32, 'a' * 63, 'z' * 64, 1):
            request = self.request()
            request['original_references']['long']['wire_sha256'] = value
            self.refuses(request)
        request = self.request()
        request['original_references']['long']['wire_hex'] = '00'
        self.refuses(request)

    def test_unknown_restore_retry_replacement_and_refill_events_refuse(self):
        for kind in ('restore-original', 'refill-work', 'retry', 'sign', 'broadcast', 'recovery-complete'):
            self.refuses(self.request(self.event(kind, 90)))

    def test_event_count_shapes_and_extra_fields_are_bounded(self):
        for value in (None, [], {}, True, [None], [dict(kind='elapsed')]):
            request = self.request()
            request['events'] = value
            self.refuses(request)
        request = self.request(*[self.event('elapsed', n) for n in range(model.MAX_EVENTS)])
        result = model.evaluate(request)
        self.assert_hold(result)
        self.assertLess(len(json.dumps(result).encode('ascii')), 65536)
        request['events'].append(self.event('elapsed', model.MAX_EVENTS))
        self.refuses(request)
        self.refuses(self.request(self.event('elapsed', 90, authority=True)))

    def test_event_times_and_send_times_refuse_invalid_order_and_types(self):
        for value in (None, True, False, '90', 90.0, -1, model.MAX_TIME + 1):
            self.refuses(self.request(self.event('elapsed', value)))
        self.refuses(self.request(self.event('elapsed', 90), self.event('elapsed', 89)))
        for value in (None, True, False, '90', 90.0, -1, 101):
            self.refuses(self.request(self.event('declared-send-confirmed', 100, leg='long', send_timestamp=value)))

    def test_invalid_leg_part_and_missing_event_fields_refuse(self):
        for value in (True, None, [], 'unknown'):
            self.refuses(self.request(self.event('reorg', 90, leg=value)))
            self.refuses(self.request(self.event('original-unavailable', 90, leg='long', part=value)))
        self.refuses(self.request(self.event('reorg', 90)))
        self.refuses(self.request(self.event('declared-send-confirmed', 90, leg='long')))

    def test_changed_send_requires_explicit_model_reorg_and_missing_send_is_not_filled(self):
        self.refuses(self.request(self.event('model-unlock-receive', 90, leg='short')))
        self.refuses(self.request(
            self.event('declared-send-confirmed', 90, leg='short', send_timestamp=89),
            self.event('declared-send-confirmed', 91, leg='short', send_timestamp=90)))

    def test_json_roundtrip_duplicate_keys_nonfinite_values_and_size_cap(self):
        request = self.request()
        raw = json.dumps(request).encode('ascii')
        self.assertEqual(model.evaluate_json(raw), model.evaluate(request))
        duplicate = raw.replace(b'"long":', b'"long":null,"long":', 1)
        for value in (b'', b' ' * (model.MAX_REQUEST + 1), bytearray(raw), 'text',
                duplicate, raw + b'{}', raw.decode('ascii').encode('utf-16'),
                b'null', b'[]', b'\xff', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.assertRaises(ValueError):
                model.evaluate_json(value)

    def test_cli_hold_contains_no_request_path_or_original_wire(self):
        result = self.cli(json.dumps(self.request()).encode('ascii'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_hold(json.loads(result.stdout))
        self.assertNotIn(b'private-request-name', result.stdout + result.stderr)
        self.assertEqual(result.stderr, b'')

    def test_cli_refusal_does_not_echo_private_inputs(self):
        result = self.cli(b'{"private-control":"unknown"}')
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'REFUSED: finite disclosure/timeout trace\n')
        result = self.cli(b'{}', '--unknown-private-argument')
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'REFUSED: finite disclosure/timeout trace\n')

    def test_optimized_execution_cannot_remove_explicit_input_checks(self):
        result = self.cli(b'{"private-control":"unknown"}', python_flags=('-O',))
        self.assertEqual(result.stdout, b'')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'REFUSED: finite disclosure/timeout trace\n')
