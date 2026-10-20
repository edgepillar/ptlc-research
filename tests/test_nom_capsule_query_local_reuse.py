"""Call-local validation reuse preserves finite retained-query comparisons."""
from contextlib import ExitStack
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import test_nom_capsule_query as fixtures
from offline_session import nom_capsule_query as binding


class CapsuleQueryLocalReuseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.CapsuleQueryControls.setUpClass()
        cls.views = fixtures.CapsuleQueryControls.views
        path = Path(__file__).resolve().parents[1] / 'compatibility/fixtures/nom_capsule_query_fields_reference.py.txt'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '957e4e03eaab4a7142be8d66df6e8f25f7a6386f54c9d742f58423edbbb4f60f'
        namespace = dict(binding.__dict__)
        exec(compile(raw, path.name, 'exec'), namespace)
        cls.reference = staticmethod(namespace['_fields'])

    @classmethod
    def tearDownClass(cls):
        fixtures.CapsuleQueryControls.tearDownClass()

    def setUp(self):
        self.retained = self.views[-1]
        self.selection = fixtures.qualification.read_selection(self.retained)
        self.query = binding.authority.read_query(**self.selection)

    def test_each_call_performs_one_complete_capsule_decode(self):
        with patch.object(binding.capsule, '_decode', wraps=binding.capsule._decode) as decode:
            first = binding._fields(self.retained, self.query)
            self.assertEqual(decode.call_count, 1)
            second = binding._fields(self.retained, self.query)
            self.assertEqual(decode.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(first['capsule_sha256'], hashlib.sha256(self.retained._wire).hexdigest())

    def test_later_calls_revalidate_bytes_after_success_or_refusal(self):
        original = self.retained._wire
        expected = binding._fields(self.retained, self.query)
        try:
            object.__setattr__(self.retained, '_wire', b'{}')
            with self.assertRaises(binding.capsule.CapsuleRefused):
                binding._fields(self.retained, self.query)
        finally:
            object.__setattr__(self.retained, '_wire', original)
        self.assertEqual(binding._fields(self.retained, self.query), expected)

    def test_returned_charges_do_not_mutate_later_results(self):
        result = binding._fields(self.retained, self.query)
        expected = copy.deepcopy(result)
        result['charged_work'].append(dict(synthetic_alias='not-retained'))
        self.assertEqual(binding._fields(self.retained, self.query), expected)

    def test_finite_values_and_refusals_match_the_frozen_reference(self):
        variants = {name:copy.deepcopy(self.selection) for name in
            ('baseline', 'renewed-challenge', 'false-disclosure', 'different-long')}
        variants['renewed-challenge']['challenge_hex'] = '47'*32
        variants['false-disclosure']['consumer_selection']['disclosure_possible'] = False
        variants['different-long']['originals']['long'] = binding.recovery.synthetic_claim(
            self.selection['terms'], 'long', '00'*64)
        queries = {name:binding.authority.read_query(**value) for name,value in variants.items()}
        comparisons = []

        def outcome(function, retained, query):
            try:
                return 'VALUE', binding.codec._canonical(function(retained, query))
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
                    OverflowError, UnicodeError) as error:
                return 'REFUSAL', type(error).__name__, str(error)

        def blocked(*args, **kwargs):
            raise AssertionError('pure field comparison attempted IO')

        def compare(label, retained, query):
            with self.subTest(label=label), ExitStack() as stack:
                for target in ('builtins.open', 'os.open', 'os.write', 'os.fsync'):
                    stack.enter_context(patch(target, side_effect=blocked))
                self.assertEqual(outcome(self.reference, retained, query),
                    outcome(binding._fields, retained, query))
                comparisons.append(label)

        for index, retained in enumerate(self.views):
            for name, query in queries.items():
                compare(str(index)+':'+name, retained, query)
        for index, wire in enumerate((b'', b'{}', b'[]', b'null', b'not-json',
                bytes([255]), b'{"schema":0}', b' '+self.retained._wire)):
            retained = object.__new__(binding.capsule.CapsuleView)
            object.__setattr__(retained, '_wire', wire)
            compare('malformed-wire:'+str(index), retained, queries['baseline'])
        compare('before-mutation', self.retained, self.query)
        original = self.retained._wire
        try:
            object.__setattr__(self.retained, '_wire', b'{}')
            compare('after-mutation', self.retained, self.query)
        finally:
            object.__setattr__(self.retained, '_wire', original)
        compare('after-restore', self.retained, self.query)
        value = binding._fields(self.retained, self.query)
        value['charged_work'].append(dict(synthetic_alias='not-retained'))
        compare('returned-value-isolated', self.retained, self.query)
        self.assertEqual(len(comparisons), 28)
