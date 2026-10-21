"""Call-local full validation preserves finite journal-continuation results."""
from contextlib import ExitStack
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import test_nom_capsule_continuity as fixtures
from offline_session import nom_capsule_continuity as continuity


class CapsuleContinuityLocalReuseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ContinuityControls.setUpClass()
        cls.views = fixtures.ContinuityControls.views
        path = Path(__file__).resolve().parents[1] / 'compatibility/fixtures/nom_capsule_continuity_compare_reference.py.txt'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == 'b5e9b6def96ee2bde5e28137561ffe9caf4415aa2e7c2746b2c2761a28de80d7'
        namespace = dict(continuity.__dict__)
        exec(compile(raw, path.name, 'exec'), namespace)
        cls.reference = staticmethod(namespace['_compare'])

    @classmethod
    def tearDownClass(cls):
        fixtures.ContinuityControls.tearDownClass()

    def test_each_call_fully_decodes_each_argument_once(self):
        for old, new, relation, prior_calls in (
                (self.views[0], self.views[-1], 'STRICT_EXTENSION', 8),
                (self.views[-1], self.views[-1], 'EXACT_REPLAY', 10)):
            with self.subTest(relation=relation):
                with patch.object(continuity.capsule, '_decode', wraps=continuity.capsule._decode) as decode:
                    reference = self.reference(old, new)
                    self.assertEqual(decode.call_count, prior_calls)
                with patch.object(continuity.capsule, '_decode', wraps=continuity.capsule._decode) as decode:
                    first = continuity._compare(old, new)
                    self.assertEqual(decode.call_count, 2)
                    second = continuity._compare(old, new)
                    self.assertEqual(decode.call_count, 4)
                self.assertEqual(first, reference)
                self.assertEqual(second, reference)
                self.assertEqual(first['journal_relation'], relation)
                self.assertEqual(first['retained_capsule_sha256'], hashlib.sha256(old._wire).hexdigest())
                self.assertEqual(first['candidate_capsule_sha256'], hashlib.sha256(new._wire).hexdigest())

    def test_later_calls_revalidate_both_arguments_after_success_or_refusal(self):
        old, new = self.views[0], self.views[-1]
        expected = continuity._compare(old, new)
        for selected in (old, new):
            original = selected._wire
            try:
                object.__setattr__(selected, '_wire', b'{}')
                with self.assertRaises(continuity.capsule.CapsuleRefused):
                    continuity._compare(old, new)
            finally:
                object.__setattr__(selected, '_wire', original)
            self.assertEqual(continuity._compare(old, new), expected)

    def test_reused_review_refuses_changed_bytes_and_isolates_returned_values(self):
        old, new = self.views[0], self.views[-1]
        selected = continuity.compare_continuation(old, new.canonical_bytes,
            expected_candidate_digest_hex=new.digest_hex)
        expected = selected.review()
        changed = selected.review()
        changed['state'] = 'SYNTHETIC_MUTATION'
        changed['candidate_charged_work'] = 999
        self.assertEqual(selected.review(), expected)
        original = selected._candidate._wire
        try:
            object.__setattr__(selected._candidate, '_wire', b'{}')
            with self.assertRaises(continuity.ContinuityRefused):
                selected.review()
            with self.assertRaises(continuity.ContinuityRefused):
                unused = selected.digest_hex
        finally:
            object.__setattr__(selected._candidate, '_wire', original)
        self.assertEqual(selected.review(), expected)
        self.assertEqual(expected['state'], 'HOLD')
        self.assertEqual(expected['recovery_action'], 'NONE')

    def test_finite_values_and_refusals_match_the_frozen_reference_without_io(self):
        helper = fixtures.ContinuityControls()
        helper.views = self.views
        last = self.views[-1]
        renewed = fixtures.qualification.from_journal(last.journal_bytes, challenge_hex='b2'*32)
        reformatted = fixtures.qualification.from_journal(last.journal_bytes.replace(b'\n', b'\r\n'),
            challenge_hex='a1'*32)
        charged = helper.rewritten(0, lambda events: events.append(dict(kind='recovery-admitted')))
        divergent = helper.rewritten(3, lambda events: events.insert(2, copy.deepcopy(events[1])))
        comparisons = []

        def outcome(function, old, new):
            try:
                value = function(old, new)
                return 'VALUE', json_wire(value)
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
                    OverflowError, UnicodeError) as error:
                return 'REFUSAL', type(error).__name__, str(error)

        def json_wire(value):
            return continuity.json.dumps(value, sort_keys=True, separators=(',', ':'),
                ensure_ascii=True, allow_nan=False).encode('ascii')

        def blocked(*args, **kwargs):
            raise AssertionError('pure continuation comparison attempted IO')

        def compare(label, old, new):
            with self.subTest(label=label), ExitStack() as stack:
                for target in ('builtins.open', 'os.open', 'os.write', 'os.fsync'):
                    stack.enter_context(patch(target, side_effect=blocked))
                self.assertEqual(outcome(self.reference, old, new),
                    outcome(continuity._compare, old, new))
                comparisons.append(label)

        for old_index, old in enumerate(self.views):
            for new_index, new in enumerate(self.views):
                compare(str(old_index)+':'+str(new_index), old, new)
        for name, old, new in (
                ('renewed', last, renewed), ('renewed-reverse', renewed, last),
                ('reformatted', last, reformatted), ('reformatted-reverse', reformatted, last),
                ('new-charge', self.views[0], charged), ('new-charge-reverse', charged, self.views[0]),
                ('divergent', last, divergent), ('divergent-reverse', divergent, last)):
            compare(name, old, new)
        for index, wire in enumerate((b'', b'{}', b'[]', b'null', b'not-json',
                bytes([255]), b'{"schema":0}', b' '+last._wire)):
            malformed = object.__new__(continuity.capsule.CapsuleView)
            object.__setattr__(malformed, '_wire', wire)
            compare('malformed-retained:'+str(index), malformed, last)
            compare('malformed-candidate:'+str(index), last, malformed)
        absent = object.__new__(continuity.capsule.CapsuleView)
        compare('absent-retained', absent, last)
        compare('absent-candidate', last, absent)
        for index, foreign in enumerate((None, {}, last._wire, object())):
            compare('foreign-retained:'+str(index), foreign, last)
            compare('foreign-candidate:'+str(index), last, foreign)
        compare('before-mutation', self.views[0], last)
        original = last._wire
        try:
            object.__setattr__(last, '_wire', b'{}')
            compare('after-mutation', self.views[0], last)
        finally:
            object.__setattr__(last, '_wire', original)
        compare('after-restore', self.views[0], last)
        value = continuity._compare(self.views[0], last)
        value['recovery_action'] = 'SYNTHETIC_MUTATION'
        compare('returned-value-isolated', self.views[0], last)
        self.assertEqual(len(comparisons), 54)
