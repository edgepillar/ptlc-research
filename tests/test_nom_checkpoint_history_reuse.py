"""Finite history comparisons preserve complete validation on every invocation."""
from contextlib import ExitStack
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import nom_checkpoint_discovery as discovery
from scripts import qualify_nom_checkpoint_discovery as fixture


class CheckpointHistoryReuseControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.contexts, cls.retained, cls.refs = fixture.fixture_contexts()
        path = Path(__file__).resolve().parents[1] / 'compatibility/fixtures/nom_checkpoint_history_reference.py.txt'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == '2d0bb5c441c8d315660a7327bf572c8eeaa66771be13337f3eab349e8c64c039'
        namespace = dict(discovery.__dict__)
        exec(compile(raw, path.name, 'exec'), namespace)
        cls.reference = staticmethod(namespace['_history'])

    def test_each_call_completely_validates_every_selected_reference(self):
        protocol = discovery.protocol
        original = protocol.ReferenceCheckpoint.as_dict
        for name, value in self.refs.items():
            with self.subTest(reference=name):
                size = len(self.reference(value))
                actual = [0]

                def complete(instance):
                    actual[0] += 1
                    return original(instance)

                with patch.object(protocol.ReferenceCheckpoint, 'as_dict', new=complete):
                    expected = self.reference(value)
                    self.assertEqual(actual[0], size+1)
                    actual[0] = 0
                    self.assertEqual(discovery._history(value), expected)
                    self.assertEqual(actual[0], size)
                    self.assertEqual(discovery._history(value), expected)
                    self.assertEqual(actual[0], 2*size)

    def test_later_calls_revalidate_after_success_refusal_and_restoration(self):
        root = self.refs['initial']
        expected = discovery._history(root)
        wire = root._policy._wire
        try:
            object.__setattr__(root._policy, '_wire', b'{}')
            with self.assertRaises(discovery.protocol.CheckpointProtocolRefused):
                discovery._history(root)
        finally:
            object.__setattr__(root._policy, '_wire', wire)
        self.assertEqual(discovery._history(root), expected)
        changed = discovery._history(root)
        changed[0]['checkpoint']['sequence'] = 999
        changed[0]['source_context_digest_hex'] = '00'*32
        self.assertEqual(discovery._history(root), expected)

    def test_reused_public_query_revalidates_and_isolates_returned_values(self):
        root = self.refs['initial']
        selected = discovery.checkpoint_read(root, challenge_hex='d1'*32)
        expected = selected.as_dict()
        changed = selected.as_dict()
        original_id = expected['service_selection']['service_id_hex']
        changed['service_selection']['service_id_hex'] = '00'*32 if original_id != '00'*32 else 'ff'*32
        self.assertEqual(selected.as_dict(), expected)
        wire = root._policy._wire
        try:
            object.__setattr__(root._policy, '_wire', b'{}')
            with self.assertRaises(discovery.CheckpointDiscoveryRefused):
                selected.as_dict()
            with self.assertRaises(discovery.CheckpointDiscoveryRefused):
                unused = selected.digest_hex
        finally:
            object.__setattr__(root._policy, '_wire', wire)
        self.assertEqual(selected.as_dict(), expected)

    def test_finite_values_and_exact_refusals_match_without_effectful_operations(self):
        comparisons = []

        def outcome(function, value):
            try:
                return 'VALUE', discovery.codec._canonical(function(value))
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError,
                    OverflowError, UnicodeError) as error:
                return 'REFUSAL', type(error).__name__, str(error)

        def blocked(*args, **kwargs):
            raise AssertionError('pure history comparison attempted an effectful operation')

        def compare(label, value):
            with self.subTest(label=label), ExitStack() as stack:
                for target in ('builtins.open', 'os.open', 'os.write', 'os.fsync', 'subprocess.Popen'):
                    stack.enter_context(patch(target, side_effect=blocked))
                self.assertEqual(outcome(self.reference, value), outcome(discovery._history, value))
                comparisons.append(label)

        for name, value in self.refs.items():
            compare('valid:'+name, value)
        root = self.refs['initial']
        for index, value in enumerate((None, {}, b'', 0, object())):
            compare('foreign:'+str(index), value)
        compare('uninitialized', object.__new__(discovery.protocol.ReferenceCheckpoint))
        for field in ('_policy', '_context', '_prior'):
            value = copy.copy(root)
            object.__delattr__(value, field)
            compare('missing:'+field, value)
            for index, foreign in enumerate(({}, b'', 0, object())):
                value = copy.copy(root)
                object.__setattr__(value, field, foreign)
                compare('foreign:'+field+':'+str(index), value)
        self_cycle = copy.copy(root)
        object.__setattr__(self_cycle, '_prior', self_cycle)
        compare('self-cycle', self_cycle)
        first, second = copy.copy(root), copy.copy(root)
        object.__setattr__(first, '_prior', second)
        object.__setattr__(second, '_prior', first)
        compare('two-node-cycle', first)
        for index, wire in enumerate((b'', b'{}', bytes([255]))):
            value, policy = copy.copy(root), copy.copy(root._policy)
            object.__setattr__(policy, '_wire', wire)
            object.__setattr__(value, '_policy', policy)
            compare('malformed-policy:'+str(index), value)
        wire = root._policy._wire
        try:
            compare('before-mutation', root)
            object.__setattr__(root._policy, '_wire', b'{}')
            compare('after-mutation', root)
        finally:
            object.__setattr__(root._policy, '_wire', wire)
        compare('after-restore', root)
        changed = discovery._history(root)
        changed[0]['checkpoint']['sequence'] = 999
        compare('returned-value-isolated', root)
        self.assertEqual(len(self.refs), 5)
        self.assertEqual(len(comparisons), 35)
