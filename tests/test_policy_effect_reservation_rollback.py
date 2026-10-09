"""In-process controls for selected retained reservation compound rollback interruptions."""

import errno
import io
import json
import os
import sqlite3
import sys
import threading
from unittest.mock import patch

import policy_effect_store_actor as actor
import test_policy_effect_constructor_paths as paths
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectReservationRollbackTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def interruption(self, kind, timing, actor_entry):
        reservation = self.path.with_name("retained-rollback.sqlite3")
        first = OSError(errno.EIO, "synthetic-selected-initial-uri-failure")
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point="as_uri",
            primary=first, actor_entry=False, created=True)
        before = self.path.read_bytes()
        entries = sorted(item.name for item in self.path.parent.iterdir())
        reserved_before = reservation.read_bytes()
        self.assertEqual(reserved_before, b"")
        identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        primary = sqlite3.OperationalError("synthetic-selected-begin-error") if kind == "sqlite" else OSError(errno.EIO, "synthetic-selected-begin-error") if kind == "os" else KeyboardInterrupt("synthetic-selected-begin-cancellation")
        rollback_primary = sqlite3.OperationalError("synthetic-selected-rollback-error")
        store_class, real_connect = source.OfflinePolicyEffectStore, sqlite3.connect
        partial = store_class.__new__(store_class)
        counts = dict(constructor=0, returned=0, connect=0, dispose=0,
            begin_attempt=0, native_begin=0, rollback_helper=0, rollback_attempt=0, native_rollback=0, wrapper_close=0,
            native_close_calls=0, owned_release=0, idempotent_close=0, fixture_native_close=0, allocation=0, public_close=0)
        connections, disposals, statements, first_close_transaction_states = [], [], [], []
        rollback_results, disposal_busy_states, closed_transaction_refusals = [], [], []
        output = io.StringIO()

        class ForwardingConnection:
            def __init__(self, native):
                self.native, self.owned = native, True

            def __getattr__(self, name):
                return getattr(self.native, name)

            @property
            def in_transaction(self):
                try:
                    return self.native.in_transaction
                except sqlite3.ProgrammingError as error:
                    closed_transaction_refusals.append(error)
                    raise

            def execute(self, sql, *args):
                statements.append(sql)
                if sql == "BEGIN IMMEDIATE":
                    counts["begin_attempt"] += 1
                    self.native.execute(sql, *args)
                    counts["native_begin"] += 1
                    raise primary
                if sql == "ROLLBACK":
                    counts["rollback_attempt"] += 1
                    if timing == "before-native-rollback":
                        raise rollback_primary
                    self.native.execute(sql, *args)
                    counts["native_rollback"] += 1
                    raise rollback_primary
                return self.native.execute(sql, *args)

            def close(self):
                counts["wrapper_close"] += 1
                owned = self.owned
                if owned:
                    first_close_transaction_states.append(self.native.in_transaction)
                self.native.close()
                counts["native_close_calls"] += 1
                counts["owned_release" if owned else "idempotent_close"] += 1
                self.owned = False

        def connect(*args, **kwargs):
            counts["connect"] += 1
            connection = ForwardingConnection(real_connect(*args, **kwargs))
            connections.append(connection)
            def cleanup():
                if connection.owned:
                    connection.native.close()
                    counts["fixture_native_close"] += 1
                    connection.owned = False
            self.addCleanup(cleanup)
            return connection

        def rollback():
            counts["rollback_helper"] += 1
            result = store_class._rollback(partial)
            rollback_results.append(result)
            return result

        def dispose():
            counts["dispose"] += 1
            disposals.append(sys.exc_info()[1])
            disposal_busy_states.append(partial._busy)
            return store_class._dispose(partial)

        def close():
            counts["public_close"] += 1
            return store_class.close(partial)

        def allocate(request):
            counts["allocation"] += 1
            return store_class.allocate_synthetic(partial, request)

        def construct(path, labels):
            counts["constructor"] += 1
            partial._rollback = rollback
            partial._dispose, partial.close, partial.allocate_synthetic = dispose, close, allocate
            store_class.__init__(partial, path, labels)
            counts["returned"] += 1
            return partial

        expected = KeyboardInterrupt if kind == "cancellation" else source.StoreOutcomeUnknown
        with patch.object(source.sqlite3, "connect", side_effect=connect), \
                patch.object(actor, "ObservedConnection", wraps=actor.ObservedConnection) as observer:
            with self.assertRaises(expected) as caught:
                if actor_entry:
                    request = self.request()
                    context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                        revision=0, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
                    argv = ["synthetic-actor", str(reservation), "allocation", "unused", "direct", "native-execute-errors-v1"]
                    with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                            patch.object(sys, "argv", argv), patch.object(sys, "stdout", output), \
                            patch.object(sys, "stdin", io.StringIO(json.dumps(context) + "\n")):
                        actor.main()
                else:
                    construct(str(reservation), prior.LABELS)
            observer.assert_not_called()
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        if kind == "cancellation":
            self.assertIs(caught.exception, primary)
        else:
            self.assertIs(type(caught.exception), source.StoreOutcomeUnknown)
            self.assertIs(caught.exception.__context__, primary)
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(disposals, [primary, caught.exception])
        self.assertIs(rollback_primary.__context__, primary)
        self.assertIsNone(rollback_primary.__cause__)
        self.assertFalse(rollback_primary.__suppress_context__)
        forwarded = int(timing == "after-native-rollback")
        attempts = 1 if forwarded else 2
        self.assertEqual(len(rollback_results), 3)
        for actual, expected_result in zip(rollback_results, [False, bool(forwarded), False]):
            self.assertIs(actual, expected_result)
        self.assertEqual(len(disposal_busy_states), 2)
        self.assertIs(disposal_busy_states[0], True)
        self.assertIs(disposal_busy_states[1], False)
        self.assertEqual(len(closed_transaction_refusals), 1)
        closed_error = closed_transaction_refusals[0]
        self.assertIs(type(closed_error), sqlite3.ProgrammingError)
        self.assertIs(closed_error.__context__, caught.exception)
        self.assertIsNone(closed_error.__cause__)
        self.assertFalse(closed_error.__suppress_context__)
        self.assertEqual(counts, dict(constructor=1, returned=0, connect=1, dispose=2,
            begin_attempt=1, native_begin=1, rollback_helper=3, rollback_attempt=attempts, native_rollback=forwarded,
            wrapper_close=2, native_close_calls=2, owned_release=1, idempotent_close=1,
            fixture_native_close=0, allocation=0, public_close=0))
        self.assertEqual(first_close_transaction_states, [not bool(forwarded)])
        self.assertEqual(statements.count("BEGIN IMMEDIATE"), 1)
        self.assertEqual(statements.count("ROLLBACK"), attempts)
        self.assertEqual(statements.count("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"), 0)
        self.assertEqual(len(connections), 1)
        self.assertIs(partial._db, connections[0])
        self.assertTrue(partial._closed)
        self.assertFalse(partial._busy)
        self.assertEqual(partial._labels, prior.LABELS)
        self.assertEqual(partial._owner, (os.getpid(), threading.get_ident()))
        self.assertFalse(connections[0].owned)
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].native.execute("SELECT 1")
        if actor_entry:
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(reservation.read_bytes(), reserved_before)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_direct_sqlite_before_native_rollback(self):
        self.interruption("sqlite", "before-native-rollback", False)

    def test_actor_sqlite_before_native_rollback(self):
        self.interruption("sqlite", "before-native-rollback", True)

    def test_direct_sqlite_after_native_rollback(self):
        self.interruption("sqlite", "after-native-rollback", False)

    def test_actor_sqlite_after_native_rollback(self):
        self.interruption("sqlite", "after-native-rollback", True)

    def test_direct_os_before_native_rollback(self):
        self.interruption("os", "before-native-rollback", False)

    def test_actor_os_before_native_rollback(self):
        self.interruption("os", "before-native-rollback", True)

    def test_direct_os_after_native_rollback(self):
        self.interruption("os", "after-native-rollback", False)

    def test_actor_os_after_native_rollback(self):
        self.interruption("os", "after-native-rollback", True)

    def test_direct_cancellation_before_native_rollback(self):
        self.interruption("cancellation", "before-native-rollback", False)

    def test_actor_cancellation_before_native_rollback(self):
        self.interruption("cancellation", "before-native-rollback", True)

    def test_direct_cancellation_after_native_rollback(self):
        self.interruption("cancellation", "after-native-rollback", False)

    def test_actor_cancellation_after_native_rollback(self):
        self.interruption("cancellation", "after-native-rollback", True)
