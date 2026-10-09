"""Selected non-SQLite rollback boundaries; observations do not authorize recovery."""

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


class PolicyEffectReservationSecondaryRollbackTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def interruption(self, primary_kind, secondary_kind, timing, actor_entry):
        reservation = self.path.with_name("retained-secondary-rollback.sqlite3")
        first = OSError(errno.EIO, "synthetic-selected-initial-uri-failure")
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point="as_uri",
            primary=first, actor_entry=False, created=True)
        before = self.path.read_bytes()
        entries = sorted(item.name for item in self.path.parent.iterdir())
        reserved_before = reservation.read_bytes()
        self.assertEqual(reserved_before, b"")
        identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        primary = sqlite3.OperationalError("synthetic-selected-begin-error") if primary_kind == "sqlite" else OSError(errno.EIO, "synthetic-selected-begin-error") if primary_kind == "os" else KeyboardInterrupt("synthetic-selected-begin-cancellation")
        secondary = OSError(errno.EIO, "synthetic-selected-rollback-error") if secondary_kind == "os" else KeyboardInterrupt("synthetic-selected-rollback-cancellation")
        forwarded = timing == "after-native-rollback"
        store_class, real_connect = source.OfflinePolicyEffectStore, sqlite3.connect
        partial = store_class.__new__(store_class)
        counts = dict(constructor=0, returned=0, connect=0, dispose=0,
            begin_attempt=0, native_begin=0, rollback_helper=0, rollback_attempt=0,
            native_rollback=0, wrapper_close=0, native_close_calls=0,
            owned_release=0, fixture_native_close=0, allocation=0, public_close=0)
        connections, disposals, statements = [], [], []
        rollback_results, rollback_errors, disposal_busy_states = [], [], []
        close_transaction_states, fixture_transaction_states = [], []
        output = io.StringIO()

        class ForwardingConnection:
            def __init__(self, native):
                self.native, self.owned = native, True

            def __getattr__(self, name):
                return getattr(self.native, name)

            def execute(self, sql, *args):
                statements.append(sql)
                if sql == "BEGIN IMMEDIATE":
                    counts["begin_attempt"] += 1
                    self.native.execute(sql, *args)
                    counts["native_begin"] += 1
                    raise primary
                if sql == "ROLLBACK":
                    counts["rollback_attempt"] += 1
                    if not forwarded:
                        raise secondary
                    self.native.execute(sql, *args)
                    counts["native_rollback"] += 1
                    raise secondary
                return self.native.execute(sql, *args)

            def close(self):
                counts["wrapper_close"] += 1
                if self.owned:
                    close_transaction_states.append(self.native.in_transaction)
                self.native.close()
                counts["native_close_calls"] += 1
                counts["owned_release"] += int(self.owned)
                self.owned = False

        def cleanup_fixture():
            for connection in connections:
                if connection.owned:
                    fixture_transaction_states.append(connection.native.in_transaction)
                    connection.native.close()
                    counts["fixture_native_close"] += 1
                    connection.owned = False

        self.addCleanup(cleanup_fixture)

        def connect(*args, **kwargs):
            counts["connect"] += 1
            connection = ForwardingConnection(real_connect(*args, **kwargs))
            connections.append(connection)
            return connection

        def rollback():
            counts["rollback_helper"] += 1
            try:
                result = store_class._rollback(partial)
            except BaseException as error:
                rollback_errors.append(error)
                raise
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

        expected = source.StoreOutcomeUnknown if forwarded and secondary_kind == "os" else type(secondary)
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
        self.assertIs(secondary.__context__, primary)
        self.assertIsNone(secondary.__cause__)
        self.assertFalse(secondary.__suppress_context__)
        self.assertIsNot(caught.exception, primary)
        if forwarded and secondary_kind == "os":
            self.assertIs(type(caught.exception), source.StoreOutcomeUnknown)
            self.assertIs(caught.exception.__context__, secondary)
            self.assertIsNone(caught.exception.__cause__)
            self.assertTrue(caught.exception.__suppress_context__)
        else:
            self.assertIs(caught.exception, secondary)
        self.assertEqual(disposals, [secondary])
        self.assertEqual(len(disposal_busy_states), 1)
        self.assertIs(disposal_busy_states[0], False)
        self.assertEqual(len(rollback_errors), 1 if forwarded else 2)
        for error in rollback_errors:
            self.assertIs(error, secondary)
        self.assertEqual(len(rollback_results), int(forwarded))
        if forwarded:
            self.assertIs(rollback_results[0], True)
        expected_counts = dict(constructor=1, returned=0, connect=1, dispose=1,
            begin_attempt=1, native_begin=1, rollback_helper=2,
            rollback_attempt=1 if forwarded else 2, native_rollback=int(forwarded),
            wrapper_close=int(forwarded), native_close_calls=int(forwarded),
            owned_release=int(forwarded), fixture_native_close=0, allocation=0, public_close=0)
        self.assertEqual(counts, expected_counts)
        self.assertEqual(close_transaction_states, [False] if forwarded else [])
        self.assertEqual(fixture_transaction_states, [])
        self.assertEqual(statements.count("BEGIN IMMEDIATE"), 1)
        self.assertEqual(statements.count("ROLLBACK"), expected_counts["rollback_attempt"])
        self.assertEqual(statements.count("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"), 0)
        self.assertEqual(len(connections), 1)
        self.assertIs(partial._db, connections[0])
        self.assertIs(partial._closed, forwarded)
        self.assertIs(partial._busy, False)
        self.assertEqual(partial._labels, prior.LABELS)
        self.assertEqual(partial._owner, (os.getpid(), threading.get_ident()))
        self.assertIs(connections[0].owned, not forwarded)
        if not forwarded:
            self.assertIs(connections[0].native.in_transaction, True)
            self.assertEqual(connections[0].native.execute("SELECT 1").fetchone(), (1,))
        if actor_entry:
            self.assertEqual(output.getvalue(), "")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(reservation.read_bytes(), reserved_before)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        journal = reservation.with_name(reservation.name + "-journal")
        expected_entries = entries if forwarded else sorted(entries + [journal.name])
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), expected_entries)
        if not forwarded:
            self.assertTrue(journal.is_file())
            self.assertFalse(journal.is_symlink())
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        else:
            self.assertFalse(journal.exists())
        cleanup_fixture()
        expected_counts["fixture_native_close"] = int(not forwarded)
        self.assertEqual(counts, expected_counts)
        self.assertEqual(fixture_transaction_states, [True] if not forwarded else [])
        self.assertFalse(connections[0].owned)
        # Fixture release is not constructor cleanup or a protocol recovery step.
        self.assertIs(partial._closed, forwarded)
        self.assertIs(partial._busy, False)
        with self.assertRaises(sqlite3.ProgrammingError) as closed:
            connections[0].native.execute("SELECT 1")
        self.assertIs(type(closed.exception), sqlite3.ProgrammingError)
        self.assertIsNone(closed.exception.__context__)
        self.assertIsNone(closed.exception.__cause__)
        self.assertFalse(closed.exception.__suppress_context__)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(reservation.read_bytes(), reserved_before)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        self.assertFalse(journal.exists())
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_direct_sqlite_os_before_native_rollback(self):
        self.interruption("sqlite", "os", "before-native-rollback", False)

    def test_actor_sqlite_os_before_native_rollback(self):
        self.interruption("sqlite", "os", "before-native-rollback", True)

    def test_direct_sqlite_os_after_native_rollback(self):
        self.interruption("sqlite", "os", "after-native-rollback", False)

    def test_actor_sqlite_os_after_native_rollback(self):
        self.interruption("sqlite", "os", "after-native-rollback", True)

    def test_direct_sqlite_cancellation_before_native_rollback(self):
        self.interruption("sqlite", "cancellation", "before-native-rollback", False)

    def test_actor_sqlite_cancellation_before_native_rollback(self):
        self.interruption("sqlite", "cancellation", "before-native-rollback", True)

    def test_direct_sqlite_cancellation_after_native_rollback(self):
        self.interruption("sqlite", "cancellation", "after-native-rollback", False)

    def test_actor_sqlite_cancellation_after_native_rollback(self):
        self.interruption("sqlite", "cancellation", "after-native-rollback", True)

    def test_direct_os_os_before_native_rollback(self):
        self.interruption("os", "os", "before-native-rollback", False)

    def test_actor_os_os_before_native_rollback(self):
        self.interruption("os", "os", "before-native-rollback", True)

    def test_direct_os_os_after_native_rollback(self):
        self.interruption("os", "os", "after-native-rollback", False)

    def test_actor_os_os_after_native_rollback(self):
        self.interruption("os", "os", "after-native-rollback", True)

    def test_direct_os_cancellation_before_native_rollback(self):
        self.interruption("os", "cancellation", "before-native-rollback", False)

    def test_actor_os_cancellation_before_native_rollback(self):
        self.interruption("os", "cancellation", "before-native-rollback", True)

    def test_direct_os_cancellation_after_native_rollback(self):
        self.interruption("os", "cancellation", "after-native-rollback", False)

    def test_actor_os_cancellation_after_native_rollback(self):
        self.interruption("os", "cancellation", "after-native-rollback", True)

    def test_direct_cancellation_os_before_native_rollback(self):
        self.interruption("cancellation", "os", "before-native-rollback", False)

    def test_actor_cancellation_os_before_native_rollback(self):
        self.interruption("cancellation", "os", "before-native-rollback", True)

    def test_direct_cancellation_os_after_native_rollback(self):
        self.interruption("cancellation", "os", "after-native-rollback", False)

    def test_actor_cancellation_os_after_native_rollback(self):
        self.interruption("cancellation", "os", "after-native-rollback", True)

    def test_direct_cancellation_cancellation_before_native_rollback(self):
        self.interruption("cancellation", "cancellation", "before-native-rollback", False)

    def test_actor_cancellation_cancellation_before_native_rollback(self):
        self.interruption("cancellation", "cancellation", "before-native-rollback", True)

    def test_direct_cancellation_cancellation_after_native_rollback(self):
        self.interruption("cancellation", "cancellation", "after-native-rollback", False)

    def test_actor_cancellation_cancellation_after_native_rollback(self):
        self.interruption("cancellation", "cancellation", "after-native-rollback", True)
