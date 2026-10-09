"""Selected disposal faults separate constructor flags from native handle state."""

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


class PolicyEffectReservationDisposalTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def fault(self, kind, timing, actor_entry):
        reservation = self.path.with_name("retained-disposal.sqlite3")
        first = OSError(errno.EIO, "synthetic-selected-initial-uri-failure")
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point="as_uri",
            primary=first, actor_entry=False, created=True)
        before, entries = self.path.read_bytes(), sorted(item.name for item in self.path.parent.iterdir())
        reserved_before = reservation.read_bytes()
        self.assertEqual(reserved_before, b"")
        identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        secondary = sqlite3.OperationalError("synthetic-selected-disposal-error") if kind == "sqlite" else OSError(errno.EIO, "synthetic-selected-disposal-error") if kind == "os" else KeyboardInterrupt("synthetic-selected-disposal-cancellation")
        store_class, real_connect = source.OfflinePolicyEffectStore, sqlite3.connect
        partial = store_class.__new__(store_class)
        counts = dict(constructor=0, returned=0, connect=0, dispose=0,
            wrapper_close=0, native_close=0, fixture_native_close=0, allocation=0, public_close=0)
        connections, disposals, statements = [], [], []
        output = io.StringIO()

        class ForwardingConnection:
            def __init__(self, native):
                self.native, self.owned = native, True

            def __getattr__(self, name):
                return getattr(self.native, name)

            def execute(self, sql, *args):
                statements.append(sql)
                return self.native.execute(sql, *args)

            def close(self):
                counts["wrapper_close"] += 1
                if timing == "before-native-close":
                    raise secondary
                self.native.close()
                counts["native_close"] += 1
                self.owned = False
                raise secondary

        def connect(*args, **kwargs):
            counts["connect"] += 1
            connection = ForwardingConnection(real_connect(*args, **kwargs))
            connections.append(connection)
            def cleanup():
                if connection.owned:
                    connection.native.close()
                    counts["fixture_native_close"] += 1
                    connection.owned = False
            connection.release = cleanup
            self.addCleanup(cleanup)
            return connection

        def dispose():
            counts["dispose"] += 1
            disposals.append(sys.exc_info()[1])
            return store_class._dispose(partial)

        def close():
            counts["public_close"] += 1
            return store_class.close(partial)

        def allocate(request):
            counts["allocation"] += 1
            return store_class.allocate_synthetic(partial, request)

        def construct(path, labels):
            counts["constructor"] += 1
            partial._dispose, partial.close, partial.allocate_synthetic = dispose, close, allocate
            store_class.__init__(partial, path, labels)
            counts["returned"] += 1
            return partial

        expected = source.StoreRefused if kind == "sqlite" else type(secondary)
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
        self.assertEqual(len(disposals), 1)
        primary = disposals[0]
        self.assertIs(type(primary), source.StoreRefused)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        self.assertIs(secondary.__context__, primary)
        self.assertIsNone(secondary.__cause__)
        self.assertFalse(secondary.__suppress_context__)
        self.assertIs(caught.exception, primary if kind == "sqlite" else secondary)
        self.assertEqual(counts, dict(constructor=1, returned=0, connect=1, dispose=1,
            wrapper_close=1, native_close=int(timing == "after-native-close"), fixture_native_close=0, allocation=0, public_close=0))
        self.assertEqual(len(connections), 1)
        self.assertIs(partial._db, connections[0])
        self.assertEqual(partial._closed, kind == "sqlite")
        self.assertFalse(partial._busy)
        self.assertEqual(partial._labels, prior.LABELS)
        self.assertEqual(partial._owner, (os.getpid(), threading.get_ident()))
        self.assertEqual(connections[0].owned, timing == "before-native-close")
        if timing == "before-native-close":
            self.assertEqual(connections[0].native.execute("SELECT 1").fetchone(), (1,))
        else:
            with self.assertRaises(sqlite3.ProgrammingError):
                connections[0].native.execute("SELECT 1")
        self.assertEqual(statements.count("BEGIN IMMEDIATE"), 1)
        self.assertEqual(statements.count("ROLLBACK"), 1)
        self.assertEqual(statements.count("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"), 1)
        if actor_entry:
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(prior.allocation_reply("unavailable", b"", b""),
                dict(exit_code="unavailable", response_class="empty", stderr_present=False))
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
        # Release only the native handle still owned by the fixture, after readback.
        connections[0].release()
        self.assertEqual(counts["fixture_native_close"], int(timing == "before-native-close"))
        self.assertFalse(connections[0].owned)
        self.assertEqual(counts["wrapper_close"], 1)
        self.assertEqual(counts["native_close"], int(timing == "after-native-close"))
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].native.execute("SELECT 1")
        self.assertEqual(partial._closed, kind == "sqlite")
        self.assertIs(secondary.__context__, primary)

    def test_direct_sqlite_before_native_close(self):
        self.fault('sqlite', 'before-native-close', False)

    def test_actor_sqlite_before_native_close(self):
        self.fault('sqlite', 'before-native-close', True)

    def test_direct_sqlite_after_native_close(self):
        self.fault('sqlite', 'after-native-close', False)

    def test_actor_sqlite_after_native_close(self):
        self.fault('sqlite', 'after-native-close', True)

    def test_direct_os_before_native_close(self):
        self.fault('os', 'before-native-close', False)

    def test_actor_os_before_native_close(self):
        self.fault('os', 'before-native-close', True)

    def test_direct_os_after_native_close(self):
        self.fault('os', 'after-native-close', False)

    def test_actor_os_after_native_close(self):
        self.fault('os', 'after-native-close', True)

    def test_direct_cancellation_before_native_close(self):
        self.fault('cancellation', 'before-native-close', False)

    def test_actor_cancellation_before_native_close(self):
        self.fault('cancellation', 'before-native-close', True)

    def test_direct_cancellation_after_native_close(self):
        self.fault('cancellation', 'after-native-close', False)

    def test_actor_cancellation_after_native_close(self):
        self.fault('cancellation', 'after-native-close', True)
