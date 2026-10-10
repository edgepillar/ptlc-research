"""Selected cooperative ownership, missing admission and exception priority."""

from contextlib import closing
import sqlite3
import sys
import weakref

import test_policy_effect_store as prior
from selected_cursor_owner import SelectedCursorOwner


class SelectedCursorOwnerTests(prior.PolicyEffectStoreCase):
    def original_checkpoint(self, original, probe, snapshot):
        original_bytes, probe_bytes, identities, entries = snapshot
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.assertEqual(probe.read_bytes(), probe_bytes)
        self.assertEqual([(path.stat().st_dev, path.stat().st_ino)
            for path in (self.path, probe)], identities)
        self.assertEqual([path.stat().st_mode & 0o777 for path in (self.path, probe)], [0o600, 0o600])
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        self.retained_original(original)

    def retained_original(self, original):
        request = self.request()
        local = prior.allocation_state(self.store, [request])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(request), original)
            after = prior.allocation_state(reopened, [request])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def native_fixture(self):
        self.assertEqual(sys.implementation.name, "cpython")
        probe = self.path.with_name("selected-cursor-owner.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)

        def connect(cache):
            return sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
                timeout=0, isolation_level=None, detect_types=0, cached_statements=cache)

        peer = connect(0)
        state = dict(peer_closed=False)

        def peer_cleanup():
            if not state["peer_closed"]:
                peer.close()
                state["peer_closed"] = True

        self.addCleanup(peer_cleanup)
        with closing(peer.cursor()) as cursor:
            self.configure(cursor)
            cursor.execute("CREATE TABLE probe(value INTEGER PRIMARY KEY)")
            cursor.executemany("INSERT INTO probe VALUES(?)", [(1,), (2,), (3,)])
        owner, borrowed = SelectedCursorOwner(lambda: connect(1)), []

        def fixture_cleanup():
            if owner._phase == "entered":
                owner.__exit__(None, None, None)
            elif owner._phase == "fresh":
                owner._connection.close()
            borrowed.clear()
            owner._cursors.clear()

        self.addCleanup(fixture_cleanup)
        snapshot = (self.path.read_bytes(), probe.read_bytes(),
            [(path.stat().st_dev, path.stat().st_ino) for path in (self.path, probe)],
            sorted(item.name for item in self.path.parent.iterdir()))
        return probe, owner, peer, borrowed, snapshot, state

    def configure(self, cursor):
        for statement, expected in (("PRAGMA journal_mode=DELETE", ("delete",)),
                ("PRAGMA synchronous=EXTRA", None), ("PRAGMA foreign_keys=ON", None),
                ("PRAGMA synchronous", (3,)), ("PRAGMA foreign_keys", (1,)),
                ("PRAGMA busy_timeout", (0,))):
            cursor.execute(statement)
            self.assertEqual(cursor.fetchone(), expected)

    def peer_exclusive(self, peer, *, busy):
        self.assertFalse(peer.in_transaction)
        with closing(peer.cursor()) as cursor:
            if busy:
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    cursor.execute("BEGIN EXCLUSIVE")
                error = caught.exception
                self.assertIs(type(error), sqlite3.OperationalError)
                self.assertEqual(error.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                self.assertEqual(error.sqlite_errorname, "SQLITE_BUSY")
                self.assertIsNone(error.__context__)
                self.assertIsNone(error.__cause__)
                self.assertFalse(error.__suppress_context__)
                self.assertFalse(peer.in_transaction)
            else:
                cursor.execute("BEGIN EXCLUSIVE")
                self.assertTrue(peer.in_transaction)
                cursor.execute("ROLLBACK")
                self.assertFalse(peer.in_transaction)

    def closed_api(self, operation):
        with self.assertRaises(sqlite3.ProgrammingError) as caught:
            operation()
        self.assertIs(type(caught.exception), sqlite3.ProgrammingError)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertFalse(caught.exception.__suppress_context__)

    def test_admitted_native_readers_close_before_parent_with_primary_retained(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state = self.native_fixture()
        primary = OSError("synthetic scope failure")
        with self.assertRaises(OSError) as caught:
            with owner:
                self.configure(owner.cursor())
                borrowed.extend([owner.cursor(), owner.cursor()])
                for cursor in borrowed:
                    cursor.execute("SELECT value FROM probe ORDER BY value")
                    self.assertEqual(cursor.fetchone(), (1,))
                    self.assertIs(cursor.connection, owner._connection)
                del cursor
                refs = [weakref.ref(cursor) for cursor in owner._cursors]
                self.assertFalse(owner._connection.in_transaction)
                self.peer_exclusive(peer, busy=True)
                self.original_checkpoint(original, probe, snapshot)
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(2, "returned", None), (1, "returned", None), (0, "returned", None)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        self.assertIsNone(report.admission)
        self.assertTrue(all(ref() is not None for ref in refs))
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        borrowed.clear()
        owner._cursors.clear()
        self.assertTrue(all(ref() is None for ref in refs))
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(), [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)

    def test_unregistered_native_reader_remains_a_negative_ownership_boundary(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state = self.native_fixture()
        with owner:
            self.configure(owner.cursor())
            borrowed.append(owner.cursor())
            # This deliberate bypass violates the selected cooperative premise.
            borrowed.append(owner._connection.cursor())
            for cursor in borrowed:
                cursor.execute("SELECT value FROM probe ORDER BY value")
                self.assertEqual(cursor.fetchone(), (1,))
            del cursor
            tracked, missing = weakref.ref(borrowed[0]), weakref.ref(borrowed[1])
            self.assertEqual(len(owner._cursors), 2)
            self.peer_exclusive(peer, busy=True)
            self.original_checkpoint(original, probe, snapshot)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in owner.report.cursors],
            [(1, "returned", None), (0, "returned", None)])
        self.assertIsNone(owner.report.primary)
        self.assertEqual(owner.report.connection_status, "returned")
        self.assertIsNone(owner.report.connection_secondary)
        self.assertIsNone(owner.report.admission)
        self.assertIsNotNone(tracked())
        self.assertIsNotNone(missing())
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.closed_api(lambda: borrowed[1].close())
        self.peer_exclusive(peer, busy=True)
        self.original_checkpoint(original, probe, snapshot)
        del borrowed[1]
        self.assertIsNone(missing())
        self.assertIsNotNone(tracked())
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        borrowed.clear()
        owner._cursors.clear()
        self.assertIsNone(tracked())
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(), [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)

    def test_registration_failure_never_exposes_or_retries_the_pending_handle(self):
        original = self.store.allocate_synthetic(self.request())
        before = self.path.read_bytes()
        events = []
        primary = MemoryError("synthetic registration failure before mutation")
        secondary = OSError("synthetic pending close failure")

        class Cursor:
            def close(inner):
                events.append("pending-close")
                raise secondary

        pending = Cursor()

        class Connection:
            def cursor(inner):
                events.append("create")
                return pending

            def close(inner):
                events.append("parent-close")

        owner = SelectedCursorOwner(Connection)

        def refuse(cursor):
            events.append("registration-refused")
            raise primary

        owner._register = refuse
        with self.assertRaises(MemoryError) as caught:
            with owner:
                owner.cursor()
                events.append("exposed")
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        self.assertEqual(events, ["create", "registration-refused", "pending-close", "parent-close"])
        self.assertEqual(owner._cursors, [])
        self.assertIs(owner._pending, pending)
        self.assertEqual(owner.report.cursors, ())
        self.assertIs(owner.report.primary, primary)
        self.assertIs(owner.report.admission.primary, primary)
        self.assertEqual(owner.report.admission.close_status, "escaped")
        self.assertIs(owner.report.admission.secondary, secondary)
        self.assertEqual(owner.report.connection_status, "returned")
        self.assertIsNone(owner.report.connection_secondary)
        self.assertEqual(self.path.read_bytes(), before)
        self.retained_original(original)

    def test_cleanup_escapes_preserve_primary_or_surface_first_on_normal_exit(self):
        original = self.store.allocate_synthetic(self.request())
        before = self.path.read_bytes()
        for primary in (OSError("synthetic scope failure"), None):
            with self.subTest(scope_failed=primary is not None):
                events = []
                cursor_error = OSError("synthetic cursor close failure")
                parent_error = OSError("synthetic parent close failure")

                class Cursor:
                    def __init__(inner, ordinal):
                        inner.ordinal = ordinal

                    def close(inner):
                        events.append(("cursor-close", inner.ordinal))
                        if inner.ordinal == 1:
                            raise cursor_error

                class Connection:
                    def __init__(inner):
                        inner.next = 0

                    def cursor(inner):
                        cursor = Cursor(inner.next)
                        inner.next += 1
                        events.append(("create", cursor.ordinal))
                        return cursor

                    def close(inner):
                        events.append(("parent-close", None))
                        raise parent_error

                owner = SelectedCursorOwner(Connection)
                with self.assertRaises(OSError) as caught:
                    with owner:
                        owner.cursor()
                        owner.cursor()
                        if primary is not None:
                            raise primary
                self.assertIs(caught.exception, primary if primary is not None else cursor_error)
                self.assertEqual(events, [("create", 0), ("create", 1),
                    ("cursor-close", 1), ("cursor-close", 0), ("parent-close", None)])
                self.assertIs(owner.report.primary, primary)
                self.assertEqual([(row.ordinal, row.status) for row in owner.report.cursors],
                    [(1, "escaped"), (0, "returned")])
                self.assertIs(owner.report.cursors[0].secondary, cursor_error)
                self.assertIsNone(owner.report.cursors[1].secondary)
                self.assertIs(owner.report.connection_secondary, parent_error)
                self.assertEqual(owner.report.connection_status, "escaped")
                self.assertIsNone(owner.report.admission)
                self.assertEqual(self.path.read_bytes(), before)
                self.retained_original(original)
