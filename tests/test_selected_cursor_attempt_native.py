"""Native checkpoints for cooperative attempt records, never retirement proof."""

from contextlib import closing
import sqlite3
import sys
import weakref

import test_policy_effect_store as prior
import test_selected_cursor_owner as baseline
from selected_cursor_attempt_owner import SelectedCursorAttemptOwner


class SelectedCursorAttemptNativeTests(prior.PolicyEffectStoreCase):
    # Reuse only checkpoint helpers; no prior test method is inherited.
    configure = baseline.SelectedCursorOwnerTests.configure
    peer_exclusive = baseline.SelectedCursorOwnerTests.peer_exclusive
    closed_api = baseline.SelectedCursorOwnerTests.closed_api
    original_checkpoint = baseline.SelectedCursorOwnerTests.original_checkpoint
    retained_original = baseline.SelectedCursorOwnerTests.retained_original

    def native_fixture(self):
        self.assertEqual(sys.implementation.name, "cpython")
        probe = self.path.with_name("selected-cursor-attempt.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)
        events, case_ref = [], weakref.ref(self)

        class ObservedCursor(sqlite3.Cursor):
            def close(inner):
                selected = owner_ref()
                record = next((row for row in selected._records if row.cursor is inner), None)
                if record is not None:
                    case_ref().assertEqual(record.status, "attempted")
                    events.append(("attempt", record.ordinal, selected._phase, record.status))
                else:
                    events.append(("untracked-api", None, selected._phase, None))
                # Observe the same native Cursor object, then delegate once.
                return sqlite3.Cursor.close(inner)

        class ObservedConnection(sqlite3.Connection):
            def cursor(inner):
                return sqlite3.Connection.cursor(inner, factory=ObservedCursor)

        def connect(cache, *, observed=False):
            return sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
                timeout=0, isolation_level=None, detect_types=0, cached_statements=cache,
                factory=ObservedConnection if observed else sqlite3.Connection)

        peer, state = connect(0), dict(peer_closed=False)

        def peer_cleanup():
            if not state["peer_closed"]:
                peer.close()
                state["peer_closed"] = True

        self.addCleanup(peer_cleanup)
        with closing(peer.cursor()) as cursor:
            self.configure(cursor)
            cursor.execute("CREATE TABLE probe(value INTEGER PRIMARY KEY)")
            cursor.executemany("INSERT INTO probe VALUES(?)", [(1,), (2,), (3,)])
        owner, borrowed = SelectedCursorAttemptOwner(lambda: connect(1, observed=True)), []
        owner_ref = weakref.ref(owner)

        def fixture_cleanup():
            if owner._phase == "entered":
                owner.__exit__(None, None, None)
            elif owner._phase == "fresh":
                owner._connection.close()
            borrowed.clear()
            owner._cursors.clear()
            owner._records.clear()

        self.addCleanup(fixture_cleanup)
        snapshot = (self.path.read_bytes(), probe.read_bytes(),
            [(path.stat().st_dev, path.stat().st_ino) for path in (self.path, probe)],
            sorted(item.name for item in self.path.parent.iterdir()))
        return probe, owner, peer, borrowed, snapshot, state, events

    def test_duplicate_admission_returns_with_creation_references_still_retained(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state, events = self.native_fixture()
        primary = OSError("synthetic scope failure")

        def duplicate(record):
            owner._cursors.extend([record, record])

        owner._register = duplicate
        with self.assertRaises(OSError) as caught:
            with owner:
                self.configure(owner.cursor())
                borrowed.extend([owner.cursor(), owner.cursor()])
                for cursor in borrowed:
                    cursor.execute("SELECT value FROM probe ORDER BY value")
                    self.assertEqual(cursor.fetchone(), (1,))
                    self.assertIs(cursor.connection, owner._connection)
                del cursor
                refs = [weakref.ref(row.cursor) for row in owner._records]
                self.assertEqual(len(owner._records), 3)
                self.assertEqual(len(owner._cursors), 6)
                self.assertTrue(all(row.status == "not-attempted" for row in owner._records))
                self.assertFalse(owner._connection.in_transaction)
                self.peer_exclusive(peer, busy=True)
                self.original_checkpoint(original, probe, snapshot)
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        self.assertEqual(events, [("attempt", ordinal, "disposed", "attempted")
            for ordinal in (2, 1, 0)])
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertIsNone(report.admission)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(2, "returned", None), (1, "returned", None), (0, "returned", None)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        self.assertTrue(all(ref() is not None for ref in refs))
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.closed_api(lambda: borrowed[0].fetchone())
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        borrowed.clear()
        owner._cursors.clear()
        self.assertTrue(all(ref() is not None for ref in refs))
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        owner._records.clear()
        self.assertTrue(all(ref() is None for ref in refs))
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(), [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)

    def test_missing_creation_record_keeps_a_native_lock_after_recorded_returns(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state, events = self.native_fixture()
        with owner:
            self.configure(owner.cursor())
            borrowed.append(owner.cursor())
            # This direct native reader deliberately violates creation ownership.
            borrowed.append(owner._connection.cursor())
            for cursor in borrowed:
                cursor.execute("SELECT value FROM probe ORDER BY value")
                self.assertEqual(cursor.fetchone(), (1,))
                self.assertIs(cursor.connection, owner._connection)
            del cursor
            tracked, missing = weakref.ref(borrowed[0]), weakref.ref(borrowed[1])
            self.assertEqual(len(owner._records), 2)
            owner._cursors.clear()
            self.assertEqual(owner._cursors, [])
            self.assertTrue(all(row.status == "not-attempted" for row in owner._records))
            self.peer_exclusive(peer, busy=True)
            self.original_checkpoint(original, probe, snapshot)
        self.assertEqual(events, [("attempt", ordinal, "disposed", "attempted")
            for ordinal in (1, 0)])
        report = owner.report
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(1, "returned", None), (0, "returned", None)])
        self.assertIsNone(report.primary)
        self.assertIsNone(report.admission)
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        self.assertIsNotNone(tracked())
        self.assertIsNotNone(missing())
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.closed_api(lambda: borrowed[1].close())
        self.assertEqual(events[-1], ("untracked-api", None, "disposed", None))
        self.peer_exclusive(peer, busy=True)
        self.original_checkpoint(original, probe, snapshot)
        del borrowed[1]
        self.assertIsNone(missing())
        self.assertIsNotNone(tracked())
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        borrowed.clear()
        owner._records.clear()
        self.assertIsNone(tracked())
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(), [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)
