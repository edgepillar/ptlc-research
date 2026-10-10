"""Injected pre-native escapes and selected reference paths, never recovery."""

from contextlib import closing
import sqlite3
import sys
import traceback
import weakref

import test_policy_effect_store as prior
import test_selected_cursor_owner as baseline
from selected_cursor_attempt_owner import SelectedCursorAttemptOwner


class SelectedCursorPrecloseEscapeNativeTests(prior.PolicyEffectStoreCase):
    # Reuse only checkpoint helpers; no prior test method is inherited.
    configure = baseline.SelectedCursorOwnerTests.configure
    peer_exclusive = baseline.SelectedCursorOwnerTests.peer_exclusive
    closed_api = baseline.SelectedCursorOwnerTests.closed_api
    original_checkpoint = baseline.SelectedCursorOwnerTests.original_checkpoint
    retained_original = baseline.SelectedCursorOwnerTests.retained_original

    def native_fixture(self):
        self.assertEqual(sys.implementation.name, "cpython")
        probe = self.path.with_name("selected-cursor-preclose.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)
        events, case_ref = [], weakref.ref(self)
        secondary = OSError("synthetic escape before native cursor close")

        class ObservedCursor(sqlite3.Cursor):
            def close(inner):
                selected = owner_ref()
                record = next(row for row in selected._records if row.cursor is inner)
                case_ref().assertEqual(record.status, "attempted")
                events.append(("attempt", record.ordinal, selected._phase, record.status))
                if record.ordinal == 2:
                    events.append(("injected", record.ordinal, "before-native"))
                    raise secondary
                events.append(("native", record.ordinal))
                return sqlite3.Cursor.close(inner)

        class ObservedConnection(sqlite3.Connection):
            def cursor(inner):
                return sqlite3.Connection.cursor(inner, factory=ObservedCursor)

            def close(inner):
                selected = owner_ref()
                events.append(("parent", selected._phase,
                    tuple(row.status for row in selected._records)))
                return sqlite3.Connection.close(inner)

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
            try:
                if owner._phase == "entered":
                    owner.__exit__(None, None, None)
                elif owner._phase == "fresh":
                    owner._connection.close()
            finally:
                if secondary.__traceback__ is not None:
                    traceback.clear_frames(secondary.__traceback__)
                borrowed.clear()
                owner._cursors.clear()
                owner._records.clear()

        self.addCleanup(fixture_cleanup)
        snapshot = (self.path.read_bytes(), probe.read_bytes(),
            [(path.stat().st_dev, path.stat().st_ino) for path in (self.path, probe)],
            sorted(item.name for item in self.path.parent.iterdir()))
        return probe, owner, peer, borrowed, snapshot, state, events, secondary

    def run_scope(self, owner, peer, borrowed, original, probe, snapshot, primary=None):
        # Catch without unittest's traceback stripping; this frame then completes.
        try:
            with owner:
                self.configure(owner.cursor())
                borrowed.extend([owner.cursor(), owner.cursor()])
                for cursor in borrowed:
                    cursor.execute("SELECT value FROM probe ORDER BY value")
                    self.assertEqual(cursor.fetchone(), (1,))
                    self.assertIs(cursor.connection, owner._connection)
                del cursor
                refs = [weakref.ref(row.cursor) for row in owner._records]
                self.assertTrue(all(row.status == "not-attempted" for row in owner._records))
                self.assertFalse(owner._connection.in_transaction)
                self.peer_exclusive(peer, busy=True)
                self.original_checkpoint(original, probe, snapshot)
                if primary is not None:
                    raise primary
        except OSError as error:
            return error, refs
        self.fail("selected escape did not propagate")

    def disposal_checkpoint(self, owner, peer, borrowed, refs, events, secondary, primary):
        self.assertEqual(events, [("attempt", 2, "disposed", "attempted"),
            ("injected", 2, "before-native"), ("attempt", 1, "disposed", "attempted"),
            ("native", 1), ("attempt", 0, "disposed", "attempted"), ("native", 0),
            ("parent", "disposed", ("returned", "returned", "escaped"))])
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertIsNone(report.admission)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(2, "escaped", secondary), (1, "returned", None), (0, "returned", None)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        self.assertEqual(owner._records[2].status, "escaped")
        self.assertIs(owner._records[2].secondary, secondary)
        self.assertIs(secondary.__context__, primary)
        self.assertIsNone(secondary.__cause__)
        self.assertFalse(secondary.__suppress_context__)
        self.assertTrue(all(ref() is not None for ref in refs))
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.closed_api(lambda: borrowed[1].fetchone())
        self.peer_exclusive(peer, busy=True)
        return report

    def final_checkpoints(self, original, probe, snapshot, peer, state):
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(),
                [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)

    def test_scope_primary_preserves_a_traceback_held_reader_after_alias_release(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state, events, secondary = self.native_fixture()
        primary = OSError("synthetic scope failure")
        propagated, refs = self.run_scope(owner, peer, borrowed, original, probe, snapshot, primary)
        self.assertIs(propagated, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        report = self.disposal_checkpoint(owner, peer, borrowed, refs, events, secondary, primary)
        self.original_checkpoint(original, probe, snapshot)
        retained_traceback = secondary.__traceback__
        names = [frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)]
        self.assertEqual(names, ["_attempt", "close"])
        exit_frame = retained_traceback.tb_frame.f_back
        self.assertEqual(exit_frame.f_code.co_name, "__exit__")
        borrowed.clear()
        owner._cursors.clear()
        owner._records.clear()
        self.assertIsNotNone(refs[0]())
        self.assertIsNone(refs[1]())
        self.assertIsNotNone(refs[2]())
        self.peer_exclusive(peer, busy=True)
        self.original_checkpoint(original, probe, snapshot)
        # Deliberately release completed frame locals, retaining the traceback chain.
        traceback.clear_frames(retained_traceback)
        self.assertIs(secondary.__traceback__, retained_traceback)
        self.assertEqual([frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)], names)
        self.assertIsNotNone(refs[0]())
        self.assertTrue(all(ref() is None for ref in refs[1:]))
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)
        # The traceback back-link still retains the completed disposal frame.
        exit_frame.clear()
        self.assertTrue(all(ref() is None for ref in refs))
        self.assertIs(owner.report, report)
        self.assertIs(report.cursors[0].secondary, secondary)
        self.assertEqual(len(events), 7)
        self.final_checkpoints(original, probe, snapshot, peer, state)

    def test_normal_exit_keeps_a_borrowed_reader_after_traceback_frame_release(self):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, borrowed, snapshot, state, events, secondary = self.native_fixture()
        propagated, refs = self.run_scope(owner, peer, borrowed, original, probe, snapshot)
        self.assertIs(propagated, secondary)
        report = self.disposal_checkpoint(owner, peer, borrowed, refs, events, secondary, None)
        self.original_checkpoint(original, probe, snapshot)
        retained_traceback = secondary.__traceback__
        names = [frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)]
        self.assertEqual(names, ["run_scope", "__exit__", "_attempt", "close"])
        owner._cursors.clear()
        owner._records.clear()
        traceback.clear_frames(retained_traceback)
        self.assertIs(secondary.__traceback__, retained_traceback)
        self.assertEqual([frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)], names)
        self.assertIsNone(refs[0]())
        self.assertTrue(all(ref() is not None for ref in refs[1:]))
        self.peer_exclusive(peer, busy=True)
        self.original_checkpoint(original, probe, snapshot)
        borrowed.clear()
        self.assertTrue(all(ref() is None for ref in refs))
        self.assertIs(owner.report, report)
        self.assertIs(report.cursors[0].secondary, secondary)
        self.assertEqual(len(events), 7)
        self.final_checkpoints(original, probe, snapshot, peer, state)
