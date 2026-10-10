"""Deliberately failed creation retention, selected references, never recovery."""

from contextlib import closing
import sqlite3
import sys
import traceback
import weakref

import test_policy_effect_store as prior
import test_selected_cursor_owner as baseline
from selected_cursor_attempt_owner import SelectedCursorAttemptOwner


class SelectedCursorRetentionEscapeNativeTests(prior.PolicyEffectStoreCase):
    # Reuse non-test helpers only; prior test methods are not inherited.
    configure = baseline.SelectedCursorOwnerTests.configure
    peer_exclusive = baseline.SelectedCursorOwnerTests.peer_exclusive
    closed_api = baseline.SelectedCursorOwnerTests.closed_api
    original_checkpoint = baseline.SelectedCursorOwnerTests.original_checkpoint
    retained_original = baseline.SelectedCursorOwnerTests.retained_original

    def native_fixture(self, original, *, primed):
        self.assertEqual(sys.implementation.name, "cpython")
        probe = self.path.with_name("selected-cursor-retention.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)
        events, refs, case_ref = [], [], weakref.ref(self)
        primary = MemoryError("synthetic escape before creation-record insertion")
        state = dict(peer_closed=False, exposed=False, failed_record_ref=None)

        class ObservedCursor(sqlite3.Cursor):
            def close(inner):
                selected = owner_ref()
                record = next(row for row in selected._records if row.cursor is inner)
                case_ref().assertEqual(record.status, "attempted")
                events.append(("close", record.ordinal, selected._phase, record.status))
                return sqlite3.Cursor.close(inner)

        class ObservedConnection(sqlite3.Connection):
            def cursor(inner):
                cursor = sqlite3.Connection.cursor(inner, factory=ObservedCursor)
                ordinal = len(refs)
                refs.append(weakref.ref(cursor))
                events.append(("factory", ordinal))
                if ordinal == 1 and primed:
                    cursor.execute("SELECT value FROM probe ORDER BY value")
                    case_ref().assertEqual(cursor.fetchone(), (1,))
                    events.append(("factory-read", ordinal, 1))
                return cursor

            def close(inner):
                selected = owner_ref()
                events.append(("parent", selected._phase,
                    tuple(row.status for row in selected._records)))
                return sqlite3.Connection.close(inner)

        def connect(cache, *, observed=False):
            return sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
                timeout=0, isolation_level=None, detect_types=0, cached_statements=cache,
                factory=ObservedConnection if observed else sqlite3.Connection)

        peer = connect(0)

        def peer_cleanup():
            if not state["peer_closed"]:
                peer.close()
                state["peer_closed"] = True

        self.addCleanup(peer_cleanup)
        with closing(peer.cursor()) as cursor:
            self.configure(cursor)
            cursor.execute("CREATE TABLE probe(value INTEGER PRIMARY KEY)")
            cursor.executemany("INSERT INTO probe VALUES(?)", [(1,), (2,), (3,)])
        owner = SelectedCursorAttemptOwner(lambda: connect(1, observed=True))
        owner_ref = weakref.ref(owner)
        snapshot = (self.path.read_bytes(), probe.read_bytes(),
            [(path.stat().st_dev, path.stat().st_ino) for path in (self.path, probe)],
            sorted(item.name for item in self.path.parent.iterdir()))

        class FailingCreationRecords(list):
            def append(inner, record):
                if record.ordinal != 1:
                    return super().append(record)
                selected = owner_ref()
                state["failed_record_ref"] = weakref.ref(record)
                case_ref().assertIs(record.cursor, refs[1]())
                case_ref().assertEqual(record.status, "not-attempted")
                case_ref().assertIsNone(record.secondary)
                case_ref().assertEqual(len(inner), 1)
                case_ref().assertEqual(len(selected._cursors), 1)
                case_ref().assertIsNone(selected._pending)
                case_ref().assertIsNone(selected._admission)
                case_ref().assertFalse(state["exposed"])
                case_ref().assertFalse(selected._connection.in_transaction)
                case_ref().peer_exclusive(peer, busy=primed)
                case_ref().original_checkpoint(original, probe, snapshot)
                events.append(("retention-escape", record.ordinal, record.status))
                raise primary

        owner._records = FailingCreationRecords()

        def fixture_cleanup():
            try:
                if owner._phase == "entered":
                    owner.__exit__(None, None, None)
                elif owner._phase == "fresh":
                    owner._connection.close()
            finally:
                if primary.__traceback__ is not None:
                    traceback.clear_frames(primary.__traceback__)
                owner._cursors.clear()
                owner._records.clear()

        self.addCleanup(fixture_cleanup)
        return probe, owner, peer, snapshot, state, events, refs, primary

    def run_scope(self, original, probe, owner, peer, snapshot, state):
        # Preserve raw traceback frames; return only after this frame completes.
        try:
            with owner:
                self.configure(owner.cursor())
                self.assertEqual(len(owner._records), 1)
                self.assertEqual(owner._records[0].status, "not-attempted")
                self.peer_exclusive(peer, busy=False)
                self.original_checkpoint(original, probe, snapshot)
                owner.cursor()
                state["exposed"] = True
        except MemoryError as error:
            return error
        self.fail("deliberate retention escape did not propagate")

    def observe_retention_escape(self, *, primed):
        original = self.store.allocate_synthetic(self.request())
        probe, owner, peer, snapshot, state, events, refs, primary = self.native_fixture(
            original, primed=primed)
        self.original_checkpoint(original, probe, snapshot)
        observed = self.run_scope(original, probe, owner, peer, snapshot, state)
        self.assertIs(observed, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        expected = [("factory", 0), ("factory", 1)]
        if primed:
            expected.append(("factory-read", 1, 1))
        expected += [("retention-escape", 1, "not-attempted"),
            ("close", 0, "disposed", "attempted"), ("parent", "disposed", ("returned",))]
        self.assertEqual(events, expected)
        self.assertFalse(state["exposed"])
        self.assertIsNone(owner._pending)
        self.assertIsNone(owner._admission)
        self.assertEqual(len(owner._records), 1)
        self.assertEqual(len(owner._cursors), 1)
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertIsNone(report.admission)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(0, "returned", None)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        self.assertTrue(all(ref() is not None for ref in refs))
        self.assertEqual(state["failed_record_ref"]().status, "not-attempted")
        self.assertIsNone(state["failed_record_ref"]().secondary)
        self.closed_api(lambda: owner._connection.execute("SELECT 1"))
        self.closed_api(lambda: refs[1]().fetchone())
        self.peer_exclusive(peer, busy=primed)
        self.original_checkpoint(original, probe, snapshot)

        retained_traceback = primary.__traceback__
        names = [frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)]
        self.assertEqual(names, ["run_scope", "cursor", "append"])
        owner._cursors.clear()
        self.assertTrue(all(ref() is not None for ref in refs))
        self.assertIsNotNone(state["failed_record_ref"]())
        self.peer_exclusive(peer, busy=primed)
        self.original_checkpoint(original, probe, snapshot)

        traceback.clear_frames(retained_traceback)
        self.assertIs(primary.__traceback__, retained_traceback)
        self.assertEqual([frame.f_code.co_name for frame, _ in traceback.walk_tb(retained_traceback)],
            names)
        self.assertIsNotNone(refs[0]())
        self.assertIsNone(refs[1]())
        self.assertIsNone(state["failed_record_ref"]())
        self.assertIs(owner.report, report)
        self.assertIs(report.primary, primary)
        self.assertEqual(events, expected)
        self.peer_exclusive(peer, busy=False)
        self.original_checkpoint(original, probe, snapshot)

        owner._records.clear()
        self.assertTrue(all(ref() is None for ref in refs))
        self.assertIs(owner.report, report)
        self.assertEqual(events, expected)
        self.peer_exclusive(peer, busy=False)
        with closing(peer.cursor()) as cursor:
            self.assertEqual(cursor.execute("SELECT value FROM probe ORDER BY value").fetchall(),
                [(1,), (2,), (3,)])
        self.original_checkpoint(original, probe, snapshot)
        peer.close()
        state["peer_closed"] = True
        self.closed_api(lambda: peer.execute("SELECT 1"))
        self.original_checkpoint(original, probe, snapshot)

    def test_idle_unretained_cursor_survives_through_the_primary_traceback_without_a_lock(self):
        self.observe_retention_escape(primed=False)

    def test_primed_unretained_reader_blocks_peer_until_completed_traceback_release(self):
        self.observe_retention_escape(primed=True)
