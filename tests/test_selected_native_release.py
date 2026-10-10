"""Closed connection APIs and selected native lock release are separate evidence."""

import sqlite3
import sys
import weakref

import test_policy_effect_store as prior


class SelectedNativeReleaseTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def original_readback(self):
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def closed_api(self, operation):
        with self.assertRaises(sqlite3.ProgrammingError) as caught:
            operation()
        self.assertIs(type(caught.exception), sqlite3.ProgrammingError)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertFalse(caught.exception.__suppress_context__)

    def selected(self, *, cursor_first):
        self.assertEqual(sys.implementation.name, "cpython")
        probe = self.path.with_name("selected-native-release.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)
        owner = sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
            timeout=0, isolation_level=None, detect_types=0, cached_statements=0)
        peer, held = None, []
        state = dict(owner_closed=False, peer_closed=False)
        counts = dict(owner_close=0, cursor_close_before=0, cursor_close_after_refused=0,
            busy=0, exclusive=0, reference_release=0, fixture_owner_close=0, fixture_peer_close=0)

        def fixture_cleanup():
            if not state["owner_closed"]:
                for cursor in held:
                    cursor.close()
                owner.close()
                state["owner_closed"] = True
                counts["fixture_owner_close"] += 1
            held.clear()
            if peer is not None and not state["peer_closed"]:
                peer.close()
                state["peer_closed"] = True
                counts["fixture_peer_close"] += 1

        self.addCleanup(fixture_cleanup)
        peer = sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
            timeout=0, isolation_level=None, detect_types=0, cached_statements=0)
        for connection in (owner, peer):
            self.assertEqual(connection.execute("PRAGMA journal_mode=DELETE").fetchone(), ("delete",))
            connection.execute("PRAGMA synchronous=EXTRA")
            connection.execute("PRAGMA foreign_keys=ON")
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone(), (3,))
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
            self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone(), (0,))
        owner.execute("CREATE TABLE probe(value INTEGER PRIMARY KEY)")
        owner.executemany("INSERT INTO probe VALUES(?)", [(1,), (2,), (3,)])
        original_bytes, probe_bytes = self.path.read_bytes(), probe.read_bytes()
        identity = (probe.stat().st_dev, probe.stat().st_ino)
        entries = sorted(item.name for item in self.path.parent.iterdir())
        held.append(owner.execute("SELECT value FROM probe ORDER BY value"))
        self.assertEqual(held[0].fetchone(), (1,))
        reference = weakref.ref(held[0])
        self.assertFalse(owner.in_transaction)
        observations = []

        def exclusive(phase, *, busy):
            self.assertFalse(peer.in_transaction)
            if busy:
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    peer.execute("BEGIN EXCLUSIVE")
                self.assertIs(type(caught.exception), sqlite3.OperationalError)
                self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                self.assertEqual(caught.exception.sqlite_errorname, "SQLITE_BUSY")
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                self.assertFalse(caught.exception.__suppress_context__)
                self.assertFalse(peer.in_transaction)
                counts["busy"] += 1
                observations.append((phase, "SQLITE_BUSY"))
            else:
                peer.execute("BEGIN EXCLUSIVE")
                self.assertTrue(peer.in_transaction)
                peer.execute("ROLLBACK")
                self.assertFalse(peer.in_transaction)
                counts["exclusive"] += 1
                observations.append((phase, "returned"))

        def checkpoint():
            self.assertEqual(probe.read_bytes(), probe_bytes)
            self.assertEqual((probe.stat().st_dev, probe.stat().st_ino), identity)
            self.assertEqual(probe.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
            self.assertEqual(self.path.read_bytes(), original_bytes)
            self.original_readback()

        exclusive("reader-live", busy=True)
        if cursor_first:
            self.assertIsNone(held[0].close())
            counts["cursor_close_before"] += 1
        self.assertIsNone(owner.close())
        state["owner_closed"] = True
        counts["owner_close"] += 1
        self.closed_api(lambda: owner.execute("SELECT 1"))
        if not cursor_first:
            self.closed_api(lambda: held[0].close())
            counts["cursor_close_after_refused"] += 1
        self.assertIsNotNone(reference())
        exclusive("connection-close-returned", busy=not cursor_first)
        checkpoint()

        # This explicit fixture reference release is not recovery or authority.
        held.clear()
        counts["reference_release"] += 1
        self.assertIsNone(reference())
        exclusive("owned-cursor-reference-released", busy=False)
        self.closed_api(lambda: owner.execute("SELECT 1"))
        checkpoint()
        self.assertEqual(peer.execute("SELECT value FROM probe ORDER BY value").fetchall(),
            [(1,), (2,), (3,)])
        self.assertEqual(observations, [("reader-live", "SQLITE_BUSY"),
            ("connection-close-returned", "returned" if cursor_first else "SQLITE_BUSY"),
            ("owned-cursor-reference-released", "returned")])
        expected = dict(owner_close=1, cursor_close_before=int(cursor_first),
            cursor_close_after_refused=int(not cursor_first), busy=1 if cursor_first else 2,
            exclusive=2 if cursor_first else 1, reference_release=1,
            fixture_owner_close=0, fixture_peer_close=0)
        self.assertEqual(counts, expected)
        fixture_cleanup()
        expected["fixture_peer_close"] = 1
        self.assertEqual(counts, expected)
        self.assertEqual(state, dict(owner_closed=True, peer_closed=True))
        self.closed_api(lambda: peer.execute("SELECT 1"))
        checkpoint()

    def test_closed_connection_retains_reader_lock_until_owned_cursor_reference_release(self):
        self.selected(cursor_first=False)

    def test_cursor_close_before_connection_close_supplies_lock_release_comparison(self):
        self.selected(cursor_first=True)
