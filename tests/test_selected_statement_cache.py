"""A selected statement cache size is not a native subordinate-handle bound."""

import sqlite3
import sys
import weakref

import test_policy_effect_store as prior


class SelectedStatementCacheTests(prior.PolicyEffectStoreCase):
    def original_readback(self, original):
        request = self.request()
        local = prior.allocation_state(self.store, [request])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(request), original)
            after = prior.allocation_state(reopened, [request])
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

    def test_one_cache_entry_does_not_bound_two_live_same_sql_readers(self):
        self.assertEqual(sys.implementation.name, "cpython")
        original = self.store.allocate_synthetic(self.request())
        probe = self.path.with_name("selected-statement-cache.sqlite3")
        probe.touch(mode=0o600, exist_ok=False)
        owner = sqlite3.connect(probe.as_uri() + "?mode=rw", uri=True,
            timeout=0, isolation_level=None, detect_types=0, cached_statements=1)
        peer, held = None, []
        state = dict(owner_closed=False, peer_closed=False)
        counts = dict(owner_close=0, cursor_close=0, cursor_close_after_refused=0,
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
        identities = [(path.stat().st_dev, path.stat().st_ino) for path in (self.path, probe)]
        entries = sorted(item.name for item in self.path.parent.iterdir())
        statement = "SELECT value FROM probe ORDER BY value"
        held.extend([owner.execute(statement), owner.execute(statement)])
        self.assertIsNot(held[0], held[1])
        self.assertIs(held[0].connection, owner)
        self.assertIs(held[1].connection, owner)
        self.assertEqual(held[0].fetchone(), (1,))
        self.assertEqual(held[1].fetchone(), (1,))
        self.assertEqual(held[0].fetchone(), (2,))
        first, second = weakref.ref(held[0]), weakref.ref(held[1])
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
            self.assertEqual(self.path.read_bytes(), original_bytes)
            self.assertEqual(probe.read_bytes(), probe_bytes)
            self.assertEqual([(path.stat().st_dev, path.stat().st_ino)
                for path in (self.path, probe)], identities)
            self.assertEqual([path.stat().st_mode & 0o777 for path in (self.path, probe)], [0o600, 0o600])
            self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
            self.original_readback(original)

        exclusive("two-live-cursors", busy=True)
        self.assertIsNone(held[0].close())
        counts["cursor_close"] += 1
        self.assertIsNotNone(first())
        self.assertEqual(held[1].fetchone(), (2,))
        self.assertFalse(owner.in_transaction)
        exclusive("one-cursor-closed", busy=True)
        checkpoint()

        self.assertIsNone(owner.close())
        state["owner_closed"] = True
        counts["owner_close"] += 1
        self.closed_api(lambda: owner.execute("SELECT 1"))
        self.closed_api(lambda: held[1].close())
        counts["cursor_close_after_refused"] += 1
        self.assertIsNotNone(first())
        self.assertIsNotNone(second())
        exclusive("connection-close-returned", busy=True)
        checkpoint()

        # Explicit fixture reference release is not a cleanup contract or authority.
        del held[1]
        counts["reference_release"] += 1
        self.assertIsNone(second())
        self.assertIsNotNone(first())
        exclusive("remaining-reader-reference-released", busy=False)
        checkpoint()
        held.clear()
        counts["reference_release"] += 1
        self.assertIsNone(first())
        exclusive("closed-cursor-reference-released", busy=False)
        checkpoint()
        self.assertEqual(peer.execute(statement).fetchall(), [(1,), (2,), (3,)])
        self.assertEqual(observations, [("two-live-cursors", "SQLITE_BUSY"),
            ("one-cursor-closed", "SQLITE_BUSY"), ("connection-close-returned", "SQLITE_BUSY"),
            ("remaining-reader-reference-released", "returned"),
            ("closed-cursor-reference-released", "returned")])
        expected = dict(owner_close=1, cursor_close=1, cursor_close_after_refused=1,
            busy=3, exclusive=2, reference_release=2, fixture_owner_close=0, fixture_peer_close=0)
        self.assertEqual(counts, expected)
        fixture_cleanup()
        expected["fixture_peer_close"] = 1
        self.assertEqual(counts, expected)
        self.closed_api(lambda: peer.execute("SELECT 1"))
        checkpoint()
