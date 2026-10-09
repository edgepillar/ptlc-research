"""Callback return is not native release or authority to recover an operation."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import sqlite3
import sys

import test_policy_effect_constructor_paths as paths
import test_policy_effect_store as prior
from qualification.selected_cleanup import SelectedFailureCleanup


class SelectedCleanupNoopTests(prior.PolicyEffectStoreCase):
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

    def closed_readback(self, native):
        with self.assertRaises(sqlite3.ProgrammingError) as closed:
            native.execute("SELECT 1")
        self.assertIs(type(closed.exception), sqlite3.ProgrammingError)
        self.assertIsNone(closed.exception.__context__)
        self.assertIsNone(closed.exception.__cause__)
        self.assertFalse(closed.exception.__suppress_context__)

    def selected(self, rollback_mode, forward_close=False):
        reservation = self.path.with_name("selected-noop-reservation.sqlite3")
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point="as_uri",
            primary=OSError(errno.EIO, "synthetic-initial-uri-failure"),
            actor_entry=False, created=True)
        original_bytes, reserved_bytes = self.path.read_bytes(), reservation.read_bytes()
        self.assertEqual(reserved_bytes, b"")
        identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        entries = sorted(item.name for item in self.path.parent.iterdir())
        primary = OSError(errno.EIO, "synthetic-diagnostic-marker-primary")
        secondary = OSError(errno.EIO, "synthetic-diagnostic-marker-rollback") if rollback_mode == "escape" else None
        native = sqlite3.connect(reservation.as_uri() + "?mode=rw", uri=True,
            timeout=0, isolation_level=None, detect_types=0)
        state = dict(owned=True)
        counts = dict(begin=0, rollback_callback=0, native_rollback=0,
            close_callback=0, native_close=0, fixture_close=0)
        events, callback_active, close_transaction, fixture_transaction = [], [], [], []

        def fixture_close():
            if state["owned"]:
                fixture_transaction.append(native.in_transaction)
                native.close()
                counts["fixture_close"] += 1
                state["owned"] = False

        self.addCleanup(fixture_close)
        self.assertEqual(native.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        native.execute("PRAGMA synchronous=EXTRA")
        native.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(native.execute("PRAGMA synchronous").fetchone(), (3,))
        self.assertEqual(native.execute("PRAGMA foreign_keys").fetchone(), (1,))

        def rollback():
            counts["rollback_callback"] += 1
            events.append("rollback-callback")
            callback_active.append(sys.exc_info()[1])
            if secondary is not None:
                raise secondary
            if rollback_mode == "forward":
                native.execute("ROLLBACK")
                counts["native_rollback"] += 1
                events.append("native-rollback-returned")
            return "synthetic-untrusted-rollback-claim"

        def close():
            counts["close_callback"] += 1
            events.append("close-callback")
            callback_active.append(sys.exc_info()[1])
            if forward_close:
                close_transaction.append(native.in_transaction)
                native.close()
                counts["native_close"] += 1
                state["owned"] = False
                events.append("native-close-returned")
            return "synthetic-untrusted-release-claim"

        guard = SelectedFailureCleanup(rollback, close)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(OSError) as caught:
                with guard:
                    native.execute("BEGIN IMMEDIATE")
                    counts["begin"] += 1
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        report = guard.report
        self.assertIs(report.primary, primary)
        self.assertIs(report.rollback_secondary, secondary)
        self.assertIsNone(report.close_secondary)
        self.assertEqual(report.rollback_status, "escaped" if secondary is not None else "returned")
        self.assertEqual(report.close_status, "returned")
        if secondary is not None:
            self.assertIs(secondary.__context__, primary)
            self.assertIsNone(secondary.__cause__)
            self.assertFalse(secondary.__suppress_context__)
        self.assertEqual(callback_active, [primary, primary])
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        for marker in ("synthetic-diagnostic-marker", "synthetic-untrusted"):
            self.assertNotIn(marker, repr(report))
        forwarded_rollback = rollback_mode == "forward"
        expected = dict(begin=1, rollback_callback=1, native_rollback=int(forwarded_rollback),
            close_callback=1, native_close=int(forward_close), fixture_close=0)
        self.assertEqual(counts, expected)
        expected_events = ["rollback-callback"]
        if forwarded_rollback:
            expected_events.append("native-rollback-returned")
        expected_events.append("close-callback")
        if forward_close:
            expected_events.append("native-close-returned")
        self.assertEqual(events, expected_events)
        self.assertEqual(close_transaction, [not forwarded_rollback] if forward_close else [])
        self.assertEqual(fixture_transaction, [])
        owned, active = not forward_close, not forwarded_rollback
        self.assertIs(state["owned"], owned)
        if owned:
            self.assertEqual(native.execute("SELECT 1").fetchone(), (1,))
            self.assertIs(native.in_transaction, active)
        else:
            self.closed_readback(native)
        journal = reservation.with_name(reservation.name + "-journal")
        self.assertEqual(journal.exists(), owned and active)
        expected_entries = sorted(entries + [journal.name]) if owned and active else entries
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), expected_entries)
        self.assertEqual(reservation.read_bytes(), reserved_bytes)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.original_readback()
        fixture_close()
        expected["fixture_close"] = int(owned)
        self.assertEqual(counts, expected)
        self.assertEqual(fixture_transaction, [active] if owned else [])
        self.assertFalse(state["owned"])
        self.assertIs(guard.report, report)
        self.closed_readback(native)
        self.assertFalse(journal.exists())
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        self.assertEqual(reservation.read_bytes(), reserved_bytes)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.original_readback()

    def test_returned_callbacks_without_native_calls_leave_active_owned_handle(self):
        self.selected("noop")

    def test_forwarded_rollback_and_returned_noop_close_leave_inactive_owned_handle(self):
        self.selected("forward")

    def test_escaped_rollback_and_returned_noop_close_preserve_primary_and_active_handle(self):
        self.selected("escape")

    def test_forwarded_callbacks_supply_separate_native_release_comparison(self):
        self.selected("forward", forward_close=True)
