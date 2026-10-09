"""Native selected cleanup controls; observations grant no recovery authority."""

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import sqlite3
import sys

import test_policy_effect_constructor_paths as paths
import test_policy_effect_store as prior
from qualification.selected_cleanup import CleanupSelectionRefused, SelectedFailureCleanup


class SelectedFailureCleanupTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def selected(self, primary_kind="os", rollback_kind="os", rollback_timing="before",
            close_kind=None, close_timing="before", fail=True):
        reservation = self.path.with_name("selected-cleanup-reservation.sqlite3")
        first = OSError(errno.EIO, "synthetic-selected-initial-uri-failure")
        paths.PolicyEffectConstructorPathTests.failure(self, reservation, point="as_uri",
            primary=first, actor_entry=False, created=True)
        original_bytes, reserved_bytes = self.path.read_bytes(), reservation.read_bytes()
        self.assertEqual(reserved_bytes, b"")
        identity = (reservation.stat().st_dev, reservation.stat().st_ino)
        entries = sorted(item.name for item in self.path.parent.iterdir())
        primary = sqlite3.OperationalError("synthetic-diagnostic-marker-first") if primary_kind == "sqlite" else OSError(errno.EIO, "synthetic-diagnostic-marker-first") if primary_kind == "os" else KeyboardInterrupt("synthetic-diagnostic-marker-first")
        secondary = None if rollback_kind is None else OSError(errno.EIO, "synthetic-diagnostic-marker-rollback") if rollback_kind == "os" else KeyboardInterrupt("synthetic-diagnostic-marker-rollback")
        close_error = None if close_kind is None else sqlite3.OperationalError("synthetic-diagnostic-marker-close") if close_kind == "sqlite" else OSError(errno.EIO, "synthetic-diagnostic-marker-close") if close_kind == "os" else KeyboardInterrupt("synthetic-diagnostic-marker-close")
        rollback_forwarded = rollback_kind is None or rollback_timing == "after"
        close_forwarded = close_kind is None or close_timing == "after"
        native = sqlite3.connect(reservation.as_uri() + "?mode=rw", uri=True,
            timeout=0, isolation_level=None, detect_types=0)
        state = dict(owned=True)
        counts = dict(begin=0, rollback_callback=0, native_rollback=0,
            close_callback=0, native_close=0, fixture_close=0)
        events, rollback_active, close_active = [], [], []
        close_transaction, fixture_transaction = [], []

        def cleanup_fixture():
            if state["owned"]:
                fixture_transaction.append(native.in_transaction)
                native.close()
                counts["fixture_close"] += 1
                state["owned"] = False

        self.addCleanup(cleanup_fixture)
        self.assertEqual(native.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        native.execute("PRAGMA synchronous=EXTRA")
        native.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(native.execute("PRAGMA synchronous").fetchone(), (3,))
        self.assertEqual(native.execute("PRAGMA foreign_keys").fetchone(), (1,))

        def rollback():
            counts["rollback_callback"] += 1
            events.append("rollback-attempt")
            rollback_active.append(sys.exc_info()[1])
            if secondary is not None and not rollback_forwarded:
                raise secondary
            native.execute("ROLLBACK")
            counts["native_rollback"] += 1
            events.append("native-rollback-returned")
            if secondary is not None:
                raise secondary
            return "synthetic-nonauthoritative-return-value"

        def close():
            counts["close_callback"] += 1
            events.append("close-attempt")
            close_active.append(sys.exc_info()[1])
            if close_error is not None and not close_forwarded:
                raise close_error
            close_transaction.append(native.in_transaction)
            native.close()
            counts["native_close"] += 1
            state["owned"] = False
            events.append("native-close-returned")
            if close_error is not None:
                raise close_error
            return "synthetic-nonauthoritative-return-value"

        guard = SelectedFailureCleanup(rollback, close)
        initial = guard.report
        self.assertEqual((initial.rollback_status, initial.close_status),
            ("not-attempted", "not-attempted"))
        self.assertIsNone(initial.primary)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if fail:
                with self.assertRaises(type(primary)) as caught:
                    with guard as entered:
                        self.assertIs(entered, guard)
                        native.execute("BEGIN IMMEDIATE")
                        counts["begin"] += 1
                        raise primary
                self.assertIs(caught.exception, primary)
                self.assertIsNone(primary.__context__)
                self.assertIsNone(primary.__cause__)
                self.assertFalse(primary.__suppress_context__)
            else:
                with guard:
                    native.execute("BEGIN IMMEDIATE")
                    counts["begin"] += 1
        report = guard.report
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn("synthetic-diagnostic-marker", repr(report))
        expected_counts = dict(begin=1, rollback_callback=int(fail),
            native_rollback=int(fail and rollback_forwarded), close_callback=int(fail),
            native_close=int(fail and close_forwarded), fixture_close=0)
        self.assertEqual(counts, expected_counts)
        if fail:
            self.assertIsNot(initial, report)
            self.assertIs(report.primary, primary)
            self.assertEqual(report.rollback_status, "returned" if secondary is None else "escaped")
            self.assertEqual(report.close_status, "returned" if close_error is None else "escaped")
            self.assertIs(report.rollback_secondary, secondary)
            self.assertIs(report.close_secondary, close_error)
            self.assertEqual(rollback_active, [primary])
            self.assertEqual(close_active, [primary])
            expected_events = ["rollback-attempt"]
            if rollback_forwarded:
                expected_events.append("native-rollback-returned")
            expected_events.append("close-attempt")
            if close_forwarded:
                expected_events.append("native-close-returned")
            self.assertEqual(events, expected_events)
            for error in (secondary, close_error):
                if error is not None:
                    self.assertIs(error.__context__, primary)
                    self.assertIsNone(error.__cause__)
                    self.assertFalse(error.__suppress_context__)
        else:
            self.assertIs(report, initial)
            self.assertEqual(events, [])
            self.assertEqual(rollback_active, [])
            self.assertEqual(close_active, [])
        self.assertEqual(close_transaction, [not rollback_forwarded] if fail and close_forwarded else [])
        self.assertEqual(fixture_transaction, [])
        active = not (fail and rollback_forwarded)
        owned = not (fail and close_forwarded)
        self.assertIs(state["owned"], owned)
        if owned:
            self.assertIs(native.in_transaction, active)
            self.assertEqual(native.execute("SELECT 1").fetchone(), (1,))
        journal = reservation.with_name(reservation.name + "-journal")
        journal_present = owned and active
        expected_entries = sorted(entries + [journal.name]) if journal_present else entries
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), expected_entries)
        self.assertEqual(journal.exists(), journal_present)
        if journal_present:
            self.assertTrue(journal.is_file())
            self.assertFalse(journal.is_symlink())
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.assertEqual(reservation.read_bytes(), reserved_bytes)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        cleanup_fixture()
        expected_counts["fixture_close"] = int(owned)
        self.assertEqual(counts, expected_counts)
        self.assertEqual(fixture_transaction, [active] if owned else [])
        self.assertFalse(state["owned"])
        self.assertIs(guard.report, report)
        with self.assertRaises(sqlite3.ProgrammingError) as closed:
            native.execute("SELECT 1")
        self.assertIs(type(closed.exception), sqlite3.ProgrammingError)
        self.assertIsNone(closed.exception.__context__)
        self.assertIsNone(closed.exception.__cause__)
        self.assertFalse(closed.exception.__suppress_context__)
        self.assertFalse(journal.exists())
        self.assertEqual(sorted(item.name for item in self.path.parent.iterdir()), entries)
        self.assertEqual(self.path.read_bytes(), original_bytes)
        self.assertEqual(reservation.read_bytes(), reserved_bytes)
        self.assertEqual((reservation.stat().st_dev, reservation.stat().st_ino), identity)
        self.assertEqual(reservation.stat().st_mode & 0o777, 0o600)
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_sqlite_primary_os_rollback_before_close_returns(self):
        self.selected("sqlite", "os", "before")

    def test_sqlite_primary_os_rollback_after_close_returns(self):
        self.selected("sqlite", "os", "after")

    def test_sqlite_primary_cancellation_rollback_before_close_returns(self):
        self.selected("sqlite", "cancellation", "before")

    def test_sqlite_primary_cancellation_rollback_after_close_returns(self):
        self.selected("sqlite", "cancellation", "after")

    def test_os_primary_os_rollback_before_close_returns(self):
        self.selected("os", "os", "before")

    def test_os_primary_os_rollback_after_close_returns(self):
        self.selected("os", "os", "after")

    def test_os_primary_cancellation_rollback_before_close_returns(self):
        self.selected("os", "cancellation", "before")

    def test_os_primary_cancellation_rollback_after_close_returns(self):
        self.selected("os", "cancellation", "after")

    def test_cancellation_primary_os_rollback_before_close_returns(self):
        self.selected("cancellation", "os", "before")

    def test_cancellation_primary_os_rollback_after_close_returns(self):
        self.selected("cancellation", "os", "after")

    def test_cancellation_primary_cancellation_rollback_before_close_returns(self):
        self.selected("cancellation", "cancellation", "before")

    def test_cancellation_primary_cancellation_rollback_after_close_returns(self):
        self.selected("cancellation", "cancellation", "after")

    def test_rollback_before_sqlite_close_before_native_call(self):
        self.selected(rollback_timing="before", close_kind="sqlite", close_timing="before")

    def test_rollback_before_sqlite_close_after_native_call(self):
        self.selected(rollback_timing="before", close_kind="sqlite", close_timing="after")

    def test_rollback_before_os_close_before_native_call(self):
        self.selected(rollback_timing="before", close_kind="os", close_timing="before")

    def test_rollback_before_os_close_after_native_call(self):
        self.selected(rollback_timing="before", close_kind="os", close_timing="after")

    def test_rollback_before_cancellation_close_before_native_call(self):
        self.selected(rollback_timing="before", close_kind="cancellation", close_timing="before")

    def test_rollback_before_cancellation_close_after_native_call(self):
        self.selected(rollback_timing="before", close_kind="cancellation", close_timing="after")

    def test_rollback_after_sqlite_close_before_native_call(self):
        self.selected(rollback_timing="after", close_kind="sqlite", close_timing="before")

    def test_rollback_after_sqlite_close_after_native_call(self):
        self.selected(rollback_timing="after", close_kind="sqlite", close_timing="after")

    def test_rollback_after_os_close_before_native_call(self):
        self.selected(rollback_timing="after", close_kind="os", close_timing="before")

    def test_rollback_after_os_close_after_native_call(self):
        self.selected(rollback_timing="after", close_kind="os", close_timing="after")

    def test_rollback_after_cancellation_close_before_native_call(self):
        self.selected(rollback_timing="after", close_kind="cancellation", close_timing="before")

    def test_rollback_after_cancellation_close_after_native_call(self):
        self.selected(rollback_timing="after", close_kind="cancellation", close_timing="after")

    def test_sqlite_primary_both_callbacks_return(self):
        self.selected(primary_kind="sqlite", rollback_kind=None)

    def test_os_primary_both_callbacks_return(self):
        self.selected(primary_kind="os", rollback_kind=None)

    def test_cancellation_primary_both_callbacks_return(self):
        self.selected(primary_kind="cancellation", rollback_kind=None)

    def test_normal_exit_has_no_cleanup_attempt(self):
        self.selected(fail=False)

    def test_reused_scope_refuses_before_any_new_callback(self):
        calls = []
        guard = SelectedFailureCleanup(lambda: calls.append("rollback"), lambda: calls.append("close"))
        with guard:
            pass
        original = guard.report
        with self.assertRaises(CleanupSelectionRefused):
            with guard:
                self.fail("reused guard entered")
        self.assertEqual(calls, [])
        self.assertIs(guard.report, original)

    def test_exit_without_entry_refuses_before_callbacks(self):
        calls = []
        guard = SelectedFailureCleanup(lambda: calls.append("rollback"), lambda: calls.append("close"))
        with self.assertRaises(CleanupSelectionRefused):
            guard.__exit__(None, None, None)
        self.assertEqual(calls, [])
        self.assertEqual((guard.report.rollback_status, guard.report.close_status),
            ("not-attempted", "not-attempted"))

    def test_noncallable_rollback_refuses_before_callbacks(self):
        calls = []
        with self.assertRaises(CleanupSelectionRefused):
            SelectedFailureCleanup(None, lambda: calls.append("close"))
        self.assertEqual(calls, [])

    def test_noncallable_close_refuses_before_callbacks(self):
        calls = []
        with self.assertRaises(CleanupSelectionRefused):
            SelectedFailureCleanup(lambda: calls.append("rollback"), None)
        self.assertEqual(calls, [])
