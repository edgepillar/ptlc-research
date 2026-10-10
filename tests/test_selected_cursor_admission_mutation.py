"""An injected partial-registration counterexample, with no native release claim."""

import test_policy_effect_store as prior
from selected_cursor_owner import SelectedCursorOwner


class SelectedCursorAdmissionMutationTests(prior.PolicyEffectStoreCase):
    def retained_original(self, original, snapshot):
        data, identity, mode, entries = snapshot
        self.assertEqual(self.path.read_bytes(), data)
        self.assertEqual((self.path.stat().st_dev, self.path.stat().st_ino), identity)
        self.assertEqual(self.path.stat().st_mode & 0o777, mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(sorted(path.name for path in self.path.parent.iterdir()), entries)
        request = self.request()
        local = prior.allocation_state(self.store, [request])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(request), original)
            after = prior.allocation_state(reopened, [request])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def test_mutated_registration_revisits_a_failed_close_without_exposure(self):
        original = self.store.allocate_synthetic(self.request())
        snapshot = (self.path.read_bytes(),
            (self.path.stat().st_dev, self.path.stat().st_ino),
            self.path.stat().st_mode & 0o777,
            sorted(path.name for path in self.path.parent.iterdir()))
        self.retained_original(original, snapshot)
        events, attempts, exposed = [], [], []
        primary = MemoryError("synthetic registration escape after insertion")
        secondary = OSError("synthetic first cursor-close escape")

        class Cursor:
            def close(inner):
                self.assertIs(owner._pending, inner)
                self.assertEqual(len(owner._cursors), 1)
                self.assertIs(owner._cursors[0], inner)
                attempt = len(attempts) + 1
                events.append(("cursor-close", attempt, owner._phase))
                if attempt == 1:
                    attempts.append((attempt, "escaped", secondary))
                    raise secondary
                attempts.append((attempt, "returned", None))

        pending = Cursor()

        class Connection:
            def cursor(inner):
                events.append(("create",))
                return pending

            def close(inner):
                events.append(("parent-close", owner._phase))

        owner = SelectedCursorOwner(Connection)

        def insert_then_escape(cursor):
            self.assertIs(cursor, pending)
            self.assertIs(owner._pending, pending)
            self.assertEqual(owner._cursors, [])
            events.append(("registration-before-insertion",))
            owner._cursors.append(cursor)
            events.append(("registration-after-insertion",))
            raise primary

        owner._register = insert_then_escape
        with self.assertRaises(MemoryError) as caught:
            with owner:
                exposed.append(owner.cursor())
        self.assertEqual(exposed, [])
        self.assertEqual(events, [("create",), ("registration-before-insertion",),
            ("registration-after-insertion",), ("cursor-close", 1, "entered"),
            ("cursor-close", 2, "disposed"), ("parent-close", "disposed")])
        self.assertEqual(attempts, [(1, "escaped", secondary), (2, "returned", None)])
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        self.assertIs(secondary.__context__, primary)
        self.assertIsNone(secondary.__cause__)
        self.assertFalse(secondary.__suppress_context__)
        self.assertIs(owner._pending, pending)
        self.assertEqual(len(owner._cursors), 1)
        self.assertIs(owner._cursors[0], pending)
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertIs(report.admission.primary, primary)
        self.assertEqual(report.admission.close_status, "escaped")
        self.assertIs(report.admission.secondary, secondary)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(0, "returned", None)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        # The later returned callback does not retire the first escaped attempt.
        self.assertIs(report.admission.secondary, attempts[0][2])
        self.retained_original(original, snapshot)
