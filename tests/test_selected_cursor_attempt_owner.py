"""Two selected synthetic attempt controls, with no native retirement claim."""

import test_policy_effect_store as prior
from selected_cursor_attempt_owner import SelectedCursorAttemptOwner
from selected_cursor_owner import CursorOwnershipRefused


class SelectedCursorAttemptOwnerTests(prior.PolicyEffectStoreCase):
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

    def original_snapshot(self):
        original = self.store.allocate_synthetic(self.request())
        snapshot = (self.path.read_bytes(),
            (self.path.stat().st_dev, self.path.stat().st_ino),
            self.path.stat().st_mode & 0o777,
            sorted(path.name for path in self.path.parent.iterdir()))
        self.retained_original(original, snapshot)
        return original, snapshot

    def test_partial_registration_preserves_the_first_attempt_without_exposure(self):
        original, snapshot = self.original_snapshot()
        events, exposed = [], []
        primary = MemoryError("synthetic registration escape after insertion")
        secondary = OSError("synthetic first cursor-close escape")

        class Cursor:
            def close(inner):
                record = owner._pending
                self.assertIs(record.cursor, inner)
                self.assertIs(owner._records[0], record)
                self.assertIs(owner._cursors[0], record)
                self.assertEqual(record.status, "attempted")
                self.assertIsNone(record.secondary)
                events.append(("cursor-close", owner._phase, record.status))
                raise secondary

        pending = Cursor()

        class Connection:
            def cursor(inner):
                events.append(("create",))
                return pending

            def close(inner):
                events.append(("parent-close", owner._phase,
                    owner._records[0].status))

        owner = SelectedCursorAttemptOwner(Connection)

        def insert_then_escape(record):
            self.assertIs(owner._pending, record)
            self.assertIs(owner._records[0], record)
            self.assertIs(record.cursor, pending)
            self.assertEqual(record.status, "not-attempted")
            events.append(("registration-before-insertion",))
            owner._cursors.append(record)
            events.append(("registration-after-insertion",))
            raise primary

        owner._register = insert_then_escape
        with self.assertRaises(MemoryError) as caught:
            with owner:
                exposed.append(owner.cursor())
        self.assertEqual(exposed, [])
        self.assertEqual(events, [("create",), ("registration-before-insertion",),
            ("registration-after-insertion",), ("cursor-close", "entered", "attempted"),
            ("parent-close", "disposed", "escaped")])
        self.assertIs(caught.exception, primary)
        self.assertIsNone(primary.__context__)
        self.assertIsNone(primary.__cause__)
        self.assertFalse(primary.__suppress_context__)
        self.assertIs(secondary.__context__, primary)
        self.assertIsNone(secondary.__cause__)
        self.assertFalse(secondary.__suppress_context__)
        record = owner._records[0]
        self.assertIs(owner._pending, record)
        self.assertIs(owner._cursors[0], record)
        self.assertIs(record.cursor, pending)
        self.assertEqual(record.status, "escaped")
        self.assertIs(record.secondary, secondary)
        report = owner.report
        self.assertIs(report.primary, primary)
        self.assertIs(report.admission.primary, primary)
        self.assertEqual(report.admission.close_status, "escaped")
        self.assertIs(report.admission.secondary, secondary)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(0, "escaped", secondary)])
        self.assertEqual(report.connection_status, "returned")
        self.assertIsNone(report.connection_secondary)
        with self.assertRaises(CursorOwnershipRefused):
            owner.cursor()
        with self.assertRaises(CursorOwnershipRefused):
            owner.__enter__()
        self.retained_original(original, snapshot)

    def test_normal_exit_attempts_each_creation_record_before_parent_escape(self):
        original, snapshot = self.original_snapshot()
        events = []
        cursor_error = OSError("synthetic last-created cursor-close escape")
        parent_error = RuntimeError("synthetic parent-close escape")

        class Cursor:
            def __init__(inner, ordinal):
                inner.ordinal = ordinal

            def close(inner):
                record = owner._records[inner.ordinal]
                self.assertIs(record.cursor, inner)
                self.assertEqual(record.status, "attempted")
                self.assertEqual(owner._phase, "disposed")
                events.append(("cursor-close", inner.ordinal, record.status))
                if inner.ordinal == 1:
                    raise cursor_error

        created = [Cursor(0), Cursor(1)]

        class Connection:
            def cursor(inner):
                ordinal = len(owner._records)
                events.append(("create", ordinal))
                return created[ordinal]

            def close(inner):
                events.append(("parent-close", owner._phase,
                    tuple(record.status for record in owner._records)))
                raise parent_error

        owner = SelectedCursorAttemptOwner(Connection)

        def duplicated_registration(record):
            self.assertIs(owner._records[record.ordinal], record)
            self.assertEqual(record.status, "not-attempted")
            owner._cursors.extend((record, record))

        owner._register = duplicated_registration
        with self.assertRaises(OSError) as caught:
            with owner:
                self.assertIs(owner.cursor(), created[0])
                self.assertIs(owner.cursor(), created[1])
                self.assertIsNone(owner._pending)
                self.assertEqual(len(owner._cursors), 4)
        self.assertIs(caught.exception, cursor_error)
        self.assertEqual(events, [("create", 0), ("create", 1),
            ("cursor-close", 1, "attempted"), ("cursor-close", 0, "attempted"),
            ("parent-close", "disposed", ("returned", "escaped"))])
        self.assertEqual(len(owner._records), 2)
        self.assertIs(owner._cursors[0], owner._cursors[1])
        self.assertIs(owner._cursors[2], owner._cursors[3])
        report = owner.report
        self.assertIsNone(report.primary)
        self.assertIsNone(report.admission)
        self.assertEqual([(row.ordinal, row.status, row.secondary) for row in report.cursors],
            [(1, "escaped", cursor_error), (0, "returned", None)])
        self.assertEqual(report.connection_status, "escaped")
        self.assertIs(report.connection_secondary, parent_error)
        self.retained_original(original, snapshot)
