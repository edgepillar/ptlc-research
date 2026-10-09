"""Selected constructor interruptions before the original actor terminal guard."""

import errno
import io
import json
import sqlite3
import sys
import unittest
from unittest.mock import patch

import policy_effect_native_observation as observation
import policy_effect_store_actor as actor
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectActorConstructorTests(prior.PolicyEffectStoreCase):
    def setUp(self):
        super().setUp()
        self.original = self.store.allocate_synthetic(self.request())

    def run_actor(self, *, before_connect=None, cut=None, primary=None, deny_setup=False,
                  deny_begin=False, rollback_denials=0, terminal=None, missing=False,
                  mismatch=False):
        request = self.request()
        labels = prior.asdict(prior.LABELS)
        if mismatch:
            labels["source_id_hex"] = "ef" * 32
        context = dict(labels=labels, operation=request.operation_id_hex, revision=0,
                       profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
        path = self.path.with_name("missing.sqlite3") if missing else self.path
        self.output = io.StringIO()
        self.constructor_calls = self.factory_calls = self.allocation_calls = self.actor_close_calls = 0
        self.constructor_returned = False
        self.connection = None
        self.native_closed = False
        self.native_close_primaries = []
        self.native_errors = []
        self.disposals = []
        self.transactions = []
        self.forwarded_transactions = []
        self.constructor_cuts = []
        outer = self
        real_connect = sqlite3.connect
        store_class = source.OfflinePolicyEffectStore

        class SelectedConnection(sqlite3.Connection):
            def execute(self, statement, parameters=()):
                if statement in ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK"):
                    outer.forwarded_transactions.append(statement.split()[0])
                try:
                    return super().execute(statement, parameters)
                except sqlite3.Error as error:
                    outer.native_errors.append((statement, error))
                    raise

            def close(self):
                outer.native_close_primaries.append(sys.exc_info()[1])
                result = super().close()
                outer.native_closed = True
                if terminal is not None and len(outer.native_close_primaries) == 1:
                    raise terminal
                return result

        def connect(*args, **kwargs):
            self.factory_calls += 1
            if before_connect is not None:
                raise before_connect
            try:
                db = real_connect(*args, **kwargs, factory=SelectedConnection)
            except sqlite3.Error as error:
                self.native_errors.append(("connect", error))
                raise
            self.connection = db
            self.addCleanup(lambda: sqlite3.Connection.close(db))

            def authorize(action, first, second, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION:
                    self.transactions.append(first)
                    if deny_begin and first == "BEGIN":
                        return sqlite3.SQLITE_DENY
                    if first == "ROLLBACK" and self.transactions.count("ROLLBACK") <= rollback_denials:
                        return sqlite3.SQLITE_DENY
                if deny_setup and action == sqlite3.SQLITE_PRAGMA and first == "synchronous":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            db.set_authorizer(authorize)
            return db

        def construct(path, labels):
            self.constructor_calls += 1
            store = store_class.__new__(store_class)
            self.actor_store = store

            def dispose():
                self.disposals.append(dict(primary=sys.exc_info()[1], closed=store._closed, busy=store._busy))
                return store_class._dispose(store)

            def close():
                self.actor_close_calls += 1
                return store_class.close(store)

            def allocate(request):
                self.allocation_calls += 1
                return store_class.allocate_synthetic(store, request)

            def selected_cut(point):
                self.constructor_cuts.append(point)
                if point == cut:
                    raise primary

            store._dispose, store.close, store.allocate_synthetic, store._cut = dispose, close, allocate, selected_cut
            store_class.__init__(store, path, labels)
            self.constructor_returned = True
            return store

        argv = ["synthetic-actor", str(path), "allocation", "unused", "direct", "native-execute-errors-v1"]
        with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                patch.object(source.sqlite3, "connect", side_effect=connect), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdin", io.StringIO(json.dumps(context) + "\n")), \
                patch.object(sys, "stdout", self.output):
            return actor.main()

    def assert_original(self):
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(self.request()), self.original)
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=1, raw_effects=0,
            retained_originals=[True], charge_sequences=[1], effect_sequences=[None],
            charged_operations=1, synthetic_effects=0, event_sequence=1))

    def assert_constructor_failure(self, *, transactions, disposals=1, native_closes=1,
                                   closed=True, connection=True):
        self.assertEqual((self.constructor_calls, self.factory_calls, self.allocation_calls,
                          self.actor_close_calls), (1, 1, 0, 0))
        self.assertFalse(self.constructor_returned)
        self.assertEqual(self.transactions, transactions)
        self.assertEqual(self.forwarded_transactions, transactions)
        self.assertEqual(len(self.disposals), disposals)
        self.assertEqual(len(self.native_close_primaries), native_closes)
        self.assertEqual(self.actor_store._closed, closed)
        self.assertFalse(self.actor_store._busy)
        self.assertEqual(self.output.getvalue(), "")
        reply = prior.allocation_reply("unavailable", b"", b"")
        self.assertEqual(reply["exit_code"], "unavailable")
        self.assertEqual(reply["response_class"], "empty")
        self.assertNotIn("native_execute_errors", reply)
        if connection:
            self.assertIs(self.actor_store._db, self.connection)
            self.assertTrue(self.native_closed)
            with self.assertRaises(sqlite3.ProgrammingError):
                self.connection.in_transaction
        else:
            self.assertIsNone(self.connection)
            self.assertIsNone(self.actor_store._db)
            self.assertFalse(self.native_closed)
        if closed:
            with self.assertRaises(source.StoreRefused):
                self.actor_store.local_view()
        self.assert_original()

    def assert_unsuppressed(self, error, *, context=None):
        self.assertIs(error.__context__, context)
        self.assertIsNone(error.__cause__)
        self.assertFalse(error.__suppress_context__)

    def assert_unknown(self, error, native):
        self.assertIs(type(error), source.StoreOutcomeUnknown)
        self.assertIs(error.__context__, native)
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assert_unsuppressed(native)

    def test_selected_factory_cancellation_has_no_connection_and_no_actor_cleanup(self):
        primary = KeyboardInterrupt("synthetic-selected-before-connect")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(before_connect=primary)
        self.assertIs(caught.exception, primary)
        self.assertIs(self.disposals[0]["primary"], primary)
        self.assert_unsuppressed(primary)
        self.assertEqual(self.native_errors, [])
        self.assert_constructor_failure(transactions=[], connection=False, native_closes=0)

    def test_native_missing_open_is_suppressed_unknown_without_creating_source(self):
        with self.assertRaises(source.StoreOutcomeUnknown) as caught:
            self.run_actor(missing=True)
        native = self.native_errors[0][1]
        self.assertEqual(len(self.native_errors), 1)
        self.assertIs(type(native), sqlite3.OperationalError)
        self.assertEqual(native.sqlite_errorcode, sqlite3.SQLITE_CANTOPEN)
        self.assert_unknown(caught.exception, native)
        self.assertIs(self.disposals[0]["primary"], native)
        self.assertFalse(self.path.with_name("missing.sqlite3").exists())
        self.assert_constructor_failure(transactions=[], connection=False, native_closes=0)

    def test_native_setup_denial_is_suppressed_unknown_after_constructor_disposal(self):
        with self.assertRaises(source.StoreOutcomeUnknown) as caught:
            self.run_actor(deny_setup=True)
        native = self.native_errors[0][1]
        self.assertEqual(len(self.native_errors), 1)
        self.assertIs(type(native), sqlite3.DatabaseError)
        self.assertEqual(native.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assert_unknown(caught.exception, native)
        self.assertIs(self.disposals[0]["primary"], native)
        self.assert_constructor_failure(transactions=[])

    def test_native_label_refusal_preserves_exact_error_after_open_rollback(self):
        with self.assertRaises(source.StoreRefused) as caught:
            self.run_actor(mismatch=True)
        self.assertIs(self.disposals[0]["primary"], caught.exception)
        self.assert_unsuppressed(caught.exception)
        self.assertEqual(self.native_errors, [])
        self.assert_constructor_failure(transactions=["BEGIN", "ROLLBACK"])

    def test_native_begin_denial_preserves_transaction_unknown_without_actor_reply(self):
        with self.assertRaises(source.StoreOutcomeUnknown) as caught:
            self.run_actor(deny_begin=True)
        native = self.native_errors[0][1]
        self.assertEqual(native.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assertEqual(len(self.native_errors), 1)
        self.assert_unknown(caught.exception, native)
        self.assertIs(self.disposals[0]["primary"], caught.exception)
        self.assert_constructor_failure(transactions=["BEGIN"])

    def cancellation(self, *, cut, transactions, rollback_denials=0):
        primary = KeyboardInterrupt("synthetic-selected-open-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(cut=cut, primary=primary, rollback_denials=rollback_denials)
        self.assertIs(caught.exception, primary)
        self.assert_unsuppressed(primary)
        self.assertTrue(all(row["primary"] is primary for row in self.disposals))
        self.assertTrue(all(error.sqlite_errorcode == sqlite3.SQLITE_AUTH for _, error in self.native_errors))
        self.assertEqual(len(self.native_errors), rollback_denials)
        if rollback_denials:
            self.assertEqual([(row["closed"], row["busy"]) for row in self.disposals], [(False, True), (True, False)])
        self.assert_constructor_failure(transactions=transactions,
            disposals=2 if rollback_denials else 1, native_closes=2 if rollback_denials else 1)

    def test_precommit_open_cancellation_rolls_back_before_constructor_disposal(self):
        self.cancellation(cut="open-before-commit", transactions=["BEGIN", "ROLLBACK"])

    def test_postcommit_open_cancellation_has_no_allocation_despite_open_commit(self):
        self.cancellation(cut="open-after-commit", transactions=["BEGIN", "COMMIT"])

    def test_one_rollback_denial_disposes_in_transaction_then_again_in_constructor(self):
        self.cancellation(cut="open-before-commit", transactions=["BEGIN", "ROLLBACK", "ROLLBACK"], rollback_denials=1)

    def test_two_rollback_denials_keep_original_and_selected_double_disposal(self):
        self.cancellation(cut="open-before-commit", transactions=["BEGIN", "ROLLBACK", "ROLLBACK"], rollback_denials=2)

    def test_setup_denial_with_post_native_close_cancellation_prevents_unknown_conversion(self):
        terminal = KeyboardInterrupt("synthetic-selected-constructor-close")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(deny_setup=True, terminal=terminal)
        native = self.native_errors[0][1]
        self.assertEqual(native.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assertIs(caught.exception, terminal)
        self.assertIs(self.native_close_primaries[0], native)
        self.assert_unsuppressed(terminal, context=native)
        self.assert_unsuppressed(native)
        self.assert_constructor_failure(transactions=[], closed=False)

    def test_open_cancellation_with_post_native_close_eio_keeps_exact_primary_context(self):
        primary = KeyboardInterrupt("synthetic-selected-open-primary")
        terminal = OSError(errno.EIO, "synthetic-selected-post-native-close")
        with self.assertRaises(OSError) as caught:
            self.run_actor(cut="open-before-commit", primary=primary, terminal=terminal)
        self.assertIs(caught.exception, terminal)
        self.assertEqual(terminal.errno, errno.EIO)
        self.assertIs(self.native_close_primaries[0], primary)
        self.assert_unsuppressed(terminal, context=primary)
        self.assert_unsuppressed(primary)
        self.assert_constructor_failure(transactions=["BEGIN", "ROLLBACK"], closed=False)

    def test_begin_denial_with_post_native_close_fault_keeps_suppressed_three_object_chain(self):
        terminal = KeyboardInterrupt("synthetic-selected-normalized-close")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(deny_begin=True, terminal=terminal)
        unknown = self.disposals[0]["primary"]
        native = self.native_errors[0][1]
        self.assertIs(caught.exception, terminal)
        self.assertIs(self.native_close_primaries[0], unknown)
        self.assertEqual(native.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assert_unsuppressed(terminal, context=unknown)
        self.assert_unknown(unknown, native)
        self.assert_constructor_failure(transactions=["BEGIN"], closed=False)

    def test_selected_sqlite_close_error_is_swallowed_after_actual_close_and_primary_survives(self):
        primary = KeyboardInterrupt("synthetic-selected-retained-primary")
        terminal = sqlite3.DatabaseError("synthetic-selected-post-close-sqlite-class")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(cut="open-before-commit", primary=primary, terminal=terminal)
        self.assertIs(caught.exception, primary)
        self.assertIs(self.native_close_primaries[0], primary)
        self.assert_unsuppressed(primary)
        self.assert_unsuppressed(terminal, context=primary)
        self.assert_constructor_failure(transactions=["BEGIN", "ROLLBACK"])

    def test_healthy_constructor_returns_original_without_duplicate_charge_and_actor_closes(self):
        self.assertEqual(self.run_actor(), 0)
        self.assertTrue(self.constructor_returned)
        self.assertEqual((self.constructor_calls, self.factory_calls, self.allocation_calls, self.actor_close_calls), (1, 1, 1, 1))
        self.assertEqual(self.transactions, ["BEGIN", "COMMIT"])
        self.assertEqual(self.forwarded_transactions, ["BEGIN", "COMMIT", "BEGIN", "COMMIT"])
        self.assertEqual(self.disposals, [dict(primary=None, closed=False, busy=False)])
        self.assertEqual(self.native_close_primaries, [None])
        self.assertEqual(self.native_errors, [])
        self.assertTrue(self.actor_store._closed)
        self.assertTrue(self.native_closed)
        with self.assertRaises(sqlite3.ProgrammingError):
            self.connection.in_transaction
        report = dict(schema=observation.SCHEMA, errors=[], overflow=False)
        expected = json.dumps(dict(charge_sequence=1, effect_sequence=None)) + "\n" + observation.canonical(report).decode("ascii") + "\n"
        self.assertEqual(self.output.getvalue(), expected)
        reply = prior.allocation_reply("unavailable", expected.encode("ascii"), b"")
        self.assertEqual(reply["exit_code"], "unavailable")
        self.assertEqual(reply["native_execute_errors"], [])
        self.assertFalse(reply["native_error_overflow"])
        self.assert_original()
