"""Original synthetic actor cleanup, cancellation and separate retained rows."""

import io
import json
import sqlite3
import sys
from unittest.mock import patch

import policy_effect_native_observation as observation
import policy_effect_store_actor as actor
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class CancellingInput(io.StringIO):
    def __init__(self, context, cancellation):
        super().__init__(context)
        self.cancellation = cancellation

    def readline(self, *args):
        if self.tell() == len(self.getvalue()):
            raise self.cancellation
        return super().readline(*args)


class PolicyEffectActorCleanupTests(prior.PolicyEffectStoreCase):
    def run_actor(self, *, point="unused", mode="direct", revision=0,
                  rollback_denials=0, deny_setup=False, cancellation=None,
                  terminal_cancellation=None):
        request = self.request(revision=revision)
        context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                       revision=revision, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)
        line = json.dumps(context) + "\n"
        incoming = CancellingInput(line, cancellation) if cancellation is not None else io.StringIO(line)
        output = io.StringIO()
        self.transactions = []
        self.constructor_calls = 0
        self.close_calls = 0
        self.closed_at_close = []

        def construct(path, labels):
            self.constructor_calls += 1
            store = source.OfflinePolicyEffectStore(path, labels)
            self.actor_store = store
            self.addCleanup(lambda: store._dispose() if not store._closed else None)

            def authorizer(action, first, second, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION:
                    self.transactions.append(first)
                    if first == "ROLLBACK" and self.transactions.count("ROLLBACK") <= rollback_denials:
                        return sqlite3.SQLITE_DENY
                if deny_setup and action == sqlite3.SQLITE_PRAGMA and first == "cache_size":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            store._db.set_authorizer(authorizer)
            original_close = store.close

            def close():
                self.close_calls += 1
                self.closed_at_close.append(store._closed)
                original_close()
                if terminal_cancellation is not None:
                    raise terminal_cancellation

            store.close = close
            return store

        argv = ["synthetic-actor", str(self.path), "allocation", point, mode, "native-execute-errors-v1"]
        with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdin", incoming), \
                patch.object(sys, "stdout", output):
            try:
                return actor.main()
            finally:
                self.actor_output = output.getvalue().encode("ascii")

    def assert_terminal(self, *, closes, transactions, retained):
        self.assertEqual(self.constructor_calls, 1)
        self.assertEqual(self.close_calls, closes)
        self.assertEqual(self.closed_at_close, [False] * closes)
        self.assertTrue(self.actor_store._closed)
        self.assertEqual(self.transactions, transactions)
        with self.assertRaises(source.StoreRefused):
            self.actor_store.local_view()
        with self.assertRaises(sqlite3.ProgrammingError):
            self.actor_store._db.in_transaction
        with self.open() as reopened:
            state = prior.allocation_state(reopened, [self.request()])
        self.assertEqual((state["raw_operations"], state["raw_effects"],
                          state["retained_originals"], state["charged_operations"]),
                         (retained, 0, [bool(retained)], retained))
        return state

    def assert_report(self, errors):
        self.assertEqual(self.actor_store._db.report(), dict(schema=observation.SCHEMA,
                         errors=errors, overflow=False))

    def test_success_closes_open_handle_once_and_retains_one_original_charge(self):
        self.assertEqual(self.run_actor(), 0)
        reply = prior.allocation_reply(0, self.actor_output, b"")
        self.assertEqual(reply["response_class"], "allocation-record")
        self.assertEqual(reply["native_execute_errors"], [])
        self.assertFalse(reply["stderr_present"])
        self.assert_terminal(closes=1, transactions=["BEGIN", "COMMIT"], retained=1)
        self.assert_report([])

    def test_policy_refusal_closes_once_without_changing_refusal_or_report(self):
        self.assertEqual(self.run_actor(revision=1), 20)
        reply = prior.allocation_reply(20, self.actor_output, b"")
        self.assertEqual(reply["response_class"], "StoreRefused")
        self.assertEqual(reply["native_execute_errors"], [])
        self.assert_terminal(closes=1, transactions=["BEGIN", "ROLLBACK"], retained=0)
        self.assert_report([])

    def test_precommit_cancellation_propagates_same_object_and_closes_open_handle(self):
        cancellation = KeyboardInterrupt("synthetic-private-command-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(point="allocation-written", cancellation=cancellation)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.actor_output, b"paused\n")
        self.assert_terminal(closes=1, transactions=["BEGIN", "ROLLBACK"], retained=0)
        self.assert_report([])

    def test_disposed_command_cancellation_is_not_replaced_by_second_close(self):
        cancellation = KeyboardInterrupt("synthetic-private-disposed-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(point="allocation-written", rollback_denials=2, cancellation=cancellation)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.actor_output, b"paused\n")
        self.assert_terminal(closes=0, transactions=["BEGIN", "ROLLBACK", "ROLLBACK"], retained=0)
        self.assert_report([dict(phase="rollback", code=None)] * 2)
        self.assertNotIn(b"synthetic-private-disposed-cancellation", self.actor_output)

    def test_native_setup_refusal_closes_before_observer_or_command_installation(self):
        with self.assertRaises(sqlite3.DatabaseError) as caught:
            self.run_actor(deny_setup=True)
        self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        self.assertEqual(self.actor_output, b"")
        self.assert_terminal(closes=1, transactions=[], retained=0)
        self.assertIs(type(self.actor_store._db), sqlite3.Connection)

    def test_terminal_cleanup_cancellation_preserves_previously_emitted_reply(self):
        cancellation = KeyboardInterrupt("synthetic-private-terminal-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(terminal_cancellation=cancellation)
        self.assertIs(caught.exception, cancellation)
        first, encoded = self.actor_output.splitlines()
        self.assertEqual(json.loads(first), dict(charge_sequence=1, effect_sequence=None))
        self.assertEqual(observation.decode(encoded), dict(schema=observation.SCHEMA, errors=[], overflow=False))
        self.assert_terminal(closes=1, transactions=["BEGIN", "COMMIT"], retained=1)
        self.assert_report([])
        self.assertNotIn(b"synthetic-private-terminal-cancellation", self.actor_output)

    def test_readiness_cancellation_closes_without_transaction_or_reply(self):
        cancellation = KeyboardInterrupt("synthetic-private-readiness-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(mode="ready", cancellation=cancellation)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.actor_output, b"ready\n")
        self.assert_terminal(closes=1, transactions=[], retained=0)
        self.assert_report([])

    def test_postcommit_cancellation_propagates_and_retains_committed_charge(self):
        cancellation = KeyboardInterrupt("synthetic-private-postcommit-cancellation")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_actor(point="allocation-after-commit", cancellation=cancellation)
        self.assertIs(caught.exception, cancellation)
        self.assertEqual(self.actor_output, b"paused\n")
        self.assert_terminal(closes=1, transactions=["BEGIN", "COMMIT"], retained=1)
        self.assert_report([])
