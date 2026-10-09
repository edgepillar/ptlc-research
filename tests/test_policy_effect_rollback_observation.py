"""Native rollback refusals, secondary cleanup and separate retained outcomes."""

import json
import os
from pathlib import Path
import selectors
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import policy_effect_native_observation as observation
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectRollbackObservationTests(prior.PolicyEffectStoreCase):
    def observed(self, *, rollback_denials=2, event_denied=False):
        transactions = []

        def authorizer(action, first, second, database, trigger):
            if action == sqlite3.SQLITE_TRANSACTION:
                transactions.append(first)
                if first == "ROLLBACK" and transactions.count("ROLLBACK") <= rollback_denials:
                    return sqlite3.SQLITE_DENY
            if event_denied and action == sqlite3.SQLITE_INSERT and first == "events":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.store._db.set_authorizer(authorizer)
        observer = observation.ObservedConnection(self.store._db)
        self.store._db = observer
        return observer, transactions

    def assert_disposed_and_absent(self, observer, request):
        self.assertTrue(self.store._closed)
        for command in (self.store.local_view, lambda: self.store.lookup_original(request),
                        lambda: self.store.allocate_synthetic(request)):
            with self.assertRaises(source.StoreRefused):
                command()
        with self.open() as reopened:
            view = prior.allocation_state(reopened, [request])
        self.assertEqual(view, dict(readback="available", raw_operations=0, raw_effects=0,
            retained_originals=[False], charge_sequences=[None], effect_sequences=[None],
            charged_operations=0, synthetic_effects=0, event_sequence=0))
        report = observer.report()
        self.assertEqual(observation.decode(observation.canonical(report)), report)
        return report

    def test_real_commit_busy_then_two_denied_rollbacks_closes_without_retained_rows(self):
        reader = sqlite3.connect(str(self.path), timeout=0, isolation_level=None)
        self.addCleanup(reader.close)
        reader.execute("BEGIN")
        self.assertEqual(reader.execute("SELECT count(*) FROM operations").fetchone(), (0,))
        observer, transactions = self.observed()
        request = self.request()
        with self.assertRaises(source.StoreOutcomeUnknown) as caught:
            self.store.allocate_synthetic(request)
        self.assertEqual(caught.exception.__context__.sqlite_errorcode, 5)
        reader.execute("ROLLBACK")
        report = self.assert_disposed_and_absent(observer, request)
        self.assertEqual(transactions, ["BEGIN", "COMMIT", "ROLLBACK", "ROLLBACK"])
        self.assertEqual(report, dict(schema=observation.SCHEMA, errors=[dict(phase="commit", code=5),
            dict(phase="rollback", code=None), dict(phase="rollback", code=None)], overflow=False))
        self.assertEqual(prior.allocation_state(self.store, [request]), dict(readback="unavailable"))
        self.assertEqual(observer.report()["errors"], report["errors"] + [dict(phase="execute-other", code=None)])

    def test_real_denied_event_insert_and_two_denied_rollbacks_preserve_error_order(self):
        observer, transactions = self.observed(event_denied=True)
        request = self.request()
        with self.assertRaises(source.StoreOutcomeUnknown) as caught:
            self.store.allocate_synthetic(request)
        self.assertEqual(caught.exception.__context__.sqlite_errorcode, sqlite3.SQLITE_AUTH)
        report = self.assert_disposed_and_absent(observer, request)
        self.assertEqual(transactions, ["BEGIN", "ROLLBACK", "ROLLBACK"])
        self.assertEqual(report["errors"], [dict(phase="event-insert", code=None),
            dict(phase="rollback", code=None), dict(phase="rollback", code=None)])
        self.assertFalse(report["overflow"])

    def test_policy_refusal_becomes_unknown_when_native_rollback_is_denied(self):
        observer, transactions = self.observed()
        request = self.request(revision=1)
        with self.assertRaises(source.StoreOutcomeUnknown):
            self.store.allocate_synthetic(request)
        report = self.assert_disposed_and_absent(observer, request)
        self.assertEqual(transactions, ["BEGIN", "ROLLBACK", "ROLLBACK"])
        self.assertEqual(report["errors"], [dict(phase="rollback", code=None)] * 2)
        self.assertFalse(report["overflow"])

    def test_second_cleanup_rollback_can_succeed_without_retrying_allocation(self):
        observer, transactions = self.observed(rollback_denials=1)
        request = self.request()

        def fail(point):
            if point == "allocation-written":
                raise RuntimeError("synthetic-private-primary-failure")

        with patch.object(self.store, "_cut", side_effect=fail):
            with self.assertRaises(source.StoreOutcomeUnknown):
                self.store.allocate_synthetic(request)
        report = self.assert_disposed_and_absent(observer, request)
        self.assertEqual(transactions, ["BEGIN", "ROLLBACK", "ROLLBACK"])
        self.assertEqual(report["errors"], [dict(phase="rollback", code=None)])
        self.assertFalse(report["overflow"])

    def test_cancellation_identity_propagates_after_two_native_rollback_refusals(self):
        observer, transactions = self.observed()
        request = self.request()
        interruption = KeyboardInterrupt("synthetic-private-cancellation")

        def cancel(point):
            if point == "allocation-written":
                raise interruption

        with patch.object(self.store, "_cut", side_effect=cancel):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.store.allocate_synthetic(request)
        self.assertIs(caught.exception, interruption)
        report = self.assert_disposed_and_absent(observer, request)
        self.assertEqual(transactions, ["BEGIN", "ROLLBACK", "ROLLBACK"])
        self.assertEqual(report["errors"], [dict(phase="rollback", code=None)] * 2)
        self.assertNotIn("synthetic-private-cancellation", json.dumps(report))

    @unittest.skipUnless(os.name == "posix", "original actor cleanup fixture requires POSIX")
    def test_original_actor_emits_unknown_before_secondary_context_exit_failure(self):
        def reap(child):
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

        replies = []
        for observed in (False, True):
            command = [sys.executable, "-B", str(Path(__file__).with_name("policy_effect_rollback_actor.py")),
                       str(self.path), "allocation", "unused", "ready"]
            if observed:
                command.append("native-execute-errors-v1")
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.addCleanup(reap, child)
            context = dict(labels=prior.asdict(prior.LABELS), operation=self.request().operation_id_hex,
                           revision=0, profile_hex=prior.WIRE.hex(), proposal=self.request().proposal_digest_hex)
            child.stdin.write((json.dumps(context) + "\n").encode("ascii")); child.stdin.flush()
            with selectors.DefaultSelector() as selected:
                selected.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selected.select(timeout=10), "synthetic rollback actor did not reach readiness")
            self.assertEqual(child.stdout.readline(), b"ready\n")
            output, error = child.communicate(b"go\n", timeout=10)
            self.assertEqual(child.returncode, 1)
            self.assertEqual(error, b"synthetic-secondary-store-refusal\n")
            reply = prior.allocation_reply(child.returncode, output, error)
            self.assertEqual(reply["response_class"], "StoreOutcomeUnknown")
            self.assertTrue(reply["stderr_present"])
            self.assertEqual(output.split(b"\n", 1)[0], b"StoreOutcomeUnknown")
            if observed:
                self.assertEqual(reply["native_execute_errors"], [dict(phase="event-insert", code=None),
                    dict(phase="rollback", code=None), dict(phase="rollback", code=None)])
                self.assertFalse(reply["native_error_overflow"])
            else:
                self.assertEqual(output, b"StoreOutcomeUnknown\n")
                self.assertNotIn("native_execute_errors", reply)
            replies.append((child.returncode, output, error))
        report = prior.allocation_evidence(replies, self.store, [self.request()], self.open)
        self.assertEqual(report["native_error_details"], "incomplete-original-execute-report")
        self.assertEqual(report["local"], report["reopened"])
        self.assertEqual((report["local"]["raw_operations"], report["local"]["raw_effects"],
                          report["local"]["retained_originals"]), (0, 0, [False]))

    def test_postcommit_failure_never_executes_denied_rollback_and_keeps_one_charge(self):
        observer, transactions = self.observed()
        request = self.request()

        def fail(point):
            if point == "allocation-after-commit":
                raise source.StoreRefused("synthetic-private-postcommit-refusal")

        with patch.object(self.store, "_cut", side_effect=fail):
            with self.assertRaises(source.StoreOutcomeUnknown):
                self.store.allocate_synthetic(request)
        self.assertFalse(self.store._closed)
        self.assertEqual(transactions, ["BEGIN", "COMMIT"])
        report = observer.report()
        self.assertEqual(report, dict(schema=observation.SCHEMA, errors=[], overflow=False))
        local = prior.allocation_state(self.store, [request])
        with self.open() as reopened:
            self.assertEqual(prior.allocation_state(reopened, [request]), local)
        self.assertEqual((local["raw_operations"], local["raw_effects"], local["retained_originals"]), (1, 0, [True]))

    def test_real_closed_cursor_and_transaction_state_errors_are_not_execute_observations(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        observer = observation.ObservedConnection(connection)
        cursor = observer.execute("SELECT 1")
        observer.close()
        with self.assertRaises(sqlite3.ProgrammingError):
            cursor.fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            observer.in_transaction
        self.assertEqual(observer.report(), dict(schema=observation.SCHEMA, errors=[], overflow=False))


if __name__ == "__main__":
    unittest.main()
