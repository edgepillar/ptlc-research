"""Actual native errors and bounded original-actor evidence before wrapping."""

import json
import os
import signal
import sqlite3
import unittest
from unittest.mock import patch

import policy_effect_native_observation as observation
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectNativeObservationTests(prior.PolicyEffectStoreCase):
    def native_case(self):
        case = prior.PolicyEffectStoreNativeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case

    def reply(self, child):
        output, error = child.communicate(timeout=10)
        self.assertEqual(error, b"")
        return prior.allocation_reply(child.returncode, output, error), output

    def test_forwarding_preserves_arguments_result_close_and_cancellation(self):
        calls, token, parameters = [], object(), (object(),)

        class Connection:
            in_transaction = True

            def execute(self, statement, received):
                calls.append((statement, received))
                return token

            def close(self):
                calls.append("close")
                return token

        connection = Connection()
        observer = observation.ObservedConnection(connection)
        self.assertIs(observer.execute("synthetic-private-sql", parameters), token)
        self.assertIs(calls[0][1], parameters)
        self.assertTrue(observer.in_transaction)
        self.assertIs(observer.close(), token)
        self.assertEqual(calls, [("synthetic-private-sql", parameters), "close"])
        for interruption in (KeyboardInterrupt, SystemExit):
            with patch.object(connection, "execute", side_effect=interruption):
                with self.assertRaises(interruption):
                    observer.execute("BEGIN IMMEDIATE")
        self.assertEqual(observer.report(), dict(schema=observation.SCHEMA, errors=[], overflow=False))

    def test_only_exact_native_busy_code_and_fixed_phases_are_retained(self):
        marker = "synthetic-private-native-message"

        class Foreign(sqlite3.OperationalError):
            @property
            def sqlite_errorcode(self):
                raise AssertionError("foreign diagnostic attribute must not be read")

            def __str__(self):
                raise AssertionError("native error text must not be read")

        class Connection:
            def execute(self, statement, parameters):
                raise self.error

        connection = Connection()
        for value in (5, True, 261, 517, 773, 19, None, "5", object()):
            observer = observation.ObservedConnection(connection)
            connection.error = sqlite3.OperationalError(marker)
            connection.error.sqlite_errorcode = value
            with self.assertRaises(sqlite3.Error) as caught:
                observer.execute("BEGIN IMMEDIATE", (marker,))
            self.assertIs(caught.exception, connection.error)
            expected = 5 if type(value) is int and value == 5 else None
            self.assertEqual(observer.report()["errors"], [dict(phase="begin", code=expected)])
            self.assertNotIn(marker, json.dumps(observer.report()))
        observer = observation.ObservedConnection(connection)
        connection.error = Foreign(marker)
        with self.assertRaises(Foreign):
            observer.execute(marker, (marker,))
        self.assertEqual(observer.report()["errors"], [dict(phase="execute-other", code=None)])

    def test_error_bound_and_defensive_report_never_retry_the_connection(self):
        calls = []
        error = sqlite3.OperationalError("synthetic-private-error")
        error.sqlite_errorcode = 5

        class Connection:
            def execute(self, statement, parameters):
                calls.append(statement)
                raise error

        observer = observation.ObservedConnection(Connection())
        statements = ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK", "INSERT INTO events VALUES (?,?,?,?,?)",
                      "INSERT INTO operations VALUES (?,?,?,?,?,NULL)", "synthetic-private-sql")
        for statement in statements:
            with self.assertRaises(sqlite3.Error):
                observer.execute(statement)
        self.assertEqual(calls, list(statements))
        report = observer.report()
        self.assertEqual([row["phase"] for row in report["errors"]], ["begin", "commit", "rollback", "event-insert"])
        self.assertTrue(report["overflow"])
        self.assertEqual(observation.decode(observation.canonical(report)), report)
        report["errors"][0]["phase"] = "synthetic-private-replacement"
        self.assertEqual(observer.report()["errors"][0]["phase"], "begin")

    def test_decoder_refuses_private_extra_noncanonical_alias_and_out_of_bound_reports(self):
        good = dict(schema=observation.SCHEMA, errors=[dict(phase="commit", code=5)], overflow=False)
        wire = observation.canonical(good)
        self.assertEqual(observation.decode(wire), good)
        rows = (dict(good, extra="synthetic-private-value"), dict(good, schema="synthetic-private-schema"),
                dict(good, overflow=0), dict(good, overflow=True), dict(good, errors={}),
                dict(good, errors=good["errors"] * 5),
                dict(good, errors=[dict(phase="synthetic-private-sql", code=5)]),
                dict(good, errors=[dict(phase="begin", code=True)]),
                dict(good, errors=[dict(phase="begin", code=517)]),
                dict(good, errors=[dict(phase="begin", code=5, message="synthetic-private-error")]))
        for row in rows:
            self.assertIsNone(observation.decode(observation.canonical(row)))
        invalid = (b"", b"\xff", wire + b"\n", b" " + wire, b"x" * 1025,
                   b"[" * 500 + b"0" + b"]" * 500,
                   wire.replace(b'"overflow":false', b'"overflow":false,"overflow":false'))
        for value in invalid:
            self.assertIsNone(observation.decode(value))
        self.assertIsNone(observation.decode(object()))

    def test_original_reply_decoder_requires_complete_report_and_omits_private_bytes(self):
        record = b'{"charge_sequence": 1, "effect_sequence": null}\n'
        report = dict(schema=observation.SCHEMA, errors=[], overflow=False)
        wire = observation.canonical(report)
        legacy = prior.allocation_reply(0, record, b"")
        self.assertEqual(prior.allocation_reply(0, record + wire + b"\n", b""),
                         dict(legacy, native_execute_errors=[], native_error_overflow=False))
        for suffix in (wire, wire + b"\nextra\n", b"synthetic-private-value\n",
                       observation.canonical(dict(report, extra="synthetic-private-value")) + b"\n"):
            reply = prior.allocation_reply(0, record + suffix, b"")
            self.assertEqual(reply["response_class"], "unrecognized")
            self.assertNotIn("synthetic-private-value", json.dumps(reply))
        for interruption in (KeyboardInterrupt, SystemExit):
            with patch.object(observation.json, "loads", side_effect=interruption):
                with self.assertRaises(interruption):
                    prior.allocation_reply(0, record + wire + b"\n", b"")

    @unittest.skipUnless(os.name == "posix", "original actor observation requires POSIX")
    def test_actual_legacy_and_observed_same_original_return_one_unchanged_charge(self):
        case = self.native_case()
        legacy = case.actor("allocation", ready=True)
        legacy.stdin.write(b"go\n"); legacy.stdin.flush()
        legacy_reply, legacy_output = self.reply(legacy)
        observed = case.actor("allocation", ready=True, observed=True)
        observed.stdin.write(b"go\n"); observed.stdin.flush()
        observed_reply, observed_output = self.reply(observed)
        self.assertEqual((legacy.returncode, observed.returncode), (0, 0))
        self.assertEqual(observed_output.split(b"\n", 1)[0] + b"\n", legacy_output)
        self.assertEqual(observed_reply, dict(legacy_reply, native_execute_errors=[], native_error_overflow=False))
        self.assertEqual((case.store.local_view().charged_operations, case.store.local_view().synthetic_effects), (1, 0))

    @unittest.skipUnless(os.name == "posix", "original actor observation requires POSIX")
    def test_actual_original_begin_busy_is_retained_before_unknown_wrapper_with_zero_rows(self):
        case = self.native_case()
        child = case.actor("allocation", ready=True, observed=True)
        holder = sqlite3.connect(str(case.path), timeout=0, isolation_level=None)
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")
        child.stdin.write(b"go\n"); child.stdin.flush()
        reply, _ = self.reply(child)
        holder.execute("ROLLBACK")
        self.assertEqual(reply, dict(exit_code=20, response_class="StoreOutcomeUnknown", stderr_present=False,
                                    native_execute_errors=[dict(phase="begin", code=5)], native_error_overflow=False))
        self.assertIsNone(case.store.lookup_original(case.request()))
        self.assertEqual(case.store.local_view().charged_operations, 0)

    def test_actual_buffered_commit_busy_is_retained_before_wrapper_and_rolled_back(self):
        reader = sqlite3.connect(str(self.path), timeout=0, isolation_level=None)
        self.addCleanup(reader.close)
        reader.execute("BEGIN")
        self.assertEqual(reader.execute("SELECT count(*) FROM operations").fetchone(), (0,))
        observer = observation.ObservedConnection(self.store._db)
        self.store._db = observer
        with self.assertRaises(source.StoreOutcomeUnknown):
            self.store.allocate_synthetic(self.request())
        reader.execute("ROLLBACK")
        self.assertEqual(observer.report(), dict(schema=observation.SCHEMA,
            errors=[dict(phase="commit", code=5)], overflow=False))
        self.assertFalse(observer.in_transaction)
        self.assertIsNone(self.store.lookup_original(self.request()))
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_postcommit_non_native_failure_keeps_one_charge_with_empty_execute_observation(self):
        observer = observation.ObservedConnection(self.store._db)
        self.store._db = observer

        def lost(point):
            if point == "allocation-after-commit":
                raise RuntimeError("synthetic-private-lost-reply")

        with patch.object(self.store, "_cut", side_effect=lost):
            with self.assertRaises(source.StoreOutcomeUnknown):
                self.store.allocate_synthetic(self.request())
        self.assertEqual(observer.report(), dict(schema=observation.SCHEMA, errors=[], overflow=False))
        self.assertIsNotNone(self.store.lookup_original(self.request()))
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (1, 0))

    @unittest.skipUnless(os.name == "posix", "original actor observation requires POSIX")
    def test_postcommit_kill_before_report_is_incomplete_with_one_retained_original(self):
        case = self.native_case()
        wire = case.wire(max_attempt_limit=1)
        case.store.replace_local_policy(0, wire, active=True)
        requests = (case.request(revision=1, wire=wire), case.request("03", revision=1, wire=wire))
        child = case.actor("allocation", "allocation-after-commit", request=requests[0], observed=True)
        child.kill()
        output, error = child.communicate(timeout=10)
        peer = case.actor("allocation", request=requests[1], ready=True, observed=True)
        peer.stdin.write(b"go\n"); peer.stdin.flush()
        peer_output, peer_error = peer.communicate(timeout=10)
        report = prior.allocation_evidence(((child.returncode, output, error),
            (peer.returncode, peer_output, peer_error)), case.store, requests, case.open)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertEqual(report["native_error_details"], "incomplete-original-execute-report")
        self.assertNotIn("native_execute_errors", report["replies"][0])
        self.assertEqual(report["replies"][1]["native_execute_errors"], [])
        self.assertEqual(report["local"], report["reopened"])
        self.assertEqual((report["local"]["charged_operations"], report["local"]["synthetic_effects"],
                          report["local"]["retained_originals"]), (1, 0, [True, False]))


if __name__ == "__main__":
    unittest.main()
