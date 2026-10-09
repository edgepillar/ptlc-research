"""Sanitized evidence survives the unchanged original availability assertion."""

import io
import json
import os
import signal
import sqlite3
import unittest
from unittest.mock import patch

import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class PolicyEffectDiagnosticsTests(prior.PolicyEffectStoreCase):
    def selected_requests(self, case=None):
        case = self if case is None else case
        wire = case.wire(max_attempt_limit=1)
        case.store.replace_local_policy(0, wire, active=True)
        return (case.request(revision=1, wire=wire), case.request("03", revision=1, wire=wire))

    def evidence(self, requests, replies, case=None):
        case = self if case is None else case
        return prior.allocation_evidence(replies, case.store, requests, case.open)

    def from_failure(self, error):
        prefix = "synthetic-distinct-allocation: "
        message = str(error)
        self.assertIn(prefix, message)
        return json.loads(message.rsplit(prefix, 1)[1])

    def test_original_reply_shapes_have_fixed_classes_without_native_error_inference(self):
        record = b'{"charge_sequence": 2, "effect_sequence": null}\n'
        known = ((0, record, "allocation-record"),
                 (20, b"StoreRefused\n", "StoreRefused"),
                 (20, b"StoreOutcomeUnknown\n", "StoreOutcomeUnknown"),
                 (-signal.SIGKILL, b"", "empty"))
        for status, output, expected in known:
            with self.subTest(expected=expected):
                reply = prior.allocation_reply(status, output, b"")
                self.assertEqual(reply, dict(exit_code=status, response_class=expected, stderr_present=False))
        invalid = (b"synthetic-private-output\n", b"\xff\n", b"x" * 4097,
                   b"[" * 1500 + b"0" + b"]" * 1500,
                   b'{"charge_sequence": true, "effect_sequence": null}\n',
                   b'{"charge_sequence": 0, "effect_sequence": null}\n',
                   b'{"charge_sequence": 257, "effect_sequence": null}\n',
                   b'{"charge_sequence": 2, "effect_sequence": 3}\n',
                   b'{"charge_sequence": 2, "effect_sequence": null, "extra": 1}\n',
                   b'{"charge_sequence": 2, "charge_sequence": 2, "effect_sequence": null}\n',
                   record + b"synthetic-private-output\n")
        for output in invalid:
            self.assertEqual(prior.allocation_reply(20, output, b"")["response_class"], "unrecognized")
        self.assertEqual(prior.allocation_reply(True, record, b"")["exit_code"], "unavailable")
        self.assertEqual(prior.allocation_reply(256, record, b"")["exit_code"], "unavailable")

    def test_stderr_failure_reaps_both_replies_before_sanitized_readback_and_assertion(self):
        case = prior.PolicyEffectStoreNativeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        marker = b"synthetic-private-output"
        children = []

        class Child:
            returncode = 20

            def __init__(self, output, error):
                self.stdin = io.BytesIO()
                self.output, self.error = output, error
                self.completed = False

            def communicate(self, timeout):
                self.completed = True
                return self.output, self.error

        children.extend((Child(marker, marker), Child(b"StoreRefused\n", b"")))
        for child in children:
            self.addCleanup(child.stdin.close)
        readback = prior.allocation_evidence

        def observed_readback(*args):
            self.assertTrue(all(child.completed for child in children))
            return readback(*args)

        with patch.object(case, "actor", side_effect=children), patch.object(prior, "allocation_evidence", side_effect=observed_readback):
            with self.assertRaises(AssertionError) as refused:
                case.test_native_distinct_original_requests_cannot_exceed_one_retained_allocation()
        self.assertNotIn(marker.decode("ascii"), str(refused.exception))
        report = self.from_failure(refused.exception)
        self.assertEqual([row["response_class"] for row in report["replies"]], ["unrecognized", "StoreRefused"])
        self.assertEqual([row["stderr_present"] for row in report["replies"]], [True, False])
        self.assertEqual(report["local"], report["reopened"])
        self.assertEqual(report["local"]["raw_operations"], 0)

    def test_complete_original_lookup_and_reopen_report_one_charge_without_new_work(self):
        requests = self.selected_requests()
        original = self.store.allocate_synthetic(requests[0])
        before = self.path.read_bytes()
        report = self.evidence(requests, ((0, b'{"charge_sequence": 2, "effect_sequence": null}\n', b""),
                                         (20, b"StoreRefused\n", b"")))
        self.assertEqual(report["schema"], "synthetic-distinct-allocation-v1")
        self.assertEqual(report["native_error_details"], "not-emitted-by-original-actor")
        expected = dict(readback="available", raw_operations=1, raw_effects=0,
                        retained_originals=[True, False], charge_sequences=[2, None],
                        effect_sequences=[None, None], charged_operations=1, synthetic_effects=0, event_sequence=2)
        self.assertEqual(report["local"], expected)
        self.assertEqual(report["reopened"], expected)
        self.assertEqual(self.store.lookup_original(requests[0]), original)
        self.assertEqual(self.path.read_bytes(), before)

    def test_conflicting_complete_request_is_unavailable_without_claiming_zero_rows(self):
        requests = self.selected_requests()
        self.store.allocate_synthetic(requests[0])
        conflicting = self.request(revision=1, wire=requests[0].profile_wire, proposal="04")
        report = self.evidence((conflicting, requests[1]), ((20, b"StoreRefused\n", b""),) * 2)
        for key in ("local", "reopened"):
            self.assertEqual(report[key], dict(readback="unavailable"))
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_readback_and_reopen_errors_never_echo_private_exception_or_assume_zero(self):
        requests = self.selected_requests()
        replies = ((20, b"StoreOutcomeUnknown\n", b""),) * 2
        marker = "synthetic-private-error"
        with patch.object(self.store, "local_view", side_effect=source.StoreOutcomeUnknown(marker)):
            report = self.evidence(requests, replies)
        self.assertEqual(report["local"], dict(readback="unavailable"))
        self.assertEqual(report["reopened"]["readback"], "available")
        self.assertNotIn(marker, json.dumps(report))

        def unavailable():
            raise RuntimeError(marker)

        report = prior.allocation_evidence(replies, self.store, requests, unavailable)
        self.assertEqual(report["reopened"], dict(readback="unavailable"))
        self.assertNotIn(marker, json.dumps(report))

    def test_cancellation_propagates_during_local_and_reopened_observation(self):
        requests = self.selected_requests()
        replies = ((20, b"StoreOutcomeUnknown\n", b""),) * 2
        for interruption in (KeyboardInterrupt, SystemExit):
            with self.subTest(interruption=interruption.__name__):
                with patch.object(self.store, "local_view", side_effect=interruption):
                    with self.assertRaises(interruption):
                        self.evidence(requests, replies)

                def cancelled():
                    raise interruption

                with self.assertRaises(interruption):
                    prior.allocation_evidence(replies, self.store, requests, cancelled)

    @unittest.skipUnless(os.name == "posix", "original actor observation requires POSIX child processes")
    def test_strict_failure_keeps_original_native_reply_classes_and_zero_rows(self):
        case = prior.PolicyEffectStoreNativeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        actor = case.actor
        children, readers = [], []

        def controlled_actor(*args, **kwargs):
            child = actor(*args, **kwargs)
            children.append(child)
            if len(children) == 2:
                reader = sqlite3.connect(str(case.path), timeout=0, isolation_level=None)
                self.addCleanup(reader.close)
                reader.execute("BEGIN")
                self.assertEqual(reader.execute("SELECT count(*) FROM operations").fetchone(), (0,))
                readers.append(reader)
            return child

        readback = prior.allocation_evidence

        def after_children(*args):
            self.assertTrue(all(child.poll() is not None for child in children))
            self.assertTrue(readers[0].in_transaction)
            readers[0].execute("ROLLBACK")
            return readback(*args)

        with patch.object(case, "actor", side_effect=controlled_actor), patch.object(prior, "allocation_evidence", side_effect=after_children):
            with self.assertRaises(AssertionError) as refused:
                case.test_native_distinct_original_requests_cannot_exceed_one_retained_allocation()
        report = self.from_failure(refused.exception)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertFalse(readers[0].in_transaction)
        for reply in report["replies"]:
            self.assertEqual((reply["exit_code"], reply["response_class"], reply["stderr_present"]), (20, "StoreOutcomeUnknown", False))
            self.assertFalse(reply["native_error_overflow"])
            self.assertTrue(reply["native_execute_errors"])
            for error in reply["native_execute_errors"]:
                self.assertIn(error["phase"], ("begin", "event-insert", "operation-insert", "commit"))
                self.assertEqual(error["code"], 5)
        self.assertEqual(report["native_error_details"], "bounded-original-execute-report")
        self.assertEqual(report["local"], report["reopened"])
        self.assertEqual((report["local"]["raw_operations"], report["local"]["charged_operations"],
                          report["local"]["retained_originals"], report["local"]["event_sequence"]), (0, 0, [False, False], 1))

    @unittest.skipUnless(os.name == "posix", "original actor observation requires POSIX child processes")
    def test_postcommit_killed_original_is_reported_as_spent_without_retry_or_effect(self):
        case = prior.PolicyEffectStoreNativeTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        requests = self.selected_requests(case)
        child = case.actor("allocation", "allocation-after-commit", request=requests[0])
        child.kill()
        output, error = child.communicate(timeout=10)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        peer = case.actor("allocation", request=requests[1], ready=True)
        peer.stdin.write(b"go\n")
        peer.stdin.flush()
        peer_output, peer_error = peer.communicate(timeout=10)
        report = self.evidence(requests, ((child.returncode, output, error),
                                         (peer.returncode, peer_output, peer_error)), case)
        self.assertEqual(report["replies"], [dict(exit_code=-signal.SIGKILL, response_class="empty", stderr_present=False),
                                             dict(exit_code=20, response_class="StoreRefused", stderr_present=False)])
        self.assertEqual(report["local"], report["reopened"])
        self.assertEqual((report["local"]["raw_operations"], report["local"]["raw_effects"],
                          report["local"]["retained_originals"], report["local"]["charge_sequences"]), (1, 0, [True, False], [2, None]))


if __name__ == "__main__":
    unittest.main()
