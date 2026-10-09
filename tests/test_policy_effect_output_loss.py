"""Original actor output failures, real pipes and separately retained originals."""

import errno
import io
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
import policy_effect_store_actor as actor
import test_policy_effect_store as prior
from qualification import policy_effect_store as source


class SelectedPipeOutput:
    """Drain real writes locally; select a closed reader or a synthetic flush fault."""

    def __init__(self, *, lose_line=None, fail_flush=None):
        self.reader, self.writer = os.pipe()
        self.lose_line = lose_line
        self.fail_flush = fail_flush
        self.line = 1
        self.flushes = 0
        self.received = bytearray()
        self.failure = None

    def write(self, text):
        if self.line == self.lose_line and self.reader is not None:
            os.close(self.reader)
            self.reader = None
        wire = text.encode("ascii")
        try:
            count = os.write(self.writer, wire)
        except OSError as error:
            self.failure = error
            raise
        if count != len(wire):
            raise AssertionError("selected small pipe write was incomplete")
        self.received.extend(os.read(self.reader, count))
        if text == "\n":
            self.line += 1
        return len(text)

    def flush(self):
        self.flushes += 1
        if self.flushes == self.fail_flush:
            self.failure = OSError(errno.EIO, "synthetic-selected-flush-fault")
            raise self.failure

    def close(self):
        for name in ("reader", "writer"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)


@unittest.skipUnless(os.name == "posix", "selected native pipe controls require POSIX")
class PolicyEffectOutputLossTests(prior.PolicyEffectStoreCase):
    def context(self, revision=0):
        request = self.request(revision=revision)
        return dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                    revision=revision, profile_hex=prior.WIRE.hex(), proposal=request.proposal_digest_hex)

    def run_actor(self, *, lose_line=None, fail_flush=None, revision=0):
        self.output = SelectedPipeOutput(lose_line=lose_line, fail_flush=fail_flush)
        self.addCleanup(self.output.close)
        self.transactions = []
        self.constructor_calls = 0
        self.close_calls = []
        self.allocation_calls = 0

        def construct(path, labels):
            self.constructor_calls += 1
            store = source.OfflinePolicyEffectStore(path, labels)
            self.actor_store = store
            self.addCleanup(lambda: store._dispose() if not store._closed else None)

            def authorizer(action, first, second, database, trigger):
                if action == sqlite3.SQLITE_TRANSACTION:
                    self.transactions.append(first)
                return sqlite3.SQLITE_OK

            store._db.set_authorizer(authorizer)
            original_close, original_allocate = store.close, store.allocate_synthetic

            def close():
                self.close_calls.append(store._closed)
                return original_close()

            def allocate(request):
                self.allocation_calls += 1
                return original_allocate(request)

            store.close, store.allocate_synthetic = close, allocate
            return store

        argv = ["synthetic-actor", str(self.path), "allocation", "unused", "direct", "native-execute-errors-v1"]
        incoming = io.StringIO(json.dumps(self.context(revision)) + "\n")
        with patch.object(actor, "OfflinePolicyEffectStore", side_effect=construct), \
                patch.object(sys, "argv", argv), patch.object(sys, "stdin", incoming), \
                patch.object(sys, "stdout", self.output):
            return actor.main()

    def assert_rows(self, retained):
        local = prior.allocation_state(self.store, [self.request()])
        with self.open() as reopened:
            after = prior.allocation_state(reopened, [self.request()])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=retained, raw_effects=0,
            retained_originals=[bool(retained)], charge_sequences=[1 if retained else None],
            effect_sequences=[None], charged_operations=retained, synthetic_effects=0,
            event_sequence=retained))

    def assert_actor_closed(self, retained=1):
        self.assertEqual((self.constructor_calls, self.allocation_calls, self.close_calls), (1, 1, [False]))
        self.assertEqual(self.transactions, ["BEGIN", "COMMIT" if retained else "ROLLBACK"])
        self.assertTrue(self.actor_store._closed)
        with self.assertRaises(source.StoreRefused):
            self.actor_store.local_view()
        with self.assertRaises(sqlite3.ProgrammingError):
            self.actor_store._db.in_transaction
        self.assertEqual(self.actor_store._db.report(), dict(schema=observation.SCHEMA, errors=[], overflow=False))
        self.assert_rows(retained)

    def assert_received(self, lines, *, report=False):
        record = (json.dumps(dict(charge_sequence=1, effect_sequence=None)) + "\n").encode("ascii")
        native = observation.canonical(dict(schema=observation.SCHEMA, errors=[], overflow=False)) + b"\n"
        self.assertEqual(bytes(self.output.received), b"" if lines == 0 else record + (native if lines == 2 else b""))
        reply = prior.allocation_reply("unavailable", bytes(self.output.received), b"")
        self.assertEqual(reply["exit_code"], "unavailable")
        self.assertEqual(reply["response_class"], "empty" if lines == 0 else "allocation-record")
        self.assertEqual("native_execute_errors" in reply, report)
        if report:
            self.assertEqual(reply["native_execute_errors"], [])
            self.assertFalse(reply["native_error_overflow"])

    def test_real_pipe_success_delivers_reply_and_report_before_one_close(self):
        self.assertEqual(self.run_actor(), 0)
        self.assert_received(2, report=True)
        self.assertEqual(self.output.flushes, 2)
        self.assertIsNone(self.output.failure)
        self.assert_actor_closed()

    def test_native_pipe_failure_before_reply_retains_one_committed_original(self):
        with self.assertRaises(BrokenPipeError) as caught:
            self.run_actor(lose_line=1)
        self.assertIs(caught.exception, self.output.failure)
        self.assertEqual(caught.exception.errno, errno.EPIPE)
        self.assert_received(0)
        self.assertEqual(self.output.flushes, 0)
        self.assert_actor_closed()

    def test_selected_reply_flush_failure_keeps_delivered_record_without_report(self):
        with self.assertRaises(OSError) as caught:
            self.run_actor(fail_flush=1)
        self.assertIs(caught.exception, self.output.failure)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assert_received(1)
        self.assertEqual(self.output.flushes, 1)
        self.assert_actor_closed()

    def test_native_report_pipe_failure_keeps_first_reply_separate_from_completion(self):
        with self.assertRaises(BrokenPipeError) as caught:
            self.run_actor(lose_line=2)
        self.assertIs(caught.exception, self.output.failure)
        self.assertEqual(caught.exception.errno, errno.EPIPE)
        self.assert_received(1)
        self.assertEqual(self.output.flushes, 1)
        self.assert_actor_closed()

    def test_selected_report_flush_failure_keeps_report_without_normal_completion(self):
        with self.assertRaises(OSError) as caught:
            self.run_actor(fail_flush=2)
        self.assertIs(caught.exception, self.output.failure)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assert_received(2, report=True)
        self.assertEqual(self.output.flushes, 2)
        self.assert_actor_closed()

    def test_native_pipe_failure_hides_refusal_without_retaining_a_charge(self):
        with self.assertRaises(BrokenPipeError) as caught:
            self.run_actor(lose_line=1, revision=1)
        self.assertIs(caught.exception, self.output.failure)
        self.assertEqual(caught.exception.errno, errno.EPIPE)
        self.assert_received(0)
        self.assertEqual(self.output.flushes, 0)
        self.assert_actor_closed(retained=0)

    def closed_consumer_child(self, *, observed):
        command = [sys.executable, "-B", "-u", "-Werror::ResourceWarning",
                   str(Path(__file__).with_name("policy_effect_store_actor.py")),
                   str(self.path), "allocation", "unused", "ready"]
        if observed:
            command.append("native-execute-errors-v1")
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def reap():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

        self.addCleanup(reap)
        child.stdin.write((json.dumps(self.context()) + "\n").encode("ascii"))
        child.stdin.flush()
        with selectors.DefaultSelector() as selected:
            selected.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selected.select(timeout=10), "original output-loss actor did not reach readiness")
        self.assertEqual(child.stdout.readline(), b"ready\n")
        child.stdout.close()
        child.stdout = None
        child.stdin.write(b"go\n")
        child.stdin.close()
        child.stdin = None
        output, error = child.communicate(timeout=10)
        self.assertIsNone(output)
        self.assertEqual(child.returncode, 1)
        self.assertIsNotNone(child.poll())
        self.assertTrue(b"BrokenPipeError" in error, "original child did not report its native output fault")
        self.assertFalse(b"ResourceWarning" in error, "original child emitted a resource warning")
        reply = prior.allocation_reply(child.returncode, b"", error)
        self.assertEqual(reply, dict(exit_code=1, response_class="empty", stderr_present=True))
        self.assert_rows(1)

    def test_original_unbuffered_legacy_child_loses_reply_after_commit_and_exits_one(self):
        self.closed_consumer_child(observed=False)

    def test_original_unbuffered_observed_child_loses_reply_and_report_after_commit(self):
        self.closed_consumer_child(observed=True)
