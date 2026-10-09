"""Direct original actor output loss under selected buffered and unbuffered CPython."""

import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import unittest

import policy_effect_native_observation as observation
import test_policy_effect_store as prior


@unittest.skipUnless(os.name == "posix" and sys.implementation.name == "cpython",
                     "selected shutdown controls require POSIX CPython")
class PolicyEffectBufferedShutdownTests(prior.PolicyEffectStoreCase):
    def run_child(self, *, observed, refused=False, lose_reader=False, unbuffered=False):
        command = [sys.executable, "-B", "-Werror::ResourceWarning"]
        if unbuffered:
            command.append("-u")
        command.extend([str(Path(__file__).with_name("policy_effect_store_actor.py")),
                        str(self.path), "allocation", "unused", "ready"])
        if observed:
            command.append("native-execute-errors-v1")
        environment = dict(os.environ)
        environment.pop("PYTHONUNBUFFERED", None)
        child = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def reap():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

        self.addCleanup(reap)
        request = self.request(revision=1 if refused else 0)
        context = dict(labels=prior.asdict(prior.LABELS), operation=request.operation_id_hex,
                       revision=request.expected_revision, profile_hex=prior.WIRE.hex(),
                       proposal=request.proposal_digest_hex)
        child.stdin.write((json.dumps(context) + "\n").encode("ascii"))
        child.stdin.flush()
        with selectors.DefaultSelector() as selected:
            selected.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selected.select(timeout=10), "selected original actor missed readiness")
        self.assertEqual(child.stdout.readline(), b"ready\n")
        if lose_reader:
            child.stdout.close()
            child.stdout = None
        child.stdin.write(b"go\n")
        child.stdin.close()
        child.stdin = None
        output, error = child.communicate(timeout=10)
        self.assertIsNotNone(child.poll())
        self.assertFalse(b"ResourceWarning" in error, "selected child emitted a resource warning")

        if lose_reader:
            self.assertIsNone(output)
            expected_status = 1 if unbuffered else 120
            self.assertEqual(child.returncode, expected_status)
            self.assertTrue(b"Traceback (most recent call last):" in error,
                            "selected child did not expose its primary exception")
            self.assertEqual(error.count(b"BrokenPipeError"), 1 if unbuffered else 2,
                             "selected primary and shutdown output faults differed")
            self.assertEqual(b"Exception ignored" in error, not unbuffered,
                             "selected shutdown diagnostic differed")
            reply = prior.allocation_reply(child.returncode, b"", error)
            self.assertEqual(reply, dict(exit_code=expected_status, response_class="empty", stderr_present=True))
        else:
            expected_status = 20 if refused else 0
            self.assertEqual(child.returncode, expected_status)
            self.assertFalse(bool(error), "selected successful output emitted stderr")
            outcome = b"StoreRefused\n" if refused else (
                json.dumps(dict(charge_sequence=1, effect_sequence=None)) + "\n").encode("ascii")
            report = observation.canonical(dict(schema=observation.SCHEMA, errors=[], overflow=False)) + b"\n"
            self.assertEqual(output, outcome + (report if observed else b""))
            reply = prior.allocation_reply(child.returncode, output, error)
            self.assertEqual(reply, dict(exit_code=expected_status,
                response_class="StoreRefused" if refused else "allocation-record", stderr_present=False,
                **(dict(native_execute_errors=[], native_error_overflow=False) if observed else {})))

        retained = 0 if refused else 1
        local = prior.allocation_state(self.store, [request])
        with self.open() as reopened:
            after = prior.allocation_state(reopened, [request])
        self.assertEqual(local, after)
        self.assertEqual(after, dict(readback="available", raw_operations=retained, raw_effects=0,
            retained_originals=[bool(retained)], charge_sequences=[1 if retained else None],
            effect_sequences=[None], charged_operations=retained, synthetic_effects=0,
            event_sequence=retained))

    def test_default_buffered_legacy_success_delivers_record_and_exits_zero(self):
        self.run_child(observed=False)

    def test_default_buffered_observed_success_delivers_record_and_report(self):
        self.run_child(observed=True)

    def test_default_buffered_legacy_refusal_delivers_reply_and_exits_twenty(self):
        self.run_child(observed=False, refused=True)

    def test_default_buffered_observed_refusal_delivers_reply_and_empty_report(self):
        self.run_child(observed=True, refused=True)

    def test_default_buffered_legacy_output_loss_exits_120_with_retained_original(self):
        self.run_child(observed=False, lose_reader=True)

    def test_default_buffered_observed_output_loss_exits_120_without_reply_or_report(self):
        self.run_child(observed=True, lose_reader=True)

    def test_default_buffered_legacy_refusal_output_loss_exits_120_without_charge(self):
        self.run_child(observed=False, refused=True, lose_reader=True)

    def test_default_buffered_observed_refusal_output_loss_exits_120_without_charge(self):
        self.run_child(observed=True, refused=True, lose_reader=True)

    def test_unbuffered_legacy_refusal_output_loss_exits_one_without_charge(self):
        self.run_child(observed=False, refused=True, lose_reader=True, unbuffered=True)

    def test_unbuffered_observed_refusal_output_loss_exits_one_without_charge(self):
        self.run_child(observed=True, refused=True, lose_reader=True, unbuffered=True)
