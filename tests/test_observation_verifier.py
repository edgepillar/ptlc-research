"""Synthetic process actors test transport and claims, not cryptographic truth."""

import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session import completion, exchange, observation_evidence as evidence
from offline_session import observation_verifier as verifier
from completion_test_support import final_signatures, released_bob


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "public worker requires Linux or macOS")
class ObservationVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.request = evidence.prepare(cls.state, cls.signature).verification_request
        cls.request_digest = completion.request_digest(json.loads(cls.request))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-observation-worker-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def result(self, outcome="verified"):
        return {"schema": verifier.RESULT_SCHEMA, "predicate": evidence.PREDICATE,
                "request_digest_hex": self.request_digest, "outcome": outcome}

    def actor(self, output=None, *, status=0, mode=None, timeout=2):
        """The selected entry file includes synthetic code; no math is performed."""
        if output is None:
            output = exchange.canonical(self.result())
        program = ("import signal,sys,time; signal.alarm(5); data=sys.stdin.buffer.read(); "
                   "sys.stderr.write('SYNTHETIC_STDERR_MARKER'); ")
        if mode == "sleep":
            program += "time.sleep(4); "
        if mode == "echo":
            program += "sys.stdout.buffer.write(data); "
        else:
            program += "sys.stdout.buffer.write(" + repr(output) + "); "
        program += "sys.stdout.buffer.flush(); sys.exit(" + str(status) + ")"
        executable = self.directory / "worker"
        arguments = (sys.executable, "-B", "-c", program)
        executable.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(item) for item in arguments) + "\n",
                              encoding="ascii")
        executable.chmod(0o700)
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        return verifier.SubprocessObservation(executable, expected_executable_sha256_hex=digest,
                                              timeout=timeout)

    def statement(self, worker, signature=None):
        raw = worker(self.state, self.signature if signature is None else signature)
        self.assertNotIn(b"SYNTHETIC_STDERR_MARKER", raw)
        self.assertEqual(raw, exchange.canonical(json.loads(raw)))
        return raw

    def outcome(self, worker):
        return evidence.parse_statement(self.state, self.signature, self.statement(worker),
            expected_verifier_profile_digest_hex=worker.profile_digest_hex).outcome

    def test_normal_positive_and_negative_require_exact_bound_result(self):
        for outcome in ("verified", "rejected"):
            for suffix in (b"", b"\n"):
                with self.subTest(outcome=outcome, suffix=suffix):
                    worker = self.actor(exchange.canonical(self.result(outcome)) + suffix)
                    self.assertEqual(self.outcome(worker), outcome)

    def test_profile_pins_contract_and_entry_file_separately_from_target(self):
        worker = self.actor()
        digest = hashlib.sha256(worker._executable.read_bytes()).hexdigest()
        expected = exchange.canonical({
            "schema": "ptlc-observation-verifier-profile-v1", "construction": "CANDIDATE-01",
            "predicate": "zenon-completion-v1", "request_schema": "ptlc-completion-request-v1",
            "result_schema": "ptlc-observation-verifier-result-v1",
            "statement_schema": "ptlc-observation-math-statement-v1",
            "adapter": "ptlc-observation-adapter-v1", "executable_sha256_hex": digest,
        })
        self.assertEqual(worker.profile_digest_hex,
                         hashlib.sha256(b"PTLC/observation-verifier-profile/v1\x00" + expected).hexdigest())
        with self.assertRaises(AttributeError):
            worker.profile_digest_hex = "11" * 32
        first_key = json.loads(self.statement(worker))["evidence_key_hex"]
        changed = self.actor(exchange.canonical(self.result()) + b"\n")
        self.assertNotEqual(changed.profile_digest_hex, worker.profile_digest_hex)
        self.assertNotEqual(json.loads(self.statement(changed))["evidence_key_hex"], first_key)
        self.assertEqual(self.outcome(worker), "unknown")

    def test_invalid_explicit_pins_paths_and_deadlines_never_launch(self):
        worker = self.actor()
        digest = worker._executable_digest
        invalid = [dict(expected_executable_sha256_hex=pin) for pin in
                   (None, bytes(32), True, "11" * 31, "AA" * 32, "gg" * 32, digest + "\n", "00" * 32)]
        invalid += [dict(expected_executable_sha256_hex=digest, timeout=item)
                    for item in (True, 0, -1, 31, float("nan"), float("inf"), "1")]
        with patch.object(verifier, "run_public_worker", side_effect=AssertionError("unexpected launch")):
            for options in invalid:
                with self.subTest(options=options), self.assertRaises(evidence.EvidenceError):
                    verifier.SubprocessObservation(worker._executable, **options)
            for path in ("worker", self.directory / "absent", self.directory):
                with self.subTest(path_type=type(path).__name__), self.assertRaises(evidence.EvidenceError):
                    verifier.SubprocessObservation(path, expected_executable_sha256_hex=digest)
            worker._executable.chmod(0o600)
            with self.assertRaises(evidence.EvidenceError):
                verifier.SubprocessObservation(worker._executable, expected_executable_sha256_hex=digest)

    def test_runtime_changed_removed_and_nonregular_file_are_unknown_without_launch(self):
        for mode in ("changed", "removed", "fifo"):
            with self.subTest(mode=mode):
                worker = self.actor()
                if mode == "changed":
                    worker._executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                else:
                    worker._executable.unlink()
                    if mode == "fifo":
                        os.mkfifo(worker._executable, 0o700)
                with patch.object(verifier, "run_public_worker", side_effect=AssertionError("unexpected launch")):
                    self.assertEqual(self.outcome(worker), "unknown")
                if mode == "fifo":
                    worker._executable.unlink()

    def test_entry_file_measurement_rejects_empty_and_oversized_regular_files(self):
        path = self.directory / "measure"
        path.touch()
        with self.assertRaises(evidence.EvidenceError):
            verifier._file_digest(path)
        with path.open("wb") as output:
            output.truncate(verifier.MAX_EXECUTABLE_BYTES + 1)
        with self.assertRaises(evidence.EvidenceError):
            verifier._file_digest(path)

    def test_all_result_fields_missing_extra_or_changed_are_unknown(self):
        variants = []
        for field in self.result():
            changed = self.result()
            del changed[field]
            variants.append(changed)
            changed = self.result()
            changed[field] = True
            variants.append(changed)
        for field, value in (("schema", completion.RESULT_SCHEMA), ("predicate", "other-v1"),
                             ("request_digest_hex", "00" * 32), ("outcome", "unknown")):
            changed = self.result()
            changed[field] = value
            variants.append(changed)
        variants.append(dict(self.result(), source="synthetic"))
        variants.append({"schema": completion.RESULT_SCHEMA, "valid": False,
                         "request_digest_hex": self.request_digest, "bitcoin_signature_hex": ""})
        for index, value in enumerate(variants):
            with self.subTest(index=index):
                self.assertEqual(self.outcome(self.actor(exchange.canonical(value))), "unknown")

    def test_malformed_noncanonical_duplicate_and_oversized_output_are_unknown(self):
        valid = exchange.canonical(self.result())
        variants = (b"", b"{", b"null", b"[]", b"\xff", valid + b"\n\n", b" " + valid,
                    json.dumps(self.result()).encode("ascii"),
                    valid[:-1] + b',"outcome":"verified"}', b"o" * 4097)
        for index, output in enumerate(variants):
            with self.subTest(index=index):
                self.assertEqual(self.outcome(self.actor(output)), "unknown")

    def test_nonzero_exit_even_with_matching_negative_output_is_unknown(self):
        worker = self.actor(exchange.canonical(self.result("rejected")), status=2)
        self.assertEqual(self.outcome(worker), "unknown")

    def test_timeout_is_unknown_and_direct_child_is_reaped(self):
        worker = self.actor(mode="sleep", timeout=0.1)
        processes = []
        actual = subprocess.Popen
        def spawn(*args, **kwargs):
            process = actual(*args, **kwargs)
            processes.append(process)
            return process
        with patch("offline_session.public_worker.subprocess.Popen", side_effect=spawn):
            self.assertEqual(self.outcome(worker), "unknown")
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)

    def test_cancellation_propagates_without_a_negative_or_state_mutation(self):
        worker = self.actor()
        before = copy.deepcopy(self.state)
        for error in (KeyboardInterrupt, SystemExit):
            with self.subTest(error=error.__name__), \
                    patch.object(verifier, "run_public_worker", side_effect=error):
                with self.assertRaises(error):
                    worker(self.state, self.signature)
        self.assertEqual(self.state, before)

    def test_invalid_local_target_never_launches_or_becomes_a_statement(self):
        worker = self.actor()
        with patch.object(verifier, "run_public_worker", side_effect=AssertionError("unexpected launch")):
            for signature in (None, bytearray(64), bytes(63), bytes(65)):
                with self.subTest(signature_type=type(signature).__name__), self.assertRaises(evidence.EvidenceError):
                    worker(self.state, signature)
            with self.assertRaises(evidence.EvidenceError):
                worker({}, self.signature)

    def test_worker_receives_only_the_exact_public_predicate_request(self):
        worker = self.actor(mode="echo")
        captured = []
        actual = verifier.run_public_worker
        def run(executable, wire, **options):
            captured.append((wire, options))
            return actual(executable, wire, **options)
        with patch.object(verifier, "run_public_worker", side_effect=run):
            raw = self.statement(worker)
        self.assertEqual(json.loads(raw)["outcome"], "unknown")
        self.assertEqual(captured, [(self.request, {"timeout": 2, "max_input_bytes": 65536,
                                                   "max_output_bytes": 4096})])
        self.assertIsNone(json.loads(captured[0][0])["bitcoin"])

    def test_normal_statement_for_another_signature_is_unknown_and_state_is_unchanged(self):
        worker = self.actor()
        before = copy.deepcopy(self.state)
        raw = self.statement(worker, bytes(64))
        self.assertEqual(json.loads(raw)["outcome"], "unknown")
        self.assertNotEqual(json.loads(raw)["request_digest_hex"], self.request_digest)
        self.assertEqual(self.state, before)


if __name__ == "__main__":
    unittest.main()
