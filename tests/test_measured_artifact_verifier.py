"""Public selection controls; synthetic results never establish curve truth."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange
from offline_session import measured_artifact_verifier as measured
from offline_session.observation_verifier import MAX_EXECUTABLE_BYTES
from offline_session.public_worker import WorkerError
from exchange_test_support import accepted, artifacts


class MeasuredArtifactVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="synthetic-measured-verifier-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.entry = self.directory / "selected-public-verifier"
        self.original = b"#!/bin/sh\nexit 0\n"
        self.entry.write_bytes(self.original)
        self.entry.chmod(0o700)
        self.pin = hashlib.sha256(self.original).hexdigest()
        _, self.context, _, self.bundle, _ = artifacts()
        self.request = exchange.verification_request(self.context, bundle=self.bundle)
        self.result = accepted(self.request)

    def select(self, **options):
        return measured.MeasuredSubprocessVerifier(self.entry,
            expected_executable_sha256_hex=self.pin, **options)

    def positive(self, executable, wire, **options):
        self.assertEqual(executable, str(self.entry))
        self.assertEqual(wire, exchange.canonical(self.request))
        self.assertEqual(options["max_input_bytes"], 32768)
        return exchange.canonical(self.result)

    def test_expected_pin_is_required_and_exact_before_filesystem_measurement(self):
        class ForeignString(str):
            def __str__(self):
                raise AssertionError("foreign string hook")
        invalid = (None, True, 1, bytes(32), "", "11" * 31, "AA" * 32,
                   "gg" * 32, self.pin + "\n", ForeignString(self.pin))
        with patch.object(measured, "_file_digest", side_effect=AssertionError("unexpected measurement")), \
                patch.object(Path, "is_file", side_effect=AssertionError("unexpected metadata")):
            with self.assertRaises(TypeError):
                measured.MeasuredSubprocessVerifier(self.entry)
            for pin in invalid:
                with self.subTest(pin_type=type(pin).__name__), self.assertRaises(exchange.VerificationError):
                    measured.MeasuredSubprocessVerifier(self.entry, expected_executable_sha256_hex=pin)

    def test_wrong_caller_pin_is_refused_without_discovery_refresh_or_launch(self):
        with patch("offline_session.artifact_verifier.run_public_worker") as runner, \
                patch.object(measured, "_file_digest", wraps=measured._file_digest) as digest:
            with self.assertRaisesRegex(exchange.VerificationError, "invalid measured public verifier selection"):
                measured.MeasuredSubprocessVerifier(self.entry, expected_executable_sha256_hex="00" * 32)
            self.assertEqual(digest.call_count, 1)
            runner.assert_not_called()
        self.assertEqual(self.entry.read_bytes(), self.original)

    def test_invalid_path_permission_and_deadline_are_sanitized_without_launch(self):
        paths = ("relative-verifier", self.directory / "absent", self.directory, None)
        with patch("offline_session.artifact_verifier.run_public_worker") as runner:
            for entry in paths:
                with self.subTest(path_type=type(entry).__name__), self.assertRaises(exchange.VerificationError) as error:
                    measured.MeasuredSubprocessVerifier(entry, expected_executable_sha256_hex=self.pin)
                self.assertNotIn(str(self.directory), str(error.exception))
            for timeout in (True, None, 0, -1, 31, float("nan"), float("inf"), "1"):
                with self.subTest(deadline_type=type(timeout).__name__), self.assertRaises(exchange.VerificationError):
                    self.select(timeout=timeout)
            self.entry.chmod(0o600)
            with self.assertRaises(exchange.VerificationError):
                self.select()
            runner.assert_not_called()

    def test_every_call_remeasures_entry_and_preserves_exact_public_receipt(self):
        original_request = copy.deepcopy(self.request)
        with patch.object(measured, "_file_digest", wraps=measured._file_digest) as digest, \
                patch("offline_session.artifact_verifier.run_public_worker", side_effect=self.positive) as runner:
            adapter = self.select(timeout=1)
            self.assertEqual(adapter(self.request), self.result)
            self.assertEqual(adapter(self.request), self.result)
            self.assertEqual(digest.call_count, 3)
            self.assertEqual(runner.call_count, 2)
            self.assertEqual(runner.call_args.kwargs["timeout"], 1)
        self.assertEqual(self.request, original_request)
        self.assertEqual(set(self.result), {"schema", "request_digest_hex", "valid"})

    def test_changed_removed_and_nonregular_entries_refuse_before_runner(self):
        for mode in ("changed", "removed", "directory", "fifo"):
            with self.subTest(mode=mode):
                self.entry.write_bytes(self.original)
                self.entry.chmod(0o700)
                adapter = self.select()
                if mode == "changed":
                    self.entry.write_bytes(b"#!/bin/sh\nexit 1\n")
                else:
                    self.entry.unlink()
                    if mode == "directory":
                        self.entry.mkdir()
                    elif mode == "fifo":
                        os.mkfifo(self.entry, 0o700)
                with patch("offline_session.artifact_verifier.run_public_worker") as runner:
                    with self.assertRaisesRegex(exchange.VerificationError, "selected public verifier is unavailable or changed") as error:
                        adapter(self.request)
                    runner.assert_not_called()
                self.assertNotIn(str(self.directory), str(error.exception))
                if self.entry.is_dir():
                    self.entry.rmdir()
                elif self.entry.exists():
                    self.entry.unlink()

    def test_empty_and_oversized_entry_refuse_the_existing_measurement_bound(self):
        adapter = self.select()
        for size in (0, MAX_EXECUTABLE_BYTES + 1):
            with self.subTest(size=size):
                with self.entry.open("wb") as output:
                    output.truncate(size)
                with patch("offline_session.artifact_verifier.run_public_worker") as runner:
                    with self.assertRaises(exchange.VerificationError):
                        adapter(self.request)
                    with self.assertRaises(exchange.VerificationError):
                        self.select()
                    runner.assert_not_called()

    def test_equal_byte_new_file_is_accepted_without_inode_or_origin_claim(self):
        adapter = self.select()
        prior = (self.entry.stat().st_dev, self.entry.stat().st_ino)
        replacement = self.directory / "equal-copy"
        replacement.write_bytes(self.original)
        replacement.chmod(0o700)
        replacement.replace(self.entry)
        self.assertNotEqual((self.entry.stat().st_dev, self.entry.stat().st_ino), prior)
        with patch("offline_session.artifact_verifier.run_public_worker", side_effect=self.positive):
            self.assertEqual(adapter(self.request), self.result)

    def test_restored_expected_bytes_pass_without_freshness_or_rollback_proof(self):
        adapter = self.select()
        self.entry.write_bytes(b"#!/bin/sh\nexit 1\n")
        with patch("offline_session.artifact_verifier.run_public_worker") as runner:
            with self.assertRaises(exchange.VerificationError):
                adapter(self.request)
            runner.assert_not_called()
        self.entry.write_bytes(self.original)
        with patch("offline_session.artifact_verifier.run_public_worker", side_effect=self.positive):
            self.assertEqual(adapter(self.request), self.result)

    def test_matching_entry_does_not_relax_exact_canonical_result_binding(self):
        adapter = self.select()
        raw = exchange.canonical(self.result)
        invalid = (b"", b"\xff", b"null", b" " + raw, raw + b"\n\n",
                   raw[:-1] + b',"valid":true}', json.dumps(self.result).encode("ascii"),
                   exchange.canonical(dict(self.result, valid=1)),
                   exchange.canonical(dict(self.result, request_digest_hex="00" * 32)),
                   exchange.canonical(dict(self.result, extra="field")))
        for response in invalid:
            with self.subTest(size=len(response)), \
                    patch("offline_session.artifact_verifier.run_public_worker", return_value=response), \
                    self.assertRaises(exchange.VerificationError):
                adapter(self.request)
        for suffix in (b"", b"\n"):
            with patch("offline_session.artifact_verifier.run_public_worker", return_value=raw + suffix):
                self.assertEqual(adapter(self.request), self.result)

    def test_transport_failures_sanitize_and_direct_cancellation_propagates(self):
        adapter = self.select()
        for error in (OSError("SYNTHETIC_PRIVATE_DETAIL"), WorkerError("SYNTHETIC_PRIVATE_DETAIL")):
            with patch("offline_session.artifact_verifier.run_public_worker", side_effect=error), \
                    self.assertRaisesRegex(exchange.VerificationError, "public verifier failed") as refused:
                adapter(self.request)
            self.assertNotIn("SYNTHETIC_PRIVATE_DETAIL", str(refused.exception))
        for cancellation in (KeyboardInterrupt, SystemExit):
            with patch("offline_session.artifact_verifier.run_public_worker", side_effect=cancellation), \
                    self.assertRaises(cancellation):
                adapter(self.request)

    def test_measurement_failures_sanitize_and_cancellation_never_launches(self):
        adapter = self.select()
        for error in (OSError("SYNTHETIC_PRIVATE_DETAIL"), ValueError("SYNTHETIC_PRIVATE_DETAIL")):
            with patch.object(measured, "_file_digest", side_effect=error), \
                    patch("offline_session.artifact_verifier.run_public_worker") as runner:
                with self.assertRaises(exchange.VerificationError) as refused:
                    adapter(self.request)
                with self.assertRaises(exchange.VerificationError):
                    self.select()
                self.assertNotIn("SYNTHETIC_PRIVATE_DETAIL", str(refused.exception))
                runner.assert_not_called()
        for cancellation in (KeyboardInterrupt, SystemExit):
            with patch.object(measured, "_file_digest", side_effect=cancellation), \
                    patch("offline_session.artifact_verifier.run_public_worker") as runner:
                with self.assertRaises(cancellation):
                    adapter(self.request)
                runner.assert_not_called()

    def test_changed_entry_refusal_leaves_original_exchange_state_unadvanced(self):
        adapter = self.select()
        state = exchange.start(self.context)
        original = copy.deepcopy(state)
        self.entry.write_bytes(b"#!/bin/sh\nexit 1\n")
        with patch("offline_session.artifact_verifier.run_public_worker") as runner:
            with self.assertRaises(exchange.VerificationError):
                exchange.retain_bitcoin(state, self.bundle, adapter)
            runner.assert_not_called()
        self.assertEqual(state, original)
        self.assertEqual(state["stage"], "BITCOIN_BOUND")


if __name__ == "__main__":
    unittest.main()
