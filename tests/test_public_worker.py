"""Actual POSIX pipe, deadline and cleanup checks using synthetic actors."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shlex
import signal
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from offline_session import public_worker


@unittest.skipUnless(sys.platform in ("darwin", "linux"), "public worker requires Linux or macOS")
class PublicWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="synthetic-public-worker-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.marker = self.directory / "marker.json"
        self.actor = Path(__file__).with_name("public_worker_actor.py").resolve()

    def executable(self, mode):
        executable = self.directory / ("worker-" + mode)
        arguments = (sys.executable, "-B", str(self.actor), mode, str(self.marker))
        executable.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in arguments) + "\n",
                              encoding="utf-8")
        executable.chmod(0o700)
        return str(executable)

    @contextmanager
    def capture_processes(self, *, wait_for_closed_stdin=False):
        actual_popen = subprocess.Popen
        processes = []
        def spawn(*args, **kwargs):
            self.assertIs(kwargs["stdin"], subprocess.PIPE)
            self.assertIs(kwargs["stdout"], subprocess.PIPE)
            self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
            self.assertTrue(kwargs["start_new_session"])
            self.assertFalse(kwargs.get("shell", False))
            process = actual_popen(*args, **kwargs)
            processes.append(process)
            if wait_for_closed_stdin:
                deadline = time.monotonic() + 1.5
                while not self.marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(self.marker.exists(), "synthetic actor did not close stdin")
            return process
        try:
            with patch("offline_session.public_worker.subprocess.Popen", side_effect=spawn):
                yield processes
        finally:
            for process in processes:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=2)

    def assert_reaped(self, processes):
        self.assertEqual(len(processes), 1)
        process = processes[0]
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)

    def run_actor(self, mode, request=b"synthetic", *, timeout=1.5, **kwargs):
        return public_worker.run_public_worker(self.executable(mode), request, timeout=timeout,
                                               max_input_bytes=65536, **kwargs)

    def test_duplex_pipe_handles_large_request_and_exact_output_limit(self):
        with self.capture_processes() as processes:
            response = self.run_actor("duplex", b"i" * 65536)
            self.assertEqual(response, b"o" * 4096)
            self.assert_reaped(processes)

    def test_stdout_flood_with_large_pending_input_rejects_without_disk_spooling(self):
        executable = self.executable("flood")
        started = time.monotonic()
        with self.capture_processes() as processes, \
                patch("tempfile.TemporaryFile", side_effect=AssertionError("unexpected output spool")), \
                patch("tempfile.NamedTemporaryFile", side_effect=AssertionError("unexpected output spool")):
            with self.assertRaisesRegex(public_worker.WorkerError, "output bound"):
                public_worker.run_public_worker(executable, b"i" * 65536, timeout=5,
                                                max_input_bytes=65536)
            # The overflow reason distinguishes early rejection from a deadline.
            # Use a generous deadline without claiming a fixed throughput rate.
            self.assertLess(time.monotonic() - started, 5)
            self.assert_reaped(processes)

    def test_output_accepts_exactly_4096_and_rejects_4097(self):
        for size in (4096, 4097):
            with self.subTest(size=size), self.capture_processes() as processes:
                if size == 4096:
                    self.assertEqual(self.run_actor("output-4096"), b"o" * 4096)
                else:
                    with self.assertRaises(public_worker.WorkerError):
                        self.run_actor("output-4097")
                self.assert_reaped(processes)

    def test_lower_output_bound_is_enforced_on_actual_pipe(self):
        with self.capture_processes() as processes:
            with self.assertRaises(public_worker.WorkerError):
                self.run_actor("output-2", max_output_bytes=1)
            self.assert_reaped(processes)

    def test_stderr_flood_is_discarded_without_blocking_stdout(self):
        with self.capture_processes() as processes:
            self.assertEqual(self.run_actor("stderr-flood"), b"ok")
            self.assert_reaped(processes)

    def test_nonzero_worker_cannot_return_apparently_valid_stdout_or_private_details(self):
        executable = self.executable("nonzero")
        with self.capture_processes() as processes:
            with self.assertRaises(public_worker.WorkerError) as error:
                public_worker.run_public_worker(executable, b"synthetic", timeout=1.5,
                                                max_input_bytes=65536)
            message = str(error.exception)
            self.assertNotIn("SYNTHETIC_STDERR_MARKER", message)
            self.assertNotIn("apparently-successful", message)
            self.assertNotIn(executable, message)
            self.assertNotIn(str(self.directory), message)
            self.assert_reaped(processes)

    def test_early_stdin_close_rejects_even_with_success_exit_and_output(self):
        with self.capture_processes(wait_for_closed_stdin=True) as processes:
            with self.assertRaises(public_worker.WorkerError):
                self.run_actor("early-close", b"i" * 65536)
            self.assert_reaped(processes)

    def test_timeout_kills_and_reaps_direct_worker(self):
        started = time.monotonic()
        with self.capture_processes() as processes:
            with self.assertRaises(public_worker.WorkerError):
                self.run_actor("timeout", timeout=0.25)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assert_reaped(processes)

    def test_stdout_eof_does_not_accept_a_still_running_worker(self):
        started = time.monotonic()
        with self.capture_processes() as processes:
            with self.assertRaises(public_worker.WorkerError):
                self.run_actor("eof-alive", timeout=0.25)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assert_reaped(processes)

    def test_worker_that_never_reads_large_stdin_still_obeys_deadline(self):
        started = time.monotonic()
        with self.capture_processes() as processes:
            with self.assertRaises(public_worker.WorkerError):
                self.run_actor("never-read", b"i" * 65536, timeout=0.25)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assert_reaped(processes)
            self.assertTrue(processes[0].stdin.closed)
            self.assertTrue(processes[0].stdout.closed)

    def test_post_spawn_select_failure_and_interrupt_clean_up_child_and_pipes(self):
        for error in (OSError("synthetic selector detail"), KeyboardInterrupt("synthetic interrupt")):
            selection = selectors.DefaultSelector()
            try:
                with self.subTest(error=type(error).__name__), self.capture_processes() as processes, \
                        patch("offline_session.public_worker.selectors.DefaultSelector", return_value=selection), \
                        patch.object(selection, "select", side_effect=error):
                    expected = KeyboardInterrupt if isinstance(error, KeyboardInterrupt) else public_worker.WorkerError
                    with self.assertRaises(expected) as caught:
                        self.run_actor("never-read")
                    if isinstance(error, KeyboardInterrupt):
                        self.assertIs(caught.exception, error)
                    else:
                        self.assertNotIn("synthetic selector detail", str(caught.exception))
                    self.assert_reaped(processes)
                    self.assertTrue(processes[0].stdin.closed)
                    self.assertTrue(processes[0].stdout.closed)
            finally:
                selection.close()

    def test_success_or_nonzero_exit_does_not_signal_a_reaped_process_group(self):
        actual_killpg = os.killpg
        for mode in ("output-1", "nonzero"):
            with self.subTest(mode=mode), self.capture_processes() as processes, \
                    patch("offline_session.public_worker.os.killpg", wraps=actual_killpg) as kill_group:
                if mode == "output-1":
                    self.assertEqual(self.run_actor(mode), b"o")
                else:
                    with self.assertRaises(public_worker.WorkerError):
                        self.run_actor(mode)
                self.assert_reaped(processes)
                kill_group.assert_not_called()

    def test_inherited_stdout_obeys_deadline_and_stops_same_group_child(self):
        try:
            with self.capture_processes() as processes:
                with self.assertRaises(public_worker.WorkerError):
                    self.run_actor("inherited-stdout", timeout=0.5)
                self.assert_reaped(processes)
                self.assertTrue(self.marker.exists(), "synthetic child was not started")
                identities = json.loads(self.marker.read_text("ascii"))
                self.assertEqual(identities["parent"], processes[0].pid)
                heartbeat = self.marker.with_suffix(".heartbeat")
                self.assertTrue(heartbeat.exists(), "synthetic child did not run")
                # An orphan may remain a zombie briefly; it must not keep executing.
                time.sleep(0.05)
                before = heartbeat.read_bytes()
                time.sleep(0.1)
                self.assertEqual(heartbeat.read_bytes(), before)
        finally:
            if self.marker.exists():
                identities = json.loads(self.marker.read_text("ascii"))
                try:
                    if os.getpgid(identities["child"]) == identities["parent"]:
                        os.kill(identities["child"], signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_oversized_or_wrong_type_request_is_rejected_before_process_creation(self):
        executable = self.executable("output-1")
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for request in (b"x" * 65537, "synthetic", bytearray(b"synthetic"), None, True):
                with self.subTest(kind=type(request).__name__), self.assertRaises(public_worker.WorkerError):
                    public_worker.run_public_worker(executable, request, timeout=1, max_input_bytes=65536)
            with self.assertRaises(public_worker.WorkerError):
                public_worker.run_public_worker(executable, b"xx", timeout=1, max_input_bytes=1)
            spawn.assert_not_called()

    def test_invalid_deadlines_and_bounds_are_rejected_before_process_creation(self):
        executable = self.executable("output-1")
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for timeout in (True, None, 0, -1, 31, float("nan"), float("inf")):
                with self.subTest(timeout=timeout), self.assertRaises(public_worker.WorkerError):
                    public_worker.run_public_worker(executable, b"x", timeout=timeout, max_input_bytes=65536)
            for limit in (True, None, 0, -1, 1.0, 65537):
                with self.subTest(input_limit=limit), self.assertRaises(public_worker.WorkerError):
                    public_worker.run_public_worker(executable, b"x", timeout=1, max_input_bytes=limit)
            for limit in (True, None, 0, -1, 1.0, 4097):
                with self.subTest(output_limit=limit), self.assertRaises(public_worker.WorkerError):
                    public_worker.run_public_worker(executable, b"x", timeout=1,
                                                    max_input_bytes=65536, max_output_bytes=limit)
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
