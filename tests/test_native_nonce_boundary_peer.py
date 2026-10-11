"""Actual command pipes distinguish death observation from a pending kill request."""

import signal
import subprocess
import sys
import unittest

from native_nonce_boundary_actor import NativePeer


class PendingKill:
    """Delay delivery until wait, exposing premature stdin closure deterministically.

    The pipe peer and eventual SIGKILL are real processes. This adapter selects a
    pending-signal scheduling cut; it is not a native signing or journal proof.
    """

    def __init__(self, process, *, timeout=False):
        self.process, self.timeout = process, timeout
        self.requested = False

    def poll(self):
        return self.process.poll()

    @property
    def returncode(self):
        return self.process.returncode

    def kill(self):
        self.requested = True

    def wait(self, timeout):
        if self.timeout:
            raise subprocess.TimeoutExpired("synthetic pending kill", timeout)
        if self.requested:
            self.process.kill()
        return self.process.wait(timeout=timeout)

    def communicate(self, timeout):
        return self.process.communicate(timeout=timeout)


class NativeNonceBoundaryPeerTests(unittest.TestCase):
    def peer(self, *, error=False, timeout=False):
        code = ("import sys;"
                + ("sys.stderr.write('synthetic-prior-error');sys.stderr.flush();" if error else "")
                + "print('ready',flush=True);"
                  "line=sys.stdin.readline();"
                  "sys.stderr.write('synthetic-command-EOF' if not line else 'synthetic-unexpected-command');"
                  "sys.stderr.flush()")
        process = subprocess.Popen([sys.executable, "-B", "-c", code], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_process, process)
        self.assertEqual(process.stdout.readline(), b"ready\n")
        peer = object.__new__(NativePeer)
        peer.child = PendingKill(process, timeout=timeout)
        peer.sigkill, peer.normal_exit, peer.buffer = 0, 0, b""
        return peer, process

    @staticmethod
    def cleanup_process(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        process.communicate(timeout=3)

    def test_pending_kill_is_reaped_before_command_stdin_can_close(self):
        peer, process = self.peer()
        peer.kill_and_reap()
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(peer.sigkill, 1)
        self.assertEqual(peer.normal_exit, 0)

    def test_prior_native_error_remains_refused_even_after_death_is_observed(self):
        peer, process = self.peer(error=True)
        with self.assertRaises(AssertionError): peer.kill_and_reap()
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertEqual(peer.sigkill, 0)

    def test_unobserved_death_timeout_does_not_close_stdin_or_acknowledge_kill(self):
        peer, process = self.peer(timeout=True)
        with self.assertRaises(subprocess.TimeoutExpired): peer.kill_and_reap()
        self.assertIsNone(process.poll())
        self.assertFalse(process.stdin.closed)
        self.assertEqual(peer.sigkill, 0)


if __name__ == "__main__":
    unittest.main()
