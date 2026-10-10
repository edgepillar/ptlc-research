"""Actual subprocess evidence retention; synthetic tools never verify signatures."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from scripts import nom_native_command as native


class NativeCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)

    def run_tool(self, code, timeout=2):
        return native.run([sys.executable, "-c", code], environment={}, directory=self.root,
                          evidence=self.root, label="build", timeout=timeout)

    def record(self):
        return json.loads((self.root / "commands.jsonl").read_text().splitlines()[-1])

    def test_complete_stdout_and_stderr_remain_private_and_bound_to_zero_exit(self):
        self.assertEqual(self.run_tool("import sys;sys.stdout.write('public-result');sys.stderr.write('synthetic-diagnostic')"),
                         b"public-result")
        self.assertEqual((self.root / "build.stderr").read_bytes(), b"synthetic-diagnostic")
        record = self.record()
        self.assertEqual(record["result"], "RETURNED ZERO")
        self.assertEqual(record["complete"], {"stdout": True, "stderr": True})
        for name in ("build.stdout", "build.stderr", "commands.jsonl"):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o600)

    def test_nonzero_exit_retains_original_streams_and_failed_result(self):
        with self.assertRaises(WorkerError):
            self.run_tool("import sys;sys.stdout.write('original-output');sys.stderr.write('original-error');sys.exit(7)")
        self.assertEqual((self.root / "build.stdout").read_bytes(), b"original-output")
        self.assertEqual((self.root / "build.stderr").read_bytes(), b"original-error")
        self.assertEqual(self.record()["result"], "FAILED")
        self.assertEqual(self.record()["exit_status"], 7)

    def test_stdout_flood_preserves_only_bounded_prefix_and_marks_incomplete(self):
        with patch.object(native, "MAX_STDOUT", 32), self.assertRaises(WorkerError):
            self.run_tool("import sys;sys.stdout.write('x'*65536)")
        self.assertEqual((self.root / "build.stdout").read_bytes(), b"x" * 32)
        self.assertEqual(self.record()["truncated_stream"], "stdout")
        self.assertFalse(self.record()["complete"]["stdout"])

    def test_stderr_flood_has_its_own_bound_and_never_becomes_result_stdout(self):
        with patch.object(native, "MAX_STDERR", 16), self.assertRaises(WorkerError):
            self.run_tool("import sys;sys.stderr.write('e'*65536)")
        self.assertEqual((self.root / "build.stderr").read_bytes(), b"e" * 16)
        self.assertEqual(self.record()["truncated_stream"], "stderr")

    def test_timeout_retains_unknown_evidence_and_reaps_owned_direct_child(self):
        with self.assertRaises(WorkerError):
            self.run_tool("import os,sys,time;sys.stdout.write(str(os.getpid()));sys.stdout.flush();time.sleep(2)", timeout=0.3)
        pid = int((self.root / "build.stdout").read_bytes())
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)
        self.assertEqual(self.record()["result"], "UNKNOWN")
        self.assertFalse(self.record()["complete"]["stdout"])

    def test_existing_evidence_is_never_overwritten_or_reexecuted(self):
        self.run_tool("print('retained original')")
        before = (self.root / "build.stdout").read_bytes()
        with patch.object(native.subprocess, "Popen") as spawn, self.assertRaises(WorkerError):
            self.run_tool("print('replacement')")
        spawn.assert_not_called()
        self.assertEqual((self.root / "build.stdout").read_bytes(), before)


if __name__ == "__main__": unittest.main()
