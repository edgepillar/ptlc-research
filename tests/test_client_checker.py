"""Public process boundaries using explicitly fabricated local checker claims.

These regular-file controls establish no curve verification or binary provenance.
The shared Rust process case separately selects the actual built checker.
"""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from offline_session.pr138 import CompatibilityError
from reference_client import checker
from reference_client.agreement import agreement_digest
from reference_client.plan import canonical
from reference_client.presignature import prepare_presignature


ROOT = Path(__file__).resolve().parents[1]
PROGRAM = '''import hashlib,json,os,sys,time
raw=sys.stdin.buffer.read()
request=json.loads(raw)
claim=dict(schema="ptlc-nom-client-presignature-result-v1",
 request_digest_hex=hashlib.sha256(raw).hexdigest(),
 context_digest_hex=request["context_digest_hex"],presignature_valid=True,
 scope="PUBLIC_MATHEMATICS_ONLY",action_permission="NONE",application="NO-GO",
 core="NO-GO",independent_assessment="UNFILLED",context_authentication="NOT_VERIFIED",
 chain_state="NOT_VERIFIED",signer_safety="NOT_ASSESSED")
def reply():return json.dumps(claim,sort_keys=True,separators=(",",":")).encode("ascii")
'''


class ClientCheckerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="public-checker-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.value = json.loads((ROOT / "reference_client/synthetic_presignature_request.json").read_bytes())
        self.counter = 0

    def executable(self, body='sys.stdout.buffer.write(reply())\n'):
        self.counter += 1
        path = self.root / ("checker-" + str(self.counter))
        # Explicitly selected regular synthetic programs. No link/FIFO/socket
        # fixture or copied native executable is needed for these controls.
        command = "exec " + shlex.quote(sys.executable) + " -B -c " + shlex.quote(PROGRAM + body)
        path.write_text("#!/bin/sh\n" + command + "\n", encoding="utf-8")
        path.chmod(0o700)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self, path, digest, value=None):
        return checker.check_preparation(self.value if value is None else value,
            executable=path, executable_sha256=digest)

    def cli(self, path, digest, *, raw=None, output=None):
        output = io.StringIO() if output is None else output
        errors = io.StringIO()
        status = checker.main(["--executable", str(path), "--sha256", digest],
            input_stream=io.BytesIO(canonical(self.value) if raw is None else raw),
            output_stream=output, error_stream=errors)
        return status, output, errors

    def test_selected_capture_does_not_authenticate_a_fabricated_mathematical_claim(self):
        self.value["presignature"]["s_hat_hex"] = "00" * 32
        original = copy.deepcopy(self.value)
        path, digest = self.executable()
        result = self.check(path, digest)
        self.assertEqual(result["backend_execution"], "COMPLETE_SELECTED_LOCAL_PROCESS")
        self.assertEqual(result["mathematical_result"], "SELECTED_EXECUTABLE_REPORTED_VALID")
        self.assertEqual(result["verification"], "CAPTURE_AND_ASSOCIATION_ONLY")
        self.assertEqual(result["source_authentication"], "NOT_ESTABLISHED_BY_THIS_TOOL")
        self.assertEqual(result["executable_selection"], "LOCAL_OWNER_SUPPLIED")
        self.assertEqual(result["action_permission"], "NONE")
        self.assertEqual((result["application"], result["core"]), ("NO-GO", "NO-GO"))
        self.assertEqual(result["independent_assessment"], "UNFILLED")
        self.assertEqual(self.value, original)

    def test_complete_original_result_is_returned_without_reencoding(self):
        path, digest = self.executable()
        result = self.check(path, digest)
        raw = result["checker_result_json"].encode("ascii")
        prepared = prepare_presignature(self.value)
        self.assertEqual(result["result_digest_hex"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(raw, canonical(json.loads(raw)))
        self.assertEqual(result["request_digest_hex"], prepared["request_digest_hex"])
        self.assertEqual(result["context_digest_hex"], prepared["crypto_request"]["context_digest_hex"])
        self.assertEqual(result["executable_bytes"], path.stat().st_size)
        self.assertEqual(result["process_exit"], 0)
        self.assertIs(result["process_stdout_complete"], True)
        self.assertIs(result["process_stderr_complete"], True)

    def test_cli_emits_one_bounded_public_response_without_private_selection_paths(self):
        path, digest = self.executable()
        status, output, errors = self.cli(path, digest)
        raw = output.getvalue().encode("ascii")
        self.assertEqual((status, errors.getvalue()), (0, ""))
        self.assertLessEqual(len(raw), checker.MAX_RESPONSE)
        self.assertEqual(raw, canonical(json.loads(raw)) + b"\n")
        self.assertNotIn(str(path), output.getvalue())
        self.assertNotIn("uid", json.loads(raw))

    def test_invalid_prefix_or_peer_overrides_never_reach_process_launch(self):
        path, digest = self.executable()
        candidates = []
        for field in ("executable", "sha256", "message_hex", "context_digest_hex", "backend"):
            value = copy.deepcopy(self.value)
            value[field] = "synthetic-peer-override"
            candidates.append(value)
        value = copy.deepcopy(self.value)
        value["bindings"][0]["entry_projection"]["amount"] = "999"
        candidates.append(value)
        with mock.patch.object(checker, "_capture") as capture:
            for value in candidates:
                with self.subTest(value=value), self.assertRaises(CompatibilityError):
                    self.check(path, digest, value)
            capture.assert_not_called()

    def test_wrong_digest_relative_or_unprotected_file_refuses_before_launch(self):
        path, digest = self.executable()
        with mock.patch.object(checker, "_capture") as capture:
            for selected, wanted in ((path, "00" * 32), (path, "AA" * 32),
                                     (Path(path.name), digest), (self.root, digest)):
                with self.subTest(selected=selected), self.assertRaises(CompatibilityError):
                    self.check(selected, wanted)
            for mode in (0o600, 0o722):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(CompatibilityError):
                    self.check(path, digest)
            capture.assert_not_called()

    def test_changed_executable_bytes_refuse_after_one_observed_process(self):
        path, unused = self.executable()
        body = "with open(" + repr(str(path)) + ", 'ab') as target:target.write(b'# changed')\n"
        body += "sys.stdout.buffer.write(reply())\n"
        program = "exec " + shlex.quote(sys.executable) + " -B -c " + shlex.quote(PROGRAM + body)
        path.write_text("#!/bin/sh\n" + program + "\n", encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with mock.patch.object(checker, "_capture", wraps=checker._capture) as capture:
            with self.assertRaises(CompatibilityError):
                self.check(path, digest)
            self.assertEqual(capture.call_count, 1)
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_observed_replacement_refuses_even_when_the_file_bytes_match(self):
        path, unused = self.executable()
        body = "from pathlib import Path\np=Path(" + repr(str(path)) + ")\n"
        body += "replacement=p.with_name('replacement')\nreplacement.write_bytes(p.read_bytes())\n"
        body += "replacement.chmod(0o700)\nos.replace(replacement,p)\nsys.stdout.buffer.write(reply())\n"
        program = "exec " + shlex.quote(sys.executable) + " -B -c " + shlex.quote(PROGRAM + body)
        path.write_text("#!/bin/sh\n" + program + "\n", encoding="utf-8")
        digest, inode = hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_ino
        with self.assertRaises(CompatibilityError):
            self.check(path, digest)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertNotEqual(path.stat().st_ino, inode)

    def test_nonzero_or_signalled_exit_with_matching_json_never_succeeds(self):
        for ending in ("raise SystemExit(2)", "import signal;os.kill(os.getpid(),signal.SIGTERM)"):
            path, digest = self.executable("sys.stdout.buffer.write(reply());sys.stdout.buffer.flush()\n" + ending)
            with self.subTest(ending=ending), self.assertRaises(CompatibilityError):
                self.check(path, digest)

    def test_empty_partial_late_or_foreign_result_bytes_refuse(self):
        bodies = ("pass", "sys.stdout.buffer.write(reply()[:-1])",
            "sys.stdout.buffer.write(reply()+b'\\n')",
            "claim['request_digest_hex']='00'*32;sys.stdout.buffer.write(reply())",
            "claim['context_digest_hex']='00'*32;sys.stdout.buffer.write(reply())",
            "claim['action_permission']='SIGN';sys.stdout.buffer.write(reply())",
            "claim['presignature_valid']=1;sys.stdout.buffer.write(reply())")
        for body in bodies:
            path, digest = self.executable(body)
            with self.subTest(body=body), self.assertRaises(CompatibilityError):
                self.check(path, digest)

    def test_either_stream_limit_stops_and_reaps_the_owned_process(self):
        original = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        for descriptor in (1, 2):
            path, digest = self.executable("while True:os.write(" + str(descriptor) + ",b'x'*4096)")
            with self.subTest(descriptor=descriptor), mock.patch.object(checker.subprocess, "Popen", side_effect=launch):
                with self.assertRaises(CompatibilityError):
                    self.check(path, digest)
                self.assertIsNotNone(children[-1].poll())
        self.assertEqual(len(children), 2)

    def test_timeout_stops_and_reaps_only_the_owned_checker_without_retry(self):
        original = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        path, digest = self.executable("sys.stdout.buffer.write(reply());sys.stdout.buffer.flush();time.sleep(60)")
        with mock.patch.object(checker, "PROCESS_SECONDS", .15), mock.patch.object(checker.subprocess, "Popen", side_effect=launch):
            with self.assertRaises(CompatibilityError):
                self.check(path, digest)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        # This is a bounded process-lifetime control, not an instruction-cut or
        # proof that a particular output write was reached before cancellation.

    def test_bounded_diagnostics_are_hashed_without_rejection_or_echo(self):
        diagnostic = b"synthetic public diagnostic\n"
        path, digest = self.executable("sys.stderr.buffer.write(" + repr(diagnostic) + ");sys.stdout.buffer.write(reply())")
        result = self.check(path, digest)
        self.assertEqual(result["process_stderr_bytes"], len(diagnostic))
        self.assertEqual(result["process_stderr_sha256"], hashlib.sha256(diagnostic).hexdigest())
        self.assertNotIn(diagnostic.decode("ascii"), canonical(result).decode("ascii"))

    def test_child_inherits_no_private_environment_and_receives_no_peer_arguments(self):
        body = "assert 'PTLC_SYNTHETIC_PRIVATE' not in os.environ\nassert len(sys.argv)==1\n"
        body += "assert os.environ['TZ']=='UTC' and os.environ['LANG']=='C'\n"
        body += "sys.stdout.buffer.write(reply())\n"
        path, digest = self.executable(body)
        with mock.patch.dict(os.environ, PTLC_SYNTHETIC_PRIVATE="synthetic-unshared-value"):
            self.assertEqual(self.check(path, digest)["action_permission"], "NONE")

    def test_cli_refuses_duplicate_or_late_input_before_launch_without_echo(self):
        path, digest = self.executable()
        valid = canonical(self.value)
        with mock.patch.object(checker, "_capture") as capture:
            for raw in (valid + b"{}", b'{"schema":"synthetic","schema":"duplicate"}', b'"synthetic-private-detail"'):
                status, output, errors = self.cli(path, digest, raw=raw)
                self.assertEqual(status, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("synthetic-private-detail", errors.getvalue())
            capture.assert_not_called()

    def test_output_failure_does_not_create_a_receipt_or_retry(self):
        class ShortOutput:
            def write(self, unused):
                return 0
            def flush(self):
                raise AssertionError("short write must refuse before flushing")
        path, digest = self.executable()
        with mock.patch.object(checker, "_capture", wraps=checker._capture) as capture:
            status, unused, errors = self.cli(path, digest, output=ShortOutput())
            self.assertEqual(status, 2)
            self.assertTrue(errors.getvalue().startswith("REFUSED:"))
            self.assertEqual(capture.call_count, 1)

    def test_standalone_discarded_or_closed_output_is_not_a_caller_receipt(self):
        path, digest = self.executable()
        argv = [sys.executable, "-B", "-m", "reference_client.checker",
                "--executable", str(path), "--sha256", digest]
        discarded = subprocess.run(argv, cwd=ROOT, input=canonical(self.value),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(discarded.returncode, 0)
        self.assertIsNone(discarded.stdout)
        self.assertEqual(discarded.stderr, b"")
        with subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            child.stdout.close()
            child.stdout = None
            missing, errors = child.communicate(canonical(self.value), timeout=15)
        self.assertIsNone(missing)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(errors, b"REFUSED: public checker result incomplete or invalid; no action authorized\n")

    def test_launch_error_is_sanitized_and_interrupt_cleanup_preserves_interrupt(self):
        path, digest = self.executable()
        with mock.patch.object(checker.subprocess, "Popen", side_effect=OSError("synthetic-private-detail")):
            status, output, errors = self.cli(path, digest)
            self.assertEqual((status, output.getvalue()), (2, ""))
            self.assertNotIn("synthetic-private-detail", errors.getvalue())
        original = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        selector = checker.selectors.DefaultSelector()
        with mock.patch.object(checker.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(selector, "select", side_effect=KeyboardInterrupt), \
                mock.patch.object(checker.subprocess, "Popen", side_effect=launch):
            with self.assertRaises(KeyboardInterrupt):
                self.check(path, digest)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_nonregular_path_and_binary_cap_refuse_without_link_or_large_file_fixtures(self):
        path, digest = self.executable()
        original = Path.lstat
        def indirect(candidate):
            return SimpleNamespace(st_mode=stat.S_IFLNK) if candidate == path else original(candidate)
        with mock.patch.object(Path, "lstat", indirect), self.assertRaises(CompatibilityError):
            self.check(path, digest)
        with mock.patch.object(checker, "MAX_EXECUTABLE", path.stat().st_size - 1), \
                mock.patch.object(checker.os, "open") as opened:
            with self.assertRaises(CompatibilityError):
                self.check(path, digest)
            opened.assert_not_called()

    def test_context_is_rederived_after_execution_and_never_automatically_retried(self):
        path, digest = self.executable()
        original = checker._capture
        def changed(*args):
            captured = original(*args)
            self.value["agreement"]["short"]["amount"] = "201"
            self.value["bindings"][0]["agreement_digest_hex"] = agreement_digest(self.value["agreement"])
            return captured
        with mock.patch.object(checker, "_capture", side_effect=changed) as capture:
            with self.assertRaises(CompatibilityError):
                self.check(path, digest)
            self.assertEqual(capture.call_count, 1)


if __name__ == "__main__":
    unittest.main()
