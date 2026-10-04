"""Explicit resource policy and failure partition; synthetic worker math only."""

from contextlib import ExitStack
from dataclasses import FrozenInstanceError
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence
from offline_session import resource_launcher, worker_resources as limits
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError, run_limited_public_worker
from completion_test_support import final_signatures, released_bob


def supported_host():
    actual_uid = os.geteuid()
    stack = ExitStack()
    stack.enter_context(patch.object(limits.sys, "platform", "linux"))
    stack.enter_context(patch.object(limits.os, "geteuid", return_value=actual_uid))
    return stack


class ResourcePolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = limits.WorkerResourceLimits(2, 128 * 1024 * 1024)

    def test_policy_is_frozen_and_profiles_distinguish_both_maxima(self):
        with self.assertRaises(FrozenInstanceError):
            self.policy.cpu_seconds = 3
        self.assertEqual(self.policy.profile_digest_hex, limits.WorkerResourceLimits(2, 128 * 1024 * 1024).profile_digest_hex)
        self.assertNotEqual(self.policy.profile_digest_hex, limits.WorkerResourceLimits(1, 128 * 1024 * 1024).profile_digest_hex)
        self.assertNotEqual(self.policy.profile_digest_hex, limits.WorkerResourceLimits(2, 64 * 1024 * 1024).profile_digest_hex)
        self.assertRegex(self.policy.profile_digest_hex, "^[0-9a-f]{64}$")

    def test_cpu_requires_a_plain_finite_positive_integer(self):
        for value in (None, True, 0, -1, 31, 2.0, float("inf"), "2", 10**100):
            with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                limits.WorkerResourceLimits(value, self.policy.address_space_bytes)

    def test_address_space_requires_a_plain_bounded_integer(self):
        for value in (None, True, 0, -1, limits.MIN_ADDRESS_SPACE_BYTES - 1,
                      limits.MAX_ADDRESS_SPACE_BYTES + 1, 128.0, "128", 10**100):
            with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                limits.WorkerResourceLimits(2, value)

    def test_no_missing_or_substituted_policy_is_accepted(self):
        for value in (None, {}, (2, 128), True):
            with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                limits._supported(value)

    def test_unsupported_platform_root_and_missing_resource_module_reject(self):
        with supported_host():
            self.assertIs(limits._supported(self.policy), self.policy)
            for platform in ("darwin", "win32", "freebsd"):
                with patch.object(limits.sys, "platform", platform), self.assertRaises(WorkerError):
                    limits._supported(self.policy)
            with patch.object(limits.os, "geteuid", return_value=0), self.assertRaises(WorkerError):
                limits._supported(self.policy)
            with patch.object(limits, "resource", None), self.assertRaises(WorkerError):
                limits._supported(self.policy)
            with patch.object(limits, "resource", object()), self.assertRaises(WorkerError):
                limits._supported(self.policy)

    def test_canonical_bounded_control_encoding(self):
        with supported_host():
            raw = "2,134217728"
            self.assertEqual(limits._encode(self.policy), raw)
            self.assertEqual(limits._decode(raw), self.policy)
            for value in (None, "", "02,134217728", "+2,134217728", "2, 134217728",
                          "2,134217728,", "2", "2,1", "9" * 1000):
                with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                    limits._decode(value)

    def test_inherited_soft_and_hard_ceilings_are_never_increased(self):
        infinity = limits.resource.RLIM_INFINITY
        for old, expected in (((infinity, infinity), 4), ((2, 9), 2), ((3, 3), 3), ((infinity, 2), 2)):
            self.assertEqual(limits._ceiling(4, old), expected)
        self.assertEqual(limits._ceiling(0, (infinity, infinity)), 0)
        with self.assertRaises(WorkerError):
            limits._ceiling(1, (0, 10))

    def test_invalid_inherited_metadata_rejects(self):
        for value in (None, [], (1,), (True, 1), (1.0, 2), (-3, 9)):
            with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                limits._ceiling(2, value)

    def kernel(self):
        r = limits.resource
        values = {r.RLIMIT_CORE: (r.RLIM_INFINITY, r.RLIM_INFINITY),
                  r.RLIMIT_CPU: (1, 9), r.RLIMIT_AS: (192 * 1024 * 1024, 256 * 1024 * 1024)}
        calls = []
        def setter(kind, pair):
            calls.append((kind, pair))
            values[kind] = pair
        return values, calls, setter

    def test_installer_lowers_both_caps_disables_core_and_checks_readback(self):
        r = limits.resource
        original = [r.getrlimit(kind) for kind in (r.RLIMIT_CPU, r.RLIMIT_AS, r.RLIMIT_CORE)]
        values, calls, setter = self.kernel()
        with supported_host(), patch.object(r, "getrlimit", side_effect=lambda kind: values[kind]), \
                patch.object(r, "setrlimit", side_effect=setter):
            limits._install(self.policy)
        self.assertEqual(calls, [(r.RLIMIT_CORE, (0, 0)), (r.RLIMIT_CPU, (1, 1)),
                                (r.RLIMIT_AS, (self.policy.address_space_bytes,) * 2)])
        self.assertEqual([r.getrlimit(kind) for kind in (r.RLIMIT_CPU, r.RLIMIT_AS, r.RLIMIT_CORE)], original)

    def test_set_failure_is_sanitized_and_no_later_limit_is_attempted(self):
        r = limits.resource
        values, calls, setter = self.kernel()
        def failing(kind, pair):
            if kind == r.RLIMIT_CPU:
                raise OSError("synthetic private resource failure")
            setter(kind, pair)
        with supported_host(), patch.object(r, "getrlimit", side_effect=lambda kind: values[kind]), \
                patch.object(r, "setrlimit", side_effect=failing), self.assertRaises(WorkerError) as caught:
            limits._install(self.policy)
        self.assertEqual(calls, [(r.RLIMIT_CORE, (0, 0))])
        self.assertNotIn("synthetic private", str(caught.exception))

    def test_successful_set_with_wrong_readback_is_not_success(self):
        r = limits.resource
        values, calls, _ = self.kernel()
        with supported_host(), patch.object(r, "getrlimit", side_effect=lambda kind: values[kind]), \
                patch.object(r, "setrlimit", side_effect=lambda kind, pair: calls.append(kind)), \
                self.assertRaises(WorkerError):
            limits._install(self.policy)
        self.assertEqual(calls, [r.RLIMIT_CORE])


class ResourceTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.signature = released_bob(), final_signatures()[0]

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-resource-unit-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.entry = self.base / "entry"
        self.entry.write_text("#!/bin/sh\nprintf synthetic\n", encoding="ascii")
        self.entry.chmod(0o700)
        self.pin = _file_digest(self.entry)
        self.descriptors = []
        for name in ("a.lock", "b.lock", "slot.lock"):
            fd = os.open(self.base / name, os.O_RDWR | os.O_CREAT, 0o600)
            self.descriptors.append(fd)
            self.addCleanup(os.close, fd)
        self.policy = limits.WorkerResourceLimits(2, 128 * 1024 * 1024)

    def run_limited(self, **changes):
        config = dict(timeout=2, max_input_bytes=65536, expected_executable_sha256_hex=self.pin,
                      ownership_descriptors=tuple(self.descriptors[:2]), admission_descriptor=self.descriptors[2],
                      resource_limits=self.policy)
        config.update(changes)
        return run_limited_public_worker(str(self.entry), b"synthetic", **config)

    def test_unsupported_or_missing_policy_never_creates_a_guard(self):
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for value in (None, {}, False):
                with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                    self.run_limited(resource_limits=value)
            with patch.object(limits.sys, "platform", "darwin"), self.assertRaises(WorkerError):
                self.run_limited()
            spawn.assert_not_called()

    def test_required_admission_cannot_be_omitted_or_overlap_ownership(self):
        with supported_host(), patch("offline_session.public_worker.subprocess.Popen") as spawn:
            for value in (None, True, self.descriptors[0], 999999):
                with self.subTest(kind=type(value).__name__), self.assertRaises(WorkerError):
                    self.run_limited(admission_descriptor=value)
            spawn.assert_not_called()

    def test_missing_policy_adapter_returns_unknown_without_any_fallback(self):
        observer = SubprocessObservation(self.entry, expected_executable_sha256_hex=self.pin)
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch("offline_session.observation_verifier.run_public_worker") as legacy, \
                patch("offline_session.observation_verifier.run_guarded_public_worker") as guarded, \
                patch("offline_session.observation_verifier.run_admitted_public_worker") as admitted:
            result = observer.observe_limited(self.state, self.signature,
                ownership_descriptors=tuple(self.descriptors[:2]), admission_descriptor=self.descriptors[2], resource_limits=None)
        self.assertEqual(json.loads(result)["outcome"], "unknown")
        for call in (spawn, legacy, guarded, admitted):
            call.assert_not_called()

    def test_synthetic_normal_verdicts_keep_math_profile_and_exact_result_binding(self):
        observer = SubprocessObservation(self.entry, expected_executable_sha256_hex=self.pin)
        profile = observer.profile_digest_hex
        target = evidence.prepare(self.state, self.signature)
        fields = evidence._fields(target, profile)
        for verdict in ("verified", "rejected"):
            wire = exchange.canonical({"schema": "ptlc-observation-verifier-result-v1",
                "predicate": evidence.PREDICATE, "request_digest_hex": fields["request_digest_hex"], "outcome": verdict})
            with patch("offline_session.observation_verifier.run_limited_public_worker", return_value=wire) as work:
                result = observer.observe_limited(self.state, self.signature,
                    ownership_descriptors=tuple(self.descriptors[:2]), admission_descriptor=self.descriptors[2], resource_limits=self.policy)
            self.assertEqual(json.loads(result)["outcome"], verdict)
            self.assertIs(work.call_args.kwargs["resource_limits"], self.policy)
            self.assertEqual(observer.profile_digest_hex, profile)

    def launcher(self):
        return ["resource_launcher.py", str(self.entry), self.pin, "2,134217728",
                ",".join(str(value) for value in self.descriptors[:2]), str(self.descriptors[2])]

    def test_launcher_setup_failure_cannot_exec_or_leak_diagnostics(self):
        diagnostic = io.StringIO()
        with supported_host(), patch.object(resource_launcher.sys, "argv", self.launcher()), \
                patch.object(resource_launcher.os, "get_inheritable", return_value=True), \
                patch.object(resource_launcher.signal, "signal"), \
                patch.object(resource_launcher, "_install", side_effect=WorkerError("synthetic private setup failure")), \
                patch.object(resource_launcher.os, "execv") as execute, patch.object(resource_launcher.sys, "stderr", diagnostic):
            self.assertEqual(resource_launcher.main(), 2)
        execute.assert_not_called()
        self.assertEqual(diagnostic.getvalue(), "public worker resources unavailable\n")

    def test_noninheritable_capability_rejects_before_setup_and_exec(self):
        with supported_host(), patch.object(resource_launcher.sys, "argv", self.launcher()), \
                patch.object(resource_launcher, "_install") as install, patch.object(resource_launcher.os, "execv") as execute, \
                patch.object(resource_launcher.sys, "stderr", io.StringIO()):
            self.assertEqual(resource_launcher.main(), 2)
        install.assert_not_called()
        execute.assert_not_called()

    def test_exec_failure_after_setup_is_sanitized(self):
        diagnostic = io.StringIO()
        with supported_host(), patch.object(resource_launcher.sys, "argv", self.launcher()), \
                patch.object(resource_launcher.os, "get_inheritable", return_value=True), \
                patch.object(resource_launcher.signal, "signal"), patch.object(resource_launcher, "_install") as install, \
                patch.object(resource_launcher.os, "execv", side_effect=OSError("synthetic private exec failure")) as execute, \
                patch.object(resource_launcher.sys, "stderr", diagnostic):
            self.assertEqual(resource_launcher.main(), 2)
        install.assert_called_once_with(self.policy)
        execute.assert_called_once_with(str(self.entry), [str(self.entry)])
        self.assertEqual(diagnostic.getvalue(), "public worker resources unavailable\n")
