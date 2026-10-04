"""Linux enforcement probes; other hosts explicitly test refusal, never skip.

Synthetic controlled workers establish CPU/address-space and lease behavior only.
The separate actual qualifier establishes the unchanged mathematical predicate.
"""

import fcntl
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from offline_session.observation_verifier import _file_digest
from offline_session.public_worker import WorkerError, run_limited_public_worker
from offline_session.worker_pool import PoolBusy
from offline_session.worker_resources import WorkerResourceLimits
from observation_store_test_support import synthetic_pool


class NativeWorkerResourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-native-resources-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "owner", self.base / "head.json"
        self.marker, self.release = self.base / "started.json", self.base / "release"
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(1, 128 * 1024 * 1024)
        self.native = sys.platform == "linux" and os.geteuid() != 0

    def require_native(self):
        if self.native:
            return True
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            with self.assertRaises(WorkerError):
                run_limited_public_worker(str(Path(sys.executable).resolve()), b"synthetic", timeout=2,
                    max_input_bytes=65536, expected_executable_sha256_hex="11" * 32,
                    ownership_descriptors=(3, 4), admission_descriptor=5, resource_limits=self.policy)
            spawn.assert_not_called()
        return False

    def start(self, worker):
        actor = Path(__file__).with_name("lease_owner_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), "limited", str(self.root),
            str(self.anchor), str(self.marker), str(self.release), "--worker", worker,
            "--pool", str(self.base / "worker-pool"), "--pool-slots", "1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            self.release.touch()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
            self.wait_capacity()
        self.addCleanup(cleanup)
        return child

    def started(self):
        deadline = time.monotonic() + 10
        while not self.marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(self.marker.exists(), "limited controlled worker did not start")
        value = json.loads(self.marker.read_bytes())
        self.assertEqual((value["leases"], value["admission_leases"], value["unrelated_leaked"]), (2, 1, False))
        self.assertEqual(value["resource_limits"], {"cpu": [1, 1],
            "address_space": [128 * 1024 * 1024] * 2, "core": [0, 0]})
        return value

    def wait_capacity(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with self.pool.acquire():
                    return
            except PoolBusy:
                time.sleep(0.005)
        self.fail("limited worker did not release shared capacity")

    def test_oversized_mapping_is_rejected_or_host_refuses_before_launch(self):
        if not self.require_native():
            return
        child = self.start("address-space")
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"completed", b""))
        self.assertTrue(self.started()["oversized_mapping_rejected"])
        self.wait_capacity()

    def test_cpu_hard_cap_survives_ignored_signal_or_host_refuses_before_launch(self):
        if not self.require_native():
            return
        descriptors = []
        child = None
        before = [resource.getrlimit(kind) for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_CORE)]
        try:
            for name in ("a.lock", "b.lock", "slot.lock"):
                fd = os.open(self.base / name, os.O_RDWR | os.O_CREAT, 0o600)
                descriptors.append(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            code = ("import json,os,resource,signal\n"
                    "print(json.dumps({'cpu':resource.getrlimit(resource.RLIMIT_CPU),"
                    "'address_space':resource.getrlimit(resource.RLIMIT_AS),"
                    "'core':resource.getrlimit(resource.RLIMIT_CORE),"
                    "'leases_inherited':all(os.get_inheritable(fd) for fd in " + repr(tuple(descriptors)) + ")}),flush=True)\n"
                    "signal.signal(signal.SIGXCPU,signal.SIG_IGN)\nwhile True: pass\n")
            entry = self.base / "cpu-entry"
            entry.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -B -c " + shlex.quote(code) + "\n", encoding="ascii")
            entry.chmod(0o700)
            launcher = Path(__file__).resolve().parents[1] / "offline_session/resource_launcher.py"
            child = subprocess.Popen([sys.executable, "-B", str(launcher), str(entry), _file_digest(entry),
                "1,134217728", ",".join(str(value) for value in descriptors[:2]), str(descriptors[2])],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=tuple(descriptors), close_fds=True)
            output, diagnostic = child.communicate(timeout=10)
            self.assertEqual((child.returncode, diagnostic), (-signal.SIGKILL, b""))
            self.assertEqual(json.loads(output), {"cpu": [1, 1], "address_space": [128 * 1024 * 1024] * 2,
                                                 "core": [0, 0], "leases_inherited": True})
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)
            for fd in descriptors:
                os.close(fd)
        self.assertEqual([resource.getrlimit(kind) for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_CORE)], before)

    def test_guard_loss_retains_capacity_until_limited_worker_exits_or_host_refuses(self):
        if not self.require_native():
            return
        child = self.start("cpu-burn")
        self.started()
        child.stdin.write(b"kill-guard\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"WorkerError", b""))
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        descriptor = os.open(self.root / "lease-a.lock", os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        self.release.touch()
        self.wait_capacity()
        descriptor = os.open(self.root / "lease-a.lock", os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    def test_cancellation_cleans_limited_worker_or_host_refuses_before_launch(self):
        if not self.require_native():
            return
        child = self.start("cpu-burn")
        self.started()
        child.stdin.write(b"cancel\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"KeyboardInterrupt", b""))
        self.wait_capacity()
        self.assertFalse(self.release.exists())

    def test_changed_pin_cannot_run_selected_entry_or_host_refuses_before_launch(self):
        if not self.require_native():
            return
        parent_limits = resource
        before = [parent_limits.getrlimit(kind) for kind in (parent_limits.RLIMIT_CPU, parent_limits.RLIMIT_AS, parent_limits.RLIMIT_CORE)]
        descriptors = []
        try:
            for name in ("a.lock", "b.lock", "slot.lock"):
                fd = os.open(self.base / name, os.O_RDWR | os.O_CREAT, 0o600)
                descriptors.append(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            entry = self.base / "entry"
            entry.write_text("#!/bin/sh\nprintf synthetic\n", encoding="ascii")
            entry.chmod(0o700)
            pin = _file_digest(entry)
            entry.write_text("#!/bin/sh\nprintf changed-synthetic\n", encoding="ascii")
            with self.assertRaises(WorkerError):
                run_limited_public_worker(str(entry), b"synthetic", timeout=2, max_input_bytes=65536,
                    expected_executable_sha256_hex=pin, ownership_descriptors=tuple(descriptors[:2]),
                    admission_descriptor=descriptors[2], resource_limits=self.policy)
        finally:
            for fd in descriptors:
                os.close(fd)
        self.assertEqual([parent_limits.getrlimit(kind) for kind in (parent_limits.RLIMIT_CPU, parent_limits.RLIMIT_AS, parent_limits.RLIMIT_CORE)], before)
