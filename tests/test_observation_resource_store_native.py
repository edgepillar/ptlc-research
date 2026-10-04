"""Linux v4 store lifecycle with controlled nonforking workers, no math proof.

Other hosts assert refusal before store/worker creation; these are not skips or
evidence of Linux enforcement. Actual Rust verdicts are qualified separately.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from offline_session import exchange
from offline_session.observation_store import ObservationStore, StoreBusy, StoreError
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.worker_pool import PoolBusy
from offline_session.worker_resources import WorkerResourceLimits
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


class NativeResourceStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.synthetic = synthetic_verifier()

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-native-resource-store-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"
        self.marker, self.release = self.base / "started.json", self.base / "release"
        self.target = self.base / "target.json"
        self.target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex()}))
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(1, 128 * 1024 * 1024)

    def require_native(self):
        if sys.platform == "linux" and os.geteuid() != 0:
            return True
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            with self.assertRaises(StoreError):
                ObservationStore.open_limited(self.root, self.anchor, store_id_hex=STORE_ID,
                    verifier=self.synthetic, worker_pool=self.pool, resource_limits=self.policy,
                    attempt_limit=2, target_limit=2)
            spawn.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertFalse(self.anchor.exists())
        return False

    def start(self, worker):
        actor = Path(__file__).with_name("lease_owner_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), "store-limited",
            str(self.root), str(self.anchor), str(self.marker), str(self.release),
            "--target", str(self.target), "--worker", worker, "--pool",
            str(self.base / "worker-pool"), "--pool-slots", "1"],
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
        self.assertTrue(self.marker.exists(), "controlled limited store worker did not start")
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
        self.fail("limited store worker did not release capacity")

    def open(self):
        entry = self.root / "controlled-worker"
        verifier = SubprocessObservation(entry.resolve(), expected_executable_sha256_hex=_file_digest(entry))
        return ObservationStore.open_limited(self.root, self.anchor, store_id_hex=STORE_ID,
            verifier=verifier, worker_pool=self.pool, resource_limits=self.policy, attempt_limit=2, target_limit=2)

    def recovered_unknown(self):
        with self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
            self.assertIsNone(store.known_statement(self.state, self.signature))
        anchor = json.loads(self.anchor.read_bytes())
        self.assertEqual((anchor["version"], anchor["worker_resource_profile_digest_hex"]),
                         (4, self.policy.profile_digest_hex))

    def test_address_space_refusal_is_charged_unknown_or_host_refuses_before_creation(self):
        if not self.require_native():
            return
        child = self.start("address-space")
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        self.assertTrue(self.started()["oversized_mapping_rejected"])
        self.wait_capacity()
        self.recovered_unknown()

    def test_cpu_death_is_charged_unknown_or_host_refuses_before_creation(self):
        if not self.require_native():
            return
        child = self.start("cpu-burn")
        self.started()
        self.release.touch()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        self.wait_capacity()
        self.recovered_unknown()

    def test_owner_death_recovers_pending_under_same_policy_or_host_refuses(self):
        if not self.require_native():
            return
        child = self.start("cpu-burn")
        self.started()
        child.kill()
        _, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, diagnostic), (-signal.SIGKILL, b""))
        self.wait_capacity()
        self.recovered_unknown()

    def test_guard_loss_excludes_reopen_until_worker_exit_or_host_refuses(self):
        if not self.require_native():
            return
        child = self.start("cpu-burn")
        self.started()
        child.stdin.write(b"kill-guard\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        with patch("offline_session.observation_store.sqlite3.connect") as connect:
            with self.assertRaises(StoreBusy):
                self.open()
            connect.assert_not_called()
        self.release.touch()
        self.wait_capacity()
        self.recovered_unknown()

    def test_cancellation_commits_unknown_and_cleans_without_release_or_host_refuses(self):
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
        self.recovered_unknown()
