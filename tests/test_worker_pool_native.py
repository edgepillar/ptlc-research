"""Real cross-process shared slots and owner/guard loss; synthetic worker math."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from offline_session.observation_store import ObservationStore
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.worker_pool import PoolBusy
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool


@unittest.skipUnless(os.name == "posix", "native shared admission requires POSIX locks and signals")
class NativeWorkerPoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.signature = released_bob(), final_signatures()[0]

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-native-pool-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.directory = self.base / "worker-pool"
        self.target = self.base / "public-target.json"
        self.target.write_text(json.dumps({"state": self.state, "signature_hex": self.signature.hex()}), encoding="ascii")

    def configure(self, slots=1):
        self.slots = slots
        self.pool = synthetic_pool(self.base, slot_limit=slots)

    def start(self, name):
        root = self.base / name
        marker = self.base / (name + ".started")
        release = self.base / (name + ".release")
        actor = Path(__file__).with_name("lease_owner_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), "store", str(root),
            str(self.base / (name + ".json")), str(marker), str(release),
            "--target", str(self.target), "--pool", str(self.directory), "--pool-slots", str(self.slots)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            release.touch()
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
            self.wait_capacity()
        self.addCleanup(cleanup)
        return child, marker, release

    def started(self, marker):
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertTrue(marker.exists(), "controlled admitted worker did not start")
        value = json.loads(marker.read_bytes())
        self.assertEqual((value["leases"], value["admission_leases"], value["unrelated_leaked"]), (2, 1, False))

    def wait_capacity(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with self.pool.acquire():
                    return
            except PoolBusy:
                time.sleep(0.005)
        self.fail("cooperative admitted worker did not release shared capacity")

    def normal_exit(self, child, release):
        release.touch()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))

    def reopened(self, name):
        root = self.base / name
        observer = SubprocessObservation(root / "controlled-worker",
            expected_executable_sha256_hex=_file_digest(root / "controlled-worker"))
        return ObservationStore.open(root, self.base / (name + ".json"), store_id_hex=STORE_ID,
            verifier=observer, worker_pool=self.pool, attempt_limit=2, target_limit=2)

    def test_two_independent_live_workers_fill_pool_and_third_has_no_charge_until_explicit_retry(self):
        self.configure(2)
        a, mark_a, release_a = self.start("a")
        self.started(mark_a)
        b, mark_b, release_b = self.start("b")
        self.started(mark_b)
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        c, mark_c, release_c = self.start("c")
        output, diagnostic = c.communicate(timeout=10)
        self.assertEqual((c.returncode, output.strip(), diagnostic), (20, b"StoreBusy", b""))
        self.assertFalse(mark_c.exists())
        with self.reopened("c") as store:
            self.assertEqual(store.summary().attempts_consumed, 0)
        self.normal_exit(a, release_a)
        again, marker, release = self.start("c")
        self.started(marker)
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        self.normal_exit(again, release)
        self.normal_exit(b, release_b)
        with self.reopened("c") as store:
            self.assertEqual(store.summary().attempts_consumed, 1)

    def test_owner_sigkill_releases_shared_slot_only_after_guarded_worker_termination(self):
        self.configure()
        child, marker, release = self.start("a")
        self.started(marker)
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        child.kill()
        _, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, diagnostic), (-signal.SIGKILL, b""))
        self.wait_capacity()
        self.assertFalse(release.exists())
        with self.reopened("a") as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)

    def test_guard_sigkill_keeps_shared_capacity_busy_after_owner_commits_unknown_and_closes(self):
        self.configure()
        child, marker, release = self.start("a")
        self.started(marker)
        child.stdin.write(b"kill-guard\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (0, b"unknown", b""))
        with self.assertRaises(PoolBusy):
            self.pool.acquire()
        other, other_marker, other_release = self.start("b")
        output, diagnostic = other.communicate(timeout=10)
        self.assertEqual((other.returncode, output.strip(), diagnostic), (20, b"StoreBusy", b""))
        self.assertFalse(other_marker.exists())
        with self.reopened("b") as store:
            self.assertEqual(store.summary().attempts_consumed, 0)
        release.touch()
        self.wait_capacity()
        with self.reopened("a") as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
        self.assertFalse(other_release.exists())

    def test_store_cancellation_stops_worker_and_releases_shared_slot_without_refund(self):
        self.configure()
        child, marker, release = self.start("a")
        self.started(marker)
        child.stdin.write(b"cancel\n")
        child.stdin.flush()
        output, diagnostic = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output.strip(), diagnostic), (20, b"KeyboardInterrupt", b""))
        self.wait_capacity()
        self.assertFalse(release.exists())
        with self.reopened("a") as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)
