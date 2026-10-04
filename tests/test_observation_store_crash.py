"""Real POSIX owner death and locking, with synthetic public-worker returns."""

import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence, observation_records as records
from offline_session.observation_store import ObservationStore, StoreOwnershipError, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_verifier


@unittest.skipUnless(os.name == "posix", "owner-death qualification requires POSIX signals and locks")
class ObservationStoreCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.verifier = synthetic_verifier()
        unknown = evidence.unknown_statement(cls.state, cls.signature,
                                              verifier_profile_digest_hex=cls.verifier.profile_digest_hex)
        cls.verified = exchange.canonical(dict(json.loads(unknown), outcome="verified"))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-observation-death-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"
        self.target = self.base / "public-target.json"
        self.target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex(),
                                                    "statement": json.loads(self.verified)}))
        self.initialize()

    def open(self, **options):
        return ObservationStore.open(self.root, self.anchor, store_id_hex=STORE_ID,
            verifier=self.verifier, attempt_limit=2, target_limit=2, **options)

    def initialize(self):
        with self.open():
            pass

    def command(self, mode, *extra, root=None, checkpoint=None):
        actor = Path(__file__).with_name("observation_store_actor.py")
        return [sys.executable, "-B", str(actor), mode, str(self.root if root is None else root),
                str(self.anchor if checkpoint is None else checkpoint), *extra]

    def probe(self, *, root=None, checkpoint=None, forbid_connect=False):
        extra = ("--forbid-connect",) if forbid_connect else ()
        return subprocess.run(self.command("probe", *extra, root=root, checkpoint=checkpoint),
                              capture_output=True, text=True, timeout=10)

    def start(self, mode, *extra):
        child = subprocess.Popen(self.command(mode, *extra), stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.addCleanup(cleanup)
        return child

    def wait_line(self, child, expected):
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=10), "actor did not reach bounded checkpoint")
        self.assertEqual(child.stdout.readline().strip(), expected)

    def kill(self, child):
        child.kill()
        _, diagnostics = child.communicate(timeout=10)
        self.assertEqual(child.returncode, -signal.SIGKILL)
        self.assertEqual(diagnostics, b"")

    def test_sigkill_at_every_admission_worker_and_result_boundary(self):
        cases = (("admission.before_db_commit", 0, None, 0),
                 ("admission.after_db_commit", None, None, 0),
                 ("admission.after_checkpoint_replace", 1, None, 0),
                 ("admission.after_checkpoint_commit", 1, None, 0),
                 ("admission.committed", 1, None, 0),
                 ("worker.returned", 1, None, 1),
                 ("result.before_db_commit", 1, None, 1),
                 ("result.after_db_commit", None, None, 1),
                 ("result.after_checkpoint_replace", 1, self.verified, 1),
                 ("result.after_checkpoint_commit", 1, self.verified, 1),
                 ("result.committed", 1, self.verified, 1))
        for index, (point, attempts, known, calls) in enumerate(cases):
            with self.subTest(point=point):
                self.root, self.anchor = self.base / str(index), self.base / (str(index) + ".json")
                self.initialize()
                marker = self.base / (str(index) + ".calls")
                child = self.start("crash", "--point", point, "--target", str(self.target), "--marker", str(marker))
                self.wait_line(child, b"paused")
                self.kill(child)
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, calls)
                with patch.object(SubprocessObservation, "observe_owned") as worker:
                    if attempts is None:
                        before = ((self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes())
                        with self.assertRaises(StoreQuarantined):
                            self.open()
                        self.assertEqual(((self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes()), before)
                    else:
                        with self.open() as store:
                            self.assertEqual(store.summary().attempts_consumed, attempts)
                            self.assertEqual(store.summary().pending_attempts, 0)
                            self.assertEqual(store.known_statement(self.state, self.signature), known)
                        worker.assert_not_called()
                self.assertEqual(len(marker.read_bytes()) if marker.exists() else 0, calls)

    def test_killed_recheck_retains_old_normal_and_consumed_allowance(self):
        with self.open() as store, patch.object(SubprocessObservation, "observe_owned", return_value=self.verified):
            store.observe(self.state, self.signature)
        marker = self.base / "recheck.calls"
        child = self.start("crash", "--recheck", "--point", "worker.returned",
                           "--target", str(self.target), "--marker", str(marker))
        self.wait_line(child, b"paused")
        self.kill(child)
        with self.open() as store, patch.object(SubprocessObservation, "observe_owned") as worker:
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().attempts_consumed, 2)
            with self.assertRaises(records.RecordExhausted):
                store.observe(self.state, self.signature, recheck=True)
            worker.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"1")

    def test_locks_precede_database_read_and_owner_death_releases_persistent_lock_files(self):
        child = self.start("hold")
        self.wait_line(child, b"held")
        locks = (self.root / "observations.lock", self.anchor.with_name(self.anchor.name + ".lock"))
        inodes = tuple(path.stat().st_ino for path in locks)
        blocked = self.probe(forbid_connect=True)
        self.assertEqual((blocked.returncode, blocked.stdout.strip(), blocked.stderr), (20, "StoreBusy", ""))
        self.kill(child)
        opened = self.probe()
        self.assertEqual((opened.returncode, opened.stdout.strip(), opened.stderr), (0, "opened", ""))
        self.assertEqual(tuple(path.stat().st_ino for path in locks), inodes)

    def test_same_database_with_another_checkpoint_blocks_before_read(self):
        with self.open():
            blocked = self.probe(checkpoint=self.base / "different.json", forbid_connect=True)
            self.assertEqual((blocked.returncode, blocked.stdout.strip(), blocked.stderr), (20, "StoreBusy", ""))
        self.assertFalse((self.base / "different.json").exists())

    def test_same_checkpoint_with_another_database_blocks_before_read_and_releases_first_lock(self):
        other_root = self.base / "other"
        with self.open():
            blocked = self.probe(root=other_root, forbid_connect=True)
            self.assertEqual((blocked.returncode, blocked.stdout.strip(), blocked.stderr), (20, "StoreBusy", ""))
        self.assertFalse((other_root / "observations.sqlite3").exists())
        opened = self.probe(root=other_root, checkpoint=self.base / "other.json")
        self.assertEqual((opened.returncode, opened.stdout.strip(), opened.stderr), (0, "opened", ""))

    def test_another_owner_cannot_recover_pending_while_original_owner_is_live(self):
        marker = self.base / "live.calls"
        child = self.start("crash", "--point", "admission.committed",
                           "--target", str(self.target), "--marker", str(marker))
        self.wait_line(child, b"paused")
        blocked = self.probe(forbid_connect=True)
        self.assertEqual((blocked.returncode, blocked.stdout.strip(), blocked.stderr), (20, "StoreBusy", ""))
        child.stdin.write(b"1")
        child.stdin.flush()
        _, diagnostics = child.communicate(timeout=10)
        self.assertEqual((child.returncode, diagnostics), (0, b""))
        with self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().attempts_consumed, 1)
        self.assertEqual(marker.read_bytes(), b"1")

    def test_forked_handle_cannot_publish_close_or_unlock_parent_owner(self):
        with self.open() as store:
            reader, writer = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(reader)
                try:
                    denied = 0
                    for call in (store.summary, lambda: store.observe(self.state, self.signature), store.close):
                        try:
                            call()
                        except StoreOwnershipError:
                            denied += 1
                    store._release()
                    os.write(writer, b"safe" if denied == 3 else b"unsafe")
                finally:
                    os.close(writer)
                    os._exit(0)
            os.close(writer)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(reader, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=10), "fork did not report ownership check")
                self.assertEqual(os.read(reader, 16), b"safe")
            finally:
                os.close(reader)
                if os.waitpid(child, os.WNOHANG)[0] == 0:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            blocked = self.probe(forbid_connect=True)
            self.assertEqual((blocked.returncode, blocked.stdout.strip(), blocked.stderr), (20, "StoreBusy", ""))
            self.assertEqual(store.summary().attempts_consumed, 0)
