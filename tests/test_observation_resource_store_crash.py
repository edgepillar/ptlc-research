"""Real POSIX v4 SQLite/checkpoint SIGKILL cuts with synthetic verdicts.

macOS explicitly simulates only the supported-host selector. SQLite, locks,
process death and rollback are real on both hosts; this proves no Linux cap.
The actual Linux worker qualifier is separate and never simulates its host.
"""

from contextlib import ExitStack, contextmanager
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
from offline_session.observation_store import ObservationStore, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from offline_session.worker_resources import WorkerResourceLimits
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


@unittest.skipUnless(os.name == "posix", "crash qualification requires POSIX signals and locks")
class ResourceStoreCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.verifier = synthetic_verifier()
        unknown = evidence.unknown_statement(cls.state, cls.signature,
            verifier_profile_digest_hex=cls.verifier.profile_digest_hex)
        cls.verified = exchange.canonical(dict(json.loads(unknown), outcome="verified"))

    def setUp(self):
        self.simulated_host = sys.platform == "darwin"
        if self.simulated_host:
            control = patch("offline_session.worker_resources.sys.platform", "linux")
            control.start()
            self.addCleanup(control.stop)
        directory = tempfile.TemporaryDirectory(prefix="synthetic-v4-store-cuts-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.select_pair("records")
        self.target = self.base / "public-target.json"
        self.target.write_bytes(exchange.canonical({"state": self.state,
            "signature_hex": self.signature.hex(), "statement": json.loads(self.verified)}))
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)
        self.pool = synthetic_pool(self.base)

    def select_pair(self, name):
        self.root, self.anchor = self.base / name, self.base / (name + ".json")
        self.marker = self.base / (name + ".calls")

    def open(self, **options):
        return ObservationStore.open_limited(self.root, self.anchor, store_id_hex=STORE_ID,
            verifier=self.verifier, worker_pool=self.pool, resource_limits=self.policy,
            attempt_limit=2, target_limit=2, **options)

    def initialize(self):
        with self.open():
            pass

    def storage(self):
        database = self.root / "observations.sqlite3"
        paths = (database, self.anchor, database.with_name(database.name + "-journal"))
        return tuple(path.read_bytes() if path.exists() else None for path in paths)

    def command(self, mode, *extra, ordinary=False):
        actor = Path(__file__).with_name("observation_store_actor.py")
        selection = [] if ordinary else ["--limited"]
        if self.simulated_host and not ordinary:
            selection.append("--synthetic-policy-host")
        return [sys.executable, "-B", str(actor), mode, str(self.root), str(self.anchor),
                *selection, *extra]

    def start(self, mode, point, *, recheck=False, spill=False):
        extra = ["--point", point, "--target", str(self.target), "--marker", str(self.marker)]
        if recheck:
            extra.append("--recheck")
        if spill:
            extra.append("--spill-cache")
        child = subprocess.Popen(self.command(mode, *extra), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.addCleanup(cleanup)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=15), "actor did not reach bounded storage cut")
        self.assertEqual(child.stdout.readline().strip(), b"paused")
        return child

    def kill(self, child):
        child.kill()
        _, diagnostics = child.communicate(timeout=10)
        self.assertEqual((child.returncode, diagnostics), (-signal.SIGKILL, b""))

    def cut(self, mode, point, **options):
        child = self.start(mode, point, **options)
        self.kill(child)

    def probe(self, *extra, ordinary=False, expected="StoreQuarantined"):
        result = subprocess.run(self.command("probe", "--forbid-connect", *extra, ordinary=ordinary),
            capture_output=True, text=True, timeout=15)
        # An attempted connect prints a separate marker even if the store sanitizes
        # its exception; expecting only the error name excludes that false positive.
        self.assertEqual((result.returncode, result.stdout.strip(), result.stderr), (20, expected, ""))

    @contextmanager
    def no_worker(self):
        with ExitStack() as controls:
            methods = [controls.enter_context(patch.object(SubprocessObservation, name))
                       for name in ("observe_limited", "observe_admitted")]
            methods.append(controls.enter_context(patch("offline_session.public_worker.subprocess.Popen")))
            yield
            for method in methods:
                method.assert_not_called()

    def assert_quarantined(self):
        before = self.storage()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.open()
        self.assertEqual(self.storage(), before)

    def assert_recovered(self, attempts, known=None):
        with self.no_worker(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (attempts, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), known)
        before = self.storage()
        with self.no_worker(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (attempts, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), known)
        self.assertEqual(self.storage(), before, "matched repeated reopen must not write or recharge")
        anchor = json.loads(self.anchor.read_bytes())
        self.assertEqual(anchor["version"], 4)
        self.assertEqual(anchor["worker_resource_profile_digest_hex"], self.policy.profile_digest_hex)

    def calls(self):
        return self.marker.read_bytes() if self.marker.exists() else b""

    def assert_hot(self, prior_database):
        database, _, journal = self.storage()
        self.assertIsNotNone(journal, "real SQLite rollback journal required")
        self.assertGreater(len(journal), 512)
        # SQLite's documented rollback header magic; no journal bytes are fabricated.
        self.assertEqual(journal[:8], bytes.fromhex("d9d505f920a163d7"))
        self.assertNotEqual(database, prior_database, "dirty pages must actually reach the database")

    def reject_changes(self):
        before = self.storage()
        for options in (("--cpu-seconds", "1"), ("--address-space-bytes", str(96 * 1024 * 1024))):
            self.probe(*options)
            self.assertEqual(self.storage(), before)
        self.probe(ordinary=True)
        self.assertEqual(self.storage(), before)

    def test_sigkill_at_every_initial_pair_write_boundary(self):
        for point, complete in (("initialize.before_db_commit", False),
                ("initialize.after_db_commit", False), ("initialize.after_checkpoint_replace", True),
                ("initialize.after_checkpoint_commit", True)):
            with self.subTest(point=point):
                self.select_pair(point)
                self.cut("initialize", point)
                if complete:
                    self.assert_recovered(0)
                else:
                    self.assert_quarantined()
                self.assertEqual(self.calls(), b"")

    def test_sigkill_at_every_admission_worker_and_result_boundary(self):
        cases = (("admission.before_db_commit", 0, None, b""),
            ("admission.after_db_commit", None, None, b""),
            ("admission.after_checkpoint_replace", 1, None, b""),
            ("admission.after_checkpoint_commit", 1, None, b""),
            ("admission.committed", 1, None, b""), ("worker.returned", 1, None, b"1"),
            ("result.before_db_commit", 1, None, b"1"), ("result.after_db_commit", None, None, b"1"),
            ("result.after_checkpoint_replace", 1, self.verified, b"1"),
            ("result.after_checkpoint_commit", 1, self.verified, b"1"),
            ("result.committed", 1, self.verified, b"1"))
        for point, attempts, known, calls in cases:
            with self.subTest(point=point):
                self.select_pair(point)
                self.initialize()
                self.cut("crash", point)
                self.assertEqual(self.calls(), calls)
                self.reject_changes()
                if attempts is None:
                    self.assert_quarantined()
                else:
                    self.assert_recovered(attempts, known)
                self.assertEqual(self.calls(), calls)

    def test_sigkill_at_every_pending_recovery_write_boundary(self):
        for point, consistent in (("recovery.before_db_commit", True),
                ("recovery.after_db_commit", False), ("recovery.after_checkpoint_replace", True),
                ("recovery.after_checkpoint_commit", True)):
            with self.subTest(point=point):
                self.select_pair(point)
                self.initialize()
                self.cut("crash", "admission.committed")
                self.cut("recover", point)
                self.reject_changes()
                if consistent:
                    self.assert_recovered(1)
                else:
                    self.assert_quarantined()
                self.assertEqual(self.calls(), b"")

    def test_wrong_policy_and_downgrade_leave_real_hot_admission_and_result_journals_unchanged(self):
        for point, attempts, calls in (("admission.before_db_commit", 0, b""),
                ("result.before_db_commit", 1, b"1")):
            with self.subTest(point=point):
                self.select_pair(point)
                self.initialize()
                prior = self.storage()
                self.cut("crash", point, spill=True)
                self.assert_hot(prior[0])
                self.reject_changes()
                self.assert_recovered(attempts)
                self.assertFalse((self.root / "observations.sqlite3-journal").exists())
                if attempts == 0:
                    self.assertEqual(self.storage(), prior, "SQLite must roll back uncommitted admission bytes")
                self.assertEqual(self.calls(), calls)

    def test_wrong_policy_and_downgrade_leave_real_hot_recovery_journal_unchanged(self):
        self.initialize()
        self.cut("crash", "admission.committed")
        prior = self.storage()
        self.cut("recover", "recovery.before_db_commit", spill=True)
        self.assert_hot(prior[0])
        self.reject_changes()
        self.assert_recovered(1)
        self.assertFalse((self.root / "observations.sqlite3-journal").exists())
        self.assertEqual(self.calls(), b"")
        self.assertEqual(json.loads(self.anchor.read_bytes())["revision"], 2)

    def test_repeated_death_before_recovery_commit_never_refunds_recharges_or_replays(self):
        self.initialize()
        self.cut("crash", "admission.committed")
        pending_anchor = self.anchor.read_bytes()
        for _ in range(3):
            self.cut("recover", "recovery.before_db_commit")
            self.assertEqual(self.anchor.read_bytes(), pending_anchor)
            self.reject_changes()
        self.assert_recovered(1)
        self.assertEqual(json.loads(self.anchor.read_bytes())["revision"], 2)
        self.assertEqual(self.calls(), b"")

    def test_killed_recheck_and_recovery_preserve_old_normal_and_exhausted_allowance(self):
        for point in ("worker.returned", "result.before_db_commit", "recovery.before_db_commit"):
            with self.subTest(point=point):
                self.select_pair(point)
                with self.open() as store, patch.object(SubprocessObservation, "observe_limited", return_value=self.verified):
                    store.observe(self.state, self.signature)
                self.cut("crash", "worker.returned" if point.startswith("recovery") else point,
                         recheck=True, spill=point == "result.before_db_commit")
                if point.startswith("recovery"):
                    self.cut("recover", point)
                self.assert_recovered(2, self.verified)
                with self.no_worker(), self.open() as store, self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, self.signature, recheck=True)
                self.assertEqual(self.calls(), b"1")

    def test_live_write_or_recovery_owner_excludes_reopen_before_sqlite_access(self):
        self.initialize()
        child = self.start("crash", "admission.committed")
        locks = (self.root / "observations.lock", self.anchor.with_name(self.anchor.name + ".lock"))
        inodes = tuple(path.stat().st_ino for path in locks)
        self.probe(expected="StoreBusy")
        self.kill(child)
        child = self.start("recover", "recovery.before_db_commit")
        self.probe(expected="StoreBusy")
        self.kill(child)
        self.assert_recovered(1)
        self.assertEqual(tuple(path.stat().st_ino for path in locks), inodes)
        self.assertEqual(self.calls(), b"")
