"""Actual public verdicts and durable explicit Linux v4 resource selection.

Policy continuity is local consistency on a trusted host, not enrollment,
anti-clone defense, source authority, a signer or a funded recovery guarantee.
"""

import argparse
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import exchange, observation_evidence as evidence
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.journal import Journal
from offline_session.observation_store import ObservationStore, StoreBusy, StoreError, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError
from offline_session.worker_resources import WorkerResourceLimits, _supported
from completion_test_support import final_signatures
from exchange_test_support import prepare
from observation_store_test_support import STORE_ID, synthetic_pool
from observation_store_fault_support import StorageFaults


class RealResourceStoreTests(unittest.TestCase):
    verifier = None
    observer = None
    observation_path = None

    @classmethod
    def setUpClass(cls):
        cls.signature = final_signatures()[0]

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-resource-store-actual-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.journal = Journal.open(self.base / "source", self.base / "source-head.json")
        self.addCleanup(self.journal.close)
        session = prepare(self.journal, verifier=self.verifier)
        self.journal.release_exchange_zenon(session)
        self.state = self.journal.get_exchange(session)
        self.before_journal = (copy.deepcopy(self.journal._state), self.journal._sequence,
            (self.base / "source/journal.sqlite3").read_bytes(), (self.base / "source-head.json").read_bytes())
        self.addCleanup(self.assert_journal_unchanged)
        self.root, self.anchor = self.base / "observations", self.base / "observation-head.json"
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)

    def assert_journal_unchanged(self):
        self.assertEqual((self.journal._state, self.journal._sequence,
            (self.base / "source/journal.sqlite3").read_bytes(), (self.base / "source-head.json").read_bytes()),
            self.before_journal)

    def config(self, **options):
        value = dict(store_id_hex=STORE_ID, verifier=self.observer, worker_pool=self.pool,
                     resource_limits=self.policy, attempt_limit=3, target_limit=2)
        value.update(options)
        return value

    def open(self, **options):
        return ObservationStore.open_limited(self.root, self.anchor, **self.config(**options))

    def pair(self):
        return (self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes()

    def outcome(self, wire, signature):
        return evidence.parse_statement(self.state, signature, wire,
            expected_verifier_profile_digest_hex=self.observer.profile_digest_hex).outcome

    def actor_command(self, mode, *extra, ordinary=False):
        selection = [] if ordinary else ["--limited"]
        return [sys.executable, "-B", str(ROOT / "tests/observation_store_actor.py"), mode,
            str(self.root), str(self.anchor), "--actual-observation", str(self.observation_path),
            "--attempt-limit", "3", "--pool-slots", "1", *selection, *extra]

    def kill_at(self, mode, point, marker, *, recheck=False, spill=False):
        target = self.base / "public-cut-target.json"
        target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex()}))
        extra = ["--point", point, "--target", str(target), "--marker", str(marker)]
        if recheck:
            extra.append("--recheck")
        if spill:
            extra.append("--spill-cache")
        child = subprocess.Popen(self.actor_command(mode, *extra), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=15), "actual limited actor did not reach storage cut")
            self.assertEqual(child.stdout.readline().strip(), b"paused")
            child.kill()
            _, diagnostics = child.communicate(timeout=10)
            self.assertEqual((child.returncode, diagnostics), (-signal.SIGKILL, b""))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def storage(self):
        database = self.root / "observations.sqlite3"
        journal = database.with_name(database.name + "-journal")
        return (*self.pair(), journal.read_bytes() if journal.exists() else None)

    def reject_changes_before_connect(self):
        before = self.storage()
        for extra, ordinary in ((("--cpu-seconds", "1"), False),
                (("--address-space-bytes", str(96 * 1024 * 1024)), False), ((), True)):
            result = subprocess.run(self.actor_command("probe", "--forbid-connect", *extra, ordinary=ordinary),
                capture_output=True, text=True, timeout=15)
            self.assertEqual((result.returncode, result.stdout.strip(), result.stderr), (20, "StoreQuarantined", ""))
            self.assertEqual(self.storage(), before)

    @contextmanager
    def no_work(self):
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch.object(SubprocessObservation, "observe_limited") as limited, \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary:
            yield
            spawn.assert_not_called()
            limited.assert_not_called()
            ordinary.assert_not_called()

    @contextmanager
    def actual_normal(self):
        actual = SubprocessObservation.observe_limited
        results = []
        def worker(observer, *arguments, **options):
            statement = actual(observer, *arguments, **options)
            if self.outcome(statement, self.signature) == "verified":
                results.append(statement)
            return statement
        with patch.object(SubprocessObservation, "observe_limited", worker), \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary:
            yield results
            ordinary.assert_not_called()
        self.assertEqual(len(results), 1, "actual normal result required before storage failure")

    def check_fault_reopen(self, expected, *, attempts=1, normal=None):
        if expected == "quarantine":
            before = self.storage()
            with self.no_work(), self.assertRaises(StoreQuarantined):
                self.open()
            self.assertEqual(self.storage(), before)
            return
        with self.no_work(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (attempts, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), normal)
        before = self.storage()
        with self.no_work(), self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, attempts)
            self.assertEqual(store.known_statement(self.state, self.signature), normal)
        self.assertEqual(self.storage(), before)
        self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"],
                         self.policy.profile_digest_hex)

    def test_actual_normal_storage_faults_distinguish_rollback_divergence_and_committed_result(self):
        cases = (("sqlite.commit", "before", "unknown"), ("sqlite.commit", "after", "quarantine"),
            ("checkpoint.write", "before", "quarantine"), ("checkpoint.fsync", "before", "quarantine"),
            ("checkpoint.replace", "after", "normal"), ("directory.fsync", "before", "normal"),
            ("directory.fsync", "after", "normal"))
        for index, (operation, timing, expected) in enumerate(cases):
            with self.subTest(operation=operation, timing=timing):
                self.root, self.anchor = self.base / ("fault-" + str(index)), self.base / ("fault-" + str(index) + ".json")
                store = self.open()
                faults = StorageFaults(("result", operation, timing))
                try:
                    with faults.inject(store), self.actual_normal() as normal:
                        with self.assertRaises(StoreQuarantined):
                            store.observe(self.state, self.signature)
                        for call in (store.summary, lambda: store.known_statement(self.state, self.signature),
                                     lambda: store.observe(self.state, self.signature, recheck=True)):
                            with self.assertRaises(StoreQuarantined):
                                call()
                        with self.pool.acquire():
                            pass
                        probe = subprocess.run(self.actor_command("probe", "--forbid-connect"),
                            capture_output=True, text=True, timeout=15)
                        self.assertEqual((probe.returncode, probe.stdout.strip(), probe.stderr), (20, "StoreBusy", ""))
                    faults.assert_fired(self)
                finally:
                    store.close()
                self.check_fault_reopen(expected, normal=normal[0] if expected == "normal" else None)

    def test_actual_recheck_with_recovery_fault_preserves_old_normal_and_charge(self):
        cases = (("sqlite.commit", "before", "unknown"), ("sqlite.commit", "after", "quarantine"),
                 ("checkpoint.replace", "after", "unknown"), ("directory.fsync", "before", "unknown"))
        for index, (operation, timing, expected) in enumerate(cases):
            with self.subTest(operation=operation, timing=timing):
                self.root, self.anchor = self.base / ("fault-recovery-" + str(index)), self.base / ("fault-recovery-" + str(index) + ".json")
                with self.open() as store:
                    normal = store.observe(self.state, self.signature)
                    self.assertEqual(self.outcome(normal, self.signature), "verified")
                def hook(name):
                    if name == "worker.returned":
                        raise RuntimeError("synthetic pending recheck")
                with self.open(hook=hook) as store, self.actual_normal():
                    with self.assertRaises(StoreQuarantined):
                        store.observe(self.state, self.signature, recheck=True)
                faults = StorageFaults(("recovery", operation, timing))
                with faults.inject(), self.no_work(), self.assertRaises(StoreQuarantined):
                    self.open()
                faults.assert_fired(self)
                self.check_fault_reopen(expected, attempts=2, normal=normal)

    def test_native_writer_file_limit_before_work_and_after_actual_normal_preserves_journal(self):
        for phase, calls, attempts in (("admission", b"", 0), ("result", b"verified", 1)):
            with self.subTest(phase=phase):
                self.root, self.anchor = self.base / ("native-fault-" + phase), self.base / ("native-fault-" + phase + ".json")
                with self.open():
                    pass
                target, marker = self.base / (phase + "-fsize-target.json"), self.base / (phase + "-fsize-calls")
                target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex()}))
                result = subprocess.run(self.actor_command("crash", "--file-size-at", phase,
                    "--target", str(target), "--marker", str(marker)), capture_output=True, text=True, timeout=15)
                probe = self.base / "synthetic-fsize-probe"
                if probe.exists():
                    probe.unlink()
                self.assertEqual((result.returncode, result.stdout.strip(), result.stderr),
                                 (20, "fsize-refused\nStoreQuarantined", ""))
                self.assertEqual(marker.read_bytes() if marker.exists() else b"", calls)
                self.check_fault_reopen("unknown", attempts=attempts)
                with self.pool.acquire():
                    pass

    def test_sigkill_after_actual_limited_verdict_and_at_result_write_boundaries(self):
        for index, (point, normal) in enumerate((("worker.returned", False),
                ("result.before_db_commit", False), ("result.after_db_commit", None),
                ("result.after_checkpoint_replace", True), ("result.after_checkpoint_commit", True),
                ("result.committed", True))):
            with self.subTest(point=point):
                self.root, self.anchor = self.base / ("result-" + str(index)), self.base / ("result-" + str(index) + ".json")
                with self.open():
                    pass
                initial_database = self.pair()[0]
                marker = self.base / ("normal-" + str(index))
                self.kill_at("crash", point, marker, spill=point == "result.before_db_commit")
                self.assertEqual(marker.read_bytes(), b"verified", "actual normal result required before SIGKILL")
                if point == "result.before_db_commit":
                    journal = self.storage()[2]
                    self.assertIsNotNone(journal)
                    self.assertGreater(len(journal), 512)
                    self.assertEqual(journal[:8], bytes.fromhex("d9d505f920a163d7"))
                    self.assertGreater(len(self.pair()[0]), len(initial_database), "real fixture pages must spill")
                self.reject_changes_before_connect()
                if normal is None:
                    before = self.storage()
                    with self.no_work(), self.assertRaises(StoreQuarantined):
                        self.open()
                    self.assertEqual(self.storage(), before)
                else:
                    with self.no_work(), self.open() as store:
                        self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
                        statement = store.known_statement(self.state, self.signature)
                        if normal:
                            self.assertEqual(self.outcome(statement, self.signature), "verified")
                        else:
                            self.assertIsNone(statement)
                    before = self.storage()
                    with self.no_work(), self.open() as store:
                        self.assertEqual(store.known_statement(self.state, self.signature), statement)
                        self.assertEqual(store.summary().attempts_consumed, 1)
                    self.assertEqual(self.storage(), before)
                    self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"],
                                     self.policy.profile_digest_hex)

    def test_sigkill_at_actual_recheck_recovery_cuts_retains_normal_and_charge(self):
        for index, (point, consistent) in enumerate((("recovery.before_db_commit", True),
                ("recovery.after_db_commit", False), ("recovery.after_checkpoint_replace", True),
                ("recovery.after_checkpoint_commit", True))):
            with self.subTest(point=point):
                self.root, self.anchor = self.base / ("recovery-" + str(index)), self.base / ("recovery-" + str(index) + ".json")
                with self.open() as store:
                    normal = store.observe(self.state, self.signature)
                    self.assertEqual(self.outcome(normal, self.signature), "verified")
                marker = self.base / ("recheck-" + str(index))
                self.kill_at("crash", "worker.returned", marker, recheck=True)
                self.assertEqual(marker.read_bytes(), b"verified", "actual recheck result required before loss")
                self.kill_at("recover", point, marker)
                self.reject_changes_before_connect()
                if consistent:
                    with self.no_work(), self.open() as store:
                        self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (2, 0))
                        self.assertEqual(store.known_statement(self.state, self.signature), normal)
                    before = self.storage()
                    with self.no_work(), self.open() as store:
                        self.assertEqual(store.summary().attempts_consumed, 2)
                        self.assertEqual(store.known_statement(self.state, self.signature), normal)
                    self.assertEqual(self.storage(), before)
                else:
                    before = self.storage()
                    with self.no_work(), self.assertRaises(StoreQuarantined):
                        self.open()
                    self.assertEqual(self.storage(), before)
                self.assertEqual(marker.read_bytes(), b"verified", "recovery must never replay the worker")

    def test_actual_positive_is_cached_under_matching_policy_without_more_work(self):
        profile = self.observer.profile_digest_hex
        with self.open() as store:
            statement = store.observe(self.state, self.signature)
            self.assertEqual(self.outcome(statement, self.signature), "verified")
            self.assertEqual(store.summary().attempts_consumed, 1)
        before = self.pair()
        with self.open() as store, patch("offline_session.public_worker.subprocess.Popen") as spawn:
            self.assertEqual(store.known_statement(self.state, self.signature), statement)
            spawn.assert_not_called()
        self.assertEqual(self.pair(), before)
        self.assertEqual(self.observer.profile_digest_hex, profile)
        self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"],
                         self.policy.profile_digest_hex)

    def test_actual_negative_survives_matching_limited_reopen(self):
        signature = bytes(64)
        with self.open() as store:
            statement = store.observe(self.state, signature)
            self.assertEqual(self.outcome(statement, signature), "rejected")
        with self.open() as store, patch("offline_session.public_worker.subprocess.Popen") as spawn:
            self.assertEqual(store.known_statement(self.state, signature), statement)
            spawn.assert_not_called()

    def test_changed_policy_cannot_recover_pending_or_run_worker(self):
        def hook(name):
            if name == "admission.committed":
                raise RuntimeError("synthetic result unavailable")
        with self.open(hook=hook) as store, patch("offline_session.public_worker.subprocess.Popen") as spawn:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            spawn.assert_not_called()
        before = self.pair()
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            with self.assertRaises(StoreQuarantined):
                self.open(resource_limits=WorkerResourceLimits(1, 128 * 1024 * 1024))
            spawn.assert_not_called()
        self.assertEqual(self.pair(), before)
        with self.open() as store, patch("offline_session.public_worker.subprocess.Popen") as spawn:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
            self.assertIsNone(store.known_statement(self.state, self.signature))
            spawn.assert_not_called()

    def test_ordinary_entry_cannot_downgrade_a_limited_pair(self):
        with self.open():
            pass
        before = self.pair()
        options = self.config()
        del options["resource_limits"]
        with patch("offline_session.public_worker.subprocess.Popen") as spawn:
            with self.assertRaises(StoreQuarantined):
                ObservationStore.open(self.root, self.anchor, **options)
            spawn.assert_not_called()
        self.assertEqual(self.pair(), before)

    def test_unsupported_host_cannot_reopen_verified_pair_or_fall_back(self):
        with self.open() as store:
            self.assertEqual(self.outcome(store.observe(self.state, self.signature), self.signature), "verified")
        before = self.pair()
        with patch("offline_session.worker_resources.sys.platform", "darwin"), \
                patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            with self.assertRaises(StoreError):
                self.open()
            spawn.assert_not_called()
            fallback.assert_not_called()
        self.assertEqual(self.pair(), before)

    def test_missing_policy_cannot_create_pair_or_select_ordinary_work(self):
        with patch("offline_session.public_worker.subprocess.Popen") as spawn, \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            with self.assertRaises(StoreError):
                self.open(resource_limits=None)
            spawn.assert_not_called()
            fallback.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertFalse(self.anchor.exists())

    def test_busy_pool_is_uncharged_then_actual_work_can_proceed(self):
        with self.open() as store:
            before = self.pair()
            with self.pool.acquire(), patch("offline_session.public_worker.subprocess.Popen") as spawn:
                with self.assertRaises(StoreBusy):
                    store.observe(self.state, self.signature)
                spawn.assert_not_called()
            self.assertEqual(store.summary().attempts_consumed, 0)
            self.assertEqual(self.pair(), before)
            self.assertEqual(self.outcome(store.observe(self.state, self.signature), self.signature), "verified")

    def test_lost_actual_normal_result_recovers_unknown_under_same_policy(self):
        actual = SubprocessObservation.observe_limited
        normal_returns = []
        def worker(observer, *args, **kwargs):
            statement = actual(observer, *args, **kwargs)
            if self.outcome(statement, self.signature) == "verified":
                normal_returns.append(statement)
            return statement
        def hook(name):
            if name == "worker.returned":
                raise RuntimeError("synthetic result unavailable")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_limited", worker):
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
        self.assertEqual(len(normal_returns), 1, "actual normal result required before loss")
        with self.open() as store, patch("offline_session.public_worker.subprocess.Popen") as spawn:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
            self.assertIsNone(store.known_statement(self.state, self.signature))
            spawn.assert_not_called()
        self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"],
                         self.policy.profile_digest_hex)


def main():
    parser = argparse.ArgumentParser(description="Qualify durable Linux worker resource selection")
    parser.add_argument("--verifier", required=True)
    parser.add_argument("--observation", required=True)
    options = parser.parse_args()
    try:
        _supported(WorkerResourceLimits(2, 128 * 1024 * 1024))
    except WorkerError:
        parser.error("resource-store qualification requires an unprivileged supported Linux host")
    RealResourceStoreTests.verifier = SubprocessVerifier(Path(options.verifier).resolve())
    path = Path(options.observation).resolve()
    RealResourceStoreTests.observation_path = path
    RealResourceStoreTests.observer = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealResourceStoreTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
