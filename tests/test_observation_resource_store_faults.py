"""v4 controlled API faults plus real disposable-writer file-size refusal.

SQLite/files/locks are real; injected EIO/ENOSPC and verdicts are synthetic.
Supported-host selection is simulated for the local macOS store only. Native
file-size refusal is distinct from Linux worker caps and actual Rust verdicts.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence
from offline_session.observation_store import ObservationStore, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from offline_session.worker_resources import WorkerResourceLimits
from completion_test_support import final_signatures, released_bob
from observation_store_fault_support import StorageFaults
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


OPERATIONS = tuple((operation, timing) for operation in (
    "sqlite.begin", "sqlite.write", "sqlite.commit", "checkpoint.write", "checkpoint.flush",
    "checkpoint.fsync", "checkpoint.replace", "directory.fsync") for timing in ("before", "after"))


class ResourceStoreFaultTests(unittest.TestCase):
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
        control = patch("offline_session.worker_resources.sys.platform", "linux")
        control.start()
        self.addCleanup(control.stop)
        directory = tempfile.TemporaryDirectory(prefix="synthetic-v4-storage-faults-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.select_pair("records")
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)

    def select_pair(self, name):
        self.root, self.anchor = self.base / name, self.base / (name + ".json")

    def open(self, **options):
        return ObservationStore.open_limited(self.root, self.anchor, store_id_hex=STORE_ID,
            verifier=self.verifier, worker_pool=self.pool, resource_limits=self.policy,
            attempt_limit=3, target_limit=2, **options)

    def storage(self):
        database = self.root / "observations.sqlite3"
        return tuple(path.read_bytes() if path.exists() else None for path in (
            database, self.anchor, database.with_name(database.name + "-journal")))

    @contextmanager
    def no_work(self):
        with patch.object(SubprocessObservation, "observe_limited") as limited, \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary, \
                patch("offline_session.public_worker.subprocess.Popen") as spawn:
            yield
            limited.assert_not_called()
            ordinary.assert_not_called()
            spawn.assert_not_called()

    def interrupted(self, point):
        def hook(name):
            if name == point:
                raise RuntimeError("synthetic pending setup")
        return hook

    def pending(self):
        with self.open(hook=self.interrupted("admission.committed")) as store, self.no_work():
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)

    def command(self, *extra):
        actor = Path(__file__).with_name("observation_store_actor.py")
        selection = ["--synthetic-policy-host"] if self.simulated_host else []
        return [sys.executable, "-B", str(actor), *extra, str(self.root), str(self.anchor),
            "--limited", "--attempt-limit", "3", "--pool-slots", "1", *selection]

    def poisoned_owner(self, store):
        for call in (store.summary, lambda: store.known_statement(self.state, self.signature),
                     lambda: store.observe(self.state, self.signature, recheck=True)):
            with self.assertRaises(StoreQuarantined) as error:
                call()
            self.assertNotIn("synthetic storage fault", str(error.exception))
        with self.pool.acquire():
            pass
        probe = subprocess.run(self.command("probe") + ["--forbid-connect"],
            capture_output=True, text=True, timeout=15)
        self.assertEqual((probe.returncode, probe.stdout.strip(), probe.stderr), (20, "StoreBusy", ""))

    def check_reopen(self, outcome, attempts=1, known=None):
        if outcome == "quarantine":
            before = self.storage()
            with self.no_work(), self.assertRaises(StoreQuarantined):
                self.open()
            self.assertEqual(self.storage(), before)
            return
        expected = self.verified if outcome == "normal" and known is None else known
        with self.no_work(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (attempts, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), expected)
        before = self.storage()
        with self.no_work(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (attempts, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), expected)
        self.assertEqual(self.storage(), before)
        self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"],
                         self.policy.profile_digest_hex)

    def partition(self, operation, timing):
        if operation in {"sqlite.begin", "sqlite.write"} or (operation == "sqlite.commit" and timing == "before"):
            return "rollback"
        if (operation == "checkpoint.replace" and timing == "after") or operation == "directory.fsync":
            return "consistent"
        return "quarantine"

    def failure(self, store, faults, *, worker=True, recheck=False, cancel=False):
        with faults.inject(store), patch.object(SubprocessObservation, "observe_limited",
                side_effect=KeyboardInterrupt if cancel else None, return_value=self.verified) as selected, \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary:
            with self.assertRaises(StoreQuarantined) as error:
                store.observe(self.state, self.signature, recheck=recheck)
            self.assertNotIn("synthetic storage fault", str(error.exception))
            self.poisoned_owner(store)
            self.assertEqual(selected.call_count, int(worker))
            ordinary.assert_not_called()
        faults.assert_fired(self)

    def test_admission_before_after_fault_matrix_never_starts_worker(self):
        for index, (operation, timing) in enumerate(OPERATIONS):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("admission-" + str(index))
                store = self.open()
                before = self.storage()
                try:
                    self.failure(store, StorageFaults(("admission", operation, timing)), worker=False)
                finally:
                    store.close()
                outcome = self.partition(operation, timing)
                self.check_reopen("unknown" if outcome != "quarantine" else outcome,
                                  attempts=0 if outcome == "rollback" else 1)
                if outcome == "rollback":
                    self.assertEqual(self.storage(), before)

    def test_result_before_after_fault_matrix_never_returns_uncommitted_normal(self):
        for index, (operation, timing) in enumerate(OPERATIONS):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("result-" + str(index))
                store = self.open()
                try:
                    self.failure(store, StorageFaults(("result", operation, timing)))
                finally:
                    store.close()
                outcome = self.partition(operation, timing)
                self.check_reopen("normal" if outcome == "consistent" else "unknown" if outcome == "rollback" else outcome)

    def test_recovery_before_after_fault_matrix_retains_charge_without_replay(self):
        for index, (operation, timing) in enumerate(OPERATIONS):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("recovery-" + str(index))
                self.pending()
                faults = StorageFaults(("recovery", operation, timing))
                with faults.inject(), self.no_work(), self.assertRaises(StoreQuarantined):
                    self.open()
                faults.assert_fired(self)
                self.check_reopen("quarantine" if self.partition(operation, timing) == "quarantine" else "unknown")

    def test_initial_pair_faults_never_reinitialize_an_incomplete_pair(self):
        for index, (operation, timing) in enumerate(OPERATIONS + (("sqlite.schema", "before"), ("sqlite.schema", "after"))):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("initialize-" + str(index))
                faults = StorageFaults(("initialize", operation, timing))
                with faults.inject(), self.no_work(), self.assertRaises(StoreQuarantined):
                    self.open()
                faults.assert_fired(self)
                consistent = (operation == "checkpoint.replace" and timing == "after") or operation == "directory.fsync"
                self.check_reopen("unknown" if consistent else "quarantine", attempts=0)

    def test_secondary_rollback_failure_keeps_handle_poisoned_until_owner_close(self):
        for phase in ("admission", "result"):
            for timing in ("before", "after"):
                with self.subTest(phase=phase, rollback=timing):
                    self.select_pair(phase + "-rollback-" + timing)
                    store = self.open()
                    try:
                        self.failure(store, StorageFaults((phase, "sqlite.write", "after"),
                            (phase, "sqlite.rollback", timing)), worker=phase == "result")
                    finally:
                        store.close()
                    self.check_reopen("unknown", attempts=int(phase == "result"))

    def test_checkpoint_cleanup_failure_preserves_orphan_and_quarantines_pair(self):
        store = self.open()
        try:
            self.failure(store, StorageFaults(("result", "checkpoint.write", "before"),
                ("result", "checkpoint.unlink", "before")))
        finally:
            store.close()
        orphan = list(self.base.glob(".observation-checkpoint-*"))
        self.assertEqual(len(orphan), 1)
        before = orphan[0].read_bytes()
        self.check_reopen("quarantine")
        self.assertEqual(orphan[0].read_bytes(), before)

    def test_cancellation_with_result_fault_retains_charge_and_uncertain_partition(self):
        for index, (operation, timing, expected) in enumerate((("sqlite.commit", "before", "unknown"),
                ("sqlite.commit", "after", "quarantine"), ("checkpoint.replace", "after", "unknown"))):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("cancel-" + str(index))
                store = self.open()
                try:
                    self.failure(store, StorageFaults(("result", operation, timing)), cancel=True)
                finally:
                    store.close()
                self.check_reopen(expected)

    def test_recheck_faults_preserve_old_normal_and_consumed_allowance(self):
        for index, (operation, timing) in enumerate((("sqlite.commit", "before"),
                ("checkpoint.replace", "after"), ("directory.fsync", "before"))):
            with self.subTest(operation=operation, timing=timing):
                self.select_pair("recheck-" + str(index))
                store = self.open()
                try:
                    with patch.object(SubprocessObservation, "observe_limited", return_value=self.verified):
                        store.observe(self.state, self.signature)
                    self.failure(store, StorageFaults(("result", operation, timing)), recheck=True)
                finally:
                    store.close()
                self.check_reopen("unknown", attempts=2, known=self.verified)

    def test_real_writer_file_size_refusal_before_admission_and_after_synthetic_result(self):
        for phase, calls, attempts in (("admission", b"", 0), ("result", b"1", 1)):
            with self.subTest(phase=phase):
                self.select_pair("file-size-" + phase)
                with self.open():
                    pass
                target, marker = self.base / (phase + "-target.json"), self.base / (phase + "-calls")
                target.write_bytes(exchange.canonical({"state": self.state, "signature_hex": self.signature.hex(),
                    "statement": json.loads(self.verified)}))
                result = subprocess.run(self.command("crash") + ["--file-size-at", phase,
                    "--target", str(target), "--marker", str(marker)], capture_output=True, text=True, timeout=15)
                self.assertEqual((result.returncode, result.stdout.strip(), result.stderr),
                                 (20, "fsize-refused\nStoreQuarantined", ""))
                self.assertEqual(marker.read_bytes() if marker.exists() else b"", calls)
                self.check_reopen("unknown", attempts=attempts)
                (self.base / "synthetic-fsize-probe").unlink()
