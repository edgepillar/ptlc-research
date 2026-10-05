"""V4 restore counterexamples with real files/locks and synthetic verdicts.

Linux host selection alone is simulated. These tests establish no Linux cap,
mathematical validity, external freshness or production restore procedure.
Snapshots are captured after source close and installed only at unowned
destination paths. A separate original owner can remain open while an older
closed snapshot is installed elsewhere; no live store files are overwritten.
"""

from contextlib import closing, contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence, observation_records as records
from offline_session.observation_store import ObservationStore, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from offline_session.public_worker import _admission_descriptor, _lease_descriptors
from offline_session.worker_resources import WorkerResourceLimits
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


class ResourceStoreRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.verifier = synthetic_verifier()
        cls.unknown = evidence.unknown_statement(cls.state, cls.signature,
            verifier_profile_digest_hex=cls.verifier.profile_digest_hex)
        cls.verified = exchange.canonical(dict(json.loads(cls.unknown), outcome="verified"))
        cls.rejected = exchange.canonical(dict(json.loads(cls.unknown), outcome="rejected"))

    def setUp(self):
        host = patch("offline_session.worker_resources.sys.platform", "linux")
        host.start()
        self.addCleanup(host.stop)
        directory = tempfile.TemporaryDirectory(prefix="synthetic-resource-restore-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)
        self.work_calls = 0

    def config(self, **options):
        value = dict(store_id_hex=STORE_ID, verifier=self.verifier, worker_pool=self.pool,
                     resource_limits=self.policy, attempt_limit=1, target_limit=2)
        value.update(options)
        return value

    def open(self, **options):
        return ObservationStore.open_limited(self.root, self.anchor, **self.config(**options))

    def pair(self):
        return (self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes()

    def copy_pair(self, pair):
        # Test-only offline copying, never an application restore or repair API.
        self.root.mkdir(mode=0o700, exist_ok=True)
        for path, raw in zip((self.root / "observations.sqlite3", self.anchor), pair):
            path.write_bytes(raw)
            path.chmod(0o600)

    def profiles(self):
        value = json.loads(self.anchor.read_bytes())
        self.assertEqual(value["version"], 4)
        return (value["store_id_hex"], value["worker_pool_profile_digest_hex"],
                value["worker_resource_profile_digest_hex"])

    @contextmanager
    def no_work(self):
        with patch.object(SubprocessObservation, "observe_limited") as limited, \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary, \
                patch("offline_session.public_worker.subprocess.Popen") as spawn:
            yield
            limited.assert_not_called()
            ordinary.assert_not_called()
            spawn.assert_not_called()

    def call(self, store, statement=None, **options):
        def worker(state, signature, *, resource_limits, ownership_descriptors, admission_descriptor):
            self.assertIs(resource_limits, self.policy)
            _admission_descriptor(admission_descriptor, _lease_descriptors(ownership_descriptors))
            self.work_calls += 1
            return self.verified if statement is None else statement
        with patch.object(SubprocessObservation, "observe_limited", side_effect=worker), \
                patch.object(SubprocessObservation, "observe_admitted") as ordinary:
            try:
                return store.observe(self.state, self.signature, **options)
            finally:
                ordinary.assert_not_called()

    def test_matching_empty_pair_restore_replenishes_exhausted_v4_quota(self):
        with self.open():
            pass
        old, profiles = self.pair(), self.profiles()
        with self.open() as store:
            self.assertEqual(self.call(store), self.verified)
            self.assertEqual(store.summary().attempts_remaining, 0)
            with self.no_work(), self.assertRaises(records.RecordExhausted):
                store.observe(self.state, self.signature, recheck=True)
        self.copy_pair(old)
        with self.no_work(), self.open() as store:
            self.assertEqual((store.summary().revision, store.summary().attempts_remaining), (0, 1))
            self.assertIsNone(store.known_statement(self.state, self.signature))
        self.assertEqual(self.pair(), old)
        self.assertEqual(self.profiles(), profiles)
        with self.open() as store:
            self.assertEqual(self.call(store), self.verified)
            self.assertEqual(store.summary().attempts_consumed, 1)
        self.assertEqual(self.work_calls, 2, "same profile and history limit allow work after coherent rewind")
        self.assertEqual(self.profiles(), profiles)

    def test_matching_normal_pair_restore_erases_later_charged_unknown_recheck(self):
        with self.open(attempt_limit=2) as store:
            self.call(store)
        old = self.pair()
        with self.open(attempt_limit=2) as store:
            self.assertEqual(self.call(store, self.unknown, recheck=True), self.unknown)
            self.assertEqual((store.summary().revision, store.summary().attempts_remaining), (4, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
        self.copy_pair(old)
        with self.no_work(), self.open(attempt_limit=2) as store:
            self.assertEqual((store.summary().revision, store.summary().attempts_consumed), (2, 1))
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
        self.assertEqual(self.pair(), old)
        with self.open(attempt_limit=2) as store:
            self.call(store, self.unknown, recheck=True)
            self.assertEqual(store.summary().attempts_consumed, 2)
        self.assertEqual(self.work_calls, 3, "local allowance is not a cumulative lifetime budget")

    def test_matching_old_pair_can_erase_later_synthetic_normal_conflict(self):
        with self.open(attempt_limit=3) as store:
            self.call(store)
        old = self.pair()
        with self.open(attempt_limit=3) as store:
            with self.assertRaises(records.RecordConflict):
                self.call(store, self.rejected, recheck=True)
            summary = store.summary()
            self.assertEqual((summary.attempts_consumed, summary.verified_claims,
                              summary.rejected_claims, summary.conflicting_targets), (2, 0, 0, 1))
            with self.assertRaises(records.RecordConflict):
                store.known_statement(self.state, self.signature)
        conflicted = self.pair()
        with closing(sqlite3.connect(self.root / "observations.sqlite3")) as connection, connection:
            wire = connection.execute("SELECT record_bytes FROM checkpoint").fetchone()[0]
        self.assertEqual([attempt["outcome"] for attempt in json.loads(wire)["attempts"]], ["verified", "rejected"])
        with self.no_work(), self.open(attempt_limit=3) as store:
            self.assertEqual(store.summary().conflicting_targets, 1)
            with self.assertRaises(records.RecordConflict):
                store.known_statement(self.state, self.signature)
        self.assertEqual(self.pair(), conflicted)
        self.copy_pair(old)
        with self.no_work(), self.open(attempt_limit=3) as store:
            summary = store.summary()
            self.assertEqual((summary.attempts_consumed, summary.rejected_claims, summary.conflicting_targets), (1, 0, 0))
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
        self.assertEqual(self.pair(), old)
        self.assertEqual(self.work_calls, 2)

    def test_single_sided_old_restore_quarantines_without_repair_both_directions(self):
        with self.open():
            pass
        old = self.pair()
        with self.open() as store:
            self.call(store)
        current = self.pair()
        for pair in ((old[0], current[1]), (current[0], old[1])):
            with self.subTest(old_database=pair[0] == old[0]):
                self.copy_pair(pair)
                with self.no_work(), self.assertRaises(StoreQuarantined):
                    self.open()
                self.assertEqual(self.pair(), pair)
                with self.pool.acquire():
                    pass
        self.copy_pair(current)
        with self.no_work(), self.open() as store:
            self.assertEqual(store.summary().attempts_remaining, 0)
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
        self.assertEqual(self.pair(), current)

    def test_empty_pair_copy_has_separate_quota_under_identical_profiles_and_physical_pool(self):
        with self.open():
            pass
        old, profiles = self.pair(), self.profiles()
        original_root, original_anchor = self.root, self.anchor
        with self.open() as original:
            self.call(original)
            original_pair = self.pair()
            self.root, self.anchor = self.base / "copy", self.base / "copy-head.json"
            self.copy_pair(old)
            self.assertEqual(self.profiles(), profiles)
            with self.open() as copied:
                self.assertEqual(copied.summary().attempts_consumed, 0)
                self.assertEqual(self.call(copied), self.verified)
                self.assertEqual(copied.summary().attempts_consumed, 1)
            self.assertEqual(original.summary().attempts_consumed, 1)
            with self.no_work(), self.assertRaises(records.RecordExhausted):
                original.observe(self.state, self.signature, recheck=True)
            self.root, self.anchor = original_root, original_anchor
            self.assertEqual(self.pair(), original_pair)
        self.assertEqual(self.work_calls, 2)
        with self.pool.acquire():
            pass

    def test_matching_pending_pair_recovery_can_repeat_but_never_replays_or_refunds(self):
        def hook(name):
            if name == "worker.returned":
                raise RuntimeError("synthetic result publication loss")
        with self.open(hook=hook) as store:
            with self.assertRaises(StoreQuarantined):
                self.call(store)
        pending = self.pair()
        for restored in (False, True):
            with self.subTest(restored=restored):
                if restored:
                    self.copy_pair(pending)
                with self.no_work(), self.open() as store:
                    summary = store.summary()
                    self.assertEqual((summary.revision, summary.attempts_consumed, summary.pending_attempts), (2, 1, 0))
                    self.assertIsNone(store.known_statement(self.state, self.signature))
                recovered = self.pair()
                with self.no_work(), self.open() as store:
                    self.assertEqual(store.summary().attempts_remaining, 0)
                self.assertEqual(self.pair(), recovered)
        self.assertEqual(self.work_calls, 1)

    def test_wrong_policy_or_mode_refuses_restored_pair_before_sqlite_while_matching_policy_accepts(self):
        with self.open():
            pass
        old = self.pair()
        with self.open() as store:
            self.call(store)
        self.copy_pair(old)
        def ordinary():
            options = self.config()
            del options["resource_limits"]
            return ObservationStore.open(self.root, self.anchor, **options)
        openers = (lambda: self.open(resource_limits=WorkerResourceLimits(1, 128 * 1024 * 1024)),
                   lambda: self.open(resource_limits=WorkerResourceLimits(2, 256 * 1024 * 1024)), ordinary)
        for opener in openers:
            with self.no_work(), patch("offline_session.observation_store.sqlite3.connect") as connect:
                with self.assertRaises(StoreQuarantined):
                    opener()
                connect.assert_not_called()
            self.assertEqual(self.pair(), old)
        with self.no_work(), self.open() as store:
            self.assertEqual((store.summary().revision, store.summary().attempts_remaining), (0, 1))
        self.assertEqual(self.pair(), old)


if __name__ == "__main__":
    unittest.main(verbosity=2)
