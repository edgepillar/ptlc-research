"""Actual public verdicts and durable explicit Linux v4 resource selection.

Policy continuity is local consistency on a trusted host, not enrollment,
anti-clone defense, source authority, a signer or a funded recovery guarantee.
"""

import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from offline_session import observation_evidence as evidence
from offline_session.artifact_verifier import SubprocessVerifier
from offline_session.journal import Journal
from offline_session.observation_store import ObservationStore, StoreBusy, StoreError, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation, _file_digest
from offline_session.public_worker import WorkerError
from offline_session.worker_resources import WorkerResourceLimits, _supported
from completion_test_support import final_signatures
from exchange_test_support import prepare
from observation_store_test_support import STORE_ID, synthetic_pool


class RealResourceStoreTests(unittest.TestCase):
    verifier = None
    observer = None

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
    RealResourceStoreTests.observer = SubprocessObservation(path, expected_executable_sha256_hex=_file_digest(path))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealResourceStoreTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
