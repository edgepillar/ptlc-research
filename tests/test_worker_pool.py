"""Shared admission metadata, ownership and record ordering; synthetic math only."""

import fcntl
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence, observation_records as records
from offline_session.observation_store import ObservationStore, StoreBusy, StoreError, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from offline_session.worker_pool import (PublicWorkerPool, PoolBusy, PoolError,
    PoolOwnershipError, PoolQuarantined, MAX_CONFIG_BYTES)
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import POOL_ID, STORE_ID, synthetic_pool, synthetic_verifier


@unittest.skipUnless(os.name == "posix", "shared admission requires POSIX advisory locks")
class WorkerPoolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-worker-pool-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root = self.base / "pool"

    def open(self, **options):
        config = dict(pool_id_hex=POOL_ID, slot_limit=2)
        config.update(options)
        return PublicWorkerPool.open(self.root, **config)

    def test_private_canonical_fixed_configuration_reopens_without_rewrite(self):
        first = self.open()
        before = {path.name: (path.stat().st_ino, path.read_bytes()) for path in self.root.iterdir()}
        second = self.open()
        self.assertEqual(first.profile_digest_hex, second.profile_digest_hex)
        self.assertEqual(before, {path.name: (path.stat().st_ino, path.read_bytes()) for path in self.root.iterdir()})
        self.assertEqual(json.loads((self.root / "pool.json").read_bytes()),
                         dict(version=1, pool_id_hex=POOL_ID, slot_limit=2))
        for path in (self.root, *self.root.iterdir()):
            self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_invalid_identity_limit_or_platform_rejects_before_directory_creation(self):
        for config in (dict(pool_id_hex="bad"), dict(slot_limit=True), dict(slot_limit=0),
                       dict(slot_limit=17), dict(slot_limit=1.0)):
            with self.subTest(fields=tuple(config)), self.assertRaises(PoolError):
                self.open(**config)
            self.assertFalse(self.root.exists())
        with patch("offline_session.worker_pool.sys.platform", "unsupported"), self.assertRaises(PoolError):
            self.open()
        self.assertFalse(self.root.exists())

    def test_distinct_handles_share_exact_finite_capacity_and_release_references(self):
        first, second = self.open(), self.open()
        with first.acquire() as a, second.acquire() as b:
            self.assertNotEqual(os.fstat(a.fileno()).st_ino, os.fstat(b.fileno()).st_ino)
            with self.assertRaises(PoolBusy):
                self.open().acquire()
        with second.acquire(), first.acquire():
            with self.assertRaises(PoolBusy):
                first.acquire()

    def test_same_physical_pool_through_a_parent_alias_has_one_capacity(self):
        pool = self.open(slot_limit=1)
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        other = PublicWorkerPool.open(alias / "pool", pool_id_hex=POOL_ID, slot_limit=1)
        with pool.acquire():
            with self.assertRaises(PoolBusy):
                other.acquire()

    def test_configuration_lock_contention_is_nonblocking_and_does_not_rewrite(self):
        self.open()
        before = (self.root / "pool.json").read_bytes()
        descriptor = os.open(self.root / "pool.lock", os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(PoolBusy):
                self.open()
        finally:
            os.close(descriptor)
        self.assertEqual((self.root / "pool.json").read_bytes(), before)
        self.open()

    def test_wrong_expected_identity_or_capacity_never_reconfigures_a_live_pool(self):
        pool = self.open()
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        with pool.acquire():
            for config in (dict(pool_id_hex="77" * 32), dict(slot_limit=1), dict(slot_limit=3)):
                with self.subTest(fields=tuple(config)), self.assertRaises(PoolQuarantined):
                    self.open(**config)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})

    def test_missing_configuration_or_slot_is_quarantined_without_reinitialization(self):
        self.open()
        for name in ("pool.json", "slot-0.lock", "pool.lock"):
            path = self.root / name
            original = path.read_bytes()
            path.unlink()
            with self.assertRaises(PoolQuarantined):
                self.open()
            self.assertFalse(path.exists())
            path.write_bytes(original)
            path.chmod(0o600)

    def test_nonprivate_directory_and_final_directory_symlink_reject(self):
        self.open()
        self.root.chmod(0o755)
        with self.assertRaises(PoolQuarantined):
            self.open()
        self.root.chmod(0o700)
        saved = self.base / "saved-pool"
        self.root.rename(saved)
        self.root.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(PoolQuarantined):
            self.open()

    def test_incomplete_first_initialization_stays_quarantined_without_repair(self):
        with patch("offline_session.worker_pool.os.fsync", side_effect=OSError("synthetic private diagnostic")):
            with self.assertRaises(PoolQuarantined) as caught:
                self.open()
        self.assertNotIn("synthetic private diagnostic", str(caught.exception))
        before = {path.name: path.read_bytes() for path in self.root.iterdir()}
        self.assertNotIn("pool.json", before)
        with self.assertRaises(PoolQuarantined):
            self.open()
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.root.iterdir()})

    def test_changed_noncanonical_oversized_or_nonprivate_configuration_rejects(self):
        pool = self.open()
        config = self.root / "pool.json"
        original = config.read_bytes()
        for wire in (original + b"\n", b"{}", b"x" * (MAX_CONFIG_BYTES + 1)):
            config.write_bytes(wire)
            with self.assertRaises(PoolQuarantined):
                pool.acquire()
            with self.assertRaises(PoolQuarantined):
                self.open()
            self.assertEqual(config.read_bytes(), wire)
        config.write_bytes(original)
        config.chmod(0o644)
        with self.assertRaises(PoolQuarantined):
            pool.acquire()

    def test_replaced_slot_and_duplicate_inode_slots_reject_without_handoff(self):
        pool = self.open()
        slot = self.root / "slot-0.lock"
        saved = self.base / "saved.lock"
        slot.rename(saved)
        slot.write_bytes(b"")
        slot.chmod(0o600)
        with self.assertRaises(PoolQuarantined):
            pool.acquire()
        slot.unlink()
        os.link(self.root / "slot-1.lock", slot)
        with self.assertRaises(PoolQuarantined):
            self.open()

    def test_symlink_nonprivate_slot_and_unknown_contents_reject(self):
        pool = self.open()
        slot = self.root / "slot-0.lock"
        slot.chmod(0o644)
        with self.assertRaises(PoolQuarantined):
            pool.acquire()
        slot.chmod(0o600)
        slot.unlink()
        slot.symlink_to(self.root / "slot-1.lock")
        with self.assertRaises(PoolQuarantined):
            self.open()
        slot.unlink()
        slot.write_bytes(b"")
        slot.chmod(0o600)
        (self.root / "unmanaged").touch()
        with self.assertRaises(PoolQuarantined):
            pool.acquire()

    def test_foreign_thread_cannot_acquire_or_close_original_lease(self):
        pool = self.open(slot_limit=1)
        with pool.acquire() as lease:
            failures = []
            def foreign():
                for call in (pool.acquire, lease.fileno, lease.close):
                    try:
                        call()
                    except PoolOwnershipError:
                        failures.append(True)
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [True] * 3)
            with self.assertRaises(PoolBusy):
                self.open(slot_limit=1).acquire()

    def test_forked_handles_cannot_acquire_or_unlock_parent_lease(self):
        pool = self.open(slot_limit=1)
        with pool.acquire() as lease:
            pid = os.fork()
            if pid == 0:
                result = 0
                for call in (pool.acquire, lease.fileno, lease.close):
                    try:
                        call()
                    except PoolOwnershipError:
                        result += 1
                os._exit(0 if result == 3 else 7)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)
            with self.assertRaises(PoolBusy):
                self.open(slot_limit=1).acquire()

    def test_closed_lease_rejects_descriptor_and_close_is_idempotent(self):
        pool = self.open(slot_limit=1)
        lease = pool.acquire()
        lease.close()
        lease.close()
        with self.assertRaises(PoolOwnershipError):
            lease.fileno()
        with pool.acquire():
            pass

    def test_matching_public_profile_in_another_physical_pool_bypasses_shared_capacity(self):
        first = self.open(slot_limit=1)
        second = synthetic_pool(self.base, slot_limit=1, directory=self.base / "clone")
        self.assertEqual(first.profile_digest_hex, second.profile_digest_hex)
        with first.acquire(), second.acquire():
            with self.assertRaises(PoolBusy):
                first.acquire()
            with self.assertRaises(PoolBusy):
                second.acquire()


@unittest.skipUnless(os.name == "posix", "owned admission records require POSIX locks")
class SharedStoreAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state, cls.signature = released_bob(), final_signatures()[0]
        cls.verifier = synthetic_verifier()
        cls.unknown = evidence.unknown_statement(cls.state, cls.signature,
            verifier_profile_digest_hex=cls.verifier.profile_digest_hex)
        cls.verified = exchange.canonical(dict(json.loads(cls.unknown), outcome="verified"))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-shared-admission-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.pool = synthetic_pool(self.base, slot_limit=1)

    def open(self, name="a", **options):
        config = dict(store_id_hex=STORE_ID, verifier=self.verifier, worker_pool=self.pool,
                      attempt_limit=2, target_limit=2)
        config.update(options)
        return ObservationStore.open(self.base / name, self.base / (name + ".json"), **config)

    def pair(self, name="a"):
        return (self.base / name / "observations.sqlite3").read_bytes(), (self.base / (name + ".json")).read_bytes()

    def test_pool_saturation_preserves_pair_and_quota_without_worker_then_explicit_retry(self):
        with self.open() as store:
            before = self.pair()
            with self.pool.acquire(), patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(StoreBusy):
                    store.observe(self.state, self.signature)
                worker.assert_not_called()
            self.assertEqual(store.summary().attempts_consumed, 0)
            self.assertEqual(self.pair(), before)
            with patch.object(SubprocessObservation, "observe_admitted", return_value=self.unknown):
                store.observe(self.state, self.signature)
            self.assertEqual(store.summary().attempts_consumed, 1)

    def test_two_owned_stores_share_slot_before_admission_through_result_commit(self):
        seen = []
        def hook(name):
            if name in {"admission.committed", "worker.returned", "result.committed"}:
                with self.assertRaises(PoolBusy):
                    self.pool.acquire()
                seen.append(name)
        with self.open(hook=hook) as first, self.open("b") as second:
            before = self.pair("b")
            def worker(state, signature, *, ownership_descriptors, admission_descriptor):
                self.assertNotIn(admission_descriptor, ownership_descriptors)
                with self.assertRaises(StoreBusy):
                    second.observe(state, signature)
                self.assertEqual(self.pair("b"), before)
                return self.verified
            with patch.object(SubprocessObservation, "observe_admitted", side_effect=worker):
                first.observe(self.state, self.signature)
            self.assertEqual(seen, ["admission.committed", "worker.returned", "result.committed"])
            with self.pool.acquire():
                pass

    def test_failed_pending_commit_releases_slot_and_invokes_no_worker(self):
        def hook(name):
            if name == "admission.before_db_commit":
                raise OSError("synthetic admission interruption")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            worker.assert_not_called()
            with self.pool.acquire():
                pass

    def test_unknown_exception_and_cancellation_release_slot_without_refunding_admitted_work(self):
        for index, result in enumerate((self.unknown, RuntimeError("synthetic failure"), KeyboardInterrupt)):
            with self.open(str(index)) as store:
                config = {"return_value": result} if type(result) is bytes else {"side_effect": result}
                with patch.object(SubprocessObservation, "observe_admitted", **config):
                    if result is KeyboardInterrupt:
                        with self.assertRaises(KeyboardInterrupt):
                            store.observe(self.state, self.signature)
                    else:
                        self.assertEqual(store.observe(self.state, self.signature), self.unknown)
                self.assertEqual(store.summary().attempts_consumed, 1)
                with self.pool.acquire():
                    pass

    def test_exhaustion_known_or_invalid_target_never_acquires_a_slot(self):
        with self.open() as store:
            with patch.object(SubprocessObservation, "observe_admitted", return_value=self.verified):
                store.observe(self.state, self.signature)
            with patch.object(PublicWorkerPool, "acquire", side_effect=AssertionError("invalid target admitted")):
                with self.assertRaises(records.RecordKnown):
                    store.observe(self.state, self.signature)
                with self.assertRaises(ValueError):
                    store.observe(self.state, bytes(63))
            with patch.object(SubprocessObservation, "observe_admitted", return_value=self.unknown):
                store.observe(self.state, self.signature, recheck=True)
            with patch.object(PublicWorkerPool, "acquire", side_effect=AssertionError("exhaustion admitted")):
                with self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, self.signature, recheck=True)

    def test_corrupted_pool_quarantines_before_pending_charge_without_rewrite(self):
        with self.open() as store:
            before = self.pair()
            config = self.base / "worker-pool/pool.json"
            config.write_bytes(config.read_bytes() + b"\n")
            with patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(StoreQuarantined):
                    store.observe(self.state, self.signature)
                worker.assert_not_called()
            self.assertEqual(self.pair(), before)
            with self.assertRaises(StoreQuarantined):
                store.summary()

    def test_wrong_pool_profile_quarantines_matching_store_pair_without_worker(self):
        with self.open():
            pass
        before = self.pair()
        for pool in (PublicWorkerPool.open(self.base / "different-id", pool_id_hex="77" * 32, slot_limit=1),
                     synthetic_pool(self.base, directory=self.base / "different-limit", slot_limit=2)):
            with patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(StoreQuarantined):
                    self.open(worker_pool=pool)
                worker.assert_not_called()
            self.assertEqual(self.pair(), before)

    def test_stored_pool_profile_type_value_and_length_quarantine_without_rewrite(self):
        with self.open():
            pass
        original = self.pair()
        database = self.base / "a/observations.sqlite3"
        for value in ("77" * 32, b"x" * 64, "x" * 2048):
            with self.subTest(kind=type(value).__name__):
                database.write_bytes(original[0])
                with sqlite3.connect(database) as connection:
                    connection.execute("UPDATE checkpoint SET worker_pool_profile=?", (value,))
                before = self.pair()
                with self.assertRaises(StoreQuarantined):
                    self.open()
                self.assertEqual(self.pair(), before)

    def test_matching_profile_clone_is_accepted_and_is_not_physical_pool_authentication(self):
        with self.open():
            pass
        clone = synthetic_pool(self.base, directory=self.base / "clone", slot_limit=1)
        with self.pool.acquire(), self.open(worker_pool=clone) as store:
            with patch.object(SubprocessObservation, "observe_admitted", return_value=self.unknown):
                store.observe(self.state, self.signature)
            self.assertEqual(store.summary().attempts_consumed, 1)

    def test_missing_pool_or_storage_overlap_rejects_before_store_creation(self):
        with self.assertRaises(StoreError):
            self.open(worker_pool=None)
        self.assertFalse((self.base / "a").exists())
        for root, anchor in ((self.base / "worker-pool", self.base / "head.json"),
                             (self.base / "a", self.base / "worker-pool/head.json")):
            with self.assertRaises(StoreQuarantined):
                ObservationStore.open(root, anchor, store_id_hex=STORE_ID, verifier=self.verifier,
                    worker_pool=self.pool, attempt_limit=2, target_limit=2)
        self.assertFalse((self.base / "a").exists())
