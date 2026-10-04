"""Synthetic verdicts qualify v4 policy continuity and durable ordering only.

Host selection is simulated for these SQLite/lock cases. Native Linux workers
and actual mathematical verdicts are qualified separately, never inferred here.
"""

import copy
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence, observation_records as records
from offline_session.observation_store import ObservationStore, StoreBusy, StoreError, StoreQuarantined
from offline_session.observation_verifier import SubprocessObservation
from offline_session.public_worker import _admission_descriptor, _lease_descriptors
from offline_session.worker_pool import PoolBusy
from offline_session.worker_resources import WorkerResourceLimits
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


class LimitedStoreContinuityTests(unittest.TestCase):
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
        directory = tempfile.TemporaryDirectory(prefix="synthetic-observation-resources-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"
        self.pool = synthetic_pool(self.base, slot_limit=1)
        self.policy = WorkerResourceLimits(2, 128 * 1024 * 1024)

    def config(self, **options):
        value = dict(store_id_hex=STORE_ID, verifier=self.verifier, worker_pool=self.pool,
                     attempt_limit=3, target_limit=2)
        value.update(options)
        return value

    def open(self, **options):
        config = self.config(resource_limits=self.policy)
        config.update(options)
        return ObservationStore.open_limited(self.root, self.anchor,
                                             **config)

    def plain(self):
        return ObservationStore.open(self.root, self.anchor, **self.config())

    def pair(self):
        return (self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes()

    @contextmanager
    def no_worker(self):
        with patch.object(SubprocessObservation, "observe_limited") as limited, \
                patch.object(SubprocessObservation, "observe_admitted") as fallback, \
                patch("offline_session.public_worker.subprocess.Popen") as spawn:
            yield
            limited.assert_not_called()
            fallback.assert_not_called()
            spawn.assert_not_called()

    def call(self, store, statement=None, **options):
        with patch.object(SubprocessObservation, "observe_limited",
                return_value=self.verified if statement is None else statement) as worker, \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            result = store.observe(self.state, self.signature, **options)
            self.assertEqual(worker.call_count, 1)
            self.assertIs(worker.call_args.kwargs["resource_limits"], self.policy)
            fallback.assert_not_called()
            return result

    def interrupt(self, point):
        def hook(name):
            if name == point:
                raise RuntimeError("synthetic interrupted persistence")
        return hook

    def test_explicit_v4_pair_reopens_with_identical_policy_without_rewrite(self):
        with self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, 0)
        before = self.pair()
        with self.no_worker(), self.open() as store:
            self.assertEqual(store.summary().revision, 0)
        self.assertEqual(self.pair(), before)
        anchor = json.loads(self.anchor.read_bytes())
        self.assertEqual(anchor["version"], 4)
        self.assertEqual(anchor["worker_resource_profile_digest_hex"], self.policy.profile_digest_hex)
        with sqlite3.connect(self.root / "observations.sqlite3") as connection:
            self.assertEqual(connection.execute("SELECT version, worker_resource_profile FROM checkpoint").fetchone(),
                             (4, self.policy.profile_digest_hex))

    def test_ordinary_v3_remains_explicit_and_never_dispatches_limited_work(self):
        with self.plain() as store, patch.object(SubprocessObservation, "observe_admitted", return_value=self.verified) as worker, \
                patch.object(SubprocessObservation, "observe_limited") as limited:
            self.assertEqual(store.observe(self.state, self.signature), self.verified)
            self.assertEqual(worker.call_count, 1)
            limited.assert_not_called()
        self.assertEqual(json.loads(self.anchor.read_bytes())["version"], 3)
        self.assertNotIn("worker_resource_profile_digest_hex", json.loads(self.anchor.read_bytes()))

    def test_ordinary_entry_cannot_downgrade_v4_or_change_its_files(self):
        with self.open():
            pass
        before = self.pair()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.plain()
        self.assertEqual(self.pair(), before)

    def test_limited_entry_cannot_automatically_upgrade_v3(self):
        with self.plain():
            pass
        before = self.pair()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.open()
        self.assertEqual(self.pair(), before)

    def test_changed_cpu_or_address_space_rejects_before_rewrite(self):
        with self.open():
            pass
        before = self.pair()
        for policy in (WorkerResourceLimits(1, 128 * 1024 * 1024),
                       WorkerResourceLimits(2, 256 * 1024 * 1024)):
            with self.subTest(policy=policy.profile_digest_hex), self.no_worker(), self.assertRaises(StoreQuarantined):
                self.open(resource_limits=policy)
            self.assertEqual(self.pair(), before)

    def test_wrong_policy_cannot_interrupt_pending_and_matching_reopen_recovers_once(self):
        with self.open(hook=self.interrupt("admission.committed")) as store, self.no_worker():
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
        before = self.pair()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.open(resource_limits=WorkerResourceLimits(1, 128 * 1024 * 1024))
        self.assertEqual(self.pair(), before)
        with self.no_worker(), self.open() as store:
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
            self.assertIsNone(store.known_statement(self.state, self.signature))
        recovered = self.pair()
        with self.no_worker(), self.open():
            pass
        self.assertEqual(self.pair(), recovered)

    def test_math_pool_and_attempt_configuration_still_bind_v4(self):
        with self.open():
            pass
        before = self.pair()
        altered = copy.copy(self.verifier)
        altered._profile_digest = "44" * 32
        other_pool = synthetic_pool(self.base, slot_limit=2, directory=self.base / "other-pool")
        for options in (dict(verifier=altered), dict(worker_pool=other_pool), dict(attempt_limit=4),
                        dict(target_limit=3), dict(store_id_hex="33" * 32)):
            with self.subTest(options=tuple(options)), self.no_worker(), self.assertRaises(StoreQuarantined):
                self.open(**options)
            self.assertEqual(self.pair(), before)

    def test_missing_or_substituted_policy_never_creates_store_files(self):
        for policy in (None, object(), {"cpu_seconds": 2, "address_space_bytes": 134217728}):
            with self.subTest(kind=type(policy).__name__), self.no_worker(), self.assertRaises(StoreError):
                self.open(resource_limits=policy)
            self.assertFalse(self.root.exists())
            self.assertFalse(self.anchor.exists())
        with self.no_worker(), self.assertRaises(TypeError):
            ObservationStore.open_limited(self.root, self.anchor, **self.config())

    def test_unsupported_host_refuses_existing_pair_before_database_connect(self):
        with self.open():
            pass
        before = self.pair()
        with patch("offline_session.worker_resources.sys.platform", "darwin"), self.no_worker(), \
                patch("offline_session.observation_store.sqlite3.connect") as connect:
            with self.assertRaises(StoreError):
                self.open()
            connect.assert_not_called()
        self.assertEqual(self.pair(), before)

    def test_wrong_policy_or_downgrade_never_connects_with_private_sidecar(self):
        with self.open():
            pass
        sidecar = self.root / "observations.sqlite3-journal"
        sidecar.write_bytes(b"synthetic bounded rollback sidecar")
        sidecar.chmod(0o600)
        before = self.pair(), sidecar.read_bytes()
        for opener in (lambda: self.open(resource_limits=WorkerResourceLimits(1, 128 * 1024 * 1024)), self.plain):
            with self.no_worker(), patch("offline_session.observation_store.sqlite3.connect") as connect:
                with self.assertRaises(StoreQuarantined):
                    opener()
                connect.assert_not_called()
            self.assertEqual((self.pair(), sidecar.read_bytes()), before)

    def test_changed_live_policy_blocks_read_work_and_slot_acquisition(self):
        with self.open() as store:
            before = self.pair()
            object.__setattr__(self.policy, "cpu_seconds", 1)
            with self.no_worker(), patch.object(type(self.pool), "acquire") as acquire:
                for call in (store.summary, lambda: store.known_statement(self.state, self.signature),
                             lambda: store.observe(self.state, self.signature)):
                    with self.assertRaises(StoreError):
                        call()
                acquire.assert_not_called()
            self.assertEqual(self.pair(), before)

    def test_policy_changed_after_admission_is_charged_unknown_without_fallback(self):
        original = self.policy.profile_digest_hex
        def hook(name):
            if name == "admission.committed":
                object.__setattr__(self.policy, "cpu_seconds", 1)
        with self.open(hook=hook) as store, self.no_worker():
            self.assertEqual(store.observe(self.state, self.signature), self.unknown)
            self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"], original)
            with self.assertRaises(StoreError):
                store.summary()
            object.__setattr__(self.policy, "cpu_seconds", 2)
            self.assertEqual(store.summary().attempts_consumed, 1)
        with self.no_worker(), self.open() as store:
            self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_worker_sees_durable_pending_policy_and_three_real_leases(self):
        def worker(state, signature, *, ownership_descriptors, admission_descriptor, resource_limits):
            self.assertIs(resource_limits, self.policy)
            _admission_descriptor(admission_descriptor, _lease_descriptors(ownership_descriptors))
            anchor = json.loads(self.anchor.read_bytes())
            self.assertEqual((anchor["version"], anchor["revision"], anchor["worker_resource_profile_digest_hex"]),
                             (4, 1, self.policy.profile_digest_hex))
            with sqlite3.connect(self.root / "observations.sqlite3") as connection:
                wire, profile = connection.execute("SELECT record_bytes, worker_resource_profile FROM checkpoint").fetchone()
            self.assertEqual(profile, self.policy.profile_digest_hex)
            self.assertIsNone(json.loads(wire)["attempts"][0]["outcome"])
            with self.assertRaises(PoolBusy):
                self.pool.acquire()
            return self.verified
        with self.open() as store, patch.object(SubprocessObservation, "observe_limited", side_effect=worker), \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            self.assertEqual(store.observe(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().revision, 2)
            fallback.assert_not_called()
        with self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)

    def test_exhausted_budget_does_not_prepare_target_acquire_slot_or_run_worker(self):
        with self.open(attempt_limit=1) as store:
            self.call(store)
            before = self.pair()
            with self.no_worker(), patch.object(type(self.pool), "acquire") as acquire, \
                    patch.object(evidence, "prepare", side_effect=AssertionError("unexpected target work")):
                with self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, self.signature, recheck=True)
                acquire.assert_not_called()
            self.assertEqual(self.pair(), before)

    def test_shared_saturation_does_not_persist_or_charge_limited_work(self):
        with self.open() as store, self.pool.acquire(), self.no_worker():
            before = self.pair()
            with self.assertRaises(StoreBusy):
                store.observe(self.state, self.signature)
            self.assertEqual(self.pair(), before)
            self.assertEqual(store.summary().attempts_consumed, 0)

    def test_normal_negative_survives_matching_policy_reopen(self):
        with self.open() as store:
            self.assertEqual(self.call(store, self.rejected), self.rejected)
        with self.no_worker(), self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.rejected)
            self.assertEqual(store.summary().rejected_claims, 1)

    def test_worker_error_is_charged_unknown_with_no_private_diagnostics(self):
        with self.open() as store, patch.object(SubprocessObservation, "observe_limited",
                side_effect=RuntimeError("synthetic private resource failure")), \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            self.assertEqual(store.observe(self.state, self.signature), self.unknown)
            self.assertEqual(store.summary().attempts_consumed, 1)
            fallback.assert_not_called()
        self.assertNotIn(b"synthetic private resource failure", b"".join(self.pair()))
        with self.no_worker(), self.open() as store:
            self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_cancellation_is_unknown_before_propagation_and_reopen(self):
        with self.open() as store, patch.object(SubprocessObservation, "observe_limited", side_effect=KeyboardInterrupt), \
                patch.object(SubprocessObservation, "observe_admitted") as fallback:
            with self.assertRaises(KeyboardInterrupt):
                store.observe(self.state, self.signature)
            self.assertEqual((store.summary().attempts_consumed, store.summary().pending_attempts), (1, 0))
            fallback.assert_not_called()
        with self.no_worker(), self.open() as store:
            self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_normal_conflict_is_durable_under_the_same_policy(self):
        with self.open() as store:
            self.call(store)
            with patch.object(SubprocessObservation, "observe_limited", return_value=self.rejected):
                with self.assertRaises(records.RecordConflict):
                    store.observe(self.state, self.signature, recheck=True)
        with self.no_worker(), self.open() as store:
            self.assertEqual(store.summary().conflicting_targets, 1)
            with self.assertRaises(records.RecordConflict):
                store.known_statement(self.state, self.signature)

    def test_torn_pair_is_quarantined_without_automatic_policy_repair(self):
        with self.open(hook=self.interrupt("admission.after_db_commit")) as store, self.no_worker():
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
        before = self.pair()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.open()
        self.assertEqual(self.pair(), before)

    def test_lost_synthetic_return_recovers_unknown_and_keeps_policy(self):
        with self.open(hook=self.interrupt("worker.returned")) as store, \
                patch.object(SubprocessObservation, "observe_limited", return_value=self.verified):
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
        with self.no_worker(), self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertIsNone(store.known_statement(self.state, self.signature))
        self.assertEqual(json.loads(self.anchor.read_bytes())["worker_resource_profile_digest_hex"], self.policy.profile_digest_hex)
        with self.pool.acquire():
            pass

    def test_changed_anchor_policy_is_not_repaired_on_reopen(self):
        with self.open():
            pass
        anchor = json.loads(self.anchor.read_bytes())
        anchor["worker_resource_profile_digest_hex"] = "55" * 32
        self.anchor.write_bytes(exchange.canonical(anchor))
        before = self.pair()
        with self.no_worker(), self.assertRaises(StoreQuarantined):
            self.open()
        self.assertEqual(self.pair(), before)

    def test_invalid_database_policy_is_bounded_and_never_rewritten(self):
        with self.open():
            pass
        original = self.pair()
        for value in ("", "f" * 129, "55" * 32, b"f" * 64):
            with self.subTest(kind=type(value).__name__, length=len(value)):
                (self.root / "observations.sqlite3").write_bytes(original[0])
                with sqlite3.connect(self.root / "observations.sqlite3") as connection:
                    connection.execute("UPDATE checkpoint SET worker_resource_profile=?", (value,))
                before = self.pair()
                with self.no_worker(), self.assertRaises(StoreQuarantined):
                    self.open()
                self.assertEqual(self.pair(), before)

    def test_policy_binding_does_not_change_pure_record_or_math_statement_bytes(self):
        with self.open() as store:
            self.call(store)
        with sqlite3.connect(self.root / "observations.sqlite3") as connection:
            limited_wire = connection.execute("SELECT record_bytes FROM checkpoint").fetchone()[0]
        self.root, self.anchor = self.base / "ordinary", self.base / "ordinary.json"
        with self.plain() as store, patch.object(SubprocessObservation, "observe_admitted", return_value=self.verified):
            self.assertEqual(store.observe(self.state, self.signature), self.verified)
        with sqlite3.connect(self.root / "observations.sqlite3") as connection:
            ordinary_wire = connection.execute("SELECT record_bytes FROM checkpoint").fetchone()[0]
        self.assertEqual(limited_wire, ordinary_wire)
