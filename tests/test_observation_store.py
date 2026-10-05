"""Owned disk sequencing uses synthetic claims; actual workers qualify separately."""

from contextlib import closing
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import exchange, observation_evidence as evidence, observation_records as records
from offline_session.observation_store import (ObservationStore, StoreBusy, StoreConflict,
    StoreError, StoreOwnershipError, StoreQuarantined, MAX_CHECKPOINT_BYTES, MAX_DATABASE_BYTES)
from offline_session.observation_verifier import SubprocessObservation
from completion_test_support import final_signatures, released_bob
from observation_store_test_support import STORE_ID, synthetic_pool, synthetic_verifier


@unittest.skipUnless(os.name == "posix", "owned store qualification requires POSIX locks")
class ObservationStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = released_bob()
        cls.signature = final_signatures()[0]
        cls.verifier = synthetic_verifier()
        cls.profile = cls.verifier.profile_digest_hex
        cls.unknown = evidence.unknown_statement(cls.state, cls.signature, verifier_profile_digest_hex=cls.profile)
        fields = json.loads(cls.unknown)
        cls.verified = exchange.canonical(dict(fields, outcome="verified"))
        cls.rejected = exchange.canonical(dict(fields, outcome="rejected"))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-observation-store-")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root, self.anchor = self.base / "records", self.base / "head.json"

    def open(self, **options):
        config = dict(store_id_hex=STORE_ID, verifier=self.verifier, worker_pool=synthetic_pool(self.base),
                      attempt_limit=3, target_limit=2)
        config.update(options)
        return ObservationStore.open(self.root, self.anchor, **config)

    def call(self, store, statement=None, **options):
        statement = self.verified if statement is None else statement
        with patch.object(SubprocessObservation, "observe_admitted", return_value=statement) as worker:
            result = store.observe(self.state, self.signature, **options)
        self.assertEqual(worker.call_count, 1)
        return result

    def pair(self):
        return (self.root / "observations.sqlite3").read_bytes(), self.anchor.read_bytes()

    def test_empty_private_pair_reopens_with_same_locally_expected_configuration(self):
        with self.open() as store:
            self.assertEqual(store.summary().attempts_remaining, 3)
            self.assertIsNone(store.known_statement(self.state, self.signature))
        before = self.pair()
        with self.open() as store:
            self.assertEqual(store.summary().revision, 0)
        self.assertEqual(self.pair(), before)
        for path in (self.root, self.root / "observations.sqlite3", self.anchor,
                     self.root / "observations.lock", self.anchor.with_name("head.json.lock")):
            self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_pending_is_in_both_files_before_worker_and_result_before_return(self):
        seen = []
        def worker(state, signature, *, ownership_descriptors, admission_descriptor):
            with closing(sqlite3.connect(self.root / "observations.sqlite3")) as connection, connection:
                wire = connection.execute("SELECT record_bytes FROM checkpoint").fetchone()[0]
            self.assertEqual(json.loads(wire)["attempts"][0]["outcome"], None)
            self.assertEqual(json.loads(self.anchor.read_bytes())["revision"], 1)
            seen.append("worker")
            return self.verified
        with self.open() as store, patch.object(SubprocessObservation, "observe_admitted", side_effect=worker):
            self.assertEqual(store.observe(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().revision, 2)
            self.assertEqual(json.loads(self.anchor.read_bytes())["revision"], 2)
        self.assertEqual(seen, ["worker"])
        with self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().attempts_consumed, 1)

    def test_exact_negative_is_retained_separately_from_unknown(self):
        with self.open() as store:
            self.assertEqual(self.call(store, self.rejected), self.rejected)
        with self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.rejected)
            self.assertEqual(store.summary().rejected_claims, 1)
            self.assertEqual(store.summary().pending_attempts, 0)

    def test_unknown_retry_and_recheck_charge_all_attempts_without_erasing_normal(self):
        with self.open() as store:
            self.assertEqual(self.call(store, self.unknown), self.unknown)
            self.assertIsNone(store.known_statement(self.state, self.signature))
        with self.open() as store:
            self.call(store)
            self.assertEqual(self.call(store, self.unknown, recheck=True), self.unknown)
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)
            self.assertEqual(store.summary().attempts_remaining, 0)
            with patch.object(SubprocessObservation, "observe_admitted") as worker, \
                    patch.object(evidence, "prepare", side_effect=AssertionError("target work after exhaustion")):
                with self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, self.signature, recheck=True)
                worker.assert_not_called()
        with self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, 3)
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)

    def test_known_claim_requires_explicit_recheck_without_worker_or_disk_change(self):
        with self.open() as store:
            self.call(store)
            before = self.pair()
            with patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(records.RecordKnown):
                    store.observe(self.state, self.signature)
                worker.assert_not_called()
            self.assertEqual(self.pair(), before)

    def test_conflicting_normal_is_committed_then_no_claim_or_further_worker_is_selected(self):
        with self.open() as store:
            self.call(store)
            with patch.object(SubprocessObservation, "observe_admitted", return_value=self.rejected):
                with self.assertRaises(records.RecordConflict):
                    store.observe(self.state, self.signature, recheck=True)
            self.assertEqual(store.summary().conflicting_targets, 1)
        with self.open() as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(records.RecordConflict):
                store.known_statement(self.state, self.signature)
            with self.assertRaises(records.RecordConflict):
                store.observe(self.state, self.signature, recheck=True)
            worker.assert_not_called()

    def test_malformed_worker_return_becomes_charged_unknown(self):
        for result in (b"{}", self.verified + b"\n", None):
            with self.subTest(result=result):
                self.root = self.base / ("records-" + str(len(str(result))))
                self.anchor = self.base / (self.root.name + ".json")
                with self.open() as store, patch.object(SubprocessObservation, "observe_admitted", return_value=result):
                    self.assertEqual(store.observe(self.state, self.signature), self.unknown)
                    self.assertEqual(store.summary().attempts_consumed, 1)
                    self.assertEqual(store.summary().pending_attempts, 0)
                    self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_cross_target_worker_return_becomes_unknown_without_admitting_other_claim(self):
        statement = evidence.unknown_statement(self.state, bytes(64), verifier_profile_digest_hex=self.profile)
        statement = exchange.canonical(dict(json.loads(statement), outcome="verified"))
        with self.open() as store:
            self.assertEqual(self.call(store, statement), self.unknown)
            self.assertIsNone(store.known_statement(self.state, self.signature))
            self.assertEqual(store.summary().verified_claims, 0)

    def test_worker_exception_has_no_diagnostics_and_commits_unknown(self):
        with self.open() as store, patch.object(SubprocessObservation, "observe_admitted", side_effect=RuntimeError("synthetic diagnostic")):
            self.assertEqual(store.observe(self.state, self.signature), self.unknown)
            self.assertEqual(store.summary().attempts_consumed, 1)
        self.assertNotIn(b"synthetic diagnostic", b"".join(self.pair()))

    def test_keyboard_interrupt_and_system_exit_commit_unknown_before_propagation(self):
        for index, exception in enumerate((KeyboardInterrupt, SystemExit, GeneratorExit)):
            with self.subTest(exception=exception.__name__):
                self.root, self.anchor = self.base / str(index), self.base / (str(index) + ".json")
                with self.open() as store, patch.object(SubprocessObservation, "observe_admitted", side_effect=exception):
                    with self.assertRaises(exception):
                        store.observe(self.state, self.signature)
                    self.assertEqual(store.summary().attempts_consumed, 1)
                    self.assertEqual(store.summary().pending_attempts, 0)
                with self.open() as store:
                    self.assertIsNone(store.known_statement(self.state, self.signature))
                    self.assertEqual(store.summary().attempts_consumed, 1)

    def test_invalid_target_recheck_choice_or_input_never_charges_or_runs_worker(self):
        with self.open() as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            before = self.pair()
            for state, signature, recheck in (({}, self.signature, False), (self.state, bytes(63), False),
                                               (self.state, None, False), (self.state, self.signature, 1),
                                               (self.state, self.signature, True)):
                with self.subTest(recheck=recheck), self.assertRaises(records.RecordError):
                    store.observe(state, signature, recheck=recheck)
            self.assertEqual(self.pair(), before)
            worker.assert_not_called()

    def test_target_limit_rejects_another_exact_key_without_running_worker_or_evicting_normal(self):
        with self.open(target_limit=1) as store:
            self.call(store)
            before = self.pair()
            with patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(records.RecordExhausted):
                    store.observe(self.state, bytes(64))
                worker.assert_not_called()
            self.assertEqual(self.pair(), before)
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)

    def test_calling_from_wrong_thread_cannot_read_mutate_or_close_or_release_lock(self):
        errors = []
        with self.open() as store:
            def foreign():
                for call in (store.summary, lambda: store.known_statement(self.state, self.signature),
                             lambda: store.observe(self.state, self.signature), store.close):
                    try:
                        call()
                    except StoreOwnershipError:
                        errors.append(True)
                store._release()
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 4)
            with self.assertRaises(StoreBusy):
                self.open()
            self.assertEqual(store.summary().attempts_consumed, 0)

    def test_reentrant_read_mutate_and_close_are_blocked_until_worker_result_is_committed(self):
        with self.open() as store:
            def worker(state, signature, *, ownership_descriptors, admission_descriptor):
                for call in (store.summary, lambda: store.known_statement(state, signature),
                             lambda: store.observe(state, signature), store.close):
                    with self.assertRaises(StoreConflict):
                        call()
                with self.assertRaises(StoreBusy):
                    self.open()
                return self.verified
            with patch.object(SubprocessObservation, "observe_admitted", side_effect=worker):
                self.assertEqual(store.observe(self.state, self.signature), self.verified)

    def test_closed_handle_cannot_read_or_start_work_and_close_is_idempotent(self):
        store = self.open()
        store.close()
        store.close()
        with self.assertRaises(StoreOwnershipError):
            store.summary()
        with patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreOwnershipError):
                store.observe(self.state, self.signature)
            worker.assert_not_called()

    def test_wrong_expected_identity_profile_or_limits_quarantines_without_worker_or_rewrite(self):
        with self.open():
            pass
        before = self.pair()
        altered = copy.copy(self.verifier)
        altered._profile_digest = "44" * 32
        for config in (dict(store_id_hex="33" * 32), dict(verifier=altered), dict(attempt_limit=4), dict(target_limit=3)):
            with self.subTest(config=tuple(config)), patch.object(SubprocessObservation, "observe_admitted") as worker:
                with self.assertRaises(StoreQuarantined):
                    self.open(**config)
                worker.assert_not_called()
                self.assertEqual(self.pair(), before)

    def test_arbitrary_callback_or_invalid_bounds_cannot_create_a_pair(self):
        for config in (dict(verifier=lambda *args: self.verified), dict(attempt_limit=0),
                       dict(target_limit=True), dict(store_id_hex="invalid")):
            with self.subTest(config=tuple(config)), self.assertRaises(StoreError):
                self.open(**config)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.anchor.exists())

    def test_changed_local_worker_profile_is_rejected_before_admission(self):
        worker = copy.copy(self.verifier)
        with self.open(verifier=worker) as store:
            before = self.pair()
            worker._profile_digest = "44" * 32
            with self.assertRaises(StoreError):
                store.observe(self.state, self.signature)
            self.assertEqual(self.pair(), before)

    def test_failed_admission_persistence_never_starts_worker_and_poisoned_handle_cannot_retry(self):
        def hook(name):
            if name == "admission.before_db_commit":
                raise OSError("synthetic admission failure")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            with self.assertRaises(StoreQuarantined):
                store.summary()
            worker.assert_not_called()
        with self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, 0)

    def test_db_commit_without_checkpoint_quarantines_pair_without_automatic_repair(self):
        def hook(name):
            if name == "admission.after_db_commit":
                raise OSError("synthetic checkpoint failure")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            worker.assert_not_called()
        before = self.pair()
        with self.assertRaises(StoreQuarantined):
            self.open()
        self.assertEqual(self.pair(), before)

    def test_result_commit_failure_never_returns_normal_and_reopen_preserves_charge_as_unknown(self):
        def hook(name):
            if name == "result.before_db_commit":
                raise OSError("synthetic result failure")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted", return_value=self.verified) as worker:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            worker.assert_called_once()
        with self.open() as store:
            self.assertEqual(store.summary().attempts_consumed, 1)
            self.assertEqual(store.summary().pending_attempts, 0)
            self.assertIsNone(store.known_statement(self.state, self.signature))

    def test_cancellation_with_uncertain_result_persistence_quarantines_before_any_claim_can_return(self):
        def hook(name):
            if name == "result.after_db_commit":
                raise OSError("synthetic cancellation checkpoint gap")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted", side_effect=KeyboardInterrupt):
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            with self.assertRaises(StoreQuarantined):
                store.summary()
        with self.assertRaises(StoreQuarantined):
            self.open()

    def test_checkpoint_replacement_failure_quarantines_owner_until_locked_reopen(self):
        def hook(name):
            if name == "result.after_checkpoint_replace":
                raise OSError("synthetic directory sync failure")
        with self.open(hook=hook) as store, patch.object(SubprocessObservation, "observe_admitted", return_value=self.verified):
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            with self.assertRaises(StoreQuarantined):
                store.known_statement(self.state, self.signature)
        with self.open() as store:
            self.assertEqual(store.known_statement(self.state, self.signature), self.verified)

    def test_failed_recovery_persistence_never_replays_worker_and_divergence_stays_quarantined(self):
        def stop(name):
            if name == "admission.committed":
                raise OSError("synthetic stop before work")
        with self.open(hook=stop) as store, patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
            worker.assert_not_called()
        def fail(name):
            if name == "recovery.after_db_commit":
                raise OSError("synthetic recovery checkpoint gap")
        with patch.object(SubprocessObservation, "observe_admitted") as worker:
            with self.assertRaises(StoreQuarantined):
                self.open(hook=fail)
            with self.assertRaises(StoreQuarantined):
                self.open()
            worker.assert_not_called()

    def test_local_target_is_snapshotted_before_work(self):
        mutable = copy.deepcopy(self.state)
        before = copy.deepcopy(mutable)
        with self.open() as store:
            def worker(state, signature, *, ownership_descriptors, admission_descriptor):
                self.assertIsNot(state, mutable)
                mutable.clear()
                self.assertEqual(state, before)
                return self.verified
            with patch.object(SubprocessObservation, "observe_admitted", side_effect=worker):
                self.assertEqual(store.observe(mutable, self.signature), self.verified)
            self.assertEqual(store.known_statement(before, self.signature), self.verified)

    def test_single_sided_old_restore_quarantines_both_directions(self):
        with self.open() as store:
            old = self.pair()
            self.call(store)
        current = self.pair()
        for database, checkpoint in ((old[0], current[1]), (current[0], old[1])):
            (self.root / "observations.sqlite3").write_bytes(database)
            self.anchor.write_bytes(checkpoint)
            with self.assertRaises(StoreQuarantined):
                self.open()

    def test_matching_pair_restore_replenishes_quota_exposing_unresolved_rollback_boundary(self):
        with self.open(attempt_limit=1) as store:
            old = self.pair()
            self.call(store)
        with self.open(attempt_limit=1) as store:
            self.assertEqual(store.summary().attempts_remaining, 0)
        (self.root / "observations.sqlite3").write_bytes(old[0])
        self.anchor.write_bytes(old[1])
        with self.open(attempt_limit=1) as store:
            self.assertEqual(store.summary().attempts_remaining, 1)
            self.call(store)
            self.assertEqual(store.summary().attempts_consumed, 1)

    def test_missing_pair_half_is_never_reinitialized(self):
        with self.open():
            pass
        old = self.pair()
        for missing in (self.anchor, self.root / "observations.sqlite3"):
            missing.unlink()
            with self.assertRaises(StoreQuarantined):
                self.open()
            self.assertFalse(missing.exists())
            (self.root / "observations.sqlite3").write_bytes(old[0])
            self.anchor.write_bytes(old[1])
            os.chmod(self.root / "observations.sqlite3", 0o600)
            os.chmod(self.anchor, 0o600)

    def test_noncanonical_oversized_or_tampered_checkpoint_is_not_rewritten(self):
        with self.open():
            pass
        original = self.anchor.read_bytes()
        for wire in (original + b"\n", b"{}", b"x" * (MAX_CHECKPOINT_BYTES + 1)):
            with self.subTest(length=len(wire)):
                self.anchor.write_bytes(wire)
                with self.assertRaises(StoreQuarantined):
                    self.open()
                self.assertEqual(self.anchor.read_bytes(), wire)

    def test_bad_database_version_type_and_record_bytes_quarantine(self):
        with self.open():
            pass
        old = self.pair()
        changes = (("version", 0), ("revision", -1), ("digest", "00" * 32),
                   ("record_bytes", b"{}"), ("record_bytes", "{}"),
                   ("record_bytes", b"x" * (records.MAX_RECORD_BYTES + 1)))
        for field, value in changes:
            with self.subTest(field=field):
                (self.root / "observations.sqlite3").write_bytes(old[0])
                with closing(sqlite3.connect(self.root / "observations.sqlite3")) as connection, connection:
                    connection.execute("UPDATE checkpoint SET " + field + "=?", (value,))
                before = self.pair()
                with self.assertRaises(StoreQuarantined):
                    self.open()
                self.assertEqual(self.pair(), before)

    def test_consistent_v1_v2_pending_pairs_quarantine_without_migration_or_recovery(self):
        def stop(name):
            if name == "admission.committed":
                raise OSError("synthetic pre-worker interruption")
        with self.open(hook=stop) as store:
            with self.assertRaises(StoreQuarantined):
                store.observe(self.state, self.signature)
        database = self.root / "observations.sqlite3"
        original = self.pair()
        for version in (1, 2):
            with self.subTest(version=version):
                database.write_bytes(original[0])
                with closing(sqlite3.connect(database)) as connection, connection:
                    wire = connection.execute("SELECT record_bytes FROM checkpoint").fetchone()[0]
                    self.assertEqual(records.inspect(wire, expected_verifier_profile_digest_hex=self.profile).pending_attempts, 1)
                    old = dict(json.loads(original[1]), version=version)
                    del old["digest_hex"]
                    del old["worker_pool_profile_digest_hex"]
                    old["digest_hex"] = hashlib.sha256(
                        ("PTLC/observation-store-checkpoint/v" + str(version)).encode("ascii")
                        + b"\x00" + exchange.canonical(old)).hexdigest()
                    connection.execute("DROP TABLE checkpoint")
                    connection.execute("CREATE TABLE checkpoint (slot INTEGER PRIMARY KEY CHECK (slot=1), "
                        "version INTEGER NOT NULL, store_id TEXT NOT NULL, revision INTEGER NOT NULL, "
                        "record_bytes BLOB NOT NULL, digest TEXT NOT NULL)")
                    connection.execute("INSERT INTO checkpoint VALUES (1, ?, ?, ?, ?, ?)",
                        (version, STORE_ID, old["revision"], wire, old["digest_hex"]))
                self.anchor.write_bytes(exchange.canonical(old))
                before = self.pair()
                with patch.object(SubprocessObservation, "observe_admitted") as worker:
                    with self.assertRaises(StoreQuarantined):
                        self.open()
                    worker.assert_not_called()
                self.assertEqual(self.pair(), before)

    def test_oversized_database_is_rejected_before_sqlite_connect(self):
        with self.open():
            pass
        with (self.root / "observations.sqlite3").open("r+b") as output:
            output.truncate(MAX_DATABASE_BYTES + 1)
        with patch("sqlite3.connect", side_effect=AssertionError("oversized database opened")) as connection:
            with self.assertRaises(StoreQuarantined):
                self.open()
            connection.assert_not_called()

    def test_symlink_pair_lock_and_nonprivate_files_are_rejected(self):
        with self.open():
            pass
        for path in (self.anchor, self.root / "observations.sqlite3", self.root / "observations.lock"):
            with self.subTest(path=path.name):
                saved = path.with_name(path.name + ".saved")
                path.rename(saved)
                path.symlink_to(saved)
                with self.assertRaises(StoreQuarantined):
                    self.open()
                path.unlink()
                saved.rename(path)
                os.chmod(path, 0o644)
                with self.assertRaises(StoreQuarantined):
                    self.open()
                os.chmod(path, 0o600)

    def test_unsupported_sidecars_and_internal_checkpoint_fail_before_work(self):
        with self.open():
            pass
        for suffix in ("-wal", "-shm"):
            sidecar = self.root / ("observations.sqlite3" + suffix)
            sidecar.write_bytes(b"synthetic")
            os.chmod(sidecar, 0o600)
            with self.assertRaises(StoreQuarantined):
                self.open()
            sidecar.unlink()
        with self.assertRaises(StoreQuarantined):
            ObservationStore.open(self.base / "internal", self.base / "internal/head.json",
                store_id_hex=STORE_ID, verifier=self.verifier, worker_pool=synthetic_pool(self.base),
                attempt_limit=2, target_limit=2)
