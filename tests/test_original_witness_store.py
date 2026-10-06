"""Owned transaction regressions with explicit forged-callback controls.

The separate post-build qualifier replays these cases with the actual selected
public signature worker. Neither run authenticates the source or its head.
"""

import ast
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from qualification import original_read_response as response, policy_effect_store as local
from original_snapshot_vectors import INPUT, OUTPUT, canonical, scenario
from scripts.qualify_original_snapshot_prefix_response import capture, counter_query
import original_snapshot_opening as opening
import original_witness_store as witness
from original_witness_store_actor import callback_control, named_packet


class OriginalWitnessStoreTests(unittest.TestCase):
    check = staticmethod(callback_control)
    actor_mode = "flags"
    actor_context = {}

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-original-witness-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/"witness.sqlite3"
        self.fixture = json.loads(OUTPUT.read_text("ascii"))
        self.packets = {name: named_packet(name) for name in self.fixture["positive_vectors"]}
        self.packets["fresh_initial_absent"] = named_packet("fresh_initial_absent")
        self.store = self.open()
        self.addCleanup(self.dispose)

    def dispose(self):
        if not self.store._closed:
            self.store.close()

    def open(self, path=None, binding=None, check=None):
        return witness.OfflineOriginalWitnessStore(str(path or self.path),
            binding or self.packets["pending"][0], verifier=check or self.check)

    def retain(self, name, store=None):
        return (store or self.store).retain(*self.packets[name])

    def seed(self):
        return self.retain("pending")

    def refused_without_callbacks(self, packet, *, store=None):
        active = store or self.store
        before = active.inspect_retained()
        calls = []
        def check(value):
            calls.append(value)
            return self.check(value)
        with patch.object(active, "_verifier", side_effect=check):
            with self.assertRaises(witness.WitnessRefused):
                active.retain(*packet)
        self.assertEqual(calls, [])
        self.assertEqual(active.inspect_retained(), before)

    def actor(self, command, point="unused"):
        process = subprocess.Popen([sys.executable, "-B", "tests/original_witness_store_actor.py",
            str(self.path), point, self.actor_mode], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def clean():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        self.addCleanup(clean)
        process.stdin.write(json.dumps(self.actor_context)+"\n")
        process.stdin.flush()
        self.assertEqual(self.line(process), "ready")
        process.stdin.write(command+"\n")
        process.stdin.flush()
        return process

    def line(self, process):
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            self.assertTrue(ready.select(15), "bounded synthetic actor response unavailable")
        return process.stdout.readline().strip()

    def test_empty_store_has_no_prior_knowledge_and_only_selected_native_settings(self):
        self.assertIsNone(self.store.inspect_retained())
        self.assertEqual(self.store._db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        self.assertEqual(self.store._db.execute("PRAGMA synchronous").fetchone(), (3,))
        self.assertEqual(self.store._db.execute("PRAGMA trusted_schema").fetchone(), (0,))
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM witness").fetchone(), (0,))

    def test_cold_store_can_retain_nine_independently_selected_live_histories(self):
        for name, packet in self.packets.items():
            if name in ("unavailable_pending", "fresh_initial_absent"):
                continue
            with self.subTest(name=name), self.open(self.path.with_name(name+".sqlite3"), packet[0]) as store:
                result = store.retain(*packet)
                claim = opening.derive_claim(*packet[:2]).as_dict()
                self.assertEqual((result.version, result.observation), (1, claim["observation"]))
                self.assertEqual(store.inspect_retained(), result)

    def test_absent_pending_completed_chain_is_persisted_and_scalar_result_is_unsigned(self):
        results = [self.retain(name) for name in ("initial_absent", "pending", "completed")]
        self.assertEqual([(r.version, r.event_sequence, r.observation) for r in results],
            [(1, 0, "absent"), (2, 1, "pending"), (3, 2, "completed")])
        with self.assertRaises(FrozenInstanceError):
            results[-1].version = 0
        self.assertEqual(set(results[-1].__dict__), {"version", "query_digest_hex", "event_sequence", "observation"})
        self.store.close()
        with self.open() as reopened:
            self.assertEqual(reopened.inspect_retained(), results[-1])

    def test_same_history_fresh_challenge_consumes_slot_without_latest_head_claim(self):
        old = self.retain("initial_absent")
        fresh = self.retain("fresh_initial_absent")
        self.assertEqual((old.event_sequence, fresh.event_sequence, fresh.observation), (0, 0, "absent"))
        self.assertNotEqual(old.query_digest_hex, fresh.query_digest_hex)
        self.assertEqual(fresh.version, 2)

    def test_completed_witness_refuses_delayed_pending_and_fresh_old_absence(self):
        self.seed()
        self.retain("completed")
        for name in ("pending", "initial_absent", "fresh_initial_absent"):
            self.refused_without_callbacks(self.packets[name])
        self.assertEqual(self.store.inspect_retained().observation, "completed")

    def test_first_retained_fork_refuses_other_signed_future_in_both_orders(self):
        for first, second in (("completed", "revoked_pending"), ("revoked_pending", "completed")):
            with self.open(self.path.with_name(first+"-fork.sqlite3")) as store:
                self.retain("pending", store)
                self.retain(first, store)
                self.refused_without_callbacks(self.packets[second], store=store)
                self.assertEqual(store.inspect_retained().version, 2)

    def test_preopened_stale_handle_reads_latest_persisted_witness_before_comparison(self):
        self.seed()
        with self.open() as stale:
            old = stale.inspect_retained()
            completed = self.retain("completed")
            self.assertNotEqual(old, completed)
            self.refused_without_callbacks(self.packets["revoked_pending"], store=stale)
            self.assertEqual(stale.inspect_retained(), completed)

    def test_separate_consumer_files_can_accept_incomparable_first_futures(self):
        self.seed()
        self.store.close()
        copied = self.path.with_name("copied.sqlite3")
        shutil.copyfile(self.path, copied)
        self.store = self.open()
        with self.open(copied) as other:
            done = self.retain("completed")
            stopped = self.retain("revoked_pending", other)
            self.assertEqual((done.event_sequence, stopped.event_sequence), (2, 2))
            self.assertNotEqual(done.query_digest_hex, stopped.query_digest_hex)

    def test_complete_original_root_profile_and_proposal_bindings_cannot_migrate(self):
        self.seed()
        for name in ("replaced_completed", "reduced_pending_two_charges"):
            self.refused_without_callbacks(self.packets[name])
        for name in ("same_id_other_proposal", "same_id_other_historical_profile"):
            vector = self.fixture["counterclaim_vectors"][name]
            with scenario(vector["actual_scenario"]) as actual:
                pair = counter_query(actual, name)
            self.refused_without_callbacks((*pair, canonical(vector["envelope"])))

    def test_signed_unavailable_nulls_do_not_erase_completed_witness(self):
        self.seed()
        self.retain("completed")
        self.refused_without_callbacks(self.packets["unavailable_pending"])
        self.assertEqual(self.store.inspect_retained().version, 2)

    def test_validly_signed_false_claims_are_not_expectation_sources(self):
        self.seed()
        for name, vector in self.fixture["counterclaim_vectors"].items():
            if not name.startswith("false_"):
                continue
            with scenario(vector["actual_scenario"]) as actual:
                pair = counter_query(actual, name)
            self.refused_without_callbacks((*pair, canonical(vector["envelope"])))

    def test_complete_opening_and_packet_grammar_refuse_before_any_callback(self):
        self.seed()
        query, opened, packet = self.packets["completed"]
        variants = [(query, opened+b"\n", packet), (query, opened, packet+b"\n"),
            (query, b"{}", packet), (query, opened, b"{}")]
        value = json.loads(packet)
        value["response"]["claim"]["observation"] = "absent"
        variants.append((query, opened, canonical(value)))
        for changed in variants:
            self.refused_without_callbacks(changed)

    def test_exact_types_and_wire_bounds_refuse_without_input_hooks(self):
        class HookBytes(bytes):
            def __len__(self):
                raise AssertionError("unexpected synthetic hook")
        query, opened, packet = self.packets["pending"]
        for changed in ((query, HookBytes(opened), packet), (query, opened, HookBytes(packet)),
                (True, opened, packet), (query, b"x"*(opening.MAX_WIRE_BYTES+1), packet),
                (query, opened, b"x"*(witness.MAX_RESPONSE_BYTES+1))):
            self.refused_without_callbacks(changed)
        malformed = copy.copy(query)
        object.__setattr__(malformed, "_wire", b"{}")
        self.refused_without_callbacks((malformed, opened, packet))

    def test_bounded_sixty_four_updates_never_evict_completed_history(self):
        self.retain("completed")
        for unused in range(witness.MAX_UPDATES-1):
            self.retain("completed")
        before = self.store.inspect_retained()
        self.assertEqual((before.version, before.observation), (64, "completed"))
        self.refused_without_callbacks(self.packets["completed"])
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM witness").fetchone(), (1,))

    def test_stored_oversized_text_and_out_of_bound_version_refuse_before_blob_loading(self):
        self.seed()
        for expression, value in (("query", "synthetic-text"), ("opening", b"x"*(opening.MAX_WIRE_BYTES+1)),
                ("version", 0), ("version", 65), ("version", 1.5)):
            with self.subTest(field=expression, value_type=type(value).__name__):
                saved = self.store._db.execute("SELECT * FROM witness").fetchone()
                self.store._db.execute("UPDATE witness SET "+expression+"=?", (value,))
                with self.assertRaises(witness.WitnessRefused):
                    self.store.inspect_retained()
                self.store._db.execute("DELETE FROM witness")
                self.store._db.execute("INSERT INTO witness VALUES(?,?,?,?,?)", saved)

    def test_stored_opening_and_query_are_revalidated_against_independent_binding(self):
        self.seed()
        for field in ("query", "opening"):
            original = self.store._db.execute("SELECT "+field+" FROM witness").fetchone()[0]
            self.store._db.execute("UPDATE witness SET "+field+"=?", (b"{}",))
            with self.assertRaises(witness.WitnessRefused):
                self.store.inspect_retained()
            self.store._db.execute("UPDATE witness SET "+field+"=?", (original,))

    def test_stored_response_is_rechecked_and_cannot_be_replaced_by_current_packet(self):
        self.seed()
        self.store._db.execute("UPDATE witness SET response=?", (b"{}",))
        with self.assertRaises(witness.WitnessRefused):
            self.store.inspect_retained()
        self.refused_without_callbacks_after_corruption(self.packets["completed"])

    def refused_without_callbacks_after_corruption(self, packet):
        calls = []
        with patch.object(self.store, "_verifier", side_effect=lambda p: calls.append(p)):
            with self.assertRaises(witness.WitnessRefused):
                self.store.retain(*packet)
        self.assertEqual(calls, [])
        self.assertEqual(self.store._db.execute("SELECT version FROM witness").fetchone(), (1,))

    def test_schema_settings_and_complete_persisted_binding_changes_refuse(self):
        self.seed()
        for pragma, wrong, restored in (("synchronous", "OFF", "EXTRA"), ("trusted_schema", "ON", "OFF")):
            self.store._db.execute("PRAGMA "+pragma+"="+wrong)
            with self.assertRaises(witness.WitnessRefused):
                self.store.inspect_retained()
            self.store._db.execute("PRAGMA "+pragma+"="+restored)
        self.store._db.execute("CREATE TABLE extra(value INTEGER)")
        with self.assertRaises(witness.WitnessRefused):
            self.store.inspect_retained()
        self.store._db.execute("DROP TABLE extra")
        self.store._db.execute("UPDATE binding SET original=?", (b"x"*len(self.store._binding[1]),))
        with self.assertRaises(witness.WitnessRefused):
            self.store.inspect_retained()

    def test_closed_foreign_thread_and_inherited_process_handles_refuse(self):
        self.seed()
        errors = []
        def foreign():
            try:
                self.store.inspect_retained()
            except witness.WitnessRefused:
                errors.append("refused")
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ["refused"])
        with patch.object(witness.os, "getpid", return_value=self.store._pid+1):
            with self.assertRaises(witness.WitnessRefused):
                self.store.retain(*self.packets["completed"])
        self.store.close()
        with self.assertRaises(witness.WitnessRefused):
            self.store.inspect_retained()

    def test_reentrant_verifier_cannot_close_inspect_or_replace_owned_witness(self):
        self.seed()
        commands = [self.store.close, self.store.inspect_retained,
            lambda: self.store.retain(*self.packets["revoked_pending"])]
        refused = []
        def check(packet):
            for command in commands:
                with self.assertRaises(witness.WitnessRefused):
                    command()
                refused.append(True)
            return self.check(packet)
        with patch.object(self.store, "_verifier", side_effect=check):
            result = self.retain("completed")
        self.assertEqual(len(refused), 6)
        self.assertEqual(result.observation, "completed")

    def test_native_writer_lock_covers_load_verification_write_and_commit(self):
        self.seed()
        peer = sqlite3.connect(str(self.path), timeout=0, isolation_level=None)
        self.addCleanup(peer.close)
        cuts = []
        def locked():
            with self.assertRaises(sqlite3.OperationalError):
                peer.execute("BEGIN IMMEDIATE")
            self.assertFalse(peer.in_transaction)
        def cut(label):
            if label in ("retain-locked", "retain-loaded", "retain-compared", "retain-written", "retain-before-commit"):
                locked()
                cuts.append(label)
        def check(packet):
            locked()
            return self.check(packet)
        with patch.object(self.store, "_cut", side_effect=cut), patch.object(self.store, "_verifier", side_effect=check):
            self.retain("completed")
        self.assertEqual(len(cuts), 5)
        peer.execute("BEGIN IMMEDIATE")
        peer.execute("ROLLBACK")

    def test_each_precommit_fault_returns_unknown_closes_handle_and_preserves_old_witness(self):
        self.seed()
        for point in ("retain-locked", "retain-loaded", "retain-compared", "retain-written", "retain-before-commit"):
            def fault(label):
                if label == point:
                    raise RuntimeError("synthetic private detail must not escape")
            with self.open() as store:
                with patch.object(store, "_cut", side_effect=fault):
                    with self.assertRaisesRegex(witness.WitnessOutcomeUnknown, "^synthetic witness command has no conclusive result$"):
                        self.retain("completed", store)
                self.assertTrue(store._closed)
            self.assertEqual(self.store.inspect_retained().version, 1)

    def test_lost_postcommit_result_is_unknown_despite_persisted_completed_witness(self):
        self.seed()
        def fault(label):
            if label == "retain-after-commit":
                raise RuntimeError("synthetic lost return")
        with self.open() as store:
            with patch.object(store, "_cut", side_effect=fault):
                with self.assertRaises(witness.WitnessOutcomeUnknown):
                    self.retain("completed", store)
            self.assertTrue(store._closed)
        result = self.store.inspect_retained()
        self.assertEqual((result.version, result.observation), (2, "completed"))
        self.refused_without_callbacks(self.packets["pending"])

    def test_refusal_after_commit_is_unknown_and_failed_rollback_disposes_handle(self):
        self.seed()
        def refuse(label):
            if label == "retain-after-commit":
                raise witness.WitnessRefused("synthetic late refusal")
        with self.open() as store, patch.object(store, "_cut", side_effect=refuse):
            with self.assertRaises(witness.WitnessOutcomeUnknown):
                self.retain("completed", store)
            self.assertTrue(store._closed)
        self.assertEqual(self.store.inspect_retained().observation, "completed")
        with self.open() as store, patch.object(store, "_rollback", return_value=False):
            with self.assertRaises(witness.WitnessOutcomeUnknown):
                self.retain("pending", store)
            self.assertTrue(store._closed)

    def test_real_sqlite_write_failure_has_no_positive_result_or_automatic_retry(self):
        self.seed()
        with self.open() as store:
            store._db.execute("PRAGMA query_only=ON")
            with self.assertRaises(witness.WitnessOutcomeUnknown):
                self.retain("completed", store)
            self.assertTrue(store._closed)
        self.assertEqual(self.store.inspect_retained().version, 1)

    def test_process_death_at_each_precommit_cut_keeps_pending_and_after_commit_keeps_completed(self):
        self.seed()
        for point in ("retain-locked", "retain-loaded", "retain-compared", "retain-written", "retain-before-commit", "retain-after-commit"):
            process = self.actor("completed", point)
            self.assertEqual(self.line(process), "paused")
            process.kill()
            output, errors = process.communicate(timeout=10)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual((output, errors), ("", ""))
            retained = self.store.inspect_retained()
            expected = (2, "completed") if point.endswith("after-commit") else (1, "pending")
            self.assertEqual((retained.version, retained.observation), expected)

    def test_process_writer_blocks_competitor_then_other_fork_refuses_after_release(self):
        self.seed()
        process = self.actor("completed", "retain-loaded")
        self.assertEqual(self.line(process), "paused")
        # Use the already-open owner; BEGIN IMMEDIATE cannot acquire the
        # writer domain while the child holds it from its persisted read.
        with self.assertRaises(witness.WitnessOutcomeUnknown):
            self.retain("revoked_pending")
        self.assertTrue(self.store._closed)
        process.stdin.write("release\n")
        process.stdin.flush()
        output, errors = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(json.loads(output), dict(version=2, observation="completed"))
        self.assertEqual(errors, "")
        self.store = self.open()
        self.refused_without_callbacks(self.packets["revoked_pending"])

    def test_preopened_process_never_overwrites_newer_completed_witness_from_stale_read(self):
        self.seed()
        process = subprocess.Popen([sys.executable, "-B", "tests/original_witness_store_actor.py",
            str(self.path), "unused", self.actor_mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        def clean():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        self.addCleanup(clean)
        process.stdin.write(json.dumps(self.actor_context)+"\n")
        process.stdin.flush()
        self.assertEqual(self.line(process), "ready")
        self.retain("completed")
        process.stdin.write("revoked_pending\n")
        process.stdin.flush()
        output, errors = process.communicate(timeout=15)
        self.assertEqual((process.returncode, output.strip(), errors), (20, "WitnessRefused", ""))
        self.assertEqual(self.store.inspect_retained().observation, "completed")

    def test_restored_consumer_copy_erases_completed_knowledge_and_accepts_other_future(self):
        self.seed()
        self.store.close()
        backup = self.path.with_name("saved.sqlite3")
        shutil.copyfile(self.path, backup)
        self.store = self.open()
        completed = self.retain("completed")
        self.refused_without_callbacks(self.packets["revoked_pending"])
        self.store.close()
        shutil.copyfile(backup, self.path)
        self.store = self.open()
        self.assertEqual(self.store.inspect_retained().observation, "pending")
        restored = self.retain("revoked_pending")
        self.assertEqual(restored.version, completed.version)
        self.assertNotEqual(restored.query_digest_hex, completed.query_digest_hex)

    def test_source_and_consumer_restore_repeat_external_synthetic_effect_without_reconciliation(self):
        self.seed()
        self.store.close()
        consumer_backup = self.path.with_name("saved-consumer.sqlite3")
        shutil.copyfile(self.path, consumer_backup)
        self.store = self.open()
        with scenario("pending") as actual:
            actual.store.close()
            source_backup = actual.path.with_name("saved-source.sqlite3")
            shutil.copyfile(actual.path, source_backup)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            external_effects = [actual.store.apply_synthetic_effect(actual.original).effect_sequence]
            self.retain("completed")
            actual.store.close()
            shutil.copyfile(source_backup, actual.path)
            actual.store = local.OfflinePolicyEffectStore(str(actual.path), actual.labels)
            self.refused_without_callbacks(self.packets["pending"])
            self.store.close()
            shutil.copyfile(consumer_backup, self.path)
            self.store = self.open()
            self.retain("pending")
            external_effects.append(actual.store.apply_synthetic_effect(actual.original).effect_sequence)
            self.retain("completed")
            self.assertEqual(external_effects, [2, 2])
            self.assertEqual((actual.store.local_view().charged_operations, actual.store.local_view().synthetic_effects), (1, 1))
            self.assertEqual(self.store.inspect_retained().observation, "completed")

    def test_forged_callback_can_store_zero_signatures_without_authentication(self):
        query, opened, packet = self.packets["pending"]
        value = json.loads(packet)
        value["response_signature_hex"] = "00"*64
        value["root_envelope"]["root_signature_hex"] = "00"*64
        with self.open(self.path.with_name("forged-control.sqlite3"), check=callback_control) as store:
            result = store.retain(query, opened, canonical(value))
            self.assertEqual(store.inspect_retained(), result)
            self.assertEqual(result.observation, "pending")

    def test_open_with_other_independent_binding_and_symlink_refuses_without_migration(self):
        self.seed()
        self.store.close()
        with self.assertRaises(witness.WitnessRefused):
            self.open(binding=self.packets["replaced_completed"][0])
        alias = self.path.with_name("alias.sqlite3")
        alias.symlink_to(self.path)
        with self.assertRaises(witness.WitnessRefused):
            self.open(alias)

    def test_original_helpers_worker_and_fixtures_stay_pinned_and_test_store_is_unwired(self):
        pins = {
            "tests/original_snapshot_opening.py": "e1e8cdd3f868bce2117c56f1eb2eab90bef8626b7687793b62214f0884805ff6",
            "tests/original_snapshot_prefix.py": "20b7e00c5aef3ec28184d385d7e10098f289a6e476373ab93527deaa7664a622",
            "qualification/examples/verify_original_read_response.rs": "e96a8219e500cd0f79716796c146f64ce22e5f95bd3af26ccd2ad8a208c4834e",
            "qualification/policy_effect_store.py": "9d5236d7bbc7ae1211b272f495026ae5b7f5825d02149cde0aaad6e062d97623",
            str(INPUT): "0f0bdf4d916c5371f35eb7c2afee03dbcdef4a319999c01955f4b052d9d8fd01",
            str(OUTPUT): "2d461a54413ef156df62db26c88ac6f789ed8ea27322f3b8b12800b74f8de1bb",
        }
        for name, pin in pins.items():
            self.assertEqual(hashlib.sha256(Path(name).read_bytes()).hexdigest(), pin)
        tree = ast.parse(Path("tests/original_witness_store.py").read_text("ascii"))
        imported = {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertEqual(imported, {"contextlib", "dataclasses", "pathlib", "offline_session", "qualification"})
        self.assertFalse(any(isinstance(n, (ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith)) for n in ast.walk(tree)))
