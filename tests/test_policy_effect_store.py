"""Real local SQLite ordering, synthetic effects and explicit unsafe boundaries."""

import ast
from contextlib import closing
from dataclasses import FrozenInstanceError, asdict, replace
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from qualification import policy_effect_store as source
import policy_effect_native_observation as native_observation


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


PROFILE = json.loads(Path("qualification/fixtures/governor_contract.json").read_text("ascii"))["assignment"]["governor_profile"]
WIRE = canonical(PROFILE)
LABELS = source.SourceLabels("ab"*32, "cd"*32, PROFILE["authority_id_hex"], PROFILE["resource_digest_hex"])


def allocation_reply(status, output, error):
    """Classify the original actor's fixed allocation replies without echoing bytes."""
    response = "unrecognized"
    if type(output) is bytes and len(output) <= 4096:
        lines = output.split(b"\n")
        if len(lines) == 3 and lines[-1] == b"":
            native = native_observation.decode(lines[1])
            reply = allocation_reply(status, lines[0] + b"\n", error)
            if native is not None and reply["response_class"] in ("allocation-record", "StoreRefused", "StoreOutcomeUnknown"):
                return dict(reply, native_execute_errors=native["errors"], native_error_overflow=native["overflow"])
        if output == b"":
            response = "empty"
        elif output in (b"StoreRefused\n", b"StoreOutcomeUnknown\n"):
            response = output[:-1].decode("ascii")
        else:
            try:
                row = json.loads(output.decode("ascii"))
                if (type(row) is dict and set(row) == {"charge_sequence", "effect_sequence"}
                        and type(row["charge_sequence"]) is int
                        and 1 <= row["charge_sequence"] <= source.MAX_EVENTS
                        and row["effect_sequence"] is None
                        and output == (json.dumps(row) + "\n").encode("ascii")):
                    response = "allocation-record"
            except (UnicodeError, ValueError, TypeError, RecursionError):
                pass
    return dict(exit_code=status if type(status) is int and -128 <= status <= 255 else "unavailable",
                response_class=response, stderr_present=type(error) is not bytes or bool(error))


def allocation_state(store, requests):
    """Read the complete originals and rows; failed readback never means zero."""
    try:
        raw_operations = store._db.execute("SELECT count(*) FROM operations").fetchone()[0]
        raw_effects = store._db.execute("SELECT count(*) FROM effects").fetchone()[0]
        view = store.local_view()
        originals = [store.lookup_original(request) for request in requests]
        return dict(readback="available", raw_operations=raw_operations, raw_effects=raw_effects,
                    retained_originals=[original is not None for original in originals],
                    charge_sequences=[None if original is None else original.charge_sequence for original in originals],
                    effect_sequences=[None if original is None else original.effect_sequence for original in originals],
                    charged_operations=view.charged_operations, synthetic_effects=view.synthetic_effects,
                    event_sequence=view.event_sequence)
    except Exception:
        return dict(readback="unavailable")


def allocation_evidence(replies, store, requests, reopen):
    """Sanitized test evidence only, never a result, permission or retry decision."""
    local = allocation_state(store, requests)
    try:
        with reopen() as reopened:
            after = allocation_state(reopened, requests)
    except Exception:
        after = dict(readback="unavailable")
    classified = [allocation_reply(status, output, error) for status, output, error in replies]
    emitted = sum("native_execute_errors" in row for row in classified)
    detail = ("bounded-original-execute-report" if emitted == len(classified) and emitted
              else "incomplete-original-execute-report" if emitted else "not-emitted-by-original-actor")
    return dict(schema="synthetic-distinct-allocation-v1", replies=classified,
                native_error_details=detail, local=local, reopened=after)


class PolicyEffectStoreCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-policy-effects-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/"source.sqlite3"
        self.store = source.OfflinePolicyEffectStore(str(self.path), LABELS, initial_profile=WIRE)
        self.addCleanup(self.dispose)

    def dispose(self):
        if not self.store._closed:
            self.store.close()

    def open(self, path=None, labels=LABELS):
        return source.OfflinePolicyEffectStore(str(path or self.path), labels)

    def request(self, operation="01", *, revision=0, wire=WIRE, proposal="02"):
        return source.OriginalRequest(operation*32, revision, wire, proposal*32)

    def wire(self, **overrides):
        return canonical(dict(PROFILE, **overrides))


class PolicyEffectStoreTests(PolicyEffectStoreCase):
    def test_complete_fourteen_field_policy_source_labels_and_native_modes(self):
        view = self.store.local_view()
        self.assertEqual(len(json.loads(view.profile_wire)), 14)
        self.assertEqual((view.revision, view.active, view.mode, view.charged_operations,
            view.synthetic_effects, view.event_sequence), (0, True, "live", 0, 0, 0))
        self.assertEqual(self.store._db.execute("PRAGMA journal_mode").fetchone(), ("delete",))
        self.assertEqual(self.store._db.execute("PRAGMA synchronous").fetchone(), (3,))
        self.assertEqual(self.store._db.execute("PRAGMA foreign_keys").fetchone(), (1,))

    def test_allocation_and_synthetic_effect_are_distinct_persisted_transactions(self):
        request = self.request()
        original = self.store.allocate_synthetic(request)
        self.assertEqual((original.charge_sequence, original.effect_sequence), (1, None))
        self.assertEqual(self.store.local_view().synthetic_effects, 0)
        applied = self.store.apply_synthetic_effect(request)
        self.assertEqual((applied.charge_sequence, applied.effect_sequence), (1, 2))
        self.assertEqual(self.store._db.execute("SELECT payload FROM effects").fetchall(), [("synthetic-effect",)])
        self.store.close()
        with self.open() as reopened:
            self.assertEqual(reopened.lookup_original(request), applied)

    def test_exact_original_replay_has_one_charge_and_effect_even_after_revocation(self):
        request = self.request()
        self.store.allocate_synthetic(request)
        applied = self.store.apply_synthetic_effect(request)
        self.store.replace_local_policy(0, WIRE, active=False)
        self.assertEqual(self.store.allocate_synthetic(request), applied)
        self.assertEqual(self.store.apply_synthetic_effect(request), applied)
        self.assertEqual(self.store.lookup_original(request), applied)
        view = self.store.local_view()
        self.assertEqual((view.charged_operations, view.synthetic_effects), (1, 1))

    def test_revocation_before_new_allocation_refuses_without_any_charge(self):
        self.store.replace_local_policy(0, WIRE, active=False)
        before = self.store.local_view()
        with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(self.request())
        self.assertEqual(self.store.local_view(), before)

    def test_revocation_between_charge_and_effect_refuses_without_refund(self):
        request = self.request()
        original = self.store.allocate_synthetic(request)
        self.store.replace_local_policy(0, WIRE, active=False)
        with self.assertRaises(source.StoreRefused): self.store.apply_synthetic_effect(request)
        self.assertEqual(self.store.lookup_original(request), original)
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (1, 0))

    def test_complete_profile_change_and_owner_rotation_refuse_old_pending_effect(self):
        changes = dict(owner_auth_key_hex="ee"*32, authority_epoch=2,
            authority_profile_digest_hex="77"*32, verifier_profile_digest_hex="88"*32,
            pool_profile_digest_hex="99"*32, resource_profile_digest_hex="aa"*32,
            max_attempt_limit=1, max_target_limit=1)
        for field, value in changes.items():
            with self.subTest(field=field):
                alternate = self.path.with_name(field+".sqlite3")
                with source.OfflinePolicyEffectStore(str(alternate), LABELS, initial_profile=WIRE) as store:
                    request = self.request()
                    store.allocate_synthetic(request)
                    store.replace_local_policy(0, self.wire(**{field:value}), active=True)
                    with self.assertRaises(source.StoreRefused): store.apply_synthetic_effect(request)
                    self.assertEqual(store.local_view().charged_operations, 1)

    def test_equal_profile_reissued_at_new_revision_does_not_refresh_old_request(self):
        request = self.request()
        self.store.allocate_synthetic(request)
        self.store.replace_local_policy(0, WIRE, active=True)
        with self.assertRaises(source.StoreRefused): self.store.apply_synthetic_effect(request)
        with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(self.request("03"))
        fresh = self.request("03", revision=1)
        self.store.allocate_synthetic(fresh)
        self.assertIsNotNone(self.store.apply_synthetic_effect(fresh).effect_sequence)

    def test_retained_charges_survive_cap_drop_below_consumed_and_owner_rotation(self):
        self.store.allocate_synthetic(self.request())
        self.store.allocate_synthetic(self.request("03"))
        wire = self.wire(max_attempt_limit=1, owner_auth_key_hex="ee"*32)
        self.store.replace_local_policy(0, wire, active=True)
        with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(self.request("04", revision=1, wire=wire))
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (2, 0))

    def test_original_operation_cannot_rebind_revision_profile_or_proposal(self):
        original = self.request()
        self.store.allocate_synthetic(original)
        for request in (replace(original, expected_revision=1),
            replace(original, profile_wire=self.wire(max_target_limit=1)),
            replace(original, proposal_digest_hex="04"*32)):
            for command in (self.store.lookup_original, self.store.allocate_synthetic, self.store.apply_synthetic_effect):
                with self.assertRaises(source.StoreRefused): command(request)
        self.assertEqual(self.store.local_view().event_sequence, 1)

    def test_different_operation_ids_can_charge_and_apply_same_proposal_twice(self):
        for request in (self.request(), self.request("03")):
            self.store.allocate_synthetic(request); self.store.apply_synthetic_effect(request)
        view = self.store.local_view()
        self.assertEqual((view.charged_operations, view.synthetic_effects), (2, 2))

    def test_synthetic_effect_without_its_charge_refuses(self):
        with self.assertRaises(source.StoreRefused): self.store.apply_synthetic_effect(self.request())
        self.assertEqual(self.store.local_view().event_sequence, 0)

    def test_unavailable_ambiguous_or_detected_compromise_refuses_new_effect_and_lookup(self):
        request = self.request()
        self.store.allocate_synthetic(request)
        for mode in source.MODES[1:]:
            self.store.set_local_source_mode(mode)
            for command in (self.store.allocate_synthetic, self.store.apply_synthetic_effect, self.store.lookup_original):
                with self.assertRaises(source.StoreRefused): command(request)
            self.assertEqual(self.store.local_view().charged_operations, 1)
            self.store.set_local_source_mode("live")
        self.store.apply_synthetic_effect(request)
        self.assertEqual(self.store.local_view().synthetic_effects, 1)

    def test_lost_allocation_reply_reconciles_original_record_without_another_charge(self):
        request = self.request()
        def lose(label):
            if label == "allocation-after-commit": raise RuntimeError("synthetic lost reply")
        with patch.object(self.store, "_cut", side_effect=lose):
            with self.assertRaises(source.StoreOutcomeUnknown): self.store.allocate_synthetic(request)
        self.assertIsNotNone(self.store.lookup_original(request))
        self.store.allocate_synthetic(request)
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_lost_effect_reply_finds_original_result_and_never_duplicates_effect(self):
        request = self.request(); self.store.allocate_synthetic(request)
        def lose(label):
            if label == "effect-after-commit": raise RuntimeError("synthetic lost reply")
        with patch.object(self.store, "_cut", side_effect=lose):
            with self.assertRaises(source.StoreOutcomeUnknown): self.store.apply_synthetic_effect(request)
        applied = self.store.lookup_original(request)
        self.assertIsNotNone(applied.effect_sequence)
        self.assertEqual(self.store.apply_synthetic_effect(request), applied)
        self.assertEqual(self.store.local_view().synthetic_effects, 1)

    def test_exception_before_commit_rolls_back_rows_and_keeps_original_charge(self):
        request = self.request(); self.store.allocate_synthetic(request)
        for point in ("effect-written", "effect-before-commit"):
            def fail(label):
                if label == point: raise RuntimeError("synthetic write fault")
            with patch.object(self.store, "_cut", side_effect=fail):
                with self.assertRaises(source.StoreOutcomeUnknown): self.store.apply_synthetic_effect(request)
            self.assertIsNone(self.store.lookup_original(request).effect_sequence)
            self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_refusal_after_commit_is_unknown_and_not_an_absent_allocation(self):
        request = self.request()
        def refuse(label):
            if label == "allocation-after-commit": raise source.StoreRefused("synthetic late refusal")
        with patch.object(self.store, "_cut", side_effect=refuse):
            with self.assertRaises(source.StoreOutcomeUnknown): self.store.allocate_synthetic(request)
        self.assertIsNotNone(self.store.lookup_original(request))
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_inconclusive_rollback_closes_handle_before_another_source_command(self):
        def fail(label):
            if label == "allocation-written": raise RuntimeError("synthetic transaction fault")
        with patch.object(self.store, "_cut", side_effect=fail), patch.object(self.store, "_rollback", return_value=False):
            with self.assertRaises(source.StoreOutcomeUnknown): self.store.allocate_synthetic(self.request())
        self.assertTrue(self.store._closed)
        with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(self.request())
        with self.open() as reopened:
            self.assertIsNone(reopened.lookup_original(self.request()))

    def test_busy_native_writer_is_unknown_and_does_not_allocate_or_refund(self):
        with self.open() as second:
            self.store._db.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaises(source.StoreOutcomeUnknown): second.allocate_synthetic(self.request())
            finally:
                self.store._db.execute("ROLLBACK")
            self.assertIsNone(second.lookup_original(self.request()))
            second.allocate_synthetic(self.request())
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_compare_and_set_policy_update_refuses_stale_admin_selection(self):
        self.assertEqual(self.store.replace_local_policy(0, WIRE, active=False), 1)
        with self.assertRaises(source.StoreRefused): self.store.replace_local_policy(0, WIRE, active=True)
        self.assertFalse(self.store.local_view().active)

    def test_native_settings_downgrade_refuses_before_any_new_charge(self):
        for pragma in ("synchronous=OFF", "foreign_keys=OFF"):
            self.store._db.execute("PRAGMA "+pragma)
            with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(self.request())
            self.store._db.execute("PRAGMA synchronous=EXTRA")
            self.store._db.execute("PRAGMA foreign_keys=ON")
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_incomplete_event_or_synthetic_effect_history_refuses_without_repair(self):
        request = self.request(); self.store.allocate_synthetic(request); self.store.apply_synthetic_effect(request)
        self.store._db.execute("DELETE FROM effects")
        with self.assertRaises(source.StoreRefused): self.store.local_view()
        self.assertEqual(self.store._db.execute("SELECT count(*) FROM effects").fetchone(), (0,))

    def test_changed_source_incarnation_resource_or_authority_refuses_open(self):
        for field in source.SourceLabels.__dataclass_fields__:
            with self.assertRaises(source.StoreRefused): self.open(labels=replace(LABELS, **{field:"dd"*32}))
        self.assertEqual(self.store.local_view().event_sequence, 0)

    def test_new_profile_cannot_reset_retained_resource_or_authority_namespace(self):
        for field in ("resource_digest_hex", "authority_id_hex"):
            with self.assertRaises(source.StoreRefused): self.store.replace_local_policy(0, self.wire(**{field:"dd"*32}), active=True)
        self.assertEqual(self.store.local_view().revision, 0)

    def test_create_never_clobbers_existing_database_and_open_does_not_create_missing(self):
        before = self.path.read_bytes()
        with self.assertRaises(source.StoreOutcomeUnknown):
            source.OfflinePolicyEffectStore(str(self.path), LABELS, initial_profile=WIRE)
        self.assertEqual(self.path.read_bytes(), before)
        missing = self.path.with_name("missing.sqlite3")
        with self.assertRaises(source.StoreOutcomeUnknown): self.open(missing)
        self.assertFalse(missing.exists())

    def test_symlink_and_foreign_schema_refuse_without_migration(self):
        alias = self.path.with_name("alias.sqlite3"); alias.symlink_to(self.path)
        with self.assertRaises(source.StoreRefused): self.open(alias)
        foreign = self.path.with_name("foreign.sqlite3")
        with closing(sqlite3.connect(str(foreign))) as db:
            db.execute("CREATE TABLE foreign_data (value TEXT)")
            db.execute("INSERT INTO foreign_data VALUES ('synthetic')")
            db.commit()
        before = foreign.read_bytes()
        with self.assertRaises(source.StoreRefused): self.open(foreign)
        self.assertEqual(foreign.read_bytes(), before)

    def test_wal_database_refuses_the_selected_rollback_journal_construction(self):
        self.store.close()
        with closing(sqlite3.connect(str(self.path))) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone(), ("wal",))
        with self.assertRaises(source.StoreRefused): self.open()

    def test_coherent_client_reopen_preserves_original_source_charge_and_effect(self):
        request = self.request(); self.store.allocate_synthetic(request); original = self.store.apply_synthetic_effect(request)
        self.store.close()
        with self.open() as reopened:
            self.assertEqual(reopened.allocate_synthetic(request), original)
            self.assertEqual(reopened.apply_synthetic_effect(request), original)
            self.assertEqual((reopened.local_view().charged_operations, reopened.local_view().synthetic_effects), (1, 1))

    def test_coherent_source_restore_repeats_effect_with_same_labels_and_current_policy(self):
        request = self.request()
        self.store.close()
        saved = self.path.with_name("old.sqlite3"); shutil.copyfile(self.path, saved)
        with self.open() as first:
            first.allocate_synthetic(request); first.apply_synthetic_effect(request)
            self.assertEqual(first.local_view().synthetic_effects, 1)
        shutil.copyfile(saved, self.path)
        with self.open() as restored:
            self.assertIsNone(restored.lookup_original(request))
            restored.allocate_synthetic(request); restored.apply_synthetic_effect(request)
            self.assertEqual(restored.local_view().synthetic_effects, 1)
        # Two actual database histories accepted the same scoped operation.

    def test_coherent_database_clones_have_independent_caps_under_same_labels(self):
        self.store.close()
        clone = self.path.with_name("clone.sqlite3"); shutil.copyfile(self.path, clone)
        request = self.request()
        with self.open() as first, self.open(clone) as second:
            for store in (first, second):
                store.allocate_synthetic(request); store.apply_synthetic_effect(request)
            self.assertEqual((first.local_view().synthetic_effects, second.local_view().synthetic_effects), (1, 1))

    def test_format_valid_zero_owner_and_local_admin_do_not_establish_authentication(self):
        wire = self.wire(owner_auth_key_hex="00"*32)
        self.store.replace_local_policy(0, wire, active=True)
        request = self.request(revision=1, wire=wire)
        self.store.allocate_synthetic(request); self.store.apply_synthetic_effect(request)
        self.assertEqual(self.store.local_view().synthetic_effects, 1)

    def test_numeric_aliases_foreign_hooks_and_inexact_profile_or_request_types_refuse_before_sql(self):
        class Hostile:
            def __getattribute__(self, name): raise AssertionError("untrusted hook ran")
            def __eq__(self, other): raise AssertionError("untrusted hook ran")
        for request in (None, {}, Hostile(), self.request(revision=True), self.request(revision=1.0),
            replace(self.request(), operation_id_hex=Hostile()), replace(self.request(), profile_wire=Hostile()),
            replace(self.request(), proposal_digest_hex="AA"*32), replace(self.request(), profile_wire=WIRE+b"\n")):
            with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(request)
        for revision in (False, -1, 33, 1.0):
            with self.assertRaises(source.StoreRefused): self.store.replace_local_policy(revision, WIRE, active=True)
        with self.assertRaises(source.StoreRefused): self.store.replace_local_policy(0, WIRE, active=1)
        self.assertEqual(self.store.local_view().event_sequence, 0)

    def test_profile_numeric_aliases_and_extra_permissions_refuse_before_open(self):
        for wire in (self.wire(max_attempt_limit=True), self.wire(authorized=True), WIRE+b" "):
            missing = self.path.with_name("bad.sqlite3")
            with patch.object(source.sqlite3, "connect") as connect:
                with self.assertRaises(source.StoreRefused): source.OfflinePolicyEffectStore(str(missing), LABELS, initial_profile=wire)
                connect.assert_not_called()
            self.assertFalse(missing.exists())

    def test_policy_and_event_bounds_do_not_reset_consumed_records(self):
        for revision in range(source.MAX_REVISION): self.store.replace_local_policy(revision, WIRE, active=True)
        with self.assertRaises(source.StoreRefused): self.store.replace_local_policy(source.MAX_REVISION, WIRE, active=True)
        self.assertEqual(self.store.local_view().revision, source.MAX_REVISION)
        self.store.allocate_synthetic(self.request(revision=source.MAX_REVISION))
        while self.store.local_view().event_sequence < source.MAX_EVENTS:
            mode = "unavailable" if self.store.local_view().mode == "live" else "live"
            self.store.set_local_source_mode(mode)
        with self.assertRaises(source.StoreRefused): self.store.set_local_source_mode("live" if self.store.local_view().mode != "live" else "unavailable")
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_foreign_thread_close_and_recursive_access_refuse_without_releasing_owner(self):
        failures = []
        def attempt():
            for command in (self.store.close, self.store.local_view):
                try: command()
                except source.StoreRefused: failures.append(True)
        thread = threading.Thread(target=attempt); thread.start(); thread.join(timeout=5)
        self.assertFalse(thread.is_alive()); self.assertEqual(failures, [True, True])
        def recurse(label):
            if label == "allocation-written":
                with self.assertRaises(source.StoreRefused): self.store.local_view()
        with patch.object(self.store, "_cut", side_effect=recurse): self.store.allocate_synthetic(self.request())
        self.assertFalse(self.store._closed)

    def test_closed_store_and_immutable_diagnostics_supply_no_capabilities(self):
        request = self.request(); record = self.store.allocate_synthetic(request); view = self.store.local_view()
        for value in (LABELS, request, record, view):
            for field in ("authorized", "authenticated", "permit", "can_start", "signature_hex"):
                self.assertFalse(hasattr(value, field))
        with self.assertRaises(FrozenInstanceError): record.effect_sequence = 99
        self.store.close()
        with self.assertRaises(source.StoreRefused): self.store.allocate_synthetic(request)

    def test_runtime_report_and_imports_include_no_runner_signer_network_or_crypto_arithmetic(self):
        report = source.runtime_report()
        self.assertEqual((report["journal_mode"], report["synchronous"], report["authentication"], report["physical_entry"]), ("delete", 3, False, False))
        tree = ast.parse(Path("qualification/policy_effect_store.py").read_text("ascii"))
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules.update(a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names)
        self.assertEqual(modules, {"contextlib", "dataclasses", "json", "os", "pathlib", "re", "sqlite3", "tempfile", "threading", "offline_session"})


@unittest.skipUnless(os.name == "posix", "native crash qualification requires POSIX signals")
class PolicyEffectStoreNativeTests(PolicyEffectStoreCase):
    def context(self, request=None, **extra):
        request = request or self.request()
        return dict(labels=asdict(LABELS), operation=request.operation_id_hex,
            revision=request.expected_revision, profile_hex=request.profile_wire.hex(),
            proposal=request.proposal_digest_hex, **extra)

    def actor(self, command, point="none", *, request=None, ready=False, observed=False, **extra):
        actor = Path(__file__).with_name("policy_effect_store_actor.py")
        arguments = [sys.executable, "-B", str(actor), str(self.path), command, point, "ready" if ready else "cut"]
        if observed:
            arguments.append("native-execute-errors-v1")
        child = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None: child.kill()
            child.communicate(timeout=10)
        self.addCleanup(cleanup)
        child.stdin.write((json.dumps(self.context(request, **extra))+"\n").encode("ascii")); child.stdin.flush()
        with selectors.DefaultSelector() as select:
            select.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(select.select(timeout=10), "synthetic actor did not reach its bounded cut")
        self.assertEqual(child.stdout.readline().strip(), b"ready" if ready else b"paused")
        return child

    def kill(self, child):
        child.kill(); output, error = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output, error), (-signal.SIGKILL, b"", b""))

    def test_sigkill_at_allocation_write_and_before_commit_leaves_no_charge(self):
        for point in ("allocation-written", "allocation-before-commit"):
            self.kill(self.actor("allocation", point))
            self.assertIsNone(self.store.lookup_original(self.request()))
            self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_sigkill_after_allocation_commit_keeps_original_charge_with_lost_reply(self):
        self.kill(self.actor("allocation", "allocation-after-commit"))
        self.assertEqual(self.store.allocate_synthetic(self.request()).charge_sequence, 1)
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_sigkill_at_effect_write_and_before_commit_keeps_charge_without_effect(self):
        self.store.allocate_synthetic(self.request())
        for point in ("effect-written", "effect-before-commit"):
            self.kill(self.actor("effect", point))
            self.assertIsNone(self.store.lookup_original(self.request()).effect_sequence)
            self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_sigkill_after_effect_commit_keeps_exact_original_effect_with_lost_reply(self):
        self.store.allocate_synthetic(self.request())
        self.kill(self.actor("effect", "effect-after-commit"))
        original = self.store.lookup_original(self.request())
        self.assertEqual(self.store.apply_synthetic_effect(self.request()), original)
        self.assertEqual(self.store.local_view().synthetic_effects, 1)

    def test_sigkill_before_policy_commit_preserves_old_policy_and_charge_lineage(self):
        self.store.allocate_synthetic(self.request())
        self.kill(self.actor("policy", "policy-written", replacement_hex=self.wire(max_attempt_limit=1).hex(), active=False))
        self.assertEqual((self.store.local_view().revision, self.store.local_view().active), (0, True))
        self.assertIsNotNone(self.store.apply_synthetic_effect(self.request()).effect_sequence)

    def test_sigkill_after_policy_commit_refuses_old_pending_effect_without_refund(self):
        self.store.allocate_synthetic(self.request())
        self.kill(self.actor("policy", "policy-after-commit", replacement_hex=WIRE.hex(), active=False))
        with self.assertRaises(source.StoreRefused): self.store.apply_synthetic_effect(self.request())
        self.assertEqual((self.store.local_view().revision, self.store.local_view().charged_operations), (1, 1))

    def test_native_same_operation_callers_reconcile_one_charge_then_one_effect(self):
        for command in ("allocation", "effect"):
            children = [self.actor(command, ready=True) for _ in range(2)]
            for child in children: child.stdin.write(b"go\n"); child.stdin.flush()
            results = []
            for child in children:
                out, err = child.communicate(timeout=10)
                self.assertEqual(err, b""); self.assertIn(child.returncode, (0, 20)); results.append(out.decode("ascii").strip())
            self.assertTrue(any(result.startswith("{") for result in results))
            if command == "allocation": self.store.allocate_synthetic(self.request())
            else: self.store.apply_synthetic_effect(self.request())
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (1, 1))

    def test_native_distinct_original_requests_cannot_exceed_one_retained_allocation(self):
        wire = self.wire(max_attempt_limit=1)
        self.store.replace_local_policy(0, wire, active=True)
        requests = (self.request(revision=1, wire=wire), self.request("03", revision=1, wire=wire))
        children = [self.actor("allocation", request=request, ready=True, observed=True) for request in requests]
        for child in children: child.stdin.write(b"go\n"); child.stdin.flush()
        replies = []
        for child in children:
            output, error = child.communicate(timeout=10)
            replies.append((child.returncode, output, error))
        report = allocation_evidence(replies, self.store, requests, self.open)
        evidence = "synthetic-distinct-allocation: " + canonical(report).decode("ascii")
        statuses = [status for status, _, _ in replies]
        for reply in report["replies"]:
            self.assertFalse(reply["stderr_present"], evidence)
        self.assertEqual(sorted(statuses), [0, 20], evidence)
        self.assertEqual(report["local"]["readback"], "available", evidence)
        self.assertEqual(report["reopened"]["readback"], "available", evidence)
        self.assertEqual(report["local"], report["reopened"], evidence)
        retained = [self.store.lookup_original(request) for request in requests]
        self.assertEqual(sum(record is not None for record in retained), 1, evidence)
        self.assertEqual(self.store.local_view().charged_operations, 1, evidence)
        self.assertEqual(report["local"]["raw_operations"], 1, evidence)
        self.assertEqual(report["local"]["raw_effects"], 0, evidence)

    def test_native_policy_update_and_effect_share_one_writer_and_selected_cutoff(self):
        self.store.allocate_synthetic(self.request())
        update = self.actor("policy", "policy-written", replacement_hex=WIRE.hex(), active=False)
        with self.assertRaises(source.StoreOutcomeUnknown): self.store.apply_synthetic_effect(self.request())
        update.stdin.write(b"commit\n"); update.stdin.flush()
        out, err = update.communicate(timeout=10)
        self.assertEqual((update.returncode, err), (0, b"")); self.assertEqual(json.loads(out), {"revision":1})
        with self.assertRaises(source.StoreRefused): self.store.apply_synthetic_effect(self.request())
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_native_effect_committed_before_revocation_remains_one_historical_effect(self):
        self.store.allocate_synthetic(self.request())
        effect = self.actor("effect", "effect-written")
        with self.assertRaises(source.StoreOutcomeUnknown): self.store.replace_local_policy(0, WIRE, active=False)
        effect.stdin.write(b"commit\n"); effect.stdin.flush()
        out, err = effect.communicate(timeout=10)
        self.assertEqual((effect.returncode, err), (0, b"")); self.assertIsNotNone(json.loads(out)["effect_sequence"])
        self.store.replace_local_policy(0, WIRE, active=False)
        self.assertIsNotNone(self.store.apply_synthetic_effect(self.request()).effect_sequence)
        self.assertEqual(self.store.local_view().synthetic_effects, 1)

    def test_inherited_native_connection_refuses_before_sql_and_parent_remains_usable(self):
        read, write = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(read)
            try: self.store.local_view()
            except source.StoreRefused: os.write(write, b"refused")
            finally: os._exit(0)
        os.close(write)
        with os.fdopen(read, "rb") as pipe: self.assertEqual(pipe.read(), b"refused")
        self.assertEqual(os.waitpid(pid, 0)[1], 0)
        self.store.allocate_synthetic(self.request())
        self.assertEqual(self.store.local_view().charged_operations, 1)
