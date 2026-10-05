"""Local SQL snapshot ordering with synthetic labels and unsigned read claims.

External audit lists expose restore counterexamples; they are ideal nonrewound
witnesses, never an implemented lineage service or admission/physical-use fence.
"""

from dataclasses import FrozenInstanceError, asdict, replace
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from offline_session import current_authority_contract as current, governor_authentication as signatures
from qualification import policy_effect_store as local, source_read_ordering as ordering
from qualification import source_response as responses, source_root_roles as roots
from test_source_response import selection


def selected_root(response):
    d = response.root_dict()
    return roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
        delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])


class ReadOrderingCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.selected = selection()
        cls.root = selected_root(cls.selected)
        d = cls.root.as_dict()
        cls.profile = ordering._canonical(d["governor_profile"])
        c = d["source_context"]
        cls.labels = local.SourceLabels(c["source_id_hex"], c["source_incarnation_hex"],
            c["authority_id_hex"], c["resource_digest_hex"])
        cls.governor = ordering._canonical(dict(cls.selected._query.as_dict()["governor_signature_request"],
            schema=signatures.ENVELOPE_SCHEMA))

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="synthetic-read-ordering-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)/"policy.sqlite3"
        self.store = local.OfflinePolicyEffectStore(str(self.path), self.labels, initial_profile=self.profile)
        self.addCleanup(self.dispose)
        self.original = local.OriginalRequest("01"*32, 0, self.profile, "02"*32)

    def dispose(self):
        if not self.store._closed:
            self.store.close()

    def query(self, *, checkpoint=None, challenge="03", root=None):
        if checkpoint is None:
            checkpoint = ordering.local_checkpoint(self.store, root or self.root)
        return current.policy_read_query(self.selected._query._expected, self.governor,
            source=self.selected._query._source, checkpoint=checkpoint, challenge_hex=challenge*32)

    def sample(self, query=None, original=None):
        return ordering.sample_original(self.store, self.root,
            self.query() if query is None else query, self.original if original is None else original)

    def open(self, path=None):
        return local.OfflinePolicyEffectStore(str(path or self.path), self.labels)


class SourceReadOrderingTests(ReadOrderingCase):
    def test_complete_unsigned_snapshot_binds_root_source_profile_query_scope_and_claim(self):
        query = self.query()
        before = self.path.read_bytes(), self.store.local_view()
        sample = self.sample(query)
        response = sample.response.as_dict()
        self.assertEqual(response["query"], query.as_dict())
        self.assertEqual(response["source_context"], self.root.as_dict()["source_context"])
        self.assertEqual(response["root_declaration_digest_hex"], self.root.message_digest_hex)
        self.assertEqual(len(response["query"]["governor_signature_request"]["assignment"]["governor_profile"]), 14)
        self.assertEqual(response["claim"]["observation"], "active")
        self.assertEqual(current.parse_claim(query, ordering._canonical(response["claim"])).as_dict(), response["claim"])
        self.assertIs(sample.original, self.original)
        self.assertIsNone(sample.original_record)
        self.assertEqual(sample.event_sequence, 0)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)

    def test_original_association_is_local_and_not_inside_the_historical_signed_response(self):
        query = self.query()
        first = self.sample(query)
        for original in (replace(self.original, operation_id_hex="04"*32),
                         replace(self.original, proposal_digest_hex="05"*32)):
            other = self.sample(query, original)
            self.assertEqual(other.response.canonical_bytes, first.response.canonical_bytes)
            self.assertNotEqual(other.digest_hex, first.digest_hex)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_reads_leave_pending_and_completed_original_records_and_charges_unchanged(self):
        allocated = self.store.allocate_synthetic(self.original)
        first = self.sample()
        self.assertEqual(first.original_record, allocated)
        applied = self.store.apply_synthetic_effect(self.original)
        before = self.path.read_bytes(), self.store.local_view()
        second = self.sample()
        self.assertEqual(second.original_record, applied)
        self.assertNotEqual(second.digest_hex, first.digest_hex)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
        self.assertEqual(second.response.canonical_bytes, first.response.canonical_bytes)

    def test_checkpoint_changes_on_policy_mode_root_and_profile_but_not_synthetic_usage(self):
        first = ordering.local_checkpoint(self.store, self.root)
        self.store.allocate_synthetic(self.original)
        self.store.apply_synthetic_effect(self.original)
        self.assertEqual(ordering.local_checkpoint(self.store, self.root), first)
        d = self.root.as_dict()
        newer = roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
            delegated_keys=d["delegated_keys"], revision=d["declaration_revision"]+1)
        self.assertNotEqual(ordering.local_checkpoint(self.store, newer), first)
        self.store.set_local_source_mode("unavailable")
        self.assertNotEqual(ordering.local_checkpoint(self.store, self.root), first)
        self.store.set_local_source_mode("live")
        self.store.replace_local_policy(0, self.profile, active=False)
        self.assertNotEqual(ordering.local_checkpoint(self.store, self.root), first)

    def test_fresh_challenge_cannot_make_a_stale_selected_sql_checkpoint_current(self):
        checkpoint = ordering.local_checkpoint(self.store, self.root)
        self.store.replace_local_policy(0, self.profile, active=False)
        before = self.store.local_view()
        for challenge in ("03", "04"):
            query = self.query(checkpoint=checkpoint, challenge=challenge)
            unsigned_stale = responses.source_response(self.root, query, observation="active")
            self.assertEqual(unsigned_stale.as_dict()["claim"]["observation"], "active")
            with self.assertRaises(local.StoreRefused):
                self.sample(query)
        self.assertEqual(self.store.local_view(), before)

    def test_fresh_revoked_read_reconciles_original_without_refund_or_pending_effect(self):
        original_record = self.store.allocate_synthetic(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        before = self.path.read_bytes(), self.store.local_view()
        sample = self.sample()
        self.assertEqual(sample.response.as_dict()["claim"]["observation"], "revoked")
        self.assertEqual(sample.original_record, original_record)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
        self.assertEqual(sample.event_sequence, 2)

    def test_policy_change_after_read_before_allocation_refuses_without_charge(self):
        self.sample()
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.store.allocate_synthetic(self.original)
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (0, 0))

    def test_policy_change_after_charge_before_synthetic_effect_retains_one_charge(self):
        self.sample()
        self.store.allocate_synthetic(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (1, 0))

    def test_synthetic_effect_commit_does_not_fence_later_physical_actuation(self):
        self.sample()
        self.store.allocate_synthetic(self.original)
        committed = self.store.apply_synthetic_effect(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        # This external list is a deliberately blind ideal actuator, not work.
        simulated_actuation = []
        simulated_actuation.append(committed.operation_id_hex)
        self.assertEqual(simulated_actuation, [self.original.operation_id_hex])
        self.assertFalse(self.store.local_view().active)
        self.assertIsNotNone(self.store.apply_synthetic_effect(self.original).effect_sequence)

    def test_unavailable_is_unsigned_unknown_while_ambiguity_and_compromise_refuse(self):
        for mode in ("unavailable", "ambiguous", "compromise-detected"):
            self.store.set_local_source_mode(mode)
            query = self.query()
            before = self.path.read_bytes(), self.store.local_view()
            if mode == "unavailable":
                claim = self.sample(query).response.as_dict()["claim"]
                self.assertEqual(claim["observation"], "unavailable")
                self.assertIsNone(claim["claimed_checkpoint"])
                self.assertIsNone(claim["assignment_digest_hex"])
            else:
                with self.assertRaises(local.StoreRefused):
                    self.sample(query)
            self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
            self.store.set_local_source_mode("live")

    def test_full_original_record_collision_refuses_without_read_or_refund(self):
        self.store.allocate_synthetic(self.original)
        before = self.path.read_bytes(), self.store.local_view()
        for original in (replace(self.original, expected_revision=1),
                         replace(self.original, proposal_digest_hex="04"*32),
                         replace(self.original, profile_wire=ordering._canonical(dict(
                             json.loads(self.profile), max_attempt_limit=1)))):
            with self.assertRaises(local.StoreRefused):
                self.sample(original=original)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)

    def test_read_uncharged_old_operation_cannot_rebind_to_new_equal_profile_revision(self):
        self.store.replace_local_policy(0, self.profile, active=True)
        with self.assertRaises(local.StoreRefused):
            self.sample()
        fresh = replace(self.original, expected_revision=1)
        self.assertIsNone(self.sample(original=fresh).original_record)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_each_complete_profile_field_is_validated_or_mismatches_the_selected_root(self):
        profile = json.loads(self.profile)
        for field, value in profile.items():
            changed = value+1 if type(value) is int else "04"*32 if field.endswith("_hex") else "unsupported"
            wire = ordering._canonical(dict(profile, **{field: changed}))
            with self.subTest(field=field):
                if type(value) is int or (field.endswith("_hex") and field not in ("authority_id_hex", "resource_digest_hex")):
                    self.store.replace_local_policy(0, wire, active=True)
                    with self.assertRaises(local.StoreRefused):
                        self.sample(self.query(checkpoint=current.PolicyCheckpoint(1, "06"*32)), replace(self.original, expected_revision=1))
                    with self.assertRaises(local.StoreRefused):
                        ordering.local_checkpoint(self.store, self.root)
                    self.store.replace_local_policy(1, self.profile, active=True)
                    self.dispose()
                    self.path.unlink()
                    self.store = local.OfflinePolicyEffectStore(str(self.path), self.labels, initial_profile=self.profile)
                else:
                    with self.assertRaises(local.StoreRefused):
                        self.store.replace_local_policy(0, wire, active=True)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_query_checkpoint_digest_profile_and_source_incarnation_cannot_replace_selection(self):
        good = self.query()
        checkpoint = current.PolicyCheckpoint(0, "04"*32)
        with self.assertRaises(local.StoreRefused):
            self.sample(self.query(checkpoint=checkpoint))
        for name in ("broader_profile", "new_incarnation", "alternate_root", "new_epoch"):
            selected = selection(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                ordering.sample_original(self.store, self.root, selected._query, self.original)
        self.assertEqual(self.sample(good).response.as_dict()["claim"]["observation"], "active")

    def test_opaque_root_and_source_profile_are_operator_premises_not_database_authentication(self):
        d = self.root.as_dict()
        context = dict(d["source_context"], provisioning_root_key_hex="ff"*32,
            source_profile_digest_hex="04"*32)
        selected = roots.root_declaration(source_context=context, governor_profile=d["governor_profile"],
            delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
        source = current.source_context(self.selected._query._expected, **{field: context[field] for field in
            ("source_id_hex", "source_profile_digest_hex", "source_incarnation_hex", "provisioning_root_key_hex")})
        query = current.policy_read_query(self.selected._query._expected, self.governor, source=source,
            checkpoint=ordering.local_checkpoint(self.store, selected), challenge_hex="03"*32)
        sample = ordering.sample_original(self.store, selected, query, self.original)
        # The all-ff encoding is not a secp256k1 x coordinate. No math runs here.
        self.assertEqual(sample.response.as_dict()["claim"]["observation"], "active")
        self.assertEqual(sample.response.root_dict()["source_context"], context)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_each_retained_source_label_mismatch_refuses_before_sql(self):
        for field in ("source_id_hex", "source_incarnation_hex", "authority_id_hex", "resource_digest_hex"):
            d = self.root.as_dict()
            context = dict(d["source_context"], **{field: "04"*32})
            profile = dict(d["governor_profile"])
            if field in profile:
                profile[field] = "04"*32
            selected = roots.root_declaration(source_context=context, governor_profile=profile,
                delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
            with self.subTest(field=field), patch.object(self.store, "_transaction") as transaction:
                with self.assertRaises(local.StoreRefused):
                    ordering.local_checkpoint(self.store, selected)
                transaction.assert_not_called()

    def test_exact_types_and_original_numbers_refuse_before_transaction_or_foreign_hooks(self):
        class Hostile:
            def __getattribute__(self, name):
                raise AssertionError("foreign hook ran")
        query = self.query()
        cases = [(Hostile(), self.root, query, self.original),
                 (self.store, Hostile(), query, self.original),
                 (self.store, self.root, Hostile(), self.original),
                 (self.store, self.root, query, Hostile()),
                 (self.store, self.root, query, replace(self.original, expected_revision=True)),
                 (self.store, self.root, query, replace(self.original, profile_wire=Hostile())),
                 (self.store, self.root, query, replace(self.original, operation_id_hex=Hostile()))]
        with patch.object(self.store, "_transaction", side_effect=AssertionError("SQL ran")):
            for args in cases:
                with self.assertRaises(ValueError):
                    ordering.sample_original(*args)

    def test_lost_read_return_replays_same_original_without_any_allocation_or_refund(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        expected = self.sample(query)
        before = self.path.read_bytes(), self.store.local_view()
        def cut(point):
            if point == "read-sample-after-commit":
                raise OSError("synthetic lost read return")
        with patch.object(self.store, "_cut", side_effect=cut), self.assertRaises(local.StoreOutcomeUnknown):
            self.sample(query)
        replay = self.sample(query)
        self.assertEqual(replay.digest_hex, expected.digest_hex)
        self.assertEqual(replay.original_record, expected.original_record)
        self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        self.assertEqual(self.sample().original_record, expected.original_record)

    def test_snapshot_and_before_commit_failures_or_cancellation_do_not_charge(self):
        for point in ("read-snapshot-selected", "read-sample-before-commit"):
            for exception in (OSError, KeyboardInterrupt, SystemExit):
                before = self.path.read_bytes(), self.store.local_view()
                def cut(label):
                    if label == point:
                        raise exception("synthetic read interruption")
                with patch.object(self.store, "_cut", side_effect=cut):
                    with self.assertRaises(local.StoreOutcomeUnknown if exception is OSError else exception):
                        self.sample()
                self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
                self.assertEqual(self.sample().event_sequence, 0)

    def test_coherent_database_restore_replays_read_charge_and_effect_despite_external_audit(self):
        query = self.query()
        first_sample = self.sample(query)
        self.store.close()
        old_database = self.path.read_bytes()
        audit = []  # Ideal nonrewound witness outside the restored local source.
        for index in range(2):
            if index:
                self.path.write_bytes(old_database)
            with self.open() as store:
                sample = ordering.sample_original(store, self.root, query, self.original)
                self.assertEqual(sample.digest_hex, first_sample.digest_hex)
                store.allocate_synthetic(self.original)
                effect = store.apply_synthetic_effect(self.original)
                audit.append((effect.operation_id_hex, effect.charge_sequence, effect.effect_sequence))
                if index == 0:
                    store.replace_local_policy(0, self.profile, active=False)
                self.assertEqual(store.local_view().charged_operations, 1)
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[0], audit[1])

    def test_coherent_clones_repeat_same_read_and_operation_under_distinct_local_storage(self):
        query = self.query()
        self.store.close()
        clone = self.path.with_name("clone.sqlite3")
        shutil.copyfile(self.path, clone)
        observed = []
        for path in (self.path, clone):
            with self.open(path) as store:
                observed.append(ordering.sample_original(store, self.root, query, self.original).digest_hex)
                store.allocate_synthetic(self.original)
                self.assertIsNotNone(store.apply_synthetic_effect(self.original).effect_sequence)
        self.assertEqual(observed[0], observed[1])

    def test_client_only_restore_and_new_id_do_not_erase_local_original_charge(self):
        old_query = self.query()
        self.store.allocate_synthetic(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.sample(old_query)
        replay = self.sample()
        self.assertEqual(replay.original_record.operation_id_hex, self.original.operation_id_hex)
        with self.assertRaises(local.StoreRefused):
            self.sample(original=replace(self.original, operation_id_hex="04"*32))
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_factory_only_frozen_samples_and_closed_or_foreign_thread_access_refuse(self):
        sample = self.sample()
        with self.assertRaises(TypeError):
            ordering.LocalReadSample()
        with self.assertRaises(FrozenInstanceError):
            sample.event_sequence = 9
        for name in ("authenticated", "authorized", "permit", "can_start", "signature_hex"):
            self.assertFalse(hasattr(sample, name))
        failures = []
        query = self.query()
        def foreign_thread():
            try:
                self.sample(query)
            except local.StoreRefused:
                failures.append(True)
        thread = threading.Thread(target=foreign_thread)
        thread.start(); thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [True])
        self.store.close()
        with self.assertRaises(local.StoreRefused):
            self.sample(query)


@unittest.skipUnless(os.name == "posix", "native read ordering requires POSIX signals")
class SourceReadOrderingNativeTests(ReadOrderingCase):
    def actor(self, query, point):
        actor = Path(__file__).with_name("source_read_ordering_actor.py")
        child = subprocess.Popen([sys.executable, "-B", str(actor), str(self.path), point],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.addCleanup(cleanup)
        packet = dict(labels=asdict(self.labels), declaration=self.root.as_dict(),
            checkpoint=query.as_dict()["expected_checkpoint"], challenge=query.as_dict()["challenge_hex"],
            operation=self.original.operation_id_hex, revision=self.original.expected_revision,
            profile_hex=self.profile.hex(), proposal=self.original.proposal_digest_hex)
        child.stdin.write((json.dumps(packet)+"\n").encode("ascii")); child.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=10), "read actor did not reach its bounded cut")
        self.assertEqual(child.stdout.readline().strip(), b"paused")
        return child

    def kill(self, child):
        child.kill()
        output, error = child.communicate(timeout=10)
        self.assertEqual((child.returncode, output, error), (-signal.SIGKILL, b"", b""))

    def release(self, child):
        child.stdin.write(b"continue\n"); child.stdin.flush()
        output, error = child.communicate(timeout=10)
        self.assertEqual((child.returncode, error), (0, b""))
        return json.loads(output)

    def test_native_writer_is_excluded_until_the_complete_read_snapshot_transaction_releases(self):
        query = self.query()
        child = self.actor(query, "read-snapshot-selected")
        with self.assertRaises(local.StoreOutcomeUnknown):
            self.store.replace_local_policy(0, self.profile, active=False)
        result = self.release(child)
        self.assertEqual(result["observation"], "active")
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_native_revocation_after_snapshot_commit_before_return_does_not_change_old_sample(self):
        query = self.query()
        child = self.actor(query, "read-sample-after-commit")
        self.store.replace_local_policy(0, self.profile, active=False)
        result = self.release(child)
        self.assertEqual(result["observation"], "active")
        with self.assertRaises(local.StoreRefused):
            self.store.allocate_synthetic(self.original)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_native_read_sigkill_before_and_after_commit_preserves_original_without_refund(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        before = self.path.read_bytes(), self.store.local_view()
        for point in ("read-snapshot-selected", "read-sample-before-commit", "read-sample-after-commit"):
            self.kill(self.actor(query, point))
            self.assertEqual((self.path.read_bytes(), self.store.local_view()), before)
            replay = self.sample(query)
            self.assertEqual(replay.original_record.charge_sequence, 1)
            self.assertIsNone(replay.original_record.effect_sequence)

    def test_native_read_after_commit_does_not_block_later_revocation_or_synthetic_effect_fence(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        child = self.actor(query, "read-sample-after-commit")
        self.store.replace_local_policy(0, self.profile, active=False)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.kill(child)
        self.assertEqual(self.sample().original_record.charge_sequence, 1)
        self.assertEqual((self.store.local_view().charged_operations, self.store.local_view().synthetic_effects), (1, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
