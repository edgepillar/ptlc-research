"""Unsigned actual-store provenance, ordering, restore and stale-use controls."""

from dataclasses import FrozenInstanceError, asdict, replace
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from offline_session import current_authority_contract as current
from qualification import original_read_contract as reads, original_read_snapshot as snapshot
from qualification import policy_effect_store as local, source_root_roles as roots
from test_source_read_ordering import ReadOrderingCase


class OriginalSnapshotCase(ReadOrderingCase):
    def root_for(self, profile):
        d = self.root.as_dict()
        return roots.root_declaration(source_context=d["source_context"], governor_profile=json.loads(profile),
            delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])

    def query(self, *, root=None, original=None, heads=None, challenge="03"):
        root, original = root or self.root, original or self.original
        heads = heads or snapshot.local_checkpoints(self.store, root)
        operation = reads.original_operation(operation_id_hex=original.operation_id_hex,
            expected_revision=original.expected_revision, profile_wire=original.profile_wire,
            proposal_digest_hex=original.proposal_digest_hex)
        return reads.original_read_query(root, operation, checkpoint=heads.policy_checkpoint,
            record_checkpoint=heads.record_checkpoint, challenge_hex=challenge*32)

    def sample(self, query=None, *, root=None):
        return snapshot.sample_original(self.store, root or self.root, query or self.query(root=root))

    def state(self):
        return self.path.read_bytes(), self.store.local_view()


class OriginalReadSnapshotTests(OriginalSnapshotCase):
    def test_real_absent_pending_and_completed_claims_bind_both_heads_and_complete_original(self):
        for observation in ("absent", "pending", "completed"):
            if observation == "pending":
                self.store.allocate_synthetic(self.original)
            elif observation == "completed":
                self.store.apply_synthetic_effect(self.original)
            query = self.query()
            before = self.state()
            claim = self.sample(query)
            value = claim.as_dict()
            self.assertEqual(value["observation"], observation)
            self.assertEqual(value["claimed_checkpoint"], query.as_dict()["expected_checkpoint"])
            self.assertEqual(value["claimed_record_checkpoint"], query.as_dict()["expected_record_checkpoint"])
            self.assertEqual(value["head_policy"], dict(governor_profile=json.loads(self.profile), active=True))
            self.assertEqual(reads.parse_claim(query, claim.canonical_bytes).as_dict(), value)
            if observation != "absent":
                self.assertEqual(value["original_record"]["original_operation"], query.as_dict()["original_operation"])
                self.assertEqual(value["original_record"]["charge_sequence"], 1)
                self.assertEqual(value["original_record"]["effect_sequence"], 2 if observation == "completed" else None)
            self.assertEqual(self.state(), before)

    def test_retained_old_pending_profile_can_be_read_after_revocation_without_reenabling_effect(self):
        self.store.allocate_synthetic(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        before = self.state()
        claim = self.sample().as_dict()
        self.assertEqual((claim["observation"], claim["head_policy"]["active"]), ("pending", False))
        self.assertEqual(claim["original_record"]["original_operation"]["expected_revision"], 0)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        with self.assertRaises(local.StoreRefused):
            self.store.allocate_synthetic(replace(self.original, operation_id_hex="04"*32))
        self.assertEqual(self.state(), before)

    def test_retained_completed_original_is_read_after_owner_epoch_caps_and_scope_pin_changes(self):
        self.store.allocate_synthetic(self.original)
        effect = self.store.apply_synthetic_effect(self.original)
        profile = json.loads(self.profile)
        changes = dict(owner_auth_key_hex="09"*32, authority_epoch=profile["authority_epoch"]+1,
            max_attempt_limit=1, max_target_limit=1, authority_profile_digest_hex="0a"*32,
            verifier_profile_digest_hex="0b"*32, pool_profile_digest_hex="0c"*32, resource_profile_digest_hex="0d"*32)
        changed = snapshot.ordering._canonical(dict(profile, **changes))
        self.store.replace_local_policy(0, changed, active=False)
        root = self.root_for(changed)
        before = self.state()
        value = self.sample(root=root).as_dict()
        self.assertEqual(value["observation"], "completed")
        self.assertEqual(value["head_policy"]["governor_profile"], json.loads(changed))
        self.assertEqual(value["original_record"]["original_operation"]["governor_profile"], profile)
        self.assertEqual(value["original_record"]["effect_sequence"], effect.effect_sequence)
        self.assertEqual(self.state(), before)
        with self.assertRaises(local.StoreRefused):
            snapshot.local_checkpoints(self.store, self.root)

    def test_retained_old_absence_is_a_lookup_not_a_new_admission_or_retry(self):
        self.store.replace_local_policy(0, self.profile, active=False)
        value = self.sample().as_dict()
        self.assertEqual((value["observation"], value["original_record"]), ("absent", None))
        with self.assertRaises(local.StoreRefused):
            self.store.allocate_synthetic(self.original)
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_absent_original_requires_complete_retained_profile_provenance_even_at_an_old_revision(self):
        self.store.replace_local_policy(0, self.profile, active=True)
        profile = json.loads(self.profile)
        for field, value in profile.items():
            if field in ("schema", "purpose", "role", "algorithm", "authority_id_hex", "resource_digest_hex"):
                continue
            changed = value+1 if type(value) is int else "04"*32
            if field.endswith("limit") and changed > 64:
                changed = value-1
            original = replace(self.original, profile_wire=snapshot.ordering._canonical(dict(profile, **{field: changed})))
            with self.subTest(field=field), self.assertRaises(local.StoreRefused):
                self.sample(self.query(original=original))
        self.assertEqual(self.store.local_view().charged_operations, 0)

    def test_same_id_with_other_proposal_revision_or_complete_profile_is_refused_never_absent(self):
        self.store.allocate_synthetic(self.original)
        self.store.replace_local_policy(0, self.profile, active=True)
        for request in (replace(self.original, proposal_digest_hex="04"*32),
                        replace(self.original, expected_revision=1),
                        replace(self.original, profile_wire=snapshot.ordering._canonical(
                            dict(json.loads(self.profile), max_attempt_limit=1)))):
            with self.subTest(request=request), self.assertRaises(local.StoreRefused):
                self.sample(self.query(original=request))
        self.assertEqual(self.sample().as_dict()["observation"], "pending")

    def test_unavailable_claim_asserts_no_state_and_does_not_hide_original_collision(self):
        self.store.allocate_synthetic(self.original)
        self.store.set_local_source_mode("unavailable")
        before = self.state()
        value = self.sample().as_dict()
        self.assertEqual(value["observation"], "unavailable")
        for field in ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"):
            self.assertIsNone(value[field])
        with self.assertRaises(local.StoreRefused):
            self.sample(self.query(original=replace(self.original, proposal_digest_hex="04"*32)))
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.assertEqual(self.state(), before)

    def test_ambiguous_or_known_compromised_modes_refuse_without_cached_fallback(self):
        self.store.allocate_synthetic(self.original)
        saved = self.sample()
        for mode in ("ambiguous", "compromise-detected"):
            self.store.set_local_source_mode(mode)
            before = self.state()
            with self.assertRaises(local.StoreRefused):
                self.sample()
            self.assertEqual(self.state(), before)
        self.assertEqual(saved.as_dict()["observation"], "pending")

    def test_record_checkpoint_changes_on_charge_and_effect_without_changing_policy_checkpoint(self):
        first = snapshot.local_checkpoints(self.store, self.root)
        old_query = self.query(heads=first)
        self.store.allocate_synthetic(self.original)
        second = snapshot.local_checkpoints(self.store, self.root)
        self.assertEqual(first.policy_checkpoint, second.policy_checkpoint)
        self.assertNotEqual(first.record_checkpoint, second.record_checkpoint)
        with self.assertRaises(local.StoreRefused):
            self.sample(old_query)
        pending_query = self.query(heads=second)
        self.store.apply_synthetic_effect(self.original)
        third = snapshot.local_checkpoints(self.store, self.root)
        self.assertEqual(first.policy_checkpoint, third.policy_checkpoint)
        self.assertNotEqual(second.record_checkpoint, third.record_checkpoint)
        with self.assertRaises(local.StoreRefused):
            self.sample(pending_query)

    def test_selected_pair_refuses_mode_history_changes_even_when_the_policy_head_repeats(self):
        heads = snapshot.local_checkpoints(self.store, self.root)
        query = self.query(heads=heads)
        for mode in ("unavailable", "live"):
            self.store.set_local_source_mode(mode)
            with self.assertRaises(local.StoreRefused):
                self.sample(query)
        now = snapshot.local_checkpoints(self.store, self.root)
        self.assertEqual(heads.policy_checkpoint, now.policy_checkpoint)
        self.assertNotEqual(heads.record_checkpoint, now.record_checkpoint)
        self.store.replace_local_policy(0, self.profile, active=False)
        after = snapshot.local_checkpoints(self.store, self.root)
        self.assertNotEqual(after.policy_checkpoint, now.policy_checkpoint)
        self.assertNotEqual(after.record_checkpoint, now.record_checkpoint)

    def test_mixed_policy_and_record_heads_do_not_produce_a_selected_snapshot(self):
        first = snapshot.local_checkpoints(self.store, self.root)
        self.store.allocate_synthetic(self.original)
        second = snapshot.local_checkpoints(self.store, self.root)
        # Policy alone is unchanged; selecting the older record head still refuses.
        mixed = copy.copy(second)
        object.__setattr__(mixed, "record_checkpoint", first.record_checkpoint)
        with self.assertRaises(local.StoreRefused):
            self.sample(self.query(heads=mixed))
        wrong = copy.copy(second)
        object.__setattr__(wrong, "policy_checkpoint", current.PolicyCheckpoint(0, "04"*32))
        with self.assertRaises(local.StoreRefused):
            self.sample(self.query(heads=wrong))

    def test_lineage_reproduces_exact_canonical_retained_rows_independent_of_local_filename(self):
        self.store.allocate_synthetic(self.original)
        self.store.apply_synthetic_effect(self.original)
        self.store.replace_local_policy(0, self.profile, active=False)
        self.store.set_local_source_mode("unavailable")
        d = self.root.as_dict()
        original = reads.original_operation(operation_id_hex=self.original.operation_id_hex,
            expected_revision=0, profile_wire=self.profile, proposal_digest_hex=self.original.proposal_digest_hex).as_dict()
        material = dict(root_declaration=d, retention_rule=reads.RETENTION_RULE,
            source=dict(revision=1, profile_hex=self.profile.hex(), active=False, mode="unavailable"),
            policies=[dict(revision=0, profile_hex=self.profile.hex(), active=True, event_sequence=0),
                dict(revision=1, profile_hex=self.profile.hex(), active=False, event_sequence=3)],
            operations=[dict(original_operation=original, charge_sequence=1, effect_sequence=2)],
            effects=[dict(operation_id_hex=self.original.operation_id_hex, event_sequence=2, payload="synthetic-effect")],
            events=[dict(event_sequence=seq, kind=kind, revision=rev, operation_id_hex=op, detail=detail)
                for seq, kind, rev, op, detail in [(1,"charge",0,self.original.operation_id_hex,""),
                    (2,"effect",0,self.original.operation_id_hex,""),(3,"policy",1,None,""),
                    (4,"mode",1,None,"unavailable")]])
        expected = hashlib.sha256(snapshot.LINEAGE_DOMAIN+snapshot.ordering._canonical(material)).hexdigest()
        heads = snapshot.local_checkpoints(self.store, self.root)
        self.assertEqual(heads.record_checkpoint, reads.RecordCheckpoint(4, expected))
        self.store.close()
        clone = self.path.with_name("other-synthetic.sqlite3")
        shutil.copyfile(self.path, clone)
        with self.open(clone) as store:
            self.assertEqual(snapshot.local_checkpoints(store, self.root).as_dict(), heads.as_dict())

    def test_all_retained_operations_and_events_change_lineage_not_only_the_selected_original(self):
        query = self.query()
        self.store.allocate_synthetic(replace(self.original, operation_id_hex="04"*32, proposal_digest_hex="05"*32))
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        selected = self.sample().as_dict()
        self.assertEqual(selected["observation"], "absent")
        self.assertEqual(selected["claimed_record_checkpoint"]["event_sequence"], 1)

    def test_read_replays_are_deterministic_and_a_new_challenge_changes_only_the_claim_binding(self):
        self.store.allocate_synthetic(self.original)
        heads = snapshot.local_checkpoints(self.store, self.root)
        first = self.sample(self.query(heads=heads))
        self.assertEqual(self.sample(self.query(heads=heads)).canonical_bytes, first.canonical_bytes)
        other = self.sample(self.query(heads=heads, challenge="04"))
        self.assertNotEqual(first.digest_hex, other.digest_hex)
        for field in ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"):
            self.assertEqual(first.as_dict()[field], other.as_dict()[field])

    def test_independently_selected_root_and_all_source_labels_must_match_before_sql(self):
        for field in ("source_id_hex", "source_incarnation_hex", "authority_id_hex", "resource_digest_hex"):
            d = self.root.as_dict()
            d["source_context"][field] = "04"*32
            if field in d["governor_profile"]:
                d["governor_profile"][field] = "04"*32
            root = roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
                delegated_keys=d["delegated_keys"], revision=d["declaration_revision"])
            with self.subTest(field=field), patch.object(self.store, "_transaction") as transaction:
                with self.assertRaises(local.StoreRefused):
                    snapshot.local_checkpoints(self.store, root)
                transaction.assert_not_called()

    def test_query_with_another_complete_root_cannot_replace_the_selected_root(self):
        d = self.root.as_dict()
        other = roots.root_declaration(source_context=d["source_context"], governor_profile=d["governor_profile"],
            delegated_keys=d["delegated_keys"], revision=d["declaration_revision"]+1)
        query = self.query(root=other)
        with patch.object(self.store, "_transaction") as transaction, self.assertRaises(local.StoreRefused):
            self.sample(query)
        transaction.assert_not_called()

    def test_exact_query_store_root_types_and_damaged_fields_run_no_foreign_hooks_or_sql(self):
        class Hostile:
            def __getattribute__(self, name):
                raise AssertionError("foreign hook ran")
        query = self.query()
        broken = copy.copy(query)
        object.__setattr__(broken, "_root", Hostile())
        cases = [(Hostile(), self.root, query), (self.store, Hostile(), query),
            (self.store, self.root, Hostile()), (self.store, self.root, broken)]
        with patch.object(self.store, "_transaction", side_effect=AssertionError("SQL ran")):
            for args in cases:
                with self.assertRaises(local.StoreRefused):
                    snapshot.sample_original(*args)

    def test_local_revision_bound_is_stricter_than_the_reference_grammar(self):
        operation = reads.original_operation(operation_id_hex="01"*32, expected_revision=33,
            profile_wire=self.profile, proposal_digest_hex="02"*32)
        query = reads.original_read_query(self.root, operation,
            checkpoint=current.PolicyCheckpoint(33,"04"*32), record_checkpoint=reads.RecordCheckpoint(1,"05"*32),
            challenge_hex="03"*32)
        with patch.object(self.store, "_transaction") as transaction, self.assertRaises(local.StoreRefused):
            self.sample(query)
        transaction.assert_not_called()

    def test_incomplete_corrupt_retention_refuses_before_absence_or_cached_return(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        saved = self.sample(query)
        self.store._db.execute("DELETE FROM events")
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        with self.assertRaises(local.StoreRefused):
            snapshot.local_checkpoints(self.store, self.root)
        self.assertEqual(saved.as_dict()["observation"], "pending")

    def test_coherent_unwitnessed_original_replacement_can_match_a_new_locally_selected_checkpoint(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        self.store._db.execute("UPDATE operations SET proposal=?", ("04"*32,))
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        with self.assertRaises(local.StoreRefused):
            self.sample(self.query())
        replacement = replace(self.original, proposal_digest_hex="04"*32)
        value = self.sample(self.query(original=replacement)).as_dict()
        self.assertEqual(value["original_record"]["original_operation"]["proposal_digest_hex"], "04"*32)
        # Complete local consistency is not authenticated original-record provenance.
        self.assertEqual(self.store.local_view().charged_operations, 1)

    def test_changed_old_policy_and_original_can_be_coherently_reselected_without_historical_authentication(self):
        self.store.allocate_synthetic(self.original)
        changed = snapshot.ordering._canonical(dict(json.loads(self.profile), owner_auth_key_hex="09"*32))
        self.store.replace_local_policy(0, changed, active=False)
        root = self.root_for(changed)
        original_query = self.query(root=root)
        forged = snapshot.ordering._canonical(dict(json.loads(self.profile), owner_auth_key_hex="ff"*32))
        self.store._db.execute("UPDATE policies SET profile=? WHERE revision=0", (forged,))
        self.store._db.execute("UPDATE operations SET profile=? WHERE revision=0", (forged,))
        with self.assertRaises(local.StoreRefused):
            self.sample(original_query, root=root)
        replacement = replace(self.original, profile_wire=forged)
        value = self.sample(self.query(root=root, original=replacement), root=root).as_dict()
        self.assertEqual(value["original_record"]["original_operation"]["governor_profile"]["owner_auth_key_hex"], "ff"*32)
        # Format-only local provenance checks do not run curve or signature math.
        self.assertFalse(value["head_policy"]["active"])

    def test_lower_current_cap_keeps_multiple_old_pending_charges_without_authorizing_any_effect(self):
        self.store.allocate_synthetic(self.original)
        self.store.allocate_synthetic(replace(self.original, operation_id_hex="04"*32))
        reduced = snapshot.ordering._canonical(dict(json.loads(self.profile), max_attempt_limit=1))
        self.store.replace_local_policy(0, reduced, active=True)
        root = self.root_for(reduced)
        value = self.sample(root=root).as_dict()
        self.assertEqual(value["observation"], "pending")
        self.assertEqual(self.store.local_view().charged_operations, 2)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        current_request = replace(self.original, operation_id_hex="05"*32, expected_revision=1, profile_wire=reduced)
        with self.assertRaises(local.StoreRefused):
            self.store.allocate_synthetic(current_request)
        self.assertEqual(self.store.local_view().synthetic_effects, 0)

    def test_coherent_restored_source_replays_old_heads_absence_charge_and_effect(self):
        query = self.query()
        first = self.sample(query)
        self.store.close()
        old = self.path.read_bytes()
        audit = []  # Ideal nonrewound witness, never an implemented external service.
        for index in range(2):
            if index:
                self.path.write_bytes(old)
            with self.open() as store:
                claim = snapshot.sample_original(store, self.root, query)
                self.assertEqual(claim.canonical_bytes, first.canonical_bytes)
                store.allocate_synthetic(self.original)
                audit.append(asdict(store.apply_synthetic_effect(self.original)))
                if index == 0:
                    store.replace_local_policy(0, self.profile, active=False)
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[0], audit[1])

    def test_coherent_clones_repeat_pending_reads_and_synthetic_effects_with_the_same_lineage(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        expected = self.sample(query)
        self.store.close()
        clone = self.path.with_name("synthetic-clone.sqlite3")
        shutil.copyfile(self.path, clone)
        audit = []
        for path in (self.path, clone):
            with self.open(path) as store:
                self.assertEqual(snapshot.sample_original(store,self.root,query).canonical_bytes, expected.canonical_bytes)
                audit.append(asdict(store.apply_synthetic_effect(self.original)))
        self.assertEqual(audit[0], audit[1])

    def test_lost_read_return_never_refunds_or_allocates_and_exact_replay_retains_pending(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        expected, before = self.sample(query), self.state()
        def cut(point):
            if point == "original-read-sample-after-commit":
                raise OSError("synthetic lost read return")
        with patch.object(self.store,"_cut",side_effect=cut), self.assertRaises(local.StoreOutcomeUnknown):
            self.sample(query)
        self.assertEqual(self.sample(query).canonical_bytes, expected.canonical_bytes)
        self.assertEqual(self.state(), before)

    def test_snapshot_and_commit_cancellation_or_failure_preserves_the_retained_original(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        for point in ("original-read-snapshot-selected", "original-read-sample-before-commit"):
            for exception in (OSError,KeyboardInterrupt,SystemExit):
                before = self.state()
                def cut(label):
                    if label == point:
                        raise exception("synthetic interruption")
                with patch.object(self.store,"_cut",side_effect=cut):
                    with self.assertRaises(local.StoreOutcomeUnknown if exception is OSError else exception):
                        self.sample(query)
                self.assertEqual(self.state(), before)

    def test_observation_can_age_after_commit_before_an_unfenced_ideal_entry(self):
        self.store.allocate_synthetic(self.original)
        self.store.apply_synthetic_effect(self.original)
        claim = self.sample()
        self.store.replace_local_policy(0,self.profile,active=False)
        entries = []  # A blind ideal actuator is intentionally outside the SQL transaction.
        entries.append(claim.as_dict()["original_record"]["original_operation"]["operation_id_hex"])
        self.assertEqual(len(entries),1)
        self.assertFalse(self.store.local_view().active)
        self.assertEqual(claim.as_dict()["head_policy"]["active"], True)

    def test_frozen_diagnostic_and_claim_have_no_capability_and_foreign_thread_or_closed_store_refuse(self):
        heads, claim = snapshot.local_checkpoints(self.store,self.root), self.sample()
        with self.assertRaises(TypeError):
            snapshot.LocalOriginalHeads()
        with self.assertRaises(FrozenInstanceError):
            heads.record_checkpoint = reads.RecordCheckpoint(1,"04"*32)
        for value in (heads,claim):
            for field in ("authenticated","authorized","permit","can_start","signature_hex"):
                self.assertFalse(hasattr(value,field))
        query, failures = self.query(), []
        def foreign():
            try:
                self.sample(query)
            except local.StoreRefused:
                failures.append(True)
        thread = threading.Thread(target=foreign)
        thread.start(); thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures,[True])
        self.store.close()
        with self.assertRaises(local.StoreRefused):
            self.sample(query)


@unittest.skipUnless(os.name == "posix", "native original snapshots require POSIX signals")
class OriginalReadSnapshotNativeTests(OriginalSnapshotCase):
    def actor(self, query, point):
        child = subprocess.Popen([sys.executable,"-B",str(Path(__file__).with_name("original_read_snapshot_actor.py")),
            str(self.path),point], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
        self.addCleanup(cleanup)
        packet = dict(labels=asdict(self.labels),declaration=self.root.as_dict(),query=query.as_dict())
        child.stdin.write((json.dumps(packet)+"\n").encode("ascii")); child.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=10),"original actor did not reach its bounded cut")
        self.assertEqual(child.stdout.readline().strip(),b"paused")
        return child

    def release(self, child):
        child.stdin.write(b"continue\n"); child.stdin.flush()
        output,error = child.communicate(timeout=10)
        self.assertEqual((child.returncode,error),(0,b""))
        return json.loads(output)

    def kill(self, child):
        child.kill()
        output,error = child.communicate(timeout=10)
        self.assertEqual((child.returncode,output,error),(-signal.SIGKILL,b"",b""))

    def test_native_complete_historical_snapshot_excludes_policy_mode_allocation_and_effect_writers(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        child = self.actor(query,"original-read-snapshot-selected")
        for writer in (lambda:self.store.replace_local_policy(0,self.profile,active=False),
                lambda:self.store.set_local_source_mode("unavailable"),
                lambda:self.store.allocate_synthetic(replace(self.original,operation_id_hex="04"*32)),
                lambda:self.store.apply_synthetic_effect(self.original)):
            with self.assertRaises(local.StoreOutcomeUnknown):
                writer()
        value = self.release(child)
        self.assertEqual(value["observation"],"pending")
        self.assertEqual(self.store.local_view().charged_operations,1)

    def test_native_pending_snapshot_can_age_to_completed_after_commit_before_delivery(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        child = self.actor(query,"original-read-sample-after-commit")
        self.store.apply_synthetic_effect(self.original)
        value = self.release(child)
        self.assertEqual(value["observation"],"pending")
        with self.assertRaises(local.StoreRefused):
            self.sample(query)
        self.assertEqual(self.sample().as_dict()["observation"],"completed")

    def test_native_revocation_after_snapshot_commit_before_return_keeps_old_profile_and_charge(self):
        self.store.allocate_synthetic(self.original)
        query = self.query()
        child = self.actor(query,"original-read-sample-after-commit")
        self.store.replace_local_policy(0,self.profile,active=False)
        value = self.release(child)
        self.assertEqual(value["head_policy"]["active"],True)
        self.assertEqual(value["original_record"]["charge_sequence"],1)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        self.assertFalse(self.sample().as_dict()["head_policy"]["active"])

    def test_native_sigkill_at_snapshot_before_commit_and_after_commit_preserves_retention_without_refund(self):
        self.store.allocate_synthetic(self.original)
        query, before = self.query(), self.state()
        for point in ("original-read-snapshot-selected","original-read-sample-before-commit","original-read-sample-after-commit"):
            self.kill(self.actor(query,point))
            self.assertEqual(self.state(),before)
            value = self.sample(query).as_dict()
            self.assertEqual(value["original_record"]["charge_sequence"],1)
            self.assertIsNone(value["original_record"]["effect_sequence"])

    def test_native_lost_delivery_after_revocation_does_not_recover_or_apply_pending_original(self):
        self.store.allocate_synthetic(self.original)
        child = self.actor(self.query(),"original-read-sample-after-commit")
        self.store.replace_local_policy(0,self.profile,active=False)
        self.kill(child)
        with self.assertRaises(local.StoreRefused):
            self.store.apply_synthetic_effect(self.original)
        value = self.sample().as_dict()
        self.assertEqual((value["observation"],value["head_policy"]["active"]),("pending",False))
        self.assertEqual((self.store.local_view().charged_operations,self.store.local_view().synthetic_effects),(1,0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
