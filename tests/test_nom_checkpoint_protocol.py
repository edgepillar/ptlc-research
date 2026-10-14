"""Selected external-reference controls; no service, custody or recovery authority."""
import copy
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_capsule_query as binding, nom_checkpoint_protocol as protocol
from offline_session import nom_source_checkpoint as source
from scripts import qualify_nom_checkpoint_protocol as q


class NoMCheckpointProtocolControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.contexts, cls.retained = q.fixture_contexts()

    def setUp(self):
        self.initial = protocol.bootstrap_reference(self.policy, self.contexts["primary"])
        self.latest = protocol.advance_reference(self.initial, self.contexts["extended"],
            expected_current_digest_hex=self.initial.digest_hex)

    def compare(self, local, current=None, challenge="d1"*32):
        current = self.latest if current is None else current
        query = protocol.checkpoint_query(current, challenge_hex=challenge)
        return protocol.compare_reference_reply(local, current, query, protocol.reference_reply(current, query))

    def assert_hold(self, result):
        self.assertEqual((result["state"], result["recovery_action"], result["application"], result["core"]),
            ("HOLD", "NONE", "NO-GO", "NO-GO"))
        for key in ("automatic_retry", "replenish_work", "replacement_original_allowed", "new_work_allowed"):
            self.assertIs(result[key], False)
        self.assertEqual(result["worker_calls"], 0)
        self.assertIs(result["disclosure_possible"], True)
        self.assertEqual(result["work_outcome"], "UNKNOWN")
        self.assertTrue(all(row["outcome"] == "UNKNOWN" for row in result["effective_charged_work"]))
        for key in ("checkpoint_storage", "atomic_service_cas", "atomic_work_entry"):
            self.assertEqual(result[key], "NOT_IMPLEMENTED")

    def service(self, **updates):
        values = dict(service_id_hex="c1"*32, service_epoch=1,
            checkpoint_key_hex=self.policy.as_dict()["checkpoint_key_hex"])
        return protocol.select_service(self.contexts["primary"], **dict(values, **updates))

    def test_explicit_bootstrap_binds_full_retained_context_and_unknown_work(self):
        value = self.initial.as_dict()
        self.assertEqual(value["sequence"], 1)
        self.assertEqual(value["previous_checkpoint_digest_hex"], "00"*32)
        self.assertEqual(value["charged_work"], self.contexts["primary"]._binding.as_dict()["charged_work"])
        self.assertEqual(value["capsule_sha256"], self.retained.digest_hex)
        self.assertEqual(value["journal_sequence"], self.retained.projection()["journal_sequence"])
        self.assertEqual(len(value["charged_work"]), 1)

    def test_exact_matching_reference_retains_hold_without_work_permission(self):
        result = self.compare(self.contexts["primary"], self.initial)
        self.assertEqual(result["journal_relation"], "MATCHING_JOURNAL")
        self.assertEqual(result["local_charged_work"], result["reference_charged_work"])
        self.assert_hold(result)

    def test_local_restore_preserves_the_newer_independent_reference_charge(self):
        result = self.compare(self.contexts["primary"])
        self.assertEqual(result["journal_relation"], "LOCAL_BEHIND_REFERENCE")
        self.assertEqual((result["local_charged_work"], result["reference_charged_work"]), (1, 2))
        self.assertEqual(result["effective_charged_work"], self.latest.as_dict()["charged_work"])
        self.assert_hold(result)

    def test_local_ahead_is_diagnostic_and_does_not_advance_external_reference(self):
        before = self.initial.canonical_bytes
        result = self.compare(self.contexts["extended"], self.initial)
        self.assertEqual(result["journal_relation"], "LOCAL_AHEAD_REFERENCE")
        self.assertEqual(len(result["effective_charged_work"]), 2)
        self.assertEqual(self.initial.canonical_bytes, before)
        self.assert_hold(result)

    def test_advance_requires_current_digest_and_retains_complete_prefix(self):
        self.assertEqual(self.latest.as_dict()["previous_checkpoint_digest_hex"], self.initial.digest_hex)
        self.assertEqual(self.latest.as_dict()["sequence"], 2)
        self.assertEqual(self.latest.as_dict()["charged_work"][:1], self.initial.as_dict()["charged_work"])
        self.assertTrue(self.latest._context._binding._capsule.journal_bytes.startswith(self.retained.journal_bytes))

    def test_stale_compare_and_advance_refuses_without_mutating_current(self):
        before = self.latest.canonical_bytes
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.advance_reference(self.latest, self.contexts["divergent"], expected_current_digest_hex=self.initial.digest_hex)
        self.assertEqual(self.latest.canonical_bytes, before)

    def test_regressed_journal_cannot_replace_current_reference(self):
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.advance_reference(self.latest, self.contexts["primary"], expected_current_digest_hex=self.latest.digest_hex)
        self.assertEqual(len(self.latest.as_dict()["charged_work"]), 2)

    def test_divergent_complete_journal_refuses_even_with_correct_current_digest(self):
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.advance_reference(self.latest, self.contexts["divergent"], expected_current_digest_hex=self.latest.digest_hex)
        with self.assertRaises(protocol.CheckpointProtocolRefused): self.compare(self.contexts["divergent"])

    def test_selected_old_current_can_fork_because_global_atomic_cas_is_absent(self):
        sibling = protocol.advance_reference(self.initial, self.contexts["divergent"], expected_current_digest_hex=self.initial.digest_hex)
        self.assertEqual(sibling.as_dict()["sequence"], self.latest.as_dict()["sequence"])
        self.assertNotEqual(sibling.digest_hex, self.latest.digest_hex)
        self.assert_hold(self.compare(self.contexts["divergent"], sibling))

    def test_duplicate_transition_returns_same_object_without_minting_sequence(self):
        self.assertIs(protocol.advance_reference(self.latest, self.contexts["extended"],
            expected_current_digest_hex=self.latest.digest_hex), self.latest)

    def test_journal_extension_without_charge_is_not_a_new_work_allowance(self):
        updated = protocol.advance_reference(self.initial, self.contexts["divergent"], expected_current_digest_hex=self.initial.digest_hex)
        self.assertEqual(updated.as_dict()["sequence"], 2)
        self.assertEqual(len(updated.as_dict()["charged_work"]), 1)
        self.assert_hold(self.compare(self.contexts["divergent"], updated))

    def test_source_keys_epoch_and_challenge_changes_do_not_create_checkpoint_sequence(self):
        for name in ("root_rotation", "source_rotation", "checkpoint_rotation", "new_epoch", "new_challenge"):
            self.assertIs(protocol.advance_reference(self.initial, self.contexts[name],
                expected_current_digest_hex=self.initial.digest_hex), self.initial)
            result = self.compare(self.contexts[name])
            self.assertEqual(len(result["effective_charged_work"]), 2)
            self.assert_hold(result)

    def test_source_unavailability_cannot_erase_newer_reference_work(self):
        result = self.compare(self.contexts["unavailable"])
        self.assertEqual(result["journal_relation"], "LOCAL_BEHIND_REFERENCE")
        self.assertEqual(len(result["effective_charged_work"]), 2)
        self.assert_hold(result)

    def test_checkpoint_counter_is_separate_from_journal_and_observer_counters(self):
        self.assertNotEqual(self.initial.as_dict()["sequence"], self.initial.as_dict()["journal_sequence"])
        knowledge = self.contexts["primary"]._binding._query.as_dict()["consumer_selection"]
        self.assertNotEqual(self.initial.as_dict()["sequence"], knowledge["retention_sequence"])
        self.assertNotEqual(self.initial.digest_hex, knowledge["external_checkpoint_digest_hex"])

    def test_old_reply_cannot_select_its_own_old_checkpoint_under_new_expectation(self):
        old = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        new = protocol.checkpoint_query(self.latest, challenge_hex="d1"*32)
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.compare_reference_reply(self.contexts["primary"], self.latest, new, protocol.reference_reply(self.initial, old))

    def test_changed_challenge_refuses_old_reply_without_updating_checkpoint(self):
        old = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        changed = protocol.checkpoint_query(self.initial, challenge_hex="d2"*32)
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.compare_reference_reply(self.contexts["primary"], self.initial, changed, protocol.reference_reply(self.initial, old))
        self.assertEqual(self.initial.as_dict()["sequence"], 1)

    def test_query_fields_cannot_be_changed_to_peer_selected_expectations(self):
        selected = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        for key in selected:
            if key == "challenge_hex":
                continue
            changed = copy.deepcopy(selected)
            changed[key] = "81"*32
            with self.assertRaises(protocol.CheckpointProtocolRefused): protocol.reference_reply(self.initial, changed)
        for bad in (True, 1.0, "1", 0):
            changed = dict(selected, expected_sequence=bad)
            with self.assertRaises(protocol.CheckpointProtocolRefused): protocol.reference_reply(self.initial, changed)
        fresh_query = dict(selected, challenge_hex="81"*32)
        fresh_reply = protocol.reference_reply(self.initial, fresh_query)
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.compare_reference_reply(self.contexts["primary"], self.initial, selected, fresh_reply)
        self.assert_hold(protocol.compare_reference_reply(self.contexts["primary"], self.initial, fresh_query, fresh_reply))

    def test_exact_reply_frame_refuses_mutation_aliases_extra_privileges_and_duplicates(self):
        query = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        wire = protocol.reference_reply(self.initial, query)
        malformed = [wire+b"\n", b" "+wire, wire.replace(b'"sequence":1', b'"sequence":1.0'),
            wire.replace(b'"sequence":1', b'"sequence":true'), wire.replace(b'{', b'{"admitted":true,', 1),
            wire.replace(b'{', b'{"schema":"duplicate",', 1), b"["*13+b"]"*13, b"x"*8193, b"", None]
        for value in malformed:
            with self.assertRaises(protocol.CheckpointProtocolRefused):
                protocol.compare_reference_reply(self.contexts["primary"], self.initial, query, value)

    def test_missing_actual_long_original_cannot_be_filled_by_reference_checkpoint(self):
        partial = q.prior.prior.prior.from_journal(b"".join(self.retained.journal_bytes.splitlines(keepends=True)[:7]), challenge_hex="a1"*32)
        self.assertIsNotNone(partial.partial_hold.selection()["recovered_long_signature_hex"])
        self.assertIsNone(partial.partial_hold.selection()["original_long_hex"])
        with self.assertRaises(ValueError): q.prior.select_context(partial)
        self.assertEqual(self.latest.as_dict()["sequence"], 2)

    def test_changed_binary_realm_refuses_even_when_work_scope_is_unchanged(self):
        values = q.prior.prior.read_selection(self.retained)
        values["network_selection"]["provisioning_root_digest_hex"] = self.contexts["primary"]._declaration.as_dict()["network_selection"]["provisioning_root_digest_hex"]
        values["network_selection"]["binary_digest_hex"] = "81"*32
        query = authority.read_query(**values)
        retained = binding.bind_read_query(self.retained, query)
        old = self.contexts["primary"]._declaration.as_dict()
        declaration = source.select_declaration(network_selection=query.as_dict()["network_selection"],
            root_key_hex=old["root_key_hex"], source_response_key_hex=old["source_response_key_hex"],
            consumer_checkpoint_key_hex=old["consumer_checkpoint_key_hex"], epoch=old["declaration_epoch"])
        context = source.select_transcript(declaration, retained, q.prior.prior.claim_wire(retained))
        self.assertEqual(context._binding.as_dict()["work_scope_digest_hex"], self.initial.as_dict()["work_scope_digest_hex"])
        with self.assertRaises(protocol.CheckpointProtocolRefused): self.compare(context, self.initial)

    def test_checkpoint_key_cannot_reuse_any_selected_source_role_encoding(self):
        old = self.contexts["primary"]._declaration.as_dict()
        for field in ("root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex"):
            with self.assertRaises(protocol.CheckpointProtocolRefused): self.service(checkpoint_key_hex=old[field])

    def test_public_key_shape_and_distinct_encodings_do_not_prove_service_or_curve(self):
        selected = self.service(checkpoint_key_hex="00"*32)
        checkpoint = protocol.bootstrap_reference(selected, self.contexts["primary"])
        result = self.compare(self.contexts["primary"], checkpoint)
        self.assertEqual(result["reply_authentication"], "NOT_PERFORMED; UNSIGNED REFERENCE FRAME")
        self.assertEqual(result["root_provisioning"], "UNFILLED")
        self.assert_hold(result)

    def test_service_identity_epoch_and_key_change_cannot_satisfy_old_query(self):
        query = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        for changes in (dict(service_id_hex="c2"*32), dict(service_epoch=2), dict(checkpoint_key_hex="82"*32)):
            selected = protocol.bootstrap_reference(self.service(**changes), self.contexts["primary"])
            with self.assertRaises(protocol.CheckpointProtocolRefused): protocol.reference_reply(selected, query)
        self.assertEqual(len(self.latest.as_dict()["charged_work"]), 2)

    def test_service_shape_integer_and_retention_limits_are_exact(self):
        for bad in (True, 1.0, "1", 0, -1, 9007199254740992):
            with self.assertRaises(protocol.CheckpointProtocolRefused): self.service(service_epoch=bad)
        for bad in (True, 1.0, "1", 0, -1, 17):
            with self.assertRaises(protocol.CheckpointProtocolRefused): self.service(max_snapshots=bad)

    def test_exhausted_reference_refuses_extension_but_keeps_exact_replay(self):
        current = protocol.bootstrap_reference(self.service(max_snapshots=1), self.contexts["primary"])
        with self.assertRaises(protocol.CheckpointProtocolRefused):
            protocol.advance_reference(current, self.contexts["extended"], expected_current_digest_hex=current.digest_hex)
        self.assertIs(protocol.advance_reference(current, self.contexts["primary"], expected_current_digest_hex=current.digest_hex), current)
        self.assertEqual(len(current.as_dict()["charged_work"]), 1)

    def test_coherent_copy_of_local_reference_and_reply_still_matches(self):
        result = self.compare(self.contexts["primary"], self.initial)
        self.assertEqual(result["journal_relation"], "MATCHING_JOURNAL")
        self.assertEqual(len(result["effective_charged_work"]), 1)
        self.assertEqual(len(self.latest.as_dict()["charged_work"]), 2)
        self.assert_hold(result)

    def test_fresh_bootstrap_from_old_local_does_not_prove_no_external_history(self):
        reboot = protocol.bootstrap_reference(self.policy, self.contexts["primary"])
        self.assertEqual(reboot.digest_hex, self.initial.digest_hex)
        self.assertNotEqual(reboot.digest_hex, self.latest.digest_hex)
        self.assert_hold(self.compare(self.contexts["primary"], reboot))

    def test_unsigned_reply_can_be_forged_from_public_fields_but_grants_no_permission(self):
        query = protocol.checkpoint_query(self.initial, challenge_hex="d1"*32)
        forged = codec._canonical(json.loads(protocol.reference_reply(self.initial, query)))
        result = protocol.compare_reference_reply(self.contexts["primary"], self.initial, query, forged)
        self.assert_hold(result)

    def test_factories_frozen_objects_and_defensive_views_are_not_incoming_capabilities(self):
        for cls in (protocol.CheckpointServiceSelection, protocol.ReferenceCheckpoint):
            with self.assertRaises(TypeError): cls()
        with self.assertRaises(FrozenInstanceError): self.initial._prior = self.latest
        before = self.initial.canonical_bytes
        value = self.initial.as_dict()
        value["charged_work"].clear()
        self.assertEqual(self.initial.canonical_bytes, before)
        with self.assertRaises(protocol.CheckpointProtocolRefused): protocol.bootstrap_reference(self.policy, self.contexts["primary"].as_dict())

    def test_invalid_and_cyclic_reference_instances_refuse_without_unbounded_recursion(self):
        invalid = object.__new__(protocol.ReferenceCheckpoint)
        with self.assertRaises(protocol.CheckpointProtocolRefused): invalid.as_dict()
        current = protocol.bootstrap_reference(self.policy, self.contexts["primary"])
        object.__setattr__(current, "_prior", current)
        with self.assertRaises(protocol.CheckpointProtocolRefused): current.as_dict()

    def test_protocol_has_no_process_network_file_or_signing_entry(self):
        with patch("builtins.open", side_effect=AssertionError("file entry")), \
             patch("os.open", side_effect=AssertionError("file entry")), \
             patch("subprocess.Popen", side_effect=AssertionError("process entry")), \
             patch("socket.socket", side_effect=AssertionError("network entry")):
            current = protocol.bootstrap_reference(self.policy, self.contexts["primary"])
            latest = protocol.advance_reference(current, self.contexts["extended"], expected_current_digest_hex=current.digest_hex)
            self.assert_hold(self.compare(self.contexts["primary"], latest))

    def test_complete_qualifier_retains_negative_and_unsafe_controls_and_prior_inputs(self):
        result = q.qualify()
        q.check_cases(result)
        previous = q.prior.inputs()[1]
        self.assertEqual(len(previous), 190)
        self.assertTrue(all(result["input_sha256"][name] == digest for name, digest in previous.items()))
        self.assertEqual(result["refusal_controls"], q.corpus()["refusal_controls"])
        self.assertEqual(set(result["unsafe_controls"]), set(q.corpus()["unsafe_controls"]))
        self.assertTrue(result["unsafe_controls"]["fork_from_old_reference"]["different_heads"])
        self.assertEqual(result["boundary"]["protocol_worker_calls"], 0)
        self.assertEqual(result["boundary"]["new_core_source_outcomes"], 0)
