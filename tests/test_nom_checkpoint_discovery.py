"""Minimum, full-opening and stale-candidate controls; never work permission."""
import ast
import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_checkpoint_discovery as discovery, nom_checkpoint_protocol as protocol
from scripts import qualify_nom_checkpoint_discovery as q


class NoMCheckpointDiscoveryControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy, cls.contexts, cls.retained, cls.refs = q.fixture_contexts()
        cls.openings = {name: discovery.checkpoint_opening(value) for name, value in cls.refs.items()}
        cls.read = discovery.checkpoint_read(cls.refs["initial"], challenge_hex="d1"*32)
        cls.later = discovery.checkpoint_read(cls.refs["latest"], challenge_hex="d1"*32)

    def inspect(self, local="primary", minimum=None, candidate="latest"):
        selected = self.read if minimum is None else minimum
        opening = None if candidate is None else self.openings[candidate]
        wire = discovery.unavailable_reply(selected) if opening is None else discovery.discovery_reply(selected, opening)
        result = discovery.inspect_discovery(self.contexts[local], selected, wire, opening)
        self.assert_hold(result)
        return result

    def assert_hold(self, result):
        self.assertEqual((result["state"], result["recovery_action"], result["application"], result["core"]),
            ("HOLD", "NONE", "NO-GO", "NO-GO"))
        self.assertEqual(result["worker_calls"], 0)
        self.assertIs(result["disclosure_possible"], True)
        self.assertEqual(result["work_outcome"], "UNKNOWN")
        self.assertTrue(all(row["outcome"] == "UNKNOWN" for row in result["effective_charged_work"]))
        for flag in ("new_work_allowed", "automatic_retry", "replenish_work", "replacement_original_allowed", "automatic_bootstrap"):
            self.assertIs(result[flag], False)
        self.assertEqual(result["candidate_latest"], "NOT_ESTABLISHED")
        self.assertEqual(result["signature_mathematics"], "NOT_PERFORMED")
        for field in ("checkpoint_storage", "atomic_service_cas", "atomic_work_entry", "service_nonrollback"):
            self.assertEqual(result[field], "NOT_IMPLEMENTED")

    def assert_bad_wire(self, wire, selection=None, opening=None):
        selection = self.read if selection is None else selection
        opening = self.openings["latest"] if opening is None else opening
        with self.assertRaises(discovery.CheckpointDiscoveryRefused):
            discovery.inspect_discovery(self.contexts["primary"], selection, wire, opening)

    def test_query_binds_complete_independent_service_minimum_and_opening(self):
        value = self.read.as_dict()
        self.assertEqual(value["service_selection"], self.policy.as_dict())
        self.assertEqual(value["minimum_sequence"], 1)
        self.assertEqual(value["minimum_checkpoint_digest_hex"], self.refs["initial"].digest_hex)
        self.assertEqual(value["minimum_opening_digest_hex"], self.openings["initial"].as_dict()["opening_digest_hex"])
        self.assertNotEqual(value["minimum_opening_digest_hex"], value["minimum_checkpoint_digest_hex"])

    def test_newer_candidate_is_discovered_without_selecting_it_as_current(self):
        before = self.read.canonical_bytes
        result = self.inspect()
        self.assertEqual((result["discovery"], result["candidate_sequence"], result["new_checkpoint_records"]),
            ("NEWER_CANDIDATE", 2, 1))
        self.assertEqual(len(result["effective_charged_work"]), 2)
        self.assertEqual(result["journal_relation"], "LOCAL_BEHIND_CANDIDATE")
        self.assertEqual(self.read.canonical_bytes, before)

    def test_later_minimum_requires_all_known_history_before_a_third_record(self):
        result = self.inspect(minimum=self.later, candidate="tail")
        self.assertEqual((result["minimum_sequence"], result["candidate_sequence"], result["new_checkpoint_records"]), (2, 3, 1))
        self.assertEqual(len(result["effective_charged_work"]), 3)
        wire = json.loads(discovery.discovery_reply(self.later, self.openings["tail"]))
        self.assertEqual(len(wire["checkpoint_lineage"]), 3)
        self.assertEqual(wire["checkpoint_lineage"][:2], self.openings["latest"].as_dict()["checkpoint_lineage"])

    def test_same_minimum_replay_is_idempotent_and_mints_no_permission(self):
        first = self.inspect(candidate="initial")
        second = self.inspect(candidate="initial")
        self.assertEqual(first, second)
        self.assertEqual((first["discovery"], first["new_checkpoint_records"]), ("MINIMUM_CANDIDATE", 0))

    def test_below_minimum_candidate_refuses_without_changing_selection(self):
        before = self.later.canonical_bytes
        with self.assertRaises(discovery.CheckpointDiscoveryRefused):
            discovery.discovery_reply(self.later, self.openings["initial"])
        self.assertEqual(self.later.canonical_bytes, before)

    def test_sibling_after_selected_later_minimum_refuses(self):
        with self.assertRaises(discovery.CheckpointDiscoveryRefused):
            discovery.discovery_reply(self.later, self.openings["sibling"])
        self.assertEqual(self.later.as_dict()["minimum_sequence"], 2)

    def test_sibling_candidates_after_same_old_minimum_still_match(self):
        first = self.inspect()
        second = self.inspect(candidate="sibling")
        self.assertEqual(first["candidate_sequence"], second["candidate_sequence"])
        self.assertNotEqual(first["candidate_checkpoint_digest_hex"], second["candidate_checkpoint_digest_hex"])
        self.assertEqual(first["candidate_latest"], second["candidate_latest"])

    def test_a_missing_lineage_record_cannot_be_replaced_by_a_later_counter(self):
        value = json.loads(discovery.discovery_reply(self.read, self.openings["tail"]))
        value["checkpoint_lineage"].pop(1)
        self.assert_bad_wire(codec._canonical(value), opening=self.openings["tail"])

    def test_reordered_lineage_or_replaced_parent_digest_refuses(self):
        original = json.loads(discovery.discovery_reply(self.read, self.openings["latest"]))
        changed = copy.deepcopy(original)
        changed["checkpoint_lineage"].reverse()
        self.assert_bad_wire(codec._canonical(changed))
        changed = copy.deepcopy(original)
        changed["checkpoint_lineage"][1]["checkpoint"]["previous_checkpoint_digest_hex"] = "81"*32
        self.assert_bad_wire(codec._canonical(changed))

    def test_known_source_view_is_bound_even_when_checkpoint_header_digest_matches(self):
        changed = protocol.bootstrap_reference(self.policy, self.contexts["source_rotation"])
        self.assertEqual(changed.digest_hex, self.refs["initial"].digest_hex)
        opening = discovery.checkpoint_opening(changed)
        self.assertNotEqual(opening.as_dict()["opening_digest_hex"], self.openings["initial"].as_dict()["opening_digest_hex"])
        with self.assertRaises(discovery.CheckpointDiscoveryRefused): discovery.discovery_reply(self.read, opening)

    def test_positive_headers_without_actual_complete_opening_refuse(self):
        wire = discovery.discovery_reply(self.read, self.openings["latest"])
        with self.assertRaises(discovery.CheckpointDiscoveryRefused):
            discovery.inspect_discovery(self.contexts["primary"], self.read, wire)

    def test_public_descriptor_dict_is_not_an_actual_opening_capability(self):
        value = self.openings["latest"].as_dict()
        with self.assertRaises(discovery.CheckpointDiscoveryRefused): discovery.checkpoint_opening(value)
        wire = discovery.discovery_reply(self.read, self.openings["latest"])
        self.assert_bad_wire(wire, opening=value)

    def test_recovered_long_bytes_cannot_fill_missing_original_for_a_new_opening(self):
        partial = q.prior.prior.prior.prior.from_journal(
            b"".join(self.retained.journal_bytes.splitlines(keepends=True)[:7]), challenge_hex="a1"*32)
        self.assertIsNotNone(partial.partial_hold.selection()["recovered_long_signature_hex"])
        self.assertIsNone(partial.partial_hold.selection()["original_long_hex"])
        with self.assertRaises(ValueError): q.prior.prior.select_context(partial)

    def test_local_ahead_preserves_larger_complete_unknown_charge_list(self):
        result = self.inspect(local="third")
        self.assertEqual(result["journal_relation"], "LOCAL_AHEAD_CANDIDATE")
        self.assertEqual(len(result["effective_charged_work"]), 3)
        self.assertEqual(result["candidate_sequence"], 2)

    def test_divergent_local_journal_refuses_despite_a_valid_candidate_prefix(self):
        with self.assertRaises(discovery.CheckpointDiscoveryRefused): self.inspect(local="divergent")

    def test_outage_preserves_newer_minimum_unknown_charges(self):
        before = self.later.canonical_bytes
        result = self.inspect(minimum=self.later, candidate=None)
        self.assertIsNone(result["candidate_checkpoint_digest_hex"])
        self.assertIsNone(result["candidate_sequence"])
        self.assertEqual(len(result["effective_charged_work"]), 2)
        self.assertEqual(self.later.canonical_bytes, before)

    def test_outage_preserves_local_work_ahead_of_the_selected_minimum(self):
        result = self.inspect(local="third", candidate=None)
        self.assertEqual(len(result["effective_charged_work"]), 3)
        self.assertEqual(result["minimum_sequence"], 1)

    def test_outage_does_not_accept_a_cached_positive_opening_as_fallback(self):
        self.assert_bad_wire(discovery.unavailable_reply(self.read))
        self.assertEqual(self.refs["latest"].as_dict()["sequence"], 2)

    def test_absence_and_extra_permission_observations_are_not_selected(self):
        value = json.loads(discovery.unavailable_reply(self.read))
        value["observation"] = "ABSENT"
        self.assert_bad_wire(codec._canonical(value))
        value = json.loads(discovery.discovery_reply(self.read, self.openings["latest"]))
        value["new_work_allowed"] = True
        self.assert_bad_wire(codec._canonical(value))

    def test_unavailable_historical_source_cannot_erase_candidate_work(self):
        result = self.inspect(local="unavailable")
        self.assertEqual(len(result["effective_charged_work"]), 2)
        self.assertEqual(result["source_currentness"], "UNFILLED")

    def test_source_rotations_epoch_and_challenge_do_not_replenish_work(self):
        for local in ("root_rotation", "source_rotation", "checkpoint_rotation", "new_epoch", "new_challenge"):
            result = self.inspect(local=local)
            self.assertEqual(len(result["effective_charged_work"]), 2)
            self.assertEqual(result["minimum_sequence"], 1)

    def test_fresh_challenge_changes_preimage_and_refuses_old_reply(self):
        fresh = discovery.checkpoint_read(self.refs["initial"], challenge_hex="d2"*32)
        old_wire = discovery.discovery_reply(self.read, self.openings["latest"])
        fresh_wire = discovery.discovery_reply(fresh, self.openings["latest"])
        self.assertNotEqual(discovery.response_message_digest(self.read, old_wire, self.openings["latest"]),
            discovery.response_message_digest(fresh, fresh_wire, self.openings["latest"]))
        self.assert_bad_wire(old_wire, selection=fresh)

    def test_fresh_challenge_old_candidate_still_matches_without_currentness(self):
        fresh = discovery.checkpoint_read(self.refs["initial"], challenge_hex="d2"*32)
        result = self.inspect(minimum=fresh, candidate="initial")
        self.assertEqual(result["candidate_sequence"], 1)
        self.assertEqual(result["candidate_latest"], "NOT_ESTABLISHED")

    def test_coherent_restore_of_minimum_local_and_reply_still_matches(self):
        restored = discovery.checkpoint_read(self.refs["initial"], challenge_hex="d3"*32)
        result = self.inspect(minimum=restored, candidate="initial")
        self.assertEqual(len(result["effective_charged_work"]), 1)
        self.assertEqual(len(self.refs["latest"].as_dict()["charged_work"]), 2)

    def test_unsigned_candidate_frame_can_be_forged_but_does_not_authorize_work(self):
        wire = discovery.discovery_reply(self.read, self.openings["latest"])
        forged = codec._canonical(json.loads(wire))
        result = discovery.inspect_discovery(self.contexts["primary"], self.read, forged, self.openings["latest"])
        self.assert_hold(result)
        self.assertEqual(result["response_authentication"], "NOT_PERFORMED; UNSIGNED REFERENCE CANDIDATE")

    def test_factories_frozen_objects_and_views_do_not_adopt_peer_selections(self):
        for cls in (discovery.NoMCheckpointReadSelection, discovery.NoMCheckpointEvidenceOpening):
            with self.assertRaises(TypeError): cls()
        with self.assertRaises(FrozenInstanceError): self.read._wire = b"{}"
        with self.assertRaises(FrozenInstanceError): self.openings["latest"]._candidate = self.refs["initial"]
        query = self.read.as_dict()
        query["minimum_sequence"] = 9
        value = self.openings["latest"].as_dict()
        value["checkpoint_lineage"].clear()
        self.assertEqual(self.read.as_dict()["minimum_sequence"], 1)
        self.assertEqual(len(self.openings["latest"].as_dict()["checkpoint_lineage"]), 2)

    def test_numeric_aliases_and_service_epoch_cannot_change_query_or_reply(self):
        query = self.read.as_dict()
        for bad in (True, 1.0, "1", 0):
            forged = object.__new__(discovery.NoMCheckpointReadSelection)
            object.__setattr__(forged, "_minimum", self.refs["initial"])
            object.__setattr__(forged, "_wire", codec._canonical(dict(query, minimum_sequence=bad)))
            with self.assertRaises(discovery.CheckpointDiscoveryRefused): forged.as_dict()
        for change in (dict(service_id_hex="c2"*32), dict(service_epoch=2), dict(checkpoint_key_hex="82"*32)):
            values = dict(service_id_hex="c1"*32, service_epoch=1,
                checkpoint_key_hex=self.policy.as_dict()["checkpoint_key_hex"])
            selected = protocol.select_service(self.contexts["primary"], **dict(values, **change))
            opening = discovery.checkpoint_opening(protocol.bootstrap_reference(selected, self.contexts["primary"]))
            with self.assertRaises(discovery.CheckpointDiscoveryRefused): discovery.discovery_reply(self.read, opening)
        for bad in (True, 2.0, "2", 0):
            value = json.loads(discovery.discovery_reply(self.read, self.openings["latest"]))
            value["checkpoint_head"]["sequence"] = bad
            self.assert_bad_wire(codec._canonical(value))

    def test_wire_bounds_depth_canonical_bytes_and_duplicate_fields_refuse(self):
        wire = discovery.discovery_reply(self.read, self.openings["latest"])
        malformed = [wire+b"\n", b" "+wire, b"", None, b"\xff", b"x"*(discovery.MAX_WIRE_BYTES+1),
            b"["*13+b"]"*13, wire.replace(b"{", b'{"schema":"duplicate",', 1)]
        for value in malformed: self.assert_bad_wire(value)

    def test_corrupt_and_cyclic_openings_cannot_supply_an_unbounded_history(self):
        forged = object.__new__(protocol.ReferenceCheckpoint)
        object.__setattr__(forged, "_policy", self.policy)
        object.__setattr__(forged, "_context", self.contexts["primary"])
        object.__setattr__(forged, "_prior", forged)
        with self.assertRaises(discovery.CheckpointDiscoveryRefused): discovery.checkpoint_opening(forged)
        empty = object.__new__(discovery.NoMCheckpointEvidenceOpening)
        with self.assertRaises(discovery.CheckpointDiscoveryRefused): empty.as_dict()
        bounded = protocol.select_service(self.contexts["primary"], service_id_hex="c1"*32, service_epoch=1,
            checkpoint_key_hex=self.policy.as_dict()["checkpoint_key_hex"], max_snapshots=1)
        initial = protocol.bootstrap_reference(bounded, self.contexts["primary"])
        with self.assertRaises(ValueError): protocol.advance_reference(initial, self.contexts["extended"],
            expected_current_digest_hex=initial.digest_hex)

    def test_extension_without_new_charge_advances_a_record_but_grants_no_allowance(self):
        result = self.inspect(minimum=self.later, candidate="uncharged")
        self.assertEqual((result["candidate_sequence"], result["new_checkpoint_records"]), (3, 1))
        self.assertEqual(len(result["effective_charged_work"]), 2)

    def test_response_preimage_has_a_new_domain_without_signer_or_io(self):
        wire = discovery.discovery_reply(self.read, self.openings["latest"])
        expected = dict(schema=discovery.MESSAGE_SCHEMA, purpose="checkpoint-response-preimage-only",
            query=self.read.as_dict(), reply=json.loads(wire))
        digest = discovery.response_message_digest(self.read, wire, self.openings["latest"])
        self.assertEqual(digest, authority._digest(discovery.MESSAGE_DOMAIN, codec._canonical(expected)))
        self.assertNotEqual(digest, authority._digest(protocol.QUERY_DOMAIN, codec._canonical(expected)))
        module = ast.parse((Path(__file__).resolve().parents[1]/"offline_session/nom_checkpoint_discovery.py").read_text("ascii"))
        imports = {node.names[0].name.split('.')[0] for node in ast.walk(module) if isinstance(node, ast.Import)}
        imports |= {node.module.split('.')[0] for node in ast.walk(module)
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module}
        self.assertFalse(imports & {"subprocess", "socket", "sqlite3", "requests", "http", "os"})
        calls = {node.func.id for node in ast.walk(module) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        calls |= {node.func.attr for node in ast.walk(module)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & {"open", "exec", "eval", "sign", "run_public_worker"})

    def test_complete_qualifier_retains_all_previous_inputs_refusals_and_unsafe_controls(self):
        value = q.qualify()
        q.check_cases(value)
        self.assertEqual(len(value["input_sha256"]), 201)
        self.assertEqual(value["refusal_controls"], q.corpus()["refusal_controls"])
        self.assertEqual(len(value["unsafe_controls"]), 4)
        _, preserved = q.prior.inputs()
        self.assertEqual(len(preserved), 196)
        self.assertTrue(all(value["input_sha256"][name] == digest for name, digest in preserved.items()))
        self.assertEqual(value["boundary"]["discovery_worker_calls"], 0)
        self.assertEqual(value["boundary"]["new_core_source_outcomes"], 0)


if __name__ == "__main__":
    unittest.main()
