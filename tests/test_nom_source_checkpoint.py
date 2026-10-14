"""Selected historical role signatures never authorize source truth or restore."""
import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_capsule_query as binding, nom_recovery as recovery
from offline_session import nom_source_checkpoint as framing
from qualification.nom_source_checkpoint_verifier import PublicSourceCheckpointCheck
from scripts import qualify_nom_source_checkpoint as q


class NoMSourceCheckpointControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.unsigned, cls.retained = q.retained_fixture()
        cls.expectations = q.fixture_expectations()
        cls.fixture = q.public_fixture()

    def setUp(self):
        self.expected = self.expectations["primary"]
        self.vector = self.fixture["positive_vectors"]["primary"]
        self.wire = q.signed_envelope(self.expected, self.vector)

    def positive(self, value):
        return framing.expected_result(framing.request_digest(value))

    def refuse_before_callback(self, wire, expected=None):
        calls = []
        def callback(value):
            calls.append(value); return self.positive(value)
        with self.assertRaises(framing.SourceCheckpointRefused):
            framing.verify_selected_transcript(self.expected if expected is None else expected, wire, verifier=callback)
        self.assertEqual(calls, [])

    def assert_hold(self, selected):
        value = selected.review()
        self.assertEqual((value["state"], value["recovery_action"], value["application"], value["core"]),
                         ("HOLD", "NONE", "NO-GO", "NO-GO"))
        self.assertEqual((value["root_provisioning"], value["source_currentness"], value["checkpoint_nonrollback"]),
                         ("UNFILLED", "UNFILLED", "UNFILLED"))
        self.assertEqual(value["operational_source_authentication"], "NOT_PERFORMED")
        self.assertEqual((value["checkpoint_storage"], value["atomic_entry"]), ("NOT_IMPLEMENTED", "NOT_IMPLEMENTED"))
        self.assertFalse(value["automatic_retry"]); self.assertFalse(value["replenish_work"])
        self.assertFalse(value["replacement_original_allowed"])

    def declaration(self, **updates):
        value = self.expected._declaration.as_dict()
        selected = dict(network_selection=value["network_selection"], root_key_hex=value["root_key_hex"],
            source_response_key_hex=value["source_response_key_hex"],
            consumer_checkpoint_key_hex=value["consumer_checkpoint_key_hex"], epoch=value["declaration_epoch"])
        selected.update(updates); return framing.select_declaration(**selected)

    def changed_consumer(self, **updates):
        selected = q.prior.read_selection(self.retained)
        selected["network_selection"] = self.expected._declaration.as_dict()["network_selection"]
        selected["consumer_selection"].update(updates)
        bound = binding.bind_read_query(self.retained, authority.read_query(**selected))
        return framing.select_transcript(self.expected._declaration, bound, q.prior.claim_wire(bound))

    def rewrite_charge(self):
        rows = [json.loads(line)["event"] for line in self.retained.journal_bytes.splitlines()]
        rows.append(dict(kind="recovery-admitted")); head = "00" * 32; wire = b""
        for index, event in enumerate(rows, 1):
            row = dict(schema="ptlc-nom-recovery-log-v1", sequence=index, previous_hash_hex=head, event=event)
            row["hash_hex"] = recovery.digest(b"ptlc-nom-log-v1", row); head = row["hash_hex"]
            wire += recovery.canonical(row) + b"\n"
        return q.prior.prior.from_journal(wire, challenge_hex="a1" * 32)

    def test_complete_retained_context_precedes_incoming_role_signatures(self):
        request = framing.request(self.expected, self.wire)
        self.assertEqual(request, self.vector["request"])
        self.assertEqual(self.expected._binding.as_dict()["charged_work"], self.retained.partial_hold.selection()["charged_work"])

    def test_all_seven_fixture_contexts_recompute_from_actual_public_originals(self):
        self.assertEqual(set(self.expectations), set(self.fixture["positive_vectors"]))
        for name, selected in self.expectations.items():
            vector = self.fixture["positive_vectors"][name]
            self.assertEqual(framing.request(selected, q.signed_envelope(selected, vector)), vector["request"])
            self.assert_hold(selected)

    def test_opaque_custody_hashes_commit_full_charged_list_without_opening_it(self):
        bound = self.expected._binding.as_dict(); checkpoint = self.expected.as_dict()["checkpoint_statement"]
        self.assertEqual(checkpoint["charged_work_digest_hex"], authority._digest(framing.WORK_DOMAIN, codec._canonical(bound["charged_work"])))
        self.assertEqual(checkpoint["charged_work_count"], len(bound["charged_work"]))
        self.assertEqual(checkpoint["capsule_sha256"], self.retained.digest_hex)
        self.assert_hold(self.expected)

    def test_missing_actual_long_original_cannot_be_filled_by_signature_or_recovered_result(self):
        lines = self.retained.journal_bytes.splitlines(keepends=True)
        # The earlier prefix has no charged recovery and cannot form a partial
        # HOLD projection. The two charged prefixes have no long original.
        with self.assertRaises(ValueError):
            q.prior.prior.from_journal(b"".join(lines[:4]), challenge_hex="a1" * 32)
        for count in (6, 7):
            retained = q.prior.prior.from_journal(b"".join(lines[:count]), challenge_hex="a1" * 32)
            self.assertIsNone(retained.partial_hold.selection()["original_long_hex"])
            with self.assertRaises(ValueError): q.select_context(retained)

    def test_root_key_hash_is_raw_key_commitment_separate_from_declaration_digest(self):
        d = self.expected._declaration
        self.assertEqual(d.as_dict()["network_selection"]["provisioning_root_digest_hex"], framing.root_key_digest(d.as_dict()["root_key_hex"]))
        self.assertNotEqual(d.digest_hex, d.as_dict()["network_selection"]["provisioning_root_digest_hex"])

    def test_root_key_commitment_mismatch_refuses(self):
        network = self.expected._declaration.as_dict()["network_selection"]; network["provisioning_root_digest_hex"] = "00" * 32
        with self.assertRaises(framing.SourceCheckpointRefused): self.declaration(network_selection=network)

    def test_every_independent_network_pin_must_match_retained_read(self):
        for field in authority._NETWORK[4:]:
            network = self.expected._declaration.as_dict()["network_selection"]; network[field] = "81" * 32
            with self.assertRaises(framing.SourceCheckpointRefused):
                declaration = self.declaration(network_selection=network)
                framing.select_transcript(declaration, self.expected._binding, self.expected._claim_wire)

    def test_distinct_role_encodings_are_required_without_asserting_distinct_custodians(self):
        d = self.expected._declaration.as_dict()
        for role in ("source_response_key_hex", "consumer_checkpoint_key_hex"):
            with self.assertRaises(framing.SourceCheckpointRefused): self.declaration(**{role:d["root_key_hex"]})
        with self.assertRaises(framing.SourceCheckpointRefused): self.declaration(consumer_checkpoint_key_hex=d["source_response_key_hex"])

    def test_declaration_epoch_exact_positive_integer_and_shape_bounds(self):
        for bad in (True, False, 0, -1, 1.0, "1", 9007199254740992, None):
            with self.assertRaises(framing.SourceCheckpointRefused): self.declaration(epoch=bad)
        for field in ("root_key_hex", "source_response_key_hex", "consumer_checkpoint_key_hex"):
            for bad in ("AB" * 32, "00" * 31, b"00" * 32, None):
                with self.assertRaises(framing.SourceCheckpointRefused): self.declaration(**{field:bad})

    def test_curve_membership_is_deliberately_not_claimed_by_python_shape_codec(self):
        d = self.declaration(source_response_key_hex="00" * 32)
        selected = framing.select_transcript(d, self.expected._binding, self.expected._claim_wire)
        self.assertEqual(selected.as_dict()["declaration"]["source_response_key_hex"], "00" * 32)
        self.assert_hold(selected)

    def test_every_statement_field_differs_from_selection_before_callback(self):
        packet = json.loads(self.wire)
        for object_name in ("declaration", "source_statement", "checkpoint_statement"):
            for field in packet[object_name]:
                changed = copy.deepcopy(packet); changed[object_name][field] = "81" * 32
                self.refuse_before_callback(codec._canonical(changed))

    def test_extra_and_missing_fields_in_every_selected_object_refuse_before_callback(self):
        packet = json.loads(self.wire)
        for path in ((), ("declaration",), ("declaration", "network_selection"), ("source_statement",), ("checkpoint_statement",)):
            at = packet
            for name in path: at = at[name]
            for field in at:
                changed = copy.deepcopy(packet); target = changed
                for name in path: target = target[name]
                del target[field]; self.refuse_before_callback(codec._canonical(changed))
            changed = copy.deepcopy(packet); target = changed
            for name in path: target = target[name]
            target["admitted"] = True; self.refuse_before_callback(codec._canonical(changed))

    def test_float_and_boolean_aliases_cannot_equal_selected_integer_context(self):
        packet = json.loads(self.wire)
        for obj, field in (("declaration", "declaration_epoch"), ("checkpoint_statement", "journal_sequence"),
                           ("checkpoint_statement", "charged_work_count"), ("checkpoint_statement", "observer_retention_sequence")):
            for bad in (float(packet[obj][field]), True):
                changed = copy.deepcopy(packet); changed[obj][field] = bad
                self.refuse_before_callback(codec._canonical(changed))
        changed = copy.deepcopy(packet); changed["checkpoint_statement"]["disclosure_possible"] = 1
        self.refuse_before_callback(codec._canonical(changed))

    def test_malformed_depth_noncanonical_duplicate_and_size_refuse_before_callback(self):
        for wire in (b"", b"[" * 13 + b"]" * 13, b"x" * 8193, self.wire+b"\n", b" "+self.wire,
                     self.wire.replace(b'"schema":', b'"\\u0073chema":'),
                     self.wire.replace(b'{', b'{"schema":"duplicate",', 1), None, bytearray(self.wire)):
            self.refuse_before_callback(wire)

    def test_each_signature_has_exact_lowercase_public_encoding(self):
        packet = json.loads(self.wire)
        for field in ("root_signature_hex", "source_signature_hex", "checkpoint_signature_hex"):
            for bad in ("AB" * 64, "00" * 63, "zz" * 64, 1, None):
                changed = copy.deepcopy(packet); changed[field] = bad; self.refuse_before_callback(codec._canonical(changed))

    def test_packager_does_not_accept_private_inputs_or_nonbytes_signature_shapes(self):
        signatures = dict(root_signature=b"\0" * 64, source_signature=b"\0" * 64, checkpoint_signature=b"\0" * 64)
        for field in signatures:
            for bad in (b"\0" * 63, bytearray(b"\0" * 64), "00" * 64, None):
                with self.assertRaises(framing.SourceCheckpointRefused): framing.envelope(self.expected, **dict(signatures, **{field:bad}))
        with self.assertRaises(TypeError): framing.envelope(self.expected, **signatures, private_key=b"\0" * 32)

    def test_callback_receives_defensive_request_copy(self):
        old = self.expected.canonical_bytes
        def callback(value):
            result = self.positive(value); value["checkpoint_statement"]["charged_work_count"] = 99; return result
        self.assertIs(framing.verify_selected_transcript(self.expected, self.wire, verifier=callback), self.expected)
        self.assertEqual(self.expected.canonical_bytes, old)

    def test_callback_flags_schema_digest_and_extra_privileges_all_refuse(self):
        for field in ("root_signature_valid", "source_signature_valid", "checkpoint_signature_valid", "schema", "request_digest_hex"):
            for bad in (False, 1, None, "00" * 32):
                def callback(value, field=field, bad=bad):
                    result = self.positive(value); result[field] = bad; return result
                with self.assertRaises(framing.SourceCheckpointRefused): framing.verify_selected_transcript(self.expected, self.wire, verifier=callback)
        for result in (None, [], {}, dict(self.vector["result"], admitted=True)):
            with self.assertRaises(framing.SourceCheckpointRefused): framing.verify_selected_transcript(self.expected, self.wire, verifier=lambda _:result)

    def test_callback_exceptions_are_sanitized_and_cancellation_propagates(self):
        def unavailable(_): raise RuntimeError("synthetic unavailable detail")
        with self.assertRaisesRegex(framing.SourceCheckpointRefused, "selected NoM public signature check unavailable") as caught:
            framing.verify_selected_transcript(self.expected, self.wire, verifier=unavailable)
        self.assertNotIn("synthetic unavailable detail", str(caught.exception))
        def cancel(_): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): framing.verify_selected_transcript(self.expected, self.wire, verifier=cancel)

    def test_mutation_of_selected_context_during_callback_refuses(self):
        selected = q.select_context(self.retained)
        def callback(value):
            result = self.positive(value)
            object.__setattr__(selected, "_claim_wire", q.prior.claim_wire(selected._binding, status="unknown"))
            return result
        with self.assertRaises(framing.SourceCheckpointRefused): framing.verify_selected_transcript(selected, self.wire, verifier=callback)

    def test_forged_callback_positive_can_accept_zero_signatures_but_stays_hold(self):
        wire = framing.envelope(self.expected, root_signature=b"\0" * 64, source_signature=b"\0" * 64, checkpoint_signature=b"\0" * 64)
        selected = framing.verify_selected_transcript(self.expected, wire, verifier=self.positive)
        self.assertIs(selected, self.expected); self.assert_hold(selected)

    def test_self_selected_test_root_is_not_independently_provisioned_authority(self):
        selected = self.expectations["root_rotation"]
        wire = q.signed_envelope(selected, self.fixture["positive_vectors"]["root_rotation"])
        selected = framing.verify_selected_transcript(selected, wire, verifier=self.positive)
        self.assertEqual(selected.review()["root_provisioning"], "UNFILLED"); self.assert_hold(selected)

    def test_coherent_old_signed_tuple_replays_without_currentness_or_restore_authority(self):
        for _ in range(2): self.assertIs(framing.verify_selected_transcript(self.expected, self.wire, verifier=self.positive), self.expected)
        self.assert_hold(self.expected)
        self.assertEqual(self.expected.as_dict()["checkpoint_statement"]["work_outcome"], "UNKNOWN")

    def test_alternate_valid_signature_changes_request_digest_and_requires_its_own_result(self):
        packet = json.loads(self.wire); packet["source_signature_hex"] = self.fixture["alternate_source_signature_hex"]
        wire = codec._canonical(packet)
        self.assertNotEqual(framing.request_digest(framing.request(self.expected, wire)), self.vector["result"]["request_digest_hex"])
        with self.assertRaises(framing.SourceCheckpointRefused): framing.verify_selected_transcript(self.expected, wire, verifier=lambda _:self.vector["result"])
        self.assertIs(framing.verify_selected_transcript(self.expected, wire, verifier=self.positive), self.expected)

    def test_root_source_checkpoint_rotation_and_epoch_preserve_existing_work_scope(self):
        old = self.expected.as_dict()["checkpoint_statement"]
        for name in ("root_rotation", "source_rotation", "checkpoint_rotation", "new_epoch"):
            new = self.expectations[name].as_dict()["checkpoint_statement"]
            self.assertEqual(new["work_scope_digest_hex"], old["work_scope_digest_hex"])
            self.assertEqual(new["charged_work_digest_hex"], old["charged_work_digest_hex"])
            self.assertNotEqual(new["declaration_digest_hex"], old["declaration_digest_hex"])
            self.refuse_before_callback(q.signed_envelope(self.expectations[name], self.fixture["positive_vectors"][name]))

    def test_new_query_challenge_changes_source_statement_without_minting_checkpoint(self):
        new = self.expectations["new_challenge"]
        self.assertNotEqual(new.as_dict()["source_statement"], self.expected.as_dict()["source_statement"])
        self.assertEqual(new.as_dict()["checkpoint_statement"], self.expected.as_dict()["checkpoint_statement"])
        self.refuse_before_callback(q.signed_envelope(new, self.fixture["positive_vectors"]["new_challenge"]))

    def test_unavailable_claim_preserves_every_unknown_charge(self):
        selected = self.expectations["unavailable"]
        self.assertEqual(selected.review()["claim_coverage"], "UNAVAILABLE_CLAIM")
        self.assertEqual(selected.as_dict()["checkpoint_statement"], self.expected.as_dict()["checkpoint_statement"])
        self.assert_hold(selected)

    def test_observer_retention_counters_are_separate_caller_assertions(self):
        checkpoint = self.expected.as_dict()["checkpoint_statement"]
        self.assertNotEqual(checkpoint["observer_retention_sequence"], checkpoint["journal_sequence"])
        changed = self.changed_consumer(retention_sequence=1)
        self.assertEqual(changed.as_dict()["checkpoint_statement"]["observer_retention_sequence"], 1)
        self.assertEqual(changed.as_dict()["checkpoint_statement"]["journal_sequence"], checkpoint["journal_sequence"])
        self.assert_hold(changed)

    def test_consumer_incarnation_and_external_checkpoint_are_separately_bound(self):
        for field in ("consumer_incarnation_hex", "external_checkpoint_digest_hex", "retention_head_digest_hex", "retention_selection_digest_hex"):
            changed = self.changed_consumer(**{field:"85" * 32})
            self.assertNotEqual(changed.canonical_bytes, self.expected.canonical_bytes)
            self.assertEqual(changed._binding.as_dict()["charged_work"], self.expected._binding.as_dict()["charged_work"])
            self.assert_hold(changed)

    def test_false_disclosure_cannot_discard_existing_possible_disclosure(self):
        with self.assertRaises(binding.CapsuleQueryRefused): self.changed_consumer(disclosure_possible=False)

    def test_added_unknown_charge_binds_new_checkpoint_without_resetting_work(self):
        retained = self.rewrite_charge(); changed = q.select_context(retained)
        before = self.expected.as_dict()["checkpoint_statement"]; after = changed.as_dict()["checkpoint_statement"]
        self.assertEqual(after["charged_work_count"], before["charged_work_count"] + 1)
        self.assertEqual(after["work_scope_digest_hex"], before["work_scope_digest_hex"])
        self.assertNotEqual(after["charged_work_digest_hex"], before["charged_work_digest_hex"])
        self.assertEqual(changed._binding.as_dict()["charged_work"][:1], self.expected._binding.as_dict()["charged_work"])
        self.refuse_before_callback(self.wire, expected=changed); self.assert_hold(changed)

    def test_unsigned_outer_rewrap_cannot_reuse_old_source_checkpoint_signatures(self):
        retained = self.rewrite_charge(); bound = binding.bind_read_query(retained, self.expected._binding._query)
        claim = json.loads(self.expected._claim_wire); claim["binding_digest_hex"] = bound.digest_hex
        changed = framing.select_transcript(self.expected._declaration, bound, codec._canonical(claim))
        self.assertNotEqual(changed.as_dict()["source_statement"], self.expected.as_dict()["source_statement"])
        self.assertNotEqual(changed.as_dict()["checkpoint_statement"], self.expected.as_dict()["checkpoint_statement"])
        self.refuse_before_callback(self.wire, expected=changed); self.assert_hold(changed)

    def test_direct_construction_wrong_types_and_detached_dictionaries_refuse(self):
        with self.assertRaises(TypeError): framing.NoMRoleDeclaration()
        with self.assertRaises(TypeError): framing.NoMSourceCheckpointSelection()
        for value in (None, {}, object(), self.expected.canonical_bytes):
            with self.assertRaises(framing.SourceCheckpointRefused): framing.select_transcript(value, self.expected._binding, self.expected._claim_wire)
            with self.assertRaises(framing.SourceCheckpointRefused): framing.select_transcript(self.expected._declaration, value, self.expected._claim_wire)
            with self.assertRaises(framing.SourceCheckpointRefused): framing.request(value, self.wire)

    def test_immutable_factories_defensive_views_and_incomplete_instances(self):
        old = self.expected.canonical_bytes
        with self.assertRaises(FrozenInstanceError): self.expected._claim_wire = b"{}"
        with self.assertRaises(FrozenInstanceError): self.expected._declaration._wire = b"{}"
        changed = self.expected.as_dict(); changed["checkpoint_statement"]["charged_work_count"] = 99
        self.assertEqual(self.expected.canonical_bytes, old)
        for cls in (framing.NoMRoleDeclaration, framing.NoMSourceCheckpointSelection):
            with self.assertRaises(framing.SourceCheckpointRefused): object.__new__(cls).as_dict()

    def test_pure_selection_and_fake_callback_have_no_process_path_or_storage_entry(self):
        with patch("subprocess.Popen", side_effect=AssertionError("process entry")), \
             patch("offline_session.nom_capsule.os.open", side_effect=AssertionError("path entry")):
            selected = framing.select_transcript(self.expected._declaration, self.expected._binding, self.expected._claim_wire)
            self.assertIs(framing.verify_selected_transcript(selected, self.wire, verifier=self.positive), selected)
            self.assert_hold(selected)

    def test_measured_public_checker_enforces_complete_result_and_output_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selected-check"; path.write_bytes(b"synthetic public worker selection"); path.chmod(0o700)
            pin = q.sha(path.read_bytes())
            worker = PublicSourceCheckpointCheck(path.resolve(), expected_executable_sha256_hex=pin)
            request = framing.request(self.expected, self.wire); result = self.positive(request)
            with patch("qualification.nom_source_checkpoint_verifier.run_public_worker", return_value=codec._canonical(result)+b"\n") as call:
                self.assertEqual(worker(request), result)
                self.assertEqual(call.call_args.kwargs["max_input_bytes"], 8192)
                self.assertEqual(call.call_args.kwargs["max_output_bytes"], 512)
            for raw in (b"{}", codec._canonical(dict(result, admitted=True)), codec._canonical(result)+b"\n\n"):
                with patch("qualification.nom_source_checkpoint_verifier.run_public_worker", return_value=raw):
                    with self.assertRaises(framing.SourceCheckpointRefused): worker(request)

    def test_public_checker_remeasures_executable_but_is_not_atomic_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "selected-check"; path.write_bytes(b"selected public checker"); path.chmod(0o700)
            worker = PublicSourceCheckpointCheck(path.resolve(), expected_executable_sha256_hex=q.sha(path.read_bytes()))
            path.write_bytes(b"changed checker")
            with patch("qualification.nom_source_checkpoint_verifier.run_public_worker") as call:
                with self.assertRaises(framing.SourceCheckpointRefused): worker(framing.request(self.expected, self.wire))
                call.assert_not_called()
            for timeout in (True, 0, -1, 31, "1"):
                with self.assertRaises(framing.SourceCheckpointRefused): PublicSourceCheckpointCheck(path.resolve(), expected_executable_sha256_hex=q.sha(path.read_bytes()), timeout=timeout)

    def test_manifest_preserves_every_previous_measured_input_and_no_new_core_outcome(self):
        manifest, measured = q.inputs()
        self.assertEqual(len(manifest["preserved_file_sha256"]), 179)
        self.assertEqual(len(measured), 190)
        self.assertEqual(manifest["boundary"]["new_core_source_outcomes"], 0)


if __name__ == "__main__": unittest.main()
