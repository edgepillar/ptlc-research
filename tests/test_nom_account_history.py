"""Bounded raw history comparisons cannot repair source or recovery authority."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec, nom_account_history as history
from offline_session import nom_authority_contract as authority, nom_vm_openings as vm
from offline_session.nom_wire import account_block_hash
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_account_history as qualifier, generate_nom_vm_openings as roles
from scripts.generate_nom_account_history import FIXTURE, corpus, query, windows, packet

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))
DIFF = "DIFFERS_FROM_SELECTION"


class NoMAccountHistoryTests(unittest.TestCase):
    def setUp(self):
        self.case = copy.deepcopy(FIX["source_cases"]["direct-success"])
        self.query = query(self.case)
        self.payload = copy.deepcopy(self.case["history"])
        self.wire = packet(self.query, self.payload)

    def inspect(self, payload=None, expected=None, **options):
        expected = self.query if expected is None else expected
        return history.inspect_history(expected, packet(expected, self.payload if payload is None else payload, **options))

    def report(self, payload=None, role="contract", **options):
        return self.inspect(payload, **options)["history_legs"]["long"][role]

    def refused(self, wire, expected=None):
        with self.assertRaisesRegex(history.NoMHistoryRefused, "^NoM account history refused$"):
            history.inspect_history(self.query if expected is None else expected, wire)

    def assert_no_permission(self, result):
        self.assertEqual((result["recovery_action"], result["application"], result["core"], result["terminal_outcome"]),
                         ("NONE", "NO-GO", "NO-GO", "NOT_ESTABLISHED"))
        for key in ("account_admission", "vm_execution", "source_authentication", "proof_verification",
                    "network_provisioning", "durable_retention"):
            self.assertEqual(result[key], "NOT_PERFORMED")
        for key in ("source_currentness", "canonicality", "finality", "restore_fence", "history_currentness"):
            self.assertEqual(result[key], "UNFILLED")
        self.assertEqual(result["auxiliary_authority_fact"], "NONE")
        self.assertEqual(result["aggregate_work_budget"], "UNSELECTED")
        self.assertEqual(result["atomic_entry"], "NOT_IMPLEMENTED")
        self.assertIs(result["replenish_work"], False)
        self.assertIs(result["replacement_original_allowed"], False)
        self.assertIs(result["retain_original_bytes"], True)
        self.assertIs(result["retain_possible_disclosure"], True)
        self.assertEqual(len(result["unselected_profiles"]), 4)

    def test_all_ten_source_cases_keep_frozen_roles_and_unfilled_authority_boundaries(self):
        for kind, case in FIX["source_cases"].items():
            expected = query(case)
            result = self.inspect(case["history"], expected=expected)
            qualifier.check_result(result, kind)
            self.assert_no_permission(result)

    def test_reclaim_history_includes_failed_unlock_receive_without_relabeling_a_refund(self):
        case = FIX["source_cases"]["unlock-at-expiry-then-reclaim"]
        result = self.inspect(case["history"], expected=query(case))
        for leg, reports in result["history_legs"].items():
            self.assertEqual(reports["contract"]["record_count"], 4)
            self.assertEqual(reports["contract"]["selected_height_coverage"], "MATCH")
            old = result["vm_opening_result"]["legs"][leg]
            self.assertEqual(old["contract_payout"]["parent_child_linkage"], DIFF)
            self.assertEqual(old["contract_payout"]["fixed_asset_and_recipient"], DIFF)
            self.assertEqual(old["unlock_send"]["method_claim"], "Reclaim")
        self.assert_no_permission(result)

    def test_removing_failed_unlock_record_exposes_gap_and_breaks_child_predecessor_link(self):
        case = FIX["source_cases"]["unlock-at-expiry-then-reclaim"]
        payload = copy.deepcopy(case["history"])
        del payload["long"]["contract"][1]
        report = self.report(payload, expected=query(case))
        self.assertEqual(report["missing_heights"], ["2"])
        self.assertEqual(report["selected_height_coverage"], DIFF)
        self.assertEqual(report["ordered_previous_links"], DIFF)

    def test_raw_duplicate_receipts_report_repeated_from_hash_without_admission_proof(self):
        case = FIX["source_cases"]["raw-receive-replay-needs-verifier"]
        result = self.inspect(case["history"], expected=query(case))
        for reports in result["history_legs"].values():
            recipient = reports["recipient"]
            self.assertEqual(recipient["selected_height_coverage"], "MATCH")
            self.assertEqual(recipient["repeated_receive_claims"][0]["indices"], [0, 1])
            self.assertEqual(recipient["repeated_receive_claims"][0]["comparison"], "REPEATED_CLAIM")
            self.assertEqual(recipient["received_marker_proof"], "ABSENT")
            self.assertEqual(recipient["duplicate_receive_admission"], "NOT_PERFORMED")
        self.assert_no_permission(result)

    def test_direct_unlock_height_twenty_one_stays_outside_actual_receipt_height_one(self):
        result = self.inspect()
        for leg, reports in result["history_legs"].items():
            self.assertEqual(reports["selected_unlock_frontier"], "OUTSIDE_SELECTED_WINDOW")
            self.assertEqual(reports["recipient"]["prior_anchor"], "PRIOR_FRONTIER_UNSELECTED")
            self.assertEqual(result["vm_opening_result"]["legs"][leg]["recipient_receipt"]["recipient_account_continuity"], DIFF)
        self.assert_no_permission(result)

    def test_proxy_caller_is_not_a_selected_recipient_frontier(self):
        for kind in ("proxy-funder-success", "proxy-third-success"):
            case = FIX["source_cases"][kind]
            result = self.inspect(case["history"], expected=query(case))
            for reports in result["history_legs"].values():
                self.assertEqual(reports["selected_unlock_frontier"], "DIFFERENT_ACCOUNT_SELECTION")
            self.assert_no_permission(result)

    def test_source_descendants_precede_parent_and_share_exact_acknowledgement(self):
        report = self.report()
        self.assertEqual(report["descendant_placement"]["unassigned_send_indices"], [])
        self.assertTrue(all(item["preceding_children"] == "MATCH" for item in report["descendant_placement"]["receives"]))
        self.assertEqual(report["prior_anchor"], "MATCH")
        self.assertEqual(report["whole_chain_coverage"], "NOT_ESTABLISHED")

    def test_reordered_claims_are_not_sorted_or_repaired_by_consumer(self):
        self.payload["long"]["contract"].reverse()
        report = self.report()
        self.assertEqual(report["selected_height_coverage"], DIFF)
        self.assertEqual(report["ordered_previous_links"], DIFF)
        self.assertEqual([header["computed_hash_hex"] for header in report["headers"]],
                         [account_block_hash(record["block"]) for record in self.payload["long"]["contract"]])
        self.assertEqual(self.payload["long"]["contract"][0]["block"]["height"], "3")

    def test_forked_height_and_duplicated_record_are_diagnostic_conflicts(self):
        self.payload["long"]["contract"].insert(1, copy.deepcopy(self.payload["long"]["contract"][1]))
        report = self.report()
        self.assertEqual(report["duplicate_heights"], ["2"])
        self.assertEqual(report["selected_height_coverage"], DIFF)
        self.assertEqual(report["ordered_previous_links"], DIFF)

    def test_missing_required_parent_payout_and_receipt_remain_distinct_from_missing_heights(self):
        for role, index, name in (("contract", 2, "receive"), ("contract", 1, "payout"), ("recipient", 0, "receipt")):
            payload = copy.deepcopy(self.payload)
            del payload["long"][role][index]
            report = self.report(payload, role=role)
            self.assertEqual(report["required_roles"][name], DIFF)
            self.assertEqual(report["selected_head"], DIFF if name in ("receive", "receipt") else "MATCH")

    def test_advertised_hash_cannot_substitute_for_recomputed_required_header(self):
        record = self.payload["long"]["contract"][1]
        record["block"]["amount"] = "999"
        report = self.report()
        self.assertEqual(report["required_roles"]["payout"], DIFF)
        self.assertEqual(report["headers"][1]["advertised_hash"], DIFF)
        self.assertEqual(report["descendant_placement"]["receives"][1]["preceding_children"], DIFF)

    def test_changes_hash_remains_separate_opaque_claim_even_when_digest_rebuilt(self):
        self.payload["long"]["contract"][1]["changes_hash_hex"] = "55" * 32
        report = self.report()
        self.assertEqual(report["required_roles"]["payout"], "MATCH")
        self.assertEqual(report["headers"][1]["advertised_hash"], "MATCH")
        self.assertIn("OPAQUE", report["headers"][1]["changes_hash"])
        self.assert_no_permission(self.inspect())

    def test_changed_head_anchor_and_account_are_independent_local_selections(self):
        read, selected = authority.read_query(**roles.selection()), roles.selection()
        wires = roles.packet(read, selected, self.case["roles"])
        for field, value in (("head_hash_hex", "55" * 32), ("address_hex", "55" * 20), ("anchor", {"height": "0", "hash_hex": "55" * 32})):
            selected_windows = windows(self.case)
            selected_windows["long"]["contract"][field] = value
            expected = history.history_query(read, *wires, selected_windows)
            report = self.report(expected=expected)
            self.assertEqual(report[{"head_hash_hex": "selected_head", "address_hex": "selected_account_profile", "anchor": "prior_anchor"}[field]], DIFF)
            self.refused(self.wire, expected)

    def test_child_acknowledgement_alias_does_not_match_parent(self):
        block = self.payload["long"]["contract"][1]["block"]
        block["momentum_hash_hex"] = "55" * 32
        report = self.report()
        self.assertEqual(report["ordered_acknowledgements"], DIFF)
        self.assertEqual(report["descendant_placement"]["receives"][1]["preceding_children"], DIFF)

    def test_regressed_account_acknowledgement_is_a_separate_conflict(self):
        self.payload["long"]["contract"][1]["block"]["momentum_height"] = "1"
        self.assertEqual(self.report()["ordered_acknowledgements"], DIFF)

    def test_unassigned_send_and_child_outside_window_are_not_complete_execution(self):
        self.payload["long"]["contract"][2]["block"]["descendant_hashes_hex"] = []
        self.assertEqual(self.report()["descendant_placement"]["unassigned_send_indices"], [1])
        self.payload["long"]["contract"][0]["block"]["descendant_hashes_hex"] = ["55" * 32]
        self.assertEqual(self.report()["descendant_placement"]["receives"][0]["preceding_children"], "CHILDREN_OUTSIDE_SELECTED_WINDOW")

    def test_record_outside_selected_window_is_retained_as_conflict(self):
        self.payload["long"]["contract"][1]["block"]["height"] = "99"
        report = self.report()
        self.assertEqual(report["outside_window_indices"], [1])
        self.assertEqual(report["missing_heights"], ["2"])

    def test_wrong_account_network_version_or_type_is_compared_without_normalizing(self):
        for field, value in (("address_hex", "55" * 20), ("chain_id", "99"), ("version", "2"), ("block_type", "3")):
            payload = copy.deepcopy(self.payload)
            payload["long"]["contract"][1]["block"][field] = value
            self.assertEqual(self.report(payload)["selected_account_profile"], DIFF)

    def test_empty_or_null_window_cannot_be_reported_as_complete_absence(self):
        self.payload["long"]["recipient"] = []
        report = self.report(role="recipient")
        self.assertEqual(report["selected_height_coverage"], DIFF)
        self.assertEqual(report["selected_head"], DIFF)
        self.payload["long"]["recipient"] = None
        self.assertEqual(self.report(role="recipient"), {"opening": "MISSING_WINDOW_CLAIM"})
        self.assert_no_permission(self.inspect())

    def test_unknown_missing_and_contradicted_history_do_not_erase_originals(self):
        for options, label in (({"status": "unknown"}, "UNKNOWN_CLAIM"), ({"missing": True}, "MISSING_HISTORY_CLAIM"),
                               ({"status": "contradicted"}, "BOUND_UNAUTHENTICATED_PAYLOAD")):
            result = self.inspect(**options)
            self.assertEqual(result["history_opening"], label)
            self.assert_no_permission(result)

    def test_payload_commitment_binds_domain_status_window_and_exact_old_bytes(self):
        value = dict(schema=history.PAYLOAD_SCHEMA, query_digest_hex=self.query.digest_hex,
                     status="supported", payload=self.payload)
        digest = history.history_digest(self.query, "supported", self.payload)
        self.assertEqual(digest, hashlib.sha256(b"ptlc-nom-account-history-payload-v1\0" + codec._canonical(value)).hexdigest())
        self.assertNotEqual(digest, history.history_digest(self.query, "contradicted", self.payload))
        self.assertNotEqual(self.query.digest_hex, self.query.as_dict()["read_query_digest_hex"])

    def test_changed_old_claim_base_or_vm_role_requires_new_auxiliary_selection(self):
        selected = roles.selection()
        read = authority.read_query(**selected)
        for options in ({"statuses": {"unlock_send": "contradicted"}}, {"missing_base": ("original_authorization",)},
                        {"missing": ("contract_payout",)}):
            wires = roles.packet(read, selected, self.case["roles"], **options)
            expected = history.history_query(read, *wires, windows(self.case))
            self.assertNotEqual(expected.digest_hex, self.query.digest_hex)
            self.refused(self.wire, expected)
            self.assert_no_permission(self.inspect(expected=expected))

    def test_changed_challenge_restore_selection_or_checkpoint_cannot_reuse_sidecar(self):
        for field in ("challenge", "checkpoint", "consumer"):
            selected = roles.selection()
            if field == "challenge": selected["challenge_hex"] = "55" * 32
            elif field == "checkpoint": selected["checkpoint_selection"]["state_root_hex"] = "55" * 32
            else: selected["consumer_selection"]["external_checkpoint_digest_hex"] = "55" * 32
            self.refused(self.wire, query(self.case, selected))

    def test_framing_has_no_implicit_authority_status_or_recovery_fields(self):
        value = json.loads(self.wire)
        for field in ("verified", "recovery_action", "proof", "source_identity"):
            changed = copy.deepcopy(value)
            changed[field] = True
            self.refused(codec._canonical(changed))

    def test_uncommitted_payload_digest_schema_status_or_query_change_refuses(self):
        for field, value in (("evidence_digest_hex", "55" * 32), ("status", "contradicted"),
                             ("schema", "unselected"), ("query_digest_hex", "55" * 32)):
            changed = json.loads(self.wire)
            changed[field] = value
            self.refused(codec._canonical(changed))
        changed = json.loads(self.wire)
        changed["payload"]["long"]["contract"][1]["changes_hash_hex"] = "55" * 32
        self.refused(codec._canonical(changed))

    def test_unknown_status_requires_null_payload_and_digest(self):
        for payload, digest in ((self.payload, None), (None, "55" * 32)):
            self.refused(codec._canonical(dict(schema=history.SCHEMA, query_digest_hex=self.query.digest_hex,
                status="unknown", evidence_digest_hex=digest, payload=payload)))

    def test_duplicate_keys_escaped_keys_nonascii_nonfinite_and_noncanonical_wire_refuse(self):
        for wire in (self.wire + b" ", self.wire.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                     self.wire.replace(b'"schema"', b'"\\u0073chema"', 1), b'{"value":NaN}',
                     b'{"value":"\xff"}', b'{"value":"\\u00e9"}'):
            self.refused(wire)

    def test_wire_type_length_and_depth_are_bounded_before_old_vm_inspection(self):
        for wire in (b"", bytearray(self.wire), self.wire.decode("ascii"), b" " * (history.MAX_WIRE_BYTES + 1),
                     b"[" * 13 + b"0" + b"]" * 13):
            self.refused(wire)
        with patch.object(vm, "inspect_vm_openings", side_effect=AssertionError("must not inspect oversized wire")):
            self.refused(b" " * (history.MAX_WIRE_BYTES + 1))

    def test_windows_require_canonical_bounded_heights_and_adjacent_anchor_selection(self):
        read = authority.read_query(**roles.selection())
        wires = roles.packet(read, roles.selection(), self.case["roles"])
        for field, value in (("first_height", "0"), ("first_height", True), ("last_height", "01"),
                             ("last_height", "65"), ("last_height", "18446744073709551616"),
                             ("anchor", {"height": "1", "hash_hex": "55" * 32}), ("address_hex", "55" * 19)):
            chosen = windows(self.case)
            chosen["long"]["contract"][field] = value
            with self.assertRaisesRegex(history.NoMHistoryRefused, "^NoM account history selection refused$"):
                history.history_query(read, *wires, chosen)

    def test_maximum_sixty_four_window_and_record_limit_is_explicit_and_finite(self):
        read = authority.read_query(**roles.selection())
        wires = roles.packet(read, roles.selection(), self.case["roles"])
        chosen = windows(self.case)
        chosen["long"]["contract"]["last_height"] = "64"
        expected = history.history_query(read, *wires, chosen)
        self.payload["long"]["contract"] = [self.payload["long"]["contract"][0]] * 64
        self.assertEqual(self.report(expected=expected)["record_count"], 64)
        self.payload["long"]["contract"].append(self.payload["long"]["contract"][0])
        with self.assertRaises(history.NoMHistoryRefused): packet(expected, self.payload)

    def test_malformed_record_extra_fields_and_wrong_widths_refuse_rebuilt_commitments(self):
        for field, value in (("hash_hex", "55" * 31), ("changes_hash_hex", "AA" * 32), ("block", [])):
            payload = copy.deepcopy(self.payload)
            payload["long"]["contract"][1][field] = value
            with self.assertRaises(history.NoMHistoryRefused): packet(self.query, payload)
        payload = copy.deepcopy(self.payload)
        payload["long"]["contract"][1]["verified"] = True
        with self.assertRaises(history.NoMHistoryRefused): packet(self.query, payload)

    def test_missing_leg_role_or_full_record_field_refuses_instead_of_inferring_state(self):
        for field in ("leg", "role", "record"):
            payload = copy.deepcopy(self.payload)
            if field == "leg": del payload["short"]
            elif field == "role": del payload["long"]["recipient"]
            else: del payload["long"]["contract"][1]["changes_hash_hex"]
            with self.assertRaises(history.NoMHistoryRefused): packet(self.query, payload)

    def test_immutable_selection_copies_cannot_change_original_query_or_retained_old_reply(self):
        with self.assertRaises(TypeError): history.NoMHistoryQuery()
        with self.assertRaises(FrozenInstanceError): self.query._wire = b""
        chosen = self.query.as_dict()
        chosen["windows"]["long"]["contract"]["head_hash_hex"] = "55" * 32
        result = self.inspect()
        result["history_claim"]["payload"]["long"]["contract"][1]["block"]["amount"] = "999"
        self.assertEqual(self.report()["required_roles"]["payout"], "MATCH")
        self.assert_no_permission(self.inspect())

    def test_missing_old_roles_stay_unselected_in_complete_history(self):
        selected = roles.selection()
        read = authority.read_query(**selected)
        wires = roles.packet(read, selected, self.case["roles"], missing=("unlock_send", "contract_receive", "contract_payout", "recipient_receipt"))
        expected = history.history_query(read, *wires, windows(self.case))
        result = self.inspect(expected=expected)
        for reports in result["history_legs"].values():
            self.assertTrue(all(value == "ROLE_UNSELECTED" for value in reports["contract"]["required_roles"].values()))
            self.assertEqual(reports["recipient"]["required_roles"], {"receipt": "ROLE_UNSELECTED"})
            self.assertEqual(reports["selected_unlock_frontier"], "ROLE_UNSELECTED")
        self.assert_no_permission(result)

    def test_native_failure_preserves_original_failed_outcome_and_never_uses_public_fixture_fallback(self):
        selected_inputs = qualifier.inputs(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with patch.object(qualifier.vm, "core_state"), patch.object(qualifier.vm, "digest", return_value="00" * 32), \
                 patch.object(qualifier.vm, "qualify", side_effect=WorkerError("native command unavailable")), \
                 patch.object(qualifier, "inputs", return_value=selected_inputs):
                with self.assertRaises(WorkerError): qualifier.qualify(ROOT, ROOT, evidence_parent=parent)
            files = list(parent.glob("account-history-*/outcome.json"))
            self.assertEqual(len(files), 1)
            result = json.loads(files[0].read_text("ascii"))
            self.assertEqual(result["outcome"], "FAILED_OR_INCOMPLETE")
            self.assertNotIn("fresh_projection", result)
            self.assertEqual(result["recovery_action"], "NONE")

    def test_pinned_manifest_and_full_source_record_set_are_required_before_projection(self):
        manifest, fixture, measured = qualifier.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"]["auxiliary_windows"], 20)
        self.assertGreater(len(measured), 40)
        for records in ({}, {"long-direct-success": {}}):
            with self.assertRaises(ValueError): corpus(records)


if __name__ == "__main__":
    unittest.main()
