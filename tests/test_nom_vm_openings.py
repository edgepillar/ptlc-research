"""Actual-source public role projections are not authenticated recovery evidence."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session import enrollment_contract as codec, nom_authority_contract as authority
from offline_session import nom_evidence_openings as base, nom_momentum as momentum
from offline_session import nom_recovery as recovery, nom_vm_openings as opening
from offline_session.nom_wire import account_block_hash, encode_call
from offline_session.public_worker import WorkerError
from scripts import qualify_nom_vm_openings as qualifier
from scripts.generate_nom_vm_openings import FIXTURE, KINDS, corpus, selection, packet

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


def rehash(record):
    record["hash_hex"] = account_block_hash(record["block"])


class NoMVMOpeningTests(unittest.TestCase):
    def setUp(self):
        self.selected = selection()
        self.query = authority.read_query(**self.selected)
        self.legs = copy.deepcopy(FIX["source_cases"]["direct-success"])
        self.claim_wire, self.base_wire, self.opening_wire = packet(self.query, self.selected, self.legs)

    def inspect(self, legs=None, **options):
        wires = packet(self.query, self.selected, self.legs if legs is None else legs, **options)
        return opening.inspect_vm_openings(self.query, *wires)

    def refused(self, *, query=None, claim_wire=None, base_wire=None, opening_wire=None):
        with self.assertRaisesRegex(opening.NoMVMOpeningRefused, "^NoM VM evidence opening refused$"):
            opening.inspect_vm_openings(query or self.query, self.claim_wire if claim_wire is None else claim_wire,
                self.base_wire if base_wire is None else base_wire,
                self.opening_wire if opening_wire is None else opening_wire)

    def assert_no_permission(self, result):
        self.assertEqual((result["recovery_action"], result["application"], result["core"], result["terminal_outcome"]),
                         ("NONE", "NO-GO", "NO-GO", "NOT_ESTABLISHED"))
        for key in ("account_admission", "vm_execution", "source_authentication", "proof_verification",
                    "network_provisioning", "durable_retention"):
            self.assertEqual(result[key], "NOT_PERFORMED")
        for key in ("source_currentness", "canonicality", "finality", "restore_fence"):
            self.assertEqual(result[key], "UNFILLED")
        self.assertEqual(result["atomic_entry"], "NOT_IMPLEMENTED")
        self.assertEqual(result["received_state_proof"], "ABSENT")
        self.assertEqual(result["aggregate_work_budget"], "UNSELECTED")
        for key in ("retain_prior_evidence", "retain_original_bytes", "retain_possible_disclosure",
                    "revalidate_funding_before_recovery", "revalidate_live_entry_before_recovery"):
            self.assertIs(result[key], True)
        for key in ("replenish_work", "replacement_original_allowed"):
            self.assertIs(result[key], False)

    def test_four_further_grammars_keep_four_unselected_and_all_eleven_requirements_unfilled(self):
        result = self.inspect()
        self.assertEqual(result["framing"], "BOUND_VM_PUBLIC_OPENINGS_ONLY")
        self.assertEqual(result["unselected_profiles"], ["network_profile", "live_funding_entry",
                         "consumer_restore_fence", "source_current_position"])
        self.assertEqual(result["claim_coverage"], "INCOMPLETE_CLAIM")
        for fact in result["comparisons"].values():
            self.assertEqual(fact["opening"], "BOUND_UNAUTHENTICATED_PAYLOAD")
        self.assert_no_permission(result)

    def test_direct_source_roles_match_funding_original_asset_and_parent_links(self):
        result = self.inspect()
        qualifier.check_result(result, "direct-success")
        for leg in ("long", "short"):
            roles = result["legs"][leg]
            self.assertEqual(roles["unlock_send"]["retained_inner_witness_and_call"], "MATCH")
            self.assertEqual(roles["contract_receive"]["funding_linkage"], "MATCH")
            self.assertEqual(roles["contract_receive"]["send_linkage"], "MATCH")
            self.assertEqual(roles["contract_payout"]["parent_child_linkage"], "MATCH")
            self.assertEqual(roles["recipient_receipt"]["payout_linkage"], "MATCH")
        self.assert_no_permission(result)

    def test_actual_direct_recipient_frontier_is_not_the_unlock_account_continuation(self):
        for leg, roles in self.inspect()["legs"].items():
            self.assertEqual(roles["recipient_receipt"]["recipient_account_continuity"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(self.legs[leg]["unlock_send"]["block"]["height"], "21")
            self.assertEqual(self.legs[leg]["recipient_receipt"]["block"]["height"], "1")

    def test_numbered_vm_momentum_stubs_do_not_match_the_selected_branch(self):
        result = self.inspect()
        for roles in result["legs"].values():
            for name in ("unlock_send", "contract_payout", "recipient_receipt"):
                self.assertEqual(roles[name]["known_acknowledgement"], "DIFFERS_FROM_SELECTION")
                self.assertEqual(roles[name]["candidate_membership"], "NOT_INCLUDED_CLAIM")
        self.assert_no_permission(result)

    def test_both_proxy_source_paths_keep_the_fixed_recipient_and_unknown_recipient_frontier(self):
        for kind in ("proxy-funder-success", "proxy-third-success"):
            result = self.inspect(FIX["source_cases"][kind])
            qualifier.check_result(result, kind)
            for roles in result["legs"].values():
                self.assertEqual(roles["unlock_send"]["method_claim"], "ProxyUnlock")
                self.assertEqual(roles["recipient_receipt"]["recipient_account_continuity"], "PRIOR_RECIPIENT_FRONTIER_UNSELECTED")
            self.assert_no_permission(result)

    def test_successful_reclaim_and_refund_are_not_an_unlock_success(self):
        result = self.inspect(FIX["source_cases"]["unlock-at-expiry-then-reclaim"])
        qualifier.check_result(result, "unlock-at-expiry-then-reclaim")
        for roles in result["legs"].values():
            self.assertEqual(roles["unlock_send"]["method_claim"], "Reclaim")
            self.assertEqual(roles["unlock_send"]["retained_inner_witness_and_call"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(roles["contract_payout"]["fixed_asset_and_recipient"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(roles["recipient_receipt"]["receive_fields"], "DIFFERS_FROM_SELECTION")
        self.assert_no_permission(result)

    def test_raw_double_credit_receipt_still_matches_from_hash_without_a_received_proof(self):
        result = self.inspect(FIX["source_cases"]["raw-receive-replay-needs-verifier"])
        qualifier.check_result(result, "raw-receive-replay-needs-verifier")
        for roles in result["legs"].values():
            self.assertEqual(roles["recipient_receipt"]["payout_linkage"], "MATCH")
            self.assertEqual(roles["recipient_receipt"]["received_marker_proof"], "ABSENT")
            self.assertEqual(roles["recipient_receipt"]["duplicate_receive_admission"], "NOT_PERFORMED")
        self.assert_no_permission(result)

    def test_forged_all_supported_reply_cannot_fill_unopened_authority_requirements(self):
        claim = json.loads(self.claim_wire)
        for fact in claim["facts"].values():
            if fact["status"] == "unknown":
                fact.update(status="supported", evidence_digest_hex="00" * 32)
        claim_wire = codec._canonical(claim)
        first, second = json.loads(self.base_wire), json.loads(self.opening_wire)
        first["claim_wire_digest_hex"] = second["claim_wire_digest_hex"] = base.claim_digest(claim_wire)
        first_wire = codec._canonical(first)
        second["base_opening_wire_digest_hex"] = opening.base_digest(first_wire)
        result = opening.inspect_vm_openings(self.query, claim_wire, first_wire, codec._canonical(second))
        self.assertEqual(result["claim_coverage"], "COMPLETE_CLAIM")
        self.assert_no_permission(result)

    def test_structurally_repaired_receipt_is_only_a_forged_control(self):
        legs = copy.deepcopy(self.legs)
        for records in legs.values():
            send, receipt = records["unlock_send"], records["recipient_receipt"]
            receipt["block"].update(previous_hash_hex=account_block_hash(send["block"]),
                                    height=str(int(send["block"]["height"]) + 1))
            rehash(receipt)
        result = self.inspect(legs)
        for roles in result["legs"].values():
            self.assertEqual(roles["recipient_receipt"]["recipient_account_continuity"], "MATCH")
        self.assert_no_permission(result)

    def test_changed_changes_hash_is_retained_but_cannot_change_the_account_hash(self):
        legs = copy.deepcopy(self.legs)
        record = legs["long"]["contract_payout"]
        record["changes_hash_hex"] = "00" * 32
        result = self.inspect(legs)
        self.assertEqual(result["legs"]["long"]["contract_payout"]["advertised_hash"], "MATCH")
        self.assertIn("OPAQUE SEPARATE CLAIM", result["legs"]["long"]["contract_payout"]["changes_hash"])
        self.assertEqual(result["opening_bundle"]["openings"]["contract_payout"]["records"]["long"], record)
        self.assert_no_permission(result)

    def test_each_well_shaped_advertised_hash_conflict_survives_a_supported_label(self):
        for name in opening.SELECTED:
            legs = copy.deepcopy(self.legs)
            record = legs["long"][name]
            record = record["receive"] if name == "contract_receive" else record
            record["hash_hex"] = "00" * 32
            result = self.inspect(legs)
            compared = result["legs"]["long"][name]
            compared = compared["receive"] if name == "contract_receive" else compared
            self.assertEqual(compared["advertised_hash"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(result["comparisons"][name]["claimed_status"], "supported")
            self.assert_no_permission(result)

    def test_rebound_contradicted_labels_remain_separate_from_matching_payload_fields(self):
        result = self.inspect(statuses={name: "contradicted" for name in opening.SELECTED})
        self.assertEqual(result["claim_coverage"], "CONTRADICTED_CLAIM")
        self.assertEqual(result["legs"]["long"]["contract_payout"]["fixed_asset_and_recipient"], "MATCH")
        self.assert_no_permission(result)

    def test_each_missing_role_preserves_originals_disclosure_and_no_terminal_outcome(self):
        for name in opening.SELECTED:
            result = self.inspect(missing=(name,))
            self.assertEqual(result["comparisons"][name]["opening"], "MISSING_OPENING")
            self.assertNotIn(name, result["legs"]["long"])
            self.assert_no_permission(result)

    def test_each_unknown_role_has_no_payload_and_never_becomes_a_negative_fact(self):
        for name in opening.SELECTED:
            result = self.inspect(statuses={name: "unknown"})
            self.assertEqual(result["comparisons"][name]["opening"], "UNKNOWN_CLAIM")
            self.assert_no_permission(result)

    def test_missing_funding_opening_cannot_be_synthesized_from_the_query(self):
        result = self.inspect(missing_base=("funding_send",))
        self.assertEqual(result["legs"]["long"]["contract_receive"]["funding_linkage"], "MISSING_FUNDING_OPENING")
        self.assert_no_permission(result)

    def test_missing_candidate_does_not_create_inclusion_or_acknowledgement_authority(self):
        result = self.inspect(missing_base=("momentum_lineage",))
        self.assertEqual(result["legs"]["long"]["contract_payout"]["candidate_membership"], "NOT_CHECKED_MISSING_CANDIDATE")
        self.assert_no_permission(result)

    def test_missing_original_opening_cannot_verify_the_selected_inner_witness(self):
        result = self.inspect(missing_base=("original_authorization",))
        self.assertEqual(result["legs"]["long"]["unlock_send"]["retained_inner_witness_and_call"], "MATCH")
        self.assertEqual(result["legs"]["long"]["unlock_send"]["inner_signature_verification"], "NOT_PERFORMED")
        self.assert_no_permission(result)

    def test_cross_leg_substitution_cannot_match_the_funding_original_or_recipient(self):
        legs = {"long": copy.deepcopy(self.legs["short"]), "short": copy.deepcopy(self.legs["long"])}
        result = self.inspect(legs)
        for roles in result["legs"].values():
            self.assertEqual(roles["unlock_send"]["retained_inner_witness_and_call"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(roles["contract_payout"]["fixed_asset_and_recipient"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(roles["recipient_receipt"]["receive_fields"], "DIFFERS_FROM_SELECTION")
        self.assert_no_permission(result)

    def test_changed_inner_completion_or_call_cannot_replace_the_retained_original(self):
        for call in ({"method": "Unlock", "entry_id_hex": "00" * 32, "witness_hex": "00" * 64},
                     {"method": "Reclaim", "entry_id_hex": self.selected["terms"]["long"]["entry_id_hex"]}):
            legs = copy.deepcopy(self.legs)
            legs["long"]["unlock_send"]["block"]["data_hex"] = encode_call(call).hex()
            rehash(legs["long"]["unlock_send"])
            self.assertEqual(self.inspect(legs)["legs"]["long"]["unlock_send"]["retained_inner_witness_and_call"], "DIFFERS_FROM_SELECTION")

    def test_direct_wrong_caller_and_proxy_wrong_destination_are_separate_conflicts(self):
        legs = copy.deepcopy(self.legs)
        legs["long"]["unlock_send"]["block"]["address_hex"] = self.selected["terms"]["alice_address_hex"]
        rehash(legs["long"]["unlock_send"])
        self.assertEqual(self.inspect(legs)["legs"]["long"]["unlock_send"]["send_fields"], "DIFFERS_FROM_SELECTION")
        legs = copy.deepcopy(FIX["source_cases"]["proxy-third-success"])
        signature = recovery.claim_signature(self.selected["terms"], "long", self.selected["originals"]["long"])
        legs["long"]["unlock_send"]["block"]["data_hex"] = encode_call(dict(method="ProxyUnlock",
            entry_id_hex=self.selected["terms"]["long"]["entry_id_hex"], destination_hex=self.selected["terms"]["alice_address_hex"],
            witness_hex=signature)).hex()
        rehash(legs["long"]["unlock_send"])
        self.assertEqual(self.inspect(legs)["legs"]["long"]["unlock_send"]["retained_inner_witness_and_call"], "DIFFERS_FROM_SELECTION")

    def test_failed_receive_marker_is_not_success_even_with_a_recomputed_hash(self):
        legs = copy.deepcopy(self.legs)
        record = legs["long"]["contract_receive"]["receive"]
        record["block"]["data_hex"] = "0000000000000002"
        rehash(record)
        self.assertEqual(self.inspect(legs)["legs"]["long"]["contract_receive"]["receive_fields_and_status_claim"], "DIFFERS_FROM_SELECTION")

    def test_parent_linkage_uses_recomputed_send_and_child_hashes_not_advertised_values(self):
        legs = copy.deepcopy(self.legs)
        for role in ("unlock_send", "contract_payout"):
            legs["long"][role]["hash_hex"] = "00" * 32
        result = self.inspect(legs)
        self.assertEqual(result["legs"]["long"]["contract_receive"]["send_linkage"], "MATCH")
        self.assertEqual(result["legs"]["long"]["contract_payout"]["parent_child_linkage"], "MATCH")
        self.assertEqual(result["legs"]["long"]["recipient_receipt"]["payout_linkage"], "MATCH")

    def test_wrong_asset_recipient_or_amount_cannot_match_a_fixed_payout(self):
        for field, value in (("amount", "99"), ("token_standard_hex", "33" * 10), ("to_address_hex", "0033" + "33" * 18)):
            legs = copy.deepcopy(self.legs)
            legs["long"]["contract_payout"]["block"][field] = value
            rehash(legs["long"]["contract_payout"])
            self.assertEqual(self.inspect(legs)["legs"]["long"]["contract_payout"]["fixed_asset_and_recipient"], "DIFFERS_FROM_SELECTION")

    def test_wrong_ancestry_descendants_or_same_height_ack_hash_cannot_match_parent(self):
        for field, value in (("previous_hash_hex", "00" * 32), ("height", "9"),
                             ("descendant_hashes_hex", []), ("momentum_hash_hex", "11" * 32)):
            legs = copy.deepcopy(self.legs)
            record = legs["long"]["contract_receive"]["receive"]
            record["block"][field] = value
            rehash(record)
            self.assertEqual(self.inspect(legs)["legs"]["long"]["contract_payout"]["parent_child_linkage"], "DIFFERS_FROM_SELECTION")

    def test_wrong_recipient_receive_source_or_earlier_ack_is_a_conflict(self):
        for field, value, comparison in (("from_block_hash_hex", "00" * 32, "payout_linkage"),
            ("momentum_height", "1", "payout_acknowledgement_order"),
            ("momentum_hash_hex", "11" * 32, "payout_acknowledgement_order")):
            legs = copy.deepcopy(self.legs)
            record = legs["long"]["recipient_receipt"]
            record["block"][field] = value
            rehash(record)
            self.assertEqual(self.inspect(legs)["legs"]["long"]["recipient_receipt"][comparison], "DIFFERS_FROM_SELECTION")

    def test_funding_receive_with_an_earlier_acknowledgement_cannot_confirm_the_funding_send(self):
        legs = copy.deepcopy(self.legs)
        record = legs["long"]["contract_receive"]["funding_receive"]
        record["block"]["momentum_height"] = "1"
        rehash(record)
        self.assertEqual(self.inspect(legs)["legs"]["long"]["contract_receive"]["funding_acknowledgement_order"], "DIFFERS_FROM_SELECTION")

    def test_forged_inclusion_uses_the_recomputed_header_and_is_still_only_a_claim(self):
        selected = copy.deepcopy(self.selected)
        candidate = json.loads(selected["candidate_wire"])
        candidate["momenta"] = candidate["momenta"][:1]
        item = candidate["momenta"][0]
        record = self.legs["long"]["contract_payout"]
        item["momentum"]["content"] = [{"address_hex": record["block"]["address_hex"],
            "height": record["block"]["height"], "hash_hex": account_block_hash(record["block"])}]
        item["hash_hex"] = momentum.momentum_hash(item["momentum"])
        selected["candidate_wire"] = codec._canonical(candidate)
        selected["required_inclusions"] = []
        selected["checkpoint_selection"]["momentum"] = {"hash_hex": item["hash_hex"],
            "height": item["momentum"]["height"], "timestamp": item["momentum"]["timestamp"]}
        query = authority.read_query(**selected)
        legs = copy.deepcopy(self.legs)
        legs["long"]["contract_payout"]["hash_hex"] = "00" * 32
        result = opening.inspect_vm_openings(query, *packet(query, selected, legs))
        compared = result["legs"]["long"]["contract_payout"]
        self.assertEqual(compared["candidate_membership"], "INCLUDED_CLAIM")
        self.assertEqual(compared["advertised_hash"], "DIFFERS_FROM_SELECTION")
        self.assertEqual(len(compared["confirmation_claims"]), 1)
        self.assert_no_permission(result)

    def test_unavailable_reply_and_all_null_payloads_do_not_erase_retained_knowledge(self):
        claim = json.loads(self.claim_wire)
        claim.update(availability="unavailable", checkpoint=None,
            facts={name: {"status": "unknown", "evidence_digest_hex": None} for name in authority.OBLIGATIONS})
        claim_wire = codec._canonical(claim)
        first, second = json.loads(self.base_wire), json.loads(self.opening_wire)
        first.update(claim_wire_digest_hex=base.claim_digest(claim_wire), openings={name: None for name in base.SELECTED})
        first_wire = codec._canonical(first)
        second.update(claim_wire_digest_hex=base.claim_digest(claim_wire),
            base_opening_wire_digest_hex=opening.base_digest(first_wire), openings={name: None for name in opening.SELECTED})
        result = opening.inspect_vm_openings(self.query, claim_wire, first_wire, codec._canonical(second))
        self.assertEqual(result["claim_coverage"], "UNAVAILABLE_CLAIM")
        self.assertEqual(result["legs"], {"long": {}, "short": {}})
        self.assert_no_permission(result)

    def test_missing_leg_parent_or_record_field_and_extra_proof_boolean_refuse(self):
        payload = json.loads(self.opening_wire)["openings"]["contract_receive"]
        for edit in ("leg", "parent", "field", "boolean"):
            changed = copy.deepcopy(payload)
            if edit == "leg": del changed["records"]["short"]
            elif edit == "parent": del changed["records"]["long"]["funding_receive"]
            elif edit == "field": del changed["records"]["long"]["receive"]["changes_hash_hex"]
            else: changed["records"]["long"]["receive"]["verified"] = True
            with self.assertRaises(opening.NoMVMOpeningRefused):
                opening.opening_digest(self.query, "contract_receive", "supported", changed)

    def test_payload_commitment_binds_complete_query_role_status_and_domain(self):
        payload = json.loads(self.opening_wire)["openings"]["contract_payout"]
        digest = opening.opening_digest(self.query, "contract_payout", "supported", payload)
        value = dict(schema=opening.PAYLOAD_SCHEMA, query_digest_hex=self.query.digest_hex,
                     obligation="contract_payout", status="supported", payload=payload)
        self.assertEqual(digest, hashlib.sha256(b"ptlc-nom-vm-evidence-payload-v1\0" + codec._canonical(value)).hexdigest())
        self.assertNotEqual(digest, opening.opening_digest(self.query, "recipient_receipt", "supported", payload))
        self.assertNotEqual(digest, opening.opening_digest(self.query, "contract_payout", "contradicted", payload))
        self.assertNotEqual(digest, base.opening_digest(self.query, "funding_send", "supported",
            {"records": {leg: {key: record[key] for key in ("hash_hex", "block")} for leg, record in payload["records"].items()}}))

    def test_changed_query_challenge_checkpoint_or_consumer_cannot_reuse_openings(self):
        for field in ("challenge", "checkpoint", "consumer"):
            selected = copy.deepcopy(self.selected)
            if field == "challenge": selected["challenge_hex"] = "55" * 32
            elif field == "checkpoint": selected["checkpoint_selection"]["state_root_hex"] = "55" * 32
            else: selected["consumer_selection"]["external_checkpoint_digest_hex"] = "55" * 32
            self.refused(query=authority.read_query(**selected))

    def test_uncommitted_payload_status_or_claim_change_refuses(self):
        value = json.loads(self.opening_wire)
        value["openings"]["contract_payout"]["records"]["long"]["changes_hash_hex"] = "55" * 32
        self.refused(opening_wire=codec._canonical(value))
        claim = json.loads(self.claim_wire)
        claim["facts"]["contract_payout"]["status"] = "contradicted"
        self.refused(claim_wire=codec._canonical(claim))

    def test_exact_base_bundle_binding_refuses_missing_or_altered_original_openings(self):
        value = json.loads(self.base_wire)
        value["openings"]["original_authorization"] = None
        self.refused(base_wire=codec._canonical(value))
        value = json.loads(self.opening_wire)
        value["base_opening_wire_digest_hex"] = "00" * 32
        self.refused(opening_wire=codec._canonical(value))

    def test_unknown_with_present_opening_and_unselected_extra_profiles_refuse(self):
        claim_wire, base_wire, raw = packet(self.query, self.selected, self.legs, statuses={"contract_payout": "unknown"})
        value = json.loads(raw)
        value["openings"]["contract_payout"] = json.loads(self.opening_wire)["openings"]["contract_payout"]
        self.refused(claim_wire=claim_wire, base_wire=base_wire, opening_wire=codec._canonical(value))
        value = json.loads(self.opening_wire)
        value["openings"]["live_funding_entry"] = {"verified": True}
        self.refused(opening_wire=codec._canonical(value))

    def test_noncanonical_duplicate_escaped_nonascii_and_nonfinite_wire_refuse(self):
        for raw in (self.opening_wire + b" ", self.opening_wire.replace(b'"schema":', b'"schema":"duplicate","schema":', 1),
                    self.opening_wire.replace(b'"schema"', b'"\\u0073chema"', 1), b'{"value":NaN}',
                    b'{"value":"\xff"}', b'{"value":"\\u00e9"}'):
            self.refused(opening_wire=raw)

    def test_wrong_field_width_type_or_record_shape_refuses_even_when_commitment_is_rebuilt(self):
        for field, value in (("hash_hex", "55" * 31), ("changes_hash_hex", "AA" * 32), ("block", [])):
            legs = copy.deepcopy(self.legs)
            legs["long"]["contract_payout"][field] = value
            with self.assertRaisesRegex(opening.NoMVMOpeningRefused, "^NoM VM commitment preparation refused$"):
                packet(self.query, self.selected, legs)
        for field, value in (("height", True), ("amount", "01"), ("chain_id", 1), ("data_hex", "ff" * 4097)):
            legs = copy.deepcopy(self.legs)
            legs["long"]["contract_payout"]["block"][field] = value
            with self.assertRaises(opening.NoMVMOpeningRefused): packet(self.query, self.selected, legs)

    def test_wire_type_size_and_depth_are_bounded_before_role_decoding(self):
        for raw in (b"", bytearray(self.opening_wire), self.opening_wire.decode("ascii"), b" " * (opening.MAX_WIRE_BYTES + 1),
                    b"[" * 13 + b"0" + b"]" * 13):
            self.refused(opening_wire=raw)
        with patch.object(base, "inspect_openings", side_effect=AssertionError("must not parse oversized wire")):
            self.refused(opening_wire=b" " * (opening.MAX_WIRE_BYTES + 1))

    def test_decoded_copies_and_replayed_or_rechallenged_claims_never_authorize_use(self):
        result = self.inspect()
        result["opening_bundle"]["openings"]["contract_payout"]["records"]["long"]["block"]["amount"] = "999"
        self.assertEqual(self.inspect()["legs"]["long"]["contract_payout"]["fixed_asset_and_recipient"], "MATCH")
        self.assert_no_permission(self.inspect())
        self.selected["challenge_hex"] = "55" * 32
        self.query = authority.read_query(**self.selected)
        self.assert_no_permission(self.inspect())

    def test_manifest_inputs_are_pinned_and_missing_records_cannot_be_projected(self):
        manifest, fixture, measured = qualifier.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["core_commit"], authority.CORE_COMMIT)
        self.assertEqual(manifest["expected_counts"]["source_case_projections"], 10)
        self.assertGreater(len(measured), 30)
        for records in ({}, {"long-direct-success": {}}):
            with self.assertRaises(ValueError): corpus(records)

    def test_native_execution_failure_preserves_failed_outcome_and_cannot_fallback_to_the_fixture(self):
        selected_inputs = qualifier.inputs(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            with patch.object(qualifier.vm, "core_state"), patch.object(qualifier.vm, "digest", return_value="00" * 32), \
                 patch.object(qualifier.vm, "qualify", side_effect=WorkerError("native command unavailable")):
                # Keep real selected-input checks while mocking only native launch/tool inspection.
                with patch.object(qualifier, "inputs", return_value=selected_inputs):
                    with self.assertRaises(WorkerError): qualifier.qualify(ROOT, ROOT, evidence_parent=parent)
            files = list(parent.glob("vm-openings-*/outcome.json"))
            self.assertEqual(len(files), 1)
            result = json.loads(files[0].read_text("ascii"))
            self.assertEqual(result["outcome"], "FAILED_OR_INCOMPLETE")
            self.assertNotIn("fresh_projection", result)
            self.assertEqual(result["recovery_action"], "NONE")


if __name__ == "__main__":
    unittest.main()
