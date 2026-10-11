"""NoM framing controls, including forgeable complete and restored claims."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from offline_session import nom_authority_contract as contract
from offline_session.nom_recovery import synthetic_claim
from nom_retention_support import MOMENTA, TERMS, original, wire


def selection():
    last = MOMENTA["baseline"]["momenta"][-1]
    network = dict(schema=contract.NETWORK_SCHEMA, core_commit=contract.CORE_COMMIT,
        chain_id=TERMS["chain_id"], genesis_hash_hex=TERMS["genesis_hash_hex"])
    for number, name in enumerate(contract._NETWORK[4:], 16):
        network[name] = bytes([number]).hex() * 32
    return {"terms": copy.deepcopy(TERMS), "network_selection": network,
        "checkpoint_selection": {"authority_revision": 7, "momentum": {"hash_hex": last["hash_hex"],
            "height": last["momentum"]["height"], "timestamp": last["momentum"]["timestamp"]}, "state_root_hex": "31" * 32},
        "consumer_selection": {"retention_selection_digest_hex": "32" * 32, "retention_head_digest_hex": "33" * 32,
            "retention_sequence": 4, "consumer_incarnation_hex": "34" * 32,
            "external_checkpoint_digest_hex": "35" * 32, "disclosure_possible": True},
        "selected_anchor_claim": copy.deepcopy(MOMENTA["baseline"]["anchor"]),
        "required_inclusions": copy.deepcopy(MOMENTA["required_inclusions"]),
        "candidate_wire": wire(MOMENTA["baseline"]), "originals": {leg: original(leg) for leg in ("long", "short")},
        "challenge_hex": "36" * 32}


def claim(query, *, status="supported", availability="available"):
    return {"schema": contract.CLAIM_SCHEMA, "query_digest_hex": query.digest_hex,
        "challenge_hex": query.as_dict()["challenge_hex"], "availability": availability,
        "checkpoint": query.as_dict()["checkpoint_selection"] if availability == "available" else None,
        "facts": {name: {"status": status, "evidence_digest_hex": None if status == "unknown" else "37" * 32}
                  for name in contract.OBLIGATIONS}}


class NoMAuthorityContractTests(unittest.TestCase):
    def setUp(self):
        self.selected = selection()
        self.query = contract.read_query(**self.selected)

    def assert_no_permission(self, result):
        self.assertEqual((result["recovery_action"], result["application"], result["core"]), ("NONE", "NO-GO", "NO-GO"))
        self.assertEqual((result["source_authentication"], result["evidence_openings"], result["atomic_entry"]),
                         ("NOT_PERFORMED", "NOT_PERFORMED", "NOT_IMPLEMENTED"))
        self.assertEqual((result["source_currentness"], result["restore_fence"]), ("UNFILLED", "UNFILLED"))
        for name in ("retain_prior_evidence", "retain_original_bytes", "retain_possible_disclosure",
                     "revalidate_funding_before_recovery", "revalidate_live_entry_before_recovery"):
            self.assertIs(result[name], True)
        for name in ("replenish_work", "replacement_original_allowed"):
            self.assertIs(result[name], False)

    def test_complete_independent_selection_and_query_roundtrip(self):
        self.assertIs(contract.parse_query(self.query, self.query.canonical_bytes), self.query)
        value = self.query.as_dict()
        self.assertEqual(value["terms"], TERMS)
        self.assertEqual(value["obligations"], list(contract.OBLIGATIONS))
        for leg in ("long", "short"):
            self.assertEqual(bytes.fromhex(value["originals_hex"][leg]), original(leg))
        expected = hashlib.sha256(b"ptlc-nom-authority-query-v1\0" + wire(value)).hexdigest()
        self.assertEqual(self.query.digest_hex, expected)

    def test_input_and_return_mutation_cannot_reselect_expected_query(self):
        before = self.query.canonical_bytes
        self.selected["network_selection"]["authority_id_hex"] = "99" * 32
        self.selected["terms"]["long"]["amount"] = "9"
        returned = self.query.as_dict()
        returned["consumer_selection"]["disclosure_possible"] = False
        self.assertEqual(self.query.canonical_bytes, before)
        with self.assertRaises(FrozenInstanceError):
            self.query._wire = b"{}"

    def test_all_supported_claim_is_forgeable_and_never_permission(self):
        value = claim(self.query)
        for fact in value["facts"].values():
            fact["evidence_digest_hex"] = "00" * 32
        result = contract.parse_claim(self.query, wire(value))
        self.assertEqual(result["coverage"], "COMPLETE_CLAIM")
        self.assert_no_permission(result)

    def test_each_obligation_is_independent_and_contradiction_dominates(self):
        for name in contract.OBLIGATIONS:
            with self.subTest(name=name):
                value = claim(self.query)
                value["facts"][name]["status"] = "contradicted"
                result = contract.parse_claim(self.query, wire(value))
                self.assertEqual(result["coverage"], "CONTRADICTED_CLAIM")
                self.assert_no_permission(result)

    def test_each_unknown_obligation_retains_all_prior_knowledge(self):
        for name in contract.OBLIGATIONS:
            value = claim(self.query)
            value["facts"][name] = {"status": "unknown", "evidence_digest_hex": None}
            result = contract.parse_claim(self.query, wire(value))
            self.assertEqual(result["coverage"], "INCOMPLETE_CLAIM")
            self.assert_no_permission(result)
        self.assertTrue(self.query.as_dict()["consumer_selection"]["disclosure_possible"])

    def test_contradicted_and_unknown_facts_stay_separate(self):
        value = claim(self.query, status="unknown")
        value["facts"]["contract_payout"] = {"status": "contradicted", "evidence_digest_hex": "41" * 32}
        result = contract.parse_claim(self.query, wire(value))
        self.assertEqual(result["coverage"], "CONTRADICTED_CLAIM")
        self.assertEqual(result["claim"]["facts"]["recipient_receipt"]["status"], "unknown")

    def test_unavailable_has_no_snapshot_facts_or_fallback(self):
        result = contract.parse_claim(self.query, wire(claim(self.query, status="unknown", availability="unavailable")))
        self.assertEqual(result["coverage"], "UNAVAILABLE_CLAIM")
        self.assert_no_permission(result)

    def test_unavailable_cannot_assert_checkpoint_or_positive_or_negative_facts(self):
        for change in ("checkpoint", "supported", "contradicted"):
            value = claim(self.query, status="unknown", availability="unavailable")
            if change == "checkpoint":
                value["checkpoint"] = self.query.as_dict()["checkpoint_selection"]
            else:
                value["facts"]["funding_send"] = {"status": change, "evidence_digest_hex": "42" * 32}
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, wire(value))

    def test_unknown_does_not_carry_a_positive_evidence_digest(self):
        value = claim(self.query, status="unknown")
        value["facts"]["funding_send"]["evidence_digest_hex"] = "43" * 32
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.parse_claim(self.query, wire(value))

    def test_supported_and_contradicted_need_strict_digest_encoding(self):
        for bad in (None, False, "AA" * 32, "00" * 31, "00" * 33, "gg" * 32):
            for status in ("supported", "contradicted"):
                value = claim(self.query, status=status)
                value["facts"]["original_authorization"]["evidence_digest_hex"] = bad
                with self.assertRaises(contract.NomAuthorityRefused):
                    contract.parse_claim(self.query, wire(value))

    def test_missing_extra_and_malformed_fact_fields_are_refused(self):
        for mode in ("missing", "extra", "fact-extra", "fact-null", "fact-status"):
            value = claim(self.query)
            if mode == "missing":
                del value["facts"]["live_funding_entry"]
            elif mode == "extra":
                value["facts"]["inner_signature_only"] = value["facts"]["original_authorization"]
            elif mode == "fact-extra":
                value["facts"]["unlock_send"]["verified"] = True
            elif mode == "fact-null":
                value["facts"]["unlock_send"] = None
            else:
                value["facts"]["unlock_send"]["status"] = "accepted"
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, wire(value))

    def test_cross_query_challenge_and_checkpoint_replies_are_refused(self):
        for name in ("schema", "query_digest_hex", "challenge_hex", "availability"):
            value = claim(self.query)
            value[name] = "different"
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, wire(value))
        for field in ("authority_revision", "state_root_hex", "momentum"):
            value = claim(self.query)
            value["checkpoint"][field] = 8 if field == "authority_revision" else ("44" * 32 if field == "state_root_hex" else {})
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, wire(value))

    def test_every_network_pin_changes_the_query_and_cannot_replace_selected_reply(self):
        old = wire(claim(self.query))
        for name in contract._NETWORK[4:]:
            selected = selection()
            selected["network_selection"][name] = "45" * 32
            changed = contract.read_query(**selected)
            self.assertNotEqual(changed.digest_hex, self.query.digest_hex)
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(changed, old)
            self.assert_no_permission(contract.parse_claim(changed, wire(claim(changed))))

    def test_network_profile_cannot_change_terms_chain_genesis_or_source_commit(self):
        for name, bad in (("chain_id", "1"), ("genesis_hash_hex", "46" * 32),
                          ("core_commit", "0" * 40), ("schema", "different")):
            selected = selection()
            selected["network_selection"][name] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)

    def test_network_pin_shapes_extra_fields_and_self_selected_zero_pins(self):
        selected = selection()
        selected["network_selection"]["trusted"] = True
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.read_query(**selected)
        for bad in (True, [], "FF" * 32, "47" * 31):
            selected = selection()
            selected["network_selection"]["authority_id_hex"] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)
        selected = selection()
        for field in contract._NETWORK[4:]:
            selected["network_selection"][field] = "00" * 32
        query = contract.read_query(**selected)
        self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))

    def test_final_context_requires_exact_hash_height_and_timestamp(self):
        for field, bad in (("hash_hex", "48" * 32), ("height", "1"), ("timestamp", "1")):
            selected = selection()
            selected["checkpoint_selection"]["momentum"][field] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)

    def test_authority_revision_is_exact_bounded_integer_without_freshness_ordering(self):
        for good in (0, contract.MAX_REVISION):
            selected = selection()
            selected["checkpoint_selection"]["authority_revision"] = good
            query = contract.read_query(**selected)
            self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))
        for bad in (-1, True, 1.0, "7", contract.MAX_REVISION + 1):
            selected = selection()
            selected["checkpoint_selection"]["authority_revision"] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)

    def test_checkpoint_null_extra_and_opaque_state_root_controls(self):
        for bad in (None, {}, dict(selection()["checkpoint_selection"], final=True)):
            selected = selection()
            selected["checkpoint_selection"] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)
        selected = selection()
        selected["checkpoint_selection"]["state_root_hex"] = "00" * 32
        query = contract.read_query(**selected)
        self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))

    def test_all_consumer_bindings_change_read_without_implementing_a_restore_fence(self):
        for name in contract._KNOWLEDGE:
            selected = selection()
            selected["consumer_selection"][name] = (5 if name == "retention_sequence" else
                False if name == "disclosure_possible" else "49" * 32)
            query = contract.read_query(**selected)
            self.assertNotEqual(query.digest_hex, self.query.digest_hex)
            self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))
        # Both coherent old and new independently selected queries still frame.
        self.assert_no_permission(contract.parse_claim(self.query, wire(claim(self.query))))

    def test_consumer_sequence_boolean_and_hex_bounds(self):
        for field, bad in (("retention_sequence", 0), ("retention_sequence", True),
                           ("retention_sequence", contract.MAX_REVISION + 1), ("disclosure_possible", 1),
                           ("external_checkpoint_digest_hex", None)):
            selected = selection()
            selected["consumer_selection"][field] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)

    def test_exact_synthetic_originals_bound_without_outer_account_authentication(self):
        selected = selection()
        selected["originals"]["long"] = synthetic_claim(TERMS, "long", "00" * 64)
        query = contract.read_query(**selected)
        self.assertNotEqual(query.digest_hex, self.query.digest_hex)
        self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))

    def test_original_leg_swap_missing_extra_type_and_noncanonical_bytes_are_refused(self):
        for mode in ("swap", "missing", "extra", "type", "oversized", "noncanonical"):
            selected = selection()
            if mode == "swap":
                selected["originals"]["long"] = original("short")
            elif mode == "missing":
                del selected["originals"]["short"]
            elif mode == "extra":
                selected["originals"]["other"] = original("long")
            elif mode == "type":
                selected["originals"]["long"] = bytearray(original("long"))
            elif mode == "oversized":
                selected["originals"]["long"] = b"0" * 8193
            else:
                selected["originals"]["long"] += b"\n"
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)

    def test_exact_raw_candidate_spacing_is_bound_separately_from_momentum_hash(self):
        selected = selection()
        selected["candidate_wire"] = b" " + selected["candidate_wire"] + b"\n"
        query = contract.read_query(**selected)
        self.assertNotEqual(query.digest_hex, self.query.digest_hex)
        self.assertEqual(query.as_dict()["checkpoint_selection"], self.query.as_dict()["checkpoint_selection"])
        expected = hashlib.sha256(b"ptlc-nom-authority-candidate-v1\0" + selected["candidate_wire"]).hexdigest()
        self.assertEqual(query.as_dict()["candidate_wire_digest_hex"], expected)

    def test_malformed_incomplete_and_mismatched_candidate_coverage_are_refused(self):
        empty = copy.deepcopy(MOMENTA["baseline"])
        empty["momenta"] = []
        for bad in (b"", b"{", b"null", b"\xff", wire(empty), b"[" * 17 + b"0" + b"]" * 17):
            selected = selection()
            selected["candidate_wire"] = bad
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.read_query(**selected)
        selected = selection()
        selected["required_inclusions"][0]["header"]["hash_hex"] = "50" * 32
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.read_query(**selected)

    def test_required_inclusion_order_and_selected_anchor_are_bound(self):
        selected = selection()
        selected["required_inclusions"].reverse()
        query = contract.read_query(**selected)
        self.assertNotEqual(query.digest_hex, self.query.digest_hex)
        selected = selection()
        selected["selected_anchor_claim"]["hash_hex"] = "51" * 32
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.read_query(**selected)

    def test_common_prefix_funding_still_requires_fresh_live_entry_and_funding_evidence(self):
        result = contract.parse_claim(self.query, wire(claim(self.query)))
        self.assertIn("funding_send", result["claim"]["facts"])
        self.assertIn("live_funding_entry", result["claim"]["facts"])
        self.assert_no_permission(result)

    def test_exact_replay_and_new_challenge_supply_no_currentness_or_charge(self):
        value = wire(claim(self.query))
        self.assertEqual(contract.parse_claim(self.query, value), contract.parse_claim(self.query, value))
        selected = selection()
        selected["challenge_hex"] = "52" * 32
        query = contract.read_query(**selected)
        self.assertNotEqual(query.digest_hex, self.query.digest_hex)
        self.assert_no_permission(contract.parse_claim(query, wire(claim(query))))

    def test_changed_complete_query_is_not_selected_from_incoming_bytes(self):
        selected = self.query.as_dict()
        selected["consumer_selection"]["disclosure_possible"] = False
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.parse_query(self.query, wire(selected))

    def test_fact_labels_cannot_select_the_expected_query(self):
        value = claim(self.query)
        value["expected_query"] = self.query.as_dict()
        with self.assertRaises(contract.NomAuthorityRefused):
            contract.parse_claim(self.query, wire(value))

    def test_noncanonical_duplicate_escaped_and_alternate_number_encodings_are_refused(self):
        raw = wire(claim(self.query))
        invalid = (raw + b"\n", b" " + raw, raw.replace(b'"available"', b'"available","availability":"available"', 1),
            raw.replace(b'"facts"', b'"\\u0066acts"', 1), raw.replace(b'"authority_revision":7', b'"authority_revision":7.0', 1),
            raw.replace(b'"authority_revision":7', b'"authority_revision":7e0', 1))
        for bad in invalid:
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, bad)

    def test_nonfinite_nonascii_deep_and_oversized_wire_are_refused(self):
        for bad in (b'{"x":NaN}', b'{"x":Infinity}', b"\xff", b"[" * 13 + b"0" + b"]" * 13,
                    b" " * (contract.MAX_WIRE_BYTES + 1), b"", bytearray(wire(claim(self.query)))):
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(self.query, bad)

    def test_exact_query_type_and_revalidation_refuse_forged_malformed_selection(self):
        with self.assertRaises(TypeError):
            contract.NoMReadQuery()
        for expected in (None, self.query.as_dict(), self.query.canonical_bytes):
            with self.assertRaises(contract.NomAuthorityRefused):
                contract.parse_claim(expected, wire(claim(self.query)))
        forged = object.__new__(contract.NoMReadQuery)
        value = self.query.as_dict()
        value["obligations"].remove("consumer_restore_fence")
        object.__setattr__(forged, "_wire", wire(value))
        with self.assertRaises(contract.NomAuthorityRefused):
            forged.as_dict()

    def test_refusal_diagnostics_do_not_echo_remote_bytes(self):
        marker = b"synthetic-reply-marker"
        try:
            contract.parse_claim(self.query, marker)
        except contract.NomAuthorityRefused as error:
            self.assertNotIn(marker.decode("ascii"), str(error))
        else:
            self.fail("malformed source claim accepted")


if __name__ == "__main__":
    unittest.main()
