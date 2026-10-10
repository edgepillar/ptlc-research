"""Claim bindings and retention plans never become chain authority."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from offline_session.nom_momentum import (
    MAX_CONTENT, MAX_MOMENTA, MAX_WIRE_BYTES, MomentumRefused, compare_candidates,
    content_bytes, header_bytes, inspect_branch, momentum_hash, momentum_preimage, parse_branch_wire,
)
from scripts.generate_nom_momentum import corpus

ROOT = Path(__file__).resolve().parents[1]


class NoMMomentumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "compatibility/fixtures/nom_momentum_v1.json").read_text("ascii"))

    def selection(self):
        return {"chain_id": self.fixture["chain_id"], "selected_anchor_claim": copy.deepcopy(self.fixture["baseline"]["anchor"]),
                "required_inclusions": copy.deepcopy(self.fixture["required_inclusions"])}

    def test_public_corpus_is_deterministic(self):
        data = (ROOT / "compatibility/fixtures/nom_momentum_v1.json").read_bytes()
        self.assertEqual((json.dumps(corpus(), sort_keys=True, indent=2) + "\n").encode("ascii"), data)

    def test_raw_hash_and_header_commitments_match_every_vector(self):
        for vector in self.fixture["hash_vectors"]:
            with self.subTest(vector["id"]):
                block = vector["momentum"]
                content = content_bytes(block["content"])
                self.assertEqual(content.hex(), vector["content_bytes_hex"])
                self.assertEqual(hashlib.sha3_256(content).hexdigest(), vector["content_hash_hex"])
                self.assertEqual(momentum_preimage(block).hex(), vector["preimage_hex"])
                self.assertEqual(momentum_hash(block), vector["hash_hex"])
                self.assertEqual(len(momentum_preimage(block)), 176 if int(block["version"]) >= 2 else 160)
                self.assertTrue(all(len(header_bytes(header)) == 60 for header in block["content"]))

    def test_every_structural_counterexample_has_its_selected_outcome(self):
        for vector in self.fixture["claim_vectors"]:
            with self.subTest(vector["id"]):
                args = {key: vector[key] for key in ("chain_id", "selected_anchor_claim", "required_inclusions")}
                result = inspect_branch(vector["claim"], **args)
                self.assertEqual((result["structure"], result["reason"]), (vector["expect_structure"], vector["expect_reason"]))
                self.assertEqual(result["recovery_action"], "NONE")
                self.assertEqual(result["canonicality"], "UNFILLED")
                self.assertEqual(result["producer_signature"], "NOT_PERFORMED")
                self.assertEqual((result["application"], result["core"]), ("NO-GO", "NO-GO"))

    def test_every_reorg_plan_preserves_disclosure_originals_and_work(self):
        for vector in self.fixture["reorg_vectors"]:
            with self.subTest(vector["id"]):
                args = {key: vector[key] for key in ("chain_id", "selected_anchor_claim", "retained_inclusions")}
                before = copy.deepcopy(vector)
                result = compare_candidates(vector["previous"], vector["candidate"], **args)
                self.assertEqual(result["relation"], vector["expect_relation"])
                self.assertEqual(result["recheck_inclusions"], vector["expect_recheck_inclusions"])
                for key in ("retain_previous_evidence", "retain_candidate_evidence", "retain_original_bytes", "retain_possible_disclosure"):
                    self.assertIs(result[key], True)
                for key in ("restore_older_journal", "replenish_work", "replacement_original_allowed"):
                    self.assertIs(result[key], False)
                self.assertEqual(result["durable_retention"], "NOT_IMPLEMENTED")
                self.assertEqual(result["accepted_branch"], "NONE")
                self.assertEqual(result["recovery_action"], "NONE")
                self.assertEqual(vector, before)

    def test_supplied_order_is_not_silently_sorted(self):
        first = self.fixture["hash_vectors"][0]
        reversed_content = next(value for value in self.fixture["hash_vectors"] if value["id"] == "supplied-content-order")
        self.assertNotEqual(first["hash_hex"], reversed_content["hash_hex"])

    def test_legacy_price_alias_is_hash_equivalence_not_admission(self):
        vectors = {value["id"]: value for value in self.fixture["hash_vectors"]}
        self.assertEqual(vectors["legacy-layout"]["hash_hex"], vectors["legacy-prices-not-hashed"]["hash_hex"])
        self.assertNotEqual(vectors["dynamic-layout"]["hash_hex"], vectors["dynamic-fusion-price"]["hash_hex"])
        self.assertNotEqual(vectors["dynamic-layout"]["hash_hex"], vectors["dynamic-work-price"]["hash_hex"])

    def test_parser_matches_dict_result_without_mutation(self):
        claim, selection = copy.deepcopy(self.fixture["baseline"]), self.selection()
        before = copy.deepcopy((claim, selection))
        self.assertEqual(parse_branch_wire(json.dumps(claim).encode("ascii"), **selection), inspect_branch(claim, **selection))
        self.assertEqual((claim, selection), before)

    def test_duplicate_keys_nonfinite_nonascii_and_invalid_json_refused(self):
        for wire in (b'{"anchor":{},"anchor":{}}', b'{"x":NaN}', b'\xff', b'{', b'[]', b'null'):
            if wire in (b'[]', b'null'):
                self.assertEqual(parse_branch_wire(wire, **self.selection())["structure"], "REFUSED")
            else:
                with self.assertRaises(MomentumRefused): parse_branch_wire(wire, **self.selection())

    def test_wire_and_json_depth_bound_is_checked_before_decoding(self):
        for wire in (b'', b' ' * (MAX_WIRE_BYTES + 1), b'[' * 17 + b'0' + b']' * 17):
            with self.assertRaises(MomentumRefused): parse_branch_wire(wire, **self.selection())

    def test_quoted_brackets_do_not_count_as_json_depth(self):
        claim = copy.deepcopy(self.fixture["baseline"]); claim["schema"] = "[" * 20
        self.assertEqual(parse_branch_wire(json.dumps(claim).encode("ascii"), **self.selection())["reason"], "CLAIM_PROFILE")

    def test_extra_fields_and_noncanonical_numbers_refused(self):
        for value in ("01", "-1", "1.0", True, 1, str(1 << 64)):
            block = copy.deepcopy(self.fixture["baseline"]["momenta"][0]["momentum"])
            block["height"] = value
            with self.assertRaises(ValueError): momentum_preimage(block)
        block["height"] = "101"; block["unselected"] = "0"
        with self.assertRaises(MomentumRefused): momentum_preimage(block)

    def test_content_and_lineage_bounds_refused(self):
        block = copy.deepcopy(self.fixture["baseline"]["momenta"][0]["momentum"])
        block["content"] *= MAX_CONTENT
        with self.assertRaises(MomentumRefused): momentum_preimage(block)
        claim = copy.deepcopy(self.fixture["baseline"]); claim["momenta"] *= MAX_MOMENTA
        self.assertEqual(inspect_branch(claim, **self.selection())["reason"], "LINEAGE_BOUND")

    def test_inclusion_bounds_and_metadata_widths_refused(self):
        selection = self.selection(); selection["required_inclusions"] *= 65
        self.assertEqual(inspect_branch(self.fixture["baseline"], **selection)["reason"], "INCLUSION_BOUND")
        claim = copy.deepcopy(self.fixture["baseline"]); claim["momenta"][0]["signature_hex"] = "01"
        self.assertEqual(inspect_branch(claim, **self.selection())["structure"], "REFUSED")

    def test_an_unmatched_retained_inclusion_cannot_authorize_fork_reconciliation(self):
        selection = self.selection(); selection["required_inclusions"][0]["header"]["hash_hex"] = "de" * 32
        result = compare_candidates(self.fixture["baseline"], self.fixture["baseline"], chain_id=selection["chain_id"],
                                    selected_anchor_claim=selection["selected_anchor_claim"], retained_inclusions=selection["required_inclusions"])
        self.assertEqual((result["relation"], result["previous_structure"]), ("UNKNOWN", "INCOMPLETE"))

    def test_reorg_reappearance_does_not_skip_rechecking_displaced_evidence(self):
        vector = next(value for value in self.fixture["reorg_vectors"] if value["id"] == "divergent-fork-rechecks-displaced")
        # The same opaque headers occur in both forks; their confirmation contexts changed.
        self.assertEqual(vector["previous"]["momenta"][1]["momentum"]["content"], vector["candidate"]["momenta"][1]["momentum"]["content"])
        result = compare_candidates(vector["previous"], vector["candidate"], **{
            key: vector[key] for key in ("chain_id", "selected_anchor_claim", "retained_inclusions")})
        self.assertIn("original", result["recheck_inclusions"])
        self.assertIn("recipient_receive", result["recheck_inclusions"])


if __name__ == "__main__": unittest.main()
