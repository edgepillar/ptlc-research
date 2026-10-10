"""Structural comparison never establishes authenticated recovery evidence."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from offline_session.nom_observation import (
    inspect_claim, parse_claim_wire, ObservationRefused, MAX_WIRE_BYTES, ROLES,
)
from offline_session.nom_wire import account_block_hash, decode_call
from offline_session.pr138 import unlock_message
from scripts.generate_nom_observation import corpus

ROOT = Path(__file__).resolve().parents[1]


class NoMObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "compatibility/fixtures/nom_observation_v1.json").read_text("ascii"))

    def result(self, claim, view=None, terms=None):
        return inspect_claim(claim, terms=terms or self.fixture["terms"],
                             selected_view_claim=view or self.fixture["baseline"]["view"])

    def test_all_selected_structural_controls_have_separate_unfilled_gates(self):
        vectors = self.fixture["claim_vectors"]
        self.assertEqual(len(vectors), 48)
        self.assertEqual(len({v["id"] for v in vectors}), 48)
        for vector in vectors:
            with self.subTest(vector=vector["id"]):
                before = json.dumps(vector["claim"], sort_keys=True)
                result = self.result(vector["claim"], vector["selected_view_claim"])
                self.assertEqual((result["structure"], result["reason"]), (vector["expect_structure"], vector["expect_reason"]))
                self.assertEqual(result["recovery_action"], "NONE")
                self.assertEqual(result["source_authentication"], "NOT_PERFORMED")
                self.assertEqual(result["signature_verification"], "NOT_PERFORMED")
                self.assertEqual(result["vm_execution"], "NOT_PERFORMED")
                self.assertEqual(result["canonicality"], "UNFILLED")
                self.assertEqual(result["finality"], "UNFILLED")
                self.assertEqual(result["application"], "NO-GO")
                self.assertEqual(result["core"], "NO-GO")
                self.assertEqual(json.dumps(vector["claim"], sort_keys=True), before)

    def test_self_selected_fork_and_matching_forgery_are_not_authenticated(self):
        for vector in self.fixture["claim_vectors"][:3]:
            self.assertEqual(self.result(vector["claim"], vector["selected_view_claim"])["structure"], "MATCH")
        fork = self.fixture["claim_vectors"][2]
        self.assertEqual(self.result(fork["claim"])["structure"], "REFUSED")

    def test_generation_is_deterministic_and_manifest_pins_every_overlay(self):
        self.assertEqual(corpus(), self.fixture)
        manifest = json.loads((ROOT / "compatibility/nom_observation_manifest.json").read_text("ascii"))
        self.assertEqual(manifest["research_baseline_commit"], "b64bc44719c602e5f23f5a3eb32317b1b0d3ccce")
        for group in ("input_sha256", "preserved_file_sha256"):
            for name, expected in manifest[group].items():
                self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)

    def test_old_witness_context_is_different_from_the_computed_funding_id(self):
        baseline = self.fixture["baseline"]
        funding_id = baseline["records"]["funding"]["hash_hex"]
        self.assertNotEqual(funding_id, self.fixture["seed_entry"]["id_hex"])
        call = decode_call(bytes.fromhex(baseline["records"]["original"]["block"]["data_hex"]))
        self.assertEqual(call["entry_id_hex"], funding_id)
        context = {"profile": "zenon-ptlc-unlock:v1", "chain_id": self.fixture["terms"]["chain_id"],
                   "point_type": 1, "entry_id_hex": funding_id, "destination_hex": self.fixture["terms"]["recipient_hex"]}
        old = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        self.assertNotEqual(unlock_message(context), old["long_message_hex"])
        # The actual-core seeded and created entry checks are a separate run.
        self.assertEqual(self.result(baseline)["signature_verification"], "NOT_PERFORMED")

    def test_absence_cannot_hide_an_invalid_supplied_hash(self):
        claim = copy.deepcopy(self.fixture["baseline"])
        claim["entry"] = None
        claim["records"]["payout"]["block"]["amount"] = "101"
        self.assertEqual(self.result(claim)["reason"], "ADVERTISED_HASH_MISMATCH")

    def test_entry_absence_with_missing_history_remains_incomplete(self):
        claim = copy.deepcopy(self.fixture["baseline"])
        claim.update(entry=None, records=dict.fromkeys(ROLES))
        result = self.result(claim)
        self.assertEqual(result["structure"], "INCOMPLETE")
        self.assertEqual(set(result["missing_claims"]), {*ROLES, "entry"})
        self.assertEqual(result["recovery_action"], "NONE")

    def test_peer_authentication_labels_and_unknown_roles_are_refused(self):
        for mutate in (lambda c: c.update(authenticated=True),
                       lambda c: c["records"].update(other=None),
                       lambda c: c["contexts"].update(trusted=True)):
            claim = copy.deepcopy(self.fixture["baseline"]); mutate(claim)
            self.assertEqual(self.result(claim)["structure"], "REFUSED")

    def test_booleans_and_noncanonical_term_numbers_are_not_uints(self):
        for field, value in (("chain_id", True), ("amount", "0100"), ("expiration_time", "-1"),
                             ("point_type", True), ("point_type", 2), ("amount", str(1 << 255))):
            terms = dict(self.fixture["terms"]); terms[field] = value
            self.assertEqual(self.result(self.fixture["baseline"], terms=terms)["structure"], "REFUSED")

    def test_entry_presence_requires_an_actual_boolean(self):
        for value in (0, 1, "false", None):
            claim = copy.deepcopy(self.fixture["baseline"]); claim["post_entry_present"] = value
            self.assertEqual(self.result(claim)["reason"], "ENTRY_PRESENCE_SHAPE")

    def test_wire_parsing_matches_dict_claims_without_authorizing_use(self):
        wire = json.dumps(self.fixture["baseline"], sort_keys=True).encode("ascii")
        result = parse_claim_wire(wire, terms=self.fixture["terms"], selected_view_claim=self.fixture["baseline"]["view"])
        self.assertEqual(result, self.result(self.fixture["baseline"]))

    def test_duplicate_nonfinite_nonascii_and_deep_json_are_refused(self):
        for wire in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":Infinity}',
                     b'"\xff"', b"[" * 2000 + b"0" + b"]" * 2000, b"{"):
            with self.assertRaises(ObservationRefused):
                parse_claim_wire(wire, terms=self.fixture["terms"], selected_view_claim=self.fixture["baseline"]["view"])

    def test_wire_limit_and_type_are_checked_before_json(self):
        for wire in (b"", b" " * (MAX_WIRE_BYTES + 1), bytearray(b"{}"), "{}"):
            with self.assertRaisesRegex(ObservationRefused, "WIRE_BOUND"):
                parse_claim_wire(wire, terms=self.fixture["terms"], selected_view_claim=self.fixture["baseline"]["view"])

    def test_uint256_hash_width_is_not_positive_amount_admission(self):
        claim = copy.deepcopy(self.fixture["baseline"])
        block = claim["records"]["funding"]["block"]
        block["amount"] = str(1 << 255)
        claim["records"]["funding"]["hash_hex"] = account_block_hash(block)
        self.assertEqual(self.result(claim)["reason"], "FUNDING_TERMS")

    def test_aliased_original_bytes_are_retained_and_never_reencoded(self):
        vector = next(v for v in self.fixture["claim_vectors"] if v["id"] == "aliased-original-is-not-normalized")
        before = vector["claim"]["records"]["original"]["block"]["data_hex"]
        self.assertEqual(self.result(vector["claim"])["structure"], "REFUSED")
        self.assertEqual(vector["claim"]["records"]["original"]["block"]["data_hex"], before)

    def test_known_height_acknowledgement_hashes_cannot_mix_forks(self):
        for role in ("original", "recipient_receive"):
            vector = next(v for v in self.fixture["claim_vectors"] if v["id"] == role + "-known-height-wrong-ack-hash")
            self.assertEqual(self.result(vector["claim"])["reason"], "ACKNOWLEDGEMENT_HASH_CLAIM")
