"""Public transcript boundaries only; no curve math, signer or nonce generation."""

import copy
import json
from pathlib import Path
import unittest

from offline_session.nonce_intent import (
    IntentError, encode_intent, public_inputs, require_exact_intent,
)
from offline_session.transcript import (
    TranscriptError, agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round,
    nonce_commitment, reveal_nonce_round, signing_context, validate_nonce_round,
    validate_signing_context,
)


def opposite_encoding(point):
    """Flip only the compressed public point parity; backend tests parse it."""
    return ("03" if point[:2] == "02" else "02") + point[2:]


class PublicNonceEdgeTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        self.rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json")
                                 .read_text("ascii"))["vectors"]
        self.corpus = json.loads((root / "qualification/fixtures/public_nonce_edges.json")
                                 .read_text("ascii"))
        public = json.loads((root / "tests/fixtures/bip340_public_vectors.json")
                            .read_text("ascii"))
        noncurve = next(row for row in public["vectors"] if row["index"] == 5)
        self.assertFalse(noncurve["valid"])
        self.noncurve_x = noncurve["public_key_hex"]
        self.assertTrue(0 < int(self.noncurve_x, 16)
                        < 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f)

    def cases(self, leg):
        return self.corpus["legs"][int(leg == "zenon")]["cases"]

    def binding(self, leg, data=None):
        data = self.data if data is None else data
        terms = agree_terms(data["terms"])
        bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
        return bitcoin if leg == "bitcoin" else bind_zenon(bitcoin, data["zenon_binding"])

    def committed(self, leg, pair, data=None):
        binding = self.binding(leg, data)
        round_id = self.rounds[int(leg == "zenon")]["round_id_hex"]
        openings = [nonce_commitment(binding, round_id, role, nonce)
                    for role, nonce in zip(("alice", "bob"), pair)]
        return binding, commit_nonce_round(binding, round_id, *openings)

    def contexts(self, leg, pair, data=None):
        binding, commitments = self.committed(leg, pair, data)
        revealed = reveal_nonce_round(commitments, *pair)
        validate_nonce_round(revealed)
        contexts = []
        for role in ("alice", "bob"):
            context = signing_context(binding, role, leg + "-claim-partial",
                                      nonce_round=revealed)
            validate_signing_context(context)
            wire = encode_intent(context)
            self.assertIsNone(require_exact_intent(context, wire))
            self.assertEqual(public_inputs(context)["public_nonces_hex"], pair)
            self.assertEqual(json.loads(wire)["signing_context"], context.as_dict())
            contexts.append(context)
        return contexts

    def test_edge_corpus_is_exactly_derived_from_preserved_public_nonces(self):
        self.assertEqual(set(self.corpus), {"schema", "note", "legs"})
        self.assertEqual(self.corpus["schema"], "ptlc-public-nonce-edge-corpus-v1")
        self.assertEqual(len(self.corpus["legs"]), 2)
        for index, leg in enumerate(("bitcoin", "zenon")):
            a, b = self.rounds[index]["public_nonces_hex"]
            a1, a2, b1, b2 = a[:66], a[66:], b[:66], b[66:]
            expected = [
                ("baseline", [a, b], True, [False, False]),
                ("equal_full", [a, a], False, [False, False]),
                ("shared_first_component", [a, a1 + b2], True, [False, False]),
                ("shared_second_component", [a, b1 + a2], True, [False, False]),
                ("repeated_components_in_alice_nonce", [a1 + a1, b], True, [False, False]),
                ("first_component_cancellation", [a, opposite_encoding(a1) + b2], True, [True, False]),
                ("second_component_cancellation", [a, b1 + opposite_encoding(a2)], True, [False, True]),
                ("both_components_cancellation", [a, opposite_encoding(a1) + opposite_encoding(a2)], True, [True, True]),
            ]
            row = self.corpus["legs"][index]
            self.assertEqual(set(row), {"leg", "cases"})
            self.assertEqual(row["leg"], leg)
            self.assertEqual(len(row["cases"]), len(expected))
            for case, (name, pair, allowed, infinity) in zip(row["cases"], expected):
                self.assertEqual(set(case), {"name", "public_nonces_hex", "python_round_accepts",
                                             "aggregate_components_infinity"})
                self.assertEqual(case, dict(name=name, public_nonces_hex=pair,
                                           python_round_accepts=allowed,
                                           aggregate_components_infinity=infinity))

    def test_full_nonce_reflection_refuses_even_with_correct_role_openings(self):
        for leg in ("bitcoin", "zenon"):
            case = self.cases(leg)[1]
            pair = case["public_nonces_hex"]
            binding, commitments = self.committed(leg, pair)
            self.assertEqual(pair[0], pair[1])
            hashes = commitments.as_dict()["commitments"]
            self.assertNotEqual(hashes["alice"], hashes["bob"])
            with self.assertRaises(TranscriptError):
                reveal_nonce_round(commitments, *pair)

    def test_shared_and_repeated_components_pass_full_transcript_shape_only(self):
        for leg in ("bitcoin", "zenon"):
            for case in self.cases(leg)[2:5]:
                with self.subTest(leg=leg, case=case["name"]):
                    pair = case["public_nonces_hex"]
                    self.assertNotEqual(pair[0], pair[1])
                    self.contexts(leg, pair)

    def test_public_cancellation_passes_full_transcript_shape_only(self):
        for leg in ("bitcoin", "zenon"):
            for case in self.cases(leg)[5:]:
                with self.subTest(leg=leg, case=case["name"]):
                    self.contexts(leg, case["public_nonces_hex"])

    def test_in_field_noncurve_nonce_components_pass_transcript_shape_only(self):
        for index, leg in enumerate(("bitcoin", "zenon")):
            for prefix in ("02", "03"):
                for role in range(2):
                    for component in range(2):
                        with self.subTest(leg=leg, prefix=prefix, role=role, component=component):
                            pair = list(self.rounds[index]["public_nonces_hex"])
                            at = component * 66
                            pair[role] = pair[role][:at] + prefix + self.noncurve_x + pair[role][at + 66:]
                            self.contexts(leg, pair)

    def test_in_field_noncurve_signer_keys_and_adaptor_pass_transcript_shape_only(self):
        for index, leg in enumerate(("bitcoin", "zenon")):
            for prefix in ("02", "03"):
                for target in ("alice", "bob", "adaptor"):
                    with self.subTest(leg=leg, prefix=prefix, target=target):
                        data = copy.deepcopy(self.data)
                        point = prefix + self.noncurve_x
                        if target == "adaptor":
                            data["terms"]["adaptor_point_sec1_hex"] = point
                        else:
                            data["terms"][leg]["signer_keys_sec1_hex"][int(target == "bob")] = point
                        for context in self.contexts(leg, self.rounds[index]["public_nonces_hex"], data):
                            inputs = public_inputs(context)
                            actual = (inputs["adaptor_point_sec1_hex"] if target == "adaptor" else
                                      inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"][int(target == "bob")])
                            self.assertEqual(actual, point)

    def test_individual_infinity_encodings_refuse_transcript_shape(self):
        for index, leg in enumerate(("bitcoin", "zenon")):
            for role in range(2):
                for component in range(2):
                    pair = list(self.rounds[index]["public_nonces_hex"])
                    at = component * 66
                    pair[role] = pair[role][:at] + "00" * 33 + pair[role][at + 66:]
                    with self.subTest(leg=leg, role=role, component=component), self.assertRaises(TranscriptError):
                        self.committed(leg, pair)

    def test_changed_public_pairs_cannot_use_old_openings_or_replace_selected_intent(self):
        for leg in ("bitcoin", "zenon"):
            baseline = self.cases(leg)[0]["public_nonces_hex"]
            _, old_commitments = self.committed(leg, baseline)
            expected = self.contexts(leg, baseline)
            for case in self.cases(leg)[1:]:
                pair = case["public_nonces_hex"]
                with self.subTest(leg=leg, case=case["name"]):
                    with self.assertRaises(TranscriptError):
                        reveal_nonce_round(old_commitments, *pair)
                    if case["python_round_accepts"]:
                        for selected, changed in zip(expected, self.contexts(leg, pair)):
                            with self.assertRaises(IntentError) as caught:
                                require_exact_intent(selected, encode_intent(changed))
                            self.assertEqual(str(caught.exception), "public nonce intent refused")
