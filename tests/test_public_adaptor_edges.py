"""Complete public cancellation contexts only; no curve math or signer bridge."""

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
    """Public compressed parity mutation; the Rust backend checks actual points."""
    return ("03" if point[:2] == "02" else "02") + point[2:]


class PublicAdaptorEdgeTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        self.rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json")
                                 .read_text("ascii"))["vectors"]
        self.edges = json.loads((root / "qualification/fixtures/public_nonce_edges.json")
                                .read_text("ascii"))["legs"]

    def binding(self, leg, point=None):
        data = copy.deepcopy(self.data)
        if point is not None:
            data["terms"]["adaptor_point_sec1_hex"] = point
        terms = agree_terms(data["terms"])
        bitcoin = bind_bitcoin(terms, data["bitcoin_binding"])
        return bitcoin if leg == "bitcoin" else bind_zenon(bitcoin, data["zenon_binding"])

    def committed(self, leg, pair, point=None):
        binding = self.binding(leg, point)
        round_id = self.rounds[int(leg == "zenon")]["round_id_hex"]
        openings = [nonce_commitment(binding, round_id, role, nonce)
                    for role, nonce in zip(("alice", "bob"), pair)]
        return binding, commit_nonce_round(binding, round_id, *openings)

    def contexts(self, leg, pair, point=None):
        binding, committed = self.committed(leg, pair, point)
        revealed = reveal_nonce_round(committed, *pair)
        validate_nonce_round(revealed)
        result = []
        for role in ("alice", "bob"):
            context = signing_context(binding, role, leg + "-claim-partial", nonce_round=revealed)
            validate_signing_context(context)
            wire = encode_intent(context)
            self.assertIsNone(require_exact_intent(context, wire))
            self.assertEqual(public_inputs(context)["public_nonces_hex"], pair)
            self.assertEqual(public_inputs(context)["adaptor_point_sec1_hex"],
                             point or self.data["terms"]["adaptor_point_sec1_hex"])
            self.assertEqual(json.loads(wire)["signing_context"], context.as_dict())
            result.append(context)
        return result

    def test_cancelling_fixture_nonce_adaptor_binds_complete_context_but_not_original_intent(self):
        for index, leg in enumerate(("bitcoin", "zenon")):
            pair = self.rounds[index]["public_nonces_hex"]
            # The public pre-signature's first 33 bytes are recomputed by Rust.
            point = opposite_encoding(self.rounds[index]["adaptor_presignature_hex"][:66])
            original = self.contexts(leg, pair)
            changed = self.contexts(leg, pair, point)
            for old, new in zip(original, changed):
                self.assertNotEqual(old.digest_hex, new.digest_hex)
                with self.assertRaises(IntentError):
                    require_exact_intent(old, encode_intent(new))
                with self.assertRaises(IntentError):
                    require_exact_intent(new, encode_intent(old))

    def test_cancelling_generator_adaptor_binds_preserved_cancellation_pair(self):
        negative_generator = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        for index, leg in enumerate(("bitcoin", "zenon")):
            case = next(row for row in self.edges[index]["cases"]
                        if row["name"] == "both_components_cancellation")
            original = self.contexts(leg, self.rounds[index]["public_nonces_hex"])
            changed = self.contexts(leg, case["public_nonces_hex"], negative_generator)
            for old, new in zip(original, changed):
                self.assertNotEqual(old.digest_hex, new.digest_hex)
                with self.assertRaises(IntentError):
                    require_exact_intent(old, encode_intent(new))

    def test_original_role_openings_refuse_rebound_adaptor_terms_even_with_same_nonces(self):
        for index, leg in enumerate(("bitcoin", "zenon")):
            pair = self.rounds[index]["public_nonces_hex"]
            point = opposite_encoding(self.rounds[index]["adaptor_presignature_hex"][:66])
            old_binding, old_committed = self.committed(leg, pair)
            binding = self.binding(leg, point)
            self.assertNotEqual(binding.digest_hex, old_binding.digest_hex)
            openings = old_committed.as_dict()["commitments"]
            stale = commit_nonce_round(binding, self.rounds[index]["round_id_hex"],
                                       openings["alice"], openings["bob"])
            with self.assertRaises(TranscriptError):
                reveal_nonce_round(stale, *pair)


if __name__ == "__main__":
    unittest.main()
