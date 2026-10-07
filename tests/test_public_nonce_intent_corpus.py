"""Bind the public Rust conformance corpus to the existing Python factory."""

import json
from pathlib import Path
import unittest

from offline_session.nonce_intent import encode_intent, require_exact_intent
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round,
    nonce_commitment, reveal_nonce_round, signing_context,
)


class PublicNonceIntentCorpusTests(unittest.TestCase):
    def test_four_fixed_intents_equal_complete_factory_outputs(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        rounds = json.loads((root / "qualification/fixtures/nonce_rounds.json")
                            .read_text("ascii"))["vectors"]
        corpus = json.loads((root / "qualification/fixtures/public_nonce_intents.json")
                            .read_text("ascii"))
        self.assertEqual(set(corpus), {"schema", "note", "vectors"})
        self.assertEqual(corpus["schema"], "ptlc-public-nonce-intent-corpus-v1")
        self.assertEqual(len(corpus["vectors"]), 4)
        actual = []
        for leg, vector in zip(("bitcoin", "zenon"), rounds):
            terms = agree_terms(data["terms"])
            binding = bind_bitcoin(terms, data["bitcoin_binding"])
            if leg == "zenon":
                binding = bind_zenon(binding, data["zenon_binding"])
            commitments = [nonce_commitment(binding, vector["round_id_hex"], role, nonce)
                           for role, nonce in zip(("alice", "bob"), vector["public_nonces_hex"])]
            committed = commit_nonce_round(binding, vector["round_id_hex"], *commitments)
            revealed = reveal_nonce_round(committed, *vector["public_nonces_hex"])
            for role in ("alice", "bob"):
                context = signing_context(binding, role, leg + "-claim-partial",
                                          nonce_round=revealed)
                packet = corpus["vectors"][len(actual)]
                wire = json.dumps(packet, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True, allow_nan=False).encode("ascii")
                self.assertEqual(wire, encode_intent(context))
                self.assertIsNone(require_exact_intent(context, wire))
                actual.append((packet["signing_context"]["leg"],
                               packet["signing_context"]["role"]))
        self.assertEqual(actual, [(leg, role) for leg in ("bitcoin", "zenon")
                                 for role in ("alice", "bob")])
