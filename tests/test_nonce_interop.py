"""Cross-language public commitments and fixture replay, never a signer bridge."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from offline_session.journal import Conflict, Journal
from offline_session.transcript import (
    agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round, nonce_commitment,
    reveal_nonce_round, signing_context, validate_nonce_round,
)


class NonceInteropTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        corpus = json.loads((root / "qualification/fixtures/nonce_rounds.json").read_text("ascii"))
        self.assertEqual(corpus["schema"], "ptlc-public-nonce-round-fixture-v1")
        self.assertEqual([item["leg"] for item in corpus["vectors"]], ["bitcoin", "zenon"])
        self.vectors = corpus["vectors"]
        self.terms = agree_terms(data["terms"])
        bitcoin = bind_bitcoin(self.terms, data["bitcoin_binding"])
        self.bindings = {"bitcoin": bitcoin, "zenon": bind_zenon(bitcoin, data["zenon_binding"])}

    def _round(self, vector):
        binding = self.bindings[vector["leg"]]
        commitments = commit_nonce_round(binding, vector["round_id_hex"], *vector["nonce_commitments_hex"])
        return reveal_nonce_round(commitments, *vector["public_nonces_hex"])

    def test_rust_and_python_agree_on_exact_staged_commitments(self):
        all_public_nonces = []
        for vector in self.vectors:
            binding = self.bindings[vector["leg"]]
            self.assertEqual(binding.digest_hex, vector["binding_digest_hex"])
            for index, role in enumerate(("alice", "bob")):
                self.assertEqual(nonce_commitment(binding, vector["round_id_hex"], role,
                                                  vector["public_nonces_hex"][index]),
                                 vector["nonce_commitments_hex"][index])
            nonce_round = self._round(vector)
            self.assertEqual(nonce_round.digest_hex, vector["round_digest_hex"])
            self.assertEqual(validate_nonce_round(nonce_round), (
                self.terms.session_id, binding.digest_hex, vector["round_id_hex"], nonce_round.digest_hex,
            ))
            all_public_nonces.extend(vector["public_nonces_hex"])
        self.assertEqual(len(set(all_public_nonces)), 4)

    def test_both_roles_and_completion_reference_the_same_round(self):
        for vector in self.vectors:
            leg = vector["leg"]
            binding, nonce_round = self.bindings[leg], self._round(vector)
            roles = [("alice", "partial"), ("bob", "partial"),
                     ("alice" if leg == "zenon" else "bob", "complete")]
            contexts = [signing_context(binding, role, leg + "-claim-" + purpose, nonce_round=nonce_round)
                        for role, purpose in roles]
            self.assertEqual(len({item.digest_hex for item in contexts}), 3)
            self.assertEqual({item.as_dict()["nonce_round_digest_hex"] for item in contexts},
                             {vector["round_digest_hex"]})

    def test_journal_records_and_replays_fixture_bytes_for_six_dynamic_scopes(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-public-interop-") as directory:
            base = Path(directory)
            records, calls = [], []
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.create_session(self.terms.session_id, self.terms.digest_hex)
                for vector in self.vectors:
                    leg, nonce_round = vector["leg"], self._round(vector)
                    actions = [("alice", "partial", vector["partial_signatures_hex"][0]),
                               ("bob", "partial", vector["partial_signatures_hex"][1]),
                               ("alice" if leg == "zenon" else "bob", "complete", vector["signature_hex"])]
                    for role, purpose, artifact in actions:
                        context = signing_context(self.bindings[leg], role, leg + "-claim-" + purpose,
                                                  nonce_round=nonce_round)
                        operation = format(len(records) + 1, "064x")
                        tag = format(len(records) + 101, "064x")
                        expected = bytes.fromhex(artifact)
                        journal.reserve(self.terms.session_id, operation, context, tag)
                        # This only returns a checked-in public fixture; it performs no signing.
                        output = journal.produce_once(self.terms.session_id, operation, expected_context=context,
                                                      callback=lambda: calls.append(operation) or expected)
                        self.assertEqual(output, expected)
                        records.append((operation, context, expected))
                self.assertTrue(journal.get_session(self.terms.session_id)["possible_exposure"])
            with Journal.open(base / "state", base / "head.json") as journal:
                for operation, context, expected in records:
                    self.assertEqual(journal.replay(self.terms.session_id, operation, expected_context=context), expected)
                self.assertEqual(journal.get_session(self.terms.session_id)["signing_rounds"], {
                    vector["leg"]: vector["round_digest_hex"] for vector in self.vectors
                })
            self.assertEqual(len(calls), 6)

    def test_other_valid_round_cannot_replay_a_recorded_output(self):
        vector = self.vectors[1]
        binding, nonce_round = self.bindings["zenon"], self._round(vector)
        context = signing_context(binding, "alice", "zenon-claim-complete", nonce_round=nonce_round)
        other = copy.deepcopy(vector)
        other["round_id_hex"] = "77" * 32
        other["nonce_commitments_hex"] = [nonce_commitment(binding, other["round_id_hex"], role, nonce)
                                            for role, nonce in zip(("alice", "bob"), other["public_nonces_hex"])]
        wrong = signing_context(binding, "alice", "zenon-claim-complete", nonce_round=self._round(other))
        with tempfile.TemporaryDirectory(prefix="ptlc-public-replay-") as directory:
            base = Path(directory)
            with Journal.open(base / "state", base / "head.json") as journal:
                journal.create_session(self.terms.session_id, self.terms.digest_hex)
                journal.reserve(self.terms.session_id, "01" * 32, context, "02" * 32)
                journal.produce_once(self.terms.session_id, "01" * 32, expected_context=context,
                                     callback=lambda: b"public-fixture-output")
                with self.assertRaises(Conflict):
                    journal.replay(self.terms.session_id, "01" * 32, expected_context=wrong)


if __name__ == "__main__":
    unittest.main()
