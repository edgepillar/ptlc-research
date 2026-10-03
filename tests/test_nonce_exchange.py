"""Public nonce-round binding tests, without signing or nonce generation.

The sample 66-byte values concatenate existing public test points. They are
encoding/binding examples, not fresh nonces produced or owned by this module.
"""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import unittest

from offline_session.transcript import (
    Commitment,
    TranscriptError,
    agree_terms,
    bind_bitcoin,
    bind_zenon,
    commit_nonce_round,
    nonce_commitment,
    reveal_nonce_round,
    signing_context,
    validate_nonce_round,
    validate_signing_context,
)


def corrupted(payload, encoded=None):
    value = object.__new__(Commitment)
    if encoded is None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    object.__setattr__(value, "_encoded", encoded)
    return value


class NonceExchangeTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).parent / "fixtures/session_terms.json"
        self.fixture = json.loads(path.read_text(encoding="ascii"))
        self.terms = agree_terms(self.fixture["terms"])
        self.bitcoin = bind_bitcoin(self.terms, self.fixture["bitcoin_binding"])
        self.zenon = bind_zenon(self.bitcoin, self.fixture["zenon_binding"])
        self.nonces = (
            "".join(self.fixture["terms"]["bitcoin"]["signer_keys_sec1_hex"]),
            "".join(self.fixture["terms"]["zenon"]["signer_keys_sec1_hex"]),
        )
        self.round_id = "aa" * 32
        self.hashes, self.commitments, self.round = self.make_round(self.bitcoin)

    def make_round(self, binding, round_id=None, nonces=None):
        round_id = self.round_id if round_id is None else round_id
        nonces = self.nonces if nonces is None else nonces
        hashes = tuple(nonce_commitment(binding, round_id, role, public_nonce)
                       for role, public_nonce in zip(("alice", "bob"), nonces))
        commitments = commit_nonce_round(binding, round_id, *hashes)
        return hashes, commitments, reveal_nonce_round(commitments, *nonces)

    def test_canonical_opening_domain_and_components(self):
        payload = {
            "schema": "ptlc-offline-transcript-v1", "stage": "nonce-opening",
            "session_id": self.bitcoin.session_id, "leg": "bitcoin",
            "binding_digest_hex": self.bitcoin.digest_hex,
            "round_id": self.round_id, "role": "alice", "public_nonce_hex": self.nonces[0],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        expected = hashlib.sha256(b"PTLC/offline-transcript/v1\x00nonce-opening\x00" + encoded).hexdigest()
        self.assertEqual(self.hashes[0], expected)
        self.assertNotEqual(expected, hashlib.sha256(encoded).hexdigest())
        self.assertNotEqual(expected, hashlib.sha256(bytes.fromhex(self.nonces[0])).hexdigest())
        swapped_components = self.nonces[0][66:] + self.nonces[0][:66]
        self.assertNotEqual(expected, nonce_commitment(self.bitcoin, self.round_id, "alice", swapped_components))

    def test_pair_and_revealed_round_reconstruct_with_exact_roles(self):
        self.assertEqual(self.commitments.stage, "nonce-commitments")
        self.assertEqual(self.round.stage, "nonce-round")
        self.assertEqual(validate_nonce_round(self.round),
                         (self.bitcoin.session_id, self.bitcoin.digest_hex, self.round_id, self.round.digest_hex))
        data = self.round.as_dict()
        self.assertEqual(data["commitments_digest_hex"], self.commitments.digest_hex)
        self.assertEqual(data["commitments"]["binding"], self.bitcoin.as_dict())
        self.assertEqual(data["public_nonces"], {"alice": self.nonces[0], "bob": self.nonces[1]})
        self.assertNotEqual(self.commitments.digest_hex, self.round.digest_hex)
        self.assertNotIn("public_nonces", self.commitments.as_dict())

    def test_opening_is_bound_to_role_round_leg_session_and_chain_binding(self):
        self.assertNotEqual(self.hashes[0], nonce_commitment(self.bitcoin, self.round_id, "bob", self.nonces[0]))
        self.assertNotEqual(self.hashes[0], nonce_commitment(self.bitcoin, "bb" * 32, "alice", self.nonces[0]))
        self.assertNotEqual(self.hashes[0], nonce_commitment(self.zenon, self.round_id, "alice", self.nonces[0]))
        changed_binding = copy.deepcopy(self.fixture["bitcoin_binding"])
        changed_binding["funding_vout"] += 1
        other_binding = bind_bitcoin(self.terms, changed_binding)
        self.assertNotEqual(self.hashes[0], nonce_commitment(other_binding, self.round_id, "alice", self.nonces[0]))
        for path, new_value in (("session_id", "77" * 32), ("genesis_hash_hex", "88" * 32)):
            changed_terms = copy.deepcopy(self.fixture["terms"])
            if path == "session_id":
                changed_terms[path] = new_value
            else:
                changed_terms["bitcoin_network"][path] = new_value
            binding = bind_bitcoin(agree_terms(changed_terms), self.fixture["bitcoin_binding"])
            with self.subTest(path=path):
                self.assertNotEqual(self.hashes[0], nonce_commitment(binding, self.round_id, "alice", self.nonces[0]))

    def test_reflected_swapped_and_mismatched_openings_fail(self):
        for nonces in ((self.nonces[1], self.nonces[0]),
                       (self.nonces[0][66:] + self.nonces[0][:66], self.nonces[1]),
                       (self.nonces[0], self.nonces[1][66:] + self.nonces[1][:66])):
            with self.subTest(nonces=nonces), self.assertRaises(TranscriptError):
                reveal_nonce_round(self.commitments, *nonces)
        swapped = commit_nonce_round(self.bitcoin, self.round_id, self.hashes[1], self.hashes[0])
        with self.assertRaises(TranscriptError):
            reveal_nonce_round(swapped, *self.nonces)
        with self.assertRaises(TranscriptError):
            commit_nonce_round(self.bitcoin, self.round_id, self.hashes[0], self.hashes[0])
        wrong_round = commit_nonce_round(self.bitcoin, "bb" * 32, *self.hashes)
        with self.assertRaises(TranscriptError):
            reveal_nonce_round(wrong_round, *self.nonces)
        wrong_leg = commit_nonce_round(self.zenon, self.round_id, *self.hashes)
        with self.assertRaises(TranscriptError):
            reveal_nonce_round(wrong_leg, *self.nonces)

    def test_equal_signer_nonces_fail_even_when_role_hashes_differ(self):
        same_nonce = self.nonces[0]
        bob_hash = nonce_commitment(self.bitcoin, self.round_id, "bob", same_nonce)
        self.assertNotEqual(self.hashes[0], bob_hash)
        pair = commit_nonce_round(self.bitcoin, self.round_id, self.hashes[0], bob_hash)
        with self.assertRaises(TranscriptError):
            reveal_nonce_round(pair, same_nonce, same_nonce)

    def test_no_reveal_without_a_valid_complete_pair(self):
        for predecessor in (self.terms, self.bitcoin, self.zenon, self.round, None, self.hashes[0]):
            with self.subTest(predecessor=type(predecessor).__name__), self.assertRaises(TranscriptError):
                reveal_nonce_round(predecessor, *self.nonces)
        for field in ("alice", "bob"):
            data = self.commitments.as_dict()
            del data["commitments"][field]
            with self.assertRaises(TranscriptError):
                reveal_nonce_round(corrupted(data), *self.nonces)

    def test_malformed_nonce_encodings_roles_rounds_and_hashes_fail(self):
        good = self.nonces[0]
        malformed = (good[:-2], good + "00", good.upper(), "gg" * 66, "00" * 66,
                     "00" * 33 + good[66:], good[:66] + "00" * 33,
                     "02" + "00" * 32 + good[66:], good[:66] + "03" + "00" * 32,
                     "04" + good[2:], good[:66] + "04" + good[68:],
                     b"bytes", None, True, 1, " " + good)
        for public_nonce in malformed:
            with self.subTest(public_nonce=public_nonce), self.assertRaises(TranscriptError):
                nonce_commitment(self.bitcoin, self.round_id, "alice", public_nonce)
            with self.assertRaises(TranscriptError):
                reveal_nonce_round(self.commitments, public_nonce, self.nonces[1])
        for role in ("Alice", "carol", "", None, True):
            with self.subTest(role=role), self.assertRaises(TranscriptError):
                nonce_commitment(self.bitcoin, self.round_id, role, good)
        for round_id in ("a", "AA" * 32, "gg" * 32, None, True, 1):
            with self.subTest(round_id=round_id), self.assertRaises(TranscriptError):
                commit_nonce_round(self.bitcoin, round_id, *self.hashes)
        for value in ("00", "GG" * 32, self.hashes[0].upper(), None, True):
            with self.subTest(hash=value), self.assertRaises(TranscriptError):
                commit_nonce_round(self.bitcoin, self.round_id, value, self.hashes[1])

    def test_static_legacy_context_is_distinct_from_dynamic_context(self):
        static = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial")
        dynamic = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial", nonce_round=self.round)
        self.assertNotIn("nonce_round", static.as_dict())
        self.assertNotIn("nonce_round_digest_hex", static.as_dict())
        self.assertEqual(static.digest_hex, "59a0ce6d925e8a6a5d07e8922714b954ba9db6ac58d8eb35e9333d81ae7082a3")
        self.assertNotEqual(static.digest_hex, dynamic.digest_hex)
        self.assertEqual(dynamic.as_dict()["nonce_round"], self.round.as_dict())
        self.assertEqual(dynamic.as_dict()["nonce_round_digest_hex"], self.round.digest_hex)
        self.assertEqual(validate_signing_context(dynamic), (self.terms.session_id, dynamic.digest_hex, "bitcoin-claim-partial"))

    def test_partials_and_completion_can_bind_one_exact_round(self):
        for binding, nonce_round, prefix, completer in (
            (self.bitcoin, self.round, "bitcoin", "bob"),
            (self.zenon, self.make_round(self.zenon)[2], "zenon", "alice"),
        ):
            contexts = [signing_context(binding, role, prefix + "-claim-partial", nonce_round=nonce_round)
                        for role in ("alice", "bob")]
            contexts.append(signing_context(binding, completer, prefix + "-claim-complete", nonce_round=nonce_round))
            self.assertEqual(len({context.digest_hex for context in contexts}), 3)
            for context in contexts:
                validate_signing_context(context)
                self.assertEqual(context.as_dict()["nonce_round_digest_hex"], nonce_round.digest_hex)
        # Stateless construction cannot enforce shared-round history; the journal pins it.
        another_round = self.make_round(self.bitcoin, round_id="bb" * 32)[2]
        changed = signing_context(self.bitcoin, "bob", "bitcoin-claim-complete", nonce_round=another_round)
        self.assertNotEqual(changed.as_dict()["nonce_round_digest_hex"], self.round.digest_hex)

    def test_context_rejects_round_for_other_leg_or_exact_binding(self):
        with self.assertRaises(TranscriptError):
            signing_context(self.zenon, "alice", "zenon-claim-partial", nonce_round=self.round)
        changed = copy.deepcopy(self.fixture["bitcoin_binding"])
        changed["funding_vout"] += 1
        other = bind_bitcoin(self.terms, changed)
        with self.assertRaises(TranscriptError):
            signing_context(other, "alice", "bitcoin-claim-partial", nonce_round=self.round)
        for invalid in (self.commitments, self.bitcoin, True, "round"):
            with self.assertRaises(TranscriptError):
                signing_context(self.bitcoin, "alice", "bitcoin-claim-partial", nonce_round=invalid)

    def test_round_reconstruction_rejects_changed_declared_context_and_hashes(self):
        for field, value in (("leg", "zenon"), ("session_id", "77" * 32),
                             ("round_id", "bb" * 32), ("binding_digest_hex", "77" * 32),
                             ("commitments_digest_hex", "77" * 32), ("schema", "future")):
            changed = self.round.as_dict()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(TranscriptError):
                validate_nonce_round(corrupted(changed))
        for target in ("commitments", "public_nonces"):
            changed = self.round.as_dict()
            changed[target]["carol"] = "00" * 32
            with self.assertRaises(TranscriptError):
                validate_nonce_round(corrupted(changed))
        changed = self.round.as_dict()
        changed["commitments"]["commitments"]["alice"] = "77" * 32
        with self.assertRaises(TranscriptError):
            validate_nonce_round(corrupted(changed))
        raw = json.dumps(self.round.as_dict(), indent=2).encode("ascii")
        with self.assertRaises(TranscriptError):
            validate_nonce_round(corrupted(None, raw))

    def test_dynamic_context_requires_both_optional_fields_and_full_reconstruction(self):
        context = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial", nonce_round=self.round)
        for field in ("nonce_round", "nonce_round_digest_hex"):
            changed = context.as_dict()
            del changed[field]
            with self.subTest(field=field), self.assertRaises(TranscriptError):
                validate_signing_context(corrupted(changed))
        changed = context.as_dict()
        changed["nonce_round_digest_hex"] = "77" * 32
        with self.assertRaises(TranscriptError):
            validate_signing_context(corrupted(changed))
        changed = context.as_dict()
        changed["nonce_round"]["public_nonces"]["alice"] = self.nonces[1]
        with self.assertRaises(TranscriptError):
            validate_signing_context(corrupted(changed))
        changed = context.as_dict()
        changed["nonce_round"] = self.commitments.as_dict()
        with self.assertRaises(TranscriptError):
            validate_signing_context(corrupted(changed))

    def test_returned_views_cannot_mutate_round_or_signing_context(self):
        context = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial", nonce_round=self.round)
        original = (self.commitments.canonical_bytes, self.round.canonical_bytes, context.canonical_bytes)
        pair_view = self.commitments.as_dict()
        pair_view["commitments"]["alice"] = "ff" * 32
        view = context.as_dict()
        view["nonce_round"]["public_nonces"]["alice"] = self.nonces[1]
        view["nonce_round"]["commitments"]["binding"]["binding"]["funding_vout"] = 3
        self.assertEqual(original, (self.commitments.canonical_bytes, self.round.canonical_bytes, context.canonical_bytes))
        with self.assertRaises(FrozenInstanceError):
            self.round._encoded = b"{}"
        validate_signing_context(context)

    def test_shape_checks_do_not_claim_curve_validity_or_global_freshness(self):
        # Nonzero coordinate bytes of the right shape are not parsed as curve points here.
        arbitrary = "02" + "ff" * 32 + "03" + "ee" * 32
        _, _, shape_round = self.make_round(self.bitcoin, nonces=(arbitrary, self.nonces[1]))
        validate_nonce_round(shape_round)
        # Repeating public encodings under another round changes its binding; this pure API
        # has no history and does not establish nonce freshness or authorize another use.
        repeated = self.make_round(self.bitcoin, round_id="cc" * 32)[2]
        self.assertNotEqual(repeated.digest_hex, self.round.digest_hex)
        self.assertEqual(repeated.as_dict()["public_nonces"], self.round.as_dict()["public_nonces"])


if __name__ == "__main__":
    unittest.main()
