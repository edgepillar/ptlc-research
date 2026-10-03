"""Finite public transcript checks; no crypto signing or chain access."""

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
    signing_context,
    validate_signing_context,
)


ROOT = Path(__file__).resolve().parents[1]


def fixture():
    return json.loads((ROOT / "tests/fixtures/session_terms.json").read_text(encoding="ascii"))


def reversed_objects(value):
    if type(value) is dict:
        return {key: reversed_objects(item) for key, item in reversed(list(value.items()))}
    if type(value) is list:
        return [reversed_objects(item) for item in value]
    return value


def corrupt_snapshot(payload, encoded=None):
    """Simulate corrupted stored bytes, bypassing the deliberately closed constructor."""
    value = object.__new__(Commitment)
    if encoded is None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    object.__setattr__(value, "_encoded", encoded)
    return value


class SessionTranscriptTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()
        self.terms = agree_terms(self.data["terms"])
        self.bitcoin = bind_bitcoin(self.terms, self.data["bitcoin_binding"])
        self.zenon = bind_zenon(self.bitcoin, self.data["zenon_binding"])

    def test_public_source_fixture_alignment(self):
        btc = json.loads((ROOT / "qualification/fixtures/bitcoin_transactions.json").read_text())
        sigs = json.loads((ROOT / "qualification/fixtures/completed_signatures.json").read_text())
        self.assertEqual(self.data["bitcoin_binding"]["claim_sighash_hex"], btc["claim"]["sighash_hex"])
        self.assertEqual(self.data["bitcoin_binding"]["claim_txid_hex"], btc["claim"]["txid_hex"])
        self.assertEqual(self.data["bitcoin_binding"]["funding_txid_hex"], btc["funding"]["txid_hex"])
        self.assertEqual(self.data["bitcoin_binding"]["funding_vout"], btc["funding"]["vout"])
        self.assertEqual(self.data["terms"]["bitcoin"]["output_key_xonly_hex"], btc["taproot"]["output_key_xonly_hex"])
        self.assertEqual(self.data["terms"]["bitcoin"]["refund_leaf_script_hex"], btc["taproot"]["refund_leaf_script_hex"])
        self.assertEqual(self.data["zenon_binding"]["message_hex"], sigs["vectors"][3]["message_hex"])
        self.assertEqual(self.data["terms"]["zenon"]["aggregate_key_xonly_hex"], sigs["vectors"][3]["public_key_hex"])

    def test_known_versioned_domain_separated_digests(self):
        self.assertEqual(self.terms.digest_hex, "b2d5c9432419ec4ef569ad94afbefa3c4f94872266db706a66e35384e687a556")
        self.assertEqual(self.bitcoin.digest_hex, "cdfdacfd8675c0a668cceb3756a961be3a3fbbebd33891b339cb3bb47f99e20e")
        self.assertEqual(self.zenon.digest_hex, "9c479abda2256dd14c3cf88105e466d33b36c20314e2f75077849b0a561c55ee")
        context = signing_context(self.zenon, "alice", "zenon-claim-complete")
        self.assertEqual(context.digest_hex, "00616a9b4ea94a544387ebd30223e377aa2f948e21fb424e4fdbd7da294cbac4")
        canonical = json.dumps(self.terms.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        self.assertEqual(self.terms.canonical_bytes, canonical)
        self.assertEqual(self.terms.digest_hex, hashlib.sha256(b"PTLC/offline-transcript/v1\x00terms\x00" + canonical).hexdigest())
        self.assertNotEqual(self.terms.digest_hex, hashlib.sha256(canonical).hexdigest())
        self.assertNotEqual(self.terms.digest_hex, hashlib.sha256(b"PTLC/offline-transcript/v1\x00bitcoin\x00" + canonical).hexdigest())

    def test_object_order_is_irrelevant_but_key_order_is_bound(self):
        reordered = agree_terms(reversed_objects(self.data["terms"]))
        self.assertEqual(reordered, self.terms)
        binding = bind_bitcoin(reordered, reversed_objects(self.data["bitcoin_binding"]))
        self.assertEqual(binding, self.bitcoin)
        changed = copy.deepcopy(self.data["terms"])
        changed["bitcoin"]["signer_keys_sec1_hex"].reverse()
        self.assertNotEqual(agree_terms(changed).digest_hex, self.terms.digest_hex)

    def test_inputs_and_returned_views_cannot_mutate_commitments(self):
        before = (self.terms.canonical_bytes, self.bitcoin.canonical_bytes, self.zenon.canonical_bytes)
        self.data["terms"]["bitcoin"]["signer_keys_sec1_hex"].reverse()
        self.data["terms"]["bitcoin_network"]["genesis_hash_hex"] = "ff" * 32
        self.data["bitcoin_binding"]["funding_vout"] = 100
        self.data["zenon_binding"]["entry_id_hex"] = "ff" * 32
        view = self.zenon.as_dict()
        view["bitcoin"]["terms"]["bitcoin"]["signer_keys_sec1_hex"].clear()
        self.assertEqual(before, (self.terms.canonical_bytes, self.bitcoin.canonical_bytes, self.zenon.canonical_bytes))
        with self.assertRaises(FrozenInstanceError):
            self.terms._encoded = b"{}"
        with self.assertRaises(TypeError):
            Commitment()

    def test_bitcoin_signing_precedes_known_zenon_entry(self):
        self.assertNotIn(b"entry_id_hex", self.terms.canonical_bytes)
        self.assertNotIn(b"entry_id_hex", self.bitcoin.canonical_bytes)
        partial = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial")
        self.assertEqual(validate_signing_context(partial)[2], "bitcoin-claim-partial")
        self.assertEqual(self.zenon.as_dict()["bitcoin_digest_hex"], self.bitcoin.digest_hex)
        self.assertEqual(self.bitcoin.as_dict()["terms_digest_hex"], self.terms.digest_hex)
        with self.assertRaises(TranscriptError):
            bind_zenon(self.terms, self.data["zenon_binding"])
        with self.assertRaises(TranscriptError):
            signing_context(self.bitcoin, "alice", "zenon-claim-partial")
        with self.assertRaises(TranscriptError):
            bind_bitcoin(self.zenon, self.data["bitcoin_binding"])

    def test_all_allowed_roles_and_purposes_have_distinct_contexts(self):
        contexts = []
        for binding, purpose, roles in (
            (self.bitcoin, "bitcoin-claim-partial", ("alice", "bob")),
            (self.zenon, "zenon-claim-partial", ("alice", "bob")),
            (self.zenon, "zenon-claim-complete", ("alice",)),
            (self.bitcoin, "bitcoin-claim-complete", ("bob",)),
        ):
            for role in roles:
                context = signing_context(binding, role, purpose)
                self.assertEqual(validate_signing_context(context), (self.terms.session_id, context.digest_hex, purpose))
                self.assertEqual(context.as_dict()["binding_digest_hex"], binding.digest_hex)
                contexts.append(context.digest_hex)
        self.assertEqual(len(set(contexts)), 6)
        for binding, role, purpose in (
            (self.zenon, "bob", "zenon-claim-complete"),
            (self.bitcoin, "alice", "bitcoin-claim-complete"),
            (self.zenon, "alice", "bitcoin-claim-partial"),
            (self.bitcoin, "alice", "claim"),
            (self.bitcoin, True, "bitcoin-claim-partial"),
            (self.bitcoin, "Alice", "bitcoin-claim-partial"),
        ):
            with self.subTest(role=role, purpose=purpose), self.assertRaises(TranscriptError):
                signing_context(binding, role, purpose)

    def test_term_mutations_change_commitment(self):
        mutations = [
            (("session_id",), "77" * 32),
            (("alice_id_hex",), "77" * 32),
            (("bob_id_hex",), "77" * 32),
            (("bitcoin_network", "label"), "another-bitcoin"),
            (("bitcoin_network", "genesis_hash_hex"), "77" * 32),
            (("zenon_network", "genesis_hash_hex"), "77" * 32),
            (("zenon_network", "chain_id"), 2),
            (("adaptor_point_sec1_hex",), "03" + self.data["terms"]["adaptor_point_sec1_hex"][2:]),
            (("bitcoin", "refund_locktime"), 500000101),
            (("bitcoin", "tapleaf_hash_hex"), "77" * 32),
            (("bitcoin", "refund_key_xonly_hex"), "77" * 32),
            (("bitcoin", "output_key_xonly_hex"), "77" * 32),
            (("zenon", "amount_base_units"), 100000001),
            (("zenon", "token_standard_hex"), "77" * 10),
            (("zenon", "destination_hex"), "77" * 20),
            (("zenon", "refund_owner_hex"), "77" * 20),
            (("zenon", "expiry"), 500000049),
            (("policy", "minimum_claim_margin_seconds"), 31),
        ]
        for path, value in mutations:
            changed = copy.deepcopy(self.data["terms"])
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertNotEqual(agree_terms(changed).digest_hex, self.terms.digest_hex)

    def test_binding_changes_propagate_to_descendants_and_signing_context(self):
        old_context = signing_context(self.zenon, "alice", "zenon-claim-complete")
        for field, value in (("funding_txid_hex", "88" * 32), ("funding_vout", 2),
                             ("claim_txid_hex", "88" * 32), ("claim_sighash_hex", "88" * 32)):
            changed = copy.deepcopy(self.data["bitcoin_binding"])
            changed[field] = value
            new_btc = bind_bitcoin(self.terms, changed)
            new_znn = bind_zenon(new_btc, self.data["zenon_binding"])
            with self.subTest(field=field):
                self.assertNotEqual(new_btc.digest_hex, self.bitcoin.digest_hex)
                self.assertNotEqual(new_znn.digest_hex, self.zenon.digest_hex)
                self.assertNotEqual(signing_context(new_znn, "alice", "zenon-claim-complete").digest_hex, old_context.digest_hex)

    def test_binding_must_match_agreed_funding_and_economic_fields(self):
        for field, value in (("value_sats", 200001), ("script_pubkey_hex", "51"),
                             ("claim_output_value_sats", 199001),
                             ("claim_destination_script_pubkey_hex", "51"),
                             ("sighash_type", "ALL"), ("sequence", 0xFFFFFFFF),
                             ("locktime", 1), ("transaction_version", 1)):
            changed = copy.deepcopy(self.data["bitcoin_binding"])
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(TranscriptError):
                bind_bitcoin(self.terms, changed)
        for field, value in (("destination_hex", "77" * 20), ("amount_base_units", 1),
                             ("token_standard_hex", "77" * 10), ("refund_owner_hex", "77" * 20),
                             ("expiry", 500000049), ("aggregate_key_xonly_hex", "77" * 32),
                             ("point_type", 0)):
            changed = copy.deepcopy(self.data["zenon_binding"])
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(TranscriptError):
                bind_zenon(self.bitcoin, changed)

    def test_zenon_exact_message_and_new_entry_id_dependency(self):
        changed = copy.deepcopy(self.data["zenon_binding"])
        changed["entry_id_hex"] = "88" * 32
        with self.assertRaises(TranscriptError):
            bind_zenon(self.bitcoin, changed)
        changed["message_hex"] = hashlib.sha3_256(bytes.fromhex(changed["entry_id_hex"] + changed["destination_hex"])).hexdigest()
        self.assertNotEqual(bind_zenon(self.bitcoin, changed).digest_hex, self.zenon.digest_hex)
        changed = copy.deepcopy(self.data["zenon_binding"])
        changed["message_hex"] = hashlib.sha256(bytes.fromhex(changed["entry_id_hex"] + changed["destination_hex"])).hexdigest()
        with self.assertRaises(TranscriptError):
            bind_zenon(self.bitcoin, changed)

    def test_missing_unknown_and_version_fields_fail_closed(self):
        targets = [(), ("bitcoin_network",), ("zenon_network",), ("bitcoin",), ("zenon",), ("policy",)]
        for path in targets:
            for operation in ("extra", "missing"):
                changed = copy.deepcopy(self.data["terms"])
                target = changed
                for part in path:
                    target = target[part]
                if operation == "extra":
                    target["unused"] = "public"
                else:
                    target.pop(next(iter(target)))
                with self.subTest(path=path, operation=operation), self.assertRaises(TranscriptError):
                    agree_terms(changed)
        for field in ("schema", "construction"):
            changed = copy.deepcopy(self.data["terms"])
            changed[field] += "-unsupported"
            with self.assertRaises(TranscriptError):
                agree_terms(changed)
        for key, parent, factory in (("bitcoin_binding", self.terms, bind_bitcoin), ("zenon_binding", self.bitcoin, bind_zenon)):
            for operation in ("extra", "missing"):
                changed = copy.deepcopy(self.data[key])
                if operation == "extra":
                    changed["verified"] = 1
                else:
                    changed.pop(next(iter(changed)))
                with self.subTest(key=key, operation=operation), self.assertRaises(TranscriptError):
                    factory(parent, changed)

    def test_strict_scalar_types_ranges_and_hex(self):
        cases = [
            (("session_id",), "AA" * 32), (("session_id",), "00" * 31),
            (("session_id",), "gg" * 32), (("session_id",), " " + "00" * 32),
            (("bitcoin_network", "label"), "not\u00e9-ascii"),
            (("bitcoin_network", "label"), ""),
            (("zenon_network", "chain_id"), True),
            (("bitcoin", "value_sats"), "200000"),
            (("bitcoin", "value_sats"), 200000.0),
            (("bitcoin", "value_sats"), 2 ** 64),
            (("bitcoin", "value_sats"), -1),
            (("bitcoin", "claim_output_value_sats"), 200000),
            (("bitcoin", "refund_locktime"), 499999999),
            (("bitcoin", "refund_locktime"), 2 ** 32),
            (("zenon", "point_type"), True),
            (("zenon", "amount_base_units"), 2 ** 256),
            (("zenon", "expiry"), -1),
            (("zenon", "expiry"), 2 ** 63),
            (("adaptor_point_sec1_hex",), "04" + "00" * 32),
            (("bitcoin", "refund_leaf_script_hex"), "0"),
            (("bitcoin", "signer_keys_sec1_hex"), []),
            (("bitcoin", "signer_keys_sec1_hex"), ["02" + "11" * 32] * 2),
        ]
        for path, value in cases:
            changed = copy.deepcopy(self.data["terms"])
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(TranscriptError):
                agree_terms(changed)
        for value in (True, -1, 2 ** 32, "1", 1.0):
            changed = copy.deepcopy(self.data["bitcoin_binding"])
            changed["funding_vout"] = value
            with self.subTest(vout=value), self.assertRaises(TranscriptError):
                bind_bitcoin(self.terms, changed)

    def test_candidate_rejects_identical_encoded_keys_across_legs(self):
        changed = copy.deepcopy(self.data["terms"])
        changed["zenon"]["signer_keys_sec1_hex"][0] = changed["bitcoin"]["signer_keys_sec1_hex"][0]
        with self.assertRaises(TranscriptError):
            agree_terms(changed)
        # This is encoded-key separation, not mathematical key/ownership validation.

    def test_oversized_deep_cyclic_and_non_json_inputs_fail_with_schema_error(self):
        nested = "end"
        for _ in range(12):
            nested = [nested]
        cyclic = []
        cyclic.append(cyclic)
        for value in (nested, cyclic, [1] * 129, {str(i): 1 for i in range(129)},
                      "a" * 20_001, 2 ** 1000, None, b"bytes", (1, 2),
                      [["a" * 2000] * 100] * 2, [[1] * 100] * 6):
            changed = copy.deepcopy(self.data["terms"])
            changed["extra"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(TranscriptError):
                agree_terms(changed)
        for raw in (b"x" * 128_001, b"[]", b"{}", b"not-json", b"\xff",
                    b"[" * 2000 + b"0" + b"]" * 2000):
            with self.subTest(encoded_length=len(raw)), self.assertRaises(TranscriptError):
                validate_signing_context(corrupt_snapshot(None, raw))

    def test_serialized_context_substitution_and_noncanonical_bytes_reject(self):
        context = signing_context(self.zenon, "alice", "zenon-claim-complete")
        for field, value in (("schema", "other"), ("leg", "bitcoin"), ("role", "bob"),
                             ("session_id", "99" * 32), ("binding_digest_hex", "99" * 32),
                             ("purpose", "bitcoin-claim-complete")):
            changed = context.as_dict()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(TranscriptError):
                validate_signing_context(corrupt_snapshot(changed))
        changed = context.as_dict()
        changed["binding"]["bitcoin_digest_hex"] = "99" * 32
        with self.assertRaises(TranscriptError):
            validate_signing_context(corrupt_snapshot(changed))
        changed = context.as_dict()
        changed["binding"]["bitcoin"]["terms_digest_hex"] = "99" * 32
        with self.assertRaises(TranscriptError):
            validate_signing_context(corrupt_snapshot(changed))
        for raw in (json.dumps(context.as_dict(), indent=2).encode("ascii"),
                    b'{"schema":"ignored",' + context.canonical_bytes[1:]):
            with self.assertRaises(TranscriptError):
                validate_signing_context(corrupt_snapshot(None, raw))

    def test_role_change_with_valid_reconstruction_is_a_different_operation(self):
        alice = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial")
        bob = signing_context(self.bitcoin, "bob", "bitcoin-claim-partial")
        self.assertNotEqual(alice.digest_hex, bob.digest_hex)
        validate_signing_context(alice)
        validate_signing_context(bob)
        replay = signing_context(self.bitcoin, "alice", "bitcoin-claim-partial")
        self.assertEqual(replay.canonical_bytes, alice.canonical_bytes)
        self.assertEqual(replay.digest_hex, alice.digest_hex)
        # Equality does not authorize another signing use; the journal enforces that boundary.


if __name__ == "__main__":
    unittest.main()
