"""Public input binding controls; no private signer or new backend is selected."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import nonce_intent as intent
from offline_session.transcript import (
    Commitment, agree_terms, bind_bitcoin, bind_zenon, commit_nonce_round,
    nonce_commitment, reveal_nonce_round, signing_context,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class NonceIntentTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.data = json.loads((root / "tests/fixtures/session_terms.json").read_text("ascii"))
        self.vectors = json.loads((root / "qualification/fixtures/nonce_rounds.json")
                                 .read_text("ascii"))["vectors"]
        self.contexts = {(leg, role): self.context(leg, role)
                         for leg in ("bitcoin", "zenon") for role in ("alice", "bob")}
        self.expected = self.contexts["bitcoin", "alice"]
        self.wire = intent.encode_intent(self.expected)
        self.packet = json.loads(self.wire)

    def context(self, leg="bitcoin", role="alice", *, data=None, vector=None,
                purpose="partial", dynamic=True):
        data = self.data if data is None else data
        terms = agree_terms(data["terms"])
        binding = bind_bitcoin(terms, data["bitcoin_binding"])
        if leg == "zenon":
            binding = bind_zenon(binding, data["zenon_binding"])
        nonce_round = None
        if dynamic:
            vector = copy.deepcopy(self.vectors[int(leg == "zenon")] if vector is None else vector)
            hashes = [nonce_commitment(binding, vector["round_id_hex"], who, nonce)
                      for who, nonce in zip(("alice", "bob"), vector["public_nonces_hex"])]
            commitments = commit_nonce_round(binding, vector["round_id_hex"], *hashes)
            nonce_round = reveal_nonce_round(commitments, *vector["public_nonces_hex"])
        return signing_context(binding, role, leg + "-claim-" + purpose, nonce_round=nonce_round)

    def refuse(self, context, wire):
        with self.assertRaises(intent.IntentError) as caught:
            intent.require_exact_intent(context, wire)
        self.assertEqual(str(caught.exception), "public nonce intent refused")

    def test_four_partial_contexts_keep_complete_selected_transcripts(self):
        for (leg, role), context in self.contexts.items():
            with self.subTest(leg=leg, role=role):
                wire = intent.encode_intent(context)
                packet = json.loads(wire)
                self.assertEqual(set(packet), {"schema", "signing_context", "public_inputs"})
                self.assertEqual(packet["schema"], intent.SCHEMA)
                self.assertEqual(packet["signing_context"], context.as_dict())
                self.assertIsNone(intent.require_exact_intent(context, wire))

    def test_bitcoin_tweak_base_and_signing_key_are_explicit_declarations(self):
        inputs = intent.public_inputs(self.expected)
        keys = inputs["key_aggregation"]
        btc = self.data["terms"]["bitcoin"]
        self.assertEqual(keys["tweak"], {"kind": "taproot-xonly", "merkle_root_hex": btc["tapleaf_hash_hex"]})
        self.assertEqual(keys["declared_base_key_xonly_hex"], btc["internal_key_xonly_hex"])
        self.assertEqual(keys["declared_signing_key_xonly_hex"], btc["output_key_xonly_hex"])
        self.assertEqual(inputs["message_hex"], self.vectors[0]["message_hex"])

    def test_zenon_is_untweaked_and_does_not_import_bitcoin_tweak(self):
        inputs = intent.public_inputs(self.contexts["zenon", "alice"])
        keys = inputs["key_aggregation"]
        self.assertEqual(keys["tweak"], {"kind": "none"})
        self.assertEqual(keys["declared_base_key_xonly_hex"], keys["declared_signing_key_xonly_hex"])
        self.assertEqual(inputs["message_hex"], self.vectors[1]["message_hex"])

    def test_ordered_keys_and_participant_index_match_each_complete_role(self):
        for (leg, role), context in self.contexts.items():
            inputs = intent.public_inputs(context)
            self.assertEqual(inputs["key_aggregation"]["ordered_signer_keys_sec1_hex"],
                             self.data["terms"][leg]["signer_keys_sec1_hex"])
            self.assertEqual(inputs["signer_index"], int(role == "bob"))
            self.assertEqual(inputs["operation"], "musig2-adaptor-partial")

    def test_both_roles_keep_the_same_ordered_complete_public_nonces(self):
        for leg, vector in zip(("bitcoin", "zenon"), self.vectors):
            for role in ("alice", "bob"):
                self.assertEqual(intent.public_inputs(self.contexts[leg, role])["public_nonces_hex"],
                                 vector["public_nonces_hex"])

    def test_adaptor_and_existing_context_digests_are_preserved_without_new_hash(self):
        self.assertEqual(self.packet["public_inputs"]["adaptor_point_sec1_hex"],
                         self.data["terms"]["adaptor_point_sec1_hex"])
        self.assertEqual(self.packet["signing_context"]["binding_digest_hex"],
                         self.expected.as_dict()["binding_digest_hex"])
        self.assertNotIn("digest_hex", self.packet)
        self.assertNotIn("intent_digest_hex", self.packet)

    def test_public_projection_is_a_defensive_copy(self):
        value = intent.public_inputs(self.expected)
        value["key_aggregation"]["ordered_signer_keys_sec1_hex"].reverse()
        value["key_aggregation"]["tweak"]["kind"] = "none"
        value["public_nonces_hex"].clear()
        self.assertEqual(intent.encode_intent(self.expected), self.wire)

    def test_mutable_input_and_transcript_copies_do_not_rebind_old_intent(self):
        self.data["bitcoin_binding"]["claim_sighash_hex"] = "99" * 32
        mutable = self.expected.as_dict()
        mutable["nonce_round"]["public_nonces"]["alice"] = "changed-public-value"
        self.assertEqual(intent.encode_intent(self.expected), self.wire)

    def test_exact_replay_and_two_callers_have_no_consume_or_deduplication(self):
        for _ in range(4):
            self.assertIsNone(intent.require_exact_intent(self.expected, self.wire))
        other_local_copy = self.context()
        self.assertEqual(intent.encode_intent(other_local_copy), self.wire)
        self.assertIsNone(intent.require_exact_intent(other_local_copy, self.wire))

    def test_completion_contexts_are_not_partial_nonce_invocations(self):
        for leg, role in (("bitcoin", "bob"), ("zenon", "alice")):
            with self.assertRaises(intent.IntentError):
                intent.encode_intent(self.context(leg, role, purpose="complete"))

    def test_static_partial_contexts_require_a_revealed_round(self):
        for leg in ("bitcoin", "zenon"):
            with self.assertRaises(intent.IntentError):
                intent.public_inputs(self.context(leg, dynamic=False))

    def test_missing_extra_and_permission_fields_at_packet_root_refuse(self):
        for field in self.packet:
            changed = copy.deepcopy(self.packet)
            del changed[field]
            self.refuse(self.expected, canonical(changed))
        for field in ("grant", "spent", "epoch", "attempt_id", "signature", "secret_nonce_hex"):
            changed = copy.deepcopy(self.packet)
            changed[field] = "public-synthetic-claim"
            self.refuse(self.expected, canonical(changed))

    def test_every_projected_scalar_and_array_element_is_bound(self):
        def leaves(value, path=()):
            if type(value) is dict:
                for key, item in value.items():
                    yield from leaves(item, path + (key,))
            elif type(value) is list:
                for index, item in enumerate(value):
                    yield from leaves(item, path + (index,))
            else:
                yield path
        for path in leaves(self.packet["public_inputs"]):
            changed = copy.deepcopy(self.packet)
            value = changed["public_inputs"]
            for key in path[:-1]:
                value = value[key]
            value[path[-1]] = "different-public-input"
            self.refuse(self.expected, canonical(changed))

    def test_projection_missing_nested_fields_and_unknown_fields_refuse(self):
        for container in ((), ("key_aggregation",), ("key_aggregation", "tweak")):
            original = self.packet["public_inputs"]
            for key in container:
                original = original[key]
            for field in (*original, "unknown"):
                changed = copy.deepcopy(self.packet)
                value = changed["public_inputs"]
                for key in container:
                    value = value[key]
                if field == "unknown":
                    value[field] = 1
                else:
                    del value[field]
                self.refuse(self.expected, canonical(changed))

    def test_each_other_valid_role_or_leg_cannot_replace_local_expectation(self):
        for context in self.contexts.values():
            wire = intent.encode_intent(context)
            if wire != self.wire:
                self.refuse(self.expected, wire)
            self.assertIsNone(intent.require_exact_intent(context, wire))

    def test_other_round_with_recomputed_openings_refuses_old_selection(self):
        vector = copy.deepcopy(self.vectors[0])
        vector["round_id_hex"] = "87" * 32
        other = self.context(vector=vector)
        self.refuse(self.expected, intent.encode_intent(other))
        self.refuse(other, self.wire)
        self.assertIsNone(intent.require_exact_intent(other, intent.encode_intent(other)))

    def test_changed_key_order_is_bound_without_recomputing_aggregate_key(self):
        data = copy.deepcopy(self.data)
        data["terms"]["bitcoin"]["signer_keys_sec1_hex"].reverse()
        other = self.context(data=data)
        self.refuse(self.expected, intent.encode_intent(other))
        self.assertEqual(intent.public_inputs(other)["key_aggregation"]["declared_signing_key_xonly_hex"],
                         intent.public_inputs(self.expected)["key_aggregation"]["declared_signing_key_xonly_hex"])

    def test_changed_tweak_is_bound_without_validating_declared_output_key(self):
        data = copy.deepcopy(self.data)
        data["terms"]["bitcoin"]["tapleaf_hash_hex"] = "88" * 32
        other = self.context(data=data)
        self.refuse(self.expected, intent.encode_intent(other))
        self.assertEqual(intent.public_inputs(other)["key_aggregation"]["declared_signing_key_xonly_hex"],
                         self.data["terms"]["bitcoin"]["output_key_xonly_hex"])

    def test_changed_adaptor_is_bound_without_curve_arithmetic(self):
        data = copy.deepcopy(self.data)
        data["terms"]["adaptor_point_sec1_hex"] = "02" + "ab" * 32
        other = self.context(data=data)
        self.refuse(self.expected, intent.encode_intent(other))
        self.assertEqual(intent.public_inputs(other)["adaptor_point_sec1_hex"], "02" + "ab" * 32)

    def test_bitcoin_message_is_supplied_and_not_a_recomputed_sighash(self):
        data = copy.deepcopy(self.data)
        data["bitcoin_binding"]["claim_sighash_hex"] = "89" * 32
        other = self.context(data=data)
        self.refuse(self.expected, intent.encode_intent(other))
        self.assertEqual(intent.public_inputs(other)["message_hex"], "89" * 32)

    def test_zenon_message_preserves_the_existing_transcript_rule(self):
        data = copy.deepcopy(self.data)
        data["terms"]["zenon"]["destination_hex"] = "8a" * 20
        binding = data["zenon_binding"]
        binding["destination_hex"] = "8a" * 20
        binding["message_hex"] = hashlib.sha3_256(bytes.fromhex(
            binding["entry_id_hex"] + binding["destination_hex"])).hexdigest()
        other = self.context("zenon", data=data)
        self.assertEqual(intent.public_inputs(other)["message_hex"], binding["message_hex"])
        self.refuse(self.contexts["zenon", "alice"], intent.encode_intent(other))

    def test_same_public_nonce_bytes_in_another_round_supply_no_freshness(self):
        vector = copy.deepcopy(self.vectors[0])
        vector["round_id_hex"] = "8b" * 32
        other = self.context(vector=vector)
        self.assertEqual(intent.public_inputs(other)["public_nonces_hex"],
                         intent.public_inputs(self.expected)["public_nonces_hex"])
        self.assertIsNone(intent.require_exact_intent(other, intent.encode_intent(other)))

    def test_self_selected_unvalidated_point_shapes_are_only_public_inputs(self):
        data = copy.deepcopy(self.data)
        data["terms"]["bitcoin"]["signer_keys_sec1_hex"][0] = "02" + "ff" * 32
        other = self.context(data=data)
        wire = intent.encode_intent(other)
        self.assertIsNone(intent.require_exact_intent(other, wire))
        self.assertEqual(intent.public_inputs(other)["key_aggregation"]["ordered_signer_keys_sec1_hex"][0],
                         "02" + "ff" * 32)

    def test_stale_local_selection_still_matches_without_external_authority(self):
        data = copy.deepcopy(self.data)
        data["terms"]["session_id"] = "8c" * 32
        newer = self.context(data=data)
        self.assertNotEqual(intent.encode_intent(newer), self.wire)
        self.assertIsNone(intent.require_exact_intent(self.expected, self.wire))

    def test_whitespace_aliases_duplicate_keys_and_trailing_bytes_refuse(self):
        duplicates = self.wire[:-1] + b',"schema":"ptlc-public-nonce-intent-v1"}'
        escaped = self.wire.replace(b'"alice"', b'"\\u0061lice"', 1)
        for wire in (b" " + self.wire, self.wire + b"\n", duplicates, escaped,
                     json.dumps(self.packet, indent=2).encode("ascii"), self.wire + self.wire):
            self.refuse(self.expected, wire)

    def test_numeric_aliases_boolean_index_and_invalid_json_refuse_without_parser(self):
        changed = copy.deepcopy(self.packet)
        changed["public_inputs"]["signer_index"] = False
        values = [canonical(changed), self.wire.replace(b'"signer_index":0', b'"signer_index":0.0'),
                  self.wire.replace(b'"signer_index":0', b'"signer_index":-0'),
                  self.wire.replace(b'"signer_index":0', b'"signer_index":0e0'),
                  b"[]", b"{}", b"null", b'"untrusted-public-value"', b"\xff" * 3,
                  b"[" * 20_000 + b"]" * 20_000]
        with patch.object(intent, "json", wraps=json) as public_json:
            public_json.loads.side_effect = AssertionError("untrusted parser")
            for wire in values:
                self.refuse(self.expected, wire)
            public_json.loads.assert_not_called()

    def test_wire_bounds_refuse_before_inspecting_context(self):
        with patch.object(intent, "_context", side_effect=AssertionError("context inspected")):
            for wire in (b"", b"0", b"x" * (intent.MAX_WIRE_BYTES + 1)):
                self.refuse(self.expected, wire)
        self.assertLessEqual(len(self.wire), intent.MAX_WIRE_BYTES)
        self.refuse(self.expected, b"x" * intent.MAX_WIRE_BYTES)

    def test_factory_bound_counts_complete_context_and_projected_arguments(self):
        data = copy.deepcopy(self.data)
        data["terms"]["bitcoin"]["funding_script_pubkey_hex"] = "51" * 10_000
        data["bitcoin_binding"]["script_pubkey_hex"] = "51" * 10_000
        data["terms"]["bitcoin"]["refund_leaf_script_hex"] = "51" * 9_750
        smaller = self.context(data=data)
        wire = intent.encode_intent(smaller)
        self.assertLessEqual(len(wire), intent.MAX_WIRE_BYTES)
        self.assertIsNone(intent.require_exact_intent(smaller, wire))
        data["terms"]["bitcoin"]["refund_leaf_script_hex"] = "51" * 10_000
        larger = self.context(data=data)
        self.assertLessEqual(len(larger.canonical_bytes), intent.MAX_WIRE_BYTES)
        with self.assertRaises(intent.IntentError) as caught:
            intent.encode_intent(larger)
        self.assertEqual(str(caught.exception), "public nonce intent refused")

    def test_nonexact_wire_types_and_foreign_hooks_are_not_called(self):
        class ForeignBytes(bytes):
            def __len__(self):
                raise AssertionError("foreign length")
            def __eq__(self, other):
                raise AssertionError("foreign equality")
        for wire in (ForeignBytes(self.wire), bytearray(self.wire), memoryview(self.wire),
                     self.wire.decode("ascii"), None, 1, True):
            self.refuse(self.expected, wire)

    def test_foreign_contexts_and_commitment_subclasses_run_no_hooks(self):
        class ForeignContext(Commitment):
            def as_dict(self):
                raise AssertionError("foreign context")
        for value in (object.__new__(ForeignContext), self.expected.as_dict(), self.wire, None):
            self.refuse(value, self.wire)

    def test_damaged_commitments_and_unknown_purposes_fail_quietly(self):
        values = [object.__new__(Commitment)]
        for encoded in (None, b"{}", b"[", self.expected.canonical_bytes + b"\n"):
            value = object.__new__(Commitment)
            object.__setattr__(value, "_encoded", encoded)
            values.append(value)
        changed = self.expected.as_dict()
        changed["purpose"] = "untrusted-public-purpose"
        value = object.__new__(Commitment)
        object.__setattr__(value, "_encoded", canonical(changed))
        values.append(value)
        for value in values:
            self.refuse(value, self.wire)

    def test_errors_do_not_echo_supplied_values_and_cancellation_is_not_retried(self):
        self.refuse(self.expected, b"public-input-that-must-not-be-echoed")
        for cancellation in (KeyboardInterrupt, SystemExit):
            with patch.object(intent, "validate_signing_context", side_effect=cancellation) as call:
                with self.assertRaises(cancellation):
                    intent.encode_intent(self.expected)
                self.assertEqual(call.call_count, 1)

    def test_module_has_no_digest_arithmetic_io_worker_or_authority_interface(self):
        source = Path(intent.__file__).read_text("ascii")
        tree = ast.parse(source)
        imports = [(node.module, node.level) if isinstance(node, ast.ImportFrom)
                   else tuple(alias.name for alias in node.names)
                   for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, [("json",), ("transcript", 1)])
        public = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)
                  and not node.name.startswith("_")}
        self.assertEqual(public, {"public_inputs", "encode_intent", "require_exact_intent"})
        self.assertNotIn("hashlib", source)


if __name__ == "__main__":
    unittest.main()
