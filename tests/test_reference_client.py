"""Offline public client integration and malformed-input controls."""

import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

from offline_session.nom_wire import decode_call
from offline_session.pr138 import CONTRACT_HEX, CompatibilityError
from reference_client.__main__ import main
from reference_client.plan import MAX_INPUT, SOURCE_COMMIT, canonical, inspect_terms


ROOT = Path(__file__).resolve().parents[1]


class ReferenceClientTests(unittest.TestCase):
    def setUp(self):
        self.terms = json.loads((ROOT / "reference_client/synthetic_terms.json").read_bytes())
        self.wire = json.loads((ROOT / "compatibility/fixtures/nom_wire_v1.json").read_bytes())

    def invoke(self, command, raw):
        output, errors = io.StringIO(), io.StringIO()
        code = main([command], input_stream=io.BytesIO(raw), output_stream=output, error_stream=errors)
        return code, output.getvalue(), errors.getvalue()

    def test_local_message_derivation_matches_preserved_completion_corpus(self):
        original = copy.deepcopy(self.terms)
        plan = inspect_terms(self.terms)
        expected = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_bytes())
        for name in ("long", "short"):
            self.assertEqual(plan["legs"][name]["unlock_message_hex"], expected[name + "_message_hex"])
            self.assertEqual(len(bytes.fromhex(plan["legs"][name]["unlock_preimage_hex"])), 101)
        self.assertEqual(self.terms, original)
        plan["terms"]["long"]["amount"] = "999"
        self.assertEqual(self.terms, original)

    def test_fixed_roles_create_keys_and_payout_destinations_are_distinct(self):
        plan = inspect_terms(self.terms)
        for name, funder, recipient in (("long", "alice", "bob"), ("short", "bob", "alice")):
            leg = plan["legs"][name]
            call = decode_call(bytes.fromhex(leg["create_data_hex"]))
            self.assertEqual(call["point_lock_hex"], self.terms[name]["funder_key_xonly_hex"])
            self.assertNotEqual(call["point_lock_hex"], self.terms["adaptor_point_sec1_hex"])
            self.assertEqual(call["destination_hex"], self.terms[recipient + "_address_hex"])
            self.assertEqual(leg["funding_sender_hex"], self.terms[funder + "_address_hex"])
            self.assertEqual(leg["funding_to_hex"], CONTRACT_HEX)
            self.assertEqual(leg["direct_unlock_sender_hex"], self.terms[recipient + "_address_hex"])
            self.assertEqual(leg["reclaim_sender_hex"], self.terms[funder + "_address_hex"])
            self.assertEqual(decode_call(bytes.fromhex(leg["reclaim_data_hex"])),
                             dict(method="Reclaim", entry_id_hex=self.terms[name]["entry_id_hex"]))

    def test_economics_commitment_binds_fields_missing_from_unlock_message(self):
        baseline = inspect_terms(self.terms)
        for field, value in (("amount", "101"), ("expires_at", "2001"), ("token_standard_hex", "03" * 10)):
            changed = copy.deepcopy(self.terms)
            changed["long"][field] = value
            plan = inspect_terms(changed)
            self.assertNotEqual(plan["terms_digest_hex"], baseline["terms_digest_hex"])
            self.assertEqual(plan["legs"]["long"]["unlock_message_hex"], baseline["legs"]["long"]["unlock_message_hex"])

    def test_plan_never_authenticates_declared_state_or_grants_an_action(self):
        plan = inspect_terms(self.terms)
        self.assertEqual(plan["action_permission"], "NONE")
        self.assertEqual(plan["entry_status"], "DECLARED_ONLY")
        self.assertEqual(plan["curve_points"], "NOT_VERIFIED")
        self.assertEqual((plan["application"], plan["core"], plan["independent_assessment"]),
                         ("NO-GO", "NO-GO", "UNFILLED"))
        self.assertIn("NO INCLUSION", plan["expiry_gap"])
        self.assertIn("receive-exact-payouts-and-confirm-recipient-balances", plan["required_event_order"])

    def test_wrong_network_source_and_extra_peer_messages_are_refused(self):
        for field, value in (("chain_id", "1"), ("chain_id", 69), ("source_commit", "00" * 20),
                             ("schema", "unknown"), ("message_hex", "00" * 32)):
            changed = dict(self.terms, **{field: value})
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                inspect_terms(changed)
        self.assertEqual(self.terms["source_commit"], SOURCE_COMMIT)

    def test_invalid_roles_widths_amounts_and_gap_are_refused(self):
        mutations = [
            ("recipient", "alice"), ("funder", "bob"), ("amount", "0"),
            ("amount", "01"), ("amount", str(1 << 256)), ("expires_at", "1499"),
            ("expires_at", True), ("funder_key_xonly_hex", "AA" * 32),
            ("entry_id_hex", self.terms["short"]["entry_id_hex"]),
            ("funder_key_xonly_hex", self.terms["short"]["funder_key_xonly_hex"]),
        ]
        for field, value in mutations:
            changed = copy.deepcopy(self.terms)
            changed["long"][field] = value
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                inspect_terms(changed)
        for changed in (dict(self.terms, alice_address_hex=self.terms["bob_address_hex"]),
                        dict(self.terms, adaptor_point_sec1_hex="04" + "11" * 32),
                        dict(self.terms, minimum_expiry_gap_seconds="0")):
            with self.assertRaises(CompatibilityError):
                inspect_terms(changed)

    def test_cli_codecs_match_every_existing_canonical_wire_and_hash_vector(self):
        for vector in self.wire["abi_vectors"]:
            code, output, errors = self.invoke("encode-call", canonical(vector["call"]))
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(json.loads(output)["data_hex"], vector["data_hex"])
        for vector in self.wire["hash_vectors"]:
            code, output, errors = self.invoke("hash-account-block", canonical(vector["block"]))
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(json.loads(output)["hash_hex"], vector["hash_hex"])
            self.assertEqual(json.loads(output)["preimage_hex"], vector["preimage_hex"])

    def test_invalid_json_is_bounded_and_never_echoed(self):
        for raw in (b"", b"{" , b"{}" * (MAX_INPUT // 2 + 1), b"\xff",
                    b'{"schema": "synthetic-sensitive-marker", "schema": "duplicate"}',
                    b'{"value": NaN}', b"[" * 2000 + b"]" * 2000, b'"synthetic-sensitive-marker"'):
            code, output, errors = self.invoke("inspect-terms", raw)
            self.assertEqual((code, output), (2, ""))
            self.assertEqual(errors, "REFUSED: invalid public input; no action authorized\n")

    def test_module_entrypoint_accepts_public_fixture_and_emits_only_json(self):
        completed = subprocess.run([sys.executable, "-B", "-m", "reference_client", "inspect-terms"],
                                   input=canonical(self.terms), capture_output=True, cwd=ROOT,
                                   timeout=10, check=False)
        self.assertEqual((completed.returncode, completed.stderr), (0, b""))
        self.assertEqual(json.loads(completed.stdout), inspect_terms(self.terms))

    def test_unsupported_arguments_are_sanitized_without_echoing_values(self):
        for argv in ([], ["synthetic-sensitive-marker"],
                     ["inspect-terms", "--synthetic-sensitive-marker"]):
            output, errors = io.StringIO(), io.StringIO()
            code = main(argv, input_stream=io.BytesIO(b"{}"), output_stream=output, error_stream=errors)
            self.assertEqual((code, output.getvalue()), (2, ""))
            self.assertEqual(errors.getvalue(), "REFUSED: invalid public input; no action authorized\n")


if __name__ == "__main__":
    unittest.main()
