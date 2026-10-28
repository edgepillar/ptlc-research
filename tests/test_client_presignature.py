"""Selected-leg preparation against historical independent message byte oracles.

Synthetic public declarations are not funding, execution or crypto evidence.
"""

import copy
import hashlib
import io
import json
from pathlib import Path
import unittest

from offline_session.nom_wire import account_block_hash
from offline_session.pr138 import CompatibilityError
from reference_client.agreement import FUNDING_SCHEMA, agreement_digest
from reference_client.plan import canonical
from reference_client.presignature import BACKEND, BACKEND_COMMIT, SCHEMA, prepare_presignature
from reference_client.__main__ import main


ROOT = Path(__file__).resolve().parents[1]


class ClientPresignatureTests(unittest.TestCase):
    def setUp(self):
        self.agreement = json.loads((ROOT / "reference_client/synthetic_agreement.json").read_bytes())
        self.inputs = json.loads((ROOT / "compatibility/fixtures/nom_bilateral_inputs_v1.json").read_bytes())
        self.completions = json.loads((ROOT / "compatibility/fixtures/nom_bilateral_completions_v1.json").read_bytes())

    def record(self, name):
        leg = self.agreement[name]
        original = self.inputs["fundings"][name]
        return dict(schema=FUNDING_SCHEMA, agreement_digest_hex=agreement_digest(self.agreement),
            leg=name, account_block=copy.deepcopy(original["block"]), entry_projection=dict(
                entry_id_hex=original["hash_hex"], creator_hex=original["block"]["address_hex"],
                point_type=1, point_lock_hex=leg["funder_key_xonly_hex"],
                destination_hex=self.agreement[leg["recipient"] + "_address_hex"],
                token_standard_hex=leg["token_standard_hex"], amount=leg["amount"],
                expires_at=leg["expires_at"]))

    def request(self, leg="long", both=False):
        return dict(schema=SCHEMA, agreement=copy.deepcopy(self.agreement), leg=leg,
            bindings=[self.record(name) for name in (("long", "short") if both else ("long",))],
            presignature=dict(r_x_hex=self.agreement["long"]["funder_key_xonly_hex"],
                s_hat_hex="00" * 32, needs_negation=False))

    def test_long_preparation_uses_its_real_declared_send_without_a_short_id(self):
        value = self.request()
        prepared = prepare_presignature(value)
        request = prepared["crypto_request"]
        self.assertNotIn("entry_id_hex", value["agreement"]["short"])
        self.assertEqual(request["message_hex"], self.completions["long_message_hex"])
        self.assertEqual(prepared["declared_entry_id_hex"], self.inputs["fundings"]["long"]["hash_hex"])
        self.assertEqual(request["key_xonly_hex"], self.agreement["long"]["funder_key_xonly_hex"])
        self.assertEqual(request["adaptor_point_sec1_hex"], self.agreement["adaptor_point_sec1_hex"])
        self.assertEqual((request["backend"], request["backend_commit"]), (BACKEND, BACKEND_COMMIT))
        self.assertEqual(prepared["request_digest_hex"], hashlib.sha256(canonical(request)).hexdigest())

    def test_adding_short_keeps_the_long_request_stable_and_selects_the_short_message(self):
        first = prepare_presignature(self.request())
        later = prepare_presignature(self.request(both=True))
        self.assertEqual(first["crypto_request"], later["crypto_request"])
        short = prepare_presignature(self.request("short", both=True))
        self.assertEqual(short["crypto_request"]["message_hex"], self.completions["short_message_hex"])
        self.assertNotEqual(first["request_digest_hex"], short["request_digest_hex"])
        self.assertEqual(short["crypto_request"]["key_xonly_hex"], self.agreement["short"]["funder_key_xonly_hex"])
        with self.assertRaises(CompatibilityError):
            prepare_presignature(self.request("short"))

    def test_prepared_request_matches_the_separate_native_historical_byte_oracle(self):
        supplied = json.loads((ROOT / "reference_client/synthetic_presignature_request.json").read_bytes())
        expected = json.loads((ROOT / "public_crypto/synthetic_long_request.json").read_bytes())
        prepared = prepare_presignature(supplied)
        self.assertEqual(prepared["crypto_request"], expected)
        self.assertEqual(expected["message_hex"], self.completions["long_message_hex"])
        signature = self.completions["long_signature_hex"]
        self.assertEqual(expected["presignature"]["r_x_hex"], signature[:64])
        order = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
        self.assertEqual(int(expected["presignature"]["s_hat_hex"], 16),
                         (int(signature[64:], 16) - 3) % order)

    def test_valid_changed_create_input_changes_the_selected_message_and_commitment(self):
        value = self.request()
        first = prepare_presignature(value)
        value["bindings"][0]["account_block"]["fused_plasma"] = "1"
        entry = value["bindings"][0]["entry_projection"]
        entry["entry_id_hex"] = account_block_hash(value["bindings"][0]["account_block"])
        second = prepare_presignature(value)
        for field in ("message_hex", "context_digest_hex"):
            self.assertNotEqual(first["crypto_request"][field], second["crypto_request"][field])

    def test_counterparty_economics_are_committed_even_when_the_selected_message_is_unchanged(self):
        first = prepare_presignature(self.request())
        value = self.request()
        value["agreement"]["short"]["amount"] = "201"
        value["bindings"][0]["agreement_digest_hex"] = agreement_digest(value["agreement"])
        second = prepare_presignature(value)
        self.assertEqual(first["crypto_request"]["message_hex"], second["crypto_request"]["message_hex"])
        self.assertNotEqual(first["crypto_request"]["context_digest_hex"], second["crypto_request"]["context_digest_hex"])

    def test_corrupt_unselected_binding_is_still_rejected(self):
        value = self.request(both=True)
        value["bindings"][1]["entry_projection"]["amount"] = "201"
        with self.assertRaises(CompatibilityError):
            prepare_presignature(value)
        value = self.request(both=True)
        value["bindings"].reverse()
        with self.assertRaises(CompatibilityError):
            prepare_presignature(value)

    def test_peer_message_context_backend_and_executable_fields_are_not_admitted(self):
        for field, supplied in (("message_hex", "00" * 32), ("context_digest_hex", "00" * 32),
                ("backend", BACKEND), ("worker", "synthetic-executable"),
                ("leg", True), ("leg", "unknown"), ("bindings", [])):
            value = self.request()
            value[field] = supplied
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                prepare_presignature(value)

    def test_selected_backend_fields_are_strict_but_curve_validity_is_not_claimed(self):
        for field, supplied in (("r_x_hex", "AA" * 32), ("s_hat_hex", "00" * 31),
                ("needs_negation", 1), ("foreign_compact_wire_hex", "00" * 65)):
            value = self.request()
            value["presignature"][field] = supplied
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                prepare_presignature(value)
        # All-zero scalars are syntactically admitted; the separate curve backend
        # must decide the public relation. Preparation must not claim success.
        prepared = prepare_presignature(self.request())
        self.assertTrue(prepared["verification"].startswith("NOT_PERFORMED"))
        self.assertNotIn("presignature_valid", prepared)

    def test_preparation_is_detached_and_never_grants_an_action(self):
        value = self.request()
        original = copy.deepcopy(value)
        prepared = prepare_presignature(value)
        for field, wanted in dict(action_permission="NONE", application="NO-GO", core="NO-GO",
                chain_state="DECLARED_ONLY", outer_signature="NOT_VERIFIED",
                contract_execution="NOT_VERIFIED", context_authentication="NOT_VERIFIED",
                independent_assessment="UNFILLED").items():
            self.assertEqual(prepared[field], wanted)
        prepared["crypto_request"]["presignature"]["r_x_hex"] = "ff" * 32
        self.assertEqual(value, original)

    def test_cli_emits_only_the_canonical_public_backend_request_or_a_sanitized_refusal(self):
        value = self.request()
        output, errors = io.StringIO(), io.StringIO()
        code = main(["prepare-presignature-check"], input_stream=io.BytesIO(canonical(value)),
                    output_stream=output, error_stream=errors)
        self.assertEqual((code, errors.getvalue()), (0, ""))
        self.assertEqual(output.getvalue().encode("ascii"),
                         canonical(prepare_presignature(value)["crypto_request"]) + b"\n")
        for raw in (b'{"schema":"synthetic-sensitive-marker","schema":"duplicate"}',
                    b'{"presignature":NaN}', b"[]", b"x" * 32769):
            output, errors = io.StringIO(), io.StringIO()
            code = main(["prepare-presignature-check"], input_stream=io.BytesIO(raw),
                        output_stream=output, error_stream=errors)
            self.assertEqual((code, output.getvalue()), (2, ""))
            self.assertEqual(errors.getvalue(), "REFUSED: invalid public input; no action authorized\n")


if __name__ == "__main__":
    unittest.main()
