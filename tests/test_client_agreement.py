"""Staged client bindings against preserved public hash and completion oracles.

Historical synthetic vectors supply byte-level oracles only. Their old runtime
results are not admission evidence for the selected current source or client.
"""

import copy
import io
import json
from pathlib import Path
import unittest

from offline_session.nom_wire import account_block_hash
from offline_session.pr138 import CompatibilityError
from reference_client.agreement import (
    AGREEMENT_SCHEMA, FUNDING_SCHEMA, REQUEST_SCHEMA, agreement_digest,
    bind_funding, inspect_agreement,
)
from reference_client.__main__ import main
from reference_client.plan import FIELDS, MAX_INPUT, SOURCE_COMMIT, canonical


ROOT = Path(__file__).resolve().parents[1]


class ClientAgreementTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((ROOT / "compatibility/fixtures/nom_bilateral_inputs_v1.json").read_bytes())
        self.completions = json.loads((ROOT / "compatibility/fixtures/nom_bilateral_completions_v1.json").read_bytes())
        self.agreement = {name: copy.deepcopy(self.original["terms"][name])
                          for name in FIELDS - {"schema", "source_commit"}}
        self.agreement.update(schema=AGREEMENT_SCHEMA, source_commit=SOURCE_COMMIT)
        for name in ("long", "short"):
            del self.agreement[name]["entry_id_hex"]

    def funding(self, name):
        leg = self.agreement[name]
        original = self.original["fundings"][name]
        return dict(schema=FUNDING_SCHEMA, agreement_digest_hex=agreement_digest(self.agreement), leg=name,
                    account_block=copy.deepcopy(original["block"]), entry_projection=dict(
                        entry_id_hex=original["hash_hex"], creator_hex=original["block"]["address_hex"],
                        point_type=1, point_lock_hex=leg["funder_key_xonly_hex"],
                        destination_hex=self.agreement[leg["recipient"] + "_address_hex"],
                        token_standard_hex=leg["token_standard_hex"], amount=leg["amount"],
                        expires_at=leg["expires_at"]))

    def request(self, name, bindings=None):
        return dict(schema=REQUEST_SCHEMA, agreement=copy.deepcopy(self.agreement),
                    bindings=[] if bindings is None else copy.deepcopy(bindings), funding=self.funding(name))

    def both(self):
        first = bind_funding(self.request("long"))
        return bind_funding(self.request("short", first["bindings"]))

    def test_prefunding_agreement_has_no_invented_entry_ids_or_unlock_messages(self):
        result = inspect_agreement(self.agreement)
        self.assertEqual(self.agreement, json.loads((ROOT / "reference_client/synthetic_agreement.json").read_bytes()))
        self.assertEqual(result["agreement"], self.agreement)
        self.assertNotIn("entry_id_hex", canonical(result).decode("ascii"))
        self.assertNotIn("unlock_message_hex", canonical(result).decode("ascii"))
        for name in ("long", "short"):
            self.assertEqual(result["create_data_hex"][name], self.original["fundings"][name]["block"]["data_hex"])
        with self.assertRaises(CompatibilityError):
            inspect_agreement(dict(self.agreement, long=dict(self.agreement["long"], entry_id_hex="11" * 32)))

    def test_staged_bindings_match_preserved_create_hashes_and_completion_messages(self):
        first = bind_funding(self.request("long"))
        self.assertEqual(first["phase"], "DECLARED_LONG_BOUND")
        self.assertIsNone(first["postfunding_plan"])
        second = bind_funding(self.request("short", first["bindings"]))
        self.assertEqual(second["phase"], "DECLARED_BOTH_BOUND")
        self.assertEqual(first["agreement_digest_hex"], second["agreement_digest_hex"])
        self.assertNotEqual(first["binding_digest_hex"], second["binding_digest_hex"])
        plan = second["postfunding_plan"]
        for name in ("long", "short"):
            self.assertEqual(plan["terms"][name]["entry_id_hex"], self.original["fundings"][name]["hash_hex"])
            self.assertEqual(plan["legs"][name]["unlock_message_hex"], self.completions[name + "_message_hex"])

    def test_replay_preserves_complete_prefix_and_never_regresses_to_one_leg(self):
        both = self.both()
        for name in ("long", "short"):
            repeated = bind_funding(self.request(name, both["bindings"]))
            self.assertEqual(repeated["transition"], "EXACT_DECLARED_REPLAY")
            self.assertEqual(repeated["phase"], "DECLARED_BOTH_BOUND")
            self.assertEqual(repeated["bindings"], both["bindings"])
            self.assertEqual(repeated["binding_digest_hex"], both["binding_digest_hex"])

    def test_short_first_reordered_duplicate_and_oversized_prefixes_are_refused(self):
        with self.assertRaises(CompatibilityError):
            bind_funding(self.request("short"))
        both = self.both()["bindings"]
        for prefix in (both[::-1], [both[0], both[0]], both + [both[1]], {}, None):
            with self.subTest(prefix_type=type(prefix).__name__), self.assertRaises(CompatibilityError):
                request = self.request("long")
                request["bindings"] = copy.deepcopy(prefix)
                bind_funding(request)

    def test_changed_valid_hash_candidate_cannot_replace_original_funding(self):
        first = bind_funding(self.request("long"))
        request = self.request("long", first["bindings"])
        request["funding"]["account_block"]["fused_plasma"] = "1"
        request["funding"]["entry_projection"]["entry_id_hex"] = account_block_hash(request["funding"]["account_block"])
        with self.assertRaises(CompatibilityError):
            bind_funding(request)
        self.assertEqual(first["bindings"][0]["account_block"]["fused_plasma"], "0")

    def test_every_economic_entry_mismatch_and_boolean_point_type_is_refused(self):
        for field, value in (("entry_id_hex", "11" * 32), ("creator_hex", self.agreement["bob_address_hex"]),
                             ("destination_hex", self.agreement["alice_address_hex"]), ("amount", "101"),
                             ("token_standard_hex", "03" * 10), ("expires_at", "2001"),
                             ("point_lock_hex", self.agreement["short"]["funder_key_xonly_hex"]), ("point_type", True)):
            request = self.request("long")
            request["funding"]["entry_projection"][field] = value
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                bind_funding(request)

    def test_send_fields_must_match_selected_create_and_cannot_claim_descendants(self):
        for field, value in (("address_hex", self.agreement["bob_address_hex"]), ("to_address_hex", self.agreement["alice_address_hex"]),
                             ("chain_id", "1"), ("amount", "101"), ("block_type", "4"),
                             ("data_hex", "00"), ("descendant_hashes_hex", ["01" * 32]),
                             ("from_block_hash_hex", "01" * 32), ("height", "0"), ("momentum_height", "0"),
                             ("previous_hash_hex", "01" * 32)):
            request = self.request("long")
            request["funding"]["account_block"][field] = value
            with self.subTest(field=field), self.assertRaises(CompatibilityError):
                bind_funding(request)

    def test_cross_agreement_and_corrupt_existing_prefixes_cannot_be_extended(self):
        first = bind_funding(self.request("long"))
        request = self.request("short", first["bindings"])
        request["agreement"]["genesis_hash_hex"] = "99" * 32
        with self.assertRaises(CompatibilityError):
            bind_funding(request)
        request = self.request("short", first["bindings"])
        request["bindings"][0]["account_block"]["nonce_hex"] = "01" * 8
        with self.assertRaises(CompatibilityError):
            bind_funding(request)

    def test_results_are_detached_from_inputs_and_all_claims_remain_unverified(self):
        request = self.request("long")
        original = copy.deepcopy(request)
        result = bind_funding(request)
        for key, value in dict(action_permission="NONE", application="NO-GO", core="NO-GO",
                               contract_execution="NOT_VERIFIED", outer_signature="NOT_VERIFIED",
                               presignatures="NOT_VERIFIED", chain_state="DECLARED_ONLY").items():
            self.assertEqual(result[key], value)
        result["bindings"][0]["entry_projection"]["amount"] = "999"
        result["agreement"]["long"]["amount"] = "999"
        self.assertEqual(request, original)

    def test_cli_commands_roundtrip_public_inputs_with_sanitized_refusals(self):
        for command, value in (("inspect-agreement", self.agreement), ("bind-funding", self.request("long"))):
            output, errors = io.StringIO(), io.StringIO()
            self.assertEqual(main([command], input_stream=io.BytesIO(canonical(value)),
                                  output_stream=output, error_stream=errors), 0)
            self.assertEqual(errors.getvalue(), "")
            self.assertEqual(json.loads(output.getvalue())["action_permission"], "NONE")
        for raw in (b'{"schema":"synthetic-sensitive-marker","schema":"duplicate"}', b"x" * (MAX_INPUT + 1),
                    b'{"bindings":NaN}', b"[]"):
            output, errors = io.StringIO(), io.StringIO()
            self.assertEqual(main(["bind-funding"], input_stream=io.BytesIO(raw),
                                  output_stream=output, error_stream=errors), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), "REFUSED: invalid public input; no action authorized\n")


if __name__ == "__main__":
    unittest.main()
