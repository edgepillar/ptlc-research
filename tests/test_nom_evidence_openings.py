"""Public commitment openings remain separate from authorization and source truth."""

import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from offline_session import nom_authority_contract as authority, nom_evidence_openings as opening
from offline_session import nom_momentum as momentum, nom_recovery as recovery, nom_wire as account
from nom_retention_support import MOMENTA, TERMS, original, wire
from test_nom_authority_contract import selection, claim


ROOT = Path(__file__).resolve().parents[1]
FUNDING = json.loads((ROOT / "compatibility/fixtures/nom_observation_v1.json").read_text("ascii"))["baseline"]["records"]["funding"]


def funding_records(terms):
    """Synthetic unsigned hash inputs only; no account wire or signer exists."""
    records = {}
    for leg in ("long", "short"):
        selected = terms[leg]
        block = copy.deepcopy(FUNDING["block"])
        block.update(chain_id=terms["chain_id"], address_hex=terms[selected["funder"] + "_address_hex"],
            amount=selected["amount"], token_standard_hex=selected["token_standard_hex"],
            momentum_hash_hex=MOMENTA["baseline"]["anchor"]["hash_hex"],
            momentum_height=MOMENTA["baseline"]["anchor"]["height"])
        block["data_hex"] = account.encode_call(dict(method="Create", expiration_time=selected["expires_at"],
            point_type=1, point_lock_hex=selected["funder_key_xonly_hex"],
            destination_hex=terms[selected["recipient"] + "_address_hex"])).hex()
        records[leg] = {"block": block, "hash_hex": account.account_block_hash(block)}
    return records


def payloads(selected):
    return {"funding_send": {"records": funding_records(selected["terms"])},
        "original_authorization": {"originals_hex": {leg: value.hex() for leg, value in selected["originals"].items()}},
        "momentum_lineage": {"candidate_wire_hex": selected["candidate_wire"].hex()}}


def packet(query, selected_payloads, *, statuses=None, missing=()):
    value = claim(query)
    statuses = statuses or {}
    for name, payload in selected_payloads.items():
        status = statuses.get(name, "supported")
        value["facts"][name] = {"status": status,
            "evidence_digest_hex": None if status == "unknown" else opening.opening_digest(query, name, status, payload)}
    claim_wire = wire(value)
    bundle = {"schema": opening.SCHEMA, "query_digest_hex": query.digest_hex,
        "claim_wire_digest_hex": opening.claim_digest(claim_wire),
        "openings": {name: None if name in missing or statuses.get(name) == "unknown" else payload
                     for name, payload in selected_payloads.items()}}
    return claim_wire, bundle


def matching_selection():
    selected = selection()
    records = funding_records(selected["terms"])
    for leg in ("long", "short"):
        selected["terms"][leg]["entry_id_hex"] = records[leg]["hash_hex"]
    # A zero inner signature is a framing-only unsafe control under new entry ids.
    selected["originals"] = {leg: recovery.synthetic_claim(selected["terms"], leg, "00" * 64)
                             for leg in ("long", "short")}
    candidate = copy.deepcopy(MOMENTA["baseline"])
    candidate["momenta"] = candidate["momenta"][:1]
    first = candidate["momenta"][0]
    first["momentum"]["content"] = [{"address_hex": record["block"]["address_hex"],
        "height": record["block"]["height"], "hash_hex": record["hash_hex"]} for record in records.values()]
    first["hash_hex"] = momentum.momentum_hash(first["momentum"])
    confirmation = {"hash_hex": first["hash_hex"], "height": first["momentum"]["height"],
                    "timestamp": first["momentum"]["timestamp"]}
    selected["required_inclusions"] = [{"id": leg + "-funding", "header": header, "confirmation": confirmation}
        for leg, header in zip(("long", "short"), first["momentum"]["content"])]
    selected["checkpoint_selection"]["momentum"] = confirmation
    selected["candidate_wire"] = wire(candidate)
    return selected


class NoMEvidenceOpeningTests(unittest.TestCase):
    def setUp(self):
        self.selected = selection()
        self.query = authority.read_query(**self.selected)
        self.payloads = payloads(self.selected)
        self.claim_wire, self.bundle = packet(self.query, self.payloads)

    def inspect(self, bundle=None, claim_wire=None, query=None):
        return opening.inspect_openings(query or self.query, claim_wire or self.claim_wire,
                                        wire(self.bundle if bundle is None else bundle))

    def assert_no_permission(self, result):
        self.assertEqual((result["recovery_action"], result["application"], result["core"]), ("NONE", "NO-GO", "NO-GO"))
        for name in ("source_authentication", "proof_verification", "network_provisioning", "durable_retention"):
            self.assertEqual(result[name], "NOT_PERFORMED")
        for name in ("source_currentness", "restore_fence", "canonicality", "finality"):
            self.assertEqual(result[name], "UNFILLED")
        self.assertEqual(result["atomic_entry"], "NOT_IMPLEMENTED")
        for name in ("retain_prior_evidence", "retain_original_bytes", "retain_possible_disclosure",
                     "revalidate_funding_before_recovery", "revalidate_live_entry_before_recovery"):
            self.assertIs(result[name], True)
        for name in ("replenish_work", "replacement_original_allowed"):
            self.assertIs(result[name], False)

    def test_three_opening_types_have_bound_payloads_and_eight_unselected_profiles(self):
        result = self.inspect()
        self.assertEqual(result["framing"], "BOUND_PUBLIC_OPENINGS_ONLY")
        self.assertEqual(result["claim_coverage"], "COMPLETE_CLAIM")
        self.assertEqual(len(result["unselected_profiles"]), 8)
        for name in opening.SELECTED:
            self.assertEqual(result["comparisons"][name]["opening"], "BOUND_UNAUTHENTICATED_PAYLOAD")
        for name in result["unselected_profiles"]:
            self.assertEqual(result["comparisons"][name]["opening"], "OPENING_PROFILE_UNSELECTED")
        self.assert_no_permission(result)

    def test_exact_originals_are_both_opened_without_signature_verification(self):
        result = self.inspect()["comparisons"]["original_authorization"]
        self.assertEqual(result["exact_originals"], {"long": "MATCH", "short": "MATCH"})
        self.assertEqual(result["inner_signature_verification"], "NOT_PERFORMED")
        self.assertEqual(result["signed_account_wire"], "ABSENT")
        for leg in ("long", "short"):
            self.assertEqual(bytes.fromhex(self.bundle["openings"]["original_authorization"]["originals_hex"][leg]), original(leg))

    def test_old_synthetic_entry_ids_differ_from_both_actual_create_hashes(self):
        result = self.inspect()["comparisons"]["funding_send"]["legs"]
        for leg in ("long", "short"):
            self.assertEqual(result[leg]["advertised_hash"], "MATCH")
            self.assertEqual(result[leg]["create_terms"], "MATCH")
            self.assertEqual(result[leg]["send_derived_entry"], "DIFFERS_FROM_SELECTION")
            self.assertEqual(result[leg]["candidate_membership"], "NOT_INCLUDED_CLAIM")
            self.assertNotEqual(result[leg]["computed_hash_hex"], TERMS[leg]["entry_id_hex"])

    def test_matching_created_ids_and_headers_still_have_no_account_authority(self):
        selected = matching_selection()
        query = authority.read_query(**selected)
        claim_wire, bundle = packet(query, payloads(selected))
        result = self.inspect(bundle, claim_wire, query)
        for leg in ("long", "short"):
            compared = result["comparisons"]["funding_send"]["legs"][leg]
            for name in ("advertised_hash", "create_terms", "send_derived_entry"):
                self.assertEqual(compared[name], "MATCH")
            self.assertEqual(compared["candidate_membership"], "INCLUDED_CLAIM")
            self.assertEqual(len(compared["confirmation_claims"]), 1)
            self.assertEqual(compared["signed_account_wire"], "ABSENT")
            for name in ("outer_account_authorization", "acknowledged_momentum_admission", "live_entry"):
                self.assertEqual(compared[name], "NOT_PERFORMED")
        self.assert_no_permission(result)
        changed = payloads(selected)
        changed["funding_send"]["records"]["long"]["hash_hex"] = "00" * 32
        claim_wire, bundle = packet(query, changed)
        result = self.inspect(bundle, claim_wire, query)
        compared = result["comparisons"]["funding_send"]["legs"]["long"]
        self.assertEqual(compared["advertised_hash"], "DIFFERS_FROM_ADVERTISED")
        self.assertEqual(compared["candidate_membership"], "INCLUDED_CLAIM")
        self.assert_no_permission(result)

    def test_advertised_hash_mismatch_is_retained_as_a_separate_comparison(self):
        changed = copy.deepcopy(self.payloads)
        changed["funding_send"]["records"]["long"]["hash_hex"] = "00" * 32
        claim_wire, bundle = packet(self.query, changed)
        result = self.inspect(bundle, claim_wire)
        self.assertEqual(result["comparisons"]["funding_send"]["legs"]["long"]["advertised_hash"], "DIFFERS_FROM_ADVERTISED")
        self.assertEqual(result["opening_bundle"]["openings"]["funding_send"], changed["funding_send"])
        self.assertEqual(result["claim"]["facts"]["funding_send"]["status"], "supported")
        self.assert_no_permission(result)

    def test_changed_create_fields_in_either_leg_are_not_hidden_by_correct_hashes(self):
        for leg in ("long", "short"):
            for field, value in (("amount", "9"), ("token_standard_hex", "03" * 10),
                                 ("address_hex", "0033" + "33" * 18), ("to_address_hex", "0044" + "44" * 18)):
                with self.subTest(leg=leg, field=field):
                    changed = copy.deepcopy(self.payloads)
                    record = changed["funding_send"]["records"][leg]
                    record["block"][field] = value
                    record["hash_hex"] = account.account_block_hash(record["block"])
                    claim_wire, bundle = packet(self.query, changed)
                    result = self.inspect(bundle, claim_wire)
                    self.assertEqual(result["comparisons"]["funding_send"]["legs"][leg]["create_terms"], "DIFFERS_FROM_SELECTION")
                    self.assert_no_permission(result)

    def test_create_key_expiry_and_recipient_are_separate_from_hash_equality(self):
        for leg in ("long", "short"):
            for field, value in (("expiration_time", "900"), ("point_lock_hex", "12" * 32),
                                 ("destination_hex", "0012" + "12" * 18), ("point_type", 0)):
                changed = copy.deepcopy(self.payloads)
                record = changed["funding_send"]["records"][leg]
                call = account.decode_call(bytes.fromhex(record["block"]["data_hex"]))
                call[field] = value
                record["block"]["data_hex"] = account.encode_call(call).hex()
                record["hash_hex"] = account.account_block_hash(record["block"])
                claim_wire, bundle = packet(self.query, changed)
                self.assertEqual(self.inspect(bundle, claim_wire)["comparisons"]["funding_send"]["legs"][leg]["create_terms"],
                                 "DIFFERS_FROM_SELECTION")

    def test_noncreate_or_aliased_abi_remains_a_structural_conflict(self):
        for raw in (b"\x01", account.encode_call({"method": "Reclaim", "entry_id_hex": "44" * 32}),
                    bytes.fromhex(self.payloads["funding_send"]["records"]["long"]["block"]["data_hex"]) + b"\0"):
            changed = copy.deepcopy(self.payloads)
            record = changed["funding_send"]["records"]["long"]
            record["block"]["data_hex"] = raw.hex()
            record["hash_hex"] = account.account_block_hash(record["block"])
            claim_wire, bundle = packet(self.query, changed)
            self.assertEqual(self.inspect(bundle, claim_wire)["comparisons"]["funding_send"]["legs"]["long"]["create_terms"],
                             "DIFFERS_FROM_SELECTION")

    def test_hash_inputs_do_not_qualify_plasma_or_acknowledged_momentum(self):
        changed = copy.deepcopy(self.payloads)
        block = changed["funding_send"]["records"]["long"]["block"]
        block.update(difficulty="99", fused_plasma="0", nonce_hex="ff" * 8, momentum_hash_hex="00" * 32, momentum_height="0")
        changed["funding_send"]["records"]["long"]["hash_hex"] = account.account_block_hash(block)
        claim_wire, bundle = packet(self.query, changed)
        result = self.inspect(bundle, claim_wire)
        self.assertEqual(result["comparisons"]["funding_send"]["legs"]["long"]["create_terms"], "MATCH")
        self.assertEqual(result["comparisons"]["funding_send"]["legs"]["long"]["acknowledged_momentum_admission"], "NOT_PERFORMED")
        self.assert_no_permission(result)

    def test_changed_shaped_original_is_retained_as_a_conflict_not_replacement(self):
        for leg in ("long", "short"):
            changed = copy.deepcopy(self.payloads)
            changed["original_authorization"]["originals_hex"][leg] = recovery.synthetic_claim(TERMS, leg, "00" * 64).hex()
            claim_wire, bundle = packet(self.query, changed)
            result = self.inspect(bundle, claim_wire)
            self.assertEqual(result["comparisons"]["original_authorization"]["exact_originals"][leg], "DIFFERS_FROM_SELECTION")
            self.assert_no_permission(result)

    def test_supported_and_contradicted_labels_do_not_determine_comparisons(self):
        for name in opening.SELECTED:
            claim_wire, bundle = packet(self.query, self.payloads, statuses={name: "contradicted"})
            result = self.inspect(bundle, claim_wire)
            self.assertEqual(result["claim_coverage"], "CONTRADICTED_CLAIM")
            self.assertEqual(result["comparisons"][name]["claimed_status"], "contradicted")
            self.assertEqual(result["opening_bundle"]["openings"][name], self.payloads[name])
            self.assert_no_permission(result)

    def test_each_missing_selected_opening_is_incomplete_without_erasure(self):
        for name in opening.SELECTED:
            claim_wire, bundle = packet(self.query, self.payloads, missing=(name,))
            result = self.inspect(bundle, claim_wire)
            self.assertEqual(result["comparisons"][name]["opening"], "MISSING_OPENING")
            self.assert_no_permission(result)

    def test_funding_without_candidate_does_not_claim_membership(self):
        claim_wire, bundle = packet(self.query, self.payloads, missing=("momentum_lineage",))
        result = self.inspect(bundle, claim_wire)
        for leg in ("long", "short"):
            self.assertEqual(result["comparisons"]["funding_send"]["legs"][leg]["candidate_membership"],
                             "NOT_CHECKED_MISSING_CANDIDATE")

    def test_unknown_claim_has_no_opening_or_fallback(self):
        for name in opening.SELECTED:
            claim_wire, bundle = packet(self.query, self.payloads, statuses={name: "unknown"})
            result = self.inspect(bundle, claim_wire)
            self.assertEqual(result["comparisons"][name]["opening"], "UNKNOWN_CLAIM")
            self.assert_no_permission(result)
            bundle["openings"][name] = self.payloads[name]
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(bundle, claim_wire)

    def test_unavailable_claim_has_null_openings_and_no_terminal_outcome(self):
        claim_wire = wire(claim(self.query, status="unknown", availability="unavailable"))
        bundle = dict(self.bundle, claim_wire_digest_hex=opening.claim_digest(claim_wire), openings=dict.fromkeys(opening.SELECTED))
        result = self.inspect(bundle, claim_wire)
        self.assertEqual(result["claim_coverage"], "UNAVAILABLE_CLAIM")
        self.assertTrue(all(item["opening"] == "UNKNOWN_CLAIM" for item in result["comparisons"].values()))
        self.assert_no_permission(result)

    def test_extra_unselected_proof_profiles_are_refused(self):
        for name in authority.OBLIGATIONS:
            if name not in opening.SELECTED:
                bundle = copy.deepcopy(self.bundle)
                bundle["openings"][name] = {"verified": True}
                with self.assertRaises(opening.NoMOpeningRefused):
                    self.inspect(bundle)
                with self.assertRaises(opening.NoMOpeningRefused):
                    opening.opening_digest(self.query, name, "supported", {})

    def test_commitment_domains_bind_the_complete_query_fact_status_and_payload(self):
        for name in opening.SELECTED:
            expected = hashlib.sha256(b"ptlc-nom-evidence-payload-v1\0" + wire(dict(schema=opening.PAYLOAD_SCHEMA,
                query_digest_hex=self.query.digest_hex, obligation=name, status="supported", payload=self.payloads[name]))).hexdigest()
            self.assertEqual(opening.opening_digest(self.query, name, "supported", self.payloads[name]), expected)
            self.assertNotEqual(expected, opening.opening_digest(self.query, name, "contradicted", self.payloads[name]))
        self.assertEqual(opening.claim_digest(self.claim_wire), hashlib.sha256(b"ptlc-nom-opened-claim-v1\0" + self.claim_wire).hexdigest())

    def test_status_relabeling_without_new_evidence_commitment_is_refused(self):
        for name in opening.SELECTED:
            value = json.loads(self.claim_wire)
            value["facts"][name]["status"] = "contradicted"
            claim_wire = wire(value)
            bundle = dict(self.bundle, claim_wire_digest_hex=opening.claim_digest(claim_wire))
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(bundle, claim_wire)

    def test_changed_payload_without_new_commitment_is_refused(self):
        for name in opening.SELECTED:
            bundle = copy.deepcopy(self.bundle)
            if name == "funding_send":
                bundle["openings"][name]["records"]["short"]["block"]["amount"] = "99"
            elif name == "original_authorization":
                bundle["openings"][name]["originals_hex"]["long"] = recovery.synthetic_claim(TERMS, "long", "00" * 64).hex()
            else:
                bundle["openings"][name]["candidate_wire_hex"] += "20"
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(bundle)

    def test_claim_wire_digest_binds_even_unselected_claim_labels(self):
        value = json.loads(self.claim_wire)
        value["facts"]["recipient_receipt"]["status"] = "contradicted"
        with self.assertRaises(opening.NoMOpeningRefused):
            self.inspect(claim_wire=wire(value))

    def test_cross_query_challenge_checkpoint_network_and_originals_are_refused(self):
        for kind in ("challenge", "checkpoint", "network", "original", "consumer"):
            selected = selection()
            if kind == "challenge":
                selected["challenge_hex"] = "88" * 32
            elif kind == "checkpoint":
                selected["checkpoint_selection"]["authority_revision"] += 1
            elif kind == "network":
                selected["network_selection"]["authority_incarnation_hex"] = "88" * 32
            elif kind == "consumer":
                selected["consumer_selection"]["disclosure_possible"] = False
            else:
                selected["originals"]["short"] = recovery.synthetic_claim(TERMS, "short", "00" * 64)
            query = authority.read_query(**selected)
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(query=query)
            for name in opening.SELECTED:
                self.assertNotEqual(opening.opening_digest(query, name, "supported", self.payloads[name]),
                                    opening.opening_digest(self.query, name, "supported", self.payloads[name]))

    def test_equal_momentum_hash_with_changed_raw_spacing_is_not_the_selected_opening(self):
        changed = copy.deepcopy(self.payloads)
        raw = json.dumps(MOMENTA["baseline"], indent=2).encode("ascii")
        changed["momentum_lineage"]["candidate_wire_hex"] = raw.hex()
        claim_wire, bundle = packet(self.query, changed)
        with self.assertRaises(opening.NoMOpeningRefused):
            self.inspect(bundle, claim_wire)

    def test_unselected_self_consistent_candidate_cannot_replace_selected_bytes(self):
        for field, size in (("public_key_hex", 32), ("signature_hex", 64)):
            changed = copy.deepcopy(self.payloads)
            candidate = copy.deepcopy(MOMENTA["baseline"])
            candidate["momenta"][-1][field] = "99" * size
            self.assertNotEqual(wire(candidate), self.selected["candidate_wire"])
            self.assertEqual(momentum.momentum_hash(candidate["momenta"][-1]["momentum"]), candidate["momenta"][-1]["hash_hex"])
            changed["momentum_lineage"]["candidate_wire_hex"] = wire(candidate).hex()
            claim_wire, bundle = packet(self.query, changed)
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(bundle, claim_wire)

    def test_both_leg_records_and_originals_are_mandatory_in_present_payloads(self):
        for name, field in (("funding_send", "records"), ("original_authorization", "originals_hex")):
            for leg in ("long", "short"):
                changed = copy.deepcopy(self.payloads[name])
                del changed[field][leg]
                with self.assertRaises(opening.NoMOpeningRefused):
                    opening.opening_digest(self.query, name, "supported", changed)

    def test_swapped_originals_or_wrong_original_terms_are_refused_not_normalized(self):
        changed = copy.deepcopy(self.payloads)
        changed["original_authorization"]["originals_hex"] = {
            "long": original("short").hex(), "short": original("long").hex()}
        claim_wire, bundle = packet(self.query, changed)
        before = wire(bundle)
        with self.assertRaises(opening.NoMOpeningRefused):
            self.inspect(bundle, claim_wire)
        self.assertEqual(wire(bundle), before)

    def test_missing_or_extra_bundle_and_payload_fields_are_refused(self):
        for field in self.bundle:
            bundle = copy.deepcopy(self.bundle)
            del bundle[field]
            with self.assertRaises(opening.NoMOpeningRefused):
                self.inspect(bundle)
        bundle = dict(self.bundle, authenticated=True)
        with self.assertRaises(opening.NoMOpeningRefused):
            self.inspect(bundle)
        for name in opening.SELECTED:
            payload = dict(self.payloads[name], verified=True)
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.opening_digest(self.query, name, "supported", payload)

    def test_oversized_original_and_candidate_hex_are_bounded_before_decode(self):
        for name, field, limit in (("momentum_lineage", "candidate_wire_hex", momentum.MAX_WIRE_BYTES),
                                   ("original_authorization", "originals_hex", recovery.MAX_WIRE)):
            payload = copy.deepcopy(self.payloads[name])
            if name == "original_authorization":
                payload[field]["long"] = "00" * (limit + 1)
            else:
                payload[field] = "00" * (limit + 1)
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.opening_digest(self.query, name, "supported", payload)

    def test_hex_aliases_wrong_types_and_empty_payload_bytes_are_refused(self):
        for value in ("", "0", "AB", "00 00", "gg", None, True, 1, b"00"):
            payload = {"candidate_wire_hex": value}
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.opening_digest(self.query, "momentum_lineage", "supported", payload)

    def test_funding_hash_input_fields_and_widths_remain_strict(self):
        for change in ({"amount": True}, {"height": "01"}, {"nonce_hex": "00"}, {"data_hex": "00" * 4097},
                       {"version": str(1 << 64)}, {"descendant_hashes_hex": ["11" * 32] * 65}):
            payload = copy.deepcopy(self.payloads["funding_send"])
            payload["records"]["long"]["block"].update(change)
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.opening_digest(self.query, "funding_send", "supported", payload)

    def test_largest_selected_funding_encodings_remain_bounded_and_unadmitted(self):
        changed = copy.deepcopy(self.payloads)
        for record in changed["funding_send"]["records"].values():
            record["block"].update(data_hex="00" * 4096, descendant_hashes_hex=["11" * 32] * 64)
            record["hash_hex"] = account.account_block_hash(record["block"])
        self.assertLess(len(wire(changed["funding_send"])), opening.MAX_FUNDING_BYTES)
        claim_wire, bundle = packet(self.query, changed)
        result = self.inspect(bundle, claim_wire)
        for leg in ("long", "short"):
            compared = result["comparisons"]["funding_send"]["legs"][leg]
            self.assertEqual(compared["advertised_hash"], "MATCH")
            self.assertEqual(compared["create_terms"], "DIFFERS_FROM_SELECTION")
        self.assert_no_permission(result)

    def test_duplicate_escaped_nonfinite_nonascii_and_noncanonical_outer_wire_are_refused(self):
        raw = wire(self.bundle)
        bad = (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":Infinity}', b'"\xff"', b'{',
               raw.replace(b'"schema":', b'"\\u0073chema":', 1), b" " + raw,
               json.dumps(self.bundle, indent=2).encode("ascii"))
        for value in bad:
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.inspect_openings(self.query, self.claim_wire, value)

    def test_outer_byte_depth_and_input_type_bounds_precede_json(self):
        for value in (b"", b" " * (opening.MAX_WIRE_BYTES + 1), bytearray(b"{}"), "{}",
                      b"[" * 2000 + b"0" + b"]" * 2000):
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.inspect_openings(self.query, self.claim_wire, value)

    def test_malformed_claims_and_selected_query_types_have_sanitized_refusals(self):
        for query, claim_wire in ((None, self.claim_wire), (self.query.as_dict(), self.claim_wire),
                                  (self.query, b"{}"), (self.query, b"")):
            with self.assertRaisesRegex(opening.NoMOpeningRefused, "^NoM public evidence opening refused$"):
                opening.inspect_openings(query, claim_wire, wire(self.bundle))
        for value in (b"", b" " * (authority.MAX_WIRE_BYTES + 1), bytearray(b"{}")):
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.claim_digest(value)

    def test_unknown_and_invalid_statuses_cannot_acquire_opening_commitments(self):
        for status in ("unknown", "verified", None, True, 1):
            with self.assertRaises(opening.NoMOpeningRefused):
                opening.opening_digest(self.query, "momentum_lineage", status, self.payloads["momentum_lineage"])

    def test_exact_replay_and_fresh_challenged_old_claim_never_establish_currentness(self):
        before = (self.query.canonical_bytes, self.claim_wire, wire(self.bundle))
        self.assertEqual(self.inspect(), self.inspect())
        selected = selection()
        selected["challenge_hex"] = "99" * 32
        query = authority.read_query(**selected)
        claim_wire, bundle = packet(query, payloads(selected))
        self.assert_no_permission(self.inspect(bundle, claim_wire, query))
        self.assertEqual(before, (self.query.canonical_bytes, self.claim_wire, wire(self.bundle)))

    def test_result_mutation_cannot_reselect_query_or_clear_disclosure(self):
        before = self.query.canonical_bytes
        result = self.inspect()
        result["claim"]["checkpoint"]["authority_revision"] = 0
        result["opening_bundle"]["openings"]["original_authorization"]["originals_hex"]["long"] = "00"
        self.assertEqual(self.query.canonical_bytes, before)
        self.assertTrue(self.query.as_dict()["consumer_selection"]["disclosure_possible"])
        self.assertEqual(self.inspect()["claim"]["checkpoint"]["authority_revision"], 7)

    def test_common_prefix_or_all_supported_openings_never_skip_fresh_funding_checks(self):
        result = self.inspect()
        self.assertTrue(result["revalidate_funding_before_recovery"])
        self.assertTrue(result["revalidate_live_entry_before_recovery"])
        self.assertEqual(result["comparisons"]["live_funding_entry"]["opening"], "OPENING_PROFILE_UNSELECTED")
        self.assert_no_permission(result)

    def test_opening_comparison_does_no_file_or_process_io(self):
        raw = wire(self.bundle)
        with patch("builtins.open", side_effect=AssertionError("unexpected file operation")), \
             patch("subprocess.Popen", side_effect=AssertionError("unexpected process operation")):
            result = opening.inspect_openings(self.query, self.claim_wire, raw)
        self.assert_no_permission(result)


if __name__ == "__main__":
    unittest.main()
