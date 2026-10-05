"""Owned samples and selected historical math remain separate trust boundaries."""

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from qualification import original_read_contract as reads, original_read_response as response
from qualification import original_read_snapshot as snapshot, policy_effect_store as local
from original_snapshot_vectors import INPUT, OUTPUT, SCENARIOS, canonical, scenario, selected, unsigned_inputs


def fixture():
    return json.loads(OUTPUT.read_text("ascii"))


def fake_check(request):
    return response.expected_result(response.request_digest(request))


class OriginalSnapshotResponseTests(unittest.TestCase):
    def test_fixture_replays_ten_actual_store_samples_and_six_explicit_counterclaims(self):
        inputs = unsigned_inputs()
        self.assertEqual(inputs, json.loads(INPUT.read_text("ascii")))
        f = fixture()
        self.assertEqual(set(f["positive_vectors"]), set(SCENARIOS))
        self.assertEqual(len(f["counterclaim_vectors"]), 6)
        for group in ("positive_vectors", "counterclaim_vectors"):
            for name, v in f[group].items():
                with self.subTest(group=group, name=name):
                    unsigned = inputs[group][name]
                    for field in ("root_declaration", "response", "message_digest_hex"):
                        self.assertEqual(v[field], unsigned[field])
                    expected = selected(v)
                    self.assertEqual(response.request(expected, canonical(v["envelope"])), v["request"])
                    self.assertEqual(response.request_digest(v["request"]), v["result"]["request_digest_hex"])
                    self.assertEqual(len(v["result"]), 4)

    def test_independently_selected_actual_samples_match_envelopes_without_mutating_any_store(self):
        for name, vector in fixture()["positive_vectors"].items():
            with self.subTest(name=name), scenario(name) as value:
                query = value.query()
                before = value.path.read_bytes(), value.store.local_view()
                expected = value.response(query)
                self.assertEqual(expected.as_dict(), vector["response"])
                result = response.verify_selected_response(expected, canonical(vector["envelope"]), verifier=fake_check)
                self.assertIs(result, expected)
                self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)

    def test_pending_completed_and_revoked_records_bind_actual_charge_and_effect_sequences(self):
        f = fixture()["positive_vectors"]
        self.assertIsNone(f["initial_absent"]["response"]["claim"]["original_record"])
        for name in ("pending", "completed", "revoked_pending", "revoked_completed", "replaced_completed"):
            claim = f[name]["response"]["claim"]
            self.assertEqual(claim["original_record"]["charge_sequence"], 1)
            self.assertEqual(claim["original_record"]["effect_sequence"],
                2 if name in ("completed", "revoked_completed", "replaced_completed") else None)
            self.assertEqual(claim["head_policy"]["active"], name in ("pending", "completed"))

    def test_changed_owner_epoch_caps_and_pins_keep_the_complete_retained_original_profile(self):
        r = fixture()["positive_vectors"]["replaced_completed"]["response"]
        old = r["query"]["original_operation"]["governor_profile"]
        head = r["claim"]["head_policy"]["governor_profile"]
        self.assertEqual(r["claim"]["original_record"]["original_operation"]["governor_profile"], old)
        for field in ("owner_auth_key_hex", "authority_epoch", "max_attempt_limit", "max_target_limit",
                "authority_profile_digest_hex", "verifier_profile_digest_hex", "pool_profile_digest_hex", "resource_profile_digest_hex"):
            self.assertNotEqual(old[field], head[field])

    def test_reduced_cap_keeps_two_old_charges_without_refund_effect_or_new_admission(self):
        with scenario("reduced_pending_two_charges") as value:
            before = value.path.read_bytes(), value.store.local_view()
            self.assertEqual(before[1].charged_operations, 2)
            self.assertEqual(json.loads(before[1].profile_wire)["max_attempt_limit"], 1)
            expected = value.response()
            self.assertEqual(expected.as_dict()["claim"]["observation"], "pending")
            with self.assertRaises(local.StoreRefused):
                value.store.apply_synthetic_effect(value.original)
            with self.assertRaises(local.StoreRefused):
                value.store.allocate_synthetic(replace(value.original, operation_id_hex="08"*32))
            self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)

    def test_unavailable_response_has_no_state_and_never_reconciles_allocates_or_refunds(self):
        with scenario("unavailable_pending") as value:
            before = value.path.read_bytes(), value.store.local_view()
            claim = value.response().as_dict()["claim"]
            self.assertEqual(claim["observation"], "unavailable")
            for field in ("claimed_checkpoint", "claimed_record_checkpoint", "head_policy", "original_record"):
                self.assertIsNone(claim[field])
            self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)
            self.assertEqual(before[1].charged_operations, 1)

    def test_mode_round_trip_preserves_policy_digest_but_binds_retained_record_history(self):
        f = fixture()["positive_vectors"]
        first, after = (f[n]["response"]["query"] for n in ("pending", "mode_round_trip_pending"))
        self.assertEqual(first["expected_checkpoint"], after["expected_checkpoint"])
        self.assertNotEqual(first["expected_record_checkpoint"], after["expected_record_checkpoint"])
        self.assertNotEqual(f["pending"]["message_digest_hex"], f["mode_round_trip_pending"]["message_digest_hex"])

    def test_actual_expectations_refuse_all_six_counterclaims_before_any_selected_checker(self):
        for name, v in fixture()["counterclaim_vectors"].items():
            with self.subTest(name=name), scenario(v["actual_scenario"]) as value:
                expected = value.response()
                calls = []
                def check(request):
                    calls.append(request)
                    return fake_check(request)
                with self.assertRaises(response.OriginalResponseError):
                    response.verify_selected_response(expected, canonical(v["envelope"]), verifier=check)
                self.assertEqual(calls, [])

    def test_packet_selected_false_claims_have_no_actual_sql_snapshot_provenance(self):
        for name, v in fixture()["counterclaim_vectors"].items():
            with self.subTest(name=name), scenario(v["actual_scenario"]) as value:
                claimed = selected(v)
                # Challenge alone is caller selected; after a managed charge the old heads refuse.
                if name == "fresh_challenge_over_initial_absence":
                    value.store.allocate_synthetic(value.original)
                try:
                    actual = snapshot.sample_original(value.store, value.root, claimed._query)
                except local.StoreRefused:
                    continue
                self.assertNotEqual(actual.as_dict(), claimed._claim.as_dict())

    def test_malicious_callback_can_forge_both_flags_even_for_zero_signatures(self):
        v = copy.deepcopy(fixture()["positive_vectors"]["pending"])
        v["envelope"]["root_envelope"]["root_signature_hex"] = "00"*64
        v["envelope"]["response_signature_hex"] = "00"*64
        with scenario("pending") as value:
            expected = value.response()
            self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=fake_check), expected)

    def test_read_can_age_before_delivery_while_its_old_selected_statement_still_matches(self):
        v = fixture()["positive_vectors"]["pending"]
        with scenario("pending") as value:
            old_query = value.query()
            def cut(name):
                if name == "original-read-sample-after-commit":
                    with local.OfflinePolicyEffectStore(str(value.path), value.labels) as writer:
                        writer.replace_local_policy(0, value.profile, active=False)
            with patch.object(value.store, "_cut", side_effect=cut):
                expected = value.response(old_query)
            self.assertTrue(expected.as_dict()["claim"]["head_policy"]["active"])
            self.assertFalse(value.store.local_view().active)
            self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=fake_check), expected)
            with self.assertRaises(local.StoreRefused):
                value.response(old_query)
            with self.assertRaises(local.StoreRefused):
                value.store.apply_synthetic_effect(value.original)

    def test_lost_sample_return_never_retries_reallocates_refunds_or_recovers(self):
        with scenario("pending") as value:
            before = value.path.read_bytes(), value.store.local_view()
            query = value.query()
            def lost(name):
                if name == "original-read-sample-after-commit":
                    raise OSError("synthetic lost sample return")
            with patch.object(value.store, "_cut", side_effect=lost), self.assertRaises(local.StoreOutcomeUnknown):
                value.response()
            self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)
            self.assertEqual(value.response(query).as_dict(), fixture()["positive_vectors"]["pending"]["response"])

    def test_restored_pending_copy_repeats_signed_checkpoint_and_synthetic_effect(self):
        with scenario("pending") as value:
            before = value.response()
            value.store.close()
            backup = value.path.with_name("saved.sqlite3")
            shutil.copyfile(value.path, backup)
            value.store = local.OfflinePolicyEffectStore(str(value.path), value.labels)
            effects = [value.store.apply_synthetic_effect(value.original).effect_sequence]
            value.store.close()
            shutil.copyfile(backup, value.path)
            value.store = local.OfflinePolicyEffectStore(str(value.path), value.labels)
            restored = value.response()
            self.assertEqual(restored.canonical_bytes, before.canonical_bytes)
            v = fixture()["positive_vectors"]["pending"]
            self.assertIs(response.verify_selected_response(restored, canonical(v["envelope"]), verifier=fake_check), restored)
            effects.append(value.store.apply_synthetic_effect(value.original).effect_sequence)
            self.assertEqual(effects, [2, 2])

    def test_unsigned_and_public_fixture_files_are_bounded_ascii_and_no_capability_result(self):
        for path in (INPUT, OUTPUT):
            wire = path.read_bytes()
            self.assertTrue(wire.isascii())
            self.assertLess(len(wire), 600000)
            for marker in (b"secret_key", b"private_key", b"mnemonic", b"current_authority", b"permit"):
                self.assertNotIn(marker, wire)
        for group in ("positive_vectors", "counterclaim_vectors"):
            for v in fixture()[group].values():
                self.assertEqual(v["result"], response.expected_result(response.request_digest(v["request"])))


if __name__ == "__main__":
    unittest.main()
