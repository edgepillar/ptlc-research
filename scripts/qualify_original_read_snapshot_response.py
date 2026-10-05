#!/usr/bin/env python3
"""Test-only actual-store binding with the existing public signature checker."""

import argparse
from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parents[1]/"tests")]
from qualification import original_read_response as response, original_read_snapshot as snapshot
from qualification import policy_effect_store as local
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from original_snapshot_vectors import OUTPUT, canonical, scenario, selected


class RealOriginalSnapshotResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(OUTPUT.read_text("ascii"))

    def raw(self, request):
        return subprocess.run([str(self.entry)], input=canonical(request), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=3, check=False)

    def test_actual_ten_owned_store_samples_match_existing_public_worker_without_sql_mutation(self):
        for name, v in self.fixture["positive_vectors"].items():
            with self.subTest(name=name), scenario(name) as value:
                query = value.query()
                before = value.path.read_bytes(), value.store.local_view()
                expected = value.response(query)
                self.assertEqual(expected.as_dict(), v["response"])
                self.assertEqual(expected.message_digest_hex, v["message_digest_hex"])
                self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=self.check), expected)
                raw = self.raw(v["request"])
                self.assertEqual((raw.returncode, raw.stdout, raw.stderr), (0, canonical(v["result"])+b"\n", b""))
                self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)

    def test_actual_six_validly_signed_counterclaims_pass_math_but_refuse_actual_expectation(self):
        for name, v in self.fixture["counterclaim_vectors"].items():
            with self.subTest(name=name), scenario(v["actual_scenario"]) as value:
                counter = selected(v)  # Intentionally unsafe packet-selected expectation.
                self.assertIs(response.verify_selected_response(counter, canonical(v["envelope"]), verifier=self.check), counter)
                actual = value.response()
                calls = []
                def check(packet):
                    calls.append(packet)
                    return self.check(packet)
                with self.assertRaises(response.OriginalResponseError):
                    response.verify_selected_response(actual, canonical(v["envelope"]), verifier=check)
                self.assertEqual(calls, [])
                if name == "fresh_challenge_over_initial_absence":
                    value.store.allocate_synthetic(value.original)
                try:
                    claim = snapshot.sample_original(value.store, value.root, counter._query)
                except local.StoreRefused:
                    continue
                self.assertNotEqual(claim.as_dict(), counter._claim.as_dict())

    def test_actual_old_signatures_refuse_changed_charge_effect_and_retained_heads(self):
        for name, v in self.fixture["positive_vectors"].items():
            with self.subTest(name=name):
                p = copy.deepcopy(v["request"])
                p["response"]["query"]["expected_record_checkpoint"]["record_lineage_digest_hex"] = "08"*32
                raw = self.raw(p)
                self.assertNotEqual(raw.returncode, 0)
                self.assertEqual((raw.stdout, raw.stderr), (b"", b""))
                record = v["response"]["claim"]["original_record"]
                if record is not None:
                    for field in ("charge_sequence", "effect_sequence"):
                        p = copy.deepcopy(v["request"])
                        p["response"]["claim"]["original_record"][field] = 1
                        if field == "charge_sequence":
                            p["response"]["claim"]["original_record"][field] = 2
                        raw = self.raw(p)
                        self.assertNotEqual(raw.returncode, 0)
                        self.assertEqual((raw.stdout, raw.stderr), (b"", b""))

    def test_actual_zero_signature_callback_forgery_is_not_public_math(self):
        with scenario("pending") as value:
            expected = value.response()
            v = copy.deepcopy(self.fixture["positive_vectors"]["pending"])
            v["envelope"]["root_envelope"]["root_signature_hex"] = "00"*64
            v["envelope"]["response_signature_hex"] = "00"*64
            def forged(packet):
                return response.expected_result(response.request_digest(packet))
            self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=forged), expected)
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(expected, canonical(v["envelope"]), verifier=self.check)

    def test_actual_signed_read_can_age_before_delivery_and_blind_ideal_entry(self):
        with scenario("pending") as value:
            query = value.query()
            def cut(name):
                if name == "original-read-sample-after-commit":
                    with local.OfflinePolicyEffectStore(str(value.path), value.labels) as writer:
                        writer.replace_local_policy(0, value.profile, active=False)
            with patch.object(value.store, "_cut", side_effect=cut):
                expected = value.response(query)
            v = self.fixture["positive_vectors"]["pending"]
            self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=self.check), expected)
            self.assertFalse(value.store.local_view().active)
            with self.assertRaises(local.StoreRefused):
                value.response(query)
            with self.assertRaises(local.StoreRefused):
                value.store.apply_synthetic_effect(value.original)
            entries = []  # Blind ideal external use is a counterexample, never an actuator.
            entries.append(expected.as_dict()["claim"]["original_record"]["original_operation"]["operation_id_hex"])
            self.assertEqual(len(entries), 1)

    def test_actual_restored_and_cloned_pending_history_repeats_math_and_synthetic_effect(self):
        with scenario("pending") as value:
            expected = value.response()
            v = self.fixture["positive_vectors"]["pending"]
            value.store.close()
            saved = value.path.with_name("saved.sqlite3")
            cloned = value.path.with_name("cloned.sqlite3")
            shutil.copyfile(value.path, saved)
            shutil.copyfile(value.path, cloned)
            effects = []
            for path in (value.path, cloned):
                with local.OfflinePolicyEffectStore(str(path), value.labels) as store:
                    claim = snapshot.sample_original(store, value.root, expected._query)
                    old = response.original_read_response(value.root, expected._query, claim)
                    self.assertEqual(old.canonical_bytes, expected.canonical_bytes)
                    self.assertIs(response.verify_selected_response(old, canonical(v["envelope"]), verifier=self.check), old)
                    effects.append(store.apply_synthetic_effect(value.original).effect_sequence)
            shutil.copyfile(saved, value.path)
            value.store = local.OfflinePolicyEffectStore(str(value.path), value.labels)
            restored = value.response()
            self.assertEqual(restored.canonical_bytes, expected.canonical_bytes)
            self.assertIs(response.verify_selected_response(restored, canonical(v["envelope"]), verifier=self.check), restored)
            effects.append(value.store.apply_synthetic_effect(value.original).effect_sequence)
            self.assertEqual(effects, [2, 2, 2])

    def test_actual_unavailable_revoked_and_lost_delivery_never_refund_retry_or_recover(self):
        for name in ("unavailable_pending", "revoked_pending", "reduced_pending_two_charges"):
            with self.subTest(name=name), scenario(name) as value:
                before = value.path.read_bytes(), value.store.local_view()
                expected = value.response()
                v = self.fixture["positive_vectors"][name]
                self.assertIs(response.verify_selected_response(expected, canonical(v["envelope"]), verifier=self.check), expected)
                with self.assertRaises(local.StoreRefused):
                    value.store.apply_synthetic_effect(value.original)
                self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)
        with scenario("pending") as value:
            before = value.path.read_bytes(), value.store.local_view()
            query = value.query()
            def lost(name):
                if name == "original-read-sample-after-commit":
                    raise OSError("synthetic lost return")
            with patch.object(value.store, "_cut", side_effect=lost), self.assertRaises(local.StoreOutcomeUnknown):
                value.response(query)
            self.assertEqual((value.path.read_bytes(), value.store.local_view()), before)
            self.assertEqual(value.response(query).as_dict(), self.fixture["positive_vectors"]["pending"]["response"])

    def test_actual_changed_entry_pin_and_cached_other_request_result_refuse(self):
        v = self.fixture["positive_vectors"]["pending"]
        with scenario("pending") as value:
            expected = value.response()
            other = self.fixture["counterclaim_vectors"]["false_absence_at_pending_head"]["result"]
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(expected, canonical(v["envelope"]), verifier=lambda _: other)
            with tempfile.TemporaryDirectory(prefix="synthetic-original-check-") as directory:
                path = Path(directory)/"worker"
                shutil.copyfile(self.entry, path)
                path.chmod(0o700)
                check = PublicOriginalResponseCheck(path.resolve(), expected_executable_sha256_hex=hashlib.sha256(path.read_bytes()).hexdigest())
                path.write_bytes(path.read_bytes()+b"\n")
                with self.assertRaises(response.OriginalResponseError):
                    response.verify_selected_response(expected, canonical(v["envelope"]), verifier=check)


def main():
    parser = argparse.ArgumentParser(description="Offline test-only owned original-snapshot signature binding")
    parser.add_argument("--original-response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.original_response_verifier).resolve()
        RealOriginalSnapshotResponseTests.entry = entry
        RealOriginalSnapshotResponseTests.check = PublicOriginalResponseCheck(entry,
            expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public original response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalSnapshotResponseTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
