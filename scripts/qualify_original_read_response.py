#!/usr/bin/env python3
"""Actual public historical original-read math; no source or recovery adapter."""

import argparse
import copy
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tests"))
from qualification import original_read_response as response, policy_effect_store as local
from qualification.original_read_response_verifier import PublicOriginalResponseCheck
from test_original_read_response import fixture, selection, fake_check, target


class RealOriginalReadResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = response._canonical(cls.primary["envelope"])

    def raw(self, wire):
        return subprocess.run([str(self.entry)], input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)

    def refused(self, wire):
        r = self.raw(wire)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (1, b"", b""))

    def store(self, path):
        d = self.expected.root_dict()
        s = d["source_context"]
        labels = local.SourceLabels(s["source_id_hex"], s["source_incarnation_hex"], s["authority_id_hex"], s["resource_digest_hex"])
        profile = response._canonical(d["governor_profile"])
        store = local.OfflinePolicyEffectStore(str(path), labels, initial_profile=profile)
        # Local state is a separate synthetic premise, not derived from a reply.
        for revision in range(4): store.replace_local_policy(revision, profile, active=True)
        o = local.OriginalRequest("01"*32, 4, profile, "02"*32)
        return store, labels, o

    def test_actual_all_twenty_two_public_responses_return_only_same_unsigned_expectation(self):
        for name, v in self.vectors["positive_vectors"].items():
            e = selection(name)
            self.assertIs(response.verify_selected_response(e, response._canonical(v["envelope"]), verifier=self.check), e)
            raw = self.raw(response._canonical(v["request"]))
            self.assertEqual((raw.returncode, raw.stdout, raw.stderr), (0, response._canonical(v["result"])+b"\n", b""))
            self.assertEqual(set(v["result"]), {"schema", "request_digest_hex", "root_signature_valid", "response_signature_valid"})

    def test_actual_peer_selected_valid_originals_roots_and_claims_refuse_before_work(self):
        for name, v in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            with patch("qualification.original_read_response_verifier.run_public_worker") as run:
                with self.assertRaises(response.OriginalResponseError):
                    response.verify_selected_response(self.expected, response._canonical(v["envelope"]), verifier=self.check)
                run.assert_not_called()

    def test_actual_all_forty_three_mathematically_signed_forbidden_reads_refuse_quietly(self):
        self.assertEqual(len(self.vectors["signed_refusal_vectors"]), 43)
        for v in self.vectors["signed_refusal_vectors"].values(): self.refused(response._canonical(v["request"]))

    def test_actual_wrong_domains_scalars_and_every_byte_of_both_signatures_refuse(self):
        for name in ("wrong_plain_prefix_signature_hex", "wrong_legacy_domain_signature_hex"):
            p = copy.deepcopy(self.primary["request"]); p["response_signature_hex"] = self.vectors[name]
            self.refused(response._canonical(p))
        for path in (("response_signature_hex",), ("root_envelope", "root_signature_hex")):
            sig = bytes.fromhex(target(self.primary["request"], path[:-1])[path[-1]])
            for i in range(64):
                changed = bytearray(sig); changed[i] ^= 1
                p = copy.deepcopy(self.primary["request"]); target(p, path[:-1])[path[-1]] = changed.hex()
                self.refused(response._canonical(p))
            for wrong in ("00"*64, "ff"*64, "00"*63, "AB"*64):
                p = copy.deepcopy(self.primary["request"]); target(p, path[:-1])[path[-1]] = wrong
                self.refused(response._canonical(p))

    def test_actual_old_signatures_cannot_follow_any_changed_complete_statement_or_root(self):
        for name, v in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            p = copy.deepcopy(v["request"]); p["response_signature_hex"] = self.primary["request"]["response_signature_hex"]
            self.refused(response._canonical(p))
        for name in ("new_root_revision", "new_incarnation", "new_head_profile", "alternate_response", "alternate_root"):
            p = copy.deepcopy(self.vectors["positive_vectors"][name]["request"])
            p["root_envelope"]["root_signature_hex"] = self.primary["request"]["root_envelope"]["root_signature_hex"]
            self.refused(response._canonical(p))

    def test_actual_alternate_valid_signatures_change_complete_results_and_refuse_cached_result(self):
        for field in ("alternate_root_signature_hex", "alternate_response_signature_hex"):
            p = copy.deepcopy(self.primary["envelope"])
            if field == "alternate_root_signature_hex": p["root_envelope"]["root_signature_hex"] = self.vectors[field]
            else: p["response_signature_hex"] = self.vectors[field]
            wire = response._canonical(p)
            self.assertIs(response.verify_selected_response(self.expected, wire, verifier=self.check), self.expected)
            with self.assertRaises(response.OriginalResponseError):
                response.verify_selected_response(self.expected, wire, verifier=lambda r:self.primary["result"])

    def test_actual_replay_restored_expectations_and_fresh_challenge_do_not_discover_current_heads(self):
        for name in ("new_policy_checkpoint", "new_record_checkpoint", "new_challenge", "new_incarnation", "alternate_root"):
            v = self.vectors["positive_vectors"][name]; e = selection(name)
            self.assertIs(response.verify_selected_response(e, response._canonical(v["envelope"]), verifier=self.check), e)
            old = copy.deepcopy(self.expected)
            self.assertIs(response.verify_selected_response(old, self.wire, verifier=self.check), old)
        new = selection("new_challenge").as_dict()
        for field in ("expected_checkpoint", "expected_record_checkpoint", "original_operation"):
            self.assertEqual(new["query"][field], self.expected.as_dict()["query"][field])
        self.assertTrue(new["claim"]["head_policy"]["active"])

    def test_malicious_callback_forges_two_flags_for_zero_signatures_but_actual_math_refuses(self):
        wire = response.envelope(self.expected, root_signature=bytes(64), response_signature=bytes(64))
        self.assertIs(response.verify_selected_response(self.expected, wire, verifier=fake_check), self.expected)
        with self.assertRaises(response.OriginalResponseError): response.verify_selected_response(self.expected, wire, verifier=self.check)

    def test_actual_historical_math_does_not_reenable_revoked_pending_effect_refund_or_mutate_sqlite(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-history-") as directory:
            path = Path(directory)/"policy.sqlite3"
            store, _, original = self.store(path)
            with store:
                store.allocate_synthetic(original)
                store.replace_local_policy(4, original.profile_wire, active=False)
                before = path.read_bytes(), store.local_view(), store.lookup_original(original)
                self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=self.check), self.expected)
                with self.assertRaises(local.StoreRefused): store.apply_synthetic_effect(original)
                self.assertEqual((path.read_bytes(), store.local_view(), store.lookup_original(original)), before)
                self.assertEqual((store.local_view().charged_operations, store.local_view().synthetic_effects), (1,0))

    def test_actual_self_selected_same_id_collisions_are_not_atomic_source_deduplication(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-collision-") as directory:
            store, _, original = self.store(Path(directory)/"policy.sqlite3")
            with store:
                store.allocate_synthetic(original)
                for name in ("same_id_changed_proposal", "same_id_changed_revision", "historical_different_profile"):
                    e = selection(name); v = self.vectors["positive_vectors"][name]
                    self.assertIs(response.verify_selected_response(e, response._canonical(v["envelope"]), verifier=self.check), e)
                    o = e.as_dict()["query"]["original_operation"]
                    changed = local.OriginalRequest(o["operation_id_hex"], o["expected_revision"], response._canonical(o["governor_profile"]), o["proposal_digest_hex"])
                    with self.assertRaises(local.StoreRefused): store.allocate_synthetic(changed)
                self.assertEqual(store.local_view().charged_operations, 1)

    def test_actual_coherent_source_clone_and_restore_repeat_synthetic_effect_despite_same_signed_history(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-copy-") as directory:
            path = Path(directory)/"policy.sqlite3"
            store, labels, original = self.store(path)
            with store:
                checkpoint, clone = Path(directory)/"checkpoint.sqlite3", Path(directory)/"clone.sqlite3"
                shutil.copyfile(path, checkpoint); shutil.copyfile(path, clone)
                store.allocate_synthetic(original); store.apply_synthetic_effect(original)
                with local.OfflinePolicyEffectStore(str(clone), labels) as copied:
                    self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=self.check), self.expected)
                    copied.allocate_synthetic(original); copied.apply_synthetic_effect(original)
                    self.assertEqual(store.local_view().synthetic_effects+copied.local_view().synthetic_effects, 2)
            shutil.copyfile(checkpoint, path)
            with local.OfflinePolicyEffectStore(str(path), labels) as restored:
                self.assertEqual(restored.local_view().synthetic_effects, 0)
                self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=self.check), self.expected)
                restored.allocate_synthetic(original); restored.apply_synthetic_effect(original)
                self.assertEqual(restored.local_view().synthetic_effects, 1)

    def test_actual_absent_unavailable_and_lost_return_do_not_reconcile_allocate_refund_or_retry(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-unknown-") as directory:
            path = Path(directory)/"policy.sqlite3"
            store, _, original = self.store(path)
            with store:
                store.allocate_synthetic(original)
                before = path.read_bytes(), store.local_view(), store.lookup_original(original)
                for name in ("absent", "unavailable"):
                    v = self.vectors["positive_vectors"][name]; e = selection(name)
                    self.assertIs(response.verify_selected_response(e, response._canonical(v["envelope"]), verifier=self.check), e)
                def lost(r): self.check(r); raise RuntimeError("synthetic lost return")
                with self.assertRaises(response.OriginalResponseError): response.verify_selected_response(self.expected, self.wire, verifier=lost)
                self.assertEqual((path.read_bytes(), store.local_view(), store.lookup_original(original)), before)
                self.assertIsNone(store.lookup_original(original).effect_sequence)

    def test_actual_statement_can_age_before_delivery_commit_and_blind_ideal_physical_entry(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-entry-") as directory:
            store, _, original = self.store(Path(directory)/"policy.sqlite3")
            with store:
                store.allocate_synthetic(original)
                e = selection("completed"); wire = response._canonical(self.vectors["positive_vectors"]["completed"]["envelope"])
                store.replace_local_policy(4, original.profile_wire, active=False)
                delivered = response.verify_selected_response(e, wire, verifier=self.check)
                with self.assertRaises(local.StoreRefused): store.apply_synthetic_effect(original)
                # Deliberately blind ideal list actuator, not a physical device.
                ideal_entry = [delivered.as_dict()["claim"]["original_record"]["original_operation"]["operation_id_hex"]]
                self.assertEqual(ideal_entry, [original.operation_id_hex])
                self.assertFalse(store.local_view().active)
                self.assertEqual(store.local_view().synthetic_effects, 0)

    def test_actual_entry_pin_canonical_aliases_legacy_packets_and_byte_bounds_fail_quietly(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-original-worker-") as directory:
            entry = Path(directory)/"worker"; entry.write_bytes(self.entry.read_bytes()); entry.chmod(0o700)
            check = PublicOriginalResponseCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
            with entry.open("ab") as stream: stream.write(b"\0")
            with patch("qualification.original_read_response_verifier.run_public_worker") as run:
                with self.assertRaises(response.OriginalResponseError): check(self.primary["request"])
                run.assert_not_called()
        wire = response._canonical(self.primary["request"])
        for invalid in (b"", b"\xff", b" "*16385, b"["*512+b"]"*512, wire+b"\n\n", b" "+wire,
                wire.replace(b'"response":', b'"\\u0072esponse":'),
                wire.replace(b'"revision":7', b'"revision":7,"revision":7'),
                wire.replace(b'"revision":7', b'"revision":7e0'), response._canonical(self.primary["envelope"]),
                response._canonical(self.primary["envelope"]["root_envelope"])):
            self.refused(invalid)
        r = self.raw(wire+b"\n")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, response._canonical(self.primary["result"])+b"\n", b""))


def main():
    parser = argparse.ArgumentParser(description="Offline public historical original-read mathematics; no source or admission")
    parser.add_argument("--original-response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.original_response_verifier).resolve()
        RealOriginalReadResponseTests.entry = entry
        RealOriginalReadResponseTests.check = PublicOriginalResponseCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError): parser.exit(1, "selected public original response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalReadResponseTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
