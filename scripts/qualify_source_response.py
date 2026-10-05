#!/usr/bin/env python3
"""Actual historical response mathematics, with no policy source connection."""

import argparse
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from qualification import source_response as response, policy_effect_store as store
from qualification.source_response_verifier import PublicResponseCheck
from test_source_response import fixture, selection, fake_check


class RealSourceResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = fixture()
        cls.primary = cls.vectors["positive_vectors"]["primary"]
        cls.expected = selection()
        cls.wire = response._canonical(cls.primary["envelope"])

    def raw(self, wire):
        return subprocess.run([str(self.entry)], input=wire, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=3)

    def test_actual_all_seventeen_responses_return_only_same_unsigned_selection(self):
        for name, vector in self.vectors["positive_vectors"].items():
            selected = selection(name)
            self.assertEqual(self.check(vector["request"]), vector["result"])
            self.assertIs(response.verify_selected_response(selected, response._canonical(vector["envelope"]), verifier=self.check), selected)
        for field in ("authorized", "provisioned", "current", "committed", "permit", "revision_advanced"):
            self.assertFalse(hasattr(self.expected, field))

    def test_actual_valid_peer_responses_and_roots_refuse_before_work(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            self.assertEqual(self.check(vector["request"]), vector["result"])
            calls=[]
            def checked(r): calls.append(True); return self.check(r)
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(self.expected, response._canonical(vector["envelope"]), verifier=checked)
            self.assertEqual(calls, [])

    def test_actual_raw_worker_refuses_all_twenty_five_mathematically_signed_forbidden_reads(self):
        for name, vector in self.vectors["signed_refusal_vectors"].items():
            with self.subTest(response=name):
                result = self.raw(response._canonical(vector["request"]))
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"", b""))

    def test_actual_wrong_roles_domain_scalars_and_each_byte_of_all_four_signatures_refuse(self):
        packet = self.primary["envelope"]
        wrong = list(self.vectors["wrong_role_signatures"].values()) + [self.vectors["wrong_domain_response_signature_hex"]]
        for sig in wrong:
            changed = dict(packet, response_signature_hex=sig)
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(self.expected, response._canonical(changed), verifier=self.check)
        packet = self.primary["request"]
        valid = self.raw(response._canonical(packet))
        self.assertEqual((valid.returncode,valid.stdout,valid.stderr),(0,response._canonical(self.primary["result"])+b"\n",b""))
        for path in (("response_signature_hex",), ("root_envelope", "root_signature_hex"), ("response", "query", "governor_signature_request", "issuer_signature_hex"), ("response", "query", "governor_signature_request", "owner_signature_hex")):
            old = packet
            for p in path: old = old[p]
            signature = bytes.fromhex(old)
            signatures = ["00"*64, "ff"*64, "ff"*32+"00"*32, "00"*32+"ff"*32]
            for i in range(64):
                c = bytearray(signature); c[i] ^= 1; signatures.append(bytes(c).hex())
            for sig in signatures:
                changed = copy.deepcopy(packet); target = changed
                for p in path[:-1]: target = target[p]
                target[path[-1]] = sig
                raw = self.raw(response._canonical(changed))
                self.assertEqual((raw.returncode,raw.stdout,raw.stderr),(1,b"",b""))

    def test_actual_old_response_signature_cannot_follow_changed_complete_response(self):
        for name, vector in self.vectors["positive_vectors"].items():
            if name == "primary": continue
            packet = dict(vector["envelope"], response_signature_hex=self.primary["envelope"]["response_signature_hex"])
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(selection(name), response._canonical(packet), verifier=self.check)

    def test_actual_old_root_signature_cannot_follow_changed_root_declaration(self):
        for name in ("alternate_root", "alternate_admin", "alternate_response", "alternate_owner", "alternate_issuer", "broader_profile", "new_epoch", "new_incarnation", "new_root_revision"):
            packet = copy.deepcopy(self.vectors["positive_vectors"][name]["envelope"])
            packet["root_envelope"]["root_signature_hex"] = self.primary["envelope"]["root_envelope"]["root_signature_hex"]
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(selection(name), response._canonical(packet), verifier=self.check)

    def test_actual_both_valid_signature_variants_change_complete_result_binding(self):
        for field in ("alternate_response_signature_hex", "alternate_root_signature_hex"):
            packet = copy.deepcopy(self.primary["envelope"])
            if field == "alternate_response_signature_hex": packet["response_signature_hex"] = self.vectors[field]
            else: packet["root_envelope"]["root_signature_hex"] = self.vectors[field]
            wire = response._canonical(packet)
            self.assertIs(response.verify_selected_response(self.expected, wire, verifier=self.check), self.expected)
            self.assertNotEqual(self.check(response.request(self.expected, wire)), self.primary["result"])
            with self.assertRaises(response.SourceResponseError):
                response.verify_selected_response(self.expected, wire, verifier=lambda r:self.primary["result"])

    def test_actual_replay_and_restored_old_selection_do_not_discover_current_revision(self):
        for name in ("new_checkpoint", "revoked", "alternate_admin", "alternate_root", "new_incarnation", "new_root_revision"):
            selected = selection(name)
            self.assertIs(response.verify_selected_response(selected, response._canonical(self.vectors["positive_vectors"][name]["envelope"]), verifier=self.check), selected)
            with self.assertRaises(response.SourceResponseError): response.verify_selected_response(selected, self.wire, verifier=self.check)
            restored = copy.deepcopy(self.expected)
            self.assertIs(response.verify_selected_response(restored, self.wire, verifier=self.check), restored)
        for _ in range(2): self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=self.check), self.expected)

    def test_malicious_selected_callback_forges_all_four_positives_for_two_zero_signatures(self):
        wire = response.envelope(self.expected, root_signature=bytes(64), response_signature=bytes(64))
        with self.assertRaises(response.SourceResponseError): response.verify_selected_response(self.expected, wire, verifier=self.check)
        self.assertIs(response.verify_selected_response(self.expected, wire, verifier=fake_check), self.expected)

    def test_actual_historical_reads_do_not_mutate_sqlite_refund_charge_or_apply_pending_effect(self):
        d = self.primary["envelope"]["root_envelope"]["declaration"]; source = d["source_context"]
        profile = response._canonical(d["governor_profile"])
        labels = store.SourceLabels(source["source_id_hex"], source["source_incarnation_hex"], source["authority_id_hex"], source["resource_digest_hex"])
        with tempfile.TemporaryDirectory(prefix="synthetic-response-policy-") as directory:
            path = Path(directory)/"policy.sqlite3"
            with store.OfflinePolicyEffectStore(str(path), labels, initial_profile=profile) as local:
                original = store.OriginalRequest("01"*32, 0, profile, "02"*32)
                local.allocate_synthetic(original)
                before = (local.local_view(), path.read_bytes())
                self.assertIs(response.verify_selected_response(self.expected, self.wire, verifier=self.check), self.expected)
                self.assertEqual((local.local_view(), path.read_bytes()), before)
                local.replace_local_policy(0, profile, active=False)
                before = (local.local_view(), path.read_bytes())
                for name in ("primary", "revoked", "absent", "unavailable", "new_challenge"):
                    selected = selection(name)
                    wire = response._canonical(self.vectors["positive_vectors"][name]["envelope"])
                    self.assertIs(response.verify_selected_response(selected, wire, verifier=self.check), selected)
                with self.assertRaises(store.StoreRefused): local.apply_synthetic_effect(original)
                self.assertEqual((local.local_view(), path.read_bytes()), before)
                self.assertEqual((local.local_view().charged_operations, local.local_view().synthetic_effects), (1,0))

    def test_actual_new_challenge_with_signed_old_active_state_is_not_a_current_read(self):
        old, new = self.expected.as_dict(), selection("new_challenge")
        self.assertNotEqual(old["query"]["challenge_hex"],new.as_dict()["query"]["challenge_hex"])
        self.assertEqual(old["query"]["expected_checkpoint"],new.as_dict()["query"]["expected_checkpoint"])
        self.assertEqual(old["claim"]["assignment_digest_hex"],new.as_dict()["claim"]["assignment_digest_hex"])
        self.assertEqual(new.as_dict()["claim"]["observation"],"active")
        self.assertIs(response.verify_selected_response(new,response._canonical(self.vectors["positive_vectors"]["new_challenge"]["envelope"]),verifier=self.check),new)

    def test_actual_entry_pin_and_bounded_canonical_wire_fail_quietly(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-response-entry-") as directory:
            entry = Path(directory)/"worker"; entry.write_bytes(self.entry.read_bytes()); entry.chmod(0o700)
            checked = PublicResponseCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
            with entry.open("ab") as stream: stream.write(b"\0")
            with patch("qualification.source_response_verifier.run_public_worker") as run:
                with self.assertRaises(response.SourceResponseError): checked(self.primary["request"])
                run.assert_not_called()
        wire = response._canonical(self.primary["request"])
        for invalid in (b"", b"\xff", b" "*16385, b"["*512+b"]"*512, wire+b"\n\n",
                wire.replace(b'"response":', b'"\\u0072esponse":'),
                wire.replace(b'"revision":0', b'"revision":0,"revision":0'),
                wire.replace(b'"revision":0', b'"revision":0e0'),
                response._canonical(self.primary["envelope"]["root_envelope"])):
            result = self.raw(invalid)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"", b""))
        result = self.raw(wire+b"\n")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, response._canonical(self.primary["result"])+b"\n", b""))


def main():
    parser = argparse.ArgumentParser(description="Offline public response mathematics; no source or admission")
    parser.add_argument("--response-verifier", required=True)
    args = parser.parse_args()
    try:
        entry = Path(args.response_verifier).resolve()
        RealSourceResponseTests.entry = entry
        RealSourceResponseTests.check = PublicResponseCheck(entry, expected_executable_sha256_hex=hashlib.sha256(entry.read_bytes()).hexdigest())
    except (OSError, ValueError, TypeError):
        parser.exit(1, "selected public response check unavailable\n")
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealSourceResponseTests))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
