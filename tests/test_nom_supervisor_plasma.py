"""Supervisor comparison never upgrades a raw original or supplies recovery authority."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from scripts import qualify_nom_supervisor_plasma as graph
from scripts.generate_nom_supervisor_plasma import FIXTURE, CASES, inputs, corpus, CAPACITY

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMSupervisorPlasmaTests(unittest.TestCase):
    def setUp(self):
        self.records = copy.deepcopy(FIX["records"])
        self.selected, self.completed, self.old = graph.selected_inputs(ROOT)

    def validate(self):
        return graph.validate_records(self.records, self.selected, self.completed, self.old)

    def step(self, label, case="complete"):
        return next(s for s in self.records[case]["trace"] if s["label"] == label)

    def control(self, label, case="complete"):
        return next(s for s in self.records[case]["controls"] if s["id"] == label)

    def stream(self):
        return b"\n".join(json.dumps({"Package": graph.PACKAGE, "Test": graph.TEST + "/" + name,
            "Action": "output", "Output": "    zz_research_nom_supervisor_plasma_test.go:500: "
            + graph.PREFIX + json.dumps(self.records[name], sort_keys=True) + "\n"}).encode("ascii")
            for name in CASES) + b"\n"

    def test_complete_subject_preserves_all_prior_bilateral_inputs(self):
        self.assertEqual(FIX, corpus(self.validate()))
        manifest, fixture, measured = graph.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"], graph.COUNTS)
        self.assertIn(graph.prior.MANIFEST, measured)
        self.assertEqual(len(graph.expected_tests()[graph.PACKAGE]), 3)

    def test_plasma_selection_requires_new_ids_and_separate_inner_witnesses(self):
        self.assertEqual(self.selected, inputs())
        for leg in ("long", "short"):
            self.assertNotEqual(self.selected["fundings"][leg]["hash_hex"], self.selected["old_funding_ids_hex"][leg])
            self.assertNotEqual(self.completed[leg + "_signature_hex"], self.old[leg + "_signature_hex"])
            self.assertEqual(self.step(leg + "-funding")["block"]["block"]["fused_plasma"], "52500")

    def test_all_generated_originals_reproduce_without_an_apply_signature(self):
        for record in self.records.values():
            for s in record["trace"]:
                self.assertEqual(s["applied_wire_hex"], s["block"]["wire_hex"])
                self.assertEqual(s["applied_delta_hex"], s["delta_patch_hex"])
                self.assertEqual(s["apply_signatures"], 0)
        self.step("long-funding")["apply_signatures"] = 1
        with self.assertRaises(ValueError): self.validate()

    def test_changed_apply_wire_or_delta_refuses(self):
        for field in ("applied_wire_hex", "applied_delta_hex"):
            self.setUp(); self.step("short-receipt")[field] = "00"
            with self.assertRaises(ValueError): self.validate()

    def test_rehashed_delta_cannot_disagree_with_the_generated_patch_commitment(self):
        s = self.step("long-funding"); delta = bytearray.fromhex(s["delta_patch_hex"]); delta[-1] ^= 1
        s["delta_patch_hex"] = s["applied_delta_hex"] = delta.hex()
        s["delta_patch_sha256"] = hashlib.sha256(delta).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_independent_delta_replay_matches_every_actual_memory_commit(self):
        for r in self.records.values():
            for s in r["trace"]:
                before = graph.replay({}, graph.decode_patch(s["before_patch_hex"]))
                after = graph.replay(before, graph.decode_patch(s["delta_patch_hex"]))
                self.assertEqual(after, graph.replay({}, graph.decode_patch(s["after_commit_patch_hex"])))
        s = self.step("short-receipt"); s["after_commit_patch_hex"] = s["before_patch_hex"]
        s["after_commit_patch_sha256"] = s["before_patch_sha256"]
        with self.assertRaises(ValueError): self.validate()

    def test_frontier_adoption_cannot_hide_an_extra_write(self):
        s = self.step("short-receipt"); data = bytes.fromhex(s["after_adopt_patch_hex"]) + b"\x01\x01\x09\x01\x01"
        s["after_adopt_patch_hex"] = data.hex(); s["after_adopt_patch_sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_cumulative_state_cannot_be_presented_as_a_transaction_delta(self):
        s = self.step("short-receipt"); s["delta_patch_hex"] = s["after_commit_patch_hex"]
        s["applied_delta_hex"] = s["delta_patch_hex"]; s["delta_patch_sha256"] = hashlib.sha256(bytes.fromhex(s["delta_patch_hex"])).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_wrong_canonical_base_total_or_available_budget_refuses(self):
        for field in ("canonical_base", "base", "total", "before_used", "after_used", "available_before", "available_after", "fusion_amount", "committed"):
            self.setUp(); self.step("short-unlock-send")["plasma"][field] = "1"
            with self.assertRaises(ValueError): self.validate()

    def test_dynamic_plasma_is_a_separate_unselected_gate(self):
        self.step("long-funding")["plasma"]["dynamic"] = True
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.step("long-funding")["plasma"]["dynamic"] = 0
        with self.assertRaises(ValueError): self.validate()

    def test_refused_inner_original_consumes_its_own_selected_plasma_once(self):
        failed = self.step("refused-short-send", "old-inner-before-valid")
        valid = self.step("short-unlock-send", "old-inner-before-valid")
        self.assertEqual(int(failed["plasma"]["after_used"]) - int(failed["plasma"]["before_used"]), 73500)
        self.assertEqual(valid["block"]["block"]["previous_hash_hex"], failed["block"]["hash_hex"])
        self.assertNotEqual(valid["block"]["wire_hex"], failed["block"]["wire_hex"])
        self.assertEqual(valid["plasma"]["before_used"], failed["plasma"]["after_used"])
        self.assertEqual(self.step("short-receipt", "old-inner-before-valid")["plasma"]["available_after"], str(CAPACITY - 220500))

    def test_old_raw_original_cannot_be_silently_upgraded(self):
        c = self.control("raw-original-without-plasma")
        self.assertEqual(c["block"], self.old["raw_original_block"])
        self.assertEqual(c["returned_error"], "ErrNotEnoughTotalPlasma")
        c["block"] = copy.deepcopy(self.step("long-funding")["block"])
        c["original_wire_hex"] = c["block"]["wire_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_depleted_attempt_keeps_the_exact_later_accepted_original(self):
        c = self.control("depleted-fusion-original"); s = self.step("long-funding")
        self.assertEqual(c["block"], s["block"])
        self.assertEqual(c["returned_error"], "ErrNotEnoughPlasma")
        self.assertEqual(c["before_patch_hex"], c["after_patch_hex"])
        c["original_wire_hex"] = "00"
        with self.assertRaises(ValueError): self.validate()

    def test_refused_control_cannot_return_a_transaction_or_mutate_memory(self):
        for field, value in (("transaction_present", True), ("returned_delta_hex", "0101610162"), ("after_patch_hex", "00")):
            self.setUp(); self.control("bad-outer-signature")[field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_late_signature_failure_does_not_adopt_the_earlier_vm_writes(self):
        for name in ("unsigned-original", "bad-outer-signature", "insufficient-token-budget"):
            c = self.control(name)
            self.assertEqual(c["before_patch_hex"], self.step("long-funding")["before_patch_hex"])
            self.assertEqual(c["before_patch_hex"], c["after_patch_hex"])
            self.assertEqual(c["before_balances"], c["after_balances"])
        self.control("unsigned-original")["before_balances"]["alice"]["long"] = "1"
        with self.assertRaises(ValueError): self.validate()

    def test_unbound_user_changes_remain_a_scoped_pass_without_adoption(self):
        c = self.control("user-advertised-changes-unbound")
        self.assertTrue(c["transaction_present"])
        self.assertEqual(c["returned_error"], "PASS")
        self.assertNotEqual(c["returned_patch_hash_hex"], c["block"]["changes_hash_hex"])
        self.assertEqual(c["returned_delta_hex"], self.step("long-funding")["delta_patch_hex"])
        c["returned_patch_hash_hex"] = c["block"]["changes_hash_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_contract_changes_mismatch_cannot_be_reclassified_as_accepted(self):
        c = self.control("contract-advertised-changes-refuse")
        self.assertEqual(c["returned_error"], "ErrEmbeddedChangesHash")
        c["returned_error"] = "PASS"; c["transaction_present"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_continuous_account_frontiers_and_mailbox_cannot_be_replaced(self):
        for field, value in (("before_frontier", graph.hh()), ("before_mailbox_head", None)):
            self.setUp(); self.step("short-create")[field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_fixed_payout_receiver_and_token_conservation_remain_required(self):
        self.step("short-receipt")["after_balances"]["alice"]["short"] = "400"
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.control("short-wrong-receiver")["returned_error"] = "PASS"
        with self.assertRaises(ValueError): self.validate()

    def test_receipt_replay_is_distinct_from_a_new_signed_successor(self):
        original = self.step("short-receipt")["block"]
        self.assertEqual(self.control("short-exact-replay")["block"], original)
        c = self.control("short-new-receipt-same-payout")
        self.assertNotEqual(c["block"]["hash_hex"], original["hash_hex"])
        c["block"] = original; c["original_wire_hex"] = original["wire_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_incomplete_cases_steps_or_controls_refuse(self):
        for target in ("case", "trace", "controls"):
            self.setUp()
            if target == "case": self.records.pop("complete")
            else: self.records["complete"][target].pop()
            with self.assertRaises(ValueError): self.validate()

    def test_duplicate_native_record_or_json_field_refuses(self):
        wire = self.stream()
        with self.assertRaises(ValueError): graph.collect_records(wire + wire.splitlines()[0] + b"\n", self.selected, self.completed, self.old)
        event = json.loads(wire.splitlines()[0]); event["Output"] = event["Output"].replace('"schema":', '"schema": "duplicate", "schema":', 1)
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)

    def test_truncated_and_wrong_test_framing_refuse(self):
        event = json.loads(self.stream().splitlines()[0]); event["Output"] = event["Output"].rstrip("\n")
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)
        event = json.loads(self.stream().splitlines()[0]); event["Test"] = graph.TEST + "/other"
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)

    def test_native_failure_preserves_failed_evidence_without_fixture_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder); parent.chmod(0o700)
            with patch.object(graph.vm, "core_state"), patch.object(graph.prior, "qualify", return_value={}), patch.object(graph, "execute", side_effect=WorkerError("selected failure")):
                with self.assertRaises(WorkerError): graph.qualify(parent, ROOT / "qualification/Cargo.toml", evidence_parent=parent / "evidence")
            outcomes = list((parent / "evidence").glob("*/outcome.json"))
            self.assertEqual(len(outcomes), 1)
            result = json.loads(outcomes[0].read_text())
            self.assertEqual(result["outcome"], "FAILED_OR_INCOMPLETE")
            self.assertEqual(result["recovery_action"], "NONE")
            self.assertNotIn("tests_passed_including_parents", result)

    def test_supervisor_result_keeps_application_and_complete_admission_unfilled(self):
        self.assertEqual((FIX["boundary"]["application"], FIX["boundary"]["core"]), ("NO-GO", "NO-GO"))
        self.assertEqual(FIX["boundary"]["complete_admission"], "UNFILLED")
        self.assertEqual(FIX["boundary"]["account_pool_and_momentum_admission"], "NOT_PERFORMED")
        self.assertEqual(FIX["boundary"]["recovery_action"], "NONE")


class NoMSupervisorPatchTests(unittest.TestCase):
    def test_selected_put_delete_replay_is_independent_and_does_not_alias(self):
        state = {b"a": b"old", b"c": b"kept"}
        result = graph.replay(state, graph.decode_patch("0001610101620164"))
        self.assertEqual(result, {b"b": b"d", b"c": b"kept"})
        self.assertEqual(state[b"a"], b"old")

    def test_unknown_opcode_duplicate_key_and_empty_key_refuse(self):
        for value in ("020161", "01016101620101610163", "01000161"):
            with self.assertRaises(ValueError): graph.decode_patch(value)

    def test_truncated_overlong_or_nonminimal_lengths_refuse(self):
        for value in ("01", "0180", "0180808000", "018100610162", "010261", "0101610262"):
            with self.assertRaises(ValueError): graph.decode_patch(value)

    def test_selected_patch_record_and_byte_bounds_refuse(self):
        records = b"".join(b"\x01\x02" + i.to_bytes(2, "big") + b"\0" for i in range(257)).hex()
        for value in (records, "00" * 65537):
            with self.assertRaises(ValueError): graph.decode_patch(value)


class NoMSupervisorSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_nom_account_authorization import NoMAccountSignatureIndependentTests
        cls.backend = NoMAccountSignatureIndependentTests
        cls.backend.setUpClass()

    def test_all_31_selected_valid_outer_signatures_verify_with_openssl(self):
        helper = self.backend(); seen = 0
        for r in FIX["records"].values():
            candidates = [s["block"] for s in r["trace"]] + [c["block"] for c in r["controls"] if c["id"] not in ("unsigned-original", "bad-outer-signature")]
            for b in candidates:
                if b["public_key_hex"]:
                    self.assertEqual(helper.verify(b), (0, b"Signature Verified Successfully")); seen += 1
        self.assertEqual(seen, 31)

    def test_both_explicit_bad_outer_signatures_refuse_independently(self):
        helper = self.backend()
        for r in FIX["records"].values():
            b = next(c["block"] for c in r["controls"] if c["id"] == "bad-outer-signature")
            self.assertEqual(helper.verify(b), (1, b"Signature Verification Failure"))

    def test_retained_signature_cannot_authorize_a_changed_message(self):
        helper = self.backend()
        for leg in ("long", "short"):
            b = next(s["block"] for s in FIX["records"]["complete"]["trace"] if s["label"] == leg + "-funding")
            changed = bytearray.fromhex(b["hash_hex"]); changed[0] ^= 1
            self.assertEqual(helper.verify(b, bytes(changed)), (1, b"Signature Verification Failure"))
