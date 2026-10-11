"""New public two-party graph stays separate from application recovery authority."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from scripts import qualify_nom_bilateral_graph as graph
from scripts.generate_nom_bilateral_graph import INPUT, COMPLETIONS, FIXTURE, CASES, inputs, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMBilateralGraphTests(unittest.TestCase):
    def setUp(self):
        self.records = copy.deepcopy(FIX["records"])
        self.selected, self.completed, self.old = graph.selected_inputs(ROOT)

    def validate(self):
        return graph.validate_records(self.records, self.selected, self.completed, self.old)

    def step(self, label, case="complete"):
        return next(s for s in self.records[case]["trace"] if s["label"] == label)

    def stream(self):
        return b"\n".join(json.dumps({"Package": graph.PACKAGE, "Test": graph.TEST + "/" + name,
            "Action": "output", "Output": "    zz_research_nom_bilateral_graph_test.go:500: "
            + graph.PREFIX + json.dumps(self.records[name], sort_keys=True) + "\n"}).encode("ascii")
            for name in CASES) + b"\n"

    def test_complete_selected_subject_preserves_the_prior_account_context_profile(self):
        self.assertEqual(FIX, corpus(self.validate()))
        manifest, fixture, measured = graph.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"], graph.COUNTS)
        self.assertIn(graph.prior.MANIFEST, measured)
        self.assertEqual(len(graph.expected_tests()[graph.PACKAGE]), 5)

    def test_new_funding_ids_and_recipients_require_separate_inner_witnesses(self):
        self.assertEqual(self.selected, inputs())
        for leg in ("long", "short"):
            self.assertNotEqual(self.selected["terms"][leg]["entry_id_hex"], self.selected["old_funding_ids_hex"][leg])
            self.assertNotEqual(self.completed[leg + "_signature_hex"], self.old[leg + "_signature_hex"])
            b = self.step(leg + "-funding")["block"]["block"]
            self.assertEqual((b["height"], b["previous_hash_hex"]), ("1", "00" * 32))

    def test_user_accounts_continue_through_their_own_funding_unlock_and_receipt(self):
        for fund, unlock, receipt in (("long", "short", "short"), ("short", "long", "long")):
            a = self.step(fund + "-funding")["block"]
            b = self.step(unlock + "-unlock-send")["block"]
            c = self.step(receipt + "-receipt")["block"]
            self.assertEqual((a["block"]["height"], b["block"]["height"], c["block"]["height"]), ("1", "2", "3"))
            self.assertEqual(b["block"]["previous_hash_hex"], a["hash_hex"])
            self.assertEqual(c["block"]["previous_hash_hex"], b["hash_hex"])
            self.assertEqual(len({a["public_key_hex"], b["public_key_hex"], c["public_key_hex"]}), 1)

    def test_one_contract_frontier_contains_both_creates_and_both_payout_batches(self):
        seq = [self.step(name)["block"] for name in ("long-create", "short-create", "short-unlock-receive", "long-unlock-receive")]
        self.assertEqual([b["block"]["height"] for b in seq], ["1", "2", "4", "6"])
        for a, b in zip(seq, seq[1:]): self.assertEqual(b["semantic_previous"], graph.hh(a["hash_hex"], a["block"]["height"]))
        self.validate()

    def test_refused_inner_witnesses_or_caller_advance_distinct_originals_before_valid_claim(self):
        for kind in CASES[1:]:
            before = self.step("refused-short-receive", kind)
            after = self.step("short-unlock-receive", kind)
            self.assertEqual(before["block"]["children"], [])
            self.assertEqual(before["before_balances"], before["after_balances"])
            self.assertNotEqual(before["method_error"], "NONE")
            self.assertEqual(after["method_error"], "NONE")
            self.assertNotEqual(before["block"]["wire_hex"], after["block"]["wire_hex"])
        self.validate()

    def test_fixed_receiver_and_account_predecessor_refusals_are_separate(self):
        c = self.records["complete"]["controls"]
        self.assertEqual(set(c[0]["checks"].values()), {"ErrABPreviousMissing"})
        self.assertEqual(c[1]["checks"], {"structural": "ErrABFromBlockReceiverMismatch", "transaction": "PASS"})
        self.validate()

    def test_exact_replay_and_new_receipt_have_different_refusal_paths(self):
        c = self.records["complete"]["controls"]
        for old, new in ((c[2], c[3]), (c[4], c[5])):
            self.assertEqual(set(old["checks"].values()), {"ErrABPrevHasCementedOnTop"})
            self.assertEqual(new["checks"], {"structural": "ErrABFromBlockAlreadyReceived", "transaction": "PASS"})
            self.assertNotEqual(old["block"]["wire_hex"], new["block"]["wire_hex"])

    def test_each_token_is_conserved_with_fixed_bilateral_final_balances(self):
        for r in self.records.values():
            self.assertEqual(r["final_balances"], {"alice": {"long": "100", "short": "200"},
                "bob": {"long": "100", "short": "200"}, "contract": {"long": "0", "short": "0"}})
        self.validate()

    def test_mutated_cross_account_predecessor_refuses_projection(self):
        self.step("short-unlock-send")["before_frontier"] = self.step("long-unlock-send")["before_frontier"]
        with self.assertRaises(ValueError): self.validate()

    def test_mutated_fixed_payout_destination_refuses_projection(self):
        self.step("short-unlock-receive")["block"]["children"][0]["block"]["to_address_hex"] = self.selected["terms"]["bob_address_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_mutated_advertised_child_hash_refuses_projection(self):
        self.step("short-unlock-receive")["block"]["children"][0]["hash_hex"] = "aa" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_mutated_outer_wire_digest_refuses_projection(self):
        self.step("short-receipt")["block"]["wire_sha256"] = "00" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_mutated_actual_memory_patch_digest_refuses_projection(self):
        self.step("long-create")["after_vm_patch_sha256"] = "00" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_rehashed_memory_discontinuity_between_same_account_steps_refuses_projection(self):
        s = self.step("short-unlock-send"); s["before_patch_hex"] = "00"
        s["before_patch_sha256"] = hashlib.sha256(b"\0").hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_actual_mailbox_head_is_required_separately_from_parent_hash(self):
        self.step("short-create")["before_mailbox_head"] = self.step("long-create")["before_mailbox_head"]
        with self.assertRaises(ValueError): self.validate()

    def test_received_marker_cannot_be_claimed_before_vm_or_removed_after_vm(self):
        for field, value in (("before_received_marker", True), ("after_received_marker", False)):
            self.setUp(); self.step("short-receipt")[field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_bad_inner_witness_cannot_be_relabeled_as_success(self):
        self.step("refused-short-receive", "old-inner-before-valid")["method_error"] = "NONE"
        with self.assertRaises(ValueError): self.validate()

    def test_balance_credit_cannot_be_duplicated_in_a_successful_trace(self):
        self.step("short-receipt")["after_balances"]["alice"]["short"] = "400"
        with self.assertRaises(ValueError): self.validate()

    def test_incomplete_case_or_step_selection_refuses(self):
        self.records.pop("complete")
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.records["complete"]["trace"].pop()
        with self.assertRaises(ValueError): self.validate()

    def test_duplicate_native_record_or_json_field_refuses(self):
        wire = self.stream()
        for changed in (wire + wire.splitlines()[0] + b"\n",):
            with self.assertRaises(ValueError): graph.collect_records(changed, self.selected, self.completed, self.old)
        event = json.loads(wire.splitlines()[0]); event["Output"] = event["Output"].replace('"schema":', '"schema": "duplicate", "schema":', 1)
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)

    def test_truncated_or_wrong_test_native_record_refuses(self):
        wire = self.stream(); event = json.loads(wire.splitlines()[0])
        event["Output"] = event["Output"].rstrip("\n")
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)
        event = json.loads(wire.splitlines()[0]); event["Test"] = graph.TEST + "/wrong"
        with self.assertRaises(ValueError): graph.collect_records(json.dumps(event).encode() + b"\n", self.selected, self.completed, self.old)

    def test_no_graph_result_supplies_admission_signing_or_recovery_capability(self):
        self.assertEqual(FIX["boundary"]["recovery_action"], "NONE")
        for field in ("supervisor_and_plasma_admission", "account_pool_and_momentum_admission", "application_signing", "journal_composition"):
            self.assertEqual(FIX["boundary"][field], "NOT_PERFORMED")
        self.assertEqual((FIX["boundary"]["application"], FIX["boundary"]["core"]), ("NO-GO", "NO-GO"))

    def test_native_failure_keeps_original_evidence_and_has_no_fixture_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder); parent.chmod(0o700)
            with patch.object(graph.vm, "core_state"), patch.object(graph.prior, "qualify", return_value={}), patch.object(graph, "execute", side_effect=WorkerError("selected failure")):
                with self.assertRaises(WorkerError): graph.qualify(parent, ROOT / "qualification/Cargo.toml", evidence_parent=parent / "evidence")
            outcomes = list((parent / "evidence").glob("*/outcome.json"))
            self.assertEqual(len(outcomes), 1)
            r = json.loads(outcomes[0].read_text())
            self.assertEqual(r["outcome"], "FAILED_OR_INCOMPLETE")
            self.assertEqual(r["recovery_action"], "NONE")
            self.assertNotIn("tests_passed_including_parents", r)


class NoMBilateralSignatureIndependentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_nom_account_authorization import NoMAccountSignatureIndependentTests
        cls.backend = NoMAccountSignatureIndependentTests
        cls.backend.setUpClass()

    def test_all_new_outer_signatures_verify_independently_with_openssl(self):
        helper = self.backend(); seen = 0
        for r in FIX["records"].values():
            candidates = [s["block"] for s in r["trace"]] + [c["block"] for c in r["controls"]]
            for b in candidates:
                if b["public_key_hex"]:
                    self.assertEqual(helper.verify(b), (0, b"Signature Verified Successfully")); seen += 1
        self.assertEqual(seen, 51)

    def test_new_outer_signature_cannot_authorize_a_different_computed_message(self):
        helper = self.backend()
        for leg in ("long", "short"):
            b = next(s["block"] for s in FIX["records"]["complete"]["trace"] if s["label"] == leg + "-funding")
            changed = bytearray.fromhex(b["hash_hex"]); changed[0] ^= 1
            self.assertEqual(helper.verify(b, bytes(changed)), (1, b"Signature Verification Failure"))
