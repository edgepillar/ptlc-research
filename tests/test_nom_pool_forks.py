"""Separate fork controls and pending caps never confer recovery authority."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import qualify_nom_pool_forks as forks
from scripts.generate_nom_pool_forks import BOUNDARY, CASES, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMPoolForkTests(unittest.TestCase):
    def setUp(self): self.records = copy.deepcopy(FIX["records"])
    def validate(self): return forks.validate_records(self.records)
    def cap(self): return self.records["actual-cap-500"]
    def candidate(self, name="block-501"): return self.cap()["candidates"][name]
    def stream(self):
        return b"\n".join(json.dumps({"Package": forks.PACKAGE, "Test": forks.TEST + "/" + name, "Action": "output",
            "Output": "    zz_research_nom_pool_forks_test.go:900: " + forks.PREFIX + json.dumps(self.records[name], sort_keys=True) + "\n"}).encode("ascii") for name in CASES) + b"\n"

    def test_complete_subject_preserves_old_swap_corpus_and_all_previous_source_pins(self):
        self.assertEqual(FIX, corpus(self.validate())); manifest, fixture, measured = forks.inputs(ROOT)
        self.assertEqual(fixture, FIX); self.assertEqual(manifest["preserved_file_sha256"], forks.prior.inputs(ROOT)[2])
        self.assertEqual(len(manifest["preserved_file_sha256"]), 85)
        self.assertIn(forks.prior.MANIFEST, measured); self.assertEqual(len(forks.expected_tests()[forks.PACKAGE]), 6)

    def test_actual_cap_cannot_be_lowered_to_make_a_small_fixture_pass(self):
        self.cap()["cap"] = 5
        with self.assertRaises(ValueError): self.validate()

    def test_fixed_first_work_nonce_and_exact_legacy_budget_are_independently_checked(self):
        first = self.candidate("block-1"); self.assertEqual(first["block"]["block"]["fused_plasma"], "0")
        self.assertEqual(self.candidate()["available_before"], "21000")
        first["block"]["block"]["nonce_hex"] = "00" * 8
        with self.assertRaises(ValueError): self.validate()

    def test_501st_control_must_pass_source_generation_and_apply_before_pool_refusal(self):
        self.candidate()["applied_wire_hex"] = ""
        with self.assertRaises(ValueError): self.validate()

    def test_cap_refusal_cannot_be_reported_as_normal_admission(self):
        self.cap()["trace"][500]["result"] = "PASS"
        with self.assertRaises(ValueError): self.validate()

    def test_cap_refusal_must_not_consume_the_original_transaction_delta(self):
        self.cap()["trace"][500]["changes_stolen"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_duplicate_at_cap_remains_idempotent_without_stealing_changes(self):
        self.cap()["trace"][501]["changes_stolen"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_valid_higher_priority_replacement_at_cap_does_not_lengthen_pending_chain(self):
        s = self.cap()["trace"][502]; self.assertEqual(s["result"], "PASS"); self.assertEqual(s["pending_count"], 500)
        s["pending_count"] = 501
        with self.assertRaises(ValueError): self.validate()

    def test_replacement_must_remove_the_exact_old_500_view_and_leave_new_one(self):
        self.cap()["views"][1]["present"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_replacement_duplicate_cannot_select_a_changed_wire_or_stale_delta(self):
        self.cap()["trace"][503]["retained_patch_hex"] = self.cap()["trace"][502]["retained_patch_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_higher_ratio_fork_removes_the_entire_old_suffix(self):
        r = self.records["ratio-higher"]; self.assertEqual(r["checkpoints"]["after-competitor"]["pending_count"], 2)
        r["views"][3]["present"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_lower_ratio_fork_refusal_preserves_the_entire_existing_suffix(self):
        r = self.records["ratio-lower"]; self.assertEqual(r["trace"][-1]["result"], "ErrPlasmaRatioIsWorse")
        r["trace"][-1]["changes_stolen"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_equal_ratio_converges_to_smallest_hash_in_both_selected_arrival_orders(self):
        for name in ("tie-smaller", "tie-larger"):
            r = self.records[name]; candidates = r["candidates"]
            smallest = min(candidates[n]["block"]["hash_hex"] for n in ("candidate-a", "candidate-b"))
            self.assertEqual([candidates[v["label"]]["block"]["hash_hex"] for v in r["views"] if v["label"] in ("candidate-a", "candidate-b") and v["present"]], [smallest])
        self.records["tie-larger"]["trace"][-1]["result"] = "PASS"
        with self.assertRaises(ValueError): self.validate()

    def test_a_fork_candidate_must_use_the_exact_retained_common_predecessor(self):
        self.records["ratio-higher"]["candidates"]["candidate-b"]["block"]["block"]["previous_hash_hex"] = "01" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_wire_plasma_fields_cannot_substitute_for_recomputed_canonical_cost(self):
        self.candidate()["canonical_base"] = "1"
        with self.assertRaises(ValueError): self.validate()

    def test_source_generated_candidate_cannot_exceed_its_actual_available_budget(self):
        self.candidate()["available_before"] = "21001"
        with self.assertRaises(ValueError): self.validate()

    def test_exact_vm_delta_is_compared_before_the_pool_augments_it(self):
        self.candidate()["delta_patch_hex"] = self.cap()["trace"][499]["retained_patch_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_independent_protobuf_encoding_rejects_rehashed_trailing_wire_alias(self):
        r = self.candidate()["block"]; r["wire_hex"] += "00"; r["roundtrip_wire_hex"] = r["wire_hex"]
        r["wire_sha256"] = hashlib.sha256(bytes.fromhex(r["wire_hex"])).hexdigest(); self.candidate()["applied_wire_hex"] = r["wire_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_wire_signature_bytes_must_match_the_exact_selected_source_wire(self):
        self.candidate()["block"]["signature_hex"] = "01" * 64
        with self.assertRaises(ValueError): self.validate()

    def test_generate_signs_once_and_exact_apply_signs_zero_times(self):
        self.candidate()["apply_signatures"] = 1
        with self.assertRaises(ValueError): self.validate()

    def test_boolean_aliases_cannot_replace_integer_signing_cap_or_pending_counts(self):
        for field in ("generation_signatures", "apply_signatures"):
            self.setUp(); self.candidate()[field] = bool(self.candidate()[field])
            with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.cap()["cap"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_complete_checkpoint_replay_cannot_hide_an_extra_logical_write(self):
        c = self.cap()["checkpoints"]["cap-refusal"]; s = forks.logical_state(c["state_dump_hex"]); s[b"\x09"] = b"\x01"
        c["state_dump_hex"] = forks.prior.encode_operations(sorted(s.items())).hex()
        with self.assertRaises(ValueError): self.validate()

    def test_pending_checkpoint_must_retain_all_500_exact_originals_in_height_order(self):
        rows = [self.cap()["candidates"]["block-" + str(i)]["block"] for i in range(500, 0, -1)]
        self.cap()["checkpoints"]["block-500"]["pending_wire_sha256"] = forks.pending_digest(rows)
        with self.assertRaises(ValueError): self.validate()

    def test_ordered_augmented_patch_cannot_drop_a_frontier_index(self):
        s = self.cap()["trace"][0]; ops = forks.prior.ordered_patch(s["retained_patch_hex"])
        s["retained_patch_hex"] = s["stored_patch_hex"] = forks.prior.encode_operations(ops[:-1]).hex()
        with self.assertRaises(ValueError): self.validate()

    def test_checkpoint_used_plasma_must_follow_the_exact_surviving_branch(self):
        self.records["ratio-higher"]["checkpoints"]["after-competitor"]["used_plasma"] = "84000"
        with self.assertRaises(ValueError): self.validate()

    def test_logical_reader_rejects_deletes_duplicate_keys_unsorted_keys_and_noncanonical_lengths(self):
        for value in ("000105", "0101050001010500", "0101050001010300", "0181000500", "010105"):
            with self.assertRaises(ValueError): forks.logical_state(value)

    def test_selected_views_are_exact_historical_versions_without_currentness_authority(self):
        self.cap()["views"][0]["frontier"] = self.cap()["views"][-1]["frontier"]
        with self.assertRaises(ValueError): self.validate()
        self.assertEqual(BOUNDARY["recovery_action"], "NONE"); self.assertEqual(BOUNDARY["application"], "NO-GO")

    def test_stable_roots_and_selected_legacy_pricing_remain_explicit(self):
        for field, value in (("final_stable_state", "01010500"), ("dynamic_plasma", True)):
            self.setUp(); self.cap()[field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_missing_extra_and_unknown_record_fields_never_supply_a_complete_corpus(self):
        del self.records["ratio-lower"]
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.cap()["current_recovery_permission"] = "ALLOW"
        with self.assertRaises(ValueError): self.validate()

    def test_native_framing_rejects_duplicate_missing_truncated_or_wrong_package_records(self):
        stream = self.stream(); self.assertEqual(forks.collect_records(stream), self.records)
        for wire in (stream + stream, b"\n".join(stream.splitlines()[:-1]), stream[:-2], stream.replace(forks.PACKAGE.encode(), b"unselected-package")):
            with self.assertRaises(ValueError): forks.collect_records(wire)

    def test_native_fragment_reassembly_retains_complete_original_record_bytes(self):
        events = [json.loads(line) for line in self.stream().splitlines()]; large = events[-1]; output = large["Output"]
        events[-1] = {**large, "Output": output[:1000]}; events.append({**large, "Output": output[1000:]})
        self.assertEqual(forks.collect_records(b"\n".join(json.dumps(e).encode("ascii") for e in events)), self.records)

    def test_failed_skipped_or_missing_native_tests_never_supply_success(self):
        names = sorted(forks.expected_tests()[forks.PACKAGE])
        for action in ("fail", "skip"):
            rows = [{"Package": forks.PACKAGE, "Test": n, "Action": action if i == 1 else "pass"} for i, n in enumerate(names)]
            rows.append({"Package": forks.PACKAGE, "Action": "pass"})
            with self.assertRaises(ValueError): forks.prior.prior.vm.selected_outcome(b"\n".join(json.dumps(e).encode("ascii") for e in rows), forks.expected_tests())


if __name__ == "__main__": unittest.main()
