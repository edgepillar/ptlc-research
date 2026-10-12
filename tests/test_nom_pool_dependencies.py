"""Adversarial controls for explicitly reconstituted pool dependencies."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import qualify_nom_pool_dependencies as dependencies
from scripts.generate_nom_pool_dependencies import BOUNDARY, CASES, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMPoolDependencyTests(unittest.TestCase):
    def setUp(self): self.records = copy.deepcopy(FIX["records"])
    def case(self, n="included-send"): return self.records[n]
    def refused(self):
        with self.assertRaises(ValueError): dependencies.validate_records(self.records)
    def stream(self):
        return b"\n".join(json.dumps({"Action": "output", "Package": dependencies.PACKAGE, "Test": dependencies.TEST + "/" + n,
            "Output": "    zz_research_nom_pool_dependencies_test.go:900: " + dependencies.PREFIX + json.dumps(self.records[n], sort_keys=True) + "\n"}).encode("ascii") for n in CASES) + b"\n"

    def test_complete_dependency_subject_preserves_every_old_swap_and_source_profile(self):
        manifest, fixture, measured = dependencies.inputs(ROOT)
        self.assertEqual(fixture, corpus(dependencies.validate_records(self.records)))
        self.assertEqual(len(manifest["preserved_file_sha256"]), 91)
        self.assertIn(dependencies.prior.MANIFEST, measured)
        self.assertEqual(len(dependencies.expected_tests()[dependencies.PACKAGE]), 4)

    def test_nonempty_send_callback_removes_the_whole_recipient_chain_including_its_prefix(self):
        self.case()["checkpoints"]["after-callback"]["recipient"] = copy.deepcopy(self.case("empty-inclusion-control")["checkpoints"]["after-callback"]["recipient"])
        self.refused()

    def test_dependent_manager_is_removed_even_without_a_receive_suffix(self):
        r = self.case("included-send-without-suffix")
        r["views"][2]["present"] = True
        self.refused()

    def test_incomplete_empty_callback_is_explicitly_a_negative_control(self):
        self.case("empty-inclusion-control")["rollback"]["included_wires"] = self.case()["rollback"]["included_wires"]
        self.refused()

    def test_empty_callback_cannot_be_reported_as_complete_dependent_prefix_eviction(self):
        self.case("empty-inclusion-control")["checkpoints"]["after-callback"]["recipient"] = copy.deepcopy(self.case()["checkpoints"]["after-callback"]["recipient"])
        self.refused()

    def test_sender_pending_manager_is_removed_after_its_stable_send_rolls_back(self):
        c = self.case()["checkpoints"]
        c["after-callback"]["sender"] = copy.deepcopy(c["before-rollback"]["sender"])
        self.refused()

    def test_unrelated_account_retains_two_exact_originals_in_height_order(self):
        self.case()["checkpoints"]["after-callback"]["unrelated"]["pending_wires"].reverse()
        self.refused()

    def test_unrelated_stale_third_block_cannot_survive_height_truncation(self):
        c = self.case()["checkpoints"]
        c["after-callback"]["unrelated"] = copy.deepcopy(c["before-rollback"]["unrelated"])
        self.refused()

    def test_stable_promotion_uses_the_exact_source_augmented_send_patch(self):
        self.case()["promotion_patch_hex"] = self.case()["candidates"]["stable-send"]["delta_patch_hex"]
        self.refused()

    def test_promoted_send_is_removed_from_pending_without_replacement(self):
        c = self.case()["checkpoints"]
        c["after-promotion"]["sender"]["pending_wires"] = c["before-promotion"]["sender"]["pending_wires"]
        self.refused()

    def test_receive_requires_the_exact_selected_global_send_lookup(self):
        self.case()["checkpoints"]["after-promotion"]["ledger"]["send_wire_hex"] = ""
        self.refused()

    def test_confirmation_is_bound_to_the_selected_promoted_momentum(self):
        self.case()["checkpoints"]["after-promotion"]["ledger"]["confirmation_height"] = "10109300"
        self.refused()

    def test_actual_mailbox_pending_entries_are_completely_reconstituted(self):
        self.case()["checkpoints"]["after-promotion"]["ledger"]["mailbox_dump_hex"] += "01010100"
        self.refused()

    def test_mailbox_pending_hashes_cannot_be_replaced_by_a_different_send(self):
        self.case()["checkpoints"]["before-rollback"]["ledger"]["mailbox_pending_hashes"] = ["00" * 32]
        self.refused()

    def test_plain_user_mailbox_must_not_acquire_an_embedded_sequencer(self):
        self.case()["checkpoints"]["before-rollback"]["ledger"]["mailbox_sequencer_size"] = "1"
        self.refused()

    def test_rollback_clears_stable_roots_lookup_confirmation_and_mailbox_before_callback(self):
        checks = self.case()["checkpoints"]
        for field in ("send_wire_hex", "confirmation_height", "mailbox_dump_hex", "mailbox_pending_hashes", "known_send_count", "known_confirmation_count"):
            with self.subTest(field=field):
                before = copy.deepcopy(checks["reconstituted-before-callback"])
                checks["reconstituted-before-callback"]["ledger"][field] = checks["before-rollback"]["ledger"][field]
                self.refused(); checks["reconstituted-before-callback"] = before

    def test_no_intermediate_pool_read_is_claimed_between_reconstitution_and_callback(self):
        self.case()["checkpoints"]["reconstituted-before-callback"]["sender"]["pending_wires"] = []
        self.refused()

    def test_source_legacy_fusion_and_pricing_selection_remain_explicit(self):
        self.case()["fusion_amount"] = "500000000000"
        self.refused()

    def test_each_candidate_uses_its_exact_available_legacy_budget(self):
        self.case()["candidates"]["dependent-receive"]["available_before"] = "420000"
        self.refused()

    def test_receive_cost_is_recomputed_independently_of_wire_cost_fields(self):
        self.case()["candidates"]["dependent-receive"]["canonical_base"] = "0"
        self.refused()

    def test_receive_delta_contains_the_exact_received_marker_and_zero_balance(self):
        c = self.case()["candidates"]["dependent-receive"]
        c["delta_patch_hex"] = c["applied_delta_hex"] = self.case()["candidates"]["recipient-prefix"]["delta_patch_hex"]
        self.refused()

    def test_exact_apply_cannot_select_a_different_original_wire_or_delta(self):
        self.case()["candidates"]["dependent-receive"]["applied_wire_hex"] = self.case()["candidates"]["recipient-prefix"]["block"]["wire_hex"]
        self.refused()

    def test_independent_protobuf_encoder_rejects_a_rehashed_trailing_wire_alias(self):
        r = self.case()["candidates"]["dependent-receive"]["block"]
        r["wire_hex"] += "f80100"; r["roundtrip_wire_hex"] = r["wire_hex"]; r["wire_sha256"] = hashlib.sha256(bytes.fromhex(r["wire_hex"])).hexdigest()
        self.refused()

    def test_generate_signs_once_and_exact_apply_signs_zero_times(self):
        self.case()["candidates"]["dependent-receive"]["apply_signatures"] = 1
        self.refused()

    def test_boolean_aliases_cannot_replace_counts_signing_or_view_presence(self):
        for change in (lambda r: r.update(signing_calls=True), lambda r: r["candidates"]["dependent-receive"].update(generation_signatures=True), lambda r: r["views"][0].update(present=0)):
            with self.subTest(change=change):
                self.records = copy.deepcopy(FIX["records"]); change(self.case()); self.refused()

    def test_normal_admission_must_steal_the_exact_transaction_changes(self):
        self.case()["trace"][0]["changes_stolen"] = False
        self.refused()

    def test_rebuilt_survivor_patch_retains_both_ordered_frontier_augmentations(self):
        self.case()["views"][5]["patch_hex"] = self.case()["trace"][1]["retained_patch_hex"]
        self.refused()

    def test_removed_originals_never_gain_historical_view_or_recovery_authority(self):
        self.case()["views"][3]["patch_present"] = True
        self.refused()

    def test_callbacks_and_readback_cannot_be_reclassified_as_replay_or_recovery(self):
        self.case()["post_callback_action"] = "RECOVER"
        self.refused()
        self.assertEqual(BOUNDARY["application"], "NO-GO"); self.assertEqual(BOUNDARY["core"], "NO-GO")

    def test_missing_extra_and_unknown_fields_cannot_supply_a_complete_subject(self):
        del self.case()["candidates"]["recipient-prefix"]
        self.refused()
        self.records = copy.deepcopy(FIX["records"]); self.case()["extra"] = False; self.refused()

    def test_native_framing_requires_complete_original_fragments_and_exact_package(self):
        stream = self.stream(); self.assertEqual(dependencies.collect_records(stream), self.records)
        with self.assertRaises(ValueError): dependencies.collect_records(stream + stream)
        rows = [json.loads(n) for n in stream.splitlines()]; source = rows[0]; out = source["Output"]; at = len(out)//2
        source["Output"] = out[:at]; tail = {**source, "Output": out[at:]}
        split = b"\n".join(json.dumps(n).encode("ascii") for n in [source, tail, *rows[1:]])
        self.assertEqual(dependencies.collect_records(split), self.records)
        tail["Package"] = "unselected/package"
        with self.assertRaises(ValueError): dependencies.collect_records(b"\n".join(json.dumps(n).encode("ascii") for n in [source, tail, *rows[1:]]))
        with self.assertRaises(ValueError): dependencies.collect_records(json.dumps(source).encode("ascii"))

    def test_failed_skipped_or_missing_native_tests_never_supply_success(self):
        names = sorted(dependencies.expected_tests()[dependencies.PACKAGE])
        for action in ("fail", "skip", None):
            rows = [{"Action": "pass", "Package": dependencies.PACKAGE, "Test": n} for n in names[1:]]
            if action: rows.append({"Action": action, "Package": dependencies.PACKAGE, "Test": names[0]})
            with self.assertRaises(ValueError): dependencies.SUPERVISOR.vm.selected_outcome(b"\n".join(json.dumps(n).encode("ascii") for n in rows), dependencies.expected_tests())


if __name__ == "__main__": unittest.main()
