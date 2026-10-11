"""Pending admission, byte custody and historical views confer no recovery authority."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts import qualify_nom_account_pool as pool
from scripts.generate_nom_account_pool import BOUNDARY, CASES, FIXTURE, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMAccountPoolTests(unittest.TestCase):
    def setUp(self):
        self.records = copy.deepcopy(FIX["records"])
        self.originals = pool.prior.inputs(ROOT)[1]

    def validate(self):
        return pool.validate_records(self.records, self.originals)

    def step(self, label, case="complete"):
        return next(s for s in self.records[case]["trace"] if s["label"] == label)

    def view(self, label, child=False):
        original = next(s["block"] for s in self.originals["records"]["complete"]["trace"] if s["label"] == label)
        if child: original = original["children"][0]
        return next(v for v in self.records["complete"]["post_rollback_views"] if v["requested_identifier"]["hash_hex"] == original["hash_hex"])

    def stream(self):
        return b"\n".join(json.dumps({"Package": pool.PACKAGE, "Test": pool.TEST + "/" + name,
            "Action": "output", "Output": "    zz_research_nom_account_pool_test.go:500: "
            + pool.PREFIX + json.dumps(self.records[name], sort_keys=True) + "\n"}).encode("ascii")
            for name in CASES) + b"\n"

    def test_complete_subject_retains_all_selected_supervisor_inputs(self):
        self.assertEqual(FIX, corpus(self.validate()))
        manifest, fixture, measured = pool.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"], pool.COUNTS)
        self.assertEqual(manifest["preserved_file_sha256"], pool.prior.inputs(ROOT)[2])
        self.assertIn(pool.prior.MANIFEST, measured)
        self.assertEqual(len(pool.expected_tests()[pool.PACKAGE]), 3)

    def test_every_admission_preserves_original_bytes_and_source_delta_without_signing(self):
        for name in CASES:
            for s, old in zip(self.records[name]["trace"], self.originals["records"][name]["trace"]):
                self.assertEqual(s["original_wire_hex"], old["block"]["wire_hex"])
                self.assertEqual(s["applied_wire_hex"], old["block"]["wire_hex"])
                self.assertEqual(s["delta_patch_hex"], old["delta_patch_hex"])
            self.assertEqual(self.records[name]["signing_calls"], 0)
        self.records["complete"]["signing_calls"] = 1
        with self.assertRaises(ValueError): self.validate()

    def test_rehashed_replacement_wire_cannot_upgrade_an_original(self):
        s = self.step("long-funding"); wire = bytes.fromhex(s["original_wire_hex"]) + b"\x00"
        s["original_wire_hex"] = s["applied_wire_hex"] = wire.hex(); s["original_wire_sha256"] = hashlib.sha256(wire).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_changed_apply_delta_or_source_plasma_refuses(self):
        for field in ("delta_patch_hex", "base_plasma", "total_plasma"):
            self.setUp(); self.step("short-receipt")[field] = "0"
            with self.assertRaises(ValueError): self.validate()

    def test_actual_pool_consumes_only_the_normal_admission_delta(self):
        self.step("long-funding")["transaction_changes_stolen"] = False
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.step("long-funding")["duplicate"]["changes_stolen"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_augmented_batch_retains_both_child_and_parent_frontier_writes_in_order(self):
        s = self.step("short-unlock-receive"); ops = pool.ordered_patch(s["stored_pool_patch_hex"])
        self.assertEqual(sum(k == b"\0" for k, _ in ops), 2)
        ops[-6:] = ops[-3:] + ops[-6:-3]
        s["stored_pool_patch_hex"] = s["retained_augmented_patch_hex"] = pool.encode_operations(ops).hex()
        with self.assertRaises(ValueError): self.validate()

    def test_cumulative_state_cannot_replace_an_actual_transaction_delta(self):
        self.step("short-receipt")["delta_patch_hex"] = self.step("short-receipt")["after_state_dump_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_actual_readback_cannot_hide_an_extra_logical_write(self):
        s = self.step("short-receipt"); ops = pool.prior.decode_patch(s["after_state_dump_hex"]); ops.append((b"\x09", b"\x01"))
        s["after_state_dump_hex"] = pool.encode_operations(ops).hex()
        with self.assertRaises(ValueError): self.validate()

    def test_missing_child_hash_index_refuses_even_when_parent_frontier_matches(self):
        s = self.step("short-unlock-receive"); ops = pool.prior.decode_patch(s["after_state_dump_hex"])
        child = self.originals["records"]["complete"]["trace"][5]["block"]["children"][0]
        key = b"\1" + bytes.fromhex(child["hash_hex"])
        self.assertIn(key, dict(ops))
        s["after_state_dump_hex"] = pool.encode_operations([(k, v) for k, v in ops if k != key]).hex()
        with self.assertRaises(ValueError): self.validate()

    def test_duplicate_pass_cannot_hide_a_side_effect(self):
        self.step("short-receipt")["duplicate"]["state_sha256_after"] = "00" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_identifier_duplicate_preserves_the_previously_stored_wire(self):
        changed = self.step("long-funding")["changed_wire_duplicate"]
        self.assertNotEqual(changed["wire_hex"], changed["stored_wire_hex"])
        changed["stored_wire_hex"] = changed["wire_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_changed_wire_observation_cannot_replace_hash_or_outer_signature(self):
        for field, value in (("hash_hex", "00" * 32), ("signature_hex", "00" * 64)):
            self.setUp(); self.step("long-funding")["changed_wire_duplicate"][field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_duplicate_observation_requires_exact_selected_header_change(self):
        changed = self.step("long-funding")["changed_wire_duplicate"]
        changed["wire_hex"] = changed["stored_wire_hex"]
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.step("short-create")["changed_wire_duplicate"] = self.step("long-funding")["changed_wire_duplicate"]
        with self.assertRaises(ValueError): self.validate()

    def test_missing_locker_refusal_cannot_be_omitted_or_converted_to_consumption(self):
        self.step("long-funding")["nil_locker"] = None
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.step("long-funding")["nil_locker"]["changes_stolen"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_stable_input_must_remain_unchanged(self):
        self.records["complete"]["final_stable_state"]["alice"] = ""
        with self.assertRaises(ValueError): self.validate()

    def test_selected_callback_cannot_claim_authentication_or_a_different_cutoff(self):
        for field, value in (("authenticated", True), ("popped_height", "10109302"), ("included_account_blocks", 1)):
            self.setUp(); self.records["complete"]["rollback_callback"][field] = value
            with self.assertRaises(ValueError): self.validate()

    def test_stale_originals_cannot_remain_pending_after_suffix_truncation(self):
        self.records["complete"]["remaining_pending_wires"]["alice"].append(self.step("short-receipt")["original_wire_hex"])
        with self.assertRaises(ValueError): self.validate()

    def test_rollback_readback_must_restore_the_selected_pre_unlock_balances(self):
        self.records["complete"]["after_rollback"]["contract"] = self.records["complete"]["before_rollback"]["contract"]
        with self.assertRaises(ValueError): self.validate()

    def test_removed_parent_view_cannot_be_invented(self):
        v = self.view("short-unlock-receive"); self.assertIs(v["present"], False)
        v["present"] = True
        with self.assertRaises(ValueError): self.validate()

    def test_stale_child_alias_requires_parent_frontier_and_is_not_an_exact_child_snapshot(self):
        v = self.view("short-unlock-receive", child=True)
        self.assertIs(v["present"], True); self.assertIs(v["patch_present"], True); self.assertEqual(v["patch_hex"], "")
        self.assertNotEqual(v["requested_identifier"], v["frontier"]["identifier"])
        v["frontier"]["identifier"] = v["requested_identifier"]
        with self.assertRaises(ValueError): self.validate()

    def test_stale_child_alias_cannot_be_promoted_to_current_restored_state(self):
        self.view("long-unlock-receive", child=True)["state_dump_hex"] = self.records["complete"]["after_rollback"]["contract"]
        with self.assertRaises(ValueError): self.validate()

    def test_child_alias_before_rollback_is_also_the_complete_parent_view(self):
        s = self.step("short-unlock-receive"); v = s["child_views"][0]
        self.assertEqual(v["frontier"], s["frontier_after"])
        v["patch_hex"] = s["stored_pool_patch_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_missing_or_extra_post_rollback_queries_refuse(self):
        self.records["complete"]["post_rollback_views"].pop()
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.records["complete"]["post_rollback_views"].append(copy.deepcopy(self.view("short-receipt")))
        with self.assertRaises(ValueError): self.validate()

    def test_unknown_fields_or_case_cannot_invent_recovery_permission(self):
        self.records["complete"]["recover"] = True
        with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.records["unselected"] = self.records.pop("complete")
        with self.assertRaises(ValueError): self.validate()
        self.assertEqual(BOUNDARY["recovery_action"], "NONE")
        self.assertEqual((BOUNDARY["application"], BOUNDARY["core"]), ("NO-GO", "NO-GO"))

    def test_boolean_flags_do_not_accept_numeric_standins(self):
        for place, field, value in (("duplicate", "changes_stolen", 0), ("nil_locker", "state_unchanged", 1)):
            self.setUp(); self.step("long-funding")[place][field] = value
            with self.assertRaises(ValueError): self.validate()
        self.setUp(); self.records["complete"]["rollback_callback"]["included_account_blocks"] = False
        with self.assertRaises(ValueError): self.validate()

    def test_selected_ordered_reader_does_not_weaken_the_preserved_unique_delta_reader(self):
        value = pool.encode_operations([(b"\0", b"a"), (b"\0", b"b")]).hex()
        self.assertEqual(pool.prior.replay({}, pool.ordered_patch(value)), {b"\0": b"b"})
        with self.assertRaises(ValueError): pool.prior.decode_patch(value)

    def test_truncated_noncanonical_empty_key_and_oversized_ordered_records_refuse(self):
        for value in ("01", "0101", "010161", "01000100", "0181006100", "0180808000", "020161", "ff", "00" * 65537):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError): pool.ordered_patch(value)

    def test_complete_native_framing_and_split_record_are_accepted(self):
        wire = self.stream(); self.assertEqual(pool.collect_records(wire, self.originals), self.records)
        events = [json.loads(line) for line in wire.splitlines()]; split = len(events[0]["Output"]) // 2
        rest = dict(events[0], Output=events[0]["Output"][split:]); events[0]["Output"] = events[0]["Output"][:split]
        fragmented = b"\n".join(json.dumps(e).encode("ascii") for e in [events[0], rest, events[1]]) + b"\n"
        self.assertEqual(pool.collect_records(fragmented, self.originals), self.records)

    def test_missing_duplicate_wrong_package_and_truncated_native_records_refuse(self):
        lines = self.stream().splitlines(); wrong = json.loads(lines[0]); wrong["Package"] = "unselected"
        truncated = json.loads(lines[0]); truncated["Output"] = truncated["Output"][:-1]
        for wire in (lines[0] + b"\n", b"\n".join(lines + [lines[0]]), json.dumps(wrong).encode(), json.dumps(truncated).encode()):
            with self.assertRaises(ValueError): pool.collect_records(wire, self.originals)

    def test_resealed_manifest_cannot_drop_a_preserved_input(self):
        _, _, measured = pool.inputs(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in measured:
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes((ROOT / name).read_bytes())
            manifest = json.loads((root / pool.MANIFEST).read_text("ascii")); manifest["preserved_file_sha256"].pop(pool.prior.MANIFEST)
            (root / pool.MANIFEST).write_text(json.dumps(manifest), encoding="ascii")
            with self.assertRaises(ValueError): pool.inputs(root)

    def test_manifest_requires_every_selected_pool_manager_and_caller_source_file(self):
        manifest, _, _ = pool.inputs(ROOT)
        self.assertTrue(pool.CORE_FILES <= set(manifest["core_file_sha256"]))
        self.assertEqual(len(manifest["core_file_sha256"]), 65)
        self.assertEqual(pool.COUNTS["total_source_tests_including_parents"], 281)

    def test_failed_or_skipped_selected_source_execution_never_supplies_success(self):
        expected = pool.expected_tests(); names = sorted(expected[pool.PACKAGE])
        for action in ("fail", "skip"):
            events = [{"Package": pool.PACKAGE, "Test": n, "Action": action if i == 1 else "pass"}
                      for i, n in enumerate(names)]
            events.append({"Package": pool.PACKAGE, "Action": "pass"})
            wire = b"\n".join(json.dumps(e).encode("ascii") for e in events)
            with self.assertRaises(ValueError): pool.prior.vm.selected_outcome(wire, expected)


if __name__ == "__main__":
    unittest.main()
