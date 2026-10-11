"""Evidence framing and graph controls; no native or cryptographic qualification.

Synthetic parser inputs below are not Go-emitted state patches or admitted
blocks. Positive source execution is mandatory in the separate offline job.
"""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.nom_wire import account_block_hash
from offline_session.pr138 import CONTRACT_HEX
from scripts.generate_nom_vm_path import ROOT, BASE, corpus
from scripts.qualify_nom_vm_path import (
    FIXTURE, FUNDING, MANIFEST, SELECTED, PREFIX, VM_TEST, VERIFIER_TEST,
    inputs, expected_tests, selected_outcome, expected_result,
    validate_record, collect_vm_records, unique_object,
)


class NoMVMPathTests(unittest.TestCase):
    def setUp(self):
        self.fixture = corpus()
        self.funding = json.loads((ROOT / FUNDING).read_text("ascii"))
        self.vector = self.fixture["vm_vectors"][0]
        self.package = "github.com/zenon-network/go-zenon/vm"
        self.names = expected_tests(self.fixture)

    def wire(self, events):
        return b"\n".join(json.dumps(e).encode("ascii") for e in events) + b"\n"

    def passes(self, names):
        events = []
        for package, tests in names.items():
            events.extend({"Package": package, "Action": "pass", "Test": t} for t in sorted(tests))
            events.append({"Package": package, "Action": "pass"})
        return events

    def parser_record(self):
        """Build a hash-consistent toy graph solely to attack parser boundaries."""
        selected = self.funding["fundings"]["long"]
        def block(**values):
            fields = dict(version="1", chain_id=selected["block"]["chain_id"], block_type="2",
                          previous_hash_hex="00"*32, height="1", momentum_hash_hex="00"*32,
                          momentum_height="0", address_hex=CONTRACT_HEX, to_address_hex="00"*20,
                          amount="0", token_standard_hex="00"*10, from_block_hash_hex="00"*32,
                          descendant_hashes_hex=[], data_hex="", fused_plasma="0", difficulty="0", nonce_hex="00"*8)
            fields.update(values)
            return dict(hash_hex=account_block_hash(fields), changes_hash_hex="00"*32, block=fields)
        original = dict(hash_hex=selected["hash_hex"], changes_hash_hex="00"*32, block=copy.deepcopy(selected["block"]))
        create = block(block_type="5", from_block_hash_hex=original["hash_hex"], data_hex="0000000000000001")
        send = block(address_hex=selected["entry"]["destination_hex"], to_address_hex=CONTRACT_HEX)
        payout = block(block_type="4", previous_hash_hex=create["hash_hex"], height="2",
                       to_address_hex=selected["entry"]["destination_hex"], amount=selected["entry"]["amount"],
                       token_standard_hex=selected["entry"]["token_standard_hex"])
        parent = block(block_type="5", previous_hash_hex=payout["hash_hex"], height="3",
                       from_block_hash_hex=send["hash_hex"], descendant_hashes_hex=[payout["hash_hex"]], data_hex="0000000000000001")
        receipt = block(block_type="3", address_hex=selected["entry"]["destination_hex"], from_block_hash_hex=payout["hash_hex"])
        events, balances, present = expected_result("direct-success", int(selected["entry"]["amount"]))
        return dict(schema="zenon-nom-vm-path-record-v1", **self.vector, funding_id_hex=selected["hash_hex"],
                    amount=selected["entry"]["amount"], entry_present=present, events=events, balances=balances,
                    blocks={"funding": original, "create-send": copy.deepcopy(original), "create-receive": create,
                            "unlock-send": send, "unlock-payout-0": payout, "unlock-receive": parent, "recipient-receive": receipt},
                    receipt_patches={"before_hex": "00000000", "after_hex": "00000001"})

    def rehash(self, record, role):
        item = record["blocks"][role]
        item["hash_hex"] = account_block_hash(item["block"])

    def fragments(self, *, width=1024):
        """Isolate stream framing; graph validation is tested separately."""
        events = []
        for vector in self.fixture["vm_vectors"]:
            payload = json.dumps(dict(vector, padding="x"*2048)) + "\n"
            parts = [payload[i:i+width] for i in range(0, len(payload), width)]
            for i, part in enumerate(parts):
                events.append(dict(Package=self.package, Action="output", Test=VM_TEST+"/"+vector["id"],
                                   Output=("    zz_research_nom_vm_path_test.go:1: " + PREFIX if i == 0 else "") + part))
        return events

    def collect_framing(self, events):
        with patch("scripts.qualify_nom_vm_path.validate_record", side_effect=lambda r, v, f: r):
            return collect_vm_records(self.wire(events), self.fixture, self.funding)

    def test_exact_reproduction_pins_new_and_preserved_inputs(self):
        manifest, fixture, measured = inputs(ROOT)
        self.assertEqual(fixture, self.fixture)
        self.assertEqual(manifest["research_baseline_commit"], BASE)
        self.assertEqual(set(manifest["input_sha256"]), set(SELECTED))
        self.assertTrue(set(SELECTED) <= measured.keys())

    def test_changed_input_is_refused_before_native_execution(self):
        manifest = json.loads((ROOT / MANIFEST).read_text("ascii"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, *manifest["input_sha256"], *manifest["preserved_file_sha256"]):
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            (root / FIXTURE).write_text(json.dumps(dict(self.fixture, profile="unselected")), encoding="ascii")
            with patch("scripts.qualify_nom_vm_path.run") as native:
                with self.assertRaises(ValueError): inputs(root)
                native.assert_not_called()

    def test_subset_duplicate_or_changed_boundary_cannot_shrink_subject(self):
        for key in ("vm_vectors", "verifier_vectors"):
            changed = copy.deepcopy(self.fixture); changed[key].pop()
            with self.assertRaises(ValueError): expected_tests(changed)
            changed = copy.deepcopy(self.fixture); changed[key][-1] = changed[key][0]
            with self.assertRaises(ValueError): expected_tests(changed)
        changed = copy.deepcopy(self.fixture); changed["boundary"]["application"] = "GO"
        with self.assertRaises(ValueError): expected_tests(changed)

    def test_exact_vm_and_verifier_results_require_all_fifty_eight_tests(self):
        self.assertEqual(len(self.names[self.package]), 33)
        self.assertEqual(len(self.names["github.com/zenon-network/go-zenon/verifier"]), 25)
        self.assertEqual(selected_outcome(self.wire(self.passes(self.names)), self.names), 58)

    def test_missing_parent_package_control_or_foreign_test_cannot_pass(self):
        events = self.passes(self.names)
        for removed in (0, len(events)-1, next(i for i,e in enumerate(events) if e.get("Test") == VERIFIER_TEST)):
            with self.assertRaises(ValueError): selected_outcome(self.wire(events[:removed]+events[removed+1:]), self.names)
        for extra in (events[0], dict(events[0], Test=VM_TEST+"/unselected"), dict(events[0], Package="example.invalid")):
            with self.assertRaises(ValueError): selected_outcome(self.wire(events+[extra]), self.names)

    def test_failure_skip_and_duplicate_json_keys_are_refused(self):
        for action in ("fail", "skip"):
            with self.assertRaises(ValueError):
                selected_outcome(self.wire(self.passes(self.names)+[dict(Package=self.package, Action=action)]), self.names)
        with self.assertRaises(ValueError): selected_outcome(b'{"Action":"fail","Action":"pass"}\n', self.names)
        with self.assertRaises(ValueError): json.loads('{"id":"first","id":"second"}', object_pairs_hook=unique_object)

    def test_fragmented_long_go_log_records_are_reassembled_by_exact_test(self):
        records = self.collect_framing(self.fragments())
        self.assertEqual(set(records), {v["id"] for v in self.fixture["vm_vectors"]})

    def test_fragment_truncation_or_test_switch_cannot_complete_evidence(self):
        events = self.fragments()
        with self.assertRaises(ValueError): self.collect_framing(events[:-1])
        events[1]["Test"] = VM_TEST+"/unselected"
        with self.assertRaises(ValueError): self.collect_framing(events)

    def test_duplicate_foreign_restart_and_wrong_action_records_are_refused(self):
        events = self.fragments()
        for changed in (events+events[:3], [dict(events[0], Package="example.invalid"),*events[1:]],
                        [events[0],events[0],*events[1:]], [dict(events[0],Action="pass"),*events[1:]]):
            with self.assertRaises(ValueError): self.collect_framing(changed)

    def test_oversized_record_and_embedded_duplicate_fields_are_refused(self):
        events = self.fragments()
        events[0]["Output"] = "    zz_research_nom_vm_path_test.go:1: " + PREFIX + "x"*65537
        with self.assertRaises(ValueError): self.collect_framing(events)
        vector = self.fixture["vm_vectors"][0]
        event = dict(Package=self.package, Action="output", Test=VM_TEST+"/"+vector["id"],
                     Output="    zz_research_nom_vm_path_test.go:1: "+PREFIX+'{"id":"first","id":"second"}\n')
        with self.assertRaises(ValueError): self.collect_framing([event])

    def test_toy_graph_is_parser_input_and_never_source_execution_evidence(self):
        record = self.parser_record()
        self.assertEqual(validate_record(record, self.vector, self.funding), record)
        # Without all exact real source package/test results, it is no pass.
        with self.assertRaises(ValueError): selected_outcome(b"", self.names)

    def test_wrong_leg_or_funding_identity_is_refused(self):
        for key, value in (("leg", "short"), ("funding_id_hex", "00"*32), ("amount", "101")):
            record = self.parser_record(); record[key] = value
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_incomplete_roles_unknown_fields_or_boolean_payouts_are_refused(self):
        for mutation in ("missing", "extra", "boolean"):
            record = self.parser_record()
            if mutation == "missing": del record["blocks"]["recipient-receive"]
            elif mutation == "extra": record["unknown"] = "unselected"
            else: record["events"][-1]["payouts"] = True
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_unchanged_hash_or_changed_executed_create_is_refused(self):
        for role in ("unlock-send", "create-send"):
            record = self.parser_record(); record["blocks"][role]["block"]["height"] = "2"
            if role == "create-send": self.rehash(record, role)
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_parent_child_context_and_fixed_asset_destination_are_bound(self):
        for key, value in (("momentum_height", "1"), ("to_address_hex", "00"*20), ("amount", "99"), ("token_standard_hex", "00"*10)):
            record = self.parser_record(); record["blocks"]["unlock-payout-0"]["block"][key] = value
            self.rehash(record, "unlock-payout-0")
            record["blocks"]["unlock-receive"]["block"]["descendant_hashes_hex"] = [record["blocks"]["unlock-payout-0"]["hash_hex"]]
            self.rehash(record, "unlock-receive")
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_receipt_from_hash_type_and_ancestry_are_required(self):
        for key, value in (("from_block_hash_hex", "00"*32), ("block_type", "2"), ("height", "2"), ("amount", "1")):
            record = self.parser_record(); record["blocks"]["recipient-receive"]["block"][key] = value
            self.rehash(record, "recipient-receive")
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_patch_hash_is_a_separate_opaque_claim_without_state_authentication(self):
        record = self.parser_record(); before = record["blocks"]["recipient-receive"]["hash_hex"]
        record["blocks"]["recipient-receive"]["changes_hash_hex"] = "ff"*32
        validate_record(record, self.vector, self.funding)
        self.assertEqual(record["blocks"]["recipient-receive"]["hash_hex"], before)
        self.assertEqual(self.fixture["boundary"]["source_authentication"], "UNFILLED")

    def test_patch_handoff_must_be_bounded_different_and_complete(self):
        for patches in ({}, {"before_hex":"00","after_hex":"00"}, {"before_hex":"00","after_hex":"g0"},
                        {"before_hex":"00","after_hex":"00"*16385}):
            record = self.parser_record(); record["receipt_patches"] = patches
            with self.assertRaises(ValueError): validate_record(record, self.vector, self.funding)

    def test_raw_replay_counterexample_and_corrupted_balance_are_not_conservation(self):
        _, normal, _ = expected_result("direct-success", 100)
        _, raw, _ = expected_result("raw-receive-replay-needs-verifier", 100)
        _, corrupted, present = expected_result("insufficient-contract-balance-rolls-back", 100)
        self.assertEqual(sum(map(int, normal.values())), 200)
        self.assertEqual(sum(map(int, raw.values())), 300)
        self.assertEqual(corrupted["contract"], "99"); self.assertTrue(present)
        with self.assertRaises(ValueError): expected_result("unselected", 100)

    def test_composed_execution_does_not_fill_independent_admission_gates(self):
        boundary = self.fixture["boundary"]
        self.assertEqual((boundary["application"], boundary["core"]), ("NO-GO", "NO-GO"))
        for gate in ("source_authentication", "canonicality", "finality", "rollback_protection", "independent_assessment"):
            self.assertEqual(boundary[gate], "UNFILLED")
        for gate in ("account_admission", "activation", "application_signing", "chain_observation",
                     "core_journal_composition", "supervisor_and_plasma_admission"):
            self.assertEqual(boundary[gate], "NOT_PERFORMED")


if __name__ == "__main__": unittest.main()
