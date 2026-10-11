"""Source account context conflicts cannot confer original recovery authority."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from offline_session.public_worker import WorkerError
from scripts import qualify_nom_account_context as context
from scripts.generate_nom_account_context import FIXTURE, vectors, corpus

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / FIXTURE).read_text("ascii"))


class NoMAccountContextTests(unittest.TestCase):
    def setUp(self):
        self.records = copy.deepcopy(FIX["records"])
        self.source = context.frozen_source()
        self.patches = context.frozen_patches()

    def record(self, role, kind, leg="long"):
        return self.records[leg + "-" + role + "-" + kind]

    def validate(self):
        return context.validate_records(self.records, self.source, self.patches)

    def stream(self):
        return b"\n".join(json.dumps({"Package": context.PACKAGE, "Test": context.TEST + "/" + v["id"],
            "Action": "output", "Output": "    zz_research_nom_account_context_test.go:500: "
            + context.PREFIX + json.dumps(self.records[v["id"]], sort_keys=True) + "\n"}).encode("ascii")
            for v in vectors()) + b"\n"

    def test_complete_context_subject_preserves_all_source_and_authorization_inputs(self):
        self.assertEqual(FIX, corpus(self.validate(), self.patches))
        manifest, fixture, measured = context.inputs(ROOT)
        self.assertEqual(fixture, FIX)
        self.assertEqual(manifest["expected_counts"], context.COUNTS)
        self.assertEqual((len(vectors()), len(context.expected_tests()[context.PACKAGE])), (84, 85))
        self.assertIn(context.auth.MANIFEST, measured)
        self.assertEqual(FIX["boundary"]["recovery_action"], "NONE")
        self.assertEqual((FIX["boundary"]["application"], FIX["boundary"]["core"]), ("NO-GO", "NO-GO"))

    def test_old_user_funding_and_unlock_cannot_inherit_invented_previous_accounts(self):
        for leg in ("long", "short"):
            for role in ("funding", "unlock-send"):
                for kind in ("original", "relocated"):
                    r = self.record(role, kind, leg)
                    self.assertEqual(set(r["checks"].values()), {"SOURCE_PANIC"})
                    self.assertEqual(r["context"]["account_frontier"], context.hh())
        self.validate()

    def test_reset_and_continued_signed_funding_are_different_entry_ids_and_originals(self):
        for leg in ("long", "short"):
            old = self.record("funding", "original", leg)
            first = self.record("funding", "reset-start", leg)
            second = self.record("funding", "next-after-reset", leg)
            self.assertEqual(set(first["checks"].values()) | set(second["checks"].values()), {"PASS"})
            self.assertEqual(second["header_previous"], context.hh(first["hash_hex"], "1"))
            self.assertEqual(second["context"]["account_frontier_wire_hex"], first["wire_hex"])
            self.assertEqual(len({old["hash_hex"], first["hash_hex"], second["hash_hex"]}), 3)
            self.assertEqual(len({old["wire_hex"], first["wire_hex"], second["wire_hex"]}), 3)
        self.assertEqual(FIX["boundary"]["journal_composition"], "NOT_PERFORMED")

    def test_batch_semantic_predecessor_is_first_child_predecessor_and_not_parent_header(self):
        for leg in ("long", "short"):
            r = self.record("unlock-receive", "original", leg)
            self.assertNotEqual(r["header_previous"], r["semantic_previous"])
            self.assertEqual(r["context"]["account_frontier"], r["semantic_previous"])
            wrong = self.record("unlock-receive", "header-predecessor-store", leg)
            self.assertEqual(wrong["context"]["account_frontier"], r["header_previous"])
            self.assertEqual(set(wrong["checks"].values()), {"ErrABPreviousMissing"})

    def test_cemented_ancestor_competing_previous_and_missing_previous_have_distinct_refusals(self):
        for kind, refusal in (("next-cemented-ancestor", "ErrABPrevHasCementedOnTop"),
                              ("next-cemented-competitor", "ErrABPrevHeightExists"),
                              ("next-wrong-previous", "ErrABPreviousMissing")):
            self.assertEqual(set(self.record("funding", kind)["checks"].values()), {refusal})
        self.validate()

    def test_replaying_old_receipt_hits_frontier_before_a_new_successor_hits_received_marker(self):
        for leg in ("long", "short"):
            old = self.record("recipient-receive", "post-vm-original", leg)
            next_block = self.record("recipient-receive", "post-vm-successor", leg)
            self.assertEqual(set(old["checks"].values()), {"ErrABPrevHeightExists"})
            self.assertEqual(next_block["checks"]["structural"], "ErrABFromBlockAlreadyReceived")
            self.assertTrue(old["context"]["received_marker"])
            self.assertTrue(next_block["context"]["received_marker"])
            self.assertNotEqual(old["wire_hex"], next_block["wire_hex"])

    def test_public_key_relocation_of_receipt_fails_fixed_payout_receiver(self):
        r = self.record("recipient-receive", "relocated")
        self.assertEqual(r["checks"], {"structural": "ErrABFromBlockReceiverMismatch", "transaction": "PASS"})
        self.assertNotEqual(r["hash_hex"], r["source_hash_hex"])
        self.validate()

    def test_receiver_enforcement_uses_ledger_frontier_and_not_declared_acknowledgement(self):
        before = self.record("recipient-receive", "wrong-recipient-before-enforcement")
        high_ack = self.record("recipient-receive", "wrong-recipient-high-ack-low-frontier")
        after = self.record("recipient-receive", "wrong-recipient-at-enforcement")
        self.assertEqual(before["checks"]["structural"], "PASS")
        self.assertEqual(high_ack["checks"]["structural"], "PASS")
        self.assertGreater(int(high_ack["acknowledged"]["height"]), int(high_ack["context"]["frontier_momentum"]["height"]))
        self.assertEqual(after["checks"]["structural"], "ErrABFromBlockReceiverMismatch")

    def test_structure_and_authorization_fail_independently_with_no_combined_admission_claim(self):
        r = self.record("funding", "next-unsigned-missing-ack")
        self.assertEqual(r["checks"], {"structural": "ErrABMAMissing", "transaction": "ErrABSignatureMissing"})
        self.assertEqual(self.record("funding", "next-ack-regression")["checks"], {"structural": "ErrABMAGap", "transaction": "PASS"})
        self.assertEqual(FIX["boundary"]["account_admission"], "NOT_PERFORMED")

    def test_actual_mailbox_queue_is_separate_from_parent_hash_and_empty_embedded_signature(self):
        for role in ("create-receive", "unlock-receive"):
            r = self.record(role, "empty-mailbox")
            self.assertEqual(r["context"]["mailbox_headers"], [])
            self.assertEqual(r["checks"], {"structural": "ErrABSequencerNothing", "transaction": "PASS"})
        self.assertEqual(self.record("create-receive", "wrong-mailbox-head")["checks"]["structural"], "ErrABSequencerNotNext")

    def test_selected_child_structural_checks_do_not_establish_recursive_child_hash_admission(self):
        for leg in ("long", "short"):
            r = self.record("unlock-receive", "child-wrong-hash", leg)
            self.assertEqual(set(r["checks"].values()), {"PASS"})
            self.assertEqual(r["hash_hex"], r["computed_hash_hex"])
            self.assertNotEqual(r["children"][0]["hash_hex"], r["children"][0]["computed_hash_hex"])
        self.assertEqual(FIX["boundary"]["supervisor_and_plasma_admission"], "NOT_PERFORMED")

    def test_descendant_version_and_acknowledgement_have_distinct_parent_and_child_refusals(self):
        self.assertEqual(self.record("unlock-receive", "child-wrong-version")["checks"], {"structural": "PASS", "transaction": "ErrABDescendantVerify"})
        self.assertEqual(self.record("unlock-receive", "child-wrong-ack")["checks"], {"structural": "ErrABMAMustBeTheSame", "transaction": "ErrABDescendantVerify"})
        self.validate()

    def test_external_contract_send_is_rejected_before_any_account_lookup(self):
        for leg in ("long", "short"):
            for kind in ("original", "rehashed", "nonempty-signature"):
                r = self.record("unlock-payout-0", kind, leg)
                self.assertEqual(set(r["checks"].values()), {"ErrABTypeInvalidExternal"})
                self.assertEqual(r["context"]["structural_account_queries"], [])
                self.assertEqual(r["context"]["transaction_account_queries"], [])

    def test_exact_vm_patches_are_distinct_and_selected_before_and_after_receive(self):
        for leg in ("long", "short"):
            self.assertNotEqual(self.patches[leg]["before_hex"], self.patches[leg]["after_hex"])
            for kind, selection in (("original", "before_hex"), ("post-vm-original", "after_hex")):
                r = self.record("recipient-receive", kind, leg)
                self.assertEqual(r["context"]["vm_patch_sha256"], hashlib.sha256(bytes.fromhex(self.patches[leg][selection])).hexdigest())
        self.validate()

    def test_changed_account_contents_can_keep_valid_signature_over_the_old_advertised_hash(self):
        base = self.record("funding", "next-after-reset")
        changed = self.record("funding", "next-old-hash")
        self.assertEqual((base["hash_hex"], base["signature_hex"]), (changed["hash_hex"], changed["signature_hex"]))
        self.assertNotEqual(changed["hash_hex"], changed["computed_hash_hex"])
        self.assertEqual(changed["checks"]["transaction"], "ErrABHashInvalid")

    def test_original_byte_replacement_even_with_unchanged_hash_is_refused(self):
        self.record("funding", "original")["original_wire_hex"] += "0801"
        with self.assertRaises(ValueError): self.validate()

    def test_reencoded_alias_is_not_preserved_exact_wire(self):
        r = self.record("funding", "next-after-reset")
        r["wire_hex"] += "0801"; r["wire_sha256"] = hashlib.sha256(bytes.fromhex(r["wire_hex"])).hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_claimed_structural_pass_cannot_erase_known_momentum_conflict(self):
        self.record("funding", "next-missing-ack")["checks"]["structural"] = "PASS"
        with self.assertRaises(ValueError): self.validate()

    def test_context_lookup_cannot_substitute_header_previous_for_batch_semantics(self):
        r = self.record("unlock-receive", "original")
        r["context"]["structural_account_queries"][0].update(r["header_previous"])
        with self.assertRaises(ValueError): self.validate()

    def test_coherent_new_frontier_identifier_cannot_replace_selected_actual_frontier(self):
        self.record("unlock-receive", "original")["context"]["account_frontier"]["hash_hex"] = "44" * 32
        with self.assertRaises(ValueError): self.validate()

    def test_received_marker_cannot_be_downgraded_by_an_unseen_claim(self):
        self.record("recipient-receive", "post-vm-successor")["context"]["received_marker"] = False
        with self.assertRaises(ValueError): self.validate()

    def test_substituted_vm_patch_is_refused_even_when_its_sha256_is_recomputed(self):
        r = self.record("recipient-receive", "post-vm-original")
        r["context"]["vm_patch_sha256"] = hashlib.sha256(b"different public patch").hexdigest()
        with self.assertRaises(ValueError): self.validate()

    def test_memory_state_patch_is_bounded_and_exactly_committed(self):
        for value in ("00" * 32769, "ff"):
            original = self.record("create-receive", "original")["context"]["account_state_patch_hex"]
            self.record("create-receive", "original")["context"]["account_state_patch_hex"] = value
            with self.assertRaises(ValueError): self.validate()
            self.record("create-receive", "original")["context"]["account_state_patch_hex"] = original

    def test_actual_empty_memory_patch_is_retained_as_empty_and_not_invented_history(self):
        for leg in ("long", "short"):
            r = self.record("funding", "original", leg)
            self.assertEqual(r["context"]["account_state_patch_hex"], "")
            self.assertEqual(r["context"]["account_state_patch_sha256"], hashlib.sha256(b"").hexdigest())
        self.validate()

    def test_source_panic_is_only_an_explicit_selected_observation_and_never_a_pass(self):
        observed = [r for r in self.records.values() if "SOURCE_PANIC" in r["checks"].values()]
        self.assertEqual(len(observed), 8)
        self.record("funding", "next-after-reset")["checks"]["structural"] = "SOURCE_PANIC"
        with self.assertRaises(ValueError): self.validate()

    def test_vm_patch_handoff_requires_both_legs_and_distinct_before_and_after_values(self):
        for changed in ({"long": self.patches["long"]},
                        {**self.patches, "long": {"before_hex": "00", "after_hex": "00"}}):
            with self.assertRaises(ValueError): context.validate_records(self.records, self.source, changed)

    def test_child_recomputed_hash_cannot_be_relabelled_as_the_advertised_hash(self):
        r = self.record("unlock-receive", "child-wrong-hash")
        r["children"][0]["computed_hash_hex"] = r["children"][0]["hash_hex"]
        with self.assertRaises(ValueError): self.validate()

    def test_missing_extra_and_changed_role_records_are_refused(self):
        for operation in (lambda: self.records.pop(next(iter(self.records))),
                          lambda: self.records.update(extra=copy.deepcopy(next(iter(self.records.values())))),
                          lambda: self.record("funding", "original").update(role="unlock-send")):
            self.records = copy.deepcopy(FIX["records"]); operation()
            with self.assertRaises(ValueError): self.validate()

    def test_uint64_fields_reject_boolean_and_overflow_without_unbounded_bit_count(self):
        for value in (True, str(1 << 64), "01"):
            self.record("funding", "original")["context"]["known_momentum"]["height"] = value
            with self.assertRaises(ValueError): self.validate()

    def test_fragmented_go_json_reassembles_only_the_exact_selected_record(self):
        events = [json.loads(line) for line in self.stream().splitlines()]
        first = events[0]; output = first["Output"]; cut = len(output) // 2
        events[:1] = [dict(first, Output=output[:cut]), dict(first, Output=output[cut:])]
        wire = b"\n".join(json.dumps(event).encode("ascii") for event in events)
        self.assertEqual(context.collect_records(wire, self.source, self.patches), self.records)

    def test_duplicate_fields_and_repeated_records_never_replace_original_evidence(self):
        wire = self.stream()
        events = [json.loads(line) for line in wire.splitlines()]
        events[0]["Output"] = events[0]["Output"].replace('"schema":', '"schema":"duplicate", "schema":', 1)
        duplicate_field = b"\n".join(json.dumps(event).encode("ascii") for event in events)
        for changed in (wire + wire.splitlines()[0] + b"\n", duplicate_field):
            with self.assertRaises(ValueError): context.collect_records(changed, self.source, self.patches)

    def test_wrong_package_test_prefix_missing_record_and_interleaved_fragments_are_refused(self):
        wire = self.stream(); events = [json.loads(line) for line in wire.splitlines()]
        fragment = dict(events[0], Output=events[0]["Output"][:200])
        interleaved = b"\n".join(json.dumps(event).encode("ascii") for event in [fragment, events[1]])
        for changed in (wire.replace(context.PACKAGE.encode(), b"different/package", 1),
                        wire.replace(b"zz_research_nom_account_context_test.go", b"different_test.go", 1),
                        b"\n".join(wire.splitlines()[:-1]), interleaved):
            with self.assertRaises(ValueError): context.collect_records(changed, self.source, self.patches)

    def test_zero_exit_requires_all_exact_parent_and_children_with_no_skip_failure_or_duplicate(self):
        names = context.expected_tests()
        events = [{"Package": context.PACKAGE, "Action": "pass", "Test": name} for name in names[context.PACKAGE]]
        events.append({"Package": context.PACKAGE, "Action": "pass"})
        encode = lambda values: b"\n".join(json.dumps(event).encode("ascii") for event in values)
        self.assertEqual(context.vm.selected_outcome(encode(events), names), 85)
        for changed in (events[1:], events + events[:1], events + [{"Package": context.PACKAGE, "Action": "skip", "Test": context.TEST}],
                        events + [{"Package": context.PACKAGE, "Action": "fail"}]):
            with self.assertRaises(ValueError): context.vm.selected_outcome(encode(changed), names)

    def test_failed_fresh_source_preserves_failure_and_never_falls_back_to_fixture(self):
        with tempfile.TemporaryDirectory(prefix="ptlc-account-context-") as folder:
            parent = Path(folder)
            with patch.object(context.vm, "core_state"), patch.object(context, "fresh_source", side_effect=WorkerError("selected source failed")),\
                 patch.object(context, "execute") as executed:
                with self.assertRaises(WorkerError): context.qualify(ROOT, Path(__file__), evidence_parent=parent)
                executed.assert_not_called()
            outcomes = list(parent.glob("account-context-*/outcome.json"))
            self.assertEqual(len(outcomes), 1)
            outcome = json.loads(outcomes[0].read_text("ascii"))
            self.assertEqual(outcome["outcome"], "FAILED_OR_INCOMPLETE")
            self.assertNotIn("fresh_projection", outcome)
            self.assertEqual(outcome["recovery_action"], "NONE")


class NoMAccountContextIndependentSignatures(unittest.TestCase):
    # Reuse the existing public-only OpenSSL runner, not Go's verifier backend.
    @classmethod
    def setUpClass(cls):
        from tests.test_nom_account_authorization import NoMAccountSignatureIndependentTests
        NoMAccountSignatureIndependentTests.setUpClass.__func__(cls)

    def verify(self, record, message=None):
        from tests.test_nom_account_authorization import NoMAccountSignatureIndependentTests
        return NoMAccountSignatureIndependentTests.verify(self, record, message)

    def test_new_connected_public_signatures_pass_independent_openssl(self):
        controls = [r for r in FIX["records"].values() if r["role"] == "funding" and len(r["signature_hex"]) == 128
                    and r["kind"] not in ("relocated", "next-bad-signature")]
        self.assertEqual(len(controls), 18)
        for r in controls: self.assertEqual(self.verify(r), (0, b"Signature Verified Successfully"))

    def test_bad_signature_and_changed_computed_contents_are_independently_refused(self):
        for leg in ("long", "short"):
            r = FIX["records"][leg + "-funding-next-bad-signature"]
            self.assertEqual(self.verify(r), (1, b"Signature Verification Failure"))
            changed = FIX["records"][leg + "-funding-next-old-hash"]
            self.assertEqual(self.verify(changed), (0, b"Signature Verified Successfully"))
            self.assertEqual(self.verify(changed, bytes.fromhex(changed["computed_hash_hex"])), (1, b"Signature Verification Failure"))
