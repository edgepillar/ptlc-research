"""Send-derived public contexts do not authenticate funding or a live swap."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from offline_session.nom_recovery import context, validate_terms
from offline_session.nom_wire import account_block_hash, decode_call
from offline_session.pr138 import unlock_message
from scripts.generate_nom_created_funding import ROOT, FIXTURE, COMPLETIONS, MUTATIONS, corpus
from scripts.qualify_nom_created_core import MANIFEST, SELECTED, TEST, inputs, expected_tests, parse_outcome
from scripts.qualify_nom_created_recovery import qualify


class NoMCreatedFundingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        self.completions = json.loads((ROOT / COMPLETIONS).read_text("ascii"))
        self.names = expected_tests(self.fixture)
        self.package = "github.com/zenon-network/go-zenon/vm/embedded/implementation"
        self.events = [{"Package": self.package, "Action": "pass", "Test": name} for name in sorted(self.names)]
        self.events.append({"Package": self.package, "Action": "pass"})

    def wire(self, events):
        return b"\n".join(json.dumps(event).encode("ascii") for event in events) + b"\n"

    def test_reproduction_and_exact_manifest_pin_the_additive_inputs(self):
        self.assertEqual(corpus(), self.fixture)
        manifest, fixture, measured = inputs(ROOT)
        self.assertEqual(fixture, self.fixture)
        self.assertEqual(manifest["research_baseline_commit"], "7327a9c52d657192871f5a1958bb530d4ea63a9b")
        self.assertEqual(set(manifest["input_sha256"]), set(SELECTED))
        self.assertTrue(set(SELECTED) <= measured.keys())

    def test_full_funding_hashes_replace_both_old_synthetic_ids(self):
        validate_terms(self.fixture["terms"])
        for leg in ("long", "short"):
            record = self.fixture["fundings"][leg]
            self.assertEqual(record["hash_hex"], account_block_hash(record["block"]))
            self.assertEqual(record["entry"]["id_hex"], record["hash_hex"])
            self.assertEqual(self.fixture["terms"][leg]["entry_id_hex"], record["hash_hex"])
            self.assertNotEqual(record["hash_hex"], self.fixture["old_entry_ids_hex"][leg])

    def test_all_funding_mutations_change_the_message_context_for_each_leg(self):
        for leg in ("long", "short"):
            baseline = self.fixture["fundings"][leg]
            for mutation in MUTATIONS:
                record = self.fixture["fundings"][leg + "-changed-" + mutation]
                self.assertEqual(record["hash_hex"], account_block_hash(record["block"]))
                self.assertNotEqual(record["hash_hex"], baseline["hash_hex"])
                changed = context(self.fixture["terms"], leg); changed["entry_id_hex"] = record["hash_hex"]
                self.assertNotEqual(unlock_message(changed), unlock_message(context(self.fixture["terms"], leg)))

    def test_inner_messages_match_exact_created_ids_and_fixed_recipients(self):
        for leg in ("long", "short"):
            record = self.fixture["fundings"][leg]
            create = decode_call(bytes.fromhex(record["block"]["data_hex"]))
            selected = context(self.fixture["terms"], leg)
            self.assertEqual(create["destination_hex"], selected["destination_hex"])
            self.assertEqual(create["point_lock_hex"], self.fixture["terms"][leg]["funder_key_xonly_hex"])
            self.assertEqual(unlock_message(selected), self.completions[leg + "_message_hex"])

    def test_public_witnesses_and_session_scope_differ_from_old_fixture(self):
        old_terms = json.loads((ROOT / "compatibility/fixtures/nom_terms_v1.json").read_text("ascii"))
        old = json.loads((ROOT / "compatibility/fixtures/nom_completions_v1.json").read_text("ascii"))
        self.assertNotEqual(old_terms["session_id_hex"], self.fixture["terms"]["session_id_hex"])
        for leg in ("long", "short"):
            self.assertNotEqual(self.completions[leg + "_signature_hex"], old[leg + "_signature_hex"])
            self.assertNotEqual(self.completions[leg + "_message_hex"], old[leg + "_message_hex"])

    def test_expiry_and_direct_proxy_permissions_are_separate_controls(self):
        for leg in ("long", "short"):
            vectors = {v["id"]: v for v in self.fixture["vectors"] if v["leg"] == leg}
            expiry = int(self.fixture["terms"][leg]["expires_at"])
            before = vectors[leg + "-direct-one-second-before-expiry"]["operations"][0]
            exact = vectors[leg + "-direct-at-expiry"]["operations"][0]
            self.assertEqual((before["timestamp"], before["expect_error"]), (str(expiry-1), "NONE"))
            self.assertEqual((exact["timestamp"], exact["expect_error"]), (str(expiry), "ErrExpired"))
            self.assertEqual(vectors[leg + "-reclaim-at-expiry"]["operations"][0]["expect_error"], "NONE")
            self.assertEqual(vectors[leg + "-direct-wrong-caller"]["operations"][0]["expect_error"], "ErrPermissionDenied")
            self.assertEqual(vectors[leg + "-proxy-third-party-fixed-recipient"]["operations"][0]["expect_error"], "NONE")

    def test_invalid_witness_preservation_and_deleted_entry_replays_are_selected(self):
        vectors = {v["id"]: v for v in self.fixture["vectors"]}
        for leg in ("long", "short"):
            invalid = vectors[leg + "-invalid-then-valid-original"]["operations"]
            self.assertEqual([v["expect_entry_after"] for v in invalid], [True, False])
            for suffix in ("direct-replay-after-deletion", "unlock-then-reclaim", "reclaim-then-unlock", "proxy-then-direct-replay"):
                operations = vectors[leg + "-" + suffix]["operations"]
                self.assertEqual([v["expect_entry_after"] for v in operations], [False, False])
                self.assertEqual(operations[-1]["expect_error"], "ErrDataNonExistent")

    def test_created_corpus_does_not_fill_chain_gates(self):
        boundary = self.fixture["boundary"]
        self.assertEqual((boundary["application"], boundary["core"]), ("NO-GO", "NO-GO"))
        for gate in ("source_authentication", "canonicality", "finality", "rollback_protection"):
            self.assertEqual(boundary[gate], "UNFILLED")
        self.assertEqual(boundary["outer_account_authorization"], "NOT_PERFORMED")
        self.assertEqual(boundary["balance_accounting"], "NOT_PERFORMED")

    def test_complete_seventy_controls_and_parent_are_required(self):
        self.assertEqual(len(self.names), 71)
        self.assertEqual(parse_outcome(self.wire(self.events), self.names), 71)

    def test_empty_missing_parent_or_missing_package_cannot_pass(self):
        for events in ([], self.events[:-1], [v for v in self.events if v.get("Test") != TEST]):
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_missing_mutation_control_cannot_be_hidden_by_parent_pass(self):
        events = [v for v in self.events if not v.get("Test", "").endswith("/short-changed-nonce-refuses-baseline-witness")]
        with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_duplicate_or_unselected_tests_and_package_passes_are_refused(self):
        for event in (self.events[0], self.events[-1], dict(self.events[0], Test=TEST+"/unselected")):
            with self.assertRaises(ValueError): parse_outcome(self.wire(self.events+[event]), self.names)

    def test_foreign_packages_are_not_source_evidence(self):
        with self.assertRaises(ValueError):
            parse_outcome(self.wire(self.events+[dict(self.events[0], Package="example.invalid/unselected")]), self.names)

    def test_failed_or_skipped_events_are_preserved_as_failure(self):
        for action in ("skip", "fail"):
            with self.assertRaises(ValueError): parse_outcome(self.wire(self.events+[dict(self.events[0], Action=action)]), self.names)

    def test_malformed_or_nonobject_events_are_refused(self):
        for wire in (b"null\n", b"[]\n", b"invalid\n"):
            with self.assertRaises(ValueError): parse_outcome(wire, self.names)

    def test_duplicate_subjects_and_invalid_names_are_refused(self):
        changed = copy.deepcopy(self.fixture); changed["vectors"][-1] = changed["vectors"][0]
        with self.assertRaises(ValueError): expected_tests(changed)
        for value in ("unselected/name", "", False, "non-ascii-\u00e9"):
            changed = copy.deepcopy(self.fixture); changed["vectors"][0]["id"] = value
            with self.assertRaises(ValueError): expected_tests(changed)

    def test_truncated_subject_cannot_select_a_smaller_successful_subset(self):
        changed = copy.deepcopy(self.fixture); changed["vectors"].pop()
        with self.assertRaises(ValueError): expected_tests(changed)

    def test_changed_fixture_is_refused_before_native_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, *SELECTED):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            (root / FIXTURE).write_bytes((root / FIXTURE).read_bytes()+b"\n")
            with self.assertRaisesRegex(ValueError, "input changed"): inputs(root)

    def test_relabelled_application_acceptance_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, FIXTURE):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            manifest = json.loads((root / MANIFEST).read_text()); manifest["application"] = "GO"
            (root / MANIFEST).write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "subject changed"): inputs(root)

    def test_actual_public_worker_recovers_originals_after_reopen_in_created_contexts(self):
        result = qualify(ROOT / "qualification/target/debug/examples/verify_nom_swap")
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(result["old_and_cross_leg_completions"], "REFUSED")
        self.assertEqual(result["original_recovery"]["two_journal_original_recovery"], "verified")
        self.assertEqual(result["core_journal_composition"], "NOT_PERFORMED")
        self.assertEqual(result["source_authentication"], "UNFILLED")
        self.assertEqual((result["application"], result["core"]), ("NO-GO", "NO-GO"))


if __name__ == "__main__": unittest.main()
