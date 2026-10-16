"""Retention review never upgrades missing native executions or altered originals."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_anchor_sqlite_evidence as evidence
from qualification import nom_anchor_sqlite_review as review


class SqlOriginalReviewBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "selected"

    def incomplete(self):
        selected = evidence.OriginalEvidence(self.directory)
        original = selected.put("original/stdout", b"synthetic original output")
        selected.finalize("NOT_QUALIFIED", dict(outcome="NOT_QUALIFIED", reason="selected cut"))
        return original

    def test_complete_retention_graph_is_not_native_qualification(self):
        self.incomplete()
        result = review.review(self.directory, self.root, allow_incomplete=True)
        self.assertEqual(result["disposition"], "RETAINABLE_NOT_QUALIFIED")
        self.assertEqual(result["comparison"], {})
        self.assertEqual(result["recovery_action"], "NONE")
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root)

    def test_claimed_completion_without_original_native_scope_refuses(self):
        selected = evidence.OriginalEvidence(self.directory)
        selected.finalize("COMPLETE_FINITE_COMPARISON", dict(schema="synthetic-incomplete-report"))
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)

    def test_changed_original_bytes_cannot_be_replaced_by_a_digest_name(self):
        original = self.incomplete()
        (self.directory / "objects" / original["sha256"]).write_bytes(b"changed synthetic original")
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)

    def test_hard_linked_object_refuses_without_deleting_either_entry(self):
        original = self.incomplete()
        path = self.directory / "objects" / original["sha256"]
        alias = self.root / "alias"
        os.link(path, alias)
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)
        self.assertTrue(alias.exists())
        self.assertEqual(path.read_bytes(), alias.read_bytes())

    def test_missing_original_event_is_not_reconstructed(self):
        self.incomplete()
        (self.directory / "events" / "0001.json").unlink()
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)
        self.assertFalse((self.directory / "events" / "0001.json").exists())

    def test_interrupted_intent_is_retained_with_unknown_completion(self):
        selected = evidence.OriginalEvidence(self.directory)
        original_write = evidence._exclusive

        def cut(path, raw):
            if path.parent.name == "objects":
                raise OSError("selected write cut")
            return original_write(path, raw)

        with patch.object(evidence, "_exclusive", side_effect=cut):
            with self.assertRaises(OSError):
                selected.put("selected/cut", b"synthetic original output")
        result = review.review(self.directory, self.root, allow_incomplete=True)
        self.assertEqual(result["disposition"], "RETAINABLE_NOT_QUALIFIED")
        self.assertEqual(result["incomplete_intents"], 1)
        self.assertIsNone(result["manifest"])

    def test_hex_encoding_cannot_hide_selected_private_path_patterns(self):
        selected = evidence.OriginalEvidence(self.directory)
        synthetic = b"/" + b"Users" + b"/synthetic-account/private-fixture"
        selected.put("synthetic/encoded", review.canonical(dict(stdout_hex=synthetic.hex())))
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)

    def test_duplicate_json_keys_are_not_normalized_into_acceptance(self):
        with self.assertRaises(review.ReviewRefused):
            review.document(b'{"position":1,"position":2}')

    def test_unreferenced_valid_object_is_not_adopted(self):
        self.incomplete()
        raw = b"unregistered synthetic original"
        (self.directory / "objects" / hashlib.sha256(raw).hexdigest()).write_bytes(raw)
        with self.assertRaises(review.ReviewRefused):
            review.review(self.directory, self.root, allow_incomplete=True)

    def test_native_sized_hex_without_email_finishes_within_its_deadline(self):
        selected = subprocess.run([sys.executable, "-B", "-c",
            "from qualification.nom_anchor_sqlite_review import sharing; "
            "sharing(b'f' * (2 * 1024**2)); print('checked')"],
            cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10, check=False)
        self.assertEqual(selected.returncode, 0)
        self.assertEqual(selected.stdout, b"checked\n")
        self.assertEqual(selected.stderr, b"")

    def test_email_punctuation_and_long_local_parts_remain_refused(self):
        for local in (b"synthetic.user+tag", b"f" * (256 * 1024)):
            with self.assertRaises(review.ReviewRefused):
                review.sharing(local + b"@" + b"example.invalid")
