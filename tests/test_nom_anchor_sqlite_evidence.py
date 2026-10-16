"""Original labels and retained identity boundaries of synthetic SQL evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qualification import nom_anchor_sqlite_evidence as evidence
from qualification.nom_anchor_sqlite_evidence import EvidenceRefused, OriginalEvidence


class OriginalSqlEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "selected"

    def test_existing_directory_is_not_adopted_or_truncated(self):
        self.directory.mkdir()
        original = self.directory / "original.txt"
        original.write_bytes(b"synthetic original")
        with self.assertRaises(EvidenceRefused):
            OriginalEvidence(self.directory)
        self.assertEqual(original.read_bytes(), b"synthetic original")

    def test_identical_originals_keep_one_object_and_distinct_labels(self):
        selected = OriginalEvidence(self.directory)
        first = selected.put("first/stdout", b"same synthetic output")
        second = selected.put("second/stdout", b"same synthetic output")
        self.assertEqual(first, second)
        self.assertEqual(len(list((self.directory / "objects").iterdir())), 1)
        result = selected.finalize("COMPLETE_FINITE_COMPARISON", dict(cases=0, native_executions=0))
        self.assertEqual(result["object_count"], 2)
        manifest = json.loads((self.directory / "manifest.json").read_bytes())
        self.assertEqual(manifest["labels"]["first/stdout"], manifest["labels"]["second/stdout"])

    def test_equal_label_with_different_contents_preserves_original(self):
        selected = OriginalEvidence(self.directory)
        original = selected.put("one/request", b"synthetic original request")
        with self.assertRaises(EvidenceRefused):
            selected.put("one/request", b"different request")
        self.assertEqual(selected.read(original["sha256"]), b"synthetic original request")

    def test_matching_digest_name_cannot_adopt_a_replaced_inode(self):
        selected = OriginalEvidence(self.directory)
        original = selected.put("original", b"synthetic original")
        path = selected.path(original["sha256"])
        replacement = self.directory / "replacement"
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
        with self.assertRaises(EvidenceRefused):
            selected.read(original["sha256"])

    def test_changed_bytes_are_refused_at_the_same_inode(self):
        selected = OriginalEvidence(self.directory)
        original = selected.put("original", b"synthetic original")
        selected.path(original["sha256"]).write_bytes(b"synthetic altered!")
        with self.assertRaises(EvidenceRefused):
            selected.read(original["sha256"])

    def test_hard_link_is_not_accepted_as_independent_evidence(self):
        selected = OriginalEvidence(self.directory)
        original = selected.put("original", b"synthetic original")
        os.link(selected.path(original["sha256"]), self.directory / "alias")
        with self.assertRaises(EvidenceRefused):
            selected.read(original["sha256"])

    def test_refused_retention_keeps_intent_without_a_completion(self):
        selected = OriginalEvidence(self.directory)
        original_write = evidence._exclusive

        def selected_cut(path, raw):
            if path.parent.name == "objects":
                raise OSError("selected cut")
            return original_write(path, raw)

        with patch("qualification.nom_anchor_sqlite_evidence._exclusive", side_effect=selected_cut):
            with self.assertRaises(OSError):
                selected.put("selected/cut", b"synthetic original")
        self.assertFalse((self.directory / "manifest.json").exists())
        events = [json.loads(path.read_bytes()) for path in (self.directory / "events").iterdir()]
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["kind"], events[0]["label"]), ("RETAIN_INTENT", "selected/cut"))
        self.assertEqual(list((self.directory / "objects").iterdir()), [])

    def test_replaced_child_directory_is_not_adopted(self):
        selected = OriginalEvidence(self.directory)
        (self.directory / "events").rename(self.directory / "original-events")
        (self.directory / "events").mkdir()
        with self.assertRaises(EvidenceRefused):
            selected.put("later", b"synthetic original")

    def test_widened_output_permissions_refuse_more_evidence(self):
        selected = OriginalEvidence(self.directory)
        self.directory.chmod(0o755)
        with self.assertRaises(EvidenceRefused):
            selected.put("later", b"synthetic original")

    def test_capacity_refusal_preserves_earlier_original(self):
        selected = OriginalEvidence(self.directory)
        original = selected.put("earlier", b"one")
        with patch("qualification.nom_anchor_sqlite_evidence.MAX_TOTAL_BYTES", 3):
            with self.assertRaises(EvidenceRefused):
                selected.put("later", b"two")
        self.assertEqual(selected.read(original["sha256"]), b"one")

    def test_completed_output_cannot_resume_or_append(self):
        selected = OriginalEvidence(self.directory)
        selected.put("original", b"synthetic original")
        selected.finalize("NOT_QUALIFIED", dict(reason="selected refusal"))
        before = (self.directory / "manifest.json").read_bytes()
        with self.assertRaises(EvidenceRefused):
            selected.put("later", b"another original")
        with self.assertRaises(EvidenceRefused):
            OriginalEvidence(self.directory)
        self.assertEqual((self.directory / "manifest.json").read_bytes(), before)
