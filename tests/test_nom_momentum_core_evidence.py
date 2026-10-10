"""Synthetic event parsing is separate from actual core execution."""

import json
from pathlib import Path
import tempfile
import unittest

from scripts.qualify_nom_momentum_core import (
    DRIVER, FIXTURE, MANIFEST, PACKAGE, ROOT, TEST, expected_tests, inputs, parse_outcome,
)


class NoMMomentumCoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        self.names = expected_tests(fixture)
        self.events = [{"Package": PACKAGE, "Action": "pass", "Test": name} for name in sorted(self.names[PACKAGE])]
        self.events.append({"Package": PACKAGE, "Action": "pass"})

    def wire(self, events):
        return b"\n".join(json.dumps(event).encode("ascii") for event in events) + b"\n"

    def test_exact_event_claims_leave_the_actual_execution_gate_separate(self):
        self.assertEqual(parse_outcome(self.wire(self.events), self.names), 51)

    def test_empty_missing_parent_or_missing_package_is_incomplete(self):
        for events in ([], self.events[:-1], [value for value in self.events if value.get("Test") != TEST]):
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_missing_subtest_cannot_be_replaced_by_parent_pass(self):
        events = [value for value in self.events if value.get("Test") != TEST + "/control/content-duplicate-header"]
        with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_fail_skip_duplicate_or_foreign_result_is_refused(self):
        for extra in ({"Package": PACKAGE, "Action": "fail", "Test": TEST},
                      {"Package": PACKAGE, "Action": "skip", "Test": TEST}, self.events[0], self.events[-1],
                      {"Package": "example.invalid/unselected", "Action": "pass"},
                      {"Package": PACKAGE, "Action": "pass", "Test": TEST + "/unselected"}):
            with self.assertRaises(ValueError): parse_outcome(self.wire(self.events + [extra]), self.names)

    def test_invalid_event_shape_is_refused(self):
        for wire in (b'[]\n', b'null\n', b'not-json\n'):
            with self.assertRaises(ValueError): parse_outcome(wire, self.names)

    def test_duplicate_or_invalid_selected_names_are_refused(self):
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        fixture["hash_vectors"].append(fixture["hash_vectors"][0])
        with self.assertRaises(ValueError): expected_tests(fixture)
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii")); fixture["source_controls"].append("unselected/name")
        with self.assertRaises(ValueError): expected_tests(fixture)

    def test_changed_fixture_fails_before_source_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, FIXTURE, DRIVER):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            (root / FIXTURE).write_bytes((root / FIXTURE).read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "selected or preserved input changed"): inputs(root)

    def test_preserved_recovery_and_observation_subjects_are_measured(self):
        manifest, fixture, measured = inputs(ROOT)
        self.assertEqual(len(manifest["core_file_sha256"]), 16)
        self.assertEqual(len(manifest["preserved_file_sha256"]), 16)
        self.assertEqual(len(expected_tests(fixture)[PACKAGE]), 51)
        self.assertIn("scripts/nom_native_command.py", measured)


if __name__ == "__main__": unittest.main()
