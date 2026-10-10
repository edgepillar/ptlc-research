"""Incomplete test-output claims never fill the source differential gate."""

import json
from pathlib import Path
import tempfile
import unittest

from scripts.qualify_nom_wire_core import (
    PACKAGE, TEST, ROOT, MANIFEST, FIXTURE, DRIVER, expected_tests, parse_outcome, inputs,
)


class NoMWireEvidenceTests(unittest.TestCase):
    def setUp(self):
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        self.names = expected_tests(fixture)
        self.events = [{"Package": PACKAGE, "Action": "pass", "Test": name} for name in sorted(self.names)]
        self.events.append({"Package": PACKAGE, "Action": "pass"})

    def wire(self, events):
        return b"\n".join(json.dumps(event).encode("ascii") for event in events) + b"\n"

    def test_exact_public_event_claims_have_explicit_host_trust(self):
        self.assertEqual(len(self.names), 45)
        self.assertEqual(parse_outcome(self.wire(self.events), self.names), 45)
        # This is event parsing, not proof that a trusted Go producer ran.

    def test_zero_exit_or_empty_output_is_not_complete_test_evidence(self):
        for events in ([], [{"Package": PACKAGE, "Action": "pass"}], self.events[:-1]):
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_missing_subtest_cannot_be_replaced_by_parent_success(self):
        removed = TEST + "/normalize/unlock-offset-gap"
        events = [event for event in self.events if event.get("Test") != removed]
        with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_failure_and_skip_are_not_relabelled_as_pass(self):
        for action in ("fail", "skip"):
            events = self.events + [{"Package": PACKAGE, "Action": action, "Test": TEST}]
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_unexpected_package_and_duplicate_results_are_refused(self):
        alternatives = [self.events + [self.events[0]], self.events + [self.events[-1]],
                        self.events + [{"Package": "example.invalid/other", "Action": "pass", "Test": TEST}],
                        self.events + [{"Package": PACKAGE, "Action": "pass", "Test": TEST + "/unselected"}]]
        for events in alternatives:
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_invalid_json_and_nonobject_events_are_refused(self):
        for wire in (b"not-json\n", b"[]\n", b"null\n"):
            with self.assertRaises(ValueError): parse_outcome(wire, self.names)

    def test_manifest_hash_refuses_changed_fixture_before_core_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, FIXTURE, DRIVER):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            (root / FIXTURE).write_bytes((root / FIXTURE).read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "selected input changed"): inputs(root)

    def test_duplicate_fixture_test_name_is_refused(self):
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        fixture["abi_vectors"].append(fixture["abi_vectors"][0])
        with self.assertRaises(ValueError): expected_tests(fixture)
        fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        fixture["controls"].append(fixture["controls"][0])
        with self.assertRaises(ValueError): expected_tests(fixture)
