"""Exact event claims are not trusted native producer attestations."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.qualify_nom_observation_core import ROOT, MANIFEST, FIXTURE, SUBJECTS, inputs, expected_tests, parse_outcome


class NoMObservationCoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads((ROOT / FIXTURE).read_text("ascii"))
        self.names = expected_tests(self.fixture)
        self.events = []
        for package, names in sorted(self.names.items()):
            self.events.extend({"Package": package, "Action": "pass", "Test": name} for name in sorted(names))
            self.events.append({"Package": package, "Action": "pass"})

    def wire(self, events):
        return b"\n".join(json.dumps(e).encode("ascii") for e in events) + b"\n"

    def test_all_three_selected_packages_and_parents_are_required(self):
        self.assertEqual(len(self.names), 3)
        self.assertEqual(parse_outcome(self.wire(self.events), self.names), 37)

    def test_zero_exit_with_empty_missing_or_duplicate_packages_is_incomplete(self):
        for events in ([], self.events[:-1], self.events + [self.events[-1]], self.events[1:]):
            with self.assertRaises(ValueError): parse_outcome(self.wire(events), self.names)

    def test_one_missing_stateful_control_cannot_be_replaced_by_parent_pass(self):
        events = [e for e in self.events if not e.get("Test", "").endswith("/created-id-refuses-old-witness")]
        with self.assertRaisesRegex(ValueError, "incomplete"): parse_outcome(self.wire(events), self.names)

    def test_failed_or_skipped_checks_are_not_relabelled(self):
        for action in ("fail", "skip"):
            event = dict(self.events[0], Action=action)
            with self.assertRaises(ValueError): parse_outcome(self.wire(self.events + [event]), self.names)

    def test_foreign_packages_and_unselected_or_duplicate_tests_are_refused(self):
        for event in (dict(self.events[0], Package="example.invalid/unselected"),
                      dict(self.events[0], Test="TestResearchNoMObservationVM/unselected"), self.events[0]):
            with self.assertRaises(ValueError): parse_outcome(self.wire(self.events + [event]), self.names)

    def test_nonobject_or_malformed_events_are_not_native_evidence(self):
        for wire in (b"[]\n", b"null\n", b"invalid\n"):
            with self.assertRaises(ValueError): parse_outcome(wire, self.names)

    def test_duplicate_subjects_are_refused_in_each_package(self):
        for _, _, key, _ in SUBJECTS:
            fixture = copy.deepcopy(self.fixture); fixture[key].append(fixture[key][0])
            with self.assertRaisesRegex(ValueError, "duplicate"): expected_tests(fixture)

    def test_changed_fixture_is_refused_before_overlay_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (MANIFEST, FIXTURE, *(s[3] for s in SUBJECTS)):
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            (root / FIXTURE).write_bytes((root / FIXTURE).read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "input changed"): inputs(root)
