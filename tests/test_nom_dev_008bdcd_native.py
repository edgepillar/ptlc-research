"""Controls for the exact native selection and its data-only result reader."""
import json
import re
import unittest

from qualification import nom_dev_008bdcd_native as selected
from qualification.nom_current_admission import PREFIX
from scripts import qualify_nom_008bdcd_native as runner


def event_bytes(events):
    return b''.join(json.dumps(event, sort_keys=True).encode('ascii') + b'\n' for event in events)


def synthetic_events():
    events = []
    for package, roots in selected.ROOTS.items():
        package = PREFIX + package
        events.append(dict(Action='start', Package=package))
        for root in roots:
            events.extend(dict(Action=action, Package=package, Test=root) for action in ('run', 'pass'))
        events.append(dict(Action='pass', Package=package))
    return events


class NoMDev008bdcdNativeControls(unittest.TestCase):
    def test_plan_uses_one_exact_filter_and_the_original_corpus(self):
        plan, index, combined = selected.selection()
        self.assertEqual((len(index), len(combined), len(selected.ROOTS)), (562, 563, 13))
        self.assertEqual(sum(map(len, selected.ROOTS.values())), 38)
        self.assertEqual(combined[selected.PROBE], plan['project_input_sha256'][selected.DRIVER])
        self.assertEqual(len(plan['project_input_sha256']), 5)
        self.assertEqual(tuple(plan['test_arguments'][-13:]), selected.PACKAGES)
        self.assertIn('-count=1', plan['test_arguments'])
        self.assertIn('-mod=readonly', plan['test_arguments'])
        self.assertNotIn('-vet=off', plan['test_arguments'])
        names = [name for roots in selected.ROOTS.values() for name in roots]
        self.assertTrue(all(re.fullmatch(selected.TEST_FILTER, name) for name in names))
        self.assertFalse(any(re.fullmatch(selected.TEST_FILTER, name + 'Other') for name in names))

    def test_stream_refuses_skipped_missing_and_additional_roots(self):
        original = synthetic_events()
        record = selected.accept_events(event_bytes(original))
        self.assertEqual((record['packages'], record['required_parents']), (13, 38))
        for events in (original[:1] + original[3:],
                       original[:2] + [dict(original[2], Action='skip')] + original[3:],
                       original[:3] + [dict(original[1], Test='TestUnselected')] + original[3:]):
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                selected.accept_events(event_bytes(events))

    def test_export_checks_original_streams_and_module_checksum_keys(self):
        self.assertTrue(runner.safe(b'go version go1.23.12 linux/amd64\n'))
        self.assertFalse(runner.safe(b'compiler path TOKEN', ('TOKEN',)))
        self.assertFalse(runner.safe(b'line with non-ASCII byte \xff'))
        row = b'example.invalid/module v1.0.0 h1:' + b'A'*43 + b'=\n'
        self.assertEqual(len(runner.module_sums(row)), 1)
        for invalid in (row + row, row.rstrip(), row.replace(b'h1:', b'h0:')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                runner.module_sums(invalid)


if __name__ == '__main__':
    unittest.main()
