"""Finite record/oracle controls. Synthetic frames do not execute node source."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

from qualification import nom_signed_price_hold as price

ROOT = Path(__file__).resolve().parents[1]


def stream(records):
    events = [dict(Action='run', Package=price.PACKAGE, Test=price.TEST)]
    for identifier, record in sorted(records.items()):
        name = price.TEST+'/'+identifier
        events.append(dict(Action='run', Package=price.PACKAGE, Test=name))
        line = '    zz_research_nom_price_hold_test.go:138: '+price.PREFIX+json.dumps(record, sort_keys=True)+'\n'
        for offset in range(0, len(line), 512):
            events.append(dict(Action='output', Package=price.PACKAGE, Test=name, Output=line[offset:offset+512]))
        events.append(dict(Action='pass', Package=price.PACKAGE, Test=name))
    events.extend([dict(Action='pass', Package=price.PACKAGE, Test=price.TEST), dict(Action='pass', Package=price.PACKAGE)])
    return events


def encoded(events):
    return b'\n'.join(json.dumps(row, sort_keys=True).encode('ascii') for row in events)+b'\n'


class SignedPriceHoldTests(unittest.TestCase):
    def setUp(self):
        self.records = price.expected_records(ROOT)

    def refused(self, events):
        with self.assertRaises((AssertionError, ValueError, KeyError, TypeError)):
            price.compare_stream(encoded(events), ROOT)

    def altered(self, identifier, **values):
        selected = copy.deepcopy(self.records)
        selected[identifier].update(values)
        self.refused(stream(selected))

    def test_complete_fragmented_record_comparison_is_not_execution_attestation(self):
        result = price.compare_stream(encoded(stream(self.records)), ROOT)
        self.assertEqual(result['source_records'], 16)
        self.assertEqual(result['execution_origin'], 'NOT_ESTABLISHED_BY_THIS_READER')
        self.assertEqual(result['recovery_action'], 'NONE')
        self.assertEqual(result['application'], 'NO-GO')

    def test_fusion_price_rise_refuses_both_originals_without_rewrite(self):
        for leg in ('long', 'short'):
            old = self.records[leg+'-minimum']
            raised = self.records[leg+'-fusion-one-above']
            self.assertTrue(old['canonical_accepts'])
            self.assertFalse(raised['canonical_accepts'])
            self.assertEqual(old['original_wire_sha256'], raised['original_wire_sha256'])
            self.assertEqual(old['original_node_hash_hex'], raised['original_node_hash_hex'])

    def test_work_price_alone_does_not_change_these_fused_only_inputs(self):
        for leg in ('long', 'short'):
            self.assertTrue(self.records[leg+'-work-only-rise']['canonical_accepts'])
            self.assertFalse(self.records[leg+'-wide-work-price']['canonical_accepts'])

    def test_untrusted_wire_base_can_disagree_in_both_directions(self):
        for leg in ('long', 'short'):
            zero = self.records[leg+'-untrusted-zero-base']
            maximum = self.records[leg+'-untrusted-max-base']
            self.assertTrue(zero['advertised_accepts'])
            self.assertFalse(zero['canonical_accepts'])
            self.assertFalse(maximum['advertised_accepts'])
            self.assertTrue(maximum['canonical_accepts'])

    def test_before_first_v2_constructor_uses_minimum_prices(self):
        self.assertTrue(all(self.records[leg+'-before-first-v2']['canonical_accepts'] for leg in ('long', 'short')))

    def test_false_positive_price_claim_refuses(self):
        self.altered('short-fusion-rise', canonical_accepts=True)

    def test_integer_boolean_refuses(self):
        self.altered('long-minimum', canonical_accepts=1)

    def test_node_identifier_substitution_refuses(self):
        self.altered('long-minimum', original_node_hash_hex='00'*32)

    def test_original_byte_digest_substitution_refuses(self):
        self.altered('long-minimum', original_wire_sha256='00'*32)

    def test_recovery_authority_claim_refuses(self):
        self.altered('long-minimum', recovery_action='RETRY')

    def test_missing_record_with_passing_outcomes_refuses(self):
        events = stream(self.records)
        events = [row for row in events if not (row['Action']=='output' and row.get('Test')==price.TEST+'/long-minimum')]
        self.refused(events)

    def test_missing_actual_outcome_refuses(self):
        events = [row for row in stream(self.records) if not (row['Action']=='pass' and row.get('Test')==price.TEST+'/long-minimum')]
        self.refused(events)

    def test_duplicate_outcome_refuses(self):
        events = stream(self.records)
        events.append(dict(Action='pass', Package=price.PACKAGE, Test=price.TEST+'/long-minimum'))
        self.refused(events)

    def test_cross_test_record_fragments_refuse(self):
        events = stream(self.records)
        selected = next(row for row in events if row['Action']=='output' and row['Test']==price.TEST+'/long-minimum')
        selected['Test'] = price.TEST+'/short-minimum'
        self.refused(events)

    def test_wrong_package_refuses(self):
        events = stream(self.records)
        for row in events: row['Package'] = 'unselected/package'
        self.refused(events)

    def test_failed_package_refuses(self):
        events = stream(self.records)
        events[-1]['Action'] = 'fail'
        self.refused(events)

    def test_missing_final_record_newline_refuses(self):
        events = stream(self.records)
        selected = [row for row in events if row['Action']=='output' and row['Test']==price.TEST+'/long-minimum']
        selected[-1]['Output'] = selected[-1]['Output'].rstrip('\n')
        self.refused(events)

    def test_oversize_transcript_refuses(self):
        with self.assertRaises(AssertionError):
            price.compare_stream(b' '*(price.MAX_STREAM+1), ROOT)

    def test_optimized_module_refuses_before_stream_access(self):
        result = subprocess.run([sys.executable, '-B', '-O', '-m', 'qualification.nom_signed_price_hold',
            '--stream', 'unselected-stream'], cwd=ROOT, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'finite price comparison requires assertions enabled', result.stderr)
        self.assertNotIn(b'FileNotFoundError', result.stderr)
