"""Scheduling and real unittest outcome controls; no protocol fixture caching."""
from collections import Counter
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest

from scripts import run_offline_shard as shard

ROOT=Path(__file__).resolve().parents[1]


class ShardRunnerTests(unittest.TestCase):
    def execute(self,cases,expected=None):
        expected=Counter(case.id() for case in cases) if expected is None else expected
        output=io.StringIO();errors=io.StringIO()
        report=shard.run(unittest.TestSuite(cases),expected,dict(selected_cases=sum(expected.values())),
            case_stream=output,error_stream=errors)
        events=[json.loads(line[len(shard.CASE_PREFIX):]) for line in output.getvalue().splitlines()]
        return report,events,errors.getvalue()

    def good(self):
        class Good(unittest.TestCase):
            def test_value(self):self.assertEqual(2+2,4)
        return Good('test_value')

    def test_partition_is_deterministic_balanced_and_covers_new_files(self):
        names=['test_'+letter+'.py' for letter in 'abcdefg']
        weights=dict(zip(names,[10,8,6,4,2,1,1]))
        value=shard.partition(names,weights,4)
        self.assertEqual(value,shard.partition(list(reversed(names)),weights,4))
        self.assertEqual(set(value),set(names))
        self.assertEqual(set(value.values()),{0,1,2,3})
        self.assertIn('test_new.py',shard.partition(names+['test_new.py'],weights,4))

    def test_duplicate_discovery_file_refuses(self):
        with self.assertRaises(ValueError):shard.partition(['test_a.py','test_a.py'])

    def test_boolean_shard_count_refuses(self):
        with self.assertRaises(ValueError):shard.partition(['test_a.py'],{},True)

    def test_boolean_weight_refuses(self):
        with self.assertRaises(ValueError):shard.partition(['test_a.py'],{'test_a.py':True})

    def test_noncanonical_shard_refuses_before_discovery(self):
        for value in ('01','1.0','4',1,True):
            with self.assertRaises(ValueError):shard.selection(Path('unselected-test-root'),value)

    def test_real_success_emits_one_complete_case_binding(self):
        case=self.good();report,events,unused=self.execute([case])
        self.assertEqual(report['outcome'],'PASS')
        self.assertEqual(events,[[case.id(),'ok']])
        self.assertEqual(report['actual_counter_sha256'],shard.counter_digest(Counter([case.id()])))

    def test_real_failure_cannot_be_reported_as_success(self):
        class Bad(unittest.TestCase):
            def test_value(self):self.fail('synthetic failure control')
        report,events,errors=self.execute([Bad('test_value')])
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(events[0][1],'failure')
        self.assertIn('synthetic failure control',errors)

    def test_skip_does_not_supply_complete_qualification(self):
        class Skip(unittest.TestCase):
            @unittest.skip('synthetic skip control')
            def test_value(self):pass
        report,events,unused=self.execute([Skip('test_value')])
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(events[0][1],'skip')

    def test_expected_failure_remains_distinct_from_success(self):
        class Red(unittest.TestCase):
            @unittest.expectedFailure
            def test_value(self):self.fail('synthetic expected failure')
        report,events,unused=self.execute([Red('test_value')])
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(events[0][1],'expected-failure')

    def test_failed_subtest_cannot_leave_a_positive_parent_event(self):
        class Sub(unittest.TestCase):
            def test_value(self):
                with self.subTest(value=1):self.fail('synthetic subtest failure')
        report,events,errors=self.execute([Sub('test_value')])
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(events[0][1],'failure')
        self.assertIn('synthetic subtest failure',errors)

    def test_missing_actual_case_refuses_a_successful_partial_run(self):
        case=self.good()
        report,events,unused=self.execute([case],Counter([case.id(),'unselected.missing.case']))
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(len(events),1)

    def test_duplicate_actual_case_refuses_an_unchanged_declared_inventory(self):
        left,right=self.good(),self.good()
        report,events,unused=self.execute([left,right],Counter([left.id()]))
        self.assertEqual(report['outcome'],'FAIL')
        self.assertEqual(len(events),2)

    def test_actual_module_discovery_partitions_the_complete_inventory(self):
        unused,complete,plan=shard.selection(ROOT,'all')
        combined=Counter();files=[];digests=set()
        for index in range(4):
            unused,selected,value=shard.selection(ROOT,str(index))
            combined.update(selected);files.extend(value['modules']);digests.add(value['assignment_sha256'])
            self.assertEqual(value['complete_counter_sha256'],plan['complete_counter_sha256'])
            self.assertEqual(value['test_source_sha256'],plan['test_source_sha256'])
        self.assertEqual(combined,complete)
        self.assertEqual(len(files),len(set(files)))
        self.assertEqual(set(files),set(plan['modules']))
        self.assertEqual(len(digests),1)

    def test_optimized_entry_refuses_before_any_discovery(self):
        result=subprocess.run([sys.executable,'-B','-O','scripts/run_offline_shard.py','--plan'],
            cwd=ROOT,capture_output=True,check=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'offline regression requires assertions enabled',result.stderr)
        self.assertNotIn(b'ImportError',result.stderr)
