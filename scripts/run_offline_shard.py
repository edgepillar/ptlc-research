"""Run an exact module partition; no test-result cache or relaxed assertions."""
import sys

if sys.flags.optimize:
    raise SystemExit('offline regression requires assertions enabled')

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import stat
import time
import unittest
import warnings

ROOT=Path(__file__).resolve().parents[1]
SHARDS=4
CASE_PREFIX='PTLC_CASE='
RESULT_PREFIX='PTLC_SHARD_RESULT='
# Scheduling hints from retained run 39129729442, not qualification results.
# Every unmeasured module still runs. No historical test file is changed.
WEIGHTS={
    'test_nom_anchor_transition_journal.py':1723,
    'test_nom_checkpoint_read_ordering.py':1606,
    'test_nom_checkpoint_discovery.py':1453,
    'test_nom_anchor_lifecycle.py':1158,
    'test_nom_checkpoint_protocol.py':606,
    'test_nom_checkpoint_response.py':590,
    'test_observation_enrollment_model.py':160,
    'test_completion_journal.py':154,
    'test_nom_source_checkpoint.py':99,
    'test_recovery_model_journal.py':99,
}


def require(value):
    if not value:raise ValueError('offline shard selection refused')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()


def counter_digest(value):
    require(type(value) is Counter and all(type(key) is str and type(n) is int and n>0 for key,n in value.items()))
    return digest(sorted(value.items()))


def partition(names,weights=None,shards=SHARDS):
    require(type(names) in (list,tuple) and names and len(names)==len(set(names)))
    require(all(type(name) is str and re.fullmatch(r'test_[A-Za-z0-9_]+\.py',name) for name in names))
    require(type(shards) is int and 1<=shards<=8)
    weights=WEIGHTS if weights is None else weights
    require(type(weights) is dict and all(type(n) is int and 1<=n<=1000000 for n in weights.values()))
    loads=[0]*shards;selected={}
    for name in sorted(names,key=lambda name:(-weights.get(name,1),name)):
        bucket=min(range(shards),key=lambda index:(loads[index],index))
        selected[name]=bucket;loads[bucket]+=weights.get(name,1)
    return selected


def cases(suite):
    if isinstance(suite,unittest.TestSuite):
        for child in suite:yield from cases(child)
    else:
        require(isinstance(suite,unittest.TestCase))
        yield suite


def selection(root,shard):
    require(shard=='all' or type(shard) is str and shard in tuple(str(i) for i in range(SHARDS)))
    directory=root/'tests'
    files=sorted(directory.glob('test_*.py'))
    require(files and all(path.parent==directory for path in directory.rglob('test_*.py')))
    source={}
    for path in files:
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=2*1024**2)
        source[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
    assigned=partition(list(source))
    for path in (root,directory):
        if str(path) not in sys.path:sys.path.insert(0,str(path))
    loader=unittest.TestLoader();chosen=unittest.TestSuite()
    complete=Counter();expected=Counter();modules=[]
    for path in files:
        suite=loader.discover(str(directory),pattern=path.name,top_level_dir=str(directory))
        require(not loader.errors)
        identities=[]
        for case in cases(suite):
            require(not isinstance(case,unittest.loader._FailedTest))
            identity=case.id()
            require(type(identity) is str and identity.isascii() and 0<len(identity)<=1024)
            identities.append(identity)
        complete.update(identities)
        if shard=='all' or assigned[path.name]==int(shard):
            # Preserve each discovered module suite and its setup/teardown behavior.
            chosen.addTest(suite);expected.update(identities);modules.append(path.name)
    require(complete and expected)
    plan=dict(schema='ptlc-offline-module-shard-plan-v1',shard=shard,shards=SHARDS,
        complete_cases=sum(complete.values()),selected_cases=sum(expected.values()),
        complete_counter_sha256=counter_digest(complete),selected_counter_sha256=counter_digest(expected),
        test_source_sha256=digest(source),assignment_sha256=digest(assigned),modules=modules)
    return chosen,expected,plan


class RecordedResult(unittest.TextTestResult):
    """Keep real unittest outcomes and emit one bounded final event per case."""
    def __init__(self,*args,case_stream=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.case_stream=sys.stdout if case_stream is None else case_stream
        self.finished=[];self.case_seconds=Counter()
        self._status=None;self._started=None
    def startTest(self,test):
        super().startTest(test);self._status=None;self._started=time.monotonic()
    def addSuccess(self,test):super().addSuccess(test);self._status='ok'
    def addError(self,test,error):super().addError(test,error);self._status='error'
    def addFailure(self,test,error):super().addFailure(test,error);self._status='failure'
    def addSkip(self,test,reason):super().addSkip(test,reason);self._status='skip'
    def addExpectedFailure(self,test,error):super().addExpectedFailure(test,error);self._status='expected-failure'
    def addUnexpectedSuccess(self,test):super().addUnexpectedSuccess(test);self._status='unexpected-success'
    def addSubTest(self,test,subtest,error):
        super().addSubTest(test,subtest,error)
        if error is not None:self._status='failure'
    def stopTest(self,test):
        super().stopTest(test)
        identity=test.id();status=self._status or 'unfinished'
        require(type(identity) is str and identity.isascii() and len(identity)<=1024)
        self.finished.append((identity,status))
        if self._started is not None:self.case_seconds[identity.split('.')[0]]+=time.monotonic()-self._started
        wire=CASE_PREFIX+json.dumps([identity,status],separators=(',',':'))+'\n'
        self.case_stream.write(wire);self.case_stream.flush()


def run(suite,expected,plan,*,case_stream=None,error_stream=None):
    require(type(expected) is Counter and sum(expected.values())==plan['selected_cases'])
    def result(*args,**kwargs):return RecordedResult(*args,case_stream=case_stream,**kwargs)
    start=time.monotonic()
    actual=unittest.TextTestRunner(stream=error_stream,verbosity=1,resultclass=result).run(suite)
    completed=Counter(identity for identity,status in actual.finished)
    statuses=Counter(status for identity,status in actual.finished)
    good=(actual.wasSuccessful() and actual.testsRun==sum(expected.values()) and completed==expected
        and statuses==Counter(ok=sum(expected.values())))
    report=dict(schema='ptlc-offline-module-shard-result-v1',outcome='PASS' if good else 'FAIL',
        plan=plan,actual_cases=actual.testsRun,finished_cases=len(actual.finished),statuses=dict(statuses),
        actual_counter_sha256=counter_digest(completed) if completed else None,
        elapsed_seconds=time.monotonic()-start,case_seconds=dict(actual.case_seconds),
        timing_scope='CASE CLOCKS EXCLUDE CLASS SETUP; ELAPSED CLOCK INCLUDES THE COMPLETE RUN',
        application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shard',choices=('all','0','1','2','3'),default='all')
    parser.add_argument('--plan',action='store_true',help='Discover exact inventory without running test methods')
    args=parser.parse_args()
    suite,expected,plan=selection(ROOT,args.shard)
    if args.plan:
        print(json.dumps(plan,sort_keys=True));return
    warnings.simplefilter('error',ResourceWarning)
    report=run(suite,expected,plan)
    print(RESULT_PREFIX+json.dumps(report,sort_keys=True))
    if report['outcome']!='PASS':raise SystemExit(1)


if __name__=='__main__':main()
