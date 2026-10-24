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
# Scheduling hints from all four OS/Python profiles in run 39997915069, attempt 1.
# Source commit: 88ae2fcf219c8bd6154d77c2068b6c5c2ad7b867.
# Values are ceiling(mean(module case seconds / profile case seconds) * 1000000).
# Case clocks exclude class setup and do not predict future wall time.
# Every discovered module still runs, including modules without a hint.
WEIGHTS={
    'test_artifact_batch_reader.py':339,
    'test_artifact_exchange.py':2329,
    'test_artifact_hygiene.py':148,
    'test_artifact_prefixes.py':226,
    'test_authentication.py':17,
    'test_authentication_pins.py':2797,
    'test_authentication_pins_crash.py':422,
    'test_authority_contract.py':20286,
    'test_build_inputs.py':3016,
    'test_cargo_resolution.py':229,
    'test_completion.py':20943,
    'test_completion_crash.py':14664,
    'test_completion_journal.py':38397,
    'test_completion_reconciliation.py':8649,
    'test_current_authority_contract.py':1542,
    'test_custody_entry_model.py':733,
    'test_demo_scalar_exposure.py':115,
    'test_dependency_contents.py':2189,
    'test_enrollment_contract.py':4695,
    'test_enrollment_signature.py':2566,
    'test_exchange_crash.py':5217,
    'test_exchange_journal.py':6306,
    'test_governor_authority_model.py':480,
    'test_governor_contract.py':3060,
    'test_governor_profile.py':1581,
    'test_governor_signature.py':859,
    'test_measured_artifact_verifier.py':102,
    'test_native_nonce_boundary_peer.py':24,
    'test_nom_5cb_command.py':172,
    'test_nom_5cb_evidence.py':17,
    'test_nom_5cb_native.py':12,
    'test_nom_account_authorization.py':278,
    'test_nom_account_context.py':231,
    'test_nom_account_history.py':1187,
    'test_nom_account_pool.py':1201,
    'test_nom_anchor_lifecycle.py':62208,
    'test_nom_anchor_sqlite_capture.py':2,
    'test_nom_anchor_sqlite_comparison.py':1,
    'test_nom_anchor_sqlite_engine.py':461,
    'test_nom_anchor_sqlite_evidence.py':13,
    'test_nom_anchor_sqlite_material.py':1,
    'test_nom_anchor_sqlite_review.py':140,
    'test_nom_anchor_transition_journal.py':88633,
    'test_nom_authority_contract.py':164,
    'test_nom_authority_model.py':34,
    'test_nom_batched_rollback.py':129,
    'test_nom_bilateral_graph.py':195,
    'test_nom_capsule.py':1066,
    'test_nom_capsule_continuity.py':1158,
    'test_nom_capsule_continuity_local_reuse.py':777,
    'test_nom_capsule_query.py':1124,
    'test_nom_capsule_query_local_reuse.py':173,
    'test_nom_checkpoint_discovery.py':110365,
    'test_nom_checkpoint_history_reuse.py':9823,
    'test_nom_checkpoint_protocol.py':59852,
    'test_nom_checkpoint_read_ordering.py':91337,
    'test_nom_checkpoint_response.py':31972,
    'test_nom_content_cap.py':292,
    'test_nom_created_funding.py':15,
    'test_nom_current_admission.py':4402,
    'test_nom_dev_5cb.py':35789,
    'test_nom_dev_abi_boundary.py':235,
    'test_nom_dev_admission.py':5703,
    'test_nom_dev_rebase.py':1726,
    'test_nom_dev_receive_data.py':265,
    'test_nom_dev_send_caller.py':197,
    'test_nom_disclosure_timeout.py':191,
    'test_nom_evidence_openings.py':334,
    'test_nom_journal_hold.py':495,
    'test_nom_keyless_supervisor.py':131,
    'test_nom_momentum.py':10,
    'test_nom_momentum_admission.py':90,
    'test_nom_momentum_core_evidence.py':10,
    'test_nom_multi_rollback.py':199,
    'test_nom_native_command.py':154,
    'test_nom_observation.py':11,
    'test_nom_observation_core_evidence.py':14,
    'test_nom_partial_custody.py':3865,
    'test_nom_pool_dependencies.py':112,
    'test_nom_pool_forks.py':948,
    'test_nom_price_account_order.py':334,
    'test_nom_price_recovery_hold.py':114,
    'test_nom_process_death.py':384,
    'test_nom_receive_commit.py':163,
    'test_nom_receive_credit.py':201,
    'test_nom_receive_point_types.py':620,
    'test_nom_receive_sequencing.py':99,
    'test_nom_recovery.py':197,
    'test_nom_recovery_cuts.py':170,
    'test_nom_recovery_delta_subject.py':4760,
    'test_nom_recovery_snapshot.py':478,
    'test_nom_retention.py':921,
    'test_nom_retention_crash.py':332,
    'test_nom_rollback_refusal.py':349,
    'test_nom_rpc_quotes.py':538,
    'test_nom_signed_io_faults.py':477,
    'test_nom_signed_originals.py':18,
    'test_nom_signed_price_hold.py':216,
    'test_nom_signed_process_cuts.py':718,
    'test_nom_signed_recovery.py':432,
    'test_nom_source_checkpoint.py':8770,
    'test_nom_strict_open.py':613,
    'test_nom_supervisor_plasma.py':229,
    'test_nom_uncertainty.py':12637,
    'test_nom_vm_openings.py':678,
    'test_nom_vm_path.py':13,
    'test_nom_wire.py':5,
    'test_nom_wire_core_evidence.py':10,
    'test_nom_worker_profile.py':83,
    'test_nom_worker_subject.py':709,
    'test_nonce_exchange.py':69,
    'test_nonce_grant_copy_model.py':167,
    'test_nonce_intent.py':709,
    'test_nonce_interop.py':145,
    'test_nonce_invocation_model.py':194,
    'test_observation_authority_model.py':1906,
    'test_observation_enrollment_model.py':37860,
    'test_observation_evidence.py':17584,
    'test_observation_records.py':5969,
    'test_observation_resource_store.py':5414,
    'test_observation_resource_store_crash.py':14905,
    'test_observation_resource_store_faults.py':24049,
    'test_observation_resource_store_native.py':1830,
    'test_observation_resource_store_restore.py':5797,
    'test_observation_review_subject.py':3052,
    'test_observation_store.py':11562,
    'test_observation_store_crash.py':5243,
    'test_observation_verifier.py':9526,
    'test_offline_shard_supervisor.py':436,
    'test_offline_shards.py':518,
    'test_original_consumer_retention_model.py':601,
    'test_original_read_contract.py':179,
    'test_original_read_provenance_model.py':1351,
    'test_original_read_response.py':582,
    'test_original_read_snapshot.py':426,
    'test_original_read_snapshot_response.py':477,
    'test_original_snapshot_opening.py':811,
    'test_original_snapshot_prefix.py':956,
    'test_original_snapshot_prefix_response.py':917,
    'test_original_witness_lifecycle.py':2479,
    'test_original_witness_store.py':8044,
    'test_partial_journal_boundary.py':2804,
    'test_policy_effect_actor_cleanup.py':29,
    'test_policy_effect_actor_constructor.py':34,
    'test_policy_effect_buffered_shutdown.py':280,
    'test_policy_effect_compound_faults.py':46,
    'test_policy_effect_constructor_paths.py':46,
    'test_policy_effect_constructor_preflight.py':32,
    'test_policy_effect_contention.py':2636,
    'test_policy_effect_diagnostics.py':127,
    'test_policy_effect_native_observation.py':150,
    'test_policy_effect_output_loss.py':102,
    'test_policy_effect_reservation_begin.py':41,
    'test_policy_effect_reservation_disposal.py':49,
    'test_policy_effect_reservation_refusals.py':31,
    'test_policy_effect_reservation_rollback.py':108,
    'test_policy_effect_reservation_secondary_rollback.py':77,
    'test_policy_effect_rollback_observation.py':113,
    'test_policy_effect_store.py':979,
    'test_policy_source_use_model.py':1196,
    'test_pr138_compatibility.py':3,
    'test_prepare_nom_5cb.py':4,
    'test_public_adaptor_edges.py':296,
    'test_public_collection_consumer.py':377,
    'test_public_nonce_edges.py':1594,
    'test_public_nonce_intent_corpus.py':33,
    'test_public_observation_model.py':13868,
    'test_public_signature_candidate.py':3229,
    'test_public_worker.py':715,
    'test_reconciliation_crash.py':14241,
    'test_reconciliation_journal.py':12807,
    'test_recovery_admission_model.py':153,
    'test_recovery_budget.py':13053,
    'test_recovery_budget_crash.py':9671,
    'test_recovery_model_journal.py':22554,
    'test_recovery_reserve_model.py':1832,
    'test_sealed_artifact_verifier.py':7,
    'test_selected_cleanup.py':105,
    'test_selected_cleanup_noop.py':15,
    'test_selected_cursor_admission_mutation.py':5,
    'test_selected_cursor_attempt_native.py':14,
    'test_selected_cursor_attempt_owner.py':5,
    'test_selected_cursor_owner.py':16,
    'test_selected_cursor_preclose_escape_native.py':16,
    'test_selected_cursor_retention_escape_native.py':24,
    'test_selected_native_release.py':25,
    'test_selected_statement_cache.py':6,
    'test_session_crash.py':1340,
    'test_session_journal.py':639,
    'test_session_transcript.py':19,
    'test_source_admin_command.py':101,
    'test_source_read_ordering.py':2561,
    'test_source_response.py':838,
    'test_source_root_roles.py':15,
    'test_swap_model.py':136,
    'test_witness_review_subject.py':6894,
    'test_worker_build.py':284,
    'test_worker_c_debug.py':125,
    'test_worker_c_symbols.py':311,
    'test_worker_debug_names.py':202,
    'test_worker_elf_metadata.py':119,
    'test_worker_leases.py':5550,
    'test_worker_macho_prefix.py':122,
    'test_worker_pool.py':3064,
    'test_worker_pool_native.py':3066,
    'test_worker_remapping.py':88,
    'test_worker_resources.py':476,
    'test_worker_resources_native.py':548,
    'test_worker_review_subject.py':10864,
    'test_worker_sections.py':175,
    'test_worker_symbols.py':152,
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
