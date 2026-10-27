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
# Scheduling hints from all four OS/Python profiles in run 40429778558, attempt 1.
# Source commit: 656b735a1f679ffe04e6e82d7a3419d02996b6d0.
# Values are ceiling(mean(module case seconds / profile case seconds) * 1000000).
# Case clocks exclude class setup and do not predict future wall time.
# Every discovered module still runs, including modules without a hint.
WEIGHTS={
    'test_artifact_batch_reader.py':381,
    'test_artifact_exchange.py':2007,
    'test_artifact_hygiene.py':199,
    'test_artifact_prefixes.py':120,
    'test_authentication.py':18,
    'test_authentication_pins.py':2496,
    'test_authentication_pins_crash.py':354,
    'test_authority_contract.py':15920,
    'test_build_inputs.py':2492,
    'test_cargo_resolution.py':207,
    'test_completion.py':18514,
    'test_completion_crash.py':16017,
    'test_completion_journal.py':30562,
    'test_completion_reconciliation.py':9872,
    'test_current_authority_contract.py':1566,
    'test_custody_entry_model.py':600,
    'test_demo_scalar_exposure.py':74,
    'test_dependency_contents.py':1471,
    'test_enrollment_contract.py':3637,
    'test_enrollment_signature.py':2512,
    'test_exchange_crash.py':4401,
    'test_exchange_journal.py':4023,
    'test_governor_authority_model.py':519,
    'test_governor_contract.py':1630,
    'test_governor_profile.py':1717,
    'test_governor_signature.py':751,
    'test_measured_artifact_verifier.py':122,
    'test_native_nonce_boundary_peer.py':18,
    'test_nom_5cb_command.py':122,
    'test_nom_5cb_evidence.py':9,
    'test_nom_5cb_native.py':9,
    'test_nom_account_authorization.py':224,
    'test_nom_account_context.py':289,
    'test_nom_account_history.py':856,
    'test_nom_account_pool.py':926,
    'test_nom_anchor_lifecycle.py':50186,
    'test_nom_anchor_sqlite_capture.py':1,
    'test_nom_anchor_sqlite_comparison.py':1,
    'test_nom_anchor_sqlite_engine.py':257,
    'test_nom_anchor_sqlite_evidence.py':9,
    'test_nom_anchor_sqlite_material.py':1,
    'test_nom_anchor_sqlite_review.py':135,
    'test_nom_anchor_transition_journal.py':69648,
    'test_nom_authority_contract.py':193,
    'test_nom_authority_model.py':28,
    'test_nom_batched_rollback.py':133,
    'test_nom_bilateral_graph.py':160,
    'test_nom_capsule.py':733,
    'test_nom_capsule_continuity.py':1396,
    'test_nom_capsule_continuity_local_reuse.py':767,
    'test_nom_capsule_query.py':925,
    'test_nom_capsule_query_local_reuse.py':146,
    'test_nom_checkpoint_discovery.py':96392,
    'test_nom_checkpoint_history_reuse.py':8363,
    'test_nom_checkpoint_protocol.py':51338,
    'test_nom_checkpoint_read_ordering.py':88395,
    'test_nom_checkpoint_response.py':31200,
    'test_nom_content_cap.py':252,
    'test_nom_created_funding.py':14,
    'test_nom_current_admission.py':3819,
    'test_nom_dev_5a2593.py':18692,
    'test_nom_dev_5a2593_legacy.py':21066,
    'test_nom_dev_5a2593_reclaim.py':652,
    'test_nom_dev_5a2593_source.py':7,
    'test_nom_dev_5cb.py':32833,
    'test_nom_dev_661b5ef.py':19880,
    'test_nom_dev_661b5ef_legacy.py':27373,
    'test_nom_dev_661b5ef_reclaim.py':651,
    'test_nom_dev_661b5ef_runtime.py':205,
    'test_nom_dev_661b5ef_source.py':8,
    'test_nom_dev_abi_boundary.py':160,
    'test_nom_dev_ac16bfd.py':19433,
    'test_nom_dev_ac16bfd_legacy.py':18950,
    'test_nom_dev_ac16bfd_reclaim.py':737,
    'test_nom_dev_ac16bfd_runtime.py':199,
    'test_nom_dev_ac16bfd_source.py':10,
    'test_nom_dev_admission.py':5125,
    'test_nom_dev_rebase.py':1229,
    'test_nom_dev_receive_data.py':160,
    'test_nom_dev_send_caller.py':166,
    'test_nom_disclosure_timeout.py':221,
    'test_nom_embedded_argument_pricing.py':124,
    'test_nom_evidence_openings.py':334,
    'test_nom_journal_hold.py':448,
    'test_nom_keyless_supervisor.py':99,
    'test_nom_momentum.py':9,
    'test_nom_momentum_admission.py':77,
    'test_nom_momentum_core_evidence.py':11,
    'test_nom_multi_rollback.py':160,
    'test_nom_native_command.py':136,
    'test_nom_observation.py':11,
    'test_nom_observation_core_evidence.py':13,
    'test_nom_partial_custody.py':3574,
    'test_nom_pool_dependencies.py':98,
    'test_nom_pool_forks.py':887,
    'test_nom_price_account_order.py':291,
    'test_nom_price_recovery_hold.py':102,
    'test_nom_process_death.py':359,
    'test_nom_receive_commit.py':154,
    'test_nom_receive_credit.py':190,
    'test_nom_receive_point_types.py':432,
    'test_nom_receive_sequencing.py':80,
    'test_nom_recovery.py':168,
    'test_nom_recovery_cuts.py':155,
    'test_nom_recovery_delta_subject.py':4007,
    'test_nom_recovery_snapshot.py':299,
    'test_nom_retention.py':627,
    'test_nom_retention_crash.py':303,
    'test_nom_rollback_refusal.py':253,
    'test_nom_rpc_quotes.py':508,
    'test_nom_signed_io_faults.py':574,
    'test_nom_signed_originals.py':16,
    'test_nom_signed_price_hold.py':37,
    'test_nom_signed_process_cuts.py':562,
    'test_nom_signed_recovery.py':223,
    'test_nom_source_checkpoint.py':7971,
    'test_nom_strict_open.py':619,
    'test_nom_supervisor_plasma.py':179,
    'test_nom_uncertainty.py':11076,
    'test_nom_vm_openings.py':604,
    'test_nom_vm_path.py':12,
    'test_nom_wire.py':4,
    'test_nom_wire_core_evidence.py':3,
    'test_nom_worker_profile.py':69,
    'test_nom_worker_subject.py':766,
    'test_nonce_exchange.py':57,
    'test_nonce_grant_copy_model.py':137,
    'test_nonce_intent.py':717,
    'test_nonce_interop.py':123,
    'test_nonce_invocation_model.py':171,
    'test_observation_authority_model.py':1592,
    'test_observation_enrollment_model.py':36189,
    'test_observation_evidence.py':14678,
    'test_observation_records.py':4762,
    'test_observation_resource_store.py':4140,
    'test_observation_resource_store_crash.py':14498,
    'test_observation_resource_store_faults.py':17674,
    'test_observation_resource_store_native.py':1713,
    'test_observation_resource_store_restore.py':5057,
    'test_observation_review_subject.py':3435,
    'test_observation_store.py':10354,
    'test_observation_store_crash.py':5136,
    'test_observation_verifier.py':7269,
    'test_offline_shard_supervisor.py':387,
    'test_offline_shards.py':475,
    'test_original_consumer_retention_model.py':482,
    'test_original_read_contract.py':121,
    'test_original_read_provenance_model.py':1243,
    'test_original_read_response.py':568,
    'test_original_read_snapshot.py':279,
    'test_original_read_snapshot_response.py':392,
    'test_original_snapshot_opening.py':737,
    'test_original_snapshot_prefix.py':707,
    'test_original_snapshot_prefix_response.py':686,
    'test_original_witness_lifecycle.py':2092,
    'test_original_witness_store.py':5929,
    'test_partial_journal_boundary.py':2448,
    'test_policy_effect_actor_cleanup.py':11,
    'test_policy_effect_actor_constructor.py':25,
    'test_policy_effect_buffered_shutdown.py':246,
    'test_policy_effect_compound_faults.py':17,
    'test_policy_effect_constructor_paths.py':23,
    'test_policy_effect_constructor_preflight.py':21,
    'test_policy_effect_contention.py':2090,
    'test_policy_effect_diagnostics.py':104,
    'test_policy_effect_native_observation.py':116,
    'test_policy_effect_output_loss.py':57,
    'test_policy_effect_reservation_begin.py':32,
    'test_policy_effect_reservation_disposal.py':33,
    'test_policy_effect_reservation_refusals.py':21,
    'test_policy_effect_reservation_rollback.py':33,
    'test_policy_effect_reservation_secondary_rollback.py':66,
    'test_policy_effect_rollback_observation.py':102,
    'test_policy_effect_store.py':860,
    'test_policy_source_use_model.py':1247,
    'test_pr138_compatibility.py':2,
    'test_prepare_nom_5cb.py':3,
    'test_public_adaptor_edges.py':310,
    'test_public_collection_consumer.py':239,
    'test_public_nonce_edges.py':1568,
    'test_public_nonce_intent_corpus.py':30,
    'test_public_observation_model.py':11313,
    'test_public_signature_candidate.py':3196,
    'test_public_worker.py':627,
    'test_reconciliation_crash.py':13894,
    'test_reconciliation_journal.py':12890,
    'test_recovery_admission_model.py':141,
    'test_recovery_budget.py':10016,
    'test_recovery_budget_crash.py':8644,
    'test_recovery_model_journal.py':22055,
    'test_recovery_reserve_model.py':1273,
    'test_sealed_artifact_verifier.py':5,
    'test_selected_cleanup.py':78,
    'test_selected_cleanup_noop.py':12,
    'test_selected_cursor_admission_mutation.py':3,
    'test_selected_cursor_attempt_native.py':10,
    'test_selected_cursor_attempt_owner.py':4,
    'test_selected_cursor_owner.py':14,
    'test_selected_cursor_preclose_escape_native.py':11,
    'test_selected_cursor_retention_escape_native.py':12,
    'test_selected_native_release.py':8,
    'test_selected_statement_cache.py':6,
    'test_session_crash.py':1035,
    'test_session_journal.py':379,
    'test_session_transcript.py':17,
    'test_source_admin_command.py':83,
    'test_source_read_ordering.py':2495,
    'test_source_response.py':818,
    'test_source_root_roles.py':14,
    'test_swap_model.py':126,
    'test_witness_review_subject.py':5255,
    'test_worker_build.py':216,
    'test_worker_c_debug.py':97,
    'test_worker_c_symbols.py':229,
    'test_worker_debug_names.py':136,
    'test_worker_elf_metadata.py':98,
    'test_worker_leases.py':4782,
    'test_worker_macho_prefix.py':110,
    'test_worker_pool.py':2878,
    'test_worker_pool_native.py':2740,
    'test_worker_remapping.py':56,
    'test_worker_resources.py':479,
    'test_worker_resources_native.py':438,
    'test_worker_review_subject.py':8158,
    'test_worker_sections.py':118,
    'test_worker_symbols.py':131,
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
