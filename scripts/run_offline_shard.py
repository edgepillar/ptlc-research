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
# Scheduling hints from all four OS/Python profiles in run 41767029820, attempt 1.
# Source commit: 9e3fe6396c9fd761446b88436241c1565fef06b0.
# Values are ceiling(mean(module case seconds / profile case seconds) * 1000000).
# Case clocks exclude class setup and do not predict future wall time.
# Every discovered module still runs, including modules without a hint.
WEIGHTS={
    'test_artifact_batch_reader.py':290,
    'test_artifact_exchange.py':2114,
    'test_artifact_hygiene.py':147,
    'test_artifact_prefixes.py':90,
    'test_authentication.py':15,
    'test_authentication_pins.py':2677,
    'test_authentication_pins_crash.py':308,
    'test_authority_contract.py':18542,
    'test_build_inputs.py':3374,
    'test_cargo_resolution.py':207,
    'test_client_agreement.py':5,
    'test_client_presignature.py':18,
    'test_completion.py':15463,
    'test_completion_crash.py':13225,
    'test_completion_journal.py':35531,
    'test_completion_reconciliation.py':7930,
    'test_current_authority_contract.py':1499,
    'test_custody_entry_model.py':541,
    'test_demo_scalar_exposure.py':75,
    'test_dependency_contents.py':2188,
    'test_enrollment_contract.py':4581,
    'test_enrollment_signature.py':2449,
    'test_exchange_crash.py':4065,
    'test_exchange_journal.py':4488,
    'test_governor_authority_model.py':409,
    'test_governor_contract.py':1991,
    'test_governor_profile.py':1580,
    'test_governor_signature.py':719,
    'test_measured_artifact_verifier.py':96,
    'test_native_nonce_boundary_peer.py':17,
    'test_nom_5cb_command.py':78,
    'test_nom_5cb_evidence.py':8,
    'test_nom_5cb_native.py':7,
    'test_nom_77ba_retention.py':6356,
    'test_nom_account_authorization.py':228,
    'test_nom_account_context.py':180,
    'test_nom_account_history.py':920,
    'test_nom_account_pool.py':972,
    'test_nom_anchor_lifecycle.py':44469,
    'test_nom_anchor_sqlite_capture.py':2,
    'test_nom_anchor_sqlite_comparison.py':1,
    'test_nom_anchor_sqlite_engine.py':132,
    'test_nom_anchor_sqlite_evidence.py':8,
    'test_nom_anchor_sqlite_material.py':1,
    'test_nom_anchor_sqlite_review.py':92,
    'test_nom_anchor_transition_journal.py':73030,
    'test_nom_authority_contract.py':127,
    'test_nom_authority_model.py':32,
    'test_nom_batched_rollback.py':101,
    'test_nom_bilateral_graph.py':161,
    'test_nom_capsule.py':733,
    'test_nom_capsule_continuity.py':972,
    'test_nom_capsule_continuity_local_reuse.py':595,
    'test_nom_capsule_query.py':868,
    'test_nom_capsule_query_local_reuse.py':140,
    'test_nom_checkpoint_discovery.py':80840,
    'test_nom_checkpoint_history_reuse.py':7822,
    'test_nom_checkpoint_protocol.py':44370,
    'test_nom_checkpoint_read_ordering.py':75271,
    'test_nom_checkpoint_response.py':27217,
    'test_nom_content_cap.py':236,
    'test_nom_created_funding.py':11,
    'test_nom_current_admission.py':3109,
    'test_nom_dev_18c048a.py':99889,
    'test_nom_dev_18c048a_source.py':30,
    'test_nom_dev_5a2593.py':15667,
    'test_nom_dev_5a2593_legacy.py':17679,
    'test_nom_dev_5a2593_reclaim.py':632,
    'test_nom_dev_5a2593_source.py':7,
    'test_nom_dev_5cb.py':26790,
    'test_nom_dev_661b5ef.py':9895,
    'test_nom_dev_661b5ef_legacy.py':23766,
    'test_nom_dev_661b5ef_reclaim.py':690,
    'test_nom_dev_661b5ef_runtime.py':190,
    'test_nom_dev_661b5ef_source.py':5,
    'test_nom_dev_77ba9c7.py':7915,
    'test_nom_dev_77ba9c7_source.py':7,
    'test_nom_dev_821bdd2.py':14319,
    'test_nom_dev_821bdd2_source.py':11,
    'test_nom_dev_abi_boundary.py':165,
    'test_nom_dev_ac16bfd.py':16043,
    'test_nom_dev_ac16bfd_legacy.py':17722,
    'test_nom_dev_ac16bfd_reclaim.py':386,
    'test_nom_dev_ac16bfd_runtime.py':178,
    'test_nom_dev_ac16bfd_source.py':8,
    'test_nom_dev_admission.py':4171,
    'test_nom_dev_rebase.py':1154,
    'test_nom_dev_receive_data.py':105,
    'test_nom_dev_send_caller.py':171,
    'test_nom_disclosure_timeout.py':53,
    'test_nom_embedded_argument_pricing.py':128,
    'test_nom_evidence_openings.py':276,
    'test_nom_fee_original_boundary.py':45,
    'test_nom_journal_hold.py':351,
    'test_nom_keyless_supervisor.py':101,
    'test_nom_momentum.py':9,
    'test_nom_momentum_admission.py':72,
    'test_nom_momentum_core_evidence.py':7,
    'test_nom_multi_rollback.py':125,
    'test_nom_native_command.py':68,
    'test_nom_observation.py':8,
    'test_nom_observation_core_evidence.py':8,
    'test_nom_partial_custody.py':1825,
    'test_nom_pool_dependencies.py':47,
    'test_nom_pool_forks.py':775,
    'test_nom_price_account_order.py':230,
    'test_nom_price_recovery_hold.py':85,
    'test_nom_process_death.py':286,
    'test_nom_receive_commit.py':120,
    'test_nom_receive_credit.py':97,
    'test_nom_receive_point_types.py':457,
    'test_nom_receive_sequencing.py':76,
    'test_nom_recovery.py':141,
    'test_nom_recovery_cuts.py':115,
    'test_nom_recovery_delta_subject.py':4860,
    'test_nom_recovery_snapshot.py':99,
    'test_nom_retention.py':548,
    'test_nom_retention_crash.py':143,
    'test_nom_rollback_refusal.py':258,
    'test_nom_rpc_quotes.py':473,
    'test_nom_signed_io_faults.py':215,
    'test_nom_signed_originals.py':15,
    'test_nom_signed_price_hold.py':31,
    'test_nom_signed_process_cuts.py':337,
    'test_nom_signed_recovery.py':153,
    'test_nom_source_checkpoint.py':7085,
    'test_nom_strict_open.py':485,
    'test_nom_supervisor_plasma.py':180,
    'test_nom_uncertainty.py':9460,
    'test_nom_vm_openings.py':522,
    'test_nom_vm_path.py':11,
    'test_nom_wire.py':3,
    'test_nom_wire_core_evidence.py':2,
    'test_nom_worker_profile.py':65,
    'test_nom_worker_subject.py':893,
    'test_nonce_exchange.py':35,
    'test_nonce_grant_copy_model.py':111,
    'test_nonce_intent.py':685,
    'test_nonce_interop.py':105,
    'test_nonce_invocation_model.py':130,
    'test_observation_authority_model.py':1433,
    'test_observation_enrollment_model.py':31744,
    'test_observation_evidence.py':14430,
    'test_observation_records.py':5625,
    'test_observation_resource_store.py':4867,
    'test_observation_resource_store_crash.py':6845,
    'test_observation_resource_store_faults.py':18977,
    'test_observation_resource_store_native.py':1204,
    'test_observation_resource_store_restore.py':4609,
    'test_observation_review_subject.py':2289,
    'test_observation_store.py':10047,
    'test_observation_store_crash.py':3173,
    'test_observation_verifier.py':5902,
    'test_offline_ci_profile_driver.py':650,
    'test_offline_ci_profile_transport.py':10,
    'test_offline_shard_supervisor.py':200,
    'test_offline_shards.py':258,
    'test_original_consumer_retention_model.py':251,
    'test_original_read_contract.py':143,
    'test_original_read_provenance_model.py':1121,
    'test_original_read_response.py':548,
    'test_original_read_snapshot.py':162,
    'test_original_read_snapshot_response.py':378,
    'test_original_snapshot_opening.py':641,
    'test_original_snapshot_prefix.py':350,
    'test_original_snapshot_prefix_response.py':817,
    'test_original_witness_lifecycle.py':1580,
    'test_original_witness_store.py':5562,
    'test_partial_journal_boundary.py':1311,
    'test_policy_effect_actor_cleanup.py':6,
    'test_policy_effect_actor_constructor.py':27,
    'test_policy_effect_buffered_shutdown.py':203,
    'test_policy_effect_compound_faults.py':8,
    'test_policy_effect_constructor_paths.py':31,
    'test_policy_effect_constructor_preflight.py':11,
    'test_policy_effect_contention.py':1301,
    'test_policy_effect_diagnostics.py':55,
    'test_policy_effect_native_observation.py':72,
    'test_policy_effect_output_loss.py':31,
    'test_policy_effect_reservation_begin.py':30,
    'test_policy_effect_reservation_disposal.py':29,
    'test_policy_effect_reservation_refusals.py':18,
    'test_policy_effect_reservation_rollback.py':30,
    'test_policy_effect_reservation_secondary_rollback.py':51,
    'test_policy_effect_rollback_observation.py':66,
    'test_policy_effect_store.py':704,
    'test_policy_source_use_model.py':681,
    'test_pr138_compatibility.py':2,
    'test_prepare_nom_5cb.py':2,
    'test_public_adaptor_edges.py':153,
    'test_public_client_ci_scope.py':683,
    'test_public_collection_consumer.py':165,
    'test_public_nonce_edges.py':803,
    'test_public_nonce_intent_corpus.py':15,
    'test_public_observation_model.py':5591,
    'test_public_signature_candidate.py':3200,
    'test_public_worker.py':278,
    'test_reconciliation_crash.py':13000,
    'test_reconciliation_journal.py':11767,
    'test_recovery_admission_model.py':116,
    'test_recovery_budget.py':7204,
    'test_recovery_budget_crash.py':4288,
    'test_recovery_model_journal.py':19699,
    'test_recovery_reserve_model.py':1433,
    'test_reference_client.py':46,
    'test_sealed_artifact_verifier.py':3,
    'test_selected_cleanup.py':66,
    'test_selected_cleanup_noop.py':7,
    'test_selected_cursor_admission_mutation.py':3,
    'test_selected_cursor_attempt_native.py':11,
    'test_selected_cursor_attempt_owner.py':2,
    'test_selected_cursor_owner.py':6,
    'test_selected_cursor_preclose_escape_native.py':9,
    'test_selected_cursor_retention_escape_native.py':8,
    'test_selected_native_release.py':5,
    'test_selected_statement_cache.py':7,
    'test_session_crash.py':650,
    'test_session_journal.py':227,
    'test_session_transcript.py':10,
    'test_source_admin_command.py':41,
    'test_source_read_ordering.py':1708,
    'test_source_response.py':1242,
    'test_source_root_roles.py':8,
    'test_swap_model.py':106,
    'test_witness_review_subject.py':2824,
    'test_worker_build.py':131,
    'test_worker_c_debug.py':59,
    'test_worker_c_symbols.py':241,
    'test_worker_debug_names.py':60,
    'test_worker_elf_metadata.py':95,
    'test_worker_leases.py':2212,
    'test_worker_macho_prefix.py':68,
    'test_worker_pool.py':1952,
    'test_worker_pool_native.py':2411,
    'test_worker_remapping.py':37,
    'test_worker_resources.py':422,
    'test_worker_resources_native.py':224,
    'test_worker_review_subject.py':4471,
    'test_worker_sections.py':57,
    'test_worker_symbols.py':90,
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
