"""Select fresh candidate-source comparisons without upgrading client behavior.

Reference labels and old source subjects retain their identities. This module
plans commands and reads finite data; it opens no compiler, node or wallet.
"""
import copy
import hashlib
import json
from pathlib import Path

from qualification import nom_dev_77ba9c7 as prior
from qualification import nom_dev_821bdd2_source as upstream
from qualification import nom_fee_original_boundary as fee

ROOT = upstream.ROOT
CORE, TREE = upstream.CORE, upstream.TREE
FIXTURE_CORE, FIXTURE_TREE = prior.FIXTURE_CORE, prior.FIXTURE_TREE
earlier, runtime, reference = prior.earlier, prior.runtime, prior.reference
require = earlier.require
MAX_STREAM = prior.MAX_STREAM
MAX_TOTAL = prior.MAX_TOTAL + 4 * MAX_STREAM
PLAN = 'compatibility/nom_dev_821bdd2_plan_v1.json'

ADDED_UPSTREAM = {
    'upstream-per-entity': dict(
        package='vm/embedded/definition',
        source='vm/embedded/definition/per_entity_iteration_test.go',
        parents=(
            'TestGetStakeListByAddressIteratesSubRange',
            'TestGetStakeListByAddressRevokedSkipped',
            'TestGetLiquidityStakeListByAddressIteratesSubRange',
            'TestGetAllPillarVotesIteratesSubRange',
            'TestGetVoteBreakdownAfterSubRangeIteration',
            'TestGetStakeListByAddressEmptyEntity',
            'TestGetStakeListByAddressSharedPrefix',
            'TestGetLiquidityStakeListByAddressSharedPrefix',
            'TestGetLiquidityStakeListByAddressEmptyEntity',
            'TestGetAllPillarVotesEmptyEntity',
            'TestGetAllPillarVotesSharedPrefix')),
    'upstream-final-tally': dict(
        package='vm/embedded/implementation',
        source='vm/embedded/implementation/accelerator_final_tally_test.go',
        parents=tuple('TestAcceleratorFinalTally_' + suffix for suffix in (
            'PostSpork_ExpiredWindow_PassingVotes_Activates',
            'PostSpork_ExpiredWindow_FailingVotes_Closes',
            'PreSpork_ExpiredWindow_ClosesWithoutTally',
            'PostSpork_VoteOnExpiredProject_Rejected',
            'PostSpork_VoteOnNonExpiredProject_Accepted',
            'PostSpork_VoteOnPhaseId_NotAffected',
            'PreSpork_VoteOnExpiredProject_Accepted'))),
}
UPSTREAM = dict(copy.deepcopy(prior.UPSTREAM), **ADDED_UPSTREAM)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identities(unit):
    require(unit in UPSTREAM)
    if unit in prior.UPSTREAM:
        return prior.identities(unit)
    spec = UPSTREAM[unit]
    names = set(spec['parents'])
    if unit == 'upstream-final-tally':
        names.update(parent + '/' + method for parent in spec['parents'][3:]
                     for method in ('VoteByName', 'VoteByProdAddress'))
    require(len(names) == {'upstream-per-entity': 11,
                          'upstream-final-tally': 15}[unit])
    return names


def inputs(root=ROOT):
    description, index = upstream.inputs(root)
    prior.inputs(root)
    require(set(ADDED_UPSTREAM[unit]['source'] for unit in ADDED_UPSTREAM)
            == upstream.ADDED)
    require(len(index) == 523 and len(reference.probes(root, 'all')) == 25)
    require(sum(len(spec['parents']) for spec in UPSTREAM.values()) == 35)
    require(sum(len(identities(unit)) for unit in UPSTREAM) == 67)
    return dict(description, core_commit=CORE, core_tree=TREE,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='UNCHANGED REFERENCE LABELS; NOT COMPILATION INPUT IDENTITIES',
        baseline_profiles=31, prior_upstream_profiles=3, added_upstream_profiles=2,
        upstream_profiles=5, upstream_test_parents=35,
        upstream_parent_and_child_outcomes=67, baseline_source_files=548,
        fee_stage_source_files=549,
        fresh_compilation='REQUIRED; NOT PERFORMED_BY_READER'), index


def probes(root=ROOT, profile='all'):
    require(profile == 'all')
    return prior.probes(root, 'all')


def source_payloads(root=ROOT, *, fee_stage=False):
    require(type(fee_stage) is bool)
    unused, index = inputs(root)
    expected = {name: row['sha256'] for name, row in index.items()}
    for name, path in probes(root).items():
        require(name not in expected)
        expected[name] = sha(earlier.regular(Path(root) / path, 2 * earlier.MIB))
    require(len(expected) == 548 and fee.DESTINATION not in expected)
    if fee_stage:
        expected[fee.DESTINATION] = sha(earlier.regular(
            Path(root) / fee.DRIVER, 128 * 1024))
    require(len(expected) == (549 if fee_stage else 548))
    return expected


def compare_source(directory, root=ROOT, profile='all', *, fee_stage=False):
    require(profile == 'all' and type(fee_stage) is bool)
    expected = source_payloads(root, fee_stage=fee_stage)
    snapshot = fee.compare_files(directory, expected)
    return dict(core_commit=CORE, core_tree=TREE, profile='all',
        upstream_files=523, project_producers=26 if fee_stage else 25,
        combined_files=len(expected), snapshot=snapshot,
        reference_fixture_core=FIXTURE_CORE,
        content='EXACT_SELECTED_CONTENTS; UNCHANGED REFERENCE PRODUCERS',
        filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_READER')


def units(profile='all'):
    require(profile == 'all')
    return prior.units('all') | set(ADDED_UPSTREAM)


def plan(root=ROOT, profile='all'):
    require(profile == 'all')
    inputs(root)
    previous = prior.plan(root, 'all')
    selected = copy.deepcopy(previous['units'])
    for unit, spec in sorted(ADDED_UPSTREAM.items()):
        selected.append(dict(unit=unit, package=spec['package'],
            parents=list(spec['parents']),
            parent_and_child_outcomes=len(identities(unit)),
            prior_streams_required=[],
            arguments=['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                '-run', '^(' + '|'.join(spec['parents']) + ')$',
                './' + spec['package']]))
    require(len(selected) == 36
            and {row['unit'] for row in selected} == units())
    return dict(schema='ptlc-nom-dev-821bdd2-reference-plan-v1',
        core_commit=CORE, core_tree=TREE, units=selected, producers=probes(root),
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        last_qualified_behavior_core=prior.CORE,
        historical_results_reclassified=False, journal_source_upgrade='NOT_SELECTED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def input_bindings(unit, prior_streams=None, root=ROOT):
    require(type(unit) is str and unit in units())
    if unit in ADDED_UPSTREAM:
        return {}
    return prior.input_bindings(unit, prior_streams, root)


def execution_plan(root=ROOT):
    """Describe intended stages; every execution and acceptance gate stays open."""
    baseline = plan(root)
    return dict(schema='ptlc-nom-dev-821bdd2-two-stage-plan-v1',
        core_commit=CORE, core_tree=TREE, baseline=baseline,
        last_qualified_behavior_core=prior.CORE,
        original_archive=dict(bytes=2072870,
            sha256='f2a566981fc469b1b60416ac7e943307fb6a01288e6d29ac4258941941ab7308'),
        required_new_compiler_workspaces=1, required_source_views=1,
        source_stages=2, stage_source_files=[548, 549],
        compiler_cache='SAME LIVE INVOCATION ONLY; NO HISTORICAL CACHE ADOPTION',
        test_result_cache='DISABLED_BY_COUNT_ONE', normal_default_vet=True,
        baseline_profiles=36, fee_profiles=1, complete_profiles=37,
        planned_native_commands=42,
        named_finite_outcomes=dict(reference=642, prior_runtime=58,
                                  upstream=67, fee_including_parent=15, total=782),
        separate_package_regression='UPSTREAM DEFINITION PACKAGE; NOT INCLUDED IN NAMED FINITE OUTCOME TOTAL',
        fee_stage=dict(producer=fee.DRIVER, destination=fee.DESTINATION,
            input_sha256=fee.INPUT_SHA, expected_sha256=fee.EXPECTED_SHA,
            cases=14, signed_synthetic_originals=2, new_keys=0, new_signatures=0,
            arguments=['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                       '-run', '^' + fee.PARENT + '$', './vm'],
            replacement_or_resigning='NOT_SELECTED'),
        added_component_coverage=dict(
            valid_cross_entity_and_shared_prefix_rows='SELECTED; ELEVEN UPSTREAM ITERATION PARENTS',
            malformed_rows='NOT_SELECTED_BY_ADDED_COMPONENTS',
            mismatched_storage_keys_and_values='NOT_SELECTED_BY_ADDED_COMPONENTS',
            iterator_failures='NOT_SELECTED_BY_ADDED_COMPONENTS',
            accelerator_exact_voting_deadline='NOT_SELECTED_BY_ADDED_COMPONENTS',
            dynamic_plasma_pre_and_post_spork='SELECTED; SEPARATE UPSTREAM TEST NAMES',
            accelerator_test_ptlc_spork='FALSE; NOT PTLC ENFORCEMENT EVIDENCE'),
        automatic_retry=False, historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_PLAN', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', recovery_action='NONE',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def frozen_plan(root=ROOT):
    """Require the checked-in plan, including exact JSON scalar types and order."""
    expected = execution_plan(root)
    value = earlier.decoded(earlier.regular(Path(root) / PLAN, 2 * earlier.MIB),
                            2 * earlier.MIB)
    canonical = lambda data: json.dumps(data, sort_keys=True, allow_nan=False).encode('ascii')
    require(canonical(value) == canonical(expected))
    return value


def read_upstream(unit, stdout, stderr):
    require(unit in UPSTREAM and type(stdout) is type(stderr) is bytes)
    if unit in prior.UPSTREAM:
        return prior.read_upstream(unit, stdout, stderr)
    require(0 < len(stdout) <= MAX_STREAM and stderr == b'')
    package = 'github.com/zenon-network/go-zenon/' + UPSTREAM[unit]['package']
    value = prior.upstream.common.event_stream(stdout, {package: identities(unit)})
    require(value['passed_including_parent'] == len(identities(unit)))
    return dict(unit=unit, required_parents=len(UPSTREAM[unit]['parents']),
        parent_and_child_outcomes=len(identities(unit)),
        value_assertions='PINNED UPSTREAM TEST IMPLEMENTATION',
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        native_execution_origin='NOT_ESTABLISHED_BY_DATA_READER')


def compare_payloads(payloads, root=ROOT, profile='all'):
    require(profile == 'all')
    require(type(payloads) is dict and set(payloads) ==
        {unit + suffix for unit in units() for suffix in ('.stdout', '.stderr')})
    require(all(type(raw) is bytes for raw in payloads.values())
            and sum(map(len, payloads.values())) <= MAX_TOTAL)
    inputs(root)
    original = {name: raw for name, raw in payloads.items()
                if name.rsplit('.', 1)[0] in reference.units('all')}
    previous = reference.compare_payloads(original, root, 'all')
    upstream_values = {unit: read_upstream(unit, payloads[unit + '.stdout'],
                                         payloads[unit + '.stderr'])
                       for unit in UPSTREAM}
    return dict(schema='ptlc-nom-dev-821bdd2-reference-values-v1',
        outcome='PASS_SELECTED_FINITE_VALUES_ONLY', core_commit=CORE, core_tree=TREE,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='REFERENCE LABELS; NOT EXECUTION SOURCE ATTESTATIONS',
        reference=previous, upstream=upstream_values, complete_profiles=36,
        reference_outcomes=642, prior_runtime_outcomes=58, upstream_outcomes=67,
        complete_original_profile_streams=72,
        original_streams_rewritten=False, historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER',
        journal_source_upgrade='NOT_SELECTED', recovery_action='NONE',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
