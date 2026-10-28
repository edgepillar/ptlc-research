"""Compare unchanged reference programs against a separate compiled source subject.

Reference fixture labels are retained verbatim. Only an external native runner
can bind actual compilation inputs and exits; this module reads finite data.
"""
import copy
import hashlib
from pathlib import Path

from qualification import nom_dev_661b5ef as reference
from qualification import nom_dev_77ba9c7_source as upstream
from qualification import nom_fee_original_boundary as fee

ROOT = upstream.ROOT
CORE, TREE = upstream.CORE, upstream.TREE
earlier = reference.earlier
runtime = reference.runtime
require = earlier.require
FIXTURE_CORE, FIXTURE_TREE = reference.CORE, reference.TREE
MAX_STREAM = 16 * 1024**2
MAX_TOTAL = reference.MAX_TOTAL + 6 * MAX_STREAM
UPSTREAM = {
    'upstream-guardians': dict(
        package='vm/embedded/implementation',
        source='vm/embedded/implementation/guardian_majority_test.go',
        parents=(
            'TestGuardian_CheckNominatedGuardians',
            'TestGuardian_NominateGuardians_ReceiveBlock_SporkGating',
            'TestGuardian_ProposeAdministrator_ThresholdsPostSpork',
            'TestGuardian_ProposeAdministrator_PreSporkTruncation',
            'TestGuardian_ProposeAdministrator_RepeatVoteCountsOnce',
            'TestGuardian_ProposeAdministrator_FinalVoteDecisive')),
    'upstream-reward-bounds': dict(
        package='vm/embedded/implementation',
        source='vm/embedded/implementation/epoch_reward_bound_test.go',
        parents=tuple('TestUpdate' + contract + 'Rewards' + condition
            for contract in ('Stake', 'Sentinel', 'Pillar')
            for condition in ('CappedAtMaxRewardEpochsPerCall',
                              'CapDoesNotSkipEpoch', 'UncappedBeforeSpork'))),
    'upstream-bridge-json': dict(
        package='rpc/api/embedded',
        source='rpc/api/embedded/bridge_unmarshal_test.go',
        parents=('TestWrapTokenRequestUnmarshalEmpty',
                 'TestUnwrapTokenRequestUnmarshalEmpty')),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identities(unit):
    require(unit in UPSTREAM)
    names = set(UPSTREAM[unit]['parents'])
    if unit == 'upstream-guardians':
        prefix = 'TestGuardian_ProposeAdministrator_'
        names.update(prefix + 'ThresholdsPostSpork/' + contract + '_Size_' + str(size)
            for contract in ('Bridge', 'Liquidity')
            for size in (5, 255, 256, 510, 511, 512, 513, 1000))
        names.update(prefix + condition + '/' + contract
            for condition in ('PreSporkTruncation', 'RepeatVoteCountsOnce')
            for contract in ('Bridge', 'Liquidity'))
        names.update(prefix + 'FinalVoteDecisive/' + contract
            + '_FinalVoteDecisive_' + str(size)
            for contract in ('Bridge', 'Liquidity') for size in (510, 511))
    require(len(names) == {'upstream-guardians': 30,
        'upstream-reward-bounds': 9, 'upstream-bridge-json': 2}[unit])
    return names


def inputs(root=ROOT):
    description, index = upstream.inputs(root)
    reference.inputs(root)
    fee.inputs(root)
    require(CORE != FIXTURE_CORE and TREE != FIXTURE_TREE)
    require(len(reference.probes(root, 'all')) == 25)
    require(sum(len(spec['parents']) for spec in UPSTREAM.values()) == 17)
    require(sum(len(identities(unit)) for unit in UPSTREAM) == 41)
    require(all(spec['source'] in index for spec in UPSTREAM.values()))
    return dict(description,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='UNCHANGED REFERENCE PROGRAM LABELS; NOT COMPILATION INPUT IDENTITIES',
        baseline_profiles=31, upstream_profiles=3, upstream_test_parents=17,
        upstream_parent_and_child_outcomes=41, baseline_source_files=546,
        fee_stage_source_files=547, fresh_compilation='REQUIRED; NOT PERFORMED_BY_READER'), index


def probes(root=ROOT, profile='all'):
    require(profile == 'all')
    return reference.probes(root, 'all')


def source_payloads(root=ROOT, *, fee_stage=False):
    require(type(fee_stage) is bool)
    unused, index = inputs(root)
    expected = {name: row['sha256'] for name, row in index.items()}
    for name, path in probes(root).items():
        require(name not in expected)
        expected[name] = sha(earlier.regular(Path(root) / path, 2 * earlier.MIB))
    require(len(expected) == 546 and fee.DESTINATION not in expected)
    if fee_stage:
        expected[fee.DESTINATION] = sha(earlier.regular(Path(root) / fee.DRIVER, 128 * 1024))
    require(len(expected) == (547 if fee_stage else 546))
    return expected


def compare_source(directory, root=ROOT, profile='all', *, fee_stage=False):
    require(profile == 'all' and type(fee_stage) is bool)
    expected = source_payloads(root, fee_stage=fee_stage)
    snapshot = fee.compare_files(directory, expected)
    return dict(core_commit=CORE, core_tree=TREE, profile='all',
        upstream_files=521, project_producers=26 if fee_stage else 25,
        combined_files=len(expected), snapshot=snapshot,
        reference_fixture_core=FIXTURE_CORE,
        content='EXACT_SELECTED_CONTENTS; UNCHANGED REFERENCE PRODUCERS',
        filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_READER')


def units(profile='all'):
    require(profile == 'all')
    return reference.units('all') | set(UPSTREAM)


def plan(root=ROOT, profile='all'):
    require(profile == 'all')
    inputs(root)
    prior = reference.plan(root, 'all')
    selected = copy.deepcopy(prior['units'])
    for unit, spec in sorted(UPSTREAM.items()):
        selected.append(dict(unit=unit, package=spec['package'],
            parents=list(spec['parents']), parent_and_child_outcomes=len(identities(unit)),
            prior_streams_required=[],
            arguments=['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                '-run', '^(' + '|'.join(spec['parents']) + ')$', './' + spec['package']]))
    require(len(selected) == 34 and {row['unit'] for row in selected} == units())
    return dict(schema='ptlc-nom-dev-77ba9c7-reference-plan-v1',
        core_commit=CORE, core_tree=TREE, units=selected, producers=probes(root),
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        historical_results_reclassified=False, journal_source_upgrade='NOT_SELECTED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def input_bindings(unit, prior_streams=None, root=ROOT):
    require(type(unit) is str and unit in units())
    if unit in UPSTREAM:
        return {}
    return reference.input_bindings(unit, prior_streams, root)


def read_upstream(unit, stdout, stderr):
    require(unit in UPSTREAM and type(stdout) is type(stderr) is bytes)
    require(0 < len(stdout) <= MAX_STREAM and stderr == b'')
    package = 'github.com/zenon-network/go-zenon/' + UPSTREAM[unit]['package']
    value = upstream.common.event_stream(stdout, {package: identities(unit)})
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
    prior = reference.compare_payloads({name: raw for name, raw in payloads.items()
        if name.rsplit('.', 1)[0] in reference.units('all')}, root, 'all')
    added = {unit: read_upstream(unit, payloads[unit + '.stdout'],
        payloads[unit + '.stderr']) for unit in UPSTREAM}
    return dict(schema='ptlc-nom-dev-77ba9c7-reference-values-v1',
        outcome='PASS_SELECTED_FINITE_VALUES_ONLY', core_commit=CORE, core_tree=TREE,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='REFERENCE LABELS; NOT EXECUTION SOURCE ATTESTATIONS',
        reference=prior, upstream=added, complete_profiles=34,
        reference_outcomes=642, prior_runtime_outcomes=58, upstream_outcomes=41,
        complete_original_profile_streams=68,
        original_streams_rewritten=False, historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER',
        journal_source_upgrade='NOT_SELECTED', recovery_action='NONE',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')
