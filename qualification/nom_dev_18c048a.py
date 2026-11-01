"""Plan finite candidate comparisons, retaining the selected behavior boundary.

Inputs and original event values are checked here. Native execution, custody,
compiler authentication and independent assessment require separate evidence.
"""
import copy
import hashlib
import json
import math
from pathlib import Path

from qualification import nom_dev_821bdd2 as prior
from qualification import nom_dev_18c048a_source as upstream
from qualification import nom_fee_original_boundary as fee

ROOT = upstream.ROOT
CORE, TREE = upstream.CORE, upstream.TREE
FIXTURE_CORE, FIXTURE_TREE = prior.FIXTURE_CORE, prior.FIXTURE_TREE
earlier, runtime, reference = prior.earlier, prior.runtime, prior.reference
require = earlier.require
MAX_STREAM = prior.MAX_STREAM
MAX_TOTAL = prior.MAX_TOTAL + 10 * MAX_STREAM
PLAN = 'compatibility/nom_dev_18c048a_plan_v1.json'
PRODUCERS = {
    'common/db/ptlc_research18_storage_test.go': 'qualification-go/nom_18c_storage_test.go',
    'vm/embedded/definition/ptlc_research18_collection_test.go': 'qualification-go/nom_18c_collection_test.go',
}
ADDED_UPSTREAM = {
    'upstream-db-tombstones': dict(package='common/db', source='common/db/enable_delete_test.go',
        parents=('TestEnableDeleteIteratorSkipsTombstones',
            'TestEnableDeleteIteratorPrevSkipsTombstones',
            'TestEnableDeleteIteratorLastSkipsTombstones',
            'TestEnableDeleteIteratorAllTombstones',
            'TestLevelDBManagerPopTombstoneIterator',
            'TestLevelDBManagerPopTombstoneIteratorReopen')),
    'upstream-definition-tombstones': dict(package='vm/embedded/definition',
        source='vm/embedded/definition/tombstone_test.go',
        parents=('TestGetAllSentinelInfoSkipsTombstones',
            'TestIterateSentinelEntriesSkipsTombstones', 'TestGetProjectListSkipsTombstones')),
    'upstream-protocol-shutdown': dict(package='protocol', source='protocol/handler_stop_test.go',
        parents=('TestProtocolManagerStopTwice', 'TestProtocolManagerStartStop')),
    'research-storage-composition': dict(package='common/db',
        source='common/db/ptlc_research18_storage_test.go',
        parents=('TestPTLCResearchStorageComposition', 'TestPTLCResearchIteratorErrorForwarding')),
    'research-collection-boundaries': dict(package='vm/embedded/definition',
        source='vm/embedded/definition/ptlc_research18_collection_test.go',
        parents=('TestPTLCResearchCollectionEmptyRows', 'TestPTLCResearchCollectionIteratorErrors')),
}
UPSTREAM = dict(copy.deepcopy(prior.UPSTREAM), **ADDED_UPSTREAM)
CHILDREN = {
    'TestPTLCResearchStorageComposition': ('snapshot_delete_mask', 'nested_snapshots',
        'live_empty_value', 'subset_complete_prefix', 'snapshot_reverse_errors', 'leveldb_pop_reopen'),
    'TestPTLCResearchIteratorErrorForwarding': ('Next', 'Prev', 'Last'),
    'TestPTLCResearchCollectionEmptyRows': ('sentinel_get_all', 'sentinel_iterate',
        'project_get_list', 'sentinel_callback_refusal'),
    'TestPTLCResearchCollectionIteratorErrors': ('sentinel_get_all', 'sentinel_iterate', 'project_get_list'),
}
DEFINITION_COMPLEMENT = (
    'TestAcceleratorStoragePrefixValues', 'TestPtlcUnlockMessageVectors',
    'TestPtlcReclaimMessageVectors', 'TestPtlcAbiBeforeReclaimLockUnchanged',
    'TestPtlcReclaimLockStorage', 'TestPtlcInfoKeyParsing',
    'TestGetAllSporksSkipsTombstones', 'TestGetSwapAssetsSkipsEmptyValues',
)
DEFINITION_COMPLEMENT_SOURCES = {
    'vm/embedded/definition/accelerator_prefix_test.go': '1705096a3e398ef6d102cda5ebd39ef8c237fae7bfd19f971dbd65e7168628d8',
    'vm/embedded/definition/ptlc_message_test.go': '763b5e6d9d8473f82853ba4effbda8e1258b7fc9827aefa04ecdb95f346a3435',
    'vm/embedded/definition/ptlc_reclaim_test.go': '8c3b4b7e5688d123b1d0b94515109bf9fe2fbacdffe00ce68d860e3440f5fb6b',
    'vm/embedded/definition/ptlc_test.go': 'd04bba951c22d585ebc5513ddd5aa830d52bc32fd06a3854a9a090c16dc1452c',
    'vm/embedded/definition/spork_test.go': 'b9d46fd685089d846deb0de46b9333fc8e1e68dbbc25109e9ea685b5646d080a',
    'vm/embedded/definition/swap_test.go': 'f84c19b74b284889a31c11bc591e7241dc766aa1733b8531334e3ba91ef918d8',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identities(unit):
    require(unit in UPSTREAM)
    if unit in prior.UPSTREAM:
        return prior.identities(unit)
    names = set(UPSTREAM[unit]['parents'])
    for parent in tuple(names):
        names.update(parent + '/' + child for child in CHILDREN.get(parent, ()))
    require(len(names) == {'upstream-db-tombstones': 6,
        'upstream-definition-tombstones': 3, 'upstream-protocol-shutdown': 2,
        'research-storage-composition': 11, 'research-collection-boundaries': 9}[unit])
    return names


def inputs(root=ROOT):
    description, index = upstream.inputs(root)
    prior.inputs(root)
    require(len(index) == 525 and len(prior.probes(root)) == 25)
    require(sum(len(spec['parents']) for spec in UPSTREAM.values()) == 50)
    require(sum(len(identities(unit)) for unit in UPSTREAM) == 98)
    require(all(index[name]['sha256'] == digest for name, digest in DEFINITION_COMPLEMENT_SOURCES.items()))
    definition = {name for name in index
        if name.startswith('vm/embedded/definition/') and name.endswith('_test.go')}
    require(definition == set(DEFINITION_COMPLEMENT_SOURCES) | {
        prior.UPSTREAM['upstream-per-entity']['source'],
        ADDED_UPSTREAM['upstream-definition-tombstones']['source']})
    definition_sets = [set(DEFINITION_COMPLEMENT),
        set(prior.UPSTREAM['upstream-per-entity']['parents']),
        set(ADDED_UPSTREAM['upstream-definition-tombstones']['parents']),
        set(ADDED_UPSTREAM['research-collection-boundaries']['parents'])]
    require(sum(map(len, definition_sets)) == len(set().union(*definition_sets)) == 24)
    return dict(description, core_commit=CORE, core_tree=TREE,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='UNCHANGED REFERENCE LABELS; NOT COMPILATION INPUT IDENTITIES',
        baseline_profiles=41, preserved_baseline_profiles=36, added_profiles=5,
        upstream_profiles=10, upstream_test_parents=50,
        upstream_parent_and_child_outcomes=98,
        baseline_source_files=552, fee_stage_source_files=553,
        definition_roots=24, definition_complement_roots=8,
        definition_root_selection='DISJOINT; NO WHOLE-PACKAGE SECOND EXECUTION',
        fresh_compilation='REQUIRED; NOT_PERFORMED_BY_READER',
        native_compatibility='UNFILLED', native_execution='NOT_PERFORMED_BY_READER'), index


def probes(root=ROOT, profile='all'):
    require(profile == 'all')
    values = dict(prior.probes(root, profile))
    require(not values.keys() & PRODUCERS.keys())
    values.update(PRODUCERS)
    require(len(values) == 27)
    return values


def source_payloads(root=ROOT, *, fee_stage=False):
    require(type(fee_stage) is bool)
    unused, index = inputs(root)
    values = {name: row['sha256'] for name, row in index.items()}
    for name, path in probes(root).items():
        require(name not in values)
        values[name] = sha(earlier.regular(Path(root) / path, 2 * earlier.MIB))
    require(len(values) == 552 and fee.DESTINATION not in values)
    if fee_stage:
        values[fee.DESTINATION] = sha(earlier.regular(Path(root) / fee.DRIVER, 128 * 1024))
    require(len(values) == (553 if fee_stage else 552))
    return values


def compare_source(directory, root=ROOT, profile='all', *, fee_stage=False):
    require(profile == 'all' and type(fee_stage) is bool)
    expected = source_payloads(root, fee_stage=fee_stage)
    return dict(core_commit=CORE, core_tree=TREE, profile='all', upstream_files=525,
        project_producers=28 if fee_stage else 27, combined_files=len(expected),
        snapshot=fee.compare_files(directory, expected), reference_fixture_core=FIXTURE_CORE,
        content='EXACT_SELECTED_CONTENTS; UNCHANGED_REFERENCE_AND_NEW_BOUNDARY_PRODUCERS',
        filesystem_mode_equality='NOT_ASSERTED', producer_authentication='NOT_ESTABLISHED_BY_READER')


def units(profile='all'):
    require(profile == 'all')
    return prior.units(profile) | set(ADDED_UPSTREAM)


def plan(root=ROOT, profile='all'):
    require(profile == 'all')
    inputs(root)
    selected = copy.deepcopy(prior.plan(root, profile)['units'])
    for unit, spec in sorted(ADDED_UPSTREAM.items()):
        selected.append(dict(unit=unit, package=spec['package'], parents=list(spec['parents']),
            parent_and_child_outcomes=len(identities(unit)), prior_streams_required=[],
            arguments=['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                '-run', '^(' + '|'.join(spec['parents']) + ')$', './' + spec['package']]))
    require(len(selected) == 41 and {row['unit'] for row in selected} == units())
    return dict(schema='ptlc-nom-dev-18c048a-reference-plan-v1', core_commit=CORE,
        core_tree=TREE, units=selected, producers=probes(root),
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        last_qualified_behavior_core=prior.prior.CORE,
        historical_results_reclassified=False, journal_source_upgrade='NOT_SELECTED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def input_bindings(unit, prior_streams=None, root=ROOT):
    require(type(unit) is str and unit in units())
    return {} if unit in ADDED_UPSTREAM else prior.input_bindings(unit, prior_streams, root)


def definition_arguments():
    return ['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
        '-run', '^(' + '|'.join(DEFINITION_COMPLEMENT) + ')$', './vm/embedded/definition']


def execution_plan(root=ROOT):
    baseline = plan(root)
    return dict(schema='ptlc-nom-dev-18c048a-two-stage-plan-v1', core_commit=CORE,
        core_tree=TREE, baseline=baseline, last_qualified_behavior_core=prior.prior.CORE,
        original_archive=dict(bytes=2076928,
            sha256='98b7c5ec34484b26159d9dbad4cbcd34426f8969caf607652036e406ed95a55c'),
        added_producer_sha256={path: sha(earlier.regular(Path(root) / path, 128 * 1024))
            for path in PRODUCERS.values()},
        required_new_compiler_workspaces=1, required_source_views=1, source_stages=2,
        stage_source_files=[552, 553],
        compiler_cache='SAME LIVE INVOCATION ONLY; NO HISTORICAL CACHE ADOPTION',
        test_result_cache='DISABLED_BY_COUNT_ONE', normal_default_vet=True,
        baseline_profiles=41, fee_profiles=1, complete_profiles=42, planned_native_commands=47,
        named_finite_outcomes=dict(reference=642, prior_runtime=58, upstream=98,
            fee_including_parent=15, total=813),
        separate_package_regression=dict(package='vm/embedded/definition',
            selected_roots=list(DEFINITION_COMPLEMENT), arguments=definition_arguments(),
            coverage_roots=24, overlap_with_profile_roots=0,
            scope='EIGHT COMPLEMENT ROOTS AND ALL OBSERVED DESCENDANTS; EXCLUDED FROM 813 PROFILE OUTCOMES'),
        fee_stage=dict(producer=fee.DRIVER, destination=fee.DESTINATION,
            input_sha256=fee.INPUT_SHA, expected_sha256=fee.EXPECTED_SHA,
            cases=14, signed_synthetic_originals=2, new_keys=0, new_signatures=0,
            arguments=['test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                '-run', '^' + fee.PARENT + '$', './vm'], replacement_or_resigning='NOT_SELECTED'),
        added_component_coverage=dict(
            storage='SNAPSHOT MASKING, NESTED VIEWS, LIVE EMPTY VALUES, PREFIXES, POP, REOPEN',
            reverse_iteration='MERGED PREV/LAST REMAIN UNSUPPORTED WITH AN ERROR',
            iterator_errors='SCRIPTED WRAPPER FORWARDING; NOT PHYSICAL IO FAULTS',
            collection_values='POST-WRAPPER EMPTY ROWS, LIVE ROWS AND CALLBACK REFUSAL',
            collection_database_errors='EXISTING PANIC AND RELEASE BOUNDARY; NOT EMPTY SUCCESS',
            protocol_shutdown='PINNED MOCK COMPONENT START/STOP; NOT A NODE OR LEAK-FREEDOM PROOF',
            malformed_rows='NOT_SELECTED', mismatched_storage_keys_and_values='NOT_SELECTED',
            accelerator_exact_voting_deadline='NOT_SELECTED_BY_ADDED_COMPONENTS',
            physical_durability='NOT_ESTABLISHED', canonicality='NOT_ESTABLISHED'),
        automatic_retry=False, historical_results_reclassified=False,
        native_execution='NOT_PERFORMED_BY_PLAN', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', recovery_action='NONE',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def frozen_plan(root=ROOT):
    expected = execution_plan(root)
    value = earlier.decoded(earlier.regular(Path(root) / PLAN, 2 * earlier.MIB), 2 * earlier.MIB)
    canonical = lambda data: json.dumps(data, sort_keys=True, allow_nan=False).encode('ascii')
    require(canonical(value) == canonical(expected))
    return value


def read_upstream(unit, stdout, stderr):
    require(unit in UPSTREAM and type(stdout) is type(stderr) is bytes)
    if unit in prior.UPSTREAM:
        return prior.read_upstream(unit, stdout, stderr)
    require(0 < len(stdout) <= MAX_STREAM and stderr == b'')
    package = 'github.com/zenon-network/go-zenon/' + UPSTREAM[unit]['package']
    value = prior.prior.upstream.common.event_stream(stdout, {package: identities(unit)})
    require(value['passed_including_parent'] == len(identities(unit)))
    return dict(unit=unit, required_parents=len(UPSTREAM[unit]['parents']),
        parent_and_child_outcomes=len(identities(unit)),
        value_assertions='PINNED_SOURCE_AND_ORIGINAL_PROJECT_BOUNDARY_TESTS',
        stdout_sha256=sha(stdout), stderr_sha256=sha(stderr),
        native_execution_origin='NOT_ESTABLISHED_BY_DATA_READER')


def compare_payloads(payloads, root=ROOT, profile='all'):
    require(profile == 'all' and type(payloads) is dict and set(payloads) ==
        {unit + suffix for unit in units() for suffix in ('.stdout', '.stderr')})
    require(all(type(raw) is bytes for raw in payloads.values()) and sum(map(len, payloads.values())) <= MAX_TOTAL)
    inputs(root)
    preserved = {name: raw for name, raw in payloads.items()
        if name.rsplit('.', 1)[0] in reference.units(profile)}
    previous = reference.compare_payloads(preserved, root, profile)
    upstream_values = {unit: read_upstream(unit, payloads[unit + '.stdout'], payloads[unit + '.stderr'])
        for unit in UPSTREAM}
    return dict(schema='ptlc-nom-dev-18c048a-reference-values-v1',
        outcome='PASS_SELECTED_FINITE_VALUES_ONLY', core_commit=CORE, core_tree=TREE,
        reference_fixture_core=FIXTURE_CORE, reference_fixture_tree=FIXTURE_TREE,
        embedded_core_labels='REFERENCE LABELS; NOT EXECUTION SOURCE ATTESTATIONS',
        reference=previous, upstream=upstream_values, complete_profiles=41,
        reference_outcomes=642, prior_runtime_outcomes=58, upstream_outcomes=98,
        complete_original_profile_streams=82, original_streams_rewritten=False,
        historical_results_reclassified=False, native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER', journal_source_upgrade='NOT_SELECTED',
        recovery_action='NONE', application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def package_events(raw, required):
    """Require successful package/root framing and all observed descendants.

    A slash in one t.Run name creates no invented intermediate parent. This is
    a bounded data check, not execution-origin or branch-coverage evidence.
    """
    require(type(raw) is bytes and 0 < len(raw) <= MAX_STREAM and raw.endswith(b'\n'))
    require(type(required) is dict and required and all(type(value) is set for value in required.values()))
    lines = raw.splitlines()
    require(len(lines) <= 10000 and all(0 < len(line) <= 65536 for line in lines))
    started, closed, states = set(), set(), {}
    for line in lines:
        row = earlier.decoded(line, 65536)
        require(type(row) is dict and set(row) <= {'Time', 'Action', 'Package', 'Test', 'Elapsed', 'Output'})
        action, package = row.get('Action'), row.get('Package')
        require(package in required and package not in closed)
        require(action in {'start', 'run', 'pause', 'cont', 'output', 'pass'})
        if 'Time' in row:
            require(type(row['Time']) is str and len(row['Time']) <= 100)
        if 'Elapsed' in row:
            value = row['Elapsed']
            require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
        name = row.get('Test')
        require(name is None or type(name) is str and name and len(name) <= 1024)
        if action == 'start':
            require(package not in started and name is None)
            started.add(package)
            continue
        require(package in started)
        if action == 'output':
            require(type(row.get('Output')) is str)
            if name is not None:
                require(states.get((package, name)) in ('RUNNING', 'PAUSED'))
            continue
        if name is None:
            require(action == 'pass' and all(state == 'PASSED' for (pkg, test), state in states.items() if pkg == package))
            roots = {test for (pkg, test) in states if pkg == package and '/' not in test}
            require(roots == required[package])
            closed.add(package)
            continue
        root = name.split('/', 1)[0]
        require(root in required[package])
        if '/' in name:
            require(states.get((package, root)) in ('RUNNING', 'PAUSED'))
        key = package, name
        if action == 'run':
            require(key not in states)
            states[key] = 'RUNNING'
        elif action == 'pause':
            require(states.get(key) == 'RUNNING')
            states[key] = 'PAUSED'
        elif action == 'cont':
            require(states.get(key) == 'PAUSED')
            states[key] = 'RUNNING'
        else:
            require(action == 'pass' and states.get(key) == 'RUNNING')
            require(all(state == 'PASSED' for (pkg, test), state in states.items()
                if pkg == package and test.startswith(name + '/')))
            states[key] = 'PASSED'
    require(started == closed == set(required) and all(value == 'PASSED' for value in states.values()))
    return dict(packages=len(closed), required_parents=sum(map(len, required.values())),
        observed_parent_and_child_outcomes=len(states), events=len(lines))
