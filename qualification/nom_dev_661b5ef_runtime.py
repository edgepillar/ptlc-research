"""Read selected upstream runtime test streams without executing a node.

These source-bound unit assertions supplement the independent PTLC value
comparisons. They are not independent protocol or observation-authority proof.
"""
import hashlib
import re

from qualification import nom_dev_661b5ef_source as source
from qualification import nom_current_admission as common

ROOT, CORE, TREE = source.ROOT, source.CORE, source.TREE
MANIFEST = 'compatibility/nom_dev_661b5ef_runtime_v1.json'
MAX_STDOUT, MAX_STDERR, MAX_EVENTS = 4*common.MIB, 64*1024, 20000
require = common.require
SPECS = {'runtime-manager-guards': ('app', 'app/run_with_config_test.go', ('TestRunWithConfig_AlreadyRunning_ReturnsError', 'TestStop_ClearsNodeManager', 'TestRunWithConfig_SecondStartPreservesFirstNode')), 'runtime-node-stop': ('node', 'node/node_stop_test.go', ('TestStopRunsAllStepsDespiteErrors', 'TestStopJoinsErrorsFromMultipleSubsystems', 'TestStopFailingCoreStillCleansUp')), 'runtime-spork-tombstone': ('vm/embedded/definition', 'vm/embedded/definition/spork_test.go', ('TestGetAllSporksSkipsTombstones',)), 'runtime-decode-limits': ('chain/nom', 'chain/nom/deserialize_decode_path_test.go', ('TestDeserializeAccountBlock_MalformedDescendantNamesIndex', 'TestDeserializeAccountBlock_MalformedNestedDescendantNamesPath', 'TestDeserializeAccountBlock_ValidDescendantsRoundTrip', 'TestDeserializeMomentum_MalformedContentAddressNamesIndex', 'TestDeserializeMomentum_MalformedContentHashNamesIndex', 'TestDeserializeMomentum_ValidContentRoundTrip', 'TestDeserializeAccountBlock_NestedPastDecoderLimitIsRejected', 'TestDeserializeAccountBlock_NestedBelowDecoderLimitDecodes')), 'runtime-manager-close': ('common/db', 'common/db/versioned_db_test.go', ('TestManagerStopIsIdempotent', 'TestLevelDBManagerStopAfterFailedClose', 'TestRebase_Stopped', 'TestMemDBManagerStopDuringAdd', 'TestMemDBManagerAddRechecksFrontierAtCommit', 'TestMemDBManagerStopConcurrentWithAdd')), 'runtime-cache-close': ('chain/cache/storage', 'chain/cache/storage/db_test.go', ('TestCacheDBManagerStopIsIdempotent', 'TestCacheDBManagerStopAfterFailedClose', 'TestGetFrontierIdentifierCorrupted', 'TestGetFrontierIdentifierReadError')), 'runtime-request-budget': ('protocol', 'protocol/handler_budget_test.go', ('TestTokenBucket_ReserveRefillAndCap', 'TestTokenBucket_RequestAboveBurstIsRefusedWithoutCharge', 'TestTokenBucket_DeficitWithoutRateIsRefused', 'TestTokenBucket_BackwardClockDoesNotRefill', 'TestHandleRequests_UnknownHashStreamIsPacedOnceBudgetRunsDry', 'TestHandleRequests_MissCostsMoreThanHit', 'TestHandleRequests_HonestSyncPaceIsNeverPaced', 'TestHandleRequests_FlatOutHashSyncIsPacedNotRefused', 'TestHandleRequests_FlatOutLargeRepliesArePacedNotRefused', 'TestHandleRequests_BudgetRefillsOverTime', 'TestHandleRequests_ReplyAboveByteBurstIsRefusedAndNotSent', 'TestHandleRequests_ReplyBytesArePaced', 'TestHandleRequests_PacedWaitAbandonedWhenPeerCloses', 'TestHandleRequests_HashRequestsDrawFromTheSharedBudget', 'TestHandleRequests_HashRequestIsChargedTheClampedAmount', 'TestHandleRequests_HashesFromNumberDrawFromTheSharedBudget', 'TestHandleRequests_MissingHeightFallbackIsCharged', 'TestHandleRequests_FlatOutFromNumberSyncIsPacedNotRefused', 'TestHandleRequests_MixedFlatOutLookupTrafficStaysInsideTimeouts', 'TestHandleRequests_MixedFlatOutByteTrafficStaysInsideTimeouts', 'TestHandleRequests_AbandonedWaitStopsBeforeTheNextStep', 'TestHandleRequests_HashReplyBytesAreCharged', 'TestHandleRequests_EmptyRequestsAreNotFree', 'TestPeer_RequestBudgetDefaultsWhenUnset', 'TestSleepUnlessClosed', 'TestRequestBudgetDefaults_CoverHonestRequesters', 'TestPeer_DefaultBudgetsAreIndependentAndEndWithTheConnection')), 'runtime-embedded-pricing': ('vm', 'vm/plasma_embedded_test.go', ('TestEmbeddedSendBasePlasma',)), 'runtime-quote-snapshot': ('rpc/api/embedded', 'rpc/api/embedded/plasma_test.go', ('TestGetRequiredPoWFusedPlasmaTarget', 'TestGetRequiredPoWFusedOnlyTargetMeetsPrice', 'TestGetRequiredResultJSONIncludesZeroFusedTarget', 'TestFusionEntryListUnmarshalFreshReceiver', 'TestGetRequiredPoWMissingCapturedFrontierCache'))}
TOP_LEVEL_TESTS = sum(len(row[2]) for row in SPECS.values())
MAX_TOTAL = len(SPECS)*(MAX_STDOUT+MAX_STDERR)
LOG_PROBES = {'node/ptlc_661b5ef_logging_test.go': 'compatibility/nom_dev_661b5ef_node_logging_test.go.txt', 'chain/cache/storage/ptlc_661b5ef_logging_test.go': 'compatibility/nom_dev_661b5ef_cache_logging_test.go.txt', 'protocol/ptlc_661b5ef_logging_test.go': 'compatibility/nom_dev_661b5ef_protocol_logging_test.go.txt'}
LOG_PROBE_BODY = '// SPDX-License-Identifier: MIT\npackage {package}\n\nimport "github.com/inconshreveable/log15"\n\n// Configure structured diagnostics before selected tests. Go test assertions,\n// panic output and framework streams retain their normal behavior.\nfunc init() {{\n\tlog15.Root().SetHandler(log15.DiscardHandler())\n}}\n'
DARWIN_CGO_CFLAGS = '-O2 -g -Wno-deprecated-declarations'
DEFAULT_CGO_PROFILE = 'GO_DEFAULT_CGO_FLAGS'
DARWIN_CGO_PROFILE = 'DARWIN_O2_G_NO_DEPRECATED_DECLARATIONS'
OWN_INPUTS = {'qualification/nom_dev_661b5ef_runtime.py','tests/test_nom_dev_661b5ef_runtime.py'} | set(LOG_PROBES.values())


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def declaration(index):
    units = {}
    for name,(package,filename,tests) in SPECS.items():
        require(all(re.fullmatch(r'Test[A-Za-z0-9_]+',test) for test in tests)
            and len(tests) == len(set(tests)))
        units[name] = dict(package=package,source_file=filename,
            source_sha256=index[filename]['sha256'],tests=list(tests),
            outcome_scope='REQUIRED TOP-LEVEL FUNCTIONS; CLOSED OBSERVED DESCENDANTS',
            fixture_scope='INERT MEMORY AND TEMPORARY LOCAL RESOURCES; NO NODE START')
    return dict(schema='ptlc-nom-dev-661b5ef-runtime-selection-v1',core_commit=CORE,
        core_tree=TREE,source_files=518,profiles=9,required_top_level_tests=58,
        units=units,excluded_real_node_test='TestRunWithConfig_StartDoesNotBlock',
        test_logging_probes=LOG_PROBES,structured_log_handler='DISCARD_DIAGNOSTICS_ONLY',
        darwin_cgo_cflags=DARWIN_CGO_CFLAGS,compiler_diagnostic_scope='EXPLICIT_DEPRECATION_CATEGORY_ONLY',
        application='NO-GO',core='NO-GO',recovery_action='NONE',
        native_execution='NOT_PERFORMED_BY_READER',independent_assessment='UNFILLED')


def inputs(root=ROOT):
    root = common.physical(root)
    unused,index = source.inputs(root)
    manifest = common.decoded(common.regular(root/MANIFEST,common.MIB),common.MIB)
    fixed = declaration(index)
    require(TOP_LEVEL_TESTS == 58 and set(manifest) == set(fixed)|{'input_sha256'})
    common.rebase.exact(fixed,{name:manifest[name] for name in fixed})
    require(set(manifest['input_sha256']) == OWN_INPUTS)
    for name,pin in manifest['input_sha256'].items():
        require(sha(common.regular(root/name,2*common.MIB)) == pin)
    probes(root)
    return manifest


def diagnostic_profile(sdk):
    return DEFAULT_CGO_PROFILE if sdk is None else DARWIN_CGO_PROFILE


def probes(root=ROOT):
    root = common.physical(root)
    for logical,name in LOG_PROBES.items():
        package = logical.rsplit('/',1)[0].rsplit('/',1)[-1]
        raw = common.regular(root/name,2*common.MIB)
        require(raw == LOG_PROBE_BODY.format(package=package).encode('ascii'))
    return dict(LOG_PROBES)


def plan(root=ROOT):
    manifest = inputs(root)
    units = []
    for unit,row in manifest['units'].items():
        pattern = '^('+'|'.join(row['tests'])+')$'
        units.append(dict(unit=unit,package=row['package'],parent=pattern,
            parent_and_child_outcomes=len(row['tests']),
            outcome_scope='TOP_LEVEL_FUNCTIONS_ONLY; CHILD COUNT OBSERVED SEPARATELY',
            prior_streams_required=[],arguments=['test','-json','-p','2','-mod=readonly',
                '-count=1','-run',pattern,'./'+row['package']]))
    return units


def read(raw, unit, root=ROOT):
    manifest = inputs(root)
    require(type(unit) is str and unit in SPECS and type(raw) is bytes
        and 0 < len(raw) <= MAX_STDOUT and raw.endswith(b'\n'))
    selected = manifest['units'][unit]
    package = common.PREFIX+selected['package']
    top = set(selected['tests'])
    lines = raw.splitlines()
    require(0 < len(lines) <= MAX_EVENTS)
    observed, states = set(), {}
    package_started = package_passed = False
    for line in lines:
        event = common.decoded(line,MAX_STDOUT)
        require(type(event) is dict and event.get('Package') == package and not package_passed)
        action, name = event.get('Action'), event.get('Test')
        require(action in ('start','run','pause','cont','output','pass'))
        if name is not None:
            require(type(name) is str and name.isascii() and 0 < len(name) <= 1024
                and name.split('/',1)[0] in top
                and all(part not in ('','.','..') for part in name.split('/')))
            observed.add(name)
        if action == 'start':
            require(not package_started and name is None)
            package_started = True
            continue
        require(package_started)
        if action == 'run':
            require(name is not None and name not in states)
            if '/' in name:
                require(states.get(name.rsplit('/',1)[0]) == 'running')
            states[name] = 'running'
        elif action == 'pause':
            require(name is not None and states.get(name) == 'running')
            states[name] = 'paused'
        elif action == 'cont':
            require(name is not None and states.get(name) == 'paused')
            states[name] = 'running'
        elif action == 'output':
            require(name is None or states.get(name) in ('running','paused'))
        elif name is None:
            require(states and all(value == 'passed' for value in states.values()))
            package_passed = True
        else:
            require(states.get(name) == 'running'
                and all(value == 'passed' for child,value in states.items()
                    if child.startswith(name+'/')))
            states[name] = 'passed'
    require(package_started and package_passed and set(states) == observed
        and all(value == 'passed' for value in states.values()))
    require({name for name in observed if '/' not in name} == top)
    stats = common.event_stream(raw,{package:observed})
    require(stats['passed_including_parent'] == len(observed))
    return dict(unit=unit,required_top_level_tests=len(top),
        observed_descendants=len(observed)-len(top),original_event_stats=stats,
        selected_source_file=selected['source_file'],selected_source_sha256=selected['source_sha256'],
        outcome='PASS_SELECTED_UPSTREAM_TEST_COMPLETION_ONLY',
        child_count_scope='OBSERVED CLOSURE; NOT AN INDEPENDENT CASE ENUMERATION',
        native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER',actual_command_exit='NOT_ESTABLISHED_BY_READER')


def compare_payloads(payloads, root=ROOT):
    inputs(root)
    require(type(payloads) is dict and set(payloads) ==
        {unit+suffix for unit in SPECS for suffix in ('.stdout','.stderr')})
    require(all(type(value) is bytes for value in payloads.values())
        and sum(map(len,payloads.values())) <= MAX_TOTAL)
    reports = {}
    for unit in SPECS:
        stderr = payloads[unit+'.stderr']
        require(len(stderr) <= MAX_STDERR)
        reports[unit] = dict(read(payloads[unit+'.stdout'],unit,root),
            stderr=dict(bytes=len(stderr),sha256=sha(stderr)))
    return dict(schema='ptlc-nom-dev-661b5ef-runtime-values-v1',
        outcome='PASS_SOURCE_SELECTED_RUNTIME_TESTS_ONLY',core_commit=CORE,core_tree=TREE,
        complete_profiles=9,required_top_level_tests=58,
        observed_descendants=sum(row['observed_descendants'] for row in reports.values()),
        profiles=reports,original_streams=18,independent_ptlc_values='SEPARATE',
        application='NO-GO',core='NO-GO',recovery_action='NONE',
        native_execution='NOT_PERFORMED_BY_READER',independent_assessment='UNFILLED')
