"""Select a finite native comparison of the exact ab8ee8d source."""
import io
import re
import zipfile

from qualification import nom_dev_ab8ee8d_source as upstream
from qualification import nom_dev_18c048a as previous
from qualification import nom_dev_008bdcd_native as baseline
from qualification.nom_current_admission import MIB, PREFIX, decoded, physical, regular, require
from qualification.nom_fee_original_boundary import compare_files
from scripts import prepare_nom_18c048a as preparation

ROOT = upstream.ROOT
ARCHIVE = dict(bytes=2264616,
    sha256='4f1e9dd18c875dbc76f2f0e3e58345cc90e64f7f202c2443c0b0ee31abd1584b')
ARCHIVE_PREFIX = 'zenon-network-go-zenon-ab8ee8d'
DRIVER = 'compatibility/core_overlay_test.go.txt'
PROBE = 'vm/embedded/implementation/zz_research_compatibility_test.go'
FIXTURES = ('pr138_messages_v1.json', 'pr138_witnesses_v1.json',
    'nom_terms_v1.json', 'nom_completions_v1.json')
ROOTS = {
    'chain/account/mailbox': (
        'TestGetUnreceivedAccountBlockHashesAtMost',
        'TestForEachUnreceivedAccountBlockHash',
    ),
    'chain/cache/storage': ('TestAddInverseReadFailureWritesNothing',),
    'chain/momentum': ('TestGetMomentumBeforeTime_SubsecondTargetTerminates',),
    'chain/nom': (
        'TestAccountBlock_UnmarshalJSON_AmountLengthIsBounded',
        'TestAccountBlock_UnmarshalJSON_DescendantDecodeIsLinear',
        'TestAccountBlock_UnmarshalJSON_DeepRejectionIsLinear',
        'TestAccountBlock_UnmarshalJSON_RepeatedDescendantKeyMerges',
        'TestAccountBlock_UnmarshalJSON_DescendantNonceIsStillChecked',
        'TestAccountBlock_MarshalJSON_NestedDescendantsRoundTrip',
        'TestAccountBlockMarshal_Check_DescendantDepthIsBounded',
        'TestAccountBlock_MarshalJSON_PreservesNilDescendantEntries',
    ),
    'common/db': ('TestLevelDBManagerAddInverseReadFailureWritesNothing',),
    'protocol': ('TestValidationFailureClassification',),
    'rpc/api': (
        'TestAccountBlock_UnmarshalJSON_DescendantDecodeIsLinear',
        'TestGetUnreceivedBlocksByAddress_PagesPastFirst500',
        'TestGetUnreceivedBlocksByAddress_WidensPastReceivedEntries',
        'TestGetUnreceivedBlocksByAddress_SmallMailboxUnchanged',
        'TestGetUnreceivedBlocksByAddress_StopsBeforeTrailingTombstones',
        'TestGetUnreceivedBlocksByAddress_ScanBound',
        'TestGetUnreceivedBlocksByAddress_ExactlyAtScanBound',
    ),
    'verifier': (
        'TestAccountBlockVerifier_NoAccountChain_ReturnsPreviousMissing',
        'TestAccountBlockVerifier_NoAccountChain_TransactionReturnsPreviousMissing',
        'TestAccountBlockVerifier_FirstBlockOfANewAccountChainIsAccepted',
        'TestIsValidationError',
        'TestDescendantVerifyErrorKeepsItsCause',
        'TestEmbeddedRefundRecoveryHeight',
        'TestEmbeddedRefundRecoveryHeight_LongStallIsLogarithmic',
    ),
    'vm': (
        'TestRollbackBeforeSave_RefundsTheSender',
        'TestRollbackBeforeSave_ZeroAmountHasNoRefund',
    ),
    'vm/abi': (
        'TestPack_FixedWidthValueMustMatchDeclaredSize',
        'TestPack_FixedWidthValueOfDeclaredSize',
        'TestPack_ZenonFixedWidthTypesRoundTrip',
        'TestPack_FixedWidthElementsMustMatchDeclaredSize',
        'TestTypeCheck_EmptySliceOfFixedArrays',
    ),
    'vm/embedded/definition': (
        'TestPtlcUnlockMessageVectors',
        'TestPtlcReclaimMessageVectors',
    ),
    'vm/embedded/implementation': ('TestResearchPR138CompatibilityCorpus',),
    'vm/vm_context': (
        'TestReset_BeforeSaveKeepsTheLiveStore',
        'TestDone_BeforeSaveKeepsTheLiveStore',
        'TestReset_TwiceKeepsTheRestoredStore',
    ),
    'chain': (
        'TestAcknowledgementRequirement_StaleAcknowledgementRejectedAfterEnforcement',
        'TestAcknowledgementRequirement_TwoSporksEnforced',
        'TestAcknowledgementRequirement_InactiveAndScheduledSporksImposeNothing',
        'TestAcknowledgementRequirement_DelayedActivationReceive',
        'TestAcknowledgementRequirement_PreActivationParentUnaffected',
        'TestAcknowledgementRequirement_EmbeddedBlocksExempt',
        'TestAcknowledgementRequirement_NonCanonicalAcknowledgementRejected',
        'TestAcknowledgementRequirement_SporkReadFailureIsError',
        'TestNewAcknowledgementRequirement_ReadsSporkContractStorage',
        'TestAcknowledgementRequirement_FilterDropsFailingSuffix',
        'TestAccountPool_StaleAcknowledgementEvictedWithSuffix',
        'TestAccountPool_UnreadableAcknowledgementKept',
        'TestAccountPool_StaleAcknowledgementRejectedAtAdmission',
        'TestAccountPool_UnreadableRequirementRefusesAdmission',
    ),
    'node': (
        'TestRPCConfigDefaultHTTPAdmissionLimits',
        'TestEffectiveMaxHTTPConnections',
        'TestEnableRPCTakesConfiguredRequestLimit',
        'TestHTTPMaxConnectionsCapsListener',
        'TestHTTPMaxConnectionsNegativeIsUncapped',
        'TestHTTPAdmissionCoversGzipClose',
        'TestHTTPMaxConnectionsCountsSlowHeaders',
        'TestHTTPMaxConnectionsZeroSelectsDefault',
        'TestHTTPAdmissionRefusalAppliesCors',
    ),
    'pillar': ('TestContentSelector_SkipsStaleAcknowledgementAndSuffix',),
    'protocol/downloader': (
        'TestHashFetchQueueFullFlagReachesBlockFetcher',
        'TestBlockFetchCompletesAfterQueueFull',
        'TestHashFetchStopFlagReleasedByCancel',
        'TestBlockFetchCompletesAfterEmptyReply',
        'TestHashFetchTruncatesOversizedReply',
        'TestSynchroniseClearsStaleContinuationFlag',
        'TestBlockFetchWithheldHeadEndsSession',
        'TestBlockFetchNoStallWhileImportBusy',
        'TestBlockFetchProgressResetsStallTimer',
        'TestBlockFetchNoStallWhenIdle',
        'TestBlockFetchLongImportResetsStallWindow',
        'TestSynchroniseStallDropGatedOnInFlight',
        'TestSynchroniseCacheFullStallNoDrop',
        'TestBlockFetchStallCapturesInFlight',
        'TestBlockFetchDeadStateGuard',
        'TestBlockFetchOmittedHeadCacheFull',
        'TestBlockFetchImportFreesCapacityDuringPass',
        'TestQueueNoProgress',
    ),
    'rpc/server': (
        'TestDefaultMaxConcurrentHTTPRequests',
        'TestHTTPAdmissionRefusesExcessRequest',
        'TestHTTPAdmissionReleasedOnPanic',
        'TestHTTPAdmissionReleasedOnContextCancel',
        'TestHTTPAdmissionBatches',
        'TestHTTPAdmissionLeavesWebSocketUnchanged',
        'TestHTTPAdmissionErrorThroughClient',
        'TestHTTPAdmissionHeldThroughReplyWrite',
        'TestHTTPAdmissionHeldWhileBodyDrains',
        'TestHTTPAdmissionRefusalClosesIncompleteBody',
        'TestHTTPAdmissionCoversEarlyAnswers',
        'TestHTTPAdmissionExpectContinueEarlyAnswer',
        'TestHTTPAdmissionExpectContinueServed',
        'TestHTTPAdmissionExpectContinueRefused',
    ),
    'vm/embedded/tests': (
        'TestMomentumContent_StaleAcknowledgementRejectedAfterEnforcement',
        'TestMomentumContent_StaleAcknowledgementReceiveWithDataRejected',
        'TestAccountPool_StaleAcknowledgementEvictedWithSuffix_EndToEnd',
        'TestMomentumContent_PreActivationParentUnaffected',
        'TestAccountPool_StaleAcknowledgementRejectedAfterFrontierMoves',
        'TestEmbeddedRefund_BeforeSporkStallsQueue',
        'TestEmbeddedRefund_AfterSporkRefundsAndAdvances',
        'TestEmbeddedRefund_SporkRecoversStalledQueue',
        'TestEmbeddedRefund_LateActivationRecoversStalledQueue',
        'TestEmbeddedSendData_BeforeSpork_ArgumentBytesUnpricedAndUnbounded',
        'TestEmbeddedSendData_AfterSpork_OversizedArgumentsRejected',
        'TestEmbeddedSendData_AfterSpork_ArgumentBytesPriced',
        'TestEmbeddedSendData_UnlockPreimageBound',
        'TestEmbeddedSendData_BridgeSignatureStringBound',
        'TestEmbeddedSendData_AfterSpork_CanonicalRecomputeMatchesApplied',
        'TestEmbeddedSendData_QuoteAtEnforcementMomentum',
        'TestEmbeddedSendData_RulesFollowAcknowledgedMomentum',
        'TestEmbeddedSendData_AfterSpork_CapBoundaryWithAbiOverhead',
        'TestEmbeddedSendData_BridgeSignatureLineBreakEndToEnd',
        'TestSporkGated_ReceiveBlockDataRejectedAfterSpork',
        'TestSporkGated_ReceiveBlockDataAcceptedBeforeSpork',
        'TestSporkGated_EmbeddedSendTrailingBytesRejectedAfterSpork',
        'TestSporkGated_EmbeddedSendNoTrailingBytesAcceptedAfterSpork',
        'TestSporkGated_PreEnforcementBlockRejectedAfterSpork',
        'TestSporkGated_PreSporkEmbeddedSendReceivedAfterSpork',
        'TestSporkGated_ExternalSignedReceiveWithDataRejectedAfterSpork',
        'TestSporkGated_ExternalSignedReceiveEmptyDataAcceptedAfterSpork',
        'TestSporkGated_NominateGuardiansSendRejectedAfterSpork',
        'TestSporkGated_NominateGuardiansSendAcceptedBeforeSpork',
        'TestSporkGated_NominateGuardiansValidSetAcceptedAfterSpork',
        'TestSporkGated_PreSporkNominateGuardiansReceivedAfterSpork',
    ),
}
PACKAGES = tuple('./' + package for package in ROOTS)
TEST_FILTER = '^(' + '|'.join(re.escape(name)
    for name in sorted({name for roots in ROOTS.values() for name in roots})) + ')$'
TEST_ARGUMENTS = ('test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                  '-timeout=4m', '-run', TEST_FILTER, *PACKAGES)


def selection(root=ROOT):
    require(len(ROOTS) == 19 and sum(map(len, ROOTS.values())) == 128
        and sum(map(len, baseline.ROOTS.values())) == 39
        and all(set(roots) <= set(ROOTS.get(package, ())) for package, roots in baseline.ROOTS.items()))
    source, index = upstream.inputs(root)
    require(PROBE not in index)
    names = (DRIVER, *('compatibility/fixtures/' + name for name in FIXTURES))
    pins = {name: previous.sha(regular(root / name, 2*MIB)) for name in names}
    paths = {name: row['sha256'] for name, row in index.items()}
    paths[PROBE] = pins[DRIVER]
    return dict(core_commit=source['tracked_core_commit'], core_tree=source['tracked_core_tree'],
        index_sha256=source['source_index_sha256'], source_files=len(index), archive=ARCHIVE,
        project_input_sha256=pins, test_roots={key: list(roots) for key, roots in ROOTS.items()},
        test_arguments=list(TEST_ARGUMENTS), baseline_core=baseline.upstream.CORE,
        baseline_parents=39, added_parents=89, selection_scope='FINITE_128_PARENTS_IN_19_PACKAGES'), index, paths


def prepare(archive, destination, root=ROOT):
    """Check and materialize one source view with the existing MIT test overlay."""
    destination = physical(destination)
    selection_record, index, paths = selection(root)
    raw = regular(archive, ARCHIVE['bytes'])
    require(len(raw) == ARCHIVE['bytes'] and previous.sha(raw) == ARCHIVE['sha256'])
    with zipfile.ZipFile(io.BytesIO(raw)) as original:
        payloads = preparation.checked_payloads(original, index, archive_prefix=ARCHIVE_PREFIX)
    payloads[PROBE] = regular(root / DRIVER, 2*MIB)
    require(previous.sha(payloads[PROBE]) == selection_record['project_input_sha256'][DRIVER])
    for package, roots in ROOTS.items():
        declared = [name.decode('ascii') for path, content in payloads.items()
            if path.rsplit('/', 1)[0] == package and path.endswith('_test.go')
            for name in re.findall(rb'^func (Test[A-Za-z0-9_]+)\(', content, re.M)]
        require('TestMain' not in declared
            and sorted(name for name in declared if re.fullmatch(TEST_FILTER, name)) == sorted(roots))
    preparation.write_payloads(destination, payloads)
    return compare_files(destination, paths)


def accept_events(raw):
    return previous.package_events(raw, {PREFIX + key: set(roots) for key, roots in ROOTS.items()})


EVENT_SCHEMA = 'ptlc-nom-original-non-output-events-v1'
EVENT_SCOPE = 'EVERY_ORIGINAL_NON_OUTPUT_EVENT_LINE'


def original_event_selection(raw):
    """Validate the full private stream, then select exact original event lines."""
    complete = accept_events(raw)
    rows = raw.splitlines(keepends=True)
    require(len(rows) == complete['events'] and all(row.endswith(b'\n') for row in rows))
    kept = [row for row in rows if decoded(row, 65536)['Action'] != 'output']
    original = dict(bytes=len(raw), sha256=previous.sha(raw))
    content = b''.join(kept)
    record = dict(schema=EVENT_SCHEMA, selection=EVENT_SCOPE,
        original_stdout=original, original_events=len(rows),
        omitted_output_events=len(rows)-len(kept), selected_events=len(kept),
        selected_stream=dict(bytes=len(content), sha256=previous.sha(content)),
        full_stdout_acceptance='NOT_CLAIMED',
        selection_completeness_by_reader='NOT_ESTABLISHED')
    accept_selected_events(content, record, original, complete)
    return content, record, complete


def accept_selected_events(raw, record, original, complete):
    """Check retained original rows without claiming unavailable stdout custody."""
    require(type(record) is type(original) is type(complete) is dict)
    require(set(record) == {'schema', 'selection', 'original_stdout', 'original_events',
        'omitted_output_events', 'selected_events', 'selected_stream',
        'full_stdout_acceptance', 'selection_completeness_by_reader'})
    require(record['schema'] == EVENT_SCHEMA and record['selection'] == EVENT_SCOPE
        and record['full_stdout_acceptance'] == 'NOT_CLAIMED'
        and record['selection_completeness_by_reader'] == 'NOT_ESTABLISHED')
    for pin in (original, record['original_stdout'], record['selected_stream']):
        require(type(pin) is dict and set(pin) == {'bytes', 'sha256'}
            and type(pin['bytes']) is int and 0 < pin['bytes'] <= previous.MAX_STREAM
            and type(pin['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', pin['sha256']) is not None)
    require(record['original_stdout'] == original
        and record['selected_stream'] == dict(bytes=len(raw), sha256=previous.sha(raw))
        and len(raw) <= original['bytes'])
    for key in ('original_events', 'omitted_output_events', 'selected_events'):
        require(type(record[key]) is int and 0 <= record[key] <= 10000)
    require(record['selected_events'] > 0
        and record['original_events'] == record['selected_events'] + record['omitted_output_events'])
    if record['omitted_output_events'] == 0:
        require(record['original_stdout'] == record['selected_stream'])
    else:
        require(original['bytes'] - len(raw) >= record['omitted_output_events'])
    rows = raw.splitlines()
    require(len(rows) == record['selected_events'])
    for row in rows:
        value = decoded(row, 65536)
        require(type(value) is dict and value.get('Action') != 'output' and 'Output' not in value)
    measured = accept_events(raw)
    require(set(complete) == set(measured)
        and all(type(value) is int and value > 0 for value in complete.values())
        and complete['events'] == record['original_events']
        and measured['events'] == record['selected_events']
        and all(complete[key] == value for key, value in measured.items() if key != 'events'))
    return dict(measured, evidence_scope=EVENT_SCOPE, full_stdout_acceptance='NOT_CLAIMED',
                selection_completeness_by_reader='NOT_ESTABLISHED')
