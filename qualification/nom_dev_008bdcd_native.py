"""Select a finite native comparison of the exact 008bdcd source."""
import io
import re
import zipfile

from qualification import nom_dev_008bdcd_source as upstream
from qualification import nom_dev_18c048a as previous
from qualification.nom_current_admission import MIB, PREFIX, physical, regular, require
from qualification.nom_fee_original_boundary import compare_files
from scripts import prepare_nom_18c048a as preparation

ROOT = upstream.ROOT
ARCHIVE = dict(bytes=2209732,
    sha256='bb6db6683795515669b88cb8e293c32e00494514d388324ebe5af55b4d63849a')
ARCHIVE_PREFIX = 'zenon-network-go-zenon-008bdcd'
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
    'vm/embedded/definition': ('TestPtlcUnlockMessageVectors', 'TestPtlcReclaimMessageVectors'),
    'vm/embedded/implementation': ('TestResearchPR138CompatibilityCorpus',),
    'vm/vm_context': (
        'TestReset_BeforeSaveKeepsTheLiveStore',
        'TestDone_BeforeSaveKeepsTheLiveStore',
        'TestReset_TwiceKeepsTheRestoredStore',
    ),
}
PACKAGES = tuple('./' + package for package in ROOTS)
TEST_FILTER = '^(' + '|'.join(re.escape(name)
    for name in sorted({name for roots in ROOTS.values() for name in roots})) + ')$'
TEST_ARGUMENTS = ('test', '-json', '-p', '2', '-mod=readonly', '-count=1',
                  '-timeout=4m', '-run', TEST_FILTER, *PACKAGES)


def selection(root=ROOT):
    source, index = upstream.inputs(root)
    require(PROBE not in index)
    names = (DRIVER, *('compatibility/fixtures/' + name for name in FIXTURES))
    pins = {name: previous.sha(regular(root / name, 2*MIB)) for name in names}
    paths = {name: row['sha256'] for name, row in index.items()}
    paths[PROBE] = pins[DRIVER]
    return dict(core_commit=source['tracked_core_commit'], core_tree=source['tracked_core_tree'],
        index_sha256=source['source_index_sha256'], source_files=len(index), archive=ARCHIVE,
        project_input_sha256=pins, test_roots={key: list(roots) for key, roots in ROOTS.items()},
        test_arguments=list(TEST_ARGUMENTS)), index, paths


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
