"""Independent finite pricing arithmetic; no ABI, quote or recovery authority."""
import ast
import hashlib
from pathlib import Path

from qualification import nom_dev_661b5ef_source as source
from qualification import nom_current_admission as common
from qualification import nom_dev_abi_boundary as framing

ROOT, CORE, TREE = source.ROOT, source.CORE, source.TREE
require = common.require
MANIFEST = 'compatibility/nom_embedded_argument_pricing_manifest.json'
INPUT = 'compatibility/fixtures/nom_embedded_argument_pricing_inputs_v1.json'
VALUES = 'compatibility/fixtures/nom_embedded_argument_pricing_values_v1.json'
DRIVER = 'compatibility/nom_embedded_argument_pricing_test.go.txt'
DESTINATION = 'vm/zz_research_nom_embedded_argument_pricing_test.go'
FRAMING = 'qualification/nom_dev_abi_boundary.py'
UNIT = 'argument-pricing'
PARENT = 'TestResearchNoMEmbeddedArgumentPricing'
PACKAGE = 'github.com/zenon-network/go-zenon/vm'
MAX_STDOUT, MAX_STDERR, MAX_REPORT, MAX_EVENTS = 2*common.MIB, 64*1024, common.MIB, 4096
SCOPE = 'HELPER ONLY; ABI, ADMISSION, QUOTE AND RECOVERY NOT ESTABLISHED'
OWN_INPUTS = {INPUT, VALUES, DRIVER, FRAMING, source.SOURCE,
    'qualification/nom_dev_661b5ef_source.py',
    'qualification/nom_embedded_argument_pricing.py',
    'tests/test_nom_embedded_argument_pricing.py'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def declaration():
    tiers = [('zero',0),('base',21000),('balance',52500),('withdraw',73500),('max',(1<<64)-1)]
    lengths = [('min_int',-(1<<63)),('negative',-1),('empty',0),('one',1),
        ('three',3),('selector',4),('first_argument',5),('thirty_one',31),
        ('thirty_two',32),('thirty_five',35),('word',36),('two_words',68),
        ('below_cap',16383),('at_cap',16384),('above_cap',16385),
        ('large_int',(1<<31)-1),('max_int',(1<<63)-1)]
    cases = [dict(id=t+'_'+n,tier=str(tier),data_length=str(length))
        for t,tier in tiers for n,length in lengths]
    require(len(cases)==85 and len({row['id'] for row in cases})==85)
    return dict(schema='ptlc-nom-embedded-argument-pricing-inputs-v1',
        core_commit=CORE,core_tree=TREE,scope=SCOPE,word_bits='64',
        argument_byte_plasma='68',data_cap='16384',cases=cases)


def cost(tier, data_length):
    require(type(tier) is int and 0<=tier<(1<<64)
        and type(data_length) is int and -(1<<63)<=data_length<(1<<63))
    if data_length>16384:
        return 0,'AB_DATA_TOO_BIG'
    # This models the selected helper's unsigned machine result. Its callers
    # supply fixed method tiers; overflow probes are not valid user quotes.
    argument_bytes = max(0,data_length-4)
    return (tier+68*argument_bytes) % (1<<64),'NONE'


def expected_report(declared=None):
    declared = declaration() if declared is None else declared
    common.rebase.exact(declaration(),declared)
    records = {}
    for case in declared['cases']:
        result,error = cost(int(case['tier']),int(case['data_length']))
        records[case['id']] = dict(tier=case['tier'],data_length=case['data_length'],
            base_plasma=str(result),returned_error=error)
    return dict(schema='ptlc-nom-embedded-argument-pricing-result-v1',
        core_commit=CORE,core_tree=TREE,scope=SCOPE,word_bits='64',
        argument_byte_plasma='68',data_cap='16384',records=records,
        application='NO-GO',core='NO-GO',recovery_action='NONE')


def inputs(root=ROOT):
    root = common.physical(root)
    unused,index = source.inputs(root)
    decoded = lambda name:common.decoded(common.regular(root/name,2*common.MIB),2*common.MIB)
    manifest = decoded(MANIFEST)
    fixed = dict(schema='ptlc-nom-embedded-argument-pricing-selection-v1',
        core_commit=CORE,core_tree=TREE,source_files=518,cases=85,outcomes=86,
        scope=SCOPE,unit=UNIT,parent=PARENT,package=PACKAGE,producer=DRIVER,
        abi_selector_bytes=4,argument_byte_plasma=68,data_cap=16384,word_bits=64,
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        application='NO-GO',core='NO-GO',recovery_action='NONE',independent_assessment='UNFILLED')
    require(set(manifest)==set(fixed)|{'input_sha256','upstream_sha256'})
    common.rebase.exact(fixed,{key:manifest[key] for key in fixed})
    require(set(manifest['input_sha256'])==OWN_INPUTS)
    for name,digest in manifest['input_sha256'].items():
        require(sha(common.regular(root/name,2*common.MIB))==digest)
    files = ('vm/plasma.go','vm/plasma_embedded_test.go','vm/constants/plasma.go')
    common.rebase.exact({name:index[name]['sha256'] for name in files},manifest['upstream_sha256'])
    declared = decoded(INPUT)
    common.rebase.exact(declaration(),declared)
    common.rebase.exact(expected_report(declared),decoded(VALUES))
    return manifest,declared


def input_bindings(root=ROOT):
    inputs(root)
    return {'PTLC_NOM_ARGUMENT_PRICING_INPUT':{'repository_file':INPUT}}


def plan(root=ROOT):
    inputs(root)
    return dict(unit=UNIT,package='vm',parent=PARENT,parent_and_child_outcomes=86,
        prior_streams_required=[],arguments=['test','-json','-p','2','-mod=readonly',
            '-count=1','-run','^'+PARENT+'$','./vm'])


def report_from_events(raw,root=ROOT):
    require(type(raw) is bytes and 0<len(raw)<=MAX_STDOUT and raw.endswith(b'\n'))
    unused,declared = inputs(root)
    expected = expected_report(declared)
    selected = {PACKAGE:{PARENT}|{PARENT+'/'+name for name in expected['records']}}
    measured = common.event_stream(raw,selected)
    require(measured['passed_including_parent']==86)
    original = common.regular(Path(root)/FRAMING,2*common.MIB)
    nodes = [node for node in ast.parse(original).body
        if isinstance(node,ast.FunctionDef) and node.name=='report_from_events']
    require(len(nodes)==1)
    namespace = dict(vars(framing))
    namespace.update(PARENT=PARENT,PACKAGE=PACKAGE,MAX_STDOUT=MAX_STDOUT,
        MAX_STDERR=MAX_STDERR,MAX_REPORT=MAX_REPORT,MAX_EVENTS=MAX_EVENTS,
        scenarios=lambda:expected['records'],expected_report=lambda:expected)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<unchanged-pricing-framing>',
        'exec',dont_inherit=True),namespace)
    report,stats = namespace['report_from_events'](raw)
    require(stats['passed_including_parent']==27)
    stats.update(passed_including_parent=86,historical_summary_outcomes=27,
        framing_source_sha256=sha(original),imported_module_mutated=False)
    return report,stats


def compare_payloads(payloads,root=ROOT):
    require(type(payloads) is dict and set(payloads)=={UNIT+'.stdout',UNIT+'.stderr'})
    require(all(type(raw) is bytes for raw in payloads.values())
        and len(payloads[UNIT+'.stderr'])<=MAX_STDERR)
    report,stats = report_from_events(payloads[UNIT+'.stdout'],root)
    return dict(schema='ptlc-nom-embedded-argument-pricing-comparison-v1',
        outcome='PASS_FINITE_HELPER_VALUES_ONLY',core_commit=CORE,core_tree=TREE,
        cases=85,outcomes=86,report=report,stdout=stats,
        stderr=dict(bytes=len(payloads[UNIT+'.stderr']),sha256=sha(payloads[UNIT+'.stderr'])),
        scope=SCOPE,native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER',actual_command_exit='NOT_ESTABLISHED_BY_READER',
        application='NO-GO',core='NO-GO',recovery_action='NONE',independent_assessment='UNFILLED')
