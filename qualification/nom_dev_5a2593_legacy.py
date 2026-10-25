"""Current-source legacy expectations; execution and new reclaim paths are separate."""
import ast
import copy
import hashlib
import json
from pathlib import Path

from qualification import nom_dev_5cb as prior
from qualification import nom_dev_5cb_reproduction as prior_reproduction
from qualification import nom_keyless_supervisor as prior_keyless
from qualification import nom_dev_5a2593_source as source

ROOT = source.ROOT
CORE, TREE = source.CORE, source.TREE
MANIFEST = 'compatibility/nom_dev_5a2593_legacy_manifest.json'
VARIANTS = 'compatibility/nom_dev_5a2593_legacy_variants_v1.json'
KEYLESS_INPUT = 'compatibility/fixtures/nom_dev_5a2593_keyless_inputs_v1.json'
KEYLESS_VALUES = 'compatibility/fixtures/nom_dev_5a2593_keyless_values_v1.json'
PROFILES = prior.PROFILES
AUXILIARY = prior.AUXILIARY
MAX_TOTAL = prior.MAX_TOTAL
earlier = prior.earlier
require = earlier.require
FROZEN = {
    'qualification/nom_dev_5cb.py':'3ee5b4667b8af10a8693802fbe056a1bc04c4c9ef542159c8b714426b33e4868',
    'qualification/nom_keyless_supervisor.py':'bd55e2ad506fcfd03f0e05a4ee9fadf0d6b772dd6de0e94576a74784343f3a53',
    'qualification/nom_dev_5cb_reproduction.py':'098bd8952dc14766b5dcfde2f459e8b5563467cddf2fe5c28380a5f90403a189',
}
PRODUCERS = {'compatibility/nom_dev_5a2593_'+kind+'_test.go.txt' for kind in AUXILIARY}|{
    'compatibility/nom_dev_5a2593_keyless_supervisor_test.go.txt'}
OWN_INPUTS = {source.SOURCE,'qualification/nom_dev_5a2593_source.py',
    'qualification/nom_dev_5a2593_legacy.py','tests/test_nom_dev_5a2593_legacy.py',
    VARIANTS,KEYLESS_INPUT,KEYLESS_VALUES}|PRODUCERS


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path):
    return earlier.decoded(earlier.regular(path,2*earlier.MIB),2*earlier.MIB)


def variants(root=ROOT):
    root=Path(root)
    value=read_json(root/VARIANTS)
    require(set(value)=={'schema','core_commit','variants'})
    require(value['schema']=='ptlc-nom-dev-5a2593-legacy-variants-v1' and value['core_commit']==CORE)
    rows=value['variants']
    require(set(rows)=={'compatibility/nom_dev_5cb_'+kind+'_test.go.txt' for kind in AUXILIARY}|{
        'compatibility/nom_dev_5cb_keyless_supervisor_test.go.txt'})
    require({row['selected'] for row in rows.values()}==PRODUCERS)
    for parent,row in rows.items():
        require(set(row)=={'selected','original_sha256','selected_sha256','edits','scope'})
        original=earlier.regular(root/parent,2*earlier.MIB)
        selected=earlier.regular(root/row['selected'],2*earlier.MIB)
        require(sha(original)==row['original_sha256'] and sha(selected)==row['selected_sha256'])
        require(row['scope']=='EXPLICIT CURRENT-SOURCE LABEL; ALL PRODUCER LOGIC UNCHANGED')
        require(len(row['edits'])==1)
        edit=row['edits'][0]
        require(set(edit)=={'before','after','after_position'})
        require(edit['before']==prior.CORE and edit['after']==CORE)
        at=edit['after_position'];require(type(at) is int and at>=0)
        body=selected.decode('ascii')
        require(body[at:at+len(CORE)]==CORE)
        require((body[:at]+prior.CORE+body[at+len(CORE):]).encode('ascii')==original)
    return rows


def inputs(root=ROOT):
    root=earlier.physical(root)
    description,index=source.inputs(root)
    prior.inputs(root)
    fixed=dict(schema='ptlc-nom-dev-5a2593-legacy-selection-v1',core_commit=CORE,core_tree=TREE,
        source_files=500,source_index_sha256=source.INDEX_SHA256,legacy_profiles=20,legacy_outcomes=479,
        historical_core=prior.CORE,historical_value_changes='NONE_SELECTED; FRESH_EXECUTION_REQUIRED',
        reclaim_profile='SEPARATE_REQUIRED',journal_source_upgrade='NOT_SELECTED',application='NO-GO',core='NO-GO',
        independent_assessment='UNFILLED')
    manifest=read_json(root/MANIFEST)
    require(set(manifest)==set(fixed)|{'input_sha256','frozen_input_sha256'})
    earlier.rebase.exact(fixed,{key:manifest[key] for key in fixed})
    require(set(manifest['input_sha256'])==OWN_INPUTS and manifest['frozen_input_sha256']==FROZEN)
    for name,pin in dict(manifest['input_sha256'],**FROZEN).items():
        require(sha(earlier.regular(root/name,2*earlier.MIB))==pin)
    variants(root)
    return manifest,index


def probes(root=ROOT,profile='all'):
    require(profile in PROFILES)
    rows=variants(root)
    return {destination:rows[parent]['selected'] if parent in rows else parent
        for destination,parent in prior.probes(root,profile).items()}


def _functions(root,module,names,namespace):
    filename=module.__name__.replace('.','/')+'.py'
    raw=earlier.regular(Path(root)/filename,2*earlier.MIB)
    require(sha(raw)==FROZEN[filename])
    nodes=[node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef) and node.name in names]
    require(len(nodes)==len(names) and {node.name for node in nodes}==set(names))
    tree=ast.Module(body=nodes,type_ignores=[])
    binding=dict(source_sha256=sha(raw),unchanged_functions=sorted(names),
        function_ast_sha256=sha(ast.dump(tree,include_attributes=False).encode('ascii')),
        imported_module_mutated=False)
    exec(compile(tree,'<current-source-legacy-reference>', 'exec',dont_inherit=True),namespace)
    return namespace,binding


def reference(root=ROOT):
    names={'auxiliary_reader','vectors','context_fixture','context_reader','compare_components'}
    namespace=dict(vars(prior));namespace.update(CORE=CORE,TREE=TREE,ROOT=Path(root))
    return _functions(root,prior,names,namespace)


def keyless_reference(root=ROOT):
    names={'sha','uint','number','replace_bytes','expected','read'}
    namespace=dict(vars(prior_keyless));namespace.update(CORE=CORE)
    return _functions(root,prior_keyless,names,namespace)


def keyless_inputs(root=ROOT):
    old,signed,plasma=prior_keyless.inputs(Path(root))
    declared=read_json(Path(root)/KEYLESS_INPUT)
    require(declared['selected_core']==CORE and declared['selected_tree']==TREE)
    inverse=copy.deepcopy(declared);inverse.update(selected_core=prior.CORE,selected_tree=prior.TREE)
    earlier.rebase.exact(old,inverse)
    fixture=read_json(Path(root)/KEYLESS_VALUES)
    require(fixture['core_commit']==CORE)
    inverse=copy.deepcopy(fixture);inverse['core_commit']=prior.CORE
    earlier.rebase.exact(read_json(Path(root)/prior.KEYLESS_VALUES),inverse)
    namespace,binding=keyless_reference(root)
    earlier.rebase.exact(fixture['records'],namespace['expected'](declared,signed,plasma))
    return declared,signed,plasma


def units(profile='all'):
    return prior.units(profile)


def compare_source(directory,root=ROOT,profile='all'):
    namespace=dict(vars(prior));namespace.update(CORE=CORE,TREE=TREE,inputs=inputs,probes=probes)
    bound,unused=_functions(root,prior,{'compare_source'},namespace)
    return bound['compare_source'](directory,root,profile)


def compare_payloads(payloads,root=ROOT,profile='all'):
    inputs(root)
    required={unit+suffix for unit in units(profile) for suffix in ('.stdout','.stderr')}
    require(type(payloads) is dict and set(payloads)==required)
    require(all(type(raw) is bytes for raw in payloads.values()) and sum(map(len,payloads.values()))<=MAX_TOTAL)
    result=dict(schema='ptlc-nom-dev-5a2593-legacy-values-v1',core_commit=CORE,core_tree=TREE,profile=profile,
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_READER',reclaim_profile='SEPARATE_REQUIRED',
        journal_source_upgrade='NOT_SELECTED',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    if profile!='keyless':
        namespace,binding=reference(root)
        components=namespace['compare_components']({name:raw for name,raw in payloads.items()
            if name.rsplit('.',1)[0] in earlier.COUNTS},root)
        require(components['source_files']==482 and components['selected_core']==CORE)
        components.update(schema='ptlc-nom-dev-5a2593-legacy-components-v1',source_files=500,
            historical_summary_source_files=482)
        result.update(components=components,reference_binding=binding)
        auxiliary={}
        for kind,count in AUXILIARY.items():
            unit=kind.replace('_','-');stderr=payloads[unit+'.stderr']
            require(len(stderr)<=64*1024)
            read,expected,selected_binding,unused=namespace['auxiliary_reader'](kind,root)
            report,stats=read(payloads[unit+'.stdout']);earlier.rebase.exact(expected,report)
            auxiliary[kind]=dict(cases=count,native_report=report,stdout=stats,
                stderr=dict(bytes=len(stderr),sha256=sha(stderr)),reader_binding=selected_binding)
        result['auxiliary']=auxiliary
    if profile!='components':
        declared,signed,plasma=keyless_inputs(root)
        namespace,binding=keyless_reference(root)
        stderr=payloads['keyless-supervisor.stderr'];require(len(stderr)<=64*1024)
        report,stats=namespace['read'](payloads['keyless-supervisor.stdout'],declared,signed,plasma)
        result['keyless']=dict(cases=24,native_report=report,stdout=stats,reference_binding=binding,
            stderr=dict(bytes=len(stderr),sha256=sha(stderr)))
    result['outcome']='PASS_SELECTED_LEGACY_VALUES_ONLY'
    return result


def plan(root=ROOT,profile='all'):
    inputs(root)
    value=copy.deepcopy(prior_reproduction.plan(root,profile))
    value.update(schema='ptlc-nom-dev-5a2593-legacy-plan-v1',core_commit=CORE,core_tree=TREE,
        producers=probes(root,profile),reclaim_profile='SEPARATE_REQUIRED')
    return value


def input_bindings(unit,prior_streams=None,root=ROOT):
    inputs(root)
    value=copy.deepcopy(prior_reproduction.input_bindings(unit,prior_streams,root))
    if unit=='keyless-supervisor':
        require(value['PTLC_NOM_KEYLESS_ORIGINAL_INPUT']=={'repository_file':prior.KEYLESS_INPUT})
        value['PTLC_NOM_KEYLESS_ORIGINAL_INPUT']={'repository_file':KEYLESS_INPUT}
    return value
