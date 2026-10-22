"""Read the finite 5cb source selection; no execution or recovery authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('5cb comparison requires assertions enabled')
import ast
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import re

from qualification import nom_current_admission as earlier
from qualification import nom_dev_admission as previous
from scripts import qualify_nom_account_context as context
from scripts import qualify_nom_vm_path as vm

ROOT = earlier.ROOT
CORE = '5cb5aac3bb21d012111d87466f946cbdccd344f6'
TREE = '08c40433726d40dd84116bca4811c1a998417498'
SOURCE = 'compatibility/nom_dev_5cb_source_v1.json'
INDEX_SHA256 = '8e038bcf5ad3f9c668f6b887b2c88cc2a6a05339a0262c0c37871f620de8dd4f'
MANIFEST = 'compatibility/nom_dev_5cb_manifest.json'
VARIANTS = 'compatibility/nom_dev_5cb_variants_v1.json'
KEYLESS_INPUT = 'compatibility/fixtures/nom_dev_5cb_keyless_inputs_v1.json'
KEYLESS_VALUES = 'compatibility/fixtures/nom_dev_5cb_keyless_values_v1.json'
KEYLESS_PRODUCER = 'compatibility/nom_dev_5cb_keyless_supervisor_test.go.txt'
CONTEXT_SHA = 'ff05e5dbcc72fbf068c867f292960a088e4d839610243b3268ba1df2aaf80d9a'
RECEIVER_IDS = frozenset(leg+'-recipient-receive-'+kind for leg in ('long','short')
    for kind in ('wrong-recipient-before-enforcement','wrong-recipient-high-ack-low-frontier'))
RECEIVER_ERROR = 'ErrABFromBlockReceiverMismatch'
COMPONENT_VARIANTS = {
    'compatibility/nom_vm_path_verifier_test.go.txt',
    'compatibility/nom_pool_dependencies_test.go.txt',
    'compatibility/nom_dev_account_context_test.go.txt',
    'compatibility/nom_momentum_admission_test.go.txt',
}
AUXILIARY = {'receive_data':14,'abi_boundary':26,'send_caller':23}
SELECTED_PRODUCERS = {
    'compatibility/nom_dev_5cb_'+name+'_test.go.txt' for name in (
        'vm_receipt_verifier','pool_dependencies','account_context','momentum_admission',
        'receive_data','abi_boundary','send_caller')}
OWN_INPUTS = {SOURCE,VARIANTS,KEYLESS_INPUT,KEYLESS_VALUES,KEYLESS_PRODUCER,
    'qualification/nom_dev_5cb.py','qualification/nom_keyless_supervisor.py',
    'qualification/nom_dev_5cb_reproduction.py',
    'tests/test_nom_dev_5cb.py','tests/test_nom_keyless_supervisor.py'}|SELECTED_PRODUCERS
FROZEN_INPUTS = set(previous.probes().values())|{
    previous.MANIFEST,earlier.MANIFEST,'scripts/qualify_nom_account_context.py',
    'qualification/nom_dev_receive_data.py','qualification/nom_dev_abi_boundary.py',
    'qualification/nom_dev_send_caller.py',
    'compatibility/nom_dev_receive_data_test.go.txt',
    'compatibility/nom_dev_abi_boundary_test.go.txt',
    'compatibility/nom_dev_send_caller_test.go.txt',
    'compatibility/fixtures/nom_signed_originals_v1.json',
    'compatibility/fixtures/nom_supervisor_plasma_v1.json'}
PROFILES = ('all','components','keyless')
MAX_TOTAL = 72*earlier.MIB


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_json(path,limit=2*earlier.MIB):
    return earlier.decoded(earlier.regular(path,limit),limit)


def producer_variants(root=ROOT):
    value=read_json(Path(root)/VARIANTS)
    assert set(value)=={'schema','core_commit','variants'}
    assert value['schema']=='ptlc-nom-dev-5cb-producer-variants-v1' and value['core_commit']==CORE
    variants=value['variants']
    parents=COMPONENT_VARIANTS|{'compatibility/nom_dev_'+kind+'_test.go.txt' for kind in AUXILIARY}
    assert type(variants) is dict and set(variants)==parents
    assert {row['selected'] for row in variants.values()}==SELECTED_PRODUCERS
    for parent,row in variants.items():
        assert set(row)=={'selected','original_sha256','selected_sha256','edits','kind','scope'}
        original=earlier.regular(Path(root)/parent,2*earlier.MIB)
        candidate=earlier.regular(Path(root)/row['selected'],2*earlier.MIB)
        assert sha(original)==row['original_sha256'] and sha(candidate)==row['selected_sha256']
        assert type(row['edits']) is list and 1<=len(row['edits'])<=3
        body=candidate.decode('ascii')
        for edit in reversed(row['edits']):
            assert set(edit)=={'before','after','after_position'}
            before,after,at=edit['before'],edit['after'],edit['after_position']
            assert type(before) is type(after) is str and before!=after
            assert type(at) is int and 0<=at<=len(body)
            assert body[at:at+len(after)]==after
            body=body[:at]+before+body[at+len(after):]
        assert body.encode('ascii')==original
    return variants


def inputs(root=ROOT):
    root=earlier.physical(root)
    manifest=read_json(root/MANIFEST)
    fixed=dict(schema='ptlc-nom-dev-5cb-selection-v1',core_commit=CORE,core_tree=TREE,
        source_files=482,source_index_sha256=INDEX_SHA256,component_profiles=16,
        selected_stateful_outcomes=342,wire_outcomes=45,pr138_outcomes=1,
        auxiliary_cases=AUXILIARY,keyless_cases=24,all_project_producers=20,
        prior_dev_source=previous.CORE,receiver_context_changes=4,receipt_verifier_changes=2,
        caller_query_count_changes=12,application='NO-GO',core='NO-GO',
        independent_assessment='UNFILLED',combined_admission='UNFILLED',journal_source_upgrade='NOT_SELECTED')
    assert type(manifest) is dict and set(manifest)==set(fixed)|{'input_sha256','frozen_input_sha256'}
    earlier.rebase.exact(fixed,{key:manifest[key] for key in fixed})
    for key,required in (('input_sha256',OWN_INPUTS),('frozen_input_sha256',FROZEN_INPUTS)):
        pins=manifest[key];assert type(pins) is dict and set(pins)==required
        for name,pin in pins.items():
            assert type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin)
            assert sha(earlier.regular(root/name,2*earlier.MIB))==pin
    old_index=previous.inputs(root)[1]
    raw=earlier.regular(root/SOURCE,earlier.MIB);assert sha(raw)==INDEX_SHA256
    index=earlier.decoded(raw,earlier.MIB);assert type(index) is dict and len(index)==482
    folded=set()
    for name,row in index.items():
        assert type(name) is str and name.isascii() and '\\' not in name and not Path(name).is_absolute()
        assert all(part not in ('','.','..','.git') for part in name.split('/'))
        assert name.casefold() not in folded;folded.add(name.casefold())
        assert type(row) is dict and set(row)=={'bytes','sha256','git_blob_sha1','mode'}
        assert type(row['bytes']) is int and 0<=row['bytes']<=8*earlier.MIB
        assert type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
        assert type(row['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}',row['git_blob_sha1'])
        assert row['mode'] in ('100644','100755')
    assert earlier.git_tree(index)==TREE
    assert all(index[name]==old_index[name] for name in ('go.mod','go.sum','LICENSE'))
    producer_variants(root)
    return manifest,index


def probes(root=ROOT,profile='all'):
    assert profile in PROFILES
    variants=producer_variants(root)
    component={target:variants[parent]['selected'] if parent in variants else parent
               for target,parent in previous.probes(root).items()}
    assert len(component)==16
    for kind in AUXILIARY:
        module=importlib.import_module('qualification.nom_dev_'+kind)
        assert module.DESTINATION not in component
        component[module.DESTINATION]=variants[module.DRIVER]['selected']
    keyless={'vm/research_nom_5cb_keyless_supervisor_test.go':KEYLESS_PRODUCER,
             'vm/zz_research_nom_supervisor_plasma_test.go':'compatibility/nom_dev_supervisor_plasma_test.go.txt'}
    if profile=='keyless':return keyless
    if profile=='components':return component
    result=dict(component)
    for target,parent in keyless.items():
        assert target not in result or result[target]==parent
        result[target]=parent
    assert len(result)==20
    return result


def compare_source(source,root=ROOT,profile='all'):
    manifest,index=inputs(root);source=earlier.physical(source)
    assert source.is_dir()
    selected=probes(root,profile)
    expected={name:dict(row) for name,row in index.items()}
    for name,parent in selected.items():
        assert name not in expected
        raw=earlier.regular(Path(root)/parent,2*earlier.MIB)
        expected[name]=dict(bytes=len(raw),sha256=sha(raw),
            git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
    directories={str(Path(name).parent) for name in expected}
    directories={str(parent) for name in directories for parent in (Path(name),*Path(name).parents)}
    seen=set();total=0
    for directory,children,names in os.walk(source,followlinks=False):
        parent=Path(directory);assert not parent.is_symlink()
        for child in children:
            path=parent/child;assert not path.is_symlink() and path.relative_to(source).as_posix() in directories
        for name in names:
            path=parent/name;relative=path.relative_to(source).as_posix()
            assert relative in expected and relative not in seen
            raw=earlier.regular(path,8*earlier.MIB);row=expected[relative];total+=len(raw)
            assert total<=64*earlier.MIB and len(raw)==row['bytes'] and sha(raw)==row['sha256']
            assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['git_blob_sha1']
            seen.add(relative)
    assert seen==set(expected)
    return dict(core_commit=CORE,core_tree=TREE,profile=profile,upstream_files=len(index),
        project_producers=len(selected),combined_files=len(seen),content='EXACT_SELECTED_CONTENTS',
        filesystem_mode_equality='NOT_ASSERTED',producer_authentication='NOT_ESTABLISHED_BY_READER')


def auxiliary_reader(kind,root=ROOT):
    assert kind in AUXILIARY
    manifest=read_json(Path(root)/MANIFEST)
    name='qualification/nom_dev_'+kind+'.py'
    raw=earlier.regular(Path(root)/name,2*earlier.MIB)
    assert sha(raw)==manifest['frozen_input_sha256'][name]
    module=importlib.import_module('qualification.nom_dev_'+kind)
    names={'expected_report','report_from_events'}
    nodes=[node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef) and node.name in names]
    assert len(nodes)==2 and {node.name for node in nodes}==names
    namespace=dict(vars(module));namespace.update(CORE=CORE,TREE=TREE)
    changed=[]
    if kind=='send_caller':
        def scenarios():
            rows=copy.deepcopy(module.scenarios())
            for row in rows.values():
                if row['balance_reads']==1 and row['dp_reads']>0:row['dp_reads']+=1
            return rows
        namespace['scenarios']=scenarios
        changed=sorted(name for name,row in module.scenarios().items() if row['balance_reads']==1 and row['dp_reads']>0)
        assert len(changed)==12
    tree=ast.Module(body=nodes,type_ignores=[])
    exec(compile(tree,'<selected-5cb-'+kind+'-reader>','exec',dont_inherit=True),namespace)
    expected=namespace['expected_report']()
    inverse=copy.deepcopy(expected);inverse['selected_core_commit']=module.CORE
    for name in changed:inverse['records'][name]['dp_reads']-=1
    assert inverse==module.expected_report() and len(expected['records'])==AUXILIARY[kind]
    return namespace['report_from_events'],expected,dict(
        original_source_sha256=sha(raw),unchanged_function_bodies=sorted(names),
        query_count_changes=changed,imported_module_mutated=False),module



def vectors():
    selected = copy.deepcopy(context.vectors())
    changed = set()
    for row in selected:
        if row['id'] in RECEIVER_IDS:
            assert row['expect_structural'] == 'PASS'
            assert row['expect_transaction'] == 'ErrABSignatureMissing'
            row['expect_structural'] = RECEIVER_ERROR
            changed.add(row['id'])
    assert changed == RECEIVER_IDS and len(selected) == 84
    return selected


def context_fixture(root):
    old = json.loads((Path(root)/context.FIXTURE).read_bytes())
    result = copy.deepcopy(old)
    assert result['vectors'] == context.vectors()
    result['vectors'] = vectors()
    for name in RECEIVER_IDS:
        row = result['records'][name]
        assert row['block']['chain_id'] == '69'
        assert row['checks'] == dict(structural='PASS', transaction='ErrABSignatureMissing')
        row['checks']['structural'] = RECEIVER_ERROR
    # Prove that only the selected vector/check values differ. This projection
    # retains its historical value metadata, separately from the selected core.
    inverse = copy.deepcopy(result)
    inverse['vectors'] = context.vectors()
    for name in RECEIVER_IDS:
        inverse['records'][name]['checks']['structural'] = 'PASS'
    assert inverse == old
    return result


def context_reader(root):
    """Rebind only vectors for three unchanged strict historical functions."""
    raw = (Path(root)/'scripts/qualify_nom_account_context.py').read_bytes()
    assert sha(raw) == CONTEXT_SHA
    names = {'validate_record', 'validate_records', 'collect_records'}
    nodes = [row for row in ast.parse(raw).body
             if isinstance(row, ast.FunctionDef) and row.name in names]
    assert {row.name for row in nodes} == names and len(nodes) == 3
    namespace = dict(vars(context))
    namespace['vectors'] = vectors
    # The bodies and constants are unchanged. This private namespace avoids
    # changing the imported historical module or relabeling its fixture.
    tree = ast.Module(body=nodes, type_ignores=[])
    body_sha = sha(ast.dump(tree, include_attributes=False).encode('ascii'))
    exec(compile(tree, '<selected-context-reader>', 'exec', dont_inherit=True), namespace)
    assert context.vectors() != vectors()
    return namespace['collect_records'], dict(
        original_source_sha256=CONTEXT_SHA, selected_function_ast_sha256=body_sha,
        unchanged_function_bodies=sorted(names), changed_global_binding='vectors',
        receiver_ids=sorted(RECEIVER_IDS), imported_module_mutated=False)


def compare_components(payloads, root=earlier.ROOT):
    """Read all exact streams; actual exits/custody remain a separate gate."""
    earlier.inputs(root)
    mods, fixtures, selected = earlier.profiles(root)
    required = {unit+suffix for unit in earlier.COUNTS for suffix in ('.stdout', '.stderr')}
    assert type(payloads) is dict and set(payloads) == required
    assert all(type(value) is bytes for value in payloads.values())
    assert sum(map(len, payloads.values())) <= earlier.MAX_TOTAL
    reports = {}
    for unit, tests in selected.items():
        stderr = payloads[unit+'.stderr']
        assert len(stderr) <= earlier.MAX_STDERR
        row = earlier.event_stream(payloads[unit+'.stdout'], tests)
        assert row['passed_including_parent'] == earlier.COUNTS[unit]
        reports[unit] = dict(row, stderr_sha256=sha(stderr), stderr_bytes=len(stderr),
                             actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER')
    funding = earlier.decoded(earlier.regular(Path(root)/vm.FUNDING, 2*earlier.MIB), 2*earlier.MIB)
    records = vm.collect_vm_records(payloads['vm-path.stdout'], fixtures['vm-path'], funding)
    assert len(records) == 32
    patches = {leg:records[leg+'-direct-success']['receipt_patches'] for leg in ('long', 'short')}
    collect_context, binding = context_reader(root)
    auth = None
    for name in earlier.MODULES:
        module = mods[name]
        unit = name.replace('_', '-')
        raw = payloads[unit+'.stdout']
        expected = fixtures[unit]
        if name == 'account_authorization':
            auth = module.collect_records(raw, records)
            actual = module.corpus(auth)
        elif name == 'account_context':
            actual = module.corpus(collect_context(raw, auth, patches), patches)
            actual['vectors'] = vectors()
            expected = context_fixture(root)
        elif name in ('bilateral_graph', 'supervisor_plasma'):
            actual = module.corpus(module.collect_records(raw, *module.selected_inputs(root)))
        elif name in ('account_pool', 'pool_dependencies'):
            kind = name.replace('_', '-')
            actual = earlier.rebase.native_records(kind, raw)
            earlier.rebase.exact(earlier.rebase.expected_records(root)[kind], actual)
            continue
        elif name in ('pool_forks', 'momentum_admission'):
            actual = module.corpus(module.collect_records(raw))
        else:
            actual = module.corpus(module.collect_records(raw, root))
        earlier.rebase.exact(expected, actual)
    assert sum(row['passed_including_parent'] for unit, row in reports.items()
               if unit not in ('wire-corpus', 'pr138-corpus')) == 342
    return dict(schema='ptlc-nom-dev-5cb-component-values-v1',
        outcome='PASS_SELECTED_SOURCE_SPECIFIC_COMPONENT_VALUES_ONLY',
        selected_core=CORE, selected_tree=TREE, source_files=482, profiles=reports,
        selected_stateful_outcomes=342, wire_outcomes=45, pr138_outcomes=1,
        historical_value_origin=earlier.rebase.CORE_COMMIT,
        receiver_expectation_changes=sorted(RECEIVER_IDS), context_reader_binding=binding,
        native_execution='NOT_PERFORMED_BY_READER',
        execution_origin='NOT_ESTABLISHED_BY_READER', current_dev_compatibility='UNFILLED',
        combined_admission='UNFILLED', journal_source_upgrade='NOT_SELECTED',
        application='NO-GO', core='NO-GO', independent_assessment='UNFILLED')


def units(profile='all'):
    assert profile in PROFILES
    result=set(earlier.COUNTS)|{name.replace('_','-') for name in AUXILIARY} if profile!='keyless' else set()
    if profile!='components':result.add('keyless-supervisor')
    return result


def compare_payloads(payloads,root=ROOT,profile='all'):
    inputs(root)
    required={unit+suffix for unit in units(profile) for suffix in ('.stdout','.stderr')}
    assert type(payloads) is dict and set(payloads)==required
    assert all(type(raw) is bytes for raw in payloads.values()) and sum(map(len,payloads.values()))<=MAX_TOTAL
    result=dict(schema='ptlc-nom-dev-5cb-comparison-v1',core_commit=CORE,core_tree=TREE,profile=profile,
        complete_source='SEPARATE_CONTENT_CHECK_REQUIRED',native_execution='NOT_PERFORMED_BY_READER',
        actual_command_exit='NOT_ESTABLISHED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_READER',
        complete_account_admission='UNFILLED',source_build_authentication='UNFILLED',
        journal_source_upgrade='NOT_SELECTED',application='NO-GO',core='NO-GO',independent_assessment='UNFILLED')
    if profile!='keyless':
        result['components']=compare_components({name:raw for name,raw in payloads.items()
            if name.rsplit('.',1)[0] in earlier.COUNTS},root)
        auxiliary={}
        for kind,count in AUXILIARY.items():
            unit=kind.replace('_','-');stderr=payloads[unit+'.stderr']
            assert len(stderr)<=64*1024
            reader,expected,binding,module=auxiliary_reader(kind,root)
            report,stats=reader(payloads[unit+'.stdout']);assert report==expected
            auxiliary[kind]=dict(cases=count,native_report=report,stdout=stats,
                stderr=dict(bytes=len(stderr),sha256=sha(stderr)),reader_binding=binding)
        result['auxiliary']=auxiliary
    if profile!='components':
        from qualification import nom_keyless_supervisor as keyless
        declared,signed,plasma=keyless.inputs(root)
        stderr=payloads['keyless-supervisor.stderr'];assert len(stderr)<=64*1024
        report,stats=keyless.read(payloads['keyless-supervisor.stdout'],declared,signed,plasma)
        result['keyless']=dict(cases=24,native_report=report,stdout=stats,
            stderr=dict(bytes=len(stderr),sha256=sha(stderr)))
    result['outcome']='PASS_SELECTED_FINITE_VALUES_ONLY'
    return result


def load_payloads(directory,profile='all'):
    directory=earlier.physical(directory);assert directory.is_dir()
    required={unit+suffix for unit in units(profile) for suffix in ('.stdout','.stderr')}
    assert {path.name for path in directory.iterdir()}==required
    values={name:earlier.regular(directory/name,16*earlier.MIB if name.endswith('.stdout') else 2*earlier.MIB) for name in sorted(required)}
    assert sum(map(len,values.values()))<=MAX_TOTAL
    return values


def main():
    import argparse
    class QuietParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('5cb comparison refused')
    parser=QuietParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--streams',type=Path,required=True)
    parser.add_argument('--profile',choices=PROFILES,default='all')
    try:
        args=parser.parse_args()
        source=compare_source(args.source,ROOT,args.profile)
        result=compare_payloads(load_payloads(args.streams,args.profile),ROOT,args.profile)
        result['complete_source']=source
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RecursionError,OverflowError,StopIteration):
        raise SystemExit('REFUSED: 5cb finite comparison') from None
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
