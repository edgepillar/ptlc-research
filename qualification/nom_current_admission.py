"""Read finite current-source component streams; no execution or recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('current admission comparison requires assertions enabled')

import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import stat

from qualification.nom_rpc_quote_source import git_tree
from scripts import compare_nom_dev_rebase as rebase
from scripts import qualify_nom_vm_path as vm
from scripts import qualify_nom_wire_core as wire

ROOT=Path(__file__).resolve().parents[1]
CORE='85c39796fa5ab6fb5ca16e61af34b6616f0ceafe'
TREE='cdeb5b6276c13447197c829c5855faa72afd86b9'
SOURCE='compatibility/nom_current_admission_source_v1.json'
INDEX_SHA256='6168b36ee6487272bf128862f141093db4d47c411a5d551fb132de5d9ab8890a'
REFERENCE='compatibility/fixtures/nom_current_admission_vm_reference_v1.json'
MANIFEST='compatibility/nom_current_admission_manifest.json'
SCHEMA='ptlc-nom-current-admission-selection-v1'
MIB=1024**2
MAX_STDOUT=16*MIB
MAX_STDERR=2*MIB
MAX_TOTAL=64*MIB
PREFIX='github.com/zenon-network/go-zenon/'
MODULES=('account_authorization','account_context','bilateral_graph','supervisor_plasma',
    'account_pool','pool_forks','pool_dependencies','momentum_admission','batched_rollback',
    'content_cap','multi_rollback','rollback_refusal')
COUNTS={'pr138-corpus':1,'wire-corpus':45,'vm-path':33,'vm-verifier':25,
    'account-authorization':127,'account-context':85,'bilateral-graph':5,'supervisor-plasma':3,
    'account-pool':3,'pool-forks':6,'pool-dependencies':4,'momentum-admission':15,
    'batched-rollback':7,'content-cap':6,'multi-rollback':8,'rollback-refusal':15}
OWN_INPUTS={SOURCE,REFERENCE,'qualification/nom_current_admission.py','tests/test_nom_current_admission.py'}
EVENT_FIELDS={'Time','Action','Package','Test','Elapsed','Output','FailedBuild'}
EVENT_ACTIONS={'start','run','pause','cont','output','pass','fail','skip','bench'}


def require(value):
    if not value:raise ValueError('current admission comparison refused')


def unique(pairs):
    result={}
    for name,value in pairs:
        require(name not in result);result[name]=value
    return result


def reject_constant(value):
    raise ValueError('nonfinite current admission value')


def decoded(raw,limit):
    require(type(raw) is bytes and 0<len(raw)<=limit)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=reject_constant)


def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=True,allow_nan=False).encode('ascii')


def physical(path):
    path=Path(path)
    if not path.is_absolute():path=Path.cwd()/path
    require('..' not in path.parts)
    require(all(not entry.is_symlink() for entry in (path,*path.parents)))
    return path


def regular(path,limit):
    path=physical(path);info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=limit)
    raw=path.read_bytes();require(len(raw)==info.st_size)
    return raw


def inputs(root=ROOT):
    root=physical(root)
    manifest=decoded(regular(root/MANIFEST,MIB),MIB)
    fixed=dict(schema=SCHEMA,core_commit=CORE,core_tree=TREE,source_files=444,project_probe_files=16,
        source_index_sha256=INDEX_SHA256,reference_scope='PUBLIC_SYNTHETIC_REFERENCE_VALUES; NOT EXECUTION EVIDENCE',
        expected_profile_outcomes=COUNTS,selected_stateful_outcomes=342,wire_outcomes=45,pr138_outcomes=1,
        historical_value_source=rebase.CORE_COMMIT,application='NO-GO',core='NO-GO',
        independent_assessment='UNFILLED',combined_admission='UNFILLED',journal_source_upgrade='NOT_SELECTED')
    require(type(manifest) is dict and set(manifest)==set(fixed)|{'input_sha256'})
    rebase.exact(fixed,{name:manifest[name] for name in fixed})
    pins=manifest['input_sha256'];require(type(pins) is dict and set(pins)==OWN_INPUTS)
    for name,pin in pins.items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin))
        require(hashlib.sha256(regular(root/name,2*MIB)).hexdigest()==pin)
    original=rebase.selection(root)
    raw=regular(root/SOURCE,MIB);require(hashlib.sha256(raw).hexdigest()==INDEX_SHA256)
    index=decoded(raw,MIB);require(type(index) is dict and len(index)==444)
    for name,row in index.items():
        require(type(name) is str and name.isascii() and '\\' not in name)
        require(not Path(name).is_absolute() and all(part not in ('','.','..','.git') for part in name.split('/')))
        require(type(row) is dict and set(row)=={'bytes','sha256','git_blob_sha1','mode'})
        require(type(row['bytes']) is int and 0<=row['bytes']<=8*MIB)
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']))
        require(type(row['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}',row['git_blob_sha1']))
        require(row['mode'] in ('100644','100755'))
    require(git_tree(index)==TREE and index['LICENSE']['sha256']=='3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986')
    require(all(index[name]==original['source_index'][name] for name in ('go.mod','go.sum')))
    reference=decoded(regular(root/REFERENCE,2*MIB),2*MIB)
    require(type(reference) is dict and set(reference)=={'schema','scope','core_commit','core_tree','records'})
    require(reference['schema']=='ptlc-nom-current-admission-vm-reference-v1'
        and reference['scope']==fixed['reference_scope'] and reference['core_commit']==CORE and reference['core_tree']==TREE)
    require(type(reference['records']) is dict and len(reference['records'])==32)
    return manifest,index,reference


def profiles(root=ROOT):
    modules={name:importlib.import_module('scripts.qualify_nom_'+name) for name in MODULES}
    fixture=vm.inputs(root)[1]
    names=vm.expected_tests(fixture)
    selected={'pr138-corpus':{PREFIX+'vm/embedded/implementation':{'TestResearchPR138CompatibilityCorpus'}},
        'wire-corpus':{wire.PACKAGE:wire.expected_tests(wire.inputs(root)[1])},
        'vm-path':{PREFIX+'vm':names[PREFIX+'vm']},'vm-verifier':{PREFIX+'verifier':names[PREFIX+'verifier']}}
    fixtures={'vm-path':fixture}
    for name,module in modules.items():
        key=name.replace('_','-');selected[key]=module.expected_tests();fixtures[key]=module.inputs(root)[1]
    require(set(selected)==set(COUNTS))
    require(all(sum(len(names) for names in packages.values())==COUNTS[key] for key,packages in selected.items()))
    return modules,fixtures,selected


def probes(root=ROOT):
    selected={'vm/embedded/implementation/zz_research_compatibility_test.go':'compatibility/core_overlay_test.go.txt',
        'vm/embedded/implementation/zz_research_nom_wire_test.go':wire.DRIVER,
        'vm/zz_research_nom_vm_path_test.go':vm.VM_DRIVER,
        'verifier/zz_research_nom_vm_path_test.go':vm.VERIFIER_DRIVER}
    for name in MODULES:
        module=importlib.import_module('scripts.qualify_nom_'+name)
        destination=module.PACKAGE.removeprefix(PREFIX)+'/zz_research_nom_'+name+'_test.go'
        require(destination not in selected);selected[destination]=module.DRIVER
    require(len(selected)==16)
    return selected


def compare_source(source,root=ROOT):
    _,index,_=inputs(root);source=physical(source)
    require(source.is_dir());expected={name:dict(row) for name,row in index.items()}
    for name,producer in probes(root).items():
        require(name not in expected);raw=regular(root/producer,8*MIB)
        expected[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest())
    seen=set();total=0
    for directory,children,names in os.walk(source,followlinks=False):
        parent=Path(directory);require(not parent.is_symlink())
        for name in children:require(not (parent/name).is_symlink())
        for name in names:
            path=parent/name;relative=path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw=regular(path,8*MIB);row=expected[relative];total+=len(raw)
            require(total<=40*MIB and len(raw)==row['bytes'])
            require(hashlib.sha256(raw).hexdigest()==row['sha256'])
            require(hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()==row['git_blob_sha1'])
            seen.add(relative)
    require(seen==set(expected) and len(seen)==460)
    return dict(core_commit=CORE,core_tree=TREE,upstream_files=444,project_probe_files=16,
        combined_files=460,content='EXACT_SELECTED_CONTENTS',filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def event_stream(raw,selected):
    require(type(raw) is bytes and 0<len(raw)<=MAX_STDOUT)
    expected={name for names in selected.values() for name in names}
    lines=raw.splitlines();require(lines)
    for line in lines:
        event=decoded(line,MAX_STDOUT)
        require(type(event) is dict and set(event)<=EVENT_FIELDS and {'Action','Package'}<=set(event))
        require(type(event['Action']) is str and event['Action'] in EVENT_ACTIONS)
        require(type(event['Package']) is str and event['Package'] in selected)
        if 'Test' in event:require(type(event['Test']) is str and event['Test'] in expected)
        if 'Output' in event:require(type(event['Output']) is str)
        if 'Time' in event:require(type(event['Time']) is str and len(event['Time'])<=128)
        if 'Elapsed' in event:
            require(type(event['Elapsed']) in (int,float) and math.isfinite(event['Elapsed']) and event['Elapsed']>=0)
        require('FailedBuild' not in event)
    count=vm.selected_outcome(raw,selected)
    return dict(passed_including_parent=count,stdout_sha256=hashlib.sha256(raw).hexdigest(),stdout_bytes=len(raw))


def compare_payloads(payloads,root=ROOT):
    inputs(root)
    modules,fixtures,selected=profiles(root)
    require(type(payloads) is dict and set(payloads)=={unit+suffix for unit in COUNTS for suffix in ('.stdout','.stderr')})
    require(all(type(value) is bytes for value in payloads.values()) and sum(map(len,payloads.values()))<=MAX_TOTAL)
    reports={}
    for unit,tests in selected.items():
        stderr=payloads[unit+'.stderr'];require(len(stderr)<=MAX_STDERR)
        row=event_stream(payloads[unit+'.stdout'],tests);require(row['passed_including_parent']==COUNTS[unit])
        reports[unit]=dict(row,stderr_sha256=hashlib.sha256(stderr).hexdigest(),stderr_bytes=len(stderr),
            actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER')
    funding=decoded(regular(root/vm.FUNDING,2*MIB),2*MIB)
    records=vm.collect_vm_records(payloads['vm-path.stdout'],fixtures['vm-path'],funding)
    require(len(records)==32)
    auth=None;patches={leg:records[leg+'-direct-success']['receipt_patches'] for leg in ('long','short')}
    for name in MODULES:
        module=modules[name];unit=name.replace('_','-');raw=payloads[unit+'.stdout']
        if name=='account_authorization':
            auth=module.collect_records(raw,records);actual=module.corpus(auth)
        elif name=='account_context':actual=module.corpus(module.collect_records(raw,auth,patches),patches)
        elif name in ('bilateral_graph','supervisor_plasma'):
            actual=module.corpus(module.collect_records(raw,*module.selected_inputs(root)))
        elif name in ('account_pool','pool_dependencies'):
            kind=name.replace('_','-');current=rebase.native_records(kind,raw)
            rebase.exact(rebase.expected_records(root)[kind],current)
            reports[unit]['value_expectation_origin']='PRESERVED_EXPLICIT_C25_VALUES; HISTORICAL_SOURCE_SELECTION_UNCHANGED'
            continue
        elif name in ('pool_forks','momentum_admission'):actual=module.corpus(module.collect_records(raw))
        else:actual=module.corpus(module.collect_records(raw,root))
        rebase.exact(fixtures[unit],actual)
    require(sum(row['passed_including_parent'] for unit,row in reports.items() if unit not in ('pr138-corpus','wire-corpus'))==342)
    return dict(schema='ptlc-nom-current-admission-components-v1',outcome='PASS_SELECTED_COMPONENT_VALUES_ONLY',
        core_commit=CORE,core_tree=TREE,profiles=reports,selected_stateful_outcomes=342,
        wire_outcomes=45,pr138_outcomes=1,vm_records=32,
        native_execution='NOT_PERFORMED_BY_READER',execution_origin='NOT_ESTABLISHED_BY_THIS_READER',
        complete_source='SEPARATE_CONTENT_CHECK_REQUIRED',stderr='DIAGNOSTIC_BYTES_RETAINED_BY_CALLER; NOT AN EXIT CODE',
        combined_admission='UNFILLED',inclusion_before_timeout='UNFILLED',source_authentication='UNFILLED',
        durable_custody='UNFILLED',journal_source_upgrade='NOT_SELECTED',journal_write='NOT_PERFORMED',
        signing='NOT_PERFORMED',retry='NOT_PERFORMED',transaction_broadcast='NOT_PERFORMED',
        independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')


def load_payloads(directory):
    directory=physical(directory);require(directory.is_dir())
    expected={unit+suffix for unit in COUNTS for suffix in ('.stdout','.stderr')}
    require({path.name for path in directory.iterdir()}==expected)
    result={};total=0
    for name in sorted(expected):
        value=regular(directory/name,MAX_STDOUT if name.endswith('.stdout') else MAX_STDERR)
        total+=len(value);require(total<=MAX_TOTAL);result[name]=value
    return result


def main():
    import argparse
    class QuietParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('current admission comparison refused')
    parser=QuietParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--streams',type=Path,required=True)
    try:
        args=parser.parse_args()
        source=compare_source(args.source)
        result=compare_payloads(load_payloads(args.streams))
        result['complete_source']=source
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RecursionError,OverflowError):
        raise SystemExit('REFUSED: current admission component comparison') from None
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
