"""Bounded price/order component comparison; no execution or recovery authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('price/account-order comparison requires assertions enabled')

import hashlib
import json
import os
from pathlib import Path
import re

from qualification import nom_current_admission as current

ROOT=Path(__file__).resolve().parents[1]
CORE=current.CORE
TREE=current.TREE
DRIVER='compatibility/nom_price_account_order_test.go.txt'
DESTINATION='dp/zz_research_nom_price_order_test.go'
FIXTURE='compatibility/fixtures/nom_price_account_order_v1.json'
ORIGINALS='compatibility/fixtures/nom_signed_originals_v1.json'
MANIFEST='compatibility/nom_price_account_order_manifest.json'
SCHEMA='ptlc-nom-price-account-order-selection-v1'
TEST='TestResearchNoMPriceOrder'
PACKAGE=current.PREFIX+'dp'
MARKER='PTLC_NOM_PRICE_ORDER_RECORD='
CASES=('minimum','work-rise','fusion-rise','missing-frontier','changed-frontier',
    'untrusted-zero-base','untrusted-max-base','blocked-descendant','reverse-order','ordered-descendant')
OWN_INPUTS={DRIVER,FIXTURE,ORIGINALS,current.SOURCE,current.MANIFEST,
    'qualification/nom_current_admission.py','qualification/nom_price_account_order.py',
    'tests/test_nom_price_account_order.py'}
require=current.require
regular=current.regular
decoded=current.decoded
exact=current.rebase.exact


def expected_records(root=ROOT):
    originals=decoded(regular(root/ORIGINALS,current.MIB),current.MIB)
    records={}
    for leg in ('long','short'):
        original=originals[leg+'-original']
        for case in CASES:
            key=leg+'-'+case
            row=dict(schema='ptlc-nom-price-order-source-v1',id=key,
                original_wire_sha256=original['wire_sha256'],original_node_hash_hex=original['hash_hex'],
                fusion_price=1051 if case in ('fusion-rise','untrusted-zero-base','blocked-descendant') else 1000,
                work_price=1103 if case in ('work-rise','fusion-rise','untrusted-zero-base','blocked-descendant') else 1000,
                selected=[],momentum_gate='PASS_DECLARED_COMPONENT',canonical_calls=1,account_frontier_calls=1,
                original_bytes_preserved=True,caller_bytes_preserved=True,state_provider='DECLARED_TEST_DOUBLE',
                account_admission='NOT_RUN',momentum_transaction_signature='NOT_RUN',recovery_action='NONE')
            if case not in ('fusion-rise','untrusted-max-base','blocked-descendant'):
                row['selected']=['diagnostic-metadata-copy' if case=='untrusted-zero-base' else 'exact-original']
            if case=='blocked-descendant':row['selected']=['unsigned-unrelated-premium']
            if case in ('reverse-order','ordered-descendant'):
                row.update(selected=['exact-original','unsigned-child'],canonical_calls=2)
            if case in ('fusion-rise','untrusted-zero-base','blocked-descendant'):
                row.update(momentum_gate='REFUSE_PRICE',account_frontier_calls=0)
            elif case in ('missing-frontier','changed-frontier','reverse-order'):
                row['momentum_gate']='REFUSE_ACCOUNT_ORDER'
            records[key]=row
    return records


def inputs(root=ROOT):
    root=current.physical(root)
    selected=decoded(regular(root/MANIFEST,current.MIB),current.MIB)
    fixed=dict(schema=SCHEMA,core_commit=CORE,core_tree=TREE,upstream_files=444,project_probe_files=1,
        probe_destination=DESTINATION,selected_go_outcomes=21,selected_records=20,
        reference_scope='PUBLIC_SYNTHETIC_FINITE_VALUES; NOT_EXECUTION_EVIDENCE',
        state_provider='DECLARED_TEST_DOUBLE',independent_assessment='UNFILLED',combined_admission='UNFILLED',
        application='NO-GO',core='NO-GO',journal_source_upgrade='NOT_SELECTED')
    require(type(selected) is dict and set(selected)==set(fixed)|{'input_sha256'})
    exact(fixed,{name:selected[name] for name in fixed})
    pins=selected['input_sha256'];require(type(pins) is dict and set(pins)==OWN_INPUTS)
    for name,pin in pins.items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin))
        require(hashlib.sha256(regular(root/name,2*current.MIB)).hexdigest()==pin)
    _,index,_=current.inputs(root)
    fixture=decoded(regular(root/FIXTURE,current.MIB),current.MIB)
    exact(dict(schema='ptlc-nom-price-account-order-reference-v1',scope=fixed['reference_scope'],
        core_commit=CORE,core_tree=TREE,records=expected_records(root)),fixture)
    return selected,index


def selected_tests():
    return {PACKAGE:{TEST}|{TEST+'/'+leg+'-'+case for leg in ('long','short') for case in CASES}}


def compare_stream(stdout,stderr,root=ROOT):
    inputs(root)
    require(type(stderr) is bytes and len(stderr)<=current.MAX_STDERR)
    events=current.event_stream(stdout,selected_tests())
    require(events['passed_including_parent']==21)
    actual={}
    for line in stdout.splitlines():
        event=decoded(line,current.MAX_STDOUT)
        output=event.get('Output','')
        if MARKER not in output:continue
        require(output.count(MARKER)==1 and event['Action']=='output')
        row=decoded(output.split(MARKER,1)[1].encode('utf-8'),64*1024)
        require(type(row) is dict and type(row.get('id')) is str)
        key=row['id'];require(key not in actual and event.get('Test')==TEST+'/'+key)
        actual[key]=row
    exact(expected_records(root),actual)
    return dict(schema='ptlc-nom-price-account-order-comparison-v1',outcome='PASS_DECLARED_COMPONENT_VALUES_ONLY',
        core_commit=CORE,core_tree=TREE,selected_go_outcomes=21,selected_records=20,
        momentum_gate_counts={'PASS_DECLARED_COMPONENT':8,'REFUSE_PRICE':6,'REFUSE_ACCOUNT_ORDER':6},
        stdout_sha256=events['stdout_sha256'],stdout_bytes=events['stdout_bytes'],
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),stderr_bytes=len(stderr),
        actual_command_exit='NOT_ESTABLISHED_BY_THIS_READER',execution_origin='NOT_ESTABLISHED_BY_THIS_READER',
        native_execution='NOT_PERFORMED_BY_READER',state_provider='DECLARED_TEST_DOUBLE',
        complete_source='SEPARATE_CONTENT_CHECK_REQUIRED',combined_admission='UNFILLED',inclusion_before_timeout='UNFILLED',
        source_authentication='UNFILLED',durable_custody='UNFILLED',disclosure_timing='UNFILLED',
        reorg_finality_availability='UNFILLED',journal_source_upgrade='NOT_SELECTED',journal_write='NOT_PERFORMED',
        unknown_work_ledger='NOT_READ_OR_CHANGED',actions=[],original_replacements=0,
        signing='NOT_PERFORMED',retry='NOT_PERFORMED',work_replenishment='NOT_PERFORMED',
        original_release='NOT_PERFORMED',transaction_broadcast='NOT_PERFORMED',
        independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')


def compare_source(source,root=ROOT):
    _,index=inputs(root)
    source=current.physical(source);require(source.is_dir())
    expected={name:dict(row) for name,row in index.items()}
    require(DESTINATION not in expected)
    raw=regular(root/DRIVER,128*1024)
    expected[DESTINATION]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob_sha1=hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest())
    seen=set();total=0
    for directory,children,names in os.walk(source,followlinks=False):
        parent=Path(directory);require(not parent.is_symlink())
        for name in children:require(not (parent/name).is_symlink())
        for name in names:
            path=parent/name;relative=path.relative_to(source).as_posix()
            require(relative in expected and relative not in seen)
            raw=regular(path,8*current.MIB);row=expected[relative];total+=len(raw)
            require(total<=40*current.MIB and len(raw)==row['bytes'])
            require(hashlib.sha256(raw).hexdigest()==row['sha256'])
            require(hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()==row['git_blob_sha1'])
            seen.add(relative)
    require(seen==set(expected) and len(seen)==445)
    return dict(core_commit=CORE,core_tree=TREE,upstream_files=444,project_probe_files=1,
        combined_files=445,content='EXACT_SELECTED_CONTENTS',filesystem_mode_equality='NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_THIS_READER')


def main():
    import argparse
    class QuietParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('price/account-order comparison refused')
    parser=QuietParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--stream',type=Path,required=True)
    parser.add_argument('--stderr',type=Path,required=True)
    try:
        args=parser.parse_args()
        source=compare_source(args.source)
        result=compare_stream(regular(args.stream,current.MAX_STDOUT),regular(args.stderr,current.MAX_STDERR))
        result['complete_source']=source
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RecursionError,OverflowError):
        raise SystemExit('REFUSED: price/account-order component comparison') from None
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
