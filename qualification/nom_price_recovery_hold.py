"""Public-synthetic refusal/hold model; no journal, source or signer authority."""
import sys

if sys.flags.optimize:
    raise SystemExit('reference recovery hold requires assertions enabled')

import hashlib
import json
from pathlib import Path
import re

from qualification.nom_rpc_quote_generic import unique
from qualification.nom_signed_price_hold import CASES,CORE,TREE,expected_records

SCHEMA='ptlc-nom-price-recovery-hold-request-v1'
RESULT='ptlc-nom-price-recovery-hold-result-v1'
SELECTION='PUBLIC_SYNTHETIC_TWO_ORIGINALS_ONLY'
MAX_REQUEST=32768
LEGS=('long','short')
COMMON=('UNAUTHENTICATED_SOURCE','UNCOMPOSED_ACCOUNT_ADMISSION','UNVERIFIED_DURABLE_CUSTODY')
INPUTS={
    'compatibility/fixtures/nom_price_recovery_hold_v1.json',
    'compatibility/fixtures/nom_signed_originals_v1.json',
    'compatibility/nom_signed_price_hold_manifest.json',
    'qualification/nom_signed_price_hold.py',
    'qualification/nom_price_recovery_hold.py',
    'tests/test_nom_price_recovery_hold.py',
}


def require(value):
    if not value:raise ValueError('reference recovery hold refused')


def inputs(root):
    raw=(root/'compatibility/nom_price_recovery_hold_manifest.json').read_bytes()
    require(len(raw)<=16384)
    manifest=json.loads(raw,object_pairs_hook=unique)
    require(manifest['schema']=='ptlc-nom-price-recovery-hold-selection-v1')
    require(manifest['core_commit']==CORE and manifest['core_tree']==TREE)
    require(manifest['selection']==SELECTION and set(manifest['input_sha256'])==INPUTS)
    for name,pin in manifest['input_sha256'].items():
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin))
        require(hashlib.sha256((root/name).read_bytes()).hexdigest()==pin)
    return manifest


def evaluate(request,root):
    """Classify supplied reference bytes; absent values remain absent."""
    inputs(root)
    require(type(request) is dict and set(request)=={'schema','selection','price_case','originals'})
    require(type(request['schema']) is str and request['schema']==SCHEMA)
    require(type(request['selection']) is str and request['selection']==SELECTION)
    case=request['price_case']
    require(type(case) is str and case in {row[0] for row in CASES})
    supplied=request['originals']
    require(type(supplied) is dict and set(supplied)==set(LEGS))
    originals=json.loads((root/'compatibility/fixtures/nom_signed_originals_v1.json').read_bytes(),object_pairs_hook=unique)
    prices=expected_records(root)
    rows={}
    for leg in LEGS:
        claim=supplied[leg]
        require(type(claim) is dict and set(claim)=={'wire_hex','node_hash_hex'})
        wire,node=claim['wire_hex'],claim['node_hash_hex']
        original=originals[leg+'-original']
        if wire is not None:
            require(type(wire) is str and wire==original['wire_hex'])
        if node is not None:
            require(type(node) is str and node==original['hash_hex'])
        price=prices[leg+'-'+case]
        reasons=list(COMMON)
        if wire is None:reasons.append('ORIGINAL_WIRE_UNAVAILABLE')
        if node is None:reasons.append('ORIGINAL_NODE_BINDING_UNAVAILABLE')
        if not price['canonical_accepts']:reasons.append('REFERENCE_CANONICAL_PRICE_COMPONENT_REFUSES')
        if price['diagnostic_metadata_copy']:reasons.append('DIAGNOSTIC_METADATA_IS_NOT_AN_ORIGINAL')
        rows[leg]=dict(state='HOLD',hold_reasons=reasons,
            supplied_wire_sha256=None if wire is None else hashlib.sha256(bytes.fromhex(wire)).hexdigest(),
            supplied_node_hash_hex=node,
            reference_canonical_price_component=price['canonical_accepts'],
            reference_advertised_price_component=price['advertised_accepts'],
            reference_record_id=price['id'],diagnostic_metadata_copy=price['diagnostic_metadata_copy'])
    return dict(schema=RESULT,outcome='HOLD_REFERENCE_PRICE_AND_CUSTODY_ONLY',selection=SELECTION,
        price_case=case,source_commit=CORE,source_tree=TREE,legs=rows,actions=[],original_replacements=0,
        source_value_origin='RETAINED_FINITE_REFERENCE_VALUES; NOT A NEW SOURCE EXECUTION',
        durable_custody='UNFILLED',source_authentication='UNFILLED',complete_admission='UNFILLED',
        inclusion_before_timeout='UNFILLED',account_ordering='UNFILLED',disclosure_timing='UNFILLED',
        canonicality='UNFILLED',finality='UNFILLED',rollback_protection='UNFILLED',availability='UNFILLED',
        journal_source_upgrade='NOT_SELECTED',journal_write='NOT_PERFORMED',unknown_work_ledger='NOT_READ_OR_CHANGED',
        signing='NOT_PERFORMED',retry='NOT_PERFORMED',work_replenishment='NOT_PERFORMED',
        original_release='NOT_PERFORMED',transaction_broadcast='NOT_PERFORMED',
        independent_assessment='UNFILLED',application='NO-GO',core='NO-GO')


def evaluate_json(raw,root):
    require(type(raw) is bytes and 0<len(raw)<=MAX_REQUEST)
    request=json.loads(raw,object_pairs_hook=unique)
    return evaluate(request,root)


def main():
    import argparse
    class QuietParser(argparse.ArgumentParser):
        def error(self,message):raise ValueError('reference recovery hold refused')
    parser=QuietParser(description=__doc__)
    parser.add_argument('--request',required=True,type=Path)
    try:
        args=parser.parse_args()
        with args.request.open('rb') as selected:raw=selected.read(MAX_REQUEST+1)
        result=evaluate_json(raw,Path(__file__).resolve().parents[1])
    except (AssertionError,OSError,ValueError,KeyError,TypeError,RecursionError,OverflowError):
        raise SystemExit('REFUSED: reference price/custody hold') from None
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
