"""Track the complete 821bdd2 source without upgrading the behavior selection."""
from pathlib import Path

from qualification import nom_dev_77ba9c7_source as baseline

ROOT = Path(__file__).resolve().parents[1]
CORE = '821bdd25eabacbf8a07b6310986f38713f27b4e3'
TREE = 'c6625d9fae0dcf77cb60b5e1572402e8b565d9c6'
SOURCE = 'compatibility/nom_dev_821bdd2_source_v1.json'
INDEX_SHA256 = 'f1f7d10dc42239e335d57b24224c22e823dd190ca77f79446b38ab79a72d024b'
PRIOR_TRACKED = '5bf75c8139e192cefaa7a9da441610f1c43622ab'
ADDED = frozenset({
    'vm/embedded/definition/per_entity_iteration_test.go',
    'vm/embedded/implementation/accelerator_final_tally_test.go',
})
CHANGED = frozenset({
    'vm/embedded/definition/common.go',
    'vm/embedded/definition/liquidity.go',
    'vm/embedded/definition/stake.go',
    'vm/embedded/implementation/accelerator.go',
    'vm/embedded/implementation/common.go',
})


def require(value):
    if not value:
        raise ValueError('821bdd2 source tracking refused')


def inputs(root=ROOT):
    """Read immutable inventories only; no archive, compiler or node is opened."""
    common = baseline.common
    root = common.physical(root)
    prior = baseline.validate_index(common.regular(root/baseline.SOURCE,common.MIB),
        digest=baseline.INDEX_SHA256,count=521,tree=baseline.TREE)
    raw = common.regular(root/SOURCE,common.MIB)
    selected = baseline.validate_index(raw,digest=INDEX_SHA256,count=523,tree=TREE)
    added = set(selected)-set(prior)
    removed = set(prior)-set(selected)
    changed = {key for key in prior if key in selected and prior[key]!=selected[key]}
    unchanged = sum(key in selected and prior[key]==selected[key] for key in prior)
    require(added==ADDED and changed==CHANGED and not removed and unchanged==516)
    require(all(selected[key]==prior[key] for key in ('LICENSE','go.mod','go.sum')))
    require(selected['LICENSE']['sha256']==baseline.LICENSE_SHA256)
    ptlc = sorted(key for key in prior if 'ptlc' in key.lower())
    require(len(ptlc)==18 and all(selected[key]==prior[key] for key in ptlc))
    return dict(tracked_core_commit=CORE,tracked_core_tree=TREE,
        source_files=523,source_index_sha256=INDEX_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=PRIOR_TRACKED,last_qualified_behavior_core=baseline.CORE,
        delta_baseline_core=baseline.CORE,added=sorted(added),changed=sorted(changed),
        removed=[],unchanged=unchanged,unchanged_ptlc_paths=ptlc,
        dependency_files_unchanged=True,license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        producer_authentication='NOT_ESTABLISHED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER',native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED',independent_assessment='UNFILLED',
        application='NO-GO',core='NO-GO'),selected
