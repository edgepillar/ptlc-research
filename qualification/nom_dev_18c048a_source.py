"""Track shared storage and lifecycle changes without selecting new behavior."""
from pathlib import Path

from qualification import nom_dev_821bdd2_source as prior

ROOT = Path(__file__).resolve().parents[1]
CORE = '18c048abb3f825274fa7b6900b65bd691ced15ef'
TREE = '460c182324f021e0e54b23fcf6df6d19a98f5e3b'
SOURCE = 'compatibility/nom_dev_18c048a_source_v1.json'
INDEX_SHA256 = '59300ed77726277034f9bccdab63c78b2e38a0ac01bb13a8d6b838a95ac99f7a'
ADDED = frozenset({
    'common/db/enable_delete_test.go',
    'vm/embedded/definition/tombstone_test.go',
})
CHANGED = frozenset({
    'common/db/enable_delete.go',
    'protocol/handler.go',
    'protocol/handler_stop_test.go',
    'protocol/sync.go',
    'vm/embedded/definition/accelerator.go',
    'vm/embedded/definition/sentinel.go',
})


def require(value):
    if not value:
        raise ValueError('18c048a source tracking refused')


def inputs(root=ROOT):
    """Check complete immutable inventories; open no archive or native engine."""
    common = prior.baseline.common
    root = common.physical(root)
    previous, baseline = prior.inputs(root)
    selected = prior.baseline.validate_index(common.regular(root/SOURCE, common.MIB),
        digest=INDEX_SHA256, count=525, tree=TREE)
    added = set(selected)-set(baseline)
    removed = set(baseline)-set(selected)
    changed = {name for name in baseline if name in selected and baseline[name] != selected[name]}
    unchanged = sum(name in selected and baseline[name] == selected[name] for name in baseline)
    require(added == ADDED and changed == CHANGED and not removed and unchanged == 517)
    require(all(selected[name] == baseline[name] for name in ('LICENSE', 'go.mod', 'go.sum')))
    require(selected['LICENSE']['sha256'] == prior.baseline.LICENSE_SHA256)
    ptlc = sorted(name for name in baseline if 'ptlc' in name.lower())
    require(len(ptlc) == 18 and all(selected[name] == baseline[name] for name in ptlc))
    require(previous['tracked_core_commit'] == prior.CORE)
    require(previous['last_qualified_behavior_core'] == prior.baseline.CORE)
    return dict(tracked_core_commit=CORE, tracked_core_tree=TREE,
        source_files=525, source_index_sha256=INDEX_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=prior.CORE, delta_baseline_core=prior.CORE,
        last_qualified_behavior_core=prior.baseline.CORE,
        added=sorted(added), changed=sorted(changed), removed=[], unchanged=unchanged,
        unchanged_ptlc_paths=ptlc, dependency_files_unchanged=True,
        license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        producer_authentication='NOT_ESTABLISHED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO'), selected
