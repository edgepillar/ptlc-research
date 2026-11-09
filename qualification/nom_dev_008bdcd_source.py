"""Track a verified source delta while keeping the existing behavior selection."""
import hashlib
import json
from pathlib import Path

from qualification import nom_current_admission as common
from qualification import nom_dev_18c048a_source as prior
from qualification import nom_dev_77ba9c7_source as inventory

ROOT = Path(__file__).resolve().parents[1]
CORE = '008bdcd60f65923952f27a9d9a8c39fba7254a21'
TREE = '75972edb844964cab52639209c3610aa9dc1cc81'
DELTA = 'compatibility/nom_dev_008bdcd_source_delta_v1.json'
DELTA_SHA256 = '4a6e0cf58bbade03d094da17979b361c373a6c8c2d0948042fad347bd06e5e67'
INDEX_SHA256 = 'c4a98ce0abbfb61702d1981a47bd64a09e20a6aa3fb2acdf8ee00a4ed23bbf76'


def inputs(root=ROOT):
    """Reconstruct and verify the complete inventory from the retained base."""
    root = common.physical(root)
    previous, baseline = prior.inputs(root)
    raw = common.regular(root/DELTA, common.MIB)
    if hashlib.sha256(raw).hexdigest() != DELTA_SHA256:
        raise ValueError('008bdcd source delta digest mismatch')
    delta = common.decoded(raw, common.MIB)
    if type(delta) is not dict or len(delta) != 126:
        raise ValueError('008bdcd source delta entry count mismatch')

    complete = json.dumps(baseline | delta, sort_keys=True).encode('ascii')
    selected = inventory.validate_index(complete, digest=INDEX_SHA256, count=562, tree=TREE)
    added = set(selected) - set(baseline)
    changed = {name for name in baseline if selected[name] != baseline[name]}
    if (len(added), len(changed)) != (37, 89) or set(delta) != added | changed:
        raise ValueError('008bdcd source delta range mismatch')
    ptlc = previous['unchanged_ptlc_paths']
    protected = set(ptlc) | {'LICENSE', 'go.mod', 'go.sum'}
    if len(ptlc) != 18 or protected & set(delta):
        raise ValueError('008bdcd source delta changed a protected entry')

    return dict(tracked_core_commit=CORE, tracked_core_tree=TREE, source_files=562,
        source_index_sha256=INDEX_SHA256, source_delta_sha256=DELTA_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=prior.CORE, delta_baseline_core=prior.CORE,
        last_qualified_behavior_core=previous['last_qualified_behavior_core'],
        added=sorted(added), changed=sorted(changed), removed=[], unchanged=len(baseline)-len(changed),
        unchanged_ptlc_paths=ptlc, dependency_files_unchanged=True,
        license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        producer_authentication='NOT_ESTABLISHED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO'), selected
