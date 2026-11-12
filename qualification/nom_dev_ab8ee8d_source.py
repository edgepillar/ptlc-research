"""Track the exact admission and refund source delta without selecting behavior."""
import hashlib
import json
from pathlib import Path

from qualification import nom_current_admission as common
from qualification import nom_dev_008bdcd_source as prior
from qualification import nom_dev_77ba9c7_source as inventory

ROOT = Path(__file__).resolve().parents[1]
CORE = 'ab8ee8da3a50231b0910c536632e9b05fff42795'
TREE = '9576b71caf1dcf0e6931e2c39af53522b63102c6'
DELTA = 'compatibility/nom_dev_ab8ee8d_source_delta_v1.json'
DELTA_SHA256 = '31c197201b5196794d0b02caabdc4b58c01e36e538ee41896b3233a5622d7c45'
INDEX_SHA256 = '951dbafdc8d86a87de720f6c6cd8df08fcb083d9da9751728810445497992818'


def inputs(root=ROOT):
    """Reconstruct the complete inventory; execute no source or archive reader."""
    root = common.physical(root)
    previous, baseline = prior.inputs(root)
    raw = common.regular(root/DELTA, common.MIB)
    if hashlib.sha256(raw).hexdigest() != DELTA_SHA256:
        raise ValueError('ab8ee8d source delta digest mismatch')
    delta = common.decoded(raw, common.MIB)
    if type(delta) is not dict or len(delta) != 39:
        raise ValueError('ab8ee8d source delta entry count mismatch')

    complete = json.dumps(baseline | delta, sort_keys=True).encode('ascii')
    selected = inventory.validate_index(complete, digest=INDEX_SHA256, count=574, tree=TREE)
    added = set(selected) - set(baseline)
    changed = {name for name in baseline if selected[name] != baseline[name]}
    if (len(added), len(changed)) != (12, 27) or set(delta) != added | changed:
        raise ValueError('ab8ee8d source delta range mismatch')
    ptlc = previous['unchanged_ptlc_paths']
    protected = set(ptlc) | {'LICENSE', 'go.sum'}
    if (len(ptlc) != 18 or protected & set(delta)
            or set(ptlc) != {name for name in selected if 'ptlc' in name.lower()}):
        raise ValueError('ab8ee8d source delta changed a protected entry')
    if 'go.mod' not in changed:
        raise ValueError('ab8ee8d source delta omitted the dependency declaration change')

    return dict(tracked_core_commit=CORE, tracked_core_tree=TREE, source_files=574,
        source_index_sha256=INDEX_SHA256, source_delta_sha256=DELTA_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=prior.CORE, delta_baseline_core=prior.CORE,
        last_qualified_behavior_core=previous['last_qualified_behavior_core'],
        added=sorted(added), changed=sorted(changed), removed=[], unchanged=len(baseline)-len(changed),
        unchanged_ptlc_paths=ptlc, dependency_files_unchanged=False,
        dependency_files_changed=['go.mod'], unchanged_dependency_paths=['go.sum'],
        go_mod_change='X_NET_V0_25_0_PROMOTED_TO_DIRECT_ONLY',
        license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        producer_authentication='NOT_ESTABLISHED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO'), selected
