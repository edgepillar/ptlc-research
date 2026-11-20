"""Reconstruct the tracked upstream source with explicit removals."""
import hashlib
import json
from pathlib import Path

from qualification import nom_current_admission as common
from qualification import nom_dev_77ba9c7_source as inventory
from qualification import nom_dev_ab8ee8d_source as prior

ROOT = Path(__file__).resolve().parents[1]
CORE = '54f6badac5064d7ca82c3dd86f0e539d9077e25b'
TREE = '93152e797c18aef0ce49c96ee63450faa1e11b3c'
DELTA = 'compatibility/nom_dev_54f6bad_source_delta_v1.json'
DELTA_SHA256 = '039187252c6d6dfa383863cdccbb3f75b773a0f88a84b57467ecc366136ecf2d'
INDEX_SHA256 = '5f7c22b96384ce270e9773febb4f0136b1a64d832a91e1a21fbc8912e00d2be9'


def reconstruct(baseline, delta):
    if type(delta) is not dict or set(delta) != {'added', 'modified', 'removed'}:
        raise ValueError('54f6bad source delta fields mismatch')
    added, modified, removed = delta['added'], delta['modified'], delta['removed']
    if (type(added) is not dict or type(modified) is not dict or type(removed) is not list
            or any(type(name) is not str for name in removed)
            or (len(added), len(modified), len(removed)) != (52, 60, 5)
            or removed != sorted(set(removed))):
        raise ValueError('54f6bad source delta entry count or order mismatch')
    removed_names = set(removed)
    baseline_names = set(baseline)
    if (set(added) & baseline_names or not set(modified) <= baseline_names
            or not removed_names <= baseline_names or removed_names & set(modified)
            or any(row == baseline[name] for name, row in modified.items())):
        raise ValueError('54f6bad source delta range mismatch')
    complete = {name: row for name, row in baseline.items() if name not in removed_names}
    complete.update(modified)
    complete.update(added)
    raw = json.dumps(complete, sort_keys=True).encode('ascii')
    return inventory.validate_index(raw, digest=INDEX_SHA256, count=621, tree=TREE)


def inputs(root=ROOT):
    """Read the source inventory and report its bounded qualification scope."""
    root = common.physical(root)
    previous, baseline = prior.inputs(root)
    raw = common.regular(root / DELTA, common.MIB)
    if hashlib.sha256(raw).hexdigest() != DELTA_SHA256:
        raise ValueError('54f6bad source delta digest mismatch')
    delta = common.decoded(raw, common.MIB)
    selected = reconstruct(baseline, delta)
    ptlc = previous['unchanged_ptlc_paths']
    protected = set(ptlc) | {'LICENSE'}
    if (len(ptlc) != 18 or set(ptlc) != {name for name in selected if 'ptlc' in name.lower()}
            or any(selected.get(name) != baseline[name] for name in protected)):
        raise ValueError('54f6bad source delta changed a protected entry')
    dependencies = {'go.mod', 'go.sum'}
    if not dependencies <= set(delta['modified']):
        raise ValueError('54f6bad source delta omitted a dependency file change')
    return dict(tracked_core_commit=CORE, tracked_core_tree=TREE, source_files=len(selected),
        source_index_sha256=INDEX_SHA256, source_delta_sha256=DELTA_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=prior.CORE, delta_baseline_core=prior.CORE,
        last_qualified_behavior_core=previous['last_qualified_behavior_core'],
        added=sorted(delta['added']), changed=sorted(delta['modified']), removed=delta['removed'],
        unchanged=len(baseline) - len(delta['modified']) - len(delta['removed']),
        unchanged_ptlc_paths=ptlc, dependency_files_unchanged=False,
        dependency_files_changed=sorted(dependencies), license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        producer_authentication='NOT_ESTABLISHED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO'), selected
