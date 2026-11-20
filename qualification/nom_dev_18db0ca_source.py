"""Reconstruct the workflow-only upstream source delta."""

import hashlib
import json
from pathlib import Path

from qualification import nom_current_admission as common
from qualification import nom_dev_54f6bad_source as prior
from qualification import nom_dev_77ba9c7_source as inventory


ROOT = Path(__file__).resolve().parents[1]
CORE = '18db0ca1777df64ce87940f3534b78db4abcd7d1'
TREE = '77eb6fec9371109a01f0898e8fd1cf773183e05e'
DELTA = 'compatibility/nom_dev_18db0ca_source_delta_v1.json'
DELTA_SHA256 = '96024906955d66fd2c47a20962f20395b07fed72be577667bb7e4090727f066c'
INDEX_SHA256 = '36da59a1dc56550e6fc44e2653d05e0bb7c11065f05814fa1065e7025363ceb5'
WORKFLOWS = frozenset({'.github/workflows/test.yml', '.github/workflows/znn_builder.yml'})
MAX_DELTA = 4096


def reconstruct(baseline, delta):
    if type(delta) is not dict or set(delta) != {'added', 'modified', 'removed'}:
        raise ValueError('18db0ca source delta fields mismatch')
    modified = delta['modified']
    if (delta['added'] != {} or delta['removed'] != [] or type(modified) is not dict
            or set(modified) != WORKFLOWS or not WORKFLOWS <= set(baseline)
            or any(row == baseline[name] for name, row in modified.items())):
        raise ValueError('18db0ca source delta requires the two changed workflow records')
    raw = json.dumps({**baseline, **modified}, sort_keys=True).encode('ascii')
    return inventory.validate_index(raw, digest=INDEX_SHA256, count=621, tree=TREE)


def inputs(root=ROOT):
    """Load the bounded index and keep earlier behavioral qualification separate."""
    root = common.physical(root)
    previous, baseline = prior.inputs(root)
    raw = common.regular(root / DELTA, MAX_DELTA)
    if hashlib.sha256(raw).hexdigest() != DELTA_SHA256:
        raise ValueError('18db0ca source delta digest mismatch')
    selected = reconstruct(baseline, common.decoded(raw, MAX_DELTA))
    return dict(tracked_core_commit=CORE, tracked_core_tree=TREE, source_files=len(selected),
        source_index_sha256=INDEX_SHA256, source_delta_sha256=DELTA_SHA256,
        source_bytes=sum(row['bytes'] for row in selected.values()),
        prior_tracked_core=prior.CORE, delta_baseline_core=prior.CORE,
        last_qualified_behavior_core=previous['last_qualified_behavior_core'],
        added=[], changed=sorted(WORKFLOWS), removed=[], unchanged=len(baseline) - len(WORKFLOWS),
        unchanged_ptlc_paths=previous['unchanged_ptlc_paths'], dependency_files_unchanged=True,
        license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        archive_verification='NOT_PERFORMED_BY_INDEX_READER',
        native_execution='NOT_PERFORMED_BY_READER', native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', independent_assessment='UNFILLED',
        application='NO-GO', core='NO-GO'), selected
