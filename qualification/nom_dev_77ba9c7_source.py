"""Bind the complete 77ba9c7 input; no execution or recovery authority."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sys

from qualification import nom_current_admission as common

if sys.flags.optimize:
    raise SystemExit('source comparison requires assertions enabled')

ROOT = Path(__file__).resolve().parents[1]
CORE = '77ba9c7ee8c881e90911946756cdb67d8b586043'
TREE = '57da4b9588e053facfdb8299181fe15a8ad2a223'
SOURCE = 'compatibility/nom_dev_77ba9c7_source_v1.json'
INDEX_SHA256 = 'bcc25ea431a467dd4381b47132ae96491bf382f5bbd6e823215b087e6c13de6c'
PRIOR_SOURCE = 'compatibility/nom_dev_661b5ef_source_v1.json'
PRIOR_SHA256 = 'a6eec89b1ca82e66cb6bcc855b1efc8b95981ffb7e43b1e3528d3daf8ba956fa'
LICENSE_SHA256 = '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
LIMIT = 64 * common.MIB


def require(value):
    if not value:
        raise ValueError('77ba9c7 source input refused')


def name(value):
    require(type(value) is str and value.isascii() and bool(value))
    require('\\' not in value and ':' not in value and not any(ord(c)<32 or ord(c)==127 for c in value))
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix()==value)
    require(all(part not in ('','.','..','.git') for part in value.split('/')))
    return value


def validate_index(raw, *, digest, count, tree):
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest()==digest)
    value = common.decoded(raw,common.MIB)
    require(type(value) is dict and len(value)==count)
    folded = set()
    for key,row in value.items():
        name(key)
        require(key.casefold() not in folded)
        folded.add(key.casefold())
        require(type(row) is dict and set(row)=={'bytes','sha256','git_blob_sha1','mode'})
        require(type(row['bytes']) is int and 0<=row['bytes']<=8*common.MIB)
        require(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']))
        require(type(row['git_blob_sha1']) is str and re.fullmatch('[0-9a-f]{40}',row['git_blob_sha1']))
        require(row['mode'] in ('100644','100755'))
    require(common.git_tree(value)==tree)
    return value


def inputs(root=ROOT):
    root = common.physical(root)
    raw = common.regular(root/SOURCE,common.MIB)
    selected = validate_index(raw,digest=INDEX_SHA256,count=521,tree=TREE)
    prior_raw = common.regular(root/PRIOR_SOURCE,common.MIB)
    prior = validate_index(prior_raw,digest=PRIOR_SHA256,count=518,
        tree='78937597e8e0e5835a8856cb44d592e349451d9f')
    added = sorted(set(selected)-set(prior))
    removed = sorted(set(prior)-set(selected))
    changed = sorted(key for key in prior if key in selected and prior[key]!=selected[key])
    unchanged = sum(key in selected and prior[key]==selected[key] for key in prior)
    require((len(added),len(changed),len(removed),unchanged)==(3,12,0,506))
    require(all(selected[key]==prior[key] for key in ('LICENSE','go.mod','go.sum')))
    require(selected['LICENSE']['sha256']==LICENSE_SHA256)
    ptlc_paths=sorted(key for key in prior if 'ptlc' in key.lower())
    require(len(ptlc_paths)==18 and all(selected[key]==prior[key] for key in ptlc_paths))
    return dict(core_commit=CORE,core_tree=TREE,source_files=521,source_index_sha256=INDEX_SHA256,
        prior_core='661b5ef404487cd41685654bf87530f10adebbe4',added=added,changed=changed,removed=removed,
        unchanged=unchanged,unchanged_ptlc_paths=ptlc_paths,dependency_files_unchanged=True,license='UPSTREAM GPL VERSION 3; SOURCE NOT VENDORED',
        native_execution='NOT_PERFORMED_BY_READER',native_compatibility='UNFILLED',
        journal_source_upgrade='NOT_SELECTED',independent_assessment='UNFILLED',
        application='NO-GO',core='NO-GO'),selected


def compare_upstream(source, root=ROOT):
    """Check a bare upstream view; producers belong to a separate selection."""
    description,selected = inputs(root)
    source = common.physical(source)
    require(source.is_dir())
    directories = {''}
    for key in selected:
        parts = key.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    seen = set()
    total = 0
    for directory,children,files in os.walk(source,followlinks=False):
        parent = Path(directory)
        for child in children:
            path = parent/child
            require(not path.is_symlink() and path.relative_to(source).as_posix() in directories)
        for filename in files:
            path = parent/filename
            relative = path.relative_to(source).as_posix()
            require(relative in selected and relative not in seen)
            raw = common.regular(path,8*common.MIB)
            row = selected[relative]
            total += len(raw)
            require(total<=LIMIT and len(raw)==row['bytes'])
            require(hashlib.sha256(raw).hexdigest()==row['sha256'])
            require(hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()==row['git_blob_sha1'])
            seen.add(relative)
    require(seen==set(selected))
    return dict(description,content='EXACT_SELECTED_UPSTREAM_BYTES',source_build_authentication='UNFILLED',
        filesystem_modes='LOGICAL_GIT_MODES_PINNED; PHYSICAL_MODE_EQUALITY_NOT_ASSERTED',
        producer_authentication='NOT_ESTABLISHED_BY_READER')
