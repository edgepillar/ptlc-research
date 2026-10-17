#!/usr/bin/env python3
"""Prepare new source-only qualification input from one pinned node archive.

The destination must be absent. This does not adopt a checkout, change a node,
start a service or authenticate an executable. Local callers select separately
owned and bounded qualification storage before invoking this helper.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.qualify_nom_signed_originals import inputs, check_source, CORE, CORE_TREE, ARCHIVE_SHA256, DRIVER, PROBE


def prepare(archive,destination,*,root=ROOT):
    if sys.flags.optimize:
        raise ValueError('signed-original preparation requires assertions enabled')
    unused,index,records=inputs(root)
    if (not archive.is_file() or archive.is_symlink() or archive.stat().st_size != 1720256
            or destination.exists() or destination.is_symlink() or not destination.parent.is_dir()):
        raise ValueError('new pinned source selection required')
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=ARCHIVE_SHA256:
        raise ValueError('selected source archive differs')
    payloads={};seen=set();top='go-zenon-'+CORE
    directories={''}
    for name in index:
        parts=name.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    with zipfile.ZipFile(archive) as selected:
        members=selected.infolist()
        if (len(members)>1000 or sum(v.file_size for v in members)>128*1024**2
                or any(v.file_size>16*1024**2 or v.flag_bits&1 for v in members)):
            raise ValueError('selected archive boundary refused')
        for entry in members:
            path=PurePosixPath(entry.filename)
            mode=entry.external_attr>>16
            if (not path.parts or path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                    or entry.filename.rstrip('/')!=path.as_posix() or path.parts[0]!=top
                    or entry.filename.casefold() in seen
                    or mode and stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR)):
                raise ValueError('selected archive member refused')
            seen.add(entry.filename.casefold())
            name='/'.join(path.parts[1:])
            if entry.is_dir():
                if name not in directories:raise ValueError('unselected source directory')
                continue
            if name not in index or name in payloads:raise ValueError('unselected source file')
            raw=selected.read(entry)
            expected=index[name]
            if (len(raw)!=expected['bytes'] or hashlib.sha256(raw).hexdigest()!=expected['sha256']
                    or hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()!=expected['git_blob_sha1']):
                raise ValueError('selected source file differs')
            payloads[name]=raw
        if set(payloads)!=set(index) or selected.testzip() is not None:
            raise ValueError('complete selected source required')
    payloads[PROBE]=(root/DRIVER).read_bytes()
    destination.mkdir(mode=0o700)
    # All contents were checked before the first write. Partial failure stays
    # at the original owned destination for separate inspection, without repair.
    for name,raw in sorted(payloads.items()):
        path=destination/name
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as output:
            output.write(raw)
    check_source(destination,index,root=root)
    return dict(outcome='PASS_SOURCE_PREPARATION_ONLY',core_commit=CORE,core_tree=CORE_TREE,
        original_source_files=443,combined_probe_files=444,archive_sha256=ARCHIVE_SHA256,
        source_license='UPSTREAM GPL VERSION3 TEXT RETAINED SEPARATELY; NOT RELICENSED',
        node_activation='NOT_PERFORMED',application='NO-GO',core='NO-GO')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--destination',type=Path,required=True)
    args=parser.parse_args()
    try:report=prepare(args.archive,args.destination)
    except (AssertionError,OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile):
        print('FAIL: pinned signed-original source preparation; preserve partial selected output',file=sys.stderr)
        return 1
    print(json.dumps(report,sort_keys=True));return 0


if __name__=='__main__':sys.exit(main())
