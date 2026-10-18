#!/usr/bin/env python3
"""Prepare one new, pinned source tree for unsigned RPC quote qualification.

Callers own admission, scratch, archive transport and retention separately. This
does not adopt a checkout, authenticate a producer or activate a node.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('FAIL: RPC source preparation requires assertions enabled')
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification.nom_rpc_quote_source import (
    ARCHIVE_BYTES, ARCHIVE_PREFIX, ARCHIVE_SHA256, CORE, TREE, PROBES,
    check_source, inputs, require,
)


def prepare(archive, destination, *, root=ROOT):
    if sys.flags.optimize:
        raise ValueError('RPC source preparation requires assertions enabled')
    unused, index, generic, ptlc = inputs(root)
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_nlink == 1
        and archive.stat().st_size == ARCHIVE_BYTES)
    require(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir())
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == ARCHIVE_SHA256)
    payloads = {}
    seen = set()
    directories = {''}
    for name in index:
        parts = name.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    with zipfile.ZipFile(archive) as selected:
        members = selected.infolist()
        require(len(members) <= 2048 and sum(row.file_size for row in members) <= 64 * 1024**2)
        require(all(row.file_size <= 16 * 1024**2 and not row.flag_bits & 1 for row in members))
        for row in members:
            path = PurePosixPath(row.filename)
            mode = row.external_attr >> 16
            folded = row.filename.rstrip('/').casefold()
            require(path.parts and not path.is_absolute() and '..' not in path.parts
                and '\\' not in row.filename and row.filename.rstrip('/') == path.as_posix()
                and path.parts[0] == ARCHIVE_PREFIX and folded not in seen)
            require(not mode or stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR))
            seen.add(folded)
            name = '/'.join(path.parts[1:])
            if row.is_dir():
                require(name in directories)
                continue
            require(name in index and name not in payloads)
            data = selected.read(row)
            expected = index[name]
            require(len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256'])
            require(hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest() == expected['git_blob_sha1'])
            payloads[name] = data
        require(set(payloads) == set(index) and selected.testzip() is None)
    for name, source in PROBES.items():
        require(name not in payloads)
        payloads[name] = (root / source).read_bytes()
    destination.mkdir(mode=0o700)
    # No write precedes the complete archive checks. Interrupted selected output
    # stays at its original name for separate inspection, without repair.
    for name, data in sorted(payloads.items()):
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
    check_source(destination, index, root)
    return dict(outcome='PASS_RPC_SOURCE_PREPARATION_ONLY', core_commit=CORE, core_tree=TREE,
        original_source_files=443, added_original_project_probes=3, combined_source_files=446,
        archive_sha256=ARCHIVE_SHA256, selected_generic_records=len(generic), selected_ptlc_records=len(ptlc),
        source_license='PINNED UPSTREAM GPL VERSION 3; NOT VENDORED OR RELICENSED',
        native_execution='NOT_PERFORMED', node_activation='NOT_PERFORMED',
        journal_source_upgrade='NOT_SELECTED', application='NO-GO', core='NO-GO')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = prepare(args.archive, args.destination)
    except (AssertionError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print('FAIL: selected RPC source preparation; preserve any partial owned output', file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
