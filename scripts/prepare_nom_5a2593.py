#!/usr/bin/env python3
"""Prepare one new 521-file source view for the pinned offline 5a2593 profiles.

The caller separately admits owned storage and retains the acquired archive.
No existing directory is adopted and no native command or network is invoked.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('REFUSED: 5a2593 preparation requires assertions enabled')
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from qualification import nom_dev_5a2593 as selected

ARCHIVE_BYTES = 1997424
ARCHIVE_SHA256 = '13219b44f2f0a0947d23b90b8c2214dccacfe39e1689ff1c7bf18a5948d03b9b'
ARCHIVE_PREFIX = 'zenon-network-go-zenon-5a2593a'
MAX_TOTAL = 64 * 1024**2
require = selected.earlier.require


def checked_payloads(archive, index):
    """Check every member and content identity before any extraction writes."""
    directories = {''}
    for name in index:
        parts = name.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    result, seen = {}, set()
    members = archive.infolist()
    require(0 < len(members) <= 2048
            and sum(row.file_size for row in members) <= MAX_TOTAL)
    for row in members:
        path = PurePosixPath(row.filename)
        mode = stat.S_IFMT(row.external_attr >> 16)
        require(row.filename.isascii() and not path.is_absolute() and path.parts
            and all(part not in ('', '.', '..', '.git') for part in path.parts)
            and '\\' not in row.filename
            and path.as_posix() == row.filename.rstrip('/')
            and path.parts[0] == ARCHIVE_PREFIX
            and 0 <= row.file_size <= 8 * 1024**2
            and row.flag_bits & 1 == 0
            and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))
        folded = row.filename.rstrip('/').casefold()
        require(folded not in seen)
        seen.add(folded)
        name = '/'.join(path.parts[1:])
        if row.is_dir():
            require(name in directories and mode in (0, stat.S_IFDIR)
                    and row.file_size == 0)
            continue
        require(mode in (0, stat.S_IFREG) and name in index and name not in result)
        pin = index[name]
        require(row.file_size == pin['bytes'])
        with archive.open(row) as stream:
            raw = stream.read(pin['bytes'] + 1)
        require(len(raw) == pin['bytes']
            and hashlib.sha256(raw).hexdigest() == pin['sha256']
            and hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii')
                             + b'\0' + raw).hexdigest() == pin['git_blob_sha1'])
        result[name] = raw
    require(set(result) == set(index))
    return result


def prepare(archive, destination, *, root=ROOT):
    require(not sys.flags.optimize)
    unused, index = selected.inputs(root)
    archive = selected.earlier.physical(archive)
    destination = selected.earlier.physical(destination)
    info = archive.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and info.st_size == ARCHIVE_BYTES
        and not destination.exists() and not destination.is_symlink()
        and destination.parent.is_dir())
    raw = selected.earlier.regular(archive, ARCHIVE_BYTES)
    require(hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA256)
    # Re-open only this retained original archive. The selected file identities
    # are checked again before returning; the caller retains custody separately.
    before = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    with zipfile.ZipFile(archive) as original:
        payloads = checked_payloads(original, index)
    after = archive.lstat()
    require(before == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and hashlib.sha256(selected.earlier.regular(archive, ARCHIVE_BYTES)).hexdigest()
                == ARCHIVE_SHA256)
    probes = selected.probes(root, 'all')
    for name, parent in probes.items():
        require(name not in payloads)
        payloads[name] = selected.earlier.regular(Path(root) / parent, 2 * 1024**2)
    require(len(payloads) == 521 and sum(map(len, payloads.values())) <= MAX_TOTAL)
    destination.mkdir(mode=0o700)
    # A partial output remains at its original new path for separate inspection.
    # There is no replacement, cleanup, aliasing or implicit repair here.
    for name, content in sorted(payloads.items()):
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
    source = selected.compare_source(destination, root, 'all')
    return dict(schema='ptlc-nom-5a2593-source-preparation-v1',
        outcome='PASS_PINNED_SOURCE_PREPARATION_ONLY',
        core_commit=selected.CORE, core_tree=selected.TREE,
        original_archive=dict(sha256=ARCHIVE_SHA256, bytes=ARCHIVE_BYTES),
        source=source, original_source_files=500, project_producers=21,
        source_views=1, source_extractions=1,
        source_license='PINNED UPSTREAM GPL VERSION 3; NOT VENDORED OR RELICENSED',
        native_execution='NOT_PERFORMED', source_build_authentication='UNFILLED',
        journal_source_upgrade='NOT_SELECTED', application='NO-GO', core='NO-GO')


def main():
    class QuietParser(argparse.ArgumentParser):
        def error(self, message):
            raise ValueError('selected 5a2593 source preparation refused')
    parser = QuietParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    try:
        args = parser.parse_args()
        report = prepare(args.archive, args.destination)
    except (AssertionError, OSError, ValueError, KeyError, TypeError,
            zipfile.BadZipFile, RuntimeError):
        print('REFUSED: 5a2593 source preparation; preserve partial owned output', file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
