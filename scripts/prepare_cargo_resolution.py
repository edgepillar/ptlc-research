#!/usr/bin/env python3
"""Copy fixed qualification source into an explicit new owned offline workspace.

Native Git inspects local immutable objects; no Cargo query, compiler, dependency
acquisition or build is performed. Trusted parents and a quiescent destination
are required; this is not a hostile-filesystem fence.
"""

import os
from pathlib import Path
import sys

if __package__:
    from . import check_cargo_resolution as check
    from .qualify_build_inputs import COMMIT, MANIFEST_SHA256
else:
    import check_cargo_resolution as check
    from qualify_build_inputs import COMMIT, MANIFEST_SHA256


def prepare(root, destination, commit, manifest_sha256):
    check.inputs.selected_source(root, commit, manifest_sha256)
    check.content.directory(destination)
    metadata = destination.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077 or any(destination.iterdir()):
        raise check.InputError("new private owned empty destination required")
    _, rows, bodies = check.inputs.source._inventory(root, commit)
    selected = [row for row in rows if row["path"].startswith("qualification/")]
    if not selected:
        raise check.InputError("fixed qualification source unavailable")
    for row in selected:
        name = row["path"]
        if (check.inputs.source._regular(root/name, check.inputs.source.MAX_BLOB_BYTES) != bodies[name]
                or check.inputs.source._index(root, name) != bodies[name]):
            raise check.InputError("fixed qualification source differs")
    for row in selected:
        path = destination/row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(bodies[row["path"]])
    count = check.selected_copy(root, commit, destination)
    return count


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        count = prepare(args.root.resolve(), args.output.absolute(), COMMIT, MANIFEST_SHA256)
        print("PASS: prepared fixed Cargo metadata source: {} files; NOT ASSESSED".format(count))
        return 0
    except (check.InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError):
        print("FAIL: fixed Cargo metadata source preparation rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
