#!/usr/bin/env python3
"""Record same-run offline measurement consistency, never release provenance.

The caller selects Cargo home and each native file. Digests are selected locally
before inspection, not authenticated distribution pins or a source/build link.
Exactly one registry cache is required; no fetching, build or worker invocation.
"""

import hashlib
from pathlib import Path
import stat
import sys

if __package__:
    from . import check_build_inputs as check
else:
    import check_build_inputs as check


COMMIT = "bd4b4b523fb3453e2af191eb01973985d6431d66"
MANIFEST_SHA256 = "0f449db4c5e7c65f826ab57c4fafe4cd288bb570b7920d29e583b6cfd62dd82f"


def select_digest(path):
    if not stat.S_ISREG(path.lstat().st_mode) or not 0 < path.stat().st_size <= check.MAX_NATIVE_BYTES:
        raise check.InputError("bounded native selection required")
    total, digest = 0, hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            part = handle.read(1024 * 1024)
            if not part:
                break
            total += len(part)
            if total > check.MAX_NATIVE_BYTES:
                raise check.InputError("native selection exceeds bound")
            digest.update(part)
    return digest.hexdigest()


def main():
    try:
        parser = check.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--cargo-home", type=Path, required=True)
        for role in check.NATIVE_ROLES:
            parser.add_argument("--" + role, type=Path, required=True)
        args = parser.parse_args()
        caches = list((args.cargo_home / "registry/cache").iterdir())
        if len(caches) != 1 or not stat.S_ISDIR(caches[0].lstat().st_mode):
            raise check.InputError("one explicit registry cache required")
        native = {}
        for role in check.NATIVE_ROLES:
            # Resolve caller-selected compiler/toolchain links, never search PATH.
            path = getattr(args, role.replace("-", "_")).resolve(strict=True)
            native[role] = (path, select_digest(path))
        report = check.inspect(args.root.resolve(), COMMIT, MANIFEST_SHA256, caches[0], native)
        report["selection_method"] = "NATIVE DIGESTS SELECTED LOCALLY IN THIS RUN; NOT EXTERNAL ATTESTATION"
        sys.stdout.buffer.write(check.encoded(report))
        print("PASS: offline build input evidence: {} archives; {} native selections; NOT ASSESSED".format(
            len(report["measured_registry_archives"]), len(report["native_inputs"])))
        return 0
    except (check.InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError):
        print("FAIL: offline build input qualification rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
