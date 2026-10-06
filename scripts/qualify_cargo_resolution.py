#!/usr/bin/env python3
"""Compare one offline metadata claim; native Git only, no Cargo or worker launch."""

from pathlib import Path
import sys

if __package__:
    from . import check_cargo_resolution as check
    from .qualify_build_inputs import COMMIT, MANIFEST_SHA256
else:
    import check_cargo_resolution as check
    from qualify_build_inputs import COMMIT, MANIFEST_SHA256


BASELINE_SHA256 = "c55ccb81a2730b8d5779011e0eceda7659b039593d5e7a2fc930112f174df9d5"


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--workspace", type=Path, required=True)
        parser.add_argument("--metadata", type=Path, required=True)
        parser.add_argument("--cargo-home", type=Path, required=True)
        parser.add_argument("--platform", choices=check.PLATFORMS, required=True)
        args = parser.parse_args()
        report = check.inspect(args.root.resolve(), COMMIT, MANIFEST_SHA256, args.workspace.absolute(),
                               args.metadata.absolute(), args.cargo_home.absolute(), args.platform, BASELINE_SHA256)
        sys.stdout.buffer.write(check.encoded(report))
        print("PASS: selected Cargo resolution evidence: {} packages; {} edges; NOT ASSESSED".format(
            report["resolution"]["package_count"], report["resolution"]["edge_count"]))
        return 0
    except (check.InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.content.tarfile.TarError, check.content.zipfile.BadZipFile, check.content.zlib.error):
        print("FAIL: selected Cargo resolution qualification rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
