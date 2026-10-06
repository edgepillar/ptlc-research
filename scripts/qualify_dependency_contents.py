#!/usr/bin/env python3
"""Select existing offline cache layouts; never download, repair or execute them."""

from pathlib import Path
import sys

if __package__:
    from . import check_dependency_contents as check
    from .qualify_build_inputs import COMMIT, MANIFEST_SHA256
else:
    import check_dependency_contents as check
    from qualify_build_inputs import COMMIT, MANIFEST_SHA256


def one_directory(root):
    check.directory(root)
    selected = []
    for child in root.iterdir():
        check.directory(child)
        selected.append(child)
        if len(selected) > 1:
            raise check.InputError("ambiguous cache namespace")
    if len(selected) != 1:
        raise check.InputError("one existing cache namespace required")
    return selected[0]


def select_checkouts(home, packages):
    pins = {row["source"].split("#")[1] for row in packages if row["kind"] == "git-record"}
    selected, count = {}, 0
    root = home / "git/checkouts"
    check.directory(root)
    for namespace in root.iterdir():
        count += 1
        if count > check.inputs.MAX_PACKAGES:
            raise check.InputError("Git cache selection exceeds bound")
        check.directory(namespace)
        for candidate in namespace.iterdir():
            count += 1
            if count > check.inputs.MAX_PACKAGES:
                raise check.InputError("Git cache selection exceeds bound")
            check.directory(candidate)
            check.directory(candidate / ".git")
            pin = check.inputs.source._git(candidate, "rev-parse", "HEAD").decode("ascii").strip()
            if pin in pins:
                if pin in selected:
                    raise check.InputError("ambiguous pinned Git checkout")
                selected[pin] = candidate
    if set(selected) != pins:
        raise check.InputError("pinned Git checkout unavailable")
    return selected


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--cargo-home", type=Path)
        parser.add_argument("--go-cache", type=Path)
        parser.add_argument("--go-module", choices=check.GO_MODULES)
        args = parser.parse_args()
        root = args.root.resolve()
        if args.cargo_home is not None and args.go_cache is None and args.go_module is None:
            check.directory(args.cargo_home)
            cache = one_directory(args.cargo_home / "registry/cache")
            installed = one_directory(args.cargo_home / "registry/src")
            if cache.name != installed.name:
                raise check.InputError("registry cache namespaces differ")
            _, _, bodies = check.inputs.selected_source(root, COMMIT, MANIFEST_SHA256)
            packages = check.inputs.cargo_records(bodies["qualification/Cargo.lock"])
            report = check.inspect_cargo(root, COMMIT, MANIFEST_SHA256, cache, installed,
                                         select_checkouts(args.cargo_home, packages))
            count = len(report["registry"])
            summary = "{} registry archives/trees; {} pinned Git trees".format(count, len(report["git"]))
        elif args.go_cache is not None and args.go_module is not None and args.cargo_home is None:
            report = check.inspect_go(root, COMMIT, MANIFEST_SHA256, args.go_cache, args.go_module)
            summary = "{} declared Go module contents".format(len(report["modules"]))
        else:
            raise check.InputError("one explicit cache profile required")
        sys.stdout.buffer.write(check.encoded(report))
        sys.stdout.flush()
        print("PASS: offline dependency content evidence: " + summary + "; NOT ASSESSED")
        return 0
    except (check.InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.tarfile.TarError, check.zipfile.BadZipFile, check.zlib.error):
        print("FAIL: offline dependency content qualification rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
