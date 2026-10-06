#!/usr/bin/env python3
"""Explicitly build one fixed-source research worker, then compare its claims.

This entry executes selected Cargo, compilers and dependency build scripts.
It acquires no dependencies and launches no verification worker. Tool/host
trust and quiescent selections remain preconditions, not provenance proof.
"""

import hashlib
import os
from pathlib import Path
import platform as host_platform
import sys

if __package__:
    from . import check_worker_build as check
    from .prepare_cargo_resolution import prepare
    from .qualify_cargo_resolution import COMMIT, MANIFEST_SHA256, BASELINE_SHA256
    from .qualify_build_inputs import select_digest
else:
    import check_worker_build as check
    from prepare_cargo_resolution import prepare
    from qualify_cargo_resolution import COMMIT, MANIFEST_SHA256, BASELINE_SHA256
    from qualify_build_inputs import select_digest

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from offline_session.public_worker import _run, WorkerError


def native_platform():
    machine = host_platform.machine()
    if sys.platform == "darwin" and machine == "arm64":
        return "aarch64-apple-darwin"
    if sys.platform == "linux" and machine == "x86_64":
        return "x86_64-unknown-linux-gnu"
    raise check.InputError("selected native host profile unavailable")


def qualify(root, workspace, build_directory, home, platform, tools):
    if platform not in check.resolution.PLATFORMS or type(tools) is not dict or set(tools) != set(check.NATIVE_ROLES):
        raise check.InputError("explicit selected platform and native tools required")
    if platform != native_platform():
        raise check.InputError("selected platform differs from native host profile")
    check.owned_directory(workspace, empty=True)
    check.owned_directory(build_directory, empty=True)
    check.separate_directories(workspace, build_directory)
    native = {role: (path, select_digest(path)) for role, path in tools.items()}
    before_tools = {role: check.inputs.measure(*native[role], check.inputs.MAX_NATIVE_BYTES) for role in check.NATIVE_ROLES}
    _, _, bodies = check.inputs.selected_source(root, COMMIT, MANIFEST_SHA256)
    packages = check.inputs.cargo_records(bodies["qualification/Cargo.lock"])
    cache = check.resolution.caches.one_directory(home/"registry/cache")
    registry = check.resolution.caches.one_directory(home/"registry/src")
    if cache.name != registry.name:
        raise check.InputError("selected registry namespaces differ")
    checkouts = check.resolution.caches.select_checkouts(home, packages)
    before_contents = check.resolution.content.inspect_cargo(root, COMMIT, MANIFEST_SHA256, cache, registry, checkouts)
    copied = prepare(root, workspace, COMMIT, MANIFEST_SHA256)
    previous_environment, previous_directory = dict(os.environ), Path.cwd()
    metadata = workspace/"metadata.json"
    messages = workspace/"build-messages.jsonl"
    try:
        for name in list(os.environ):
            if name.startswith(("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                                "CARGO_BUILD_RUSTC", "CARGO_BUILD_TARGET")):
                del os.environ[name]
        target_token = platform.upper().replace("-", "_")
        os.environ.update(RUSTC=str(tools["rustc"]), CC=str(tools["c-compiler"]),
                          CARGO_HOME=str(home), CARGO_NET_OFFLINE="true",
                          CARGO_TARGET_DIR=str(workspace/"metadata-target"))
        for suffix in (platform, platform.replace("-", "_")):
            os.environ["CC_"+suffix] = str(tools["c-compiler"])
        os.environ["CARGO_TARGET_"+target_token+"_LINKER"] = str(tools["c-compiler"])
        os.environ.pop("CARGO_TARGET_"+target_token+"_RUSTFLAGS", None)
        os.chdir(workspace)
        manifest = str(workspace/"qualification/Cargo.toml")
        raw = _run([str(tools["cargo"]), "metadata", "--locked", "--offline", "--format-version", "1",
                    "--manifest-path", manifest, "--filter-platform", platform], b"", timeout=30,
                   max_output_bytes=check.resolution.MAX_JSON_BYTES)
        with metadata.open("xb") as handle:
            handle.write(raw)
        prebuild = check.resolution.inspect(root, COMMIT, MANIFEST_SHA256, workspace, metadata, home, platform, BASELINE_SHA256)
        if prebuild["selected_contents_sha256"] != hashlib.sha256(check.encoded(before_contents)).hexdigest():
            raise check.InputError("selected contents changed before build")
        check.owned_directory(build_directory, empty=True)
        os.environ["CARGO_TARGET_DIR"] = str(build_directory)
        raw = _run([str(tools["cargo"]), "build", "--locked", "--offline", "--message-format=json",
                    "--manifest-path", manifest, "--example", check.WORKER, "--target", platform,
                    "--target-dir", str(build_directory)], b"", timeout=240, max_output_bytes=check.MAX_STREAM_BYTES)
        with messages.open("xb") as handle:
            handle.write(raw)
    finally:
        os.chdir(previous_directory)
        os.environ.clear()
        os.environ.update(previous_environment)
    worker = build_directory/platform/"debug/examples"/check.WORKER
    report = check.inspect(root, COMMIT, MANIFEST_SHA256, BASELINE_SHA256, workspace, metadata, home,
                           platform, build_directory, messages, 0, native, select_digest(worker))
    if (report["prepared_source_files"] != copied
            or report["selected_contents_sha256"] != prebuild["selected_contents_sha256"]
            or report["resolution_sha256"] != hashlib.sha256(check.encoded(prebuild["resolution"])).hexdigest()):
        raise check.InputError("selected source and contents changed after build")
    for role in check.NATIVE_ROLES:
        if check.inputs.measure(*native[role], check.inputs.MAX_NATIVE_BYTES) != before_tools[role]:
            raise check.InputError("selected native input changed after build")
    report["execution"] = "SEPARATE BOUNDED SELECTED NATIVE BUILD RETURNED ZERO; NOT ATTESTED"
    report["pre_post_comparison"] = "SELECTED SOURCE, CONTENTS AND THREE NATIVE INPUTS MATCH"
    report["native_digest_selection"] = "LOCALLY SELECTED IN THIS RUN; NOT DISTRIBUTION ATTESTATION"
    return report


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in ("workspace", "build-directory", "cargo-home")+check.NATIVE_ROLES:
            parser.add_argument("--"+name, type=Path, required=True)
        parser.add_argument("--platform", choices=check.resolution.PLATFORMS, required=True)
        args = parser.parse_args()
        tools = {role: getattr(args, role.replace("-", "_")).resolve() for role in check.NATIVE_ROLES}
        report = qualify(args.root.resolve(), args.workspace.absolute(), args.build_directory.absolute(),
                         args.cargo_home.absolute(), args.platform, tools)
        sys.stdout.buffer.write(check.encoded(report))
        print("PASS: selected fresh worker build: {} artifact claims; {} records; NOT ASSESSED".format(
            report["claims"]["records"]["compiler-artifact"], report["claims"]["record_count"]))
        return 0
    except (check.InputError, WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        print("FAIL: selected worker build qualification rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
