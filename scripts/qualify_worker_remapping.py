#!/usr/bin/env python3
"""Build two fixed-source private workers with a separate target-only Rust profile.

Selected native tools and build scripts execute offline. Verification workers
are not launched. Complete-byte observations do not authorize artifact release.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sys

if __package__:
    from . import qualify_worker_build as original
    from . import check_artifact_prefixes as scanner
else:
    import qualify_worker_build as original
    import check_artifact_prefixes as scanner


check = original.check
InputError = check.InputError
REFUSAL = "selected remapping qualification refused"
DESTINATIONS = dict(zip(scanner.ROLES, ("/ptlc/source/", "/ptlc/build/",
                                       "/ptlc/cache/", "/ptlc/repository/")))
PAIR_FIELDS = ("source_commit", "witness_manifest_sha256", "resolution_baseline_sha256",
               "platform", "prepared_source_files", "resolution_sha256", "selected_contents_sha256")


def selected_locations(root, workspace, build_directory, home):
    paths = (workspace, build_directory, home, root)
    identities = []
    for path in paths:
        if type(path) is not type(Path()):
            raise InputError(REFUSAL)
        text = str(path)
        check.resolution.absolute(text)
        if "=" in text or not scanner.MIN_PREFIX_BYTES <= len(text) <= scanner.MAX_PREFIX_BYTES-1:
            raise InputError(REFUSAL)
        check.resolution.content.directory(path)
        status = path.lstat()
        if status.st_uid != os.geteuid():
            raise InputError(REFUSAL)
        identities.append((status.st_dev, status.st_ino))
    if len(set(identities)) != len(paths):
        raise InputError(REFUSAL)
    for path in (workspace, build_directory):
        check.separate_directories(path, home)
        if path in root.parents:
            raise InputError(REFUSAL)
    return {role: str(path).encode("ascii") for role, path in zip(scanner.ROLES, paths)}


def encoded_flags(locations):
    # Validate exact built-in selections before formatting private arguments.
    copied = scanner.selected_prefixes(dict(first=locations, second=locations))["first"]
    for value in copied.values():
        try:
            text = value.decode("ascii")
        except UnicodeError:
            raise InputError(REFUSAL) from None
        check.resolution.absolute(text)
        if "=" in text:
            raise InputError(REFUSAL)
    order = sorted(scanner.ROLES, key=lambda role: (len(copied[role]), scanner.ROLES.index(role)))
    return "\x1f".join("--remap-path-prefix="+copied[role].decode("ascii")+"/="+DESTINATIONS[role]
                       for role in order)


def selected_profile():
    return dict(schema="ptlc-offline-target-rust-remapping-profile-v1",
                option="--remap-path-prefix", option_count=4,
                transport="CARGO_ENCODED_RUSTFLAGS; ASCII UNIT SEPARATOR",
                destinations=DESTINATIONS.copy(), from_scope="FOUR EXPLICIT DIRECTORY PREFIXES WITH TRAILING SLASH",
                ordering="SHORTEST BYTE PREFIX FIRST; FIXED ROLE ORDER BREAKS TIES",
                target_scope="EXPLICIT NATIVE TARGET ONLY",
                host_rust_coverage="BUILD-SCRIPT AND PROC-MACRO COMPILATION NOT COVERED",
                c_linker_and_support_inputs="NO ADDITIONAL REMAPPING; NOT FULLY ASSESSED",
                root_claim_profile=check.ROOT_PROFILE.copy(), root_features=[],
                profile_origin="FIXED DRIVER SELECTION; NOT CARGO CLAIM ATTESTATION")


def validate_pair(root, selections, home, platform, tools):
    scanner.fields(selections, scanner.SELECTIONS)
    scanner.fields(tools, check.NATIVE_ROLES)
    if type(platform) is not str or platform not in check.resolution.PLATFORMS or platform != original.native_platform():
        raise InputError(REFUSAL)
    if any(type(path) is not type(Path()) or not path.is_absolute() for path in tools.values()):
        raise InputError(REFUSAL)
    locations, directories, copied = {}, [], {}
    for name in scanner.SELECTIONS:
        pair = selections[name]
        if type(pair) is not tuple or len(pair) != 2:
            raise InputError(REFUSAL)
        locations[name] = selected_locations(root, pair[0], pair[1], home)
        for path in pair:
            check.owned_directory(path, empty=True)
            directories.append(path)
        copied[name] = pair
    for i, path in enumerate(directories):
        for other in directories[i+1:]:
            check.separate_directories(path, other)
            a, b = path.lstat(), other.lstat()
            if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
                raise InputError(REFUSAL)
    return copied, scanner.selected_prefixes(locations)


@contextmanager
def _environment(tools, home, workspace, platform, flags):
    previous_environment, previous_directory = dict(os.environ), Path.cwd()
    try:
        for name in list(os.environ):
            if name.startswith(("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                                "CARGO_BUILD_RUSTC", "CARGO_BUILD_TARGET")):
                del os.environ[name]
        target_token = platform.upper().replace("-", "_")
        os.environ.update(RUSTC=str(tools["rustc"]), CC=str(tools["c-compiler"]), CARGO_HOME=str(home),
                          CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(workspace/"metadata-target"),
                          CARGO_ENCODED_RUSTFLAGS=flags)
        for suffix in (platform, platform.replace("-", "_")):
            os.environ["CC_"+suffix] = str(tools["c-compiler"])
        os.environ["CARGO_TARGET_"+target_token+"_LINKER"] = str(tools["c-compiler"])
        os.environ.pop("CARGO_TARGET_"+target_token+"_RUSTFLAGS", None)
        os.chdir(workspace)
        yield
    finally:
        try:
            os.chdir(previous_directory)
        finally:
            os.environ.clear()
            os.environ.update(previous_environment)


def _save_private(path, raw):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(raw)


def _build(root, workspace, build_directory, home, platform, tools, flags):
    # Reuse the fixed-source gates, not the original companion's flag selection.
    check.owned_directory(workspace, empty=True)
    check.owned_directory(build_directory, empty=True)
    native = {role: (tools[role], original.select_digest(tools[role])) for role in check.NATIVE_ROLES}
    before_tools = {role: check.inputs.measure(*native[role], check.inputs.MAX_NATIVE_BYTES) for role in check.NATIVE_ROLES}
    _, _, bodies = check.inputs.selected_source(root, original.COMMIT, original.MANIFEST_SHA256)
    packages = check.inputs.cargo_records(bodies["qualification/Cargo.lock"])
    cache = check.resolution.caches.one_directory(home/"registry/cache")
    registry = check.resolution.caches.one_directory(home/"registry/src")
    if cache.name != registry.name:
        raise InputError(REFUSAL)
    checkouts = check.resolution.caches.select_checkouts(home, packages)
    before_contents = check.resolution.content.inspect_cargo(root, original.COMMIT, original.MANIFEST_SHA256,
                                                            cache, registry, checkouts)
    copied = original.prepare(root, workspace, original.COMMIT, original.MANIFEST_SHA256)
    metadata, messages = workspace/"metadata.json", workspace/"build-messages.jsonl"
    with _environment(tools, home, workspace, platform, flags):
        manifest = str(workspace/"qualification/Cargo.toml")
        raw = original._run([str(tools["cargo"]), "metadata", "--locked", "--offline", "--format-version", "1",
                             "--manifest-path", manifest, "--filter-platform", platform], b"", timeout=30,
                            max_output_bytes=check.resolution.MAX_JSON_BYTES)
        _save_private(metadata, raw)
        prebuild = check.resolution.inspect(root, original.COMMIT, original.MANIFEST_SHA256, workspace,
                                           metadata, home, platform, original.BASELINE_SHA256)
        if prebuild["selected_contents_sha256"] != hashlib.sha256(check.encoded(before_contents)).hexdigest():
            raise InputError(REFUSAL)
        check.owned_directory(build_directory, empty=True)
        os.environ["CARGO_TARGET_DIR"] = str(build_directory)
        raw = original._run([str(tools["cargo"]), "build", "--locked", "--offline", "--message-format=json",
                             "--manifest-path", manifest, "--example", check.WORKER, "--target", platform,
                             "--target-dir", str(build_directory)], b"", timeout=240,
                            max_output_bytes=check.MAX_STREAM_BYTES)
        _save_private(messages, raw)
    worker = build_directory/platform/"debug/examples"/check.WORKER
    report = check.inspect(root, original.COMMIT, original.MANIFEST_SHA256, original.BASELINE_SHA256,
                           workspace, metadata, home, platform, build_directory, messages, 0, native,
                           original.select_digest(worker))
    if (report["prepared_source_files"] != copied or report["selected_contents_sha256"] != prebuild["selected_contents_sha256"]
            or report["resolution_sha256"] != hashlib.sha256(check.encoded(prebuild["resolution"])).hexdigest()):
        raise InputError(REFUSAL)
    for role in check.NATIVE_ROLES:
        if check.inputs.measure(*native[role], check.inputs.MAX_NATIVE_BYTES) != before_tools[role]:
            raise InputError(REFUSAL)
    report.update(execution="SEPARATE BOUNDED SELECTED NATIVE BUILD RETURNED ZERO; NOT ATTESTED",
                  pre_post_comparison="SELECTED SOURCE, CONTENTS AND THREE NATIVE INPUTS MATCH",
                  native_digest_selection="LOCALLY SELECTED IN THIS RUN; NOT DISTRIBUTION ATTESTATION")
    return report


def qualify(root, selections, home, platform, tools):
    try:
        pairs, locations = validate_pair(root, selections, home, platform, tools)
        tools = {role: tools[role] for role in check.NATIVE_ROLES}
        flags = {name: encoded_flags(locations[name]) for name in scanner.SELECTIONS}
        builds = {name: _build(root, *pairs[name], home, platform, tools, flags[name]) for name in scanner.SELECTIONS}
        first, second = (builds[name] for name in scanner.SELECTIONS)
        if (any(first[field] != second[field] for field in PAIR_FIELDS)
                or first["claims"]["selected_root"] != second["claims"]["selected_root"]
                or any(first["measured_inputs"][role] != second["measured_inputs"][role] for role in check.NATIVE_ROLES)):
            raise InputError(REFUSAL)
        arguments = []
        for name in scanner.SELECTIONS:
            worker = pairs[name][1]/platform/"debug/examples"/check.WORKER
            measured = builds[name]["measured_inputs"]["original-response-worker"]
            arguments.extend((worker, measured["selected_sha256"], measured["bytes"]))
        comparison = scanner.inspect(*arguments, locations)
        return dict(schema="ptlc-offline-rust-path-remapping-pair-v1", selected_profile=selected_profile(),
                    builds=builds, comparison=comparison,
                    pair_selection="TWO SEPARATE FRESH BUILDS; SAME LOGICAL PROFILE AND SELECTED NATIVE BYTES",
                    execution_origin="TRUSTED DRIVER AND HOST; NOT ATTESTED",
                    artifact_publication="KEEP BOTH ARTIFACTS PRIVATE", reproducibility="NOT VERIFIED",
                    source_to_worker="NOT VERIFIED", independent_privacy_assessment="NOT ASSESSED",
                    application_and_core="NO-GO")
    except (InputError, original.WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = check.inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in scanner.SELECTIONS:
            parser.add_argument("--"+name+"-workspace", type=Path, required=True)
            parser.add_argument("--"+name+"-build-directory", type=Path, required=True)
        for name in ("cargo-home",)+check.NATIVE_ROLES:
            parser.add_argument("--"+name, type=Path, required=True)
        parser.add_argument("--platform", choices=check.resolution.PLATFORMS, required=True)
        args = parser.parse_args()
        pairs = {name: (getattr(args, name+"_workspace").absolute(),
                        getattr(args, name+"_build_directory").absolute()) for name in scanner.SELECTIONS}
        tools = {role: getattr(args, role.replace("-", "_")).resolve() for role in check.NATIVE_ROLES}
        report = qualify(args.root.resolve(), pairs, args.cargo_home.absolute(), args.platform, tools)
        sys.stdout.buffer.write(check.encoded(report))
        print("PASS: selected target-only Rust remapping pair; two builds; complete byte scan; NOT ASSESSED")
        return 0
    except (InputError, original.WorkerError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, check.resolution.content.tarfile.TarError, check.resolution.content.zipfile.BadZipFile,
            check.resolution.content.zlib.error):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
