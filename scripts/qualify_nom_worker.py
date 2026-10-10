#!/usr/bin/env python3
"""Build the fixed NoM source and exercise its public recovery with an empty environment.

All native selections and original command streams remain in explicit private
directories. Hash agreement and same-run execution are not independent review,
complete compilation provenance, runtime/library authentication or a sandbox.
"""

import hashlib
import os
from pathlib import Path
import sys

if __package__:
    from . import check_nom_worker_subject as subject
    from . import check_worker_build as build
    from . import nom_native_command as native
    from . import qualify_worker_build as host
    from . import qualify_nom_recovery as recovery
    from .qualify_build_inputs import select_digest
else:
    import check_nom_worker_subject as subject
    import check_worker_build as build
    import qualify_worker_build as host
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts import nom_native_command as native
    from scripts import qualify_nom_recovery as recovery
    from qualify_build_inputs import select_digest

from offline_session.nom_verifier import CLEAN_EXECUTION_PROFILE
from offline_session.public_worker import WorkerError


SUBJECT_SHA256 = "59d9b134d4be55f3dc98797529aff86d121fdce3d0e2ddce8dfd7b9c171cf179"
BASELINE_PATH = "qualification/fixtures/nom_worker_resolution_v1.json"
BASELINE_SHA256 = "4a3efecfa0d9b4f66bc97e80e4c8adf69eac4c262b79211d44aee010f07ce368"
SELECTION = "PROJECT SELECTED CARGO 1.90.0 WORKSPACE CLAIMS; NOT INDEPENDENT ATTESTATION"
ALIASES = {"aarch64-apple-darwin": "apple", "x86_64-unknown-linux-gnu": "linux"}


def refuse_configuration(workspace, home):
    # Cargo searches cwd ancestors and its selected home independently of env flags.
    candidates = [home / name for name in ("config", "config.toml")]
    for parent in (workspace,) + tuple(workspace.parents):
        candidates.extend(parent / ".cargo" / name for name in ("config", "config.toml"))
    if any(path.exists() or path.is_symlink() for path in candidates):
        raise subject.SubjectError("ambient Cargo configuration is outside this selected profile")


def environment(tools, home, workspace, platform, apple_sdk_root=None):
    value = dict(PATH=os.pathsep.join((str(tools["rustc"].parent), str(tools["c-compiler"].parent),
                                     "/usr/bin", "/bin")),
                 RUSTC=str(tools["rustc"]), CC=str(tools["c-compiler"]), CARGO_HOME=str(home),
                 CARGO_NET_OFFLINE="true", CARGO_TARGET_DIR=str(workspace / "metadata-target"))
    for suffix in (platform, platform.replace("-", "_")):
        value["CC_" + suffix] = str(tools["c-compiler"])
    value["CARGO_TARGET_" + platform.upper().replace("-", "_") + "_LINKER"] = str(tools["c-compiler"])
    if apple_sdk_root is not None:
        value["SDKROOT"] = str(apple_sdk_root)
    return value


def select_sdk(platform, apple_sdk_root):
    if platform == "aarch64-apple-darwin":
        if (not isinstance(apple_sdk_root, Path) or not apple_sdk_root.is_absolute()
                or not apple_sdk_root.is_dir()):
            raise subject.SubjectError("explicit trusted Apple SDK directory required")
    elif apple_sdk_root is not None:
        raise subject.SubjectError("Apple SDK is outside the selected Linux profile")
    # Directory selection is not a hash inventory or authentication of SDK contents.
    return apple_sdk_root


def selections(root, workspace, home, evidence, tools):
    if type(tools) is not dict or set(tools) != set(build.NATIVE_ROLES):
        raise subject.SubjectError("three explicit native selections required")
    for path in (workspace, evidence):
        build.owned_directory(path, empty=True)
    build.separate_directories(workspace, evidence)
    refuse_configuration(workspace, home)
    manifest, bodies = subject.prepare(root, workspace, subject.SUBJECT_COMMIT, SUBJECT_SHA256)
    packages = build.inputs.cargo_records(bodies["qualification/Cargo.lock"])
    cache = build.resolution.caches.one_directory(home / "registry/cache")
    registry = build.resolution.caches.one_directory(home / "registry/src")
    if cache.name != registry.name:
        raise subject.SubjectError("selected registry namespaces differ")
    checkouts = build.resolution.caches.select_checkouts(home, packages)
    contents = lambda: dict(registry=build.resolution.content.registry_contents(cache, registry, packages),
                            git=build.resolution.content.git_contents(checkouts, packages))
    before = contents()
    pins = {role: select_digest(path) for role, path in tools.items()}
    measured = {role: build.inputs.measure(path, pins[role], build.inputs.MAX_NATIVE_BYTES)
                for role, path in tools.items()}
    return manifest, bodies, packages, registry, checkouts, contents, before, pins, measured


def metadata(workspace, evidence, home, tools, platform, packages, registry, checkouts):
    refuse_configuration(workspace, home)
    raw = native.run([str(tools["cargo"]), "metadata", "--locked", "--offline", "--format-version", "1",
                      "--manifest-path", str(workspace / "qualification/Cargo.toml"), "--filter-platform", platform],
                     environment=environment(tools, home, workspace, platform), directory=workspace,
                     evidence=evidence, label="metadata-" + ALIASES[platform], timeout=30)
    return raw, build.resolution.normalize(raw, packages, workspace, registry, checkouts, worker=subject.WORKER)


def compare_after(root, workspace, home, manifest, bodies, contents, before, pins, measured, tools):
    after, after_bodies = subject.verify(root, subject.SUBJECT_COMMIT, SUBJECT_SHA256)
    if after != manifest or after_bodies != bodies or contents() != before:
        raise subject.SubjectError("selected source or dependency contents changed")
    subject.selected_copy(workspace, manifest, bodies)
    refuse_configuration(workspace, home)
    for role, path in tools.items():
        if build.inputs.measure(path, pins[role], build.inputs.MAX_NATIVE_BYTES) != measured[role]:
            raise subject.SubjectError("selected native tool bytes changed")


def generate_baseline(root, workspace, home, evidence, tools):
    manifest, bodies, packages, registry, checkouts, contents, before, pins, measured = selections(
        root, workspace, home, evidence, tools)
    profiles = {platform: metadata(workspace, evidence, home, tools, platform, packages, registry, checkouts)[1]
                for platform in build.resolution.PLATFORMS}
    compare_after(root, workspace, home, manifest, bodies, contents, before, pins, measured, tools)
    return dict(schema="ptlc-nom-worker-resolution-baseline-v1", source_commit=subject.SUBJECT_COMMIT,
                subject_sha256=SUBJECT_SHA256, worker=subject.WORKER, selection=SELECTION, profiles=profiles)


def baseline(root):
    raw = subject.source._regular(root / BASELINE_PATH, subject.source.MAX_MANIFEST_BYTES)
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256 or subject.source._index(root, BASELINE_PATH) != raw:
        raise subject.SubjectError("selected NoM resolution baseline differs")
    value = subject.source._json(raw)
    build.resolution.exact(value, {"schema", "source_commit", "subject_sha256", "worker", "selection", "profiles"})
    if (raw != subject.encoded(value) or value["schema"] != "ptlc-nom-worker-resolution-baseline-v1"
            or value["source_commit"] != subject.SUBJECT_COMMIT or value["subject_sha256"] != SUBJECT_SHA256
            or value["worker"] != subject.WORKER or value["selection"] != SELECTION
            or type(value["profiles"]) is not dict or set(value["profiles"]) != set(build.resolution.PLATFORMS)):
        raise subject.SubjectError("NoM baseline fields differ")
    return value


def qualify(root, workspace, build_directory, home, evidence, platform, tools, *, apple_sdk_root=None):
    if platform not in build.resolution.PLATFORMS or platform != host.native_platform():
        raise subject.SubjectError("actual native platform selection required")
    sdk = select_sdk(platform, apple_sdk_root)
    selected_baseline = baseline(root)
    build.owned_directory(build_directory, empty=True)
    for other in (workspace, evidence):
        build.separate_directories(build_directory, other)
    manifest, bodies, packages, registry, checkouts, contents, before, pins, measured = selections(
        root, workspace, home, evidence, tools)
    raw_metadata, normalized = metadata(workspace, evidence, home, tools, platform, packages, registry, checkouts)
    if normalized != selected_baseline["profiles"][platform]:
        raise subject.SubjectError("actual NoM workspace resolution differs from project selection")
    compare_after(root, workspace, home, manifest, bodies, contents, before, pins, measured, tools)
    env = environment(tools, home, workspace, platform, sdk)
    env["CARGO_TARGET_DIR"] = str(build_directory)
    messages = native.run([str(tools["cargo"]), "build", "--locked", "--offline", "--message-format=json",
                           "--manifest-path", str(workspace / "qualification/Cargo.toml"), "--example", subject.WORKER,
                           "--target", platform, "--target-dir", str(build_directory)],
                          environment=env, directory=workspace, evidence=evidence, label="build")
    claims = build.compare(messages, build.resolution.json_claim(raw_metadata), normalized, workspace,
                           build_directory, platform, 0, worker=subject.WORKER)
    executable = build_directory / claims["selected_root"]["executable_relative_path"]
    worker_pin = select_digest(executable)
    if not os.access(executable, os.X_OK):
        raise subject.SubjectError("selected built worker is not executable")
    math = recovery.qualify(executable, execution_profile=CLEAN_EXECUTION_PROFILE, root=workspace)
    if select_digest(executable) != worker_pin:
        raise subject.SubjectError("selected built worker changed across actual recovery")
    compare_after(root, workspace, home, manifest, bodies, contents, before, pins, measured, tools)
    if baseline(root) != selected_baseline:
        raise subject.SubjectError("project resolution selection changed")
    return dict(schema="ptlc-nom-worker-qualification-v1", source_commit=subject.SUBJECT_COMMIT,
                source_tree=manifest["tree"], subject_sha256=SUBJECT_SHA256, baseline_sha256=BASELINE_SHA256,
                platform=platform, prepared_source_files=len(manifest["build_source_paths"]),
                selected_dependency_contents_sha256=hashlib.sha256(subject.encoded(before)).hexdigest(),
                registry_archive_trees=len(before["registry"]), pinned_git_trees=len(before["git"]),
                resolution_sha256=hashlib.sha256(subject.encoded(normalized)).hexdigest(),
                selected_native_tools_compared=3, worker_sha256=worker_pin, claims=claims,
                public_recovery=math, execution_profile=CLEAN_EXECUTION_PROFILE,
                boundary=dict(execution="SEPARATE OBSERVED NATIVE BUILD AND PUBLIC RECOVERY; NOT ATTESTED",
                              child_environment="EXPLICITLY EMPTY AT EXEC; RUNTIME MAY CHANGE IT",
                              cargo_configuration="ABSENT AT SELECTED HOME AND WORKSPACE ANCESTORS AT CHECKS",
                              compiled_closure="NOT DETERMINED", tool_support_and_loader="NOT AUTHENTICATED",
                              native_sdk=("EXPLICIT DIRECTORY SELECTION; CONTENTS NOT AUTHENTICATED"
                                          if sdk is not None else "NO APPLE SDK SELECTED"),
                              restored_copies="NO PROTECTION", independent_assessment="NOT ASSESSED",
                              private_artifact_release="NOT ASSESSED", application_and_core="NO-GO"))


def main():
    try:
        parser = subject.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in ("workspace", "cargo-home", "evidence") + build.NATIVE_ROLES:
            parser.add_argument("--" + name, type=Path, required=True)
        parser.add_argument("--build-directory", type=Path)
        parser.add_argument("--platform", choices=build.resolution.PLATFORMS)
        parser.add_argument("--apple-sdk-root", type=Path)
        parser.add_argument("--emit-baseline", action="store_true")
        args = parser.parse_args()
        tools = {role: getattr(args, role.replace("-", "_")).resolve() for role in build.NATIVE_ROLES}
        common = (args.root.resolve(), args.workspace.absolute(), args.cargo_home.absolute(), args.evidence.absolute(), tools)
        if args.emit_baseline:
            if args.build_directory is not None or args.platform is not None or args.apple_sdk_root is not None:
                raise subject.SubjectError("baseline generation and native qualification are separate")
            report = generate_baseline(*common)
        else:
            if args.build_directory is None or args.platform is None:
                raise subject.SubjectError("explicit native build and platform required")
            report = qualify(common[0], common[1], args.build_directory.absolute(), common[2], common[3], args.platform,
                             tools, apple_sdk_root=args.apple_sdk_root.resolve() if args.apple_sdk_root else None)
        sys.stdout.buffer.write(subject.encoded(report))
        return 0
    except (subject.SubjectError, WorkerError, recovery.RecoveryError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            AssertionError, EOFError, build.resolution.content.tarfile.TarError, build.resolution.content.zipfile.BadZipFile,
            build.resolution.content.zlib.error):
        print("FAIL: NoM worker qualification rejected; private command evidence retained", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
