#!/usr/bin/env python3
"""Compare bounded selected-root Cargo build claims and explicitly selected bytes.

Native Git reads immutable source objects. Cargo, compilers, build scripts and
workers are never launched. Agreement is not authenticated build provenance.
"""

import hashlib
import os
from pathlib import Path
import sys

if __package__:
    from . import check_cargo_resolution as resolution
else:
    import check_cargo_resolution as resolution


inputs = resolution.inputs
InputError = inputs.InputError
encoded = inputs.encoded
NATIVE_ROLES = ("cargo", "rustc", "c-compiler")
WORKER = "verify_original_read_response"
MAX_STREAM_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_RECORDS = 4096
MAX_VALUES = 200000
PROFILE_FIELDS = {"opt_level", "debuginfo", "debug_assertions", "overflow_checks", "test"}
ROOT_PROFILE = dict(opt_level="0", debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)
ARTIFACT_FIELDS = {"reason", "package_id", "manifest_path", "target", "profile", "features",
                   "filenames", "executable", "fresh"}
SCRIPT_FIELDS = {"reason", "package_id", "linked_libs", "linked_paths", "cfgs", "env", "out_dir"}


def owned_directory(path, empty=False):
    resolution.content.directory(path)
    status = path.lstat()
    if status.st_uid != os.geteuid() or status.st_mode & 0o077 or (empty and any(path.iterdir())):
        raise InputError("private owned selected directory required")


def separate_directories(workspace, build_directory):
    for first, second in ((workspace, build_directory), (build_directory, workspace)):
        if first == second or first in second.parents:
            raise InputError("separate selected source and build directories required")


def records(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_STREAM_BYTES or not raw.endswith(b"\n"):
        raise InputError("bounded complete build stream required")
    lines = raw[:-1].split(b"\n")
    if not 0 < len(lines) <= MAX_RECORDS:
        raise InputError("build record bound exceeded")
    result, values = [], 0
    for line in lines:
        if not line or len(line) > MAX_LINE_BYTES or b"\r" in line:
            raise InputError("unsupported build record framing")
        row = resolution.json_claim(line)
        if type(row) is not dict or type(row.get("reason")) is not str:
            raise InputError("build record object required")
        pending = [row]
        while pending:
            value = pending.pop()
            values += 1
            if values > MAX_VALUES:
                raise InputError("aggregate build value bound exceeded")
            if type(value) is dict:
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
        result.append(row)
    return result


def profile(value):
    resolution.exact(value, PROFILE_FIELDS)
    if (type(value["opt_level"]) is not str or value["opt_level"] not in {"0", "1", "2", "3", "s", "z"}
            or type(value["debuginfo"]) is not int or not 0 <= value["debuginfo"] <= 2
            or any(type(value[name]) is not bool for name in ("debug_assertions", "overflow_checks", "test"))):
        raise InputError("unsupported artifact profile")


def private_strings(value):
    if (type(value) is not list or len(value) > 512
            or any(type(v) is not str or len(v) > 4096 or "\x00" in v for v in value)):
        raise InputError("private build output bound exceeded")


def bind_target(row, package):
    if row["manifest_path"] != package["manifest_path"]:
        raise InputError("artifact manifest differs from selected metadata")
    if (type(row["target"]) is not dict
            or not any(encoded(row["target"]) == encoded(t) for t in package["targets"])):
        raise InputError("artifact target differs from selected metadata")


def compare(raw, metadata, selected, workspace, build_directory, platform, exit_status):
    """Metadata and selected resolution must already pass the fixed comparison.

    This internal predicate does not independently select or verify a baseline.
    The public inspect entry performs those checks before calling it.
    """
    if type(exit_status) is not int or exit_status != 0 or platform not in resolution.PLATFORMS:
        raise InputError("selected successful build status required")
    if resolution.absolute(metadata["target_directory"]) != workspace/"metadata-target":
        raise InputError("selected metadata query directory differs")
    by_id = {p["id"]: p for p in metadata["packages"]}
    root_id = metadata["resolve"]["root"]
    expected_executable = build_directory/platform/"debug/examples"/WORKER
    counts = {name: 0 for name in ("compiler-artifact", "compiler-message", "build-script-executed", "build-finished")}
    selected_root, duplicates, finished = None, set(), False
    rows = records(raw)
    for row in rows:
        if finished:
            raise InputError("record follows terminal build result")
        reason = row["reason"]
        if reason not in counts:
            raise InputError("unsupported build record reason")
        counts[reason] += 1
        if reason == "build-finished":
            resolution.exact(row, {"reason", "success"})
            if row["success"] is not True:
                raise InputError("successful terminal build result required")
            finished = True
            continue
        package_id = resolution.opaque(row.get("package_id"))
        if package_id not in by_id:
            raise InputError("build package absent from selected resolution")
        package = by_id[package_id]
        if reason == "compiler-message":
            resolution.exact(row, {"reason", "package_id", "manifest_path", "target", "message"})
            bind_target(row, package)
            message = row["message"]
            if type(message) is not dict or message.get("level") not in ("warning", "note", "help"):
                raise InputError("unsupported or failed compiler diagnostic")
            continue
        if reason == "build-script-executed":
            resolution.exact(row, SCRIPT_FIELDS)
            if not any(t["kind"] == ["custom-build"] for t in package["targets"]):
                raise InputError("build script absent from selected declaration")
            for name in ("linked_libs", "linked_paths", "cfgs"):
                private_strings(row[name])
            env = row["env"]
            if type(env) is not list or len(env) > 512:
                raise InputError("private build environment bound exceeded")
            for pair in env:
                if type(pair) is not list or len(pair) != 2:
                    raise InputError("private build environment shape differs")
                private_strings(pair)
            resolution.relative(row["out_dir"], build_directory)
            continue
        resolution.exact(row, ARTIFACT_FIELDS)
        bind_target(row, package)
        profile(row["profile"])
        features = resolution.symbols(row["features"])
        if set(features) - set(package["features"]):
            raise InputError("artifact feature absent from selected declaration")
        if row["fresh"] is not False:
            raise InputError("cached or unsupported artifact freshness refused")
        filenames = row["filenames"]
        if type(filenames) is not list or not 0 < len(filenames) <= 32:
            raise InputError("artifact output path bound exceeded")
        names = [resolution.relative(v, build_directory) for v in filenames]
        if len(names) != len(set(names)):
            raise InputError("duplicate artifact output path")
        executable = row["executable"]
        if executable is not None:
            resolution.relative(executable, build_directory)
            if executable not in filenames:
                raise InputError("artifact executable absent from outputs")
        signature = encoded(dict(package_id=package_id, target=row["target"], profile=row["profile"],
                                 features=features, filenames=sorted(names), executable=executable))
        if signature in duplicates:
            raise InputError("duplicate operative artifact record")
        duplicates.add(signature)
        if package_id == root_id and row["target"]["name"] == WORKER:
            if (selected_root is not None or row["profile"] != ROOT_PROFILE or features
                    or resolution.absolute(executable) != expected_executable):
                raise InputError("selected root artifact differs or is ambiguous")
            targets = selected["packages"][selected["root"]]["targets"]
            matches = [t for t in targets if t["name"] == WORKER]
            if len(matches) != 1:
                raise InputError("selected root source target ambiguous")
            selected_root = dict(package=selected["root"], target=matches[0], profile=ROOT_PROFILE.copy(),
                                 features=features, fresh=False,
                                 executable_relative_path=expected_executable.relative_to(build_directory).as_posix())
    if not finished or counts["build-finished"] != 1 or selected_root is None:
        raise InputError("complete unambiguous selected root build claim required")
    return dict(record_count=len(rows), records=counts, selected_root=selected_root,
                other_artifact_claims=counts["compiler-artifact"]-1)


def inspect(root, commit, manifest_sha256, baseline_sha256, workspace, metadata_path, home,
            platform, build_directory, messages_path, exit_status, native, worker_sha256):
    owned_directory(workspace)
    owned_directory(build_directory)
    separate_directories(workspace, build_directory)
    if type(native) is not dict or set(native) != set(NATIVE_ROLES):
        raise InputError("all three explicit native input selections required")
    measured = {}
    for role in NATIVE_ROLES:
        selection = native[role]
        if type(selection) is not tuple or len(selection) != 2 or not isinstance(selection[0], Path):
            raise InputError("explicit native path and digest required")
        measured[role] = inputs.measure(selection[0], selection[1], inputs.MAX_NATIVE_BYTES)
    evidence = resolution.inspect(root, commit, manifest_sha256, workspace, metadata_path, home, platform, baseline_sha256)
    with resolution.content.regular(metadata_path, resolution.MAX_JSON_BYTES) as handle:
        metadata = resolution.json_claim(handle.read(resolution.MAX_JSON_BYTES+1))
    # Re-read metadata must still normalize to the verified complete resolution.
    _, _, bodies = inputs.selected_source(root, commit, manifest_sha256)
    packages = inputs.cargo_records(bodies["qualification/Cargo.lock"])
    registry = resolution.caches.one_directory(home/"registry/src")
    checkouts = resolution.caches.select_checkouts(home, packages)
    if resolution.normalize(encoded(metadata), packages, workspace, registry, checkouts) != evidence["resolution"]:
        raise InputError("metadata changed after selected comparison")
    with resolution.content.regular(messages_path, MAX_STREAM_BYTES) as handle:
        raw = handle.read(MAX_STREAM_BYTES+1)
    result = compare(raw, metadata, evidence["resolution"], workspace, build_directory, platform, exit_status)
    worker = build_directory/result["selected_root"]["executable_relative_path"]
    relative_parents = worker.relative_to(build_directory).parts[:-1]
    parent = build_directory
    for name in relative_parents:
        parent = parent/name
        resolution.content.directory(parent)
    measured["original-response-worker"] = inputs.measure(worker, worker_sha256, inputs.MAX_NATIVE_BYTES)
    if not os.access(worker, os.X_OK):
        raise InputError("selected worker is not executable")
    return dict(schema="ptlc-offline-selected-worker-build-evidence-v1", source_commit=commit,
                witness_manifest_sha256=manifest_sha256, resolution_baseline_sha256=baseline_sha256,
                platform=platform, prepared_source_files=evidence["prepared_source_files"],
                resolution_sha256=hashlib.sha256(encoded(evidence["resolution"])).hexdigest(),
                selected_contents_sha256=evidence["selected_contents_sha256"],
                claims=result, measured_inputs=measured, reported_exit_status=exit_status,
                outcome="SELECTED ROOT BUILD CLAIM AND BYTES MATCH; NOT ASSESSED",
                exit_status_origin="OPERATOR REPORTED; NOT AUTHENTICATED",
                generator_origin="NOT AUTHENTICATED", compiled_closure="NOT DETERMINED",
                source_to_worker="NOT VERIFIED", independent_assessment="NOT ASSESSED",
                filesystem="OWNED QUIESCENT SELECTIONS AND TRUSTED PARENTS; NO ATOMIC BUILD SNAPSHOT",
                application_and_core="NO-GO")


def main():
    try:
        parser = inputs.source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        for name in ("commit", "manifest-sha256", "baseline-sha256", "worker-sha256"):
            parser.add_argument("--expect-"+name, required=True)
        for name in ("workspace", "metadata", "cargo-home", "build-directory", "messages"):
            parser.add_argument("--"+name, type=Path, required=True)
        parser.add_argument("--platform", choices=resolution.PLATFORMS, required=True)
        parser.add_argument("--reported-exit-status", type=int, required=True)
        for role in NATIVE_ROLES:
            parser.add_argument("--"+role, type=Path, required=True)
            parser.add_argument("--expect-"+role+"-sha256", required=True)
        args = parser.parse_args()
        native = {role: (getattr(args, role.replace("-", "_")).absolute(),
                         getattr(args, "expect_"+role.replace("-", "_")+"_sha256")) for role in NATIVE_ROLES}
        report = inspect(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256,
                         args.expect_baseline_sha256, args.workspace.absolute(), args.metadata.absolute(),
                         args.cargo_home.absolute(), args.platform, args.build_directory.absolute(),
                         args.messages.absolute(), args.reported_exit_status, native, args.expect_worker_sha256)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError,
            EOFError, resolution.content.tarfile.TarError, resolution.content.zipfile.BadZipFile,
            resolution.content.zlib.error):
        print("FAIL: selected worker build comparison rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
