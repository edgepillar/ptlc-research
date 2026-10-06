#!/usr/bin/env python3
"""Measure explicitly selected offline inputs without fetching or executing them.

Locked archive agreement and selected native bytes do not attest an installed
source tree, a build, a release, reviewer independence or application authority.
The lock readers deliberately accept only the selected generated record forms.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

if __package__:
    from . import check_observation_subject as source
else:
    import check_observation_subject as source


InputError = source.SubjectError
encoded = source.encoded
MANIFEST = "review/witness-subject.json"
SOURCE_PATHS = (
    "LICENSE", "THIRD_PARTY_NOTICES.md", "qualification/Cargo.lock",
    "qualification/Cargo.toml", "qualification/examples/verify_original_read_response.rs",
    "qualification/examples/verify_source_root.rs", "qualification-go/go.mod",
    "qualification-go/go.sum", "qualification-bitcoin-go/go.mod",
    "qualification-bitcoin-go/go.sum",
)
NATIVE_ROLES = ("cargo", "rustc", "c-compiler", "original-response-worker")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_PACKAGES = 512
MAX_NATIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVES_BYTES = 512 * 1024 * 1024
NAME = r"[A-Za-z][A-Za-z0-9_-]{0,63}"
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?"


def _text(raw):
    if type(raw) is not bytes or len(raw) > source.MAX_MANIFEST_BYTES:
        raise InputError("record exceeds bound")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise InputError("record encoding refused") from None
    if any(ord(c) < 32 and c not in "\n\t\r" for c in text) or "\x7f" in text:
        raise InputError("record encoding refused")
    return text


def _string(raw):
    # This is a literal-string subset of TOML, not a general TOML parser.
    if re.fullmatch(r'"[^"\\\x00-\x1f]*"', raw) is None:
        raise InputError("unsupported lock literal")
    return json.loads(raw)


def cargo_records(raw):
    """Read package records only; do not resolve features or a compiled closure."""
    lines = [s.strip() for s in _text(raw).splitlines()
             if s.strip() and not s.lstrip().startswith("#")]
    if not lines or lines.pop(0) != "version = 4":
        raise InputError("unsupported lock version")
    packages, row, array = [], None, None
    for line in lines:
        if array is not None:
            if line == "]":
                array = None
            else:
                if not line.endswith(",") or len(row["dependencies"]) >= MAX_PACKAGES:
                    raise InputError("unsupported dependency record")
                item = _string(line[:-1])
                if not item or len(item) > 512 or item in row["dependencies"]:
                    raise InputError("invalid dependency record")
                row["dependencies"].append(item)
            continue
        if line == "[[package]]":
            row = {}
            packages.append(row)
            if len(packages) > MAX_PACKAGES:
                raise InputError("package count exceeds bound")
            continue
        if row is None or " = " not in line:
            raise InputError("unsupported lock record")
        key, value = line.split(" = ", 1)
        if key not in {"name", "version", "source", "checksum", "dependencies"} or key in row:
            raise InputError("unsupported or duplicate lock field")
        if key == "dependencies":
            if value != "[":
                raise InputError("unsupported dependency list")
            row[key], array = [], True
        else:
            row[key] = _string(value)
    if array is not None or not packages:
        raise InputError("incomplete lock record")
    seen, archive_names = set(), set()
    for row in packages:
        if (not {"name", "version"} <= set(row)
                or re.fullmatch(NAME, row["name"]) is None
                or re.fullmatch(VERSION, row["version"]) is None):
            raise InputError("invalid package identity")
        selected = row.get("source")
        key = (row["name"], row["version"], selected)
        if key in seen:
            raise InputError("duplicate package identity")
        seen.add(key)
        if selected == REGISTRY:
            source._hex(row.get("checksum"), 64)
            filename = row["name"] + "-" + row["version"] + ".crate"
            if filename.lower() in archive_names:
                raise InputError("archive name alias")
            archive_names.add(filename.lower())
            row["kind"] = "registry-archive"
        elif selected is None:
            if "checksum" in row:
                raise InputError("local checksum substitution")
            row["kind"] = "local-record"
        else:
            match = re.fullmatch(
                r"git\+https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+"
                r"\?rev=([0-9a-f]{40})#([0-9a-f]{40})", selected)
            if match is None or match[1] != match[2] or "checksum" in row:
                raise InputError("unsupported or unpinned Git source")
            row["kind"] = "git-record"
    return sorted(packages, key=lambda r: (r["name"], r["version"], r.get("source", "")))


def go_records(mod_raw, sum_raw):
    """Keep declared requirements and checksum history separate from resolution."""
    requirements, module, language, block = [], None, None, False
    for line in _text(mod_raw).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("module ") and module is None and not block:
            module = source._path(line[7:])
        elif line.startswith("go ") and language is None and not block:
            language = line[3:]
            if re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", language) is None:
                raise InputError("invalid Go language record")
        elif line == "require (" and not block:
            block = True
        elif line == ")" and block:
            block = False
        elif block:
            match = re.fullmatch(r"(\S+) (v[0-9][A-Za-z0-9.+-]*)( // indirect)?", line)
            if match is None:
                raise InputError("unsupported Go requirement")
            requirements.append(dict(module=source._path(match[1]), version=match[2],
                                     indirect=match[3] is not None))
        else:
            raise InputError("unsupported Go module directive")
    if block or module is None or language is None or not requirements:
        raise InputError("incomplete Go module record")
    if len(requirements) > MAX_PACKAGES or len({r["module"] for r in requirements}) != len(requirements):
        raise InputError("duplicate or excessive Go requirements")
    checksums, seen = [], set()
    for line in _text(sum_raw).splitlines():
        match = re.fullmatch(r"(\S+) (v[0-9][A-Za-z0-9.+-]*)(/go.mod)? (h1:([A-Za-z0-9+/]{43}=))", line)
        if match is None:
            raise InputError("unsupported Go checksum")
        name, version, suffix, checksum, body = match.groups()
        source._path(name)
        digest = base64.b64decode(body, validate=True)
        if len(digest) != 32 or base64.b64encode(digest).decode("ascii") != body:
            raise InputError("noncanonical Go checksum")
        key = (name, version, suffix)
        if key in seen or len(checksums) >= 4096:
            raise InputError("duplicate or excessive Go checksums")
        seen.add(key)
        checksums.append(dict(module=name, version=version, kind="go.mod" if suffix else "module-content",
                              recorded_h1=checksum, contents="NOT MEASURED"))
    if not checksums or any((r["module"], r["version"], None) not in seen
                           or (r["module"], r["version"], "/go.mod") not in seen for r in requirements):
        raise InputError("required Go checksum missing")
    return dict(module=module, go=language, declared_requirements=requirements,
                checksum_records=checksums, resolved_closure="NOT DETERMINED")


def measure(path, expected, bound):
    """Stream regular owned files; no hostile filesystem or launch atomicity claim."""
    source._hex(expected, 64)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= bound:
            raise InputError("regular bounded input required")
        digest, total = hashlib.sha256(), 0
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
                raise InputError("input changed during selection")
            while True:
                part = handle.read(min(1024 * 1024, bound + 1 - total))
                if not part:
                    break
                total += len(part)
                if total > bound:
                    raise InputError("input exceeds bound")
                digest.update(part)
            after = os.fstat(handle.fileno())
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or total != before.st_size:
            raise InputError("input changed during measurement")
    except OSError:
        raise InputError("selected input unavailable") from None
    actual = digest.hexdigest()
    if actual != expected:
        raise InputError("selected input digest differs")
    return dict(bytes=total, selected_sha256=expected, measured_sha256=actual,
                status="SELECTED BYTES MATCH")


def selected_source(root, commit, manifest_sha256):
    source._hex(commit, 40)
    source._hex(manifest_sha256, 64)
    raw = source._regular(root / MANIFEST, source.MAX_MANIFEST_BYTES)
    selected = source._json(raw)
    if (raw != encoded(selected) or hashlib.sha256(raw).hexdigest() != manifest_sha256
            or type(selected) is not dict or selected.get("schema") != "ptlc-witness-review-subject-v1"
            or selected.get("commit") != commit or source._index(root, MANIFEST) != raw):
        raise InputError("selected source manifest differs")
    tree, rows, bodies = source._inventory(root, commit)
    files = selected.get("files")
    if type(files) is not list or selected.get("tree") != tree or type(selected.get("file_count")) is not int:
        raise InputError("source inventory identity differs")
    normalized = []
    for row in files:
        if type(row) is not dict or row.get("observation_status") not in {"added", "changed", "unchanged"}:
            raise InputError("source inventory record differs")
        normalized.append({k: v for k, v in row.items() if k != "observation_status"})
    if selected["file_count"] != len(rows) or encoded(normalized) != encoded(rows):
        raise InputError("complete source inventory differs")
    records = []
    for row in rows:
        name = row["path"]
        if name not in SOURCE_PATHS:
            continue
        if (source._regular(root / name, source.MAX_BLOB_BYTES) != bodies[name]
                or source._index(root, name) != bodies[name]):
            raise InputError("selected source input differs in checkout or index")
        records.append(dict(row, status="IMMUTABLE SOURCE BYTES MATCH"))
    if len(records) != len(SOURCE_PATHS):
        raise InputError("selected source input missing")
    return tree, records, {name: bodies[name] for name in SOURCE_PATHS}


def inspect(root, commit, manifest_sha256, registry_cache, native):
    if type(native) is not dict or set(native) != set(NATIVE_ROLES):
        raise InputError("exact native selection required")
    tree, records, bodies = selected_source(root, commit, manifest_sha256)
    packages = cargo_records(bodies["qualification/Cargo.lock"])
    archives, total = [], 0
    if not stat.S_ISDIR(registry_cache.lstat().st_mode):
        raise InputError("one regular registry directory required")
    for row in packages:
        if row["kind"] != "registry-archive":
            continue
        name = row["name"] + "-" + row["version"] + ".crate"
        entry = measure(registry_cache / name, row["checksum"], MAX_ARCHIVE_BYTES)
        total += entry["bytes"]
        if total > MAX_ARCHIVES_BYTES:
            raise InputError("aggregate archive bound exceeded")
        archives.append(dict(entry, name=row["name"], version=row["version"],
                             logical_file=name, expectation="SELECTED CARGO.LOCK CHECKSUM"))
    if not archives:
        raise InputError("registry archive selection empty")
    native_records = []
    for role in NATIVE_ROLES:
        path, digest = native[role]
        native_records.append(dict(measure(path, digest, MAX_NATIVE_BYTES), role=role,
                                   expectation="CALLER SELECTED DIGEST; ORIGIN NOT ATTESTED"))
    go = {name: go_records(bodies[name + "/go.mod"], bodies[name + "/go.sum"])
          for name in ("qualification-go", "qualification-bitcoin-go")}
    return dict(schema="ptlc-offline-build-input-evidence-v1", source_commit=commit, source_tree=tree,
        witness_manifest_sha256=manifest_sha256, source_inputs=records, cargo_lock_records=packages,
        measured_registry_archives=archives, registry_archive_bytes=total, native_inputs=native_records,
        go_records=go, outcome="SELECTED MEASUREMENTS MATCH; NOT ASSESSED",
        boundary=dict(installed_dependency_sources="NOT MEASURED", git_dependency_contents="NOT MEASURED",
            go_module_contents="NOT MEASURED", minimal_compiled_closure="NOT DETERMINED",
            build_execution="NOT PERFORMED BY THIS CHECK", source_to_executable_provenance="NOT VERIFIED",
            runtime_environment="NOT ATTESTED", license_compliance="NOT ASSESSED",
            reproducible_or_portable_build="NOT ESTABLISHED", independent_review="NOT ASSESSED",
            application_and_core="NO-GO"))


def main():
    try:
        parser = source._Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True)
        parser.add_argument("--expect-manifest-sha256", required=True)
        parser.add_argument("--registry-cache", type=Path, required=True)
        for role in NATIVE_ROLES:
            parser.add_argument("--" + role, type=Path, required=True)
            parser.add_argument("--expect-" + role + "-sha256", required=True)
        args = parser.parse_args()
        native = {role: (getattr(args, role.replace("-", "_")),
                         getattr(args, "expect_" + role.replace("-", "_") + "_sha256"))
                  for role in NATIVE_ROLES}
        report = inspect(args.root.resolve(), args.expect_commit, args.expect_manifest_sha256,
                         args.registry_cache, native)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError, KeyError, UnicodeError, RuntimeError):
        print("FAIL: offline build input inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
