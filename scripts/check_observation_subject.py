#!/usr/bin/env python3
"""Inspect an explicitly selected offline observation review snapshot.

This source-identity tool reads local Git objects, never a verifier, wallet or
chain. A matching inventory is neither independent assessment nor provenance.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile

if __package__:
    from .check_artifacts import PATTERNS
else:
    from check_artifacts import PATTERNS


REPOSITORY = "https://github.com/edgepillar/ptlc-research"
SUBJECT_COMMIT = "f81e376e96e339647bb065739b4461235f865d2c"
BASELINE_COMMIT = "e592633e4c630cfe3f4669876f6f63b80d2e33d6"
BASELINE_SHA256 = "df9ae22448a71fc7bbec24cfe2654e0a7f88bc1792eefc97e7b780bff6636295"
ORIGINAL_PATH = "review/subject.json"
SUBJECT_PATH = "review/observation-subject.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_BLOB_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_FILES = 4096


class SubjectError(Exception):
    """A sanitized source inspection failure, never a validity verdict."""


@dataclass(frozen=True)
class Pins:
    commit: str
    baseline_commit: str = BASELINE_COMMIT
    baseline_sha256: str = BASELINE_SHA256


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SubjectError("duplicate manifest key")
            result[key] = value
        return result
    if len(raw) > MAX_MANIFEST_BYTES:
        raise SubjectError("manifest exceeds bound")
    try:
        return json.loads(raw.decode("ascii"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, RecursionError):
        raise SubjectError("invalid manifest encoding") from None


def _path(name):
    if (type(name) is not str or not name or not name.isascii()
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(char in name for char in "\\:") or name.startswith("/")
            or any(part in {".", "..", ".git", ""} for part in name.split("/"))
            or str(PurePosixPath(name)) != name
            or any(pattern.search(name) for _, pattern in PATTERNS)):
        raise SubjectError("unsafe source path")
    return name


def _hex(value, length):
    if type(value) is not str or re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is None:
        raise SubjectError("immutable identity required")
    return value


def _git(root, *arguments):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        result = subprocess.run(["git", "--no-lazy-fetch", "--no-replace-objects", *arguments],
            cwd=root, env=environment, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise SubjectError("local Git inspection unavailable") from None
    if result.returncode != 0:
        raise SubjectError("local Git object or index unavailable")
    return result.stdout


def _blob(root, object_id):
    _hex(object_id, 40)
    size = int(_git(root, "cat-file", "-s", object_id))
    if not 0 <= size <= MAX_BLOB_BYTES:
        raise SubjectError("source blob exceeds bound")
    raw = _git(root, "cat-file", "blob", object_id)
    if len(raw) != size:
        raise SubjectError("source blob size mismatch")
    return raw


def _regular(path, bound):
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > bound:
            raise SubjectError("regular bounded input required")
        with path.open("rb") as handle:
            raw = handle.read(bound + 1)
    except OSError:
        raise SubjectError("input unavailable") from None
    if len(raw) > bound:
        raise SubjectError("input exceeds bound")
    return raw


def _index(root, name):
    entries = _git(root, "ls-files", "--stage", "-z", "--", name).split(b"\0")
    entries = [entry for entry in entries if entry]
    if len(entries) != 1:
        raise SubjectError("one indexed manifest required")
    header, path = entries[0].split(b"\t", 1)
    mode, object_id, stage = header.split()
    if mode not in {b"100644", b"100755"} or stage != b"0" or path != name.encode("ascii"):
        raise SubjectError("regular resolved index entry required")
    return _blob(root, object_id.decode("ascii"))


def _inventory(root, commit):
    _hex(commit, 40)
    if _git(root, "cat-file", "-t", commit).strip() != b"commit":
        raise SubjectError("commit object required")
    tree = _git(root, "rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
    _hex(tree, 40)
    entries = [entry for entry in _git(root, "ls-tree", "-r", "-z", commit).split(b"\0") if entry]
    if not 0 < len(entries) <= MAX_FILES:
        raise SubjectError("source file count exceeds bound")
    records, bodies, total = [], {}, 0
    for entry in entries:
        header, name = entry.split(b"\t", 1)
        try:
            mode, kind, object_id = header.decode("ascii").split()
            name = _path(name.decode("ascii"))
        except UnicodeError:
            raise SubjectError("ASCII source path required") from None
        if mode not in {"100644", "100755"} or kind != "blob" or name in bodies:
            raise SubjectError("regular unique source files required")
        raw = _blob(root, object_id)
        try:
            text = raw.decode("ascii")
        except UnicodeError:
            raise SubjectError("ASCII source required") from None
        if any(pattern.search(text) for _, pattern in PATTERNS):
            raise SubjectError("source fails limited disclosure check")
        total += len(raw)
        if total > MAX_SOURCE_BYTES:
            raise SubjectError("source snapshot exceeds bound")
        records.append({"path": name, "mode": mode, "git_blob": object_id,
                        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        bodies[name] = raw
    return tree, sorted(records, key=lambda row: row["path"]), bodies


def generate(root, pins):
    """Build from exact local objects; protect the old manifest in three places."""
    _hex(pins.baseline_sha256, 64)
    baseline_tree, baseline_files, _ = _inventory(root, pins.baseline_commit)
    tree, files, bodies = _inventory(root, pins.commit)
    original = bodies.get(ORIGINAL_PATH)
    if original is None or hashlib.sha256(original).hexdigest() != pins.baseline_sha256:
        raise SubjectError("frozen baseline manifest changed at source")
    for candidate in (_regular(root / ORIGINAL_PATH, MAX_MANIFEST_BYTES), _index(root, ORIGINAL_PATH)):
        if candidate != original:
            raise SubjectError("frozen baseline manifest changed in checkout or index")
    baseline_expected = {"schema": "ptlc-review-subject-v1", "repository": REPOSITORY,
                         "commit": pins.baseline_commit, "tree": baseline_tree,
                         "file_count": len(baseline_files), "files": baseline_files}
    if _json(original) != baseline_expected:
        raise SubjectError("baseline inventory differs from exact Git objects")
    baseline = {row["path"]: row for row in baseline_files}
    counts = {"added": 0, "changed": 0, "unchanged": 0}
    for row in files:
        old = baseline.get(row["path"])
        status = "added" if old is None else "unchanged" if old == row else "changed"
        counts[status] += 1
        row["baseline_status"] = status
    removed = sorted(set(baseline) - set(bodies))
    return {"schema": "ptlc-observation-review-subject-v1", "repository": REPOSITORY,
            "commit": pins.commit, "tree": tree, "file_count": len(files), "files": files,
            "baseline": {"commit": pins.baseline_commit, "tree": baseline_tree,
                         "file_count": len(baseline_files), "manifest_path": ORIGINAL_PATH,
                         "manifest_sha256": pins.baseline_sha256},
            "delta": dict(counts, removed_paths=removed)}


def verify_manifest(root, pins, raw):
    _json(raw)
    expected = generate(root, pins)
    if raw != encoded(expected):
        raise SubjectError("manifest differs from canonical complete subject")
    return expected


def verify_checkout(root, pins):
    raw = _regular(root / SUBJECT_PATH, MAX_MANIFEST_BYTES)
    expected = verify_manifest(root, pins, raw)
    if _index(root, SUBJECT_PATH) != raw:
        raise SubjectError("indexed subject manifest differs")
    return expected


def verify_archive(path, expected):
    """Read a bounded plain tar without extraction; reject appended members too."""
    records = {row["path"]: row for row in expected["files"]}
    directories = {str(parent) for name in records for parent in PurePosixPath(name).parents if str(parent) != "."}
    seen, dirs = set(), set()
    try:
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise SubjectError("regular bounded plain tar required")
        with path.open("rb") as handle, tarfile.open(fileobj=handle, mode="r|", ignore_zeros=True) as archive:
            members = 0
            for member in archive:
                members += 1
                if members > len(records) + len(directories):
                    raise SubjectError("archive member count exceeds subject")
                name = _path(member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name)
                if member.mode & ~0o777:
                    raise SubjectError("special archive permission bits rejected")
                if member.isdir():
                    if name not in directories or name in dirs:
                        raise SubjectError("unexpected archive directory")
                    dirs.add(name)
                    continue
                if (member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or member.sparse is not None
                        or any(key.startswith("GNU.sparse") for key in member.pax_headers)
                        or name not in records or name in seen):
                    raise SubjectError("unexpected archive source member")
                row = records[name]
                if member.size != row["bytes"] or bool(member.mode & 0o111) != (row["mode"] == "100755"):
                    raise SubjectError("archive size or executable class mismatch")
                stream = archive.extractfile(member)
                if stream is None:
                    raise SubjectError("archive member unavailable")
                with stream:
                    raw = stream.read(member.size + 1)
                if len(raw) != member.size or hashlib.sha256(raw).hexdigest() != row["sha256"]:
                    raise SubjectError("archive source digest mismatch")
                seen.add(name)
        if seen != set(records):
            raise SubjectError("archive omits source files")
    except (OSError, tarfile.TarError, EOFError):
        raise SubjectError("plain source archive inspection failed") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SubjectError("invalid inspection arguments")


def main():
    try:
        parser = _Parser(description=__doc__)
        parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
        parser.add_argument("--expect-commit", required=True, metavar="COMMIT")
        parser.add_argument("--emit", action="store_true")
        parser.add_argument("--archive", type=Path)
        arguments = parser.parse_args()
        root, pins = arguments.root.resolve(), Pins(arguments.expect_commit)
        if arguments.emit:
            if arguments.archive is not None:
                raise SubjectError("emit and archive inspection are separate")
            sys.stdout.buffer.write(encoded(generate(root, pins)))
            return 0
        expected = verify_checkout(root, pins)
        if arguments.archive is not None:
            verify_archive(arguments.archive, expected)
        print("PASS: complete observation subject: {} files; frozen baseline: {} files".format(
            expected["file_count"], expected["baseline"]["file_count"]))
        return 0
    except (SubjectError, OSError, UnicodeError, ValueError, RecursionError):
        print("FAIL: observation subject inspection rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
