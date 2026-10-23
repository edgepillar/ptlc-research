#!/usr/bin/env python3
"""Check index blobs and working files for accidental disclosure patterns.

This is an ASCII/path/token hygiene check, not a language classifier, secret
scanner, or guarantee of anonymity. It never reads Git identity or credentials.
"""

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path


PATTERNS = (
    ("local home path", re.compile(r"/(?:Users|home)/[^/\s]+/")),
    ("Windows home path", re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+\\")),
    ("email address", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    ("private key header", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")),
    ("credential-shaped token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b")),
)


def _git(root, *arguments, input_data=None):
    result = subprocess.run(
        ["git", "--no-lazy-fetch", "--no-replace-objects", *arguments],
        cwd=root,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Git inspection failed")
    return result.stdout



def _index_blobs(root, object_ids):
    """Read exact typed/sized index objects, preserving duplicate selections."""
    if not object_ids:
        return []
    if len(object_ids) > 65536 or any(
            type(value) is not bytes or re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None
            for value in object_ids):
        raise RuntimeError("Git index selection refused")
    if len({len(value) for value in object_ids}) != 1:
        raise RuntimeError("Git index object format refused")
    requests = b"".join(value + b"\n" for value in object_ids)
    metadata = _git(root, "cat-file", "--batch-check", input_data=requests)
    rows = metadata.splitlines(keepends=True)
    if len(rows) != len(object_ids):
        raise RuntimeError("Git index metadata refused")
    sizes, headers, total = [], [], 0
    for object_id, row in zip(object_ids, rows):
        fields = row.rstrip(b"\n").split(b" ")
        if (len(fields) != 3 or fields[:2] != [object_id, b"blob"]
                or re.fullmatch(rb"0|[1-9][0-9]{0,8}", fields[2]) is None):
            raise RuntimeError("Git index metadata refused")
        size = int(fields[2])
        if size > 16*1024**2 or total + size > 128*1024**2:
            raise RuntimeError("Git index content exceeds bound")
        header = object_id + b" blob " + str(size).encode("ascii") + b"\n"
        if row != header:
            raise RuntimeError("Git index metadata framing refused")
        sizes.append(size); headers.append(header); total += size
    raw = _git(root, "cat-file", "--batch", input_data=requests)
    if len(raw) != total + sum(len(header)+1 for header in headers):
        raise RuntimeError("Git index batch framing refused")
    result, offset = [], 0
    for object_id, size, header in zip(object_ids, sizes, headers):
        if raw[offset:offset+len(header)] != header:
            raise RuntimeError("Git index batch identity refused")
        start = offset+len(header); end = start+size
        if raw[end:end+1] != b"\n":
            raise RuntimeError("Git index batch framing refused")
        value = raw[start:end]
        algorithm = hashlib.sha1 if len(object_id) == 40 else hashlib.sha256
        actual = algorithm(b"blob "+str(size).encode("ascii")+b"\0"+value).hexdigest().encode("ascii")
        if actual != object_id:
            raise RuntimeError("Git index object identity refused")
        result.append(value); offset = end+1
    if offset != len(raw):
        raise RuntimeError("Git index batch framing refused")
    return result


def check(root):
    """Inspect both candidate versions; diagnostics never include their bytes."""
    root = root.resolve()
    failures = []
    checked = 0

    def inspect(content, label):
        nonlocal checked
        try:
            text = content.decode("ascii")
        except UnicodeDecodeError:
            failures.append(label + ": content must be ASCII English text")
            return
        checked += 1
        for description, pattern in PATTERNS:
            if pattern.search(text):
                failures.append(label + ": possible " + description)

    def filename(raw_name, label):
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            failures.append(label + ": filename contains non-ASCII characters")
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            failures.append(label + ": filename contains control characters")
            return None
        for description, pattern in PATTERNS:
            if pattern.search(name):
                failures.append(label + ": filename contains possible " + description)
        return name

    # Read the actual index blobs, even when their worktree copy was removed or
    # replaced. Worktree bytes are not evidence about what git commit would use.
    staged = _git(root, "ls-files", "--stage", "-z")
    entries = list(filter(None, staged.split(b"\0")))
    selected_ids = []
    for entry in entries:
        header, unused_name = entry.split(b"\t", 1)
        mode, object_id, unused_stage = header.split()
        if mode in (b"100644", b"100755"):
            selected_ids.append(object_id)
    blobs = iter(_index_blobs(root, selected_ids))
    for number, entry in enumerate(entries, 1):
        header, raw_name = entry.split(b"\t", 1)
        mode, object_id, stage = header.split()
        label = "index candidate {}".format(number)
        filename(raw_name, label)
        if stage != b"0":
            failures.append(label + ": unresolved index entry requires manual review")
        if mode not in (b"100644", b"100755"):
            failures.append(label + ": non-regular index entry requires manual review")
            continue
        inspect(next(blobs), label)

    listed = _git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    names = sorted(set(name for name in listed.split(b"\0") if name))
    for number, raw_name in enumerate(names, 1):
        label = "worktree candidate {}".format(number)
        name = filename(raw_name, label)
        if name is None:
            continue
        path = root / name
        if path.is_symlink() or root not in path.resolve().parents:
            failures.append(label + ": symlinks or external targets require manual review")
            continue
        if not path.exists():
            continue  # The index version was already inspected independently.
        if not path.is_file():
            failures.append(label + ": non-file candidate requires manual review")
            continue
        inspect(path.read_bytes(), label)
    return checked, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        checked, failures = check(arguments.root)
    except (OSError, RuntimeError, ValueError):
        print("FAIL: unable to inspect Git candidates", file=sys.stderr)
        return 1
    if failures:
        for failure in failures:
            print("FAIL: " + failure, file=sys.stderr)
        return 1
    print("PASS: checked {} index/worktree file versions for ASCII and disclosure patterns".format(checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
