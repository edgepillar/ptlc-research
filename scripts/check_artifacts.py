#!/usr/bin/env python3
"""Check index blobs and working files for accidental disclosure patterns.

This is an ASCII/path/token hygiene check, not a language classifier, secret
scanner, or guarantee of anonymity. It never reads Git identity or credentials.
"""

import argparse
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


def _git(root, *arguments):
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Git inspection failed")
    return result.stdout


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
    for number, entry in enumerate(filter(None, staged.split(b"\0")), 1):
        header, raw_name = entry.split(b"\t", 1)
        mode, object_id, stage = header.split()
        label = "index candidate {}".format(number)
        filename(raw_name, label)
        if stage != b"0":
            failures.append(label + ": unresolved index entry requires manual review")
        if mode not in (b"100644", b"100755"):
            failures.append(label + ": non-regular index entry requires manual review")
            continue
        inspect(_git(root, "cat-file", "blob", object_id.decode("ascii")), label)

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
