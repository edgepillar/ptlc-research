#!/usr/bin/env python3
"""Observe selected private bytes and compare two bounded artifact streams.

No build, worker or network is invoked. A negative scan does not qualify an
artifact for publication, and byte agreement is not build provenance.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

if __package__:
    from . import check_dependency_contents as contents
else:
    import check_dependency_contents as contents


InputError = contents.InputError
encoded = contents.encoded
ROLES = ("selected-source-location", "selected-build-location",
         "selected-cache-location", "selected-repository-location")
SELECTIONS = ("first", "second")
SCHEMA = "ptlc-offline-private-prefix-selection-v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SELECTION_BYTES = 128 * 1024
MIN_PREFIX_BYTES = 8
MAX_PREFIX_BYTES = 4096
CHUNK_BYTES = 64 * 1024
REFUSAL = "selected artifact comparison refused"


def fields(value, expected):
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != set(expected)):
        raise InputError(REFUSAL)


def selected_prefixes(value):
    fields(value, SELECTIONS)
    for selection in SELECTIONS:
        row = value[selection]
        fields(row, ROLES)
        for prefix in row.values():
            if type(prefix) is not bytes or not MIN_PREFIX_BYTES <= len(prefix) <= MAX_PREFIX_BYTES:
                raise InputError(REFUSAL)
        if len(set(row.values())) != len(ROLES):
            raise InputError(REFUSAL)
    # Copy the bounded selections so the scan does not use a mutable mapping.
    return {name: {role: value[name][role] for role in ROLES} for name in SELECTIONS}


def decode_prefixes(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SELECTION_BYTES or not raw.isascii():
        raise InputError(REFUSAL)
    # Bound nested containers before the JSON decoder sees them.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (123, 91):
            depth += 1
            if depth > 4:
                raise InputError(REFUSAL)
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise InputError(REFUSAL)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InputError(REFUSAL)
            result[key] = value
        return result

    def refuse_number(_):
        raise InputError(REFUSAL)

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                           parse_int=refuse_number, parse_float=refuse_number,
                           parse_constant=refuse_number)
        fields(value, ("schema", *SELECTIONS))
        if type(value["schema"]) is not str or value["schema"] != SCHEMA:
            raise InputError(REFUSAL)
        result = {}
        for selection in SELECTIONS:
            fields(value[selection], ROLES)
            result[selection] = {}
            for role, text in value[selection].items():
                if (type(text) is not str or not 2*MIN_PREFIX_BYTES <= len(text) <= 2*MAX_PREFIX_BYTES
                        or len(text) % 2 or re.fullmatch("[0-9a-f]+", text) is None):
                    raise InputError(REFUSAL)
                result[selection][role] = bytes.fromhex(text)
        return selected_prefixes(result)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError(REFUSAL) from None


def owned_file(path, bound, private=False):
    if type(path) is not type(Path()):
        raise InputError(REFUSAL)
    contents.directory(path.parent)
    status = path.lstat()
    if (not stat.S_ISREG(status.st_mode) or status.st_uid != os.geteuid()
            or not 0 < status.st_size <= bound or (private and status.st_mode & 0o077)):
        raise InputError(REFUSAL)


def load_prefixes(path):
    try:
        owned_file(path, MAX_SELECTION_BYTES, private=True)
        with contents.regular(path, MAX_SELECTION_BYTES) as handle:
            opened = os.fstat(handle.fileno())
            if opened.st_uid != os.geteuid() or opened.st_mode & 0o077:
                raise InputError(REFUSAL)
            return decode_prefixes(handle.read(MAX_SELECTION_BYTES+1))
    except (InputError, OSError, ValueError, TypeError):
        raise InputError(REFUSAL) from None


def pin(digest, size):
    contents.inputs.source._hex(digest, 64)
    if type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES:
        raise InputError(REFUSAL)


class _Scan:
    def __init__(self, prefixes):
        self.prefixes = prefixes
        self.present = dict.fromkeys(ROLES, False)
        self.overlap = max(map(len, prefixes.values()))-1
        self.tail = b""
        self.digest = hashlib.sha256()
        self.bytes = 0

    def feed(self, chunk):
        self.digest.update(chunk)
        self.bytes += len(chunk)
        combined = self.tail+chunk
        for role in ROLES:
            if not self.present[role] and self.prefixes[role] in combined:
                self.present[role] = True
        self.tail = combined[-self.overlap:]

    def report(self, expected_sha256, expected_bytes):
        digest = self.digest.hexdigest()
        if digest != expected_sha256 or self.bytes != expected_bytes:
            raise InputError(REFUSAL)
        return dict(sha256=digest, bytes=self.bytes, selected_prefix_presence=self.present.copy(),
                    present_role_count=sum(self.present.values()))


def inspect(first, first_sha256, first_bytes, second, second_sha256, second_bytes, prefixes):
    """Read only owned, quiescent selections with trusted ancestors.

    Expected hashes, sizes and prefixes come from the caller. Their independent
    origin and the relationship to any source/build claim are not attested.
    """
    try:
        selected = selected_prefixes(prefixes)
        for digest, size in ((first_sha256, first_bytes), (second_sha256, second_bytes)):
            pin(digest, size)
        for path in (first, second):
            owned_file(path, MAX_ARTIFACT_BYTES)
        left, right = _Scan(selected["first"]), _Scan(selected["second"])
        agreement = True
        with contents.regular(first, MAX_ARTIFACT_BYTES) as left_file:
            with contents.regular(second, MAX_ARTIFACT_BYTES) as right_file:
                left_stat, right_stat = os.fstat(left_file.fileno()), os.fstat(right_file.fileno())
                if ((left_stat.st_dev, left_stat.st_ino) == (right_stat.st_dev, right_stat.st_ino)
                        or any(s.st_uid != os.geteuid() for s in (left_stat, right_stat))
                        or left_stat.st_size != first_bytes or right_stat.st_size != second_bytes):
                    raise InputError(REFUSAL)
                while True:
                    a = left_file.read(min(CHUNK_BYTES, first_bytes+1-left.bytes))
                    b = right_file.read(min(CHUNK_BYTES, second_bytes+1-right.bytes))
                    if not a and not b:
                        break
                    if a != b:
                        agreement = False
                    left.feed(a)
                    right.feed(b)
                    if left.bytes > first_bytes or right.bytes > second_bytes:
                        raise InputError(REFUSAL)
                measured = dict(first=left.report(first_sha256, first_bytes),
                                second=right.report(second_sha256, second_bytes))
        return dict(schema="ptlc-offline-selected-artifact-prefix-evidence-v1", artifacts=measured,
                    byte_relation="MATCH" if agreement else "DIFFER",
                    byte_comparison="COMPLETE SELECTED STREAMS",
                    outcome="SELECTED BYTE OBSERVATIONS ONLY; NOT ASSESSED",
                    selection_origin="CALLER SELECTED; NOT AUTHENTICATED",
                    prefix_scope="FOUR EXACT CALLER-SELECTED BYTE STRINGS PER ARTIFACT",
                    artifact_publication="KEEP BOTH ARTIFACTS PRIVATE",
                    independent_privacy_assessment="NOT ASSESSED",
                    reproducibility="NOT VERIFIED", source_to_worker="NOT VERIFIED",
                    filesystem="OWNED QUIESCENT INPUTS AND TRUSTED ANCESTORS; NO ATOMIC SNAPSHOT",
                    application_and_core="NO-GO")
    except (InputError, OSError, ValueError, TypeError):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = contents.inputs.source._Parser(description=__doc__)
        for selection in SELECTIONS:
            parser.add_argument("--"+selection, required=True, type=Path)
            parser.add_argument("--expect-"+selection+"-sha256", required=True)
            parser.add_argument("--expect-"+selection+"-bytes", required=True, type=int)
        parser.add_argument("--private-prefixes", required=True, type=Path)
        args = parser.parse_args()
        prefixes = load_prefixes(args.private_prefixes.absolute())
        report = inspect(args.first.absolute(), args.expect_first_sha256, args.expect_first_bytes,
                         args.second.absolute(), args.expect_second_sha256, args.expect_second_bytes,
                         prefixes)
        sys.stdout.buffer.write(encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
