#!/usr/bin/env python3
"""Localize four private strings in bounded raw ELF64/Mach-O64 declarations.

No native reader or worker is launched. Fixed group booleans do not identify a
producer, validate a loader, attest provenance or authorize artifact release.
"""

import os
from pathlib import Path
import struct
import sys

if __package__:
    from . import check_artifact_prefixes as scanner
else:
    import check_artifact_prefixes as scanner


InputError = scanner.InputError
REFUSAL = "selected worker section observation refused"
MAX_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 4096
MAX_TABLE_BYTES = 1024 * 1024
MAX_NAME_BYTES = 256
GROUPS = ("declared-compressed-section", "declared-symbol-or-string-table",
          "declared-debug-section", "other-file-backed-section",
          "outside-selected-ranges", "crosses-selected-boundary")


def _span(raw, start, size):
    if start > len(raw) or size > len(raw)-start:
        raise InputError(REFUSAL)
    return start, start+size


def _disjoint(rows, protected):
    rows = sorted(row for row in rows if row[0] != row[1])
    if len(rows) > MAX_RECORDS:
        raise InputError(REFUSAL)
    for i, (start, end, _) in enumerate(rows):
        if (i and start < rows[i-1][1]) or any(start < b and a < end for a, b in protected):
            raise InputError(REFUSAL)
    return rows


def _elf(raw):
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise InputError(REFUSAL)
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    _, _, version, _, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, names = header
    if (version != 1 or ehsize != 64 or shsize != 64 or not 2 <= shnum <= MAX_RECORDS
            or not 0 < names < shnum or phnum > MAX_RECORDS):
        raise InputError(REFUSAL)
    table = _span(raw, shoff, shnum*64)
    protected = [(0, 64), table]
    if table[0] < 64:
        raise InputError(REFUSAL)
    if phnum:
        if not 0 < phsize <= MAX_NAME_BYTES or phnum*phsize > MAX_TABLE_BYTES:
            raise InputError(REFUSAL)
        program = _span(raw, phoff, phnum*phsize)
        if program[0] < 64 or program[0] < table[1] and table[0] < program[1]:
            raise InputError(REFUSAL)
        protected.append(program)
    elif phoff:
        raise InputError(REFUSAL)
    rows = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff+i*64) for i in range(shnum)]
    if any(rows[0]):
        raise InputError(REFUSAL)
    name_row = rows[names]
    if name_row[1] != 3 or not 1 < name_row[5] <= MAX_TABLE_BYTES or name_row[2] & 0x800:
        raise InputError(REFUSAL)
    name_start, name_end = _span(raw, name_row[4], name_row[5])
    if raw[name_start] or raw[name_end-1]:
        raise InputError(REFUSAL)
    ranges = []
    for name_index, kind, flags, _, start, size, _, _, _, _ in rows[1:]:
        if name_index >= name_row[5]:
            raise InputError(REFUSAL)
        name_at = name_start+name_index
        name_stop = raw.find(b"\x00", name_at, min(name_end, name_at+MAX_NAME_BYTES+1))
        if name_stop < 0:
            raise InputError(REFUSAL)
        name = raw[name_at:name_stop]
        if kind == 0:
            continue
        if kind == 8:
            if flags & 0x800:
                raise InputError(REFUSAL)
            continue
        begin, end = _span(raw, start, size)
        if flags & 0x800 or name.startswith(b".zdebug_"):
            group = GROUPS[0]
        elif kind in (2, 3, 11):
            group = GROUPS[1]
        elif name == b".debug" or name.startswith(b".debug_"):
            group = GROUPS[2]
        else:
            group = GROUPS[3]
        ranges.append((begin, end, group))
    return "ELF64 LITTLE ENDIAN", _disjoint(ranges, protected)


def _macho(raw):
    if len(raw) < 32 or raw[:4] != b"\xcf\xfa\xed\xfe":
        raise InputError(REFUSAL)
    header = struct.unpack_from("<8I", raw)
    count, size = header[4:6]
    if not 0 < count <= MAX_RECORDS or not 0 < size <= MAX_TABLE_BYTES:
        raise InputError(REFUSAL)
    _, limit = _span(raw, 32, size)
    position, ranges, sections, symbol_seen = 32, [], 0, False
    for _ in range(count):
        if position+8 > limit:
            raise InputError(REFUSAL)
        command, length = struct.unpack_from("<II", raw, position)
        if length < 8 or length % 8 or position+length > limit or command == 1:
            raise InputError(REFUSAL)
        if command == 0x19:
            if length < 72:
                raise InputError(REFUSAL)
            segment = struct.unpack_from("<II16sQQQQiiII", raw, position)
            file_start, file_end = _span(raw, segment[5], segment[6])
            sections += segment[9]
            if sections > MAX_RECORDS or length != 72+80*segment[9]:
                raise InputError(REFUSAL)
            for i in range(segment[9]):
                section = struct.unpack_from("<16s16sQQIIIIIIII", raw, position+72+80*i)
                amount, offset, flags = section[3], section[4], section[8]
                if flags & 0xff in (1, 0xc, 0x12):
                    continue
                start, end = _span(raw, offset, amount)
                if amount and (start < file_start or end > file_end):
                    raise InputError(REFUSAL)
                group = GROUPS[2] if flags & 0x02000000 else GROUPS[3]
                ranges.append((start, end, group))
        elif command == 2:
            if symbol_seen or length != 24:
                raise InputError(REFUSAL)
            symbol_seen = True
            _, _, offset, symbols, strings, amount = struct.unpack_from("<6I", raw, position)
            for start, end in (_span(raw, offset, symbols*16), _span(raw, strings, amount)):
                ranges.append((start, end, GROUPS[1]))
        position += length
    if position != limit:
        raise InputError(REFUSAL)
    return "THIN MACH-O64 LITTLE ENDIAN", _disjoint(ranges, [(0, limit)])


def _layout(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise InputError(REFUSAL)
    if raw[:4] == b"\x7fELF":
        return _elf(raw)
    return _macho(raw)


def _localize(raw, prefixes):
    kind, ranges = _layout(raw)
    partition, end = [], 0
    for start, stop, group in ranges:
        if end < start:
            partition.append((end, start, GROUPS[4]))
        partition.append((start, stop, group))
        end = stop
    if end < len(raw):
        partition.append((end, len(raw), GROUPS[4]))
    result = {role: dict.fromkeys(GROUPS, False) for role in scanner.ROLES}
    for role, prefix in prefixes.items():
        for start, stop, group in partition:
            if not result[role][group] and raw.find(prefix, start, stop) >= 0:
                result[role][group] = True
        for _, boundary, _ in partition[:-1]:
            if raw.find(prefix, max(0, boundary-len(prefix)+1),
                        min(len(raw), boundary+len(prefix)-1)) >= 0:
                result[role][GROUPS[5]] = True
                break
    return dict(format=kind, group_presence=result)


def inspect(first, first_sha256, first_bytes, second, second_sha256, second_bytes, prefixes):
    """Consume two bounded owned streams; all expectations are caller-selected."""
    try:
        selected = scanner.selected_prefixes(prefixes)
        for digest, size in ((first_sha256, first_bytes), (second_sha256, second_bytes)):
            scanner.pin(digest, size)
            if size > MAX_BYTES:
                raise InputError(REFUSAL)
        for path in (first, second):
            scanner.owned_file(path, MAX_BYTES)
        with scanner.contents.regular(first, MAX_BYTES) as left_file:
            with scanner.contents.regular(second, MAX_BYTES) as right_file:
                states = [os.fstat(handle.fileno()) for handle in (left_file, right_file)]
                if ((states[0].st_dev, states[0].st_ino) == (states[1].st_dev, states[1].st_ino)
                        or any(s.st_uid != os.geteuid() for s in states)
                        or [s.st_size for s in states] != [first_bytes, second_bytes]):
                    raise InputError(REFUSAL)
                bodies = (left_file.read(first_bytes+1), right_file.read(second_bytes+1))
                artifacts = {}
                for name, raw, digest, size in zip(scanner.SELECTIONS, bodies,
                                                  (first_sha256, second_sha256), (first_bytes, second_bytes)):
                    scan = scanner._Scan(selected[name])
                    scan.feed(raw)
                    measured = scan.report(digest, size)
                    local = _localize(raw, selected[name])
                    if any(any(local['group_presence'][role].values()) != measured['selected_prefix_presence'][role]
                           for role in scanner.ROLES):
                        raise InputError(REFUSAL)
                    artifacts[name] = dict(measured=measured, **local)
                relation = "MATCH" if bodies[0] == bodies[1] else "DIFFER"
        return dict(schema="ptlc-offline-worker-section-evidence-v1", artifacts=artifacts,
                    byte_relation=relation, byte_comparison="COMPLETE SELECTED STREAMS",
                    localization="RAW DECLARED RANGES AND THEIR COMPLEMENT; FIXED GROUP BOOLEANS",
                    format_validation="BOUNDED RANGE SELECTION ONLY; NOT LOADER OR COMPLETE FORMAT CONFORMANCE",
                    producer_attribution="NOT DETERMINED", decompression_and_debug_decoding="NOT PERFORMED",
                    selection_origin="CALLER SELECTED; NOT AUTHENTICATED",
                    artifact_publication="KEEP BOTH ARTIFACTS PRIVATE", independent_privacy_assessment="NOT ASSESSED",
                    reproducibility="NOT VERIFIED", source_to_worker="NOT VERIFIED",
                    filesystem="OWNED QUIESCENT INPUTS AND TRUSTED ANCESTORS; NO ATOMIC SNAPSHOT",
                    application_and_core="NO-GO")
    except (InputError, OSError, ValueError, TypeError, struct.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = scanner.contents.inputs.source._Parser(description=__doc__)
        for name in scanner.SELECTIONS:
            parser.add_argument("--"+name, type=Path, required=True)
            parser.add_argument("--expect-"+name+"-sha256", required=True)
            parser.add_argument("--expect-"+name+"-bytes", type=int, required=True)
        parser.add_argument("--private-prefixes", type=Path, required=True)
        args = parser.parse_args()
        prefixes = scanner.load_prefixes(args.private_prefixes.absolute())
        report = inspect(args.first.absolute(), args.expect_first_sha256, args.expect_first_bytes,
                         args.second.absolute(), args.expect_second_sha256, args.expect_second_bytes, prefixes)
        sys.stdout.buffer.write(scanner.encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
