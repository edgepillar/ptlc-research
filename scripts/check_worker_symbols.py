#!/usr/bin/env python3
"""Observe bounded symbol-name references without emitting private names.

Declared type/index agreement is not producer identity, loader validation,
source authentication or permission to release either selected artifact.
"""

import os
from pathlib import Path
import struct
import sys

if __package__:
    from . import check_worker_sections as sections
else:
    import check_worker_sections as sections


scanner = sections.scanner
InputError = sections.InputError
REFUSAL = 'selected worker symbol observation refused'
MAX_SYMBOLS = 131072
MAX_STRING_BYTES = 16 * 1024 * 1024
MAX_NAME_BYTES = 8192
GROUPS = ('raw-selected-string-table', 'referenced-elf-file-name',
          'referenced-elf-other-name', 'referenced-macho-object-stab-name',
          'referenced-macho-other-stab-name', 'referenced-macho-non-stab-name',
          'outside-selected-string-tables', 'crosses-selected-string-table-boundary')


def _declarations(raw):
    kind, selected_ranges = sections._layout(raw)
    string_ranges, references, total = set(), [], 0
    permitted = {(start, end) for start, end, group in selected_ranges
                 if group == sections.GROUPS[1]}
    if kind == 'ELF64 LITTLE ENDIAN':
        header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
        rows = [struct.unpack_from('<IIQQQQIIQQ', raw, header[5]+i*64)
                for i in range(header[11])]
        for row in rows:
            if row[1] not in (2, 11):
                continue
            if (row[2] & 0x800 or row[9] != 24 or row[5] % 24
                    or not 0 < row[6] < len(rows)):
                raise InputError(REFUSAL)
            symbols = row[5]//24
            total += symbols
            if total > MAX_SYMBOLS:
                raise InputError(REFUSAL)
            table = rows[row[6]]
            if table[1] != 3 or table[2] & 0x800 or not table[5]:
                raise InputError(REFUSAL)
            start, end = sections._span(raw, table[4], table[5])
            if (raw[start] or raw[end-1] or (start, end) not in permitted
                    or symbols and (row[4], row[4]+row[5]) not in permitted):
                raise InputError(REFUSAL)
            string_ranges.add((start, end))
            if symbols and raw[row[4]:row[4]+24] != b'\x00'*24:
                raise InputError(REFUSAL)
            for i in range(symbols):
                index, info, _, _, _, _ = struct.unpack_from('<IBBHQQ', raw, row[4]+i*24)
                references.append((start, end, index, GROUPS[1] if info & 15 == 4 else GROUPS[2]))
    else:
        header = struct.unpack_from('<8I', raw)
        position = 32
        for _ in range(header[4]):
            command, size = struct.unpack_from('<II', raw, position)
            if command == 2:
                _, _, offset, total, start, amount = struct.unpack_from('<6I', raw, position)
                if total > MAX_SYMBOLS:
                    raise InputError(REFUSAL)
                _, end = sections._span(raw, start, amount)
                if amount:
                    string_ranges.add((start, end))
                for i in range(total):
                    index, flags, _, _, _ = struct.unpack_from('<IBBHQ', raw, offset+16*i)
                    group = GROUPS[3] if flags == 0x66 else GROUPS[4] if flags & 0xe0 else GROUPS[5]
                    references.append((start, end, index, group))
            position += size
    if sum(end-start for start, end in string_ranges) > MAX_STRING_BYTES:
        raise InputError(REFUSAL)
    return kind, sorted(string_ranges), references


def _localize(raw, prefixes):
    kind, tables, references = _declarations(raw)
    partition, end = [], 0
    for start, stop in tables:
        if end < start:
            partition.append((end, start, GROUPS[6]))
        partition.append((start, stop, GROUPS[0]))
        end = stop
    if end < len(raw):
        partition.append((end, len(raw), GROUPS[6]))
    result = {role: dict.fromkeys(GROUPS, False) for role in scanner.ROLES}
    for role, prefix in prefixes.items():
        for start, stop, group in partition:
            if raw.find(prefix, start, stop) >= 0:
                result[role][group] = True
        for _, boundary, _ in partition[:-1]:
            if raw.find(prefix, max(0, boundary-len(prefix)+1),
                        min(len(raw), boundary+len(prefix)-1)) >= 0:
                result[role][GROUPS[7]] = True
                break
    termini = {}
    for start, end, index, group in references:
        if index == 0:
            continue
        if index >= end-start:
            raise InputError(REFUSAL)
        key = (start, end, index)
        if key not in termini:
            at = start+index
            stop = raw.find(b'\x00', at, min(end, at+MAX_NAME_BYTES+1))
            if stop < 0:
                raise InputError(REFUSAL)
            termini[key] = stop
        for role, prefix in prefixes.items():
            if not result[role][group] and raw.find(prefix, start+index, termini[key]) >= 0:
                result[role][group] = True
    earlier = sections._localize(raw, prefixes)
    for role, row in result.items():
        if (any(row[group] for group in GROUPS[1:6]) and not row[GROUPS[0]]
                or row[GROUPS[0]] and not earlier['group_presence'][role][sections.GROUPS[1]]):
            raise InputError(REFUSAL)
    return dict(format=kind, group_presence=result)


def inspect(first, first_sha256, first_bytes, second, second_sha256, second_bytes, prefixes):
    """Read two caller-selected owned streams; preserve all stability guards."""
    try:
        selected = scanner.selected_prefixes(prefixes)
        for digest, size in ((first_sha256, first_bytes), (second_sha256, second_bytes)):
            scanner.pin(digest, size)
            if size > sections.MAX_BYTES:
                raise InputError(REFUSAL)
        for path in (first, second):
            scanner.owned_file(path, sections.MAX_BYTES)
        with scanner.contents.regular(first, sections.MAX_BYTES) as left:
            with scanner.contents.regular(second, sections.MAX_BYTES) as right:
                states = [os.fstat(handle.fileno()) for handle in (left, right)]
                if ((states[0].st_dev, states[0].st_ino) == (states[1].st_dev, states[1].st_ino)
                        or any(s.st_uid != os.geteuid() for s in states)
                        or [s.st_size for s in states] != [first_bytes, second_bytes]):
                    raise InputError(REFUSAL)
                bodies = (left.read(first_bytes+1), right.read(second_bytes+1))
                artifacts = {}
                for name, raw, digest, size in zip(scanner.SELECTIONS, bodies,
                                                  (first_sha256, second_sha256), (first_bytes, second_bytes)):
                    scan = scanner._Scan(selected[name]); scan.feed(raw)
                    measured = scan.report(digest, size)
                    observed = _localize(raw, selected[name])
                    if any(any(observed['group_presence'][role].values()) != measured['selected_prefix_presence'][role]
                           for role in scanner.ROLES):
                        raise InputError(REFUSAL)
                    artifacts[name] = dict(measured=measured, **observed)
                relation = 'MATCH' if bodies[0] == bodies[1] else 'DIFFER'
        return dict(schema='ptlc-offline-worker-symbol-reference-evidence-v1', artifacts=artifacts,
                    byte_relation=relation, byte_comparison='COMPLETE SELECTED STREAMS',
                    reference_validation='BOUNDED NAME REFERENCES ONLY; NO FULL SYMBOL/VALUE/LOADER VALIDATION',
                    producer_attribution='NOT DETERMINED', text_and_debug_decoding='NOT PERFORMED',
                    selection_origin='CALLER SELECTED; NOT AUTHENTICATED',
                    artifact_publication='KEEP BOTH ARTIFACTS PRIVATE', independent_privacy_assessment='NOT ASSESSED',
                    reproducibility='NOT VERIFIED', source_to_worker='NOT VERIFIED',
                    filesystem='OWNED QUIESCENT INPUTS AND TRUSTED ANCESTORS; NO ATOMIC SNAPSHOT',
                    application_and_core='NO-GO')
    except (InputError, OSError, ValueError, TypeError, RuntimeError, struct.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = scanner.contents.inputs.source._Parser(description=__doc__)
        for name in scanner.SELECTIONS:
            parser.add_argument('--'+name, type=Path, required=True)
            parser.add_argument('--expect-'+name+'-sha256', required=True)
            parser.add_argument('--expect-'+name+'-bytes', type=int, required=True)
        parser.add_argument('--private-prefixes', type=Path, required=True)
        args = parser.parse_args()
        report = inspect(args.first.absolute(), args.expect_first_sha256, args.expect_first_bytes,
                         args.second.absolute(), args.expect_second_sha256, args.expect_second_bytes,
                         scanner.load_prefixes(args.private_prefixes.absolute()))
        sys.stdout.buffer.write(scanner.encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError, RuntimeError):
        print('FAIL: '+REFUSAL, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
