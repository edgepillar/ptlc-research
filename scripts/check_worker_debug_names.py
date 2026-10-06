#!/usr/bin/env python3
"""Observe bounded debug-pool entries and declared source STAB names privately.

No DWARF reference, source path, producer identity or earlier execution is
authenticated. Both selected artifacts remain private under every outcome.
"""

import os
from pathlib import Path
import struct
import sys

if __package__:
    from . import check_worker_symbols as symbols
else:
    import check_worker_symbols as symbols


sections = symbols.sections
scanner = symbols.scanner
InputError = symbols.InputError
REFUSAL = 'selected worker debug-name observation refused'
MAX_POOL_BYTES = 16 * 1024 * 1024
MAX_POOL_ENTRIES = 131072
MAX_ENTRY_BYTES = 65536
GROUPS = ('raw-elf-debug-str-pool', 'terminated-elf-debug-str-entry',
          'raw-elf-debug-line-str-pool', 'terminated-elf-debug-line-str-entry',
          'raw-macho-symbol-string-table', 'referenced-macho-source-stab-name',
          'referenced-macho-included-source-stab-name', 'referenced-macho-other-name',
          'outside-selected-name-regions', 'crosses-selected-name-region-boundary')
POOLS = {b'.debug_str': 0, b'.debug_line_str': 2}


def _regions(raw, kind):
    if kind != 'ELF64 LITTLE ENDIAN':
        _, tables, _ = symbols._declarations(raw)
        return [(start, end, 4) for start, end in tables]
    header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, header[5]+i*64)
            for i in range(header[11])]
    table = rows[header[12]]
    name_start, name_end = sections._span(raw, table[4], table[5])
    selected, seen = [], set()
    for row in rows[1:]:
        at = name_start+row[0]
        stop = raw.find(b'\x00', at, min(name_end, at+sections.MAX_NAME_BYTES+1))
        name = raw[at:stop]
        if name in (b'.zdebug_str', b'.zdebug_line_str'):
            raise InputError(REFUSAL)
        if name not in POOLS:
            continue
        if name in seen or row[1] != 1 or row[2] & 0x800:
            raise InputError(REFUSAL)
        seen.add(name)
        start, end = sections._span(raw, row[4], row[5])
        if start != end:
            selected.append((start, end, POOLS[name]))
    if sum(end-start for start, end, _ in selected) > MAX_POOL_BYTES:
        raise InputError(REFUSAL)
    return sorted(selected)


def _macho_references(raw):
    header = struct.unpack_from('<8I', raw)
    position = 32
    for _ in range(header[4]):
        command, size = struct.unpack_from('<II', raw, position)
        if command == 2:
            _, _, offset, total, start, amount = struct.unpack_from('<6I', raw, position)
            for i in range(total):
                index, flags, _, _, _ = struct.unpack_from('<IBBHQ', raw, offset+16*i)
                yield start, start+amount, index, flags
        position += size


def _localize(raw, prefixes):
    earlier = symbols._localize(raw, prefixes)
    kind = earlier['format']
    regions = _regions(raw, kind)
    partition, end = [], 0
    for start, stop, group in regions:
        if end < start:
            partition.append((end, start, 8))
        partition.append((start, stop, group))
        end = stop
    if end < len(raw):
        partition.append((end, len(raw), 8))
    result = {role: dict.fromkeys(GROUPS, False) for role in scanner.ROLES}
    for role, prefix in prefixes.items():
        for start, stop, group in partition:
            if raw.find(prefix, start, stop) >= 0:
                result[role][GROUPS[group]] = True
        for _, boundary, _ in partition[:-1]:
            if raw.find(prefix, max(0, boundary-len(prefix)+1),
                        min(len(raw), boundary+len(prefix)-1)) >= 0:
                result[role][GROUPS[9]] = True
                break
    if kind == 'ELF64 LITTLE ENDIAN':
        count = 0
        for start, end, group in regions:
            at = start
            while at < end:
                stop = raw.find(b'\x00', at, min(end, at+MAX_ENTRY_BYTES+1))
                count += 1
                if stop < 0 or count > MAX_POOL_ENTRIES:
                    raise InputError(REFUSAL)
                for role, prefix in prefixes.items():
                    if raw.find(prefix, at, stop) >= 0:
                        result[role][GROUPS[group+1]] = True
                at = stop+1
    else:
        termini = {}
        for start, end, index, flags in _macho_references(raw):
            if index == 0:
                continue
            if index >= end-start:
                raise InputError(REFUSAL)
            key = (start, index)
            if key not in termini:
                at = start+index
                stop = raw.find(b'\x00', at, min(end, at+symbols.MAX_NAME_BYTES+1))
                if stop < 0:
                    raise InputError(REFUSAL)
                termini[key] = stop
            group = 5 if flags == 0x64 else 6 if flags == 0x84 else 7
            for role, prefix in prefixes.items():
                if raw.find(prefix, start+index, termini[key]) >= 0:
                    result[role][GROUPS[group]] = True
    section = sections._localize(raw, prefixes)
    for role, row in result.items():
        if (row[GROUPS[1]] and not row[GROUPS[0]]
                or row[GROUPS[3]] and not row[GROUPS[2]]
                or any(row[group] for group in GROUPS[5:8]) and not row[GROUPS[4]]
                or any(row[group] for group in (GROUPS[0], GROUPS[2]))
                and not section['group_presence'][role][sections.GROUPS[2]]):
            raise InputError(REFUSAL)
        if kind != 'ELF64 LITTLE ENDIAN':
            old = earlier['group_presence'][role]
            if (row[GROUPS[4]] != old[symbols.GROUPS[0]]
                    or any(row[group] for group in GROUPS[5:7]) and not old[symbols.GROUPS[4]]
                    or row[GROUPS[7]] and not any(old[group] for group in symbols.GROUPS[3:6])):
                raise InputError(REFUSAL)
    return dict(format=kind, group_presence=result)


def inspect(first, first_sha256, first_bytes, second, second_sha256, second_bytes, prefixes):
    """Read two owned pinned streams and close all stability guards before return."""
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
        return dict(schema='ptlc-offline-worker-debug-name-evidence-v1', artifacts=artifacts,
                    byte_relation=relation, byte_comparison='COMPLETE SELECTED STREAMS',
                    pool_validation='TWO SELECTED NUL-DELIMITED ELF POOLS ONLY; NO DWARF REFERENCES/FORMS/VERSION VALIDATION',
                    symbol_agreement='PRECEDING SYMBOL GRAMMAR IN MEMORY FROM THE SAME STREAMS; NO EXTRA SYMBOL ACQUISITIONS',
                    name_semantics='DECLARED TYPE/TERMINATION ONLY; NO TEXT, PATH, STAB SEQUENCE OR SOURCE VALIDATION',
                    producer_attribution='NOT DETERMINED',
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
