#!/usr/bin/env python3
"""Observe bounded ELF64 loader declarations without resolving or executing them.

Fixed metadata observations do not authenticate a loader, dependencies, producer,
source correspondence or runtime closure. Selected inputs must remain quiescent.
"""

import hashlib
import os
from pathlib import Path
import struct
import sys

if __package__:
    from . import check_artifact_prefixes as scanner
else:
    import check_artifact_prefixes as scanner


InputError = scanner.InputError
REFUSAL = "selected worker ELF metadata observation refused"
MAX_BYTES = 32 * 1024 * 1024
MAX_HEADERS = 1024
MAX_INTERPRETER_BYTES = 4096
MAX_DYNAMIC_BYTES = 65536


def _span(raw, start, size):
    if start > len(raw) or size > len(raw)-start:
        raise InputError(REFUSAL)
    return start, start+size


def _observe(raw):
    if (type(raw) is not bytes or not 64 <= len(raw) <= MAX_BYTES
            or raw[:7] != b"\x7fELF\x02\x01\x01"):
        raise InputError(REFUSAL)
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, _, version, _, phoff, _, _, ehsize, phsize, phnum, _, _, _ = header
    if (kind not in (2, 3) or version != 1 or ehsize != 64 or phsize != 56
            or not 1 <= phnum <= MAX_HEADERS or phoff < 64):
        raise InputError(REFUSAL)
    table = _span(raw, phoff, phnum*56)
    protected, selected, seen = [(0, 64), table], [], set()
    for i in range(phnum):
        record = struct.unpack_from("<IIQQQQQQ", raw, phoff+i*56)
        program, _, start, _, _, size, _, _ = record
        begin, end = _span(raw, start, size)
        if program not in (2, 3):
            continue
        if (program in seen or any(begin < b and a < end for a, b in protected)
                or any(begin < b and a < end for a, b in selected)):
            raise InputError(REFUSAL)
        seen.add(program)
        selected.append((begin, end))
        if program == 3:
            if not 2 <= size <= MAX_INTERPRETER_BYTES:
                raise InputError(REFUSAL)
            payload = raw[begin:end]
            if payload[-1:] != b"\x00" or b"\x00" in payload[:-1]:
                raise InputError(REFUSAL)
        elif not 16 <= size <= MAX_DYNAMIC_BYTES or size % 16:
            raise InputError(REFUSAL)
    return dict(format="ELF64 LITTLE ENDIAN", declared_entry_kind="ET_EXEC" if kind == 2 else "ET_DYN",
                declared_interpreter=3 in seen, declared_dynamic_segment=2 in seen)


def inspect(worker, expected_sha256, expected_bytes):
    """Read one caller-pinned complete stream; never open a declared interpreter."""
    try:
        scanner.pin(expected_sha256, expected_bytes)
        if expected_bytes > MAX_BYTES:
            raise InputError(REFUSAL)
        scanner.owned_file(worker, MAX_BYTES)
        with scanner.contents.regular(worker, MAX_BYTES) as handle:
            status = os.fstat(handle.fileno())
            if status.st_uid != os.geteuid() or status.st_size != expected_bytes:
                raise InputError(REFUSAL)
            raw = handle.read(expected_bytes+1)
            if len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise InputError(REFUSAL)
            declarations = _observe(raw)
        return dict(schema="ptlc-offline-worker-elf-declarations-v1",
                    measurement=dict(sha256=expected_sha256, bytes=expected_bytes),
                    declarations=declarations,
                    observation_scope="DECLARED METADATA ONLY; INTERPRETER AND DYNAMIC STRINGS SUPPRESSED",
                    loader_conformance="NOT VALIDATED; SELECTED BOUNDS AND FRAMING ONLY",
                    runtime_closure="NOT AUTHENTICATED", producer_attribution="NOT DETERMINED",
                    source_to_worker="NOT VERIFIED", reproducibility="NOT VERIFIED",
                    selection_origin="CALLER SELECTED; NOT AUTHENTICATED",
                    filesystem="OWNED QUIESCENT INPUT AND TRUSTED ANCESTORS; NO ATOMIC SNAPSHOT",
                    artifact_publication="KEEP SELECTED ARTIFACT PRIVATE",
                    independent_privacy_assessment="NOT ASSESSED", application_and_core="NO-GO")
    except (InputError, OSError, ValueError, TypeError, struct.error):
        raise InputError(REFUSAL) from None


def main():
    try:
        parser = scanner.contents.inputs.source._Parser(description=__doc__)
        parser.add_argument("--worker", type=Path, required=True)
        parser.add_argument("--expect-sha256", required=True)
        parser.add_argument("--expect-bytes", type=int, required=True)
        args = parser.parse_args()
        report = inspect(args.worker.absolute(), args.expect_sha256, args.expect_bytes)
        sys.stdout.buffer.write(scanner.encoded(report))
        return 0
    except (InputError, OSError, ValueError, TypeError):
        print("FAIL: "+REFUSAL, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
